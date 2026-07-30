//! The ChunkStore block engine (spec §5/§6).
//!
//! One engine instance serves exactly one volume under exactly one lease
//! epoch. In strict mode local state is a deletable cache. In relaxed mode,
//! acknowledged generations between the local and remote durability
//! watermarks live in the pending-pack journal and therefore make that Host
//! state authoritative until the background publisher advances the remote
//! watermark.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cats_api::chunk::{self, CHUNKS_PER_LEAF, CHUNK_SIZE};

use crate::crashpoint;
use crate::format::{
    self, ChunkRef, LeafRef, PackByteRange, PackEntry, PackHeader, BITMAP_HEADER_LEN,
};
use cats_storage::{BlobError, BlobStore, MetaError, MetadataStore};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("i/o out of bounds: offset {offset} len {len} volume size {size}")]
    OutOfBounds { offset: u64, len: u64, size: u64 },
    #[error("attachment is fenced; refusing writes")]
    Fenced,
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

#[cfg(target_os = "linux")]
fn punch_hole(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `file` owns a live fd for the duration of the call; the flags
    // request the documented in-place hole-punch operation, and the checked
    // volume offsets are representable by Linux `off_t` on supported targets.
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as libc::off_t,
            len as libc::off_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn punch_hole(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut request = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: offset as libc::off_t,
        fp_length: len as libc::off_t,
    };
    // SAFETY: `file` remains open for the call and `request` is a fully
    // initialized `fpunchhole_t` whose pointer is valid for the call duration.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &mut request) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// What one garbage-collection pass found and removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcStats {
    pub data_objects_live: usize,
    pub data_objects_deleted: usize,
    pub map_nodes_live: usize,
    pub map_nodes_deleted: usize,
}

/// When a FLUSH acknowledgment is allowed to reach the Guest (ADR-0022).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityMode {
    /// FLUSH acks only after the commit is durable in the object store and the
    /// map CAS has succeeded (spec §6). Any acknowledged write survives losing
    /// the host outright.
    Strict,
    /// FLUSH acks once the pack is durable on the local disk; a background
    /// committer publishes staged packs in order — on its timer, and eagerly
    /// whenever the queue crosses `EAGER_DRAIN_WATERMARK`, so the interval
    /// bounds the idle-tail latency rather than paces bursts.
    /// Acknowledged-but-unpublished writes survive a blockd crash on the same
    /// host (pack replay), but not the loss of the host. The authoritative RPO
    /// is the observed age/bytes between the local and remote watermarks. The
    /// drain interval is a target, not a bound: a remote outage can extend it.
    ///
    /// `drain_interval_ms == 0` disables the background committer entirely;
    /// explicit drains still work. This is a deterministic mode for tests.
    Relaxed { drain_interval_ms: u64 },
}

/// Default per-volume local replication backlog. This is an admission boundary,
/// not an RPO promise: while remote publication is unavailable, acknowledged
/// relaxed FLUSHes remain durable on this Host and consume this reservation.
/// Once it is full, new dirty barriers park without calling the remote stores.
pub const DEFAULT_MAX_STAGED_BYTES: u64 = 8 << 30;

/// A second bound prevents a workload made entirely of tiny barriers from
/// exhausting directory entries and in-memory queue metadata before it reaches
/// the byte limit.
pub const DEFAULT_MAX_STAGED_PACKS: usize = 4_096;

/// Per-volume physical local footprint ceiling for cache blocks plus pending
/// packs. Clean committed cache chunks are evicted below this watermark;
/// dirty or remotely unpublished chunks are pinned and cause local
/// backpressure instead.
pub const DEFAULT_MAX_LOCAL_BYTES: u64 = 16 << 30;

/// Queue depth past which a relaxed stage kicks the committer instead of
/// letting packs sit until the timer. Above one so the single-pack case (an
/// idle volume's periodic journal commit) still batches with whatever the
/// next few milliseconds bring, and low enough that a burst starts draining
/// long before the configured backpressure cap is in sight.
const EAGER_DRAIN_WATERMARK: usize = 2;

/// Payload bytes one drain batch may hold in memory at once. A batch of
/// sparse packs is far below this; a run of dense 4 MiB-base commits gets
/// split into successive batches instead of pulling gigabytes into RAM.
const MAX_BATCH_BYTES: usize = 256 << 20;

/// Conservative space accounting for the JSON metadata around one pending
/// pack. Admission must reserve the later pack before dirty cache can consume
/// the whole local quota, or no publisher input could ever be created.
const PACK_RESERVATION_FIXED_BYTES: u64 = 4 << 10;
const PACK_RESERVATION_PER_ENTRY_BYTES: u64 = 512;
const PACK_RESERVATION_PER_RANGE_BYTES: u64 = 192;

/// What wakes the background committer.
struct CommitterSignal {
    stop: bool,
    kick: bool,
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

/// Observable local/remote durability watermarks for one attached volume.
///
/// `local_durable_generation` is what a relaxed Guest FLUSH has reached on the
/// Host NVMe. `remote_durable_generation` is the latest S3 + metadata-CAS
/// generation and therefore the restore point after permanent Host loss.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DurabilityStatus {
    pub mode: String,
    pub local_durable_generation: i64,
    pub remote_durable_generation: i64,
    pub unpublished_generations: usize,
    pub unpublished_bytes: u64,
    pub oldest_unpublished_age_ms: u64,
    pub max_unpublished_generations: usize,
    pub max_unpublished_bytes: u64,
    pub local_allocated_bytes: u64,
    /// Physical bytes plus space reserved to stage the current dirty set.
    #[serde(default)]
    pub local_accounted_bytes: u64,
    pub max_local_bytes: u64,
    pub evicted_cache_chunks: u64,
    pub backpressured: bool,
    pub fenced: bool,
    pub last_publish_error: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirtyByteRange {
    start: u32,
    end: u32,
}

impl DirtyByteRange {
    fn len(self) -> usize {
        (self.end - self.start) as usize
    }
}

fn merge_dirty_range(ranges: &mut Vec<DirtyByteRange>, mut new_range: DirtyByteRange) {
    let mut index = 0;
    while index < ranges.len() {
        let current = ranges[index];
        if current.end < new_range.start {
            index += 1;
            continue;
        }
        if new_range.end < current.start {
            break;
        }
        new_range.start = new_range.start.min(current.start);
        new_range.end = new_range.end.max(current.end);
        ranges.remove(index);
    }
    ranges.insert(index, new_range);
}

fn pack_reservation_upper(payload_bytes: u64, entries: usize, ranges: usize) -> u64 {
    payload_bytes
        .saturating_add(PACK_RESERVATION_FIXED_BYTES)
        .saturating_add((entries as u64).saturating_mul(PACK_RESERVATION_PER_ENTRY_BYTES))
        .saturating_add((ranges as u64).saturating_mul(PACK_RESERVATION_PER_RANGE_BYTES))
}

fn apply_publishable_entry(image: &mut [u8], entry: &PackEntry, payload: &[u8]) -> Result<()> {
    let start = entry.payload_offset as usize;
    let end = start
        .checked_add(entry.len as usize)
        .ok_or_else(|| EngineError::Corrupt("pack payload range overflow".into()))?;
    let source = payload
        .get(start..end)
        .ok_or_else(|| EngineError::Corrupt("pack payload range is out of bounds".into()))?;
    if hex::encode(format::sha256(source)) != entry.sha256_hex {
        return Err(EngineError::Corrupt("pack entry hash mismatch".into()));
    }
    if entry.is_base() {
        if source.len() != CHUNK_SIZE as usize {
            return Err(EngineError::Corrupt(
                "pack base is not one full chunk".into(),
            ));
        }
        image.copy_from_slice(source);
        return Ok(());
    }
    let page_bytes = cats_api::chunk::DIRTY_PAGE_SIZE as usize;
    let expected = entry.page_mask.count_ones() as usize * page_bytes;
    if source.len() != expected {
        return Err(EngineError::Corrupt(format!(
            "pack delta carries {} bytes for {} pages",
            source.len(),
            entry.page_mask.count_ones()
        )));
    }
    let mut consumed = 0;
    for page in 0..cats_api::chunk::PAGES_PER_CHUNK {
        if entry.page_mask & (1u64 << page) == 0 {
            continue;
        }
        let at = page as usize * page_bytes;
        image[at..at + page_bytes].copy_from_slice(&source[consumed..consumed + page_bytes]);
        consumed += page_bytes;
    }
    Ok(())
}

fn apply_local_entry(image: &mut [u8], entry: &PackEntry, payload: &[u8]) -> Result<()> {
    if entry.is_discard() {
        image.fill(0);
        return Ok(());
    }
    if !entry.is_byte_overlay() {
        return apply_publishable_entry(image, entry, payload);
    }
    let entry_start = entry.payload_offset as usize;
    let entry_end = entry_start
        .checked_add(entry.len as usize)
        .ok_or_else(|| EngineError::Corrupt("byte-overlay entry overflow".into()))?;
    let entry_payload = payload
        .get(entry_start..entry_end)
        .ok_or_else(|| EngineError::Corrupt("byte-overlay entry is out of bounds".into()))?;
    if hex::encode(format::sha256(entry_payload)) != entry.sha256_hex {
        return Err(EngineError::Corrupt(
            "byte-overlay entry hash mismatch".into(),
        ));
    }
    for range in &entry.byte_ranges {
        let source_start = range.payload_offset as usize;
        let source_end = source_start
            .checked_add(range.len as usize)
            .ok_or_else(|| EngineError::Corrupt("byte-overlay payload overflow".into()))?;
        let destination_start = range.chunk_offset as usize;
        let destination_end = destination_start
            .checked_add(range.len as usize)
            .ok_or_else(|| EngineError::Corrupt("byte-overlay chunk overflow".into()))?;
        let source = payload
            .get(source_start..source_end)
            .ok_or_else(|| EngineError::Corrupt("byte-overlay payload is out of bounds".into()))?;
        let destination = image
            .get_mut(destination_start..destination_end)
            .ok_or_else(|| EngineError::Corrupt("byte-overlay chunk is out of bounds".into()))?;
        destination.copy_from_slice(source);
    }
    Ok(())
}

pub struct ChunkEngine {
    cfg: EngineConfig,
    size: u64,
    chunk_count: u64,
    blob: Arc<dyn BlobStore>,
    meta: Arc<dyn MetadataStore>,
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

/// Packs staged locally but not yet published to the object store.
struct StagedQueue {
    packs: std::collections::VecDeque<StagedPack>,
    bytes: u64,
    /// Base generation the next staged pack chains onto: the committed
    /// generation plus one per pack already staged ahead of it. Kept as its
    /// own monotonic counter rather than derived from `generation` and the
    /// queue length, because a publish bumps the one and pops the other in
    /// two steps and a stage between them must not see the half-applied sum.
    next_base: i64,
}

/// One staged pack; the payload stays in the pack file so the queue costs
/// memory proportional to its length, not to the bytes awaiting upload.
struct StagedPack {
    txn: String,
    path: PathBuf,
    encoded_bytes: u64,
    staged_at_unix_ms: u64,
    chunks: Vec<u64>,
}

impl ChunkEngine {
    /// Attach to a volume: acquire the lease (bumping the fencing epoch),
    /// start lease renewal, then load the committed map and recover pending
    /// packs under the live lease.
    pub fn attach(
        cfg: EngineConfig,
        blob: Arc<dyn BlobStore>,
        meta: Arc<dyn MetadataStore>,
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
        let head = meta.load_head(&cfg.volume_id)?;
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

        let epoch = meta.acquire_lease(&cfg.volume_id, &cfg.attachment_id, cfg.lease_ttl_ms)?;

        fs::create_dir_all(cfg.data_dir.join("pending"))?;
        let cache = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(cfg.data_dir.join("cache.data"))?;
        #[cfg(unix)]
        let cache_was_allocated = {
            use std::os::unix::fs::MetadataExt;
            cache.metadata()?.blocks() != 0
        };
        if cache.metadata()?.len() != size {
            cache.set_len(size)?;
        }

        let (bitmap_file, dirty) = Self::open_bitmap(&cfg.data_dir, chunk_count)?;

        let engine = Arc::new(Self {
            size,
            chunk_count,
            blob,
            meta,
            cache,
            bitmap: Mutex::new(bitmap_file),
            state: Mutex::new(EngineState {
                dirty,
                dirty_ranges: vec![Vec::new(); chunk_count as usize],
                map: vec![ChunkRef::Hole; chunk_count as usize],
                leaf_refs: vec![LeafRef::Empty; chunk::leaf_count(size) as usize],
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
        let recovered = engine
            .load_committed_map()
            .and_then(|()| engine.recover_pending_packs());
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
        engine.start_committer_thread();
        if engine.staged.lock().unwrap().packs.len() > EAGER_DRAIN_WATERMARK {
            engine.kick_committer();
        }
        Ok(engine)
    }

    fn open_bitmap(data_dir: &std::path::Path, chunk_count: u64) -> Result<(File, Vec<u64>)> {
        let path = data_dir.join("dirty.bitmap");
        let existed = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let expected_len = BITMAP_HEADER_LEN + chunk_count * 8;
        let mut dirty = vec![0u64; chunk_count as usize];
        if existed && file.metadata()?.len() == expected_len {
            let mut header = vec![0u8; BITMAP_HEADER_LEN as usize];
            file.read_exact_at(&mut header, 0)?;
            let stored = format::decode_bitmap_header(&header)
                .map_err(|e| EngineError::Corrupt(e.to_string()))?;
            if stored != chunk_count {
                return Err(EngineError::Corrupt(
                    "dirty bitmap chunk count mismatch".into(),
                ));
            }
            let mut words = vec![0u8; (chunk_count * 8) as usize];
            file.read_exact_at(&mut words, BITMAP_HEADER_LEN)?;
            for (i, w) in dirty.iter_mut().enumerate() {
                *w = u64::from_le_bytes(words[i * 8..i * 8 + 8].try_into().unwrap());
            }
        } else {
            file.set_len(0)?;
            file.write_all_at(&format::encode_bitmap_header(chunk_count), 0)?;
            file.set_len(expected_len)?;
            file.sync_data()?;
        }
        Ok((file, dirty))
    }

    fn load_committed_map(&self) -> Result<()> {
        let head = self.meta.load_head(&self.cfg.volume_id)?;
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

    pub fn durability_status(&self) -> DurabilityStatus {
        let remote_durable_generation = self.generation();
        let unstaged_reservation = self.unstaged_pack_reservation_bytes();
        let staged = self.staged.lock().unwrap();
        let unpublished_generations = staged.packs.len();
        let unpublished_bytes = staged.bytes;
        let local_allocated_bytes = self
            .cache_allocated_bytes()
            .unwrap_or(0)
            .saturating_add(unpublished_bytes);
        let local_accounted_bytes = local_allocated_bytes
            .saturating_add(unstaged_reservation)
            .saturating_add(self.inflight_staging_bytes.load(Ordering::Relaxed));
        let oldest_unpublished_age_ms = staged
            .packs
            .front()
            .map(|pack| unix_time_ms().saturating_sub(pack.staged_at_unix_ms))
            .unwrap_or(0);
        let status = DurabilityStatus {
            mode: match self.cfg.durability {
                DurabilityMode::Strict => "strict",
                DurabilityMode::Relaxed { .. } => "relaxed",
            }
            .to_string(),
            local_durable_generation: staged.next_base,
            remote_durable_generation,
            unpublished_generations,
            unpublished_bytes,
            oldest_unpublished_age_ms,
            max_unpublished_generations: self.cfg.max_staged_packs,
            max_unpublished_bytes: self.cfg.max_staged_bytes,
            local_allocated_bytes,
            local_accounted_bytes,
            max_local_bytes: self.cfg.max_local_bytes,
            evicted_cache_chunks: self.evicted_cache_chunks.load(Ordering::Relaxed),
            backpressured: unpublished_generations >= self.cfg.max_staged_packs
                || unpublished_bytes >= self.cfg.max_staged_bytes
                || local_accounted_bytes >= self.cfg.max_local_bytes
                || self.backpressure_waiters.load(Ordering::Relaxed) != 0,
            fenced: self.is_fenced(),
            last_publish_error: self.last_publish_error.lock().unwrap().clone(),
        };
        drop(staged);
        status
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
            manifest.base_map(self.size).map_err(|_| {
                EngineError::Corrupt(format!(
                    "image {} does not fit volume {} of {} bytes",
                    manifest.image_id, self.cfg.volume_id, self.size
                ))
            })?
        };

        let chunks: Vec<u64> = manifest.chunks.iter().map(|c| c.chunk_idx).collect();
        let txn = format!("img-{}", &manifest.image_id[..16]);
        let mut new_leaves = vec![LeafRef::Empty; chunk::leaf_count(self.size) as usize];
        let new_gen =
            self.publish_map(&txn, 0, 1, self.epoch, &new_map, &mut new_leaves, &chunks)?;

        let mut st = self.state.lock().unwrap();
        st.map = new_map;
        st.leaf_refs = new_leaves;
        st.generation = new_gen;
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

    /// Delete objects this volume no longer references (spec §9).
    ///
    /// Liveness is "reachable from the volume's current Root": the root node, the
    /// leaf nodes it names, and every object every `ChunkRef` names — which after
    /// delta packs means a base **and all of its deltas**, not just the newest
    /// object for a chunk (ADR-0016).
    ///
    /// Two things it must not do, both introduced by this branch:
    ///
    /// * Never touch `images/`. Those objects belong to the image and are shared
    ///   by every volume provisioned from it, so deleting a volume must not delete
    ///   the fleet's rootfs (ADR-0017). This function only ever lists and deletes
    ///   under this volume's own prefix, and a base whose ref names an image is
    ///   simply not one of this volume's objects.
    /// * Never race a commit. It runs on the engine, which holds the volume's
    ///   lease, so no other writer can be publishing objects that the Root does
    ///   not name yet. A pending pack of this writer's own is safe either way:
    ///   recovery replays it from the pack file and re-uploads whatever was
    ///   deleted.
    ///
    /// Commit records are left alone: they are the audit trail, they are tiny, and
    /// pruning them is a retention policy rather than garbage collection.
    pub fn collect_garbage(&self) -> Result<GcStats> {
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        // Block commits for the scan so the live set and the Root agree. Both
        // locks: `flush_lock` stops new stages, `publish_lock` stops the
        // background committer from uploading objects the Root does not name
        // yet — GC would sweep those as garbage right before their CAS.
        let _flush = self.flush_lock.lock().unwrap();
        let _publish = self.publish_lock.lock().unwrap();
        let vol = &self.cfg.volume_id;

        let (live_data, live_nodes) = {
            let st = self.state.lock().unwrap();
            let mut data: HashSet<String> = HashSet::new();
            for chunk_ref in &st.map {
                // A base that came from an image is not this volume's object; it
                // lives under `images/` and is not a candidate for deletion here.
                if chunk_ref.image().is_some() {
                    for delta in chunk_ref.delta_object_ids() {
                        data.insert(delta.to_string());
                    }
                } else {
                    for object_id in chunk_ref.object_ids() {
                        data.insert(object_id.to_string());
                    }
                }
            }
            let mut nodes: HashSet<String> = HashSet::new();
            for leaf in &st.leaf_refs {
                if let LeafRef::Present { object_id, .. } = leaf {
                    nodes.insert(object_id_hex(object_id).to_string());
                }
            }
            let head = self.meta.load_head(vol)?;
            if let Some(root) = &head.root_object_id {
                nodes.insert(root_object_hex(root).to_string());
            }
            (data, nodes)
        };

        let mut stats = GcStats::default();
        for key in self.blob.list(&format!("volumes/{vol}/data/"))? {
            let object_id = key.rsplit('/').next().unwrap_or_default();
            if live_data.contains(object_id) {
                continue;
            }
            self.blob.delete(&key)?;
            stats.data_objects_deleted += 1;
        }
        for key in self.blob.list(&format!("volumes/{vol}/maps/"))? {
            let node = key.rsplit('/').next().unwrap_or_default();
            if live_nodes.contains(object_id_hex(node)) {
                continue;
            }
            self.blob.delete(&key)?;
            stats.map_nodes_deleted += 1;
        }
        stats.data_objects_live = live_data.len();
        stats.map_nodes_live = live_nodes.len();
        tracing::info!(
            volume = %vol,
            data_objects_live = stats.data_objects_live,
            data_objects_deleted = stats.data_objects_deleted,
            map_nodes_live = stats.map_nodes_live,
            map_nodes_deleted = stats.map_nodes_deleted,
            "garbage collected"
        );
        Ok(stats)
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
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

    fn cache_allocated_bytes(&self) -> std::io::Result<u64> {
        use std::os::unix::fs::MetadataExt;
        Ok(self.cache.metadata()?.blocks().saturating_mul(512))
    }

    /// Space the current dirty set will need when it becomes an immutable
    /// pending pack. Counting it before the bytes are physically duplicated is
    /// what prevents dirty cache from consuming the last byte needed to create
    /// publisher input.
    fn unstaged_pack_reservation_bytes(&self) -> u64 {
        let st = self.state.lock().unwrap();
        let dirty: Vec<(u64, u64)> = st
            .dirty
            .iter()
            .enumerate()
            .filter(|(_, word)| **word != 0)
            .map(|(chunk, word)| (chunk as u64, *word))
            .collect();
        if dirty.is_empty() && st.discarded.is_empty() {
            return 0;
        }
        let mut discarded: Vec<u64> = st.discarded.iter().copied().collect();
        discarded.sort_unstable();
        let plans = plan_commit(&dirty, &st.map, &discarded);
        let (payload_bytes, ranges) = match self.cfg.durability {
            DurabilityMode::Strict => (
                plans
                    .iter()
                    .fold(0u64, |sum, plan| sum.saturating_add(plan.len() as u64)),
                0,
            ),
            DurabilityMode::Relaxed { .. } => {
                let mut bytes = 0u64;
                let mut ranges = 0usize;
                for plan in &plans {
                    let dirty_ranges = &st.dirty_ranges[plan.chunk_idx as usize];
                    bytes = bytes.saturating_add(
                        dirty_ranges
                            .iter()
                            .fold(0u64, |sum, range| sum.saturating_add(range.len() as u64)),
                    );
                    ranges = ranges.saturating_add(dirty_ranges.len());
                }
                (bytes, ranges)
            }
        };
        pack_reservation_upper(payload_bytes, plans.len(), ranges)
    }

    fn local_accounted_bytes(&self) -> std::io::Result<u64> {
        // Read state before staged to preserve the engine's state -> staged
        // lock order. `inflight_staging_bytes` covers the transition between
        // the two representations.
        let unstaged = self.unstaged_pack_reservation_bytes();
        let staged = self.staged.lock().unwrap().bytes;
        Ok(self
            .cache_allocated_bytes()?
            .saturating_add(staged)
            .saturating_add(unstaged)
            .saturating_add(self.inflight_staging_bytes.load(Ordering::Relaxed)))
    }

    /// Worst-case incremental cache allocation plus local-pack reservation for
    /// one Relaxed WRITE. Overlapping dirty ranges make this conservative, not
    /// unsafe; admission may stage a little early but can never strand a dirty
    /// cache with no room for its pack.
    fn write_admission_bytes(&self, offset: u64, len: usize) -> u64 {
        let first = offset / CHUNK_SIZE as u64;
        let last = (offset + len as u64 - 1) / CHUNK_SIZE as u64;
        let chunks = (last - first + 1) as usize;
        let st = self.state.lock().unwrap();
        let mut relaxed_payload = 0u64;
        // A write may straddle two filesystem allocation blocks. A fully
        // hydrated chunk has already allocated the cache range it overwrites.
        let mut cache_allocation: u64 = 8 << 10;
        let mut pos = offset;
        let end = offset + len as u64;
        while pos < end {
            let chunk_idx = pos / CHUNK_SIZE as u64;
            let in_chunk = pos % CHUNK_SIZE as u64;
            let span = (end - pos).min(CHUNK_SIZE as u64 - in_chunk);
            if !st.hydrated[chunk_idx as usize] {
                cache_allocation = cache_allocation.saturating_add(span);
            }
            relaxed_payload =
                relaxed_payload.saturating_add(if st.discarded.contains(&chunk_idx) {
                    CHUNK_SIZE as u64
                } else {
                    span
                });
            pos += span;
        }
        drop(st);
        let payload = match self.cfg.durability {
            DurabilityMode::Strict => (chunks as u64).saturating_mul(CHUNK_SIZE as u64),
            DurabilityMode::Relaxed { .. } => relaxed_payload,
        };
        cache_allocation.saturating_add(pack_reservation_upper(payload, chunks, chunks))
    }

    fn stage_before_write_pressure(&self, required_bytes: u64) -> Result<()> {
        if !self.has_unstaged_changes() {
            return Ok(());
        }
        if self.local_accounted_bytes()?.saturating_add(required_bytes) <= self.cfg.max_local_bytes
        {
            return Ok(());
        }
        // Relaxed turns this into a local-only implicit writeback barrier and
        // leaves publication to the background thread. Strict already defines
        // its barrier as remote, so pressure may synchronously publish there.
        self.flush()?;
        if matches!(self.cfg.durability, DurabilityMode::Relaxed { .. }) {
            self.kick_committer();
        }
        Ok(())
    }

    /// Make room below the per-volume physical quota by punching holes in the
    /// least-recently-used clean committed chunks. Dirty chunks and every chunk
    /// named by an unpublished pack are authoritative local state and are
    /// never eviction candidates.
    fn ensure_local_capacity(
        &self,
        additional_bytes: u64,
        protected: &HashSet<u64>,
    ) -> Result<std::sync::MutexGuard<'_, ()>> {
        if additional_bytes > self.cfg.max_local_bytes {
            return Err(EngineError::InvalidConfig(format!(
                "one local I/O requires {additional_bytes} reserved bytes, above the per-volume \
                 limit {}",
                self.cfg.max_local_bytes
            )));
        }
        let mut cache_space = self.cache_space.lock().unwrap();
        loop {
            if self.is_fenced() {
                return Err(EngineError::Fenced);
            }
            let (staged_bytes, pinned): (u64, HashSet<u64>) = {
                let staged = self.staged.lock().unwrap();
                (
                    staged.bytes,
                    staged
                        .packs
                        .iter()
                        .flat_map(|pack| pack.chunks.iter().copied())
                        .collect(),
                )
            };
            let allocated = self
                .cache_allocated_bytes()?
                .saturating_add(staged_bytes)
                .saturating_add(self.unstaged_pack_reservation_bytes())
                .saturating_add(self.inflight_staging_bytes.load(Ordering::Relaxed));
            if allocated.saturating_add(additional_bytes) <= self.cfg.max_local_bytes {
                return Ok(cache_space);
            }

            let candidate = {
                let st = self.state.lock().unwrap();
                (0..self.chunk_count)
                    .filter(|chunk| {
                        let index = *chunk as usize;
                        st.cache_present[index]
                            && st.dirty[index] == 0
                            && !st.discarded.contains(chunk)
                            && !st.freezing.contains(chunk)
                            && !pinned.contains(chunk)
                            && !protected.contains(chunk)
                    })
                    .min_by_key(|chunk| st.last_access[*chunk as usize])
            };
            if let Some(chunk) = candidate {
                let _gate = self.io_gate.write().unwrap();
                let mut st = self.state.lock().unwrap();
                let still_pinned = {
                    let staged = self.staged.lock().unwrap();
                    staged.packs.iter().any(|pack| pack.chunks.contains(&chunk))
                };
                let index = chunk as usize;
                if st.cache_present[index]
                    && st.dirty[index] == 0
                    && !st.discarded.contains(&chunk)
                    && !st.freezing.contains(&chunk)
                    && !still_pinned
                    && !protected.contains(&chunk)
                {
                    punch_hole(&self.cache, chunk * CHUNK_SIZE as u64, CHUNK_SIZE as u64)?;
                    st.hydrated[index] = false;
                    st.cache_present[index] = false;
                    self.evicted_cache_chunks.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }

            // Only authoritative local state remains. Do not invoke DB/S3 on
            // this caller: park until the publisher advances the remote
            // watermark and makes a chunk evictable.
            self.kick_committer();
            self.backpressure_waiters.fetch_add(1, Ordering::Relaxed);
            let (guard, _timeout) = self
                .local_space
                .wait_timeout(cache_space, Duration::from_millis(250))
                .unwrap();
            self.backpressure_waiters.fetch_sub(1, Ordering::Relaxed);
            cache_space = guard;
        }
    }

    /// TRIM / WRITE_ZEROES: V1 writes literal zeros (spec §7).
    pub fn write_zeroes(&self, offset: u64, len: u64) -> Result<()> {
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

    /// Admission for a new local durability barrier. The wait is deliberately
    /// local-state-only: the background committer owns all DB/S3 calls. A
    /// prolonged outage therefore shows up as queue age and backpressure, not
    /// as a remote error injected into ext4.
    fn wait_for_staging_space(&self) -> Result<()> {
        let mut staged = self.staged.lock().unwrap();
        while staged.packs.len() >= self.cfg.max_staged_packs
            || staged.bytes >= self.cfg.max_staged_bytes
        {
            if self.is_fenced() {
                return Err(EngineError::Fenced);
            }
            self.kick_committer();
            self.backpressure_waiters.fetch_add(1, Ordering::Relaxed);
            let (guard, _timeout) = self
                .staged_space
                .wait_timeout(staged, Duration::from_millis(250))
                .unwrap();
            self.backpressure_waiters.fetch_sub(1, Ordering::Relaxed);
            staged = guard;
        }
        Ok(())
    }

    fn wait_for_staging_space_for(&self, required_bytes: u64) -> Result<()> {
        let mut staged = self.staged.lock().unwrap();
        while staged.packs.len() >= self.cfg.max_staged_packs
            || (!staged.packs.is_empty()
                && staged.bytes.saturating_add(required_bytes) > self.cfg.max_staged_bytes)
        {
            if self.is_fenced() {
                return Err(EngineError::Fenced);
            }
            self.kick_committer();
            self.backpressure_waiters.fetch_add(1, Ordering::Relaxed);
            let (guard, _timeout) = self
                .staged_space
                .wait_timeout(staged, Duration::from_millis(250))
                .unwrap();
            self.backpressure_waiters.fetch_sub(1, Ordering::Relaxed);
            staged = guard;
        }
        Ok(())
    }

    fn kick_committer(&self) {
        let (lock, cv) = &*self.committer_signal;
        lock.lock().unwrap().kick = true;
        cv.notify_all();
    }

    /// Freeze the dirty set and write it as a pending pack on local disk.
    /// No-op on a clean volume. Caller holds `flush_lock`.
    fn stage_pack(&self) -> Result<()> {
        // ---- freeze the barrier ----
        //
        // Everything in here blocks every Guest read and write on this volume, so
        // it does the minimum a point-in-time image requires: pick the dirty set
        // and copy the bytes this commit will publish. Hashing is pure computation
        // over a private copy, so it happens after the barrier is released.
        //
        // A commit publishes only the dirty 64 KiB pages of each chunk (spec
        // §6.2). The pages it does not carry are unchanged since the last commit
        // and are therefore already immutable in the object store, so leaving
        // them out cannot make the image inconsistent — which is what makes the
        // barrier proportional to what the Guest actually wrote instead of to the
        // 4 MiB chunks it touched.
        let relaxed = matches!(self.cfg.durability, DurabilityMode::Relaxed { .. });
        let (plans, frozen_ranges, base_generation, payload) = {
            let _barrier = self.io_gate.write().unwrap();
            let mut st = self.state.lock().unwrap();
            let dirty: Vec<(u64, u64)> = (0..self.chunk_count)
                .filter(|&c| st.dirty[c as usize] != 0)
                .map(|c| (c, st.dirty[c as usize]))
                .collect();
            let mut discarded: Vec<u64> = st.discarded.iter().copied().collect();
            discarded.sort_unstable();
            if dirty.is_empty() && discarded.is_empty() {
                return Ok(());
            }
            // Plans are made against the committed map even when packs are
            // staged ahead of this one. A stale view can only misjudge a
            // chunk's delta-chain length (a chunk written across many staged
            // packs grows past MAX_DELTA_LAYERS until its next base rewrite);
            // it cannot affect correctness, because deltas apply in pack
            // order at publish either way.
            let base_map = st.map.clone();
            let base_generation = self.staged.lock().unwrap().next_base;
            let plans = plan_commit(&dirty, &base_map, &discarded);
            let frozen_ranges: Vec<Vec<DirtyByteRange>> = plans
                .iter()
                .map(|plan| st.dirty_ranges[plan.chunk_idx as usize].clone())
                .collect();
            // Copy before mutating the dirty set. A local cache read error must
            // leave the writes available for a retry in this process.
            let payload = if relaxed {
                copy_dirty_ranges(&self.cache, &plans, &frozen_ranges)?
            } else {
                let bytes: usize = plans.iter().map(|p| p.len()).sum();
                // One allocation for the whole pack: `vec![0u8; n]` for a large
                // `n` comes from fresh zero pages, while an allocation per chunk
                // charged a page-fault storm to the barrier.
                let mut payload = vec![0u8; bytes];
                copy_planned_pages(&self.cache, &plans, &mut payload)?;
                payload
            };
            if relaxed {
                st.freezing
                    .extend(plans.iter().map(|plan| plan.chunk_idx));
            }
            let range_count = frozen_ranges.iter().map(Vec::len).sum();
            self.inflight_staging_bytes.store(
                pack_reservation_upper(payload.len() as u64, plans.len(), range_count),
                Ordering::Relaxed,
            );
            for &(c, _) in &dirty {
                st.dirty[c as usize] = 0;
                st.dirty_ranges[c as usize].clear();
            }
            st.discarded.clear();
            (plans, frozen_ranges, base_generation, payload)
        };

        // Barrier released: hash the frozen bytes and describe the pack.
        let entries = if relaxed {
            describe_overlay_pack(&plans, &frozen_ranges, &payload)
        } else {
            describe_pack(&plans, &payload)
        };

        // Commit size is the single most useful number when a Guest workload
        // stalls on FLUSH: the barrier above is held for as long as it takes to
        // copy the published bytes, and the commit then writes them twice more
        // (pack file, then objects).
        tracing::info!(
            volume = %self.cfg.volume_id,
            base_generation,
            dirty_chunks = plans.len(),
            base_rewrites = plans.iter().filter(|p| p.is_base()).count(),
            pack_bytes = payload.len(),
            "commit barrier frozen"
        );
        let txn = uuid::Uuid::new_v4().simple().to_string();
        let header = PackHeader {
            txn: txn.clone(),
            volume_id: self.cfg.volume_id.clone(),
            base_generation,
            lease_epoch: self.epoch,
            entries,
        };
        let projected_bytes = format::encode_pack(&header, &payload).len() as u64;
        self.inflight_staging_bytes
            .store(projected_bytes, Ordering::Relaxed);
        let protected: HashSet<u64> = plans.iter().map(|plan| plan.chunk_idx).collect();
        if let Err(error) = self.wait_for_staging_space_for(projected_bytes) {
            self.restore_frozen_plans(&plans, &frozen_ranges);
            self.inflight_staging_bytes.store(0, Ordering::Relaxed);
            self.local_space.notify_all();
            return Err(error);
        }
        // The exact projected pack is already represented by
        // `inflight_staging_bytes`; adding it again would double count.
        let _cache_space = match self.ensure_local_capacity(0, &protected) {
            Ok(space) => space,
            Err(error) => {
                self.restore_frozen_plans(&plans, &frozen_ranges);
                self.inflight_staging_bytes.store(0, Ordering::Relaxed);
                self.local_space.notify_all();
                return Err(error);
            }
        };
        let encoded_bytes = match self.write_pack_file(&header, &payload) {
            Ok(bytes) => bytes,
            Err(error) => {
                // The volatile dirty set was moved out under the barrier, but
                // no durable pack exists. Put it back before surfacing the local
                // I/O error so a retry in the same process cannot lose writes.
                // Promoting a planned base to all-dirty pages is conservative.
                self.restore_frozen_plans(&plans, &frozen_ranges);
                self.inflight_staging_bytes.store(0, Ordering::Relaxed);
                self.local_space.notify_all();
                return Err(error);
            }
        };
        {
            let mut staged = self.staged.lock().unwrap();
            staged.packs.push_back(StagedPack {
                txn: txn.clone(),
                path: self.pack_path(base_generation, &txn),
                encoded_bytes,
                staged_at_unix_ms: unix_time_ms(),
                chunks: plans.iter().map(|plan| plan.chunk_idx).collect(),
            });
            staged.bytes = staged.bytes.saturating_add(encoded_bytes);
            staged.next_base += 1;
            let backlog = staged.packs.len();
            drop(staged);
            self.unfreeze_plans(&plans);
            self.inflight_staging_bytes.store(0, Ordering::Relaxed);
            self.local_space.notify_all();
            if backlog > EAGER_DRAIN_WATERMARK {
                // A burst is forming: drain continuously instead of letting
                // the queue climb toward the backpressure cap on the timer.
                self.kick_committer();
            }
        }
        crashpoint::maybe_crash(crashpoint::AFTER_PACK);
        Ok(())
    }

    fn restore_frozen_plans(&self, plans: &[ChunkPlan], frozen_ranges: &[Vec<DirtyByteRange>]) {
        let mut st = self.state.lock().unwrap();
        for (plan, ranges) in plans.iter().zip(frozen_ranges) {
            st.freezing.remove(&plan.chunk_idx);
            if plan.page_mask == 0 {
                st.discarded.insert(plan.chunk_idx);
            } else {
                st.dirty[plan.chunk_idx as usize] |= plan.page_mask;
                for range in ranges {
                    merge_dirty_range(&mut st.dirty_ranges[plan.chunk_idx as usize], *range);
                }
            }
        }
        drop(st);
        self.hydration_cv.notify_all();
    }

    fn unfreeze_plans(&self, plans: &[ChunkPlan]) {
        let mut st = self.state.lock().unwrap();
        for plan in plans {
            st.freezing.remove(&plan.chunk_idx);
        }
        drop(st);
        self.hydration_cv.notify_all();
    }

    /// Publish every staged pack, oldest first; returns the committed
    /// generation once the queue is empty.
    ///
    /// On a fencing failure the engine fails closed. On a transient store
    /// failure the queue keeps the remaining packs — volatile dirty bits for
    /// their frozen sets were cleared, but the pack files and the persistent
    /// bitmap survive, so neither a retry nor a restart can lose the data.
    pub fn drain_staged(&self) -> Result<i64> {
        loop {
            if self.drain_one_batch()? {
                return Ok(self.generation());
            }
        }
    }

    /// Publish one batch under one `publish_lock` hold; returns true once the
    /// queue is empty. The lock is released between batches so a parked FLUSH
    /// or a GC scan never waits out an entire multi-batch drain.
    fn drain_one_batch(&self) -> Result<bool> {
        let _publish = self.publish_lock.lock().unwrap();
        // Batch the queue: one upload wave, one CAS, however many packs are
        // waiting — bounded by bytes so a run of dense commits does not pull
        // gigabytes of payload into memory at once.
        let snapshot: Vec<(String, PathBuf)> = {
            let staged = self.staged.lock().unwrap();
            staged
                .packs
                .iter()
                .map(|p| (p.txn.clone(), p.path.clone()))
                .collect()
        };
        if snapshot.is_empty() {
            return Ok(true);
        }
        let mut decoded: Vec<(PackHeader, Vec<u8>)> = Vec::new();
        let mut batched_bytes = 0usize;
        for (txn, path) in &snapshot {
            let bytes = fs::read(path)?;
            batched_bytes += bytes.len();
            let (header, payload) = format::decode_pack(&bytes)
                .map_err(|e| EngineError::Corrupt(format!("staged pack {txn}: {e}")))?;
            decoded.push((header, payload));
            if batched_bytes >= MAX_BATCH_BYTES {
                break;
            }
        }
        let (base_map, base_leaves) = {
            let st = self.state.lock().unwrap();
            (st.map.clone(), st.leaf_refs.clone())
        };
        let packs: Vec<(&PackHeader, &[u8])> = decoded
            .iter()
            .map(|(header, payload)| (header, payload.as_slice()))
            .collect();
        match self.commit_pack_batch(&packs, base_map, base_leaves) {
            Ok(_) => {
                for (header, _) in &decoded {
                    if let Err(error) = self.finish_committed_pack(header) {
                        // The remote CAS already advanced. Retrying this pack as
                        // an unpublished generation would manufacture a CAS
                        // conflict and self-fence a healthy writer. Local
                        // cleanup is conservative and recoverable: a surviving
                        // pack is recognized as superseded on the next attach,
                        // and dirty bitmap bits may only cause a duplicate
                        // future delta.
                        tracing::warn!(
                            volume = %self.cfg.volume_id,
                            txn = %header.txn,
                            "remote commit succeeded but local pack cleanup failed: {error}"
                        );
                    }
                }
                let mut staged = self.staged.lock().unwrap();
                for _ in 0..decoded.len() {
                    staged.packs.pop_front();
                }
                staged.bytes = staged.packs.iter().map(|pack| pack.encoded_bytes).sum();
                drop(staged);
                *self.last_publish_error.lock().unwrap() = None;
                // Room just opened up: wake any FLUSH parked on the cap.
                self.staged_space.notify_all();
                self.local_space.notify_all();
                Ok(false)
            }
            Err(e) => {
                *self.last_publish_error.lock().unwrap() = Some(e.to_string());
                if matches!(e, EngineError::Meta(MetaError::CasConflict { .. }))
                    || matches!(e, EngineError::Meta(MetaError::Fenced))
                {
                    self.fenced.store(true, Ordering::SeqCst);
                    self.staged_space.notify_all();
                    self.local_space.notify_all();
                }
                Err(e)
            }
        }
    }

    // -----------------------------------------------------------------
    // Commit path (shared by flush and recovery)
    // -----------------------------------------------------------------

    /// Object id for one pack entry. A commit publishes at most one object per
    /// chunk, so the txn and chunk index identify it; the suffix keeps a delta
    /// from ever colliding with a base written for the same chunk in a replay.
    fn object_id(txn: &str, entry: &PackEntry) -> String {
        if entry.is_base() {
            format!("{txn}-c{}", entry.chunk_idx)
        } else {
            format!("{txn}-c{}-d", entry.chunk_idx)
        }
    }

    /// Publish a map as the volume's committed state: re-encode the leaves the
    /// change touched, write the root and the commit record, then CAS the head
    /// (spec §6 steps 3-5).
    ///
    /// Shared by the commit path and by provisioning from a shared base image,
    /// which differ only in where the chunk refs came from — everything about
    /// durability, fencing and the CAS is the same, and must stay that way.
    #[allow(clippy::too_many_arguments)]
    fn publish_map(
        &self,
        txn: &str,
        base_generation: i64,
        new_generation: i64,
        lease_epoch: i64,
        new_map: &[ChunkRef],
        new_leaves: &mut [LeafRef],
        chunks: &[u64],
    ) -> Result<i64> {
        let vol = &self.cfg.volume_id;
        let mut touched: Vec<u64> = chunks.iter().map(|c| c / CHUNKS_PER_LEAF as u64).collect();
        touched.sort_unstable();
        touched.dedup();
        for leaf_idx in touched {
            let first = leaf_idx * CHUNKS_PER_LEAF as u64;
            let end = (first + CHUNKS_PER_LEAF as u64).min(self.chunk_count);
            let slice = &new_map[first as usize..end as usize];
            if slice.iter().all(|r| r.is_hole()) {
                new_leaves[leaf_idx as usize] = LeafRef::Empty;
                continue;
            }
            let encoded = format::encode_leaf(first, slice);
            let hash = format::sha256(&encoded);
            let object_id = format!("{}.node", hex::encode(hash));
            self.blob
                .put_immutable(&chunk::keys::map_node(vol, &hex::encode(hash)), &encoded)?;
            new_leaves[leaf_idx as usize] = LeafRef::Present { hash, object_id };
        }

        let root_encoded = format::encode_root(self.size, new_leaves);
        let root_hash = format::sha256(&root_encoded);
        let root_hex = hex::encode(root_hash);
        let root_object_id = format!("{root_hex}.node");
        self.blob
            .put_immutable(&chunk::keys::map_node(vol, &root_hex), &root_encoded)?;
        let record = serde_json::json!({
            "txn": txn,
            "generation": new_generation,
            "root_hash": root_hex,
            "lease_epoch": lease_epoch,
            "chunks": chunks,
        });
        self.blob.put_immutable(
            &chunk::keys::commit_record(vol, new_generation, txn),
            record.to_string().as_bytes(),
        )?;
        crashpoint::maybe_crash(crashpoint::BEFORE_CAS);

        let new_gen = self.meta.cas_head(
            vol,
            base_generation,
            new_generation,
            root_hash,
            &root_object_id,
            &self.cfg.attachment_id,
            self.epoch,
        )?;
        crashpoint::maybe_crash(crashpoint::AFTER_CAS);
        Ok(new_gen)
    }

    /// Upload one object per pack entry, concurrently.
    ///
    /// The objects are independent: distinct keys, immutable content, no ordering
    /// among them. The only ordering the protocol needs is that all of them are
    /// durable before a map node references them, and the join at the end of this
    /// function is exactly that boundary — `AFTER_DATA_UPLOAD` still means what it
    /// meant, so the crash matrix is unaffected.
    ///
    /// Serially this cost one network round trip per object. Measured on S3, a
    /// 48-chunk commit spent about 1.6 s of its 1.7 s waiting for 48 sequential
    /// PUTs of 64 KiB each, which is why publishing 64x fewer bytes only bought
    /// 2.9x (see experiments/vhost-user-blk-frontend-20260726).
    fn upload_batch(&self, packs: &[(&PackHeader, &[u8])]) -> Result<()> {
        let vol = &self.cfg.volume_id;
        let items: Vec<(String, &[u8])> = packs
            .iter()
            .flat_map(|(header, payload)| {
                header.entries.iter().filter(|e| !e.is_discard()).map(|e| {
                    let at = e.payload_offset as usize;
                    let bytes = &payload[at..at + e.len as usize];
                    let object_id = Self::object_id(&header.txn, e);
                    (chunk::keys::data(vol, &object_id), bytes)
                })
            })
            .collect();

        let put = |item: &(String, &[u8])| -> Result<()> {
            self.blob.put_immutable(&item.0, item.1)?;
            Ok(())
        };

        let workers = upload_workers(items.len());
        if workers <= 1 {
            for item in &items {
                put(item)?;
            }
            return Ok(());
        }

        // Work-stealing over one shared cursor rather than a static split: object
        // sizes differ (a base is 4 MiB, a delta can be one 64 KiB page), so a
        // fixed slice per worker would leave some idle while others upload bases.
        let next = std::sync::atomic::AtomicUsize::new(0);
        let failure: Mutex<Option<EngineError>> = Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    if failure.lock().unwrap().is_some() {
                        return;
                    }
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else {
                        return;
                    };
                    if let Err(error) = put(item) {
                        let mut slot = failure.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(error);
                        }
                        return;
                    }
                });
            }
        });
        match failure.into_inner().unwrap() {
            // The pack files stay on disk, so recovery replays every object
            // including any that did land before the failure.
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn commit_pack(
        &self,
        header: &PackHeader,
        payload: &[u8],
        base_map: Vec<ChunkRef>,
        base_leaves: Vec<LeafRef>,
    ) -> Result<i64> {
        self.commit_pack_batch(&[(header, payload)], base_map, base_leaves)
    }

    /// Commit a chain of staged packs as ONE published step: every pack's
    /// objects go up in a single concurrent wave, the map applies the packs in
    /// chain order, and a single CAS advances the head by the number of packs.
    /// With one pack this is exactly the old per-pack commit.
    ///
    /// Only the final generation gets a commit record. On a crash after the
    /// CAS the batch's earlier pack files replay as "superseded lineage" and
    /// are discarded — correct, because their content is already in the
    /// committed map. On a crash before it, recovery replays them one by one
    /// through this same path, and writes their records then. Records are NOT
    /// pre-uploaded for intermediate packs on purpose: a pre-CAS crash would
    /// replay per pack with a real root hash, and the differing bytes would
    /// trip `put_immutable`'s immutability check on the same record key.
    fn commit_pack_batch(
        &self,
        packs: &[(&PackHeader, &[u8])],
        base_map: Vec<ChunkRef>,
        base_leaves: Vec<LeafRef>,
    ) -> Result<i64> {
        let materialized = if packs
            .iter()
            .any(|(header, _)| header.entries.iter().any(PackEntry::is_byte_overlay))
        {
            Some(self.materialize_overlay_batch(packs, &base_map)?)
        } else {
            None
        };
        let effective: Vec<(&PackHeader, &[u8])> = match &materialized {
            Some(packs) => packs
                .iter()
                .map(|(header, payload)| (header, payload.as_slice()))
                .collect(),
            None => packs.to_vec(),
        };
        let packs = effective.as_slice();
        let first = packs.first().expect("commit batch must not be empty").0;
        let last = packs.last().expect("checked").0;
        let base_generation = first.base_generation;

        // 1. Data objects for the whole batch (idempotent keys from the txns).
        self.upload_batch(packs)?;
        crashpoint::maybe_crash(crashpoint::AFTER_DATA_UPLOAD);

        // 2. Apply the packs to the map in chain order.
        let mut new_map = base_map;
        let mut chunks: Vec<u64> = Vec::new();
        for (header, _) in packs {
            Self::apply_pack_entries(&mut new_map, header)?;
            chunks.extend(header.entries.iter().map(|e| e.chunk_idx));
        }
        chunks.sort_unstable();
        chunks.dedup();

        // 3-5. Map, root, commit record, CAS jumping one step per pack.
        let mut new_leaves = base_leaves;
        let new_gen = self.publish_map(
            &last.txn,
            base_generation,
            base_generation + packs.len() as i64,
            last.lease_epoch,
            &new_map,
            &mut new_leaves,
            &chunks,
        )?;

        // 6. Swap in the committed map.
        {
            let mut st = self.state.lock().unwrap();
            st.map = new_map;
            st.leaf_refs = new_leaves;
            st.generation = new_gen;
            // Publication materializes cold Relaxed overlays in private publisher
            // memory, not in `cache.data`. Preserve each chunk's existing cache
            // completeness instead of promoting it merely because its remote map
            // advanced; the next read will hydrate the new map plus any newer
            // local overlays. Strict writes were already hydrated before write.
        }
        Ok(new_gen)
    }

    /// Turn exact Guest byte overlays into the complete immutable pages used by
    /// the remote ChunkStore format. Every GET and hash in this function runs
    /// only on the publisher thread; the Guest WRITE/FLUSH path has already
    /// acknowledged the local pack.
    fn materialize_overlay_batch(
        &self,
        packs: &[(&PackHeader, &[u8])],
        base_map: &[ChunkRef],
    ) -> Result<Vec<(PackHeader, Vec<u8>)>> {
        let page_bytes = cats_api::chunk::DIRTY_PAGE_SIZE as usize;
        let mut working_map = base_map.to_vec();
        let mut images: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut materialized = Vec::with_capacity(packs.len());

        for (header, payload) in packs {
            let mut output = Vec::new();
            let mut entries = Vec::with_capacity(header.entries.len());
            for entry in &header.entries {
                if entry.is_discard() {
                    images.insert(entry.chunk_idx, vec![0u8; CHUNK_SIZE as usize]);
                    entries.push(PackEntry {
                        chunk_idx: entry.chunk_idx,
                        payload_offset: output.len() as u64,
                        len: 0,
                        sha256_hex: hex::encode(format::sha256(&[])),
                        page_mask: 0,
                        byte_ranges: Vec::new(),
                    });
                    continue;
                }

                if let std::collections::hash_map::Entry::Vacant(slot) =
                    images.entry(entry.chunk_idx)
                {
                    let image = self.fetch_chunk_image(&working_map[entry.chunk_idx as usize])?;
                    slot.insert(image);
                }
                let image = images.get_mut(&entry.chunk_idx).expect("inserted");
                apply_local_entry(image, entry, payload)?;

                let start = output.len();
                if entry.is_base() {
                    output.extend_from_slice(image);
                } else {
                    for page in 0..cats_api::chunk::PAGES_PER_CHUNK {
                        if entry.page_mask & (1u64 << page) == 0 {
                            continue;
                        }
                        let at = page as usize * page_bytes;
                        output.extend_from_slice(&image[at..at + page_bytes]);
                    }
                }
                let bytes = &output[start..];
                entries.push(PackEntry {
                    chunk_idx: entry.chunk_idx,
                    payload_offset: start as u64,
                    len: bytes.len() as u32,
                    sha256_hex: hex::encode(format::sha256(bytes)),
                    page_mask: entry.page_mask,
                    byte_ranges: Vec::new(),
                });
            }
            let materialized_header = PackHeader {
                txn: header.txn.clone(),
                volume_id: header.volume_id.clone(),
                base_generation: header.base_generation,
                lease_epoch: header.lease_epoch,
                entries,
            };
            Self::apply_pack_entries(&mut working_map, &materialized_header)?;
            materialized.push((materialized_header, output));
        }
        Ok(materialized)
    }

    /// Apply one pack's entries onto a map: a base entry replaces the chunk's
    /// reference outright, a delta entry appends a layer to whatever the chunk
    /// already had, a discard turns it into a hole (GC removes the orphaned
    /// objects, and a cold read of the chunk then costs nothing at all).
    fn apply_pack_entries(map: &mut [ChunkRef], header: &PackHeader) -> Result<()> {
        for e in &header.entries {
            let slot = &mut map[e.chunk_idx as usize];
            if e.is_discard() {
                *slot = ChunkRef::Hole;
                continue;
            }
            let sha: [u8; 32] = hex::decode(&e.sha256_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| EngineError::Corrupt("bad sha in pack".into()))?;
            let object_id = Self::object_id(&header.txn, e);
            *slot = if e.is_base() {
                ChunkRef::Base(format::BaseRef::local(object_id, e.len, sha))
            } else {
                slot.clone().with_delta(format::DeltaRef {
                    object_id,
                    page_mask: e.page_mask,
                    len: e.len,
                    sha256: sha,
                })
            };
        }
        Ok(())
    }

    /// Post-commit cleanup: sync the persistent bitmap with the volatile
    /// truth for the frozen chunks and drop the pack.
    fn finish_committed_pack(&self, header: &PackHeader) -> Result<()> {
        {
            let st = self.state.lock().unwrap();
            let bitmap = self.bitmap.lock().unwrap();
            for e in &header.entries {
                let word = st.dirty[e.chunk_idx as usize];
                bitmap.write_all_at(&word.to_le_bytes(), BITMAP_HEADER_LEN + e.chunk_idx * 8)?;
            }
            bitmap.sync_data()?;
        }
        let path = self.pack_path(header.base_generation, &header.txn);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// The base-generation prefix makes lexicographic order equal generation
    /// order, which recovery relies on to replay a staged chain (relaxed mode
    /// leaves several pending packs behind; spec §6.1 replays them sorted).
    fn pack_path(&self, base_generation: i64, txn: &str) -> PathBuf {
        self.cfg
            .data_dir
            .join("pending")
            .join(format!("{base_generation:020}-{txn}.pack"))
    }

    fn write_pack_file(&self, header: &PackHeader, payload: &[u8]) -> Result<u64> {
        let encoded = format::encode_pack(header, payload);
        let encoded_bytes = encoded.len() as u64;
        let dir = self.cfg.data_dir.join("pending");
        let tmp = dir.join(format!(".tmp-{}", header.txn));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&encoded)?;
            f.sync_data()?;
        }
        fs::rename(&tmp, self.pack_path(header.base_generation, &header.txn))?;
        File::open(&dir)?.sync_all()?;
        Ok(encoded_bytes)
    }

    // -----------------------------------------------------------------
    // Recovery (spec §6.1)
    // -----------------------------------------------------------------

    fn recover_pending_packs(&self) -> Result<()> {
        let dir = self.cfg.data_dir.join("pending");
        let mut packs = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name.ends_with(".pack") {
                packs.push(path);
            } else if name.starts_with(".tmp-") {
                // Torn pack write: never renamed, safe to drop.
                let _ = fs::remove_file(&path);
            }
        }
        packs.sort();

        if matches!(self.cfg.durability, DurabilityMode::Relaxed { .. }) {
            return self.recover_relaxed_queue(packs);
        }

        for path in packs {
            let bytes = fs::read(&path)?;
            let (header, payload) = match format::decode_pack(&bytes) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("discarding undecodable pack {}: {e}", path.display());
                    let _ = fs::remove_file(&path);
                    continue;
                }
            };
            if header.volume_id != self.cfg.volume_id {
                return Err(EngineError::Corrupt("pack volume id mismatch".into()));
            }
            let head = self.meta.load_head(&self.cfg.volume_id)?;
            let record_key = chunk::keys::commit_record(
                &self.cfg.volume_id,
                header.base_generation + 1,
                &header.txn,
            );
            if self.blob.exists(&record_key)? && head.generation > header.base_generation {
                // CAS happened before the crash; only clean up. The dirty
                // bits stay set conservatively (we cannot tell post-barrier
                // writes apart anymore), which at worst re-commits the chunk.
                tracing::info!(txn = %header.txn, "pack already committed; cleaning up");
                let _ = fs::remove_file(&path);
                continue;
            }
            if head.generation != header.base_generation {
                tracing::warn!(
                    txn = %header.txn,
                    head_gen = head.generation,
                    pack_base = header.base_generation,
                    "discarding pack from a superseded lineage"
                );
                let _ = fs::remove_file(&path);
                continue;
            }
            // Replay: object/record bytes keep the pack's original epoch so
            // the keys and contents stay byte-identical (idempotent);
            // the CAS itself always runs under the *current* lease epoch.
            tracing::info!(txn = %header.txn, "replaying pending pack");
            let (base_map, base_leaves) = {
                let st = self.state.lock().unwrap();
                (st.map.clone(), st.leaf_refs.clone())
            };
            match self.commit_pack(&header, &payload, base_map, base_leaves) {
                Ok(_) => {
                    self.finish_committed_pack(&header)?;
                    // Reload so later packs see the new base.
                    self.load_committed_map()?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Rebuild a relaxed local durability queue without issuing a remote write.
    ///
    /// A blockd restart on the same Host must not turn an S3/DB outage into an
    /// attach failure after the committed map has been loaded. Packs below the
    /// remote generation were already included by a successful (possibly
    /// batched) CAS and are local cleanup residue. Packs from the remote
    /// generation onward are the acknowledged local chain and must be kept in
    /// exact generation order.
    fn recover_relaxed_queue(&self, packs: Vec<PathBuf>) -> Result<()> {
        let committed = self.generation();
        let mut expected = committed;
        let mut recovered = std::collections::VecDeque::new();
        let mut recovered_bytes = 0u64;

        for path in packs {
            let bytes = fs::read(&path)?;
            let (header, _payload) = format::decode_pack(&bytes)
                .map_err(|error| EngineError::Corrupt(format!("staged pack: {error}")))?;
            if header.volume_id != self.cfg.volume_id {
                return Err(EngineError::Corrupt("pack volume id mismatch".into()));
            }
            if header.base_generation < committed {
                // A prior batch CAS included this generation. It is safe to
                // remove the stale local file; the committed map is the truth.
                let _ = fs::remove_file(&path);
                continue;
            }
            if header.base_generation != expected {
                return Err(EngineError::Corrupt(format!(
                    "relaxed pack chain has a gap: expected base generation \
                     {expected}, found {}",
                    header.base_generation
                )));
            }

            let metadata = fs::metadata(&path)?;
            let encoded_bytes = metadata.len();
            let staged_at_unix_ms = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or_else(unix_time_ms);
            let chunks = header.entries.iter().map(|entry| entry.chunk_idx).collect();
            recovered.push_back(StagedPack {
                txn: header.txn,
                path,
                encoded_bytes,
                staged_at_unix_ms,
                chunks,
            });
            recovered_bytes = recovered_bytes.saturating_add(encoded_bytes);
            expected += 1;
        }

        let mut staged = self.staged.lock().unwrap();
        staged.packs = recovered;
        staged.bytes = recovered_bytes;
        staged.next_base = expected;
        drop(staged);

        // The persistent page bitmap cannot distinguish bytes already captured
        // by a relaxed pack from post-barrier, unacknowledged writes. The packs
        // are the local durability oracle after a process crash, so discard the
        // latter conservatively and rebuild cache completeness from the remote
        // map plus those exact overlays on demand.
        {
            let mut st = self.state.lock().unwrap();
            st.dirty.fill(0);
            st.dirty_ranges.iter_mut().for_each(Vec::clear);
            st.discarded.clear();
            st.hydrated.fill(false);
            st.freezing.clear();
        }
        {
            let bitmap = self.bitmap.lock().unwrap();
            for chunk in 0..self.chunk_count {
                bitmap.write_all_at(&0u64.to_le_bytes(), BITMAP_HEADER_LEN + chunk * 8)?;
            }
            bitmap.sync_data()?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Cache hydration + dirty tracking
    // -----------------------------------------------------------------

    /// Ensure the cache holds the full content of `chunk_idx` (committed
    /// base hydrated, or the chunk is a hole / locally dirty).
    /// Make every chunk in `first..=last` present in the local cache.
    ///
    /// Misses are fetched concurrently. Serially, a cold read cost one round trip
    /// per chunk: 64 MiB off S3 ran at 73 MiB/s on a 12.5 Gbps instance because
    /// nothing overlapped. The chunks are independent objects, and
    /// `ensure_cache_complete` already coordinates concurrent hydration of the
    /// same chunk, so the only thing missing was issuing them together.
    ///
    /// The common case is that everything is already cached, so the fast path
    /// takes the state lock once and spawns nothing.
    fn hydrate_range(&self, first: u64, last: u64) -> Result<()> {
        let misses: Vec<u64> = {
            let st = self.state.lock().unwrap();
            (first..=last)
                .filter(|c| !st.hydrated[*c as usize])
                .collect()
        };
        match misses.len() {
            0 => return Ok(()),
            1 => return self.ensure_cache_complete(misses[0]),
            _ => {}
        }

        let next = std::sync::atomic::AtomicUsize::new(0);
        let failure: Mutex<Option<EngineError>> = Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..fetch_workers(misses.len()) {
                scope.spawn(|| loop {
                    if failure.lock().unwrap().is_some() {
                        return;
                    }
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(chunk_idx) = misses.get(index) else {
                        return;
                    };
                    if let Err(error) = self.ensure_cache_complete(*chunk_idx) {
                        let mut slot = failure.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(error);
                        }
                        return;
                    }
                });
            }
        });
        match failure.into_inner().unwrap() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn ensure_cache_complete(&self, chunk_idx: u64) -> Result<()> {
        loop {
            let chunk_ref = {
                let mut st = self.state.lock().unwrap();
                if st.hydrated[chunk_idx as usize] {
                    return Ok(());
                }
                if st.hydrating.contains(&chunk_idx) || st.freezing.contains(&chunk_idx) {
                    let _unused = self
                        .hydration_cv
                        .wait(st)
                        .map_err(|_| EngineError::Corrupt("poisoned lock".into()))?;
                    continue;
                }
                let chunk_ref = st.map[chunk_idx as usize].clone();
                if chunk_ref.is_hole() {
                    // Sparse cache file already reads as zeros.
                    st.hydrated[chunk_idx as usize] = true;
                    return Ok(());
                }
                st.hydrating.insert(chunk_idx);
                chunk_ref
            };
            let result = if matches!(self.cfg.durability, DurabilityMode::Relaxed { .. }) {
                self.hydrate_chunk_with_local_state(chunk_idx)
            } else {
                self.hydrate_chunk(chunk_idx, &chunk_ref)
            };
            let mut st = self.state.lock().unwrap();
            st.hydrating.remove(&chunk_idx);
            if result.is_ok() {
                st.hydrated[chunk_idx as usize] = true;
                st.cache_present[chunk_idx as usize] = true;
                st.access_clock = st.access_clock.saturating_add(1);
                st.last_access[chunk_idx as usize] = st.access_clock;
            }
            self.hydration_cv.notify_all();
            return result;
        }
    }

    /// Fetch one object and check it against the reference that named it.
    ///
    /// `image` selects the namespace: a chunk provisioned from a shared base image
    /// lives outside this volume's prefix and is read, never written, from here.
    fn fetch_verified(
        &self,
        object_id: &str,
        len: u32,
        sha: [u8; 32],
        image: Option<&str>,
    ) -> Result<Vec<u8>> {
        let key = match image {
            Some(image) => chunk::keys::image_data(image, object_id),
            None => chunk::keys::data(&self.cfg.volume_id, object_id),
        };
        let bytes = self.blob.get(&key)?;
        if bytes.len() != len as usize {
            return Err(EngineError::Corrupt(format!(
                "object {object_id} length mismatch"
            )));
        }
        if format::sha256(&bytes) != sha {
            return Err(EngineError::Corrupt(format!(
                "object {object_id} checksum mismatch"
            )));
        }
        Ok(bytes)
    }

    /// Fetch a layered chunk's base and every delta at once.
    ///
    /// Returns them in the order they must be applied. Each is verified against
    /// the reference that named it, exactly as a serial fetch would.
    fn fetch_layers(
        &self,
        base: Option<&format::BaseRef>,
        deltas: &[format::DeltaRef],
    ) -> Result<Layers> {
        if deltas.len() + usize::from(base.is_some()) <= 1 {
            let base_bytes = match base {
                Some(base) => Some(self.fetch_verified(
                    &base.object_id,
                    base.len,
                    base.sha256,
                    base.image.as_deref(),
                )?),
                None => None,
            };
            let delta_bytes = deltas
                .iter()
                // Deltas are always written by this volume, never shared.
                .map(|d| self.fetch_verified(&d.object_id, d.len, d.sha256, None))
                .collect::<Result<Vec<_>>>()?;
            return Ok((base_bytes, delta_bytes));
        }

        // A chain is at most MAX_DELTA_LAYERS + 1 objects, so one thread each.
        let (base_bytes, delta_bytes) = std::thread::scope(|scope| {
            let base_handle = base.map(|base| {
                scope.spawn(move || {
                    self.fetch_verified(
                        &base.object_id,
                        base.len,
                        base.sha256,
                        base.image.as_deref(),
                    )
                })
            });
            let delta_handles: Vec<_> = deltas
                .iter()
                .map(|delta| {
                    scope.spawn(move || {
                        self.fetch_verified(&delta.object_id, delta.len, delta.sha256, None)
                    })
                })
                .collect();
            let base_bytes = base_handle
                .map(|handle| handle.join().expect("layer fetch thread panicked"))
                .transpose();
            let delta_bytes: Result<Vec<Vec<u8>>> = delta_handles
                .into_iter()
                .map(|handle| handle.join().expect("layer fetch thread panicked"))
                .collect();
            (base_bytes, delta_bytes)
        });
        Ok((base_bytes?, delta_bytes?))
    }

    /// Materialize one committed chunk in memory. The publisher also uses this
    /// to merge a local byte overlay without touching the Guest cache.
    fn fetch_chunk_image(&self, chunk_ref: &ChunkRef) -> Result<Vec<u8>> {
        let page = cats_api::chunk::DIRTY_PAGE_SIZE as usize;
        let image = match chunk_ref {
            ChunkRef::Hole => vec![0u8; CHUNK_SIZE as usize],
            ChunkRef::Base(base) => self.fetch_verified(
                &base.object_id,
                base.len,
                base.sha256,
                base.image.as_deref(),
            )?,
            ChunkRef::Layered { base, deltas } => {
                // Fetch the whole layer stack at once. Applying the deltas is
                // order-dependent; fetching them is not, and a full chain is five
                // objects, which serially is five round trips.
                let (base_bytes, delta_bytes) = self.fetch_layers(base.as_ref(), deltas)?;
                let mut image = match base_bytes {
                    Some(bytes) => bytes,
                    None => vec![0u8; CHUNK_SIZE as usize],
                };
                if image.len() != CHUNK_SIZE as usize {
                    return Err(EngineError::Corrupt(
                        "layered chunk base is not a full chunk".into(),
                    ));
                }
                for (delta, bytes) in deltas.iter().zip(delta_bytes) {
                    let mut consumed = 0usize;
                    for page_idx in 0..cats_api::chunk::PAGES_PER_CHUNK {
                        if delta.page_mask & (1u64 << page_idx) == 0 {
                            continue;
                        }
                        let at = page_idx as usize * page;
                        image[at..at + page].copy_from_slice(&bytes[consumed..consumed + page]);
                        consumed += page;
                    }
                    if consumed != bytes.len() {
                        return Err(EngineError::Corrupt(format!(
                            "delta {} carries {} bytes for {} pages",
                            delta.object_id,
                            bytes.len(),
                            delta.page_mask.count_ones()
                        )));
                    }
                }
                image
            }
        };
        Ok(image)
    }

    /// Materialize one chunk into the local cache from its committed objects.
    ///
    /// A layered chunk is assembled base-first and then delta by delta, so a
    /// later delta overwrites an earlier one on any page they share. The result
    /// is written as one full chunk so nothing stale can survive underneath it —
    /// which matters because the cache file outlives an attachment.
    fn hydrate_chunk(&self, chunk_idx: u64, chunk_ref: &ChunkRef) -> Result<()> {
        let image = self.fetch_chunk_image(chunk_ref)?;
        let protected = HashSet::from([chunk_idx]);
        let _cache_space = self.ensure_local_capacity(image.len() as u64, &protected)?;
        let _gate = self.io_gate.write().unwrap();
        self.cache
            .write_all_at(&image, chunk_idx * CHUNK_SIZE as u64)?;
        Ok(())
    }

    /// Hydrate a relaxed chunk without overwriting newer byte overlays. The
    /// remote fetch is optimistic and concurrent; only the short validation +
    /// local merge is serialized with FLUSH and publication.
    fn hydrate_chunk_with_local_state(&self, chunk_idx: u64) -> Result<()> {
        loop {
            let (generation, chunk_ref) = {
                let st = self.state.lock().unwrap();
                (st.generation, st.map[chunk_idx as usize].clone())
            };
            let mut image = self.fetch_chunk_image(&chunk_ref)?;

            let _flush = self.flush_lock.lock().unwrap();
            let protected = HashSet::from([chunk_idx]);
            let _cache_space = self.ensure_local_capacity(CHUNK_SIZE as u64, &protected)?;
            let _publish = self.publish_lock.lock().unwrap();
            let _gate = self.io_gate.write().unwrap();
            {
                let st = self.state.lock().unwrap();
                if st.generation != generation || st.map[chunk_idx as usize] != chunk_ref {
                    continue;
                }
            }

            let staged_paths: Vec<PathBuf> = {
                let staged = self.staged.lock().unwrap();
                staged
                    .packs
                    .iter()
                    .filter(|pack| pack.chunks.contains(&chunk_idx))
                    .map(|pack| pack.path.clone())
                    .collect()
            };
            for path in staged_paths {
                let bytes = fs::read(path)?;
                let (header, payload) = format::decode_pack(&bytes).map_err(|error| {
                    EngineError::Corrupt(format!("staged pack during hydrate: {error}"))
                })?;
                if let Some(entry) = header
                    .entries
                    .iter()
                    .find(|entry| entry.chunk_idx == chunk_idx)
                {
                    apply_local_entry(&mut image, entry, &payload)?;
                }
            }

            {
                let st = self.state.lock().unwrap();
                if st.discarded.contains(&chunk_idx) {
                    image.fill(0);
                }
                let chunk_start = chunk_idx * CHUNK_SIZE as u64;
                for range in &st.dirty_ranges[chunk_idx as usize] {
                    self.cache.read_exact_at(
                        &mut image[range.start as usize..range.end as usize],
                        chunk_start + range.start as u64,
                    )?;
                }
            }
            self.cache
                .write_all_at(&image, chunk_idx * CHUNK_SIZE as u64)?;
            return Ok(());
        }
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

    // -----------------------------------------------------------------
    // Lease renewal / shutdown
    // -----------------------------------------------------------------

    /// Sweep unreachable objects on a timer for as long as this attachment lives.
    ///
    /// The lease holder is the only place a sweep is safe without a grace period,
    /// and this process is it. Without something on a timer, superseded objects
    /// accumulate for the life of a volume: a Guest that rewrites the same chunk
    /// all day leaves a dead 4 MiB object behind every time its delta chain
    /// resets, and nothing would ever remove them.
    pub fn start_gc_thread(self: &Arc<Self>, interval: Duration) {
        if interval.is_zero() {
            return;
        }
        let engine = Arc::downgrade(self);
        let stop = self.stop_renew.clone();
        let handle = std::thread::Builder::new()
            .name("gc".into())
            .spawn(move || loop {
                // Shares the renewal stop signal: both threads exist exactly as
                // long as the attachment does, and detach must not wait on either.
                let (lock, cv) = &*stop;
                let stopped = {
                    let guard = lock.lock().unwrap();
                    let (guard, _timeout) = cv
                        .wait_timeout_while(guard, interval, |stopped| !*stopped)
                        .unwrap();
                    *guard
                };
                if stopped {
                    return;
                }
                let Some(engine) = engine.upgrade() else {
                    return;
                };
                if engine.is_fenced() {
                    return;
                }
                if let Err(error) = engine.collect_garbage() {
                    // Garbage is not urgent: a failed sweep is retried next tick
                    // and never blocks the Guest.
                    tracing::warn!("garbage collection failed: {error}");
                }
            })
            .expect("spawn gc thread");
        *self.gc_thread.lock().unwrap() = Some(handle);
    }

    fn start_renew_thread(self: &Arc<Self>) {
        let engine = Arc::downgrade(self);
        let stop = self.stop_renew.clone();
        let interval = Duration::from_millis((self.cfg.lease_ttl_ms / 3).max(50) as u64);
        let handle = std::thread::Builder::new()
            .name("lease-renew".into())
            .spawn(move || loop {
                // Waiting on a condvar rather than sleeping: a detach has to be able
                // to interrupt this. A plain sleep made every stop, suspend and
                // migration wait out up to a third of the lease TTL per volume.
                let (lock, cv) = &*stop;
                let stopped = {
                    let guard = lock.lock().unwrap();
                    let (guard, _timeout) = cv
                        .wait_timeout_while(guard, interval, |stopped| !*stopped)
                        .unwrap();
                    *guard
                };
                if stopped {
                    return;
                }
                let Some(engine) = engine.upgrade() else {
                    return;
                };
                if engine.is_fenced() {
                    return;
                }
                match engine.meta.renew_lease(
                    &engine.cfg.volume_id,
                    &engine.cfg.attachment_id,
                    engine.epoch,
                    engine.cfg.lease_ttl_ms,
                ) {
                    Ok(()) => {}
                    // The row no longer names this attachment and epoch: the
                    // lease was revoked or acquired by someone else. That is
                    // the one terminal outcome.
                    Err(e @ (MetaError::Fenced | MetaError::NotFound(_))) => {
                        tracing::error!("lease renewal failed; fencing writes: {e}");
                        engine.fenced.store(true, Ordering::SeqCst);
                        engine.staged_space.notify_all();
                        engine.local_space.notify_all();
                        return;
                    }
                    // A slow or unreachable metadata store is not a fence: the
                    // row still names this attachment, so the next attempt
                    // renews straight through an expiry lapse, and publishes
                    // stay guarded by the epoch CAS in the meantime.
                    Err(e) => {
                        tracing::warn!("lease renewal attempt failed; will retry: {e}");
                    }
                }
            })
            .expect("spawn lease renew thread");
        *self.renew_thread.lock().unwrap() = Some(handle);
    }

    /// Relaxed mode only: publish staged packs on a timer. Shares the
    /// stop/wake condvar with lease renewal so detach interrupts the wait
    /// instead of sleeping it out.
    fn start_committer_thread(self: &Arc<Self>) {
        let DurabilityMode::Relaxed { drain_interval_ms } = self.cfg.durability else {
            return;
        };
        if drain_interval_ms == 0 {
            // No background committer: drains happen on demand (backpressure,
            // detach, `cats sync`). Deterministic mode for tests.
            return;
        }
        let engine = Arc::downgrade(self);
        let signal = self.committer_signal.clone();
        let interval = Duration::from_millis(drain_interval_ms.max(50));
        let handle = std::thread::Builder::new()
            .name("pack-committer".into())
            .spawn(move || loop {
                let (lock, cv) = &*signal;
                let stopped = {
                    let guard = lock.lock().unwrap();
                    let (mut guard, _timeout) = cv
                        .wait_timeout_while(guard, interval, |s| !s.stop && !s.kick)
                        .unwrap();
                    guard.kick = false;
                    guard.stop
                };
                if stopped {
                    return;
                }
                let Some(engine) = engine.upgrade() else {
                    return;
                };
                if engine.is_fenced() {
                    return;
                }
                if let Err(e) = engine.drain_staged() {
                    // Transient store trouble: the queue keeps the packs and
                    // the next tick (or the next kick) retries. Relaxed FLUSH
                    // never joins this remote path; once local admission is
                    // full it waits for this publisher to reclaim space.
                    tracing::warn!(volume = %engine.cfg.volume_id, "background drain failed: {e}");
                }
            })
            .expect("spawn pack committer thread");
        *self.committer_thread.lock().unwrap() = Some(handle);
    }

    /// Graceful detach: publish every locally acknowledged generation before
    /// releasing the lease. A failed drain keeps renewal, the lease and all
    /// local journal files alive so the caller can retry; silently releasing
    /// them would turn a transient remote outage into acknowledged data loss.
    pub fn detach(&self) -> Result<()> {
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        self.drain_staged()?;
        self.stop_renewal();
        self.meta
            .release_lease(&self.cfg.volume_id, &self.cfg.attachment_id, self.epoch)?;
        Ok(())
    }
}

impl ChunkEngine {
    fn stop_renewal(&self) {
        let (lock, cv) = &*self.stop_renew;
        *lock.lock().unwrap() = true;
        cv.notify_all();
        let (lock, cv) = &*self.committer_signal;
        lock.lock().unwrap().stop = true;
        cv.notify_all();
        if let Some(handle) = self.renew_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.gc_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.committer_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ChunkEngine {
    fn drop(&mut self) {
        self.stop_renewal();
    }
}

/// How many objects a commit uploads at once.
///
/// Not derived from the core count the way `commit_workers` is: this work is a
/// blocked socket, not a busy CPU, so the useful number is set by the object
/// store's round-trip time and its per-connection throughput rather than by the
/// machine. Sixteen keeps a remote store's pipe full without turning a large
/// commit into hundreds of concurrent connections.
const MAX_UPLOAD_CONCURRENCY: usize = 16;

fn upload_workers(objects: usize) -> usize {
    objects.clamp(1, MAX_UPLOAD_CONCURRENCY)
}

/// A layered chunk's fetched objects: the base (absent when the chunk's base is a
/// hole) and each delta, in the order they must be applied.
type Layers = (Option<Vec<u8>>, Vec<Vec<u8>>);

/// How many chunks one read hydrates at once. Same reasoning as the upload cap,
/// and the same number: a cold read is round-trip bound in exactly the same way a
/// commit is.
fn fetch_workers(chunks: usize) -> usize {
    chunks.clamp(1, MAX_UPLOAD_CONCURRENCY)
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

/// What one commit publishes for one chunk.
#[derive(Debug, Clone)]
struct ChunkPlan {
    chunk_idx: u64,
    /// Pages carried by this entry; `full_page_mask()` means a whole-chunk base.
    page_mask: u64,
}

impl ChunkPlan {
    fn is_base(&self) -> bool {
        self.page_mask == format::full_page_mask()
    }

    /// Payload bytes this plan contributes to the pack.
    fn len(&self) -> usize {
        self.page_mask.count_ones() as usize * cats_api::chunk::DIRTY_PAGE_SIZE as usize
    }

    /// Byte runs to copy out of the cache, coalescing adjacent dirty pages so a
    /// scattered mask still costs few reads.
    fn runs(&self, payload_offset: usize) -> Vec<CopyRun> {
        let page = cats_api::chunk::DIRTY_PAGE_SIZE as u64;
        let chunk_start = self.chunk_idx * CHUNK_SIZE as u64;
        let mut runs = Vec::new();
        let mut dst = payload_offset;
        let mut page_idx = 0u32;
        while page_idx < cats_api::chunk::PAGES_PER_CHUNK {
            if self.page_mask & (1u64 << page_idx) == 0 {
                page_idx += 1;
                continue;
            }
            let first = page_idx;
            while page_idx < cats_api::chunk::PAGES_PER_CHUNK
                && self.page_mask & (1u64 << page_idx) != 0
            {
                page_idx += 1;
            }
            let len = ((page_idx - first) as u64 * page) as usize;
            runs.push(CopyRun {
                file_offset: chunk_start + first as u64 * page,
                dst_offset: dst,
                len,
            });
            dst += len;
        }
        runs
    }
}

/// One contiguous copy from the cache file into the pack payload.
#[derive(Debug, Clone, Copy)]
struct CopyRun {
    file_offset: u64,
    dst_offset: usize,
    len: usize,
}

/// Decide what each dirty chunk publishes: a delta of its dirty pages, or a
/// fresh full base.
///
/// A base is written when the chunk's delta chain is full, or when the Guest
/// dirtied more than half the chunk — past that point a delta saves little and
/// resetting the chain is worth more than the bytes.
fn plan_commit(dirty: &[(u64, u64)], base_map: &[ChunkRef], discarded: &[u64]) -> Vec<ChunkPlan> {
    let pages_per_chunk = cats_api::chunk::PAGES_PER_CHUNK;
    // A discarded chunk carries no pages: `ChunkPlan::len()` is zero, so it
    // occupies no payload and its pack entry publishes no object. It still has to
    // be in the plan, because the commit is what turns its map entry into a Hole
    // and a pending pack has to be able to replay that.
    discarded
        .iter()
        .map(|&chunk_idx| ChunkPlan {
            chunk_idx,
            page_mask: 0,
        })
        .chain(dirty.iter().map(|&(chunk_idx, mask)| {
            let dense = mask.count_ones() * 2 > pages_per_chunk;
            let chain_full = base_map[chunk_idx as usize].layer_count() >= MAX_DELTA_LAYERS;
            let page_mask = if dense || chain_full {
                format::full_page_mask()
            } else {
                mask
            };
            ChunkPlan {
                chunk_idx,
                page_mask,
            }
        }))
        .collect()
}

/// How many threads to use for one commit's copy/hash work.
///
/// Both are per-chunk independent, and both are a large share of FLUSH latency:
/// measured on aarch64, sha256 runs at ~546 MiB/s per core and accounts for
/// roughly 47% of a commit, while the copy reads the dirty set out of the cache
/// file. The cap keeps a big commit from spawning hundreds of threads.
fn commit_workers(units: usize) -> usize {
    const MAX: usize = 8;
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX)
        .min(units)
        .max(1)
}

/// Copy the planned bytes out of the cache into the pack payload.
///
/// Runs inside the exclusive commit barrier, so it is the one thing that must be
/// as short as possible: the destination ranges are disjoint and `read_exact_at`
/// takes `&self`, so the copy parallelizes without any locking.
fn copy_planned_pages(cache: &File, plans: &[ChunkPlan], payload: &mut [u8]) -> Result<()> {
    let mut runs = Vec::with_capacity(plans.len());
    let mut offset = 0usize;
    for plan in plans {
        runs.extend(plan.runs(offset));
        offset += plan.len();
    }
    debug_assert_eq!(offset, payload.len());

    let workers = commit_workers(runs.len());
    if workers == 1 {
        for run in &runs {
            cache.read_exact_at(
                &mut payload[run.dst_offset..run.dst_offset + run.len],
                run.file_offset,
            )?;
        }
        return Ok(());
    }

    // Runs are in increasing destination order, so a contiguous group of runs
    // owns a contiguous span of the payload and each worker can be handed its
    // own `&mut` slice.
    let per_worker = runs.len().div_ceil(workers);
    let mut failure: Option<std::io::Error> = None;
    let mut rest = payload;
    let mut spans: Vec<(&[CopyRun], &mut [u8], usize)> = Vec::new();
    for group in runs.chunks(per_worker) {
        let span_start = group[0].dst_offset;
        let span_end = group[group.len() - 1].dst_offset + group[group.len() - 1].len;
        let (span, tail) = rest.split_at_mut(span_end - span_start);
        rest = tail;
        spans.push((group, span, span_start));
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = spans
            .into_iter()
            .map(|(group, span, span_start)| {
                scope.spawn(move || -> std::io::Result<()> {
                    for run in group {
                        let start = run.dst_offset - span_start;
                        cache.read_exact_at(&mut span[start..start + run.len], run.file_offset)?;
                    }
                    Ok(())
                })
            })
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(Err(error)) if failure.is_none() => failure = Some(error),
                Ok(_) => {}
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(std::io::Error::other("commit copy worker panicked"));
                    }
                }
            }
        }
    });
    match failure {
        Some(error) => Err(error.into()),
        None => Ok(()),
    }
}

fn copy_dirty_ranges(
    cache: &File,
    plans: &[ChunkPlan],
    ranges: &[Vec<DirtyByteRange>],
) -> Result<Vec<u8>> {
    let bytes: usize = ranges
        .iter()
        .flat_map(|ranges| ranges.iter())
        .map(|range| range.len())
        .sum();
    let mut payload = vec![0u8; bytes];
    let mut destination = 0usize;
    for (plan, ranges) in plans.iter().zip(ranges) {
        let chunk_start = plan.chunk_idx * CHUNK_SIZE as u64;
        for range in ranges {
            let len = range.len();
            cache.read_exact_at(
                &mut payload[destination..destination + len],
                chunk_start + range.start as u64,
            )?;
            destination += len;
        }
    }
    Ok(payload)
}

/// Hash the frozen bytes and describe the pack entries, in chunk order.
///
/// Runs after the barrier is released, over a private copy, so it is pure
/// computation — but it is still on the Guest's FLUSH latency, so it is worth
/// spreading across cores.
fn describe_pack(plans: &[ChunkPlan], payload: &[u8]) -> Vec<PackEntry> {
    let mut offsets = Vec::with_capacity(plans.len());
    let mut offset = 0usize;
    for plan in plans {
        offsets.push(offset);
        offset += plan.len();
    }
    let describe = |(plan, start): (&ChunkPlan, &usize)| PackEntry {
        chunk_idx: plan.chunk_idx,
        payload_offset: *start as u64,
        len: plan.len() as u32,
        sha256_hex: hex::encode(format::sha256(&payload[*start..*start + plan.len()])),
        page_mask: plan.page_mask,
        byte_ranges: Vec::new(),
    };
    let jobs: Vec<(&ChunkPlan, &usize)> = plans.iter().zip(offsets.iter()).collect();
    let workers = commit_workers(jobs.len());
    if workers == 1 {
        return jobs.into_iter().map(describe).collect();
    }
    let per_worker = jobs.len().div_ceil(workers);
    let mut entries: Vec<PackEntry> = std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(per_worker)
            .map(|group| {
                scope.spawn(move || {
                    group
                        .iter()
                        .map(|(plan, start)| describe((plan, start)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("commit hash worker panicked"))
            .collect()
    });
    // Groups are handed out in order, but be explicit: recovery and the map
    // update both assume entries are ordered by chunk index.
    entries.sort_unstable_by_key(|entry| entry.chunk_idx);
    entries
}

fn describe_overlay_pack(
    plans: &[ChunkPlan],
    ranges: &[Vec<DirtyByteRange>],
    payload: &[u8],
) -> Vec<PackEntry> {
    let mut payload_offset = 0usize;
    plans
        .iter()
        .zip(ranges)
        .map(|(plan, ranges)| {
            let entry_start = payload_offset;
            let byte_ranges = ranges
                .iter()
                .map(|range| {
                    let len = range.len();
                    let descriptor = PackByteRange {
                        chunk_offset: range.start,
                        payload_offset: payload_offset as u64,
                        len: len as u32,
                    };
                    payload_offset += len;
                    descriptor
                })
                .collect();
            PackEntry {
                chunk_idx: plan.chunk_idx,
                payload_offset: entry_start as u64,
                len: (payload_offset - entry_start) as u32,
                sha256_hex: hex::encode(format::sha256(&payload[entry_start..payload_offset])),
                page_mask: plan.page_mask,
                byte_ranges,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_metadata_store_sqlite::SqliteMetadataStore;
    use cats_object_store_file::FileBlobStore;
    use std::sync::atomic::AtomicU64;

    struct Env {
        _dir: tempfile::TempDir,
        blob: Arc<dyn BlobStore>,
        meta: Arc<dyn MetadataStore>,
        data_dir: PathBuf,
    }

    const VOL: &str = "vol_test";
    const SIZE: u64 = 8 * CHUNK_SIZE as u64; // 32 MiB logical

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let data_dir = dir.path().join("data");
        Env {
            _dir: dir,
            blob,
            meta,
            data_dir,
        }
    }

    fn attach(env: &Env, attachment: &str) -> Arc<ChunkEngine> {
        ChunkEngine::attach(
            EngineConfig::new(VOL, &env.data_dir, attachment),
            env.blob.clone(),
            env.meta.clone(),
        )
        .unwrap()
    }

    /// Attach on a different "host" (fresh data dir).
    fn attach_at(env: &Env, attachment: &str, dir: &str) -> Arc<ChunkEngine> {
        ChunkEngine::attach(
            EngineConfig::new(VOL, env.data_dir.parent().unwrap().join(dir), attachment),
            env.blob.clone(),
            env.meta.clone(),
        )
        .unwrap()
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn write_read_roundtrip_and_holes() {
        let env = env();
        let e = attach(&env, "attA");
        let data = pattern(10_000, 1);
        e.write(1234, &data).unwrap();
        let mut back = vec![0u8; 10_000];
        e.read(1234, &mut back).unwrap();
        assert_eq!(back, data);
        // Untouched region reads zeros.
        let mut z = vec![1u8; 4096];
        e.read(SIZE - 4096, &mut z).unwrap();
        assert!(z.iter().all(|&b| b == 0));
        // Out of bounds is rejected.
        assert!(e.read(SIZE - 1, &mut [0u8; 2]).is_err());
        assert!(e.write(SIZE, b"x").is_err());
        e.detach().unwrap();
    }

    #[test]
    fn flush_commits_and_survives_full_cache_wipe() {
        let env = env();
        let data1 = pattern(CHUNK_SIZE as usize, 3); // full chunk 0
        let data2 = pattern(5000, 9); // straddles chunk 2/3 boundary
        {
            let e = attach(&env, "attA");
            e.write(0, &data1).unwrap();
            e.write(3 * CHUNK_SIZE as u64 - 2500, &data2).unwrap();
            let generation = e.flush().unwrap();
            assert_eq!(generation, 1);
            // Empty dirty set: flush is a no-op that keeps the generation.
            assert_eq!(e.flush().unwrap(), 1);
            e.detach().unwrap();
        }
        // Simulate a brand-new host: wipe every local byte.
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach(&env, "attB");
        assert_eq!(e.generation(), 1);
        let mut back = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(back, data1);
        let mut back2 = vec![0u8; 5000];
        e.read(3 * CHUNK_SIZE as u64 - 2500, &mut back2).unwrap();
        assert_eq!(back2, data2);
        // A hole chunk still reads zeros after recovery.
        let mut z = vec![1u8; 512];
        e.read(5 * CHUNK_SIZE as u64, &mut z).unwrap();
        assert!(z.iter().all(|&b| b == 0));
        e.detach().unwrap();
    }

    /// Interval 0 = no background committer: relaxed engines in these tests
    /// drain explicitly, deterministically.
    const NO_TIMER: u64 = 0;

    fn attach_relaxed(env: &Env, attachment: &str) -> Arc<ChunkEngine> {
        let mut cfg = EngineConfig::new(VOL, &env.data_dir, attachment);
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap()
    }

    #[test]
    fn relaxed_flush_acks_locally_and_the_drain_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBlob {
            inner: Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap()),
            gets: AtomicU64::new(0),
            data_puts: AtomicU64::new(0),
        });
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        let e = ChunkEngine::attach(cfg, counting.clone(), meta).unwrap();

        e.write(0, &pattern(4096, 7)).unwrap();
        let acked = e.flush().unwrap();
        assert_eq!(acked, 1, "flush reports the pack's target generation");
        assert_eq!(
            counting.data_puts.load(Ordering::SeqCst),
            0,
            "a relaxed ack must not wait on the object store"
        );
        assert_eq!(e.generation(), 0, "nothing committed yet");
        let status = e.durability_status();
        assert_eq!(status.local_durable_generation, 1);
        assert_eq!(status.remote_durable_generation, 0);
        assert_eq!(status.unpublished_generations, 1);
        assert!(status.unpublished_bytes > 4096);
        assert!(!status.backpressured);
        assert_eq!(status.last_publish_error, None);

        // An empty flush with a staged backlog still acks the same target.
        assert_eq!(e.flush().unwrap(), 1);

        assert_eq!(e.drain_staged().unwrap(), 1);
        assert!(counting.data_puts.load(Ordering::SeqCst) > 0);
        assert_eq!(e.generation(), 1);
        e.detach().unwrap();
    }

    #[test]
    fn relaxed_restart_rebuilds_the_local_watermark_without_remote_writes() {
        use cats_storage::blob::FaultyBlobStore;

        let dir = tempfile::tempdir().unwrap();
        let healthy: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let faulty = Arc::new(FaultyBlobStore::new(healthy.clone()));
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let data_dir = dir.path().join("data");

        {
            let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
            cfg.durability = DurabilityMode::Relaxed {
                drain_interval_ms: NO_TIMER,
            };
            let e = ChunkEngine::attach(cfg, healthy.clone(), meta.clone()).unwrap();
            e.write(100, &pattern(4096, 1)).unwrap();
            assert_eq!(e.flush().unwrap(), 1);
            // Overwrite the same pages in a second staged pack: replay order
            // becomes observable in the final bytes.
            e.write(100, &pattern(4096, 2)).unwrap();
            e.write(CHUNK_SIZE as u64 + 7, b"second-chunk").unwrap();
            assert_eq!(e.flush().unwrap(), 2);
            assert_eq!(e.generation(), 0, "both packs staged, none committed");
            // Crash: Drop stops threads but does not drain.
        }

        faulty.fail_puts.store(10, Ordering::SeqCst);
        let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        let e = ChunkEngine::attach(cfg, faulty.clone(), meta).unwrap();
        assert_eq!(
            faulty.fail_puts.load(Ordering::SeqCst),
            10,
            "same-host relaxed recovery must not issue a remote PUT"
        );
        let status = e.durability_status();
        assert_eq!(status.local_durable_generation, 2);
        assert_eq!(status.remote_durable_generation, 0);
        assert_eq!(status.unpublished_generations, 2);

        // The cache plus local journal remains the running truth while the
        // remote watermark is behind.
        let mut b = vec![0u8; 4096];
        e.read(100, &mut b).unwrap();
        assert_eq!(b, pattern(4096, 2), "the later staged pack wins");
        let mut s = vec![0u8; 12];
        e.read(CHUNK_SIZE as u64 + 7, &mut s).unwrap();
        assert_eq!(&s, b"second-chunk");

        faulty.fail_puts.store(0, Ordering::SeqCst);
        assert_eq!(e.drain_staged().unwrap(), 2);
        e.detach().unwrap();
    }

    #[test]
    fn remote_outage_is_observable_but_does_not_fail_relaxed_flush() {
        use cats_storage::blob::FaultyBlobStore;

        let dir = tempfile::tempdir().unwrap();
        let healthy: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let faulty = Arc::new(FaultyBlobStore::new(healthy));
        faulty.fail_puts.store(u64::MAX, Ordering::SeqCst);
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: 50,
        };
        let e = ChunkEngine::attach(cfg, faulty, meta).unwrap();

        e.write(0, &pattern(4096, 9)).unwrap();
        assert_eq!(
            e.flush().unwrap(),
            1,
            "remote failure must not become Guest EIO"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let status = e.durability_status();
            if status.last_publish_error.is_some() {
                assert_eq!(status.local_durable_generation, 1);
                assert_eq!(status.remote_durable_generation, 0);
                assert_eq!(status.unpublished_generations, 1);
                assert!(status.unpublished_bytes > 0);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "background publisher failure never reached durability status"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // Drop models a process failure and deliberately avoids the forced
        // remote drain performed by graceful detach.
    }

    #[test]
    fn relaxed_cold_cache_write_and_flush_issue_no_remote_read() {
        struct SwitchableGetFailure {
            inner: Arc<dyn BlobStore>,
            fail_gets: AtomicBool,
            gets: AtomicU64,
        }
        impl BlobStore for SwitchableGetFailure {
            fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
                self.inner.put_immutable(key, data)
            }
            fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
                self.gets.fetch_add(1, Ordering::SeqCst);
                if self.fail_gets.load(Ordering::SeqCst) {
                    return Err(BlobError::Backend {
                        key: key.to_string(),
                        message: "injected GET outage".into(),
                    });
                }
                self.inner.get(key)
            }
            fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
                self.inner.exists(key)
            }
            fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
                self.inner.delete(key)
            }
            fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
                self.inner.list(prefix)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let healthy: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let original = pattern(CHUNK_SIZE as usize, 71);
        {
            let e = ChunkEngine::attach(
                EngineConfig::new(VOL, dir.path().join("seed"), "seed"),
                healthy.clone(),
                meta.clone(),
            )
            .unwrap();
            e.write(0, &original).unwrap();
            e.flush().unwrap();
            e.detach().unwrap();
        }

        let switched = Arc::new(SwitchableGetFailure {
            inner: healthy.clone(),
            fail_gets: AtomicBool::new(false),
            gets: AtomicU64::new(0),
        });
        let mut cfg = EngineConfig::new(VOL, dir.path().join("relaxed"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        let e = ChunkEngine::attach(cfg, switched.clone(), meta.clone()).unwrap();
        let before = switched.gets.load(Ordering::SeqCst);
        switched.fail_gets.store(true, Ordering::SeqCst);
        let update = pattern(4096, 99);
        e.write(123, &update).unwrap();
        assert_eq!(e.flush().unwrap(), 2);
        assert_eq!(
            switched.gets.load(Ordering::SeqCst),
            before,
            "cold-cache relaxed WRITE/FLUSH must not issue an object GET"
        );

        switched.fail_gets.store(false, Ordering::SeqCst);
        let mut live = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut live).unwrap();
        let mut expected = original.clone();
        expected[123..123 + update.len()].copy_from_slice(&update);
        assert_eq!(
            live, expected,
            "a cold read merges the remote base with the local overlay"
        );
        e.drain_staged().unwrap();
        e.detach().unwrap();
        let restored = ChunkEngine::attach(
            EngineConfig::new(VOL, dir.path().join("restored"), "attB"),
            healthy,
            meta,
        )
        .unwrap();
        let mut actual = vec![0u8; CHUNK_SIZE as usize];
        restored.read(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
        restored.detach().unwrap();
    }

    #[test]
    fn relaxed_read_waits_until_a_frozen_cold_overlay_is_journaled() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();
        let blob: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let original = pattern(CHUNK_SIZE as usize, 81);
        {
            let seed = ChunkEngine::attach(
                EngineConfig::new(VOL, dir.path().join("seed"), "seed"),
                blob.clone(),
                meta.clone(),
            )
            .unwrap();
            seed.write(0, &original).unwrap();
            seed.flush().unwrap();
            seed.detach().unwrap();
        }

        let mut cfg = EngineConfig::new(VOL, dir.path().join("relaxed"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        // The first tiny pack fits. The second overlay is larger than this cap,
        // so it may enter only after the first pack drains; that holds it
        // deterministically in the freeze-to-journal interval.
        cfg.max_staged_bytes = 1 << 20;
        let e = ChunkEngine::attach(cfg, blob, meta).unwrap();
        assert!(
            !e.state.lock().unwrap().map[0].is_hole(),
            "the committed seed chunk must be present before the relaxed writes"
        );
        e.write(17, b"x").unwrap();
        e.flush().unwrap();
        assert!(e.durability_status().unpublished_bytes < 1 << 20);

        let large_offset = 1 << 20;
        let large = pattern((2 << 20) + cats_api::chunk::DIRTY_PAGE_SIZE as usize, 92);
        e.write(large_offset, &large).unwrap();
        let flushing = {
            let e = e.clone();
            thread::spawn(move || e.flush())
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if e.state.lock().unwrap().freezing.contains(&0) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "second FLUSH never reached the frozen-overlay interval"
            );
            thread::sleep(Duration::from_millis(1));
        }

        let (read_tx, read_rx) = mpsc::channel();
        let reading = {
            let e = e.clone();
            thread::spawn(move || {
                let mut bytes = vec![0u8; CHUNK_SIZE as usize];
                let result = e.read(0, &mut bytes).map(|()| bytes);
                read_tx.send(result).unwrap();
            })
        };
        assert!(
            read_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "cold read escaped while its local overlay was neither dirty nor journaled"
        );

        // Publishing the first pack makes local staging room. The second FLUSH
        // can then insert its durable pack and wake the reader.
        e.drain_staged().unwrap();
        flushing.join().unwrap().unwrap();
        let actual = read_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reader did not wake after the pack became visible")
            .unwrap();
        reading.join().unwrap();

        let mut expected = original;
        expected[17] = b'x';
        expected[large_offset as usize..large_offset as usize + large.len()]
            .copy_from_slice(&large);
        e.drain_staged().unwrap();
        if actual != expected {
            let mismatch = actual
                .iter()
                .zip(&expected)
                .position(|(actual, expected)| actual != expected)
                .unwrap();
            let st = e.state.lock().unwrap();
            panic!(
                "mismatch at byte {mismatch}: actual={} expected={}, actual_sha={} expected_sha={}, generation={}, staged={}, hydrated={}, map={:?}",
                actual[mismatch],
                expected[mismatch],
                hex::encode(format::sha256(&actual)),
                hex::encode(format::sha256(&expected)),
                st.generation,
                e.staged.lock().unwrap().packs.len(),
                st.hydrated[0],
                st.map[0],
            );
        }
        e.detach().unwrap();
    }

    #[test]
    fn local_quota_evicts_clean_chunks_but_preserves_committed_reads() {
        let env = env();
        let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attA");
        // One dense chunk plus one same-sized pending pack fits; retaining two
        // dense clean chunks while staging the second does not.
        cfg.max_local_bytes = 9 << 20;
        let e = ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap();
        let first = pattern(CHUNK_SIZE as usize, 31);
        let second = pattern(CHUNK_SIZE as usize, 47);

        e.write(0, &first).unwrap();
        e.flush().unwrap();
        e.write(CHUNK_SIZE as u64, &second).unwrap();
        e.flush().unwrap();

        let status = e.durability_status();
        assert!(
            status.evicted_cache_chunks >= 1,
            "the second dense commit should evict a clean LRU chunk"
        );
        assert!(status.local_allocated_bytes <= status.max_local_bytes);

        let mut restored = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut restored).unwrap();
        assert_eq!(restored, first, "an evicted clean chunk rehydrates exactly");
        e.detach().unwrap();
    }

    #[test]
    fn relaxed_dirty_cache_reserves_pack_space_and_cannot_deadlock_the_quota() {
        let env = env();
        let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attA");
        cfg.durability = DurabilityMode::Relaxed {
            // Only a pressure kick, not this timer, can publish in test time.
            drain_interval_ms: 3_600_000,
        };
        // One dense cache chunk plus its future pack fits. Two dirty cache
        // chunks do not, so the second WRITE must first stage the first one and
        // let the background publisher reclaim its reservation.
        cfg.max_local_bytes = 10 << 20;
        let e = ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap();
        let first = pattern(CHUNK_SIZE as usize, 61);
        let second = pattern(CHUNK_SIZE as usize, 73);
        e.write(0, &first).unwrap();
        let dirty = e.durability_status();
        assert_eq!(dirty.unpublished_generations, 0);
        assert!(
            dirty.local_accounted_bytes > dirty.local_allocated_bytes,
            "the future pending pack must be reserved before FLUSH"
        );

        let worker = e.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let result = worker.write(CHUNK_SIZE as u64, &second);
            let _ = tx.send(result);
        });
        rx.recv_timeout(Duration::from_secs(5))
            .expect("quota pressure deadlocked before a pack could be published")
            .unwrap();
        handle.join().unwrap();

        let status = e.durability_status();
        assert!(
            status.remote_durable_generation >= 1,
            "the implicit local stage did not give the publisher work"
        );
        assert!(status.local_accounted_bytes <= status.max_local_bytes);
        e.flush().unwrap();
        e.detach().unwrap();
    }

    #[test]
    fn relaxed_detach_publishes_staged_packs() {
        let env = env();
        let data = pattern(4096, 5);
        {
            let e = attach_relaxed(&env, "attA");
            e.write(2 * CHUNK_SIZE as u64, &data).unwrap();
            e.flush().unwrap();
            assert_eq!(e.generation(), 0);
            e.detach().unwrap();
        }
        // A different host with nothing local sees the detach-drained state.
        let e = attach_at(&env, "attB", "data-b");
        assert_eq!(e.generation(), 1);
        let mut back = vec![0u8; 4096];
        e.read(2 * CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, data);
        e.detach().unwrap();
    }

    #[test]
    fn failed_detach_keeps_the_journal_and_lease_for_retry() {
        use cats_storage::blob::FaultyBlobStore;

        let dir = tempfile::tempdir().unwrap();
        let healthy: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let faulty = Arc::new(FaultyBlobStore::new(healthy.clone()));
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let mut cfg = EngineConfig::new(VOL, dir.path().join("data-a"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        let e = ChunkEngine::attach(cfg, faulty.clone(), meta.clone()).unwrap();
        e.write(0, &pattern(4096, 4)).unwrap();
        e.flush().unwrap();

        faulty.fail_puts.store(u64::MAX, Ordering::SeqCst);
        assert!(e.detach().is_err(), "the mandatory drain must fail closed");
        assert_eq!(e.durability_status().unpublished_generations, 1);
        let competitor = ChunkEngine::attach(
            EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
            healthy.clone(),
            meta.clone(),
        );
        assert!(matches!(
            competitor,
            Err(EngineError::Meta(MetaError::LeaseHeld))
        ));

        faulty.fail_puts.store(0, Ordering::SeqCst);
        e.detach().unwrap();
        let next = ChunkEngine::attach(
            EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
            healthy,
            meta,
        )
        .unwrap();
        assert_eq!(next.generation(), 1);
        next.detach().unwrap();
    }

    /// Counts head swaps, so a test can prove a batch is one CAS.
    struct CountingMeta {
        inner: Arc<dyn MetadataStore>,
        cas_calls: AtomicU64,
    }

    impl MetadataStore for CountingMeta {
        fn create_volume(&self, v: &str, s: u64) -> cats_storage::metadata::Result<()> {
            self.inner.create_volume(v, s)
        }
        fn load_head(
            &self,
            v: &str,
        ) -> cats_storage::metadata::Result<cats_storage::metadata::VolumeHead> {
            self.inner.load_head(v)
        }
        fn delete_volume(&self, v: &str) -> cats_storage::metadata::Result<()> {
            self.inner.delete_volume(v)
        }
        fn resize_volume(&self, v: &str, s: u64) -> cats_storage::metadata::Result<()> {
            self.inner.resize_volume(v, s)
        }
        fn acquire_lease(&self, v: &str, a: &str, ttl: i64) -> cats_storage::metadata::Result<i64> {
            self.inner.acquire_lease(v, a, ttl)
        }
        fn renew_lease(
            &self,
            v: &str,
            a: &str,
            epoch: i64,
            ttl: i64,
        ) -> cats_storage::metadata::Result<()> {
            self.inner.renew_lease(v, a, epoch, ttl)
        }
        fn release_lease(
            &self,
            v: &str,
            a: &str,
            epoch: i64,
        ) -> cats_storage::metadata::Result<()> {
            self.inner.release_lease(v, a, epoch)
        }
        fn revoke_lease(&self, v: &str) -> cats_storage::metadata::Result<()> {
            self.inner.revoke_lease(v)
        }
        #[allow(clippy::too_many_arguments)]
        fn cas_head(
            &self,
            v: &str,
            expected: i64,
            new_generation: i64,
            hash: [u8; 32],
            object: &str,
            a: &str,
            epoch: i64,
        ) -> cats_storage::metadata::Result<i64> {
            self.cas_calls.fetch_add(1, Ordering::SeqCst);
            self.inner
                .cas_head(v, expected, new_generation, hash, object, a, epoch)
        }
        fn create_snapshot(
            &self,
            s: &str,
            v: &str,
        ) -> cats_storage::metadata::Result<cats_storage::metadata::SnapshotRow> {
            self.inner.create_snapshot(s, v)
        }
        fn list_snapshots(
            &self,
            v: &str,
        ) -> cats_storage::metadata::Result<Vec<cats_storage::metadata::SnapshotRow>> {
            self.inner.list_snapshots(v)
        }
    }

    #[test]
    fn batched_drain_publishes_the_whole_queue_in_one_cas() {
        let dir = tempfile::tempdir().unwrap();
        let blob: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let meta = Arc::new(CountingMeta {
            inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
            cas_calls: AtomicU64::new(0),
        });
        meta.create_volume(VOL, SIZE).unwrap();
        let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        let e = ChunkEngine::attach(cfg, blob.clone(), meta.clone()).unwrap();

        for i in 0..5u8 {
            e.write(i as u64 * CHUNK_SIZE as u64, &pattern(4096, i + 1))
                .unwrap();
            assert_eq!(e.flush().unwrap(), i as i64 + 1);
        }
        assert_eq!(e.generation(), 0, "five packs staged, none committed");
        let before = meta.cas_calls.load(Ordering::SeqCst);

        assert_eq!(e.drain_staged().unwrap(), 5, "head jumps one step per pack");
        assert_eq!(
            meta.cas_calls.load(Ordering::SeqCst) - before,
            1,
            "the whole batch publishes under a single swap"
        );
        e.detach().unwrap();

        // A fresh host sees every pack's content: the batch really committed.
        let mut cfg = EngineConfig::new(VOL, dir.path().join("data-b"), "attB");
        cfg.durability = DurabilityMode::Strict;
        let e = ChunkEngine::attach(cfg, blob, meta).unwrap();
        assert_eq!(e.generation(), 5);
        for i in 0..5u8 {
            let mut back = vec![0u8; 4096];
            e.read(i as u64 * CHUNK_SIZE as u64, &mut back).unwrap();
            assert_eq!(back, pattern(4096, i + 1), "chunk {i}");
        }
        e.detach().unwrap();
    }

    #[test]
    fn eager_committer_drains_a_burst_without_the_timer() {
        let env = env();
        let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attA");
        // An hour on the timer: only the eager kick can drain in test time.
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: 3_600_000,
        };
        let e = ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap();
        for i in 0..8u8 {
            e.write(i as u64 * CHUNK_SIZE as u64, &pattern(4096, i + 1))
                .unwrap();
            e.flush().unwrap();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while e.generation() < 8 {
            assert!(
                std::time::Instant::now() < deadline,
                "the eager kick never drained the queue: generation {}",
                e.generation()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        e.detach().unwrap();
    }

    /// The regression this branch exists to kill: a store with visible
    /// per-object latency must not turn an fsync burst into multi-second
    /// stalls once the staged queue crosses the backpressure cap.
    #[test]
    fn a_slow_store_burst_never_stalls_a_flush_for_long() {
        struct SlowBlob {
            inner: Arc<dyn BlobStore>,
        }
        impl BlobStore for SlowBlob {
            fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
                std::thread::sleep(Duration::from_millis(25));
                self.inner.put_immutable(k, d)
            }
            fn get(&self, k: &str) -> cats_storage::blob::Result<Vec<u8>> {
                self.inner.get(k)
            }
            fn exists(&self, k: &str) -> cats_storage::blob::Result<bool> {
                self.inner.exists(k)
            }
            fn delete(&self, k: &str) -> cats_storage::blob::Result<()> {
                self.inner.delete(k)
            }
            fn list(&self, p: &str) -> cats_storage::blob::Result<Vec<String>> {
                self.inner.list(p)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let blob: Arc<dyn BlobStore> = Arc::new(SlowBlob {
            inner: Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap()),
        });
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: 3_600_000,
        };
        let e = ChunkEngine::attach(cfg, blob, meta).unwrap();

        let mut lat_ms = Vec::new();
        for i in 0..24u32 {
            e.write((i as u64 % 8) * CHUNK_SIZE as u64, &pattern(4096, i as u8))
                .unwrap();
            let t0 = std::time::Instant::now();
            e.flush().unwrap();
            lat_ms.push(t0.elapsed().as_millis());
        }
        println!("slow-store burst flush latencies (ms): {lat_ms:?}");
        let max = lat_ms.iter().max().copied().unwrap_or(0);
        assert!(
            max < 300,
            "a flush stalled for {max} ms; a flush below the cap must never \
             touch the publish path"
        );
        e.detach().unwrap();
    }

    /// Once local admission is full, FLUSH may park, but only the named
    /// background thread may touch the remote store. This is the structural
    /// isolation that keeps a transient store error out of the Guest I/O path.
    #[test]
    fn backpressure_waits_for_the_background_publisher() {
        struct ThreadRecordingBlob {
            inner: Arc<dyn BlobStore>,
            put_threads: Mutex<Vec<String>>,
        }
        impl BlobStore for ThreadRecordingBlob {
            fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
                std::thread::sleep(Duration::from_millis(100));
                self.put_threads.lock().unwrap().push(
                    std::thread::current()
                        .name()
                        .unwrap_or("<unnamed>")
                        .to_string(),
                );
                self.inner.put_immutable(k, d)
            }
            fn get(&self, k: &str) -> cats_storage::blob::Result<Vec<u8>> {
                self.inner.get(k)
            }
            fn exists(&self, k: &str) -> cats_storage::blob::Result<bool> {
                self.inner.exists(k)
            }
            fn delete(&self, k: &str) -> cats_storage::blob::Result<()> {
                self.inner.delete(k)
            }
            fn list(&self, p: &str) -> cats_storage::blob::Result<Vec<String>> {
                self.inner.list(p)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let blob = Arc::new(ThreadRecordingBlob {
            inner: Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap()),
            put_threads: Mutex::new(Vec::new()),
        });
        let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: 50,
        };
        cfg.max_staged_packs = 1;
        let e = ChunkEngine::attach(cfg, blob.clone(), meta).unwrap();

        e.write(0, &pattern(4096, 1)).unwrap();
        assert_eq!(e.flush().unwrap(), 1);
        e.write(CHUNK_SIZE as u64, &pattern(4096, 2)).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(e.flush().unwrap(), 2);
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "the second FLUSH should have observed local admission pressure"
        );
        let threads = blob.put_threads.lock().unwrap().clone();
        assert!(!threads.is_empty());
        assert!(
            threads.iter().all(|name| name == "pack-committer"),
            "remote PUT escaped the background publisher: {threads:?}"
        );
        e.detach().unwrap();
    }

    #[test]
    fn provisioning_refuses_staged_commits() {
        let env = env();
        let e = attach_relaxed(&env, "attA");
        e.write(0, &pattern(4096, 3)).unwrap();
        e.flush().unwrap();
        let manifest = format::ImageManifest {
            version: 1,
            image_id: "0123456789abcdef0123456789abcdef".into(),
            size_bytes: SIZE,
            chunks: vec![],
        };
        let err = e.provision_from_image(&manifest).unwrap_err();
        assert!(
            err.to_string().contains("staged commits"),
            "unexpected error: {err}"
        );
        e.detach().unwrap();
    }

    #[test]
    fn multi_generation_overwrites_read_latest() {
        let env = env();
        {
            let e = attach(&env, "attA");
            e.write(100, &pattern(4096, 1)).unwrap();
            e.flush().unwrap();
            e.write(100, &pattern(4096, 2)).unwrap();
            e.write(CHUNK_SIZE as u64 + 7, b"second-chunk").unwrap();
            assert_eq!(e.flush().unwrap(), 2);
            e.detach().unwrap();
        }
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach(&env, "attB");
        let mut b = vec![0u8; 4096];
        e.read(100, &mut b).unwrap();
        assert_eq!(b, pattern(4096, 2));
        let mut s = vec![0u8; 12];
        e.read(CHUNK_SIZE as u64 + 7, &mut s).unwrap();
        assert_eq!(&s, b"second-chunk");
        e.detach().unwrap();
    }

    /// Object store whose reads are slower than the lease TTL, reproducing
    /// the 2026-07-29 production failure: a 60 GiB volume's attach (map load
    /// and recovery) took 1.9 s against a 1.5 s TTL, renewal only began after
    /// attach, so the first renewal always found the lease expired and every
    /// start of that Cat self-fenced before the Guest's first write.
    struct SlowBlob {
        inner: Arc<dyn BlobStore>,
        delay: std::time::Duration,
    }
    impl BlobStore for SlowBlob {
        fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
            self.inner.put_immutable(k, d)
        }
        fn get(&self, k: &str) -> cats_storage::blob::Result<Vec<u8>> {
            std::thread::sleep(self.delay);
            self.inner.get(k)
        }
        fn exists(&self, k: &str) -> cats_storage::blob::Result<bool> {
            self.inner.exists(k)
        }
        fn delete(&self, k: &str) -> cats_storage::blob::Result<()> {
            self.inner.delete(k)
        }
        fn list(&self, p: &str) -> cats_storage::blob::Result<Vec<String>> {
            self.inner.list(p)
        }
    }

    #[test]
    fn attach_slower_than_the_lease_ttl_does_not_self_fence() {
        let env = env();
        {
            let e = attach(&env, "attA");
            e.write(0, &pattern(CHUNK_SIZE as usize, 5)).unwrap();
            e.flush().unwrap();
            e.detach().unwrap();
        }
        // Cold host: the committed map must be read back through the store.
        fs::remove_dir_all(&env.data_dir).unwrap();
        let slow: Arc<dyn BlobStore> = Arc::new(SlowBlob {
            inner: env.blob.clone(),
            delay: std::time::Duration::from_millis(150),
        });
        let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attB");
        cfg.lease_ttl_ms = 100;
        let e = ChunkEngine::attach(cfg, slow, env.meta.clone()).unwrap();
        // Outlive several renewal intervals to prove the thread keeps the
        // lease alive rather than the attach merely squeaking through.
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(!e.is_fenced(), "an uncontended lapse must not fence");
        e.write(100, b"still writable").unwrap();
        e.flush().unwrap();
        e.detach().unwrap();
    }

    /// Counting wrapper to prove holes never hit the blobstore and that a
    /// relaxed ack publishes nothing.
    struct CountingBlob {
        inner: Arc<dyn BlobStore>,
        gets: AtomicU64,
        data_puts: AtomicU64,
    }
    impl BlobStore for CountingBlob {
        fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
            if k.contains("/data/") {
                self.data_puts.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.put_immutable(k, d)
        }
        fn get(&self, k: &str) -> cats_storage::blob::Result<Vec<u8>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(k)
        }
        fn exists(&self, k: &str) -> cats_storage::blob::Result<bool> {
            self.inner.exists(k)
        }
        fn delete(&self, k: &str) -> cats_storage::blob::Result<()> {
            self.inner.delete(k)
        }
        fn list(&self, p: &str) -> cats_storage::blob::Result<Vec<String>> {
            self.inner.list(p)
        }
    }

    /// Bytes a commit actually publishes, so a test can assert that a small Guest
    /// write does not turn into a 4 MiB upload.
    struct SizingBlob {
        inner: Arc<dyn BlobStore>,
        data_bytes: AtomicU64,
        data_objects: AtomicU64,
        image_bytes: AtomicU64,
    }
    impl BlobStore for SizingBlob {
        fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
            // Image objects also live under a `/data/` path, but they belong to the
            // image and are written once for the whole fleet, so a volume's cost has
            // to be counted separately from them.
            if k.starts_with("images/") && k.contains("/data/") {
                self.image_bytes.fetch_add(d.len() as u64, Ordering::SeqCst);
            } else if k.contains("/data/") {
                self.data_bytes.fetch_add(d.len() as u64, Ordering::SeqCst);
                self.data_objects.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.put_immutable(k, d)
        }
        fn get(&self, k: &str) -> cats_storage::blob::Result<Vec<u8>> {
            self.inner.get(k)
        }
        fn exists(&self, k: &str) -> cats_storage::blob::Result<bool> {
            self.inner.exists(k)
        }
        fn delete(&self, k: &str) -> cats_storage::blob::Result<()> {
            self.inner.delete(k)
        }
        fn list(&self, p: &str) -> cats_storage::blob::Result<Vec<String>> {
            self.inner.list(p)
        }
    }

    fn sizing_env() -> (Env, Arc<SizingBlob>) {
        let env = env();
        let sizing = Arc::new(SizingBlob {
            inner: env.blob.clone(),
            data_bytes: AtomicU64::new(0),
            data_objects: AtomicU64::new(0),
            image_bytes: AtomicU64::new(0),
        });
        (env, sizing)
    }

    fn attach_with(env: &Env, blob: Arc<dyn BlobStore>, attachment: &str) -> Arc<ChunkEngine> {
        ChunkEngine::attach(
            EngineConfig::new(VOL, &env.data_dir, attachment),
            blob,
            env.meta.clone(),
        )
        .unwrap()
    }

    const PAGE: u64 = cats_api::chunk::DIRTY_PAGE_SIZE as u64;

    /// A golden rootfs stand-in: distinct content per chunk, one all-zero chunk,
    /// and a tail shorter than a chunk — the shapes a real image has.
    fn golden_image(dir: &std::path::Path, chunks: u64) -> PathBuf {
        let path = dir.join(format!("golden-{chunks}.raw"));
        let mut f = File::create(&path).unwrap();
        for chunk in 0..chunks {
            let body = if chunk == 1 {
                vec![0u8; CHUNK_SIZE as usize]
            } else {
                pattern(CHUNK_SIZE as usize, chunk as u8 + 100)
            };
            f.write_all(&body).unwrap();
        }
        f.write_all(&pattern(4096, 42)).unwrap();
        f.sync_all().unwrap();
        path
    }

    #[test]
    fn a_volume_provisioned_from_an_image_publishes_no_data_of_its_own() {
        let (env, sizing) = sizing_env();
        let image = golden_image(env.data_dir.parent().unwrap(), 3);
        let published = crate::image::publish(sizing.as_ref(), &image).unwrap();
        // Chunk 1 was all zeros, so the image stored 2 chunks plus the padded tail.
        assert_eq!(published.manifest.chunks.len(), 3);
        let image_cost = sizing.image_bytes.load(Ordering::SeqCst);
        assert_eq!(image_cost, 3 * CHUNK_SIZE as u64);
        sizing.data_bytes.store(0, Ordering::SeqCst);
        sizing.data_objects.store(0, Ordering::SeqCst);
        sizing.image_bytes.store(0, Ordering::SeqCst);

        let e = attach_with(&env, sizing.clone(), "attA");
        let gen = e.provision_from_image(&published.manifest).unwrap();
        assert_eq!(gen, 1);

        // This is the whole point: a Cat's private cost for its root disk is zero
        // data objects, only map nodes.
        assert_eq!(sizing.data_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(sizing.data_objects.load(Ordering::SeqCst), 0);
        assert_eq!(sizing.image_bytes.load(Ordering::SeqCst), 0);

        // And a fresh host still reads the image content, chunk 1 as zeros and the
        // padded tail included.
        e.detach().unwrap();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        assert_eq!(e.generation(), 1);
        let raw = fs::read(&image).unwrap();
        let mut got = vec![0u8; raw.len()];
        e.read(0, &mut got).unwrap();
        assert_eq!(got, raw);
        let mut tail = vec![0xffu8; CHUNK_SIZE as usize - 4096];
        e.read(3 * CHUNK_SIZE as u64 + 4096, &mut tail).unwrap();
        assert!(
            tail.iter().all(|b| *b == 0),
            "padding past the image reads as zeros"
        );
    }

    #[test]
    fn writing_onto_a_provisioned_chunk_publishes_one_page_and_keeps_sharing_the_base() {
        let (env, sizing) = sizing_env();
        let image = golden_image(env.data_dir.parent().unwrap(), 3);
        let published = crate::image::publish(sizing.as_ref(), &image).unwrap();
        let e = attach_with(&env, sizing.clone(), "attA");
        e.provision_from_image(&published.manifest).unwrap();
        sizing.data_bytes.store(0, Ordering::SeqCst);
        sizing.image_bytes.store(0, Ordering::SeqCst);

        // One 4 KiB write into a shared chunk.
        let patch = pattern(4096, 7);
        e.write(0, &patch).unwrap();
        assert_eq!(e.flush().unwrap(), 2);

        // Delta packs and image sharing compose: the Cat publishes the 64 KiB page
        // it dirtied, not a 4 MiB private copy of the shared chunk.
        assert_eq!(sizing.data_bytes.load(Ordering::SeqCst), PAGE);
        assert_eq!(sizing.image_bytes.load(Ordering::SeqCst), 0);
        {
            let st = e.state.lock().unwrap();
            // The base is still the image's object — sharing did not erode.
            assert_eq!(
                st.map[0].image(),
                Some(published.manifest.image_id.as_str())
            );
            assert_eq!(st.map[0].layer_count(), 1, "one delta over the shared base");
            // An untouched chunk is still a plain reference into the image.
            assert_eq!(
                st.map[2].image(),
                Some(published.manifest.image_id.as_str())
            );
            assert_eq!(st.map[2].layer_count(), 0);
        }

        // The write wins over the image on the page it touched, and the rest of the
        // chunk still comes from the image, reassembled on a host with no cache.
        e.detach().unwrap();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let raw = fs::read(&image).unwrap();
        let mut got = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut got).unwrap();
        assert_eq!(&got[..4096], &patch[..]);
        assert_eq!(&got[4096..], &raw[4096..CHUNK_SIZE as usize]);
    }

    #[test]
    fn provisioning_refuses_to_run_over_a_volume_that_is_not_empty() {
        let env = env();
        let image = golden_image(env.data_dir.parent().unwrap(), 2);
        let published = crate::image::publish(env.blob.as_ref(), &image).unwrap();

        // Unflushed writes: the cache would disagree with the map being published.
        let e = attach(&env, "attA");
        e.write(0, &pattern(4096, 3)).unwrap();
        assert!(e.provision_from_image(&published.manifest).is_err());

        // Committed data: provisioning replaces the whole map, so this would be a
        // silent data loss rather than an error.
        e.flush().unwrap();
        assert!(e.provision_from_image(&published.manifest).is_err());
        let mut got = vec![0u8; 4096];
        e.read(0, &mut got).unwrap();
        assert_eq!(got, pattern(4096, 3));
    }

    #[test]
    fn an_image_larger_than_the_volume_is_refused_rather_than_truncated() {
        let env = env(); // 8 chunks
        let big = golden_image(env.data_dir.parent().unwrap(), 16);
        let published = crate::image::publish(env.blob.as_ref(), &big).unwrap();
        let e = attach(&env, "attA");
        // Silently dropping the tail would give the Guest a corrupt rootfs.
        assert!(e.provision_from_image(&published.manifest).is_err());
        assert_eq!(e.generation(), 0);
    }

    /// A blob store that measures how many uploads were in flight at once, and
    /// makes each one slow enough for overlap to be visible.
    struct ConcurrencyProbe {
        inner: Arc<dyn BlobStore>,
        in_flight: AtomicU64,
        peak: AtomicU64,
        data_puts: AtomicU64,
    }
    impl BlobStore for ConcurrencyProbe {
        fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
            if k.contains("/data/") {
                self.data_puts.fetch_add(1, Ordering::SeqCst);
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                // Stand in for a network round trip.
                std::thread::sleep(Duration::from_millis(20));
                let result = self.inner.put_immutable(k, d);
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                return result;
            }
            self.inner.put_immutable(k, d)
        }
        fn get(&self, k: &str) -> cats_storage::blob::Result<Vec<u8>> {
            if k.contains("/data/") {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                let result = self.inner.get(k);
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                return result;
            }
            self.inner.get(k)
        }
        fn exists(&self, k: &str) -> cats_storage::blob::Result<bool> {
            self.inner.exists(k)
        }
        fn delete(&self, k: &str) -> cats_storage::blob::Result<()> {
            self.inner.delete(k)
        }
        fn list(&self, p: &str) -> cats_storage::blob::Result<Vec<String>> {
            self.inner.list(p)
        }
    }

    #[test]
    fn a_commit_uploads_its_objects_concurrently() {
        // A commit's objects have distinct keys and no ordering between them, so
        // uploading them one round trip at a time is pure latency. On S3 that was
        // ~33 ms per object and most of a commit.
        let env = env();
        let probe = Arc::new(ConcurrencyProbe {
            inner: env.blob.clone(),
            in_flight: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            data_puts: AtomicU64::new(0),
        });
        let e = attach_with(&env, probe.clone(), "attA");
        let page = vec![0x33u8; PAGE as usize];
        for chunk in 0..8u64 {
            e.write(chunk * CHUNK_SIZE as u64, &page).unwrap();
        }
        assert_eq!(e.flush().unwrap(), 1);

        assert_eq!(probe.data_puts.load(Ordering::SeqCst), 8);
        // Peak concurrency, not wall clock: the whole suite runs in parallel, so a
        // latency bound here would measure the machine's load. Serial uploads peak
        // at exactly 1, which is the regression this catches.
        assert!(
            probe.peak.load(Ordering::SeqCst) >= 2,
            "uploads ran one at a time (peak in flight {})",
            probe.peak.load(Ordering::SeqCst)
        );
        assert_eq!(probe.in_flight.load(Ordering::SeqCst), 0, "a worker leaked");
        e.detach().unwrap();

        // The committed data is still readable from a cold cache, which is the
        // part concurrency could plausibly have broken.
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, probe.clone(), "attB");
        let mut back = vec![0u8; PAGE as usize];
        for chunk in 0..8u64 {
            e.read(chunk * CHUNK_SIZE as u64, &mut back).unwrap();
            assert_eq!(back, page, "chunk {chunk} came back wrong");
        }
        e.detach().unwrap();
    }

    #[test]
    fn a_cold_read_fetches_its_chunks_and_layers_concurrently() {
        // Reads had the same shape of problem the commit path did: one blocking
        // GET per object, none overlapping. A cold 64 MiB read off S3 ran at
        // 73 MiB/s on a 12.5 Gbps instance because of it.
        let env = env();
        let probe = Arc::new(ConcurrencyProbe {
            inner: env.blob.clone(),
            in_flight: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            data_puts: AtomicU64::new(0),
        });

        // Four chunks with a base plus two deltas each: 12 objects to fetch.
        let e = attach_with(&env, probe.clone(), "attA");
        let whole = pattern(CHUNK_SIZE as usize, 5);
        for chunk in 0..4u64 {
            e.write(chunk * CHUNK_SIZE as u64, &whole).unwrap();
        }
        e.flush().unwrap();
        // Distinct pages per round, so the chain is genuinely two deltas deep: a
        // delta that fully rewrote the previous one would replace it instead.
        for round in 0..2u64 {
            for chunk in 0..4u64 {
                e.write(
                    chunk * CHUNK_SIZE as u64 + round * PAGE,
                    &pattern(4096, round as u8 + 20),
                )
                .unwrap();
            }
            e.flush().unwrap();
        }
        {
            let st = e.state.lock().unwrap();
            assert_eq!(st.map[0].layer_count(), 2, "expected a base plus 2 deltas");
        }
        e.detach().unwrap();

        // A brand-new host: every one of those objects has to come back.
        fs::remove_dir_all(&env.data_dir).unwrap();
        probe.peak.store(0, Ordering::SeqCst);
        let e = attach_with(&env, probe.clone(), "attB");
        let mut back = vec![0u8; 4 * CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();

        assert!(
            probe.peak.load(Ordering::SeqCst) >= 2,
            "cold read fetched one object at a time (peak in flight {})",
            probe.peak.load(Ordering::SeqCst)
        );
        assert_eq!(probe.in_flight.load(Ordering::SeqCst), 0, "a fetch leaked");
        // Concurrency must not change what comes back: each round's write wins on
        // the page it touched, the base shows through everywhere else.
        for chunk in 0..4usize {
            let at = chunk * CHUNK_SIZE as usize;
            assert_eq!(
                &back[at..at + 4096],
                &pattern(4096, 20)[..],
                "chunk {chunk}"
            );
            let second = at + PAGE as usize;
            assert_eq!(&back[second..second + 4096], &pattern(4096, 21)[..]);
            assert_eq!(&back[at + 4096..second], &whole[4096..PAGE as usize]);
        }
        e.detach().unwrap();
    }

    #[test]
    fn gc_keeps_every_layer_of_a_live_chain_and_drops_superseded_objects() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");

        // Chunk 0: a base, then two deltas on different pages -- all three live.
        let whole = pattern(CHUNK_SIZE as usize, 4);
        e.write(0, &whole).unwrap();
        e.flush().unwrap();
        for round in 0..2u64 {
            e.write(round * PAGE, &pattern(4096, round as u8 + 30))
                .unwrap();
            e.flush().unwrap();
        }
        // Chunk 1: written twice densely, so the first base is superseded.
        e.write(CHUNK_SIZE as u64, &pattern(CHUNK_SIZE as usize, 6))
            .unwrap();
        e.flush().unwrap();
        e.write(CHUNK_SIZE as u64, &pattern(CHUNK_SIZE as usize, 7))
            .unwrap();
        e.flush().unwrap();

        let before = env.blob.list("volumes/vol_test/data/").unwrap().len();
        let stats = e.collect_garbage().unwrap();
        let after = env.blob.list("volumes/vol_test/data/").unwrap().len();

        // Live: chunk 0's base + 2 deltas, chunk 1's second base. Dead: chunk 1's
        // first base. A GC that only kept the newest object per chunk would have
        // deleted chunk 0's base and its first delta and corrupted the volume.
        assert_eq!(stats.data_objects_live, 4);
        assert_eq!(stats.data_objects_deleted, 1);
        assert_eq!(after, before - 1);
        assert!(stats.map_nodes_deleted > 0, "superseded map nodes survived");

        // The volume still reads correctly from a host with nothing cached.
        e.detach().unwrap();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let mut back = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(&back[..4096], &pattern(4096, 30)[..]);
        assert_eq!(
            &back[PAGE as usize..PAGE as usize + 4096],
            &pattern(4096, 31)[..]
        );
        assert_eq!(&back[4096..PAGE as usize], &whole[4096..PAGE as usize]);
        e.read(CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, pattern(CHUNK_SIZE as usize, 7));
        e.detach().unwrap();
    }

    #[test]
    fn gc_never_deletes_a_shared_image_even_though_the_volume_references_it() {
        let (env, sizing) = sizing_env();
        let image = golden_image(env.data_dir.parent().unwrap(), 3);
        let published = crate::image::publish(sizing.as_ref(), &image).unwrap();
        let image_keys = env
            .blob
            .list(&format!("images/{}/", published.manifest.image_id))
            .unwrap();
        assert!(!image_keys.is_empty());

        let e = attach_with(&env, sizing.clone(), "attA");
        e.provision_from_image(&published.manifest).unwrap();
        // One page written onto a shared chunk: that delta is this volume's and
        // must survive; the image base underneath it is not ours to delete.
        e.write(0, &pattern(4096, 9)).unwrap();
        e.flush().unwrap();

        let stats = e.collect_garbage().unwrap();
        assert_eq!(
            stats.data_objects_live, 1,
            "only the volume's own delta is a volume object"
        );
        assert_eq!(stats.data_objects_deleted, 0);
        assert_eq!(
            env.blob
                .list(&format!("images/{}/", published.manifest.image_id))
                .unwrap(),
            image_keys,
            "GC touched the shared image"
        );

        // And the volume still reassembles from image base + local delta.
        e.detach().unwrap();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let raw = fs::read(&image).unwrap();
        let mut back = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(&back[..4096], &pattern(4096, 9)[..]);
        assert_eq!(&back[4096..], &raw[4096..CHUNK_SIZE as usize]);
        e.detach().unwrap();
    }

    #[test]
    fn gc_on_an_untouched_volume_deletes_nothing() {
        let env = env();
        let e = attach(&env, "attA");
        e.write(0, &pattern(4096, 1)).unwrap();
        e.flush().unwrap();
        let first = e.collect_garbage().unwrap();
        assert_eq!(first.data_objects_deleted, 0);
        // Idempotent: a second pass finds nothing new.
        let second = e.collect_garbage().unwrap();
        assert_eq!(second, first);
        e.detach().unwrap();
    }

    #[test]
    fn discarding_whole_chunks_frees_their_objects_instead_of_publishing_zeros() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");
        let whole = pattern(CHUNK_SIZE as usize, 8);
        for chunk in 0..3u64 {
            e.write(chunk * CHUNK_SIZE as u64, &whole).unwrap();
        }
        assert_eq!(e.flush().unwrap(), 1);
        assert_eq!(
            sizing.data_bytes.load(Ordering::SeqCst),
            3 * CHUNK_SIZE as u64
        );
        sizing.data_bytes.store(0, Ordering::SeqCst);

        // Discard chunks 1 and 2 in full.
        e.write_zeroes(CHUNK_SIZE as u64, 2 * CHUNK_SIZE as u64)
            .unwrap();
        assert_eq!(e.flush().unwrap(), 2);

        // Nothing was published for them: writing 8 MiB of zeros would have been
        // the old behaviour, and would also have kept the old objects alive.
        assert_eq!(sizing.data_bytes.load(Ordering::SeqCst), 0);
        {
            let st = e.state.lock().unwrap();
            assert!(matches!(st.map[0], ChunkRef::Base(_)), "chunk 0 untouched");
            assert!(matches!(st.map[1], ChunkRef::Hole));
            assert!(matches!(st.map[2], ChunkRef::Hole));
        }

        // And GC can now take what they used to reference.
        let stats = e.collect_garbage().unwrap();
        assert_eq!(stats.data_objects_live, 1);
        assert_eq!(stats.data_objects_deleted, 2);

        // The Guest sees zeros, from a host with nothing cached.
        e.detach().unwrap();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let mut back = vec![0xffu8; CHUNK_SIZE as usize];
        e.read(CHUNK_SIZE as u64, &mut back).unwrap();
        assert!(
            back.iter().all(|b| *b == 0),
            "discarded chunk must read zero"
        );
        e.read(0, &mut back).unwrap();
        assert_eq!(
            back, whole,
            "an untouched chunk must survive a neighbour's discard"
        );
        e.detach().unwrap();
    }

    #[test]
    fn a_partial_discard_writes_zeros_and_a_later_write_cancels_a_discard() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");
        let whole = pattern(CHUNK_SIZE as usize, 9);
        e.write(0, &whole).unwrap();
        e.flush().unwrap();
        sizing.data_bytes.store(0, Ordering::SeqCst);

        // Not chunk-aligned: only the covered pages are zeroed, and the chunk
        // stays a real object because most of it still holds data.
        e.write_zeroes(PAGE, PAGE).unwrap();
        e.flush().unwrap();
        assert_eq!(sizing.data_bytes.load(Ordering::SeqCst), PAGE);
        {
            let st = e.state.lock().unwrap();
            assert!(!matches!(st.map[0], ChunkRef::Hole));
        }
        let mut back = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(&back[..PAGE as usize], &whole[..PAGE as usize]);
        assert!(back[PAGE as usize..2 * PAGE as usize]
            .iter()
            .all(|b| *b == 0));

        // A write after a discard, before the commit, must win: the chunk is real
        // data again, not a hole.
        e.write_zeroes(0, CHUNK_SIZE as u64).unwrap();
        let patch = pattern(4096, 3);
        e.write(0, &patch).unwrap();
        e.flush().unwrap();
        {
            let st = e.state.lock().unwrap();
            assert!(
                !matches!(st.map[0], ChunkRef::Hole),
                "a write after a discard was lost"
            );
        }
        e.detach().unwrap();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let mut back = vec![0xffu8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(&back[..4096], &patch[..]);
        assert!(
            back[4096..].iter().all(|b| *b == 0),
            "the discard still applied"
        );
        e.detach().unwrap();
    }

    #[test]
    fn the_gc_thread_sweeps_on_its_own_and_does_not_delay_detach() {
        let env = env();
        let e = attach(&env, "attA");
        // Two dense generations of one chunk: the first object becomes garbage.
        e.write(0, &pattern(CHUNK_SIZE as usize, 1)).unwrap();
        e.flush().unwrap();
        e.write(0, &pattern(CHUNK_SIZE as usize, 2)).unwrap();
        e.flush().unwrap();
        assert_eq!(env.blob.list("volumes/vol_test/data/").unwrap().len(), 2);

        e.start_gc_thread(Duration::from_millis(50));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while env.blob.list("volumes/vol_test/data/").unwrap().len() > 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "gc thread never swept"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        // And it must not hold up a stop, the way lease renewal used to.
        let started = std::time::Instant::now();
        e.detach().unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "detach waited {:?} on the gc thread",
            started.elapsed()
        );
    }

    #[test]
    fn a_sparse_write_publishes_only_its_dirty_pages() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");
        // One 4 KiB write in each of three chunks: three dirty 64 KiB pages, not
        // three 4 MiB chunks.
        for chunk in 0..3u64 {
            e.write(chunk * CHUNK_SIZE as u64, &pattern(4096, chunk as u8 + 1))
                .unwrap();
        }
        assert_eq!(e.flush().unwrap(), 1);

        assert_eq!(
            sizing.data_bytes.load(Ordering::SeqCst),
            3 * PAGE,
            "a commit must publish dirty pages, not whole chunks"
        );
        assert_eq!(sizing.data_objects.load(Ordering::SeqCst), 3);
        let st = e.state.lock().unwrap();
        for chunk in 0..3usize {
            match &st.map[chunk] {
                ChunkRef::Layered { base, deltas } => {
                    assert!(base.is_none(), "chunk {chunk} had no committed base yet");
                    assert_eq!(deltas.len(), 1);
                    assert_eq!(deltas[0].page_mask, 1, "only the first page is dirty");
                }
                other => panic!("chunk {chunk} should be layered, got {other:?}"),
            }
        }
        drop(st);
        e.detach().unwrap();
    }

    #[test]
    fn a_dense_write_publishes_a_full_base() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");
        // More than half the chunk: a delta would save little and resetting the
        // chain is worth more than the bytes.
        e.write(0, &pattern(CHUNK_SIZE as usize / 2 + 1, 3))
            .unwrap();
        e.flush().unwrap();
        assert_eq!(
            sizing.data_bytes.load(Ordering::SeqCst),
            CHUNK_SIZE as u64,
            "a dense write should publish one full chunk"
        );
        let st = e.state.lock().unwrap();
        assert!(matches!(st.map[0], ChunkRef::Base(_)));
        drop(st);
        e.detach().unwrap();
    }

    #[test]
    fn delta_chains_are_capped_by_a_base_rewrite() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");
        // Each commit dirties one page of chunk 0, so each adds a layer until the
        // cap forces a fresh base.
        for round in 0..=MAX_DELTA_LAYERS {
            e.write(round as u64 * PAGE, &pattern(4096, round as u8))
                .unwrap();
            e.flush().unwrap();
            let st = e.state.lock().unwrap();
            let layers = st.map[0].layer_count();
            if round < MAX_DELTA_LAYERS {
                assert_eq!(layers, round + 1, "round {round} should add a layer");
            } else {
                assert_eq!(
                    layers, 0,
                    "the commit past the cap must publish a fresh base instead"
                );
                assert!(matches!(st.map[0], ChunkRef::Base(_)));
            }
        }
        // Cheap for the first four commits, one full chunk for the rewrite.
        assert_eq!(
            sizing.data_bytes.load(Ordering::SeqCst),
            MAX_DELTA_LAYERS as u64 * PAGE + CHUNK_SIZE as u64
        );
        e.detach().unwrap();
    }

    #[test]
    fn layered_chunks_reassemble_after_the_cache_is_wiped() {
        let env = env();
        let e = attach(&env, "attA");
        // Build a chunk out of a base plus several deltas on different pages,
        // including one page written twice so a later delta has to win.
        e.write(0, &pattern(CHUNK_SIZE as usize, 9)).unwrap(); // dense -> base
        e.flush().unwrap();
        let mut expected = pattern(CHUNK_SIZE as usize, 9);
        for (round, page) in [1u64, 5, 5, 63].into_iter().enumerate() {
            let data = pattern(4096, 100 + round as u8);
            e.write(page * PAGE, &data).unwrap();
            expected[(page * PAGE) as usize..(page * PAGE) as usize + data.len()]
                .copy_from_slice(&data);
            e.flush().unwrap();
        }
        {
            let st = e.state.lock().unwrap();
            assert!(
                st.map[0].layer_count() > 1,
                "the chunk should be layered for this test to mean anything"
            );
        }
        e.detach().unwrap();

        // Fresh host, empty cache: everything has to come back from the objects.
        let restored = attach_at(&env, "attB", "data-host-b");
        let mut got = vec![0u8; CHUNK_SIZE as usize];
        restored.read(0, &mut got).unwrap();
        assert_eq!(got, expected, "layered reassembly must be byte-exact");
        restored.detach().unwrap();
    }

    #[test]
    fn hole_reads_do_not_touch_the_blobstore() {
        let env = env();
        {
            let e = attach(&env, "attA");
            e.write(0, &pattern(4096, 5)).unwrap();
            e.flush().unwrap();
            e.detach().unwrap();
        }
        fs::remove_dir_all(&env.data_dir).unwrap();
        let counting = Arc::new(CountingBlob {
            inner: env.blob.clone(),
            gets: AtomicU64::new(0),
            data_puts: AtomicU64::new(0),
        });
        let e = ChunkEngine::attach(
            EngineConfig::new(VOL, &env.data_dir, "attB"),
            counting.clone(),
            env.meta.clone(),
        )
        .unwrap();
        let after_attach = counting.gets.load(Ordering::SeqCst); // root + leaf loads
        let mut z = vec![1u8; 4096];
        e.read(6 * CHUNK_SIZE as u64, &mut z).unwrap();
        assert!(z.iter().all(|&b| b == 0));
        assert_eq!(
            counting.gets.load(Ordering::SeqCst),
            after_attach,
            "hole read must not GET"
        );
        // Reading committed data hydrates exactly once.
        let mut b = vec![0u8; 4096];
        e.read(0, &mut b).unwrap();
        e.read(0, &mut b).unwrap();
        assert_eq!(counting.gets.load(Ordering::SeqCst), after_attach + 1);
        e.detach().unwrap();
    }

    #[test]
    fn stale_writer_is_fenced_and_cannot_commit() {
        let env = env();
        let e1 = attach(&env, "attA");
        e1.write(0, &pattern(1024, 1)).unwrap();
        // Control plane fences the volume (host presumed lost).
        env.meta.revoke_lease(VOL).unwrap();
        let err = e1.flush().unwrap_err();
        assert!(
            matches!(err, EngineError::Meta(_)),
            "flush must fail after revoke: {err}"
        );
        assert!(e1.is_fenced());
        assert!(matches!(e1.write(0, b"x"), Err(EngineError::Fenced)));
        // The new attachment lands on a fresh host and takes over from the
        // last committed state (the fenced writer's un-acked flush is gone).
        let e2 = attach_at(&env, "attB", "data-host-b");
        assert_eq!(e2.generation(), 0);
        e2.write(0, &pattern(1024, 2)).unwrap();
        assert_eq!(e2.flush().unwrap(), 1);
        e2.detach().unwrap();
        assert!(matches!(e1.detach(), Err(EngineError::Fenced)));
    }

    #[test]
    fn failed_upload_leaves_pack_and_recovery_replays_it() {
        use cats_storage::blob::FaultyBlobStore;
        let env = env();
        let faulty = Arc::new(FaultyBlobStore::new(env.blob.clone()));
        let data = pattern(2048, 7);
        {
            let e = ChunkEngine::attach(
                EngineConfig::new(VOL, &env.data_dir, "attA"),
                faulty.clone(),
                env.meta.clone(),
            )
            .unwrap();
            e.write(0, &data).unwrap();
            faulty.fail_puts.store(1, Ordering::SeqCst);
            assert!(e.flush().is_err());
            // Pack file remains for recovery.
            let pending: Vec<_> = fs::read_dir(env.data_dir.join("pending"))
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            assert_eq!(pending.len(), 1);
            e.detach().unwrap();
        }
        // Reattach with a healthy store: recovery replays the pack.
        let e = attach(&env, "attB");
        assert_eq!(e.generation(), 1, "recovery must replay the pending pack");
        assert!(fs::read_dir(env.data_dir.join("pending"))
            .unwrap()
            .next()
            .is_none());
        let mut b = vec![0u8; 2048];
        e.read(0, &mut b).unwrap();
        assert_eq!(b, data);
        // And the replayed state survives a cache wipe.
        e.detach().unwrap();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach(&env, "attC");
        let mut b = vec![0u8; 2048];
        e.read(0, &mut b).unwrap();
        assert_eq!(b, data);
        e.detach().unwrap();
    }

    #[test]
    fn write_zeroes_marks_dirty_and_commits_zeros() {
        let env = env();
        {
            let e = attach(&env, "attA");
            e.write(0, &pattern(8192, 1)).unwrap();
            e.flush().unwrap();
            e.write_zeroes(0, 8192).unwrap();
            e.flush().unwrap();
            e.detach().unwrap();
        }
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach(&env, "attB");
        let mut b = vec![1u8; 8192];
        e.read(0, &mut b).unwrap();
        assert!(b.iter().all(|&x| x == 0));
        e.detach().unwrap();
    }

    #[test]
    fn detaching_does_not_wait_out_the_lease_renewal_interval() {
        // A stop, a suspend and a cold migration all detach. Joining a thread that
        // is sleeping out ttl/3 put that whole interval on the critical path of
        // every one of them, per volume.
        let env = env();
        let e = ChunkEngine::attach(
            EngineConfig {
                volume_id: VOL.into(),
                data_dir: env.data_dir.clone(),
                attachment_id: "attDetach".into(),
                lease_ttl_ms: 6_000,
                durability: DurabilityMode::Strict,
                max_staged_bytes: DEFAULT_MAX_STAGED_BYTES,
                max_staged_packs: DEFAULT_MAX_STAGED_PACKS,
                max_local_bytes: DEFAULT_MAX_LOCAL_BYTES,
            },
            env.blob.clone(),
            env.meta.clone(),
        )
        .unwrap();
        let started = std::time::Instant::now();
        e.detach().unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "detach waited {elapsed:?} on a 6 s lease (renewal interval is 2 s)"
        );
        // And the lease really was released: the next attachment gets it at once.
        let next = attach(&env, "attDetach2");
        assert!(next.epoch() > e.epoch());
        next.detach().unwrap();
    }

    #[test]
    fn snapshot_captures_generation() {
        let env = env();
        let e = attach(&env, "attA");
        e.write(0, &pattern(512, 1)).unwrap();
        e.flush().unwrap();
        let snap = env.meta.create_snapshot("snap_1", VOL).unwrap();
        assert_eq!(snap.generation, 1);
        e.detach().unwrap();
    }
}

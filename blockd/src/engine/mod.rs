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

pub use cats_api::blockd::{
    DurabilityStatus, DEFAULT_MAX_LOCAL_BYTES, DEFAULT_MAX_STAGED_BYTES, DEFAULT_MAX_STAGED_PACKS,
};
use cats_api::chunk::{self, CHUNKS_PER_LEAF, CHUNK_SIZE};

use crate::crashpoint;
use crate::format::{
    self, ChunkRef, LeafRef, PackByteRange, PackEntry, PackHeader, BITMAP_HEADER_LEN,
};
use cats_storage::{BlobError, BlobStore, MetaError, MetadataStore};

mod gc;
mod hydrate;
mod lease;
mod pack;
mod plan;
mod publish;
mod quota;
mod recovery;
mod status;

pub use gc::GcStats;
use pack::{apply_local_entry, merge_dirty_range, DirtyByteRange, StagedPack, StagedQueue};
use plan::{commit_workers, copy_planned_pages, plan_commit, ChunkPlan};
use publish::{CommitterSignal, EAGER_DRAIN_WATERMARK, MAX_UPLOAD_CONCURRENCY};
use quota::{pack_reservation_upper, punch_hole};
pub use status::DurabilityMode;

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

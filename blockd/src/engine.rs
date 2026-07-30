//! The ChunkStore block engine (spec §5/§6).
//!
//! One engine instance serves exactly one volume under exactly one lease
//! epoch. Local state (cache, dirty bitmap, pending packs) is deletable;
//! everything acknowledged through FLUSH is reconstructible from the
//! BlobStore + MetadataStore alone.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use cats_api::chunk::{self, CHUNKS_PER_LEAF, CHUNK_SIZE};

use crate::crashpoint;
use crate::format::{self, ChunkRef, LeafRef, PackEntry, PackHeader, BITMAP_HEADER_LEN};
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

/// What one garbage-collection pass found and removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcStats {
    pub data_objects_live: usize,
    pub data_objects_deleted: usize,
    pub map_nodes_live: usize,
    pub map_nodes_deleted: usize,
}

/// When a FLUSH acknowledgment is allowed to reach the Guest (ADR-0021).
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
    /// host (pack replay), but not the loss of the host. The loss window is
    /// bounded by the drain interval plus the staged backlog.
    ///
    /// `drain_interval_ms == 0` disables the background committer entirely
    /// (drains still happen on backpressure, detach and demand) — a
    /// deterministic mode for tests.
    Relaxed { drain_interval_ms: u64 },
}

/// Staged packs a relaxed volume may accumulate before FLUSH stops acking
/// locally. Past the cap a FLUSH waits for the committer to pop a batch
/// (bounded by one publish round) — or drains inline when no committer runs —
/// so an object-store outage degrades latency instead of growing the loss
/// window. Batched publishing keeps a drain round flat-cost, which is what
/// lets the cap sit this high.
pub const MAX_STAGED_PACKS: usize = 64;

/// Queue depth past which a relaxed stage kicks the committer instead of
/// letting packs sit until the timer. Above one so the single-pack case (an
/// idle volume's periodic journal commit) still batches with whatever the
/// next few milliseconds bring, and low enough that a burst starts draining
/// long before the `MAX_STAGED_PACKS` backpressure cap is in sight.
const EAGER_DRAIN_WATERMARK: usize = 2;

/// Payload bytes one drain batch may hold in memory at once. A batch of
/// sparse packs is far below this; a run of dense 4 MiB-base commits gets
/// split into successive batches instead of pulling gigabytes into RAM.
const MAX_BATCH_BYTES: usize = 256 << 20;

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
        }
    }
}

struct EngineState {
    /// Volatile dirty bitmap; one u64 word per chunk (64 x 64KiB pages).
    dirty: Vec<u64>,
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
    /// Chunks currently being hydrated (singleflight).
    hydrating: HashSet<u64>,
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
}

/// Packs staged locally but not yet published to the object store.
struct StagedQueue {
    packs: std::collections::VecDeque<StagedPack>,
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
                map: vec![ChunkRef::Hole; chunk_count as usize],
                leaf_refs: vec![LeafRef::Empty; chunk::leaf_count(size) as usize],
                generation: 0,
                discarded: HashSet::new(),
                hydrated: vec![false; chunk_count as usize],
                hydrating: HashSet::new(),
            }),
            hydration_cv: Condvar::new(),
            io_gate: RwLock::new(()),
            flush_lock: Mutex::new(()),
            publish_lock: Mutex::new(()),
            staged_space: Condvar::new(),
            staged: Mutex::new(StagedQueue {
                packs: std::collections::VecDeque::new(),
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
        // Recovery published or discarded every pending pack, so the staged
        // chain restarts at the committed generation.
        engine.staged.lock().unwrap().next_base = engine.generation();
        if engine.is_fenced() {
            // The lease was revoked or taken while recovery ran. Serving the
            // Guest read-only from here would end at its first write with an
            // I/O error it cannot interpret; fail the attach with the reason.
            engine.stop_renewal();
            return Err(EngineError::Meta(MetaError::Fenced));
        }
        engine.start_committer_thread();
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
            manifest
                .base_map(self.size)
                .map_err(|_| EngineError::Corrupt(format!(
                    "image {} does not fit volume {} of {} bytes",
                    manifest.image_id, self.cfg.volume_id, self.size
                )))?
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
        let first = offset / CHUNK_SIZE as u64;
        let last = (offset + buf.len() as u64 - 1) / CHUNK_SIZE as u64;
        self.hydrate_range(first, last)?;
        self.cache.read_exact_at(buf, offset)?;
        Ok(())
    }

    pub fn write(&self, offset: u64, data: &[u8]) -> Result<()> {
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        self.check_bounds(offset, data.len() as u64)?;
        if data.is_empty() {
            return Ok(());
        }
        let _gate = self.io_gate.read().unwrap();
        let first_chunk = offset / CHUNK_SIZE as u64;
        let last_chunk = (offset + data.len() as u64 - 1) / CHUNK_SIZE as u64;
        self.hydrate_range(first_chunk, last_chunk)?;
        self.cache.write_all_at(data, offset)?;
        self.mark_dirty(offset, data.len() as u64)?;
        Ok(())
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
        let _gate = self.io_gate.read().unwrap();
        let chunk = CHUNK_SIZE as u64;
        let zeros = vec![0u8; CHUNK_SIZE as usize];
        for chunk_idx in first..last {
            self.cache.write_all_at(&zeros, chunk_idx * chunk)?;
        }
        let mut st = self.state.lock().unwrap();
        let bitmap = self.bitmap.lock().unwrap();
        for chunk_idx in first..last {
            // A discard supersedes any uncommitted write to the same chunk.
            st.dirty[chunk_idx as usize] = 0;
            bitmap.write_all_at(&0u64.to_le_bytes(), BITMAP_HEADER_LEN + chunk_idx * 8)?;
            st.discarded.insert(chunk_idx);
            st.hydrated[chunk_idx as usize] = true;
        }
        bitmap.sync_data()?;
        Ok(())
    }

    /// FLUSH (spec §6): freeze the dirty set into a staged pack, then publish
    /// according to the durability mode (ADR-0021).
    ///
    /// Strict: returns only after this pack — and anything staged before it —
    /// is committed to the object store; the acknowledgment IS the durability
    /// point. Relaxed: returns once the pack is durable on local disk and
    /// leaves publishing to the background committer, unless the backlog has
    /// hit `MAX_STAGED_PACKS`, in which case it drains inline so an object
    /// store outage degrades latency instead of growing the loss window.
    ///
    /// Returns the generation the acknowledged state is (or, staged, will be)
    /// committed at.
    pub fn flush(&self) -> Result<i64> {
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        let backlog = {
            let _flush = self.flush_lock.lock().unwrap();
            self.stage_pack()?;
            self.staged.lock().unwrap().packs.len()
        };
        match self.cfg.durability {
            DurabilityMode::Strict => self.drain_staged(),
            DurabilityMode::Relaxed { drain_interval_ms }
                if backlog > MAX_STAGED_PACKS && drain_interval_ms > 0 =>
            {
                // Parked, not conscripted: joining the drain itself would put
                // this FLUSH in a publish_lock convoy behind every other
                // capped FLUSH — the exact pathology sustained fsync load
                // showed in production (fsync floor rose to a full publish
                // round, p90 to several).
                self.wait_for_staging_space()?;
                Ok(self.staged.lock().unwrap().next_base)
            }
            DurabilityMode::Relaxed { .. } if backlog > MAX_STAGED_PACKS => self.drain_staged(),
            DurabilityMode::Relaxed { .. } => Ok(self.staged.lock().unwrap().next_base),
        }
    }

    /// A FLUSH past the backpressure cap parks here until the committer pops
    /// a batch, so it stalls for at most about one publish round. Falls back
    /// to an inline drain if no room appears — a wedged committer (store
    /// outage) must not park guest FLUSHes forever.
    fn wait_for_staging_space(&self) -> Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut staged = self.staged.lock().unwrap();
        while staged.packs.len() > MAX_STAGED_PACKS {
            self.kick_committer();
            if std::time::Instant::now() >= deadline {
                drop(staged);
                self.drain_staged()?;
                return Ok(());
            }
            let (guard, _timeout) = self
                .staged_space
                .wait_timeout(staged, Duration::from_millis(100))
                .unwrap();
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
        let (plans, base_generation, payload) = {
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
            for &(c, _) in &dirty {
                st.dirty[c as usize] = 0;
            }
            st.discarded.clear();
            // Plans are made against the committed map even when packs are
            // staged ahead of this one. A stale view can only misjudge a
            // chunk's delta-chain length (a chunk written across many staged
            // packs grows past MAX_DELTA_LAYERS until its next base rewrite);
            // it cannot affect correctness, because deltas apply in pack
            // order at publish either way.
            let base_map = st.map.clone();
            let base_generation = self.staged.lock().unwrap().next_base;
            drop(st);

            let plans = plan_commit(&dirty, &base_map, &discarded);
            let bytes: usize = plans.iter().map(|p| p.len()).sum();
            // One allocation for the whole pack: `vec![0u8; n]` for a large `n`
            // comes from fresh zero pages, while an allocation per chunk charged
            // a page-fault storm to the barrier.
            let mut payload = vec![0u8; bytes];
            copy_planned_pages(&self.cache, &plans, &mut payload)?;
            (plans, base_generation, payload)
        };

        // Barrier released: hash the frozen bytes and describe the pack.
        let entries = describe_pack(&plans, &payload);

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
        self.write_pack_file(&header, &payload)?;
        {
            let mut staged = self.staged.lock().unwrap();
            staged.packs.push_back(StagedPack {
                txn: txn.clone(),
                path: self.pack_path(base_generation, &txn),
            });
            staged.next_base += 1;
            let backlog = staged.packs.len();
            drop(staged);
            if backlog > EAGER_DRAIN_WATERMARK {
                // A burst is forming: drain continuously instead of letting
                // the queue climb toward the backpressure cap on the timer.
                self.kick_committer();
            }
        }
        crashpoint::maybe_crash(crashpoint::AFTER_PACK);
        Ok(())
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
                    self.finish_committed_pack(header)?;
                }
                let mut staged = self.staged.lock().unwrap();
                for _ in 0..decoded.len() {
                    staged.packs.pop_front();
                }
                drop(staged);
                // Room just opened up: wake any FLUSH parked on the cap.
                self.staged_space.notify_all();
                Ok(false)
            }
            Err(e) => {
                if matches!(e, EngineError::Meta(MetaError::CasConflict { .. }))
                    || matches!(e, EngineError::Meta(MetaError::Fenced))
                {
                    self.fenced.store(true, Ordering::SeqCst);
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
            for (header, _) in packs {
                for e in &header.entries {
                    // The frozen image is the committed base; cache holds it.
                    st.hydrated[e.chunk_idx as usize] = true;
                }
            }
        }
        Ok(new_gen)
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

    fn write_pack_file(&self, header: &PackHeader, payload: &[u8]) -> Result<()> {
        let encoded = format::encode_pack(header, payload);
        let dir = self.cfg.data_dir.join("pending");
        let tmp = dir.join(format!(".tmp-{}", header.txn));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&encoded)?;
            f.sync_data()?;
        }
        fs::rename(&tmp, self.pack_path(header.base_generation, &header.txn))?;
        File::open(&dir)?.sync_all()?;
        Ok(())
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
                let chunk_ref = st.map[chunk_idx as usize].clone();
                if chunk_ref.is_hole() {
                    // Sparse cache file already reads as zeros.
                    st.hydrated[chunk_idx as usize] = true;
                    return Ok(());
                }
                if st.hydrating.contains(&chunk_idx) {
                    let _unused = self
                        .hydration_cv
                        .wait(st)
                        .map_err(|_| EngineError::Corrupt("poisoned lock".into()))?;
                    continue;
                }
                st.hydrating.insert(chunk_idx);
                chunk_ref
            };
            let result = self.hydrate_chunk(chunk_idx, &chunk_ref);
            let mut st = self.state.lock().unwrap();
            st.hydrating.remove(&chunk_idx);
            if result.is_ok() {
                st.hydrated[chunk_idx as usize] = true;
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

    /// Materialize one chunk into the local cache from its committed objects.
    ///
    /// A layered chunk is assembled base-first and then delta by delta, so a
    /// later delta overwrites an earlier one on any page they share. The result
    /// is written as one full chunk so nothing stale can survive underneath it —
    /// which matters because the cache file outlives an attachment.
    fn hydrate_chunk(&self, chunk_idx: u64, chunk_ref: &ChunkRef) -> Result<()> {
        let page = cats_api::chunk::DIRTY_PAGE_SIZE as usize;
        let image = match chunk_ref {
            ChunkRef::Hole => return Ok(()),
            ChunkRef::Base(base) => {
                self.fetch_verified(&base.object_id, base.len, base.sha256, base.image.as_deref())?
            }
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
        self.cache
            .write_all_at(&image, chunk_idx * CHUNK_SIZE as u64)?;
        Ok(())
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
            let mask = if st.discarded.remove(&chunk_idx) {
                format::full_page_mask()
            } else {
                mask
            };
            let word = &mut st.dirty[chunk_idx as usize];
            if *word | mask != *word {
                *word |= mask;
                changed.push(chunk_idx);
            }
            pos += span as u64;
        }
        if !changed.is_empty() {
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
                    // the next tick (or the next kick) retries. FLUSH drains
                    // inline once the backlog cap is hit, so the window stays
                    // bounded even if this keeps failing.
                    tracing::warn!(volume = %engine.cfg.volume_id, "background drain failed: {e}");
                }
            })
            .expect("spawn pack committer thread");
        *self.committer_thread.lock().unwrap() = Some(handle);
    }

    /// Graceful detach: publishes anything still staged (a forced flush point
    /// of the relaxed contract, ADR-0021), then releases the lease unless this
    /// attachment has been fenced.
    ///
    /// If the final drain fails the lease is released anyway: holding it
    /// hostage to a store outage would trade the documented relaxed loss
    /// window for unavailability. The staged packs stay on disk, so a
    /// same-host reattach still replays them.
    pub fn detach(&self) {
        if !self.is_fenced() {
            if let Err(e) = self.drain_staged() {
                tracing::error!(
                    volume = %self.cfg.volume_id,
                    "final drain on detach failed; staged packs remain on disk: {e}"
                );
            }
        }
        self.stop_renewal();
        if !self.is_fenced() {
            let _ =
                self.meta
                    .release_lease(&self.cfg.volume_id, &self.cfg.attachment_id, self.epoch);
        }
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
        e.detach();
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
            e.detach();
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
        e.detach();
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

        // An empty flush with a staged backlog still acks the same target.
        assert_eq!(e.flush().unwrap(), 1);

        assert_eq!(e.drain_staged().unwrap(), 1);
        assert!(counting.data_puts.load(Ordering::SeqCst) > 0);
        assert_eq!(e.generation(), 1);
        e.detach();
    }

    #[test]
    fn staged_packs_replay_in_order_after_a_crash() {
        let env = env();
        {
            let e = attach_relaxed(&env, "attA");
            e.write(100, &pattern(4096, 1)).unwrap();
            assert_eq!(e.flush().unwrap(), 1);
            // Overwrite the same pages in a second staged pack: replay order
            // becomes observable in the final bytes.
            e.write(100, &pattern(4096, 2)).unwrap();
            e.write(CHUNK_SIZE as u64 + 7, b"second-chunk").unwrap();
            assert_eq!(e.flush().unwrap(), 2);
            assert_eq!(e.generation(), 0, "both packs staged, none committed");
            // Crash: drop without detach. Drop stops threads but must not
            // drain — draining here would hide recovery bugs. The local state
            // survives as a whole (cache, bitmap and pending packs are one
            // deletable unit; a pack replay reads the frozen bytes from the
            // pack but trusts the cache for everything it re-marks hydrated).
        }
        let e = attach(&env, "attA");
        assert_eq!(e.generation(), 2, "recovery replayed the staged chain");
        let mut b = vec![0u8; 4096];
        e.read(100, &mut b).unwrap();
        assert_eq!(b, pattern(4096, 2), "the later staged pack wins");
        let mut s = vec![0u8; 12];
        e.read(CHUNK_SIZE as u64 + 7, &mut s).unwrap();
        assert_eq!(&s, b"second-chunk");
        e.detach();
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
            e.detach();
        }
        // A different host with nothing local sees the detach-drained state.
        let e = attach_at(&env, "attB", "data-b");
        assert_eq!(e.generation(), 1);
        let mut back = vec![0u8; 4096];
        e.read(2 * CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, data);
        e.detach();
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
        fn load_head(&self, v: &str) -> cats_storage::metadata::Result<cats_storage::metadata::VolumeHead> {
            self.inner.load_head(v)
        }
        fn delete_volume(&self, v: &str) -> cats_storage::metadata::Result<()> {
            self.inner.delete_volume(v)
        }
        fn resize_volume(&self, v: &str, s: u64) -> cats_storage::metadata::Result<()> {
            self.inner.resize_volume(v, s)
        }
        fn acquire_lease(
            &self,
            v: &str,
            a: &str,
            ttl: i64,
        ) -> cats_storage::metadata::Result<i64> {
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
        e.detach();

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
        e.detach();
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
        e.detach();
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
        e.detach();
    }

    /// Sustained fsync load past the cap: the production regression had every
    /// FLUSH join a publish_lock convoy (fsync floor = one full publish round,
    /// p90 = several). A capped FLUSH must now park for about one batch round.
    #[test]
    fn a_capped_flush_parks_for_one_round_instead_of_joining_a_convoy() {
        struct SlowBlob {
            inner: Arc<dyn BlobStore>,
        }
        impl BlobStore for SlowBlob {
            fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
                std::thread::sleep(Duration::from_millis(100));
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
        for i in 0..80u32 {
            e.write((i as u64 % 8) * CHUNK_SIZE as u64, &pattern(4096, i as u8))
                .unwrap();
            let t0 = std::time::Instant::now();
            e.flush().unwrap();
            lat_ms.push(t0.elapsed().as_millis());
        }
        let max = lat_ms.iter().max().copied().unwrap_or(0);
        println!("capped burst: max flush {max} ms, tail {:?}", &lat_ms[64..]);
        assert!(
            max < 3_000,
            "a capped flush stalled {max} ms; parking should bound it near one \
             batch round"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while e.generation() < 80 {
            assert!(
                std::time::Instant::now() < deadline,
                "committer never converged: generation {}",
                e.generation()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        e.detach();
    }

    #[test]
    fn cap_overflow_without_a_committer_still_drains_inline() {
        let env = env();
        let e = attach_relaxed(&env, "attA");
        for i in 0..70u32 {
            e.write((i as u64 % 8) * CHUNK_SIZE as u64, &pattern(4096, i as u8))
                .unwrap();
            e.flush().unwrap();
        }
        // Flushes past the cap fell back to inline batched drains (interval 0
        // means no committer to park behind), and nothing was lost.
        assert_eq!(e.drain_staged().unwrap(), 70);
        let mut back = vec![0u8; 4096];
        e.read((69 % 8) * CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, pattern(4096, 69));
        e.detach();
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
        e.detach();
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
            e.detach();
        }
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach(&env, "attB");
        let mut b = vec![0u8; 4096];
        e.read(100, &mut b).unwrap();
        assert_eq!(b, pattern(4096, 2));
        let mut s = vec![0u8; 12];
        e.read(CHUNK_SIZE as u64 + 7, &mut s).unwrap();
        assert_eq!(&s, b"second-chunk");
        e.detach();
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
            e.detach();
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
        e.detach();
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
        e.detach();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        assert_eq!(e.generation(), 1);
        let raw = fs::read(&image).unwrap();
        let mut got = vec![0u8; raw.len()];
        e.read(0, &mut got).unwrap();
        assert_eq!(got, raw);
        let mut tail = vec![0xffu8; CHUNK_SIZE as usize - 4096];
        e.read(3 * CHUNK_SIZE as u64 + 4096, &mut tail).unwrap();
        assert!(tail.iter().all(|b| *b == 0), "padding past the image reads as zeros");
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
            assert_eq!(st.map[0].image(), Some(published.manifest.image_id.as_str()));
            assert_eq!(st.map[0].layer_count(), 1, "one delta over the shared base");
            // An untouched chunk is still a plain reference into the image.
            assert_eq!(st.map[2].image(), Some(published.manifest.image_id.as_str()));
            assert_eq!(st.map[2].layer_count(), 0);
        }

        // The write wins over the image on the page it touched, and the rest of the
        // chunk still comes from the image, reassembled on a host with no cache.
        e.detach();
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
        e.detach();

        // The committed data is still readable from a cold cache, which is the
        // part concurrency could plausibly have broken.
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, probe.clone(), "attB");
        let mut back = vec![0u8; PAGE as usize];
        for chunk in 0..8u64 {
            e.read(chunk * CHUNK_SIZE as u64, &mut back).unwrap();
            assert_eq!(back, page, "chunk {chunk} came back wrong");
        }
        e.detach();
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
        e.detach();

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
            assert_eq!(&back[at..at + 4096], &pattern(4096, 20)[..], "chunk {chunk}");
            let second = at + PAGE as usize;
            assert_eq!(&back[second..second + 4096], &pattern(4096, 21)[..]);
            assert_eq!(&back[at + 4096..second], &whole[4096..PAGE as usize]);
        }
        e.detach();
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
            e.write(round * PAGE, &pattern(4096, round as u8 + 30)).unwrap();
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
        e.detach();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let mut back = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(&back[..4096], &pattern(4096, 30)[..]);
        assert_eq!(&back[PAGE as usize..PAGE as usize + 4096], &pattern(4096, 31)[..]);
        assert_eq!(&back[4096..PAGE as usize], &whole[4096..PAGE as usize]);
        e.read(CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, pattern(CHUNK_SIZE as usize, 7));
        e.detach();
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
        e.detach();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let raw = fs::read(&image).unwrap();
        let mut back = vec![0u8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(&back[..4096], &pattern(4096, 9)[..]);
        assert_eq!(&back[4096..], &raw[4096..CHUNK_SIZE as usize]);
        e.detach();
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
        e.detach();
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
        assert_eq!(sizing.data_bytes.load(Ordering::SeqCst), 3 * CHUNK_SIZE as u64);
        sizing.data_bytes.store(0, Ordering::SeqCst);

        // Discard chunks 1 and 2 in full.
        e.write_zeroes(CHUNK_SIZE as u64, 2 * CHUNK_SIZE as u64).unwrap();
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
        e.detach();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let mut back = vec![0xffu8; CHUNK_SIZE as usize];
        e.read(CHUNK_SIZE as u64, &mut back).unwrap();
        assert!(back.iter().all(|b| *b == 0), "discarded chunk must read zero");
        e.read(0, &mut back).unwrap();
        assert_eq!(back, whole, "an untouched chunk must survive a neighbour's discard");
        e.detach();
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
        assert!(back[PAGE as usize..2 * PAGE as usize].iter().all(|b| *b == 0));

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
        e.detach();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach_with(&env, sizing.clone(), "attB");
        let mut back = vec![0xffu8; CHUNK_SIZE as usize];
        e.read(0, &mut back).unwrap();
        assert_eq!(&back[..4096], &patch[..]);
        assert!(back[4096..].iter().all(|b| *b == 0), "the discard still applied");
        e.detach();
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
            assert!(std::time::Instant::now() < deadline, "gc thread never swept");
            std::thread::sleep(Duration::from_millis(20));
        }

        // And it must not hold up a stop, the way lease renewal used to.
        let started = std::time::Instant::now();
        e.detach();
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
        e.detach();
    }

    #[test]
    fn a_dense_write_publishes_a_full_base() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");
        // More than half the chunk: a delta would save little and resetting the
        // chain is worth more than the bytes.
        e.write(0, &pattern(CHUNK_SIZE as usize / 2 + 1, 3)).unwrap();
        e.flush().unwrap();
        assert_eq!(
            sizing.data_bytes.load(Ordering::SeqCst),
            CHUNK_SIZE as u64,
            "a dense write should publish one full chunk"
        );
        let st = e.state.lock().unwrap();
        assert!(matches!(st.map[0], ChunkRef::Base(_)));
        drop(st);
        e.detach();
    }

    #[test]
    fn delta_chains_are_capped_by_a_base_rewrite() {
        let (env, sizing) = sizing_env();
        let e = attach_with(&env, sizing.clone(), "attA");
        // Each commit dirties one page of chunk 0, so each adds a layer until the
        // cap forces a fresh base.
        for round in 0..=MAX_DELTA_LAYERS {
            e.write(round as u64 * PAGE, &pattern(4096, round as u8)).unwrap();
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
        e.detach();
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
        e.detach();

        // Fresh host, empty cache: everything has to come back from the objects.
        let restored = attach_at(&env, "attB", "data-host-b");
        let mut got = vec![0u8; CHUNK_SIZE as usize];
        restored.read(0, &mut got).unwrap();
        assert_eq!(got, expected, "layered reassembly must be byte-exact");
        restored.detach();
    }

    #[test]
    fn hole_reads_do_not_touch_the_blobstore() {
        let env = env();
        {
            let e = attach(&env, "attA");
            e.write(0, &pattern(4096, 5)).unwrap();
            e.flush().unwrap();
            e.detach();
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
        e.detach();
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
        e2.detach();
        e1.detach();
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
            e.detach();
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
        e.detach();
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach(&env, "attC");
        let mut b = vec![0u8; 2048];
        e.read(0, &mut b).unwrap();
        assert_eq!(b, data);
        e.detach();
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
            e.detach();
        }
        fs::remove_dir_all(&env.data_dir).unwrap();
        let e = attach(&env, "attB");
        let mut b = vec![1u8; 8192];
        e.read(0, &mut b).unwrap();
        assert!(b.iter().all(|&x| x == 0));
        e.detach();
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
            },
            env.blob.clone(),
            env.meta.clone(),
        )
        .unwrap();
        let started = std::time::Instant::now();
        e.detach();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "detach waited {elapsed:?} on a 6 s lease (renewal interval is 2 s)"
        );
        // And the lease really was released: the next attachment gets it at once.
        let next = attach(&env, "attDetach2");
        assert!(next.epoch() > e.epoch());
        next.detach();
    }

    #[test]
    fn snapshot_captures_generation() {
        let env = env();
        let e = attach(&env, "attA");
        e.write(0, &pattern(512, 1)).unwrap();
        e.flush().unwrap();
        let snap = env.meta.create_snapshot("snap_1", VOL).unwrap();
        assert_eq!(snap.generation, 1);
        e.detach();
    }
}

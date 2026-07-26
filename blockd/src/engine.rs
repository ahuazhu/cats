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

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub volume_id: String,
    pub data_dir: PathBuf,
    pub attachment_id: String,
    pub lease_ttl_ms: i64,
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
            lease_ttl_ms: 5_000,
        }
    }
}

struct EngineState {
    /// Volatile dirty bitmap; one u64 word per chunk (64 x 64KiB pages).
    dirty: Vec<u64>,
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
    fenced: AtomicBool,
    epoch: i64,
    stop_renew: Arc<AtomicBool>,
    renew_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl ChunkEngine {
    /// Attach to a volume: acquire the lease (bumping the fencing epoch),
    /// recover pending packs, load the committed map, start lease renewal.
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
                hydrated: vec![false; chunk_count as usize],
                hydrating: HashSet::new(),
            }),
            hydration_cv: Condvar::new(),
            io_gate: RwLock::new(()),
            flush_lock: Mutex::new(()),
            fenced: AtomicBool::new(false),
            epoch,
            stop_renew: Arc::new(AtomicBool::new(false)),
            renew_thread: Mutex::new(None),
            cfg,
        });

        engine.load_committed_map()?;
        engine.recover_pending_packs()?;
        engine.start_renew_thread();
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

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check_bounds(offset, buf.len() as u64)?;
        let mut chunk_idx = offset / CHUNK_SIZE as u64;
        let end = offset + buf.len() as u64;
        while chunk_idx * (CHUNK_SIZE as u64) < end {
            self.ensure_cache_complete(chunk_idx)?;
            chunk_idx += 1;
        }
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
        for c in first_chunk..=last_chunk {
            self.ensure_cache_complete(c)?;
        }
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
        const ZBUF: usize = 1 << 20;
        let zeros = vec![0u8; ZBUF.min(len as usize).max(1)];
        let mut done = 0u64;
        while done < len {
            let step = ZBUF.min((len - done) as usize);
            self.write(offset + done, &zeros[..step])?;
            done += step as u64;
        }
        Ok(())
    }

    /// Durable FLUSH: freeze the dirty set, publish a new generation
    /// (spec §6), return the committed generation.
    pub fn flush(&self) -> Result<i64> {
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        let _flush = self.flush_lock.lock().unwrap();

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
        let (plans, base_generation, base_map, base_leaves, payload) = {
            let _barrier = self.io_gate.write().unwrap();
            let mut st = self.state.lock().unwrap();
            let dirty: Vec<(u64, u64)> = (0..self.chunk_count)
                .filter(|&c| st.dirty[c as usize] != 0)
                .map(|c| (c, st.dirty[c as usize]))
                .collect();
            if dirty.is_empty() {
                return Ok(st.generation);
            }
            for &(c, _) in &dirty {
                st.dirty[c as usize] = 0;
            }
            let base_generation = st.generation;
            let base_map = st.map.clone();
            let base_leaves = st.leaf_refs.clone();
            drop(st);

            let plans = plan_commit(&dirty, &base_map);
            let bytes: usize = plans.iter().map(|p| p.len()).sum();
            // One allocation for the whole pack: `vec![0u8; n]` for a large `n`
            // comes from fresh zero pages, while an allocation per chunk charged
            // a page-fault storm to the barrier.
            let mut payload = vec![0u8; bytes];
            copy_planned_pages(&self.cache, &plans, &mut payload)?;
            (plans, base_generation, base_map, base_leaves, payload)
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
        crashpoint::maybe_crash(crashpoint::AFTER_PACK);

        let committed = self.commit_pack(&header, &payload, base_map, base_leaves);
        match committed {
            Ok(gen) => {
                self.finish_committed_pack(&header)?;
                Ok(gen)
            }
            Err(e) => {
                // The pack stays behind for recovery; volatile dirty bits for
                // the frozen set were cleared, but the persistent bitmap still
                // has them, so a restart cannot lose the data.
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

    fn commit_pack(
        &self,
        header: &PackHeader,
        payload: &[u8],
        base_map: Vec<ChunkRef>,
        base_leaves: Vec<LeafRef>,
    ) -> Result<i64> {
        let vol = &self.cfg.volume_id;

        // 1. Data objects (idempotent keys derived from txn).
        for e in &header.entries {
            let bytes =
                &payload[e.payload_offset as usize..e.payload_offset as usize + e.len as usize];
            let object_id = Self::object_id(&header.txn, e);
            self.blob
                .put_immutable(&chunk::keys::data(vol, &object_id), bytes)?;
        }
        crashpoint::maybe_crash(crashpoint::AFTER_DATA_UPLOAD);

        // 2. New map: a base entry replaces the chunk's reference outright, a
        //    delta entry appends a layer to whatever the chunk already had.
        let mut new_map = base_map;
        for e in &header.entries {
            let sha: [u8; 32] = hex::decode(&e.sha256_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| EngineError::Corrupt("bad sha in pack".into()))?;
            let object_id = Self::object_id(&header.txn, e);
            let slot = &mut new_map[e.chunk_idx as usize];
            *slot = if e.is_base() {
                ChunkRef::Base {
                    object_id,
                    len: e.len,
                    sha256: sha,
                }
            } else {
                slot.clone().with_delta(format::DeltaRef {
                    object_id,
                    page_mask: e.page_mask,
                    len: e.len,
                    sha256: sha,
                })
            };
        }

        // 3. Re-encode only the touched leaves.
        let mut new_leaves = base_leaves;
        let mut touched: Vec<u64> = header
            .entries
            .iter()
            .map(|e| e.chunk_idx / CHUNKS_PER_LEAF as u64)
            .collect();
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

        // 4. Root node + commit record.
        let root_encoded = format::encode_root(self.size, &new_leaves);
        let root_hash = format::sha256(&root_encoded);
        let root_hex = hex::encode(root_hash);
        let root_object_id = format!("{root_hex}.node");
        self.blob
            .put_immutable(&chunk::keys::map_node(vol, &root_hex), &root_encoded)?;
        let record = serde_json::json!({
            "txn": header.txn,
            "generation": header.base_generation + 1,
            "root_hash": root_hex,
            "lease_epoch": header.lease_epoch,
            "chunks": header.entries.iter().map(|e| e.chunk_idx).collect::<Vec<_>>(),
        });
        self.blob.put_immutable(
            &chunk::keys::commit_record(vol, header.base_generation + 1, &header.txn),
            record.to_string().as_bytes(),
        )?;
        crashpoint::maybe_crash(crashpoint::BEFORE_CAS);

        // 5. Root CAS — the durability point.
        let new_gen = self.meta.cas_head(
            vol,
            header.base_generation,
            root_hash,
            &root_object_id,
            &self.cfg.attachment_id,
            self.epoch,
        )?;
        crashpoint::maybe_crash(crashpoint::AFTER_CAS);

        // 6. Swap in the committed map.
        {
            let mut st = self.state.lock().unwrap();
            st.map = new_map;
            st.leaf_refs = new_leaves;
            st.generation = new_gen;
            for e in &header.entries {
                // The frozen image is the committed base; cache holds it.
                st.hydrated[e.chunk_idx as usize] = true;
            }
        }
        Ok(new_gen)
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
        let path = self.pack_path(&header.txn);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn pack_path(&self, txn: &str) -> PathBuf {
        self.cfg
            .data_dir
            .join("pending")
            .join(format!("{txn}.pack"))
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
        fs::rename(&tmp, self.pack_path(&header.txn))?;
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
    fn fetch_verified(&self, object_id: &str, len: u32, sha: [u8; 32]) -> Result<Vec<u8>> {
        let key = chunk::keys::data(&self.cfg.volume_id, object_id);
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
            ChunkRef::Base {
                object_id,
                len,
                sha256,
            } => self.fetch_verified(object_id, *len, *sha256)?,
            ChunkRef::Layered { base, deltas } => {
                let mut image = match base {
                    Some(base) => {
                        self.fetch_verified(&base.object_id, base.len, base.sha256)?
                    }
                    None => vec![0u8; CHUNK_SIZE as usize],
                };
                if image.len() != CHUNK_SIZE as usize {
                    return Err(EngineError::Corrupt(
                        "layered chunk base is not a full chunk".into(),
                    ));
                }
                for delta in deltas {
                    let bytes =
                        self.fetch_verified(&delta.object_id, delta.len, delta.sha256)?;
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

    fn start_renew_thread(self: &Arc<Self>) {
        let engine = Arc::downgrade(self);
        let stop = self.stop_renew.clone();
        let interval = Duration::from_millis((self.cfg.lease_ttl_ms / 3).max(50) as u64);
        let handle = std::thread::Builder::new()
            .name("lease-renew".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let Some(engine) = engine.upgrade() else {
                    return;
                };
                if engine.is_fenced() {
                    return;
                }
                if let Err(e) = engine.meta.renew_lease(
                    &engine.cfg.volume_id,
                    &engine.cfg.attachment_id,
                    engine.epoch,
                    engine.cfg.lease_ttl_ms,
                ) {
                    tracing::error!("lease renewal failed; fencing writes: {e}");
                    engine.fenced.store(true, Ordering::SeqCst);
                    return;
                }
            })
            .expect("spawn lease renew thread");
        *self.renew_thread.lock().unwrap() = Some(handle);
    }

    /// Graceful detach: callers should `flush()` first. Releases the lease
    /// unless this attachment has been fenced.
    pub fn detach(&self) {
        self.stop_renew.store(true, Ordering::SeqCst);
        if let Some(h) = self.renew_thread.lock().unwrap().take() {
            let _ = h.join();
        }
        if !self.is_fenced() {
            let _ =
                self.meta
                    .release_lease(&self.cfg.volume_id, &self.cfg.attachment_id, self.epoch);
        }
    }
}

impl Drop for ChunkEngine {
    fn drop(&mut self) {
        self.stop_renew.store(true, Ordering::SeqCst);
        if let Some(h) = self.renew_thread.lock().unwrap().take() {
            let _ = h.join();
        }
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
fn plan_commit(dirty: &[(u64, u64)], base_map: &[ChunkRef]) -> Vec<ChunkPlan> {
    let pages_per_chunk = cats_api::chunk::PAGES_PER_CHUNK;
    dirty
        .iter()
        .map(|&(chunk_idx, mask)| {
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
        })
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

    /// Counting wrapper to prove holes never hit the blobstore.
    struct CountingBlob {
        inner: Arc<dyn BlobStore>,
        gets: AtomicU64,
    }
    impl BlobStore for CountingBlob {
        fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
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
    }
    impl BlobStore for SizingBlob {
        fn put_immutable(&self, k: &str, d: &[u8]) -> cats_storage::blob::Result<()> {
            if k.contains("/data/") {
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
        assert!(matches!(st.map[0], ChunkRef::Base { .. }));
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
                assert!(matches!(st.map[0], ChunkRef::Base { .. }));
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

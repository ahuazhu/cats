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

use crate::blobstore::{BlobError, BlobStore};
use crate::crashpoint;
use crate::format::{self, ChunkRef, LeafRef, PackEntry, PackHeader, BITMAP_HEADER_LEN};
use crate::meta::{MetaError, MetadataStore};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("i/o out of bounds: offset {offset} len {len} volume size {size}")]
    OutOfBounds { offset: u64, len: u64, size: u64 },
    #[error("attachment is fenced; refusing writes")]
    Fenced,
    #[error("volume corrupt: {0}")]
    Corrupt(String),
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
        let (frozen, base_generation, base_map, base_leaves, payload, entries) = {
            let _barrier = self.io_gate.write().unwrap();
            let mut st = self.state.lock().unwrap();
            let frozen: Vec<u64> = (0..self.chunk_count)
                .filter(|&c| st.dirty[c as usize] != 0)
                .collect();
            if frozen.is_empty() {
                return Ok(st.generation);
            }
            for &c in &frozen {
                st.dirty[c as usize] = 0;
            }
            let base_generation = st.generation;
            let base_map = st.map.clone();
            let base_leaves = st.leaf_refs.clone();
            drop(st);

            // Copy the frozen chunk images while writers are blocked so the
            // pack is a consistent point-in-time barrier image.
            let mut payload = Vec::with_capacity(frozen.len() * CHUNK_SIZE as usize);
            let mut entries = Vec::with_capacity(frozen.len());
            for &c in &frozen {
                let mut chunk_bytes = vec![0u8; CHUNK_SIZE as usize];
                self.cache
                    .read_exact_at(&mut chunk_bytes, c * CHUNK_SIZE as u64)?;
                let sha = format::sha256(&chunk_bytes);
                entries.push(PackEntry {
                    chunk_idx: c,
                    payload_offset: payload.len() as u64,
                    len: CHUNK_SIZE,
                    sha256_hex: hex::encode(sha),
                });
                payload.extend_from_slice(&chunk_bytes);
            }
            (
                frozen,
                base_generation,
                base_map,
                base_leaves,
                payload,
                entries,
            )
        };
        let _ = frozen;

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

    fn data_object_id(txn: &str, chunk_idx: u64) -> String {
        format!("{txn}-c{chunk_idx}")
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
            let object_id = Self::data_object_id(&header.txn, e.chunk_idx);
            self.blob
                .put_immutable(&chunk::keys::data(vol, &object_id), bytes)?;
        }
        crashpoint::maybe_crash(crashpoint::AFTER_DATA_UPLOAD);

        // 2. New map: apply frozen refs onto the base map.
        let mut new_map = base_map;
        for e in &header.entries {
            let sha: [u8; 32] = hex::decode(&e.sha256_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| EngineError::Corrupt("bad sha in pack".into()))?;
            new_map[e.chunk_idx as usize] = ChunkRef::Base {
                object_id: Self::data_object_id(&header.txn, e.chunk_idx),
                len: e.len,
                sha256: sha,
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
            let base = {
                let mut st = self.state.lock().unwrap();
                if st.hydrated[chunk_idx as usize] {
                    return Ok(());
                }
                let chunk_ref = st.map[chunk_idx as usize].clone();
                match chunk_ref {
                    ChunkRef::Hole => {
                        // Sparse cache file already reads as zeros.
                        st.hydrated[chunk_idx as usize] = true;
                        return Ok(());
                    }
                    ChunkRef::Base {
                        object_id,
                        len,
                        sha256,
                    } => {
                        if st.hydrating.contains(&chunk_idx) {
                            let _unused = self
                                .hydration_cv
                                .wait(st)
                                .map_err(|_| EngineError::Corrupt("poisoned lock".into()))?;
                            continue;
                        }
                        st.hydrating.insert(chunk_idx);
                        (object_id, len, sha256)
                    }
                }
            };
            let (object_id, len, sha) = base;
            let result = self.hydrate_chunk(chunk_idx, &object_id, len, sha);
            let mut st = self.state.lock().unwrap();
            st.hydrating.remove(&chunk_idx);
            if result.is_ok() {
                st.hydrated[chunk_idx as usize] = true;
            }
            self.hydration_cv.notify_all();
            return result;
        }
    }

    fn hydrate_chunk(
        &self,
        chunk_idx: u64,
        object_id: &str,
        len: u32,
        sha: [u8; 32],
    ) -> Result<()> {
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
        self.cache
            .write_all_at(&bytes, chunk_idx * CHUNK_SIZE as u64)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobstore::FileBlobStore;
    use crate::meta::SqliteMeta;
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
        let meta = Arc::new(SqliteMeta::open(&dir.path().join("meta.db")).unwrap());
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
        fn put_immutable(&self, k: &str, d: &[u8]) -> crate::blobstore::Result<()> {
            self.inner.put_immutable(k, d)
        }
        fn get(&self, k: &str) -> crate::blobstore::Result<Vec<u8>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(k)
        }
        fn exists(&self, k: &str) -> crate::blobstore::Result<bool> {
            self.inner.exists(k)
        }
        fn delete(&self, k: &str) -> crate::blobstore::Result<()> {
            self.inner.delete(k)
        }
        fn list(&self, p: &str) -> crate::blobstore::Result<Vec<String>> {
            self.inner.list(p)
        }
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
        use crate::blobstore::FaultyBlobStore;
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

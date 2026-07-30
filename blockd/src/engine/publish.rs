use super::*;

/// Queue depth past which a relaxed stage kicks the committer instead of
/// letting packs sit until the timer. Above one so the single-pack case (an
/// idle volume's periodic journal commit) still batches with whatever the
/// next few milliseconds bring, and low enough that a burst starts draining
/// long before the configured backpressure cap is in sight.
pub(super) const EAGER_DRAIN_WATERMARK: usize = 2;

/// Payload bytes one drain batch may hold in memory at once. A batch of
/// sparse packs is far below this; a run of dense 4 MiB-base commits gets
/// split into successive batches instead of pulling gigabytes into RAM.
const MAX_BATCH_BYTES: usize = 256 << 20;

/// What wakes the background committer.
pub(super) struct CommitterSignal {
    pub(super) stop: bool,
    pub(super) kick: bool,
}

/// How many objects a commit uploads at once.
///
/// Not derived from the core count the way `commit_workers` is: this work is a
/// blocked socket, not a busy CPU, so the useful number is set by the object
/// store's round-trip time and its per-connection throughput rather than by the
/// machine. Sixteen keeps a remote store's pipe full without turning a large
/// commit into hundreds of concurrent connections.
pub(super) const MAX_UPLOAD_CONCURRENCY: usize = 16;

fn upload_workers(objects: usize) -> usize {
    objects.clamp(1, MAX_UPLOAD_CONCURRENCY)
}

impl ChunkEngine {
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
    pub(super) fn drain_one_batch(&self) -> Result<bool> {
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
    pub(super) fn object_id(txn: &str, entry: &PackEntry) -> String {
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
    pub(super) fn publish_map(
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
    pub(super) fn upload_batch(&self, packs: &[(&PackHeader, &[u8])]) -> Result<()> {
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

    pub(super) fn commit_pack(
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
    pub(super) fn commit_pack_batch(
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
    pub(super) fn materialize_overlay_batch(
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
    pub(super) fn apply_pack_entries(map: &mut [ChunkRef], header: &PackHeader) -> Result<()> {
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
    pub(super) fn finish_committed_pack(&self, header: &PackHeader) -> Result<()> {
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

    /// Relaxed mode only: publish staged packs on a timer. Shares the
    /// stop/wake condvar with lease renewal so detach interrupts the wait
    /// instead of sleeping it out.
    pub(super) fn start_committer_thread(self: &Arc<Self>) {
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
}

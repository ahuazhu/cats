use super::*;

impl ChunkEngine {
    /// Freeze the dirty set and write it as a pending pack on local disk.
    /// No-op on a clean volume. Caller holds `flush_lock`.
    pub(super) fn stage_pack(&self) -> Result<()> {
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
                st.freezing.extend(plans.iter().map(|plan| plan.chunk_idx));
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

    pub(super) fn restore_frozen_plans(
        &self,
        plans: &[ChunkPlan],
        frozen_ranges: &[Vec<DirtyByteRange>],
    ) {
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

    pub(super) fn unfreeze_plans(&self, plans: &[ChunkPlan]) {
        let mut st = self.state.lock().unwrap();
        for plan in plans {
            st.freezing.remove(&plan.chunk_idx);
        }
        drop(st);
        self.hydration_cv.notify_all();
    }

    /// The base-generation prefix makes lexicographic order equal generation
    /// order, which recovery relies on to replay a staged chain (relaxed mode
    /// leaves several pending packs behind; spec §6.1 replays them sorted).
    pub(super) fn pack_path(&self, base_generation: i64, txn: &str) -> PathBuf {
        self.cfg
            .data_dir
            .join(PENDING_PACK_DIR)
            .join(format!("{base_generation:020}-{txn}{PACK_FILE_SUFFIX}"))
    }

    pub(super) fn write_pack_file(&self, header: &PackHeader, payload: &[u8]) -> Result<u64> {
        let encoded = format::encode_pack(header, payload);
        let encoded_bytes = encoded.len() as u64;
        let dir = self.cfg.data_dir.join(PENDING_PACK_DIR);
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DirtyByteRange {
    pub(super) start: u32,
    pub(super) end: u32,
}

impl DirtyByteRange {
    pub(super) fn len(self) -> usize {
        (self.end - self.start) as usize
    }
}

pub(super) fn merge_dirty_range(ranges: &mut Vec<DirtyByteRange>, mut new_range: DirtyByteRange) {
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

pub(super) fn apply_publishable_entry(
    image: &mut [u8],
    entry: &PackEntry,
    payload: &[u8],
) -> Result<()> {
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

pub(super) fn apply_local_entry(image: &mut [u8], entry: &PackEntry, payload: &[u8]) -> Result<()> {
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

/// Packs staged locally but not yet published to the object store.
pub(super) struct StagedQueue {
    pub(super) packs: std::collections::VecDeque<StagedPack>,
    pub(super) bytes: u64,
    /// Base generation the next staged pack chains onto: the committed
    /// generation plus one per pack already staged ahead of it. Kept as its
    /// own monotonic counter rather than derived from `generation` and the
    /// queue length, because a publish bumps the one and pops the other in
    /// two steps and a stage between them must not see the half-applied sum.
    pub(super) next_base: i64,
}

/// One staged pack; the payload stays in the pack file so the queue costs
/// memory proportional to its length, not to the bytes awaiting upload.
pub(super) struct StagedPack {
    pub(super) txn: String,
    pub(super) path: PathBuf,
    pub(super) encoded_bytes: u64,
    pub(super) staged_at_unix_ms: u64,
    pub(super) chunks: Vec<u64>,
}

pub(super) fn copy_dirty_ranges(
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
pub(super) fn describe_pack(plans: &[ChunkPlan], payload: &[u8]) -> Vec<PackEntry> {
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

pub(super) fn describe_overlay_pack(
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

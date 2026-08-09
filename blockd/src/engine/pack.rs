use super::*;

const PACK_PREFIX_BYTES: usize = 8 + 2 + 4;
const EMPTY_SHA256_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const BYTE_RANGES_JSON_PREFIX: &str = ",\"byte_ranges\":[";

#[cfg(test)]
std::thread_local! {
    static FAIL_STAGE_WRITE_AT: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) struct StageWriteFailureGuard {
    previous: Option<usize>,
}

#[cfg(test)]
impl StageWriteFailureGuard {
    pub(super) fn set(pack_index: usize) -> Self {
        let previous = FAIL_STAGE_WRITE_AT.replace(Some(pack_index));
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for StageWriteFailureGuard {
    fn drop(&mut self) {
        FAIL_STAGE_WRITE_AT.set(self.previous);
    }
}

fn inject_stage_write_failure(_pack_index: usize) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_STAGE_WRITE_AT.get() == Some(_pack_index) {
        return Err(std::io::Error::other("injected staged-pack write failure"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct PackFragment {
    plan_index: usize,
    range_start: usize,
    range_end: usize,
    payload_offset: usize,
    payload_len: usize,
    page_mask: u64,
    range_json_bytes: usize,
    entry_json_bytes: usize,
}

struct DraftPack {
    txn: String,
    base_generation: i64,
    empty_header_json_bytes: usize,
    fragments: Vec<PackFragment>,
    payload_start: usize,
    payload_len: usize,
    entries_json_bytes: usize,
    materialized_bytes: usize,
}

struct PreparedBarrierPack {
    header: PackHeader,
    payload_start: usize,
    payload_len: usize,
    encoded_bytes: u64,
    fragments: Vec<PackFragment>,
    chunks: Vec<u64>,
}

struct BarrierPackInput<'a> {
    volume_id: &'a str,
    lease_epoch: i64,
    base_generation: i64,
    plans: &'a [ChunkPlan],
    frozen_ranges: &'a [Vec<DirtyByteRange>],
    payload: &'a [u8],
    relaxed: bool,
    limit: usize,
}

struct OverlayRangeUnit {
    plan_index: usize,
    range_index: usize,
    range: DirtyByteRange,
    global_payload_offset: usize,
    force_full_base: bool,
}

fn json_len<T: serde::Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .expect("pack metadata serializes")
        .len()
}

fn overlay_entry_json_bytes(
    plan: &ChunkPlan,
    fragment: &PackFragment,
    range_count: usize,
) -> Option<usize> {
    let entry = PackEntry {
        chunk_idx: plan.chunk_idx,
        payload_offset: u64::try_from(fragment.payload_offset).ok()?,
        len: u32::try_from(fragment.payload_len).ok()?,
        sha256_hex: EMPTY_SHA256_HEX.into(),
        page_mask: fragment.page_mask,
        byte_ranges: Vec::new(),
    };
    json_len(&entry)
        .checked_add(BYTE_RANGES_JSON_PREFIX.len())?
        .checked_add(fragment.range_json_bytes)?
        .checked_add(range_count.saturating_sub(1))?
        .checked_add(1)
}

fn atomic_entry_json_bytes(plan: &ChunkPlan, payload_offset: usize) -> Option<usize> {
    let entry = PackEntry {
        chunk_idx: plan.chunk_idx,
        payload_offset: u64::try_from(payload_offset).ok()?,
        len: u32::try_from(plan.len()).ok()?,
        sha256_hex: EMPTY_SHA256_HEX.into(),
        page_mask: plan.page_mask,
        byte_ranges: Vec::new(),
    };
    Some(json_len(&entry))
}

impl DraftPack {
    fn new(volume_id: &str, lease_epoch: i64, base_generation: i64) -> Self {
        let txn = uuid::Uuid::new_v4().simple().to_string();
        let empty_header_json_bytes = json_len(&PackHeader {
            txn: txn.clone(),
            volume_id: volume_id.to_string(),
            base_generation,
            lease_epoch,
            entries: Vec::new(),
        });
        Self {
            txn,
            base_generation,
            empty_header_json_bytes,
            fragments: Vec::new(),
            payload_start: 0,
            payload_len: 0,
            entries_json_bytes: 0,
            materialized_bytes: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.fragments.is_empty()
    }

    fn encoded_bytes_with(
        &self,
        entries_json_bytes: usize,
        entry_count: usize,
        payload_len: usize,
    ) -> Option<usize> {
        PACK_PREFIX_BYTES
            .checked_add(self.empty_header_json_bytes)?
            .checked_add(entries_json_bytes)?
            .checked_add(entry_count.saturating_sub(1))?
            .checked_add(payload_len)
    }

    fn candidate_fits(
        &self,
        entries_json_bytes: usize,
        entry_count: usize,
        payload_len: usize,
        materialized_bytes: usize,
        limit: usize,
    ) -> Result<bool> {
        let encoded_bytes = self
            .encoded_bytes_with(entries_json_bytes, entry_count, payload_len)
            .ok_or_else(|| EngineError::Corrupt("pack encoded length overflow".into()))?;
        let working_set = pack_working_set_bytes(encoded_bytes, materialized_bytes)
            .ok_or_else(|| EngineError::Corrupt("pack working-set overflow".into()))?;
        Ok(working_set <= limit)
    }

    fn try_push_atomic(
        &mut self,
        plan_index: usize,
        plan: &ChunkPlan,
        global_payload_offset: usize,
        limit: usize,
    ) -> Result<bool> {
        let payload_len = self
            .payload_len
            .checked_add(plan.len())
            .ok_or_else(|| EngineError::Corrupt("pack payload length overflow".into()))?;
        let entry_json_bytes = atomic_entry_json_bytes(plan, self.payload_len)
            .ok_or_else(|| EngineError::Corrupt("pack entry length overflow".into()))?;
        let entries_json_bytes = self
            .entries_json_bytes
            .checked_add(entry_json_bytes)
            .ok_or_else(|| EngineError::Corrupt("pack header length overflow".into()))?;
        let materialized_bytes = self
            .materialized_bytes
            .checked_add(plan.len())
            .ok_or_else(|| EngineError::Corrupt("materialized pack length overflow".into()))?;
        if !self.candidate_fits(
            entries_json_bytes,
            self.fragments.len() + 1,
            payload_len,
            materialized_bytes,
            limit,
        )? {
            return Ok(false);
        }
        if self.fragments.is_empty() {
            self.payload_start = global_payload_offset;
        }
        self.fragments.push(PackFragment {
            plan_index,
            range_start: 0,
            range_end: 0,
            payload_offset: self.payload_len,
            payload_len: plan.len(),
            page_mask: plan.page_mask,
            range_json_bytes: 0,
            entry_json_bytes,
        });
        self.payload_len = payload_len;
        self.entries_json_bytes = entries_json_bytes;
        self.materialized_bytes = materialized_bytes;
        Ok(true)
    }

    fn try_push_range(
        &mut self,
        plan: &ChunkPlan,
        unit: &OverlayRangeUnit,
        limit: usize,
    ) -> Result<bool> {
        let plan_index = unit.plan_index;
        let range_index = unit.range_index;
        let range = unit.range;
        let descriptor = PackByteRange {
            chunk_offset: range.start,
            payload_offset: u64::try_from(self.payload_len)
                .map_err(|_| EngineError::Corrupt("pack payload offset overflow".into()))?,
            len: u32::try_from(range.len())
                .map_err(|_| EngineError::Corrupt("pack range length overflow".into()))?,
        };
        let descriptor_json_bytes = json_len(&descriptor);
        let payload_len = self
            .payload_len
            .checked_add(range.len())
            .ok_or_else(|| EngineError::Corrupt("pack payload length overflow".into()))?;
        let extends_last = self.fragments.last().is_some_and(|fragment| {
            fragment.plan_index == plan_index && fragment.range_end == range_index
        });
        let mut candidate = if extends_last {
            self.fragments.last().expect("checked").clone()
        } else {
            PackFragment {
                plan_index,
                range_start: range_index,
                range_end: range_index,
                payload_offset: self.payload_len,
                payload_len: 0,
                page_mask: 0,
                range_json_bytes: 0,
                entry_json_bytes: 0,
            }
        };
        let old_entry_json_bytes = candidate.entry_json_bytes;
        let old_materialized_bytes = if candidate.page_mask == 0 {
            0
        } else {
            materialized_page_mask_bytes(candidate.page_mask)
                .ok_or_else(|| EngineError::Corrupt("materialized pack length overflow".into()))?
        };
        candidate.range_end = range_index + 1;
        candidate.payload_len = candidate
            .payload_len
            .checked_add(range.len())
            .ok_or_else(|| EngineError::Corrupt("pack entry length overflow".into()))?;
        let range_page_mask = format::page_mask(range.start, range.end - range.start);
        candidate.page_mask = if plan.is_base() || unit.force_full_base {
            format::full_page_mask()
        } else {
            candidate.page_mask | range_page_mask
        };
        candidate.range_json_bytes = candidate
            .range_json_bytes
            .checked_add(descriptor_json_bytes)
            .ok_or_else(|| EngineError::Corrupt("pack range header overflow".into()))?;
        candidate.entry_json_bytes = overlay_entry_json_bytes(
            plan,
            &candidate,
            candidate.range_end - candidate.range_start,
        )
        .ok_or_else(|| EngineError::Corrupt("pack entry length overflow".into()))?;

        let entries_json_bytes = self
            .entries_json_bytes
            .checked_sub(old_entry_json_bytes)
            .and_then(|bytes| bytes.checked_add(candidate.entry_json_bytes))
            .ok_or_else(|| EngineError::Corrupt("pack header length overflow".into()))?;
        let new_materialized_bytes = materialized_page_mask_bytes(candidate.page_mask)
            .ok_or_else(|| EngineError::Corrupt("materialized pack length overflow".into()))?;
        let materialized_bytes = self
            .materialized_bytes
            .checked_sub(old_materialized_bytes)
            .and_then(|bytes| bytes.checked_add(new_materialized_bytes))
            .ok_or_else(|| EngineError::Corrupt("materialized pack length overflow".into()))?;
        let entry_count = if extends_last {
            self.fragments.len()
        } else {
            self.fragments.len() + 1
        };
        if !self.candidate_fits(
            entries_json_bytes,
            entry_count,
            payload_len,
            materialized_bytes,
            limit,
        )? {
            return Ok(false);
        }
        if self.fragments.is_empty() {
            self.payload_start = unit.global_payload_offset;
        }
        if extends_last {
            *self.fragments.last_mut().expect("checked") = candidate;
        } else {
            self.fragments.push(candidate);
        }
        self.payload_len = payload_len;
        self.entries_json_bytes = entries_json_bytes;
        self.materialized_bytes = materialized_bytes;
        Ok(true)
    }
}

fn draft_pack(
    volume_id: &str,
    lease_epoch: i64,
    first_base_generation: i64,
    pack_index: usize,
) -> Result<DraftPack> {
    let offset = i64::try_from(pack_index)
        .map_err(|_| EngineError::Corrupt("barrier pack count exceeds i64".into()))?;
    let base_generation = first_base_generation
        .checked_add(offset)
        .ok_or_else(|| EngineError::Corrupt("barrier generation overflow".into()))?;
    Ok(DraftPack::new(volume_id, lease_epoch, base_generation))
}

fn finish_draft_pack(
    draft: DraftPack,
    input: &BarrierPackInput<'_>,
) -> Result<PreparedBarrierPack> {
    let payload_end = draft
        .payload_start
        .checked_add(draft.payload_len)
        .ok_or_else(|| EngineError::Corrupt("pack payload range overflow".into()))?;
    let pack_payload = input
        .payload
        .get(draft.payload_start..payload_end)
        .ok_or_else(|| EngineError::Corrupt("pack payload range is out of bounds".into()))?;
    let mut entries = Vec::with_capacity(draft.fragments.len());
    for fragment in &draft.fragments {
        let plan = input
            .plans
            .get(fragment.plan_index)
            .ok_or_else(|| EngineError::Corrupt("pack plan index is out of bounds".into()))?;
        let start = fragment.payload_offset;
        let end = start
            .checked_add(fragment.payload_len)
            .ok_or_else(|| EngineError::Corrupt("pack entry range overflow".into()))?;
        let entry_payload = pack_payload
            .get(start..end)
            .ok_or_else(|| EngineError::Corrupt("pack entry range is out of bounds".into()))?;
        let byte_ranges = if input.relaxed && fragment.range_end > fragment.range_start {
            let ranges = input
                .frozen_ranges
                .get(fragment.plan_index)
                .and_then(|ranges| ranges.get(fragment.range_start..fragment.range_end))
                .ok_or_else(|| EngineError::Corrupt("pack byte range is out of bounds".into()))?;
            let mut local_offset = fragment.payload_offset;
            let mut descriptors = Vec::with_capacity(ranges.len());
            for range in ranges {
                descriptors.push(PackByteRange {
                    chunk_offset: range.start,
                    payload_offset: u64::try_from(local_offset)
                        .map_err(|_| EngineError::Corrupt("pack payload offset overflow".into()))?,
                    len: u32::try_from(range.len()).map_err(|_| {
                        EngineError::Corrupt("pack byte range length overflow".into())
                    })?,
                });
                local_offset = local_offset.checked_add(range.len()).ok_or_else(|| {
                    EngineError::Corrupt("pack byte range offset overflow".into())
                })?;
            }
            descriptors
        } else {
            Vec::new()
        };
        entries.push(PackEntry {
            chunk_idx: plan.chunk_idx,
            payload_offset: u64::try_from(fragment.payload_offset)
                .map_err(|_| EngineError::Corrupt("pack payload offset overflow".into()))?,
            len: u32::try_from(fragment.payload_len)
                .map_err(|_| EngineError::Corrupt("pack entry length overflow".into()))?,
            sha256_hex: hex::encode(format::sha256(entry_payload)),
            page_mask: fragment.page_mask,
            byte_ranges,
        });
    }
    let header = PackHeader {
        txn: draft.txn.clone(),
        volume_id: input.volume_id.to_string(),
        base_generation: draft.base_generation,
        lease_epoch: input.lease_epoch,
        entries,
    };
    let encoded_bytes = format::encoded_pack_len(&header, pack_payload.len())
        .ok_or_else(|| EngineError::Corrupt("pack encoded length overflow".into()))?;
    let projected_encoded = draft
        .encoded_bytes_with(
            draft.entries_json_bytes,
            draft.fragments.len(),
            draft.payload_len,
        )
        .ok_or_else(|| EngineError::Corrupt("pack encoded length overflow".into()))?;
    if encoded_bytes != projected_encoded {
        return Err(EngineError::Corrupt(
            "pack boundary projection disagrees with exact encoding".into(),
        ));
    }
    let materialized_bytes = materialized_pack_bytes(&header)
        .ok_or_else(|| EngineError::Corrupt("materialized pack length overflow".into()))?;
    let working_set = pack_working_set_bytes(encoded_bytes, materialized_bytes)
        .ok_or_else(|| EngineError::Corrupt("pack working-set overflow".into()))?;
    if working_set > input.limit {
        return Err(EngineError::Corrupt(
            "prepared pack exceeds publisher working-set limit".into(),
        ));
    }
    let mut chunks: Vec<u64> = header.entries.iter().map(|entry| entry.chunk_idx).collect();
    chunks.sort_unstable();
    chunks.dedup();
    Ok(PreparedBarrierPack {
        header,
        payload_start: draft.payload_start,
        payload_len: draft.payload_len,
        encoded_bytes: u64::try_from(encoded_bytes)
            .map_err(|_| EngineError::Corrupt("pack encoded length exceeds u64".into()))?,
        fragments: draft.fragments,
        chunks,
    })
}

fn prepare_barrier_packs_once(
    input: &BarrierPackInput<'_>,
    force_full_base: &[bool],
) -> Result<Vec<PreparedBarrierPack>> {
    let mut drafts = Vec::new();
    let mut draft = draft_pack(input.volume_id, input.lease_epoch, input.base_generation, 0)?;
    let mut global_payload_offset = 0usize;

    for (plan_index, plan) in input.plans.iter().enumerate() {
        let ranges = &input.frozen_ranges[plan_index];
        if !input.relaxed || ranges.is_empty() {
            if input.relaxed && ranges.is_empty() && plan.page_mask != 0 {
                return Err(EngineError::Corrupt(
                    "relaxed data plan has no exact byte ranges".into(),
                ));
            }
            loop {
                if draft.try_push_atomic(plan_index, plan, global_payload_offset, input.limit)? {
                    global_payload_offset = global_payload_offset
                        .checked_add(plan.len())
                        .ok_or_else(|| {
                            EngineError::Corrupt("barrier payload length overflow".into())
                        })?;
                    break;
                }
                if draft.is_empty() {
                    return Err(EngineError::InvalidConfig(
                        "publisher working-set limit cannot fit one pack entry".into(),
                    ));
                }
                drafts.push(draft);
                draft = draft_pack(
                    input.volume_id,
                    input.lease_epoch,
                    input.base_generation,
                    drafts.len(),
                )?;
            }
            continue;
        }

        for (range_index, range) in ranges.iter().copied().enumerate() {
            loop {
                let unit = OverlayRangeUnit {
                    plan_index,
                    range_index,
                    range,
                    global_payload_offset,
                    force_full_base: force_full_base[plan_index],
                };
                if draft.try_push_range(plan, &unit, input.limit)? {
                    global_payload_offset = global_payload_offset
                        .checked_add(range.len())
                        .ok_or_else(|| {
                            EngineError::Corrupt("barrier payload length overflow".into())
                        })?;
                    break;
                }
                if draft.is_empty() {
                    return Err(EngineError::InvalidConfig(
                        "publisher working-set limit cannot fit one byte range".into(),
                    ));
                }
                drafts.push(draft);
                draft = draft_pack(
                    input.volume_id,
                    input.lease_epoch,
                    input.base_generation,
                    drafts.len(),
                )?;
            }
        }
    }
    if !draft.is_empty() {
        drafts.push(draft);
    }
    if global_payload_offset != input.payload.len() {
        return Err(EngineError::Corrupt(
            "barrier payload does not match its plans".into(),
        ));
    }
    drafts
        .into_iter()
        .map(|draft| finish_draft_pack(draft, input))
        .collect()
}

fn prepare_barrier_packs(input: &BarrierPackInput<'_>) -> Result<Vec<PreparedBarrierPack>> {
    let mut force_full_base = vec![false; input.plans.len()];
    loop {
        let prepared = prepare_barrier_packs_once(input, &force_full_base)?;
        if !input.relaxed {
            return Ok(prepared);
        }
        let mut fragment_counts = vec![0usize; input.plans.len()];
        for pack in &prepared {
            for fragment in &pack.fragments {
                if !input.frozen_ranges[fragment.plan_index].is_empty() {
                    fragment_counts[fragment.plan_index] += 1;
                }
            }
        }
        let mut changed = false;
        for (plan_index, count) in fragment_counts.into_iter().enumerate() {
            if count > 1 && !force_full_base[plan_index] {
                force_full_base[plan_index] = true;
                changed = true;
            }
        }
        if !changed {
            return Ok(prepared);
        }
    }
}

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

        // Commit size is the single most useful number when a Guest workload
        // stalls on FLUSH: the barrier above is held for as long as it takes to
        // copy the published bytes. A large logical barrier is split only after
        // this point, in the existing canonical plan/range order.
        tracing::info!(
            volume = %self.cfg.volume_id,
            base_generation,
            dirty_chunks = plans.len(),
            base_rewrites = plans.iter().filter(|p| p.is_base()).count(),
            pack_bytes = payload.len(),
            "commit barrier frozen"
        );
        let limit = publisher_working_set_limit();
        let pack_input = BarrierPackInput {
            volume_id: &self.cfg.volume_id,
            lease_epoch: self.epoch,
            base_generation,
            plans: &plans,
            frozen_ranges: &frozen_ranges,
            payload: &payload,
            relaxed,
            limit,
        };
        let prepared = match prepare_barrier_packs(&pack_input) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.restore_frozen_plans(&plans, &frozen_ranges);
                self.inflight_staging_bytes.store(0, Ordering::Relaxed);
                self.local_space.notify_all();
                return Err(error);
            }
        };
        let pack_count = i64::try_from(prepared.len())
            .map_err(|_| EngineError::Corrupt("barrier pack count exceeds i64".into()));
        let next_base = pack_count.and_then(|count| {
            base_generation
                .checked_add(count)
                .ok_or_else(|| EngineError::Corrupt("barrier generation overflow".into()))
        });
        let next_base = match next_base {
            Ok(next_base) => next_base,
            Err(error) => {
                self.restore_frozen_plans(&plans, &frozen_ranges);
                self.inflight_staging_bytes.store(0, Ordering::Relaxed);
                self.local_space.notify_all();
                return Err(error);
            }
        };
        let projected_bytes = prepared
            .iter()
            .try_fold(0u64, |total, pack| total.checked_add(pack.encoded_bytes));
        let projected_bytes = match projected_bytes {
            Some(projected_bytes) => projected_bytes,
            None => {
                self.restore_frozen_plans(&plans, &frozen_ranges);
                self.inflight_staging_bytes.store(0, Ordering::Relaxed);
                self.local_space.notify_all();
                return Err(EngineError::Corrupt(
                    "barrier encoded length exceeds u64".into(),
                ));
            }
        };
        self.inflight_staging_bytes
            .store(projected_bytes, Ordering::Relaxed);
        let protected: HashSet<u64> = plans.iter().map(|plan| plan.chunk_idx).collect();
        if let Err(error) = self.wait_for_staging_space_for(projected_bytes, prepared.len()) {
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

        let mut durable_prefix = 0usize;
        for (pack_index, pack) in prepared.iter().enumerate() {
            let payload_end = pack.payload_start + pack.payload_len;
            let pack_payload = &payload[pack.payload_start..payload_end];
            let write = inject_stage_write_failure(pack_index)
                .map_err(EngineError::Io)
                .and_then(|()| self.write_pack_file(&pack.header, pack_payload));
            match write {
                Ok(encoded_bytes) if encoded_bytes == pack.encoded_bytes => {
                    durable_prefix += 1;
                }
                Ok(_) => {
                    self.remove_pack_artifacts(&pack.header);
                    self.restore_after_durable_prefix(
                        &plans,
                        &frozen_ranges,
                        &prepared[..durable_prefix],
                        relaxed,
                    );
                    let backlog =
                        self.enqueue_durable_prefix(&prepared[..durable_prefix], base_generation);
                    self.finish_partial_stage(backlog);
                    return Err(EngineError::Corrupt(
                        "staged pack length changed while writing".into(),
                    ));
                }
                Err(error) => {
                    self.remove_pack_artifacts(&pack.header);
                    self.restore_after_durable_prefix(
                        &plans,
                        &frozen_ranges,
                        &prepared[..durable_prefix],
                        relaxed,
                    );
                    let backlog =
                        self.enqueue_durable_prefix(&prepared[..durable_prefix], base_generation);
                    self.finish_partial_stage(backlog);
                    return Err(error);
                }
            }
        }
        let backlog = self.enqueue_durable_prefix(&prepared, base_generation);
        debug_assert_eq!(self.staged.lock().unwrap().next_base, next_base);
        self.unfreeze_plans(&plans);
        self.finish_partial_stage(backlog);
        crashpoint::maybe_crash(crashpoint::AFTER_PACK);
        Ok(())
    }

    fn enqueue_durable_prefix(&self, packs: &[PreparedBarrierPack], base_generation: i64) -> usize {
        let mut staged = self.staged.lock().unwrap();
        debug_assert_eq!(staged.next_base, base_generation);
        let staged_at_unix_ms = unix_time_ms();
        for pack in packs {
            staged.bytes = staged.bytes.saturating_add(pack.encoded_bytes);
            staged.packs.push_back(StagedPack {
                txn: pack.header.txn.clone(),
                path: self.pack_path(pack.header.base_generation, &pack.header.txn),
                encoded_bytes: pack.encoded_bytes,
                staged_at_unix_ms,
                chunks: pack.chunks.clone(),
            });
        }
        let count = i64::try_from(packs.len())
            .expect("prepared barrier pack count was validated before persistence");
        staged.next_base = base_generation
            .checked_add(count)
            .expect("prepared barrier generation range was validated before persistence");
        staged.packs.len()
    }

    fn finish_partial_stage(&self, backlog: usize) {
        self.inflight_staging_bytes.store(0, Ordering::Relaxed);
        self.local_space.notify_all();
        self.staged_space.notify_all();
        if backlog > EAGER_DRAIN_WATERMARK {
            self.kick_committer();
        }
    }

    fn remove_pack_artifacts(&self, header: &PackHeader) {
        let pending = self.cfg.data_dir.join(PENDING_PACK_DIR);
        let _ = fs::remove_file(self.pack_path(header.base_generation, &header.txn));
        let _ = fs::remove_file(pending.join(format!(".tmp-{}", header.txn)));
        if let Ok(directory) = File::open(pending) {
            let _ = directory.sync_all();
        }
    }

    fn restore_after_durable_prefix(
        &self,
        plans: &[ChunkPlan],
        frozen_ranges: &[Vec<DirtyByteRange>],
        durable: &[PreparedBarrierPack],
        relaxed: bool,
    ) {
        let mut covered_plans = vec![false; plans.len()];
        let mut covered_ranges = vec![0usize; plans.len()];
        for pack in durable {
            for fragment in &pack.fragments {
                if relaxed && !frozen_ranges[fragment.plan_index].is_empty() {
                    covered_ranges[fragment.plan_index] =
                        covered_ranges[fragment.plan_index].max(fragment.range_end);
                } else {
                    covered_plans[fragment.plan_index] = true;
                }
            }
        }

        let mut state = self.state.lock().unwrap();
        for (plan_index, (plan, ranges)) in plans.iter().zip(frozen_ranges).enumerate() {
            state.freezing.remove(&plan.chunk_idx);
            if covered_plans[plan_index] {
                continue;
            }
            if plan.page_mask == 0 {
                state.discarded.insert(plan.chunk_idx);
                continue;
            }
            if relaxed {
                for range in ranges.iter().skip(covered_ranges[plan_index]) {
                    state.dirty[plan.chunk_idx as usize] |=
                        format::page_mask(range.start, range.len() as u32);
                    merge_dirty_range(&mut state.dirty_ranges[plan.chunk_idx as usize], *range);
                }
            } else {
                state.dirty[plan.chunk_idx as usize] |= plan.page_mask;
                for range in ranges {
                    merge_dirty_range(&mut state.dirty_ranges[plan.chunk_idx as usize], *range);
                }
            }
        }
        drop(state);
        self.hydration_cv.notify_all();
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

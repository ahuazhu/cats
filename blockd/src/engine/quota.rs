use super::*;

#[cfg(target_os = "linux")]
pub(super) fn punch_hole(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
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
pub(super) fn punch_hole(file: &File, offset: u64, len: u64) -> std::io::Result<()> {
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

/// Conservative space accounting for the JSON metadata around one pending
/// pack. Admission must reserve the later pack before dirty cache can consume
/// the whole local quota, or no publisher input could ever be created.
const PACK_RESERVATION_FIXED_BYTES: u64 = 4 << 10;
const PACK_RESERVATION_PER_ENTRY_BYTES: u64 = 512;
const PACK_RESERVATION_PER_RANGE_BYTES: u64 = 192;

pub(super) fn pack_reservation_upper(payload_bytes: u64, entries: usize, ranges: usize) -> u64 {
    payload_bytes
        .saturating_add(PACK_RESERVATION_FIXED_BYTES)
        .saturating_add((entries as u64).saturating_mul(PACK_RESERVATION_PER_ENTRY_BYTES))
        .saturating_add((ranges as u64).saturating_mul(PACK_RESERVATION_PER_RANGE_BYTES))
}

impl ChunkEngine {
    pub(super) fn cache_allocated_bytes(&self) -> std::io::Result<u64> {
        use std::os::unix::fs::MetadataExt;
        Ok(self.cache.metadata()?.blocks().saturating_mul(512))
    }

    /// Space the current dirty set will need when it becomes an immutable
    /// pending pack. Counting it before the bytes are physically duplicated is
    /// what prevents dirty cache from consuming the last byte needed to create
    /// publisher input.
    pub(super) fn unstaged_pack_reservation_bytes(&self) -> u64 {
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

    pub(super) fn local_accounted_bytes(&self) -> std::io::Result<u64> {
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
    pub(super) fn write_admission_bytes(&self, offset: u64, len: usize) -> u64 {
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

    pub(super) fn stage_before_write_pressure(&self, required_bytes: u64) -> Result<()> {
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
    pub(super) fn ensure_local_capacity(
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

    /// Admission for a new local durability barrier. The wait is deliberately
    /// local-state-only: the background committer owns all DB/S3 calls. A
    /// prolonged outage therefore shows up as queue age and backpressure, not
    /// as a remote error injected into ext4.
    pub(super) fn wait_for_staging_space(&self) -> Result<()> {
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

    pub(super) fn wait_for_staging_space_for(&self, required_bytes: u64) -> Result<()> {
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
}

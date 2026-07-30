use super::*;

/// A layered chunk's fetched objects: the base (absent when the chunk's base is a
/// hole) and each delta, in the order they must be applied.
type Layers = (Option<Vec<u8>>, Vec<Vec<u8>>);

/// How many chunks one read hydrates at once. Same reasoning as the upload cap,
/// and the same number: a cold read is round-trip bound in exactly the same way a
/// commit is.
fn fetch_workers(chunks: usize) -> usize {
    chunks.clamp(1, MAX_UPLOAD_CONCURRENCY)
}

impl ChunkEngine {
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
    pub(super) fn hydrate_range(&self, first: u64, last: u64) -> Result<()> {
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

    pub(super) fn ensure_cache_complete(&self, chunk_idx: u64) -> Result<()> {
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
    pub(super) fn fetch_verified(
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
    pub(super) fn fetch_layers(
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
    pub(super) fn fetch_chunk_image(&self, chunk_ref: &ChunkRef) -> Result<Vec<u8>> {
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
    pub(super) fn hydrate_chunk(&self, chunk_idx: u64, chunk_ref: &ChunkRef) -> Result<()> {
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
    pub(super) fn hydrate_chunk_with_local_state(&self, chunk_idx: u64) -> Result<()> {
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
}

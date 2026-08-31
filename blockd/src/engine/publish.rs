use super::*;

#[cfg(test)]
std::thread_local! {
    static BACKGROUND_PUBLISHER_CONTEXT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

/// Test-only causal marker for remote calls. Data PUTs fan out from the named
/// committer onto scoped upload workers, so a raw thread-name assertion would
/// mistake those children for Guest callers. The marker is entered only by the
/// background committer and explicitly inherited by its scoped workers.
#[cfg(test)]
struct BackgroundPublisherContext {
    previous: bool,
}

#[cfg(test)]
impl BackgroundPublisherContext {
    fn enter(enabled: bool) -> Self {
        let previous = BACKGROUND_PUBLISHER_CONTEXT.replace(enabled);
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for BackgroundPublisherContext {
    fn drop(&mut self) {
        BACKGROUND_PUBLISHER_CONTEXT.set(self.previous);
    }
}

#[cfg(test)]
pub(super) fn is_background_publisher_context() -> bool {
    BACKGROUND_PUBLISHER_CONTEXT.get()
}

/// Queue depth past which a relaxed stage kicks the committer instead of
/// letting packs sit until the timer. Above one so the single-pack case (an
/// idle volume's periodic journal commit) still batches with whatever the
/// next few milliseconds bring, and low enough that a burst starts draining
/// long before the configured backpressure cap is in sight.
pub(super) const EAGER_DRAIN_WATERMARK: usize = 2;

/// Roots on both sides of one attempted CAS. Keeping the evidence together
/// makes it harder for reconciliation to compare a generation without its
/// corresponding root identity.
struct CasEvidence<'a> {
    base_generation: i64,
    base_root_hash: Option<[u8; 32]>,
    base_root_object_id: Option<&'a str>,
    target_generation: i64,
    target_root_hash: [u8; 32],
    target_root_object_id: &'a str,
}

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

fn entry_payload<'a>(entry: &PackEntry, payload: &'a [u8]) -> Result<&'a [u8]> {
    let start = usize::try_from(entry.payload_offset)
        .map_err(|_| EngineError::Corrupt("pack payload offset exceeds usize".into()))?;
    let len = usize::try_from(entry.len)
        .map_err(|_| EngineError::Corrupt("pack payload length exceeds usize".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| EngineError::Corrupt("pack payload range overflow".into()))?;
    payload
        .get(start..end)
        .ok_or_else(|| EngineError::Corrupt("pack payload range is out of bounds".into()))
}

/// Validate the complete persisted entry projection before materialization can
/// issue a GET and before publication can index or PUT anything. Pending packs
/// are crash residue and therefore untrusted input even when their outer header
/// decoded successfully.
fn validate_pack_entries(header: &PackHeader, payload: &[u8], chunk_count: u64) -> Result<()> {
    if header.entries.is_empty() {
        return Err(EngineError::Corrupt(
            "pack must contain at least one entry".into(),
        ));
    }
    let mut chunks = HashSet::with_capacity(header.entries.len());
    let mut payload_cursor = 0usize;
    for entry in &header.entries {
        if entry.chunk_idx >= chunk_count {
            return Err(EngineError::Corrupt("pack chunk is out of bounds".into()));
        }
        if !chunks.insert(entry.chunk_idx) {
            return Err(EngineError::Corrupt(
                "pack contains duplicate chunk entries".into(),
            ));
        }

        let start = usize::try_from(entry.payload_offset)
            .map_err(|_| EngineError::Corrupt("pack payload offset exceeds usize".into()))?;
        if start != payload_cursor {
            return Err(EngineError::Corrupt(
                "pack entries do not cover their payload canonically".into(),
            ));
        }
        let source = entry_payload(entry, payload)?;
        payload_cursor = start
            .checked_add(source.len())
            .ok_or_else(|| EngineError::Corrupt("pack payload range overflow".into()))?;
        if hex::encode(format::sha256(source)) != entry.sha256_hex {
            return Err(EngineError::Corrupt("pack entry hash mismatch".into()));
        }

        if entry.is_discard() {
            if !source.is_empty() || entry.is_byte_overlay() {
                return Err(EngineError::Corrupt(
                    "pack discard carries data or byte ranges".into(),
                ));
            }
            continue;
        }

        if !entry.is_byte_overlay() {
            let expected = materialized_entry_bytes(entry)
                .ok_or_else(|| EngineError::Corrupt("pack entry length overflow".into()))?;
            if source.len() != expected {
                return Err(EngineError::Corrupt(format!(
                    "pack entry carries {} bytes for {} pages",
                    source.len(),
                    entry.page_mask.count_ones()
                )));
            }
            continue;
        }

        let entry_end = payload_cursor;
        let mut range_payload_cursor = start;
        let mut previous_chunk_end = None;
        let mut range_page_mask = 0u64;
        for range in &entry.byte_ranges {
            if range.len == 0 {
                return Err(EngineError::Corrupt(
                    "pack byte range must not be empty".into(),
                ));
            }
            let chunk_end = range
                .chunk_offset
                .checked_add(range.len)
                .filter(|end| *end <= CHUNK_SIZE)
                .ok_or_else(|| EngineError::Corrupt("pack byte range exceeds its chunk".into()))?;
            if previous_chunk_end.is_some_and(|end| range.chunk_offset < end) {
                return Err(EngineError::Corrupt(
                    "pack byte ranges are not in canonical chunk order".into(),
                ));
            }
            previous_chunk_end = Some(chunk_end);

            let range_start = usize::try_from(range.payload_offset).map_err(|_| {
                EngineError::Corrupt("pack byte range payload offset exceeds usize".into())
            })?;
            if range_start != range_payload_cursor {
                return Err(EngineError::Corrupt(
                    "pack byte ranges do not cover their entry canonically".into(),
                ));
            }
            let range_len = usize::try_from(range.len)
                .map_err(|_| EngineError::Corrupt("pack byte range length exceeds usize".into()))?;
            range_payload_cursor = range_start
                .checked_add(range_len)
                .ok_or_else(|| EngineError::Corrupt("pack byte range payload overflow".into()))?;
            if range_payload_cursor > entry_end || range_payload_cursor > payload.len() {
                return Err(EngineError::Corrupt(
                    "pack byte range payload is out of bounds".into(),
                ));
            }
            range_page_mask |= format::page_mask(range.chunk_offset, range.len);
        }
        if range_payload_cursor != entry_end {
            return Err(EngineError::Corrupt(
                "pack byte ranges do not cover the complete entry".into(),
            ));
        }
        if !entry.is_base() && range_page_mask != entry.page_mask {
            return Err(EngineError::Corrupt(
                "pack byte ranges disagree with their page mask".into(),
            ));
        }
    }
    if payload_cursor != payload.len() {
        return Err(EngineError::Corrupt(
            "pack entries do not cover the complete payload".into(),
        ));
    }
    Ok(())
}

pub(super) struct PreparedMapPublication {
    pub(super) base_root_hash: Option<[u8; 32]>,
    pub(super) base_root_object_id: Option<String>,
    pub(super) leaf_nodes: Vec<([u8; 32], Vec<u8>)>,
    pub(super) root_bytes: Vec<u8>,
    pub(super) root_hash: [u8; 32],
    pub(super) root_object_id: String,
    pub(super) leaves: Vec<LeafRef>,
}

#[derive(serde::Serialize)]
struct CommitRecord<'a> {
    chunks: &'a [u64],
    generation: i64,
    lease_epoch: i64,
    root_hash: &'a str,
    txn: &'a str,
}

pub(super) fn encode_commit_record(
    txn: &str,
    generation: i64,
    lease_epoch: i64,
    root_hash: &str,
    chunks: &[u64],
) -> Vec<u8> {
    serde_json::to_vec(&CommitRecord {
        chunks,
        generation,
        lease_epoch,
        root_hash,
        txn,
    })
    .expect("commit record fields always serialize")
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
        let mut encoded_bytes = 0usize;
        let mut materialized_bytes = 0usize;
        let mut batch_epoch = None;
        for (txn, path) in &snapshot {
            let mut file = File::open(path)?;
            let file_bytes = usize::try_from(file.metadata()?.len())
                .map_err(|_| EngineError::Corrupt(format!("staged pack {txn} is too large")))?;
            let candidate_encoded = encoded_bytes
                .checked_add(file_bytes)
                .ok_or_else(|| EngineError::Corrupt("publisher encoded length overflow".into()))?;
            let minimum_working_set = pack_working_set_bytes(candidate_encoded, 0)
                .ok_or_else(|| EngineError::Corrupt("publisher working-set overflow".into()))?;
            if minimum_working_set > publisher_working_set_limit() {
                if decoded.is_empty() {
                    return Err(EngineError::Corrupt(format!(
                        "staged pack {txn} exceeds the publisher working-set limit"
                    )));
                }
                break;
            }

            // Read only the fixed prefix and bounded JSON header first. M is
            // derivable from the header, so a candidate that would cross the
            // exact batch budget is rejected before any of its payload enters
            // memory.
            let mut prefix = [0u8; format::ENCODED_PACK_PREFIX_LEN];
            file.read_exact(&mut prefix).map_err(|error| {
                if error.kind() == ErrorKind::UnexpectedEof {
                    EngineError::Corrupt(format!("staged pack {txn} is truncated"))
                } else {
                    EngineError::Io(error)
                }
            })?;
            let encoded_header_bytes = format::encoded_pack_header_len(&prefix)
                .map_err(|error| EngineError::Corrupt(format!("staged pack {txn}: {error}")))?;
            if encoded_header_bytes > file_bytes {
                return Err(EngineError::Corrupt(format!(
                    "staged pack {txn} header exceeds its file length"
                )));
            }
            let mut header_bytes = vec![0u8; encoded_header_bytes];
            header_bytes[..prefix.len()].copy_from_slice(&prefix);
            file.read_exact(&mut header_bytes[prefix.len()..])
                .map_err(|error| {
                    if error.kind() == ErrorKind::UnexpectedEof {
                        EngineError::Corrupt(format!("staged pack {txn} header is truncated"))
                    } else {
                        EngineError::Io(error)
                    }
                })?;
            let (header, payload_offset) = format::decode_pack_header(&header_bytes)
                .map_err(|error| EngineError::Corrupt(format!("staged pack {txn}: {error}")))?;
            if payload_offset != encoded_header_bytes {
                return Err(EngineError::Corrupt(format!(
                    "staged pack {txn} header length is inconsistent"
                )));
            }
            drop(header_bytes);
            self.validate_pack_lineage(&header)?;
            let header_epoch = header
                .attachment_epoch_value()
                .map_err(|error| EngineError::Corrupt(error.to_string()))?;
            match batch_epoch {
                Some(epoch) if header_epoch != epoch => break,
                None => batch_epoch = Some(header_epoch),
                Some(_) => {}
            }
            let candidate_materialized = materialized_bytes
                .checked_add(materialized_pack_bytes(&header).ok_or_else(|| {
                    EngineError::Corrupt("materialized pack length overflow".into())
                })?)
                .ok_or_else(|| {
                    EngineError::Corrupt("publisher materialized length overflow".into())
                })?;
            let working_set = pack_working_set_bytes(candidate_encoded, candidate_materialized)
                .ok_or_else(|| EngineError::Corrupt("publisher working-set overflow".into()))?;
            if working_set > publisher_working_set_limit() {
                if decoded.is_empty() {
                    return Err(EngineError::Corrupt(format!(
                        "staged pack {txn} exceeds the publisher working-set limit"
                    )));
                }
                break;
            }

            let payload_bytes = file_bytes - payload_offset;
            let mut payload = vec![0u8; payload_bytes];
            file.read_exact(&mut payload).map_err(|error| {
                if error.kind() == ErrorKind::UnexpectedEof {
                    EngineError::Corrupt(format!("staged pack {txn} payload is truncated"))
                } else {
                    EngineError::Io(error)
                }
            })?;
            let mut trailing = [0u8; 1];
            if file.read(&mut trailing)? != 0 {
                return Err(EngineError::Corrupt(format!(
                    "staged pack {txn} changed length while reading"
                )));
            }
            encoded_bytes = candidate_encoded;
            materialized_bytes = candidate_materialized;
            decoded.push((header, payload));
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
        leaves: &mut [LeafRef],
        map_chunks: &[u64],
        record_chunks: &[u64],
    ) -> Result<(i64, RemoteHead)> {
        let vol = &self.cfg.volume_id;
        let prepared = self.prepare_map_publication(base_generation, new_map, leaves, map_chunks);
        for (hash, encoded) in &prepared.leaf_nodes {
            self.blob
                .put_immutable(&chunk::keys::map_node(vol, &hex::encode(hash)), encoded)?;
        }
        let root_hex = hex::encode(prepared.root_hash);
        self.blob
            .put_immutable(&chunk::keys::map_node(vol, &root_hex), &prepared.root_bytes)?;
        let record =
            encode_commit_record(txn, new_generation, lease_epoch, &root_hex, record_chunks);
        self.blob.put_immutable(
            &chunk::keys::commit_record(vol, new_generation, txn),
            &record,
        )?;
        crashpoint::maybe_crash(crashpoint::BEFORE_CAS);

        let expected_head = remote_head(
            base_generation,
            prepared.base_root_hash,
            prepared.base_root_object_id.as_deref(),
        )?;
        let target_head = remote_head(
            new_generation,
            Some(prepared.root_hash),
            Some(&prepared.root_object_id),
        )?;
        let requested = self.authority.compare_and_swap_head(
            vol,
            self.size,
            &expected_head,
            &target_head,
            &self.cfg.attachment_id,
            self.epoch,
        );
        let new_gen = match requested {
            Ok(generation) => generation,
            Err(error @ (MetaError::Backend(_) | MetaError::CasConflict { .. })) => self
                .reconcile_ambiguous_cas(
                    error,
                    CasEvidence {
                        base_generation,
                        base_root_hash: prepared.base_root_hash,
                        base_root_object_id: prepared.base_root_object_id.as_deref(),
                        target_generation: new_generation,
                        target_root_hash: prepared.root_hash,
                        target_root_object_id: &prepared.root_object_id,
                    },
                )?,
            Err(error) => return Err(EngineError::Meta(error)),
        };
        crashpoint::maybe_crash(crashpoint::AFTER_CAS);
        if new_gen != new_generation {
            return Err(EngineError::Corrupt(
                "authority returned a generation different from the exact published head".into(),
            ));
        }
        leaves.clone_from_slice(&prepared.leaves);
        Ok((new_gen, target_head))
    }

    pub(super) fn prepare_map_publication(
        &self,
        base_generation: i64,
        new_map: &[ChunkRef],
        base_leaves: &[LeafRef],
        chunks: &[u64],
    ) -> PreparedMapPublication {
        // Capture the predecessor before replacing touched leaves. A CAS
        // response can be reconciled only against the complete before/after
        // heads, never generation alone.
        let (base_root_hash, base_root_object_id) = if base_generation == 0 {
            (None, None)
        } else {
            let encoded = format::encode_root(self.size, base_leaves);
            let hash = format::sha256(&encoded);
            (Some(hash), Some(format!("{}.node", hex::encode(hash))))
        };
        let mut leaves = base_leaves.to_vec();
        let mut leaf_nodes = Vec::new();
        let mut touched: Vec<u64> = chunks.iter().map(|c| c / CHUNKS_PER_LEAF as u64).collect();
        touched.sort_unstable();
        touched.dedup();
        for leaf_idx in touched {
            let first = leaf_idx * CHUNKS_PER_LEAF as u64;
            let end = (first + CHUNKS_PER_LEAF as u64).min(self.chunk_count);
            let slice = &new_map[first as usize..end as usize];
            if slice.iter().all(|r| r.is_hole()) {
                leaves[leaf_idx as usize] = LeafRef::Empty;
                continue;
            }
            let encoded = format::encode_leaf(first, slice);
            let hash = format::sha256(&encoded);
            let object_id = format!("{}.node", hex::encode(hash));
            leaves[leaf_idx as usize] = LeafRef::Present { hash, object_id };
            leaf_nodes.push((hash, encoded));
        }

        let root_bytes = format::encode_root(self.size, &leaves);
        let root_hash = format::sha256(&root_bytes);
        let root_hex = hex::encode(root_hash);
        let root_object_id = format!("{root_hex}.node");
        PreparedMapPublication {
            base_root_hash,
            base_root_object_id,
            leaf_nodes,
            root_bytes,
            root_hash,
            root_object_id,
            leaves,
        }
    }

    /// Resolve a CAS whose response did not prove whether the new root became
    /// authoritative. The PostgreSQL adapter orders this read behind the CAS,
    /// even when the original caller timed out while that statement ran.
    ///
    /// Root bytes are not enough: an attachment may have committed and then
    /// been revoked. Only the exact target generation/root under this same
    /// owner and epoch proves success. Every other authoritative change is an
    /// unrelated lineage and fails closed.
    fn reconcile_ambiguous_cas(&self, error: MetaError, evidence: CasEvidence<'_>) -> Result<i64> {
        let head = match self.authority.load_head(&self.cfg.volume_id) {
            Ok(head) => head,
            Err(_) => return Err(EngineError::Meta(error)),
        };

        if head.lease_owner.as_deref() != Some(self.cfg.attachment_id.as_str())
            || head.lease_epoch != self.epoch
        {
            return Err(EngineError::Meta(MetaError::Fenced));
        }
        if head.size_bytes == self.size
            && head.generation == evidence.target_generation
            && head.root_hash == Some(evidence.target_root_hash)
            && head.root_object_id.as_deref() == Some(evidence.target_root_object_id)
        {
            tracing::warn!(
                volume = %self.cfg.volume_id,
                generation = evidence.target_generation,
                "root CAS response was ambiguous; authoritative head proves it committed"
            );
            return Ok(evidence.target_generation);
        }

        // A transport/backend failure with the unchanged base is retryable:
        // the pack remains the local durability oracle. A reported conflict,
        // or any generation movement, means another lineage won.
        if matches!(&error, MetaError::Backend(_))
            && head.size_bytes == self.size
            && head.generation == evidence.base_generation
            && head.root_hash == evidence.base_root_hash
            && head.root_object_id.as_deref() == evidence.base_root_object_id
        {
            return Err(EngineError::Meta(error));
        }
        Err(EngineError::Meta(MetaError::CasConflict {
            expected: evidence.base_generation,
        }))
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
        let mut items: Vec<(String, &[u8])> = Vec::new();
        for (header, payload) in packs {
            for entry in header.entries.iter().filter(|entry| !entry.is_discard()) {
                let bytes = entry_payload(entry, payload)?;
                let object_id = Self::object_id(&header.txn, entry);
                items.push((chunk::keys::data(vol, &object_id), bytes));
            }
        }

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
        #[cfg(test)]
        let background_publisher = is_background_publisher_context();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    #[cfg(test)]
                    let _publisher_context =
                        BackgroundPublisherContext::enter(background_publisher);
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
    /// CAS the batch's earlier pack files are covered by the authoritative
    /// generation and are discarded — correct, because their content is
    /// already in the committed map. On a crash before it, recovery may replay
    /// a smaller prefix through this same path and write intermediate records.
    /// The final record therefore binds the last pack's own txn/chunks while
    /// its Root binds the whole applied prefix: regrouping produces identical
    /// bytes for the same final key without persisting a batch identity.
    pub(super) fn commit_pack_batch(
        &self,
        packs: &[(&PackHeader, &[u8])],
        base_map: Vec<ChunkRef>,
        base_leaves: Vec<LeafRef>,
    ) -> Result<i64> {
        let first = packs
            .first()
            .ok_or_else(|| EngineError::Corrupt("commit batch must not be empty".into()))?
            .0;
        let base_generation = first.base_generation;
        let pack_count = i64::try_from(packs.len())
            .map_err(|_| EngineError::Corrupt("commit batch length exceeds i64".into()))?;
        let new_generation = base_generation
            .checked_add(pack_count)
            .ok_or_else(|| EngineError::Corrupt("commit generation overflow".into()))?;

        let batch_epoch = first
            .attachment_epoch_value()
            .map_err(|error| EngineError::Corrupt(error.to_string()))?;
        let mut expected_generation = base_generation;
        let mut txns = HashSet::with_capacity(packs.len());
        for (header, payload) in packs {
            self.validate_pack_lineage(header)?;
            if header.volume_id != self.cfg.volume_id {
                return Err(EngineError::Corrupt("commit batch volume mismatch".into()));
            }
            if header.base_generation != expected_generation {
                return Err(EngineError::Corrupt(format!(
                    "commit batch generation gap: expected {expected_generation}, found {}",
                    header.base_generation
                )));
            }
            if header
                .attachment_epoch_value()
                .map_err(|error| EngineError::Corrupt(error.to_string()))?
                != batch_epoch
            {
                return Err(EngineError::Corrupt(
                    "commit batch crosses lease epochs".into(),
                ));
            }
            if !txns.insert(header.txn.as_str()) {
                return Err(EngineError::Corrupt(
                    "commit batch reuses a transaction id".into(),
                ));
            }
            validate_pack_entries(header, payload, self.chunk_count)?;
            expected_generation = expected_generation
                .checked_add(1)
                .ok_or_else(|| EngineError::Corrupt("commit generation overflow".into()))?;
        }
        debug_assert_eq!(expected_generation, new_generation);

        // Establish the complete generation range before materialization can
        // read remote bases and, critically, before this batch can issue any
        // immutable PUT or authority CAS. Exhaustion therefore leaves no
        // orphaned remote objects behind.
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
        let last = packs
            .last()
            .expect("non-empty batch was checked before materialization")
            .0;

        // 1. Data objects for the whole batch (idempotent keys from the txns).
        self.upload_batch(packs)?;
        crashpoint::maybe_crash(crashpoint::AFTER_DATA_UPLOAD);

        // 2. Apply the packs to the map in chain order.
        let mut new_map = base_map;
        let mut map_chunks: Vec<u64> = Vec::new();
        for (header, _) in packs {
            Self::apply_pack_entries(&mut new_map, header)?;
            map_chunks.extend(header.entries.iter().map(|e| e.chunk_idx));
        }
        map_chunks.sort_unstable();
        map_chunks.dedup();
        let mut record_chunks: Vec<u64> =
            last.entries.iter().map(|entry| entry.chunk_idx).collect();
        record_chunks.sort_unstable();
        record_chunks.dedup();

        // 3-5. Map, root, commit record, CAS jumping one step per pack.
        let mut new_leaves = base_leaves;
        let (new_gen, remote_head) = self.publish_map(
            &last.txn,
            base_generation,
            new_generation,
            last.attachment_epoch_value()
                .map_err(|error| EngineError::Corrupt(error.to_string()))?,
            &new_map,
            &mut new_leaves,
            &map_chunks,
            &record_chunks,
        )?;

        // 6. Swap in the committed map.
        {
            let mut st = self.state.lock().unwrap();
            st.map = new_map;
            st.leaf_refs = new_leaves;
            st.generation = new_gen;
            st.remote_head = remote_head;
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
        let page_bytes = cats_protocol::chunk::DIRTY_PAGE_SIZE as usize;
        let mut outputs: Vec<Vec<u8>> = packs
            .iter()
            .map(|(header, _)| {
                materialized_pack_bytes(header)
                    .map(Vec::with_capacity)
                    .ok_or_else(|| EngineError::Corrupt("materialized pack length overflow".into()))
            })
            .collect::<Result<_>>()?;
        let mut materialized_entries: Vec<Vec<Option<PackEntry>>> = packs
            .iter()
            .map(|(header, _)| vec![None; header.entries.len()])
            .collect();
        let mut chunks: Vec<u64> = packs
            .iter()
            .flat_map(|(header, _)| header.entries.iter().map(|entry| entry.chunk_idx))
            .collect();
        chunks.sort_unstable();
        chunks.dedup();

        // Process one chunk through every pack before moving to the next. This
        // preserves cross-pack overlay order while holding exactly one 4 MiB
        // image scratch instead of a HashMap of every touched chunk image.
        for chunk_idx in chunks {
            let base_ref = base_map
                .get(chunk_idx as usize)
                .ok_or_else(|| EngineError::Corrupt("pack chunk is out of bounds".into()))?;
            let mut image: Option<Vec<u8>> = None;
            for (pack_index, (header, payload)) in packs.iter().enumerate() {
                for (entry_index, entry) in header.entries.iter().enumerate() {
                    if entry.chunk_idx != chunk_idx {
                        continue;
                    }
                    let output = &mut outputs[pack_index];
                    if entry.is_discard() {
                        match &mut image {
                            Some(image) => image.fill(0),
                            None => image = Some(vec![0u8; CHUNK_SIZE as usize]),
                        }
                        materialized_entries[pack_index][entry_index] = Some(PackEntry {
                            chunk_idx,
                            payload_offset: output.len() as u64,
                            len: 0,
                            sha256_hex: hex::encode(format::sha256(&[])),
                            page_mask: 0,
                            byte_ranges: Vec::new(),
                        });
                        continue;
                    }
                    if image.is_none() {
                        image = Some(self.fetch_chunk_image(base_ref)?);
                    }
                    let image = image.as_mut().expect("initialized");
                    apply_local_entry(image, entry, payload)?;

                    let start = output.len();
                    if entry.is_base() {
                        output.extend_from_slice(image);
                    } else {
                        for page in 0..cats_protocol::chunk::PAGES_PER_CHUNK {
                            if entry.page_mask & (1u64 << page) == 0 {
                                continue;
                            }
                            let at = page as usize * page_bytes;
                            output.extend_from_slice(&image[at..at + page_bytes]);
                        }
                    }
                    let bytes = &output[start..];
                    materialized_entries[pack_index][entry_index] = Some(PackEntry {
                        chunk_idx,
                        payload_offset: start as u64,
                        len: bytes.len() as u32,
                        sha256_hex: hex::encode(format::sha256(bytes)),
                        page_mask: entry.page_mask,
                        byte_ranges: Vec::new(),
                    });
                }
            }
        }

        packs
            .iter()
            .zip(outputs)
            .zip(materialized_entries)
            .map(|(((header, _), output), entries)| {
                let entries = entries
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| {
                        EngineError::Corrupt("pack materialization omitted an entry".into())
                    })?;
                Ok((
                    PackHeader {
                        txn: header.txn.clone(),
                        volume_id: header.volume_id.clone(),
                        base_generation: header.base_generation,
                        lease_epoch: header.lease_epoch,
                        attachment_id: header.attachment_id.clone(),
                        attachment_epoch: header.attachment_epoch,
                        acquire_origin: header.acquire_origin.clone(),
                        entries,
                    },
                    output,
                ))
            })
            .collect()
    }

    /// Apply one pack's entries onto a map: a base entry replaces the chunk's
    /// reference outright, a delta entry appends a layer to whatever the chunk
    /// already had, a discard turns it into a hole (GC removes the orphaned
    /// objects, and a cold read of the chunk then costs nothing at all).
    pub(super) fn apply_pack_entries(map: &mut [ChunkRef], header: &PackHeader) -> Result<()> {
        for e in &header.entries {
            let index = usize::try_from(e.chunk_idx)
                .map_err(|_| EngineError::Corrupt("pack chunk index exceeds usize".into()))?;
            let slot = map
                .get_mut(index)
                .ok_or_else(|| EngineError::Corrupt("pack chunk is out of bounds".into()))?;
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
                #[cfg(test)]
                let _publisher_context = BackgroundPublisherContext::enter(true);
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

fn remote_head(
    generation: i64,
    root_hash: Option<[u8; 32]>,
    root_object_id: Option<&str>,
) -> Result<RemoteHead> {
    let generation = u64::try_from(generation)
        .ok()
        .and_then(Generation::new)
        .ok_or_else(|| EngineError::Corrupt("head generation is outside the wire range".into()))?;
    let root_object_id = root_object_id
        .map(|value| {
            AsciiText::new(value.to_string())
                .ok_or_else(|| EngineError::Corrupt("root object id is not valid ASCII".into()))
        })
        .transpose()?;
    Ok(RemoteHead {
        generation,
        root_hash: root_hash.map(Sha256Digest::from_bytes),
        root_object_id,
    })
}

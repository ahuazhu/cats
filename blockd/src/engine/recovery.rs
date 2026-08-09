use super::*;

impl ChunkEngine {
    pub(super) fn recover_pending_packs(&self) -> Result<()> {
        let dir = self.cfg.data_dir.join(PENDING_PACK_DIR);
        let mut packs = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name.ends_with(PACK_FILE_SUFFIX) {
                packs.push(path);
            } else if name.starts_with(".tmp-") {
                // Torn pack write: never renamed, safe to drop.
                let _ = fs::remove_file(&path);
            }
        }
        packs.sort();

        if matches!(self.cfg.durability, DurabilityMode::Relaxed { .. }) {
            return self.recover_relaxed_queue(packs);
        }

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
            let head = self.authority.load_head(&self.cfg.volume_id)?;
            if head.generation > header.base_generation {
                // A sole serialized publisher can advance past this exact
                // contiguous pack only by a successful batch CAS that included
                // it. Intermediate packs intentionally have no commit record;
                // the authoritative head is the cleanup oracle for both
                // Strict and Relaxed recovery.
                tracing::info!(txn = %header.txn, "pack covered by authoritative head; cleaning up");
                let _ = fs::remove_file(&path);
                continue;
            }
            if head.generation < header.base_generation {
                return Err(EngineError::Corrupt(format!(
                    "pending pack chain is ahead of authority: head generation {}, pack base {}",
                    head.generation, header.base_generation
                )));
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

    /// Rebuild a relaxed local durability queue without issuing a remote write.
    ///
    /// A blockd restart on the same Host must not turn an S3/DB outage into an
    /// attach failure after the committed map has been loaded. Packs below the
    /// remote generation were already included by a successful (possibly
    /// batched) CAS and are local cleanup residue. Packs from the remote
    /// generation onward are the acknowledged local chain and must be kept in
    /// exact generation order.
    pub(super) fn recover_relaxed_queue(&self, packs: Vec<PathBuf>) -> Result<()> {
        let committed = self.generation();
        let mut expected = committed;
        let mut recovered = std::collections::VecDeque::new();
        let mut recovered_bytes = 0u64;

        for path in packs {
            let bytes = fs::read(&path)?;
            let (header, _payload) = format::decode_pack(&bytes)
                .map_err(|error| EngineError::Corrupt(format!("staged pack: {error}")))?;
            if header.volume_id != self.cfg.volume_id {
                return Err(EngineError::Corrupt("pack volume id mismatch".into()));
            }
            if header.base_generation < committed {
                // A prior batch CAS included this generation. It is safe to
                // remove the stale local file; the committed map is the truth.
                let _ = fs::remove_file(&path);
                continue;
            }
            if header.base_generation != expected {
                return Err(EngineError::Corrupt(format!(
                    "relaxed pack chain has a gap: expected base generation \
                     {expected}, found {}",
                    header.base_generation
                )));
            }

            let metadata = fs::metadata(&path)?;
            let encoded_bytes = metadata.len();
            let staged_at_unix_ms = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or_else(unix_time_ms);
            let chunks = header.entries.iter().map(|entry| entry.chunk_idx).collect();
            recovered.push_back(StagedPack {
                txn: header.txn,
                path,
                encoded_bytes,
                staged_at_unix_ms,
                chunks,
            });
            recovered_bytes = recovered_bytes.saturating_add(encoded_bytes);
            expected = expected.checked_add(1).ok_or_else(|| {
                EngineError::Corrupt("relaxed pack generation range overflows".into())
            })?;
        }

        let mut staged = self.staged.lock().unwrap();
        staged.packs = recovered;
        staged.bytes = recovered_bytes;
        staged.next_base = expected;
        drop(staged);

        // The persistent page bitmap cannot distinguish bytes already captured
        // by a relaxed pack from post-barrier, unacknowledged writes. The packs
        // are the local durability oracle after a process crash, so discard the
        // latter conservatively and rebuild cache completeness from the remote
        // map plus those exact overlays on demand.
        {
            let mut st = self.state.lock().unwrap();
            st.dirty.fill(0);
            st.dirty_ranges.iter_mut().for_each(Vec::clear);
            st.discarded.clear();
            st.hydrated.fill(false);
            st.freezing.clear();
        }
        {
            let bitmap = self.bitmap.lock().unwrap();
            for chunk in 0..self.chunk_count {
                bitmap.write_all_at(&0u64.to_le_bytes(), BITMAP_HEADER_LEN + chunk * 8)?;
            }
            bitmap.sync_data()?;
        }
        Ok(())
    }
}

use super::*;

/// What one garbage-collection pass found and removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcStats {
    pub data_objects_live: usize,
    pub data_objects_deleted: usize,
    pub map_nodes_live: usize,
    pub map_nodes_deleted: usize,
}

impl ChunkEngine {
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
            .spawn(move || {
                loop {
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
                }
            })
            .expect("spawn gc thread");
        *self.gc_thread.lock().unwrap() = Some(handle);
    }
}

use super::*;
use cats_api::blockd::DurabilityStatus;

/// When a FLUSH acknowledgment is allowed to reach the Guest (ADR-0022).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityMode {
    /// FLUSH acks only after the commit is durable in the object store and the
    /// map CAS has succeeded (spec §6). Any acknowledged write survives losing
    /// the host outright.
    Strict,
    /// FLUSH acks once the pack is durable on the local disk; a background
    /// committer publishes staged packs in order — on its timer, and eagerly
    /// whenever the queue crosses `EAGER_DRAIN_WATERMARK`, so the interval
    /// bounds the idle-tail latency rather than paces bursts.
    /// Acknowledged-but-unpublished writes survive a blockd crash on the same
    /// host (pack replay), but not the loss of the host. The authoritative RPO
    /// is the observed age/bytes between the local and remote watermarks. The
    /// drain interval is a target, not a bound: a remote outage can extend it.
    ///
    /// `drain_interval_ms == 0` disables the background committer entirely;
    /// explicit drains still work. This is a deterministic mode for tests.
    Relaxed { drain_interval_ms: u64 },
}

impl ChunkEngine {
    pub fn durability_status(&self) -> DurabilityStatus {
        let (remote_durable_generation, remote_head) = {
            let state = self.state.lock().unwrap();
            (state.generation, state.remote_head.clone())
        };
        let unstaged_reservation = self.unstaged_pack_reservation_bytes();
        let staged = self.staged.lock().unwrap();
        let unpublished_generations = staged.packs.len();
        let unpublished_bytes = staged.bytes;
        let local_allocated_bytes = self
            .cache_allocated_bytes()
            .unwrap_or(0)
            .saturating_add(unpublished_bytes);
        let local_accounted_bytes = local_allocated_bytes
            .saturating_add(unstaged_reservation)
            .saturating_add(self.inflight_staging_bytes.load(Ordering::Relaxed));
        let oldest_unpublished_age_ms = staged
            .packs
            .front()
            .map(|pack| unix_time_ms().saturating_sub(pack.staged_at_unix_ms))
            .unwrap_or(0);
        let lineage = self
            .authorized_attachment
            .as_ref()
            .map(|attachment| &attachment.identity);
        let status = DurabilityStatus {
            volume_id: self.cfg.volume_id.clone(),
            attachment_id: self.cfg.attachment_id.clone(),
            attachment_epoch: lineage.map(|identity| identity.attachment_epoch),
            acquire_origin: lineage.map(|identity| identity.acquire_origin.clone()),
            node_id: lineage.map(|identity| identity.node_id.clone()),
            placement_epoch: lineage.map(|identity| identity.placement_epoch),
            guest_io_enabled: lineage.map(|_| self.guest_io_enabled),
            // Process-attempt identity belongs to the composition root, not
            // the storage engine. The target control server fills these only
            // when exact signed CLI inputs are present.
            size_bytes: None,
            scope_id: None,
            process_identity_token: None,
            device_ownership_token: None,
            control_only: None,
            remote_head: self.authorized_attachment.as_ref().map(|_| remote_head),
            mode: match self.cfg.durability {
                DurabilityMode::Strict => "strict",
                DurabilityMode::Relaxed { .. } => "relaxed",
            }
            .to_string(),
            local_durable_generation: staged.next_base,
            remote_durable_generation,
            unpublished_generations,
            unpublished_bytes,
            oldest_unpublished_age_ms,
            max_unpublished_generations: self.cfg.max_staged_packs,
            max_unpublished_bytes: self.cfg.max_staged_bytes,
            local_allocated_bytes,
            local_accounted_bytes,
            max_local_bytes: self.cfg.max_local_bytes,
            evicted_cache_chunks: self.evicted_cache_chunks.load(Ordering::Relaxed),
            backpressured: unpublished_generations >= self.cfg.max_staged_packs
                || unpublished_bytes >= self.cfg.max_staged_bytes
                || local_accounted_bytes >= self.cfg.max_local_bytes
                || self.backpressure_waiters.load(Ordering::Relaxed) != 0,
            fenced: self.is_fenced(),
            last_publish_error: self.last_publish_error.lock().unwrap().clone(),
        };
        drop(staged);
        status
    }
}

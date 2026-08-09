use super::*;

impl ChunkEngine {
    pub(super) fn start_renew_thread(self: &Arc<Self>) {
        let engine = Arc::downgrade(self);
        let stop = self.stop_renew.clone();
        let interval = Duration::from_millis((self.cfg.lease_ttl_ms / 3).max(50) as u64);
        let handle = std::thread::Builder::new()
            .name("lease-renew".into())
            .spawn(move || {
                loop {
                    // Waiting on a condvar rather than sleeping: a detach has to be able
                    // to interrupt this. A plain sleep made every stop, suspend and
                    // migration wait out up to a third of the lease TTL per volume.
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
                    match engine.authority.renew_lease(
                        &engine.cfg.volume_id,
                        &engine.cfg.attachment_id,
                        engine.epoch,
                        engine.cfg.lease_ttl_ms,
                    ) {
                        Ok(()) => {}
                        // The row no longer names this attachment and epoch: the
                        // lease was revoked or acquired by someone else. That is
                        // the one terminal outcome.
                        Err(e @ (MetaError::Fenced | MetaError::NotFound(_))) => {
                            tracing::error!("lease renewal failed; fencing writes: {e}");
                            engine.fenced.store(true, Ordering::SeqCst);
                            engine.staged_space.notify_all();
                            engine.local_space.notify_all();
                            return;
                        }
                        // A slow or unreachable metadata store is not a fence: the
                        // row still names this attachment, so the next attempt
                        // renews straight through an expiry lapse, and publishes
                        // stay guarded by the epoch CAS in the meantime.
                        Err(e) => {
                            tracing::warn!("lease renewal attempt failed; will retry: {e}");
                        }
                    }
                }
            })
            .expect("spawn lease renew thread");
        *self.renew_thread.lock().unwrap() = Some(handle);
    }

    /// Graceful detach: publish every locally acknowledged generation before
    /// releasing the lease. A failed drain keeps renewal, the lease and all
    /// local journal files alive so the caller can retry; silently releasing
    /// them would turn a transient remote outage into acknowledged data loss.
    pub fn detach(&self) -> Result<()> {
        let AuthorityBackend::Legacy(metadata) = &self.authority else {
            return Err(EngineError::GuestIoDisabled);
        };
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        self.drain_staged()?;
        self.stop_renewal();
        metadata.release_lease(&self.cfg.volume_id, &self.cfg.attachment_id, self.epoch)?;
        Ok(())
    }

    /// Stop a target-authority serving process without releasing or otherwise
    /// mutating attachment ownership. The Runtime reconciler owns the later
    /// exact release transition.
    pub fn stop_authorized_serving(&self) -> Result<()> {
        if !matches!(&self.authority, AuthorityBackend::Target(_))
            || self.authorized_attachment.is_none()
        {
            return Err(EngineError::InvalidConfig(
                "engine is not an authorized target serving attachment".into(),
            ));
        }
        if self.is_fenced() {
            return Err(EngineError::Fenced);
        }
        self.drain_staged()?;
        self.stop_renewal();
        Ok(())
    }

    pub(super) fn stop_renewal(&self) {
        let (lock, cv) = &*self.stop_renew;
        *lock.lock().unwrap() = true;
        cv.notify_all();
        let (lock, cv) = &*self.committer_signal;
        lock.lock().unwrap().stop = true;
        cv.notify_all();
        if let Some(handle) = self.renew_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.gc_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.committer_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

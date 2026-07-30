use super::*;

impl NodeRuntime {
    pub(super) fn run_action(&self, job: &NodeJob) -> Result<ObservedState> {
        match &job.action {
            NodeJobAction::StartCat {
                cat_id,
                volumes,
                cpus,
                memory_mib,
                ..
            } => {
                // Launches are no longer serialized node-wide, so they need
                // their own ceiling; see `launch_admission`. Warm restore
                // charges the wake budget inside `restore_cat`, so this stays on
                // the StartCat action only.
                let _permit = self
                    .launch_admission
                    .acquire(resume_commitment_bytes(*memory_mib))
                    .with_context(|| format!("admit launch of cat {cat_id}"))?;
                self.start_cat(
                    cat_id,
                    job.cat_generation,
                    volumes.clone(),
                    *cpus,
                    *memory_mib,
                    false,
                )
            }
            NodeJobAction::StopCat { cat_id } => self.stop_cat(cat_id, true),
            NodeJobAction::SuspendCat { cat_id, work_fence } => {
                self.suspend_cat(cat_id, work_fence.as_ref())
            }
            NodeJobAction::ResumeCat { cat_id } => self.resume_cat(cat_id),
            NodeJobAction::WarmCat { cat_id } => self.warm_cat(cat_id),
            NodeJobAction::RestoreCat { cat_id } => self.restore_cat(cat_id, job.cat_generation),
            NodeJobAction::AttachDisk { cat_id, volume } => {
                self.attach_disk(cat_id, volume.clone())
            }
            NodeJobAction::DetachDisk { cat_id, disk_id } => self.detach_disk(cat_id, disk_id),
            NodeJobAction::SyncCat { cat_id } => self.sync_cat(cat_id),
            NodeJobAction::CleanupCat { cat_id } => self.stop_cat(cat_id, false),
        }
    }

    // ------------------------------------------------------------------
    // Suspend / resume (pause + page-out)
    // ------------------------------------------------------------------

    fn suspend_cat(
        &self,
        cat_id: &str,
        work_fence: Option<&SuspendWorkFence>,
    ) -> Result<ObservedState> {
        let (conn, activity) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if rt.state == ObservedState::Suspended {
                return Ok(ObservedState::Suspended);
            }
            if rt.state != ObservedState::Running {
                bail!("cannot suspend from {:?}", rt.state);
            }
            (rt.conn(), rt.activity.clone())
        };

        // Close the Node proxy/exec gate before asking the Guest Agent to
        // close its user-work gate. Any rejected arrival increments the local
        // sequence and cancels this suspend.
        let node_sequence = activity.prepare()?;
        let attempt = (|| -> Result<()> {
            let mut client = conn.connect()?;
            let expected_guest_sequence = match work_fence {
                Some(fence) => fence.guest_lease_sequence,
                None => client.work_status(None, 0)?.lease_sequence,
            };
            client.prepare_suspend(expected_guest_sequence)?;

            // ADR-0002 order: quiesce + durable FLUSH before pausing.
            client.syncfs()?;
            let guest_status = client.work_status(None, 0)?;
            if guest_status.lease_sequence != expected_guest_sequence
                || !activity.unchanged_since(node_sequence)
            {
                let _ = client.abort_suspend();
                return Err(ActivityChanged.into());
            }

            let mut cats = self.cats.lock().unwrap();
            let rt = cats
                .get_mut(cat_id)
                .context("cat vanished during suspend")?;
            if rt.state != ObservedState::Running {
                let _ = client.abort_suspend();
                return Err(ActivityChanged.into());
            }
            match &rt.ch {
                Some(chrt) => ch::pause(&chrt.api_sock)?,
                None => {
                    let guest = rt.guest.as_ref().context("guest process missing")?;
                    signal(guest, libc::SIGSTOP);
                }
            }
            let page_out_target = match &rt.ch {
                Some(chrt) => Some((
                    rt.guest.as_ref().context("VMM process missing")?.id(),
                    chrt.memory_file.clone(),
                )),
                None => None,
            };
            rt.state = ObservedState::Suspended;
            drop(cats);

            // A proxy/exec can arrive in the tiny pause window. It never
            // enters the guest, but it does invalidate the gate. Resume now;
            // the control plane will retry after the work event is visible.
            if !activity.unchanged_since(node_sequence) {
                let mut cats = self.cats.lock().unwrap();
                let rt = cats.get_mut(cat_id).context("cat vanished after pause")?;
                match &rt.ch {
                    Some(chrt) => ch::resume(&chrt.api_sock)?,
                    None => {
                        let guest = rt.guest.as_ref().context("guest process missing")?;
                        signal(guest, libc::SIGCONT);
                    }
                }
                rt.state = ObservedState::Running;
                drop(cats);
                let mut resumed = conn.connect()?;
                let _ = resumed.abort_suspend();
                return Err(ActivityChanged.into());
            }
            if let Some((vmm_pid, memory_file)) = page_out_target {
                match ch::page_out_memory(vmm_pid, &memory_file) {
                    Ok(stats) => tracing::info!(
                        cat = %cat_id,
                        vmm_pid,
                        ranges = stats.ranges,
                        advised_bytes = stats.bytes_advised,
                        rss_before_bytes = stats.rss_before_bytes,
                        rss_after_bytes = stats.rss_after_bytes,
                        "paged out suspended Guest memory"
                    ),
                    Err(error) => {
                        // Never report a pause-only Cat as Suspended. Return it
                        // to Running and let the controller retry or demote it.
                        let mut cats = self.cats.lock().unwrap();
                        let rt = cats
                            .get_mut(cat_id)
                            .context("cat vanished after page-out failure")?;
                        let chrt = rt.ch.as_ref().context("CH runtime missing")?;
                        ch::resume(&chrt.api_sock)?;
                        rt.state = ObservedState::Running;
                        bail!("Guest memory page-out failed: {error:#}");
                    }
                }
            }
            Ok(())
        })();

        if attempt.is_err() {
            activity.open();
            if let Ok(mut client) = conn.connect() {
                let _ = client.abort_suspend();
            }
        }
        attempt.map(|()| ObservedState::Suspended)
    }

    fn resume_cat(&self, cat_id: &str) -> Result<ObservedState> {
        // Read the commitment and drop the lock: `acquire` may block on other
        // wakes, and holding `cats` across that wait would deadlock every
        // other job on this node.
        let memory_mib = {
            let cats = self.cats.lock().unwrap();
            let rt = cats.get(cat_id).context("cat is not on this node")?;
            if rt.state == ObservedState::Running {
                return Ok(ObservedState::Running);
            }
            if rt.state != ObservedState::Suspended {
                bail!("cannot resume from {:?}", rt.state);
            }
            rt.memory_mib
        };
        // Held until this wake finishes; released on every exit path.
        let _permit = self
            .admission
            .acquire(resume_commitment_bytes(memory_mib))
            .with_context(|| format!("admit resume of cat {cat_id}"))?;

        let mut cats = self.cats.lock().unwrap();
        // The Cat may have moved while this wake sat in the queue.
        let rt = cats.get_mut(cat_id).context("cat is not on this node")?;
        if rt.state == ObservedState::Running {
            return Ok(ObservedState::Running);
        }
        if rt.state != ObservedState::Suspended {
            bail!("cannot resume from {:?}", rt.state);
        }
        match &rt.ch {
            Some(chrt) => ch::resume(&chrt.api_sock)?,
            None => {
                let guest = rt.guest.as_ref().context("guest process missing")?;
                signal(guest, libc::SIGCONT);
            }
        }
        let expected = rt.boot_id.clone();
        let conn = rt.conn();
        drop(cats);
        // The resumed guest must be the same one (boot_id preserved).
        let mut client = conn.connect()?;
        let (boot_id, _) = client.health()?;
        if expected.as_deref() != Some(boot_id.as_str()) {
            bail!("resume produced a different boot id");
        }
        let mut cats = self.cats.lock().unwrap();
        let rt = cats.get_mut(cat_id).context("cat vanished during resume")?;
        rt.state = ObservedState::Running;
        rt.activity.open();
        let conn = rt.conn();
        drop(cats);
        if let Ok(mut client) = conn.connect() {
            let _ = client.abort_suspend();
        }
        Ok(ObservedState::Running)
    }

    // ------------------------------------------------------------------
    // Warm (snapshot + exit) / restore
    // ------------------------------------------------------------------

    fn warm_cat(&self, cat_id: &str) -> Result<ObservedState> {
        let mut cats = self.cats.lock().unwrap();
        let rt = cats.get_mut(cat_id).context("cat is not on this node")?;
        match rt.state {
            ObservedState::Warm => return Ok(ObservedState::Warm),
            // A prior FakeVmm attempt may have stopped the Guest and then
            // failed its remote drain. Its blockds and local journals remain,
            // so the same job can retry the drain without recreating state.
            ObservedState::Warming if rt.ch.is_none() && rt.guest.is_none() => {}
            ObservedState::Suspended | ObservedState::Running => {}
            other => bail!("cannot warm from {other:?}"),
        }
        // CH mode: real memory snapshot, then everything exits (ADR-0002).
        if rt.ch.is_some() {
            let api = rt.ch.as_ref().expect("checked").api_sock.clone();
            if rt.state != ObservedState::Suspended {
                // Not paused yet: durable flush first, then pause.
                let mut client = rt.conn().connect()?;
                client.syncfs()?;
                ch::pause(&api)?;
            }
            // Warm is a forced remote-drain point (ADR-0022): the VMM exits and a
            // restore may happen after this host is long gone.
            for proc in rt.blockds.values() {
                proc.drain()
                    .with_context(|| format!("warm drain of {}", proc.grant.disk_id))?;
            }
            let memory_file = rt.ch.as_ref().expect("checked").memory_file.clone();
            ch::sync_memory_backing(&memory_file)?;
            let snap_dir = rt.dir.join("snapshot");
            let _ = std::fs::remove_dir_all(&snap_dir);
            ch::snapshot(&api, &snap_dir)?;
            if let Some(mut vmm) = rt.guest.take() {
                ch::shutdown_vmm(&api, &mut vmm);
            }
            let nbd_devices: Vec<String> = rt
                .ch
                .as_ref()
                .expect("checked")
                .nbd
                .values()
                .cloned()
                .collect();
            if let VmmMode::CloudHypervisor(chc) = &self.cfg.vmm {
                for dev in &nbd_devices {
                    ch::nbd_detach(chc, dev);
                }
            }
            let cat_dir = rt.dir.clone();
            for (_, mut p) in rt.blockds.drain() {
                let _ = p.child.kill();
                let _ = p.child.wait();
                p.remove_socket_files(&cat_dir);
            }
            if let Some(chrt) = &mut rt.ch {
                chrt.snapshot_dir = Some(snap_dir);
            }
            rt.state = ObservedState::Warm;
            return Ok(ObservedState::Warm);
        }
        if rt.guest.is_some() {
            if let Some(g) = &rt.guest {
                signal(g, libc::SIGCONT); // wake a suspended guest to snapshot it
            }
            let mut client = rt.conn().connect()?;
            // First freeze the Guest-visible state locally and persist the
            // process identity. The Guest must then exit before the remote
            // drain, otherwise a late fsync could advance the local watermark
            // after the supposedly final publish.
            client.syncfs()?;
            client.save_state(&rt.state_file())?;
            let _ = client.shutdown();
            if let Some(mut g) = rt.guest.take() {
                let _ = g.kill();
                let _ = g.wait();
            }
            rt.state = ObservedState::Warming;
        }
        for proc in rt.blockds.values() {
            proc.drain()
                .with_context(|| format!("warm drain of {}", proc.grant.disk_id))?;
        }
        let cat_dir = rt.dir.clone();
        for (_, mut p) in rt.blockds.drain() {
            let _ = p.child.kill();
            let _ = p.child.wait();
            p.remove_socket_files(&cat_dir);
        }
        rt.state = ObservedState::Warm;
        Ok(ObservedState::Warm)
    }

    fn restore_cat(&self, cat_id: &str, generation: i64) -> Result<ObservedState> {
        let (volumes, expected_boot_id, cpus, memory_mib) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            if rt.state != ObservedState::Warm {
                bail!("cannot restore from {:?}", rt.state);
            }
            match &rt.ch {
                Some(chrt) => {
                    anyhow::ensure!(
                        chrt.snapshot_dir.as_ref().is_some_and(|d| d.exists()),
                        "warm snapshot is missing"
                    );
                }
                None => anyhow::ensure!(rt.state_file().exists(), "warm snapshot is missing"),
            }
            (
                rt.volumes.clone(),
                rt.boot_id.clone(),
                rt.cpus,
                rt.memory_mib,
            )
        };
        // Warm reads Guest RAM back out of the snapshot, so it is charged the
        // same resume commitment as Suspended (ADR-0002 §8). Acquired before
        // any state is torn down so a queued restore stays restorable.
        let _permit = self
            .admission
            .acquire(resume_commitment_bytes(memory_mib))
            .with_context(|| format!("admit warm restore of cat {cat_id}"))?;
        {
            // Re-validate: the Cat may have moved while queued.
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            if rt.state != ObservedState::Warm {
                bail!("cannot restore from {:?}", rt.state);
            }
        }
        self.retire_warm_metering(cat_id)?;
        // CH mode keeps the runtime entry (start_cat_ch consumes it).
        if matches!(self.cfg.vmm, VmmMode::Fake) {
            self.cats.lock().unwrap().remove(cat_id);
        }
        // Re-launch on the preserved local state (cache + snapshot). The
        // fake VMM re-acquires the volume leases; the production vhost
        // implementation keeps the lease alive across Warm instead.
        let observed = self.start_cat(cat_id, generation, volumes, cpus, memory_mib, true)?;
        // A real VMM snapshot preserves the Guest Agent's quiescing bit.
        // Restoring is a committed wake, so reopen the Guest-side admission
        // gate before reporting Running. FakeVmm restores a fresh registry;
        // AbortSuspend is harmless there too.
        if let Some(conn) = self.cats.lock().unwrap().get(cat_id).map(CatRuntime::conn) {
            if let Ok(mut client) = conn.connect() {
                client.abort_suspend()?;
            }
        }
        let now_boot = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .and_then(|rt| rt.boot_id.clone());
        if expected_boot_id.is_some() && now_boot != expected_boot_id {
            let _ = self.stop_cat(cat_id, false);
            bail!("warm restore lost process identity");
        }
        Ok(observed)
    }

    // ------------------------------------------------------------------
    // Hot attach / detach
    // ------------------------------------------------------------------

    fn attach_disk(&self, cat_id: &str, grant: VolumeGrant) -> Result<ObservedState> {
        let activity = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .context("cat is not running on this node")?
            .activity
            .clone();
        let _activity = activity.acquire()?;
        let mut cats = self.cats.lock().unwrap();
        let rt = cats
            .get_mut(cat_id)
            .context("cat is not running on this node")?;
        if rt.state != ObservedState::Running {
            bail!("hot attach requires a running cat");
        }
        if rt.ch.is_some() {
            // vm.add-disk hotplug lands with the vhost-user milestone; cold
            // cats pick bindings up at the next start.
            bail!("hot attach is not supported in Cloud Hypervisor mode yet");
        }
        if rt.blockds.contains_key(&grant.disk_id) {
            return Ok(ObservedState::Running); // idempotent
        }
        let dir = rt.dir.clone();
        // Unreachable in Cloud Hypervisor mode (hot attach is rejected above).
        let proc = self.spawn_blockd(cat_id, &dir, &grant, 1, None)?;
        let process_id = proc.child.id();
        rt.blockds.insert(grant.disk_id.clone(), proc);
        if let Err(error) = self.attach_to_metering(rt, process_id) {
            if let Some(mut proc) = rt.blockds.remove(&grant.disk_id) {
                let _ = proc.child.kill();
                let _ = proc.child.wait();
            }
            return Err(error);
        }
        rt.volumes.push(grant);
        self.write_disk_map(rt)?;
        Ok(ObservedState::Running)
    }

    /// `cats sync`: everything acknowledged inside the guest becomes durable
    /// in the object store before this returns. A Running Cat flushes the Guest
    /// page cache first. A Suspended Cat was already syncfs'd before pause, so
    /// its frozen block engines can be drained without resuming it.
    fn sync_cat(&self, cat_id: &str) -> Result<ObservedState> {
        let (state, activity) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats.get(cat_id).context("cat is not on this node")?;
            (rt.state, rt.activity.clone())
        };
        let _activity = if state == ObservedState::Running {
            Some(activity.acquire()?)
        } else {
            None
        };
        let cats = self.cats.lock().unwrap();
        let rt = cats.get(cat_id).context("cat is not on this node")?;
        match rt.state {
            ObservedState::Running => {
                rt.conn().connect()?.syncfs().context("guest syncfs")?;
            }
            ObservedState::Suspended => {}
            other => bail!("cannot sync cat in {other:?}"),
        }
        for proc in rt.blockds.values() {
            proc.drain()?;
        }
        Ok(rt.state)
    }

    fn detach_disk(&self, cat_id: &str, disk_id: &str) -> Result<ObservedState> {
        let activity = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .context("cat is not running on this node")?
            .activity
            .clone();
        let _activity = activity.acquire()?;
        let mut cats = self.cats.lock().unwrap();
        let rt = cats
            .get_mut(cat_id)
            .context("cat is not running on this node")?;
        if !rt.blockds.contains_key(disk_id) {
            return Ok(rt.state); // idempotent
        }
        // Final durable flush through the guest before the backend exits.
        rt.conn()
            .connect()
            .context("connect guest for disk detach")?
            .flush_disk(disk_id)
            .with_context(|| format!("guest flush of {disk_id}"))?;
        // A relaxed Guest FLUSH only advances the local watermark. Keep the
        // binding, blockd and journal intact unless the forced remote drain
        // succeeds.
        rt.blockds
            .get(disk_id)
            .expect("checked")
            .drain()
            .with_context(|| format!("detach drain of {disk_id}"))?;

        let mut proc = rt.blockds.remove(disk_id).expect("checked");
        let volume_index = rt
            .volumes
            .iter()
            .position(|volume| volume.disk_id == disk_id);
        let removed_volume = volume_index.map(|index| rt.volumes.remove(index));
        if let Err(error) = self.write_disk_map(rt) {
            rt.blockds.insert(disk_id.to_string(), proc);
            if let (Some(index), Some(volume)) = (volume_index, removed_volume) {
                rt.volumes.insert(index, volume);
            }
            return Err(error);
        }
        let _ = proc.child.kill();
        let _ = proc.child.wait();
        Ok(rt.state)
    }
}

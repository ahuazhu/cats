//! Re-adopting the processes this node started, after the agent restarts
//! (ADR-0028 §3).
//!
//! The ledger says what this node last started. It is not, by itself, evidence
//! that those processes are still there: pids are recycled, hosts reboot, and a
//! `cats-blockd` holding a lease on someone else's volume looks exactly like
//! ours from the outside. So a record is only turned back into a supervised
//! [`CatRuntime`] after a four-step proof, in this order:
//!
//! 1. the host has not rebooted since the record was written;
//! 2. every recorded pid still has the recorded start ticks and executable;
//! 3. each blockd self-reports the recorded volume and attachment over its
//!    control socket, and the Guest reports the recorded boot id;
//! 4. every blockd's data directory is still there.
//!
//! Anything less is residue: reported, logged, and otherwise left exactly as
//! found. Adoption never kills, drains, or deletes — a Cat this node cannot
//! prove it owns may still be owned by a live process holding a lease, and the
//! existing fail-closed handling in `stop_cat` is what deals with it.
//!
//! Residue must also stay out of [`NodeRuntime::snapshot`], which is what the
//! heartbeat reports. Omitting a Cat leaves the node Lost, which is recoverable;
//! reporting it as `Cold` would tell the control plane the disk was released
//! while a blockd may still hold its lease (ADR-0028 §7).

use super::ledger::{BlockdRecord, CatLedgerRecord};
use super::*;

use crate::proc::{host_boot_id, ProcIdentity};

/// What one [`NodeRuntime::adopt_from_ledger`] pass concluded.
///
/// Summarised into the startup log by `server::spawn`, which is where an
/// operator recovering a node reads which Cat is blocking it (ADR-0028 §5).
pub(crate) struct AdoptionOutcome {
    /// Cat ids now present in `NodeRuntime::cats`.
    pub adopted: Vec<String>,
    /// `(cat id, human reason it was not adopted)`. Left untouched on disk.
    pub residue: Vec<(String, String)>,
}

impl NodeRuntime {
    /// Rebuild the runtime inventory from the ledger, adopting only what this
    /// node can prove it started.
    ///
    /// Never fails: an unreadable ledger, a malformed record and a vanished
    /// process are all just Cats that do not get adopted.
    ///
    /// Blocking: probes `/proc`, Unix sockets and directories. `server::spawn`
    /// calls it before it serves anything or contacts the control plane.
    pub(crate) fn adopt_from_ledger(&self) -> AdoptionOutcome {
        let mut outcome = AdoptionOutcome {
            adopted: Vec::new(),
            residue: Vec::new(),
        };
        let records = match self.ledger.load_all() {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!("scanning the node runtime ledger failed: {error:#}");
                return outcome;
            }
        };
        let host_boot = host_boot_id();
        for record in records {
            let cat_id = record.cat_id.clone();
            match self.proven_runtime(&record, host_boot.as_deref()) {
                Ok(runtime) => {
                    let (generation, state) = (runtime.generation, runtime.state);
                    match self.adopt_proven(&cat_id, runtime) {
                        Ok(()) => {
                            tracing::info!(
                                cat = %cat_id,
                                generation,
                                ?state,
                                "adopted the runtime this node started before the restart"
                            );
                            outcome.adopted.push(cat_id);
                        }
                        Err(reason) => {
                            tracing::warn!(cat = %cat_id, "not adopting: {reason}");
                            outcome.residue.push((cat_id, reason));
                        }
                    }
                }
                Err(error) => {
                    let reason = format!("{error:#}");
                    tracing::warn!(
                        cat = %cat_id,
                        "not adopting; leaving local state as residue: {reason}"
                    );
                    outcome.residue.push((cat_id, reason));
                }
            }
        }
        outcome
    }

    /// Publish a proven runtime, unless this Cat is already supervised.
    fn adopt_proven(&self, cat_id: &str, runtime: CatRuntime) -> std::result::Result<(), String> {
        // Poison recovery rather than a panic: adoption runs before this node
        // serves anything, so the only state a poisoned `cats` map can hold is
        // what `NodeRuntime::new` put there.
        let mut cats = self
            .cats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cats.contains_key(cat_id) {
            return Err("a runtime for this cat is already supervised".to_string());
        }
        cats.insert(cat_id.to_string(), runtime);
        Ok(())
    }

    /// The ADR-0028 §3 proof. `Ok` means every step passed and the returned
    /// runtime describes processes that are provably the ones this node
    /// started.
    fn proven_runtime(
        &self,
        record: &CatLedgerRecord,
        host_boot: Option<&str>,
    ) -> Result<CatRuntime> {
        // Step 1. A reboot invalidates every recorded pid at once, so this
        // settles the whole Cat before anything is probed.
        anyhow::ensure!(
            record.host_boot_id.as_deref() == host_boot,
            "the host rebooted since this record was written (recorded boot {}, current {}), so no recorded pid can be trusted",
            record.host_boot_id.as_deref().unwrap_or("<none>"),
            host_boot.unwrap_or("<none>")
        );
        // Only Running is adopted here. ADR-0028 §7 stages Suspended and Warm
        // separately because restoring them wrong risks a Cat that can no
        // longer be restored at all, and Stopping must wait for the control
        // plane to retry its own job.
        anyhow::ensure!(
            record.state == ObservedState::Running,
            "recorded state is {:?}; this stage adopts Running only",
            record.state
        );

        // Step 2. Process identity, for the guest and for every blockd. A Cat
        // is adopted whole or not at all: a runtime missing one of its block
        // backends is not a runtime that can serve its Guest.
        let recorded_guest = record
            .guest
            .as_ref()
            .context("a Running record with no recorded guest process")?;
        let guest = proven_process(recorded_guest).context("guest/VMM")?;
        let mut blockds = HashMap::with_capacity(record.blockds.len());
        for blockd in &record.blockds {
            let child = proven_process(&blockd.proc)
                .with_context(|| format!("blockd for disk {}", blockd.grant.disk_id))?;
            blockds.insert(
                blockd.grant.disk_id.clone(),
                BlockdProc {
                    child,
                    socket: blockd.socket.clone(),
                    vhost_user_socket: blockd.vhost_user_socket.clone(),
                    control_socket: blockd.control_socket.clone(),
                    grant: blockd.grant.clone(),
                },
            );
        }
        // A Cat is adopted whole or not at all, so the runtime rebuilt here has
        // to cover exactly the disks the record describes. Two records for one
        // disk would silently collapse into one supervised backend, and a grant
        // with no blockd behind it would be a Cat whose Guest is missing a
        // device. Neither is a runtime this node may claim to be supervising.
        anyhow::ensure!(
            blockds.len() == record.blockds.len(),
            "the record names the same disk more than once"
        );
        for volume in &record.volumes {
            anyhow::ensure!(
                blockds.contains_key(&volume.disk_id),
                "no blockd is recorded for attached disk {}",
                volume.disk_id
            );
        }

        // Step 3. Identity over the protocols, not just over /proc. Matching
        // start ticks say the process never died; only its own answer says it
        // is serving what this record claims.
        for blockd in &record.blockds {
            proven_blockd_identity(blockd)
                .with_context(|| format!("blockd for disk {}", blockd.grant.disk_id))?;
        }
        let ch = record.ch.as_ref().map(|ch| ChRuntime {
            api_sock: ch.api_sock.clone(),
            vsock_sock: ch.vsock_sock.clone(),
            memory_file: ch.memory_file.clone(),
            nbd: ch
                .nbd
                .iter()
                .map(|(disk_id, device)| (disk_id.clone(), device.clone()))
                .collect(),
            snapshot_dir: ch.snapshot_dir.clone(),
            network: ch.network.clone(),
        });
        let conn = match &ch {
            Some(chrt) => GuestConn::Vsock(chrt.vsock_sock.clone(), GUEST_VSOCK_PORT),
            None => GuestConn::Unix(record.ctl_sock.clone()),
        };
        let recorded_boot = record
            .boot_id
            .as_deref()
            .context("record carries no Guest boot id")?;
        let (boot_id, _) = conn
            .connect()
            .context("connect the guest")?
            .health()
            .context("guest health probe")?;
        anyhow::ensure!(
            boot_id == recorded_boot,
            "the guest reports boot id {boot_id:?}, not the recorded {recorded_boot:?}"
        );

        // Step 4. In relaxed mode with `R < L` this directory holds the only
        // authoritative copy of the unpublished writes (ADR-0021); a blockd
        // whose journal is not where the record says it is has not been proven.
        for blockd in &record.blockds {
            anyhow::ensure!(
                blockd.data_dir.is_dir(),
                "data directory {} for disk {} is missing",
                blockd.data_dir.display(),
                blockd.grant.disk_id
            );
        }

        Ok(CatRuntime {
            generation: record.generation,
            cpus: record.cpus,
            memory_mib: record.memory_mib,
            state: record.state,
            guest: Some(guest),
            boot_id: record.boot_id.clone(),
            blockds,
            volumes: record.volumes.clone(),
            dir: record.dir.clone(),
            ctl_sock: record.ctl_sock.clone(),
            web_sock: record.web_sock.clone(),
            runtime_sock: record.runtime_sock.clone(),
            // Deliberately fresh: in-flight proxy and exec work did not survive
            // the restart, so there is no activity to carry over.
            activity: Arc::new(RuntimeActivity::default()),
            metering: record.metering.as_ref().map(|metering| RuntimeMetering {
                cgroup_path: metering.cgroup_path.clone(),
                source_epoch: metering.source_epoch.clone(),
            }),
            ch,
        })
    }
}

/// ADR-0028 §3 step 2: the pid must still name the exact process recorded.
fn proven_process(recorded: &ProcIdentity) -> Result<ProcHandle> {
    let live = ProcIdentity::sample(recorded.pid);
    anyhow::ensure!(
        live.start_ticks == recorded.start_ticks,
        "process {} has start ticks {:?}, not the recorded {:?}; it is gone or its pid was recycled",
        recorded.pid,
        live.start_ticks,
        recorded.start_ticks
    );
    anyhow::ensure!(
        live.exe == recorded.exe,
        "process {} runs {:?}, not the recorded {:?}",
        recorded.pid,
        live.exe,
        recorded.exe
    );
    let mut handle = ProcHandle::Adopted {
        pid: recorded.pid,
        start_ticks: recorded.start_ticks,
    };
    anyhow::ensure!(
        !handle
            .exited()
            .with_context(|| format!("probe process {}", recorded.pid))?,
        "process {} is gone",
        recorded.pid
    );
    Ok(handle)
}

/// ADR-0028 §3 step 3 for one blockd: it has to name the volume it holds.
fn proven_blockd_identity(record: &BlockdRecord) -> Result<()> {
    let status = BlockdProc::status_at(&record.control_socket, &record.grant.disk_id)
        .context("read the blockd control status")?;
    // A `cats-blockd` older than ADR-0028 leaves both fields empty. It may well
    // be ours, but it cannot show that it is, and binding a live blockd to a
    // volume on a pid match alone is exactly the mistake this proof exists to
    // prevent. Refusing is the safe default.
    anyhow::ensure!(
        !status.volume_id.is_empty() && !status.attachment_id.is_empty(),
        "the blockd reports no volume identity, so it cannot prove what it holds"
    );
    anyhow::ensure!(
        status.volume_id == record.grant.volume_id,
        "the blockd serves volume {:?}, not the recorded {:?}",
        status.volume_id,
        record.grant.volume_id
    );
    anyhow::ensure!(
        status.attachment_id == record.grant.attachment_id,
        "the blockd serves attachment {:?}, not the recorded {:?}",
        status.attachment_id,
        record.grant.attachment_id
    );
    Ok(())
}

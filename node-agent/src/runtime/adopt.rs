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
//!    control socket, and the Guest — or, when it cannot speak for itself, the
//!    VMM holding it — confirms the state the record claims;
//! 4. every recorded data directory is still there.
//!
//! Every state that can leave a live process behind is adoptable, because from
//! stage 5 on the processes outlive the agent (per-Cat systemd scope). A state
//! this proof refuses would then be an unclaimed orphan: nothing supervises it,
//! `Resume`/`Stop` cannot find it, and the fail-closed unsupervised-residue rule
//! in `stop_cat` will not clean it up either — the `residue` sweep reclaims only
//! what a live process is provably not using. What is alive differs per state:
//!
//! - `Running`: VMM and blockds up, Guest answering. The full proof.
//! - `Suspended`: same processes, but the Guest is paused and cannot answer, so
//!   step 3 asks the VMM (`vm.info`) instead of the Guest. It is never resumed
//!   to prove it — that would cost a real wake and break ADR-0002.
//! - `Stopping`: no Guest; `stop_cat` deliberately keeps the blockds and their
//!   journals alive so the same job can retry its forced remote drain. On a
//!   relaxed volume those journals are the only authoritative copy of the
//!   unpublished writes (ADR-0021/0022).
//! - `Warm`: nothing is alive at all and the facts are files, so the proof is
//!   made entirely on disk — and the boot-id gate does not apply (ADR-0028 §3).
//!
//! Anything less is residue: reported, logged, and otherwise left exactly as
//! found. Adoption never kills, drains, or deletes — a Cat this node cannot
//! prove it owns may still be owned by a live process holding a lease. What
//! becomes of that residue is decided elsewhere: `stop_cat` fails closed on it,
//! and the sweep in `residue` reclaims the part of it that is provably not
//! durability state and reports the rest (issue #99).
//!
//! Residue must also stay out of [`NodeRuntime::snapshot`], which is what the
//! heartbeat reports. Omitting a Cat leaves the node Lost, which is recoverable;
//! reporting it as `Cold` would tell the control plane the disk was released
//! while a blockd may still hold its lease (ADR-0028 §7).

use super::ledger::{BlockdRecord, CatLedgerRecord, ChRecord};
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

    /// The ADR-0028 §3 proof, dispatched on the recorded state. `Ok` means
    /// every step that applies to that state passed and the returned runtime
    /// describes exactly what this node left behind.
    fn proven_runtime(
        &self,
        record: &CatLedgerRecord,
        host_boot: Option<&str>,
    ) -> Result<CatRuntime> {
        match record.state {
            // Everything with resident processes shares one proof; only the
            // Guest half of step 3 varies (see `proven_guest_identity`).
            ObservedState::Running | ObservedState::Suspended | ObservedState::Stopping => {
                proven_resident_runtime(record, host_boot)
            }
            // Warm has no process to prove, and deliberately no boot-id gate.
            ObservedState::Warm => proven_warm_runtime(record),
            // Every remaining state is transitional: the record describes a Cat
            // mid-job, and what is alive is whatever that job had reached. There
            // is nothing stable to prove, so it stays residue with a reason.
            other => anyhow::bail!(
                "recorded state is {other:?}; only Running, Suspended, Warm and Stopping are adoptable"
            ),
        }
    }
}

/// The proof for a record whose processes are still resident: `Running`,
/// `Suspended` and `Stopping`.
fn proven_resident_runtime(
    record: &CatLedgerRecord,
    host_boot: Option<&str>,
) -> Result<CatRuntime> {
    // Step 1. A reboot invalidates every recorded pid at once, so this settles
    // the whole Cat before anything is probed.
    anyhow::ensure!(
        record.host_boot_id.as_deref() == host_boot,
        "the host rebooted since this record was written (recorded boot {}, current {}), so no recorded pid can be trusted",
        record.host_boot_id.as_deref().unwrap_or("<none>"),
        host_boot.unwrap_or("<none>")
    );

    // Step 2. Process identity, for the guest and for every blockd. A Cat is
    // adopted whole or not at all: a runtime missing one of its block backends
    // is not a runtime that can serve its Guest.
    //
    // Stopping is the exception on the Guest: `stop_cat` only converges there
    // once the Guest is already gone, and what it keeps alive on purpose is the
    // blockds and their journals.
    let guest = if record.state == ObservedState::Stopping {
        // A Stopping record that names a Guest anyway describes something this
        // node cannot account for, and adopting it with no Guest would leave a
        // live VMM unsupervised — the orphan this whole proof exists to avoid.
        anyhow::ensure!(
            record.guest.is_none(),
            "a Stopping record still names a guest process, which stop_cat never leaves behind"
        );
        None
    } else {
        let recorded_guest = record.guest.as_ref().with_context(|| {
            format!("a {:?} record with no recorded guest process", record.state)
        })?;
        Some(proven_process(recorded_guest).context("guest/VMM")?)
    };
    let mut blockds = HashMap::with_capacity(record.blockds.len());
    for blockd in &record.blockds {
        let child = proven_process(&blockd.proc)
            .with_context(|| format!("blockd for disk {}", blockd.grant.disk_id))?;
        blockds.insert(
            blockd.grant.disk_id.clone(),
            BlockdProc {
                child,
                // Same path `spawn_blockd` redirects stderr to. An adopted
                // blockd is still writing to the file the agent that spawned
                // it created, so a later startup failure quotes the right log.
                log_path: blockd_log_path(&record.dir, &blockd.grant.disk_id),
                socket: blockd.socket.clone(),
                vhost_user_socket: blockd.vhost_user_socket.clone(),
                control_socket: blockd.control_socket.clone(),
                grant: blockd.grant.clone(),
            },
        );
    }
    // A Cat is adopted whole or not at all, so the runtime rebuilt here has to
    // cover exactly the disks the record describes. Two records for one disk
    // would silently collapse into one supervised backend, and a grant with no
    // blockd behind it would be a Cat whose Guest is missing a device. Neither
    // is a runtime this node may claim to be supervising.
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

    // Step 3. Identity over the protocols, not just over /proc. Matching start
    // ticks say the process never died; only its own answer says it is serving
    // what this record claims.
    for blockd in &record.blockds {
        proven_blockd_identity(blockd)
            .with_context(|| format!("blockd for disk {}", blockd.grant.disk_id))?;
    }
    let ch = record.ch.as_ref().map(ch_runtime);
    proven_guest_identity(record, ch.as_ref())?;

    // Step 4. In relaxed mode with `R < L` this directory holds the only
    // authoritative copy of the unpublished writes (ADR-0021); a blockd whose
    // journal is not where the record says it is has not been proven.
    for blockd in &record.blockds {
        anyhow::ensure!(
            blockd.data_dir.is_dir(),
            "data directory {} for disk {} is missing",
            blockd.data_dir.display(),
            blockd.grant.disk_id
        );
    }

    Ok(runtime_from(record, guest, blockds, ch))
}

/// The proof for a `Warm` record, which has no live process at all.
///
/// `warm_cat` drains, kills and removes every blockd and shuts the VMM down, and
/// the ledger record is written only after the job settles, so a Warm record has
/// no Guest and an empty blockd list. Everything left to prove is on local disk.
///
/// The boot-id gate deliberately does not apply here (ADR-0028 §3). It exists to
/// reject recorded pids after a reboot, and Warm records none: its snapshot,
/// memory backing and journals are files, which a reboot does not invalidate.
/// Gating Warm on the boot id would discard every restorable Warm Cat the first
/// time the host came back.
fn proven_warm_runtime(record: &CatLedgerRecord) -> Result<CatRuntime> {
    // Rebuilding Warm means rebuilding it with nothing running. A record that
    // names a process would leave that process unsupervised, so it is not a Warm
    // record this node may claim — and it is exactly the case where skipping the
    // boot-id gate would be wrong.
    anyhow::ensure!(
        record.guest.is_none(),
        "a Warm record still names a guest process, which warm_cat never leaves behind"
    );
    anyhow::ensure!(
        record.blockds.is_empty(),
        "a Warm record still names {} blockd process(es), which warm_cat never leaves behind",
        record.blockds.len()
    );
    let ch = record.ch.as_ref().map(ch_runtime);
    match &ch {
        // Cloud Hypervisor: `start_cat_ch` restores from exactly these two.
        Some(chrt) => {
            let snapshot_dir = chrt
                .snapshot_dir
                .as_ref()
                .context("the Warm record names no snapshot directory")?;
            anyhow::ensure!(
                snapshot_dir.is_dir(),
                "the warm snapshot directory {} is missing",
                snapshot_dir.display()
            );
            // `is_file`, matching what a warm restore itself demands of it.
            anyhow::ensure!(
                chrt.memory_file.is_file(),
                "the warm Guest memory backing {} is missing",
                chrt.memory_file.display()
            );
        }
        // FakeVmm: the saved Guest state file is the whole snapshot, and it is
        // what `restore_cat` checks for before it will restore.
        None => {
            let state_file = warm_state_file(&record.dir);
            anyhow::ensure!(
                state_file.exists(),
                "the warm guest state file {} is missing",
                state_file.display()
            );
        }
    }
    // No blockd survives Warm, so `record.blockds` is empty and the disks have
    // to be checked through the grants instead. The journals they left behind
    // are still local state a restore reads back, so a Warm Cat missing one is
    // not a Warm Cat this node can claim.
    for volume in &record.volumes {
        let data_dir = volume_data_dir(&record.dir, &volume.disk_id);
        anyhow::ensure!(
            data_dir.is_dir(),
            "data directory {} for disk {} is missing",
            data_dir.display(),
            volume.disk_id
        );
    }
    Ok(runtime_from(record, None, HashMap::new(), ch))
}

/// The fields of a rebuilt runtime that come straight from the record, whatever
/// state it is in.
fn runtime_from(
    record: &CatLedgerRecord,
    guest: Option<ProcHandle>,
    blockds: HashMap<String, BlockdProc>,
    ch: Option<ChRuntime>,
) -> CatRuntime {
    CatRuntime {
        generation: record.generation,
        cpus: record.cpus,
        memory_mib: record.memory_mib,
        state: record.state,
        guest,
        boot_id: record.boot_id.clone(),
        blockds,
        volumes: record.volumes.clone(),
        dir: record.dir.clone(),
        ctl_sock: record.ctl_sock.clone(),
        web_sock: record.web_sock.clone(),
        runtime_sock: record.runtime_sock.clone(),
        // Deliberately fresh: in-flight proxy and exec work did not survive the
        // restart, so there is no activity to carry over.
        activity: Arc::new(RuntimeActivity::default()),
        metering: record.metering.as_ref().map(|metering| RuntimeMetering {
            cgroup_path: metering.cgroup_path.clone(),
            source_epoch: metering.source_epoch.clone(),
        }),
        ch,
    }
}

/// `ChRuntime` is not serializable, so the ledger mirrors it; this is the way
/// back.
fn ch_runtime(record: &ChRecord) -> ChRuntime {
    ChRuntime {
        api_sock: record.api_sock.clone(),
        vsock_sock: record.vsock_sock.clone(),
        memory_file: record.memory_file.clone(),
        nbd: record
            .nbd
            .iter()
            .map(|(disk_id, device)| (disk_id.clone(), device.clone()))
            .collect(),
        snapshot_dir: record.snapshot_dir.clone(),
        network: record.network.clone(),
    }
}

/// ADR-0028 §3 step 3 for the Guest half, which is the one part of the proof
/// that depends on the recorded state.
fn proven_guest_identity(record: &CatLedgerRecord, ch: Option<&ChRuntime>) -> Result<()> {
    match record.state {
        // Running: the Guest is up, so it answers for itself.
        ObservedState::Running => {
            let conn = match ch {
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
            Ok(())
        }
        // Suspended: the Guest is paused and cannot answer anything. Resuming it
        // to find out would cost a real wake and break the Suspended contract
        // (ADR-0002), so the VMM is asked instead.
        ObservedState::Suspended => match ch {
            Some(chrt) => proven_paused_vm(&chrt.api_sock),
            // FakeVmm has no VMM to ask: the "Guest" is the SIGSTOPped
            // guest-agent process itself, and a stopped process answers nothing
            // on any channel — there is no second party here that could speak
            // for it. Process identity plus the blockd handshakes are the whole
            // of the available evidence. ADR-0028 §6 already accepts the weaker
            // identity on this path; it never carries production workload.
            None => Ok(()),
        },
        // Stopping has no Guest left to prove; everything still alive is a
        // blockd, and step 3 has already proved each of those.
        ObservedState::Stopping => Ok(()),
        // Unreachable while `proven_runtime` routes only the three resident
        // states here. Refusing is the fail-closed answer if that ever changes.
        other => anyhow::bail!("no Guest proof is defined for recorded state {other:?}"),
    }
}

/// ADR-0028 §3 step 3 for a Suspended VMM: one `vm.info` shows both that the
/// recorded VMM process is serving the recorded API socket and that it holds the
/// VM in the state the record claims.
fn proven_paused_vm(api_sock: &Path) -> Result<()> {
    let (status, body) = ch::ch_api(api_sock, "GET", "/api/v1/vm.info", None)
        .with_context(|| format!("query the recorded VMM api socket {}", api_sock.display()))?;
    anyhow::ensure!(
        (200..300).contains(&status),
        "the recorded VMM answered vm.info with status {status}: {}",
        body.trim()
    );
    // Whatever comes back is another process's output on a recovery path, so an
    // unreadable body is a failed proof, never a panic.
    let state = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .as_ref()
        .and_then(|info| info.get("state"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .context("the recorded VMM answered vm.info without a readable VM state")?;
    anyhow::ensure!(
        state.eq_ignore_ascii_case("paused"),
        "the recorded VMM reports VM state {state:?}, not the paused state the record claims"
    );
    Ok(())
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

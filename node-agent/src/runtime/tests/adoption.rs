//! Re-adopting a running Cat after the agent restarts (ADR-0028 §3, stage 2).
//!
//! Every test here starts a real Cat — a real `cats-blockd` per disk and a real
//! `cats-guest-agent` — with one `NodeRuntime`, then builds a *second*
//! `NodeRuntime` over the same state directory and asks it to adopt. That
//! second runtime is the restarted agent: it shares nothing with the first but
//! the filesystem and the processes still running on the host, which is exactly
//! the situation the proof has to survive.
//!
//! The first runtime keeps its owned `Child` handles throughout, so it — not
//! the adopter — tears the Cat down at the end of each test.

use super::*;

use std::collections::BTreeMap;

use cats_api::nodejob::job_id;
use cats_storage::AdapterConfig;

use ledger::CatLedgerRecord;

const VOLUME_SIZE: u64 = 2 * cats_api::chunk::CHUNK_SIZE as u64;
const CPUS: u32 = 2;
const MEMORY_MIB: u64 = 512;

struct AdoptEnv {
    _dir: tempfile::TempDir,
    root: PathBuf,
    cfg: NodeConfig,
    /// The agent that started the Cat and still owns its children.
    runtime: NodeRuntime,
}

fn adopt_env(node_id: &str) -> AdoptEnv {
    let dir = tempfile::tempdir().expect("create test root");
    let root = dir.path().to_path_buf();
    let cfg = NodeConfig {
        node_id: node_id.to_string(),
        state_dir: root.join("node-state"),
        blockd_bin: crate::testutil::workspace_bin("cats-blockd"),
        guest_agent_bin: crate::testutil::workspace_bin("cats-guest-agent"),
        metadata_store: AdapterSelection {
            name: "sqlite".into(),
            config: AdapterConfig::from_pairs([(
                "path",
                root.join("meta.db").display().to_string(),
            )])
            .expect("SQLite adapter config"),
        },
        object_store: AdapterSelection {
            name: "file".into(),
            config: AdapterConfig::from_pairs([("root", root.join("blob").display().to_string())])
                .expect("File adapter config"),
        },
        blockd_lease_ttl_ms: 1_200,
        blockd_max_staged_bytes: cats_api::blockd::DEFAULT_MAX_STAGED_BYTES,
        blockd_max_staged_packs: cats_api::blockd::DEFAULT_MAX_STAGED_PACKS,
        blockd_max_local_bytes: cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES,
        metering_cgroup_root: None,
        vmm: VmmMode::Fake,
        wake_budget: WakeBudget::default(),
    };
    let runtime = NodeRuntime::new(cfg.clone()).expect("open node runtime");
    AdoptEnv {
        _dir: dir,
        root,
        cfg,
        runtime,
    }
}

impl AdoptEnv {
    /// A fresh agent process over the same state directory and the same
    /// still-running children.
    fn restarted_agent(&self) -> NodeRuntime {
        NodeRuntime::new(self.cfg.clone()).expect("open the restarted node runtime")
    }

    fn run(&self, job: NodeJob) -> NodeJobResult {
        let result = self.runtime.execute(job);
        assert_eq!(
            result.phase,
            JobPhase::Succeeded,
            "job failed: {:?}",
            result.error
        );
        result
    }

    fn record(&self, cat_id: &str) -> CatLedgerRecord {
        self.runtime
            .ledger
            .load_all()
            .expect("load ledger records")
            .into_iter()
            .find(|record| record.cat_id == cat_id)
            .unwrap_or_else(|| panic!("no runtime ledger record for {cat_id}"))
    }

    fn rewrite_record(&self, record: &CatLedgerRecord) {
        self.runtime
            .ledger
            .put(record)
            .expect("rewrite the runtime ledger record");
    }
}

/// The pids a runtime currently supervises for one Cat: the guest, and one per
/// disk.
fn supervised_pids(runtime: &NodeRuntime, cat_id: &str) -> (u32, BTreeMap<String, u32>) {
    let cats = runtime.cats.lock().expect("cats mutex");
    let rt = cats
        .get(cat_id)
        .unwrap_or_else(|| panic!("{cat_id} is not supervised"));
    (
        rt.guest.as_ref().expect("a Running Cat has a guest").id(),
        rt.blockds
            .iter()
            .map(|(disk_id, blockd)| (disk_id.clone(), blockd.child.id()))
            .collect(),
    )
}

fn grant(cat_id: &str, disk_id: &str, mount_path: &str) -> VolumeGrant {
    VolumeGrant {
        disk_id: disk_id.to_string(),
        volume_id: format!("vol_{cat_id}_{disk_id}"),
        attachment_id: format!("att_{cat_id}_{disk_id}"),
        epoch: 0,
        size_bytes: VOLUME_SIZE,
        mount_path: mount_path.to_string(),
        durability: Default::default(),
    }
}

fn start_job(cat_id: &str, generation: i64, disks: &[(&str, &str)]) -> NodeJob {
    NodeJob {
        job_id: job_id(cat_id, generation, "start_cat"),
        cat_generation: generation,
        action: NodeJobAction::StartCat {
            cat_id: cat_id.to_string(),
            image: "test".into(),
            cpus: CPUS,
            memory_mib: MEMORY_MIB,
            volumes: disks
                .iter()
                .map(|(disk_id, mount_path)| grant(cat_id, disk_id, mount_path))
                .collect(),
        },
    }
}

fn simple_job(cat_id: &str, generation: i64, kind: &str, action: NodeJobAction) -> NodeJob {
    NodeJob {
        job_id: job_id(cat_id, generation, kind),
        cat_generation: generation,
        action,
    }
}

fn stop_job(cat_id: &str, generation: i64) -> NodeJob {
    simple_job(
        cat_id,
        generation,
        "stop_cat",
        NodeJobAction::StopCat {
            cat_id: cat_id.to_string(),
            disposition: StopCatDisposition::Cold,
        },
    )
}

#[test]
fn a_running_cat_is_adopted_by_a_restarted_agent() {
    const CAT: &str = "cat_adopt_running";
    let env = adopt_env("node_adopt_running");
    env.run(start_job(CAT, 3, &[("root", "/"), ("data", "/data")]));
    let before = supervised_pids(&env.runtime, CAT);

    let restarted = env.restarted_agent();
    assert!(
        restarted.snapshot().is_empty(),
        "a fresh runtime knows nothing until it adopts"
    );
    let outcome = restarted.adopt_from_ledger();

    assert_eq!(outcome.adopted, [CAT.to_string()]);
    assert!(
        outcome.residue.is_empty(),
        "unexpected residue: {:?}",
        outcome.residue
    );
    assert_eq!(
        restarted.snapshot(),
        vec![(CAT.to_string(), 3, ObservedState::Running)],
        "the adopted Cat keeps its generation and state"
    );
    assert_eq!(
        supervised_pids(&restarted, CAT),
        before,
        "adoption must bind to the very processes that were already running"
    );

    let cats = restarted.cats.lock().expect("cats mutex");
    let adopted = cats.get(CAT).expect("adopted runtime");
    assert_eq!(adopted.cpus, CPUS);
    assert_eq!(adopted.memory_mib, MEMORY_MIB);
    assert_eq!(adopted.dir, env.cfg.state_dir.join("cats").join(CAT));
    let mut volumes: Vec<&str> = adopted
        .volumes
        .iter()
        .map(|volume| volume.disk_id.as_str())
        .collect();
    volumes.sort_unstable();
    assert_eq!(volumes, ["data", "root"]);
    assert!(
        adopted.boot_id.is_some(),
        "the recorded Guest boot id is restored"
    );
    drop(cats);

    env.run(stop_job(CAT, 4));
}

/// Each of these breaks exactly one step of the ADR-0028 §3 proof. The expected
/// reason is asserted too: a later check firing first would make an earlier one
/// look tested when it is not.
#[test]
fn an_unprovable_identity_leaves_the_cat_as_residue() {
    const CAT: &str = "cat_adopt_unproven";
    let env = adopt_env("node_adopt_unproven");
    env.run(start_job(CAT, 1, &[("root", "/")]));
    let proven = env.record(CAT);

    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, &str, Box<dyn Fn(&mut CatLedgerRecord)>)> = vec![
        (
            "the host rebooted",
            "the host rebooted",
            Box::new(|record| {
                record.host_boot_id = Some("00000000-0000-4000-8000-000000000000".to_string());
            }),
        ),
        (
            "the recorded start ticks do not match",
            "start ticks",
            Box::new(|record| {
                let guest = record.guest.as_mut().expect("a Running record has a guest");
                guest.start_ticks = Some(guest.start_ticks.unwrap_or(0).wrapping_add(1));
            }),
        ),
        (
            "a blockd serves a different volume",
            "serves volume",
            Box::new(|record| {
                record.blockds[0].grant.volume_id = "vol_someone_else".to_string();
            }),
        ),
        (
            "the guest reports a different boot id",
            "boot id",
            Box::new(|record| record.boot_id = Some("not-the-recorded-boot-id".to_string())),
        ),
        (
            "a blockd data directory is missing",
            "data directory",
            Box::new(|record| {
                record.blockds[0].data_dir = record.dir.join("vol-not-there");
            }),
        ),
    ];

    for (case, expected_reason, break_it) in cases {
        let mut record = proven.clone();
        break_it(&mut record);
        env.rewrite_record(&record);

        let restarted = env.restarted_agent();
        let outcome = restarted.adopt_from_ledger();

        assert!(
            outcome.adopted.is_empty(),
            "{case}: adopted a Cat it could not prove"
        );
        assert_eq!(outcome.residue.len(), 1, "{case}");
        assert_eq!(outcome.residue[0].0, CAT, "{case}");
        assert!(
            outcome.residue[0].1.contains(expected_reason),
            "{case}: reported {:?}, which does not mention {expected_reason:?}",
            outcome.residue[0].1
        );
        assert!(
            restarted.snapshot().is_empty(),
            "{case}: residue must not reach the heartbeat"
        );
    }

    env.run(stop_job(CAT, 2));
}

/// A `cats-blockd` older than ADR-0028 answers `status` without any volume
/// identity. It may well be ours, but it cannot show that it is, so it is not
/// adoptable — the empty payload must not read as "no mismatch, therefore fine".
#[test]
fn a_blockd_that_cannot_name_its_volume_is_not_adopted() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    /// Byte-for-byte what an older blockd emitted: no `volume_id`, no
    /// `attachment_id`.
    const LEGACY_STATUS: &str = "{\"mode\":\"strict\",\"local_durable_generation\":1,\"remote_durable_generation\":1,\"unpublished_generations\":0,\"unpublished_bytes\":0,\"oldest_unpublished_age_ms\":0,\"max_unpublished_generations\":4096,\"max_unpublished_bytes\":8589934592,\"local_allocated_bytes\":0,\"max_local_bytes\":17179869184,\"evicted_cache_chunks\":0,\"backpressured\":false,\"fenced\":false,\"last_publish_error\":null}";

    const CAT: &str = "cat_adopt_legacy_blockd";
    let env = adopt_env("node_adopt_legacy_blockd");
    env.run(start_job(CAT, 1, &[("root", "/")]));

    let legacy_socket = env.root.join("legacy-blockd-ctl.sock");
    let listener = UnixListener::bind(&legacy_socket).expect("bind the legacy control socket");
    let responder = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the status probe");
        let mut command = String::new();
        BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut command)
            .expect("read the control command");
        assert_eq!(command, "status\n");
        stream
            .write_all(format!("OK {LEGACY_STATUS}\n").as_bytes())
            .expect("answer the status probe");
    });

    let mut record = env.record(CAT);
    record.blockds[0].control_socket = legacy_socket;
    env.rewrite_record(&record);

    let restarted = env.restarted_agent();
    let outcome = restarted.adopt_from_ledger();

    // Assert before joining: an earlier step failing would leave the responder
    // blocked in `accept`, and a failed assertion is a far better outcome than
    // a test that hangs.
    assert!(outcome.adopted.is_empty());
    assert_eq!(outcome.residue.len(), 1);
    assert!(
        outcome.residue[0].1.contains("no volume identity"),
        "unexpected reason: {:?}",
        outcome.residue[0].1
    );
    assert!(restarted.snapshot().is_empty());
    responder.join().expect("legacy responder thread");

    env.run(stop_job(CAT, 2));
}

/// ADR-0028 §7 stages Suspended and Warm separately. A Warm record has no
/// resident processes at all, so "nothing failed the process check" must not be
/// mistaken for "everything passed it".
#[test]
fn a_warm_record_is_residue_not_an_adoption() {
    const CAT: &str = "cat_adopt_warm";
    let env = adopt_env("node_adopt_warm");
    env.run(start_job(CAT, 1, &[("root", "/")]));
    env.run(simple_job(
        CAT,
        2,
        "warm_cat",
        NodeJobAction::WarmCat {
            cat_id: CAT.to_string(),
        },
    ));
    assert_eq!(env.record(CAT).state, ObservedState::Warm);

    let restarted = env.restarted_agent();
    let outcome = restarted.adopt_from_ledger();

    assert!(outcome.adopted.is_empty());
    assert_eq!(outcome.residue.len(), 1);
    assert!(
        outcome.residue[0].1.contains("Warm"),
        "unexpected reason: {:?}",
        outcome.residue[0].1
    );
    assert!(restarted.snapshot().is_empty());

    env.run(stop_job(CAT, 3));
}

/// The safety property behind the whole conservative design: a Cat this node
/// cannot prove it owns is *absent* from the heartbeat snapshot, not reported
/// as `Cold`. Reporting Cold would tell the control plane the disk was released
/// while a blockd may still hold its lease; omitting it only keeps the node
/// Lost, which is the recoverable side (ADR-0028 §7).
#[test]
fn an_unadopted_cat_is_absent_from_the_heartbeat_snapshot() {
    const CAT: &str = "cat_adopt_absent";
    let env = adopt_env("node_adopt_absent");
    env.run(start_job(CAT, 5, &[("root", "/")]));

    let mut record = env.record(CAT);
    record.boot_id = Some("a-boot-id-this-guest-never-had".to_string());
    env.rewrite_record(&record);

    let restarted = env.restarted_agent();
    let outcome = restarted.adopt_from_ledger();
    assert_eq!(outcome.residue.len(), 1);

    let snapshot = restarted.snapshot();
    assert!(
        snapshot.is_empty(),
        "an unproven Cat must not be reported at all, and least of all as Cold: {snapshot:?}"
    );
    assert!(
        restarted.telemetry().observed_cats == 0,
        "an unproven Cat must not be counted as owned either"
    );

    env.run(stop_job(CAT, 6));
}

/// Adoption observes; it never cleans up. A Cat left as residue keeps its
/// ledger record, its runtime directory, its blockd journals and its processes,
/// because a live blockd may still hold the volume lease.
#[test]
fn adoption_leaves_residue_on_disk_untouched() {
    const CAT: &str = "cat_adopt_untouched";
    let env = adopt_env("node_adopt_untouched");
    env.run(start_job(CAT, 1, &[("root", "/")]));
    let before = supervised_pids(&env.runtime, CAT);

    let mut record = env.record(CAT);
    let data_dir = record.blockds[0].data_dir.clone();
    let control_socket = record.blockds[0].control_socket.clone();
    let ctl_sock = record.ctl_sock.clone();
    let dir = record.dir.clone();
    record.host_boot_id = Some("00000000-0000-4000-8000-0000000000ff".to_string());
    env.rewrite_record(&record);

    let restarted = env.restarted_agent();
    assert_eq!(restarted.adopt_from_ledger().residue.len(), 1);

    assert!(dir.is_dir(), "the runtime directory was removed");
    assert!(
        data_dir.is_dir(),
        "the blockd journal directory was removed"
    );
    let kept = env.record(CAT);
    assert_eq!(
        serde_json::to_string(&kept).expect("encode"),
        serde_json::to_string(&record).expect("re-encode"),
        "the ledger record must be left exactly as found"
    );
    assert_eq!(
        supervised_pids(&env.runtime, CAT),
        before,
        "the owning runtime still supervises the same processes"
    );
    // Both still answer, so neither was signalled.
    BlockdProc::status_at(&control_socket, "root").expect("the blockd is still serving");
    GuestConn::Unix(ctl_sock)
        .connect()
        .expect("connect the guest")
        .health()
        .expect("the guest is still healthy");

    env.run(stop_job(CAT, 2));
}

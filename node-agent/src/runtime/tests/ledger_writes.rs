//! The runtime ledger write path (legacy-ledger characterization CH-01/CH-02, stage 1).
//!
//! These tests drive real NodeJobs through `execute` with real `cats-blockd`
//! and `cats-guest-agent` children, because the property under test is exactly
//! that the settled end state of a job — and nothing else — reaches the disk.

use super::*;

use cats_api::nodejob::job_id;

const VOLUME_SIZE: u64 = 2 * cats_api::chunk::CHUNK_SIZE as u64;
const CPUS: u32 = 2;
const MEMORY_MIB: u64 = 512;

struct LedgerEnv {
    _dir: tempfile::TempDir,
    state_dir: PathBuf,
    runtime: NodeRuntime,
}

fn ledger_env(node_id: &str) -> LedgerEnv {
    let dir = tempfile::tempdir().expect("create test root");
    let root = dir.path().to_path_buf();
    let state_dir = root.join("node-state");
    let runtime =
        NodeRuntime::new(real_child_node_config(&root, node_id)).expect("open node runtime");
    LedgerEnv {
        _dir: dir,
        state_dir,
        runtime,
    }
}

impl LedgerEnv {
    fn records(&self) -> Vec<ledger::CatLedgerRecord> {
        self.runtime.ledger.load_all().expect("load ledger records")
    }

    fn ledger_dir(&self) -> PathBuf {
        self.state_dir.join("runtime-ledger")
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
fn a_started_cat_is_recorded_with_one_entry_per_attached_volume() {
    const CAT: &str = "cat_ledger_start";
    let env = ledger_env("node_ledger_start");

    env.run(start_job(CAT, 3, &[("root", "/"), ("data", "/data")]));

    let records = env.records();
    assert_eq!(records.len(), 1, "one record per running Cat");
    let record = &records[0];
    assert_eq!(record.cat_id, CAT);
    assert_eq!(record.node_id, "node_ledger_start");
    assert_eq!(record.generation, 3);
    assert_eq!(record.state, ObservedState::Running);
    assert_eq!(record.cpus, CPUS);
    assert_eq!(record.memory_mib, MEMORY_MIB);
    assert_eq!(record.dir, env.state_dir.join("cats").join(CAT));
    assert!(
        record.guest.as_ref().is_some_and(|guest| guest.pid > 0),
        "a Running Cat has a resident guest process"
    );
    assert!(record.boot_id.is_some(), "the guest reported a boot id");

    let disk_ids: Vec<&str> = record
        .blockds
        .iter()
        .map(|blockd| blockd.grant.disk_id.as_str())
        .collect();
    assert_eq!(disk_ids, ["data", "root"]);
    for blockd in &record.blockds {
        assert!(
            blockd.proc.pid > 0,
            "blockd for {} recorded without a pid",
            blockd.grant.disk_id
        );
        assert_eq!(
            blockd.data_dir,
            record.dir.join(format!("vol-{}", blockd.grant.disk_id)),
            "the recorded data dir must be the one blockd was given"
        );
        assert_eq!(
            blockd.grant.attachment_id,
            format!("att_{CAT}_{}", blockd.grant.disk_id)
        );
    }
    let volume_ids: Vec<&str> = record
        .volumes
        .iter()
        .map(|volume| volume.disk_id.as_str())
        .collect();
    assert_eq!(volume_ids, ["root", "data"]);

    env.run(stop_job(CAT, 4));
}

#[test]
fn a_cat_that_reached_cold_is_forgotten() {
    const CAT: &str = "cat_ledger_stop";
    let env = ledger_env("node_ledger_stop");

    env.run(start_job(CAT, 1, &[("root", "/")]));
    assert_eq!(env.records().len(), 1);

    let stopped = env.run(stop_job(CAT, 2));
    assert_eq!(stopped.observed_state, ObservedState::Cold);
    assert!(
        env.records().is_empty(),
        "a Cold Cat must leave no runtime ledger record"
    );
}

/// `suspend_cat` can bounce Running -> Suspended -> Running inside one job when
/// guest work arrives in the pause window. Only the state the job settles on
/// may be recorded, which is why the write happens once in `execute_locked`
/// rather than at each `cats` mutation.
#[test]
fn only_the_settled_state_of_each_job_is_recorded() {
    const CAT: &str = "cat_ledger_suspend";
    let env = ledger_env("node_ledger_suspend");

    env.run(start_job(CAT, 1, &[("root", "/")]));

    env.run(simple_job(
        CAT,
        2,
        "suspend_cat",
        NodeJobAction::SuspendCat {
            cat_id: CAT.to_string(),
            work_fence: None,
        },
    ));
    let records = env.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, ObservedState::Suspended);
    assert_eq!(records[0].generation, 2);

    env.run(simple_job(
        CAT,
        3,
        "resume_cat",
        NodeJobAction::ResumeCat {
            cat_id: CAT.to_string(),
        },
    ));
    let records = env.records();
    assert_eq!(records.len(), 1, "resume must not add a second record");
    assert_eq!(records[0].state, ObservedState::Running);
    assert_eq!(records[0].generation, 3);

    env.run(stop_job(CAT, 4));
}

/// The legacy ledger is a local recovery aid, not authority (ADR-0040 §1). A
/// node that cannot write it has lost the ability to re-adopt the Cat later; it has not
/// lost the Cat, and must not fail the job that started it.
#[test]
fn an_unwritable_ledger_does_not_fail_the_job() {
    const CAT: &str = "cat_ledger_unwritable";
    let env = ledger_env("node_ledger_unwritable");

    // Replace the directory with a regular file: every `put` then fails with
    // ENOTDIR whatever uid the test runs as. Dropping the write permission bits
    // instead would be a no-op under root, which is how the Linux container
    // gate runs.
    let ledger_dir = env.ledger_dir();
    std::fs::remove_dir_all(&ledger_dir).expect("remove the ledger directory");
    std::fs::write(&ledger_dir, b"not a directory").expect("occupy the ledger path");

    let started = env.runtime.execute(start_job(CAT, 1, &[("root", "/")]));
    assert_eq!(
        started.phase,
        JobPhase::Succeeded,
        "an unwritable ledger must not fail a start: {:?}",
        started.error
    );
    assert_eq!(started.observed_state, ObservedState::Running);

    // The same holds for the removal side of the write path.
    let stopped = env.runtime.execute(stop_job(CAT, 2));
    assert_eq!(
        stopped.phase,
        JobPhase::Succeeded,
        "an unwritable ledger must not fail a stop: {:?}",
        stopped.error
    );
    assert_eq!(stopped.observed_state, ObservedState::Cold);
}

//! Re-adopting a Cat after the agent restarts (ADR-0028 §3).
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
//!
//! Coverage runs one state per test, because what is alive differs so much
//! between them: `Running` (everything up), `Suspended` (up but paused),
//! `Stopping` (blockds only) and `Warm` (nothing at all).

use super::*;

use std::collections::BTreeMap;

use ledger::{CatLedgerRecord, ChRecord};

/// Adopt on a restarted agent, asserting the ledger yielded exactly `CAT` and
/// left nothing behind. The caller then asserts what is state-specific.
fn adopt_only_cat(restarted: &NodeRuntime, cat_id: &str) {
    let outcome = restarted.adopt_from_ledger();
    assert_eq!(outcome.adopted, [cat_id.to_string()]);
    assert!(
        outcome.residue.is_empty(),
        "unexpected residue: {:?}",
        outcome.residue
    );
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

/// The pids a runtime supervises for one Cat's disks, for a Cat that may have
/// no guest left.
fn supervised_blockd_pids(runtime: &NodeRuntime, cat_id: &str) -> BTreeMap<String, u32> {
    let cats = runtime.cats.lock().expect("cats mutex");
    let rt = cats
        .get(cat_id)
        .unwrap_or_else(|| panic!("{cat_id} is not supervised"));
    rt.blockds
        .iter()
        .map(|(disk_id, blockd)| (disk_id.clone(), blockd.child.id()))
        .collect()
}

/// The scheduler state letter for a pid: `T` while a process is SIGSTOPped, `S`
/// or `R` once it runs again. How a paused FakeVmm guest is observed from the
/// outside, without asking it anything.
#[cfg(target_os = "linux")]
fn process_state(pid: u32) -> char {
    // Field 3 of /proc/<pid>/stat, which starts after the comm field's closing
    // paren (see `proc::parse_start_ticks` for why comm cannot be split on).
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc stat");
    stat.rsplit_once(')')
        .and_then(|(_, after_comm)| after_comm.split_whitespace().next())
        .and_then(|state| state.chars().next())
        .unwrap_or_else(|| panic!("no state field in /proc/{pid}/stat"))
}

#[cfg(not(target_os = "linux"))]
fn process_state(pid: u32) -> char {
    let output = Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
        .expect("run ps");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .chars()
        .next()
        .unwrap_or_else(|| panic!("ps reported no state for pid {pid}"))
}

/// A stand-in for the Cloud Hypervisor API socket, answering one `vm.info`.
///
/// CH mode itself needs KVM, so this is how the CH half of the Suspended proof
/// — the half that must never resume the Guest to learn anything — is exercised
/// on any host.
fn fake_vm_info(socket: &Path, status: &str, body: &str) -> std::thread::JoinHandle<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let listener = UnixListener::bind(socket).expect("bind the fake CH api socket");
    let (status, body) = (status.to_string(), body.to_string());
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the vm.info probe");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        // Read the whole request before answering: closing this end while the
        // client is still writing would fail its request, not its proof.
        let mut request = String::new();
        loop {
            let mut line = String::new();
            if reader
                .read_line(&mut line)
                .expect("read the vm.info request")
                == 0
            {
                break;
            }
            let blank = line == "\r\n" || line == "\n";
            request.push_str(&line);
            if blank {
                break;
            }
        }
        assert!(
            request.contains("GET /api/v1/vm.info "),
            "the proof asked something other than vm.info: {request}"
        );
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .expect("answer the vm.info probe");
    })
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
    let env = real_cat_env("node_adopt_running");
    env.run(start_job(CAT, 3, &[("root", "/"), ("data", "/data")]));
    let before = supervised_pids(&env.runtime, CAT);

    let restarted = env.restarted_agent();
    assert!(
        restarted.snapshot().is_empty(),
        "a fresh runtime knows nothing until it adopts"
    );
    adopt_only_cat(&restarted, CAT);
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
    let env = real_cat_env("node_adopt_unproven");
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
        (
            "the recorded state is not one this node can prove",
            "recorded state is Failed",
            Box::new(|record| record.state = ObservedState::Failed),
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
    let env = real_cat_env("node_adopt_legacy_blockd");
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

/// A Suspended Cat's processes are all still there; only its Guest is paused.
/// Adoption has to bind to them without waking anything: a resume costs a real
/// wake and would break the Suspended contract (ADR-0002).
#[test]
fn a_suspended_cat_is_adopted_and_left_paused() {
    const CAT: &str = "cat_adopt_suspended";
    let env = real_cat_env("node_adopt_suspended");
    env.run(start_job(CAT, 1, &[("root", "/"), ("data", "/data")]));
    env.run(simple_job(
        CAT,
        2,
        "suspend_cat",
        NodeJobAction::SuspendCat {
            cat_id: CAT.to_string(),
            work_fence: None,
        },
    ));
    assert_eq!(env.record(CAT).state, ObservedState::Suspended);
    let before = supervised_pids(&env.runtime, CAT);
    let guest_pid = before.0;
    assert_eq!(
        process_state(guest_pid),
        'T',
        "the FakeVmm guest is SIGSTOPped while Suspended"
    );

    let restarted = env.restarted_agent();
    adopt_only_cat(&restarted, CAT);
    assert_eq!(
        restarted.snapshot(),
        vec![(CAT.to_string(), 2, ObservedState::Suspended)],
        "an adopted Suspended Cat stays Suspended"
    );
    assert_eq!(
        supervised_pids(&restarted, CAT),
        before,
        "adoption must bind to the very processes that were already running"
    );
    // The whole point: nothing woke the Guest to prove it was there. A resumed
    // guest would answer again — and would report `S`, not `T`.
    assert_eq!(
        process_state(guest_pid),
        'T',
        "adoption resumed the paused guest"
    );

    env.run(stop_job(CAT, 3));
}

/// In Cloud Hypervisor mode the paused Guest cannot answer, but the VMM holding
/// it can, and its answer proves both halves at once: the recorded process is
/// serving the recorded API socket, and the VM really is paused.
#[test]
fn a_suspended_cat_is_proven_through_the_vmm_not_the_guest() {
    const CAT: &str = "cat_adopt_suspended_ch";
    let env = real_cat_env("node_adopt_suspended_ch");
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
    let suspended = env.record(CAT);

    // (case, vm.info status, vm.info body, expected reason or None to adopt)
    let cases: [(&str, &str, &str, Option<&str>); 4] = [
        (
            "the VMM reports the recorded paused state",
            "200 OK",
            r#"{"config":{"cpus":{"boot_vcpus":2}},"state":"Paused"}"#,
            None,
        ),
        (
            "the VMM is serving, but the VM is not paused",
            "200 OK",
            r#"{"state":"Running"}"#,
            Some("not the paused state"),
        ),
        (
            "the body is not something a VM state can be read out of",
            "200 OK",
            "<html>who knows what is on this socket</html>",
            Some("without a readable VM state"),
        ),
        (
            "the socket answers, but not for a VM",
            "404 Not Found",
            r#"{"error":"no vm"}"#,
            Some("status 404"),
        ),
    ];

    for (index, (case, status, body, expected_reason)) in cases.into_iter().enumerate() {
        let api_sock = env.root.join(format!("fake-ch-api-{index}.sock"));
        let responder = fake_vm_info(&api_sock, status, body);
        let mut record = suspended.clone();
        record.ch = Some(ChRecord {
            api_sock,
            vsock_sock: env.root.join("fake-ch-vsock.sock"),
            memory_file: record.dir.join(crate::ch::GUEST_MEMORY_FILE),
            nbd: BTreeMap::new(),
            snapshot_dir: None,
            network: None,
        });
        env.rewrite_record(&record);

        let restarted = env.restarted_agent();
        let outcome = restarted.adopt_from_ledger();

        // Assert before joining: if the proof never reached vm.info the
        // responder is still blocked in `accept`, and a failed assertion beats a
        // hung test.
        match expected_reason {
            None => {
                assert_eq!(outcome.adopted, [CAT.to_string()], "{case}");
                assert_eq!(
                    restarted.snapshot(),
                    vec![(CAT.to_string(), 2, ObservedState::Suspended)],
                    "{case}"
                );
            }
            Some(reason) => {
                assert!(outcome.adopted.is_empty(), "{case}");
                assert_eq!(outcome.residue.len(), 1, "{case}");
                assert!(
                    outcome.residue[0].1.contains(reason),
                    "{case}: reported {:?}, which does not mention {reason:?}",
                    outcome.residue[0].1
                );
                assert!(restarted.snapshot().is_empty(), "{case}");
            }
        }
        responder.join().expect("fake vm.info responder thread");
    }

    env.rewrite_record(&suspended);
    env.run(stop_job(CAT, 3));
}

/// `warm_cat` leaves nothing running: every blockd is drained, killed and
/// removed, and the VMM is gone. The record is written after that, so it carries
/// no guest and an empty blockd list, and the whole proof is made on disk.
#[test]
fn a_warm_cat_is_adopted_with_no_processes_at_all() {
    const CAT: &str = "cat_adopt_warm";
    let env = real_cat_env("node_adopt_warm");
    env.run(start_job(CAT, 1, &[("root", "/"), ("data", "/data")]));
    env.run(simple_job(
        CAT,
        2,
        "warm_cat",
        NodeJobAction::WarmCat {
            cat_id: CAT.to_string(),
        },
    ));
    let record = env.record(CAT);
    assert_eq!(record.state, ObservedState::Warm);
    assert!(record.guest.is_none(), "Warm has no resident guest");
    assert!(
        record.blockds.is_empty(),
        "warm_cat removes every blockd, so the record lists none"
    );

    let restarted = env.restarted_agent();
    adopt_only_cat(&restarted, CAT);
    assert_eq!(
        restarted.snapshot(),
        vec![(CAT.to_string(), 2, ObservedState::Warm)]
    );
    let cats = restarted.cats.lock().expect("cats mutex");
    let adopted = cats.get(CAT).expect("adopted runtime");
    assert!(adopted.guest.is_none());
    assert!(adopted.blockds.is_empty());
    let mut volumes: Vec<&str> = adopted
        .volumes
        .iter()
        .map(|volume| volume.disk_id.as_str())
        .collect();
    volumes.sort_unstable();
    assert_eq!(
        volumes,
        ["data", "root"],
        "the grants a restore needs must survive"
    );
    drop(cats);

    env.run(stop_job(CAT, 3));
}

/// The reboot exception (ADR-0028 §3). The boot-id gate exists to reject
/// recorded pids, and Warm records none; its snapshot and journals are files,
/// which a reboot does not invalidate. Gating Warm on the boot id would turn
/// every restorable Warm Cat on the host into residue the first time it came
/// back up.
#[test]
fn a_warm_cat_survives_a_host_reboot() {
    const CAT: &str = "cat_adopt_warm_reboot";
    let env = real_cat_env("node_adopt_warm_reboot");
    env.run(start_job(CAT, 1, &[("root", "/")]));
    env.run(simple_job(
        CAT,
        2,
        "warm_cat",
        NodeJobAction::WarmCat {
            cat_id: CAT.to_string(),
        },
    ));
    let mut record = env.record(CAT);
    record.host_boot_id = Some("00000000-0000-4000-8000-00000000beef".to_string());
    env.rewrite_record(&record);

    let restarted = env.restarted_agent();
    let outcome = restarted.adopt_from_ledger();

    assert_eq!(
        outcome.adopted,
        [CAT.to_string()],
        "a host reboot must not discard a restorable Warm Cat: {:?}",
        outcome.residue
    );
    assert_eq!(
        restarted.snapshot(),
        vec![(CAT.to_string(), 2, ObservedState::Warm)]
    );

    env.run(stop_job(CAT, 3));
}

/// Warm's evidence is entirely local files, so each one of them is load-bearing:
/// a Cat whose snapshot or journal is gone is not restorable, and claiming to
/// supervise it would tell the control plane otherwise.
#[test]
fn a_warm_record_missing_its_local_state_is_residue() {
    const CAT: &str = "cat_adopt_warm_incomplete";
    let env = real_cat_env("node_adopt_warm_incomplete");
    env.run(start_job(CAT, 1, &[("root", "/")]));
    env.run(simple_job(
        CAT,
        2,
        "warm_cat",
        NodeJobAction::WarmCat {
            cat_id: CAT.to_string(),
        },
    ));
    let warm = env.record(CAT);

    // The two CH-mode files. CH mode needs KVM, but the record shape does not,
    // and it is the shape the proof reads.
    let present_memory_file = warm.dir.join(crate::ch::GUEST_MEMORY_FILE);
    std::fs::write(&present_memory_file, b"guest memory backing").expect("write memory backing");
    let present_snapshot = warm.dir.join("snapshot");
    std::fs::create_dir_all(&present_snapshot).expect("create snapshot dir");
    let ch_record = |snapshot_dir: PathBuf, memory_file: PathBuf| ChRecord {
        api_sock: env.root.join("unused-ch-api.sock"),
        vsock_sock: env.root.join("unused-ch-vsock.sock"),
        memory_file,
        nbd: BTreeMap::new(),
        snapshot_dir: Some(snapshot_dir),
        network: None,
    };

    let cases = [
        ("the snapshot directory is gone", "snapshot directory", {
            let mut record = warm.clone();
            record.ch = Some(ch_record(
                record.dir.join("snapshot-that-is-not-there"),
                present_memory_file.clone(),
            ));
            record
        }),
        ("the guest memory backing is gone", "memory backing", {
            let mut record = warm.clone();
            record.ch = Some(ch_record(
                present_snapshot.clone(),
                record.dir.join("guest-memory-that-is-not-there.bin"),
            ));
            record
        }),
    ];
    for (case, expected_reason, record) in cases {
        env.rewrite_record(&record);

        let restarted = env.restarted_agent();
        let outcome = restarted.adopt_from_ledger();

        assert!(outcome.adopted.is_empty(), "{case}: adopted anyway");
        assert_eq!(outcome.residue.len(), 1, "{case}");
        assert!(
            outcome.residue[0].1.contains(expected_reason),
            "{case}: reported {:?}, which does not mention {expected_reason:?}",
            outcome.residue[0].1
        );
        assert!(restarted.snapshot().is_empty(), "{case}");
    }

    // The FakeVmm equivalents, which have to remove real files.
    env.rewrite_record(&warm);
    let data_dir = volume_data_dir(&warm.dir, "root");
    std::fs::rename(&data_dir, warm.dir.join("vol-root-moved")).expect("move the volume journal");
    let restarted = env.restarted_agent();
    let outcome = restarted.adopt_from_ledger();
    assert!(outcome.adopted.is_empty(), "adopted without a journal");
    assert!(
        outcome.residue[0].1.contains("data directory"),
        "unexpected reason: {:?}",
        outcome.residue[0].1
    );
    std::fs::rename(warm.dir.join("vol-root-moved"), &data_dir).expect("restore the journal");

    let state_file = warm_state_file(&warm.dir);
    std::fs::remove_file(&state_file).expect("remove the warm guest state file");
    let restarted = env.restarted_agent();
    let outcome = restarted.adopt_from_ledger();
    assert!(outcome.adopted.is_empty(), "adopted without a snapshot");
    assert!(
        outcome.residue[0].1.contains("warm guest state file"),
        "unexpected reason: {:?}",
        outcome.residue[0].1
    );
    assert!(restarted.snapshot().is_empty());

    // The owning runtime still has the Cat; Stop tears the rest down.
    env.run(stop_job(CAT, 3));
}

/// `stop_cat` converges to Stopping when the Guest is already gone but the
/// forced remote drain failed, and it deliberately keeps the blockds and their
/// journals alive so the same job can retry. On a relaxed volume with `R < L`
/// those journals hold the only authoritative copy of the unpublished writes
/// (ADR-0021/0022), so this is the state with real data at stake.
#[test]
fn a_stopping_cat_is_adopted_with_its_blockds_and_no_guest() {
    const CAT: &str = "cat_adopt_stopping";
    let env = real_cat_env("node_adopt_stopping");
    env.run(start_job(CAT, 4, &[("root", "/"), ("data", "/data")]));
    let (_, blockd_pids) = supervised_pids(&env.runtime, CAT);

    // Reaching Stopping for real needs a remote drain to fail against a broken
    // object store; what adoption sees either way is this record, so the record
    // is what the test builds: the Guest gone, every blockd still serving.
    let mut record = env.record(CAT);
    record.state = ObservedState::Stopping;
    record.guest = None;
    env.rewrite_record(&record);

    let restarted = env.restarted_agent();
    adopt_only_cat(&restarted, CAT);
    assert_eq!(
        restarted.snapshot(),
        vec![(CAT.to_string(), 4, ObservedState::Stopping)],
        "an adopted Stopping Cat stays Stopping, so the retry can find it"
    );
    assert_eq!(
        supervised_blockd_pids(&restarted, CAT),
        blockd_pids,
        "the adopted blockds must be the very processes holding the journals"
    );
    let cats = restarted.cats.lock().expect("cats mutex");
    assert!(
        cats.get(CAT).expect("adopted runtime").guest.is_none(),
        "Stopping has no Guest to adopt"
    );
    drop(cats);

    env.run(stop_job(CAT, 5));
}

/// Adoption may only rebuild a runtime that accounts for every process the
/// record names. `Stopping` and `Warm` are rebuilt with no Guest — and Warm with
/// no blockds — so a record whose state says that while still naming those
/// processes has to be refused, not adopted with the processes dropped on the
/// floor. Dropping them is what leaves an unsupervised orphan.
#[test]
fn a_record_naming_a_process_its_state_cannot_have_is_residue() {
    const CAT: &str = "cat_adopt_impossible";
    let env = real_cat_env("node_adopt_impossible");
    env.run(start_job(CAT, 1, &[("root", "/")]));
    let running = env.record(CAT);

    let cases = [
        (
            "Stopping still names a guest",
            "a Stopping record still names a guest process",
            {
                let mut record = running.clone();
                record.state = ObservedState::Stopping;
                record
            },
        ),
        (
            "Warm still names a guest",
            "a Warm record still names a guest process",
            {
                let mut record = running.clone();
                record.state = ObservedState::Warm;
                record.blockds.clear();
                record
            },
        ),
        (
            "Warm still names a blockd",
            "still names 1 blockd process",
            {
                let mut record = running.clone();
                record.state = ObservedState::Warm;
                record.guest = None;
                record
            },
        ),
    ];
    for (case, expected_reason, record) in cases {
        env.rewrite_record(&record);

        let restarted = env.restarted_agent();
        let outcome = restarted.adopt_from_ledger();

        assert!(outcome.adopted.is_empty(), "{case}: adopted anyway");
        assert_eq!(outcome.residue.len(), 1, "{case}");
        assert!(
            outcome.residue[0].1.contains(expected_reason),
            "{case}: reported {:?}, which does not mention {expected_reason:?}",
            outcome.residue[0].1
        );
        assert!(restarted.snapshot().is_empty(), "{case}");
    }

    env.run(stop_job(CAT, 2));
}

/// The blockd handshake is not skipped just because there is no Guest: a
/// Stopping record still has to prove which volume each surviving process holds.
#[test]
fn a_stopping_cat_whose_blockd_serves_another_volume_is_residue() {
    const CAT: &str = "cat_adopt_stopping_mismatch";
    let env = real_cat_env("node_adopt_stopping_mismatch");
    env.run(start_job(CAT, 1, &[("root", "/")]));

    let mut record = env.record(CAT);
    record.state = ObservedState::Stopping;
    record.guest = None;
    record.blockds[0].grant.volume_id = "vol_someone_else".to_string();
    env.rewrite_record(&record);

    let restarted = env.restarted_agent();
    let outcome = restarted.adopt_from_ledger();

    assert!(outcome.adopted.is_empty());
    assert_eq!(outcome.residue.len(), 1);
    assert!(
        outcome.residue[0].1.contains("serves volume"),
        "unexpected reason: {:?}",
        outcome.residue[0].1
    );
    assert!(restarted.snapshot().is_empty());

    env.run(stop_job(CAT, 2));
}

/// The safety property behind the whole conservative design: a Cat this node
/// cannot prove it owns is *absent* from the heartbeat snapshot, not reported
/// as `Cold`. Reporting Cold would tell the control plane the disk was released
/// while a blockd may still hold its lease; omitting it only keeps the node
/// Lost, which is the recoverable side (ADR-0028 §7).
#[test]
fn an_unadopted_cat_is_absent_from_the_heartbeat_snapshot() {
    const CAT: &str = "cat_adopt_absent";
    let env = real_cat_env("node_adopt_absent");
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
    let env = real_cat_env("node_adopt_untouched");
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

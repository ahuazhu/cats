use std::collections::VecDeque;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use cats_api::runtime_reconciliation::{
    decode_runtime_checkpoint, encode_runtime_checkpoint, spec_digest, AppliedDesiredEvidence,
    AssignedKind, AssignedPlacement, CheckpointRouteGate, ContractErrorDetail, ContractVersion,
    DesiredRuntimeSpec, EndpointGuardCount, EndpointIntent, Epoch, GuestTransportEvidence,
    Hostname, HttpProtocol, Id, Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission, MacAddress,
    NetworkConfig, RandomId128, ReconcileStep, RequireIdleCheckpoint, Revision, RouteGateBinding,
    RouteGateState, RuntimeCheckpoint, RuntimeConfig, RuntimeTarget, RuntimeTransition,
    Sha256Digest, StableState, UnixMillis, WarmSnapshotEvidence, RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
};
use tempfile::TempDir;

use super::admission_port::{AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult};
use super::checkpoint::{
    CheckpointStoreError, EndpointEffectEdge, EndpointEffectEdgeStatus, FileCheckpointStore,
    StoredCheckpoint, WriteStage, TEST_PROCESS_EXIT_CODE,
};
use super::gate_planner::{
    applied_desired_evidence, AppliedDesiredError, GateReconcileError, GateSequencer,
    GateTransitionResult, PersistTimes,
};

#[test]
fn checkpoint_store_round_trips_canonical_contract_and_digest() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&desired, 10);
    let store = store(&root, &desired.cat_id);

    assert!(store.load().expect("empty store").is_none());
    let stored = store.create(&checkpoint).expect("create checkpoint");
    assert_eq!(stored.checkpoint(), &checkpoint);
    assert_eq!(
        stored.content_digest(),
        &cats_api::runtime_reconciliation::checkpoint_content_digest(&checkpoint)
            .expect("checkpoint digest")
    );

    let mut replacement = checkpoint.clone();
    replacement.updated_at_unix_ms = unix_ms(11);
    let replacement = store
        .replace(&stored, &replacement)
        .expect("replace checkpoint");
    assert_eq!(
        store.load().expect("load").expect("present").checkpoint(),
        replacement.checkpoint()
    );
    assert_eq!(
        fs::read(store.path()).expect("wire"),
        encode_runtime_checkpoint(replacement.checkpoint()).expect("canonical wire")
    );
}

#[test]
fn checkpoint_reader_is_bounded_and_fails_closed_on_corruption() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&desired, 10);
    let store = store(&root, &desired.cat_id);
    let mut exact = encode_runtime_checkpoint(&checkpoint).expect("wire");
    exact.resize(RUNTIME_CHECKPOINT_MAX_WIRE_BYTES, b' ');
    fs::write(store.path(), &exact).expect("write exact-limit checkpoint");
    assert_eq!(
        store
            .load()
            .expect("exact limit")
            .expect("present")
            .checkpoint(),
        &checkpoint
    );

    exact.push(b' ');
    fs::write(store.path(), &exact).expect("write oversize checkpoint");
    let error = store.load().expect_err("oversize must fail");
    assert!(matches!(
        error,
        CheckpointStoreError::Contract(contract)
            if matches!(
                contract.error.as_ref(),
                ContractErrorDetail::LimitExceeded {
                    maximum,
                    observed_at_least,
                    ..
                } if maximum.get() == RUNTIME_CHECKPOINT_MAX_WIRE_BYTES as u64
                    && observed_at_least.get()
                        == RUNTIME_CHECKPOINT_MAX_WIRE_BYTES as u64 + 1
            )
    ));

    fs::write(store.path(), b"{not-json").expect("write corrupt checkpoint");
    assert!(matches!(
        store.load().expect_err("corrupt must fail"),
        CheckpointStoreError::Contract(_)
    ));
}

#[test]
fn checkpoint_target_fifo_is_rejected_before_open_can_block() {
    run_checkpoint_open_probe("regular");
    run_checkpoint_open_probe("fifo");
    run_checkpoint_open_probe("lock_fifo");
    run_checkpoint_open_probe("temp_fifo");
}

#[test]
fn checkpoint_open_probe_child() {
    let Ok(root) = std::env::var("CATS_CHECKPOINT_OPEN_PROBE_ROOT") else {
        return;
    };
    let mode = std::env::var("CATS_CHECKPOINT_OPEN_PROBE_MODE").expect("probe mode");
    let opened = FileCheckpointStore::open(Path::new(&root), &id("cat_01"));
    if mode == "lock_contended" {
        assert!(matches!(
            opened,
            Err(CheckpointStoreError::WriterAlreadyActive { .. })
        ));
        return;
    }
    if mode == "lock_fifo" {
        assert!(matches!(
            opened,
            Err(CheckpointStoreError::UnsafeEntry { .. })
        ));
        return;
    }
    let store = opened.expect("open checkpoint store in probe");
    match mode.as_str() {
        "regular" | "temp_fifo" => {
            assert!(store.load().expect("load regular target").is_some())
        }
        "fifo" => assert!(matches!(
            store.load().expect_err("FIFO target must fail closed"),
            CheckpointStoreError::UnsafeEntry { .. }
        )),
        "file_synced_exit" => {
            let current = store
                .load()
                .expect("load checkpoint before process exit")
                .expect("checkpoint before process exit");
            let mut replacement = current.checkpoint().clone();
            replacement.updated_at_unix_ms = unix_ms(11);
            store.inject_process_exit_once(WriteStage::FileSynced);
            let _ = store.replace(&current, &replacement);
            panic!("FileSynced process-exit fault returned");
        }
        "recover_file_synced_exit" => {
            assert!(
                !Path::new(&root).join(".cat-cat_01.checkpoint.tmp").exists(),
                "new writer process must remove the exact crashed temp"
            );
            let current = store
                .load()
                .expect("load checkpoint after process exit")
                .expect("checkpoint after process exit");
            assert_eq!(current.checkpoint().updated_at_unix_ms, unix_ms(10));
        }
        other => panic!("unknown checkpoint open probe mode {other}"),
    }
}

fn run_checkpoint_open_probe(mode: &str) {
    let root = TempDir::new().expect("probe tempdir");
    let target = root.path().join("cat-cat_01.checkpoint.json");
    if matches!(mode, "fifo" | "lock_fifo" | "temp_fifo") {
        let fifo_path = match mode {
            "fifo" => target.clone(),
            "lock_fifo" => root.path().join("cat-cat_01.checkpoint.lock"),
            "temp_fifo" => root.path().join(".cat-cat_01.checkpoint.tmp"),
            _ => unreachable!("matched FIFO probe mode"),
        };
        let target = CString::new(fifo_path.as_os_str().as_encoded_bytes()).expect("FIFO path");
        // SAFETY: `target` is a live NUL-terminated path for the duration of
        // the call. `mkfifo` retains no pointer.
        assert_eq!(unsafe { libc::mkfifo(target.as_ptr(), 0o600) }, 0);
    }
    if mode != "fifo" {
        let desired = desired(
            1,
            RuntimeTarget::Running,
            1,
            RuntimeTransition::CancelAndDrain,
        );
        fs::write(
            &target,
            encode_runtime_checkpoint(&running_checkpoint(&desired, 10)).expect("checkpoint wire"),
        )
        .expect("write regular checkpoint");
    }

    let status = run_checkpoint_process_probe(root.path(), mode);
    assert!(status.success(), "{mode} checkpoint open probe failed");
}

fn run_checkpoint_process_probe(root: &Path, mode: &str) -> std::process::ExitStatus {
    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("runtime::reconciliation::tests::checkpoint_open_probe_child")
        .arg("--nocapture")
        .env("CATS_CHECKPOINT_OPEN_PROBE_ROOT", root)
        .env("CATS_CHECKPOINT_OPEN_PROBE_MODE", mode)
        .spawn()
        .expect("spawn checkpoint open probe");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().expect("poll checkpoint open probe") {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill blocked checkpoint open probe");
            child.wait().expect("reap blocked checkpoint open probe");
            panic!("{mode} checkpoint open probe exceeded hard deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn checkpoint_writer_flock_excludes_a_real_second_process() {
    let root = TempDir::new().expect("tempdir");
    let owner = store(&root, &id("cat_01"));

    let status = run_checkpoint_process_probe(root.path(), "lock_contended");
    assert!(
        status.success(),
        "second process did not observe held flock"
    );
    drop(owner);
}

#[test]
fn filesynced_process_exit_leaves_one_temp_for_a_new_process_to_clean() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&desired, 10);
    let checkpoint_store = store(&root, &desired.cat_id);
    checkpoint_store
        .create(&checkpoint)
        .expect("initial checkpoint");
    drop(checkpoint_store);

    let crashed = run_checkpoint_process_probe(root.path(), "file_synced_exit");
    assert_eq!(crashed.code(), Some(TEST_PROCESS_EXIT_CODE));
    assert_eq!(checkpoint_temp_stats(root.path()).0, 1);
    assert!(root.path().join(".cat-cat_01.checkpoint.tmp").exists());

    let recovered = run_checkpoint_process_probe(root.path(), "recover_file_synced_exit");
    assert!(recovered.success(), "new writer process failed recovery");
    assert_eq!(checkpoint_temp_stats(root.path()), (0, 0));

    let reopened = store(&root, &desired.cat_id);
    assert_eq!(
        reopened
            .load()
            .expect("load after process recovery")
            .expect("checkpoint after process recovery")
            .checkpoint(),
        &checkpoint
    );
}

#[test]
fn every_checkpoint_publish_crash_point_has_a_conservative_visible_state() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let desired = desired(
            1,
            RuntimeTarget::Running,
            1,
            RuntimeTransition::CancelAndDrain,
        );
        let mut checkpoint = running_checkpoint(&desired, 10);
        let store = store(&root, &desired.cat_id);
        let original = store.create(&checkpoint).expect("initial checkpoint");
        checkpoint.updated_at_unix_ms = unix_ms(11);
        store.inject_crash_once(stage);
        assert!(matches!(
            store
                .replace(&original, &checkpoint)
                .expect_err("injected crash"),
            CheckpointStoreError::InjectedCrash
        ));

        let visible = store.load().expect("load after crash").expect("target");
        match stage {
            WriteStage::Write | WriteStage::TempWritten | WriteStage::FileSynced => {
                assert_eq!(visible.checkpoint(), original.checkpoint());
            }
            WriteStage::Renamed | WriteStage::DirectorySynced => {
                assert_eq!(visible.checkpoint(), &checkpoint);
            }
        }
    }
}

#[test]
fn close_effect_is_not_called_when_the_checkpoint_publish_crashes() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let source_desired = desired(
            1,
            RuntimeTarget::Running,
            1,
            RuntimeTransition::CancelAndDrain,
        );
        let source_checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&source_checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
            store.path(),
        );
        let stop = desired(
            2,
            RuntimeTarget::Suspended,
            1,
            RuntimeTransition::CancelAndDrain,
        );

        store.inject_crash_once(stage);
        let error = GateSequencer::new(&store, &mut port)
            .close_all(&source, &stop, times(20, 21))
            .expect_err("pre-effect checkpoint crash");
        assert!(matches!(
            error,
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        assert!(port.calls.is_empty());
        assert_eq!(port.current.lifecycle_admission(), LifecycleAdmission::Open);

        let visible = store.load().expect("load visible target").expect("target");
        match stage {
            WriteStage::Write | WriteStage::TempWritten | WriteStage::FileSynced => {
                assert_eq!(visible.checkpoint(), &source_checkpoint);
            }
            WriteStage::Renamed | WriteStage::DirectorySynced => {
                assert_closed(visible.checkpoint());
                assert_eq!(visible.checkpoint().desired_revision, revision(2));
            }
        }
    }
}

#[test]
fn post_effect_publish_crash_leaves_both_states_conservatively_closed() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let source_desired = desired(
            1,
            RuntimeTarget::Running,
            1,
            RuntimeTransition::CancelAndDrain,
        );
        let source_checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&source_checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::Closed {
            revision: revision(2),
        });
        let stop = desired(
            2,
            RuntimeTarget::Suspended,
            1,
            RuntimeTransition::CancelAndDrain,
        );

        // close_all publishes once before the port call and once afterwards.
        store.inject_crash_on_nth(stage, 2);
        let error = GateSequencer::new(&store, &mut port)
            .close_all(&source, &stop, times(20, 21))
            .expect_err("post-effect checkpoint crash");
        assert!(matches!(
            error,
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        assert_eq!(port.calls, vec![PortCall::Close]);
        assert_eq!(
            port.current.lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        assert_closed(
            store
                .load()
                .expect("load visible target")
                .expect("target")
                .checkpoint(),
        );
    }
}

#[test]
fn stale_temp_is_never_adopted_and_semantic_target_aba_is_rejected() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&desired, 10);
    let store = store(&root, &desired.cat_id);
    let stored = store.create(&checkpoint).expect("initial checkpoint");

    let mut fake_temp = checkpoint.clone();
    fake_temp.updated_at_unix_ms = unix_ms(999);
    fs::write(
        root.path().join(".cat-cat_01.checkpoint.tmp.crashed"),
        encode_runtime_checkpoint(&fake_temp).expect("temp wire"),
    )
    .expect("write stale temp");
    assert_eq!(
        store.load().expect("load").expect("target").checkpoint(),
        &checkpoint
    );

    let original_wire = encode_runtime_checkpoint(&checkpoint).expect("wire");
    store.before_publish_once(move |target| {
        let replacement = target.with_extension("aba");
        fs::write(&replacement, &original_wire).expect("write ABA replacement");
        fs::rename(replacement, target).expect("replace target with same semantic content");
    });
    let mut next = checkpoint.clone();
    next.updated_at_unix_ms = unix_ms(11);
    assert!(matches!(
        store.replace(&stored, &next).expect_err("ABA must fail"),
        CheckpointStoreError::ConcurrentUpdate { .. }
    ));
    assert_eq!(
        store.load().expect("load").expect("target").checkpoint(),
        &checkpoint
    );
}

#[test]
fn checkpoint_temp_space_is_bounded_across_failures_and_restart() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&desired, 10);
    let store = store(&root, &desired.cat_id);
    let mut expected = store.create(&checkpoint).expect("initial checkpoint");
    let mut replacement = checkpoint.clone();
    replacement.updated_at_unix_ms = unix_ms(11);

    for stage in [
        WriteStage::Write,
        WriteStage::TempWritten,
        WriteStage::FileSynced,
    ] {
        for _ in 0..4 {
            store.inject_crash_once(stage);
            assert!(matches!(
                store
                    .replace(&expected, &replacement)
                    .expect_err("injected pre-rename failure"),
                CheckpointStoreError::InjectedCrash
            ));
            assert_checkpoint_temp_bound(root.path());
        }
    }

    for _ in 0..4 {
        let original_wire = encode_runtime_checkpoint(expected.checkpoint()).expect("wire");
        store.before_publish_once(move |target| {
            let replacement = target.with_extension("second-cas");
            fs::write(&replacement, &original_wire).expect("write CAS replacement");
            fs::rename(replacement, target).expect("replace target before second CAS");
        });
        assert!(matches!(
            store
                .replace(&expected, &replacement)
                .expect_err("second CAS must reject target replacement"),
            CheckpointStoreError::ConcurrentUpdate { .. }
        ));
        assert_checkpoint_temp_bound(root.path());
        expected = store.load().expect("reload target").expect("checkpoint");
    }

    let deterministic_temp = root.path().join(".cat-cat_01.checkpoint.tmp");
    fs::write(&deterministic_temp, vec![b'x'; 4096]).expect("write crashed deterministic temp");
    drop(store);
    let restarted =
        FileCheckpointStore::open(root.path(), &desired.cat_id).expect("restart checkpoint store");
    assert!(
        !deterministic_temp.exists(),
        "a new writer session must remove only its exact stale temp basename"
    );
    expected = restarted
        .load()
        .expect("load after restart")
        .expect("checkpoint");
    restarted
        .replace(&expected, &replacement)
        .expect("eventual successful replacement");
    assert_eq!(checkpoint_temp_stats(root.path()), (0, 0));
}

#[test]
fn unrelated_publication_recovery_open_preserves_checkpoint_temp() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&desired, 10);
    let store = store(&root, &desired.cat_id);
    store.create(&checkpoint).expect("initial checkpoint");
    drop(store);

    let temporary = root.path().join(".cat-cat_01.checkpoint.tmp");
    let bytes = b"interrupted checkpoint publication";
    fs::write(&temporary, bytes).expect("write checkpoint temp");
    let before = fs::metadata(&temporary).expect("checkpoint temp metadata");

    let opened = FileCheckpointStore::open_preserving_checkpoint_temp(root.path(), &desired.cat_id);
    assert!(matches!(
        opened,
        Err(CheckpointStoreError::UnsafeEntry { .. })
    ));
    assert_eq!(fs::read(&temporary).expect("checkpoint temp bytes"), bytes);
    let after = fs::metadata(&temporary).expect("checkpoint temp metadata after open");
    assert_eq!(after.dev(), before.dev());
    assert_eq!(after.ino(), before.ino());
    assert_eq!(after.nlink(), before.nlink());
}

fn assert_checkpoint_temp_bound(root: &Path) {
    let (count, bytes) = checkpoint_temp_stats(root);
    assert!(count <= 1, "checkpoint temp count grew to {count}");
    assert!(
        bytes <= RUNTIME_CHECKPOINT_MAX_WIRE_BYTES as u64,
        "checkpoint temp bytes grew to {bytes}"
    );
}

fn checkpoint_temp_stats(root: &Path) -> (usize, u64) {
    fs::read_dir(root)
        .expect("read checkpoint directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".cat-cat_01.checkpoint.tmp")
        })
        .fold((0, 0), |(count, bytes), entry| {
            let len = entry.metadata().map_or(0, |metadata| metadata.len());
            (count + 1, bytes.saturating_add(len))
        })
}

#[test]
fn checkpoint_target_and_directory_symlinks_are_rejected() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let store = store(&root, &desired.cat_id);
    let outside = root.path().join("outside");
    fs::write(&outside, b"outside").expect("outside file");
    symlink(&outside, store.path()).expect("target symlink");
    assert!(matches!(
        store.load().expect_err("target symlink"),
        CheckpointStoreError::UnsafeEntry { .. }
    ));
    assert_eq!(fs::read(&outside).expect("outside unchanged"), b"outside");

    let real = root.path().join("real");
    fs::create_dir(&real).expect("real directory");
    let alias = root.path().join("alias");
    symlink(&real, &alias).expect("directory symlink");
    assert!(FileCheckpointStore::open(&alias, &desired.cat_id).is_err());
}

#[test]
fn checkpoint_target_hardlink_and_publish_time_symlink_are_rejected() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let outside = root.path().join("outside");
    fs::write(&outside, b"outside").expect("outside file");
    let store = store(&root, &desired.cat_id);
    fs::hard_link(&outside, store.path()).expect("target hardlink");
    assert!(matches!(
        store.load().expect_err("target hardlink"),
        CheckpointStoreError::UnsafeEntry { .. }
    ));
    fs::remove_file(store.path()).expect("remove test hardlink");
    assert_eq!(fs::read(&outside).expect("outside unchanged"), b"outside");

    let checkpoint = running_checkpoint(&desired, 10);
    let stored = store.create(&checkpoint).expect("checkpoint");
    let outside_for_hook = outside.clone();
    store.before_publish_once(move |target| {
        fs::remove_file(target).expect("remove target for symlink substitution");
        symlink(&outside_for_hook, target).expect("substitute target symlink");
    });
    let mut next = checkpoint;
    next.updated_at_unix_ms = unix_ms(11);
    assert!(matches!(
        store
            .replace(&stored, &next)
            .expect_err("publish-time symlink"),
        CheckpointStoreError::UnsafeEntry { .. }
    ));
    assert_eq!(fs::read(&outside).expect("outside unchanged"), b"outside");
}

#[test]
fn second_checkpoint_writer_is_refused() {
    let root = TempDir::new().expect("tempdir");
    let cat_id = id("cat_01");
    let _first = store(&root, &cat_id);
    let second = FileCheckpointStore::open(root.path(), &cat_id);
    assert!(matches!(
        second,
        Err(CheckpointStoreError::WriterAlreadyActive { .. })
    ));
}

#[test]
fn one_store_serializes_concurrent_compare_and_replace_writers() {
    let root = TempDir::new().expect("tempdir");
    let desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&desired, 10);
    let store = Arc::new(store(&root, &desired.cat_id));
    let expected = store.create(&checkpoint).expect("checkpoint");
    let barrier = Arc::new(Barrier::new(3));
    let mut writers = Vec::new();
    for updated_at in [11, 12] {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let expected = expected.clone();
        let mut replacement = checkpoint.clone();
        replacement.updated_at_unix_ms = unix_ms(updated_at);
        writers.push(std::thread::spawn(move || {
            barrier.wait();
            store.replace(&expected, &replacement)
        }));
    }
    barrier.wait();
    let results: Vec<_> = writers
        .into_iter()
        .map(|writer| writer.join().expect("writer thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(CheckpointStoreError::ConcurrentUpdate { .. })))
            .count(),
        1
    );
    let visible = store.load().expect("load").expect("checkpoint");
    assert!(matches!(
        visible.checkpoint().updated_at_unix_ms.get(),
        11 | 12
    ));
}

#[test]
fn applied_evidence_requires_exact_revision_digest_placement_and_incarnation() {
    let current = desired(
        7,
        RuntimeTarget::Running,
        9,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&current, 10);
    assert_eq!(
        applied_desired_evidence(&checkpoint, &current).expect("exact evidence"),
        AppliedDesiredEvidence {
            desired_revision: current.desired_revision,
            spec_digest: current.spec_digest.clone(),
            placement: current.placement.clone(),
            target: RuntimeTarget::Running,
        }
    );

    let newer = desired(
        8,
        RuntimeTarget::Running,
        9,
        RuntimeTransition::CancelAndDrain,
    );
    assert!(matches!(
        applied_desired_evidence(&checkpoint, &newer),
        Err(AppliedDesiredError::Revision { .. })
    ));

    let mut different_spec = current.clone();
    different_spec.runtime.memory_bytes += 1;
    refresh_spec_digest(&mut different_spec);
    assert!(matches!(
        applied_desired_evidence(&checkpoint, &different_spec),
        Err(AppliedDesiredError::SpecDigest { .. })
    ));

    let mut different_placement = current.clone();
    different_placement.placement.placement_epoch = epoch(4);
    refresh_spec_digest(&mut different_placement);
    let mut placement_bound = checkpoint.clone();
    placement_bound.spec_digest = different_placement.spec_digest.clone();
    assert!(matches!(
        applied_desired_evidence(&placement_bound, &different_placement),
        Err(AppliedDesiredError::Placement { .. })
    ));

    let mut require_idle = desired(
        8,
        RuntimeTarget::Suspended,
        9,
        RuntimeTransition::RequireIdle {
            attempt_id: random('a'),
            source_revision: revision(7),
            source_runtime_incarnation: random('9'),
        },
    );
    // Bind the checkpoint to the new desired while retaining its real
    // incarnation. This isolates the incarnation check from revision/digest.
    let mut bound = checkpoint.clone();
    bound.desired_revision = require_idle.desired_revision;
    bound.spec_digest = require_idle.spec_digest.clone();
    bound.stable_state = None;
    assert!(matches!(
        applied_desired_evidence(&bound, &require_idle),
        Err(AppliedDesiredError::RuntimeIncarnation)
    ));

    require_idle.cat_id = id("cat_other");
    refresh_spec_digest(&mut require_idle);
    assert!(matches!(
        applied_desired_evidence(&bound, &require_idle),
        Err(AppliedDesiredError::WrongCat { .. })
    ));
}

#[test]
fn applied_evidence_rejects_invalid_checkpoint_and_wrong_route_binding() {
    let current = desired(
        7,
        RuntimeTarget::Running,
        9,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&current, 10);

    let mut wrong_workspace = checkpoint.clone();
    wrong_workspace.route_gates[0].binding.workspace_id = id("ws_other");
    assert!(matches!(
        applied_desired_evidence(&wrong_workspace, &current),
        Err(AppliedDesiredError::RouteWorkspace { .. })
    ));

    let mut wrong_binding = checkpoint.clone();
    wrong_binding.route_gates[0].binding.target_port = 9090;
    assert!(matches!(
        applied_desired_evidence(&wrong_binding, &current),
        Err(AppliedDesiredError::ActiveRouteBinding { .. })
    ));

    let mut invalid_checkpoint = checkpoint;
    invalid_checkpoint
        .route_gates
        .push(invalid_checkpoint.route_gates[0].clone());
    assert!(matches!(
        applied_desired_evidence(&invalid_checkpoint, &current),
        Err(AppliedDesiredError::CheckpointContract { .. })
    ));
}

#[test]
fn install_and_close_are_checkpoint_first() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let source_checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&source_checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
        store.path(),
    );

    let stop_desired = desired(
        2,
        RuntimeTarget::Suspended,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    port.expected_disk.push_back(DiskMarker::Closed {
        revision: revision(2),
    });
    let closed = {
        let mut sequencer = GateSequencer::new(&store, &mut port);
        sequencer
            .close_all(&source, &stop_desired, times(20, 21))
            .expect("close")
    };
    assert_eq!(port.calls, vec![PortCall::Close]);
    assert_closed(closed.checkpoint().checkpoint());

    let running_desired = desired(
        3,
        RuntimeTarget::Running,
        2,
        RuntimeTransition::CancelAndDrain,
    );
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(3),
        endpoint_id: id("ep_01"),
        route_epoch: epoch(2),
    });
    let installed = {
        let mut sequencer = GateSequencer::new(&store, &mut port);
        sequencer
            .install_gate(
                closed.checkpoint(),
                &running_desired,
                &id("ep_01"),
                times(30, 31),
            )
            .expect("install fresh epoch")
    };
    assert_eq!(port.calls, vec![PortCall::Close, PortCall::Install]);
    let installed = installed.checkpoint().checkpoint();
    assert_eq!(installed.desired_revision, revision(3));
    assert_eq!(installed.lifecycle_admission, LifecycleAdmission::Open);
    assert_eq!(installed.route_gates[0].binding.route_epoch, epoch(2));
    assert_eq!(installed.route_gates[0].gate, RouteGateState::Active);
}

#[test]
fn admission_tuple_mismatch_fails_closed_after_durable_close_intent() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let source_checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&source_checkpoint).expect("source checkpoint");
    let mut wrong_cell_checkpoint = source_checkpoint.clone();
    wrong_cell_checkpoint.spec_digest = digest('e');
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&wrong_cell_checkpoint).expect("wrong cell snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::Closed {
        revision: revision(2),
    });
    let stop = desired(
        2,
        RuntimeTarget::Suspended,
        1,
        RuntimeTransition::CancelAndDrain,
    );

    let error = GateSequencer::new(&store, &mut port)
        .close_all(&source, &stop, times(20, 21))
        .expect_err("wrong complete expected tuple");
    assert!(matches!(
        error,
        GateReconcileError::Port(GatePortError::StateMismatch)
    ));
    assert_eq!(
        port.current.lifecycle_admission(),
        LifecycleAdmission::Closed
    );
    assert_closed(
        store
            .load()
            .expect("load")
            .expect("checkpoint")
            .checkpoint(),
    );
}

#[test]
fn a_closed_epoch_cannot_reopen_but_a_higher_epoch_can() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let mut checkpoint = running_checkpoint(&source_desired, 10);
    checkpoint.lifecycle_admission = LifecycleAdmission::Closed;
    checkpoint.route_gates[0].gate = RouteGateState::Closed;
    let store = store(&root, &source_desired.cat_id);
    let stored = store.create(&checkpoint).expect("checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );

    let same_epoch = desired(
        2,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    let error = GateSequencer::new(&store, &mut port)
        .install_gate(&stored, &same_epoch, &id("ep_01"), times(20, 21))
        .expect_err("closed epoch reuse");
    assert!(matches!(error, GateReconcileError::ClosedEpochReuse(_)));
    assert!(port.calls.is_empty());
    assert_eq!(
        store.load().expect("load").expect("present").checkpoint(),
        &checkpoint
    );

    let higher_epoch = desired(
        2,
        RuntimeTarget::Running,
        2,
        RuntimeTransition::CancelAndDrain,
    );
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_01"),
        route_epoch: epoch(2),
    });
    let installed = GateSequencer::new(&store, &mut port)
        .install_gate(&stored, &higher_epoch, &id("ep_01"), times(30, 31))
        .expect("higher epoch can recover a closed gate");
    assert_eq!(
        installed.checkpoint().checkpoint().route_gates[0]
            .binding
            .route_epoch,
        epoch(2)
    );
}

#[test]
fn require_idle_busy_is_one_shot_and_keeps_the_old_gate_open() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let stored = store.create(&checkpoint).expect("checkpoint");
    let desired = require_idle_desired(2, 1, 7, 'a');
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.idle_results.push_back(Ok(IdleCloseResult::Busy {
        platform_guards: 0,
        endpoint_guards: vec![EndpointGuardCount {
            endpoint_id: id("ep_01"),
            active_guards: 2,
        }],
    }));
    port.expected_disk.push_back(DiskMarker::Armed);

    let result = GateSequencer::new(&store, &mut port)
        .begin_require_idle(&stored, &desired, times(20, 21))
        .expect("Busy outcome");
    let GateTransitionResult::RequireIdleBusy {
        checkpoint,
        gate_closed,
        port_error,
    } = result
    else {
        panic!("expected Busy")
    };
    assert!(!gate_closed);
    assert!(port_error.is_none());
    assert_eq!(port.calls, vec![PortCall::TryIdle]);
    assert_eq!(
        checkpoint.checkpoint().lifecycle_admission,
        LifecycleAdmission::Open
    );
    assert_eq!(
        checkpoint.checkpoint().route_gates[0].gate,
        RouteGateState::Active
    );
    assert!(matches!(
        &checkpoint.checkpoint().require_idle,
        RequireIdleCheckpoint::Busy {
            gate_closed: false,
            endpoint_guards,
            ..
        } if endpoint_guards[0].active_guards == 2
    ));

    let error = GateSequencer::new(&store, &mut port)
        .begin_require_idle(&checkpoint, &desired, times(22, 23))
        .expect_err("attempt cannot be evaluated again");
    assert!(matches!(error, GateReconcileError::WrongRequireIdleSource));
    assert_eq!(port.calls, vec![PortCall::TryIdle]);
}

#[test]
fn fresh_running_after_open_busy_keeps_the_same_gate_epoch() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let source_checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&source_checkpoint).expect("source checkpoint");
    let suspended = require_idle_desired(2, 1, 7, 'f');
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
        store.path(),
    );
    port.idle_results.push_back(Ok(IdleCloseResult::Busy {
        platform_guards: 1,
        endpoint_guards: Vec::new(),
    }));
    port.expected_disk.push_back(DiskMarker::Armed);
    let busy = GateSequencer::new(&store, &mut port)
        .begin_require_idle(&source, &suspended, times(20, 21))
        .expect("Busy");
    let GateTransitionResult::RequireIdleBusy {
        checkpoint: busy,
        gate_closed: false,
        ..
    } = busy
    else {
        panic!("expected open Busy")
    };

    let fresh_running = desired(
        3,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(3),
        endpoint_id: id("ep_01"),
        route_epoch: epoch(7),
    });
    let installed = GateSequencer::new(&store, &mut port)
        .install_gate(&busy, &fresh_running, &id("ep_01"), times(30, 31))
        .expect("fresh Running can retain an epoch that was never closed");
    assert_eq!(
        installed.checkpoint().checkpoint().route_gates[0]
            .binding
            .route_epoch,
        epoch(7)
    );
    assert_eq!(
        port.current.applied_desired_revision(),
        fresh_running.desired_revision
    );
    assert_eq!(port.current.lifecycle_admission(), LifecycleAdmission::Open);
}

#[test]
fn ordinary_transition_after_open_busy_compares_the_live_source_tuple() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let source_checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&source_checkpoint).expect("source checkpoint");
    let suspended = require_idle_desired(2, 1, 7, '7');
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
        store.path(),
    );
    port.idle_results.push_back(Ok(IdleCloseResult::Busy {
        platform_guards: 1,
        endpoint_guards: Vec::new(),
    }));
    port.expected_disk.push_back(DiskMarker::Armed);
    let busy = GateSequencer::new(&store, &mut port)
        .begin_require_idle(&source, &suspended, times(20, 21))
        .expect("Busy");
    let GateTransitionResult::RequireIdleBusy {
        checkpoint: busy,
        gate_closed: false,
        ..
    } = busy
    else {
        panic!("expected open Busy")
    };

    let cold = desired(3, RuntimeTarget::Cold, 7, RuntimeTransition::CancelAndDrain);
    port.expected_disk.push_back(DiskMarker::Closed {
        revision: revision(3),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_all(&busy, &cold, times(30, 31))
        .expect("manual close after Busy");
    assert_closed(closed.checkpoint().checkpoint());
    assert_eq!(port.calls, vec![PortCall::TryIdle, PortCall::Close]);
    assert_eq!(
        port.current.applied_desired_revision(),
        cold.desired_revision
    );
}

#[test]
fn require_idle_cannot_arm_across_placement_or_runtime_incarnation() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let source_checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&source_checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
        store.path(),
    );

    let mut moved = require_idle_desired(2, 1, 7, '8');
    moved.placement.placement_epoch = epoch(4);
    refresh_spec_digest(&mut moved);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .begin_require_idle(&source, &moved, times(20, 21))
            .expect_err("placement changed"),
        GateReconcileError::WrongRequireIdleSource
    ));

    let mut wrong_incarnation = require_idle_desired(2, 1, 7, '9');
    wrong_incarnation.transition = RuntimeTransition::RequireIdle {
        attempt_id: random('9'),
        source_revision: revision(1),
        source_runtime_incarnation: random('6'),
    };
    refresh_spec_digest(&mut wrong_incarnation);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .begin_require_idle(&source, &wrong_incarnation, times(20, 21))
            .expect_err("runtime incarnation changed"),
        GateReconcileError::WrongRequireIdleSource
    ));
    assert!(port.calls.is_empty());
    assert_eq!(
        store
            .load()
            .expect("load")
            .expect("checkpoint")
            .checkpoint(),
        &source_checkpoint
    );
}

#[test]
fn require_idle_close_and_late_busy_never_reopen_the_epoch() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let stored = store.create(&checkpoint).expect("checkpoint");
    let suspended_desired = require_idle_desired(2, 1, 7, 'b');
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.idle_results.push_back(Ok(IdleCloseResult::Closed));
    port.expected_disk.push_back(DiskMarker::Armed);
    let closed = GateSequencer::new(&store, &mut port)
        .begin_require_idle(&stored, &suspended_desired, times(20, 21))
        .expect("closed");
    let GateTransitionResult::RequireIdleClosed { checkpoint: closed } = closed else {
        panic!("expected closed")
    };
    assert_closed(closed.checkpoint());

    let busy = GateSequencer::new(&store, &mut port)
        .record_post_close_busy(&closed, &suspended_desired, unix_ms(22))
        .expect("watcher/quiesce Busy");
    let GateTransitionResult::RequireIdleBusy {
        checkpoint: busy,
        gate_closed,
        ..
    } = busy
    else {
        panic!("expected Busy")
    };
    assert!(gate_closed);
    assert_closed(busy.checkpoint());
    assert!(matches!(
        busy.checkpoint().require_idle,
        RequireIdleCheckpoint::Busy {
            gate_closed: true,
            ..
        }
    ));

    let old_epoch_running = desired(
        3,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let error = GateSequencer::new(&store, &mut port)
        .install_gate(&busy, &old_epoch_running, &id("ep_01"), times(30, 31))
        .expect_err("old epoch cannot reopen");
    assert!(matches!(error, GateReconcileError::ClosedEpochReuse(_)));
}

#[test]
fn armed_restart_becomes_busy_closed_without_reevaluating_idle() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let mut armed_checkpoint = running_checkpoint(&source_desired, 10);
    let desired = require_idle_desired(2, 1, 7, 'c');
    armed_checkpoint.desired_revision = desired.desired_revision;
    armed_checkpoint.spec_digest = desired.spec_digest.clone();
    armed_checkpoint.stable_state = None;
    armed_checkpoint.step = ReconcileStep::CloseAdmission {
        require_idle_attempt_id: Some(random('c')),
    };
    armed_checkpoint.require_idle = RequireIdleCheckpoint::Armed {
        attempt_id: random('c'),
        source_revision: revision(1),
        source_runtime_incarnation: random('5'),
    };
    let store = store(&root, &desired.cat_id);
    let armed = store.create(&armed_checkpoint).expect("armed checkpoint");
    // A new agent process starts with every in-memory gate closed even when
    // the last durable checkpoint still says Active.
    let restart_snapshot = AdmissionSnapshot::from_checkpoint(&armed_checkpoint)
        .expect("snapshot")
        .fail_closed();
    let mut port = FakePort::new(restart_snapshot, store.path());
    port.expected_disk.push_back(DiskMarker::BusyClosed);

    let result = GateSequencer::new(&store, &mut port)
        .recover_armed(&armed, &desired, times(20, 21))
        .expect("recover armed");
    assert_eq!(port.calls, vec![PortCall::Close]);
    assert!(port.idle_results.is_empty());
    let GateTransitionResult::RequireIdleBusy {
        checkpoint,
        gate_closed,
        ..
    } = result
    else {
        panic!("expected Busy")
    };
    assert!(gate_closed);
    assert_closed(checkpoint.checkpoint());
    assert_eq!(
        port.current.lifecycle_admission(),
        LifecycleAdmission::Closed
    );

    let error = GateSequencer::new(&store, &mut port)
        .recover_armed(&checkpoint, &desired, times(22, 23))
        .expect_err("terminal attempt is not replayed");
    assert!(matches!(
        error,
        GateReconcileError::WrongRequireIdleCheckpoint
    ));
    assert_eq!(port.calls, vec![PortCall::Close]);
}

#[test]
fn stale_armed_attempt_is_rejected_before_disk_or_gate_change() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let mut armed_checkpoint = running_checkpoint(&source_desired, 10);
    let suspended = require_idle_desired(2, 1, 7, 'd');
    armed_checkpoint.desired_revision = suspended.desired_revision;
    armed_checkpoint.spec_digest = suspended.spec_digest.clone();
    armed_checkpoint.stable_state = None;
    armed_checkpoint.step = ReconcileStep::CloseAdmission {
        require_idle_attempt_id: Some(random('d')),
    };
    armed_checkpoint.require_idle = RequireIdleCheckpoint::Armed {
        attempt_id: random('d'),
        source_revision: revision(1),
        source_runtime_incarnation: random('5'),
    };
    let store = store(&root, &suspended.cat_id);
    let armed = store.create(&armed_checkpoint).expect("armed checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&armed_checkpoint).expect("snapshot"),
        store.path(),
    );
    let fresh_running = desired(
        3,
        RuntimeTarget::Running,
        8,
        RuntimeTransition::CancelAndDrain,
    );

    let error = GateSequencer::new(&store, &mut port)
        .recover_armed(&armed, &fresh_running, times(20, 21))
        .expect_err("stale Armed must fail");
    assert!(matches!(
        error,
        GateReconcileError::AppliedDesired(AppliedDesiredError::Revision { .. })
    ));
    assert!(port.calls.is_empty());
    assert_eq!(
        store.load().expect("load").expect("present").checkpoint(),
        &armed_checkpoint
    );
}

#[test]
fn ambiguous_idle_result_is_persisted_busy_closed_before_forced_close() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let stored = store.create(&checkpoint).expect("checkpoint");
    let desired = require_idle_desired(2, 1, 7, 'e');
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.idle_results.push_back(Err(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::Armed);
    port.expected_disk.push_back(DiskMarker::BusyClosed);

    let result = GateSequencer::new(&store, &mut port)
        .begin_require_idle(&stored, &desired, times(20, 21))
        .expect("ambiguous becomes terminal Busy");
    assert_eq!(port.calls, vec![PortCall::TryIdle, PortCall::Close]);
    let GateTransitionResult::RequireIdleBusy {
        checkpoint,
        gate_closed,
        port_error,
    } = result
    else {
        panic!("expected Busy")
    };
    assert!(gate_closed);
    assert_eq!(port_error, Some(GatePortError::Unavailable));
    assert_closed(checkpoint.checkpoint());
}

#[test]
fn invalid_busy_guard_evidence_is_settled_closed() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = desired(
        1,
        RuntimeTarget::Running,
        7,
        RuntimeTransition::CancelAndDrain,
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let stored = store.create(&checkpoint).expect("checkpoint");
    let desired = require_idle_desired(2, 1, 7, 'e');
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.idle_results.push_back(Ok(IdleCloseResult::Busy {
        platform_guards: 0,
        endpoint_guards: vec![EndpointGuardCount {
            endpoint_id: id("ep_unknown"),
            active_guards: 1,
        }],
    }));
    port.expected_disk.push_back(DiskMarker::Armed);
    port.expected_disk.push_back(DiskMarker::BusyClosed);

    let result = GateSequencer::new(&store, &mut port)
        .begin_require_idle(&stored, &desired, times(20, 21))
        .expect("invalid evidence is settled conservatively");
    let GateTransitionResult::RequireIdleBusy {
        checkpoint,
        gate_closed,
        port_error,
    } = result
    else {
        panic!("expected Busy")
    };
    assert!(gate_closed);
    assert_eq!(port_error, Some(GatePortError::InvalidBusyEvidence));
    assert_closed(checkpoint.checkpoint());
    assert_eq!(port.calls, vec![PortCall::TryIdle, PortCall::Close]);
}

#[test]
fn endpoint_change_closes_only_a_then_installs_a_at_a_higher_epoch() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let source_checkpoint = running_checkpoint(&source_desired, 10);
    let b_before = route(&source_checkpoint, "ep_b").clone();
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&source_checkpoint).expect("source checkpoint");
    let desired = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });

    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close A");
    let GateTransitionResult::EndpointClosed {
        checkpoint: closed,
        port_error: None,
    } = closed
    else {
        panic!("expected endpoint close")
    };
    assert_eq!(
        route(closed.checkpoint(), "ep_a").gate,
        RouteGateState::Closed
    );
    assert_eq!(route(closed.checkpoint(), "ep_b"), &b_before);
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);

    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(&closed, &desired, &id("ep_a"), unix_ms(22))
        .expect("prepare changed A");
    let GateTransitionResult::EndpointPrepared {
        checkpoint: prepared,
    } = prepared
    else {
        panic!("expected prepared endpoint")
    };
    let prepared_a = route(prepared.checkpoint(), "ep_a");
    assert_eq!(prepared_a.binding.route_epoch, epoch(2));
    assert_eq!(prepared_a.binding.target_port, 9090);
    assert_eq!(prepared_a.gate, RouteGateState::Closed);
    assert!(matches!(
        prepared.checkpoint().step,
        ReconcileStep::InstallGate {
            ref endpoint_id,
            route_epoch,
        } if endpoint_id == &id("ep_a") && route_epoch == epoch(2)
    ));
    // The old Closed binding remains in the cell until InstallGate performs
    // its exact compare-and-replace.
    assert_eq!(
        snapshot_route(&port.current, "ep_a").binding.route_epoch,
        epoch(1)
    );
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);

    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    let installed = GateSequencer::new(&store, &mut port)
        .install_gate(&prepared, &desired, &id("ep_a"), times(23, 24))
        .expect("install changed A");
    let installed = installed.checkpoint().checkpoint();
    assert_eq!(route(installed, "ep_a").binding.route_epoch, epoch(2));
    assert_eq!(route(installed, "ep_a").gate, RouteGateState::Active);
    assert_eq!(route(installed, "ep_b"), &b_before);
    assert!(matches!(
        installed.step,
        ReconcileStep::Stable {
            state: StableState::Running
        }
    ));
    assert_eq!(
        port.calls,
        vec![PortCall::CloseGate(id("ep_a")), PortCall::Install]
    );
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);
}

#[test]
fn endpoint_remove_closes_drains_and_compare_removes_only_a() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let source_checkpoint = running_checkpoint(&source_desired, 10);
    let b_before = route(&source_checkpoint, "ep_b").clone();
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&source_checkpoint).expect("source checkpoint");
    let desired =
        running_desired_with_endpoints(2, vec![endpoint("ep_b", "b.example.test", 7, 8081)]);
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&source_checkpoint).expect("snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close removed A");
    let closed = closed.checkpoint();
    port.expected_disk.push_back(DiskMarker::EndpointRemoving {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let removed = GateSequencer::new(&store, &mut port)
        .remove_closed_gate(closed, &desired, &id("ep_a"), unix_ms(22))
        .expect("remove A");
    let GateTransitionResult::EndpointRemoved {
        checkpoint: removed,
        port_error: None,
    } = removed
    else {
        panic!("expected endpoint removal")
    };
    assert!(removed
        .checkpoint()
        .route_gates
        .iter()
        .all(|route| route.binding.endpoint_id != id("ep_a")));
    assert_eq!(route(removed.checkpoint(), "ep_b"), &b_before);
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);
    assert!(matches!(
        removed.checkpoint().step,
        ReconcileStep::Stable {
            state: StableState::Running
        }
    ));
    assert_eq!(
        port.calls,
        vec![
            PortCall::CloseGate(id("ep_a")),
            PortCall::RemoveGate(id("ep_a"))
        ]
    );
}

#[test]
fn new_endpoint_installs_in_id_order_without_rebinding_existing_b() {
    let root = TempDir::new().expect("tempdir");
    let source_desired =
        running_desired_with_endpoints(1, vec![endpoint("ep_b", "b.example.test", 7, 8081)]);
    let desired = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let b_before = route(&checkpoint, "ep_b").clone();
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let installed = GateSequencer::new(&store, &mut port)
        .install_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("install new A");
    assert_eq!(
        route(installed.checkpoint().checkpoint(), "ep_a").gate,
        RouteGateState::Active
    );
    assert_eq!(
        route(installed.checkpoint().checkpoint(), "ep_b"),
        &b_before
    );
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);
    assert_eq!(port.calls, vec![PortCall::Install]);
}

#[test]
fn ambiguous_endpoint_close_is_confirmed_but_pre_effect_error_is_retried() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let desired = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.endpoint_results
        .push_back(EndpointPortResult::ErrorAfter(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let confirmed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("ambiguous close has exact postcondition");
    assert!(matches!(
        confirmed,
        GateTransitionResult::EndpointClosed {
            port_error: Some(GatePortError::Unavailable),
            ..
        }
    ));
    assert_eq!(
        snapshot_route(&port.current, "ep_a").gate,
        RouteGateState::Closed
    );
    assert_eq!(
        snapshot_route(&port.current, "ep_b").gate,
        RouteGateState::Active
    );

    let retry_root = TempDir::new().expect("retry tempdir");
    let retry_store =
        FileCheckpointStore::open(retry_root.path(), &source_desired.cat_id).expect("retry store");
    let retry_source = retry_store
        .create(&checkpoint)
        .expect("retry source checkpoint");
    let mut retry_port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        retry_store.path(),
    );
    retry_port
        .endpoint_results
        .push_back(EndpointPortResult::ErrorBefore(GatePortError::Unavailable));
    retry_port
        .expected_disk
        .push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
    let error = GateSequencer::new(&retry_store, &mut retry_port)
        .close_gate(&retry_source, &desired, &id("ep_a"), times(20, 21))
        .expect_err("pre-effect error remains retryable");
    assert!(matches!(
        error,
        GateReconcileError::Port(GatePortError::Unavailable)
    ));
    let staged = retry_store
        .load()
        .expect("load staged")
        .expect("staged checkpoint");
    assert_eq!(
        route(staged.checkpoint(), "ep_a").gate,
        RouteGateState::Active
    );
    retry_port
        .expected_disk
        .push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
    GateSequencer::new(&retry_store, &mut retry_port)
        .close_gate(&staged, &desired, &id("ep_a"), times(22, 23))
        .expect("retry exact token");
    assert_eq!(
        snapshot_route(&retry_port.current, "ep_b").gate,
        RouteGateState::Active
    );
}

#[test]
fn same_session_close_retry_requires_the_exact_predecessor_edge() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let desired = running_desired_with_endpoints(
        3,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot"),
        store.path(),
    );
    let exact_predecessor = port.current.clone();
    port.endpoint_results
        .push_back(EndpointPortResult::ErrorBefore(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(3),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
            .expect_err("leave durable close token before effect"),
        GateReconcileError::Port(GatePortError::Unavailable)
    ));
    let close_step = store
        .load()
        .expect("load close token")
        .expect("close token");
    assert_eq!(port.calls, vec![PortCall::CloseGate(id("ep_a"))]);

    // Keep one checkpoint-first oracle queued for the eventual exact retry.
    // A mismatched tuple must not consume it or call the port.
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(3),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let mut wrong_placement = exact_predecessor.placement().clone();
    wrong_placement.placement_epoch = epoch(99);
    let mut wrong_routes = exact_predecessor.endpoints().to_vec();
    wrong_routes[1].gate = RouteGateState::Closed;
    let mismatches = [
        (
            "lower revision",
            AdmissionSnapshot::new(
                revision(1),
                exact_predecessor.spec_digest().clone(),
                exact_predecessor.placement().clone(),
                exact_predecessor.runtime_incarnation().cloned(),
                exact_predecessor.lifecycle_admission(),
                exact_predecessor.endpoints().to_vec(),
            ),
        ),
        (
            "wrong digest",
            AdmissionSnapshot::new(
                exact_predecessor.applied_desired_revision(),
                digest('a'),
                exact_predecessor.placement().clone(),
                exact_predecessor.runtime_incarnation().cloned(),
                exact_predecessor.lifecycle_admission(),
                exact_predecessor.endpoints().to_vec(),
            ),
        ),
        (
            "wrong placement",
            AdmissionSnapshot::new(
                exact_predecessor.applied_desired_revision(),
                exact_predecessor.spec_digest().clone(),
                wrong_placement,
                exact_predecessor.runtime_incarnation().cloned(),
                exact_predecessor.lifecycle_admission(),
                exact_predecessor.endpoints().to_vec(),
            ),
        ),
        (
            "wrong runtime incarnation",
            AdmissionSnapshot::new(
                exact_predecessor.applied_desired_revision(),
                exact_predecessor.spec_digest().clone(),
                exact_predecessor.placement().clone(),
                Some(random('6')),
                exact_predecessor.lifecycle_admission(),
                exact_predecessor.endpoints().to_vec(),
            ),
        ),
        (
            "wrong lifecycle admission",
            AdmissionSnapshot::new(
                exact_predecessor.applied_desired_revision(),
                exact_predecessor.spec_digest().clone(),
                exact_predecessor.placement().clone(),
                exact_predecessor.runtime_incarnation().cloned(),
                LifecycleAdmission::Closed,
                exact_predecessor.endpoints().to_vec(),
            ),
        ),
        (
            "wrong routes",
            AdmissionSnapshot::new(
                exact_predecessor.applied_desired_revision(),
                exact_predecessor.spec_digest().clone(),
                exact_predecessor.placement().clone(),
                exact_predecessor.runtime_incarnation().cloned(),
                exact_predecessor.lifecycle_admission(),
                wrong_routes,
            ),
        ),
    ];
    for (reason, mismatch) in mismatches {
        port.current = mismatch;
        assert!(
            matches!(
                GateSequencer::new(&store, &mut port)
                    .close_gate(&close_step, &desired, &id("ep_a"), times(22, 23))
                    .expect_err(reason),
                GateReconcileError::EndpointCellMismatch
            ),
            "unexpected result for {reason}"
        );
        assert_eq!(port.calls, vec![PortCall::CloseGate(id("ep_a"))]);
    }

    port.current = exact_predecessor;
    GateSequencer::new(&store, &mut port)
        .close_gate(&close_step, &desired, &id("ep_a"), times(26, 27))
        .expect("exact same-session predecessor retries close");
    assert_eq!(
        port.calls,
        vec![
            PortCall::CloseGate(id("ep_a")),
            PortCall::CloseGate(id("ep_a")),
        ]
    );
}

#[test]
fn restart_cannot_replay_close_from_the_predecessor_without_its_edge() {
    let root = TempDir::new().expect("tempdir");
    let (source_desired, desired) = endpoint_change_desireds();
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let exact_predecessor =
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot");
    let mut port = FakePort::new(exact_predecessor.clone(), store.path());
    port.endpoint_results
        .push_back(EndpointPortResult::ErrorBefore(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect_err("leave durable close token");
    drop(port);
    drop(store);

    let restarted_store = FileCheckpointStore::open(root.path(), &source_desired.cat_id)
        .expect("restart checkpoint store");
    let close_step = restarted_store
        .load()
        .expect("load after restart")
        .expect("close token after restart");
    let mut restarted_port = FakePort::new(exact_predecessor.clone(), restarted_store.path());
    // This marker makes the old heuristic observable without weakening the
    // fixed zero-side-effect assertion.
    restarted_port
        .expected_disk
        .push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
    assert!(matches!(
        GateSequencer::new(&restarted_store, &mut restarted_port)
            .close_gate(&close_step, &desired, &id("ep_a"), times(22, 23))
            .expect_err("disk token cannot reconstruct the process-local edge"),
        GateReconcileError::EndpointCellMismatch
    ));
    assert_eq!(restarted_port.current, exact_predecessor);
    assert!(restarted_port.calls.is_empty());
}

#[test]
fn stale_endpoint_tokens_and_restart_state_have_zero_endpoint_side_effects() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let desired = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.endpoint_results
        .push_back(EndpointPortResult::ErrorBefore(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect_err("leave durable token before effect");
    let staged = store.load().expect("load").expect("staged");
    let calls_before = port.calls.clone();

    let newer = running_desired_with_endpoints(
        3,
        vec![
            endpoint("ep_a", "a.example.test", 3, 9091),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&staged, &newer, &id("ep_a"), times(22, 23))
            .expect_err("stale revision"),
        GateReconcileError::WrongCloseGateCheckpoint(_)
    ));
    assert_eq!(port.calls, calls_before);

    let mut wrong_placement = desired.clone();
    wrong_placement.placement.placement_epoch = epoch(4);
    refresh_spec_digest(&mut wrong_placement);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&staged, &wrong_placement, &id("ep_a"), times(24, 25))
            .expect_err("wrong placement"),
        GateReconcileError::WrongCloseGateCheckpoint(_)
    ));
    assert_eq!(port.calls, calls_before);

    let mut wrong_incarnation = staged.checkpoint().clone();
    wrong_incarnation.runtime_incarnation = Some(random('6'));
    for route in &mut wrong_incarnation.route_gates {
        route.binding.runtime_incarnation = random('6');
    }
    port.current =
        AdmissionSnapshot::from_checkpoint(&wrong_incarnation).expect("wrong incarnation cell");
    let wrong_incarnation_cell = port.current.clone();
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&staged, &desired, &id("ep_a"), times(25, 26))
            .expect_err("stale runtime incarnation"),
        GateReconcileError::EndpointCellMismatch
    ));
    assert_eq!(port.current, wrong_incarnation_cell);
    assert_eq!(port.calls, calls_before);

    let mut newer_checkpoint = running_checkpoint(&newer, 30);
    newer_checkpoint.runtime_incarnation = staged.checkpoint().runtime_incarnation.clone();
    for route in &mut newer_checkpoint.route_gates {
        route.binding.runtime_incarnation = staged
            .checkpoint()
            .runtime_incarnation
            .clone()
            .expect("incarnation");
    }
    port.current = AdmissionSnapshot::from_checkpoint(&newer_checkpoint).expect("newer cell");
    let newer_cell = port.current.clone();
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&staged, &desired, &id("ep_a"), times(27, 28))
            .expect_err("stale token cannot close newer binding"),
        GateReconcileError::EndpointCellMismatch
    ));
    assert_eq!(port.current, newer_cell);
    assert_eq!(port.calls, calls_before);

    // A process restart starts every in-memory gate Closed. Endpoint-only
    // recovery must not pretend B remained Active or resurrect old epochs.
    port.current = AdmissionSnapshot::from_checkpoint(staged.checkpoint())
        .expect("staged snapshot")
        .fail_closed();
    let restart_state = port.current.clone();
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&staged, &desired, &id("ep_a"), times(29, 30))
            .expect_err("restart requires fresh global epochs"),
        GateReconcileError::EndpointCellMismatch
    ));
    assert_eq!(port.current, restart_state);
    assert_eq!(port.calls, calls_before);
}

#[test]
fn endpoint_deltas_are_processed_one_at_a_time_in_id_order() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 1, 8081),
        ],
    );
    let desired = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 2, 9091),
        ],
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_b"), times(20, 21))
            .expect_err("B cannot overtake A"),
        GateReconcileError::EndpointOutOfOrder(_)
    ));
    assert!(port.calls.is_empty());

    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let a_closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(22, 23))
        .expect("close A");
    let a_prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(a_closed.checkpoint(), &desired, &id("ep_a"), unix_ms(24))
        .expect("prepare A");
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    let a_installed = GateSequencer::new(&store, &mut port)
        .install_gate(
            a_prepared.checkpoint(),
            &desired,
            &id("ep_a"),
            times(25, 26),
        )
        .expect("install A");
    assert!(matches!(
        a_installed.checkpoint().checkpoint().step,
        ReconcileStep::CloseGate {
            ref endpoint_id,
            route_epoch,
        } if endpoint_id == &id("ep_b") && route_epoch == epoch(1)
    ));
    assert_eq!(
        route(a_installed.checkpoint().checkpoint(), "ep_a").gate,
        RouteGateState::Active
    );
    assert_eq!(
        route(a_installed.checkpoint().checkpoint(), "ep_b").gate,
        RouteGateState::Active
    );

    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_b"),
        route_epoch: epoch(1),
    });
    GateSequencer::new(&store, &mut port)
        .close_gate(
            a_installed.checkpoint(),
            &desired,
            &id("ep_b"),
            times(27, 28),
        )
        .expect("close B after A is complete");
}

#[test]
fn changed_binding_must_advance_route_epoch_before_any_effect() {
    let root = TempDir::new().expect("tempdir");
    let source_desired =
        running_desired_with_endpoints(1, vec![endpoint("ep_a", "a.example.test", 1, 8080)]);
    let desired =
        running_desired_with_endpoints(2, vec![endpoint("ep_a", "a.example.test", 1, 9090)]);
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
            .expect_err("same epoch changed binding"),
        GateReconcileError::RouteEpochNotAdvanced(_)
    ));
    assert!(port.calls.is_empty());
    assert_eq!(
        store
            .load()
            .expect("load")
            .expect("checkpoint")
            .checkpoint(),
        &checkpoint
    );
}

#[test]
fn endpoint_close_token_publish_crashes_never_reach_the_cell() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let (source_desired, desired) = endpoint_change_desireds();
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
            store.path(),
        );
        store.inject_crash_once(stage);
        assert!(matches!(
            GateSequencer::new(&store, &mut port)
                .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
                .expect_err("token publication crash"),
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        assert!(port.calls.is_empty());
        assert_eq!(
            snapshot_route(&port.current, "ep_a").gate,
            RouteGateState::Active
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );

        let visible = store.load().expect("load visible").expect("checkpoint");
        match stage {
            WriteStage::Write | WriteStage::TempWritten | WriteStage::FileSynced => {
                assert_eq!(visible.checkpoint().desired_revision, revision(1));
            }
            WriteStage::Renamed | WriteStage::DirectorySynced => {
                assert_eq!(visible.checkpoint().desired_revision, revision(2));
                assert!(matches!(
                    visible.checkpoint().step,
                    ReconcileStep::CloseGate { .. }
                ));
            }
        }
        port.expected_disk.push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        GateSequencer::new(&store, &mut port)
            .close_gate(&visible, &desired, &id("ep_a"), times(22, 23))
            .expect("retry visible token state");
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );
    }
}

#[test]
fn endpoint_close_post_effect_publish_crashes_are_confirmed_without_touching_b() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let (source_desired, desired) = endpoint_change_desireds();
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        store.inject_crash_on_nth(stage, 2);
        assert!(matches!(
            GateSequencer::new(&store, &mut port)
                .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
                .expect_err("closed publication crash"),
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        assert_eq!(port.calls, vec![PortCall::CloseGate(id("ep_a"))]);
        assert_eq!(
            snapshot_route(&port.current, "ep_a").gate,
            RouteGateState::Closed
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );

        let visible = store.load().expect("load visible").expect("checkpoint");
        GateSequencer::new(&store, &mut port)
            .close_gate(&visible, &desired, &id("ep_a"), times(22, 23))
            .expect("confirm or republish Closed");
        assert_eq!(
            route(
                store
                    .load()
                    .expect("load final")
                    .expect("checkpoint")
                    .checkpoint(),
                "ep_a"
            )
            .gate,
            RouteGateState::Closed
        );
        assert_eq!(port.calls, vec![PortCall::CloseGate(id("ep_a"))]);
    }
}

#[test]
fn changed_entry_prepare_crashes_leave_the_old_epoch_closed() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let (source_desired, desired) = endpoint_change_desireds();
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        let closed = GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
            .expect("close A");
        let calls_before = port.calls.clone();
        store.inject_crash_once(stage);
        assert!(matches!(
            GateSequencer::new(&store, &mut port)
                .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22),)
                .expect_err("prepare publication crash"),
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        assert_eq!(port.calls, calls_before);
        assert_eq!(
            snapshot_route(&port.current, "ep_a").binding.route_epoch,
            epoch(1)
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_a").gate,
            RouteGateState::Closed
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );

        let visible = store.load().expect("load visible").expect("checkpoint");
        let prepared = GateSequencer::new(&store, &mut port)
            .prepare_changed_gate(&visible, &desired, &id("ep_a"), unix_ms(23))
            .expect("retry prepare");
        assert_eq!(
            route(prepared.checkpoint().checkpoint(), "ep_a")
                .binding
                .route_epoch,
            epoch(2)
        );
        assert_eq!(
            route(prepared.checkpoint().checkpoint(), "ep_a").gate,
            RouteGateState::Closed
        );
    }
}

#[test]
fn removed_entry_publish_crashes_adopt_only_exact_cell_absence() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let (source_desired, desired) = endpoint_remove_desireds();
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        let closed = GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
            .expect("close A");
        port.expected_disk.push_back(DiskMarker::EndpointRemoving {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        store.inject_crash_once(stage);
        assert!(matches!(
            GateSequencer::new(&store, &mut port)
                .remove_closed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22),)
                .expect_err("remove publication crash"),
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        assert!(port
            .current
            .endpoints()
            .iter()
            .all(|route| route.binding.endpoint_id != id("ep_a")));
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );
        assert_eq!(
            port.calls
                .iter()
                .filter(|call| matches!(call, PortCall::RemoveGate(_)))
                .count(),
            1
        );

        let visible = store.load().expect("load visible").expect("checkpoint");
        if visible
            .checkpoint()
            .route_gates
            .iter()
            .any(|route| route.binding.endpoint_id == id("ep_a"))
        {
            GateSequencer::new(&store, &mut port)
                .remove_closed_gate(&visible, &desired, &id("ep_a"), unix_ms(23))
                .expect("retry exact absence");
        }
        assert_eq!(
            port.calls
                .iter()
                .filter(|call| matches!(call, PortCall::RemoveGate(_)))
                .count(),
            1
        );
    }
}

#[test]
fn restart_cannot_reopen_a_durable_install_step_from_an_all_closed_cell() {
    let root = TempDir::new().expect("tempdir");
    let source_desired =
        running_desired_with_endpoints(1, vec![endpoint("ep_a", "a.example.test", 1, 8080)]);
    let desired =
        running_desired_with_endpoints(2, vec![endpoint("ep_a", "a.example.test", 2, 9090)]);
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close old A");
    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
        .expect("prepare new A");
    let closed_restart_cell =
        AdmissionSnapshot::from_checkpoint(prepared.checkpoint().checkpoint())
            .expect("prepared snapshot")
            .fail_closed();
    let old_predecessor_restart_cell = port.current.clone().fail_closed();

    drop(port);
    drop(store);

    let restarted_store = FileCheckpointStore::open(root.path(), &source_desired.cat_id)
        .expect("restart checkpoint store");
    let install_step = restarted_store
        .load()
        .expect("load after restart")
        .expect("install checkpoint");
    let mut restarted_port = FakePort::new(closed_restart_cell.clone(), restarted_store.path());
    restarted_port
        .expected_disk
        .push_back(DiskMarker::Installed {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(2),
        });
    assert!(matches!(
        GateSequencer::new(&restarted_store, &mut restarted_port)
            .install_gate(&install_step, &desired, &id("ep_a"), times(23, 24))
            .expect_err("disk state alone must not authorize InstallGate after restart"),
        GateReconcileError::FreshRouteEpochRequired(endpoint_id)
            if endpoint_id == id("ep_a")
    ));
    assert_eq!(restarted_port.current, closed_restart_cell);
    assert!(restarted_port.calls.is_empty());
    let still_prepared = restarted_store
        .load()
        .expect("reload after refused restart install")
        .expect("prepared checkpoint");
    assert_eq!(
        route(still_prepared.checkpoint(), "ep_a").gate,
        RouteGateState::Closed,
        "lost continuity must be rejected before the durable gate is marked Active"
    );

    let mut old_predecessor_port =
        FakePort::new(old_predecessor_restart_cell.clone(), restarted_store.path());
    let old_predecessor_error = GateSequencer::new(&restarted_store, &mut old_predecessor_port)
        .install_gate(&install_step, &desired, &id("ep_a"), times(25, 26))
        .expect_err("the old Closed predecessor also lost continuity");
    assert!(
        matches!(
            old_predecessor_error,
            GateReconcileError::FreshRouteEpochRequired(ref endpoint_id)
                if endpoint_id == &id("ep_a")
        ),
        "unexpected old-predecessor error: {old_predecessor_error:?}"
    );
    assert_eq!(old_predecessor_port.current, old_predecessor_restart_cell);
    assert!(old_predecessor_port.calls.is_empty());
}

#[test]
fn restart_confirms_an_exact_active_install_postcondition_without_reinstalling() {
    let root = TempDir::new().expect("tempdir");
    let source_desired =
        running_desired_with_endpoints(1, vec![endpoint("ep_a", "a.example.test", 1, 8080)]);
    let desired =
        running_desired_with_endpoints(2, vec![endpoint("ep_a", "a.example.test", 2, 9090)]);
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close old A");
    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
        .expect("prepare new A");

    store.inject_crash_once(WriteStage::Renamed);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24))
            .expect_err("leave the durable Active InstallGate postcondition"),
        GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
    ));
    assert_eq!(
        port.calls,
        vec![PortCall::CloseGate(id("ep_a"))],
        "the injected pre-effect crash must not reach InstallGate"
    );
    let active_install = store
        .load()
        .expect("load active token")
        .expect("checkpoint");
    let active_cell = AdmissionSnapshot::from_checkpoint(active_install.checkpoint())
        .expect("active install snapshot");
    assert_eq!(
        snapshot_route(&active_cell, "ep_a").gate,
        RouteGateState::Active
    );

    drop(port);
    drop(store);

    let restarted_store = FileCheckpointStore::open(root.path(), &source_desired.cat_id)
        .expect("restart checkpoint store");
    let active_install = restarted_store
        .load()
        .expect("load after restart")
        .expect("active install checkpoint");
    let mut restarted_port = FakePort::new(active_cell, restarted_store.path());
    let installed = GateSequencer::new(&restarted_store, &mut restarted_port)
        .install_gate(&active_install, &desired, &id("ep_a"), times(25, 26))
        .expect("confirm exact Active postcondition");
    assert!(matches!(
        installed.checkpoint().checkpoint().step,
        ReconcileStep::Stable {
            state: StableState::Running
        }
    ));
    assert!(restarted_port.calls.is_empty());
}

#[test]
fn same_session_install_retry_requires_the_exact_predecessor() {
    let root = TempDir::new().expect("tempdir");
    let source_desired =
        running_desired_with_endpoints(1, vec![endpoint("ep_a", "a.example.test", 1, 8080)]);
    let desired =
        running_desired_with_endpoints(2, vec![endpoint("ep_a", "a.example.test", 2, 9090)]);
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close old A");
    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
        .expect("prepare new A");
    let exact_predecessor = port.current.clone();
    port.endpoint_results
        .push_back(EndpointPortResult::ErrorBefore(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24))
            .expect_err("pre-effect error remains retryable in this session"),
        GateReconcileError::Port(GatePortError::Unavailable)
    ));
    let install_step = store
        .load()
        .expect("load install token")
        .expect("checkpoint");
    assert_eq!(
        port.calls
            .iter()
            .filter(|call| matches!(call, PortCall::Install))
            .count(),
        1
    );

    port.current = AdmissionSnapshot::new(
        revision(1),
        digest('a'),
        exact_predecessor.placement().clone(),
        exact_predecessor.runtime_incarnation().cloned(),
        exact_predecessor.lifecycle_admission(),
        exact_predecessor.endpoints().to_vec(),
    );
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .install_gate(&install_step, &desired, &id("ep_a"), times(25, 26))
            .expect_err("a lower revision with an arbitrary digest is not the predecessor"),
        GateReconcileError::EndpointCellMismatch
    ));
    assert_eq!(
        port.calls
            .iter()
            .filter(|call| matches!(call, PortCall::Install))
            .count(),
        1
    );

    port.current = exact_predecessor;
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    GateSequencer::new(&store, &mut port)
        .install_gate(&install_step, &desired, &id("ep_a"), times(27, 28))
        .expect("exact same-session predecessor can retry");
    assert_eq!(
        port.calls
            .iter()
            .filter(|call| matches!(call, PortCall::Install))
            .count(),
        2
    );
}

#[test]
fn ambiguous_install_response_is_confirmed_but_restart_cannot_replay_it_closed() {
    let root = TempDir::new().expect("tempdir");
    let source_desired =
        running_desired_with_endpoints(1, vec![endpoint("ep_a", "a.example.test", 1, 8080)]);
    let desired =
        running_desired_with_endpoints(2, vec![endpoint("ep_a", "a.example.test", 2, 9090)]);
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close old A");
    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
        .expect("prepare new A");
    port.endpoint_results
        .push_back(EndpointPortResult::ErrorAfter(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    store.inject_crash_on_nth(WriteStage::TempWritten, 2);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24))
            .expect_err("crash after ambiguous effect confirmation"),
        GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
    ));
    assert_eq!(
        snapshot_route(&port.current, "ep_a").gate,
        RouteGateState::Active
    );
    let active_install = store
        .load()
        .expect("load active token")
        .expect("checkpoint");
    let restarted_closed = AdmissionSnapshot::from_checkpoint(active_install.checkpoint())
        .expect("active snapshot")
        .fail_closed();

    drop(port);
    drop(store);

    let restarted_store = FileCheckpointStore::open(root.path(), &source_desired.cat_id)
        .expect("restart checkpoint store");
    let active_install = restarted_store
        .load()
        .expect("load after restart")
        .expect("active install checkpoint");
    let mut restarted_port = FakePort::new(restarted_closed.clone(), restarted_store.path());
    assert!(matches!(
        GateSequencer::new(&restarted_store, &mut restarted_port)
            .install_gate(&active_install, &desired, &id("ep_a"), times(25, 26))
            .expect_err("ambiguous old effect cannot be retried from disk after restart"),
        GateReconcileError::FreshRouteEpochRequired(endpoint_id)
            if endpoint_id == id("ep_a")
    ));
    assert_eq!(restarted_port.current, restarted_closed);
    assert!(restarted_port.calls.is_empty());
}

#[test]
fn install_publish_crashes_never_reopen_old_epoch_before_the_active_token_is_durable() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let (source_desired, desired) = endpoint_change_desireds();
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        let closed = GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
            .expect("close A");
        let prepared = GateSequencer::new(&store, &mut port)
            .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
            .expect("prepare A");
        let calls_before = port.calls.clone();
        store.inject_crash_once(stage);
        assert!(matches!(
            GateSequencer::new(&store, &mut port)
                .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24),)
                .expect_err("active token publication crash"),
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        assert_eq!(port.calls, calls_before);
        assert_eq!(
            snapshot_route(&port.current, "ep_a").binding.route_epoch,
            epoch(1)
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_a").gate,
            RouteGateState::Closed
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );

        let visible = store.load().expect("load visible").expect("checkpoint");
        port.expected_disk.push_back(DiskMarker::Installed {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(2),
        });
        GateSequencer::new(&store, &mut port)
            .install_gate(&visible, &desired, &id("ep_a"), times(25, 26))
            .expect("retry install");
        assert_eq!(
            snapshot_route(&port.current, "ep_a").binding.route_epoch,
            epoch(2)
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );
    }
}

#[test]
fn install_post_effect_publish_crashes_confirm_active_without_a_second_effect() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let (source_desired, desired) = endpoint_change_desireds();
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        let closed = GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
            .expect("close A");
        let prepared = GateSequencer::new(&store, &mut port)
            .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
            .expect("prepare A");
        port.expected_disk.push_back(DiskMarker::Installed {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(2),
        });
        store.inject_crash_on_nth(stage, 2);
        assert!(matches!(
            GateSequencer::new(&store, &mut port)
                .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24),)
                .expect_err("post-install publication crash"),
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));
        let install_calls = port
            .calls
            .iter()
            .filter(|call| matches!(call, PortCall::Install))
            .count();
        assert_eq!(install_calls, 1);
        assert_eq!(
            snapshot_route(&port.current, "ep_a").binding.route_epoch,
            epoch(2)
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_a").gate,
            RouteGateState::Active
        );
        assert_eq!(
            snapshot_route(&port.current, "ep_b").gate,
            RouteGateState::Active
        );

        let visible = store.load().expect("load visible").expect("checkpoint");
        if matches!(visible.checkpoint().step, ReconcileStep::InstallGate { .. }) {
            GateSequencer::new(&store, &mut port)
                .install_gate(&visible, &desired, &id("ep_a"), times(25, 26))
                .expect("confirm Active and finish checkpoint");
        }
        assert_eq!(
            port.calls
                .iter()
                .filter(|call| matches!(call, PortCall::Install))
                .count(),
            1
        );
    }
}

#[test]
fn late_install_completion_error_releases_the_edge_for_a_higher_epoch() {
    let root = TempDir::new().expect("tempdir");
    let (source_desired, desired) = endpoint_change_desireds();
    let checkpoint = running_checkpoint(&source_desired, 10);
    let b_before = route(&checkpoint, "ep_b").clone();
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close A at epoch 1");
    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
        .expect("prepare A at epoch 2");
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    // InstallGate publishes the Active token first and the final Stable
    // checkpoint second. The second rename is already visible when this late
    // injected error is returned.
    store.inject_crash_on_nth(WriteStage::DirectorySynced, 2);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24))
            .expect_err("late completion acknowledgement is lost"),
        GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
    ));
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);
    let stable_epoch_two = store
        .load()
        .expect("load visible final checkpoint")
        .expect("visible final checkpoint");
    assert!(matches!(
        stable_epoch_two.checkpoint().step,
        ReconcileStep::Stable {
            state: StableState::Running
        }
    ));
    assert_eq!(route(stable_epoch_two.checkpoint(), "ep_b"), &b_before);

    let desired_epoch_three = running_desired_with_endpoints(
        3,
        vec![
            endpoint("ep_a", "a.example.test", 3, 10000),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(3),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(
            &stable_epoch_two,
            &desired_epoch_three,
            &id("ep_a"),
            times(25, 26),
        )
        .expect("close A at epoch 2");
    assert_eq!(route(closed.checkpoint().checkpoint(), "ep_b"), &b_before);
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);
    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(
            closed.checkpoint(),
            &desired_epoch_three,
            &id("ep_a"),
            unix_ms(27),
        )
        .expect("prepare A at epoch 3 after late prior error");
    assert_eq!(route(prepared.checkpoint().checkpoint(), "ep_b"), &b_before);
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(3),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(3),
    });
    let installed = GateSequencer::new(&store, &mut port)
        .install_gate(
            prepared.checkpoint(),
            &desired_epoch_three,
            &id("ep_a"),
            times(28, 29),
        )
        .expect("install A at epoch 3");
    assert_eq!(
        route(installed.checkpoint().checkpoint(), "ep_b"),
        &b_before
    );
    assert_eq!(snapshot_route(&port.current, "ep_b"), &b_before);
}

#[test]
fn failed_final_publish_does_not_leave_an_unpublished_next_edge() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 1, 8081),
        ],
    );
    let desired = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 2, 9091),
        ],
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot"),
        store.path(),
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(1),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
        .expect("close A");
    let prepared = GateSequencer::new(&store, &mut port)
        .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
        .expect("prepare A");
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    // The final checkpoint would publish B's CloseGate token. Fail before
    // that rename after A's exact effect has already completed.
    store.inject_crash_on_nth(WriteStage::FileSynced, 2);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24))
            .expect_err("final checkpoint remains the active A token"),
        GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
    ));
    let active_a = store
        .load()
        .expect("load active A token")
        .expect("active A token");
    assert!(matches!(
        active_a.checkpoint().step,
        ReconcileStep::InstallGate {
            ref endpoint_id,
            route_epoch,
        } if endpoint_id == &id("ep_a") && route_epoch == epoch(2)
    ));

    // A fresher Desired may legitimately supersede the unpublished B edge.
    // It must not collide with process-local state from the failed replace.
    let fresher = running_desired_with_endpoints(
        3,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 3, 10001),
        ],
    );
    port.expected_disk.push_back(DiskMarker::EndpointClosing {
        revision: revision(3),
        endpoint_id: id("ep_b"),
        route_epoch: epoch(1),
    });
    GateSequencer::new(&store, &mut port)
        .close_gate(&active_a, &fresher, &id("ep_b"), times(25, 26))
        .expect("fresher B edge supersedes the unpublished one");
    assert_eq!(
        snapshot_route(&port.current, "ep_a").gate,
        RouteGateState::Active
    );
    assert_eq!(
        snapshot_route(&port.current, "ep_a").binding.route_epoch,
        epoch(2)
    );
    assert_eq!(
        snapshot_route(&port.current, "ep_b").gate,
        RouteGateState::Closed
    );
}

#[test]
fn invalid_next_endpoint_is_rejected_before_install_effect_or_edge_leak() {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 7, 8081),
        ],
    );
    let mut checkpoint = running_checkpoint(&source_desired, 10);
    checkpoint.lifecycle_admission = LifecycleAdmission::Closed;
    checkpoint.stable_state = None;
    checkpoint.step = ReconcileStep::CloseAdmission {
        require_idle_attempt_id: None,
    };
    for route in &mut checkpoint.route_gates {
        route.gate = RouteGateState::Closed;
    }
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let mut port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot"),
        store.path(),
    );

    let stale_b = running_desired_with_endpoints(
        2,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 6, 9091),
        ],
    );
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(2),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .install_gate(&source, &stale_b, &id("ep_a"), times(20, 21))
            .expect_err("B's regressed epoch must invalidate the plan before A changes"),
        GateReconcileError::RouteEpochNotAdvanced(endpoint_id)
            if endpoint_id == id("ep_b")
    ));
    assert!(port.calls.is_empty(), "invalid completion plan reached A");
    port.expected_disk.clear();
    assert_eq!(
        store
            .load()
            .expect("load after rejected plan")
            .expect("source remains")
            .checkpoint(),
        &checkpoint
    );

    let corrected = running_desired_with_endpoints(
        3,
        vec![
            endpoint("ep_a", "a.example.test", 3, 10000),
            endpoint("ep_b", "b.example.test", 8, 10001),
        ],
    );
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(3),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(3),
    });
    let installed = GateSequencer::new(&store, &mut port)
        .install_gate(&source, &corrected, &id("ep_a"), times(22, 23))
        .expect("corrected higher A epoch is not blocked by the rejected plan");
    assert_eq!(
        route(installed.checkpoint().checkpoint(), "ep_a").gate,
        RouteGateState::Active
    );
    assert_eq!(
        route(installed.checkpoint().checkpoint(), "ep_a")
            .binding
            .route_epoch,
        epoch(3)
    );
}

#[test]
fn ordinary_global_close_revokes_every_pending_endpoint_edge() {
    let (_root, stop, store, source, mut port, pending_a) = pending_edge_global_fixture();
    port.expected_disk.push_back(DiskMarker::Closed {
        revision: revision(2),
    });
    let closed = GateSequencer::new(&store, &mut port)
        .close_all(&source, &stop, times(20, 21))
        .expect("ordinary global close");
    assert_eq!(
        store
            .endpoint_effect_edge_status(&pending_a)
            .expect("edge status"),
        EndpointEffectEdgeStatus::Missing
    );
    install_fresh_two_endpoint_epochs(&store, &mut port, closed.checkpoint());
}

#[test]
fn ambiguous_global_close_revokes_every_pending_endpoint_edge() {
    let (_root, stop, store, source, mut port, pending_a) = pending_edge_global_fixture();
    port.global_results
        .push_back(EndpointPortResult::ErrorAfter(GatePortError::Unavailable));
    port.expected_disk.push_back(DiskMarker::Closed {
        revision: revision(2),
    });
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_all(&source, &stop, times(20, 21))
            .expect_err("ambiguous global close remains diagnostic"),
        GateReconcileError::Port(GatePortError::Unavailable)
    ));
    assert_eq!(
        store
            .endpoint_effect_edge_status(&pending_a)
            .expect("edge status"),
        EndpointEffectEdgeStatus::Missing
    );
    let closed = store
        .load()
        .expect("load durable close token")
        .expect("global close token");
    install_fresh_two_endpoint_epochs(&store, &mut port, &closed);
}

#[test]
fn late_global_completion_error_cannot_leave_endpoint_edges() {
    let (_root, stop, store, source, mut port, pending_a) = pending_edge_global_fixture();
    port.expected_disk.push_back(DiskMarker::Closed {
        revision: revision(2),
    });
    store.inject_crash_on_nth(WriteStage::DirectorySynced, 2);
    assert!(matches!(
        GateSequencer::new(&store, &mut port)
            .close_all(&source, &stop, times(20, 21))
            .expect_err("lose the final global-close acknowledgement"),
        GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
    ));
    assert_eq!(
        store
            .endpoint_effect_edge_status(&pending_a)
            .expect("edge status"),
        EndpointEffectEdgeStatus::Missing
    );
    let closed = store
        .load()
        .expect("load durable global close")
        .expect("global close checkpoint");
    install_fresh_two_endpoint_epochs(&store, &mut port, &closed);
}

#[test]
fn require_idle_revokes_edges_only_after_an_actual_or_ambiguous_close() {
    for outcome in ["busy", "closed", "ambiguous", "late_closed"] {
        let root = TempDir::new().expect("tempdir");
        let source_desired = desired(
            1,
            RuntimeTarget::Running,
            7,
            RuntimeTransition::CancelAndDrain,
        );
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let pending = arm_pending_close_edge(&store, &checkpoint, "ep_01");
        let desired = require_idle_desired(2, 1, 7, 'a');
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::Armed);
        match outcome {
            "busy" => port.idle_results.push_back(Ok(IdleCloseResult::Busy {
                platform_guards: 0,
                endpoint_guards: vec![EndpointGuardCount {
                    endpoint_id: id("ep_01"),
                    active_guards: 1,
                }],
            })),
            "closed" | "late_closed" => {
                port.idle_results.push_back(Ok(IdleCloseResult::Closed));
            }
            "ambiguous" => {
                port.idle_results.push_back(Err(GatePortError::Unavailable));
                port.expected_disk.push_back(DiskMarker::BusyClosed);
            }
            _ => unreachable!("closed outcome set"),
        }
        if outcome == "late_closed" {
            store.inject_crash_on_nth(WriteStage::DirectorySynced, 2);
        }

        let result = GateSequencer::new(&store, &mut port).begin_require_idle(
            &source,
            &desired,
            times(20, 21),
        );
        if outcome == "late_closed" {
            assert!(matches!(
                result.expect_err("late closed checkpoint acknowledgement"),
                GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
            ));
        } else {
            result.expect("RequireIdle outcome");
        }
        let expected = if outcome == "busy" {
            EndpointEffectEdgeStatus::Exact
        } else {
            EndpointEffectEdgeStatus::Missing
        };
        assert_eq!(
            store
                .endpoint_effect_edge_status(&pending)
                .expect("edge status"),
            expected,
            "wrong edge result for {outcome}"
        );
    }
}

#[test]
fn final_endpoint_publication_keeps_only_a_confirmed_durable_next_edge() {
    for stage in [
        WriteStage::TempWritten,
        WriteStage::FileSynced,
        WriteStage::Renamed,
        WriteStage::DirectorySynced,
    ] {
        let root = TempDir::new().expect("tempdir");
        let source_desired = running_desired_with_endpoints(
            1,
            vec![
                endpoint("ep_a", "a.example.test", 1, 8080),
                endpoint("ep_b", "b.example.test", 1, 8081),
            ],
        );
        let desired = running_desired_with_endpoints(
            2,
            vec![
                endpoint("ep_a", "a.example.test", 2, 9090),
                endpoint("ep_b", "b.example.test", 2, 9091),
            ],
        );
        let checkpoint = running_checkpoint(&source_desired, 10);
        let store = store(&root, &source_desired.cat_id);
        let source = store.create(&checkpoint).expect("source checkpoint");
        let mut port = FakePort::new(
            AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot"),
            store.path(),
        );
        port.expected_disk.push_back(DiskMarker::EndpointClosing {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(1),
        });
        let closed = GateSequencer::new(&store, &mut port)
            .close_gate(&source, &desired, &id("ep_a"), times(20, 21))
            .expect("close A");
        let prepared = GateSequencer::new(&store, &mut port)
            .prepare_changed_gate(closed.checkpoint(), &desired, &id("ep_a"), unix_ms(22))
            .expect("prepare A");
        let predecessor = port.current.clone();
        port.expected_disk.push_back(DiskMarker::Installed {
            revision: revision(2),
            endpoint_id: id("ep_a"),
            route_epoch: epoch(2),
        });
        store.inject_crash_on_nth(stage, 2);
        assert!(matches!(
            GateSequencer::new(&store, &mut port)
                .install_gate(prepared.checkpoint(), &desired, &id("ep_a"), times(23, 24))
                .expect_err("final publication fault"),
            GateReconcileError::Checkpoint(CheckpointStoreError::InjectedCrash)
        ));

        let active = port.current.clone();
        let current = EndpointEffectEdge::new(predecessor, active.clone(), id("ep_a"));
        assert_eq!(
            store
                .endpoint_effect_edge_status(&current)
                .expect("current edge status"),
            EndpointEffectEdgeStatus::Missing,
            "confirmed A edge was restored after {stage:?}"
        );
        let next = EndpointEffectEdge::new(
            active.clone(),
            snapshot_with_closed_endpoint(&active, "ep_b"),
            id("ep_b"),
        );
        let expected_next = if matches!(stage, WriteStage::Renamed | WriteStage::DirectorySynced) {
            EndpointEffectEdgeStatus::Exact
        } else {
            EndpointEffectEdgeStatus::Missing
        };
        assert_eq!(
            store
                .endpoint_effect_edge_status(&next)
                .expect("next edge status"),
            expected_next,
            "wrong next edge result after {stage:?}"
        );
    }
}

fn endpoint_change_desireds() -> (DesiredRuntimeSpec, DesiredRuntimeSpec) {
    (
        running_desired_with_endpoints(
            1,
            vec![
                endpoint("ep_a", "a.example.test", 1, 8080),
                endpoint("ep_b", "b.example.test", 7, 8081),
            ],
        ),
        running_desired_with_endpoints(
            2,
            vec![
                endpoint("ep_a", "a.example.test", 2, 9090),
                endpoint("ep_b", "b.example.test", 7, 8081),
            ],
        ),
    )
}

fn endpoint_remove_desireds() -> (DesiredRuntimeSpec, DesiredRuntimeSpec) {
    (
        running_desired_with_endpoints(
            1,
            vec![
                endpoint("ep_a", "a.example.test", 1, 8080),
                endpoint("ep_b", "b.example.test", 7, 8081),
            ],
        ),
        running_desired_with_endpoints(2, vec![endpoint("ep_b", "b.example.test", 7, 8081)]),
    )
}

fn route<'a>(checkpoint: &'a RuntimeCheckpoint, endpoint_id: &str) -> &'a CheckpointRouteGate {
    checkpoint
        .route_gates
        .iter()
        .find(|route| route.binding.endpoint_id == id(endpoint_id))
        .expect("checkpoint route")
}

fn snapshot_route<'a>(
    snapshot: &'a AdmissionSnapshot,
    endpoint_id: &str,
) -> &'a CheckpointRouteGate {
    snapshot
        .endpoints()
        .iter()
        .find(|route| route.binding.endpoint_id == id(endpoint_id))
        .expect("snapshot route")
}

fn snapshot_with_closed_endpoint(
    snapshot: &AdmissionSnapshot,
    endpoint_id: &str,
) -> AdmissionSnapshot {
    let mut endpoints = snapshot.endpoints().to_vec();
    endpoints
        .iter_mut()
        .find(|route| route.binding.endpoint_id == id(endpoint_id))
        .expect("snapshot route")
        .gate = RouteGateState::Closed;
    AdmissionSnapshot::new(
        snapshot.applied_desired_revision(),
        snapshot.spec_digest().clone(),
        snapshot.placement().clone(),
        snapshot.runtime_incarnation().cloned(),
        snapshot.lifecycle_admission(),
        endpoints,
    )
}

fn arm_pending_close_edge(
    store: &FileCheckpointStore,
    checkpoint: &RuntimeCheckpoint,
    endpoint_id: &str,
) -> EndpointEffectEdge {
    let predecessor = AdmissionSnapshot::from_checkpoint(checkpoint).expect("edge predecessor");
    let edge = EndpointEffectEdge::new(
        predecessor.clone(),
        snapshot_with_closed_endpoint(&predecessor, endpoint_id),
        id(endpoint_id),
    );
    assert!(
        store
            .arm_endpoint_effect_edge(&edge)
            .expect("arm test endpoint edge"),
        "test edge must be unique"
    );
    edge
}

fn pending_edge_global_fixture() -> (
    TempDir,
    DesiredRuntimeSpec,
    FileCheckpointStore,
    StoredCheckpoint,
    FakePort,
    EndpointEffectEdge,
) {
    let root = TempDir::new().expect("tempdir");
    let source_desired = running_desired_with_endpoints(
        1,
        vec![
            endpoint("ep_a", "a.example.test", 1, 8080),
            endpoint("ep_b", "b.example.test", 1, 8081),
        ],
    );
    let checkpoint = running_checkpoint(&source_desired, 10);
    let store = store(&root, &source_desired.cat_id);
    let source = store.create(&checkpoint).expect("source checkpoint");
    let pending = arm_pending_close_edge(&store, &checkpoint, "ep_a");
    let port = FakePort::new(
        AdmissionSnapshot::from_checkpoint(&checkpoint).expect("source snapshot"),
        store.path(),
    );
    let mut stop = source_desired;
    stop.desired_revision = revision(2);
    stop.target = RuntimeTarget::Suspended;
    stop.transition = RuntimeTransition::CancelAndDrain;
    refresh_spec_digest(&mut stop);
    (root, stop, store, source, port, pending)
}

fn install_fresh_two_endpoint_epochs(
    store: &FileCheckpointStore,
    port: &mut FakePort,
    closed: &StoredCheckpoint,
) {
    let fresh = running_desired_with_endpoints(
        3,
        vec![
            endpoint("ep_a", "a.example.test", 2, 9090),
            endpoint("ep_b", "b.example.test", 2, 9091),
        ],
    );
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(3),
        endpoint_id: id("ep_a"),
        route_epoch: epoch(2),
    });
    let a = GateSequencer::new(store, port)
        .install_gate(closed, &fresh, &id("ep_a"), times(30, 31))
        .expect("install fresh A after global close");
    port.expected_disk.push_back(DiskMarker::Installed {
        revision: revision(3),
        endpoint_id: id("ep_b"),
        route_epoch: epoch(2),
    });
    let complete = GateSequencer::new(store, port)
        .install_gate(a.checkpoint(), &fresh, &id("ep_b"), times(32, 33))
        .expect("install fresh B after global close");
    assert!(complete
        .checkpoint()
        .checkpoint()
        .route_gates
        .iter()
        .all(|route| route.gate == RouteGateState::Active));
}

fn store(root: &TempDir, cat_id: &Id) -> FileCheckpointStore {
    FileCheckpointStore::open(root.path(), cat_id).expect("checkpoint store")
}

fn desired(
    revision_value: u64,
    target: RuntimeTarget,
    route_epoch_value: u64,
    transition: RuntimeTransition,
) -> DesiredRuntimeSpec {
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: id("ws_01"),
        cat_id: id("cat_01"),
        desired_revision: revision(revision_value),
        target,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: id("node_a"),
            placement_epoch: epoch(3),
        },
        runtime: RuntimeConfig {
            vcpus: 2,
            memory_bytes: 2_147_483_648,
            boot_image_digest: digest('0'),
            guest_config_digest: digest('1'),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id("net_01"),
                guest_mac: MacAddress::new("02:ca:0a:f0:00:06").expect("MAC"),
                guest_ipv4: Ipv4Address::new("10.240.0.6").expect("guest IP"),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.240.0.5").expect("gateway IP"),
            },
        },
        volumes: Vec::new(),
        endpoints: vec![EndpointIntent {
            endpoint_id: id("ep_01"),
            hostname: Hostname::new("app.example.test").expect("hostname"),
            route_epoch: epoch(route_epoch_value),
            protocol: HttpProtocol::Http,
            target_port: 8080,
        }],
        transition,
        spec_digest: digest('f'),
    };
    refresh_spec_digest(&mut desired);
    desired
}

fn running_desired_with_endpoints(
    revision_value: u64,
    endpoints: Vec<EndpointIntent>,
) -> DesiredRuntimeSpec {
    let mut desired = desired(
        revision_value,
        RuntimeTarget::Running,
        1,
        RuntimeTransition::CancelAndDrain,
    );
    desired.endpoints = endpoints;
    refresh_spec_digest(&mut desired);
    desired
}

fn endpoint(
    endpoint_id: &str,
    hostname: &str,
    route_epoch_value: u64,
    target_port: u16,
) -> EndpointIntent {
    EndpointIntent {
        endpoint_id: id(endpoint_id),
        hostname: Hostname::new(hostname).expect("hostname"),
        route_epoch: epoch(route_epoch_value),
        protocol: HttpProtocol::Http,
        target_port,
    }
}

fn require_idle_desired(
    revision_value: u64,
    source_revision: u64,
    route_epoch_value: u64,
    attempt: char,
) -> DesiredRuntimeSpec {
    desired(
        revision_value,
        RuntimeTarget::Suspended,
        route_epoch_value,
        RuntimeTransition::RequireIdle {
            attempt_id: random(attempt),
            source_revision: revision(source_revision),
            source_runtime_incarnation: random('5'),
        },
    )
}

fn running_checkpoint(desired: &DesiredRuntimeSpec, updated_at: u64) -> RuntimeCheckpoint {
    let incarnation = random('5');
    RuntimeCheckpoint {
        version: ContractVersion::V1,
        cat_id: desired.cat_id.clone(),
        node_id: desired.placement.node_id.clone(),
        placement_epoch: desired.placement.placement_epoch,
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        runtime_incarnation: Some(incarnation.clone()),
        stable_state: Some(StableState::Running),
        step: ReconcileStep::Stable {
            state: StableState::Running,
        },
        processes: Vec::new(),
        volumes: Vec::new(),
        mounts: Vec::new(),
        networks: Vec::new(),
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission: LifecycleAdmission::Open,
        route_gates: desired
            .endpoints
            .iter()
            .map(|endpoint| CheckpointRouteGate {
                binding: RouteGateBinding {
                    workspace_id: desired.workspace_id.clone(),
                    endpoint_id: endpoint.endpoint_id.clone(),
                    hostname: endpoint.hostname.clone(),
                    cat_id: desired.cat_id.clone(),
                    node_id: desired.placement.node_id.clone(),
                    runtime_incarnation: incarnation.clone(),
                    route_epoch: endpoint.route_epoch,
                    protocol: endpoint.protocol,
                    target_port: endpoint.target_port,
                },
                gate: RouteGateState::Active,
            })
            .collect(),
        require_idle: RequireIdleCheckpoint::NotApplicable,
        updated_at_unix_ms: unix_ms(updated_at),
    }
}

fn refresh_spec_digest(desired: &mut DesiredRuntimeSpec) {
    desired.spec_digest = spec_digest(desired).expect("spec digest");
}

fn assert_closed(checkpoint: &RuntimeCheckpoint) {
    assert_eq!(checkpoint.lifecycle_admission, LifecycleAdmission::Closed);
    assert!(checkpoint
        .route_gates
        .iter()
        .all(|route| route.gate == RouteGateState::Closed));
}

fn id(value: &str) -> Id {
    Id::new(value).expect("ID")
}

fn random(digit: char) -> RandomId128 {
    RandomId128::new(std::iter::repeat_n(digit, 32).collect::<String>()).expect("random ID")
}

fn digest(digit: char) -> Sha256Digest {
    Sha256Digest::new(format!(
        "sha256:{}",
        std::iter::repeat_n(digit, 64).collect::<String>()
    ))
    .expect("digest")
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("revision")
}

fn epoch(value: u64) -> Epoch {
    Epoch::new(value).expect("epoch")
}

fn unix_ms(value: u64) -> UnixMillis {
    UnixMillis::new(value).expect("time")
}

fn times(before: u64, after: u64) -> PersistTimes {
    PersistTimes {
        before_effect: unix_ms(before),
        after_effect: unix_ms(after),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PortCall {
    Install,
    CloseGate(Id),
    RemoveGate(Id),
    Close,
    TryIdle,
}

#[derive(Debug)]
enum DiskMarker {
    Installed {
        revision: Revision,
        endpoint_id: Id,
        route_epoch: Epoch,
    },
    Closed {
        revision: Revision,
    },
    EndpointClosing {
        revision: Revision,
        endpoint_id: Id,
        route_epoch: Epoch,
    },
    EndpointRemoving {
        revision: Revision,
        endpoint_id: Id,
        route_epoch: Epoch,
    },
    Armed,
    BusyClosed,
}

#[derive(Debug, Clone, Copy)]
enum EndpointPortResult {
    ErrorBefore(GatePortError),
    ErrorAfter(GatePortError),
}

struct FakePort {
    current: AdmissionSnapshot,
    checkpoint_path: PathBuf,
    expected_disk: VecDeque<DiskMarker>,
    idle_results: VecDeque<Result<IdleCloseResult, GatePortError>>,
    endpoint_results: VecDeque<EndpointPortResult>,
    global_results: VecDeque<EndpointPortResult>,
    calls: Vec<PortCall>,
}

impl FakePort {
    fn new(current: AdmissionSnapshot, checkpoint_path: &Path) -> Self {
        Self {
            current,
            checkpoint_path: checkpoint_path.to_path_buf(),
            expected_disk: VecDeque::new(),
            idle_results: VecDeque::new(),
            endpoint_results: VecDeque::new(),
            global_results: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    fn assert_checkpoint_first(&mut self) {
        let marker = self
            .expected_disk
            .pop_front()
            .expect("test must specify the checkpoint expected before each effect");
        let bytes = fs::read(&self.checkpoint_path).expect("read checkpoint at effect boundary");
        let checkpoint =
            decode_runtime_checkpoint(&bytes).expect("decode checkpoint at effect boundary");
        match marker {
            DiskMarker::Installed {
                revision,
                endpoint_id,
                route_epoch,
            } => {
                assert_eq!(checkpoint.desired_revision, revision);
                assert_eq!(checkpoint.lifecycle_admission, LifecycleAdmission::Open);
                assert!(matches!(
                    checkpoint.step,
                    ReconcileStep::InstallGate {
                        endpoint_id: ref installed_endpoint,
                        route_epoch: installed_epoch,
                    } if installed_endpoint == &endpoint_id && installed_epoch == route_epoch
                ));
                assert!(checkpoint.route_gates.iter().any(|route| {
                    route.binding.endpoint_id == endpoint_id
                        && route.binding.route_epoch == route_epoch
                        && route.gate == RouteGateState::Active
                }));
            }
            DiskMarker::Closed { revision } => {
                assert_eq!(checkpoint.desired_revision, revision);
                assert_closed(&checkpoint);
                assert!(matches!(
                    checkpoint.step,
                    ReconcileStep::CloseAdmission {
                        require_idle_attempt_id: None
                    }
                ));
            }
            DiskMarker::EndpointClosing {
                revision,
                endpoint_id,
                route_epoch,
            } => {
                assert_eq!(checkpoint.desired_revision, revision);
                assert_eq!(checkpoint.lifecycle_admission, LifecycleAdmission::Open);
                assert!(matches!(
                    checkpoint.step,
                    ReconcileStep::CloseGate {
                        endpoint_id: ref closing_endpoint,
                        route_epoch: closing_epoch,
                    } if closing_endpoint == &endpoint_id && closing_epoch == route_epoch
                ));
                let route = checkpoint
                    .route_gates
                    .iter()
                    .find(|route| route.binding.endpoint_id == endpoint_id)
                    .expect("closing Endpoint entry");
                assert_eq!(route.binding.route_epoch, route_epoch);
                assert_eq!(route.gate, RouteGateState::Active);
            }
            DiskMarker::EndpointRemoving {
                revision,
                endpoint_id,
                route_epoch,
            } => {
                assert_eq!(checkpoint.desired_revision, revision);
                assert!(matches!(
                    checkpoint.step,
                    ReconcileStep::CloseGate {
                        endpoint_id: ref removing_endpoint,
                        route_epoch: removing_epoch,
                    } if removing_endpoint == &endpoint_id && removing_epoch == route_epoch
                ));
                let route = checkpoint
                    .route_gates
                    .iter()
                    .find(|route| route.binding.endpoint_id == endpoint_id)
                    .expect("removing Endpoint entry");
                assert_eq!(route.binding.route_epoch, route_epoch);
                assert_eq!(route.gate, RouteGateState::Closed);
            }
            DiskMarker::Armed => assert!(matches!(
                checkpoint.require_idle,
                RequireIdleCheckpoint::Armed { .. }
            )),
            DiskMarker::BusyClosed => {
                assert_closed(&checkpoint);
                assert!(matches!(
                    checkpoint.require_idle,
                    RequireIdleCheckpoint::Busy {
                        gate_closed: true,
                        ..
                    }
                ));
            }
        }
    }

    fn apply(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        mismatch: AdmissionSnapshot,
    ) -> Result<(), GatePortError> {
        if &self.current == replacement {
            return Ok(());
        }
        if &self.current != expected {
            self.current = mismatch;
            return Err(GatePortError::StateMismatch);
        }
        self.current = replacement.clone();
        Ok(())
    }

    fn apply_endpoint(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<(), GatePortError> {
        if &self.current == replacement {
            return Ok(());
        }
        if &self.current != expected {
            return Err(GatePortError::StateMismatch);
        }
        self.current = replacement.clone();
        Ok(())
    }

    fn apply_endpoint_result(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<(), GatePortError> {
        match self.endpoint_results.pop_front() {
            Some(EndpointPortResult::ErrorBefore(error)) => Err(error),
            Some(EndpointPortResult::ErrorAfter(error)) => {
                self.apply_endpoint(expected, replacement)?;
                Err(error)
            }
            None => self.apply_endpoint(expected, replacement),
        }
    }
}

impl AdmissionGatePort for FakePort {
    fn snapshot(&self) -> AdmissionSnapshot {
        self.current.clone()
    }

    fn install_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        _endpoint_id: &Id,
    ) -> Result<(), GatePortError> {
        self.calls.push(PortCall::Install);
        self.assert_checkpoint_first();
        self.apply_endpoint_result(expected, replacement)
    }

    fn close_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &Id,
    ) -> Result<(), GatePortError> {
        self.calls.push(PortCall::CloseGate(endpoint_id.clone()));
        self.assert_checkpoint_first();
        self.apply_endpoint_result(expected, replacement)
    }

    fn remove_closed_gate(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
        endpoint_id: &Id,
    ) -> Result<(), GatePortError> {
        self.calls.push(PortCall::RemoveGate(endpoint_id.clone()));
        self.assert_checkpoint_first();
        self.apply_endpoint_result(expected, replacement)
    }

    fn close_all(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<(), GatePortError> {
        self.calls.push(PortCall::Close);
        self.assert_checkpoint_first();
        match self.global_results.pop_front() {
            Some(EndpointPortResult::ErrorBefore(error)) => Err(error),
            Some(EndpointPortResult::ErrorAfter(error)) => {
                self.apply(expected, replacement, replacement.clone())?;
                Err(error)
            }
            None => self.apply(expected, replacement, replacement.clone()),
        }
    }

    fn try_close_all_if_idle(
        &mut self,
        expected: &AdmissionSnapshot,
        replacement: &AdmissionSnapshot,
    ) -> Result<IdleCloseResult, GatePortError> {
        self.calls.push(PortCall::TryIdle);
        self.assert_checkpoint_first();
        let result = self
            .idle_results
            .pop_front()
            .expect("test must specify idle result");
        if matches!(result, Ok(IdleCloseResult::Closed)) {
            self.apply(expected, replacement, replacement.clone())?;
        } else if result.is_err() {
            self.current = replacement.clone();
        } else if &self.current != expected {
            self.current = replacement.clone();
            return Err(GatePortError::StateMismatch);
        }
        result
    }
}

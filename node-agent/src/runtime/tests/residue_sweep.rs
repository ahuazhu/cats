//! What the runtime-directory sweep may reclaim, and what it must not touch
//! (issue #99).

use super::*;

use crate::runtime::residue::allocated_tree_bytes;

/// A node whose state directory is `state_dir` and which supervises nothing.
fn swept_node(state_dir: &Path) -> NodeRuntime {
    NodeRuntime::new(stub_node_config(state_dir, VmmMode::Fake)).unwrap()
}

/// The shape `start_cat_ch` leaves behind: a Guest memory backing plus one
/// volume directory per attached disk, each holding a chunk cache.
fn abandoned_runtime_dir(state_dir: &Path, cat_id: &str, disks: &[&str]) -> PathBuf {
    let dir = state_dir.join("cats").join(cat_id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(crate::ch::GUEST_MEMORY_FILE),
        vec![7_u8; 128 * 1024],
    )
    .unwrap();
    for disk_id in disks {
        let volume = volume_data_dir(&dir, disk_id);
        std::fs::create_dir_all(volume.join(cats_api::blockd::PENDING_PACK_DIR)).unwrap();
        std::fs::write(volume.join("cache.data"), vec![9_u8; 64 * 1024]).unwrap();
        std::fs::write(volume.join("dirty.bitmap"), vec![0_u8; 4096]).unwrap();
    }
    dir
}

fn write_pending_pack(dir: &Path, disk_id: &str) {
    let pending = volume_data_dir(dir, disk_id).join(cats_api::blockd::PENDING_PACK_DIR);
    std::fs::create_dir_all(&pending).unwrap();
    std::fs::write(
        pending.join(format!(
            "00000000000000000003-txn{}",
            cats_api::blockd::PACK_FILE_SUFFIX
        )),
        vec![3_u8; 32 * 1024],
    )
    .unwrap();
}

#[test]
fn reclaims_a_runtime_directory_that_holds_no_unpublished_writes() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = swept_node(temp.path());
    let dir = abandoned_runtime_dir(temp.path(), "cat-a", &["dsk_root"]);

    let report = runtime.sweep_runtime_residue();

    assert!(!dir.exists(), "nothing in it was durability state");
    assert!(
        report.reclaimed_bytes >= 128 * 1024,
        "the freed bytes must include the Guest memory backing: {report:?}"
    );
    assert_eq!(report.dirs, 0);
    assert_eq!(report.bytes, 0);
}

/// The whole point of the fail-closed rule: a pending pack may be the only
/// authoritative copy of a relaxed volume's acknowledged writes (ADR-0021), and
/// whether its lineage is superseded is a question only blockd can put to the
/// metadata store. The Guest RAM beside it carries no such question.
#[test]
fn keeps_a_volume_holding_unpublished_packs_and_reports_it() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = swept_node(temp.path());
    let dir = abandoned_runtime_dir(temp.path(), "cat-a", &["dsk_root", "dsk_data"]);
    write_pending_pack(&dir, "dsk_data");

    let report = runtime.sweep_runtime_residue();

    assert!(
        volume_data_dir(&dir, "dsk_data").is_dir(),
        "a journal with unpublished packs must survive"
    );
    assert!(
        !volume_data_dir(&dir, "dsk_root").exists(),
        "a cache-only volume beside it is still reclaimable"
    );
    assert!(
        !dir.join(crate::ch::GUEST_MEMORY_FILE).exists(),
        "Guest RAM backing is not durability state, whatever the journals hold"
    );
    assert_eq!(report.dirs, 1, "the directory that stayed must be reported");
    assert!(
        report.bytes >= 32 * 1024,
        "the reported bytes must cover what stayed: {report:?}"
    );
    assert_eq!(
        runtime.telemetry().unsupervised_runtime_dirs,
        Some(1),
        "heartbeats must carry the same count"
    );
    assert_eq!(
        runtime.telemetry().unsupervised_runtime_bytes,
        Some(report.bytes)
    );
}

#[test]
fn never_touches_a_directory_its_cat_still_supervises() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = swept_node(temp.path());
    let dir = abandoned_runtime_dir(temp.path(), "cat-a", &["dsk_root"]);
    runtime.cats.lock().unwrap().insert(
        "cat-a".to_string(),
        test_runtime(ObservedState::Running, PathBuf::from("/unused-cgroup")),
    );

    let report = runtime.sweep_runtime_residue();

    assert!(dir.join(crate::ch::GUEST_MEMORY_FILE).is_file());
    assert!(volume_data_dir(&dir, "dsk_root").is_dir());
    assert_eq!(report, crate::runtime::residue::RuntimeResidue::default());
}

/// A Warm Cat's Guest RAM backing *is* its snapshot: `start_cat_ch` refuses to
/// restore without it. The snapshot directory beside it is what tells the sweep
/// so, because a Warm record that fails re-adoption leaves nothing else behind.
#[test]
fn leaves_a_warm_snapshots_memory_backing_alone() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = swept_node(temp.path());
    let dir = abandoned_runtime_dir(temp.path(), "cat-a", &["dsk_root"]);
    std::fs::create_dir_all(dir.join("snapshot")).unwrap();
    std::fs::write(dir.join("snapshot/state.json"), b"{}").unwrap();

    let report = runtime.sweep_runtime_residue();

    assert!(
        dir.join(crate::ch::GUEST_MEMORY_FILE).is_file(),
        "deleting this makes the Warm Cat unrestorable"
    );
    assert!(volume_data_dir(&dir, "dsk_root").is_dir());
    assert_eq!(report.reclaimed_bytes, 0);
    assert_eq!(report.dirs, 1);
}

/// The FakeVmm spelling of the same rule.
#[test]
fn leaves_a_fake_vmm_warm_state_file_alone() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = swept_node(temp.path());
    let dir = abandoned_runtime_dir(temp.path(), "cat-a", &["dsk_root"]);
    std::fs::write(warm_state_file(&dir), b"{}").unwrap();

    let report = runtime.sweep_runtime_residue();

    assert!(volume_data_dir(&dir, "dsk_root").is_dir());
    assert_eq!(report.reclaimed_bytes, 0);
    assert_eq!(report.dirs, 1);
}

/// Most of this residue predates the runtime ledger and has no record to prove
/// liveness against, so the sweep asks the sockets instead. A blockd still
/// serving its control socket is a process whose cache and bitmap must not be
/// deleted underneath it.
#[test]
fn leaves_a_runtime_a_process_is_still_serving() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = swept_node(temp.path());
    let dir = abandoned_runtime_dir(temp.path(), "cat-a", &["dsk_root"]);
    // Bound where the sweep will look for it: the path is derived from
    // `(state_dir, cat_id, kind)`, and this test's state directory is its own
    // tempdir, so nothing else can be listening here.
    let control = short_socket_path(temp.path(), "cat-a", "ctl-dsk_root");
    let listener = std::os::unix::net::UnixListener::bind(&control).unwrap();

    let report = runtime.sweep_runtime_residue();

    assert!(
        dir.join(crate::ch::GUEST_MEMORY_FILE).is_file(),
        "a live blockd means a live Cat this node simply cannot prove it owns"
    );
    assert!(volume_data_dir(&dir, "dsk_root").is_dir());
    assert_eq!(report.reclaimed_bytes, 0);
    assert_eq!(report.dirs, 1);

    drop(listener);
    std::fs::remove_file(&control).unwrap();
}

/// The socket file a crashed process leaves behind refuses connections, which
/// is the answer the sweep needs: nothing is serving it.
#[test]
fn a_stale_socket_file_does_not_protect_a_dead_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = swept_node(temp.path());
    let dir = abandoned_runtime_dir(temp.path(), "cat-a", &["dsk_root"]);
    let control = short_socket_path(temp.path(), "cat-a", "ctl-dsk_root");
    drop(std::os::unix::net::UnixListener::bind(&control).unwrap());
    assert!(control.exists(), "a crash leaves the socket file behind");

    let report = runtime.sweep_runtime_residue();

    assert!(!dir.exists());
    assert!(report.reclaimed_bytes > 0);

    std::fs::remove_file(&control).unwrap();
}

/// One real Cat's directory, swept twice: while its processes are up, and once
/// they are gone. Both halves need a real `start_cat`.
///
/// The liveness probe reconstructs socket paths rather than remembering them,
/// so only a real `spawn_blockd` proves it looks where blockd actually binds —
/// get that wrong and the sweep calls every live Cat dead. And only a real
/// blockd proves what a strict volume's journal directory holds once it has
/// published everything, which is what makes the second half reclaimable.
#[test]
fn a_real_cats_directory_becomes_reclaimable_exactly_when_its_processes_die() {
    let env = real_cat_env("node-residue");
    env.run(start_job("cat_residue", 1, &[("root", "/")]));
    let dir = env.cfg.state_dir.join("cats").join("cat_residue");
    assert!(
        volume_data_dir(&dir, "root")
            .join(cats_api::blockd::PENDING_PACK_DIR)
            .is_dir(),
        "a real blockd data directory has a pending-pack journal"
    );

    // A restarted agent that has not adopted anything supervises nothing, so
    // every directory under `cats/` looks abandoned from the inside.
    let live = env.restarted_agent().sweep_runtime_residue();

    assert!(
        volume_data_dir(&dir, "root").is_dir(),
        "the journal of a live blockd must not be deleted underneath it"
    );
    assert_eq!(live.reclaimed_bytes, 0);
    assert_eq!(live.dirs, 1, "and it must be reported, not silently kept");

    // Kill the processes and leave everything else exactly where it is: the
    // directory, the journals, and the socket files a killed server does not
    // get to remove. That is what an orphaned runtime looks like on disk.
    let mut rt = env
        .runtime
        .cats
        .lock()
        .unwrap()
        .remove("cat_residue")
        .expect("the Cat is supervised");
    if let Some(mut guest) = rt.guest.take() {
        guest.kill_and_reap();
    }
    for (_, mut blockd) in rt.blockds.drain() {
        blockd.child.kill_and_reap();
    }
    assert!(dir.is_dir(), "killing the processes leaves the directory");

    let dead = env.restarted_agent().sweep_runtime_residue();

    assert!(
        !dir.exists(),
        "a strict volume that published everything holds no durability state"
    );
    assert!(dead.reclaimed_bytes > 0);
    assert_eq!(dead.dirs, 0);
}

/// Reporting apparent size would alarm on bytes the disk never spent: the same
/// 51 directories measured 348 GiB apparent against ~53 GiB allocated, because
/// `prepare_memory_backing` writes a sparse file.
#[test]
fn measures_allocated_bytes_and_does_not_follow_symlinks() {
    use std::io::Write;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("cache")).unwrap();
    let mut file = std::fs::File::create(temp.path().join("cache/chunk")).unwrap();
    file.write_all(&vec![1_u8; 8192]).unwrap();
    std::os::unix::fs::symlink(temp.path().join("cache"), temp.path().join("cache-link")).unwrap();

    let used = allocated_tree_bytes(temp.path()).unwrap();

    assert!(used >= 8192);
    assert!(
        used < 32 * 1024 * 1024,
        "following the symlink would double-count the tree"
    );
}

#[test]
fn a_sparse_file_is_counted_by_what_it_occupies_not_by_its_length() {
    let temp = tempfile::tempdir().unwrap();
    let sparse = temp.path().join("guest-memory.bin");
    crate::ch::prepare_memory_backing(&sparse, 512).unwrap();
    assert_eq!(std::fs::metadata(&sparse).unwrap().len(), 512 << 20);

    let used = allocated_tree_bytes(&sparse).unwrap();

    assert!(
        used < 512 << 20,
        "a sparse 512 MiB backing must not be reported as 512 MiB: {used}"
    );
}

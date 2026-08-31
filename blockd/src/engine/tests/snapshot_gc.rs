use super::*;

#[test]
fn gc_keeps_the_complete_object_graph_pinned_by_a_snapshot_root() {
    let env = env();
    let e = attach(&env, "attA");

    e.write(0, &pattern(CHUNK_SIZE as usize, 1)).unwrap();
    e.flush().unwrap();
    let snapshot = env.meta.create_snapshot("snap_gc_pin", VOL).unwrap();
    let snapshot_data = env.blob.list("volumes/vol_test/data/").unwrap();
    let snapshot_maps = env.blob.list("volumes/vol_test/maps/").unwrap();
    assert_eq!(snapshot_data.len(), 1, "calibration: one snapshot base");
    assert_eq!(snapshot_maps.len(), 2, "calibration: one leaf and one root");
    assert!(
        snapshot
            .root_object_id
            .as_deref()
            .is_some_and(|root| snapshot_maps.iter().any(|key| key.ends_with(root))),
        "calibration: the captured snapshot Root is present"
    );

    // A dense rewrite makes the captured Root, Leaf and Base unreachable from
    // the current head while the snapshot still pins their exact object graph.
    e.write(0, &pattern(CHUNK_SIZE as usize, 2)).unwrap();
    e.flush().unwrap();
    assert_eq!(
        env.meta.list_snapshots(VOL).unwrap(),
        vec![snapshot],
        "calibration: the snapshot remains live before GC"
    );

    e.collect_garbage().unwrap();

    for key in snapshot_data.iter().chain(&snapshot_maps) {
        assert!(
            env.blob.exists(key).unwrap(),
            "GC deleted object pinned only by the live snapshot: {key}"
        );
    }
    e.detach().unwrap();
}

use super::*;
use crate::gc::{collect_garbage, GarbageCollectionClaim, RetainedRoot, RetainedRootSource};
use std::time::{Duration, Instant};

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
    let snapshot_root = RetainedRoot {
        source: RetainedRootSource::Snapshot {
            snapshot_id: Id::new(snapshot.snapshot_id.clone()).unwrap(),
        },
        head: RemoteHead {
            generation: Generation::new(u64::try_from(snapshot.generation).unwrap()).unwrap(),
            root_hash: snapshot.root_hash.map(Sha256Digest::from_bytes),
            root_object_id: snapshot
                .root_object_id
                .clone()
                .map(|value| AsciiText::new(value).unwrap()),
        },
    };

    // A dense rewrite makes the captured Root, Leaf and Base unreachable from
    // the current head while the snapshot still pins their exact object graph.
    e.write(0, &pattern(CHUNK_SIZE as usize, 2)).unwrap();
    e.flush().unwrap();
    assert_eq!(
        env.meta.list_snapshots(VOL).unwrap(),
        vec![snapshot.clone()],
        "calibration: the snapshot remains live before GC"
    );

    e.detach().unwrap();
    let current = remote_head_from_fixture_projection(&env.meta.load_head(VOL).unwrap()).unwrap();
    let claim = GarbageCollectionClaim::new(
        Id::new("22222222222222222222222222222222").unwrap(),
        Id::new(VOL).unwrap(),
        SIZE,
        vec![
            RetainedRoot {
                source: RetainedRootSource::Current,
                head: current,
            },
            snapshot_root,
        ],
    )
    .unwrap();
    collect_garbage(
        env.blob.as_ref(),
        &claim,
        cats_storage::BLOB_LIST_PAGE_MAX_KEYS,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();

    for key in snapshot_data.iter().chain(&snapshot_maps) {
        assert!(
            env.blob.exists(key).unwrap(),
            "GC deleted object pinned only by the live snapshot: {key}"
        );
    }
}

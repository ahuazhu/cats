use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::chunk::{self, CHUNK_SIZE};
use cats_api::runtime_reconciliation::{AsciiText, Generation, Id, RemoteHead, Sha256Digest};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_storage::{BlobStore, MetadataStore, SnapshotRow, VolumeHead};

use super::*;
use crate::engine::{ChunkEngine, DurabilityMode, EngineConfig};

const VOL: &str = "vol_gc_test";
const SIZE: u64 = 8 * CHUNK_SIZE as u64;
const ATTACHMENT: &str = "att_gc_test";

struct Fixture {
    _dir: tempfile::TempDir,
    blob: Arc<FileBlobStore>,
    meta: Arc<SqliteMetadataStore>,
    data_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let meta_path = dir.path().join("meta.db");
        let meta = Arc::new(SqliteMetadataStore::open(&meta_path).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        cats_test_support::install_sqlite_grant(&meta_path, VOL, ATTACHMENT, 1).unwrap();
        Self {
            data_dir: dir.path().join("data"),
            _dir: dir,
            blob,
            meta,
        }
    }

    fn attach(&self) -> Arc<ChunkEngine> {
        ChunkEngine::attach_granted_epoch(
            EngineConfig {
                volume_id: VOL.into(),
                data_dir: self.data_dir.clone(),
                attachment_id: ATTACHMENT.into(),
                lease_ttl_ms: 15_000,
                durability: DurabilityMode::Strict,
                max_staged_bytes: cats_api::blockd::DEFAULT_MAX_STAGED_BYTES,
                max_staged_packs: cats_api::blockd::DEFAULT_MAX_STAGED_PACKS,
                max_local_bytes: cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES,
            },
            1,
            self.blob.clone(),
            self.meta.clone(),
        )
        .unwrap()
    }

    fn current_root(&self) -> RetainedRoot {
        RetainedRoot {
            source: RetainedRootSource::Current,
            head: remote_head(&self.meta.load_head(VOL).unwrap()),
        }
    }

    fn snapshot_root(snapshot: &SnapshotRow) -> RetainedRoot {
        RetainedRoot {
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
        }
    }

    fn claim(&self, roots: Vec<RetainedRoot>, discriminator: u8) -> GarbageCollectionClaim {
        GarbageCollectionClaim::new(
            Id::new(format!("{discriminator:032x}")).unwrap(),
            Id::new(VOL.to_string()).unwrap(),
            SIZE,
            roots,
        )
        .unwrap()
    }
}

fn remote_head(head: &VolumeHead) -> RemoteHead {
    RemoteHead {
        generation: Generation::new(u64::try_from(head.generation).unwrap()).unwrap(),
        root_hash: head.root_hash.map(Sha256Digest::from_bytes),
        root_object_id: head
            .root_object_id
            .clone()
            .map(|value| AsciiText::new(value).unwrap()),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(index as u8))
        .collect()
}

#[test]
fn plan_keeps_the_complete_base_delta_graph_pinned_only_by_a_snapshot_root() {
    let fixture = Fixture::new();
    let engine = fixture.attach();

    engine.write(0, &pattern(CHUNK_SIZE as usize, 1)).unwrap();
    engine.flush().unwrap();
    engine
        .write(chunk::DIRTY_PAGE_SIZE as u64, &pattern(4096, 2))
        .unwrap();
    engine.flush().unwrap();
    engine
        .write(2 * chunk::DIRTY_PAGE_SIZE as u64, &pattern(4096, 3))
        .unwrap();
    engine.flush().unwrap();
    let snapshot = fixture.meta.create_snapshot("snap_gc_pin", VOL).unwrap();
    let snapshot_root = Fixture::snapshot_root(&snapshot);
    let snapshot_graph = trace_live_objects(
        fixture.blob.as_ref(),
        &Id::new(VOL.to_string()).unwrap(),
        SIZE,
        std::slice::from_ref(&snapshot_root),
        deadline(),
    )
    .unwrap();
    assert_eq!(
        snapshot_graph.data_objects().len(),
        3,
        "calibration: snapshot contains one Base and two Delta objects"
    );
    assert_eq!(
        snapshot_graph.map_nodes().len(),
        2,
        "calibration: snapshot contains one Root and one Leaf"
    );

    // The dense rewrite makes every snapshot graph object unreachable from the
    // current head. Only the explicit retained Root can keep it live.
    engine.write(0, &pattern(CHUNK_SIZE as usize, 9)).unwrap();
    engine.flush().unwrap();
    engine.detach().unwrap();

    let claim = fixture.claim(vec![fixture.current_root(), snapshot_root], 1);
    let plan = plan_garbage(fixture.blob.as_ref(), &claim, 1, deadline()).unwrap();
    for key in snapshot_graph.data_objects() {
        assert!(
            plan.keeps_data_object(key),
            "snapshot-only data object was planned for deletion: {key}"
        );
    }
    for key in snapshot_graph.map_nodes() {
        assert!(
            plan.keeps_map_node(key),
            "snapshot-only map node was planned for deletion: {key}"
        );
    }
}

#[test]
fn a_missing_snapshot_root_aborts_before_any_delete() {
    let fixture = Fixture::new();
    let engine = fixture.attach();
    engine.write(0, &pattern(CHUNK_SIZE as usize, 1)).unwrap();
    engine.flush().unwrap();
    let snapshot = fixture
        .meta
        .create_snapshot("snap_missing_root", VOL)
        .unwrap();
    let snapshot_root = Fixture::snapshot_root(&snapshot);
    engine.write(0, &pattern(CHUNK_SIZE as usize, 2)).unwrap();
    engine.flush().unwrap();
    engine.detach().unwrap();

    let orphan = format!("volumes/{VOL}/data/ffffffffffffffffffffffffffffffff-c7");
    fixture.blob.put_immutable(&orphan, b"garbage").unwrap();
    let root_key = format!(
        "volumes/{VOL}/maps/{}",
        snapshot.root_object_id.as_deref().unwrap()
    );
    fixture.blob.delete(&root_key).unwrap();
    let claim = fixture.claim(vec![fixture.current_root(), snapshot_root], 2);

    assert!(collect_garbage(fixture.blob.as_ref(), &claim, 1, deadline()).is_err());
    assert!(
        fixture.blob.exists(&orphan).unwrap(),
        "a failed Root read performed a deletion"
    );
}

#[test]
fn a_missing_snapshot_leaf_or_data_object_aborts_before_any_delete() {
    for missing_map in [true, false] {
        let fixture = Fixture::new();
        let engine = fixture.attach();
        engine.write(0, &pattern(CHUNK_SIZE as usize, 3)).unwrap();
        engine.flush().unwrap();
        let snapshot = fixture
            .meta
            .create_snapshot(
                if missing_map {
                    "snap_missing_leaf"
                } else {
                    "snap_missing_data"
                },
                VOL,
            )
            .unwrap();
        let snapshot_root = Fixture::snapshot_root(&snapshot);
        let graph = trace_live_objects(
            fixture.blob.as_ref(),
            &Id::new(VOL.to_string()).unwrap(),
            SIZE,
            std::slice::from_ref(&snapshot_root),
            deadline(),
        )
        .unwrap();
        engine.write(0, &pattern(CHUNK_SIZE as usize, 4)).unwrap();
        engine.flush().unwrap();
        engine.detach().unwrap();

        let missing = if missing_map {
            graph
                .map_nodes()
                .iter()
                .find(|key| !key.ends_with(snapshot.root_object_id.as_deref().unwrap()))
                .unwrap()
        } else {
            graph.data_objects().iter().next().unwrap()
        };
        fixture.blob.delete(missing).unwrap();
        let orphan = format!("volumes/{VOL}/data/ffffffffffffffffffffffffffffffff-c7");
        fixture.blob.put_immutable(&orphan, b"garbage").unwrap();
        let claim = fixture.claim(vec![fixture.current_root(), snapshot_root], 3);

        assert!(collect_garbage(fixture.blob.as_ref(), &claim, 1, deadline()).is_err());
        assert!(
            fixture.blob.exists(&orphan).unwrap(),
            "a missing live {} performed a deletion",
            if missing_map { "Leaf" } else { "Base" }
        );
    }
}

#[test]
fn executor_requires_the_exact_claim_and_never_touches_images_or_commits() {
    let fixture = Fixture::new();
    let engine = fixture.attach();
    engine.write(0, &pattern(4096, 5)).unwrap();
    engine.flush().unwrap();
    engine.detach().unwrap();

    let garbage_data = format!("volumes/{VOL}/data/ffffffffffffffffffffffffffffffff-c7");
    let garbage_map = format!("volumes/{VOL}/maps/{}.node", "f".repeat(64));
    let commit = format!("volumes/{VOL}/commits/999-retained.json");
    let image = format!("images/{}/manifest.json", "a".repeat(64));
    for (key, bytes) in [
        (&garbage_data, b"garbage".as_slice()),
        (&garbage_map, b"garbage".as_slice()),
        (&commit, b"audit".as_slice()),
        (&image, b"image".as_slice()),
    ] {
        fixture.blob.put_immutable(key, bytes).unwrap();
    }

    let roots = vec![fixture.current_root()];
    let claim = fixture.claim(roots.clone(), 4);
    let other_claim = fixture.claim(roots, 5);
    let plan = plan_garbage(fixture.blob.as_ref(), &claim, 1, deadline()).unwrap();
    assert_eq!(plan.data_objects_candidates(), 1);
    assert_eq!(plan.map_objects_candidates(), 1);
    assert!(matches!(
        execute_garbage_plan(
            fixture.blob.as_ref(),
            &other_claim,
            plan.clone(),
            deadline()
        ),
        Err(GcError::ClaimMismatch)
    ));
    assert!(fixture.blob.exists(&garbage_data).unwrap());

    let stats = execute_garbage_plan(fixture.blob.as_ref(), &claim, plan, deadline()).unwrap();
    assert_eq!(stats.data_objects_deleted, 1);
    assert_eq!(stats.map_objects_deleted, 1);
    assert!(fixture.blob.exists(&commit).unwrap());
    assert!(fixture.blob.exists(&image).unwrap());

    // This test directly removed blob objects only after the engine detached;
    // leave no local state that another fixture could accidentally adopt.
    fs::remove_dir_all(&fixture.data_dir).unwrap();
}

//! Shared semantic contracts for every provider adapter.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cats_storage::{BlobError, BlobStore, MetaError, MetadataStore};

static NEXT_CONTRACT_ID: AtomicU64 = AtomicU64::new(0);

fn unique_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}_{}",
        std::process::id(),
        NEXT_CONTRACT_ID.fetch_add(1, Ordering::Relaxed)
    )
}

/// Run the provider-neutral immutable-object contract against one adapter.
pub fn blob_store_contract(make_store: impl FnOnce() -> Arc<dyn BlobStore>) {
    let store = make_store();
    let namespace = unique_id("contract");
    let data_key = format!("{namespace}/volumes/v1/data/a");
    let map_key = format!("{namespace}/volumes/v1/maps/m1.node");
    let missing_key = format!("{namespace}/volumes/v1/data/missing");
    let outside_key = format!("{namespace}/other/unlisted");
    let list_prefix = format!("{namespace}/volumes/v1/");

    store.put_immutable(&data_key, b"hello").unwrap();
    assert_eq!(store.get(&data_key).unwrap(), b"hello");
    assert_eq!(store.get_bounded(&data_key, 5).unwrap(), b"hello");
    assert!(matches!(
        store.get_bounded(&data_key, 4),
        Err(BlobError::TooLarge {
            maximum: 4,
            observed_at_least: 5,
            ..
        })
    ));
    assert!(store.exists(&data_key).unwrap());
    assert!(!store.exists(&missing_key).unwrap());
    assert!(matches!(
        store.get(&missing_key),
        Err(BlobError::NotFound(_))
    ));
    assert!(matches!(
        store.get_bounded(&missing_key, 5),
        Err(BlobError::NotFound(_))
    ));

    store.put_immutable(&data_key, b"hello").unwrap();
    assert!(matches!(
        store.put_immutable(&data_key, b"different"),
        Err(BlobError::Backend { .. })
    ));
    assert_eq!(store.get(&data_key).unwrap(), b"hello");

    store.put_immutable(&map_key, b"node").unwrap();
    store.put_immutable(&outside_key, b"outside").unwrap();
    assert_eq!(
        store.list(&list_prefix).unwrap(),
        vec![data_key.clone(), map_key.clone()]
    );

    for key in ["", "/absolute", "../escape", "a//b", "a/./b"] {
        assert!(matches!(
            store.put_immutable(key, b"value"),
            Err(BlobError::InvalidKey { .. })
        ));
    }

    store.delete(&data_key).unwrap();
    store.delete(&data_key).unwrap();
    assert!(!store.exists(&data_key).unwrap());
    store.delete(&map_key).unwrap();
    store.delete(&outside_key).unwrap();
}

/// Run the provider-neutral volume, fencing, CAS, and snapshot contract
/// against one metadata adapter.
pub fn metadata_store_contract(make_store: impl FnOnce() -> Arc<dyn MetadataStore>) {
    let store = make_store();
    volume_and_resize_contract(store.as_ref());
    lease_contract(store.as_ref());
    expiry_and_stale_epoch_contract(store.as_ref());
    generation_and_snapshot_contract(store.as_ref());
}

fn volume_and_resize_contract(store: &dyn MetadataStore) {
    let volume = unique_id("volume");
    let initial_size = 1 << 22;
    store.create_volume(&volume, initial_size).unwrap();
    assert!(matches!(
        store.create_volume(&volume, initial_size),
        Err(MetaError::AlreadyExists(_))
    ));

    let head = store.load_head(&volume).unwrap();
    assert_eq!(head.volume_id, volume);
    assert_eq!(head.size_bytes, initial_size);
    assert_eq!(head.generation, 0);
    assert_eq!(head.root_hash, None);
    assert_eq!(head.root_object_id, None);
    assert_eq!(head.lease_owner, None);
    assert_eq!(head.lease_epoch, 0);
    assert!(matches!(
        store.load_head(&unique_id("missing")),
        Err(MetaError::NotFound(_))
    ));

    store.resize_volume(&volume, initial_size * 2).unwrap();
    assert_eq!(
        store.load_head(&volume).unwrap().size_bytes,
        initial_size * 2
    );
    assert!(store.resize_volume(&volume, initial_size).is_err());

    let epoch = store
        .acquire_lease(&volume, "resize-owner", 60_000)
        .unwrap();
    assert!(store.resize_volume(&volume, initial_size * 4).is_err());
    store.release_lease(&volume, "resize-owner", epoch).unwrap();
    store.resize_volume(&volume, initial_size * 4).unwrap();

    assert!(matches!(
        store.create_volume(&unique_id("too_large"), u64::MAX),
        Err(MetaError::InvalidArgument(_))
    ));
    assert!(matches!(
        store.acquire_lease(&volume, "invalid-ttl", 0),
        Err(MetaError::InvalidArgument(_))
    ));
    assert!(matches!(
        store.acquire_lease(&volume, "invalid-ttl", i64::MAX),
        Err(MetaError::InvalidArgument(_))
    ));

    store.delete_volume(&volume).unwrap();
    assert!(matches!(
        store.load_head(&volume),
        Err(MetaError::NotFound(_))
    ));
}

fn lease_contract(store: &dyn MetadataStore) {
    let volume = unique_id("lease");
    store.create_volume(&volume, 1 << 22).unwrap();

    let first = store
        .acquire_lease(&volume, "attachment-a", 60_000)
        .unwrap();
    assert_eq!(first, 1);
    let head = store.load_head(&volume).unwrap();
    assert_eq!(head.lease_owner.as_deref(), Some("attachment-a"));
    assert_eq!(head.lease_epoch, first);
    assert!(matches!(
        store.acquire_lease(&volume, "attachment-b", 60_000),
        Err(MetaError::LeaseHeld)
    ));
    store
        .renew_lease(&volume, "attachment-a", first, 60_000)
        .unwrap();
    store.revoke_lease(&volume).unwrap();
    let revoked = store.load_head(&volume).unwrap();
    assert_eq!(revoked.lease_owner.as_deref(), Some("attachment-a"));
    assert_eq!(revoked.lease_epoch, first + 1);
    assert!(matches!(
        store.renew_lease(&volume, "attachment-a", first, 60_000),
        Err(MetaError::Fenced)
    ));

    let second = store
        .acquire_lease(&volume, "attachment-b", 60_000)
        .unwrap();
    assert_eq!(second, 3, "revoke and acquire must each consume an epoch");
    assert!(matches!(
        store.renew_lease(&volume, "attachment-a", first, 60_000),
        Err(MetaError::Fenced)
    ));
    store
        .release_lease(&volume, "attachment-b", second)
        .unwrap();
    assert_eq!(store.load_head(&volume).unwrap().lease_owner, None);
    let third = store
        .acquire_lease(&volume, "attachment-c", 60_000)
        .unwrap();
    assert!(third > second);

    store.delete_volume(&volume).unwrap();
}

fn expiry_and_stale_epoch_contract(store: &dyn MetadataStore) {
    let renewable = unique_id("renewable");
    store.create_volume(&renewable, 1 << 22).unwrap();
    let renewable_epoch = store.acquire_lease(&renewable, "attachment-a", 10).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    store
        .renew_lease(&renewable, "attachment-a", renewable_epoch, 60_000)
        .unwrap();
    store
        .cas_head(
            &renewable,
            0,
            1,
            [1; 32],
            "root-1",
            "attachment-a",
            renewable_epoch,
        )
        .unwrap();
    store.delete_volume(&renewable).unwrap();

    let takeover = unique_id("takeover");
    store.create_volume(&takeover, 1 << 22).unwrap();
    let old_epoch = store.acquire_lease(&takeover, "attachment-a", 10).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let new_epoch = store
        .acquire_lease(&takeover, "attachment-b", 60_000)
        .unwrap();
    assert!(new_epoch > old_epoch);
    assert!(matches!(
        store.renew_lease(&takeover, "attachment-a", old_epoch, 60_000),
        Err(MetaError::Fenced)
    ));
    assert!(store
        .cas_head(
            &takeover,
            0,
            1,
            [2; 32],
            "stale-root",
            "attachment-a",
            old_epoch,
        )
        .is_err());
    store
        .cas_head(
            &takeover,
            0,
            1,
            [3; 32],
            "live-root",
            "attachment-b",
            new_epoch,
        )
        .unwrap();
    store.delete_volume(&takeover).unwrap();
}

fn generation_and_snapshot_contract(store: &dyn MetadataStore) {
    let volume = unique_id("generation");
    let snapshot_a = unique_id("snapshot");
    let snapshot_b = unique_id("snapshot");
    store.create_volume(&volume, 1 << 22).unwrap();
    let epoch = store
        .acquire_lease(&volume, "attachment-a", 60_000)
        .unwrap();

    assert!(matches!(
        store.cas_head(
            &volume,
            0,
            0,
            [0; 32],
            "invalid-root",
            "attachment-a",
            epoch,
        ),
        Err(MetaError::InvalidArgument(_))
    ));
    assert_eq!(
        store
            .cas_head(&volume, 0, 1, [7; 32], "root-1", "attachment-a", epoch,)
            .unwrap(),
        1
    );
    assert!(matches!(
        store.cas_head(&volume, 0, 2, [8; 32], "conflict", "attachment-a", epoch,),
        Err(MetaError::CasConflict { expected: 0 })
    ));
    assert!(store
        .cas_head(
            &volume,
            1,
            2,
            [8; 32],
            "stale-epoch",
            "attachment-a",
            epoch + 1,
        )
        .is_err());

    let first = store.create_snapshot(&snapshot_a, &volume).unwrap();
    assert_eq!(first.generation, 1);
    assert_eq!(first.root_hash, Some([7; 32]));
    assert_eq!(first.root_object_id.as_deref(), Some("root-1"));

    assert_eq!(
        store
            .cas_head(&volume, 1, 4, [9; 32], "root-4", "attachment-a", epoch,)
            .unwrap(),
        4
    );
    let second = store.create_snapshot(&snapshot_b, &volume).unwrap();
    assert_eq!(second.generation, 4);
    let mut snapshots = store.list_snapshots(&volume).unwrap();
    snapshots.sort_by(|left, right| left.snapshot_id.cmp(&right.snapshot_id));
    let mut expected_ids = [snapshot_a, snapshot_b];
    expected_ids.sort();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].snapshot_id, expected_ids[0]);
    assert_eq!(snapshots[1].snapshot_id, expected_ids[1]);
    assert!(matches!(
        store.create_snapshot(&unique_id("missing_snapshot"), &unique_id("missing_volume")),
        Err(MetaError::NotFound(_))
    ));

    let head = store.load_head(&volume).unwrap();
    assert_eq!(head.generation, 4);
    assert_eq!(head.root_hash, Some([9; 32]));
    assert_eq!(head.root_object_id.as_deref(), Some("root-4"));
    store.delete_volume(&volume).unwrap();
}

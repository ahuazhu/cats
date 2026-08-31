//! Shared semantic contracts for every provider adapter.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cats_storage::{BlobError, BlobListPage, BlobStore, MetaError, MetadataStore};

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

    // Calibrate cursor traversal against a late key after multiple full pages
    // that a selective GC would classify as entirely live. A scan that keeps
    // restarting at the prefix would never discover the final garbage key.
    let cursor_prefix = format!("{namespace}/volumes/v1/cursor/");
    let cursor_keys = [
        format!("{cursor_prefix}00-live"),
        format!("{cursor_prefix}01-live"),
        format!("{cursor_prefix}02-live"),
        format!("{cursor_prefix}03-live"),
        format!("{cursor_prefix}99-garbage"),
    ];
    for key in &cursor_keys {
        store.put_immutable(key, b"cursor").unwrap();
    }
    let first = store.list_after_bounded(&cursor_prefix, None, 2).unwrap();
    assert_eq!(
        first,
        BlobListPage {
            keys: cursor_keys[..2].to_vec(),
            is_truncated: true,
        }
    );
    let second = store
        .list_after_bounded(&cursor_prefix, first.keys.last().map(String::as_str), 2)
        .unwrap();
    assert_eq!(
        second,
        BlobListPage {
            keys: cursor_keys[2..4].to_vec(),
            is_truncated: true,
        }
    );
    let final_page = store
        .list_after_bounded(&cursor_prefix, second.keys.last().map(String::as_str), 2)
        .unwrap();
    assert_eq!(
        final_page,
        BlobListPage {
            keys: cursor_keys[4..].to_vec(),
            is_truncated: false,
        }
    );
    assert_eq!(
        store
            .list_after_bounded(
                &cursor_prefix,
                final_page.keys.last().map(String::as_str),
                2
            )
            .unwrap(),
        BlobListPage {
            keys: Vec::new(),
            is_truncated: false,
        }
    );
    assert!(matches!(
        store.list_after_bounded(&cursor_prefix, Some(&outside_key), 2),
        Err(BlobError::InvalidKey { .. })
    ));

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
    for key in &cursor_keys {
        store.delete(key).unwrap();
    }
    store.delete(&outside_key).unwrap();
}

/// Run the compatibility data-plane contract against one metadata adapter.
///
/// `install_grant` is a test-only stand-in for the external Volume Authority:
/// it writes an exact owner/epoch but is deliberately not a `MetadataStore`
/// method. This preserves renewal, fencing, CAS and snapshot evidence without
/// restoring a second production ownership authority.
pub fn metadata_store_contract(
    store: Arc<dyn MetadataStore>,
    install_grant: impl Fn(&str, &str, i64),
) {
    immutable_volume_contract(store.as_ref());
    lease_and_fencing_contract(store.as_ref(), &install_grant);
    expiry_and_stale_epoch_contract(store.as_ref(), &install_grant);
    generation_and_snapshot_contract(store.as_ref(), &install_grant);
}

fn immutable_volume_contract(store: &dyn MetadataStore) {
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

    assert_eq!(
        store.load_head(&volume).unwrap().size_bytes,
        initial_size,
        "volume capacity is immutable on the compatibility port"
    );

    assert!(matches!(
        store.create_volume(&unique_id("too_large"), u64::MAX),
        Err(MetaError::InvalidArgument(_))
    ));
    store.delete_volume(&volume).unwrap();
    assert!(matches!(
        store.load_head(&volume),
        Err(MetaError::NotFound(_))
    ));
}

fn lease_and_fencing_contract(store: &dyn MetadataStore, install_grant: &impl Fn(&str, &str, i64)) {
    let volume = unique_id("lease");
    store.create_volume(&volume, 1 << 22).unwrap();

    install_grant(&volume, "attachment-a", 1);
    let first = store.load_head(&volume).unwrap();
    assert_eq!(first.lease_owner.as_deref(), Some("attachment-a"));
    assert_eq!(first.lease_epoch, 1);
    store
        .renew_lease(&volume, "attachment-a", 1, 60_000)
        .unwrap();

    // The external authority changes the epoch. Every old data-plane request
    // must fail closed, even when the owner string is unchanged.
    install_grant(&volume, "attachment-a", 2);
    assert!(matches!(
        store.renew_lease(&volume, "attachment-a", 1, 60_000),
        Err(MetaError::Fenced)
    ));
    assert!(store
        .cas_head(&volume, 0, 1, [1; 32], "stale-root", "attachment-a", 1,)
        .is_err());

    install_grant(&volume, "attachment-b", 3);
    store
        .cas_head(&volume, 0, 1, [2; 32], "live-root", "attachment-b", 3)
        .unwrap();
    store.release_lease(&volume, "attachment-b", 3).unwrap();
    assert_eq!(store.load_head(&volume).unwrap().lease_owner, None);
    store.delete_volume(&volume).unwrap();
}

fn expiry_and_stale_epoch_contract(
    store: &dyn MetadataStore,
    install_grant: &impl Fn(&str, &str, i64),
) {
    let renewable = unique_id("renewable");
    store.create_volume(&renewable, 1 << 22).unwrap();
    install_grant(&renewable, "attachment-a", 1);
    store
        .renew_lease(&renewable, "attachment-a", 1, 10)
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    store
        .renew_lease(&renewable, "attachment-a", 1, 60_000)
        .unwrap();
    store
        .cas_head(&renewable, 0, 1, [3; 32], "root-1", "attachment-a", 1)
        .unwrap();
    store.delete_volume(&renewable).unwrap();

    let takeover = unique_id("takeover");
    store.create_volume(&takeover, 1 << 22).unwrap();
    install_grant(&takeover, "attachment-a", 1);
    install_grant(&takeover, "attachment-b", 2);
    assert!(matches!(
        store.renew_lease(&takeover, "attachment-a", 1, 60_000),
        Err(MetaError::Fenced)
    ));
    assert!(store
        .cas_head(&takeover, 0, 1, [4; 32], "stale-root", "attachment-a", 1,)
        .is_err());
    store
        .cas_head(&takeover, 0, 1, [5; 32], "live-root", "attachment-b", 2)
        .unwrap();
    store.delete_volume(&takeover).unwrap();
}

fn generation_and_snapshot_contract(
    store: &dyn MetadataStore,
    install_grant: &impl Fn(&str, &str, i64),
) {
    let volume = unique_id("generation");
    let snapshot_a = unique_id("snapshot");
    let snapshot_b = unique_id("snapshot");
    store.create_volume(&volume, 1 << 22).unwrap();
    install_grant(&volume, "attachment-a", 1);
    assert!(matches!(
        store.cas_head(&volume, 0, 0, [0; 32], "invalid-root", "attachment-a", 1,),
        Err(MetaError::InvalidArgument(_))
    ));

    assert_eq!(
        store
            .cas_head(&volume, 0, 1, [7; 32], "root-1", "attachment-a", 1)
            .unwrap(),
        1
    );
    assert!(matches!(
        store.cas_head(&volume, 0, 2, [8; 32], "conflict", "attachment-a", 1),
        Err(MetaError::CasConflict { expected: 0 })
    ));
    assert!(store
        .cas_head(&volume, 1, 2, [8; 32], "stale-epoch", "attachment-a", 2,)
        .is_err());

    let first = store.create_snapshot(&snapshot_a, &volume).unwrap();
    assert_eq!(first.generation, 1);
    assert_eq!(first.root_hash, Some([7; 32]));
    assert_eq!(first.root_object_id.as_deref(), Some("root-1"));

    assert_eq!(
        store
            .cas_head(&volume, 1, 4, [9; 32], "root-4", "attachment-a", 1)
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

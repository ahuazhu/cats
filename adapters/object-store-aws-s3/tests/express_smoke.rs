//! Smoke test against a real bucket: the full BlobStore surface the engine
//! uses (put_immutable twice, immutability conflict, get, exists, list,
//! delete), driven by the same env vars the commit_cost bench reads.
//!
//! Ignored by default; needs a real bucket:
//! `CATS_BENCH_S3_BUCKET=... [CATS_BENCH_S3_ENDPOINT=... etc.] \
//!  cargo test --release -p cats-object-store-aws-s3 --test express_smoke -- --ignored --nocapture`

use std::sync::Arc;

use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_storage::blob::BlobStore;
use cats_storage::{open_blob_store, AdapterConfig, BlobStoreFactory};

fn store(prefix: &str) -> Arc<dyn BlobStore> {
    let bucket = std::env::var("CATS_BENCH_S3_BUCKET").expect("CATS_BENCH_S3_BUCKET");
    let mut pairs = vec![
        ("bucket".to_string(), bucket),
        ("prefix".to_string(), prefix.to_string()),
    ];
    if let Ok(region) = std::env::var("AWS_REGION") {
        pairs.push(("region".to_string(), region));
    }
    for (var, option) in [
        ("CATS_BENCH_S3_ENDPOINT", "endpoint"),
        ("CATS_BENCH_S3_SIGNING_SERVICE", "signing-service"),
        ("CATS_BENCH_S3_VIRTUAL_HOST", "virtual-host"),
        ("CATS_BENCH_S3_EXPRESS_SESSION", "express-session"),
    ] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                pairs.push((option.to_string(), value));
            }
        }
    }
    let config = AdapterConfig::from_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.clone())))
        .expect("adapter options");
    open_blob_store(
        cats_object_store_aws_s3::ADAPTER_NAME,
        &config,
        &[&AwsS3BlobStoreFactory as &dyn BlobStoreFactory],
    )
    .expect("open blob store")
}

#[test]
#[ignore = "needs a real bucket; run explicitly with --ignored --nocapture"]
fn full_surface_against_real_bucket() {
    let run = format!(
        "smoke-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let store = store(&run);
    let key = "volumes/smoke/data/obj-1";
    let body = b"cats smoke test payload".to_vec();

    store.put_immutable(key, &body).expect("first put");
    println!("put_immutable #1: ok");
    store
        .put_immutable(key, &body)
        .expect("idempotent second put with identical bytes");
    println!("put_immutable #2 (same bytes): ok (idempotent)");
    let conflict = store.put_immutable(key, b"different bytes");
    assert!(
        conflict.is_err(),
        "immutable overwrite with different content must fail"
    );
    println!("put_immutable #3 (different bytes): rejected as expected");

    assert_eq!(store.get(key).expect("get"), body);
    println!("get: ok");
    assert!(store.exists(key).expect("exists"));
    assert!(!store
        .exists("volumes/smoke/data/missing")
        .expect("exists missing"));
    println!("exists / not-exists: ok");

    let listed = store.list("volumes/smoke/data/").expect("list");
    assert_eq!(listed, vec![key.to_string()]);
    println!("list: ok ({listed:?})");

    store.delete(key).expect("delete");
    assert!(!store.exists(key).expect("exists after delete"));
    println!("delete: ok");
    println!("smoke test passed for run prefix {run}");
}

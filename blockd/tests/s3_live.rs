//! Live S3-compatibility test. Runs only when CATS_S3_TEST_ENDPOINT is set
//! (CI/dev use a MinIO container):
//!
//! ```bash
//! docker run -d --name cats-minio -p 9000:9000 \
//!   -e MINIO_ROOT_USER=catsdev -e MINIO_ROOT_PASSWORD=catsdev-secret \
//!   minio/minio server /data
//! docker exec cats-minio mc alias set local http://127.0.0.1:9000 catsdev catsdev-secret
//! docker exec cats-minio mc mb local/cats-test
//! CATS_S3_TEST_ENDPOINT=http://127.0.0.1:9000 \
//! CATS_S3_ACCESS_KEY=catsdev CATS_S3_SECRET_KEY=catsdev-secret \
//! CATS_S3_TEST_BUCKET=cats-test cargo test -p cats-blockd --test s3_live
//! ```

use std::sync::Arc;

use cats_blockd::blobstore::{BlobError, BlobStore};
use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_blockd::meta::{MetadataStore, SqliteMeta};
use cats_blockd::s3::{S3BlobStore, S3Config};

fn live_store(prefix: &str) -> Option<S3BlobStore> {
    let endpoint = std::env::var("CATS_S3_TEST_ENDPOINT").ok()?;
    let bucket = std::env::var("CATS_S3_TEST_BUCKET").unwrap_or_else(|_| "cats-test".into());
    let access_key = std::env::var("CATS_S3_ACCESS_KEY").expect("CATS_S3_ACCESS_KEY");
    let secret_key = std::env::var("CATS_S3_SECRET_KEY").expect("CATS_S3_SECRET_KEY");
    Some(
        S3BlobStore::new(S3Config {
            endpoint,
            bucket,
            region: "us-east-1".into(),
            access_key,
            secret_key,
            prefix: prefix.to_string(),
        })
        .unwrap(),
    )
}

#[test]
fn blobstore_contract_against_live_s3() {
    let Some(store) = live_store(&format!("contract-{}", std::process::id())) else {
        eprintln!("skipped: CATS_S3_TEST_ENDPOINT not set");
        return;
    };
    store
        .put_immutable("volumes/v1/data/a", b"hello-s3")
        .unwrap();
    store
        .put_immutable("volumes/v1/data/a", b"hello-s3")
        .unwrap(); // idempotent
    assert_eq!(store.get("volumes/v1/data/a").unwrap(), b"hello-s3");
    assert!(store.exists("volumes/v1/data/a").unwrap());
    assert!(!store.exists("volumes/v1/data/missing").unwrap());
    assert!(matches!(
        store.get("volumes/v1/data/missing"),
        Err(BlobError::NotFound(_))
    ));
    store
        .put_immutable("volumes/v1/maps/m1.node", b"node")
        .unwrap();
    let listed = store.list("volumes/v1/").unwrap();
    assert_eq!(
        listed,
        vec![
            "volumes/v1/data/a".to_string(),
            "volumes/v1/maps/m1.node".to_string()
        ]
    );
    store.delete("volumes/v1/data/a").unwrap();
    store.delete("volumes/v1/data/a").unwrap(); // idempotent delete
    assert!(!store.exists("volumes/v1/data/a").unwrap());
    store.delete("volumes/v1/maps/m1.node").unwrap();
}

#[test]
fn engine_flush_and_empty_cache_restore_through_live_s3() {
    let Some(store) = live_store(&format!("engine-{}", std::process::id())) else {
        eprintln!("skipped: CATS_S3_TEST_ENDPOINT not set");
        return;
    };
    let blob: Arc<dyn BlobStore> = Arc::new(store);
    let dir = tempfile::tempdir().unwrap();
    let meta = Arc::new(SqliteMeta::open(&dir.path().join("meta.db")).unwrap());
    let size = 2 * cats_api::chunk::CHUNK_SIZE as u64;
    meta.create_volume("vol_live", size).unwrap();

    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    {
        let engine = ChunkEngine::attach(
            EngineConfig::new("vol_live", dir.path().join("data-a"), "att_a"),
            blob.clone(),
            meta.clone(),
        )
        .unwrap();
        engine.write(4096, &payload).unwrap();
        assert_eq!(engine.flush().unwrap(), 1);
        engine.detach();
    }
    // Fresh "host", empty cache: everything must come back from S3.
    let engine = ChunkEngine::attach(
        EngineConfig::new("vol_live", dir.path().join("data-b"), "att_b"),
        blob,
        meta,
    )
    .unwrap();
    let mut back = vec![0u8; payload.len()];
    engine.read(4096, &mut back).unwrap();
    assert_eq!(back, payload, "cold restore through live S3 lost data");
    engine.detach();
}

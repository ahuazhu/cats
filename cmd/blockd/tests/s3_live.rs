//! Live AWS S3 adapter compatibility test. Runs only when
//! CATS_AWS_S3_TEST_ENDPOINT is set
//! (CI/dev use a MinIO container):
//!
//! ```bash
//! docker run -d --name cats-minio -p 9000:9000 \
//!   -e MINIO_ROOT_USER=catsdev -e MINIO_ROOT_PASSWORD=catsdev-secret \
//!   minio/minio server /data
//! docker exec cats-minio mc alias set local http://127.0.0.1:9000 catsdev catsdev-secret
//! docker exec cats-minio mc mb local/cats-test
//! CATS_AWS_S3_TEST_ENDPOINT=http://127.0.0.1:9000 \
//! AWS_ACCESS_KEY_ID=catsdev AWS_SECRET_ACCESS_KEY=catsdev-secret \
//! CATS_AWS_S3_TEST_BUCKET=cats-test cargo test -p cats-blockd-daemon --test s3_live
//! ```

use std::sync::Arc;

use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_aws_s3::{AwsS3BlobStore, AwsS3Config};
use cats_storage::{BlobError, BlobStore, MetadataStore};

fn live_store(prefix: &str) -> Option<AwsS3BlobStore> {
    let endpoint = std::env::var("CATS_AWS_S3_TEST_ENDPOINT").ok()?;
    let bucket = std::env::var("CATS_AWS_S3_TEST_BUCKET").unwrap_or_else(|_| "cats-test".into());
    let access_key = std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID");
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY");
    Some(
        AwsS3BlobStore::new(AwsS3Config {
            endpoint,
            bucket,
            region: "us-east-1".into(),
            access_key,
            secret_key,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
            prefix: prefix.to_string(),
        })
        .unwrap(),
    )
}

#[test]
fn blobstore_contract_against_live_s3() {
    let Some(store) = live_store(&format!("contract-{}", std::process::id())) else {
        eprintln!("skipped: CATS_AWS_S3_TEST_ENDPOINT not set");
        return;
    };
    store
        .put_immutable("volumes/v1/data/a", b"hello-s3")
        .unwrap();
    store
        .put_immutable("volumes/v1/data/a", b"hello-s3")
        .unwrap(); // idempotent
    assert!(matches!(
        store.put_immutable("volumes/v1/data/a", b"different"),
        Err(BlobError::Backend { .. })
    ));
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
        eprintln!("skipped: CATS_AWS_S3_TEST_ENDPOINT not set");
        return;
    };
    let blob: Arc<dyn BlobStore> = Arc::new(store);
    let dir = tempfile::tempdir().unwrap();
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
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

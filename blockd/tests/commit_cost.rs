//! What a FLUSH actually spends its time on.
//!
//! Guest workloads on real hardware stall for hundreds of milliseconds per FLUSH
//! (evidence: experiments/vhost-user-blk-frontend-20260726). A commit publishes
//! the dirty 64 KiB pages of each dirty chunk, so the cost scales with what the
//! Guest wrote — except when a chunk is written densely or its delta chain is
//! full, where the commit publishes a fresh 4 MiB base instead. This measures
//! both shapes.
//!
//! Ignored by default; run with
//! `cargo test --release -p cats-blockd --test commit_cost -- --ignored --nocapture`.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_blockd::format;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStore;
use cats_storage::blob::{BlobStore, Result as BlobResult};
use cats_storage::{open_blob_store, AdapterConfig, BlobStoreFactory, MetadataStore};

const CHUNK: u64 = cats_api::chunk::CHUNK_SIZE as u64;
const PAGE: u64 = cats_api::chunk::DIRTY_PAGE_SIZE as u64;

/// Counts the bytes a commit actually publishes, which is the number the flush
/// cost should track.
struct SizingBlob {
    inner: Arc<dyn BlobStore>,
    data_bytes: AtomicU64,
}

impl BlobStore for SizingBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> BlobResult<()> {
        if key.contains("/data/") {
            self.data_bytes.fetch_add(data.len() as u64, Ordering::SeqCst);
        }
        self.inner.put_immutable(key, data)
    }
    fn get(&self, key: &str) -> BlobResult<Vec<u8>> {
        self.inner.get(key)
    }
    fn exists(&self, key: &str) -> BlobResult<bool> {
        self.inner.exists(key)
    }
    fn delete(&self, key: &str) -> BlobResult<()> {
        self.inner.delete(key)
    }
    fn list(&self, prefix: &str) -> BlobResult<Vec<String>> {
        self.inner.list(prefix)
    }
}

/// The object store a benchmark run measures against.
///
/// Defaults to a local file store so the benchmark runs anywhere. Set
/// `CATS_BENCH_S3_BUCKET` to measure against real S3 instead, which is the number
/// that matters: an object there costs a PUT round trip rather than a `create` +
/// `sync_data` + `hard_link`, and both delta packs and golden roots are about how
/// many bytes and objects reach the object store.
///
/// `prefix` keeps concurrent and repeated runs from colliding in one bucket.
fn object_store(dir: &Path, prefix: &str) -> Arc<dyn BlobStore> {
    match std::env::var("CATS_BENCH_S3_BUCKET") {
        Ok(bucket) if !bucket.is_empty() => {
            let mut pairs = vec![
                ("bucket".to_string(), bucket),
                ("prefix".to_string(), format!("bench/{prefix}")),
            ];
            if let Ok(region) = std::env::var("AWS_REGION") {
                pairs.push(("region".to_string(), region));
            }
            let config = AdapterConfig::from_pairs(
                pairs.iter().map(|(k, v)| (k.as_str(), v.clone())),
            )
            .expect("s3 adapter options");
            open_blob_store(
                cats_object_store_aws_s3::ADAPTER_NAME,
                &config,
                &[&AwsS3BlobStoreFactory as &dyn BlobStoreFactory],
            )
            .expect("open s3 object store")
        }
        _ => Arc::new(FileBlobStore::open(dir.join("blob")).expect("blob")),
    }
}

struct Env {
    _dir: tempfile::TempDir,
    engine: Arc<ChunkEngine>,
    published: Arc<SizingBlob>,
}

fn env(chunks: u64, run: &str) -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let published = Arc::new(SizingBlob {
        inner: object_store(dir.path(), run),
        data_bytes: AtomicU64::new(0),
    });
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).expect("meta"));
    meta.create_volume("vol_commit", chunks * CHUNK)
        .expect("volume");
    let engine = ChunkEngine::attach(
        EngineConfig::new("vol_commit", dir.path().join("data"), "att-commit"),
        published.clone(),
        meta,
    )
    .expect("attach");
    Env {
        _dir: dir,
        engine,
        published,
    }
}

/// One 64 KiB page dirtied per chunk: the shape a 4 KiB random-write Guest
/// workload produces, where a tiny write used to dirty a whole 4 MiB chunk.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn flush_cost_scales_with_the_dirty_set() {
    let volume_chunks = 64;
    let repeats = 3;
    println!(
        "\n{:>12} {:>12} {:>14} {:>12} {:>16} {:>14}",
        "dirty chunks", "dirty pages", "published MiB", "flush ms", "ms per pub MiB", "sha256 MiB/s"
    );
    for dirty_chunks in [1u64, 8, 16, 32, 48] {
        let mut samples = Vec::new();
        let mut published = 0u64;
        for repeat in 0..repeats {
            let env = env(volume_chunks, &format!("sparse-{dirty_chunks}-{repeat}"));
            let page = vec![0x5au8; PAGE as usize];
            for chunk in 0..dirty_chunks {
                env.engine
                    .write(chunk * CHUNK, &page)
                    .expect("dirty one page");
            }
            let started = Instant::now();
            env.engine.flush().expect("flush");
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            published = env.published.data_bytes.load(Ordering::SeqCst);
            env.engine.detach();
        }
        samples.sort_by(f64::total_cmp);
        let flush_ms = samples[samples.len() / 2];
        let published_mib = published as f64 / (1024.0 * 1024.0);

        // How fast can this machine hash the published bytes? If hashing is a
        // small fraction of the flush, the copy and the writes dominate.
        let image = vec![0x5au8; published as usize];
        let started = Instant::now();
        let mut offset = 0usize;
        while offset < image.len() {
            let end = (offset + PAGE as usize).min(image.len());
            let _ = format::sha256(&image[offset..end]);
            offset = end;
        }
        let hash_mib_s = published_mib / started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);

        println!(
            "{:>12} {:>12} {:>14.2} {:>12.1} {:>16.2} {:>14.0}",
            dirty_chunks,
            dirty_chunks,
            published_mib,
            flush_ms,
            flush_ms / published_mib.max(f64::MIN_POSITIVE),
            hash_mib_s
        );
    }
}

/// Dense writes still publish full 4 MiB bases, so this is the shape delta packs
/// deliberately do not change.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn flush_cost_for_dense_writes() {
    let volume_chunks = 64;
    let repeats = 3;
    println!(
        "\n{:>12} {:>14} {:>12} {:>16}",
        "dirty chunks", "published MiB", "flush ms", "ms per pub MiB"
    );
    for dirty_chunks in [8u64, 32, 48] {
        let mut samples = Vec::new();
        let mut published = 0u64;
        for repeat in 0..repeats {
            let env = env(volume_chunks, &format!("dense-{dirty_chunks}-{repeat}"));
            let whole = vec![0xa5u8; CHUNK as usize];
            for chunk in 0..dirty_chunks {
                env.engine
                    .write(chunk * CHUNK, &whole)
                    .expect("dirty a whole chunk");
            }
            let started = Instant::now();
            env.engine.flush().expect("flush");
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            published = env.published.data_bytes.load(Ordering::SeqCst);
            env.engine.detach();
        }
        samples.sort_by(f64::total_cmp);
        let flush_ms = samples[samples.len() / 2];
        let published_mib = published as f64 / (1024.0 * 1024.0);
        println!(
            "{:>12} {:>14.2} {:>12.1} {:>16.2}",
            dirty_chunks,
            published_mib,
            flush_ms,
            flush_ms / published_mib
        );
    }
}

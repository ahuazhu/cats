//! What a FLUSH actually spends its time on.
//!
//! Guest workloads on real hardware stall for hundreds of milliseconds per FLUSH
//! (evidence: experiments/vhost-user-blk-frontend-20260726). The commit protocol
//! copies every dirty 4 MiB chunk under an exclusive barrier, hashes it, writes a
//! pending pack and uploads the objects, so the cost scales with the dirty set.
//! This measures the whole FLUSH and its parts against the dirty-chunk count so
//! an optimization can be aimed at the part that dominates.
//!
//! Ignored by default; run with
//! `cargo test --release -p cats-blockd --test commit_cost -- --ignored --nocapture`.

use std::sync::Arc;
use std::time::Instant;

use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_blockd::format;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_storage::MetadataStore;

const CHUNK: u64 = cats_api::chunk::CHUNK_SIZE as u64;
const PAGE: u64 = cats_api::chunk::DIRTY_PAGE_SIZE as u64;

struct Env {
    _dir: tempfile::TempDir,
    engine: Arc<ChunkEngine>,
}

fn env(chunks: u64) -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).expect("blob"));
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).expect("meta"));
    meta.create_volume("vol_commit", chunks * CHUNK).expect("volume");
    let engine = ChunkEngine::attach(
        EngineConfig::new("vol_commit", dir.path().join("data"), "att-commit"),
        blob,
        meta,
    )
    .expect("attach");
    Env { _dir: dir, engine }
}

#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn flush_cost_scales_with_the_dirty_set() {
    let volume_chunks = 64;
    println!(
        "\n{:>12} {:>10} {:>12} {:>14} {:>16}",
        "dirty chunks", "pack MiB", "flush ms", "ms per MiB", "sha256 MiB/s"
    );
    let repeats = 3;
    for dirty_chunks in [1u64, 8, 16, 32, 48] {
        // Median of a few samples: a single flush on a shared machine is noisy
        // enough to invert the smallest point.
        let mut samples = Vec::new();
        for _ in 0..repeats {
            let env = env(volume_chunks);
            // Touch one 64 KiB page in each of `dirty_chunks` chunks: exactly the
            // shape a 4 KiB random-write Guest workload produces, where a tiny
            // write dirties a whole chunk.
            let page = vec![0x5au8; PAGE as usize];
            for chunk in 0..dirty_chunks {
                env.engine
                    .write(chunk * CHUNK, &page)
                    .expect("dirty one page");
            }
            let started = Instant::now();
            env.engine.flush().expect("flush");
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            env.engine.detach();
        }
        samples.sort_by(f64::total_cmp);
        let flush_ms = samples[samples.len() / 2];
        let pack_mib = (dirty_chunks * CHUNK) as f64 / (1024.0 * 1024.0);

        // How fast can this machine hash the same bytes? If hashing is a small
        // fraction of the flush, the copy and the writes dominate.
        let image = vec![0x5au8; (dirty_chunks * CHUNK) as usize];
        let started = Instant::now();
        let mut offset = 0usize;
        while offset < image.len() {
            let _ = format::sha256(&image[offset..offset + CHUNK as usize]);
            offset += CHUNK as usize;
        }
        let hash_mib_s = pack_mib / started.elapsed().as_secs_f64();

        println!(
            "{:>12} {:>10.0} {:>12.1} {:>14.2} {:>16.0}",
            dirty_chunks, pack_mib, flush_ms, flush_ms / pack_mib, hash_mib_s
        );
    }
}

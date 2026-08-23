//! Shared base images — "golden roots" (ADR-0017, spec §6.3).
//!
//! Every Cat starts from the same rootfs, and before this module every Cat also
//! uploaded its own private copy of it: `create` streamed the image through the
//! block frontend, dirtied every chunk, and committed a few hundred MiB that were
//! byte-identical to what the previous create had committed. On S3 that is the
//! dominant cost of a cold create.
//!
//! An image is instead published **once** into its own namespace, keyed by the
//! digest of the image file, with each chunk keyed by the digest of the chunk. A
//! volume is then provisioned by writing a Map that references those objects, so
//! provisioning moves zero data bytes. `ChunkRef` carries the image a base came
//! from (`format::BaseRef::image`), so a read knows which namespace to fetch from
//! and a write publishes only the page it touched — the shared base stays shared.
//!
//! Two properties make this safe to do concurrently and repeatedly:
//!
//! * The image id is the digest of the file, so any node computes the same id for
//!   the same image and publishing it twice writes identical bytes to identical
//!   keys, which `BlobStore::put_immutable` defines as a no-op.
//! * The manifest is written **last**. A reader that finds the manifest knows
//!   every object it names is already durable, so a publish interrupted halfway
//!   leaves unreferenced objects rather than a referenceable-but-incomplete image.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use cats_api::chunk::{self, CHUNK_SIZE};
use cats_api::runtime_reconciliation::Sha256Digest;
use cats_storage::{
    encode_image_manifest, read_image_manifest, BlobError, BlobStore, ImageManifestReadError,
    LowerHexSha256,
};
use sha2::Digest;

use crate::format::{self, ImageChunk, ImageManifest, FORMAT_VERSION};

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("image {0} is empty")]
    Empty(String),
    #[error("image {path} is not usable: {message}")]
    Invalid { path: String, message: String },
    #[error(transparent)]
    Blob(#[from] cats_storage::BlobError),
    #[error("image i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("image manifest for {0} is corrupt")]
    Corrupt(String),
}

pub type Result<T> = std::result::Result<T, ImageError>;

/// What a publish did, so callers can report whether it moved any bytes.
#[derive(Debug, Clone)]
pub struct Published {
    pub manifest: ImageManifest,
    /// True when the manifest was already there and nothing was uploaded.
    pub already_present: bool,
    pub objects_written: usize,
    pub bytes_written: u64,
}

/// How many of an image's chunks to publish at once. Same reasoning as the commit
/// path's `MAX_UPLOAD_CONCURRENCY`: this is round-trip latency, not CPU.
fn publish_workers(objects: usize) -> usize {
    objects.clamp(1, 16)
}

/// Scan an image file into the chunk list that describes it.
///
/// Chunks are content-addressed and all-zero chunks are dropped, so a sparse
/// image publishes only the chunks it actually uses and an image containing the
/// same chunk twice stores it once.
pub(crate) fn scan(path: &Path) -> Result<(String, ImageManifest, Vec<u64>)> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Err(ImageError::Empty(path.display().to_string()));
    }
    // The tail chunk is zero-padded: a volume is chunk-aligned, so the bytes past
    // the image read as zeros either way, and every base object staying exactly
    // one chunk keeps the layering rules in the engine uniform.
    let size_bytes = chunk::round_up_to_chunk(file_len);
    let chunk_count = size_bytes / CHUNK_SIZE as u64;

    let mut file_digest = sha2::Sha256::new();
    let mut chunks = Vec::new();
    let mut offsets = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    for chunk_idx in 0..chunk_count {
        let at = chunk_idx * CHUNK_SIZE as u64;
        let want = (file_len - at).min(CHUNK_SIZE as u64) as usize;
        buf[want..].fill(0);
        file.read_exact_at(&mut buf[..want], at)?;
        // Hash the file as the user gave it to us, not the padding: the id then
        // matches `sha256sum` on the image, which is what an operator can check.
        file_digest.update(&buf[..want]);
        if buf.iter().all(|b| *b == 0) {
            continue;
        }
        let object_id = hex::encode(format::sha256(&buf));
        chunks.push(ImageChunk {
            chunk_idx,
            object_id: LowerHexSha256::new(object_id).ok_or_else(|| ImageError::Invalid {
                path: path.display().to_string(),
                message: "computed chunk digest was not lowercase SHA-256".into(),
            })?,
            len: CHUNK_SIZE,
        });
        offsets.push(at);
    }
    let image_id = hex::encode(file_digest.finalize());
    let manifest = ImageManifest {
        version: FORMAT_VERSION,
        image_id: LowerHexSha256::new(image_id.clone()).ok_or_else(|| ImageError::Invalid {
            path: path.display().to_string(),
            message: "computed image digest was not lowercase SHA-256".into(),
        })?,
        size_bytes,
        chunks,
    };
    Ok((image_id, manifest, offsets))
}

/// Publish `path` as a shared base image, or return the existing one.
pub fn publish(blob: &dyn BlobStore, path: &Path) -> Result<Published> {
    let (image_id, manifest, offsets) = scan(path)?;

    if blob.exists(&chunk::keys::image_manifest(&image_id))? {
        // Already published — by an earlier launch, or by another node. Trust the
        // stored manifest rather than the freshly scanned one so a reader and a
        // writer of the same image can never disagree about what it contains.
        return Ok(Published {
            manifest: load(blob, &image_id)?,
            already_present: true,
            objects_written: 0,
            bytes_written: 0,
        });
    }

    // Concurrently: an image is hundreds of objects, and against a remote store
    // each one is an `exists` plus a `put` round trip. Publishing 512 MiB serially
    // took 8.3 s on S3, which landed on whichever launch published first.
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    // One upload per distinct content, not per chunk: an image that repeats a
    // chunk stores it once, and deduplicating here rather than relying on an
    // `exists` check makes that true whatever order the workers run in.
    let mut seen = std::collections::HashSet::new();
    let work: Vec<(&ImageChunk, u64)> = manifest
        .chunks
        .iter()
        .zip(offsets)
        .filter(|(chunk, _)| seen.insert(chunk.object_id.as_str()))
        .collect();
    let next = AtomicUsize::new(0);
    let objects_written = AtomicUsize::new(0);
    let bytes_written = AtomicU64::new(0);
    let failure: std::sync::Mutex<Option<ImageError>> = std::sync::Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..publish_workers(work.len()) {
            scope.spawn(|| {
                // Per-thread buffer; the file itself is shared, which is safe
                // because every read is positional.
                let mut buf = vec![0u8; CHUNK_SIZE as usize];
                loop {
                    if failure.lock().unwrap().is_some() {
                        return;
                    }
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((chunk, at)) = work.get(index) else {
                        return;
                    };
                    let result = (|| -> Result<bool> {
                        let key = chunk::keys::image_data(&image_id, chunk.object_id.as_str());
                        if blob.exists(&key)? {
                            return Ok(false);
                        }
                        let want = (file_len - at).min(CHUNK_SIZE as u64) as usize;
                        buf[want..].fill(0);
                        file.read_exact_at(&mut buf[..want], *at)?;
                        if hex::encode(format::sha256(&buf)) != chunk.object_id.as_str() {
                            // The file changed under us between the scan and the
                            // upload; the manifest would name the wrong bytes.
                            return Err(ImageError::Invalid {
                                path: path.display().to_string(),
                                message: "image file changed while it was being published".into(),
                            });
                        }
                        blob.put_immutable(&key, &buf)?;
                        Ok(true)
                    })();
                    match result {
                        Ok(true) => {
                            objects_written.fetch_add(1, Ordering::Relaxed);
                            bytes_written.fetch_add(CHUNK_SIZE as u64, Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(error) => {
                            let mut slot = failure.lock().unwrap();
                            if slot.is_none() {
                                *slot = Some(error);
                            }
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(error) = failure.into_inner().unwrap() {
        return Err(error);
    }
    let objects_written = objects_written.into_inner();
    let bytes_written = bytes_written.into_inner();

    // Last: the manifest is what makes the image referenceable.
    blob.put_immutable(
        &chunk::keys::image_manifest(&image_id),
        &encode_image_manifest(&manifest).map_err(|_| ImageError::Corrupt(image_id.clone()))?,
    )?;
    Ok(Published {
        manifest,
        already_present: false,
        objects_written,
        bytes_written,
    })
}

pub fn load(blob: &dyn BlobStore, image_id: &str) -> Result<ImageManifest> {
    let digest = Sha256Digest::new(format!("sha256:{image_id}"))
        .ok_or_else(|| ImageError::Corrupt(image_id.to_string()))?;
    read_image_manifest(blob, &digest).map_err(|error| match error {
        ImageManifestReadError::NotFound { key } => ImageError::Blob(BlobError::NotFound(key)),
        ImageManifestReadError::BackendUnavailable { key } => {
            ImageError::Blob(BlobError::Backend {
                key,
                message: "image manifest backend unavailable".into(),
            })
        }
        ImageManifestReadError::TooLarge { .. } | ImageManifestReadError::Corrupt { .. } => {
            ImageError::Corrupt(image_id.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_object_store_file::FileBlobStore;
    use std::io::Write;
    use std::sync::Arc;

    fn image_file(dir: &Path, chunks: &[u8]) -> std::path::PathBuf {
        let path = dir.join(format!("img-{}.raw", chunks.len()));
        let mut f = File::create(&path).unwrap();
        for byte in chunks {
            f.write_all(&vec![*byte; CHUNK_SIZE as usize]).unwrap();
        }
        f.sync_all().unwrap();
        path
    }

    fn store(dir: &Path) -> Arc<dyn BlobStore> {
        Arc::new(FileBlobStore::open(dir.join("blob")).unwrap())
    }

    #[test]
    fn publishing_is_idempotent_and_the_second_publish_uploads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let blob = store(dir.path());
        let path = image_file(dir.path(), &[1, 2, 3]);

        let first = publish(blob.as_ref(), &path).unwrap();
        assert!(!first.already_present);
        assert_eq!(first.objects_written, 3);
        assert_eq!(first.bytes_written, 3 * CHUNK_SIZE as u64);

        let second = publish(blob.as_ref(), &path).unwrap();
        assert!(second.already_present);
        assert_eq!(second.objects_written, 0);
        assert_eq!(second.bytes_written, 0);
        assert_eq!(second.manifest.image_id, first.manifest.image_id);

        // The id is the digest of the file, so an operator can verify it, and any
        // node publishing the same image lands on the same namespace.
        assert_eq!(
            first.manifest.image_id.as_str(),
            hex::encode(format::sha256(&std::fs::read(&path).unwrap()))
        );
    }

    #[test]
    fn identical_chunks_and_zero_chunks_are_not_stored_twice_or_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let blob = store(dir.path());
        // Two identical non-zero chunks around one all-zero chunk.
        let path = image_file(dir.path(), &[7, 0, 7]);

        let published = publish(blob.as_ref(), &path).unwrap();
        // Chunk 1 is a hole; chunks 0 and 2 share one content-addressed object.
        assert_eq!(published.manifest.chunks.len(), 2);
        assert_eq!(published.objects_written, 1);
        assert_eq!(
            published.manifest.chunks[0].object_id,
            published.manifest.chunks[1].object_id
        );
        assert_eq!(
            blob.list(&format!("images/{}/data/", published.manifest.image_id))
                .unwrap()
                .len(),
            1
        );

        let map = format::image_base_map(&published.manifest, 3 * CHUNK_SIZE as u64).unwrap();
        assert!(matches!(map[1], crate::format::ChunkRef::Hole));
        assert_eq!(map[0].image(), Some(published.manifest.image_id.as_str()));
    }

    #[test]
    fn a_tail_shorter_than_a_chunk_is_padded_rather_than_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let blob = store(dir.path());
        let path = dir.path().join("short.raw");
        let mut f = File::create(&path).unwrap();
        f.write_all(&vec![9u8; CHUNK_SIZE as usize + 4096]).unwrap();
        f.sync_all().unwrap();

        let published = publish(blob.as_ref(), &path).unwrap();
        assert_eq!(published.manifest.size_bytes, 2 * CHUNK_SIZE as u64);
        assert_eq!(published.manifest.chunks.len(), 2);
        // Both objects are full chunks; the tail one is zero-padded, and its
        // content hash is the hash of the padded bytes so a read verifies.
        for chunk in &published.manifest.chunks {
            assert_eq!(chunk.len, CHUNK_SIZE);
            let bytes = blob
                .get(&chunk::keys::image_data(
                    published.manifest.image_id.as_str(),
                    chunk.object_id.as_str(),
                ))
                .unwrap();
            assert_eq!(bytes.len(), CHUNK_SIZE as usize);
            assert_eq!(
                hex::encode(format::sha256(&bytes)),
                chunk.object_id.as_str()
            );
        }
    }

    #[test]
    fn an_image_is_only_referenceable_once_its_manifest_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let blob = store(dir.path());
        let path = image_file(dir.path(), &[4]);
        let published = publish(blob.as_ref(), &path).unwrap();

        // Simulate a publish that died before the manifest: the data object is
        // there, but nothing can reference it.
        blob.delete(&chunk::keys::image_manifest(
            published.manifest.image_id.as_str(),
        ))
        .unwrap();
        assert!(load(blob.as_ref(), published.manifest.image_id.as_str()).is_err());

        // Re-publishing finishes the job without re-uploading the data.
        let again = publish(blob.as_ref(), &path).unwrap();
        assert!(!again.already_present);
        assert_eq!(again.objects_written, 0);
        assert!(load(blob.as_ref(), published.manifest.image_id.as_str()).is_ok());
    }

    #[test]
    fn an_empty_file_is_rejected_rather_than_published_as_an_empty_image() {
        let dir = tempfile::tempdir().unwrap();
        let blob = store(dir.path());
        let path = dir.path().join("empty.raw");
        File::create(&path).unwrap();
        assert!(matches!(
            publish(blob.as_ref(), &path),
            Err(ImageError::Empty(_))
        ));
    }
}

//! Immutable object stores (spec §2). Production backend is S3 (`s3.rs`);
//! `FileBlobStore` is the dev/test backend with identical semantics.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("blob io error on {key}: {source}")]
    Io {
        key: String,
        #[source]
        source: std::io::Error,
    },
    #[error("blob backend error on {key}: {message}")]
    Backend { key: String, message: String },
}

pub type Result<T> = std::result::Result<T, BlobError>;

/// Immutable object store. Objects are written once; a repeated
/// `put_immutable` with the same key must carry identical bytes and is a
/// no-op. `delete` exists only for GC.
pub trait BlobStore: Send + Sync {
    fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()>;
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn exists(&self, key: &str) -> Result<bool>;
    fn delete(&self, key: &str) -> Result<()>;
    /// List keys under a prefix (GC and tests).
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Filesystem-backed blob store: `<root>/<key>` with atomic tmp+rename PUT.
pub struct FileBlobStore {
    root: PathBuf,
    tmp_seq: AtomicU64,
}

impl FileBlobStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| BlobError::Io {
            key: root.display().to_string(),
            source: e,
        })?;
        Ok(Self {
            root,
            tmp_seq: AtomicU64::new(0),
        })
    }

    fn path_for(&self, key: &str) -> PathBuf {
        // Keys are forward-slash paths controlled by our own code; reject
        // anything that could escape the root.
        assert!(
            !key.split('/').any(|seg| seg == ".." || seg.is_empty()),
            "malformed blob key: {key}"
        );
        self.root.join(key)
    }

    fn io_err(key: &str, source: std::io::Error) -> BlobError {
        BlobError::Io {
            key: key.to_string(),
            source,
        }
    }
}

impl BlobStore for FileBlobStore {
    fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.path_for(key);
        if path.exists() {
            // Immutability: same key must mean same content.
            let existing = fs::read(&path).map_err(|e| Self::io_err(key, e))?;
            if existing == data {
                return Ok(());
            }
            return Err(BlobError::Backend {
                key: key.to_string(),
                message: "immutable object overwrite with different content".into(),
            });
        }
        let parent = path.parent().expect("key has parent");
        fs::create_dir_all(parent).map_err(|e| Self::io_err(key, e))?;
        let tmp = parent.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            self.tmp_seq.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| Self::io_err(key, e))?;
            f.write_all(data).map_err(|e| Self::io_err(key, e))?;
            f.sync_data().map_err(|e| Self::io_err(key, e))?;
        }
        fs::rename(&tmp, &path).map_err(|e| Self::io_err(key, e))?;
        // Persist the rename itself.
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        match fs::read(self.path_for(key)) {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(BlobError::NotFound(key.to_string())),
            Err(e) => Err(Self::io_err(key, e)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path_for(key).exists())
    }

    fn delete(&self, key: &str) -> Result<()> {
        match fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Self::io_err(key, e)),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(Self::io_err(prefix, e)),
            };
            for entry in entries {
                let entry = entry.map_err(|e| Self::io_err(prefix, e))?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&self.root) {
                    let key = rel
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/");
                    if key.starts_with(prefix)
                        && !Path::new(&key)
                            .file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with(".tmp-"))
                    {
                        out.push(key);
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Test helper: wraps a store and fails operations on demand.
pub struct FaultyBlobStore {
    pub inner: Arc<dyn BlobStore>,
    /// Fail the next N put calls with a retryable backend error.
    pub fail_puts: AtomicU64,
}

impl FaultyBlobStore {
    pub fn new(inner: Arc<dyn BlobStore>) -> Self {
        Self {
            inner,
            fail_puts: AtomicU64::new(0),
        }
    }
}

impl BlobStore for FaultyBlobStore {
    fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()> {
        loop {
            let n = self.fail_puts.load(Ordering::SeqCst);
            if n == 0 {
                break;
            }
            if self
                .fail_puts
                .compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Err(BlobError::Backend {
                    key: key.to_string(),
                    message: "injected put failure".into(),
                });
            }
        }
        self.inner.put_immutable(key, data)
    }
    fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.inner.get(key)
    }
    fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_roundtrip_and_immutability() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileBlobStore::open(dir.path()).unwrap();
        store.put_immutable("volumes/v1/data/a", b"hello").unwrap();
        assert_eq!(store.get("volumes/v1/data/a").unwrap(), b"hello");
        assert!(store.exists("volumes/v1/data/a").unwrap());
        // Idempotent same-content put.
        store.put_immutable("volumes/v1/data/a", b"hello").unwrap();
        // Different content is rejected.
        assert!(store.put_immutable("volumes/v1/data/a", b"other").is_err());
        assert!(matches!(
            store.get("volumes/v1/data/missing"),
            Err(BlobError::NotFound(_))
        ));
        store.put_immutable("volumes/v1/maps/x.node", b"n").unwrap();
        assert_eq!(
            store.list("volumes/v1/").unwrap(),
            vec![
                "volumes/v1/data/a".to_string(),
                "volumes/v1/maps/x.node".to_string()
            ]
        );
        store.delete("volumes/v1/data/a").unwrap();
        assert!(!store.exists("volumes/v1/data/a").unwrap());
        // Deleting a missing key is fine (GC idempotency).
        store.delete("volumes/v1/data/a").unwrap();
    }

    #[test]
    fn faulty_store_injects_put_failures() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Arc::new(FileBlobStore::open(dir.path()).unwrap());
        let faulty = FaultyBlobStore::new(inner);
        faulty.fail_puts.store(1, Ordering::SeqCst);
        assert!(faulty.put_immutable("k", b"v").is_err());
        faulty.put_immutable("k", b"v").unwrap();
        assert_eq!(faulty.get("k").unwrap(), b"v");
    }
}

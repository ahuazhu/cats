//! Contract for immutable remote objects.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("invalid object key {key:?}: {message}")]
    InvalidKey { key: String, message: String },
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

/// Validate the portable key subset shared by every blob-store adapter.
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.starts_with('/')
        || key
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(BlobError::InvalidKey {
            key: key.to_string(),
            message: "expected a non-empty relative slash-separated key".into(),
        });
    }
    Ok(())
}

/// Immutable object store contract.
///
/// Objects are written once. Repeating `put_immutable` with the same key and
/// bytes is a no-op; attempting to reuse a key for different bytes must fail.
/// `delete` exists only for garbage collection and must be idempotent.
pub trait BlobStore: Send + Sync {
    fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()>;
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn exists(&self, key: &str) -> Result<bool>;
    fn delete(&self, key: &str) -> Result<()>;
    /// Return sorted keys below `prefix`.
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Provider-neutral fault decorator used by crash and retry tests.
pub struct FaultyBlobStore {
    pub inner: Arc<dyn BlobStore>,
    /// Fail the next N immutable writes with a retryable backend error.
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
            let remaining = self.fail_puts.load(Ordering::SeqCst);
            if remaining == 0 {
                break;
            }
            if self
                .fail_puts
                .compare_exchange(remaining, remaining - 1, Ordering::SeqCst, Ordering::SeqCst)
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

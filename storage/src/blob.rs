//! Contract for immutable remote objects.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

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
    #[error(
        "object {key} exceeds the {maximum}-byte read limit (observed at least {observed_at_least})"
    )]
    TooLarge {
        key: String,
        maximum: usize,
        observed_at_least: usize,
    },
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
    /// Read at most `maximum` bytes.
    ///
    /// This conservative default bounds the returned allocation, but an
    /// adapter must override it before claiming production resource bounds: a
    /// default implementation may have buffered the complete object in `get`.
    fn get_bounded(&self, key: &str, maximum: usize) -> Result<Vec<u8>> {
        let bytes = self.get(key)?;
        if bytes.len() > maximum {
            return Err(BlobError::TooLarge {
                key: key.to_string(),
                maximum,
                observed_at_least: bytes.len(),
            });
        }
        Ok(bytes)
    }
    /// A bounded read whose transport and retry budget must finish by
    /// `deadline`. Production adapters override this together with
    /// `get_bounded`; the default only provides fail-closed result semantics.
    fn get_bounded_until(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(BlobError::Backend {
                key: key.to_string(),
                message: "bounded read deadline elapsed".into(),
            });
        }
        let bytes = self.get_bounded(key, maximum)?;
        if Instant::now() > deadline {
            return Err(BlobError::Backend {
                key: key.to_string(),
                message: "bounded read deadline elapsed".into(),
            });
        }
        Ok(bytes)
    }
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

    fn get_bounded(&self, key: &str, maximum: usize) -> Result<Vec<u8>> {
        self.inner.get_bounded(key, maximum)
    }

    fn get_bounded_until(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Vec<u8>> {
        self.inner.get_bounded_until(key, maximum, deadline)
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

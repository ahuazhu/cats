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

/// One bounded page from the beginning of an exact object prefix.
///
/// Delete reconciliation deliberately does not expose provider continuation
/// tokens.  It deletes this page and then lists from the beginning again, so
/// an interrupted pass never persists provider-specific cursor state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobListPage {
    pub keys: Vec<String>,
    pub is_truncated: bool,
}

/// One bounded LIST result whose adapter contract guarantees a fresh,
/// linearizable view after DELETE.
///
/// This capability is deliberately distinct from [`BlobListPage`]. An
/// eventually-consistent or otherwise unqualified adapter may support normal
/// listing, but it cannot authorize a destructive reconciliation receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedDeleteListPage {
    page: BlobListPage,
}

impl QualifiedDeleteListPage {
    /// Stamp a page only when the adapter's provider contract guarantees
    /// strong read-after-delete and LIST consistency for the exact prefix.
    pub fn from_strongly_consistent_adapter(page: BlobListPage) -> Self {
        Self { page }
    }

    pub fn into_page(self) -> BlobListPage {
        self.page
    }
}

pub const BLOB_LIST_PAGE_MAX_KEYS: usize = 1_000;

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
    /// Idempotent delete bounded by one caller-owned absolute deadline.
    /// Production adapters override this so transport, credential refresh,
    /// retries and response reads all share that deadline.
    fn delete_until(&self, key: &str, deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            return Err(deadline_error(key, "delete"));
        }
        self.delete(key)?;
        if Instant::now() > deadline {
            return Err(deadline_error(key, "delete"));
        }
        Ok(())
    }
    /// Return sorted keys below `prefix`.
    fn list(&self, prefix: &str) -> Result<Vec<String>>;

    /// Return at most `maximum` sorted keys from the beginning of `prefix`.
    ///
    /// Adapters must override this method so the provider response and local
    /// allocation are genuinely bounded. The default fails closed instead of
    /// implementing a misleading `list`-then-truncate allocation.
    fn list_bounded(&self, prefix: &str, maximum: usize) -> Result<BlobListPage> {
        validate_list_maximum(prefix, maximum)?;
        Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "blob adapter does not implement a resource-bounded LIST".into(),
        })
    }

    /// Return at most `maximum` sorted keys below `prefix` and strictly after
    /// `after_key`.
    ///
    /// The cursor is the last provider-neutral object key returned to the
    /// caller, not an opaque provider continuation token. This makes a full
    /// non-destructive scan restartable without leaking an adapter's wire
    /// protocol. Adapters must override this method before callers rely on
    /// cursor pagination. The compatibility default supports only the first
    /// page through an existing `list_bounded` implementation and fails
    /// closed for a continuation page.
    fn list_after_bounded(
        &self,
        prefix: &str,
        after_key: Option<&str>,
        maximum: usize,
    ) -> Result<BlobListPage> {
        validate_list_after(prefix, after_key)?;
        validate_list_maximum(prefix, maximum)?;
        if after_key.is_some() {
            return Err(BlobError::Backend {
                key: prefix.to_string(),
                message: "blob adapter does not implement resource-bounded cursor LIST".into(),
            });
        }
        let page = self.list_bounded(prefix, maximum)?;
        validate_list_page(prefix, after_key, maximum, &page)?;
        Ok(page)
    }

    /// Destructive, strongly-consistent bounded LIST under one absolute
    /// deadline. The default is intentionally unqualified: normal LIST
    /// support is not evidence that an empty result may settle deletion.
    fn list_for_delete_bounded_until(
        &self,
        prefix: &str,
        _maximum: usize,
        _deadline: Instant,
    ) -> Result<QualifiedDeleteListPage> {
        Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "blob adapter is not qualified for destructive LIST consistency".into(),
        })
    }
}

fn deadline_error(key: &str, operation: &str) -> BlobError {
    BlobError::Backend {
        key: key.to_string(),
        message: format!("{operation} deadline elapsed"),
    }
}

pub fn validate_list_maximum(prefix: &str, maximum: usize) -> Result<()> {
    if !(1..=BLOB_LIST_PAGE_MAX_KEYS).contains(&maximum) {
        return Err(BlobError::InvalidKey {
            key: prefix.to_string(),
            message: format!("list page maximum must be in 1..={BLOB_LIST_PAGE_MAX_KEYS}"),
        });
    }
    Ok(())
}

/// Validate the provider-neutral exclusive LIST cursor.
pub fn validate_list_after(prefix: &str, after_key: Option<&str>) -> Result<()> {
    validate_list_result(prefix, &[])?;
    let Some(after_key) = after_key else {
        return Ok(());
    };
    validate_key(after_key)?;
    if !after_key.starts_with(prefix) {
        return Err(BlobError::InvalidKey {
            key: after_key.to_string(),
            message: format!("LIST cursor is outside the requested prefix {prefix:?}"),
        });
    }
    Ok(())
}

pub fn validate_list_result(prefix: &str, keys: &[String]) -> Result<()> {
    if prefix.is_empty() || prefix.starts_with('/') {
        return Err(BlobError::InvalidKey {
            key: prefix.to_string(),
            message: "expected a non-empty relative prefix".into(),
        });
    }
    for key in keys {
        validate_key(key)?;
        if !key.starts_with(prefix) {
            return Err(BlobError::Backend {
                key: prefix.to_string(),
                message: format!("LIST returned key outside the requested prefix: {key}"),
            });
        }
    }
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "LIST keys are not in strictly increasing lexical order".into(),
        });
    }
    Ok(())
}

/// Validate one bounded, strictly ordered, exclusive LIST page.
pub fn validate_list_page(
    prefix: &str,
    after_key: Option<&str>,
    maximum: usize,
    page: &BlobListPage,
) -> Result<()> {
    validate_list_after(prefix, after_key)?;
    validate_list_maximum(prefix, maximum)?;
    if page.keys.len() > maximum {
        return Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "bounded LIST exceeded its requested key count".into(),
        });
    }
    if page.keys.is_empty() && page.is_truncated {
        return Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "bounded LIST claimed an empty truncated page".into(),
        });
    }
    validate_list_result(prefix, &page.keys)?;
    if after_key.is_some_and(|after_key| page.keys.iter().any(|key| key.as_str() <= after_key)) {
        return Err(BlobError::Backend {
            key: prefix.to_string(),
            message: "cursor LIST returned a key at or before its exclusive cursor".into(),
        });
    }
    Ok(())
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

    fn delete_until(&self, key: &str, deadline: Instant) -> Result<()> {
        self.inner.delete_until(key, deadline)
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix)
    }

    fn list_bounded(&self, prefix: &str, maximum: usize) -> Result<BlobListPage> {
        self.inner.list_bounded(prefix, maximum)
    }

    fn list_after_bounded(
        &self,
        prefix: &str,
        after_key: Option<&str>,
        maximum: usize,
    ) -> Result<BlobListPage> {
        self.inner.list_after_bounded(prefix, after_key, maximum)
    }

    fn list_for_delete_bounded_until(
        &self,
        prefix: &str,
        maximum: usize,
        deadline: Instant,
    ) -> Result<QualifiedDeleteListPage> {
        self.inner
            .list_for_delete_bounded_until(prefix, maximum, deadline)
    }
}

//! Provider-neutral [`BlobStore`] decorators shared by storage-engine tests.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cats_storage::{BlobError, BlobListPage, BlobStore};

fn is_data_object(key: &str) -> bool {
    key.contains("/data/")
}

/// Adds independently configurable latency to object reads and writes.
pub struct SlowBlob {
    inner: Arc<dyn BlobStore>,
    get_delay: Duration,
    put_delay: Duration,
}

impl SlowBlob {
    pub fn new(inner: Arc<dyn BlobStore>) -> Self {
        Self {
            inner,
            get_delay: Duration::ZERO,
            put_delay: Duration::ZERO,
        }
    }

    pub fn with_get_delay(mut self, delay: Duration) -> Self {
        self.get_delay = delay;
        self
    }

    pub fn with_put_delay(mut self, delay: Duration) -> Self {
        self.put_delay = delay;
        self
    }
}

impl BlobStore for SlowBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        if !self.put_delay.is_zero() {
            std::thread::sleep(self.put_delay);
        }
        self.inner.put_immutable(key, data)
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        if !self.get_delay.is_zero() {
            std::thread::sleep(self.get_delay);
        }
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }

    fn list_after_bounded(
        &self,
        prefix: &str,
        after_key: Option<&str>,
        maximum: usize,
    ) -> cats_storage::blob::Result<BlobListPage> {
        self.inner.list_after_bounded(prefix, after_key, maximum)
    }
}

/// Counts all reads and volume/image data-object writes.
pub struct CountingBlob {
    inner: Arc<dyn BlobStore>,
    gets: AtomicU64,
    data_puts: AtomicU64,
}

impl CountingBlob {
    pub fn new(inner: Arc<dyn BlobStore>) -> Self {
        Self {
            inner,
            gets: AtomicU64::new(0),
            data_puts: AtomicU64::new(0),
        }
    }

    pub fn get_count(&self) -> u64 {
        self.gets.load(Ordering::SeqCst)
    }

    pub fn data_put_count(&self) -> u64 {
        self.data_puts.load(Ordering::SeqCst)
    }
}

impl BlobStore for CountingBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        if is_data_object(key) {
            self.data_puts.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.put_immutable(key, data)
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }

    fn list_after_bounded(
        &self,
        prefix: &str,
        after_key: Option<&str>,
        maximum: usize,
    ) -> cats_storage::blob::Result<BlobListPage> {
        self.inner.list_after_bounded(prefix, after_key, maximum)
    }
}

/// Counts bytes and objects published for private volumes separately from
/// shared golden images.
pub struct SizingBlob {
    inner: Arc<dyn BlobStore>,
    data_bytes: AtomicU64,
    data_objects: AtomicU64,
    image_bytes: AtomicU64,
}

impl SizingBlob {
    pub fn new(inner: Arc<dyn BlobStore>) -> Self {
        Self {
            inner,
            data_bytes: AtomicU64::new(0),
            data_objects: AtomicU64::new(0),
            image_bytes: AtomicU64::new(0),
        }
    }

    pub fn data_bytes(&self) -> u64 {
        self.data_bytes.load(Ordering::SeqCst)
    }

    pub fn data_objects(&self) -> u64 {
        self.data_objects.load(Ordering::SeqCst)
    }

    pub fn image_bytes(&self) -> u64 {
        self.image_bytes.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.data_bytes.store(0, Ordering::SeqCst);
        self.data_objects.store(0, Ordering::SeqCst);
        self.image_bytes.store(0, Ordering::SeqCst);
    }
}

impl BlobStore for SizingBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        if key.starts_with("images/") && is_data_object(key) {
            self.image_bytes
                .fetch_add(data.len() as u64, Ordering::SeqCst);
        } else if is_data_object(key) {
            self.data_bytes
                .fetch_add(data.len() as u64, Ordering::SeqCst);
            self.data_objects.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.put_immutable(key, data)
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }

    fn list_after_bounded(
        &self,
        prefix: &str,
        after_key: Option<&str>,
        maximum: usize,
    ) -> cats_storage::blob::Result<BlobListPage> {
        self.inner.list_after_bounded(prefix, after_key, maximum)
    }
}

/// Makes data-object operations slow enough to observe their peak concurrency.
pub struct ConcurrencyProbe {
    inner: Arc<dyn BlobStore>,
    delay: Duration,
    in_flight: AtomicU64,
    peak: AtomicU64,
    data_puts: AtomicU64,
}

impl ConcurrencyProbe {
    pub fn new(inner: Arc<dyn BlobStore>, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            in_flight: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            data_puts: AtomicU64::new(0),
        }
    }

    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::SeqCst)
    }

    pub fn data_put_count(&self) -> u64 {
        self.data_puts.load(Ordering::SeqCst)
    }

    pub fn reset_peak(&self) {
        self.peak.store(0, Ordering::SeqCst);
    }

    fn record<T>(&self, operation: impl FnOnce() -> T) -> T {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        let result = operation();
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

impl BlobStore for ConcurrencyProbe {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        if is_data_object(key) {
            self.data_puts.fetch_add(1, Ordering::SeqCst);
            return self.record(|| self.inner.put_immutable(key, data));
        }
        self.inner.put_immutable(key, data)
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        if is_data_object(key) {
            return self.record(|| self.inner.get(key));
        }
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }

    fn list_after_bounded(
        &self,
        prefix: &str,
        after_key: Option<&str>,
        maximum: usize,
    ) -> cats_storage::blob::Result<BlobListPage> {
        self.inner.list_after_bounded(prefix, after_key, maximum)
    }
}

/// Runtime-switchable read outage used to assert cold-cache boundaries.
pub struct SwitchableFailureBlob {
    inner: Arc<dyn BlobStore>,
    fail_gets: AtomicBool,
    gets: AtomicU64,
}

impl SwitchableFailureBlob {
    pub fn new(inner: Arc<dyn BlobStore>) -> Self {
        Self {
            inner,
            fail_gets: AtomicBool::new(false),
            gets: AtomicU64::new(0),
        }
    }

    pub fn set_fail_gets(&self, fail: bool) {
        self.fail_gets.store(fail, Ordering::SeqCst);
    }

    pub fn get_count(&self) -> u64 {
        self.gets.load(Ordering::SeqCst)
    }
}

impl BlobStore for SwitchableFailureBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        self.inner.put_immutable(key, data)
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        if self.fail_gets.load(Ordering::SeqCst) {
            return Err(BlobError::Backend {
                key: key.to_string(),
                message: "injected GET outage".into(),
            });
        }
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }

    fn list_after_bounded(
        &self,
        prefix: &str,
        after_key: Option<&str>,
        maximum: usize,
    ) -> cats_storage::blob::Result<BlobListPage> {
        self.inner.list_after_bounded(prefix, after_key, maximum)
    }
}

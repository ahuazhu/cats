//! Bounded Control Plane adapter for immutable golden-image manifests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::Sha256Digest;
use cats_storage::{read_image_manifest_until, BlobStore, ImageManifestReadError, ImageManifestV1};

use super::cat_create_service::{CatCreateManifestResolver, ServiceFuture, ValidatedImageManifest};

const MAX_ACTIVE_READS: usize = 2;
const MAX_QUEUED_READS: usize = 32;
const READ_DEADLINE: Duration = Duration::from_secs(10);

pub(crate) struct ImmutableImageManifestResolver {
    blob: Arc<dyn BlobStore>,
    active: Arc<tokio::sync::Semaphore>,
    queued: Arc<tokio::sync::Semaphore>,
    inflight: Arc<InflightReads>,
    read_deadline: Duration,
    #[cfg(test)]
    after_active_acquired: Option<Arc<TestReadHook>>,
}

#[cfg(test)]
#[derive(Default)]
struct TestReadHook {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[derive(Default)]
struct InflightReads {
    count: AtomicUsize,
    completed: tokio::sync::Notify,
}

impl InflightReads {
    fn start(self: &Arc<Self>) -> InflightReadGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        InflightReadGuard(self.clone())
    }

    async fn wait_until_idle(&self) {
        loop {
            // Register before observing the counter so a completion between
            // the two operations cannot become a lost wakeup.
            let completed = self.completed.notified();
            if self.count.load(Ordering::Acquire) == 0 {
                return;
            }
            completed.await;
        }
    }
}

struct InflightReadGuard(Arc<InflightReads>);

impl Drop for InflightReadGuard {
    fn drop(&mut self) {
        self.0.count.fetch_sub(1, Ordering::AcqRel);
        self.0.completed.notify_waiters();
    }
}

impl ImmutableImageManifestResolver {
    pub(crate) fn new(blob: Arc<dyn BlobStore>) -> Self {
        Self {
            blob,
            active: Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_READS)),
            queued: Arc::new(tokio::sync::Semaphore::new(MAX_QUEUED_READS)),
            inflight: Arc::new(InflightReads::default()),
            read_deadline: READ_DEADLINE,
            #[cfg(test)]
            after_active_acquired: None,
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        // Closing the queue rejects new work. Closing the active semaphore
        // wakes every queued waiter without revoking permits already owned by
        // synchronous reads; those permits remain held until provider I/O
        // returns within its absolute transport deadline.
        self.queued.close();
        self.active.close();
    }

    /// Reject new reads, clear queued reads, and wait no longer than the same
    /// absolute provider-I/O bound for already-active blocking reads to exit.
    /// A false result means a provider violated its deadline; callers may
    /// continue process shutdown and any eventual late result is discarded.
    pub(crate) async fn shutdown(&self) -> bool {
        self.begin_shutdown();
        tokio::time::timeout(self.read_deadline, self.inflight.wait_until_idle())
            .await
            .is_ok()
    }

    #[cfg(test)]
    fn with_deadline(blob: Arc<dyn BlobStore>, read_deadline: Duration) -> Self {
        let mut resolver = Self::new(blob);
        resolver.read_deadline = read_deadline;
        resolver
    }

    #[cfg(test)]
    fn with_active_hook(
        blob: Arc<dyn BlobStore>,
        read_deadline: Duration,
        hook: Arc<TestReadHook>,
    ) -> Self {
        let mut resolver = Self::with_deadline(blob, read_deadline);
        resolver.after_active_acquired = Some(hook);
        resolver
    }
}

impl CatCreateManifestResolver for ImmutableImageManifestResolver {
    fn resolve<'a>(
        &'a self,
        boot_image_digest: &'a Sha256Digest,
    ) -> ServiceFuture<'a, ValidatedImageManifest> {
        Box::pin(async move {
            // Register before any queue/active admission. Otherwise shutdown
            // could close both semaphores after an old request acquired its
            // active permit but before it registered provider I/O, observe
            // zero, and return while that request starts a blocking read.
            let inflight = self.inflight.start();
            let deadline = Instant::now() + self.read_deadline;
            // This permit is owned by the waiting future, so cancellation or a
            // timeout removes it from the queue immediately. No manifest body
            // is read or retained while waiting for an active slot.
            let queued = self
                .queued
                .clone()
                .try_acquire_owned()
                .map_err(|error| match error {
                    tokio::sync::TryAcquireError::Closed => {
                        ApiError::unavailable("image manifest reader is shutting down")
                    }
                    tokio::sync::TryAcquireError::NoPermits => {
                        ApiError::unavailable("image manifest read queue is full")
                    }
                })?;
            let active = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.active.clone().acquire_owned(),
            )
            .await
            .map_err(|_| ApiError::unavailable("image manifest read deadline elapsed"))?
            .map_err(|_| ApiError::unavailable("image manifest reader is shutting down"))?;
            drop(queued);

            #[cfg(test)]
            if let Some(hook) = &self.after_active_acquired {
                hook.reached.notify_one();
                hook.release.notified().await;
            }

            let blob = self.blob.clone();
            let digest = boot_image_digest.clone();
            let task = tokio::task::spawn_blocking(move || {
                // The active permit lives until synchronous provider I/O
                // actually returns. Timing out the HTTP future therefore
                // discards a late result without admitting replacement work
                // above the fixed two-read bound.
                let _active = active;
                let _inflight = inflight;
                read_image_manifest_until(blob.as_ref(), &digest, deadline)
            });
            let manifest = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task)
                .await
                .map_err(|_| ApiError::unavailable("image manifest read deadline elapsed"))?
                .map_err(|_| ApiError::internal("image manifest reader task failed"))?
                .map_err(map_read_error)?;
            to_validated(manifest, boot_image_digest)
        })
    }
}

fn to_validated(
    manifest: ImageManifestV1,
    expected: &Sha256Digest,
) -> crate::store::Result<ValidatedImageManifest> {
    let boot_image_digest = Sha256Digest::new(format!("sha256:{}", manifest.image_id.as_str()))
        .ok_or_else(|| ApiError::internal("validated image manifest lost its digest invariant"))?;
    if &boot_image_digest != expected {
        return Err(ApiError::internal(
            "image manifest reader returned a different digest",
        ));
    }
    Ok(ValidatedImageManifest {
        boot_image_digest,
        size_bytes: manifest.size_bytes,
    })
}

fn map_read_error(error: ImageManifestReadError) -> ApiError {
    match error {
        ImageManifestReadError::NotFound { .. } => ApiError::not_found("boot image"),
        ImageManifestReadError::TooLarge { .. } | ImageManifestReadError::Corrupt { .. } => {
            ApiError::failed_precondition("boot image manifest is invalid")
        }
        ImageManifestReadError::BackendUnavailable { .. } => {
            ApiError::unavailable("image manifest backend is unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Condvar;

    use cats_storage::{BlobError, IMAGE_MANIFEST_MAX_BYTES};

    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FIXED: &[u8] = b"{\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}";

    struct CountingBlob {
        reads: AtomicUsize,
    }

    impl BlobStore for CountingBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn get(&self, _key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            unreachable!()
        }

        fn get_bounded_until(
            &self,
            _key: &str,
            maximum: usize,
            _deadline: Instant,
        ) -> cats_storage::blob::Result<Vec<u8>> {
            assert_eq!(maximum, IMAGE_MANIFEST_MAX_BYTES);
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(FIXED.to_vec())
        }

        fn exists(&self, _key: &str) -> cats_storage::blob::Result<bool> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn resolver_returns_only_the_validated_digest_and_size() {
        let blob = Arc::new(CountingBlob {
            reads: AtomicUsize::new(0),
        });
        let resolver = ImmutableImageManifestResolver::new(blob.clone());
        let digest = Sha256Digest::new(DIGEST).unwrap();
        let result = resolver.resolve(&digest).await.unwrap();
        assert_eq!(result.boot_image_digest, digest);
        assert_eq!(result.size_bytes, 4_194_304);
        assert_eq!(blob.reads.load(Ordering::SeqCst), 1);
    }

    struct ErrorBlob(BlobError);

    impl BlobStore for ErrorBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn get(&self, _key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            unreachable!()
        }

        fn get_bounded_until(
            &self,
            _key: &str,
            _maximum: usize,
            _deadline: Instant,
        ) -> cats_storage::blob::Result<Vec<u8>> {
            Err(match &self.0 {
                BlobError::NotFound(key) => BlobError::NotFound(key.clone()),
                BlobError::Backend { key, message } => BlobError::Backend {
                    key: key.clone(),
                    message: message.clone(),
                },
                _ => unreachable!(),
            })
        }

        fn exists(&self, _key: &str) -> cats_storage::blob::Result<bool> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn missing_and_backend_errors_remain_distinct() {
        let digest = Sha256Digest::new(DIGEST).unwrap();
        let missing = ImmutableImageManifestResolver::new(Arc::new(ErrorBlob(
            BlobError::NotFound("secret/provider/key".into()),
        )))
        .resolve(&digest)
        .await
        .unwrap_err();
        assert_eq!(missing.code, cats_api::error::ErrorCode::NotFound);
        assert!(!missing.message.contains("secret"));

        let unavailable =
            ImmutableImageManifestResolver::new(Arc::new(ErrorBlob(BlobError::Backend {
                key: "secret/provider/key".into(),
                message: "credential leaked".into(),
            })))
            .resolve(&digest)
            .await
            .unwrap_err();
        assert_eq!(unavailable.code, cats_api::error::ErrorCode::Unavailable);
        assert!(!unavailable.message.contains("credential"));
    }

    struct BlockingBlob {
        released: AtomicBool,
        changed: Condvar,
        lock: std::sync::Mutex<()>,
        active: AtomicUsize,
        maximum_active: AtomicUsize,
    }

    impl BlockingBlob {
        fn new() -> Self {
            Self {
                released: AtomicBool::new(false),
                changed: Condvar::new(),
                lock: std::sync::Mutex::new(()),
                active: AtomicUsize::new(0),
                maximum_active: AtomicUsize::new(0),
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.changed.notify_all();
        }
    }

    impl BlobStore for BlockingBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn get(&self, _key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            unreachable!()
        }

        fn get_bounded_until(
            &self,
            key: &str,
            maximum: usize,
            deadline: Instant,
        ) -> cats_storage::blob::Result<Vec<u8>> {
            assert_eq!(maximum, IMAGE_MANIFEST_MAX_BYTES);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum_active.fetch_max(active, Ordering::SeqCst);
            let mut guard = self.lock.lock().unwrap();
            while !self.released.load(Ordering::SeqCst) {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Err(BlobError::Backend {
                        key: key.to_string(),
                        message: "deadline".into(),
                    });
                };
                let (next, timeout) = self.changed.wait_timeout(guard, remaining).unwrap();
                guard = next;
                if timeout.timed_out() {
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Err(BlobError::Backend {
                        key: key.to_string(),
                        message: "deadline".into(),
                    });
                }
            }
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(FIXED.to_vec())
        }

        fn exists(&self, _key: &str) -> cats_storage::blob::Result<bool> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            unreachable!()
        }
    }

    async fn wait_until(mut predicate: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !predicate() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_queue_health_and_cancellation_stay_bounded() {
        let blob = Arc::new(BlockingBlob::new());
        let resolver = Arc::new(ImmutableImageManifestResolver::new(blob.clone()));
        let spawn_read = |resolver: Arc<ImmutableImageManifestResolver>| {
            tokio::spawn(async move {
                let digest = Sha256Digest::new(DIGEST).unwrap();
                resolver.resolve(&digest).await
            })
        };

        let active = [spawn_read(resolver.clone()), spawn_read(resolver.clone())];
        wait_until(|| blob.active.load(Ordering::SeqCst) == MAX_ACTIVE_READS).await;
        let mut queued = Vec::new();
        for _ in 0..MAX_QUEUED_READS {
            queued.push(spawn_read(resolver.clone()));
        }
        wait_until(|| resolver.queued.available_permits() == 0).await;

        let digest = Sha256Digest::new(DIGEST).unwrap();
        let overloaded = resolver.resolve(&digest).await.unwrap_err();
        assert_eq!(overloaded.code, cats_api::error::ErrorCode::Unavailable);
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::time::sleep(Duration::from_millis(10)),
        )
        .await
        .unwrap();
        assert_eq!(blob.maximum_active.load(Ordering::SeqCst), MAX_ACTIVE_READS);

        queued.pop().unwrap().abort();
        wait_until(|| resolver.queued.available_permits() == 1).await;
        for task in queued {
            task.abort();
        }
        wait_until(|| resolver.queued.available_permits() == MAX_QUEUED_READS).await;
        blob.release();
        for task in active {
            task.await.unwrap().unwrap();
        }
        assert_eq!(resolver.active.available_permits(), MAX_ACTIVE_READS);
    }

    struct SlowBlob {
        entered_provider_read: tokio::sync::Notify,
        released: AtomicBool,
        changed: Condvar,
        lock: std::sync::Mutex<()>,
    }

    impl SlowBlob {
        fn new() -> Self {
            Self {
                entered_provider_read: tokio::sync::Notify::new(),
                released: AtomicBool::new(false),
                changed: Condvar::new(),
                lock: std::sync::Mutex::new(()),
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.changed.notify_all();
        }
    }

    impl BlobStore for SlowBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn get(&self, _key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            unreachable!()
        }

        fn get_bounded_until(
            &self,
            _key: &str,
            _maximum: usize,
            _deadline: Instant,
        ) -> cats_storage::blob::Result<Vec<u8>> {
            self.entered_provider_read.notify_one();
            // Deliberately outlive the supplied deadline so the tests cover
            // a provider that violates the transport bound.
            let mut guard = self.lock.lock().unwrap();
            while !self.released.load(Ordering::SeqCst) {
                guard = self.changed.wait(guard).unwrap();
            }
            Ok(FIXED.to_vec())
        }

        fn exists(&self, _key: &str) -> cats_storage::blob::Result<bool> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> cats_storage::blob::Result<()> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn timeout_discards_late_result_but_holds_active_permit_until_io_returns() {
        let blob = Arc::new(SlowBlob::new());
        let resolver =
            ImmutableImageManifestResolver::with_deadline(blob.clone(), Duration::from_millis(20));
        let digest = Sha256Digest::new(DIGEST).unwrap();
        let error = resolver.resolve(&digest).await.unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
        assert_eq!(resolver.active.available_permits(), MAX_ACTIVE_READS - 1);
        blob.release();
        wait_until(|| resolver.active.available_permits() == MAX_ACTIVE_READS).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_rejects_new_work_and_clears_the_queue_without_releasing_active_io() {
        let blob = Arc::new(BlockingBlob::new());
        let resolver = Arc::new(ImmutableImageManifestResolver::new(blob.clone()));
        let spawn_read = |resolver: Arc<ImmutableImageManifestResolver>| {
            tokio::spawn(async move {
                let digest = Sha256Digest::new(DIGEST).unwrap();
                resolver.resolve(&digest).await
            })
        };
        let active = [spawn_read(resolver.clone()), spawn_read(resolver.clone())];
        wait_until(|| blob.active.load(Ordering::SeqCst) == MAX_ACTIVE_READS).await;
        let queued = spawn_read(resolver.clone());
        wait_until(|| resolver.queued.available_permits() == MAX_QUEUED_READS - 1).await;

        let shutdown_resolver = resolver.clone();
        let shutdown = tokio::spawn(async move { shutdown_resolver.shutdown().await });
        let queued_error = queued.await.unwrap().unwrap_err();
        assert_eq!(queued_error.code, cats_api::error::ErrorCode::Unavailable);
        let digest = Sha256Digest::new(DIGEST).unwrap();
        assert_eq!(
            resolver.resolve(&digest).await.unwrap_err().code,
            cats_api::error::ErrorCode::Unavailable
        );
        assert_eq!(blob.active.load(Ordering::SeqCst), MAX_ACTIVE_READS);

        blob.release();
        for task in active {
            task.await.unwrap().unwrap();
        }
        assert!(shutdown.await.unwrap());
        assert_eq!(blob.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_cannot_pass_a_request_paused_after_active_admission() {
        let blob = Arc::new(CountingBlob {
            reads: AtomicUsize::new(0),
        });
        let hook = Arc::new(TestReadHook::default());
        let resolver = Arc::new(ImmutableImageManifestResolver::with_active_hook(
            blob.clone(),
            Duration::from_secs(1),
            hook.clone(),
        ));
        let read_resolver = resolver.clone();
        let read = tokio::spawn(async move {
            let digest = Sha256Digest::new(DIGEST).unwrap();
            read_resolver.resolve(&digest).await
        });
        hook.reached.notified().await;

        let shutdown_resolver = resolver.clone();
        let mut shutdown = tokio::spawn(async move { shutdown_resolver.shutdown().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err(),
            "shutdown returned while an admitted request had not started provider I/O"
        );
        assert_eq!(blob.reads.load(Ordering::SeqCst), 0);

        hook.release.notify_one();
        read.await.unwrap().unwrap();
        assert!(shutdown.await.unwrap());
        assert_eq!(blob.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_wait_is_bounded_and_late_provider_results_are_discarded() {
        let blob = Arc::new(SlowBlob::new());
        let resolver = Arc::new(ImmutableImageManifestResolver::with_deadline(
            blob.clone(),
            Duration::from_millis(20),
        ));
        let read_resolver = resolver.clone();
        let read = tokio::spawn(async move {
            let digest = Sha256Digest::new(DIGEST).unwrap();
            read_resolver.resolve(&digest).await
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            blob.entered_provider_read.notified(),
        )
        .await
        .unwrap();

        let started = Instant::now();
        assert!(!resolver.shutdown().await);
        assert!(started.elapsed() < Duration::from_millis(80));
        assert_eq!(
            read.await.unwrap().unwrap_err().code,
            cats_api::error::ErrorCode::Unavailable
        );
        assert_eq!(resolver.inflight.count.load(Ordering::SeqCst), 1);

        blob.release();
        wait_until(|| resolver.inflight.count.load(Ordering::SeqCst) == 0).await;
        let digest = Sha256Digest::new(DIGEST).unwrap();
        assert_eq!(
            resolver.resolve(&digest).await.unwrap_err().code,
            cats_api::error::ErrorCode::Unavailable
        );
    }
}

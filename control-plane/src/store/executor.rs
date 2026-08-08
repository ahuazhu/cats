//! Fixed-size executor for the synchronous PostgreSQL control-store client.
//!
//! The `postgres` crate owns a Tokio runtime internally, so its blocking API
//! cannot run on a Cats Tokio worker.  This executor gives that API a small,
//! explicit thread and queue budget.  A queued job stays removable until a
//! worker claims it; dropping the returned future therefore guarantees that a
//! mutation which has not started will never run later.

use std::collections::VecDeque;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::task::{Context, Poll};

use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Limits {
    pub(super) workers: usize,
    pub(super) queue_capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) limits: Limits,
    pub(super) active: usize,
    pub(super) queued: usize,
    pub(super) peak_active: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmitError {
    Full,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecutionError {
    Panicked,
    Shutdown,
}

type JobFn = Box<dyn FnOnce() + Send + 'static>;

struct Job {
    id: usize,
    run: JobFn,
}

#[derive(Default)]
struct QueueState {
    jobs: VecDeque<Job>,
    shutdown: bool,
}

struct Inner {
    limits: Limits,
    queue: Mutex<QueueState>,
    available: Condvar,
    next_id: AtomicUsize,
    active: AtomicUsize,
    peak_active: AtomicUsize,
}

/// One owned, fixed set of worker threads.
///
/// This type is deliberately not `Clone`: one owner closes the queue and
/// joins every worker. Submitted futures retain only a weak reference, so
/// they cannot accidentally keep a shutdown executor alive forever.
pub(super) struct BlockingExecutor {
    inner: Arc<Inner>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl BlockingExecutor {
    pub(super) fn new(thread_name: &str, limits: Limits) -> std::io::Result<BlockingExecutor> {
        if limits.workers == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "blocking executor needs a worker",
            ));
        }
        if limits.queue_capacity == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "blocking queue must have positive bounded capacity",
            ));
        }

        let inner = Arc::new(Inner {
            limits,
            queue: Mutex::new(QueueState::default()),
            available: Condvar::new(),
            next_id: AtomicUsize::new(1),
            active: AtomicUsize::new(0),
            peak_active: AtomicUsize::new(0),
        });
        let mut workers = Vec::with_capacity(limits.workers);
        for index in 0..limits.workers {
            let worker_inner = Arc::clone(&inner);
            let name = format!("{thread_name}-{index}");
            match std::thread::Builder::new()
                .name(name)
                .spawn(move || worker_loop(&worker_inner))
            {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    shutdown(&inner);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self { inner, workers })
    }

    /// Admit one job without waiting for queue space.
    ///
    /// `Full` is the executor's backpressure boundary. No closure has been
    /// retained or run when this method returns an error.
    pub(super) fn try_execute<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> Result<Execution<T>, SubmitError> {
        let (result_tx, result_rx) = oneshot::channel();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let run = Box::new(move || {
            let outcome = match panic::catch_unwind(AssertUnwindSafe(operation)) {
                Ok(value) => Outcome::Completed(value),
                Err(_) => Outcome::Panicked,
            };
            let _ = result_tx.send(outcome);
        });

        let mut state = lock_unpoisoned(&self.inner.queue);
        if state.shutdown {
            return Err(SubmitError::Shutdown);
        }
        if state.jobs.len() >= self.inner.limits.queue_capacity {
            return Err(SubmitError::Full);
        }
        state.jobs.push_back(Job { id, run });
        drop(state);
        self.inner.available.notify_one();
        Ok(Execution {
            id: Some(id),
            executor: Arc::downgrade(&self.inner),
            result: result_rx,
        })
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        let queued = lock_unpoisoned(&self.inner.queue).jobs.len();
        Snapshot {
            limits: self.inner.limits,
            active: self.inner.active.load(Ordering::Acquire),
            queued,
            peak_active: self.inner.peak_active.load(Ordering::Acquire),
        }
    }
}

impl Drop for BlockingExecutor {
    fn drop(&mut self) {
        shutdown(&self.inner);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn shutdown(inner: &Inner) {
    let mut state = lock_unpoisoned(&inner.queue);
    state.shutdown = true;
    state.jobs.clear();
    drop(state);
    inner.available.notify_all();
}

fn worker_loop(inner: &Inner) {
    loop {
        let job = {
            let mut state = lock_unpoisoned(&inner.queue);
            while state.jobs.is_empty() && !state.shutdown {
                state = match inner.available.wait(state) {
                    Ok(state) => state,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            if state.shutdown {
                return;
            }
            state.jobs.pop_front()
        };
        let Some(job) = job else {
            continue;
        };
        let _active = ActiveJob::new(inner);
        (job.run)();
    }
}

struct ActiveJob<'a> {
    inner: &'a Inner,
}

impl<'a> ActiveJob<'a> {
    fn new(inner: &'a Inner) -> Self {
        let active = inner.active.fetch_add(1, Ordering::AcqRel) + 1;
        inner.peak_active.fetch_max(active, Ordering::AcqRel);
        Self { inner }
    }
}

impl Drop for ActiveJob<'_> {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::AcqRel);
    }
}

enum Outcome<T> {
    Completed(T),
    Panicked,
}

/// Awaitable ownership of one admitted job.
///
/// Until the worker removes its `id` from the queue, dropping this future
/// removes the closure itself. That is stronger than dropping only a result
/// receiver, which would detach a queued mutation and let it run later.
pub(super) struct Execution<T> {
    id: Option<usize>,
    executor: Weak<Inner>,
    result: oneshot::Receiver<Outcome<T>>,
}

impl<T> Execution<T> {
    /// Leave an admitted job in the queue when its result is intentionally
    /// unobserved. This is reserved for cancellation cleanup whose whole
    /// purpose is to outlive the future being dropped.
    pub(super) fn detach(mut self) {
        self.id = None;
    }
}

impl<T> Future for Execution<T> {
    type Output = Result<T, ExecutionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.result).poll(cx) {
            Poll::Ready(Ok(Outcome::Completed(value))) => {
                self.id = None;
                Poll::Ready(Ok(value))
            }
            Poll::Ready(Ok(Outcome::Panicked)) => {
                self.id = None;
                Poll::Ready(Err(ExecutionError::Panicked))
            }
            Poll::Ready(Err(_)) => {
                self.id = None;
                Poll::Ready(Err(ExecutionError::Shutdown))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Drop for Execution<T> {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let Some(executor) = self.executor.upgrade() else {
            return;
        };
        let mut state = lock_unpoisoned(&executor.queue);
        if let Some(position) = state.jobs.iter().position(|job| job.id == id) {
            state.jobs.remove(position);
        }
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

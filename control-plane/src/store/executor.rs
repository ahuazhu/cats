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
    pub(super) cleanup_capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) limits: Limits,
    pub(super) active: usize,
    pub(super) queued: usize,
    pub(super) cleanup_queued: usize,
    pub(super) peak_active: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmitError {
    Full,
    Shutdown,
}

pub(super) enum CleanupSubmitError<F> {
    Full(F),
    Shutdown(F),
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
    cleanups: VecDeque<JobFn>,
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
        if limits.cleanup_capacity == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "blocking cleanup queue must have positive bounded capacity",
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

    /// Admit non-cancellable cleanup into capacity reserved from request work.
    ///
    /// The caller retains the closure on rejection, so a synchronous client's
    /// unique owner is never captured by a cancelable retry task. Workers give
    /// this queue priority to release connection permits and advisory locks.
    pub(super) fn try_execute_cleanup<F>(&self, operation: F) -> Result<(), CleanupSubmitError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut state = lock_unpoisoned(&self.inner.queue);
        if state.shutdown {
            return Err(CleanupSubmitError::Shutdown(operation));
        }
        if state.cleanups.len() >= self.inner.limits.cleanup_capacity {
            return Err(CleanupSubmitError::Full(operation));
        }
        state.cleanups.push_back(Box::new(move || {
            let _ = panic::catch_unwind(AssertUnwindSafe(operation));
        }));
        drop(state);
        self.inner.available.notify_one();
        Ok(())
    }

    /// Wait for reserved cleanup capacity without running the destructor on
    /// the caller. Production connection budgets make this wait unnecessary;
    /// it is the fail-closed admission path if that invariant is ever broken.
    pub(super) fn execute_cleanup<F>(&self, operation: F) -> Result<(), CleanupSubmitError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut state = lock_unpoisoned(&self.inner.queue);
        while state.cleanups.len() >= self.inner.limits.cleanup_capacity && !state.shutdown {
            state = match self.inner.available.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        if state.shutdown {
            return Err(CleanupSubmitError::Shutdown(operation));
        }
        state.cleanups.push_back(Box::new(move || {
            let _ = panic::catch_unwind(AssertUnwindSafe(operation));
        }));
        drop(state);
        self.inner.available.notify_one();
        Ok(())
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        let state = lock_unpoisoned(&self.inner.queue);
        Snapshot {
            limits: self.inner.limits,
            active: self.inner.active.load(Ordering::Acquire),
            queued: state.jobs.len(),
            cleanup_queued: state.cleanups.len(),
            peak_active: self.inner.peak_active.load(Ordering::Acquire),
        }
    }

    /// Close admission and discard every queued job without waiting for an
    /// already-running job. The owner must still drop this executor to join
    /// its workers before releasing the resource protected by those jobs.
    pub(super) fn begin_shutdown(&self) {
        shutdown(&self.inner);
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
    let (abandoned, abandoned_cleanups) = {
        let mut state = lock_unpoisoned(&inner.queue);
        state.shutdown = true;
        (
            std::mem::take(&mut state.jobs),
            std::mem::take(&mut state.cleanups),
        )
    };
    inner.available.notify_all();
    // A captured request may own an arbitrarily slow destructor. Workers and
    // submitters must be able to observe shutdown while those closures drop.
    drop(abandoned);
    drop(abandoned_cleanups);
}

fn worker_loop(inner: &Inner) {
    loop {
        let job = {
            let mut state = lock_unpoisoned(&inner.queue);
            while state.jobs.is_empty() && state.cleanups.is_empty() && !state.shutdown {
                state = match inner.available.wait(state) {
                    Ok(state) => state,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            if state.shutdown {
                return;
            }
            state
                .cleanups
                .pop_front()
                .map(|run| Job { id: 0, run })
                .or_else(|| state.jobs.pop_front())
        };
        // Cleanup admission may be waiting for the reserved queue slot that
        // was just claimed. Notify only after releasing the queue mutex.
        inner.available.notify_all();
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
        let abandoned = {
            let mut state = lock_unpoisoned(&executor.queue);
            state
                .jobs
                .iter()
                .position(|job| job.id == id)
                .and_then(|position| state.jobs.remove(position))
        };
        // Dropping the closure while holding `queue` would let a request's
        // destructor stop every submitter and worker in this executor.
        drop(abandoned);
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

use super::*;
use crate::store::executor::{BlockingExecutor, Limits, SubmitError};

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn test_store() -> Arc<Store> {
    Arc::new(Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap())
}

#[test]
fn persistent_connection_budget_has_a_hard_limit_and_backpressure() {
    static TEST_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
    const LIMIT: usize = 3;

    let permits = (0..LIMIT)
        .map(|_| acquire_connection_budget(&TEST_CONNECTIONS, LIMIT, "test").unwrap())
        .collect::<Vec<_>>();
    let error = acquire_connection_budget(&TEST_CONNECTIONS, LIMIT, "test")
        .err()
        .expect("the connection budget must reject work at its hard limit");
    assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);

    drop(permits);
    assert_eq!(TEST_CONNECTIONS.load(Ordering::Acquire), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_queue_backpressures_and_cancelled_mutation_never_runs() {
    let executor = BlockingExecutor::new(
        "cats-control-pg-backpressure-test",
        Limits {
            workers: 1,
            queue_capacity: 1,
        },
    )
    .unwrap();
    let (release_active, wait_for_release) = mpsc::channel();
    let active = executor
        .try_execute(move || wait_for_release.recv().unwrap())
        .unwrap();
    while executor.snapshot().active != 1 {
        tokio::task::yield_now().await;
    }

    let mutations = Arc::new(AtomicUsize::new(0));
    let queued_mutations = Arc::clone(&mutations);
    let cancelled = executor
        .try_execute(move || queued_mutations.fetch_add(1, Ordering::SeqCst))
        .unwrap();
    assert_eq!(executor.snapshot().queued, 1);
    assert!(matches!(
        executor.try_execute(|| ()),
        Err(SubmitError::Full)
    ));

    drop(cancelled);
    assert_eq!(
        executor.snapshot().queued,
        0,
        "dropping the future must remove, not merely detach, its mutation"
    );
    let replacement_mutations = Arc::clone(&mutations);
    let replacement = executor
        .try_execute(move || replacement_mutations.fetch_add(1, Ordering::SeqCst))
        .expect("cancellation must immediately release queue capacity");

    release_active.send(()).unwrap();
    active.await.unwrap();
    assert_eq!(replacement.await.unwrap(), 0);
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrency_never_exceeds_the_declared_thread_limit() {
    let executor = BlockingExecutor::new(
        "cats-control-pg-bound-test",
        Limits {
            workers: 2,
            queue_capacity: 32,
        },
    )
    .unwrap();
    let thread_ids = Arc::new(Mutex::new(HashSet::new()));
    let mut work = Vec::new();
    for _ in 0..24 {
        let thread_ids = Arc::clone(&thread_ids);
        work.push(
            executor
                .try_execute(move || {
                    thread_ids
                        .lock()
                        .unwrap()
                        .insert(std::thread::current().id());
                    std::thread::sleep(Duration::from_millis(10));
                })
                .unwrap(),
        );
    }
    for job in work {
        job.await.unwrap();
    }

    let snapshot = executor.snapshot();
    assert_eq!(snapshot.limits.workers, 2);
    assert_eq!(snapshot.limits.queue_capacity, 32);
    assert!(snapshot.peak_active <= snapshot.limits.workers);
    assert!(thread_ids.lock().unwrap().len() <= snapshot.limits.workers);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_second_database_stall_does_not_delay_health() {
    let store = test_store();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let health_server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" })),
        )
        .await
        .unwrap();
    });

    let stalled_store = Arc::clone(&store);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let stalled = tokio::spawn(async move {
        stalled_store
            .execute(move |store| {
                let _ = started_tx.send(());
                store.with(|client| {
                    client.simple_query("SELECT pg_sleep(10)")?;
                    Ok(())
                })
            })
            .await
    });
    started_rx
        .await
        .expect("the stalled query must have started");
    let snapshot = Store::executor_snapshot().unwrap();
    assert!(snapshot.active >= 1);
    assert!(snapshot.active <= CONTROL_STORE_BLOCKING_WORKERS);

    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        reqwest::get(format!("http://{addr}/healthz")),
    )
    .await
    .expect("health must not wait for PostgreSQL")
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(started.elapsed() < Duration::from_secs(1));

    stalled
        .await
        .unwrap()
        .expect_err("the running query must end at its configured timeout");
    health_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_reuses_one_connection_and_reconnects_with_all_timeouts() {
    let store = test_store();
    let mut backend_pids = HashSet::new();
    let mut worker_threads = HashSet::new();
    let mut work = tokio::task::JoinSet::new();
    for _ in 0..48 {
        let store = Arc::clone(&store);
        work.spawn(async move {
            store
                .execute(|store| {
                    let worker_thread = std::thread::current().id();
                    store.with(|client| {
                        let row = client.query_one(
                            "SELECT pg_backend_pid(), current_setting('statement_timeout'),
                                    current_setting('lock_timeout')",
                            &[],
                        )?;
                        Ok((worker_thread, row.get(0), row.get(1), row.get(2)))
                    })
                })
                .await
        });
    }
    while let Some(result) = work.join_next().await {
        let (worker_thread, pid, statement, lock): (std::thread::ThreadId, i32, String, String) =
            result.unwrap().unwrap();
        worker_threads.insert(worker_thread);
        backend_pids.insert(pid);
        assert_eq!(statement, "5s");
        assert_eq!(lock, "2s");
    }
    assert_eq!(CONTROL_STORE_CONNECTIONS, 1);
    assert!(!worker_threads.is_empty());
    assert!(worker_threads.len() <= CONTROL_STORE_BLOCKING_WORKERS);
    assert_eq!(
        backend_pids.len(),
        CONTROL_STORE_CONNECTIONS,
        "concurrent load must reuse the bounded connection instead of growing FDs"
    );

    let old_pid = *backend_pids.iter().next().unwrap();
    store
        .execute(|store| {
            let client = store.client.lock().unwrap().take();
            drop(client);
            Ok(())
        })
        .await
        .unwrap();
    let (new_pid, statement, lock): (i32, String, String) = store
        .execute(|store| {
            store.with(|client| {
                let row = client.query_one(
                    "SELECT pg_backend_pid(), current_setting('statement_timeout'),
                            current_setting('lock_timeout')",
                    &[],
                )?;
                Ok((row.get(0), row.get(1), row.get(2)))
            })
        })
        .await
        .unwrap();
    assert_ne!(new_pid, old_pid);
    assert_eq!(statement, "5s");
    assert_eq!(lock, "2s");
}

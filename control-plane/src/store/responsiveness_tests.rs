use super::*;
use crate::store::executor::{BlockingExecutor, Limits, SubmitError};

use futures_util::FutureExt;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn test_store() -> Arc<Store> {
    Arc::new(Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap())
}

fn dsn_with_application_name(dsn: &str, application_name: &str) -> String {
    let mut url = reqwest::Url::parse(dsn).unwrap();
    url.query_pairs_mut()
        .append_pair("application_name", application_name);
    url.to_string()
}

async fn wait_for_postgres_activity(
    dsn: &str,
    application_name: &str,
    query_pattern: &str,
    require_active_transaction: bool,
    require_waiting_advisory_lock: bool,
) {
    let dsn = dsn.to_string();
    let application_name = application_name.to_string();
    let expected_application_name = application_name.clone();
    let query_pattern = query_pattern.to_string();
    let expected_query_pattern = query_pattern.clone();
    let found = tokio::time::timeout(
        cats_test_support::poll_bound() + Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            let mut observer = postgres::Client::connect(&dsn, postgres::NoTls).unwrap();
            let deadline = Instant::now() + cats_test_support::poll_bound();
            loop {
                let found: bool = observer
                    .query_one(
                        "SELECT EXISTS(
                           SELECT 1
                           FROM pg_stat_activity AS activity
                           WHERE activity.pid <> pg_backend_pid()
                             AND activity.application_name = $1
                             AND activity.query LIKE $2
                             AND (NOT $3 OR (
                                 activity.state = 'active'
                                 AND activity.xact_start IS NOT NULL
                             ))
                             AND (NOT $4 OR EXISTS(
                                 SELECT 1 FROM pg_locks AS lock
                                 WHERE lock.pid = activity.pid
                                   AND lock.locktype = 'advisory'
                                   AND NOT lock.granted
                             ))
                         )",
                        &[
                            &application_name,
                            &query_pattern,
                            &require_active_transaction,
                            &require_waiting_advisory_lock,
                        ],
                    )
                    .unwrap()
                    .get(0);
                if found {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }),
    )
    .await
    .expect("the bounded PostgreSQL activity observer must finish")
    .unwrap();
    assert!(
        found,
        "expected PostgreSQL activity for application {expected_application_name} and query \
         {expected_query_pattern}"
    );
}

struct ActiveRoleGuard {
    label: &'static str,
    active: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<String>>>,
}

impl Drop for ActiveRoleGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.events
            .lock()
            .unwrap()
            .push(format!("{}:stop", self.label));
    }
}

async fn run_pending_test_role(
    label: &'static str,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    starts: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<String>>>,
) {
    events.lock().unwrap().push(format!("{label}:start"));
    starts.fetch_add(1, Ordering::SeqCst);
    let active_now = active.fetch_add(1, Ordering::SeqCst) + 1;
    max_active.fetch_max(active_now, Ordering::SeqCst);
    let _active = ActiveRoleGuard {
        label,
        active,
        events,
    };
    std::future::pending::<()>().await;
}

#[derive(Default)]
struct FaultProxyState {
    rejecting: bool,
    generation: u64,
    connections: Vec<tokio::task::AbortHandle>,
}

/// Raw TCP relay whose fault transition closes both halves of every accepted
/// connection and rejects new ones. Unlike a host firewall blackhole, this is
/// deterministic and leaves no machine-global network state behind.
struct FaultProxy {
    address: std::net::SocketAddr,
    state: Arc<Mutex<FaultProxyState>>,
    active: Arc<AtomicUsize>,
    accept_task: tokio::task::JoinHandle<()>,
}

struct ActiveProxyConnection(Arc<AtomicUsize>);

impl Drop for ActiveProxyConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl FaultProxy {
    async fn start(upstream_dsn: &str) -> Self {
        let upstream = reqwest::Url::parse(upstream_dsn).unwrap();
        let upstream_host = upstream.host_str().unwrap().to_string();
        let upstream_port = upstream.port().unwrap_or(5432);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(FaultProxyState::default()));
        let active = Arc::new(AtomicUsize::new(0));
        let task_state = Arc::clone(&state);
        let task_active = Arc::clone(&active);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    return;
                };
                let generation = {
                    let state = task_state.lock().unwrap();
                    if state.rejecting {
                        continue;
                    }
                    state.generation
                };
                let Ok(mut outbound) =
                    tokio::net::TcpStream::connect((&*upstream_host, upstream_port)).await
                else {
                    continue;
                };
                let connection_active = Arc::clone(&task_active);
                let connection = tokio::spawn(async move {
                    connection_active.fetch_add(1, Ordering::AcqRel);
                    let _active = ActiveProxyConnection(connection_active);
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
                let abort = connection.abort_handle();
                let mut state = task_state.lock().unwrap();
                if state.rejecting || state.generation != generation {
                    abort.abort();
                } else {
                    state.connections.push(abort);
                }
            }
        });
        Self {
            address,
            state,
            active,
            accept_task,
        }
    }

    fn proxied_dsn(&self, dsn: &str) -> String {
        let mut url = reqwest::Url::parse(dsn).unwrap();
        url.set_host(Some(&self.address.ip().to_string())).unwrap();
        url.set_port(Some(self.address.port())).unwrap();
        url.to_string()
    }

    fn sever_and_reject(&self) {
        let connections = {
            let mut state = self.state.lock().unwrap();
            state.rejecting = true;
            state.generation = state.generation.wrapping_add(1);
            std::mem::take(&mut state.connections)
        };
        for connection in connections {
            connection.abort();
        }
    }

    fn recover(&self) {
        self.state.lock().unwrap().rejecting = false;
    }

    async fn wait_for_connections(&self, minimum: usize) {
        tokio::time::timeout(cats_test_support::poll_bound(), async {
            while self.active.load(Ordering::Acquire) < minimum {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fault proxy did not observe the expected established sessions");
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.sever_and_reject();
    }
}

#[test]
fn postgres_client_has_transport_and_connect_convergence_deadlines() {
    let dsn = DsnSource::Literal("postgres://localhost/postgres".to_string())
        .resolve()
        .unwrap();
    let config: postgres::Config = dsn.parse().unwrap();
    assert_eq!(
        config.get_connect_timeout(),
        Some(&CONTROL_STORE_CONNECT_TIMEOUT)
    );
    assert_eq!(
        config.get_tcp_user_timeout(),
        Some(&CONTROL_STORE_TCP_USER_TIMEOUT)
    );
    assert!(config.get_keepalives());
    assert_eq!(config.get_keepalives_idle(), CONTROL_STORE_KEEPALIVE_IDLE);
    assert_eq!(
        config.get_keepalives_interval(),
        Some(CONTROL_STORE_KEEPALIVE_INTERVAL)
    );
    assert_eq!(
        config.get_keepalives_retries(),
        Some(CONTROL_STORE_KEEPALIVE_RETRIES)
    );
    assert_eq!(
        CONTROL_STORE_ESTABLISHED_IO_FAILURE_BOUND,
        CONTROL_STORE_KEEPALIVE_IDLE + CONTROL_STORE_TCP_USER_TIMEOUT
    );
}

#[test]
fn persistent_connection_budget_has_a_hard_limit_and_backpressure() {
    static TEST_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
    const LIMIT: usize = 3;

    let rejection_count = metrics::rejection_count(metrics::RejectionKind::SingletonConnection);
    let permits = (0..LIMIT)
        .map(|_| {
            acquire_connection_budget(
                &TEST_CONNECTIONS,
                LIMIT,
                "test",
                metrics::RejectionKind::SingletonConnection,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let error = acquire_connection_budget(
        &TEST_CONNECTIONS,
        LIMIT,
        "test",
        metrics::RejectionKind::SingletonConnection,
    )
    .err()
    .expect("the connection budget must reject work at its hard limit");
    assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
    assert!(
        metrics::rejection_count(metrics::RejectionKind::SingletonConnection) > rejection_count
    );

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
            cleanup_capacity: 1,
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
async fn observation_lane_has_one_worker_one_waiter_and_queued_cancel_is_removable() {
    let lane = ObservationStoreLane::connect_from_async(
        DsnSource::Literal(crate::testsupport::isolated_control_store_url()),
        None,
    )
    .await
    .unwrap();
    let (release_active, wait_for_release) = mpsc::channel();
    let active_lane = Arc::clone(&lane);
    let active = tokio::spawn(async move {
        active_lane
            .execute(move |_| {
                wait_for_release.recv().unwrap();
                Ok(())
            })
            .await
    });
    while lane.snapshot().active != 1 {
        tokio::task::yield_now().await;
    }

    let mutations = Arc::new(AtomicUsize::new(0));
    let queued_mutations = Arc::clone(&mutations);
    let queued_lane = Arc::clone(&lane);
    let queued = tokio::spawn(async move {
        queued_lane
            .execute(move |_| {
                queued_mutations.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
    });
    while lane.snapshot().queued != 1 {
        tokio::task::yield_now().await;
    }
    let rejection = lane
        .execute(|_| Ok(()))
        .await
        .expect_err("active + one waiter is the exact lane capacity");
    assert_eq!(rejection.code, cats_api::error::ErrorCode::Unavailable);

    queued.abort();
    assert!(queued.await.unwrap_err().is_cancelled());
    while lane.snapshot().queued != 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(mutations.load(Ordering::SeqCst), 0);

    release_active.send(()).unwrap();
    active.await.unwrap().unwrap();
    lane.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observation_lane_shutdown_discards_waiter_and_joins_active_work() {
    let lane = ObservationStoreLane::connect_from_async(
        DsnSource::Literal(crate::testsupport::isolated_control_store_url()),
        None,
    )
    .await
    .unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let active_lane = Arc::clone(&lane);
    let active = tokio::spawn(async move {
        active_lane
            .execute(move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(move || {
        entered_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap()
    })
    .await
    .unwrap();

    let mutations = Arc::new(AtomicUsize::new(0));
    let queued_mutations = Arc::clone(&mutations);
    let queued_lane = Arc::clone(&lane);
    let queued = tokio::spawn(async move {
        queued_lane
            .execute(move |_| {
                queued_mutations.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
    });
    while lane.snapshot().queued != 1 {
        tokio::task::yield_now().await;
    }

    let shutdown_lane = Arc::clone(&lane);
    let mut shutdown = tokio::spawn(async move { shutdown_lane.shutdown().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
            .await
            .is_err(),
        "shutdown must join a claimed operation instead of detaching it"
    );
    assert_eq!(mutations.load(Ordering::SeqCst), 0);

    release_tx.send(()).unwrap();
    shutdown.await.unwrap();
    active.await.unwrap().unwrap();
    let queued_error = queued
        .await
        .unwrap()
        .expect_err("shutdown must discard the queued waiter");
    assert_eq!(queued_error.code, cats_api::error::ErrorCode::Unavailable);
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.snapshot().connected, 0);
}

struct BlockingDrop {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
}

impl Drop for BlockingDrop {
    fn drop(&mut self) {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        let _ = self.release.recv();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_queued_job_drops_captures_without_holding_the_queue_lock() {
    let executor = Arc::new(
        BlockingExecutor::new(
            "cats-control-pg-drop-test",
            Limits {
                workers: 1,
                queue_capacity: 2,
                cleanup_capacity: 1,
            },
        )
        .unwrap(),
    );
    let (release_active, wait_for_release) = mpsc::channel();
    let active = executor
        .try_execute(move || wait_for_release.recv().unwrap())
        .unwrap();
    while executor.snapshot().active != 1 {
        tokio::task::yield_now().await;
    }

    let (drop_entered_tx, drop_entered_rx) = mpsc::channel();
    let (release_drop_tx, release_drop_rx) = mpsc::channel();
    let slow_drop = BlockingDrop {
        entered: Some(drop_entered_tx),
        release: release_drop_rx,
    };
    let cancelled = executor
        .try_execute(move || drop(slow_drop))
        .expect("the cancellable job fits in the queue");
    let cancel_thread = std::thread::spawn(move || drop(cancelled));
    drop_entered_rx
        .recv_timeout(cats_test_support::poll_bound())
        .expect("cancellation must start dropping the queued closure");

    let (submitted_tx, submitted_rx) = mpsc::channel();
    let submit_executor = Arc::clone(&executor);
    let submit_thread = std::thread::spawn(move || {
        let replacement = submit_executor.try_execute(|| 42);
        let _ = submitted_tx.send(replacement);
    });
    // A submit that waits behind the captured destructor stays parked until
    // the error branch below releases it, so the wide shared poll bound
    // still discriminates.
    let replacement = match submitted_rx.recv_timeout(cats_test_support::poll_bound()) {
        Ok(Ok(replacement)) => replacement,
        Ok(Err(error)) => panic!("replacement unexpectedly rejected: {error:?}"),
        Err(error) => {
            // Always unblock the destructor so a regression fails instead of
            // stranding the test process in a mutex/join deadlock.
            let _ = release_drop_tx.send(());
            let _ = cancel_thread.join();
            let _ = submit_thread.join();
            panic!("submit waited behind a captured destructor: {error}");
        }
    };

    release_active.send(()).unwrap();
    active.await.unwrap();
    assert_eq!(
        tokio::time::timeout(cats_test_support::poll_bound(), replacement)
            .await
            .expect("the worker must progress while cancellation Drop is blocked")
            .unwrap(),
        42
    );

    release_drop_tx.send(()).unwrap();
    cancel_thread.join().unwrap();
    submit_thread.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrency_never_exceeds_the_declared_thread_limit() {
    let executor = BlockingExecutor::new(
        "cats-control-pg-bound-test",
        Limits {
            workers: 2,
            queue_capacity: 32,
            cleanup_capacity: 2,
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
async fn cleanup_has_reserved_capacity_and_runs_before_queued_requests() {
    let executor = BlockingExecutor::new(
        "cats-control-pg-cleanup-test",
        Limits {
            workers: 1,
            queue_capacity: 1,
            cleanup_capacity: 1,
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

    let (order_tx, order_rx) = mpsc::channel();
    let request_tx = order_tx.clone();
    let queued = executor
        .try_execute(move || request_tx.send("request").unwrap())
        .unwrap();
    assert!(matches!(
        executor.try_execute(|| ()),
        Err(SubmitError::Full)
    ));

    let cleanup_tx = order_tx;
    assert!(
        executor
            .try_execute_cleanup(move || cleanup_tx.send("cleanup").unwrap())
            .is_ok(),
        "cleanup capacity is independent from the full request queue"
    );
    assert_eq!(executor.snapshot().cleanup_queued, 1);

    release_active.send(()).unwrap();
    active.await.unwrap();
    assert_eq!(
        order_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap(),
        "cleanup"
    );
    assert_eq!(
        order_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap(),
        "request"
    );
    queued.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joinable_leadership_cleanup_waits_for_saturated_reserved_capacity() {
    let executor = BlockingExecutor::new(
        "cats-control-pg-joinable-cleanup-test",
        Limits {
            workers: 1,
            queue_capacity: 1,
            cleanup_capacity: 1,
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
    assert!(
        executor.try_execute_cleanup(|| {}).is_ok(),
        "the first cleanup fills the reserved queue"
    );
    assert_eq!(executor.snapshot().cleanup_queued, 1);

    let physically_closed = Arc::new(AtomicUsize::new(0));
    let completed = Arc::clone(&physically_closed);
    let mut cleanup = Box::pin(execute_leadership_cleanup_on(&executor, move || {
        completed.store(1, Ordering::SeqCst);
    }));
    tokio::select! {
        result = &mut cleanup => panic!("joinable cleanup bypassed saturation: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    assert_eq!(physically_closed.load(Ordering::SeqCst), 0);

    release_active.send(()).unwrap();
    cleanup.await.unwrap();
    assert_eq!(physically_closed.load(Ordering::SeqCst), 1);
    active.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poisoned_store_mutex_still_releases_the_physical_connection() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let backend_pid: i32 = store
        .with(|client| client.query_one("SELECT pg_backend_pid()", &[])?.try_get(0))
        .unwrap();
    let observer = Arc::new(Store::connect(&url, None).unwrap());

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _client = store.client.lock().unwrap();
        panic!("poison the client mutex");
    }));
    assert!(poisoned.is_err());
    assert!(store.client.is_poisoned());
    drop(store);

    tokio::time::timeout(cats_test_support::poll_bound(), async {
        loop {
            let still_connected: bool = observer
                .execute(move |store| {
                    store.with(|client| {
                        client
                            .query_one(
                                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid = $1)",
                                &[&backend_pid],
                            )?
                            .try_get(0)
                    })
                })
                .await
                .unwrap();
            if !still_connected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("poison recovery must still schedule physical Client destruction");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_second_database_stall_does_not_delay_health() {
    let store = test_store();
    let timeout_count = metrics::snapshot(&store).postgres_statement_timeouts;
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
    assert!(
        metrics::snapshot(&store).postgres_statement_timeouts > timeout_count,
        "the statement deadline must be observable"
    );
    health_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lane_wait_has_a_deadline_without_releasing_the_active_call() {
    let store = test_store();
    let timeout_count = metrics::snapshot(&store).lane_acquire_timeouts;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let active_store = Arc::clone(&store);
    let active = tokio::spawn(async move {
        active_store
            .execute(move |_| {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();

    let started = Instant::now();
    let error = store
        .execute(|store| store.list_all_cats())
        .await
        .expect_err("the lane waiter must time out");
    assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
    assert!(started.elapsed() >= CONTROL_STORE_LANE_ACQUIRE_TIMEOUT);
    assert!(started.elapsed() < CONTROL_STORE_LANE_ACQUIRE_TIMEOUT + Duration::from_secs(2));
    assert!(
        !active.is_finished(),
        "timing out a waiter must not finish the started call"
    );
    let snapshot = Store::executor_snapshot().unwrap();
    assert!(snapshot.active >= 1);
    assert!(snapshot.active <= CONTROL_STORE_BLOCKING_WORKERS);
    assert!(metrics::snapshot(&store).lane_acquire_timeouts > timeout_count);

    release_tx.send(()).unwrap();
    active.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotent_transaction_lock_timeout_is_observable() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Arc::new(Store::connect(&url, None).unwrap());
    let workspace = store
        .execute(|store| {
            store.ensure_configured_accounts(&BTreeMap::from([(
                "timeout-metrics".to_string(),
                "org_timeout_metrics".to_string(),
            )]))?;
            let account = store
                .account_for_organization("org_timeout_metrics")?
                .expect("bootstrap account exists");
            Ok(store
                .workspaces_for_account(&account.id)?
                .into_iter()
                .find(|workspace| workspace.is_default)
                .expect("bootstrap workspace exists"))
        })
        .await
        .unwrap();
    let blocker = Store::connect(&url, None).unwrap();
    let timeout_count = metrics::snapshot(&store).postgres_statement_timeouts;
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocker = std::thread::spawn(move || {
        blocker
            .enter(move |client| {
                let client = client?;
                let mut transaction = client.transaction().map_err(internal)?;
                transaction
                    .batch_execute("LOCK TABLE cats IN ACCESS EXCLUSIVE MODE")
                    .map_err(internal)?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                transaction.commit().map_err(internal)
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();

    store
        .execute(move |store| {
            store.create_cat_idempotent(
                &workspace,
                "lock-timeout",
                "test",
                1,
                256,
                1 << 20,
                true,
                None,
                None,
                DiskDurability::Strict,
                "lock-timeout-key",
                "POST /cats timeout-metrics/lock-timeout",
            )
        })
        .await
        .expect_err("the configured lock_timeout must terminate the waiter");
    assert!(
        metrics::snapshot(&store).postgres_statement_timeouts > timeout_count,
        "the lock deadline must increment the fixed timeout counter"
    );

    release_tx.send(()).unwrap();
    blocker.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_started_idempotent_mutation_settles_once_on_retry() {
    const APPLICATION_NAME: &str = "cats-issue-283-started-idempotency-cancel";
    const IDEMPOTENCY_KEY: &str = "started-cancel-create-key";
    const ROUTE: &str = "POST /cats started-cancel/one";

    let direct_dsn = crate::testsupport::isolated_control_store_url();
    let store_dsn = dsn_with_application_name(&direct_dsn, APPLICATION_NAME);
    let first = Arc::new(
        Store::connect_from_async(DsnSource::Literal(store_dsn.clone()), None)
            .await
            .unwrap(),
    );
    let second = Arc::new(
        Store::connect_from_async(DsnSource::Literal(store_dsn), None)
            .await
            .unwrap(),
    );
    let workspace = first
        .execute(|store| {
            store.ensure_configured_accounts(&std::collections::BTreeMap::from([(
                "started-cancel".to_string(),
                "org_started_cancel".to_string(),
            )]))?;
            let account = store
                .account_for_organization("org_started_cancel")?
                .expect("bootstrap account exists");
            Ok(store
                .workspaces_for_account(&account.id)?
                .into_iter()
                .find(|workspace| workspace.is_default)
                .expect("bootstrap workspace exists"))
        })
        .await
        .unwrap();

    let blocker_dsn = direct_dsn.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let mut client = postgres::Client::connect(&blocker_dsn, postgres::NoTls).unwrap();
        let mut transaction = client.transaction().unwrap();
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended(
                    current_schema() || ':idempotency:' || $1 || ':' || $2,
                    0::BIGINT
                 ))",
                &[&IDEMPOTENCY_KEY, &ROUTE],
            )
            .unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        transaction.rollback().unwrap();
    });
    locked_rx.recv().unwrap();

    let first_store = Arc::clone(&first);
    let first_workspace = workspace.clone();
    let first_caller = tokio::spawn(async move {
        first_store
            .execute(move |store| {
                store.create_cat_idempotent(
                    &first_workspace,
                    "one",
                    "test",
                    1,
                    256,
                    1 << 20,
                    true,
                    None,
                    None,
                    DiskDurability::Strict,
                    IDEMPOTENCY_KEY,
                    ROUTE,
                )
            })
            .await
    });
    wait_for_postgres_activity(
        &direct_dsn,
        APPLICATION_NAME,
        "%pg_advisory_xact_lock%",
        true,
        true,
    )
    .await;

    first_caller.abort();
    assert!(
        first_caller.await.unwrap_err().is_cancelled(),
        "the Tokio caller, not the already-started transaction, is cancelled"
    );
    release_tx.send(()).unwrap();

    let retried = second
        .execute({
            let workspace = workspace.clone();
            move |store| {
                store.create_cat_idempotent(
                    &workspace,
                    "one",
                    "test",
                    1,
                    256,
                    1 << 20,
                    true,
                    None,
                    None,
                    DiskDurability::Strict,
                    IDEMPOTENCY_KEY,
                    ROUTE,
                )
            }
        })
        .await
        .unwrap();
    blocker.join().unwrap();

    let (cats, operations) = second
        .execute({
            let workspace_id = workspace.id.clone();
            move |store| {
                Ok((
                    store.list_cats(&workspace_id)?,
                    store.list_operations(&workspace_id)?,
                ))
            }
        })
        .await
        .unwrap();
    assert_eq!(
        cats.len(),
        1,
        "the cancelled caller must not duplicate the Cat"
    );
    assert_eq!(
        operations.len(),
        1,
        "the initial completion and retry must share one Operation"
    );
    assert_eq!(cats[0].id, retried.0.id);
    assert_eq!(operations[0].id, retried.2.id);
    assert_eq!(
        cats[0].generation, 1,
        "the idempotent create generation advances exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_oci_session_drop_releases_ownership_through_the_bounded_executor() {
    let url = crate::testsupport::isolated_control_store_url();
    let first = Arc::new(Store::connect(&url, None).unwrap());
    let second = Arc::new(Store::connect(&url, None).unwrap());
    let operation_ids = (0..3)
        .map(|index| format!("bounded-oci-drop-{index}"))
        .collect::<Vec<_>>();
    let mut leases = Vec::new();
    for operation_id in &operation_ids {
        let operation_id = operation_id.clone();
        leases.push(
            first
                .execute(move |store| store.try_oci_deployment_lease(&operation_id))
                .await
                .unwrap()
                .expect("the first replica owns each distinct OCI lock"),
        );
    }

    let mut drops = tokio::task::JoinSet::new();
    for lease in leases {
        drops.spawn(async move { drop(lease) });
    }
    tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(result) = drops.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("dropping persistent clients must not block Tokio workers");

    let mut reacquired = Vec::new();
    for operation_id in operation_ids {
        let second = Arc::clone(&second);
        reacquired.push(
            tokio::time::timeout(cats_test_support::poll_bound(), async move {
                loop {
                    let operation_id = operation_id.clone();
                    if let Some(lease) = second
                        .execute(move |store| store.try_oci_deployment_lease(&operation_id))
                        .await
                        .unwrap()
                    {
                        return lease;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the bounded drop job must physically release advisory ownership"),
        );
    }
    execute_leadership(move || {
        drop(reacquired);
        Ok(())
    })
    .await
    .unwrap();

    let executor = control_store_leadership_executor().unwrap().snapshot();
    assert!(executor.active <= CONTROL_STORE_LEADERSHIP_WORKERS);
    assert!(executor.queued <= CONTROL_STORE_LEADERSHIP_QUEUE_CAPACITY);
    assert!(executor.peak_active <= CONTROL_STORE_LEADERSHIP_WORKERS);
    assert!(metrics::snapshot(&first).oci_connections <= CONTROL_STORE_OCI_CONNECTIONS);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_recover_after_established_connections_are_severed() {
    let direct_dsn = crate::testsupport::isolated_control_store_url();
    // Install the schema directly so proxy behavior, rather than concurrent
    // migration, is the only fault variable below.
    drop(Store::connect(&direct_dsn, None).unwrap());
    let proxy = FaultProxy::start(&direct_dsn).await;
    let proxied_dsn = proxy.proxied_dsn(&direct_dsn);
    let first = Arc::new(
        Store::connect_from_async(DsnSource::Literal(proxied_dsn.clone()), None)
            .await
            .unwrap(),
    );
    let second = Arc::new(
        Store::connect_from_async(DsnSource::Literal(proxied_dsn), None)
            .await
            .unwrap(),
    );
    let workspace = first
        .execute(|store| {
            store.ensure_configured_accounts(&BTreeMap::from([(
                "fault-replicas".to_string(),
                "org_fault_replicas".to_string(),
            )]))?;
            let account = store
                .account_for_organization("org_fault_replicas")?
                .expect("bootstrap account exists");
            Ok(store
                .workspaces_for_account(&account.id)?
                .into_iter()
                .find(|workspace| workspace.is_default)
                .expect("bootstrap workspace exists"))
        })
        .await
        .unwrap();

    let first_session_store = Arc::clone(&first);
    let first_session = execute_leadership(move || {
        first_session_store.singleton_session(SingletonRole::Reconciler)
    })
    .await
    .unwrap();
    let (first_session, first_owned) = execute_leadership(move || {
        let mut session = first_session;
        let acquired = session.try_acquire()?;
        Ok((session, acquired))
    })
    .await
    .unwrap();
    assert!(first_owned);

    let second_session_store = Arc::clone(&second);
    let second_session = execute_leadership(move || {
        second_session_store.singleton_session(SingletonRole::Reconciler)
    })
    .await
    .unwrap();
    let (second_session, second_owned) = execute_leadership(move || {
        let mut session = second_session;
        let acquired = session.try_acquire()?;
        Ok((session, acquired))
    })
    .await
    .unwrap();
    assert!(!second_owned);

    let oci_owner = first
        .execute(|store| store.try_oci_deployment_lease("fault-proxy-oci"))
        .await
        .unwrap()
        .expect("the first replica owns the OCI advisory lock");
    assert!(second
        .execute(|store| store.try_oci_deployment_lease("fault-proxy-oci"))
        .await
        .unwrap()
        .is_none());
    proxy.wait_for_connections(5).await;
    let connection_metrics = metrics::snapshot(&first);
    assert_eq!(
        connection_metrics.normal_connections,
        CONTROL_STORE_CONNECTIONS
    );
    assert!(connection_metrics.singleton_connections >= 2);
    assert!(connection_metrics.singleton_connections <= CONTROL_STORE_SINGLETON_CONNECTIONS);
    assert!(connection_metrics.oci_connections >= 1);
    assert!(connection_metrics.oci_connections <= CONTROL_STORE_OCI_CONNECTIONS);

    let first_query_store = Arc::clone(&first);
    let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
    let first_query = tokio::spawn(async move {
        first_query_store
            .execute(move |store| {
                let _ = first_started_tx.send(());
                store.with(|client| {
                    client.simple_query(
                        "SELECT pg_sleep(10) /* cats-issue-283-established-first */",
                    )?;
                    Ok(())
                })
            })
            .await
    });
    let second_query_store = Arc::clone(&second);
    let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
    let second_query = tokio::spawn(async move {
        second_query_store
            .execute(move |store| {
                let _ = second_started_tx.send(());
                store.with(|client| {
                    client.simple_query(
                        "SELECT pg_sleep(10) /* cats-issue-283-established-second */",
                    )?;
                    Ok(())
                })
            })
            .await
    });
    first_started_rx.await.unwrap();
    second_started_rx.await.unwrap();
    let observer_dsn = direct_dsn.clone();
    let both_queries_started = tokio::time::timeout(
        cats_test_support::poll_bound() + Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            let bounded_observer_dsn = DsnSource::Literal(observer_dsn).resolve().unwrap();
            let mut observer = bounded_observer_dsn
                .parse::<postgres::Config>()
                .unwrap()
                .connect(postgres::NoTls)
                .unwrap();
            let deadline = Instant::now() + cats_test_support::poll_bound();
            loop {
                let row = observer
                    .query_one(
                        "SELECT
                           EXISTS(SELECT 1 FROM pg_stat_activity
                                  WHERE pid <> pg_backend_pid() AND state='active'
                                    AND query LIKE $1),
                           EXISTS(SELECT 1 FROM pg_stat_activity
                                  WHERE pid <> pg_backend_pid() AND state='active'
                                    AND query LIKE $2)",
                        &[
                            &"%cats-issue-283-established-first%",
                            &"%cats-issue-283-established-second%",
                        ],
                    )
                    .unwrap();
                if row.get::<_, bool>(0) && row.get::<_, bool>(1) {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }),
    )
    .await
    .expect("the bounded SQL observer must finish")
    .unwrap();
    assert!(
        both_queries_started,
        "both SQL calls must be active before the established connections are severed"
    );

    let failure_started = Instant::now();
    proxy.sever_and_reject();
    for query in [first_query, second_query] {
        tokio::time::timeout(Duration::from_secs(2), query)
            .await
            .expect("a severed started SQL call must physically converge")
            .unwrap()
            .expect_err("requests in the injected fault window may fail");
    }
    assert!(failure_started.elapsed() < Duration::from_secs(2));

    // The old advisory sessions were severed with the normal connections.
    // Dropping the client objects cannot preserve ownership at PostgreSQL.
    execute_leadership(move || {
        drop(first_session);
        drop(second_session);
        drop(oci_owner);
        Ok(())
    })
    .await
    .unwrap();
    proxy.recover();

    let recover = |store: Arc<Store>| async move {
        tokio::time::timeout(cats_test_support::poll_bound(), async move {
            loop {
                match store.execute(|store| store.list_all_cats()).await {
                    Ok(cats) => return cats,
                    Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                }
            }
        })
        .await
        .expect("replica did not reconnect inside the configured transport bound")
    };
    let (first_cats, second_cats) =
        tokio::join!(recover(Arc::clone(&first)), recover(Arc::clone(&second)));
    assert_eq!(
        first_cats.iter().map(|cat| &cat.id).collect::<Vec<_>>(),
        second_cats.iter().map(|cat| &cat.id).collect::<Vec<_>>()
    );

    let create_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let create_on = |store: Arc<Store>| {
        let workspace = workspace.clone();
        let barrier = Arc::clone(&create_barrier);
        async move {
            barrier.wait().await;
            store
                .execute(move |store| {
                    store.create_cat_idempotent(
                        &workspace,
                        "settled",
                        "test",
                        1,
                        256,
                        1 << 20,
                        true,
                        None,
                        None,
                        DiskDurability::Strict,
                        "fault-create-key",
                        "POST /cats fault-replicas/settled",
                    )
                })
                .await
                .unwrap()
        }
    };
    let (created_first, created_second) = tokio::join!(
        create_on(Arc::clone(&first)),
        create_on(Arc::clone(&second))
    );
    assert_eq!(created_first.0.id, created_second.0.id);
    assert_eq!(created_first.2.id, created_second.2.id);
    assert_eq!(
        first
            .execute({
                let workspace_id = workspace.id.clone();
                move |store| store.list_cats(&workspace_id)
            })
            .await
            .unwrap()
            .len(),
        1,
        "the retried create must have one side effect"
    );

    let cat_id = created_first.0.id.clone();
    let action_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let act_on = |store: Arc<Store>| {
        let cat_id = cat_id.clone();
        let barrier = Arc::clone(&action_barrier);
        async move {
            barrier.wait().await;
            store
                .execute(move |store| {
                    store.set_desired_idempotent(
                        &cat_id,
                        DesiredState::Cold,
                        None,
                        "cat.stop",
                        "fault-stop-key",
                        "POST /cats/settled/actions/stop",
                    )
                })
                .await
                .unwrap()
        }
    };
    let (action_first, action_second) =
        tokio::join!(act_on(Arc::clone(&first)), act_on(Arc::clone(&second)));
    assert_eq!(action_first.id, action_second.id);
    let settled = first
        .execute({
            let cat_id = created_first.0.id.clone();
            move |store| store.must_get_cat_by_id(&cat_id)
        })
        .await
        .unwrap();
    assert_eq!(settled.generation, 2, "revision must settle exactly once");
    assert_eq!(settled.desired_state, DesiredState::Cold);

    let recovered_owner_store = Arc::clone(&second);
    let recovered_owner = execute_leadership(move || {
        recovered_owner_store.singleton_session(SingletonRole::Reconciler)
    })
    .await
    .unwrap();
    let recovered_owner = tokio::time::timeout(cats_test_support::poll_bound(), async move {
        let mut session = recovered_owner;
        loop {
            let (returned, acquired) = execute_leadership(move || {
                let mut session = session;
                let acquired = session.try_acquire()?;
                Ok((session, acquired))
            })
            .await
            .unwrap();
            session = returned;
            if acquired {
                return session;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("severing the old session must release leadership inside the recovery bound");
    let recovered_standby_store = Arc::clone(&first);
    let recovered_standby = execute_leadership(move || {
        recovered_standby_store.singleton_session(SingletonRole::Reconciler)
    })
    .await
    .unwrap();
    let (recovered_standby, acquired) = execute_leadership(move || {
        let mut session = recovered_standby;
        let acquired = session.try_acquire()?;
        Ok((session, acquired))
    })
    .await
    .unwrap();
    assert!(!acquired, "only one recovered replica may own leadership");
    let recovered_oci = tokio::time::timeout(cats_test_support::poll_bound(), async {
        loop {
            if let Some(lease) = second
                .execute(|store| store.try_oci_deployment_lease("fault-proxy-oci"))
                .await
                .unwrap()
            {
                return lease;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("OCI ownership must be reacquirable inside the recovery bound");
    assert!(first
        .execute(|store| store.try_oci_deployment_lease("fault-proxy-oci"))
        .await
        .unwrap()
        .is_none());

    execute_leadership(move || {
        drop(recovered_owner);
        drop(recovered_standby);
        drop(recovered_oci);
        Ok(())
    })
    .await
    .unwrap();

    // Repeatedly poll then cancel a mutation while this Store's lane is held.
    // A leaked admission permit would make one of these futures resolve with
    // backpressure before the declared capacity is crossed.
    let blocker_store = Arc::clone(&first);
    let (blocker_started_tx, blocker_started_rx) = tokio::sync::oneshot::channel();
    let (release_blocker_tx, release_blocker_rx) = mpsc::channel();
    let blocker = tokio::spawn(async move {
        blocker_store
            .execute(move |_| {
                let _ = blocker_started_tx.send(());
                release_blocker_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    blocker_started_rx.await.unwrap();
    for index in 0..(CONTROL_STORE_BLOCKING_WORKERS + CONTROL_STORE_QUEUE_CAPACITY + 4) {
        let account_id = workspace.account_id.clone();
        let slug = format!("cancelled-{index}");
        let pending = first
            .execute(move |store| store.create_workspace(&account_id, &slug, "must never execute"));
        assert!(
            pending.now_or_never().is_none(),
            "cancellation leaked an admission permit at iteration {index}"
        );
    }
    release_blocker_tx.send(()).unwrap();
    blocker.await.unwrap().unwrap();
    let workspaces = first
        .execute({
            let account_id = workspace.account_id.clone();
            move |store| store.workspaces_for_account(&account_id)
        })
        .await
        .unwrap();
    assert!(
        workspaces
            .iter()
            .all(|workspace| !workspace.slug.starts_with("cancelled-")),
        "cancelled mutations must have no delayed or duplicate side effects"
    );

    let snapshot = metrics::snapshot(&first);
    assert!(snapshot.normal.active <= CONTROL_STORE_BLOCKING_WORKERS);
    assert!(snapshot.normal.queued <= CONTROL_STORE_QUEUE_CAPACITY);
    assert!(snapshot.admission_depth <= snapshot.admission_capacity);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_usage_projector_shutdown_joins_before_standby_takeover() {
    let dsn = crate::testsupport::isolated_control_store_url();
    let leader_store = Arc::new(Store::connect(&dsn, None).unwrap());
    let standby_store = Arc::new(Store::connect(&dsn, None).unwrap());
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));

    let leader =
        crate::server::spawn_managed_singleton_task(leader_store, SingletonRole::UsageProjector, {
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            let starts = Arc::clone(&starts);
            let events = Arc::clone(&events);
            move || {
                run_pending_test_role(
                    "leader",
                    Arc::clone(&active),
                    Arc::clone(&max_active),
                    Arc::clone(&starts),
                    Arc::clone(&events),
                )
            }
        });
    tokio::time::timeout(cats_test_support::poll_bound(), async {
        while starts.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the managed UsageProjector must acquire leadership");

    let standby =
        crate::server::spawn_singleton_task(standby_store, SingletonRole::UsageProjector, {
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            let starts = Arc::clone(&starts);
            let events = Arc::clone(&events);
            move || {
                run_pending_test_role(
                    "standby",
                    Arc::clone(&active),
                    Arc::clone(&max_active),
                    Arc::clone(&starts),
                    Arc::clone(&events),
                )
            }
        });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 1, "the standby is fenced");

    leader.shutdown().await.unwrap();
    tokio::time::timeout(cats_test_support::poll_bound(), async {
        while starts.load(Ordering::SeqCst) != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the standby must acquire after joined projector shutdown");
    assert_eq!(max_active.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["leader:start", "leader:stop", "standby:start"]
    );
    standby.abort();
    let _ = standby.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faulted_singleton_session_stops_the_old_role_before_standby_starts() {
    const LEADER_APPLICATION: &str = "cats-issue-283-singleton-fault-leader";
    const STANDBY_APPLICATION: &str = "cats-issue-283-singleton-fault-standby";

    let direct_dsn = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&direct_dsn, None).unwrap());
    let proxy = FaultProxy::start(&direct_dsn).await;
    let leader_dsn = dsn_with_application_name(&proxy.proxied_dsn(&direct_dsn), LEADER_APPLICATION);
    let standby_dsn = dsn_with_application_name(&direct_dsn, STANDBY_APPLICATION);
    let leader_store = Arc::new(
        Store::connect_from_async(DsnSource::Literal(leader_dsn), None)
            .await
            .unwrap(),
    );
    let standby_store = Arc::new(
        Store::connect_from_async(DsnSource::Literal(standby_dsn), None)
            .await
            .unwrap(),
    );

    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let leader_task =
        crate::server::spawn_singleton_task(leader_store, SingletonRole::UsageProjector, {
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            let starts = Arc::clone(&starts);
            let events = Arc::clone(&events);
            move || {
                run_pending_test_role(
                    "leader",
                    Arc::clone(&active),
                    Arc::clone(&max_active),
                    Arc::clone(&starts),
                    Arc::clone(&events),
                )
            }
        });
    tokio::time::timeout(cats_test_support::poll_bound(), async {
        while starts.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the proxy-backed replica must acquire leadership");
    proxy.wait_for_connections(2).await;

    // Observe a completed health check, then phase the standby's first failed
    // election attempt so the next leader check precedes its retry. The event
    // log and max_active assertion remain the correctness oracle.
    wait_for_postgres_activity(&direct_dsn, LEADER_APPLICATION, "SELECT 1", false, false).await;
    let health_observed = Instant::now();
    tokio::time::sleep(Duration::from_millis(650)).await;

    let standby_task =
        crate::server::spawn_singleton_task(standby_store, SingletonRole::UsageProjector, {
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            let starts = Arc::clone(&starts);
            let events = Arc::clone(&events);
            move || {
                run_pending_test_role(
                    "standby",
                    Arc::clone(&active),
                    Arc::clone(&max_active),
                    Arc::clone(&starts),
                    Arc::clone(&events),
                )
            }
        });
    wait_for_postgres_activity(
        &direct_dsn,
        STANDBY_APPLICATION,
        "%pg_try_advisory_lock%",
        false,
        false,
    )
    .await;
    assert!(
        health_observed.elapsed() < Duration::from_millis(900),
        "the fault phase must be calibrated before the leader's next health check"
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1, "the standby is waiting");

    proxy.sever_and_reject();
    tokio::time::timeout(cats_test_support::poll_bound(), async {
        loop {
            let events = events.lock().unwrap().clone();
            if events.iter().any(|event| event == "leader:stop")
                && events.iter().any(|event| event == "standby:start")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the standby must take over after the faulted leader stops");

    let events = events.lock().unwrap().clone();
    let leader_stop = events
        .iter()
        .position(|event| event == "leader:stop")
        .unwrap();
    let standby_start = events
        .iter()
        .position(|event| event == "standby:start")
        .unwrap();
    assert!(
        leader_stop < standby_start,
        "old role must stop before standby starts: {events:?}"
    );
    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert_eq!(
        max_active.load(Ordering::SeqCst),
        1,
        "singleton role executions must never overlap"
    );

    leader_task.abort();
    standby_task.abort();
    let _ = leader_task.await;
    let _ = standby_task.await;
    tokio::time::timeout(cats_test_support::poll_bound(), async {
        while active.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("singleton role cleanup must finish");
}

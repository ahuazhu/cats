use std::sync::mpsc;
use std::time::{Duration, Instant};

use cats_control_plane::store::Store;
use postgres::NoTls;

const SCHEMA_BOOTSTRAP_LOCK_CLASS: i32 = 420111;
const SCHEMA_BOOTSTRAP_LOCK_OBJECT: i32 = 1;

fn with_application_name(dsn: &str, application_name: &str) -> String {
    let separator = if dsn.contains('?') { '&' } else { '?' };
    format!("{dsn}{separator}application_name={application_name}")
}

fn with_test_marker(dsn: &str, marker: Option<&str>) -> String {
    let marker_suffix = "%20-ccats.test_schema_bootstrap%3Don";
    let base = dsn
        .strip_suffix(marker_suffix)
        .expect("isolated test DSN must carry the exact schema-bootstrap marker");
    marker.map_or_else(
        || base.to_string(),
        |value| format!("{base}%20-ccats.test_schema_bootstrap%3D{value}"),
    )
}

fn connect_in_background(
    dsn: String,
) -> (
    std::thread::JoinHandle<()>,
    mpsc::Receiver<Result<(), cats_api::error::ApiError>>,
) {
    let (result_tx, result_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = Store::connect(&dsn, None).map(drop);
        let _ = result_tx.send(result);
    });
    (worker, result_rx)
}

#[test]
fn isolated_schema_bootstrap_waits_on_the_test_global_ddl_lock_only_for_exact_marker() {
    let marked_dsn = cats_control_plane::testsupport::isolated_control_store_url();
    let absent_dsn = with_test_marker(
        &cats_control_plane::testsupport::isolated_control_store_url(),
        None,
    );
    let off_dsn = with_test_marker(
        &cats_control_plane::testsupport::isolated_control_store_url(),
        Some("off"),
    );
    let marked_options = marked_dsn
        .parse::<postgres::Config>()
        .unwrap()
        .get_options()
        .unwrap()
        .to_string();
    assert!(marked_options.contains("-csearch_path=t_"));
    assert!(marked_options.ends_with(" -ccats.test_schema_bootstrap=on"));
    assert!(absent_dsn
        .parse::<postgres::Config>()
        .unwrap()
        .get_options()
        .unwrap()
        .contains("-csearch_path=t_"));
    assert!(!absent_dsn
        .parse::<postgres::Config>()
        .unwrap()
        .get_options()
        .unwrap()
        .contains("cats.test_schema_bootstrap"));
    assert!(off_dsn
        .parse::<postgres::Config>()
        .unwrap()
        .get_options()
        .unwrap()
        .ends_with(" -ccats.test_schema_bootstrap=off"));

    let base_dsn = cats_control_plane::testsupport::base_url();
    let mut holder = postgres::Client::connect(&base_dsn, NoTls).unwrap();
    let blocker_pid: i32 = holder
        .query_one(
            "SELECT pg_backend_pid(), pg_advisory_lock($1, $2)",
            &[&SCHEMA_BOOTSTRAP_LOCK_CLASS, &SCHEMA_BOOTSTRAP_LOCK_OBJECT],
        )
        .unwrap()
        .get(0);

    // Merely having a custom setting, or having no setting at all, must not
    // alter the production 5s/2s + per-schema bootstrap behavior.
    for dsn in [absent_dsn, off_dsn] {
        let (worker, result_rx) = connect_in_background(dsn);
        result_rx
            .recv_timeout(cats_test_support::poll_bound())
            .expect("an unmarked schema bootstrap waited on the test-only global lock")
            .expect("an unmarked schema bootstrap failed");
        worker.join().unwrap();
    }

    let application_name = format!("cats-schema-bootstrap-{}", uuid::Uuid::new_v4().simple());
    let marked_dsn = with_application_name(&marked_dsn, &application_name);
    let (worker, result_rx) = connect_in_background(marked_dsn);
    let mut observer = postgres::Client::connect(&base_dsn, NoTls).unwrap();

    let observation_deadline = Instant::now() + cats_test_support::poll_bound();
    let waiting_pid = loop {
        match result_rx.try_recv() {
            Ok(result) => panic!(
                "marked Store::connect completed before waiting on the global DDL lock: {result:?}"
            ),
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("marked Store::connect worker exited without reporting a result")
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let waiting_pid = observer
            .query_opt(
                "SELECT pid
                   FROM pg_stat_activity
                  WHERE application_name=$1
                    AND wait_event_type='Lock'
                    AND wait_event='advisory'
                    AND $2 = ANY(pg_blocking_pids(pid))
                  ORDER BY pid
                  LIMIT 1",
                &[&application_name, &blocker_pid],
            )
            .unwrap()
            .map(|row| row.get::<_, i32>(0));
        if let Some(waiting_pid) = waiting_pid {
            break waiting_pid;
        }
        assert!(
            Instant::now() < observation_deadline,
            "marked Store::connect never entered the calibrated advisory-lock wait"
        );
        std::thread::sleep(Duration::from_millis(10));
    };

    let wait_observed_at = Instant::now();
    while wait_observed_at.elapsed() <= Duration::from_millis(2_200) {
        assert!(
            matches!(result_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "marked Store::connect did not remain blocked beyond the production 2s lock timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let still_waiting: bool = observer
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM pg_stat_activity
                 WHERE pid=$1
                   AND application_name=$2
                   AND wait_event_type='Lock'
                   AND wait_event='advisory'
                   AND $3 = ANY(pg_blocking_pids(pid))
             )",
            &[&waiting_pid, &application_name, &blocker_pid],
        )
        .unwrap()
        .get(0);
    assert!(
        still_waiting,
        "marked Store::connect left the calibrated advisory wait before release"
    );

    let unlocked: bool = holder
        .query_one(
            "SELECT pg_advisory_unlock($1, $2)",
            &[&SCHEMA_BOOTSTRAP_LOCK_CLASS, &SCHEMA_BOOTSTRAP_LOCK_OBJECT],
        )
        .unwrap()
        .get(0);
    assert!(unlocked, "test holder did not own the global DDL lock");
    result_rx
        .recv_timeout(cats_test_support::poll_bound())
        .expect("marked schema bootstrap did not finish within its test budget after release")
        .expect("marked schema bootstrap failed after the global DDL lock was released");
    worker.join().unwrap();
}

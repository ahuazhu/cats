//! How much of a concurrent launch is serialized by the node agent.
//!
//! `NodeRuntime::execute` runs every job under a node-wide mutex except the
//! Suspended resume path (ADR-0002 §8), because `start_cat` used to allocate
//! node-global resources. This measures what that costs for a concurrent cold
//! launch and asserts the property the fix relies on: N launches must not take N
//! times as long as one.
//!
//! FakeVmm only: the point is the node agent's own locking, not the VMM.

use std::sync::Arc;
use std::time::Instant;

use cats_api::nodejob::{job_id, NodeJob, NodeJobAction, VolumeGrant};
use cats_api::resources::ObservedState;
use cats_node_agent::admission::WakeBudget;
use cats_node_agent::runtime::NodeRuntime;
use cats_test_support::{fake_node_config, NodeConfigBuilder};

const SIZE: u64 = 2 * cats_api::chunk::CHUNK_SIZE as u64;

fn runtime(dir: &std::path::Path) -> Arc<NodeRuntime> {
    runtime_with(dir, WakeBudget::default())
}

fn runtime_with(dir: &std::path::Path, wake_budget: WakeBudget) -> Arc<NodeRuntime> {
    let builder = NodeConfigBuilder::new(dir, "node_conc").with_lease_ttl_ms(1_500);
    Arc::new(
        NodeRuntime::new(fake_node_config!(builder, wake_budget = wake_budget))
            .expect("open node runtime"),
    )
}

fn start_job(cat: &str) -> NodeJob {
    NodeJob {
        job_id: job_id(cat, 1, "start_cat"),
        cat_generation: 1,
        action: NodeJobAction::StartCat {
            cat_id: cat.into(),
            image: "test".into(),
            cpus: 1,
            memory_mib: 256,
            volumes: vec![VolumeGrant {
                disk_id: format!("root_{cat}"),
                volume_id: format!("vol_{cat}"),
                attachment_id: format!("att_{cat}"),
                epoch: 0,
                size_bytes: SIZE,
                mount_path: "/".into(),
                durability: Default::default(),
            }],
        },
    }
}

/// Launch one Cat, then `n` concurrently, and report both. A node that
/// serializes launches shows `concurrent ≈ n × single`.
#[test]
fn concurrent_cold_launch_is_not_serialized() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime(dir.path());
    let n = 8;

    // Two throwaway launches first: the very first one pays for binary loading,
    // schema creation and page-cache warming, which would otherwise dwarf the
    // per-launch cost this test is about.
    for warmup in 0..2 {
        let result = runtime.execute(start_job(&format!("cat_warmup_{warmup}")));
        assert_eq!(
            result.observed_state,
            ObservedState::Running,
            "warmup launch failed: {result:?}"
        );
    }
    let started = Instant::now();
    let result = runtime.execute(start_job("cat_single"));
    let single_ms = started.elapsed().as_millis();
    assert_eq!(
        result.observed_state,
        ObservedState::Running,
        "single launch failed: {result:?}"
    );

    let started = Instant::now();
    let mut workers = Vec::new();
    for index in 0..n {
        let runtime = runtime.clone();
        workers.push(std::thread::spawn(move || {
            runtime.execute(start_job(&format!("cat_conc_{index}")))
        }));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("launch thread panicked"))
        .collect();
    let concurrent_ms = started.elapsed().as_millis();

    for (index, result) in results.iter().enumerate() {
        assert_eq!(
            result.observed_state,
            ObservedState::Running,
            "cat_conc_{index} failed: {result:?}"
        );
    }

    let serial_ms = single_ms * n as u128;
    println!(
        "single launch {single_ms} ms; {n} concurrent {concurrent_ms} ms; \
         fully serialized would be {serial_ms} ms; speedup {:.2}x",
        serial_ms as f64 / concurrent_ms.max(1) as f64
    );

    // The threshold is deliberately loose: this asserts "launches overlap", not
    // a performance number. Fully serialized execution lands at ~serial_ms.
    assert!(
        concurrent_ms < serial_ms * 3 / 4,
        "concurrent launch looks serialized: {concurrent_ms} ms for {n} launches \
         versus {single_ms} ms for one"
    );
}

/// Concurrency is bounded, not unlimited: with a ceiling of two, six launches
/// must queue and all still succeed. A launch must never be *refused* for
/// exceeding a byte budget the way a wake is — a node whose wake budget is
/// smaller than one Cat can still launch it cold.
#[test]
fn concurrent_launches_queue_under_the_ceiling_instead_of_failing() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_with(
        dir.path(),
        WakeBudget {
            // Deliberately below one Cat's 256 MiB resume commitment.
            commitment_bytes: 128 * 1024 * 1024,
            max_wakes: 2,
            ..Default::default()
        },
    );

    let mut workers = Vec::new();
    for index in 0..6 {
        let runtime = runtime.clone();
        workers.push(std::thread::spawn(move || {
            runtime.execute(start_job(&format!("cat_bound_{index}")))
        }));
    }
    for worker in workers {
        let result = worker.join().expect("launch thread panicked");
        assert_eq!(
            result.observed_state,
            ObservedState::Running,
            "a queued launch must still succeed: {result:?}"
        );
    }
    assert_eq!(
        runtime.wake_load().wakes,
        0,
        "a launch leaked a wake permit"
    );
}

/// Where does concurrent launch actually flatten out, and why?
///
/// Raises the ceiling out of the way so the remaining limit is the machine and
/// the shared state, not policy. Effective parallelism is `n * single / wall`.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn concurrent_launch_scaling() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_with(
        dir.path(),
        WakeBudget {
            commitment_bytes: u64::MAX,
            max_wakes: 64,
            ..Default::default()
        },
    );
    for warmup in 0..2 {
        runtime.execute(start_job(&format!("cat_scale_warm_{warmup}")));
    }
    let started = Instant::now();
    runtime.execute(start_job("cat_scale_single"));
    let single_ms = started.elapsed().as_millis().max(1);
    println!(
        "\nsingle launch {single_ms} ms on {} logical cpus\n{:>12} {:>10} {:>14} {:>22}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        "concurrent",
        "wall ms",
        "ms per launch",
        "effective parallelism"
    );
    for n in [1usize, 2, 4, 8, 16, 24] {
        let started = Instant::now();
        let mut workers = Vec::new();
        for index in 0..n {
            let runtime = runtime.clone();
            let tag = format!("cat_scale_{n}_{index}");
            workers.push(std::thread::spawn(move || runtime.execute(start_job(&tag))));
        }
        let failures = workers
            .into_iter()
            .map(|worker| worker.join().expect("launch thread panicked"))
            .filter(|result| result.observed_state != ObservedState::Running)
            .count();
        let wall_ms = started.elapsed().as_millis().max(1);
        assert_eq!(failures, 0, "{failures} of {n} launches failed");
        println!(
            "{:>12} {:>10} {:>14.1} {:>21.2}x",
            n,
            wall_ms,
            wall_ms as f64 / n as f64,
            (single_ms * n as u128) as f64 / wall_ms as f64
        );
    }
}

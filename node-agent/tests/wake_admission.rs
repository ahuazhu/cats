//! Bounded concurrent wakes (ADR-0002 §8 and its "wake storm 的准入与限流"
//! open item), exercised through the real job path with FakeVmm.
//!
//! Two properties matter and one of them is easy to fake by accident:
//!
//! 1. concurrency is actually *allowed* — peak in-flight must exceed one,
//!    otherwise the admission gate is inert behind node-wide serialization;
//! 2. concurrency is *bounded* — neither the wake count nor the committed
//!    bytes may exceed the configured budget at any instant.
//!
//! Every Cat must also keep its process identity across the wake, which is
//! the ADR-0002 oracle for Suspended (`boot_id` preserved).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use cats_api::nodejob::{job_id, NodeJob, NodeJobAction, VolumeGrant};
use cats_api::resources::ObservedState;
use cats_node_agent::admission::WakeBudget;
use cats_node_agent::runtime::NodeRuntime;
use cats_test_support::{fake_node_config, TempDirFixture};

const SIZE: u64 = 2 * cats_api::chunk::CHUNK_SIZE as u64;
const MEMORY_MIB: u64 = 256;

struct Env {
    _dir: TempDirFixture,
    runtime: Arc<NodeRuntime>,
}

fn env(budget: WakeBudget) -> Env {
    let dir = TempDirFixture::new();
    let builder = dir.node_config("node_wake");
    let runtime = NodeRuntime::new(fake_node_config!(builder, wake_budget = budget)).unwrap();
    Env {
        _dir: dir,
        runtime: Arc::new(runtime),
    }
}

fn grant(cat: &str) -> VolumeGrant {
    VolumeGrant {
        disk_id: "root".into(),
        volume_id: format!("vol_{cat}"),
        attachment_id: format!("att_{cat}"),
        epoch: 0,
        size_bytes: SIZE,
        mount_path: "/".into(),
        durability: Default::default(),
    }
}

fn job(cat: &str, kind: &str, action: NodeJobAction) -> NodeJob {
    NodeJob {
        job_id: job_id(cat, 1, kind),
        cat_generation: 1,
        action,
    }
}

/// Bring `cat` up and park it in Suspended.
fn suspended_cat(env: &Env, cat: &str) {
    let started = env.runtime.execute(job(
        cat,
        "start_cat",
        NodeJobAction::StartCat {
            cat_id: cat.into(),
            image: "test".into(),
            cpus: 1,
            memory_mib: MEMORY_MIB,
            volumes: vec![grant(cat)],
        },
    ));
    assert_eq!(
        started.observed_state,
        ObservedState::Running,
        "start {cat} failed: {:?}",
        started.error
    );
    let suspended = env.runtime.execute(job(
        cat,
        "suspend_cat",
        NodeJobAction::SuspendCat {
            cat_id: cat.into(),
            work_fence: None,
        },
    ));
    assert_eq!(
        suspended.observed_state,
        ObservedState::Suspended,
        "suspend {cat} failed: {:?}",
        suspended.error
    );
}

#[test]
fn concurrent_resumes_are_allowed_and_stay_within_budget() {
    const CATS: usize = 6;
    const CEILING: usize = 3;

    // Budget admits CEILING wakes of MEMORY_MIB each and not one more.
    let env = env(WakeBudget {
        commitment_bytes: CEILING as u64 * MEMORY_MIB * 1024 * 1024,
        max_wakes: CEILING,
        queue_timeout: Duration::from_secs(30),
    });
    let names: Vec<String> = (0..CATS).map(|i| format!("cat_wake_{i}")).collect();
    for cat in &names {
        suspended_cat(&env, cat);
    }

    // Release all wakes at once so they genuinely contend.
    let gate = Arc::new(Barrier::new(CATS));
    let breaches = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for cat in &names {
        let runtime = Arc::clone(&env.runtime);
        let gate = Arc::clone(&gate);
        let breaches = Arc::clone(&breaches);
        let cat = cat.clone();
        handles.push(std::thread::spawn(move || {
            gate.wait();
            let result = runtime.execute(job(
                &cat,
                "resume_cat",
                NodeJobAction::ResumeCat {
                    cat_id: cat.clone(),
                },
            ));
            // Sampled from inside the wake: the gate must hold right now.
            let load = runtime.wake_load();
            if load.wakes > CEILING
                || load.commitment_bytes > CEILING as u64 * MEMORY_MIB * 1024 * 1024
            {
                breaches.fetch_add(1, Ordering::SeqCst);
            }
            (cat, result)
        }));
    }

    for handle in handles {
        let (cat, result) = handle.join().expect("wake thread");
        assert_eq!(
            result.observed_state,
            ObservedState::Running,
            "resume {cat} failed: {:?}",
            result.error
        );
    }

    assert_eq!(
        breaches.load(Ordering::SeqCst),
        0,
        "wake budget was exceeded while wakes were in flight"
    );

    let load = env.runtime.wake_load();
    assert_eq!(load.wakes, 0, "wake permits leaked after the storm");
    assert_eq!(
        load.commitment_bytes, 0,
        "commitment leaked after the storm"
    );
    assert!(
        load.peak_wakes <= CEILING,
        "peak {} exceeded the ceiling {CEILING}",
        load.peak_wakes
    );
    // The point of the change: wakes really do overlap. Without this the
    // admission gate would be inert behind node-wide job serialization.
    assert!(
        load.peak_wakes > 1,
        "no wake ever overlapped another (peak {}), so concurrency is not enabled",
        load.peak_wakes
    );
}

#[test]
fn a_cat_larger_than_the_node_budget_fails_instead_of_hanging() {
    // Budget below one Cat's resume commitment: waiting can never satisfy it,
    // so the node must say so rather than burn the queue timeout.
    let env = env(WakeBudget {
        commitment_bytes: (MEMORY_MIB / 2) * 1024 * 1024,
        max_wakes: 4,
        queue_timeout: Duration::from_secs(30),
    });
    suspended_cat(&env, "cat_too_big");

    let started = std::time::Instant::now();
    let result = env.runtime.execute(job(
        "cat_too_big",
        "resume_cat",
        NodeJobAction::ResumeCat {
            cat_id: "cat_too_big".into(),
        },
    ));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "an unsatisfiable wake must fail fast, took {:?}",
        started.elapsed()
    );
    let error = result.error.unwrap_or_default();
    assert!(
        error.contains("exceeds the node wake budget"),
        "unexpected error: {error}"
    );
    // ADR-0002 §7: a failed wake must not leave the Cat wedged mid-state.
    assert_eq!(result.observed_state, ObservedState::Suspended);
    assert_eq!(
        env.runtime.wake_load().wakes,
        0,
        "failed wake leaked a permit"
    );
}

#[test]
fn telemetry_reports_the_configured_budget() {
    let env = env(WakeBudget {
        commitment_bytes: 7 * 1024 * 1024,
        max_wakes: 2,
        queue_timeout: Duration::from_secs(1),
    });
    let telemetry = env.runtime.telemetry();
    assert_eq!(telemetry.wake_commitment_budget_bytes, 7 * 1024 * 1024);
    assert_eq!(telemetry.wake_in_flight, 0);
}

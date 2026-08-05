use super::*;

const CONCURRENT_CATS: usize = 8;

fn start_concurrently(runtime: &Arc<NodeRuntime>, cats: usize, prefix: &str) -> Vec<NodeJobResult> {
    let start = Arc::new(std::sync::Barrier::new(cats));
    let workers: Vec<_> = (0..cats)
        .map(|index| {
            let runtime = Arc::clone(runtime);
            let start = Arc::clone(&start);
            let cat = format!("{prefix}_{index}");
            std::thread::spawn(move || {
                start.wait();
                runtime.execute(start_job(&cat, 1, &[("root", "/")]))
            })
        })
        .collect();
    workers
        .into_iter()
        .map(|worker| worker.join().expect("launch thread panicked"))
        .collect()
}

/// Structural replacement for the old wall-clock speedup assertion. Each
/// worker rendezvous occurs inside its real `spawn_blockd`, after the child is
/// ready but before that function returns, so all eight arrivals prove the
/// block-backend launch stage itself overlaps.
#[test]
fn concurrent_cold_launch_is_not_serialized() {
    let dir = tempfile::tempdir().expect("create test root");
    let probe = Arc::new(LaunchOverlapProbe::new(CONCURRENT_CATS));
    let mut runtime = NodeRuntime::new(real_child_node_config(dir.path(), "node_conc"))
        .expect("open node runtime");
    runtime.launch_overlap_probe = Some(Arc::clone(&probe));
    let runtime = Arc::new(runtime);

    for (index, result) in start_concurrently(&runtime, CONCURRENT_CATS, "cat_conc")
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            result.observed_state,
            ObservedState::Running,
            "cat_conc_{index} failed: {result:?}"
        );
    }
    assert_eq!(
        probe.arrived(),
        CONCURRENT_CATS,
        "the launch overlap probe did not observe every Cat"
    );
    assert_eq!(
        probe.timed_out.load(Ordering::SeqCst),
        0,
        "the launch overlap probe reached its liveness guard"
    );
    assert_eq!(
        runtime.launch_admission.load().peak_wakes,
        CONCURRENT_CATS,
        "all rendezvoused launches must hold admission simultaneously"
    );
}

/// Known-negative calibration: serializing only `spawn_blockd` must be enough
/// to trip the probe. This closes the blind spot where the older rendezvous,
/// placed after `spawn_blockd` returned, still passed despite a serialized
/// backend-launch stage.
#[test]
fn serialized_spawn_blockd_is_rejected_and_reaps_started_children() {
    const CATS: usize = 2;
    let dir = tempfile::tempdir().expect("create test root");
    let probe = Arc::new(LaunchOverlapProbe::with_timeout(
        CATS,
        Duration::from_millis(500),
    ));
    let mut runtime = NodeRuntime::new(real_child_node_config(dir.path(), "node_serial_spawn"))
        .expect("open node runtime");
    runtime.launch_overlap_probe = Some(Arc::clone(&probe));
    runtime.spawn_blockd_test_lock = Some(Arc::new(Mutex::new(())));
    let runtime = Arc::new(runtime);

    let results = start_concurrently(&runtime, CATS, "cat_serial_spawn");
    for result in results {
        assert_eq!(
            result.phase,
            JobPhase::Failed,
            "known-negative passed: {result:?}"
        );
        assert_eq!(result.observed_state, ObservedState::Cold);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.contains("launch overlap probe")),
            "known-negative produced the wrong error: {result:?}"
        );
    }
    assert_eq!(
        probe.arrived(),
        1,
        "only the lock holder may reach the probe"
    );
    assert_eq!(
        probe.timed_out.load(Ordering::SeqCst),
        1,
        "the serialized spawn must hit the bounded liveness guard exactly once"
    );
    assert!(
        runtime.cats.lock().unwrap().is_empty(),
        "failed starts must not leave supervised runtimes"
    );
}

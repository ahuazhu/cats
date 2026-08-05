use super::*;

const CONCURRENT_CATS: usize = 8;

/// Structural replacement for the old wall-clock speedup assertion. Each
/// worker has already started its real blockd before it can rendezvous, so all
/// eight arrivals prove the Cat launch paths themselves overlap.
#[test]
fn concurrent_cold_launch_is_not_serialized() {
    let dir = tempfile::tempdir().expect("create test root");
    let probe = Arc::new(LaunchOverlapProbe::new(CONCURRENT_CATS));
    let mut runtime = NodeRuntime::new(real_child_node_config(dir.path(), "node_conc"))
        .expect("open node runtime");
    runtime.launch_overlap_probe = Some(Arc::clone(&probe));
    let runtime = Arc::new(runtime);

    let start = Arc::new(std::sync::Barrier::new(CONCURRENT_CATS));
    let workers: Vec<_> = (0..CONCURRENT_CATS)
        .map(|index| {
            let runtime = Arc::clone(&runtime);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                runtime.execute(start_job(&format!("cat_conc_{index}"), 1, &[("root", "/")]))
            })
        })
        .collect();

    for (index, worker) in workers.into_iter().enumerate() {
        let result = worker.join().expect("launch thread panicked");
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

//! Suspend execution locking, exercised with real FakeVmm Guest processes.
//!
//! The proxy holds a Guest `syncfs` response at a deterministic boundary. That
//! makes overlap observable without treating wall-clock timing as a correctness
//! oracle, while all work before and after the boundary remains the real Guest
//! protocol and storage path.

use super::*;

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use cats_api::guest::{read_frame, write_frame, GuestRequest, GuestRequestBody, GuestResponse};

fn lifecycle_job(cat_id: &str, generation: i64, kind: &str, action: NodeJobAction) -> NodeJob {
    NodeJob {
        job_id: job_id(cat_id, generation, kind),
        cat_generation: generation,
        action,
    }
}

fn suspend_job(cat_id: &str, generation: i64, kind: &str) -> NodeJob {
    lifecycle_job(
        cat_id,
        generation,
        kind,
        NodeJobAction::SuspendCat {
            cat_id: cat_id.to_string(),
            work_fence: None,
        },
    )
}

fn resume_job(cat_id: &str, generation: i64, kind: &str) -> NodeJob {
    lifecycle_job(
        cat_id,
        generation,
        kind,
        NodeJobAction::ResumeCat {
            cat_id: cat_id.to_string(),
        },
    )
}

fn stop_job(cat_id: &str, generation: i64, kind: &str) -> NodeJob {
    lifecycle_job(
        cat_id,
        generation,
        kind,
        NodeJobAction::StopCat {
            cat_id: cat_id.to_string(),
            disposition: StopCatDisposition::Cold,
        },
    )
}

/// Put a transparent proxy in front of one Cat's Guest control socket and
/// hold the first `syncfs` response until `release` fires.
fn intercept_suspend_syncfs(
    runtime: &NodeRuntime,
    state_dir: &Path,
    cat_id: &str,
    arrived: mpsc::Sender<String>,
    release: mpsc::Receiver<()>,
) -> (PathBuf, PathBuf, std::thread::JoinHandle<()>) {
    let original = runtime
        .cats
        .lock()
        .unwrap()
        .get(cat_id)
        .expect("started Cat")
        .ctl_sock
        .clone();
    let proxy = short_socket_path(state_dir, cat_id, "suspend-test-proxy");
    let _ = std::fs::remove_file(&proxy);
    let listener = UnixListener::bind(&proxy).expect("bind suspend control proxy");
    let name = cat_id.to_string();
    let upstream_socket = original.clone();
    let worker = std::thread::spawn(move || {
        let (mut downstream, _) = listener.accept().expect("accept node connection");
        let mut upstream =
            UnixStream::connect(&upstream_socket).expect("connect real Guest control");
        let mut held_syncfs = false;
        while let Ok(request) = read_frame::<_, GuestRequest>(&mut downstream) {
            let is_syncfs = matches!(&request.body, GuestRequestBody::Syncfs);
            write_frame(&mut upstream, &request).expect("forward Guest request");
            let response: GuestResponse = read_frame(&mut upstream).expect("read Guest response");
            if is_syncfs && !held_syncfs {
                held_syncfs = true;
                arrived.send(name.clone()).expect("report syncfs arrival");
                release.recv().expect("release held syncfs");
            }
            write_frame(&mut downstream, &response).expect("forward Guest response");
        }
    });
    runtime
        .cats
        .lock()
        .unwrap()
        .get_mut(cat_id)
        .expect("started Cat")
        .ctl_sock = proxy.clone();
    (original, proxy, worker)
}

fn restore_control_socket(runtime: &NodeRuntime, cat_id: &str, original: PathBuf, proxy: &Path) {
    runtime
        .cats
        .lock()
        .unwrap()
        .get_mut(cat_id)
        .expect("Cat still exists")
        .ctl_sock = original;
    std::fs::remove_file(proxy).expect("remove suspend control proxy");
}

#[test]
fn different_cats_suspend_concurrently_but_one_cat_remains_serialized() {
    const CAT_A: &str = "cat_suspend_a";
    const CAT_B: &str = "cat_suspend_b";
    const CAT_SAME: &str = "cat_suspend_same";

    let env = real_cat_env("node_suspend_concurrency");
    for cat_id in [CAT_A, CAT_B, CAT_SAME] {
        env.run(start_job(cat_id, 1, &[("root", "/")]));
    }

    let (arrived_tx, arrived_rx) = mpsc::channel();
    let mut releases = Vec::new();
    let mut proxies = Vec::new();
    let mut workers = Vec::new();

    for cat_id in [CAT_A, CAT_B] {
        let (release_tx, release_rx) = mpsc::channel();
        proxies.push((
            cat_id,
            intercept_suspend_syncfs(
                &env.runtime,
                &env.cfg.state_dir,
                cat_id,
                arrived_tx.clone(),
                release_rx,
            ),
        ));
        releases.push(release_tx);
    }
    let (same_arrived_tx, same_arrived_rx) = mpsc::channel();
    let (same_release_tx, same_release_rx) = mpsc::channel();
    let same_proxy = intercept_suspend_syncfs(
        &env.runtime,
        &env.cfg.state_dir,
        CAT_SAME,
        same_arrived_tx,
        same_release_rx,
    );
    let runtime = Arc::new(env.runtime);
    for cat_id in [CAT_A, CAT_B] {
        let runtime = Arc::clone(&runtime);
        workers.push(std::thread::spawn(move || {
            runtime.execute(suspend_job(cat_id, 2, "suspend_concurrently"))
        }));
    }

    let first = arrived_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = arrived_rx.recv_timeout(Duration::from_secs(2));
    for release in releases {
        release.send(()).unwrap();
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let second = second.unwrap_or_else(|_| {
        panic!("second Cat was serialized behind {first} by the node-wide lock")
    });
    assert_ne!(first, second);
    assert!(results.iter().all(|result| {
        result.phase == JobPhase::Succeeded && result.observed_state == ObservedState::Suspended
    }));

    for (cat_id, (original, proxy, proxy_worker)) in proxies {
        proxy_worker.join().unwrap();
        restore_control_socket(&runtime, cat_id, original, &proxy);
    }

    // The same Cat must still serialize. Hold its first suspend at syncfs and
    // verify a second job cannot complete until that per-Cat operation settles.
    let (original, proxy, proxy_worker) = same_proxy;
    let first_runtime = Arc::clone(&runtime);
    let first = std::thread::spawn(move || {
        first_runtime.execute(suspend_job(CAT_SAME, 2, "suspend_same_first"))
    });
    same_arrived_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let (completed_tx, completed_rx) = mpsc::channel();
    let second_runtime = Arc::clone(&runtime);
    let second = std::thread::spawn(move || {
        let result = second_runtime.execute(suspend_job(CAT_SAME, 3, "suspend_same_second"));
        completed_tx.send(()).unwrap();
        result
    });
    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "a second SuspendCat bypassed the per-Cat lock"
    );
    same_release_tx.send(()).unwrap();
    assert_eq!(first.join().unwrap().phase, JobPhase::Succeeded);
    assert_eq!(second.join().unwrap().phase, JobPhase::Succeeded);
    proxy_worker.join().unwrap();
    restore_control_socket(&runtime, CAT_SAME, original, &proxy);

    for cat_id in [CAT_A, CAT_B, CAT_SAME] {
        assert_eq!(
            runtime
                .execute(resume_job(cat_id, 4, "resume_after_concurrency"))
                .observed_state,
            ObservedState::Running
        );
        assert_eq!(
            runtime
                .execute(stop_job(cat_id, 5, "stop_after_concurrency"))
                .observed_state,
            ObservedState::Cold
        );
    }
}

#[test]
fn an_abandoned_suspend_result_does_not_leak_the_per_cat_lock_or_gate() {
    const CAT: &str = "cat_suspend_abandoned";

    let env = real_cat_env("node_suspend_abandoned");
    env.run(start_job(CAT, 1, &[("root", "/")]));
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (original, proxy, proxy_worker) = intercept_suspend_syncfs(
        &env.runtime,
        &env.cfg.state_dir,
        CAT,
        arrived_tx,
        release_rx,
    );
    let runtime = Arc::new(env.runtime);
    let worker_runtime = Arc::clone(&runtime);
    let (result_tx, result_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = worker_runtime.execute(suspend_job(CAT, 2, "suspend_abandoned"));
        let _ = result_tx.send(result);
    });
    arrived_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // Model the dispatch deadline expiring: the blocking job keeps running,
    // but nobody remains to receive its eventual result.
    drop(result_rx);
    release_tx.send(()).unwrap();
    worker.join().unwrap();
    proxy_worker.join().unwrap();
    restore_control_socket(&runtime, CAT, original, &proxy);

    assert_eq!(
        runtime
            .execute(resume_job(CAT, 3, "resume_after_abandoned_result"))
            .observed_state,
        ObservedState::Running,
        "the abandoned caller leaked the per-Cat lock or Guest work gate"
    );
    assert_eq!(
        runtime
            .execute(suspend_job(CAT, 4, "suspend_after_abandoned_result"))
            .observed_state,
        ObservedState::Suspended,
        "a later suspend could not acquire the cleaned-up per-Cat path"
    );
    assert_eq!(
        runtime
            .execute(stop_job(CAT, 5, "stop_after_abandoned_result"))
            .observed_state,
        ObservedState::Cold
    );
}

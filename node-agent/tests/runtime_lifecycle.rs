//! Node-runtime integration tests with real child processes: the full
//! Running -> Suspended -> Running -> Warm -> Running -> Cold ladder
//! (ADR-0002) with boot-id oracles, plus hot attach/detach and journal
//! idempotency. Storage flows through real cats-blockd instances.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cats_api::guest::{
    AcquireGuestWorkLeaseRequest, GuestRequestBody, GuestResponseBody, GuestWorkLease,
    GUEST_WORK_LEASES_PATH,
};
use cats_api::nodejob::{job_id, JobPhase, NodeJob, NodeJobAction, SuspendWorkFence, VolumeGrant};
use cats_api::resources::ObservedState;
use cats_node_agent::guest_client::GuestClient;
use cats_node_agent::runtime::{NodeConfig, NodeRuntime};
use cats_node_agent::testutil::workspace_bin;
use cats_storage::{AdapterConfig, AdapterSelection};

const CAT: &str = "cat_rt";
const SIZE: u64 = 2 * cats_api::chunk::CHUNK_SIZE as u64;

struct Env {
    _dir: tempfile::TempDir,
    runtime: NodeRuntime,
    state_dir: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("node-state");
    let meta_path = dir.path().join("meta.db");
    let metadata_store = AdapterSelection {
        name: "sqlite".into(),
        config: AdapterConfig::from_pairs([("path", meta_path.display().to_string())]).unwrap(),
    };
    let object_store = AdapterSelection {
        name: "file".into(),
        config: AdapterConfig::from_pairs([(
            "root",
            dir.path().join("blob").display().to_string(),
        )])
        .unwrap(),
    };
    let runtime = NodeRuntime::new(
        NodeConfig {
            node_id: "node_test".into(),
            state_dir: state_dir.clone(),
            blockd_bin: workspace_bin("cats-blockd"),
            guest_agent_bin: workspace_bin("cats-guest-agent"),
            metadata_store,
            object_store,
            blockd_lease_ttl_ms: 1200,
            metering_cgroup_root: None,
            wake_budget: Default::default(),
            vmm: cats_node_agent::runtime::VmmMode::Fake,
        },
    );
    Env {
        _dir: dir,
        runtime,
        state_dir,
    }
}

fn grant(disk: &str, attempt: i64) -> VolumeGrant {
    VolumeGrant {
        disk_id: disk.to_string(),
        volume_id: format!("vol_{disk}"),
        attachment_id: format!("att_{disk}_{attempt}"),
        epoch: 0,
        size_bytes: SIZE,
        mount_path: if disk == "root" {
            "/".into()
        } else {
            "/data".into()
        },
    }
}

fn start_job(generation: i64) -> NodeJob {
    NodeJob {
        job_id: job_id(CAT, generation, "start_cat"),
        cat_generation: generation,
        action: NodeJobAction::StartCat {
            cat_id: CAT.into(),
            image: "test".into(),
            cpus: 1,
            memory_mib: 256,
            volumes: vec![grant("root", generation)],
        },
    }
}

fn simple(generation: i64, kind: &str, action: NodeJobAction) -> NodeJob {
    NodeJob {
        job_id: job_id(CAT, generation, kind),
        cat_generation: generation,
        action,
    }
}

fn guest(env: &Env) -> GuestClient {
    GuestClient::connect(&env.state_dir.join("cats").join(CAT).join("ctl.sock")).unwrap()
}

fn boot_id(env: &Env) -> String {
    guest(env).health().unwrap().0
}

fn guest_work(socket: &Path, method: &str, route: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = UnixStream::connect(socket).unwrap();
    write!(
        stream,
        "{method} {route} HTTP/1.1\r\nhost: cats-runtime\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let status = std::str::from_utf8(&response[..split])
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, response[split + 4..].to_vec())
}

/// `cats exec` must survive a command that prints nothing for a long time.
///
/// The guest-agent connection carried a 30 s read timeout meant for health
/// probes, so any quiet command -- a build, a test run, a large install -- was
/// killed at 30 s with "Resource temporarily unavailable". Measured on real
/// hardware before the fix: `sleep 20` returned, `sleep 40` failed after 30.7 s.
#[test]
fn exec_survives_a_command_that_is_quiet_for_longer_than_a_health_probe() {
    let env = env();
    assert_eq!(
        env.runtime.execute(start_job(1)).observed_state,
        ObservedState::Running
    );
    let started = std::time::Instant::now();
    let (code, stdout, stderr) = env
        .runtime
        .exec(CAT, vec!["sh".into(), "-c".into(), "sleep 35; echo awake".into()])
        .expect("a long quiet command must not be cut off");
    assert!(
        started.elapsed() >= Duration::from_secs(35),
        "the command did not actually run for 35 s"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.trim(), "awake");
}

#[test]
fn suspend_rejects_active_guest_work_then_succeeds_on_last_release() {
    let env = env();
    assert_eq!(
        env.runtime.execute(start_job(1)).observed_state,
        ObservedState::Running
    );
    let runtime_socket = env.runtime.runtime_socket_for(CAT).unwrap();
    let acquire = serde_json::to_vec(&AcquireGuestWorkLeaseRequest {
        label: "user-job".into(),
        ttl_ms: 5_000,
    })
    .unwrap();
    let (status, body) = guest_work(&runtime_socket, "POST", GUEST_WORK_LEASES_PATH, &acquire);
    assert_eq!(status, 201);
    let lease_id = serde_json::from_slice::<GuestWorkLease>(&body).unwrap().id;
    let active = guest(&env).work_status(None, 0).unwrap();
    let rejected = env.runtime.execute(simple(
        2,
        "suspend_active_work",
        NodeJobAction::SuspendCat {
            cat_id: CAT.into(),
            work_fence: Some(SuspendWorkFence {
                control_work_version: 1,
                guest_lease_sequence: active.lease_sequence,
            }),
        },
    ));
    assert_eq!(rejected.phase, JobPhase::Rejected);
    assert_eq!(rejected.observed_state, ObservedState::Running);

    let (status, body) = guest_work(
        &runtime_socket,
        "DELETE",
        &format!("{GUEST_WORK_LEASES_PATH}/{lease_id}"),
        &[],
    );
    assert_eq!(status, 204);
    assert!(body.is_empty());
    let idle = guest(&env).work_status(None, 0).unwrap();
    assert!(idle.leases.is_empty());
    let suspended = env.runtime.execute(simple(
        3,
        "suspend_after_release",
        NodeJobAction::SuspendCat {
            cat_id: CAT.into(),
            work_fence: Some(SuspendWorkFence {
                control_work_version: 2,
                guest_lease_sequence: idle.lease_sequence,
            }),
        },
    ));
    assert_eq!(suspended.phase, JobPhase::Succeeded);
    assert_eq!(suspended.observed_state, ObservedState::Suspended);
}

#[test]
fn cold_fallback_tears_down_an_existing_suspended_runtime_before_restart() {
    let env = env();
    let started = env.runtime.execute(start_job(1));
    assert_eq!(
        started.observed_state,
        ObservedState::Running,
        "start failed: {:?}",
        started.error
    );
    let original_boot = boot_id(&env);
    let suspended = env.runtime.execute(simple(
        1,
        "suspend_before_cold_fallback",
        NodeJobAction::SuspendCat {
            cat_id: CAT.into(),
            work_fence: None,
        },
    ));
    assert_eq!(suspended.observed_state, ObservedState::Suspended);

    // A control plane that lost placement can legitimately send a fresh Cold
    // start while the old Node process still remembers the host-bound
    // runtime. The Node must clean the old runtime first.
    let restarted = env.runtime.execute(start_job(2));
    assert_eq!(
        restarted.observed_state,
        ObservedState::Running,
        "cold fallback restart failed: {:?}",
        restarted.error
    );
    assert_ne!(
        boot_id(&env),
        original_boot,
        "Cold fallback must replace the old process identity"
    );
}

#[test]
fn full_lifecycle_ladder_with_boot_id_oracles() {
    let env = env();

    // Cold start.
    let res = env.runtime.execute(start_job(1));
    assert_eq!(
        res.observed_state,
        ObservedState::Running,
        "start failed: {:?}",
        res.error
    );
    let boot1 = boot_id(&env);

    // Write data through the real storage path and make it durable.
    let payload = b"persistent-bytes".to_vec();
    let mut g = guest(&env);
    g.request(GuestRequestBody::WriteBlock {
        disk_id: "root".into(),
        offset: 4096,
        data_hex: hex::encode(&payload),
    })
    .unwrap();
    g.flush_disk("root").unwrap();

    // Suspended (pause): process survives, boot id unchanged on resume.
    let res = env.runtime.execute(simple(
        1,
        "suspend_cat",
        NodeJobAction::SuspendCat {
            cat_id: CAT.into(),
            work_fence: None,
        },
    ));
    assert_eq!(res.observed_state, ObservedState::Suspended);
    let res = env.runtime.execute(simple(
        1,
        "resume_cat",
        NodeJobAction::ResumeCat { cat_id: CAT.into() },
    ));
    assert_eq!(
        res.observed_state,
        ObservedState::Running,
        "resume failed: {:?}",
        res.error
    );
    assert_eq!(boot_id(&env), boot1, "suspend/resume must keep the process");

    // Warm (snapshot + exit): no resident processes, identity preserved.
    env.runtime.execute(simple(
        1,
        "suspend_cat2",
        NodeJobAction::SuspendCat {
            cat_id: CAT.into(),
            work_fence: None,
        },
    ));
    let res = env.runtime.execute(simple(
        1,
        "warm_cat",
        NodeJobAction::WarmCat { cat_id: CAT.into() },
    ));
    assert_eq!(
        res.observed_state,
        ObservedState::Warm,
        "warm failed: {:?}",
        res.error
    );
    assert!(
        GuestClient::connect(&env.state_dir.join("cats").join(CAT).join("ctl.sock")).is_err(),
        "guest must be gone while Warm"
    );

    let res = env.runtime.execute(simple(
        1,
        "restore_cat",
        NodeJobAction::RestoreCat { cat_id: CAT.into() },
    ));
    assert_eq!(
        res.observed_state,
        ObservedState::Running,
        "restore failed: {:?}",
        res.error
    );
    assert_eq!(
        boot_id(&env),
        boot1,
        "warm restore must preserve process identity"
    );

    // Data written before Warm is still there (local warm cache or remote).
    let mut g = guest(&env);
    match g
        .request(GuestRequestBody::ReadBlock {
            disk_id: "root".into(),
            offset: 4096,
            len: 16,
        })
        .unwrap()
    {
        GuestResponseBody::Data { data_hex } => assert_eq!(hex::decode(data_hex).unwrap(), payload),
        other => panic!("unexpected {other:?}"),
    }

    // Exec runs a real command in the "guest".
    let (code, stdout, _) = env
        .runtime
        .exec(CAT, vec!["echo".into(), "hello".into()])
        .unwrap();
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "hello");

    // Stop -> Cold; a fresh start must be a *new* boot (oracle flips).
    let res = env.runtime.execute(simple(
        1,
        "stop_cat",
        NodeJobAction::StopCat { cat_id: CAT.into() },
    ));
    assert_eq!(res.observed_state, ObservedState::Cold);
    let res = env.runtime.execute(start_job(2));
    assert_eq!(
        res.observed_state,
        ObservedState::Running,
        "restart failed: {:?}",
        res.error
    );
    let boot2 = boot_id(&env);
    assert_ne!(boot2, boot1, "cold start must not reuse process identity");

    // Durable data survives the cold restart through the blobstore.
    let mut g = guest(&env);
    match g
        .request(GuestRequestBody::ReadBlock {
            disk_id: "root".into(),
            offset: 4096,
            len: 16,
        })
        .unwrap()
    {
        GuestResponseBody::Data { data_hex } => assert_eq!(hex::decode(data_hex).unwrap(), payload),
        other => panic!("unexpected {other:?}"),
    }
    env.runtime.execute(simple(
        2,
        "stop_cat",
        NodeJobAction::StopCat { cat_id: CAT.into() },
    ));
}

#[test]
fn hot_attach_detach_and_journal_idempotency() {
    let env = env();
    let res = env.runtime.execute(start_job(1));
    assert_eq!(
        res.observed_state,
        ObservedState::Running,
        "{:?}",
        res.error
    );

    // Journal: the same job id replays without side effects.
    let boot1 = boot_id(&env);
    let replay = env.runtime.execute(start_job(1));
    assert_eq!(replay.observed_state, ObservedState::Running);
    assert_eq!(
        boot_id(&env),
        boot1,
        "journal replay must not restart the guest"
    );

    // Hot attach a data disk, write, flush, detach.
    let res = env.runtime.execute(simple(
        1,
        "attach_data",
        NodeJobAction::AttachDisk {
            cat_id: CAT.into(),
            volume: grant("data", 1),
        },
    ));
    assert_eq!(
        res.observed_state,
        ObservedState::Running,
        "{:?}",
        res.error
    );

    let mut g = guest(&env);
    match g.request(GuestRequestBody::Health).unwrap() {
        GuestResponseBody::Health { disks, .. } => {
            assert!(
                disks.contains(&"data".to_string()),
                "disk map must include hot disk"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    g.request(GuestRequestBody::WriteBlock {
        disk_id: "data".into(),
        offset: 0,
        data_hex: hex::encode(b"on-data-disk"),
    })
    .unwrap();
    g.flush_disk("data").unwrap();

    let res = env.runtime.execute(simple(
        1,
        "detach_data",
        NodeJobAction::DetachDisk {
            cat_id: CAT.into(),
            disk_id: "data".into(),
        },
    ));
    assert_eq!(
        res.observed_state,
        ObservedState::Running,
        "{:?}",
        res.error
    );

    // Block ops on the detached disk now fail cleanly.
    let mut g = guest(&env);
    let resp = g.request(GuestRequestBody::ReadBlock {
        disk_id: "data".into(),
        offset: 0,
        len: 4,
    });
    assert!(resp.is_err(), "reads from a detached disk must fail");

    env.runtime.execute(simple(
        1,
        "stop_cat",
        NodeJobAction::StopCat { cat_id: CAT.into() },
    ));
}

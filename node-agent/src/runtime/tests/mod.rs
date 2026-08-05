use super::*;

use cats_api::nodejob::job_id;

use ledger::CatLedgerRecord;

mod adoption;
mod ledger_writes;
mod residue_sweep;
mod suspend_concurrency;

// ---------------------------------------------------------------------------
// Real-Cat harness
//
// Shared by the sibling test modules that need an actual Cat rather than a
// hand-built `CatRuntime`: a real `cats-blockd` per disk and a real
// `cats-guest-agent`, started by one `NodeRuntime` over a tempdir state
// directory. `restarted_agent` builds a second `NodeRuntime` over the same
// directory and the same still-running processes, which is what an agent
// restart actually looks like.
// ---------------------------------------------------------------------------

const VOLUME_SIZE: u64 = 2 * cats_api::chunk::CHUNK_SIZE as u64;
const CPUS: u32 = 2;
const MEMORY_MIB: u64 = 512;

struct RealCatEnv {
    _dir: tempfile::TempDir,
    root: PathBuf,
    cfg: NodeConfig,
    /// The agent that started the Cat and still owns its children.
    runtime: NodeRuntime,
}

fn real_cat_env(node_id: &str) -> RealCatEnv {
    let dir = tempfile::tempdir().expect("create test root");
    let root = dir.path().to_path_buf();
    let cfg = real_child_node_config(&root, node_id);
    let runtime = NodeRuntime::new(cfg.clone()).expect("open node runtime");
    RealCatEnv {
        _dir: dir,
        root,
        cfg,
        runtime,
    }
}

impl RealCatEnv {
    /// A fresh agent process over the same state directory and the same
    /// still-running children.
    fn restarted_agent(&self) -> NodeRuntime {
        NodeRuntime::new(self.cfg.clone()).expect("open the restarted node runtime")
    }

    fn run(&self, job: NodeJob) -> NodeJobResult {
        let result = self.runtime.execute(job);
        assert_eq!(
            result.phase,
            JobPhase::Succeeded,
            "job failed: {:?}",
            result.error
        );
        result
    }

    fn record(&self, cat_id: &str) -> CatLedgerRecord {
        self.runtime
            .ledger
            .load_all()
            .expect("load ledger records")
            .into_iter()
            .find(|record| record.cat_id == cat_id)
            .unwrap_or_else(|| panic!("no runtime ledger record for {cat_id}"))
    }

    fn rewrite_record(&self, record: &CatLedgerRecord) {
        self.runtime
            .ledger
            .put(record)
            .expect("rewrite the runtime ledger record");
    }
}

fn grant(cat_id: &str, disk_id: &str, mount_path: &str) -> VolumeGrant {
    VolumeGrant {
        disk_id: disk_id.to_string(),
        volume_id: format!("vol_{cat_id}_{disk_id}"),
        attachment_id: format!("att_{cat_id}_{disk_id}"),
        epoch: 0,
        size_bytes: VOLUME_SIZE,
        mount_path: mount_path.to_string(),
        durability: Default::default(),
    }
}

fn start_job(cat_id: &str, generation: i64, disks: &[(&str, &str)]) -> NodeJob {
    NodeJob {
        job_id: job_id(cat_id, generation, "start_cat"),
        cat_generation: generation,
        action: NodeJobAction::StartCat {
            cat_id: cat_id.to_string(),
            image: "test".into(),
            cpus: CPUS,
            memory_mib: MEMORY_MIB,
            volumes: disks
                .iter()
                .map(|(disk_id, mount_path)| grant(cat_id, disk_id, mount_path))
                .collect(),
        },
    }
}

#[derive(Default)]
struct RecordingUsageFinalizer {
    targets: Mutex<Vec<CatTelemetryTarget>>,
}

#[test]
fn forced_blockd_drain_allows_remote_tail_beyond_status_probe_deadline() {
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixListener;

    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("blockd-control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let responder = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut command = String::new();
        std::io::BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut command)
            .unwrap();
        assert_eq!(command, "drain\n");
        std::thread::sleep(BLOCKD_STATUS_TIMEOUT + Duration::from_millis(250));
        stream.write_all(b"OK {}\n").unwrap();
    });

    let started = Instant::now();
    BlockdProc::drain_at(&socket, "disk-a").unwrap();
    assert!(started.elapsed() > BLOCKD_STATUS_TIMEOUT);
    responder.join().unwrap();
}

impl UsageFinalizer for RecordingUsageFinalizer {
    fn finalize(&self, target: CatTelemetryTarget) -> Result<()> {
        self.targets.lock().unwrap().push(target);
        Ok(())
    }
}

fn test_runtime(state: ObservedState, cgroup_path: PathBuf) -> CatRuntime {
    CatRuntime {
        generation: 1,
        cpus: 1,
        memory_mib: 256,
        state,
        guest: None,
        boot_id: Some("boot-a".to_string()),
        blockds: HashMap::new(),
        volumes: Vec::new(),
        dir: PathBuf::from("/tmp/cats-metering-test"),
        ctl_sock: PathBuf::from("/tmp/cats-metering-test-ctl"),
        web_sock: PathBuf::from("/tmp/cats-metering-test-web"),
        runtime_sock: PathBuf::from("/tmp/cats-metering-test-runtime"),
        activity: Arc::new(RuntimeActivity::default()),
        metering: Some(RuntimeMetering {
            cgroup_path,
            source_epoch: "epoch-a".to_string(),
        }),
        ch: None,
    }
}

#[test]
fn warm_hides_compute_meter_while_suspended_keeps_it() {
    let mut runtime = test_runtime(
        ObservedState::Suspended,
        PathBuf::from("/sys/fs/cgroup/cats/cat-a"),
    );

    assert!(runtime.telemetry_target("cat-a").metering.is_some());
    runtime.state = ObservedState::Warm;
    assert!(runtime.telemetry_target("cat-a").metering.is_none());
    assert!(runtime
        .lifecycle_telemetry_target("cat-a")
        .metering
        .is_some());
}

#[test]
fn warm_retirement_finalizes_then_drops_the_metering_cgroup() {
    let temp = tempfile::tempdir().unwrap();
    let cgroup = temp.path().join("cat-a");
    std::fs::create_dir(&cgroup).unwrap();
    let finalizer = Arc::new(RecordingUsageFinalizer::default());
    let runtime = NodeRuntime::new(stub_node_config(temp.path(), VmmMode::Fake))
        .unwrap()
        .with_usage_finalizer(finalizer.clone());
    runtime.cats.lock().unwrap().insert(
        "cat-a".to_string(),
        test_runtime(ObservedState::Warm, cgroup.clone()),
    );

    runtime.retire_warm_metering("cat-a").unwrap();

    let targets = finalizer.targets.lock().unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].metering.as_ref().unwrap().source_epoch,
        "epoch-a"
    );
    drop(targets);
    assert!(runtime
        .cats
        .lock()
        .unwrap()
        .get("cat-a")
        .unwrap()
        .metering
        .is_none());
    assert!(!cgroup.exists());
}

#[test]
fn proxy_request_preserves_method_path_headers_and_body() {
    let request = ProxyHttpRequest {
        method: "POST".to_string(),
        path: "/api/items?q=one".to_string(),
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("connection".to_string(), "keep-alive".to_string()),
        ],
        body: br#"{"name":"cat"}"#.to_vec(),
        target_port: 8080,
        route_epoch: 7,
    };
    let raw = build_guest_http_request(&request).unwrap();
    let text = String::from_utf8(raw).unwrap();
    assert!(text.starts_with("POST /api/items?q=one HTTP/1.1\r\n"));
    assert!(text.contains("host: guest\r\n"));
    assert!(text.contains("content-type: application/json\r\n"));
    assert!(text.contains("x-cats-route-epoch: 7\r\n"));
    assert!(!text.contains("keep-alive"));
    assert!(text.ends_with(r#"{"name":"cat"}"#));
}

#[test]
fn proxy_response_preserves_status_headers_and_decodes_chunks() {
    let raw = b"HTTP/1.1 201 Created\r\n\
                content-type: text/plain\r\n\
                transfer-encoding: chunked\r\n\
                connection: close\r\n\r\n\
                5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let response = parse_guest_http_response(raw).unwrap();
    assert_eq!(response.status, 201);
    assert_eq!(response.body, b"hello world");
    assert_eq!(
        response.headers,
        vec![("content-type".to_string(), "text/plain".to_string())]
    );
}

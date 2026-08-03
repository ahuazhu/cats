use super::*;

mod ledger_writes;

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
    let adapter = AdapterSelection::new("unused", cats_storage::AdapterConfig::default());
    let finalizer = Arc::new(RecordingUsageFinalizer::default());
    let runtime = NodeRuntime::new(NodeConfig {
        node_id: "node-a".to_string(),
        state_dir: temp.path().to_path_buf(),
        blockd_bin: PathBuf::from("unused-blockd"),
        guest_agent_bin: PathBuf::from("unused-guest-agent"),
        metadata_store: adapter.clone(),
        object_store: adapter,
        blockd_lease_ttl_ms: 1_000,
        blockd_max_staged_bytes: cats_api::blockd::DEFAULT_MAX_STAGED_BYTES,
        blockd_max_staged_packs: cats_api::blockd::DEFAULT_MAX_STAGED_PACKS,
        blockd_max_local_bytes: cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES,
        metering_cgroup_root: None,
        vmm: VmmMode::Fake,
        wake_budget: WakeBudget::default(),
    })
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

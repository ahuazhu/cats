//! Durable usage delivery remains independent after the legacy heartbeat and
//! work-status transports have been removed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use cats_api::agent_registration::{
    verify_request_proof, Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER, REGISTRATION_PATH,
};
use cats_api::metering::{CatUsageCheckpoint, UsageMetric};
use cats_api::nodejob::{job_id, NodeJob, NodeJobAction, VolumeGrant};
use cats_api::resources::ObservedState;
use cats_api::runtime_reconciliation::{
    decode_agent_registration_attempt, encode_agent_session, AgentSession, AsciiText,
    ContractVersion, CredentialBinding, Epoch, GuestRuntimeProfileReceipt, Id, NodeBootId,
    NodeIdentity, NodeIdentityState, Sha256Digest, UnixMillis,
};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_node_agent::agent_registration::AgentRegistrationConfig;
use cats_node_agent::runtime::NodeRuntime;
use cats_node_agent::server::{spawn, ServerConfig};
use cats_node_agent::usage_spool::UsageSpool;
use cats_storage::MetadataStore;
use cats_test_support::{fake_node_config, NodeConfigBuilder, TempDirFixture};

const HEARTBEAT_MS: u64 = 200;
const WORK_PRODUCER_CAT: &str = "cat_work_producer";
const WORK_PRODUCER_GENERATION: i64 = 1;

/// Longer than any plausible lease, so if liveness is coupled to upload at all
/// the heartbeat gap becomes unmistakable rather than marginal.
const USAGE_HANG: Duration = Duration::from_secs(30);

#[derive(Clone, Default)]
struct MockControlPlane {
    registrations: Arc<AtomicUsize>,
    usage_attempts: Arc<AtomicUsize>,
    legacy_heartbeat_attempts: Arc<AtomicUsize>,
    legacy_work_status_attempts: Arc<AtomicUsize>,
}

async fn trap_legacy_heartbeat(State(cp): State<MockControlPlane>) -> StatusCode {
    cp.legacy_heartbeat_attempts.fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

async fn trap_legacy_work_status(State(cp): State<MockControlPlane>) -> StatusCode {
    cp.legacy_work_status_attempts
        .fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

/// Stands in for an ingest that is grinding through a large backlog: the request
/// never returns within the agent's client timeout.
async fn mock_usage_hang(State(cp): State<MockControlPlane>) -> StatusCode {
    cp.usage_attempts.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(USAGE_HANG).await;
    StatusCode::NO_CONTENT
}

async fn mock_usage_ok(State(cp): State<MockControlPlane>) -> StatusCode {
    cp.usage_attempts.fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

async fn mock_registration(
    State(cp): State<MockControlPlane>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    cp.registrations.fetch_add(1, Ordering::SeqCst);
    verify_request_proof(
        "POST",
        REGISTRATION_PATH,
        &body,
        headers
            .get(NODE_CREDENTIAL_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        headers
            .get(NODE_PUBLIC_KEY_SPKI_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        headers
            .get(NODE_SIGNATURE_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let attempt = decode_agent_registration_attempt(&body).unwrap();
    (
        [("content-type", JSON_CONTENT_TYPE)],
        encode_agent_session(&AgentSession {
            version: ContractVersion::V1,
            node_id: attempt.node_id,
            immutable_host_id: attempt.immutable_host_id,
            node_boot_id: attempt.node_boot_id,
            agent_instance_id: attempt.agent_instance_id,
            agent_session_epoch: Epoch::new(1).unwrap(),
            registration_attempt_id: attempt.registration_attempt_id,
            guest_config_digest: attempt.guest_config_digest,
            lease_deadline_unix_ms: UnixMillis::new(1_900_000_060_000).unwrap(),
        })
        .unwrap(),
    )
        .into_response()
}

async fn start_mock(hang_usage: bool) -> (MockControlPlane, String) {
    let cp = MockControlPlane::default();
    let usage = if hang_usage {
        post(mock_usage_hang)
    } else {
        post(mock_usage_ok)
    };
    let app = Router::new()
        .route("/v1/internal/usage/checkpoints", usage)
        .route(REGISTRATION_PATH, post(mock_registration))
        // These are traps, not compatibility behavior: a regression in the
        // agent's outbound task graph gets a successful response and is
        // detected only by the exact zero-call assertions below.
        .route("/v1/nodes/heartbeat", post(trap_legacy_heartbeat))
        .route("/v1/nodes/work-status", post(trap_legacy_work_status))
        .with_state(cp.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (cp, format!("http://{addr}"))
}

fn assert_signed_registration_without_legacy_posts(cp: &MockControlPlane) {
    assert!(
        cp.registrations.load(Ordering::SeqCst) >= 1,
        "the positive signed registration probe never reached the mock control plane",
    );
    assert_eq!(
        cp.legacy_heartbeat_attempts.load(Ordering::SeqCst),
        0,
        "the retired heartbeat transport was resurrected",
    );
    assert_eq!(
        cp.legacy_work_status_attempts.load(Ordering::SeqCst),
        0,
        "the retired work-status transport was resurrected",
    );
}

/// Put one checkpoint in the spool the agent will open, so the uploader has
/// something to send. Without this the delivery path short-circuits on an empty
/// spool and never makes a request -- which would let these tests pass even with
/// upload wired back into the heartbeat loop.
fn seed_spool(state_dir: &std::path::Path) {
    let spool = UsageSpool::open(&state_dir.join("usage-spool.sqlite3")).unwrap();
    spool
        .enqueue(&[CatUsageCheckpoint {
            event_id: "evt_seed_1".into(),
            source_id: "node/node_a/cat/cat_seed".into(),
            source_epoch: "epoch-1".into(),
            sequence: 1,
            observed_at_unix_ms: 1_785_000_000_000,
            cat_id: "cat_seed".into(),
            cat_generation: 1,
            metric: UsageMetric::CpuUsec,
            cumulative_quantity: 1_000,
        }])
        .unwrap();
}

async fn start_agent(
    dir: &TempDirFixture,
    control_plane_url: String,
) -> cats_node_agent::server::Handle {
    let state_dir = dir.path().join("node-a");
    std::fs::create_dir_all(&state_dir).unwrap();
    seed_spool(&state_dir);
    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    let signer = Ed25519RequestSigner::from_pkcs8_pem(
        Id::new("credential_node_a").unwrap(),
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
    )
    .unwrap();
    let receipt = GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        initramfs_digest: None,
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    };
    let registration = AgentRegistrationConfig::for_loopback_test(
        NodeIdentity {
            version: ContractVersion::V1,
            node_id: Id::new("node_a").unwrap(),
            immutable_host_id: Id::new("host_a").unwrap(),
            credential_id: signer.credential_id().clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: Id::new("state_a").unwrap(),
            state: NodeIdentityState::Provisioned,
        },
        signer,
        state_dir.clone(),
        NodeBootId::new("11111111111111111111111111111111").unwrap(),
        &receipt,
    )
    .unwrap();
    let mut node_config =
        fake_node_config!(
            NodeConfigBuilder::new(dir.path(), "node_a".to_string()).with_state_dir(state_dir)
        );
    node_config.state_dir = registration.runtime_state_directory();
    spawn(ServerConfig {
        listen: "127.0.0.1:0".into(),
        control_plane_url,
        auth_token: "dev-service-token".into(),
        agent_registration: registration,
        route_grant_verifier: Arc::new(
            cats_node_agent::route_grant::RouteGrantVerifier::from_ed25519_pem(include_bytes!(
                "../../tests/fixtures/route_grant_public_ed25519.pem"
            ))
            .unwrap(),
        ),
        heartbeat_ms: HEARTBEAT_MS,
        storage_meta,
        node: node_config,
    })
    .await
    .unwrap()
}

fn start_work_producer_job() -> NodeJob {
    NodeJob {
        job_id: job_id(WORK_PRODUCER_CAT, WORK_PRODUCER_GENERATION, "start_cat"),
        cat_generation: WORK_PRODUCER_GENERATION,
        action: NodeJobAction::StartCat {
            cat_id: WORK_PRODUCER_CAT.into(),
            image: "test".into(),
            cpus: 1,
            memory_mib: 256,
            volumes: vec![VolumeGrant {
                disk_id: "root_work_producer".into(),
                volume_id: "vol_work_producer".into(),
                attachment_id: "att_work_producer".into(),
                epoch: 0,
                size_bytes: 2 * cats_api::chunk::CHUNK_SIZE as u64,
                mount_path: "/".into(),
                durability: Default::default(),
            }],
        },
    }
}

fn cleanup_work_producer_job() -> NodeJob {
    NodeJob {
        job_id: job_id(WORK_PRODUCER_CAT, WORK_PRODUCER_GENERATION, "cleanup_cat"),
        cat_generation: WORK_PRODUCER_GENERATION,
        action: NodeJobAction::CleanupCat {
            cat_id: WORK_PRODUCER_CAT.into(),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkProducerPids {
    guest: u32,
    blockd: u32,
}

fn work_producer_pids(runtime: &NodeRuntime) -> WorkProducerPids {
    let path = runtime
        .cfg
        .state_dir
        .path()
        .join("runtime-ledger")
        .join(format!("{WORK_PRODUCER_CAT}.json"));
    let record: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let guest = u32::try_from(record["guest"]["pid"].as_u64().unwrap()).unwrap();
    let blockds = record["blockds"].as_array().unwrap();
    assert_eq!(blockds.len(), 1, "calibration Cat must own one blockd");
    let blockd = u32::try_from(blockds[0]["proc"]["pid"].as_u64().unwrap()).unwrap();
    assert_ne!(guest, blockd);
    WorkProducerPids { guest, blockd }
}

fn process_exists(pid: u32) -> bool {
    let pid = libc::pid_t::try_from(pid).unwrap();
    // SAFETY: signal 0 sends no signal and copies the scalar pid. This probe
    // never kills a process, including if the numeric pid was already reused.
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => false,
        Some(libc::EPERM) => true,
        error => panic!("probing pid {pid} failed with {error:?}"),
    }
}

fn wait_for_exact_children_reaped(pids: WorkProducerPids) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_exists(pids.guest) || process_exists(pids.blockd) {
        assert!(
            Instant::now() < deadline,
            "calibration children were not reaped: {pids:?}",
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Owns the exact FakeVmm children from the instant StartCat succeeds. Its
/// Drop path is deliberately assertion-free: it may run while another test
/// assertion is already unwinding and must still attempt CleanupCat.
struct RunningWorkProducer {
    runtime: Arc<NodeRuntime>,
    pids: Option<WorkProducerPids>,
    armed: bool,
}

impl RunningWorkProducer {
    fn start(runtime: Arc<NodeRuntime>) -> Self {
        let result = runtime.execute(start_work_producer_job());
        let mut producer = Self {
            runtime,
            pids: None,
            armed: result.observed_state == ObservedState::Running,
        };
        assert_eq!(
            result.observed_state,
            ObservedState::Running,
            "FakeVmm work producer did not start: {:?}",
            result.error,
        );
        producer.pids = Some(work_producer_pids(&producer.runtime));
        producer
    }

    fn calibrate(&self, inject_panic_after_status: bool) {
        // This is the exact positive seam the removed watcher used: a Running
        // runtime must be discoverable and its Guest must produce work status.
        let mut targets = self.runtime.activity_targets();
        assert_eq!(
            targets.len(),
            1,
            "Running Cat missing from activity targets"
        );
        let (cat_id, generation, connection) = targets.pop().unwrap();
        assert_eq!(cat_id, WORK_PRODUCER_CAT);
        assert_eq!(generation, WORK_PRODUCER_GENERATION);
        let status = connection
            .connect()
            .and_then(|mut guest| guest.work_status(None, 0))
            .unwrap();
        assert!(!status.source_epoch.is_empty());
        if inject_panic_after_status {
            panic!("injected work-producer calibration failure");
        }
    }

    fn pids(&self) -> WorkProducerPids {
        self.pids.expect("Running producer has recorded child pids")
    }

    async fn stop(mut self) {
        let runtime = Arc::clone(&self.runtime);
        let pids = self.pids();
        let result = tokio::task::spawn_blocking(move || {
            let result = runtime.execute(cleanup_work_producer_job());
            if result.observed_state == ObservedState::Cold {
                wait_for_exact_children_reaped(pids);
            }
            result
        })
        .await
        .unwrap();
        if result.observed_state == ObservedState::Cold {
            self.armed = false;
        }
        assert_eq!(result.observed_state, ObservedState::Cold);
    }
}

impl Drop for RunningWorkProducer {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let runtime = Arc::clone(&self.runtime);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            runtime.execute(cleanup_work_producer_job())
        }));
        self.armed = false;
    }
}

async fn start_running_work_producer(
    agent: &cats_node_agent::server::Handle,
) -> RunningWorkProducer {
    let runtime = Arc::clone(&agent.state.runtime);
    tokio::task::spawn_blocking(move || {
        let producer = RunningWorkProducer::start(runtime);
        producer.calibrate(false);
        producer
    })
    .await
    .unwrap()
}

/// A wedged upload remains bounded to its own task.
#[tokio::test]
async fn a_hanging_usage_upload_does_not_delay_the_heartbeat() {
    let dir = TempDirFixture::new();
    let (cp, url) = start_mock(true).await;
    let _agent = start_agent(&dir, url).await;

    // Enough ticks that a single coupled upload would be obvious: with the old
    // inline call the second heartbeat would not arrive for 10 s.
    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS * 12)).await;

    assert!(
        cp.usage_attempts.load(Ordering::SeqCst) >= 1,
        "the uploader must still be trying on its own channel"
    );
    assert_signed_registration_without_legacy_posts(&cp);
}

/// The upload still happens without either retired Node transport.
#[tokio::test]
async fn usage_upload_runs_on_its_own_channel() {
    let dir = TempDirFixture::new();
    let (cp, url) = start_mock(false).await;
    let agent = start_agent(&dir, url).await;
    let producer = start_running_work_producer(&agent).await;

    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS * 10)).await;
    producer.stop().await;
    assert!(
        cp.usage_attempts.load(Ordering::SeqCst) >= 1,
        "decoupling must not mean the upload stops happening"
    );
    assert_signed_registration_without_legacy_posts(&cp);
}

#[test]
fn panicking_calibration_reaps_its_exact_fakevmm_children() {
    let dir = TempDirFixture::new();
    let runtime = Arc::new(
        NodeRuntime::new(fake_node_config!(NodeConfigBuilder::new(
            dir.path(),
            "node_panic_cleanup",
        )))
        .unwrap(),
    );
    let observed_pids = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&observed_pids);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let producer = RunningWorkProducer::start(runtime);
        *capture.lock().unwrap() = Some(producer.pids());
        producer.calibrate(true);
    }));
    assert!(panic.is_err(), "calibration failure was not injected");

    let pids = observed_pids
        .lock()
        .unwrap()
        .expect("calibration did not record exact child pids");
    wait_for_exact_children_reaped(pids);
    assert!(!process_exists(pids.guest), "Guest pid survived unwind");
    assert!(!process_exists(pids.blockd), "blockd pid survived unwind");
}

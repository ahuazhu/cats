//! Startup ordering and the control-plane connection loop (ADR-0040 §6).
//!
//! Two properties are under test here, and they are the two halves of "a node
//! agent survives its own restart":
//!
//! 1. A control plane that is unreachable at startup degrades the agent instead
//!    of ending it. `spawn` used to register inside a 30-second deadline and
//!    `bail!` — with `Restart=always` in the systemd units that turned a
//!    control-plane outage into a restart loop.
//! 2. The agent adopts its local inventory *before* it announces itself, so the
//!    very first heartbeat carries every Cat it re-adopted at the generation it
//!    recorded. That complete same-generation inventory is the only thing that
//!    recovers a `Lost` node. A Cat adoption refused must stay out of the
//!    heartbeat entirely (ADR-0040 §6 fail-closed rule), never reported as `Cold`.
//!
//! The stub control plane below implements only `/v1/nodes/register` and
//! `/v1/nodes/heartbeat` and records what it received; the real handlers are
//! covered by the control-plane tests.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

use cats_api::nodejob::{job_id, NodeJob, NodeJobAction, StopCatDisposition, VolumeGrant};
use cats_api::requests::{HeartbeatRequest, RegisterNodeRequest};
use cats_api::resources::ObservedState;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_node_agent::runtime::{NodeConfig, NodeRuntime};
use cats_node_agent::server::{spawn, Handle, ServerConfig};
use cats_storage::MetadataStore;
use cats_test_support::{fake_node_config, NodeConfigBuilder};

const SERVICE_TOKEN: &str = "test-service-token";
const HEARTBEAT_MS: u64 = 100;
const VOLUME_SIZE: u64 = 2 * cats_api::chunk::CHUNK_SIZE as u64;

// ---------------------------------------------------------------------------
// Stub control plane
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct StubControlPlane {
    registrations: Arc<Mutex<Vec<RegisterNodeRequest>>>,
    heartbeats: Arc<Mutex<Vec<HeartbeatRequest>>>,
}

impl StubControlPlane {
    /// Serve on an already-bound listener. The caller owns the address, which
    /// is what lets a test start the control plane *after* the node agent is
    /// already looking for it.
    fn serve(&self, listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
        let app = Router::new()
            .route("/v1/nodes/register", post(register_node))
            .route("/v1/nodes/heartbeat", post(heartbeat))
            .with_state(self.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        })
    }

    fn registrations(&self) -> Vec<RegisterNodeRequest> {
        self.registrations
            .lock()
            .expect("registration log mutex")
            .clone()
    }

    fn heartbeats(&self) -> Vec<HeartbeatRequest> {
        self.heartbeats.lock().expect("heartbeat log mutex").clone()
    }
}

async fn register_node(
    State(stub): State<StubControlPlane>,
    Json(request): Json<RegisterNodeRequest>,
) -> StatusCode {
    stub.registrations
        .lock()
        .expect("registration log mutex")
        .push(request);
    StatusCode::NO_CONTENT
}

async fn heartbeat(
    State(stub): State<StubControlPlane>,
    Json(request): Json<HeartbeatRequest>,
) -> StatusCode {
    stub.heartbeats
        .lock()
        .expect("heartbeat log mutex")
        .push(request);
    StatusCode::NO_CONTENT
}

/// An address nothing is listening on: bound to learn a free port, then
/// released. A test that wants the control plane to appear later binds it
/// again.
async fn reserved_address() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve a loopback port");
    let address = listener.local_addr().expect("reserved local address");
    drop(listener);
    address
}

async fn listen_on(address: SocketAddr) -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind(address)
        .await
        .unwrap_or_else(|error| panic!("bind the reserved address {address}: {error}"))
}

// ---------------------------------------------------------------------------
// Node agent fixture
// ---------------------------------------------------------------------------

/// A node-agent configuration over `root`, reusable across "restarts": two
/// agents built from the same root share a state directory and therefore the
/// same runtime ledger.
fn node_config(root: &Path, node_id: &str) -> NodeConfig {
    fake_node_config!(NodeConfigBuilder::new(root, node_id))
}

fn server_config(node: NodeConfig, root: &Path, control_plane_url: String) -> ServerConfig {
    let storage_meta: Arc<dyn MetadataStore> = Arc::new(
        SqliteMetadataStore::open(&root.join("meta.db")).expect("open the metadata store"),
    );
    ServerConfig {
        listen: "127.0.0.1:0".into(),
        advertise_url: None,
        control_plane_url,
        auth_token: SERVICE_TOKEN.into(),
        route_grant_verifier: Arc::new(
            cats_node_agent::route_grant::RouteGrantVerifier::from_ed25519_pem(include_bytes!(
                "../../tests/fixtures/route_grant_public_ed25519.pem"
            ))
            .unwrap(),
        ),
        gateway_url: "http://127.0.0.1:1".into(),
        cpus: 4,
        memory_mib: 4_096,
        initially_cordoned: false,
        heartbeat_ms: HEARTBEAT_MS,
        node,
        storage_meta,
    }
}

fn start_job(cat_id: &str, generation: i64) -> NodeJob {
    NodeJob {
        job_id: job_id(cat_id, generation, "start_cat"),
        cat_generation: generation,
        action: NodeJobAction::StartCat {
            cat_id: cat_id.to_string(),
            image: "test".into(),
            cpus: 1,
            memory_mib: 256,
            volumes: vec![VolumeGrant {
                disk_id: "root".into(),
                volume_id: format!("vol_{cat_id}"),
                attachment_id: format!("att_{cat_id}"),
                epoch: 0,
                size_bytes: VOLUME_SIZE,
                mount_path: "/".into(),
                durability: Default::default(),
            }],
        },
    }
}

fn stop_job(cat_id: &str, generation: i64) -> NodeJob {
    NodeJob {
        job_id: job_id(cat_id, generation, "stop_cat"),
        cat_generation: generation,
        action: NodeJobAction::StopCat {
            cat_id: cat_id.to_string(),
            disposition: StopCatDisposition::Cold,
        },
    }
}

/// Run a blocking `NodeRuntime` job off the async executor.
async fn run_job(runtime: &Arc<NodeRuntime>, job: NodeJob) {
    let runtime = runtime.clone();
    let result = tokio::task::spawn_blocking(move || runtime.execute(job))
        .await
        .expect("job thread");
    assert_eq!(
        result.phase,
        cats_api::nodejob::JobPhase::Succeeded,
        "job failed: {:?}",
        result.error
    );
}

/// The agent that started the Cat and still owns its child processes. Building
/// a second agent over the same state directory is what "restarting the agent"
/// means here.
async fn agent_with_a_running_cat(root: &Path, node_id: &str, cat_id: &str) -> Arc<NodeRuntime> {
    let config = node_config(root, node_id);
    let runtime = tokio::task::spawn_blocking(move || NodeRuntime::new(config))
        .await
        .expect("runtime thread")
        .expect("open the node runtime");
    let runtime = Arc::new(runtime);
    run_job(&runtime, start_job(cat_id, 7)).await;
    runtime
}

/// Rewrite the on-disk ledger record so its Guest boot id no longer matches the
/// live Guest. Step 3 of ADR-0040 §6 adoption proof then fails and the Cat is
/// residue — the agent's own ledger API is crate-private, so this edits the
/// published JSON the way a stale record on a real host would read.
fn break_recorded_boot_id(state_dir: &Path, cat_id: &str) {
    let path = state_dir
        .join("runtime-ledger")
        .join(format!("{cat_id}.json"));
    let text = std::fs::read_to_string(&path).expect("read the runtime ledger record");
    let mut record: serde_json::Value =
        serde_json::from_str(&text).expect("parse the runtime ledger record");
    assert!(
        record.get("boot_id").is_some_and(|value| value.is_string()),
        "the record must carry a Guest boot id to invalidate: {record}"
    );
    record["boot_id"] = serde_json::Value::String("a-boot-id-this-guest-never-had".into());
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&record).expect("re-encode the runtime ledger record"),
    )
    .expect("rewrite the runtime ledger record");
}

async fn poll_until(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    done()
}

async fn healthz(handle: &Handle) -> StatusCode {
    reqwest::get(format!("{}/healthz", handle.base_url()))
        .await
        .expect("the node agent must still answer")
        .status()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The regression test for the deleted `bail!`. `spawn` used to poll for 30
/// seconds and then fail the whole process; now it returns promptly and serves,
/// with nothing at all listening on the control-plane port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_serves_when_the_control_plane_is_not_listening() {
    let root = tempfile::tempdir().expect("test root");
    let nowhere = reserved_address().await;
    let config = node_config(root.path(), "node_offline_start");

    let started = Instant::now();
    let handle = tokio::time::timeout(
        Duration::from_secs(5),
        spawn(server_config(
            config,
            root.path(),
            format!("http://{nowhere}"),
        )),
    )
    .await
    .expect("spawn must not wait out a registration deadline")
    .expect("an unreachable control plane must not end the node agent (ADR-0040 §6)");
    // The old code could only return after a successful registration, so it
    // could never have returned at all against a dead port.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "spawn blocked on the control plane for {:?}",
        started.elapsed()
    );

    assert_eq!(healthz(&handle).await, StatusCode::OK);
    let authenticated = reqwest::Client::new()
        .post(format!("{}/v1/cats/absent/exec", handle.base_url()))
        .bearer_auth(SERVICE_TOKEN)
        .json(&cats_api::requests::ExecRequest {
            command: vec!["true".into()],
            env: Default::default(),
            stdin: Vec::new(),
            timeout_ms: None,
        })
        .send()
        .await
        .expect("the node agent must serve its job surface");
    assert_eq!(
        authenticated.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the runtime answered, so the agent is serving and not merely bound"
    );

    // Several registration retries later it is still here, still serving.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(healthz(&handle).await, StatusCode::OK);
}

/// The other half: an outage the agent lived through has to end by itself. No
/// restart, no operator action — the background loop keeps retrying and picks
/// the control plane up when it appears.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_registers_once_the_control_plane_comes_back() {
    let root = tempfile::tempdir().expect("test root");
    let address = reserved_address().await;
    let config = node_config(root.path(), "node_reconnect");

    let handle = spawn(server_config(
        config,
        root.path(),
        format!("http://{address}"),
    ))
    .await
    .expect("spawn during a control-plane outage");

    // Long enough for the retry loop to have failed several times.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let stub = StubControlPlane::default();
    let server = stub.serve(listen_on(address).await);

    assert!(
        poll_until(Duration::from_secs(10), || !stub.registrations().is_empty()).await,
        "the agent never registered after the control plane came back"
    );
    let registrations = stub.registrations();
    assert_eq!(registrations[0].node_id, "node_reconnect");
    assert_eq!(registrations[0].cpus, 4);
    assert_eq!(
        registrations[0].route_grant_public_key_sha256.as_deref(),
        Some(
            cats_node_agent::route_grant::RouteGrantVerifier::from_ed25519_pem(include_bytes!(
                "../../tests/fixtures/route_grant_public_ed25519.pem"
            ))
            .unwrap()
            .public_key_sha256()
        )
    );

    assert!(
        poll_until(Duration::from_secs(10), || !stub.heartbeats().is_empty()).await,
        "registration succeeded but heartbeats never followed"
    );
    assert_eq!(healthz(&handle).await, StatusCode::OK);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_forwards_the_initially_cordoned_setting() {
    let root = tempfile::tempdir().expect("test root");
    let stub = StubControlPlane::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub control plane");
    let address = listener.local_addr().expect("stub address");
    let server = stub.serve(listener);

    let mut config = server_config(
        node_config(root.path(), "node_initially_cordoned"),
        root.path(),
        format!("http://{address}"),
    );
    config.initially_cordoned = true;
    let handle = spawn(config).await.expect("start the node agent");

    assert!(
        poll_until(Duration::from_secs(10), || !stub.registrations().is_empty()).await,
        "the agent never registered"
    );
    assert!(
        stub.registrations()[0].initially_cordoned,
        "the node agent dropped the fail-closed admission setting"
    );

    drop(handle);
    server.abort();
}

/// Adoption runs before registration, so the inventory is complete from the
/// first heartbeat on. That is what lets the control plane recover a `Lost`
/// node: it requires every non-deleting claim at the claimed generation, and a
/// second heartbeat is too late if the first one already reported an empty
/// node.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_heartbeat_after_a_restart_carries_the_adopted_cat() {
    const CAT: &str = "cat_restart_adopted";
    let root = tempfile::tempdir().expect("test root");
    let previous = agent_with_a_running_cat(root.path(), "node_restart_adopt", CAT).await;

    let stub = StubControlPlane::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub control plane");
    let address = listener.local_addr().expect("stub address");
    let server = stub.serve(listener);

    let restarted = spawn(server_config(
        node_config(root.path(), "node_restart_adopt"),
        root.path(),
        format!("http://{address}"),
    ))
    .await
    .expect("restart the node agent over the same state directory");

    assert!(
        poll_until(Duration::from_secs(10), || !stub.heartbeats().is_empty()).await,
        "the restarted agent never heartbeat"
    );
    let first = stub.heartbeats().remove(0);
    assert_eq!(
        first
            .cats
            .iter()
            .map(|cat| (cat.cat_id.as_str(), cat.generation, cat.state))
            .collect::<Vec<_>>(),
        vec![(CAT, 7, ObservedState::Running)],
        "the first heartbeat must already carry the adopted Cat at its recorded generation"
    );

    drop(restarted);
    server.abort();
    // The agent that owns the child processes tears the Cat down.
    run_job(&previous, stop_job(CAT, 8)).await;
}

/// The safety half of ADR-0040 §6 fail-closed rule. A Cat this node cannot prove it owns is
/// absent from every heartbeat, never reported as `Cold`: the same handler
/// trusts node-reported state at a matching generation, so `Cold` would say the
/// disk was released while an old blockd may still hold its lease. Omitting it
/// only keeps the node `Lost`, which is recoverable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cat_adoption_refused_never_appears_in_a_heartbeat() {
    const CAT: &str = "cat_restart_residue";
    let root = tempfile::tempdir().expect("test root");
    let previous = agent_with_a_running_cat(root.path(), "node_restart_residue", CAT).await;
    let config = node_config(root.path(), "node_restart_residue");
    break_recorded_boot_id(&config.state_dir, CAT);

    let stub = StubControlPlane::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub control plane");
    let address = listener.local_addr().expect("stub address");
    let server = stub.serve(listener);

    let restarted = spawn(server_config(
        config,
        root.path(),
        format!("http://{address}"),
    ))
    .await
    .expect("restart the node agent over the same state directory");

    assert!(
        poll_until(Duration::from_secs(10), || stub.heartbeats().len() >= 3).await,
        "the restarted agent never heartbeat"
    );
    for (index, heartbeat) in stub.heartbeats().iter().enumerate() {
        assert!(
            heartbeat.cats.is_empty(),
            "heartbeat {index} reported a Cat adoption refused: {:?}",
            heartbeat.cats
        );
    }

    drop(restarted);
    server.abort();
    run_job(&previous, stop_job(CAT, 8)).await;
}

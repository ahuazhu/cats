//! Liveness must not share a channel with anything remote.
//!
//! Usage upload used to run inline in the heartbeat loop, so its duration was
//! added to the interval between heartbeats. In production the upload backlog
//! grew until one attempt hit the agent's 10 s client timeout, which is the same
//! value as the control plane's node lease -- so a single slow upload was enough
//! to have the Host declared Lost, every ~70 s, indefinitely. Every Cat on it
//! flapped with it, new Cats could not be scheduled during the Lost windows, and
//! stops could not converge.
//!
//! These tests pin the separation: a usage endpoint that hangs far longer than
//! the lease must not disturb the heartbeat cadence, and the upload must still
//! happen on its own.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use cats_api::metering::{CatUsageCheckpoint, UsageMetric};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_node_agent::server::{spawn, ServerConfig};
use cats_node_agent::usage_spool::UsageSpool;
use cats_storage::MetadataStore;
use cats_test_support::{fake_node_config, NodeConfigBuilder, TempDirFixture};

const HEARTBEAT_MS: u64 = 200;

/// Longer than any plausible lease, so if liveness is coupled to upload at all
/// the heartbeat gap becomes unmistakable rather than marginal.
const USAGE_HANG: Duration = Duration::from_secs(30);

#[derive(Clone, Default)]
struct MockControlPlane {
    heartbeats: Arc<Mutex<Vec<Instant>>>,
    usage_attempts: Arc<AtomicUsize>,
}

async fn mock_heartbeat(State(cp): State<MockControlPlane>) -> StatusCode {
    cp.heartbeats.lock().unwrap().push(Instant::now());
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

async fn start_mock(hang_usage: bool) -> (MockControlPlane, String) {
    let cp = MockControlPlane::default();
    let usage = if hang_usage {
        post(mock_usage_hang)
    } else {
        post(mock_usage_ok)
    };
    let app = Router::new()
        .route("/v1/nodes/heartbeat", post(mock_heartbeat))
        .route("/v1/internal/usage/checkpoints", usage)
        .route(
            "/v1/nodes/register",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/v1/nodes/work-status",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .with_state(cp.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (cp, format!("http://{addr}"))
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
    spawn(ServerConfig {
        advertise_url: None,
        listen: "127.0.0.1:0".into(),
        control_plane_url,
        auth_token: "dev-service-token".into(),
        route_grant_verifier: Arc::new(
            cats_node_agent::route_grant::RouteGrantVerifier::from_ed25519_pem(include_bytes!(
                "../../tests/fixtures/route_grant_public_ed25519.pem"
            ))
            .unwrap(),
        ),
        gateway_url: "http://127.0.0.1:1".into(),
        cpus: 4,
        memory_mib: 4096,
        initially_cordoned: false,
        heartbeat_ms: HEARTBEAT_MS,
        storage_meta,
        node: fake_node_config!(
            NodeConfigBuilder::new(dir.path(), "node_a".to_string()).with_state_dir(state_dir)
        ),
    })
    .await
    .unwrap()
}

/// The heartbeat keeps its cadence while usage upload is wedged.
#[tokio::test]
async fn a_hanging_usage_upload_does_not_delay_the_heartbeat() {
    let dir = TempDirFixture::new();
    let (cp, url) = start_mock(true).await;
    let _agent = start_agent(&dir, url).await;

    // Enough ticks that a single coupled upload would be obvious: with the old
    // inline call the second heartbeat would not arrive for 10 s.
    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS * 12)).await;

    let beats = cp.heartbeats.lock().unwrap().clone();
    assert!(
        beats.len() >= 8,
        "expected a steady heartbeat while upload hangs, got {} in {} ms",
        beats.len(),
        HEARTBEAT_MS * 12
    );
    let worst_gap = beats
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .max()
        .expect("at least two heartbeats");
    assert!(
        worst_gap < Duration::from_millis(HEARTBEAT_MS * 5),
        "heartbeat stalled for {worst_gap:?}; liveness is still coupled to usage upload"
    );
    assert!(
        cp.usage_attempts.load(Ordering::SeqCst) >= 1,
        "the uploader must still be trying on its own channel"
    );
}

/// The upload still happens without the heartbeat carrying it.
#[tokio::test]
async fn usage_upload_runs_on_its_own_channel() {
    let dir = TempDirFixture::new();
    let (cp, url) = start_mock(false).await;
    let _agent = start_agent(&dir, url).await;

    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS * 10)).await;
    assert!(
        cp.usage_attempts.load(Ordering::SeqCst) >= 1,
        "decoupling must not mean the upload stops happening"
    );
    assert!(
        !cp.heartbeats.lock().unwrap().is_empty(),
        "the heartbeat must still be running too"
    );
}

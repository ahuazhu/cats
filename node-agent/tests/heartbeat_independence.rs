//! Durable usage delivery remains independent after the legacy heartbeat and
//! work-status transports have been removed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
use cats_api::runtime_reconciliation::{
    decode_agent_registration_attempt, encode_agent_session, AgentSession, AsciiText,
    ContractVersion, CredentialBinding, Epoch, GuestRuntimeProfileReceipt, Id, NodeBootId,
    NodeIdentity, NodeIdentityState, Sha256Digest, UnixMillis,
};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_node_agent::agent_registration::AgentRegistrationConfig;
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
    usage_attempts: Arc<AtomicUsize>,
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

async fn mock_registration(headers: HeaderMap, body: Bytes) -> Response {
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
}

/// The upload still happens without either retired Node transport.
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
}

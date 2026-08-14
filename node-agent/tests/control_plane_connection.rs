//! Process-level Agent registration durability and response-loss tests.

use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::routing::post;
use axum::Router;
use cats_api::agent_registration::{
    encode_agent_registration_error, verify_request_proof, AgentRegistrationError,
    AgentRegistrationErrorDetail, Ed25519RequestSigner, JSON_CONTENT_TYPE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
    REGISTRATION_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_agent_registration_attempt, encode_agent_session, AgentSession, AsciiText,
    ContractVersion, CredentialBinding, Epoch, GuestRuntimeProfileReceipt, Id, NodeBootId,
    NodeIdentity, NodeIdentityState, Sha256Digest, UnixMillis,
};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_node_agent::agent_registration::{
    AgentRegistrationConfig, PENDING_ATTEMPT_RELATIVE_PATH, SESSION_RELATIVE_PATH,
};
use cats_node_agent::runtime::NodeConfig;
use cats_node_agent::server::{spawn, ServerConfig};
use cats_storage::MetadataStore;
use cats_test_support::{fake_node_config, NodeConfigBuilder};
use futures_util::stream;

#[derive(Clone, Copy)]
enum FirstReply {
    LoseBody,
    EpochMismatch(Epoch),
    Accept,
}

#[derive(Clone)]
struct StubControl {
    first_reply: FirstReply,
    attempts: Arc<Mutex<Vec<Vec<u8>>>>,
    committed: Arc<Mutex<HashMap<String, AgentSession>>>,
}

impl StubControl {
    async fn start(first_reply: FirstReply) -> (Self, String, tokio::task::JoinHandle<()>) {
        let state = Self {
            first_reply,
            attempts: Arc::new(Mutex::new(Vec::new())),
            committed: Arc::new(Mutex::new(HashMap::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(REGISTRATION_PATH, post(register))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (state, format!("http://{address}"), task)
    }
}

async fn register(
    State(state): State<StubControl>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
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
    let request_number = {
        let mut attempts = state.attempts.lock().unwrap();
        attempts.push(body.to_vec());
        attempts.len()
    };
    if request_number == 1 {
        if let FirstReply::EpochMismatch(current) = state.first_reply {
            let error = AgentRegistrationError {
                version: ContractVersion::V1,
                error: AgentRegistrationErrorDetail::SessionEpochMismatch {
                    current_agent_session_epoch: Some(current),
                    presented_expected_agent_session_epoch: attempt.expected_agent_session_epoch,
                },
                message: "expected epoch changed".into(),
            };
            return Response::builder()
                .status(StatusCode::CONFLICT)
                .header("content-type", JSON_CONTENT_TYPE)
                .body(Body::from(encode_agent_registration_error(&error).unwrap()))
                .unwrap();
        }
    }
    let session = state
        .committed
        .lock()
        .unwrap()
        .entry(attempt.registration_attempt_id.to_string())
        .or_insert_with(|| AgentSession {
            version: ContractVersion::V1,
            node_id: attempt.node_id.clone(),
            immutable_host_id: attempt.immutable_host_id.clone(),
            node_boot_id: attempt.node_boot_id.clone(),
            agent_instance_id: attempt.agent_instance_id.clone(),
            agent_session_epoch: Epoch::new(
                attempt
                    .expected_agent_session_epoch
                    .map_or(1, |epoch| epoch.get() + 1),
            )
            .unwrap(),
            registration_attempt_id: attempt.registration_attempt_id.clone(),
            guest_config_digest: attempt.guest_config_digest.clone(),
            lease_deadline_unix_ms: UnixMillis::new(1_900_000_060_000).unwrap(),
        })
        .clone();
    if request_number == 1 && matches!(state.first_reply, FirstReply::LoseBody) {
        let failed = stream::once(async {
            Err::<Bytes, std::io::Error>(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "injected response loss after commit",
            ))
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", JSON_CONTENT_TYPE)
            .body(Body::from_stream(failed))
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", JSON_CONTENT_TYPE)
        .body(Body::from(encode_agent_session(&session).unwrap()))
        .unwrap()
}

fn receipt() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        initramfs_digest: None,
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn signer() -> Ed25519RequestSigner {
    Ed25519RequestSigner::from_pkcs8_pem(
        Id::new("credential_node_a").unwrap(),
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
    )
    .unwrap()
}

fn registration(root: &Path) -> AgentRegistrationConfig {
    let signer = signer();
    AgentRegistrationConfig::for_loopback_test(
        NodeIdentity {
            version: ContractVersion::V1,
            node_id: Id::new("node_a").unwrap(),
            provider_scope: cats_api::runtime_reconciliation::ProviderScope {
                provider: Id::new("test_provider").unwrap(),
                partition: Id::new("test_partition").unwrap(),
                account_id: Id::new("test_account").unwrap(),
                region: Id::new("test_region").unwrap(),
            },
            immutable_host_id: Id::new("host_a").unwrap(),
            credential_id: signer.credential_id().clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: Id::new("state_a").unwrap(),
            state: NodeIdentityState::Provisioned,
        },
        signer,
        root.join("state-a"),
        NodeBootId::new("11111111111111111111111111111111").unwrap(),
        &receipt(),
    )
    .unwrap()
}

fn config(root: &Path, control_plane_url: String) -> ServerConfig {
    let registration = registration(root);
    let mut node: NodeConfig = fake_node_config!(
        NodeConfigBuilder::new(root, "node_a").with_state_dir(registration.state_path())
    );
    node.state_dir = registration.runtime_state_directory();
    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&root.join("meta.db")).unwrap());
    ServerConfig {
        listen: "127.0.0.1:0".into(),
        control_plane_url,
        auth_token: "test-service-token".into(),
        agent_registration: registration,
        route_grant_verifier: Arc::new(
            cats_node_agent::route_grant::RouteGrantVerifier::from_ed25519_pem(include_bytes!(
                "../../tests/fixtures/route_grant_public_ed25519.pem"
            ))
            .unwrap(),
        ),
        heartbeat_ms: 100,
        node,
        storage_meta,
    }
}

#[tokio::test]
async fn response_loss_retries_the_exact_durable_attempt_and_only_then_opens_runtime() {
    let root = tempfile::tempdir().unwrap();
    let (control, url, _server) = StubControl::start(FirstReply::LoseBody).await;
    let node = spawn(config(root.path(), url)).await.unwrap();
    let attempts = control.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0], attempts[1]);
    assert!(!root
        .path()
        .join("state-a")
        .join(PENDING_ATTEMPT_RELATIVE_PATH)
        .exists());
    assert!(root
        .path()
        .join("state-a")
        .join(SESSION_RELATIVE_PATH)
        .exists());
    assert_eq!(node.state.agent_session.agent_session_epoch.get(), 1);
}

#[tokio::test]
async fn epoch_mismatch_is_durable_before_a_new_attempt_is_sent() {
    let root = tempfile::tempdir().unwrap();
    let current = Epoch::new(7).unwrap();
    let (control, url, _server) = StubControl::start(FirstReply::EpochMismatch(current)).await;
    let node = spawn(config(root.path(), url)).await.unwrap();
    let attempts = control.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 2);
    let first = decode_agent_registration_attempt(&attempts[0]).unwrap();
    let second = decode_agent_registration_attempt(&attempts[1]).unwrap();
    assert_eq!(first.expected_agent_session_epoch, None);
    assert_eq!(second.expected_agent_session_epoch, Some(current));
    assert_ne!(
        first.registration_attempt_id,
        second.registration_attempt_id
    );
    assert_eq!(node.state.agent_session.agent_session_epoch.get(), 8);
}

#[tokio::test]
async fn accepted_session_is_used_as_the_next_process_expected_epoch() {
    let root = tempfile::tempdir().unwrap();
    let (first_control, first_url, _first_server) = StubControl::start(FirstReply::Accept).await;
    let first = spawn(config(root.path(), first_url)).await.unwrap();
    assert_eq!(first.state.agent_session.agent_session_epoch.get(), 1);
    first.shutdown();
    drop(first);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (second_control, second_url, _second_server) = StubControl::start(FirstReply::Accept).await;
    let second = spawn(config(root.path(), second_url)).await.unwrap();
    let attempts = second_control.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        decode_agent_registration_attempt(&attempts[0])
            .unwrap()
            .expected_agent_session_epoch,
        Some(Epoch::new(1).unwrap())
    );
    assert_eq!(second.state.agent_session.agent_session_epoch.get(), 2);
    assert_eq!(first_control.attempts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn startup_resolves_an_old_process_pending_attempt_then_replaces_its_session() {
    let root = tempfile::tempdir().unwrap();
    let setup = registration(root.path());
    let registration_dir = setup.state_path().join("agent-registration");
    std::fs::create_dir_all(&registration_dir).unwrap();
    std::fs::set_permissions(&registration_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let old = cats_api::runtime_reconciliation::AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: setup.identity().node_id.clone(),
        immutable_host_id: setup.identity().immutable_host_id.clone(),
        node_boot_id: NodeBootId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        agent_instance_id: cats_api::runtime_reconciliation::RandomId128::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap(),
        registration_attempt_id: cats_api::runtime_reconciliation::RandomId128::new(
            "cccccccccccccccccccccccccccccccc",
        )
        .unwrap(),
        guest_config_digest: cats_api::runtime_reconciliation::guest_config_digest(&receipt())
            .unwrap(),
        expected_agent_session_epoch: None,
    };
    let old_bytes =
        cats_api::runtime_reconciliation::encode_agent_registration_attempt(&old).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(setup.state_path().join(PENDING_ATTEMPT_RELATIVE_PATH))
        .unwrap()
        .write_all(&old_bytes)
        .unwrap();
    drop(setup);

    let (control, url, _server) = StubControl::start(FirstReply::Accept).await;
    let node = spawn(config(root.path(), url)).await.unwrap();
    let attempts = control.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0], old_bytes);
    let current = decode_agent_registration_attempt(&attempts[1]).unwrap();
    assert_eq!(current.expected_agent_session_epoch, Epoch::new(1));
    assert_eq!(
        current.node_boot_id,
        NodeBootId::new("11111111111111111111111111111111").unwrap()
    );
    assert_ne!(current.agent_instance_id, old.agent_instance_id);
    assert_eq!(
        node.state.agent_session.agent_session_epoch,
        Epoch::new(2).unwrap()
    );
}

#[tokio::test]
async fn plain_404_is_terminal_and_retains_the_durable_pending_attempt() {
    let root = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, Router::new()).await;
    });
    let registration = registration(root.path());
    let error = registration
        .register_until_session(&format!("http://{address}"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("route is not deployed"));
    assert!(registration
        .state_path()
        .join(PENDING_ATTEMPT_RELATIVE_PATH)
        .exists());
    assert!(!registration
        .state_path()
        .join(SESSION_RELATIVE_PATH)
        .exists());
    task.abort();
}

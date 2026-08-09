use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER, REGISTRATION_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_agent_session, decode_desired_read_snapshot, decode_observation_acceptance,
    decode_runtime_spine_error, encode_agent_registration_attempt, encode_desired_read_request,
    encode_node_observation, guest_config_digest, inventory_digest, AgentRegistrationAttempt,
    ContractErrorDetail, ContractVersion, CredentialBinding, DesiredReadRequest, Epoch, Id,
    NodeBootId, NodeIdentity, NodeIdentityState, NodeObservation, RandomId128,
    RuntimeSpineErrorDetail, RuntimeSpineHttpProblem, Sequence, SessionBinding, UnixMillis,
};
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::SqliteUsageStore;
use cats_storage::MetadataStore;
use reqwest::{Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DESIRED_PATH: &str = "/v1/internal/runtime/desired-reads";
const OBSERVATION_PATH: &str = "/v1/internal/runtime/observations";
const SERVICE_TOKEN: &str = "runtime-spine-http-service-token";
const ADMIN_TOKEN: &str = "runtime-spine-http-admin-token";

async fn pending_chunked_request(addr: std::net::SocketAddr, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {JSON_CONTENT_TYPE}\r\n\
         Accept: {JSON_CONTENT_TYPE}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
         1\r\n{{\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream
}

async fn raw_status(mut stream: TcpStream) -> StatusCode {
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(12), stream.read_to_end(&mut response))
        .await
        .expect("signed ingress did not enforce its body deadline")
        .unwrap();
    let line = std::str::from_utf8(&response)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    StatusCode::from_u16(
        line.split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap(),
    )
    .unwrap()
}

struct Context {
    _dir: tempfile::TempDir,
    server: Handle,
    client: reqwest::Client,
    signer: Ed25519RequestSigner,
    session: cats_api::runtime_reconciliation::AgentSession,
}

impl Context {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("storage.db")).unwrap());
        let receipt = cats_control_plane::testsupport::test_guest_runtime_profile_receipt();
        let server = spawn(Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: DsnSource::Literal(
                cats_control_plane::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            storage_meta,
            image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
            auth_token: SERVICE_TOKEN.into(),
            guest_runtime_profile_receipt: receipt.clone(),
            runtime_provisioner_trust_bundle:
                cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
            route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
            admin_token: ADMIN_TOKEN.into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 30_000,
            reconcile_interval_ms: 60_000,
            auto_tier_policy: AutoTierPolicy::default(),
            oci_deploy_sync_wait_ms: 5_000,
        })
        .await
        .unwrap();
        let signer = Ed25519RequestSigner::from_pkcs8_pem(
            Id::new("credential_spine_a").unwrap(),
            include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
        )
        .unwrap();
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: Id::new("node_spine_a").unwrap(),
            immutable_host_id: Id::new("host_spine_a").unwrap(),
            credential_id: signer.credential_id().clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: Id::new("state_spine_a").unwrap(),
            state: NodeIdentityState::Provisioned,
        };
        cats_control_plane::testsupport::provision_node_identity(
            &server.state.store,
            identity.clone(),
        )
        .await;
        let attempt = AgentRegistrationAttempt {
            version: ContractVersion::V1,
            node_id: identity.node_id,
            immutable_host_id: identity.immutable_host_id,
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            registration_attempt_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
            guest_config_digest: guest_config_digest(&receipt).unwrap(),
            expected_agent_session_epoch: None,
        };
        let body = encode_agent_registration_attempt(&attempt).unwrap();
        let proof = signer.sign("POST", REGISTRATION_PATH, &body);
        let response = reqwest::Client::new()
            .post(format!("{}{REGISTRATION_PATH}", server.base_url()))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session = decode_agent_session(&response.bytes().await.unwrap()).unwrap();
        Self {
            _dir: dir,
            server,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            signer,
            session,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.base_url())
    }

    fn signed(&self, path: &str, body: Vec<u8>) -> reqwest::RequestBuilder {
        let proof = self.signer.sign("POST", path, &body);
        self.client
            .post(self.url(path))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
    }

    fn binding(&self) -> SessionBinding {
        SessionBinding {
            node_id: self.session.node_id.clone(),
            node_boot_id: self.session.node_boot_id.clone(),
            agent_instance_id: self.session.agent_instance_id.clone(),
            agent_session_epoch: self.session.agent_session_epoch,
        }
    }

    fn full_observation(&self, read_position: Sequence, observation_id: &str) -> NodeObservation {
        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new(observation_id).unwrap(),
            node_id: self.session.node_id.clone(),
            node_boot_id: self.session.node_boot_id.clone(),
            agent_instance_id: self.session.agent_instance_id.clone(),
            agent_session_epoch: self.session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(1).unwrap(),
            observed_at_unix_ms: UnixMillis::new(1).unwrap(),
            complete_inventory: true,
            inventory_epoch: Epoch::new(1).unwrap(),
            inventory_digest: None,
            inventory_read_position: Some(read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: Vec::new(),
            residue: Vec::new(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        observation
    }

    async fn fingerprint(&self) -> String {
        cats_control_plane::testsupport::runtime_spine_state_fingerprint(
            &self.server.state.store,
            self.session.node_id.clone(),
        )
        .await
    }
}

async fn spine_error(
    response: reqwest::Response,
) -> cats_api::runtime_reconciliation::RuntimeSpineError {
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        JSON_CONTENT_TYPE
    );
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    decode_runtime_spine_error(&response.bytes().await.unwrap()).unwrap()
}

#[tokio::test]
async fn signed_desired_and_full_observation_commit_and_replay_exact_bytes() {
    let context = Context::new().await;
    let desired = DesiredReadRequest {
        version: ContractVersion::V1,
        session: context.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let desired_body = encode_desired_read_request(&desired).unwrap();
    let first = context
        .signed(DESIRED_PATH, desired_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_bytes = first.bytes().await.unwrap();
    let snapshot = decode_desired_read_snapshot(&first_bytes).unwrap();
    assert!(snapshot.desired_specs.is_empty());

    let replay = context
        .signed(DESIRED_PATH, desired_body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.bytes().await.unwrap(), first_bytes);

    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        node_id: context.session.node_id.clone(),
        node_boot_id: context.session.node_boot_id.clone(),
        agent_instance_id: context.session.agent_instance_id.clone(),
        agent_session_epoch: context.session.agent_session_epoch,
        heartbeat_sequence: Sequence::new(1).unwrap(),
        observed_at_unix_ms: UnixMillis::new(1).unwrap(),
        complete_inventory: true,
        inventory_epoch: Epoch::new(1).unwrap(),
        inventory_digest: None,
        inventory_read_position: Some(snapshot.read_position),
        key_ring_version: None,
        key_ring_digest: None,
        loaded_kids: Vec::new(),
        runtimes: Vec::new(),
        residue: Vec::new(),
    };
    observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
    let observation_body = encode_node_observation(&observation).unwrap();
    let accepted = context
        .signed(OBSERVATION_PATH, observation_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let accepted_bytes = accepted.bytes().await.unwrap();
    let acceptance = decode_observation_acceptance(&accepted_bytes).unwrap();
    assert_eq!(acceptance.observation_id, observation.observation_id);

    let replay = context
        .signed(OBSERVATION_PATH, observation_body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.bytes().await.unwrap(), accepted_bytes);
}

#[tokio::test]
async fn definite_session_rejections_are_exact_409_and_zero_write() {
    let context = Context::new().await;
    let mut wrong = context.binding();
    wrong.agent_instance_id = RandomId128::new("99999999999999999999999999999999").unwrap();
    let request = DesiredReadRequest {
        version: ContractVersion::V1,
        session: wrong,
        request_sequence: Sequence::new(1).unwrap(),
    };
    let before = context.fingerprint().await;
    let response = context
        .signed(DESIRED_PATH, encode_desired_read_request(&request).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(matches!(
        spine_error(response).await.error.as_ref(),
        RuntimeSpineErrorDetail::ContractError { contract_error }
            if matches!(contract_error.error.as_ref(), ContractErrorDetail::WrongSession { .. })
    ));
    assert_eq!(context.fingerprint().await, before);

    // The rejected sequence was not consumed.
    let correct = DesiredReadRequest {
        version: ContractVersion::V1,
        session: context.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    assert_eq!(
        context
            .signed(DESIRED_PATH, encode_desired_read_request(&correct).unwrap(),)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let expired = Context::new().await;
    cats_control_plane::testsupport::expire_agent_session_for_test(
        &expired.server.state.store,
        expired.session.node_id.clone(),
    )
    .await;
    let before = expired.fingerprint().await;
    let request = DesiredReadRequest {
        version: ContractVersion::V1,
        session: expired.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let response = expired
        .signed(DESIRED_PATH, encode_desired_read_request(&request).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(matches!(
        spine_error(response).await.error.as_ref(),
        RuntimeSpineErrorDetail::ContractError { contract_error }
            if matches!(contract_error.error.as_ref(), ContractErrorDetail::SessionExpired { .. })
    ));
    assert_eq!(expired.fingerprint().await, before);
}

#[tokio::test]
async fn definite_cursor_rejections_are_exact_409_and_zero_write() {
    let expired = Context::new().await;
    let desired = DesiredReadRequest {
        version: ContractVersion::V1,
        session: expired.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let response = expired
        .signed(DESIRED_PATH, encode_desired_read_request(&desired).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot = decode_desired_read_snapshot(&response.bytes().await.unwrap()).unwrap();
    cats_control_plane::testsupport::expire_runtime_cursor_for_test(
        &expired.server.state.store,
        expired.session.node_id.clone(),
    )
    .await;
    let before = expired.fingerprint().await;
    let observation =
        expired.full_observation(snapshot.read_position, "cccccccccccccccccccccccccccccccc");
    let response = expired
        .signed(
            OBSERVATION_PATH,
            encode_node_observation(&observation).unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(matches!(
        spine_error(response).await.error.as_ref(),
        RuntimeSpineErrorDetail::ContractError { contract_error }
            if matches!(
                contract_error.error.as_ref(),
                ContractErrorDetail::InventoryReadPositionExpired { .. }
            )
    ));
    assert_eq!(expired.fingerprint().await, before);

    let changed = Context::new().await;
    let desired = DesiredReadRequest {
        version: ContractVersion::V1,
        session: changed.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let response = changed
        .signed(DESIRED_PATH, encode_desired_read_request(&desired).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot = decode_desired_read_snapshot(&response.bytes().await.unwrap()).unwrap();
    cats_control_plane::testsupport::insert_assigned_desired_after_cursor_for_test(
        &changed.server.state.store,
        changed.session.node_id.clone(),
    )
    .await;
    let before = changed.fingerprint().await;
    let observation =
        changed.full_observation(snapshot.read_position, "dddddddddddddddddddddddddddddddd");
    let response = changed
        .signed(
            OBSERVATION_PATH,
            encode_node_observation(&observation).unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(matches!(
        spine_error(response).await.error.as_ref(),
        RuntimeSpineErrorDetail::ContractError { contract_error }
            if matches!(contract_error.error.as_ref(), ContractErrorDetail::AssignedSetChanged { .. })
    ));
    assert_eq!(changed.fingerprint().await, before);
}

#[tokio::test]
async fn admission_order_and_signature_path_binding_fail_closed() {
    let context = Context::new().await;

    let method = context
        .client
        .request(Method::GET, context.url(DESIRED_PATH))
        .send()
        .await
        .unwrap();
    assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(matches!(
        spine_error(method).await.error.as_ref(),
        RuntimeSpineErrorDetail::HttpRequestRejected {
            problem: RuntimeSpineHttpProblem::MethodNotAllowed
        }
    ));

    let media = context
        .client
        .post(context.url(DESIRED_PATH))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(media.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let missing_proof = context
        .client
        .post(context.url(DESIRED_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(missing_proof.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(
        spine_error(missing_proof).await.error.as_ref(),
        RuntimeSpineErrorDetail::AuthenticationFailed
    ));

    let shared_bearer = context
        .client
        .post(context.url(DESIRED_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {SERVICE_TOKEN}"),
        )
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(shared_bearer.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(
        spine_error(shared_bearer).await.error.as_ref(),
        RuntimeSpineErrorDetail::HttpRequestRejected {
            problem: RuntimeSpineHttpProblem::AuthorizationNotAllowed
        }
    ));

    let request = DesiredReadRequest {
        version: ContractVersion::V1,
        session: context.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let body = encode_desired_read_request(&request).unwrap();
    let wrong_path_proof = context.signer.sign("POST", OBSERVATION_PATH, &body);
    let response = context
        .client
        .post(context.url(DESIRED_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header(NODE_CREDENTIAL_ID_HEADER, wrong_path_proof.credential_id)
        .header(
            NODE_PUBLIC_KEY_SPKI_HEADER,
            wrong_path_proof.public_key_spki,
        )
        .header(NODE_SIGNATURE_HEADER, wrong_path_proof.signature)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observation_renews_while_the_ordinary_store_connection_is_saturated() {
    let context = Context::new().await;
    let desired = DesiredReadRequest {
        version: ContractVersion::V1,
        session: context.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let desired_body = encode_desired_read_request(&desired).unwrap();
    let desired_response = context
        .signed(DESIRED_PATH, desired_body)
        .send()
        .await
        .unwrap();
    assert_eq!(desired_response.status(), StatusCode::OK);
    let snapshot = decode_desired_read_snapshot(&desired_response.bytes().await.unwrap()).unwrap();

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let ordinary_store = Arc::clone(&context.server.state.store);
    let ordinary = tokio::spawn(async move {
        ordinary_store
            .execute(move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(move || {
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ordinary Store closure must own its connection lane")
    })
    .await
    .unwrap();

    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
        node_id: context.session.node_id.clone(),
        node_boot_id: context.session.node_boot_id.clone(),
        agent_instance_id: context.session.agent_instance_id.clone(),
        agent_session_epoch: context.session.agent_session_epoch,
        heartbeat_sequence: Sequence::new(1).unwrap(),
        observed_at_unix_ms: UnixMillis::new(1).unwrap(),
        complete_inventory: true,
        inventory_epoch: Epoch::new(1).unwrap(),
        inventory_digest: None,
        inventory_read_position: Some(snapshot.read_position),
        key_ring_version: None,
        key_ring_digest: None,
        loaded_kids: Vec::new(),
        runtimes: Vec::new(),
        residue: Vec::new(),
    };
    observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        context
            .signed(
                OBSERVATION_PATH,
                encode_node_observation(&observation).unwrap(),
            )
            .send(),
    )
    .await
    .expect("the reserved observation lane must not wait for ordinary Store work")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let accepted = decode_observation_acceptance(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(accepted.observation_id, observation.observation_id);

    release_tx.send(()).unwrap();
    ordinary.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_bodies_hit_the_absolute_deadline_release_admission_and_never_touch_store() {
    let context = Context::new().await;
    let before = context.fingerprint().await;
    let mut pending = Vec::new();
    for _ in 0..65 {
        pending.push(pending_chunked_request(context.server.addr, DESIRED_PATH).await);
    }

    let desired = DesiredReadRequest {
        version: ContractVersion::V1,
        session: context.binding(),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let body = encode_desired_read_request(&desired).unwrap();
    let saturated = tokio::time::timeout(
        Duration::from_secs(2),
        context.signed(DESIRED_PATH, body.clone()).send(),
    )
    .await
    .expect("the nonblocking global admission waited")
    .unwrap();
    assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);

    for stream in pending {
        assert_eq!(raw_status(stream).await, StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(context.fingerprint().await, before);

    let accepted = context.signed(DESIRED_PATH, body).send().await.unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
}

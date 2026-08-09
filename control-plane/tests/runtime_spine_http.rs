use std::sync::Arc;

use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER, REGISTRATION_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_agent_session, decode_desired_read_snapshot, decode_observation_acceptance,
    decode_runtime_spine_error, encode_agent_registration_attempt, encode_desired_read_request,
    encode_node_observation, guest_config_digest, inventory_digest, AgentRegistrationAttempt,
    ContractVersion, CredentialBinding, DesiredReadRequest, Epoch, Id, NodeBootId, NodeIdentity,
    NodeIdentityState, NodeObservation, RandomId128, RuntimeSpineErrorDetail,
    RuntimeSpineHttpProblem, Sequence, SessionBinding, UnixMillis,
};
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::SqliteUsageStore;
use cats_storage::MetadataStore;
use reqwest::{Method, StatusCode};

const DESIRED_PATH: &str = "/v1/internal/runtime/desired-reads";
const OBSERVATION_PATH: &str = "/v1/internal/runtime/observations";
const SERVICE_TOKEN: &str = "runtime-spine-http-service-token";
const ADMIN_TOKEN: &str = "runtime-spine-http-admin-token";

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

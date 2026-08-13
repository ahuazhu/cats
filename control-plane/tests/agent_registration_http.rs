use std::sync::Arc;

use cats_api::agent_registration::{
    decode_agent_registration_error, AgentRegistrationErrorDetail, Ed25519RequestSigner,
    HttpRequestRejection, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
    REGISTRATION_PATH, REGISTRATION_REQUEST_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    decode_agent_session, encode_agent_registration_attempt, guest_config_digest,
    AgentRegistrationAttempt, ContractErrorDetail, ContractVersion, CredentialBinding, Id,
    NodeBootId, NodeIdentity, NodeIdentityState, RandomId128,
};
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_metering::SqliteUsageStore;
use reqwest::{Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SERVICE_TOKEN: &str = "registration-http-service-token";
const ADMIN_TOKEN: &str = "registration-http-admin-token";

async fn pending_chunked_request(addr: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {REGISTRATION_PATH} HTTP/1.1\r\nHost: {addr}\r\n\
         Content-Type: {JSON_CONTENT_TYPE}\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n1\r\n{{\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream
}

async fn raw_status(mut stream: TcpStream) -> StatusCode {
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(12),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("registration ingress did not enforce its body deadline")
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
    attempt: AgentRegistrationAttempt,
}

impl Context {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let receipt = cats_control_plane::testsupport::test_guest_runtime_profile_receipt();
        let server = spawn(Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: DsnSource::Literal(
                cats_control_plane::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            #[cfg(debug_assertions)]
            retired_storage_meta_for_tests: None,
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
            Id::new("credential_http_a").unwrap(),
            include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
        )
        .unwrap();
        cats_control_plane::testsupport::provision_node_identity(
            &server.state.store,
            NodeIdentity {
                version: ContractVersion::V1,
                node_id: Id::new("node_http_a").unwrap(),
                immutable_host_id: Id::new("host_http_a").unwrap(),
                credential_id: signer.credential_id().clone(),
                credential_binding: CredentialBinding::PublicKey {
                    public_key_spki_sha256: signer.public_key_spki_sha256(),
                },
                state_path_id: Id::new("state_http_a").unwrap(),
                state: NodeIdentityState::Provisioned,
            },
        )
        .await;
        let attempt = AgentRegistrationAttempt {
            version: ContractVersion::V1,
            node_id: Id::new("node_http_a").unwrap(),
            immutable_host_id: Id::new("host_http_a").unwrap(),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            registration_attempt_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
            guest_config_digest: guest_config_digest(&receipt).unwrap(),
            expected_agent_session_epoch: None,
        };
        Self {
            _dir: dir,
            server,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            signer,
            attempt,
        }
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}{}", self.server.base_url(), suffix)
    }

    fn signed_request(&self, body: Vec<u8>) -> reqwest::RequestBuilder {
        let proof = self.signer.sign("POST", REGISTRATION_PATH, &body);
        self.client
            .post(self.url(REGISTRATION_PATH))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
    }
}

async fn registration_error(
    response: reqwest::Response,
) -> cats_api::agent_registration::AgentRegistrationError {
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
    decode_agent_registration_error(&response.bytes().await.unwrap()).unwrap()
}

#[tokio::test]
async fn real_postgres_registration_and_exact_replay_return_the_immutable_session() {
    let context = Context::new().await;
    let body = encode_agent_registration_attempt(&context.attempt).unwrap();
    let first = context.signed_request(body.clone()).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
        JSON_CONTENT_TYPE
    );
    assert_eq!(
        first.headers().get(reqwest::header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let first_bytes = first.bytes().await.unwrap();
    let first_session = decode_agent_session(&first_bytes).unwrap();
    assert_eq!(first_session.node_id, context.attempt.node_id);
    assert_eq!(
        first_session.immutable_host_id,
        context.attempt.immutable_host_id
    );
    assert_eq!(first_session.node_boot_id, context.attempt.node_boot_id);
    assert_eq!(
        first_session.agent_instance_id,
        context.attempt.agent_instance_id
    );
    assert_eq!(
        first_session.registration_attempt_id,
        context.attempt.registration_attempt_id
    );
    assert_eq!(
        first_session.guest_config_digest,
        context.attempt.guest_config_digest
    );

    let replay = context.signed_request(body).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.bytes().await.unwrap(), first_bytes);
}

#[tokio::test]
async fn admission_order_and_proof_mutations_are_closed() {
    let context = Context::new().await;
    let body = encode_agent_registration_attempt(&context.attempt).unwrap();

    let method = context
        .client
        .request(Method::GET, context.url(REGISTRATION_PATH))
        .send()
        .await
        .unwrap();
    assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        method.headers().get(reqwest::header::ALLOW).unwrap(),
        "POST"
    );
    assert!(matches!(
        registration_error(method).await.error,
        AgentRegistrationErrorDetail::HttpRequestRejected {
            problem: HttpRequestRejection::MethodNotAllowed
        }
    ));

    let query = context
        .client
        .post(context.url(&format!("{REGISTRATION_PATH}?")))
        .send()
        .await
        .unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(
        registration_error(query).await.error,
        AgentRegistrationErrorDetail::HttpRequestRejected {
            problem: HttpRequestRejection::QueryNotAllowed
        }
    ));

    let media = context
        .client
        .post(context.url(REGISTRATION_PATH))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(reqwest::header::CONTENT_ENCODING, "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(media.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(matches!(
        registration_error(media).await.error,
        AgentRegistrationErrorDetail::HttpRequestRejected {
            problem: HttpRequestRejection::ContentTypeNotAllowed
        }
    ));

    let duplicate_media = context
        .client
        .post(context.url(REGISTRATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate_media.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(matches!(
        registration_error(duplicate_media).await.error,
        AgentRegistrationErrorDetail::HttpRequestRejected {
            problem: HttpRequestRejection::ContentTypeNotAllowed
        }
    ));

    let encoding = context
        .client
        .post(context.url(REGISTRATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::CONTENT_ENCODING, "identity")
        .header(reqwest::header::AUTHORIZATION, "Bearer forbidden")
        .send()
        .await
        .unwrap();
    assert_eq!(encoding.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(matches!(
        registration_error(encoding).await.error,
        AgentRegistrationErrorDetail::HttpRequestRejected {
            problem: HttpRequestRejection::ContentEncodingNotAllowed
        }
    ));

    let authorization = context
        .client
        .post(context.url(REGISTRATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::AUTHORIZATION, "Bearer forbidden")
        .send()
        .await
        .unwrap();
    assert_eq!(authorization.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(
        registration_error(authorization).await.error,
        AgentRegistrationErrorDetail::HttpRequestRejected {
            problem: HttpRequestRejection::AuthorizationNotAllowed
        }
    ));

    let oversized = context
        .client
        .post(context.url(REGISTRATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .body(vec![b'x'; REGISTRATION_REQUEST_MAX_WIRE_BYTES + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(matches!(
        registration_error(oversized).await.error,
        AgentRegistrationErrorDetail::ContractError {
            contract_error
        } if matches!(contract_error.error.as_ref(), ContractErrorDetail::LimitExceeded { .. })
    ));

    let missing = context
        .client
        .post(context.url(REGISTRATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .body(br#"{"not":"valid"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .unwrap(),
        NODE_AUTHENTICATE_CHALLENGE
    );
    assert!(matches!(
        registration_error(missing).await.error,
        AgentRegistrationErrorDetail::AuthenticationFailed
    ));

    let proof = context.signer.sign("POST", REGISTRATION_PATH, &body);
    let duplicate_proof = context
        .client
        .post(context.url(REGISTRATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id.clone())
        .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
        .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
        .header(NODE_SIGNATURE_HEADER, proof.signature)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate_proof.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(
        registration_error(duplicate_proof).await.error,
        AgentRegistrationErrorDetail::AuthenticationFailed
    ));

    let mut changed = body.clone();
    let changed_index = changed.len() - 2;
    changed[changed_index] ^= 1;
    let mutated = context
        .signed_request(body)
        .body(changed)
        .send()
        .await
        .unwrap();
    assert_eq!(mutated.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(
        registration_error(mutated).await.error,
        AgentRegistrationErrorDetail::AuthenticationFailed
    ));

    let malformed = br#"{"version":1}"#.to_vec();
    let malformed = context.signed_request(malformed).send().await.unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(
        registration_error(malformed).await.error,
        AgentRegistrationErrorDetail::ContractError {
            contract_error
        } if matches!(contract_error.error.as_ref(), ContractErrorDetail::MalformedPayload { .. })
    ));

    assert_eq!(
        context
            .client
            .post(context.url(&format!("{REGISTRATION_PATH}/")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    for path in [
        "/v1/nodes/register",
        "/v1/nodes/heartbeat",
        // Inventory is carried by the signed A20 heartbeat/full-observation
        // spine; there is no standalone compatibility mutation endpoint.
        "/v1/nodes/inventory",
        "/v1/nodes/work-status",
        "/v1/internal/work/acquire",
        "/v1/internal/work/release",
    ] {
        for token in [SERVICE_TOKEN, ADMIN_TOKEN] {
            assert_eq!(
                context
                    .client
                    .post(context.url(path))
                    .bearer_auth(token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND,
                "legacy shared-bearer mutation route {path} is reachable",
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_bodies_hit_deadline_release_global_admission_and_cannot_register() {
    let context = Context::new().await;
    let before = cats_control_plane::testsupport::runtime_spine_state_fingerprint(
        &context.server.state.store,
        context.attempt.node_id.clone(),
    )
    .await;
    let mut openers = tokio::task::JoinSet::new();
    for _ in 0..65 {
        openers.spawn(pending_chunked_request(context.server.addr));
    }
    let mut pending = tokio::task::JoinSet::new();
    while let Some(stream) = openers.join_next().await {
        pending.spawn(raw_status(stream.unwrap()));
    }

    let first_rejection =
        tokio::time::timeout(std::time::Duration::from_secs(2), pending.join_next())
            .await
            .expect("registration saturation was never observed")
            .expect("the pending response set ended before saturation")
            .unwrap();
    assert_eq!(first_rejection, StatusCode::SERVICE_UNAVAILABLE);

    let body = encode_agent_registration_attempt(&context.attempt).unwrap();
    let saturated = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        context.signed_request(body.clone()).send(),
    )
    .await
    .expect("the nonblocking registration admission waited")
    .unwrap();
    assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);

    while let Some(status) = pending.join_next().await {
        assert_eq!(status.unwrap(), StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(
        cats_control_plane::testsupport::runtime_spine_state_fingerprint(
            &context.server.state.store,
            context.attempt.node_id.clone(),
        )
        .await,
        before,
    );

    let registered = context.signed_request(body).send().await.unwrap();
    assert_eq!(registered.status(), StatusCode::OK);
}

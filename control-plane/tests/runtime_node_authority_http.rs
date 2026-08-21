//! Real PostgreSQL plus HTTP acceptance coverage for the A23 administrator
//! Node-authority ingress.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::{
    JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER,
    NODE_SIGNATURE_HEADER,
};
use cats_api::runtime_node_authority::{
    runtime_node_authority_signed_request, NODE_AUTHORITY_APPLY_ID_HEADER,
    PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_SIGNATURE_HEADER, RUNTIME_NODE_AUTHORITY_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_runtime_node_authority_apply_result, encode_runtime_node_authority_apply,
    object_write_writer_authority_id, runtime_provisioner_active_set_digest,
    AllocatableMemoryBytes, AllocatableVcpus, AsciiText, Base64UrlNoPad, ContractVersion,
    CredentialBinding, Epoch, GuestIpv4Pool, GuestIpv4PoolKind, Id, Ipv4Address, NodeIdentity,
    NodeIdentityState, NodePlacementPolicy, NodeTransportTarget, RandomId128,
    RuntimeNodeAuthorityApply, RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeProvisionerActiveSet,
    RuntimeProvisionerCredential, RuntimeProvisionerExpectedPrevious,
    RuntimeProvisionerTrustBundle, RuntimeSchedulingState, Sha256Digest,
};
use cats_control_plane::server::{Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_control_plane::testsupport::spawn_control_plane_for_test as spawn;
use cats_metering::SqliteUsageStore;
use reqwest::{Method, RequestBuilder, StatusCode};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

const DEPLOYMENT_ID: &str = "deployment_a";
const PROVISIONER_ID: &str = "provisioner_a";
const SERVICE_TOKEN: &str = "runtime-node-authority-service-token";
const ADMIN_TOKEN: &str = "runtime-node-authority-admin-token";
const RFC8032_TEST_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RFC8032_SECOND_TEST_SEED: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

struct Context {
    _dir: tempfile::TempDir,
    server: Handle,
    http: reqwest::Client,
    signer: Ed25519KeyPair,
    provisioner_id: String,
}

async fn pending_machine_body(addr: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {RUNTIME_NODE_AUTHORITY_PATH} HTTP/1.1\r\nHost: {addr}\r\n\
         Content-Type: {JSON_CONTENT_TYPE}\r\n\
         Cats-Provisioner-Credential-Id: {PROVISIONER_ID}\r\n\
         Cats-Provisioner-Signature: invalid\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\n{{\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream
}

async fn read_raw_response(mut stream: TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    tokio::time::timeout(
        cats_test_support::poll_bound(),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("A23 raw request exceeded its absolute deadline")
    .unwrap();
    response
}

async fn chunked_machine_request(context: &Context, body: &[u8]) -> Vec<u8> {
    let signed =
        runtime_node_authority_signed_request(DEPLOYMENT_ID, &context.provisioner_id, body);
    let signature = URL_SAFE_NO_PAD.encode(context.signer.sign(&signed).as_ref());
    let mut stream = TcpStream::connect(context.server.addr).await.unwrap();
    let headers = format!(
        "POST {RUNTIME_NODE_AUTHORITY_PATH} HTTP/1.1\r\nHost: {}\r\n\
         Content-Type: {JSON_CONTENT_TYPE}\r\n\
         Cats-Provisioner-Credential-Id: {}\r\n\
         Cats-Provisioner-Signature: {signature}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        context.server.addr,
        context.provisioner_id,
        body.len(),
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
    read_raw_response(stream).await
}

impl Context {
    async fn new() -> Self {
        Self::with_store(
            cats_control_plane::testsupport::isolated_control_store_url(),
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
            PROVISIONER_ID,
            &RFC8032_TEST_SEED,
        )
        .await
    }

    async fn with_store(
        control_store_dsn: String,
        trust_bundle: RuntimeProvisionerTrustBundle,
        provisioner_id: &str,
        seed: &[u8; 32],
    ) -> Self {
        let signer = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(signer.public_key().as_ref());
        assert!(trust_bundle.credentials.iter().any(|credential| {
            credential.credential_id.as_str() == provisioner_id
                && credential.public_key_spki.as_str() == URL_SAFE_NO_PAD.encode(&spki)
        }));
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let server = spawn(Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: DsnSource::Literal(control_store_dsn),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
            auth_token: SERVICE_TOKEN.into(),
            guest_runtime_profile_receipt:
                cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle: trust_bundle,
            production_cutover_operator_trust_bundle:
                cats_control_plane::testsupport::test_production_cutover_operator_trust_bundle(),
            admin_token: ADMIN_TOKEN.into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            oci_deploy_sync_wait_ms: 5_000,
        })
        .await
        .unwrap();
        Self {
            _dir: dir,
            server,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            signer,
            provisioner_id: provisioner_id.to_owned(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.base_url())
    }

    fn signed(&self, body: Vec<u8>) -> RequestBuilder {
        self.signed_with(&self.provisioner_id, &self.signer, body)
    }

    fn signed_with(
        &self,
        provisioner_id: &str,
        signer: &Ed25519KeyPair,
        body: Vec<u8>,
    ) -> RequestBuilder {
        let signed = runtime_node_authority_signed_request(DEPLOYMENT_ID, provisioner_id, &body);
        let signature = URL_SAFE_NO_PAD.encode(signer.sign(&signed).as_ref());
        self.http
            .post(self.url(RUNTIME_NODE_AUTHORITY_PATH))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(PROVISIONER_CREDENTIAL_ID_HEADER, provisioner_id)
            .header(PROVISIONER_SIGNATURE_HEADER, signature)
            .body(body)
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn provisioner_credential(name: &str, spki: &str) -> RuntimeProvisionerCredential {
    RuntimeProvisionerCredential {
        credential_id: id(name),
        public_key_spki: Base64UrlNoPad::new(spki).unwrap(),
    }
}

fn active_set(credentials: Vec<RuntimeProvisionerCredential>) -> RuntimeProvisionerActiveSet {
    RuntimeProvisionerActiveSet {
        version: ContractVersion::V1,
        deployment_id: id(DEPLOYMENT_ID),
        credentials,
    }
}

fn trust(
    revision: u64,
    credentials: Vec<RuntimeProvisionerCredential>,
    previous: Option<&RuntimeProvisionerActiveSet>,
) -> RuntimeProvisionerTrustBundle {
    RuntimeProvisionerTrustBundle {
        version: ContractVersion::V1,
        deployment_id: id(DEPLOYMENT_ID),
        trust_revision: Epoch::new(revision).unwrap(),
        expected_previous: previous.map(|active| RuntimeProvisionerExpectedPrevious {
            trust_revision: Epoch::new(revision - 1).unwrap(),
            active_set_sha256: runtime_provisioner_active_set_digest(active).unwrap(),
        }),
        credentials,
    }
}

fn identity() -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node_http_a"),
        provider_scope: cats_api::runtime_reconciliation::ProviderScope {
            provider: id("test_provider"),
            partition: id("test_partition"),
            account_id: id("test_account"),
            region: id("test_region"),
        },
        immutable_host_id: id("host_http_a"),
        credential_id: id("node_credential_http_a"),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(6),
        },
        state_path_id: id("state_path_http_a"),
        state: NodeIdentityState::Provisioned,
    }
}

fn policy(revision: u64, state: RuntimeSchedulingState, memory: u64) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: id("node_http_a"),
        policy_revision: Epoch::new(revision).unwrap(),
        scheduling_state: state,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(memory).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: digest(7),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://node-http.internal:7301").unwrap(),
    }
}

fn provision(apply_id: u128) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(apply_id),
        node_id: id("node_http_a"),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(identity()),
            placement_policy: Box::new(policy(1, RuntimeSchedulingState::Cordoned, 16 << 30)),
        },
    }
}

fn update(
    apply_id: u128,
    expected: u64,
    state: RuntimeSchedulingState,
) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(apply_id),
        node_id: id("node_http_a"),
        mutation: RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision: Epoch::new(expected).unwrap(),
            placement_policy: Box::new(policy(expected + 1, state, 16 << 30)),
        },
    }
}

fn writer_authority(apply_id: u128, object_store_scope_id: &str) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(apply_id),
        node_id: id("node_http_a"),
        mutation: RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
            expected_policy_revision: Epoch::new(1).unwrap(),
            object_provider_scope: cats_api::runtime_reconciliation::ProviderScope {
                provider: id("test_object_provider"),
                partition: id("test_object_partition"),
                account_id: id("test_object_account"),
                region: id("test_object_region"),
            },
            workload_principal_id: AsciiText::new(
                "arn:test:iam::test_object_account:role/cats-object-write-gateway",
            )
            .unwrap(),
            object_store_scope_id: AsciiText::new(object_store_scope_id).unwrap(),
        },
    }
}

fn assigned_writer_authority_id(apply: &RuntimeNodeAuthorityApply) -> Id {
    let RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
        object_provider_scope,
        workload_principal_id,
        object_store_scope_id,
        ..
    } = &apply.mutation
    else {
        panic!("fixture is a writer authority apply")
    };
    object_write_writer_authority_id(
        &apply.node_id,
        object_provider_scope,
        workload_principal_id,
        object_store_scope_id,
    )
}

async fn exact_body(response: reqwest::Response) -> Vec<u8> {
    assert_eq!(
        response.headers()[reqwest::header::CACHE_CONTROL],
        "no-store"
    );
    assert_eq!(
        response.headers()[reqwest::header::CONTENT_TYPE],
        JSON_CONTENT_TYPE
    );
    response.bytes().await.unwrap().to_vec()
}

#[tokio::test]
async fn machine_apply_replay_conflict_and_persisted_precondition_are_exact() {
    let context = Context::new().await;
    let request = provision(1);
    let request_body = encode_runtime_node_authority_apply(&request).unwrap();
    let first = context.signed(request_body.clone()).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert!(first
        .headers()
        .get(NODE_AUTHORITY_APPLY_ID_HEADER)
        .is_none());
    let first_body = exact_body(first).await;
    let result = decode_runtime_node_authority_apply_result(&first_body).unwrap();
    assert_eq!(result.apply_id, request.apply_id);
    assert_eq!(result.outcome, RuntimeNodeAuthorityOutcome::Provisioned);

    let replay = context.signed(request_body).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(exact_body(replay).await, first_body);

    let conflicting = update(1, 1, RuntimeSchedulingState::Schedulable);
    let conflict = context
        .signed(encode_runtime_node_authority_apply(&conflicting).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert!(conflict
        .headers()
        .get(NODE_AUTHORITY_APPLY_ID_HEADER)
        .is_none());
    assert_eq!(
        exact_body(conflict).await,
        br#"{"code":"apply_id_conflict","message":"runtime node authority apply ID conflicts with another request"}"#
    );

    let rejected = update(2, 9, RuntimeSchedulingState::Schedulable);
    let rejected_body = encode_runtime_node_authority_apply(&rejected).unwrap();
    let precondition = context.signed(rejected_body.clone()).send().await.unwrap();
    assert_eq!(precondition.status(), StatusCode::CONFLICT);
    assert_eq!(
        precondition.headers()[NODE_AUTHORITY_APPLY_ID_HEADER],
        rejected.apply_id.as_str()
    );
    let precondition_body = exact_body(precondition).await;
    assert_eq!(
        precondition_body,
        br#"{"code":"authority_precondition_failed","message":"runtime node authority precondition failed"}"#
    );
    let replay = context.signed(rejected_body).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(
        replay.headers()[NODE_AUTHORITY_APPLY_ID_HEADER],
        rejected.apply_id.as_str()
    );
    assert_eq!(exact_body(replay).await, precondition_body);
}

#[tokio::test]
async fn signed_writer_authority_apply_returns_one_assigned_authority_id() {
    let context = Context::new().await;
    let provisioned = context
        .signed(encode_runtime_node_authority_apply(&provision(1)).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(provisioned.status(), StatusCode::OK);

    let request = writer_authority(2, "arn:test:s3:::cats-http/chunks");
    let request_body = encode_runtime_node_authority_apply(&request).unwrap();
    let applied = context.signed(request_body.clone()).send().await.unwrap();
    assert_eq!(applied.status(), StatusCode::OK);
    let applied_body = exact_body(applied).await;
    let result = decode_runtime_node_authority_apply_result(&applied_body).unwrap();
    assert_eq!(
        result.outcome,
        RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned
    );
    assert_eq!(
        result.writer_authority_id,
        Some(assigned_writer_authority_id(&request))
    );

    // Exact replay returns the same assigned authority; a second apply ID with
    // a changed binding is refused rather than silently rebinding the Host.
    let replay = context.signed(request_body).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(exact_body(replay).await, applied_body);

    let changed = writer_authority(3, "arn:test:s3:::cats-http-other/chunks");
    let refused = context
        .signed(encode_runtime_node_authority_apply(&changed).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(
        exact_body(refused).await,
        br#"{"code":"authority_precondition_failed","message":"runtime node authority precondition failed"}"#
    );

    // An unsigned bearer envelope is still the only authentication the ingress
    // knows; the writer authority adds no second mechanism.
    let unsigned = context
        .http
        .post(context.url(RUNTIME_NODE_AUTHORITY_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .bearer_auth(ADMIN_TOKEN)
        .body(
            encode_runtime_node_authority_apply(&writer_authority(
                4,
                "arn:test:s3:::cats-http/chunks",
            ))
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn machine_envelope_rejects_legacy_and_node_credentials_before_decode() {
    let context = Context::new().await;
    for token in [
        ADMIN_TOKEN,
        SERVICE_TOKEN,
        "cats_wst_0123456789abcdef0123456789abcdef",
    ] {
        let response = context
            .http
            .post(context.url(RUNTIME_NODE_AUTHORITY_PATH))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .bearer_auth(token)
            .body("not-json")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            exact_body(response).await,
            br#"{"code":"authentication_failed","message":"runtime node authority authentication failed"}"#
        );
    }

    let node_proof = context
        .http
        .post(context.url(RUNTIME_NODE_AUTHORITY_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(NODE_CREDENTIAL_ID_HEADER, "node_credential")
        .header(NODE_PUBLIC_KEY_SPKI_HEADER, "node_spki")
        .header(NODE_SIGNATURE_HEADER, "node_signature")
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(node_proof.status(), StatusCode::UNAUTHORIZED);

    let body = encode_runtime_node_authority_apply(&provision(10)).unwrap();
    let mut changed = body.clone();
    changed.push(b' ');
    let signed = runtime_node_authority_signed_request(DEPLOYMENT_ID, PROVISIONER_ID, &body);
    let signature = URL_SAFE_NO_PAD.encode(context.signer.sign(&signed).as_ref());
    let wrong_body = context
        .http
        .post(context.url(RUNTIME_NODE_AUTHORITY_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_ID)
        .header(PROVISIONER_SIGNATURE_HEADER, signature)
        .body(changed)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_body.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn route_media_and_wire_caps_are_closed_before_domain_decode() {
    let context = Context::new().await;
    let method = context
        .http
        .request(Method::GET, context.url(RUNTIME_NODE_AUTHORITY_PATH))
        .send()
        .await
        .unwrap();
    assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(method.headers()[reqwest::header::ALLOW], "POST");
    assert_eq!(method.headers()[reqwest::header::CACHE_CONTROL], "no-store");

    let query = context
        .http
        .post(context.url(&format!("{RUNTIME_NODE_AUTHORITY_PATH}?x=1")))
        .send()
        .await
        .unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        exact_body(query).await,
        br#"{"code":"invalid_request_target","message":"runtime node authority request target is invalid"}"#
    );

    for path in [
        format!("{RUNTIME_NODE_AUTHORITY_PATH}/"),
        "/v1/admin/runtime/node-authority-%61pplies".to_owned(),
    ] {
        assert_eq!(
            context
                .http
                .post(context.url(&path))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    let media = context
        .http
        .post(context.url(RUNTIME_NODE_AUTHORITY_PATH))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(media.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let mut at_limit = vec![b' '; 65_536];
    at_limit[0] = b'{';
    at_limit[1] = b'}';
    let accepted_into_decoder = context.signed(at_limit).send().await.unwrap();
    assert_eq!(accepted_into_decoder.status(), StatusCode::BAD_REQUEST);

    let over_limit = context.signed(vec![b' '; 65_537]).send().await.unwrap();
    assert_eq!(over_limit.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        exact_body(over_limit).await,
        br#"{"code":"request_too_large","message":"runtime node authority request is too large"}"#
    );

    let mut chunked_at_limit = vec![b' '; 65_536];
    chunked_at_limit[0] = b'{';
    chunked_at_limit[1] = b'}';
    let response = chunked_machine_request(&context, &chunked_at_limit).await;
    assert!(std::str::from_utf8(&response)
        .unwrap()
        .starts_with("HTTP/1.1 400 Bad Request\r\n"));
    let response = chunked_machine_request(&context, &vec![b' '; 65_537]).await;
    let response = std::str::from_utf8(&response).unwrap();
    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with(
        r#"{"code":"request_too_large","message":"runtime node authority request is too large"}"#
    ));
}

#[tokio::test]
async fn persisted_trust_rotation_immediately_retires_local_old_key_and_new_key_replays() {
    let a = provisioner_credential(
        "provisioner_a",
        "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    );
    let b = provisioner_credential(
        "provisioner_b",
        "MCowBQYDK2VwAyEAPUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw",
    );
    let revision_one_set = active_set(vec![a.clone()]);
    let revision_two_set = active_set(vec![a.clone(), b.clone()]);
    let dsn = cats_control_plane::testsupport::isolated_control_store_url();
    cats_control_plane::testsupport::seed_runtime_provisioner_trust_bundle(
        &dsn,
        &trust(1, revision_one_set.credentials.clone(), None),
    );
    let context = Context::with_store(
        dsn,
        trust(
            2,
            revision_two_set.credentials.clone(),
            Some(&revision_one_set),
        ),
        "provisioner_a",
        &RFC8032_TEST_SEED,
    )
    .await;

    let apply = update(50, 1, RuntimeSchedulingState::Schedulable);
    let body = encode_runtime_node_authority_apply(&apply).unwrap();
    let first = context.signed(body.clone()).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::CONFLICT);
    assert_eq!(
        first.headers()[NODE_AUTHORITY_APPLY_ID_HEADER],
        apply.apply_id.as_str()
    );
    let first_body = exact_body(first).await;

    cats_control_plane::testsupport::install_runtime_provisioner_trust_bundle(
        &context.server.state.store,
        trust(3, vec![b.clone()], Some(&revision_two_set)),
    )
    .await;

    // The replica still has A in its immutable local bundle. The mandatory
    // persisted lineage check must nevertheless reject it before replay.
    let retired = context.signed(body.clone()).send().await.unwrap();
    assert_eq!(retired.status(), StatusCode::UNAUTHORIZED);
    assert!(retired
        .headers()
        .get(NODE_AUTHORITY_APPLY_ID_HEADER)
        .is_none());
    assert_eq!(
        exact_body(retired).await,
        br#"{"code":"authentication_failed","message":"runtime node authority authentication failed"}"#
    );

    let signer_b = Ed25519KeyPair::from_seed_unchecked(&RFC8032_SECOND_TEST_SEED).unwrap();
    let mut spki_b = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki_b.extend_from_slice(signer_b.public_key().as_ref());
    assert_eq!(URL_SAFE_NO_PAD.encode(spki_b), b.public_key_spki.as_str());
    let replay = context
        .signed_with("provisioner_b", &signer_b, body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(
        replay.headers()[NODE_AUTHORITY_APPLY_ID_HEADER],
        apply.apply_id.as_str()
    );
    assert_eq!(exact_body(replay).await, first_body);
}

#[tokio::test]
async fn global_admission_is_exactly_32_nonblocking_requests_and_releases_on_cancel() {
    let context = Context::new().await;
    let pending =
        futures_util::future::join_all((0..32).map(|_| pending_machine_body(context.server.addr)))
            .await;
    // Let Hyper dispatch all 32 parsed header blocks into the handler. The
    // bodies intentionally remain incomplete after global admission.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let full = context
        .http
        .post(context.url(RUNTIME_NODE_AUTHORITY_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_ID)
        .header(PROVISIONER_SIGNATURE_HEADER, "invalid")
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(full.headers()[reqwest::header::RETRY_AFTER], "1");
    assert_eq!(
        exact_body(full).await,
        br#"{"code":"temporarily_unavailable","message":"runtime node authority is temporarily unavailable"}"#
    );

    drop(pending);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let released = context
        .http
        .post(context.url(RUNTIME_NODE_AUTHORITY_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_ID)
        .header(PROVISIONER_SIGNATURE_HEADER, "invalid")
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn absolute_deadline_closes_an_incomplete_body_with_the_one_retryable_error() {
    let context = Context::new().await;
    let stream = pending_machine_body(context.server.addr).await;
    let started = std::time::Instant::now();
    let response = read_raw_response(stream).await;
    assert!(started.elapsed() >= std::time::Duration::from_secs(9));
    let response = std::str::from_utf8(&response).unwrap();
    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.to_ascii_lowercase().contains("retry-after: 1\r\n"));
    assert!(response
        .to_ascii_lowercase()
        .contains("cache-control: no-store\r\n"));
    assert!(response.ends_with(
        r#"{"code":"temporarily_unavailable","message":"runtime node authority is temporarily unavailable"}"#
    ));
}

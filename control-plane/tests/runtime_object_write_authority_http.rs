//! Real PostgreSQL plus HTTP acceptance coverage for one Node reading its own
//! object-write writer authority.
//!
//! Control derives `owa1_<64hex>` from the Node ID, so the value is per Node
//! while the fleet deployment writes one shared worker environment. This route
//! is the only way a Node can learn it, so the identity boundary here is load
//! bearing: the authenticated A19 credential selects the Node, the request may
//! only restate it, and a stale or foreign session gets no answer.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER, REGISTRATION_PATH,
};
use cats_api::object_write_gateway::{
    decode_object_write_writer_authority_read, encode_object_write_writer_authority_read,
    encode_object_write_writer_authority_view, ObjectWriteWriterAuthorityRead,
    ObjectWriteWriterAuthorityStateV1, ObjectWriteWriterAuthorityView,
    OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH,
};
use cats_api::runtime_node_authority::{
    runtime_node_authority_signed_request, PROVISIONER_CREDENTIAL_ID_HEADER,
    PROVISIONER_SIGNATURE_HEADER, RUNTIME_NODE_AUTHORITY_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_agent_session, decode_runtime_node_authority_apply_result,
    encode_agent_registration_attempt, encode_runtime_node_authority_apply, guest_config_digest,
    object_write_writer_authority_id, AgentRegistrationAttempt, AgentSession,
    AllocatableMemoryBytes, AllocatableVcpus, AsciiText, ContractVersion, CredentialBinding, Epoch,
    GuestIpv4Pool, GuestIpv4PoolKind, Id, Ipv4Address, NodeBootId, NodeIdentity, NodeIdentityState,
    NodePlacementPolicy, NodeTransportTarget, ProviderScope, RandomId128,
    RuntimeNodeAuthorityApply, RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeSchedulingState, SessionBinding,
};
use cats_control_plane::server::{Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_control_plane::testsupport::spawn_control_plane_for_test as spawn;
use cats_metering::SqliteUsageStore;
use reqwest::StatusCode;
use ring::signature::Ed25519KeyPair;

const DEPLOYMENT_ID: &str = "deployment_a";
const PROVISIONER_ID: &str = "provisioner_a";
const SERVICE_TOKEN: &str = "object-write-authority-read-service-token";
const ADMIN_TOKEN: &str = "object-write-authority-read-admin-token";
const WORKLOAD_PRINCIPAL: &str = "arn:test:iam::test_object_account:role/cats-object-write-gateway";
const OBJECT_STORE_SCOPE: &str = "arn:test:s3:::cats-owra/chunks";
/// RFC 8032 test vector 1 secret key: the exact private half of the SPKI in
/// `test_runtime_provisioner_trust_bundle`.
const PROVISIONER_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn text(value: &str) -> AsciiText {
    AsciiText::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn host_scope() -> ProviderScope {
    ProviderScope {
        provider: id("test_provider"),
        partition: id("test_partition"),
        account_id: id("test_account"),
        region: id("test_region"),
    }
}

fn object_scope() -> ProviderScope {
    ProviderScope {
        provider: id("test_object_provider"),
        partition: id("test_object_partition"),
        account_id: id("test_object_account"),
        region: id("test_object_region"),
    }
}

/// One per-Node A19 signer from a fixed seed, so the provisioned credential
/// binding and the request proof are the same real key pair.
fn node_signer(credential_id: &str, seed: u8) -> Ed25519RequestSigner {
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend(std::iter::repeat_n(seed, 32));
    Ed25519RequestSigner::from_pkcs8_der(id(credential_id), &pkcs8).unwrap()
}

/// One provisioned Node: its A19 signer, its identity and its current session.
struct Node {
    signer: Ed25519RequestSigner,
    identity: NodeIdentity,
    session: AgentSession,
}

impl Node {
    fn binding(&self) -> SessionBinding {
        SessionBinding {
            node_id: self.session.node_id.clone(),
            node_boot_id: self.session.node_boot_id.clone(),
            agent_instance_id: self.session.agent_instance_id.clone(),
            agent_session_epoch: self.session.agent_session_epoch,
        }
    }

    fn assigned_writer_authority_id(&self) -> Id {
        object_write_writer_authority_id(
            &self.identity.node_id,
            &object_scope(),
            &text(WORKLOAD_PRINCIPAL),
            &text(OBJECT_STORE_SCOPE),
        )
    }
}

struct Context {
    _dir: tempfile::TempDir,
    server: Handle,
    http: reqwest::Client,
    provisioner: Ed25519KeyPair,
}

impl Context {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let server = spawn(Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: DsnSource::Literal(
                cats_control_plane::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
            auth_token: SERVICE_TOKEN.into(),
            noded_service_token: "semantic-node-test-token-00000000".into(),
            guest_runtime_profile_receipt:
                cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle:
                cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
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
            provisioner: Ed25519KeyPair::from_seed_unchecked(&PROVISIONER_SEED).unwrap(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.base_url())
    }

    /// One operator apply through the independent A23 machine ingress.
    async fn apply(&self, apply: &RuntimeNodeAuthorityApply) -> RuntimeNodeAuthorityOutcome {
        let body = encode_runtime_node_authority_apply(apply).unwrap();
        let signed = runtime_node_authority_signed_request(DEPLOYMENT_ID, PROVISIONER_ID, &body);
        let signature = URL_SAFE_NO_PAD.encode(self.provisioner.sign(&signed).as_ref());
        let response = self
            .http
            .post(self.url(RUNTIME_NODE_AUTHORITY_PATH))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_ID)
            .header(PROVISIONER_SIGNATURE_HEADER, signature)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        decode_runtime_node_authority_apply_result(&response.bytes().await.unwrap())
            .unwrap()
            .outcome
    }

    /// Provision one Node identity and placement policy, then register its
    /// current Agent session with its own A19 credential.
    async fn provision_node(&self, index: u8) -> Node {
        let suffix = char::from(b'a' + index);
        let signer = node_signer(&format!("credential_owra_{suffix}"), 0x11 + index);
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: id(&format!("node_owra_{suffix}")),
            provider_scope: host_scope(),
            immutable_host_id: id(&format!("host_owra_{suffix}")),
            credential_id: signer.credential_id().clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: id(&format!("state_owra_{suffix}")),
            state: NodeIdentityState::Provisioned,
        };
        let policy = NodePlacementPolicy {
            version: ContractVersion::V1,
            node_id: identity.node_id.clone(),
            policy_revision: Epoch::new(1).unwrap(),
            scheduling_state: RuntimeSchedulingState::Cordoned,
            allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
            allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
            capabilities: RuntimePlacementCapabilities {
                vmm: RuntimePlacementVmm::CloudHypervisor,
                block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
                guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
                guest_transport: RuntimePlacementGuestTransport::Vsock,
                guest_agent_protocol_version: ContractVersion::V1,
                guest_config_digest: guest_config_digest(
                    &cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
                )
                .unwrap(),
            },
            guest_ipv4_pool: GuestIpv4Pool {
                kind: GuestIpv4PoolKind::PrivateIpv4_16,
                network_address: Ipv4Address::new("10.240.0.0").unwrap(),
                prefix_length: 16,
            },
            node_transport_target: NodeTransportTarget::new(format!(
                "https://node-owra-{suffix}.internal:7301"
            ))
            .unwrap(),
        };
        assert_eq!(
            self.apply(&RuntimeNodeAuthorityApply {
                version: ContractVersion::V1,
                apply_id: random(u128::from(index) + 1),
                node_id: identity.node_id.clone(),
                mutation: RuntimeNodeAuthorityMutation::Provision {
                    node_identity: Box::new(identity.clone()),
                    placement_policy: Box::new(policy),
                },
            })
            .await,
            RuntimeNodeAuthorityOutcome::Provisioned
        );

        let attempt = AgentRegistrationAttempt {
            version: ContractVersion::V1,
            node_id: identity.node_id.clone(),
            immutable_host_id: identity.immutable_host_id.clone(),
            node_boot_id: NodeBootId::new(format!("{:032x}", u128::from(index) + 0x11)).unwrap(),
            agent_instance_id: random(u128::from(index) + 0x21),
            registration_attempt_id: random(u128::from(index) + 0x31),
            guest_config_digest: guest_config_digest(
                &cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
            )
            .unwrap(),
            expected_agent_session_epoch: None,
        };
        let body = encode_agent_registration_attempt(&attempt).unwrap();
        let proof = signer.sign("POST", REGISTRATION_PATH, &body);
        let response = self
            .http
            .post(self.url(REGISTRATION_PATH))
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
        Node {
            signer,
            identity,
            session,
        }
    }

    /// Open one Node's writer authority through the same operator command an
    /// administrator runs.
    async fn provision_writer_authority(&self, node: &Node, apply_id: u128) -> Id {
        assert_eq!(
            self.apply(&RuntimeNodeAuthorityApply {
                version: ContractVersion::V1,
                apply_id: random(apply_id),
                node_id: node.identity.node_id.clone(),
                mutation: RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
                    expected_policy_revision: Epoch::new(1).unwrap(),
                    object_provider_scope: object_scope(),
                    workload_principal_id: text(WORKLOAD_PRINCIPAL),
                    object_store_scope_id: text(OBJECT_STORE_SCOPE),
                },
            })
            .await,
            RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned
        );
        node.assigned_writer_authority_id()
    }

    /// One A19-signed authority read: `signer` proves the identity, `session`
    /// is the session the request names. They are separate so a test can have
    /// one Node name another Node's session.
    async fn read(
        &self,
        signer: &Ed25519RequestSigner,
        session: &SessionBinding,
    ) -> reqwest::Response {
        let body = encode_object_write_writer_authority_read(&ObjectWriteWriterAuthorityRead {
            version: ContractVersion::V1,
            session: session.clone(),
        })
        .unwrap();
        let proof = signer.sign("POST", OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH, &body);
        self.http
            .post(self.url(OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
            .send()
            .await
            .unwrap()
    }
}

async fn accepted_view(response: reqwest::Response) -> ObjectWriteWriterAuthorityView {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[reqwest::header::CONTENT_TYPE],
        JSON_CONTENT_TYPE
    );
    assert_eq!(
        response.headers()[reqwest::header::CACHE_CONTROL],
        "no-store"
    );
    let body = response.bytes().await.unwrap();
    let view = cats_api::object_write_gateway::decode_object_write_writer_authority_view(&body)
        .expect("the route answers exactly one canonical view");
    assert_eq!(
        encode_object_write_writer_authority_view(&view).unwrap(),
        body.to_vec(),
        "the response body is the canonical encoding of its own view"
    );
    view
}

#[tokio::test]
async fn a_node_reads_its_own_writer_authority_over_the_signed_route() {
    let context = Context::new().await;
    let node = context.provision_node(0).await;

    // Before the operator command there is nothing to publish under, and the
    // answer says exactly that rather than failing or guessing.
    let absent = accepted_view(context.read(&node.signer, &node.binding()).await).await;
    assert_eq!(absent.session, node.binding());
    assert_eq!(absent.authority, ObjectWriteWriterAuthorityStateV1::Absent);

    let assigned = context.provision_writer_authority(&node, 0x40).await;
    let opened = accepted_view(context.read(&node.signer, &node.binding()).await).await;
    assert_eq!(opened.session, node.binding());
    assert_eq!(
        opened.authority,
        ObjectWriteWriterAuthorityStateV1::Open {
            writer_authority_id: assigned.clone(),
        },
        "the Node reads exactly the authority ID Control assigned its Host"
    );
    assert!(
        assigned.as_str().starts_with("owa1_"),
        "the answer is Control's derived ID, not a caller-chosen value: {assigned}"
    );
}

#[tokio::test]
async fn a_node_asking_about_another_node_is_refused() {
    let context = Context::new().await;
    let mine = context.provision_node(0).await;
    let neighbour = context.provision_node(1).await;
    let assigned = context.provision_writer_authority(&mine, 0x40).await;

    // Calibration: each Node's own read is answered over this exact route.
    assert_eq!(
        accepted_view(context.read(&mine.signer, &mine.binding()).await)
            .await
            .authority,
        ObjectWriteWriterAuthorityStateV1::Open {
            writer_authority_id: assigned,
        }
    );
    assert_eq!(
        accepted_view(context.read(&neighbour.signer, &neighbour.binding()).await)
            .await
            .authority,
        ObjectWriteWriterAuthorityStateV1::Absent
    );

    let refused = context.read(&neighbour.signer, &mine.binding()).await;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "a Node may not read another Node's writer authority"
    );
    let refused_body = refused.bytes().await.unwrap();
    assert!(
        !String::from_utf8_lossy(&refused_body).contains("owa1_"),
        "a refusal must not leak the other Node's authority ID: {}",
        String::from_utf8_lossy(&refused_body)
    );
}

#[tokio::test]
async fn an_unproven_writer_authority_read_is_refused_with_a_node_signature_challenge() {
    let context = Context::new().await;
    let node = context.provision_node(0).await;
    context.provision_writer_authority(&node, 0x40).await;
    let body = encode_object_write_writer_authority_read(&ObjectWriteWriterAuthorityRead {
        version: ContractVersion::V1,
        session: node.binding(),
    })
    .unwrap();
    // Calibration: this exact body is the canonical request the route accepts.
    decode_object_write_writer_authority_read(&body).unwrap();

    let unsigned = context
        .http
        .post(context.url(OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    assert!(unsigned
        .headers()
        .contains_key(reqwest::header::WWW_AUTHENTICATE));

    // A valid signature over a different path is not a proof for this route.
    let wrong_path_proof = node.signer.sign("POST", REGISTRATION_PATH, &body);
    let mismatched = context
        .http
        .post(context.url(OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH))
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
    assert_eq!(mismatched.status(), StatusCode::UNAUTHORIZED);

    // Calibration: the same credential over the exact path is accepted.
    assert_eq!(
        context.read(&node.signer, &node.binding()).await.status(),
        StatusCode::OK
    );
}

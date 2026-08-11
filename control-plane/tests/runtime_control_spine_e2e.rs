//! Cross-router PostgreSQL acceptance for the production runtime authority.
//!
//! Production authority mutations enter through one of two independently
//! composed HTTP servers sharing only their durable PostgreSQL schema and
//! configured authorities. Direct Store access is limited to explicit test
//! setup/terminal-corruption fixtures and the final read-only facts projection.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER, REGISTRATION_PATH,
};
use cats_api::cat_create::decode_cat_create_v2_accepted_response;
use cats_api::requests::ListResponse;
use cats_api::resources::Disk;
use cats_api::runtime_node_authority::{
    runtime_node_authority_signed_request, PROVISIONER_CREDENTIAL_ID_HEADER,
    PROVISIONER_SIGNATURE_HEADER, RUNTIME_NODE_AUTHORITY_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_agent_session, decode_desired_read_snapshot, decode_observation_acceptance,
    decode_operation, decode_runtime_node_authority_apply_result,
    encode_agent_registration_attempt, encode_desired_read_request, encode_node_observation,
    encode_operation, encode_runtime_node_authority_apply, guest_config_digest, inventory_digest,
    AgentRegistrationAttempt, AllocatableMemoryBytes, AllocatableVcpus, ContractVersion,
    CredentialBinding, DesiredReadRequest, Durability, Epoch, GuestIpv4Pool, GuestIpv4PoolKind, Id,
    Ipv4Address, NodeBootId, NodeIdentity, NodeIdentityState, NodeObservation, NodePlacementPolicy,
    NodeTransportTarget, Operation, OperationFailure, OperationPhase, OperationSuccess,
    OperationTerminal, RandomId128, Revision, RuntimeNodeAuthorityApply,
    RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome, RuntimePlacementBlockFrontend,
    RuntimePlacementCapabilities, RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport,
    RuntimePlacementVmm, RuntimeSchedulingState, Sequence, SessionBinding, Sha256Digest,
    UnixMillis, DESIRED_READ_PATH, OBSERVATION_PATH,
};
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{
    spawn, spawn_runtime_authority_with_billing_for_tests, Config, Handle,
};
use cats_control_plane::store::DsnSource;
use cats_control_plane::testsupport::RuntimeCutoverAcceptanceFacts;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::{
    CheckoutIntent, CheckoutPayment, CheckoutRefund, CreditApplyOutcome, CreditStore,
    CreditStoreFuture, CreditSummary, SqliteUsageStore,
};
use cats_storage::{
    encode_image_manifest, image_manifest_key, BlobError, BlobStore, ImageManifestV1,
    LowerHexSha256, MetadataStore, IMAGE_MANIFEST_MAX_BYTES,
};
use reqwest::{RequestBuilder, Response, StatusCode};
use ring::signature::Ed25519KeyPair;

const DEPLOYMENT_ID: &str = "deployment_a";
const PROVISIONER_ID: &str = "provisioner_a";
const SERVICE_TOKEN: &str = "runtime-control-spine-service-token";
const ADMIN_TOKEN: &str = "runtime-control-spine-admin-token";
const IMAGE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const IMAGE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CAT_CREATE_BODY: &[u8] = br#"{"name":"app","boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vcpus":2,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"strict"}"#;
const PERSISTENT_DISK_CREATE_BODY: &[u8] =
    br#"{"durability":"strict","name":"data","size_bytes":1073741824}"#;
const RFC8032_TEST_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

struct ToggleCreditStore {
    inner: Arc<SqliteUsageStore>,
    funded: AtomicBool,
}

impl ToggleCreditStore {
    fn new(inner: Arc<SqliteUsageStore>) -> Self {
        Self {
            inner,
            funded: AtomicBool::new(true),
        }
    }

    fn set_funded(&self, funded: bool) {
        self.funded.store(funded, Ordering::SeqCst);
    }
}

impl CreditStore for ToggleCreditStore {
    fn ensure_account<'a>(
        &'a self,
        billing_account_id: &'a str,
        account_id: &'a str,
        currency: &'a str,
        signup_credit_nanos: i128,
        created_at_unix_ms: i64,
    ) -> CreditStoreFuture<'a, CreditSummary> {
        let funded = &self.funded;
        let future = CreditStore::ensure_account(
            self.inner.as_ref(),
            billing_account_id,
            account_id,
            currency,
            signup_credit_nanos,
            created_at_unix_ms,
        );
        Box::pin(async move {
            let mut summary = future.await?;
            summary.credit_nanos = if funded.load(Ordering::SeqCst) {
                10_000_000_000
            } else {
                0
            };
            Ok(summary)
        })
    }

    fn summary<'a>(&'a self, billing_account_id: &'a str) -> CreditStoreFuture<'a, CreditSummary> {
        CreditStore::summary(self.inner.as_ref(), billing_account_id)
    }

    fn create_checkout_intent<'a>(
        &'a self,
        intent: &'a CheckoutIntent,
    ) -> CreditStoreFuture<'a, CheckoutIntent> {
        CreditStore::create_checkout_intent(self.inner.as_ref(), intent)
    }

    fn attach_checkout_session<'a>(
        &'a self,
        intent_id: &'a str,
        stripe_session_id: &'a str,
        checkout_url: &'a str,
    ) -> CreditStoreFuture<'a, CheckoutIntent> {
        CreditStore::attach_checkout_session(
            self.inner.as_ref(),
            intent_id,
            stripe_session_id,
            checkout_url,
        )
    }

    fn apply_checkout_payment<'a>(
        &'a self,
        payment: &'a CheckoutPayment,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome> {
        CreditStore::apply_checkout_payment(self.inner.as_ref(), payment)
    }

    fn apply_checkout_refund<'a>(
        &'a self,
        refund: &'a CheckoutRefund,
    ) -> CreditStoreFuture<'a, CreditApplyOutcome> {
        CreditStore::apply_checkout_refund(self.inner.as_ref(), refund)
    }
}

struct FixedImageBlob {
    key: String,
    body: Vec<u8>,
    reads: AtomicUsize,
}

impl FixedImageBlob {
    fn read(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        if key != self.key {
            return Err(BlobError::NotFound(key.to_owned()));
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.body.clone())
    }
}

impl BlobStore for FixedImageBlob {
    fn put_immutable(&self, key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
        Err(BlobError::Backend {
            key: key.to_owned(),
            message: "read-only acceptance image store".into(),
        })
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.read(key)
    }

    fn get_bounded_until(
        &self,
        key: &str,
        maximum: usize,
        deadline: Instant,
    ) -> cats_storage::blob::Result<Vec<u8>> {
        if maximum != IMAGE_MANIFEST_MAX_BYTES || Instant::now() >= deadline {
            return Err(BlobError::Backend {
                key: key.to_owned(),
                message: "unexpected manifest read boundary".into(),
            });
        }
        self.read(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        Ok(key == self.key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        Err(BlobError::Backend {
            key: key.to_owned(),
            message: "read-only acceptance image store".into(),
        })
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        Ok(self
            .key
            .starts_with(prefix)
            .then(|| self.key.clone())
            .into_iter()
            .collect())
    }
}

struct Context {
    _dir: tempfile::TempDir,
    first: Handle,
    second: Handle,
    http: reqwest::Client,
    node_signer: Ed25519RequestSigner,
    provisioner_signer: Ed25519KeyPair,
    release: cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt,
    image_blob: Arc<FixedImageBlob>,
    config: Config,
    credits: Arc<ToggleCreditStore>,
}

impl Context {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("storage.db")).unwrap());
        let release = cats_control_plane::testsupport::test_guest_runtime_profile_receipt();
        let digest = Sha256Digest::new(IMAGE_DIGEST).unwrap();
        let manifest = ImageManifestV1 {
            version: 1,
            image_id: LowerHexSha256::new(IMAGE_HEX).unwrap(),
            size_bytes: 4_194_304,
            chunks: Vec::new(),
        };
        let image_blob = Arc::new(FixedImageBlob {
            key: image_manifest_key(&digest),
            body: encode_image_manifest(&manifest).unwrap(),
            reads: AtomicUsize::new(0),
        });
        let credits = Arc::new(ToggleCreditStore::new(usage.clone()));
        let config = Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: DsnSource::Literal(
                cats_control_plane::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: credits.clone(),
            storage_meta,
            image_blob: image_blob.clone(),
            auth_token: SERVICE_TOKEN.into(),
            guest_runtime_profile_receipt: release.clone(),
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
        };
        let first = spawn(config.clone()).await.unwrap();
        let second = spawn(config.clone()).await.unwrap();
        let node_signer = Ed25519RequestSigner::from_pkcs8_pem(
            id("credential_cutover_a"),
            include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
        )
        .unwrap();
        let provisioner_signer = Ed25519KeyPair::from_seed_unchecked(&RFC8032_TEST_SEED).unwrap();
        Self {
            _dir: dir,
            first,
            second,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            node_signer,
            provisioner_signer,
            release,
            image_blob,
            config,
            credits,
        }
    }

    fn node_request(&self, server: &Handle, path: &str, body: Vec<u8>) -> RequestBuilder {
        let proof = self.node_signer.sign("POST", path, &body);
        self.http
            .post(format!("{}{path}", server.base_url()))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
    }

    fn registration_request(&self, server: &Handle, body: Vec<u8>) -> RequestBuilder {
        let proof = self.node_signer.sign("POST", REGISTRATION_PATH, &body);
        self.http
            .post(format!("{}{REGISTRATION_PATH}", server.base_url()))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
    }

    fn node_authority_request(&self, server: &Handle, body: Vec<u8>) -> RequestBuilder {
        let signed = runtime_node_authority_signed_request(DEPLOYMENT_ID, PROVISIONER_ID, &body);
        let signature = URL_SAFE_NO_PAD.encode(self.provisioner_signer.sign(&signed).as_ref());
        self.http
            .post(format!(
                "{}{RUNTIME_NODE_AUTHORITY_PATH}",
                server.base_url()
            ))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_ID)
            .header(PROVISIONER_SIGNATURE_HEADER, signature)
            .body(body)
    }

    fn cat_create_request(
        &self,
        server: &Handle,
        workspace_id: &str,
        idempotency_key: &str,
    ) -> RequestBuilder {
        self.http
            .post(format!(
                "{}/v1/workspaces/{workspace_id}/cats",
                server.base_url()
            ))
            .bearer_auth(ADMIN_TOKEN)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header("Idempotency-Key", idempotency_key)
            .body(CAT_CREATE_BODY.to_vec())
    }

    fn persistent_disk_create_request(
        &self,
        server: &Handle,
        workspace_id: &str,
        idempotency_key: &str,
    ) -> RequestBuilder {
        self.http
            .post(format!(
                "{}/v1/workspaces/{workspace_id}/disks",
                server.base_url()
            ))
            .bearer_auth(ADMIN_TOKEN)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header("Idempotency-Key", idempotency_key)
            .body(PERSISTENT_DISK_CREATE_BODY.to_vec())
    }

    fn operation_request(
        &self,
        server: &Handle,
        workspace_id: &str,
        operation_id: &str,
    ) -> RequestBuilder {
        self.http
            .get(format!(
                "{}/v1/workspaces/{workspace_id}/operations/{operation_id}",
                server.base_url()
            ))
            .bearer_auth(ADMIN_TOKEN)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random(value: &str) -> RandomId128 {
    RandomId128::new(value).unwrap()
}

fn node_identity(signer: &Ed25519RequestSigner) -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node_cutover_a"),
        immutable_host_id: id("host_cutover_a"),
        credential_id: signer.credential_id().clone(),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: signer.public_key_spki_sha256(),
        },
        state_path_id: id("state_cutover_a"),
        state: NodeIdentityState::Provisioned,
    }
}

fn placement_policy(
    release: &cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt,
    revision: u64,
    scheduling_state: RuntimeSchedulingState,
) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: id("node_cutover_a"),
        policy_revision: Epoch::new(revision).unwrap(),
        scheduling_state,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: guest_config_digest(release).unwrap(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://node-cutover.internal:7301")
            .unwrap(),
    }
}

fn provision_apply(context: &Context) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        node_id: id("node_cutover_a"),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(node_identity(&context.node_signer)),
            placement_policy: Box::new(placement_policy(
                &context.release,
                1,
                RuntimeSchedulingState::Cordoned,
            )),
        },
    }
}

fn schedulable_apply(context: &Context) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        node_id: id("node_cutover_a"),
        mutation: RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision: Epoch::new(1).unwrap(),
            placement_policy: Box::new(placement_policy(
                &context.release,
                2,
                RuntimeSchedulingState::Schedulable,
            )),
        },
    }
}

fn session_binding(session: &cats_api::runtime_reconciliation::AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn full_observation(
    session: &cats_api::runtime_reconciliation::AgentSession,
    read_position: Sequence,
) -> NodeObservation {
    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: random("44444444444444444444444444444444"),
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
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

async fn json_body(response: Response, expected_status: StatusCode) -> Vec<u8> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response.headers()[reqwest::header::CONTENT_TYPE],
        JSON_CONTENT_TYPE
    );
    assert_eq!(
        response.headers()[reqwest::header::CACHE_CONTROL],
        "no-store"
    );
    response.bytes().await.unwrap().to_vec()
}

async fn send_through_replica_barrier(
    first: RequestBuilder,
    second: RequestBuilder,
) -> (Response, Response) {
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first_barrier = barrier.clone();
    let first = async move {
        first_barrier.wait().await;
        first.send().await.unwrap()
    };
    let second = async move {
        barrier.wait().await;
        second.send().await.unwrap()
    };
    tokio::join!(first, second)
}

async fn assert_exact_operation_response(response: Response, expected: &Operation) {
    let body = json_body(response, StatusCode::OK).await;
    assert_eq!(body, encode_operation(expected).unwrap());
    assert_eq!(decode_operation(&body).unwrap(), *expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_replicas_share_registration_observation_and_cat_create_authority() {
    let context = Context::new().await;

    let provision = provision_apply(&context);
    let provision_body = encode_runtime_node_authority_apply(&provision).unwrap();
    let first = context
        .node_authority_request(&context.first, provision_body.clone())
        .send()
        .await
        .unwrap();
    let first_body = json_body(first, StatusCode::OK).await;
    let result = decode_runtime_node_authority_apply_result(&first_body).unwrap();
    assert_eq!(result.apply_id, provision.apply_id);
    assert_eq!(result.outcome, RuntimeNodeAuthorityOutcome::Provisioned);
    let replay = context
        .node_authority_request(&context.second, provision_body)
        .send()
        .await
        .unwrap();
    assert_eq!(json_body(replay, StatusCode::OK).await, first_body);

    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: id("node_cutover_a"),
        immutable_host_id: id("host_cutover_a"),
        node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
        agent_instance_id: random("22222222222222222222222222222222"),
        registration_attempt_id: random("33333333333333333333333333333333"),
        guest_config_digest: guest_config_digest(&context.release).unwrap(),
        expected_agent_session_epoch: None,
    };
    let registration_body = encode_agent_registration_attempt(&attempt).unwrap();
    let registered = context
        .registration_request(&context.first, registration_body.clone())
        .send()
        .await
        .unwrap();
    let registered_body = json_body(registered, StatusCode::OK).await;
    let session = decode_agent_session(&registered_body).unwrap();
    assert_eq!(session.node_id, attempt.node_id);
    assert_eq!(
        session.registration_attempt_id,
        attempt.registration_attempt_id
    );
    let replay = context
        .registration_request(&context.second, registration_body)
        .send()
        .await
        .unwrap();
    assert_eq!(json_body(replay, StatusCode::OK).await, registered_body);

    let desired_one = DesiredReadRequest {
        version: ContractVersion::V1,
        session: session_binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let desired_one_body = encode_desired_read_request(&desired_one).unwrap();
    let desired = context
        .node_request(&context.second, DESIRED_READ_PATH, desired_one_body.clone())
        .send()
        .await
        .unwrap();
    let desired_body = json_body(desired, StatusCode::OK).await;
    let empty_snapshot = decode_desired_read_snapshot(&desired_body).unwrap();
    assert!(empty_snapshot.desired_specs.is_empty());
    let replay = context
        .node_request(&context.first, DESIRED_READ_PATH, desired_one_body)
        .send()
        .await
        .unwrap();
    assert_eq!(json_body(replay, StatusCode::OK).await, desired_body);

    // Make a strict current-vs-immutable lease assertion deterministic even
    // on a PostgreSQL clock whose visible precision is one millisecond.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let observation = full_observation(&session, empty_snapshot.read_position);
    let observation_body = encode_node_observation(&observation).unwrap();
    let (first_observation, second_observation) = send_through_replica_barrier(
        context.node_request(&context.first, OBSERVATION_PATH, observation_body.clone()),
        context.node_request(&context.second, OBSERVATION_PATH, observation_body),
    )
    .await;
    let first_observation_body = json_body(first_observation, StatusCode::OK).await;
    let second_observation_body = json_body(second_observation, StatusCode::OK).await;
    assert_eq!(second_observation_body, first_observation_body);
    let acceptance = decode_observation_acceptance(&first_observation_body).unwrap();
    assert_eq!(acceptance.observation_id, observation.observation_id);
    assert!(acceptance.lease_deadline_unix_ms > session.lease_deadline_unix_ms);

    let schedulable = schedulable_apply(&context);
    let schedulable_body = encode_runtime_node_authority_apply(&schedulable).unwrap();
    let updated = context
        .node_authority_request(&context.second, schedulable_body.clone())
        .send()
        .await
        .unwrap();
    let updated_body = json_body(updated, StatusCode::OK).await;
    let result = decode_runtime_node_authority_apply_result(&updated_body).unwrap();
    assert_eq!(result.apply_id, schedulable.apply_id);
    assert_eq!(result.outcome, RuntimeNodeAuthorityOutcome::PolicyUpdated);
    let replay = context
        .node_authority_request(&context.first, schedulable_body)
        .send()
        .await
        .unwrap();
    assert_eq!(json_body(replay, StatusCode::OK).await, updated_body);

    let workspaces = context
        .http
        .get(format!("{}/v1/admin/workspaces", context.first.base_url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(workspaces.status(), StatusCode::OK);
    assert_eq!(
        workspaces.headers()[reqwest::header::CONTENT_TYPE],
        JSON_CONTENT_TYPE
    );
    let workspaces: ListResponse<cats_api::auth::Workspace> =
        serde_json::from_slice(&workspaces.bytes().await.unwrap()).unwrap();
    let workspace = workspaces
        .items
        .into_iter()
        .find(|workspace| workspace.is_default)
        .expect("bootstrap account has one default Workspace");
    let workspace_id = workspace.id;
    let account_id = workspace.account_id;
    let idempotency_key = "two-replica-cat-create";
    let (first_create, second_create) = send_through_replica_barrier(
        context.cat_create_request(&context.first, &workspace_id, idempotency_key),
        context.cat_create_request(&context.second, &workspace_id, idempotency_key),
    )
    .await;
    let first_create_body = json_body(first_create, StatusCode::ACCEPTED).await;
    let second_create_body = json_body(second_create, StatusCode::ACCEPTED).await;
    assert_eq!(second_create_body, first_create_body);
    let created = decode_cat_create_v2_accepted_response(&first_create_body).unwrap();
    let reads_after_commit = context.image_blob.reads.load(Ordering::SeqCst);
    assert!((1..=2).contains(&reads_after_commit));

    let replay = context
        .cat_create_request(&context.second, &workspace_id, idempotency_key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        json_body(replay, StatusCode::ACCEPTED).await,
        first_create_body
    );
    assert_eq!(
        context.image_blob.reads.load(Ordering::SeqCst),
        reads_after_commit,
        "settled replay must not re-read the immutable manifest"
    );

    let disk_key = "two-replica-persistent-disk-create";
    let (first_disk, second_disk) = send_through_replica_barrier(
        context.persistent_disk_create_request(&context.first, &workspace_id, disk_key),
        context.persistent_disk_create_request(&context.second, &workspace_id, disk_key),
    )
    .await;
    let first_disk_body = json_body(first_disk, StatusCode::CREATED).await;
    let second_disk_body = json_body(second_disk, StatusCode::CREATED).await;
    assert_eq!(second_disk_body, first_disk_body);
    let disk: Disk = serde_json::from_slice(&first_disk_body).unwrap();
    assert_eq!(disk.workspace_id, workspace_id);
    assert_eq!(disk.name, "data");
    assert_eq!(disk.size_bytes, 1_073_741_824);
    assert_eq!(disk.kind, cats_api::resources::DiskKind::Persistent);
    assert_eq!(disk.state, cats_api::resources::DiskState::Available);
    assert_eq!(
        context.image_blob.reads.load(Ordering::SeqCst),
        reads_after_commit,
        "PersistentDisk create must not read the Root image manifest"
    );
    let disk_replay = context
        .persistent_disk_create_request(&context.first, &workspace_id, disk_key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        json_body(disk_replay, StatusCode::CREATED).await,
        first_disk_body
    );
    let disk_name_conflict = context
        .persistent_disk_create_request(&context.second, &workspace_id, "disk-name-conflict")
        .send()
        .await
        .unwrap();
    assert_eq!(
        json_body(disk_name_conflict, StatusCode::CONFLICT).await,
        br#"{"code":"already_exists","message":"disk name already exists"}"#
    );

    let desired_two = DesiredReadRequest {
        version: ContractVersion::V1,
        session: session_binding(&session),
        request_sequence: Sequence::new(2).unwrap(),
    };
    let desired_two_body = encode_desired_read_request(&desired_two).unwrap();
    let desired = context
        .node_request(&context.first, DESIRED_READ_PATH, desired_two_body.clone())
        .send()
        .await
        .unwrap();
    let desired_body = json_body(desired, StatusCode::OK).await;
    let snapshot = decode_desired_read_snapshot(&desired_body).unwrap();
    assert_eq!(snapshot.desired_specs.len(), 1);
    let desired = &snapshot.desired_specs[0];
    assert_eq!(desired.cat_id, created.cat_id);
    assert_eq!(desired.workspace_id.as_str(), workspace_id);
    assert_eq!(desired.placement.node_id, session.node_id);
    assert_eq!(desired.runtime.boot_image_digest.as_str(), IMAGE_DIGEST);
    assert_eq!(desired.volumes.len(), 1);
    assert_eq!(desired.volumes[0].durability, Durability::Strict);
    let replay = context
        .node_request(&context.second, DESIRED_READ_PATH, desired_two_body)
        .send()
        .await
        .unwrap();
    assert_eq!(json_body(replay, StatusCode::OK).await, desired_body);

    // Public Operation observation is workspace-qualified and reads the exact
    // canonical runtime_operations record written by Cat-create.
    let operation_path = format!(
        "{}/v1/workspaces/{workspace_id}/operations/{}",
        context.first.base_url(),
        created.operation_id
    );
    let unauthenticated = context.http.get(&operation_path).send().await.unwrap();
    assert_eq!(
        json_body(unauthenticated, StatusCode::UNAUTHORIZED).await,
        br#"{"code":"unauthenticated","message":"missing or invalid authentication credential"}"#
    );

    let missing = context
        .operation_request(&context.first, &workspace_id, "op_missing")
        .send()
        .await
        .unwrap();
    let missing_body = json_body(missing, StatusCode::NOT_FOUND).await;
    assert_eq!(
        missing_body,
        br#"{"code":"not_found","message":"operation not found"}"#
    );

    let sibling_workspace = context
        .first
        .state
        .store
        .execute(move |store| store.create_workspace(&account_id, "sibling", "Sibling"))
        .await
        .unwrap();
    let wrong_workspace = context
        .operation_request(
            &context.second,
            &sibling_workspace.id,
            created.operation_id.as_str(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        json_body(wrong_workspace, StatusCode::NOT_FOUND).await,
        missing_body
    );

    let pending_response = context
        .operation_request(
            &context.second,
            &workspace_id,
            created.operation_id.as_str(),
        )
        .send()
        .await
        .unwrap();
    let pending_body = json_body(pending_response, StatusCode::OK).await;
    let pending = decode_operation(&pending_body).unwrap();
    assert_eq!(pending.operation_id, created.operation_id);
    assert_eq!(pending.workspace_id.as_str(), workspace_id);
    assert_eq!(pending.phase, OperationPhase::Pending);
    assert_eq!(pending_body, encode_operation(&pending).unwrap());

    let completed_at = UnixMillis::new(pending.updated_at_unix_ms.get() + 1).unwrap();
    let mut succeeded = pending.clone();
    succeeded.phase = OperationPhase::Succeeded;
    succeeded.updated_at_unix_ms = completed_at;
    succeeded.terminal = Some(OperationTerminal::Succeeded {
        result: OperationSuccess {
            observation_id: random("55555555555555555555555555555555"),
            node_id: succeeded.placement.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(2).unwrap(),
            observed_target: succeeded.target,
            runtime_incarnation: Some(random("66666666666666666666666666666666")),
        },
        completed_at_unix_ms: completed_at,
    });

    let mut failed = pending.clone();
    failed.phase = OperationPhase::Failed;
    failed.updated_at_unix_ms = completed_at;
    failed.terminal = Some(OperationTerminal::Failed {
        error: Box::new(OperationFailure::HostLost {
            node_id: failed.placement.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            host_fence_event_id: id("fence_operation_read"),
        }),
        completed_at_unix_ms: completed_at,
    });

    let mut superseded = pending.clone();
    superseded.phase = OperationPhase::Superseded;
    superseded.updated_at_unix_ms = completed_at;
    superseded.terminal = Some(OperationTerminal::Superseded {
        superseded_by_revision: Revision::new(pending.desired_revision.get() + 1).unwrap(),
        superseded_by_operation_id: id("op_replacement"),
        completed_at_unix_ms: completed_at,
    });

    for (index, terminal) in [succeeded, failed, superseded].into_iter().enumerate() {
        cats_control_plane::testsupport::settle_runtime_operation_for_test(
            &context.first.state.store,
            terminal.clone(),
        )
        .await;
        let server = if index % 2 == 0 {
            &context.first
        } else {
            &context.second
        };
        let response = context
            .operation_request(server, &workspace_id, terminal.operation_id.as_str())
            .send()
            .await
            .unwrap();
        assert_exact_operation_response(response, &terminal).await;
    }

    let facts = cats_control_plane::testsupport::runtime_cutover_acceptance_facts(
        &context.first.state.store,
        session.node_id.clone(),
    )
    .await;
    assert_eq!(
        facts,
        RuntimeCutoverAcceptanceFacts {
            node_identity_count: 1,
            node_credential_lineage_count: 1,
            node_policy_count: 1,
            node_authority_apply_count: 2,
            registration_attempt_count: 1,
            current_session_count: 1,
            desired_read_state_count: 1,
            observation_receive_state_count: 1,
            admission_inventory_state_count: 1,
            current_cat_observation_count: 0,
            cat_record_count: 1,
            disk_record_count: 2,
            volume_record_count: 2,
            desired_spec_count: 1,
            endpoint_record_count: 1,
            hostname_lookup_count: 1,
            runtime_operation_count: 1,
            api_result_count: 3,
            retired_node_count: 0,
            retired_cat_count: 0,
            registration_attempt_lease_deadline_unix_ms: Some(
                i64::try_from(session.lease_deadline_unix_ms.get()).unwrap(),
            ),
            current_session_lease_deadline_unix_ms: Some(
                i64::try_from(acceptance.lease_deadline_unix_ms.get()).unwrap(),
            ),
            desired_read_last_request_sequence: Some(2),
            stored_api_response_body: Some(first_create_body),
            stored_persistent_disk_response_body: Some(first_disk_body),
        }
    );

    cats_control_plane::testsupport::corrupt_runtime_operation_projection_for_test(
        &context.first.state.store,
        created.operation_id.clone(),
    )
    .await;
    let corrupt = context
        .operation_request(&context.first, &workspace_id, created.operation_id.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(corrupt.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        context
            .http
            .get(format!("{}/healthz", context.first.base_url()))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    context.first.shutdown().await.unwrap();
    context.second.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_disk_exact_replay_precedes_mutable_funding_admission() {
    let context = Context::new().await;
    let mut billed_config = context.config.clone();
    billed_config.billing_enforcement_enabled = true;
    let billed = spawn_runtime_authority_with_billing_for_tests(billed_config)
        .await
        .unwrap();
    let workspaces = context
        .http
        .get(format!("{}/v1/admin/workspaces", billed.base_url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(workspaces.status(), StatusCode::OK);
    let workspaces: ListResponse<cats_api::auth::Workspace> =
        serde_json::from_slice(&workspaces.bytes().await.unwrap()).unwrap();
    let workspace_id = workspaces
        .items
        .into_iter()
        .find(|workspace| workspace.is_default)
        .expect("bootstrap account has one default Workspace")
        .id;

    let key = "funding-change-replay";
    let first = context
        .persistent_disk_create_request(&billed, &workspace_id, key)
        .send()
        .await
        .unwrap();
    let first_body = json_body(first, StatusCode::CREATED).await;
    context.credits.set_funded(false);

    let replay = context
        .persistent_disk_create_request(&billed, &workspace_id, key)
        .send()
        .await
        .unwrap();
    assert_eq!(json_body(replay, StatusCode::CREATED).await, first_body);
    let fresh = context
        .persistent_disk_create_request(&billed, &workspace_id, "unfunded-fresh-key")
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), StatusCode::PAYMENT_REQUIRED);

    let facts = cats_control_plane::testsupport::runtime_cutover_acceptance_facts(
        &billed.state.store,
        id("node_no_runtime_rows"),
    )
    .await;
    assert_eq!(
        (
            facts.volume_record_count,
            facts.disk_record_count,
            facts.api_result_count,
        ),
        (1, 1, 1)
    );

    billed.shutdown().await.unwrap();
    context.first.shutdown().await.unwrap();
    context.second.shutdown().await.unwrap();
}

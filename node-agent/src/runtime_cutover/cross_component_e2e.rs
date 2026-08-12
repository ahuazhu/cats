//! PostgreSQL-backed acceptance across the production Control composition and
//! the signed Node Runtime spine. The effect deliberately stops at the exact
//! recording `RefreshInventory` seam; it is not a physical Guest/VMM test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
use cats_api::cat_create::decode_cat_create_v2_accepted_response;
use cats_api::requests::ListResponse;
use cats_api::runtime_node_authority::{
    runtime_node_authority_signed_request, PROVISIONER_CREDENTIAL_ID_HEADER,
    PROVISIONER_SIGNATURE_HEADER, RUNTIME_NODE_AUTHORITY_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_runtime_node_authority_apply_result, encode_runtime_node_authority_apply,
    guest_config_digest, AllocatableMemoryBytes, AllocatableVcpus, AppliedDesiredEvidence,
    CheckpointEvidence, Condition, ContractVersion, CredentialBinding, DesiredReadSnapshot,
    DesiredRuntimeSpec, Epoch, GuestIpv4Pool, GuestIpv4PoolKind, GuestTransportEvidence, HostPath,
    Id, InventorySource, Ipv4Address, LifecycleAdmission, NodeBootId, NodeIdentity,
    NodeIdentityState, NodePlacementPolicy, NodeTransportTarget, ObservedRuntimeStatus,
    ProgressingReason, RandomId128, ReconcileStep, RuntimeNodeAuthorityApply,
    RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome, RuntimePlacementBlockFrontend,
    RuntimePlacementCapabilities, RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport,
    RuntimePlacementVmm, RuntimeSchedulingState, Sequence, Sha256Digest, UnixMillis,
    WarmSnapshotEvidence,
};
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::SqliteUsageStore;
use cats_storage::{
    encode_image_manifest, image_manifest_key, BlobError, BlobStore, ImageManifestV1,
    LowerHexSha256, MetadataStore, IMAGE_MANIFEST_MAX_BYTES,
};
use reqwest::{Response, StatusCode};
use ring::signature::Ed25519KeyPair;

use crate::agent_registration::AgentRegistrationConfig;
use crate::runtime_spine::{
    CompleteRuntimeInventory, InventoryCoverageAggregator, RuntimeDesiredEffect,
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeInventoryKeyRing,
    RuntimeInventoryScanContext, RuntimeInventoryScanOutcome, RuntimeInventoryScanner,
    RuntimeSpineDeadlinePolicy, RuntimeSpineHttpClient, RuntimeSpineRunStep, RuntimeSpineRunner,
};

const DEPLOYMENT_ID: &str = "deployment_a";
const PROVISIONER_ID: &str = "provisioner_a";
const SERVICE_TOKEN: &str = "runtime-cross-component-service-token";
const ADMIN_TOKEN: &str = "runtime-cross-component-admin-token";
const IMAGE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const IMAGE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CAT_CREATE_BODY: &[u8] = br#"{"name":"runtime-spine-app","boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vcpus":2,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"strict"}"#;
const RFC8032_TEST_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

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
        Err(read_only_blob_error(key))
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
            return Err(read_only_blob_error(key));
        }
        self.read(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        Ok(key == self.key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        Err(read_only_blob_error(key))
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

fn read_only_blob_error(key: &str) -> BlobError {
    BlobError::Backend {
        key: key.to_owned(),
        message: "read-only cross-component image store".into(),
    }
}

struct ControlContext {
    _directory: tempfile::TempDir,
    server: Handle,
    control_store_url: String,
    http: reqwest::Client,
    release: cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt,
    image_blob: Arc<FixedImageBlob>,
}

impl ControlContext {
    async fn spawn() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let control_store_url = cats_control_plane::testsupport::isolated_control_store_url();
        let usage = Arc::new(SqliteUsageStore::open(&directory.path().join("usage.db")).unwrap());
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&directory.path().join("storage.db")).unwrap());
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
        let server = spawn(Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: DsnSource::Literal(control_store_url.clone()),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
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
            node_lease_timeout_ms: 120_000,
            reconcile_interval_ms: 60_000,
            auto_tier_policy: AutoTierPolicy::default(),
            oci_deploy_sync_wait_ms: 5_000,
        })
        .await
        .unwrap();
        Self {
            _directory: directory,
            server,
            control_store_url,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            release,
            image_blob,
        }
    }
}

#[derive(Debug, Clone)]
struct ScanRecord {
    desired: DesiredReadSnapshot,
    inventory_epoch: Epoch,
}

#[derive(Default)]
struct CompleteAssignedScanner {
    records: Mutex<Vec<ScanRecord>>,
}

impl crate::runtime_spine::inventory_scanner_sealed::Sealed for CompleteAssignedScanner {}

impl RuntimeInventoryScanner for CompleteAssignedScanner {
    fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
        context.check_active()?;
        let coordinates = context.coordinates().clone();
        self.records.lock().unwrap().push(ScanRecord {
            desired: coordinates.desired.clone(),
            inventory_epoch: coordinates.inventory_epoch,
        });

        let mut coverage = InventoryCoverageAggregator::new();
        for source in [
            InventorySource::Checkpoint,
            InventorySource::Systemd,
            InventorySource::Process,
            InventorySource::ControlSocket,
            InventorySource::BlockFrontend,
            InventorySource::Network,
            InventorySource::DataDirectory,
            InventorySource::PendingPack,
            InventorySource::WarmSnapshot,
            InventorySource::MetadataStore,
            InventorySource::GuestMount,
        ] {
            coverage.record(source)?;
        }
        let runtimes = coordinates
            .desired
            .desired_specs
            .iter()
            .map(|desired| observed_missing_runtime(desired, coordinates.inventory_epoch))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(RuntimeInventoryScanOutcome::Complete(
            CompleteRuntimeInventory::from_validated_coverage(
                coverage.finish()?,
                UnixMillis::new(1_900_000_006_000).unwrap(),
                RuntimeInventoryKeyRing::Unavailable,
                runtimes,
                Vec::new(),
            ),
        ))
    }
}

fn observed_missing_runtime(
    desired: &DesiredRuntimeSpec,
    inventory_epoch: Epoch,
) -> anyhow::Result<ObservedRuntimeStatus> {
    let step = ReconcileStep::InspectInventory { inventory_epoch };
    Ok(ObservedRuntimeStatus {
        cat_id: desired.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        }),
        runtime_incarnation: None,
        stable_state: None,
        step: step.clone(),
        checkpoint: CheckpointEvidence::Missing {
            checkpoint_path: HostPath::new(format!(
                "/var/lib/cats/cross-component/{}.json",
                desired.cat_id
            ))
            .context("cross-component checkpoint path is invalid")?,
        },
        processes: Vec::new(),
        volumes: Vec::new(),
        mounts: Vec::new(),
        networks: Vec::new(),
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission: LifecycleAdmission::Closed,
        routes: Vec::new(),
        platform_guards: 0,
        conditions: vec![Condition::Progressing {
            reason: ProgressingReason::ReconcileStep { step },
        }],
    })
}

#[derive(Debug, Clone)]
struct EffectRecord {
    desired: DesiredRuntimeSpec,
    observation_id: RandomId128,
    inventory_epoch: Epoch,
    inventory_read_position: Sequence,
    desired_read_position: Sequence,
}

#[derive(Default)]
struct RecordingRefreshEffect {
    records: Mutex<Vec<EffectRecord>>,
}

impl RuntimeDesiredEffect for RecordingRefreshEffect {
    fn apply(
        &self,
        context: RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        context.check_active()?;
        let admission = context.accepted_full()?;
        let observed = admission
            .observation()
            .runtimes
            .iter()
            .find(|runtime| runtime.cat_id == desired.cat_id)
            .context("recorded effect lacks the assigned Cat in its accepted full inventory")?;
        anyhow::ensure!(
            observed.applied_desired.as_ref()
                == Some(&AppliedDesiredEvidence {
                    desired_revision: desired.desired_revision,
                    spec_digest: desired.spec_digest.clone(),
                    placement: desired.placement.clone(),
                    target: desired.target,
                }),
            "recorded effect was not bound to the exact accepted Desired"
        );
        self.records.lock().unwrap().push(EffectRecord {
            desired: desired.clone(),
            observation_id: admission.observation().observation_id.clone(),
            inventory_epoch: admission.attestation().inventory_epoch,
            inventory_read_position: admission.attestation().inventory_read_position,
            desired_read_position: admission
                .desired_read_position()
                .context("recorded effect lacks its fresh Desired cursor")?,
        });
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
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
        node_id: id("node_cross_component_a"),
        immutable_host_id: id("host_cross_component_a"),
        credential_id: signer.credential_id().clone(),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: signer.public_key_spki_sha256(),
        },
        state_path_id: id("state_cross_component_a"),
        state: NodeIdentityState::Provisioned,
    }
}

fn placement_policy(
    release: &cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt,
    policy_revision: u64,
    scheduling_state: RuntimeSchedulingState,
) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: id("node_cross_component_a"),
        policy_revision: Epoch::new(policy_revision).unwrap(),
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
            network_address: Ipv4Address::new("10.241.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new(
            "https://node-cross-component.internal:7301",
        )
        .unwrap(),
    }
}

async fn apply_node_authority(
    context: &ControlContext,
    signer: &Ed25519KeyPair,
    apply: &RuntimeNodeAuthorityApply,
) -> RuntimeNodeAuthorityOutcome {
    let body = encode_runtime_node_authority_apply(apply).unwrap();
    let signed = runtime_node_authority_signed_request(DEPLOYMENT_ID, PROVISIONER_ID, &body);
    let signature = URL_SAFE_NO_PAD.encode(signer.sign(&signed).as_ref());
    let response = context
        .http
        .post(format!(
            "{}{RUNTIME_NODE_AUTHORITY_PATH}",
            context.server.base_url()
        ))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header(PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_ID)
        .header(PROVISIONER_SIGNATURE_HEADER, signature)
        .body(body)
        .send()
        .await
        .unwrap();
    let body = json_body(response, StatusCode::OK).await;
    decode_runtime_node_authority_apply_result(&body)
        .unwrap()
        .outcome
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

async fn next_step(runner: &mut RuntimeSpineRunner) -> RuntimeSpineRunStep {
    let deadlines =
        RuntimeSpineDeadlinePolicy::new(Duration::from_secs(10), Duration::from_secs(10))
            .unwrap()
            .deadlines_from(Instant::now())
            .unwrap();
    tokio::time::timeout(
        Duration::from_secs(15),
        runner.run_once_with_deadlines(deadlines),
    )
    .await
    .expect("Runtime spine step exceeded its test deadline")
    .unwrap()
}

#[tokio::test]
async fn postgres_runtime_schema_write_barrier_calibrates_retired_route_zero_write() {
    let context = ControlContext::spawn().await;
    let barrier = cats_control_plane::testsupport::RuntimeSchemaWriteBarrierForTest::acquire(
        &context.control_store_url,
    )
    .await;
    barrier.calibrate_dml_blocked().await;

    let response = context
        .http
        .post(format!("{}/v1/nodes/inventory", context.server.base_url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    barrier.finish_unchanged().await;
    context.server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_control_and_restarted_node_runner_reach_one_recorded_cat_effect() {
    let context = ControlContext::spawn().await;
    let provisioner = Ed25519KeyPair::from_seed_unchecked(&RFC8032_TEST_SEED).unwrap();
    let node_signer = Ed25519RequestSigner::from_pkcs8_pem(
        id("credential_cross_component_a"),
        include_bytes!("../../../tests/fixtures/route_grant_private_ed25519.pem"),
    )
    .unwrap();
    let identity = node_identity(&node_signer);
    let state_parent = tempfile::tempdir().unwrap();
    let registration = AgentRegistrationConfig::for_loopback_test(
        identity.clone(),
        node_signer,
        state_parent.path().join("node-state"),
        NodeBootId::new("11111111111111111111111111111111").unwrap(),
        &context.release,
    )
    .unwrap();

    let provision = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        node_id: identity.node_id.clone(),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(identity.clone()),
            placement_policy: Box::new(placement_policy(
                &context.release,
                1,
                RuntimeSchedulingState::Cordoned,
            )),
        },
    };
    assert_eq!(
        apply_node_authority(&context, &provisioner, &provision).await,
        RuntimeNodeAuthorityOutcome::Provisioned
    );

    let session = tokio::time::timeout(
        Duration::from_secs(10),
        registration.register_until_session(&context.server.base_url()),
    )
    .await
    .expect("A19 registration did not complete")
    .unwrap();
    assert_eq!(session.node_id, identity.node_id);

    let scanner = Arc::new(CompleteAssignedScanner::default());
    let effect = Arc::new(RecordingRefreshEffect::default());
    let client = RuntimeSpineHttpClient::for_loopback_test(
        &context.server.base_url(),
        registration.runtime_request_signer(),
    )
    .unwrap();
    let mut runner = RuntimeSpineRunner::new_with_desired_effects(
        registration.runtime_state_directory(),
        session.clone(),
        client.clone(),
        scanner.clone(),
        effect.clone(),
    )
    .unwrap();

    assert!(matches!(
        next_step(&mut runner).await,
        RuntimeSpineRunStep::DesiredAccepted
    ));
    assert!(matches!(
        next_step(&mut runner).await,
        RuntimeSpineRunStep::ObservationAccepted {
            service_ready: false
        }
    ));
    {
        let scans = scanner.records.lock().unwrap();
        assert_eq!(scans.len(), 1);
        assert!(scans[0].desired.desired_specs.is_empty());
        assert_eq!(scans[0].inventory_epoch, Epoch::new(1).unwrap());
    }
    assert!(effect.records.lock().unwrap().is_empty());

    let uncordon = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        node_id: identity.node_id.clone(),
        mutation: RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision: Epoch::new(1).unwrap(),
            placement_policy: Box::new(placement_policy(
                &context.release,
                2,
                RuntimeSchedulingState::Schedulable,
            )),
        },
    };
    assert_eq!(
        apply_node_authority(&context, &provisioner, &uncordon).await,
        RuntimeNodeAuthorityOutcome::PolicyUpdated
    );

    let workspaces = context
        .http
        .get(format!("{}/v1/admin/workspaces", context.server.base_url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(workspaces.status(), StatusCode::OK);
    let workspaces: ListResponse<cats_api::auth::Workspace> =
        serde_json::from_slice(&workspaces.bytes().await.unwrap()).unwrap();
    let workspace = workspaces
        .items
        .into_iter()
        .find(|workspace| workspace.is_default)
        .expect("bootstrap account has one default Workspace");
    let create = context
        .http
        .post(format!(
            "{}/v1/workspaces/{}/cats",
            context.server.base_url(),
            workspace.id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header("Idempotency-Key", "runtime-spine-cross-component-create")
        .body(CAT_CREATE_BODY.to_vec())
        .send()
        .await
        .unwrap();
    let create_body = json_body(create, StatusCode::ACCEPTED).await;
    let created = decode_cat_create_v2_accepted_response(&create_body).unwrap();
    assert_eq!(context.image_blob.reads.load(Ordering::SeqCst), 1);

    // The pre-restart process durably accepts the post-create Desired, but it
    // performs neither the assigned full scan nor an effect.
    assert!(matches!(
        next_step(&mut runner).await,
        RuntimeSpineRunStep::DesiredAccepted
    ));
    assert!(effect.records.lock().unwrap().is_empty());
    runner.shutdown().await.unwrap();

    // A successor cannot inherit process-local admission. Its first step is a
    // fresh complete assigned observation, its second a fresh Desired read,
    // and only its third may dispatch the exact per-Cat effect.
    let mut restarted = RuntimeSpineRunner::new_with_desired_effects(
        registration.runtime_state_directory(),
        session.clone(),
        client,
        scanner.clone(),
        effect.clone(),
    )
    .unwrap();
    assert!(matches!(
        next_step(&mut restarted).await,
        RuntimeSpineRunStep::ObservationAccepted {
            service_ready: true
        }
    ));
    assert!(effect.records.lock().unwrap().is_empty());
    let scanned_desired = {
        let scans = scanner.records.lock().unwrap();
        assert_eq!(scans.len(), 2);
        assert_eq!(scans[1].inventory_epoch, Epoch::new(2).unwrap());
        assert_eq!(scans[1].desired.desired_specs.len(), 1);
        assert_eq!(scans[1].desired.desired_specs[0].cat_id, created.cat_id);
        scans[1].desired.desired_specs[0].clone()
    };
    assert!(matches!(
        next_step(&mut restarted).await,
        RuntimeSpineRunStep::DesiredAccepted
    ));
    assert!(effect.records.lock().unwrap().is_empty());
    assert!(matches!(
        next_step(&mut restarted).await,
        RuntimeSpineRunStep::EffectRefreshInventory { cat_id }
            if cat_id == created.cat_id
    ));
    let effects = effect.records.lock().unwrap().clone();
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].desired, scanned_desired);
    assert_eq!(effects[0].desired.cat_id, created.cat_id);
    assert_eq!(effects[0].inventory_epoch, Epoch::new(2).unwrap());
    assert!(effects[0].desired_read_position >= effects[0].inventory_read_position);
    assert!(!effects[0].observation_id.as_str().is_empty());

    for path in [
        "/v1/nodes/register",
        "/v1/nodes/heartbeat",
        "/v1/nodes/work-status",
        "/v1/internal/work/acquire",
        "/v1/internal/work/release",
    ] {
        for token in [SERVICE_TOKEN, ADMIN_TOKEN] {
            let response = context
                .http
                .post(format!("{}{path}", context.server.base_url()))
                .bearer_auth(token)
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    let facts = cats_control_plane::testsupport::runtime_cutover_acceptance_facts(
        &context.server.state.store,
        identity.node_id,
    )
    .await;
    assert_eq!(facts.node_identity_count, 1);
    assert_eq!(facts.node_authority_apply_count, 2);
    assert_eq!(facts.registration_attempt_count, 1);
    assert_eq!(facts.current_session_count, 1);
    assert_eq!(facts.desired_read_state_count, 1);
    assert_eq!(facts.observation_receive_state_count, 1);
    assert_eq!(facts.admission_inventory_state_count, 1);
    assert_eq!(facts.current_cat_observation_count, 1);
    assert_eq!(facts.cat_record_count, 1);
    assert_eq!(facts.desired_spec_count, 1);
    assert_eq!(facts.runtime_operation_count, 1);
    assert_eq!(facts.api_result_count, 1);
    assert_eq!(facts.desired_read_last_request_sequence, Some(3));
    assert_eq!(facts.stored_api_response_body, Some(create_body));

    restarted.shutdown().await.unwrap();
    context.server.shutdown().await.unwrap();
}

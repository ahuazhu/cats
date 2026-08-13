//! PostgreSQL-backed acceptance across the production Control composition and
//! the signed Node Runtime spine. The portable case stops at a recording
//! `RefreshInventory` seam; the Linux case uses the installed scanner and
//! production signed effect through the durable `ProvisionRootImage`
//! checkpoint. Neither case launches a Guest or VMM.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
use cats_api::cat_create::decode_cat_create_v2_accepted_response;
#[cfg(target_os = "linux")]
use cats_api::cat_create::CatCreateV2Request;
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
use cats_metering::SqliteUsageStore;
use cats_storage::{
    encode_image_manifest, image_manifest_key, BlobError, BlobStore, ImageManifestV1,
    LowerHexSha256, IMAGE_MANIFEST_MAX_BYTES,
};
use reqwest::{Response, StatusCode};
use ring::signature::Ed25519KeyPair;

#[cfg(target_os = "linux")]
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, decode_agent_session, decode_runtime_checkpoint, spec_digest,
    AcquireOrigin, AdmissionInventoryAttestation, AgentSession, AsciiText, AssignedKind,
    ControlHandshakeEvidence, DiskKind, Durability, Generation, HttpProtocol, IsolatedIpv4Kind,
    LastVolumeTransition, LocalLineageState, NodeObservation, ObservationAcceptance,
    ObservedDiskKind, OwnershipTokenEvidence, ProcessRole, ProcessState, RemoteHead,
    RuntimeCheckpoint, RuntimeTarget, RuntimeTransition, SessionBinding, VolumeAccess,
    VolumeAcquire, VolumeAuthorityEvidence, VolumeDisposition,
};
#[cfg(target_os = "linux")]
use cats_metadata_store_postgres::PostgresVolumeDataAuthority;
#[cfg(target_os = "linux")]
use cats_storage::authority::{RuntimeVolumeInventoryAuthority, VolumeDataAuthority};
#[cfg(target_os = "linux")]
use cats_storage::{decode_image_manifest, AdapterConfig, AdapterSelection};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
#[cfg(target_os = "linux")]
use std::process::Command;

use crate::agent_registration::AgentRegistrationConfig;
#[cfg(target_os = "linux")]
use crate::ch::{BlockPath, ChConfig};
#[cfg(target_os = "linux")]
use crate::runtime::reconciliation::{
    current_kernel_node_boot_id, installed_clean_slate_scanner,
    installed_root_process_effect_ports, runtime_checkpoint_path, AdmissionCellRegistry,
    AuthorizedBlockdLaunchConfig, BlockdSocketIntentStore, InstalledCleanSlateProbeConfig,
    ManagedBlockdSocketOwnerRetirement, NodeGlobalManagedProcessAdmission,
    PlatformSystemdRootProvisionProcessPort, RetainedManagedBlockdSocketRoot,
    RetainedManagedVmmLaunchRoot, RetainedManagedVmmSocketRoot, RootProvisionProcessPort,
    RootProvisionProcessStop, RootProvisionSystemdConfig, VmmSocketReceiptStore,
    BLOCKD_SOCKET_INTENT_NAMESPACE, INSTALLED_VMM_SOCKET_ROOT, VMM_LAUNCH_FILE_NAMESPACE,
};
#[cfg(target_os = "linux")]
use crate::runtime_spine::RuntimeSpineFullScan;
use crate::runtime_spine::{
    CompleteRuntimeInventory, InventoryCoverageAggregator, RuntimeDesiredEffect,
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeInventoryKeyRing,
    RuntimeInventoryScanContext, RuntimeInventoryScanOutcome, RuntimeInventoryScanner,
    RuntimeSpineDeadlinePolicy, RuntimeSpineHttpClient, RuntimeSpineRunStep, RuntimeSpineRunner,
};
#[cfg(target_os = "linux")]
use crate::state_directory::StateDirectory;

const DEPLOYMENT_ID: &str = "deployment_a";
const PROVISIONER_ID: &str = "provisioner_a";
const SERVICE_TOKEN: &str = "runtime-cross-component-service-token";
const ADMIN_TOKEN: &str = "runtime-cross-component-admin-token";
const IMAGE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const IMAGE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
#[cfg(target_os = "linux")]
const PRODUCTION_CHECKPOINT_NAMESPACE: &str = "checkpoints";
#[cfg(target_os = "linux")]
const IMDS_ADDRESS: &str = "169.254.169.254";
#[cfg(target_os = "linux")]
const IMDS_TOKEN: &str = "cats-hermetic-imdsv2-token";
#[cfg(target_os = "linux")]
const IMDS_ROLE: &str = "cats-hermetic-runtime-role";
#[cfg(target_os = "linux")]
const IMDS_CREDENTIAL_PATH: &str =
    "/latest/meta-data/iam/security-credentials/cats-hermetic-runtime-role";
#[cfg(target_os = "linux")]
const AWS_REGION: &str = "us-test-1";
#[cfg(target_os = "linux")]
const AWS_PREFIX: &str = "runtime-cutover-hermetic";
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
            retired_storage_meta_for_tests: None,
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

#[cfg(target_os = "linux")]
fn production_e2e_placement_policy(
    release: &cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt,
    policy_revision: u64,
    scheduling_state: RuntimeSchedulingState,
) -> NodePlacementPolicy {
    let mut policy = placement_policy(release, policy_revision, scheduling_state);
    policy.capabilities.block_frontend = RuntimePlacementBlockFrontend::VhostUserBlk;
    policy
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

#[cfg(target_os = "linux")]
fn production_node_signer() -> Ed25519RequestSigner {
    Ed25519RequestSigner::from_pkcs8_pem(
        id("credential_cross_component_a"),
        include_bytes!("../../../tests/fixtures/route_grant_private_ed25519.pem"),
    )
    .unwrap()
}

#[cfg(target_os = "linux")]
fn provision_installed_runtime_namespaces(state: &StateDirectory) {
    let launch_root = state.path().join(VMM_LAUNCH_FILE_NAMESPACE);
    if !launch_root.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700).create(&launch_root).unwrap();
    }
    RetainedManagedVmmLaunchRoot::open_existing(state.clone()).unwrap();

    if VmmSocketReceiptStore::open_existing(state.clone()).is_err() {
        VmmSocketReceiptStore::provision_for_test(state.clone()).unwrap();
    }

    if state
        .path()
        .join(BLOCKD_SOCKET_INTENT_NAMESPACE)
        .try_exists()
        .unwrap()
    {
        BlockdSocketIntentStore::open_existing(state.clone()).unwrap();
    } else {
        BlockdSocketIntentStore::provision_for_test(state.clone()).unwrap();
    }

    let blockd_root = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed();
    let blockd_path = std::path::Path::new(blockd_root.path().as_str());
    if blockd_path.exists() {
        RetainedManagedBlockdSocketRoot::open_installed().unwrap();
    } else {
        std::fs::create_dir_all(blockd_path.parent().unwrap()).unwrap();
        RetainedManagedBlockdSocketRoot::provision_for_test(blockd_path).unwrap();
    }

    let vmm_path = std::path::Path::new(INSTALLED_VMM_SOCKET_ROOT);
    if vmm_path.exists() {
        RetainedManagedVmmSocketRoot::open_installed().unwrap();
    } else {
        std::fs::create_dir_all(vmm_path.parent().unwrap()).unwrap();
        RetainedManagedVmmSocketRoot::provision_for_test(vmm_path).unwrap();
    }
}

#[cfg(target_os = "linux")]
fn production_registration(
    identity: NodeIdentity,
    state_path: std::path::PathBuf,
    release: &cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt,
) -> AgentRegistrationConfig {
    let registration = AgentRegistrationConfig::for_loopback_test(
        identity,
        production_node_signer(),
        state_path,
        current_kernel_node_boot_id().unwrap(),
        release,
    )
    .unwrap();
    provision_installed_runtime_namespaces(&registration.runtime_state_directory());
    registration
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct HermeticImdsState {
    token_requests: usize,
    role_requests: usize,
    credential_requests: usize,
    violations: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HermeticImdsReply {
    Token,
    Role,
    Credentials,
    Rejected,
}

#[cfg(target_os = "linux")]
fn exact_header(
    headers: &axum::http::HeaderMap,
    name: axum::http::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

#[cfg(target_os = "linux")]
fn exact_imds_host(headers: &axum::http::HeaderMap) -> bool {
    let mut values = headers.get_all(axum::http::header::HOST).iter();
    let exact = values.next().is_some_and(|value| {
        value.as_bytes() == b"169.254.169.254" || value.as_bytes() == b"169.254.169.254:80"
    });
    exact && values.next().is_none()
}

#[cfg(target_os = "linux")]
fn record_imds_request(
    state: &mut HermeticImdsState,
    method: &axum::http::Method,
    path_and_query: &str,
    headers: &axum::http::HeaderMap,
    body_is_empty: bool,
) -> HermeticImdsReply {
    use axum::http::header::HeaderName;

    let token_header = HeaderName::from_static("x-aws-ec2-metadata-token");
    let ttl_header = HeaderName::from_static("x-aws-ec2-metadata-token-ttl-seconds");
    let common_request_is_exact = exact_imds_host(headers) && body_is_empty;
    let reply = if common_request_is_exact
        && method == axum::http::Method::PUT
        && path_and_query == "/latest/api/token"
        && exact_header(headers, ttl_header.clone(), "21600")
        && headers.get(&token_header).is_none()
        && state.token_requests == 0
        && state.role_requests == 0
        && state.credential_requests == 0
    {
        state.token_requests += 1;
        HermeticImdsReply::Token
    } else if common_request_is_exact
        && method == axum::http::Method::GET
        && path_and_query == "/latest/meta-data/iam/security-credentials/"
        && exact_header(headers, token_header.clone(), IMDS_TOKEN)
        && headers.get(&ttl_header).is_none()
        && state.token_requests == 1
        && state.role_requests == 0
        && state.credential_requests == 0
    {
        state.role_requests += 1;
        HermeticImdsReply::Role
    } else if common_request_is_exact
        && method == axum::http::Method::GET
        && path_and_query == IMDS_CREDENTIAL_PATH
        && exact_header(headers, token_header, IMDS_TOKEN)
        && headers.get(&ttl_header).is_none()
        && state.token_requests == 1
        && state.role_requests == 1
        && state.credential_requests == 0
    {
        state.credential_requests += 1;
        HermeticImdsReply::Credentials
    } else {
        state.violations.push(format!(
            "unexpected IMDS request: method={method} target={path_and_query} host={:?} ttl={:?} token={:?} empty_body={body_is_empty}",
            headers.get(axum::http::header::HOST),
            headers.get(&ttl_header),
            headers.get("x-aws-ec2-metadata-token")
        ));
        HermeticImdsReply::Rejected
    };
    reply
}

#[cfg(target_os = "linux")]
async fn hermetic_imds_handler(
    axum::extract::State(state): axum::extract::State<Arc<Mutex<HermeticImdsState>>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let (parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(axum::http::uri::PathAndQuery::as_str)
        .unwrap_or_else(|| parts.uri.path())
        .to_owned();
    let reply = match axum::body::to_bytes(body, 1).await {
        Ok(body) => record_imds_request(
            &mut state.lock().unwrap(),
            &parts.method,
            &path_and_query,
            &parts.headers,
            body.is_empty(),
        ),
        Err(error) => {
            state.lock().unwrap().violations.push(format!(
                "oversized IMDS request body: method={} target={path_and_query}: {error}",
                parts.method
            ));
            HermeticImdsReply::Rejected
        }
    };
    match reply {
        HermeticImdsReply::Token => (StatusCode::OK, IMDS_TOKEN).into_response(),
        HermeticImdsReply::Role => (StatusCode::OK, IMDS_ROLE).into_response(),
        HermeticImdsReply::Credentials => (
            StatusCode::OK,
            [(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
            r#"{"AccessKeyId":"AKIAHERMETICCATS","SecretAccessKey":"hermetic-secret-access-key","Token":"hermetic-session-token"}"#,
        )
            .into_response(),
        HermeticImdsReply::Rejected => (
            StatusCode::BAD_REQUEST,
            "strict hermetic IMDSv2 request rejected",
        )
            .into_response(),
    }
}

#[cfg(target_os = "linux")]
async fn hermetic_s3_handler(
    axum::extract::State(requests): axum::extract::State<Arc<Mutex<Vec<String>>>>,
    request: axum::extract::Request,
) -> (StatusCode, &'static str) {
    record_s3_request(
        &mut requests.lock().unwrap(),
        request.method(),
        &request.uri().to_string(),
    );
    // A client bug must settle immediately so this oracle cannot be hidden by
    // the production adapter's retry policy.
    (StatusCode::BAD_REQUEST, "unexpected hermetic S3 request")
}

#[cfg(target_os = "linux")]
fn record_s3_request(requests: &mut Vec<String>, method: &axum::http::Method, target: &str) {
    requests.push(format!("{method} {target}"));
}

#[cfg(target_os = "linux")]
struct HermeticAwsBoundary {
    imds: Arc<Mutex<HermeticImdsState>>,
    s3_requests: Arc<Mutex<Vec<String>>>,
    s3_endpoint: String,
    imds_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    s3_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    imds_task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    s3_task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    added_imds_address: bool,
}

#[cfg(target_os = "linux")]
impl HermeticAwsBoundary {
    async fn start() -> Self {
        let mut boundary = Self {
            imds: Arc::new(Mutex::new(HermeticImdsState::default())),
            s3_requests: Arc::new(Mutex::new(Vec::new())),
            s3_endpoint: String::new(),
            imds_shutdown: None,
            s3_shutdown: None,
            imds_task: None,
            s3_task: None,
            added_imds_address: false,
        };

        let lo = Command::new("/usr/sbin/ip")
            .args(["-json", "address", "show", "dev", "lo"])
            .output()
            .expect("inspect loopback addresses with installed iproute2");
        assert!(lo.status.success(), "ip failed to inspect loopback: {lo:?}");
        assert!(
            !String::from_utf8_lossy(&lo.stdout).contains(IMDS_ADDRESS),
            "hermetic E2E requires {IMDS_ADDRESS} to be absent before setup"
        );
        let add = Command::new("/usr/sbin/ip")
            .args(["address", "add", "169.254.169.254/32", "dev", "lo"])
            .output()
            .expect("add hermetic IMDS loopback address");
        assert!(
            add.status.success(),
            "ip failed to add IMDS address: {add:?}"
        );
        boundary.added_imds_address = true;

        let imds_listener = tokio::net::TcpListener::bind("169.254.169.254:80")
            .await
            .expect("bind strict hermetic IMDSv2 endpoint");
        let s3_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hermetic S3 tripwire");
        boundary.s3_endpoint = format!(
            "http://{}",
            s3_listener.local_addr().expect("read S3 tripwire address")
        );

        let (imds_shutdown, imds_shutdown_rx) = tokio::sync::oneshot::channel();
        let imds = Arc::clone(&boundary.imds);
        boundary.imds_task = Some(tokio::spawn(async move {
            axum::serve(
                imds_listener,
                axum::Router::new()
                    .fallback(hermetic_imds_handler)
                    .with_state(imds),
            )
            .with_graceful_shutdown(async move {
                let _ = imds_shutdown_rx.await;
            })
            .await
        }));
        boundary.imds_shutdown = Some(imds_shutdown);

        let (s3_shutdown, s3_shutdown_rx) = tokio::sync::oneshot::channel();
        let s3_requests = Arc::clone(&boundary.s3_requests);
        boundary.s3_task = Some(tokio::spawn(async move {
            axum::serve(
                s3_listener,
                axum::Router::new()
                    .fallback(hermetic_s3_handler)
                    .with_state(s3_requests),
            )
            .with_graceful_shutdown(async move {
                let _ = s3_shutdown_rx.await;
            })
            .await
        }));
        boundary.s3_shutdown = Some(s3_shutdown);
        boundary
    }

    fn object_store_config(&self) -> AdapterSelection {
        AdapterSelection::new(
            "aws-s3",
            AdapterConfig::from_pairs([
                ("endpoint", self.s3_endpoint.clone()),
                ("bucket", "cats-cross-component".to_owned()),
                ("region", AWS_REGION.to_owned()),
                ("prefix", AWS_PREFIX.to_owned()),
            ])
            .unwrap(),
        )
    }

    fn assert_exact_boundary(&self) {
        let imds = self.imds.lock().unwrap();
        assert_eq!(imds.token_requests, 1, "IMDSv2 token request cardinality");
        assert_eq!(imds.role_requests, 1, "IMDS role request cardinality");
        assert_eq!(
            imds.credential_requests, 1,
            "IMDS credential request cardinality"
        );
        assert!(
            imds.violations.is_empty(),
            "strict IMDSv2 boundary violations: {:?}",
            imds.violations
        );
        let s3_requests = self.s3_requests.lock().unwrap();
        assert!(
            s3_requests.is_empty(),
            "ProvisionRootImage checkpoint prefix unexpectedly accessed S3: {s3_requests:?}"
        );
    }

    async fn shutdown(mut self) {
        if let Some(shutdown) = self.imds_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.s3_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.imds_task.take() {
            task.await
                .expect("join hermetic IMDS server")
                .expect("serve hermetic IMDS endpoint");
        }
        if let Some(task) = self.s3_task.take() {
            task.await
                .expect("join hermetic S3 server")
                .expect("serve hermetic S3 endpoint");
        }
        // Graceful server joins drain every already accepted request before
        // the transcript is settled, so a queued S3 call cannot arrive after
        // the zero-request assertion.
        self.assert_exact_boundary();
        assert!(
            self.remove_imds_address(),
            "ip failed to remove the hermetic IMDS loopback address"
        );
        let lo = Command::new("/usr/sbin/ip")
            .args(["-json", "address", "show", "dev", "lo"])
            .output()
            .expect("reinspect loopback after hermetic AWS shutdown");
        assert!(
            lo.status.success(),
            "ip failed to reinspect loopback: {lo:?}"
        );
        assert!(
            !String::from_utf8_lossy(&lo.stdout).contains(IMDS_ADDRESS),
            "hermetic IMDS loopback address survived explicit shutdown"
        );
    }

    fn remove_imds_address(&mut self) -> bool {
        if !self.added_imds_address {
            return true;
        }
        let removed = Command::new("/usr/sbin/ip")
            .args(["address", "delete", "169.254.169.254/32", "dev", "lo"])
            .status()
            .is_ok_and(|status| status.success());
        self.added_imds_address = !removed;
        removed
    }

    fn detach_tripwires_fail_safe(&mut self) {
        // Dropping a oneshot sender would gracefully stop its server. On a
        // panic we instead detach both servers and deliberately retain the
        // 169.254.169.254 local address. Runtime teardown may later abort the
        // tasks, but the retained local alias still fails closed rather than
        // exposing a surviving systemd child to a real instance-metadata
        // route. Only `shutdown`, after exact process retirement and a
        // terminal full scan, may disarm this trap.
        if let Some(shutdown) = self.imds_shutdown.take() {
            std::mem::forget(shutdown);
        }
        if let Some(shutdown) = self.s3_shutdown.take() {
            std::mem::forget(shutdown);
        }
        if let Some(task) = self.imds_task.take() {
            std::mem::forget(task);
        }
        if let Some(task) = self.s3_task.take() {
            std::mem::forget(task);
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for HermeticAwsBoundary {
    fn drop(&mut self) {
        self.detach_tripwires_fail_safe();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn panic_cleanup_detaches_tripwires_without_disarming_imds_trap() {
    let (imds_shutdown, _imds_shutdown_rx) = tokio::sync::oneshot::channel();
    let (s3_shutdown, _s3_shutdown_rx) = tokio::sync::oneshot::channel();
    let imds_task = tokio::spawn(std::future::pending::<std::io::Result<()>>());
    let s3_task = tokio::spawn(std::future::pending::<std::io::Result<()>>());
    let mut boundary = HermeticAwsBoundary {
        imds: Arc::new(Mutex::new(HermeticImdsState::default())),
        s3_requests: Arc::new(Mutex::new(Vec::new())),
        s3_endpoint: "http://127.0.0.1:1".to_owned(),
        imds_shutdown: Some(imds_shutdown),
        s3_shutdown: Some(s3_shutdown),
        imds_task: Some(imds_task),
        s3_task: Some(s3_task),
        // This test exercises only the state transition; no host address is
        // created, and Drop must not attempt to remove one.
        added_imds_address: true,
    };
    boundary.detach_tripwires_fail_safe();
    assert!(boundary.imds_shutdown.is_none());
    assert!(boundary.s3_shutdown.is_none());
    assert!(boundary.imds_task.is_none());
    assert!(boundary.s3_task.is_none());
    assert!(boundary.added_imds_address);
    boundary.added_imds_address = false;
}

#[cfg(target_os = "linux")]
#[test]
fn hermetic_aws_boundary_rejects_wrong_imds_requests_and_records_s3() {
    let mut state = HermeticImdsState::default();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::HOST,
        axum::http::HeaderValue::from_static("169.254.169.254"),
    );
    headers.insert(
        "x-aws-ec2-metadata-token-ttl-seconds",
        axum::http::HeaderValue::from_static("60"),
    );
    assert_eq!(
        record_imds_request(
            &mut state,
            &axum::http::Method::PUT,
            "/latest/api/token",
            &headers,
            true,
        ),
        HermeticImdsReply::Rejected
    );

    headers.remove("x-aws-ec2-metadata-token-ttl-seconds");
    headers.insert(
        "x-aws-ec2-metadata-token-ttl-seconds",
        axum::http::HeaderValue::from_static("21600"),
    );
    assert_eq!(
        record_imds_request(
            &mut state,
            &axum::http::Method::PUT,
            "/latest/api/wrong-token-path",
            &headers,
            true,
        ),
        HermeticImdsReply::Rejected
    );

    headers.remove("x-aws-ec2-metadata-token-ttl-seconds");
    headers.insert(
        "x-aws-ec2-metadata-token",
        axum::http::HeaderValue::from_static("wrong-token"),
    );
    assert_eq!(
        record_imds_request(
            &mut state,
            &axum::http::Method::GET,
            "/latest/meta-data/iam/security-credentials/",
            &headers,
            true,
        ),
        HermeticImdsReply::Rejected
    );
    assert_eq!(
        record_imds_request(
            &mut state,
            &axum::http::Method::GET,
            "/latest/meta-data/iam/security-credentials/",
            &headers,
            false,
        ),
        HermeticImdsReply::Rejected
    );
    assert_eq!(state.violations.len(), 4);
    assert_eq!(state.token_requests, 0);
    assert_eq!(state.role_requests, 0);
    assert_eq!(state.credential_requests, 0);

    let mut s3_requests = Vec::new();
    record_s3_request(
        &mut s3_requests,
        &axum::http::Method::GET,
        "/cats-cross-component/unexpected",
    );
    assert_eq!(
        s3_requests,
        ["GET /cats-cross-component/unexpected".to_owned()]
    );
}

#[cfg(target_os = "linux")]
fn production_authorized_blockd_launch(
    context: &ControlContext,
    state: &StateDirectory,
    aws: &HermeticAwsBoundary,
) -> AuthorizedBlockdLaunchConfig {
    let postgres_url_file = state.path().join("postgres.url");
    if postgres_url_file.try_exists().unwrap() {
        assert_eq!(
            std::fs::read(&postgres_url_file).unwrap(),
            context.control_store_url.as_bytes()
        );
        assert_eq!(
            std::fs::metadata(&postgres_url_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    } else {
        std::fs::write(&postgres_url_file, context.control_store_url.as_bytes()).unwrap();
        std::fs::set_permissions(&postgres_url_file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    AuthorizedBlockdLaunchConfig {
        blockd_binary: "/opt/cats/bin/cats-blockd".into(),
        metadata_store: AdapterSelection::new(
            "postgres",
            AdapterConfig::from_pairs([(
                "url-file",
                postgres_url_file.to_string_lossy().into_owned(),
            )])
            .unwrap(),
        ),
        object_store: aws.object_store_config(),
        max_staged_bytes: cats_api::blockd::DEFAULT_MAX_STAGED_BYTES,
        max_staged_packs: cats_api::blockd::DEFAULT_MAX_STAGED_PACKS,
        max_local_bytes: cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES,
    }
}

#[cfg(target_os = "linux")]
fn production_installed_probe_config(
    state: StateDirectory,
    authority: Arc<PostgresVolumeDataAuthority>,
    blob_store: Arc<FixedImageBlob>,
    authorized_blockd_launch: AuthorizedBlockdLaunchConfig,
) -> InstalledCleanSlateProbeConfig {
    let inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority> = authority;
    let blob_store: Arc<dyn BlobStore> = blob_store;
    InstalledCleanSlateProbeConfig {
        state_directory: state,
        cloud_hypervisor_binary: "/opt/cats/bin/cloud-hypervisor".into(),
        blockd_binary: "/opt/cats/bin/cats-blockd".into(),
        guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
        ip_binary: "/usr/sbin/ip".into(),
        kernel_nbd_inventory: None,
        metering_cgroup_root: None,
        volume_inventory_authority: inventory_authority,
        blob_store,
        root_provision_systemd: RootProvisionSystemdConfig::new(authorized_blockd_launch).unwrap(),
    }
}

#[cfg(target_os = "linux")]
fn production_cutover_config(
    context: &ControlContext,
    registration: AgentRegistrationConfig,
    authority: Arc<PostgresVolumeDataAuthority>,
    blob_store: Arc<FixedImageBlob>,
    aws: &HermeticAwsBoundary,
    observation_barrier_for_test: super::RuntimeObservationBarrierForTest,
) -> super::SignedRuntimeCutoverConfig {
    let state = registration.runtime_state_directory();
    let authorized_blockd_launch = production_authorized_blockd_launch(context, &state, aws);
    let data_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
    let inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority> = authority;
    let blob_store: Arc<dyn BlobStore> = blob_store;
    super::SignedRuntimeCutoverConfig {
        listen: "127.0.0.1:0".into(),
        route_v2_machine: None,
        control_plane_url: context.server.base_url(),
        agent_registration: registration,
        ch_config: ChConfig {
            block_direct: false,
            vmm_launcher_bin: "/opt/cats/bin/cats-vmm-launcher".into(),
            ch_bin: "/opt/cats/bin/cloud-hypervisor".into(),
            kernel: "/opt/cats/release/guest/vmlinuz".into(),
            initramfs: None,
            boot_contract: None,
            cmdline: context.release.kernel_cmdline.as_str().to_owned(),
            seed_image: None,
            // The production default Kernel NBD path requires the Host's
            // configured nbd module/device pool. This focused, isolated Linux
            // E2E selects the separately validated native vhost-user path
            // while retaining the installed generic BlockFrontend residue scan.
            block_path: BlockPath::VhostUser,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin: "/usr/sbin/nbd-client".into(),
            nbd_devices: 64,
            ip_bin: "/usr/sbin/ip".into(),
        },
        authorized_blockd_launch,
        guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
        metering_cgroup_root: None,
        volume_data_authority: data_authority,
        volume_inventory_authority: inventory_authority,
        blob_store,
        volume_lease_duration_ms: 60_000,
        deadline_policy: RuntimeSpineDeadlinePolicy::new(
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .unwrap(),
        observation_barrier_for_test: Some(observation_barrier_for_test),
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_provision_root_checkpoint(
    state_path: &std::path::Path,
    cat_id: &Id,
    handle: &super::SignedRuntimeCutoverHandle,
) -> (Vec<u8>, RuntimeCheckpoint) {
    let path = runtime_checkpoint_path(&state_path.join(PRODUCTION_CHECKPOINT_NAMESPACE), cat_id);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(bytes) = std::fs::read(&path) {
            let checkpoint = decode_runtime_checkpoint(&bytes).unwrap();
            if matches!(checkpoint.step, ReconcileStep::ProvisionRootImage { .. }) {
                return (bytes, checkpoint);
            }
        }
        assert!(
            !handle.runner_task.is_finished(),
            "production signed Runtime runner stopped before A22 checkpoint publication"
        );
        assert!(
            Instant::now() < deadline,
            "production signed Runtime runner did not reach ProvisionRootImage"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(target_os = "linux")]
fn assert_same_session_lineage(left: &AgentSession, right: &AgentSession) {
    assert_eq!(left.version, right.version);
    assert_eq!(left.node_id, right.node_id);
    assert_eq!(left.immutable_host_id, right.immutable_host_id);
    assert_eq!(left.node_boot_id, right.node_boot_id);
    assert_eq!(left.agent_instance_id, right.agent_instance_id);
    assert_eq!(left.agent_session_epoch, right.agent_session_epoch);
    assert_eq!(left.registration_attempt_id, right.registration_attempt_id);
    assert_eq!(left.guest_config_digest, right.guest_config_digest);
}

#[cfg(target_os = "linux")]
async fn wait_for_initial_empty_inventory(
    context: &ControlContext,
    state_path: &std::path::Path,
    identity: &NodeIdentity,
    handle: &super::SignedRuntimeCutoverHandle,
) -> (AgentSession, Epoch) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let fingerprint = cats_control_plane::testsupport::runtime_spine_state_fingerprint(
            &context.server.state.store,
            identity.node_id.clone(),
        )
        .await;
        let fingerprint: serde_json::Value = serde_json::from_str(&fingerprint).unwrap();
        if fingerprint["inventory"].is_object() {
            let session: AgentSession =
                serde_json::from_value(fingerprint["session"]["record"].clone()).unwrap();
            let durable_session = decode_agent_session(
                &std::fs::read(state_path.join(crate::agent_registration::SESSION_RELATIVE_PATH))
                    .unwrap(),
            )
            .unwrap();
            assert_same_session_lineage(&session, &durable_session);
            assert!(session.lease_deadline_unix_ms >= durable_session.lease_deadline_unix_ms);
            assert_eq!(session.node_id, identity.node_id);
            assert_eq!(session.immutable_host_id, identity.immutable_host_id);
            assert_eq!(session.node_boot_id, current_kernel_node_boot_id().unwrap());
            assert_eq!(session.agent_session_epoch, Epoch::new(1).unwrap());

            let received: NodeObservation =
                serde_json::from_value(fingerprint["receive"]["observation"].clone()).unwrap();
            let acceptance: ObservationAcceptance =
                serde_json::from_value(fingerprint["receive"]["acceptance"].clone()).unwrap();
            let attestation: AdmissionInventoryAttestation =
                serde_json::from_value(fingerprint["inventory"]["attestation"].clone()).unwrap();
            let full: NodeObservation =
                serde_json::from_value(fingerprint["inventory"]["full_observation"].clone())
                    .unwrap();
            let assigned: DesiredReadSnapshot =
                serde_json::from_value(fingerprint["inventory"]["assigned_snapshot"].clone())
                    .unwrap();

            assert_eq!(received, full);
            assert!(full.complete_inventory);
            assert!(full.runtimes.is_empty());
            assert!(full.residue.is_empty());
            assert!(assigned.desired_specs.is_empty());
            assert_eq!(full.node_id, session.node_id);
            assert_eq!(full.node_boot_id, session.node_boot_id);
            assert_eq!(full.agent_instance_id, session.agent_instance_id);
            assert_eq!(full.agent_session_epoch, session.agent_session_epoch);
            assert_eq!(assigned.session.node_id, session.node_id);
            assert_eq!(assigned.session.node_boot_id, session.node_boot_id);
            assert_eq!(
                assigned.session.agent_instance_id,
                session.agent_instance_id
            );
            assert_eq!(
                assigned.session.agent_session_epoch,
                session.agent_session_epoch
            );
            assert_eq!(acceptance.session, assigned.session);
            assert_eq!(acceptance.observation_id, full.observation_id);
            assert_eq!(acceptance.heartbeat_sequence, full.heartbeat_sequence);
            assert_eq!(attestation.node_id, session.node_id);
            assert_eq!(attestation.agent_session_epoch, session.agent_session_epoch);
            assert_eq!(attestation.inventory_epoch, full.inventory_epoch);
            assert_eq!(
                Some(&attestation.inventory_digest),
                full.inventory_digest.as_ref()
            );
            assert_eq!(
                Some(attestation.inventory_read_position),
                full.inventory_read_position
            );
            assert_eq!(attestation.inventory_read_position, assigned.read_position);
            assert_eq!(fingerprint["cat_observations"].as_i64(), Some(0));
            return (session, full.inventory_epoch);
        }
        assert!(
            !handle.runner_task.is_finished(),
            "production signed Runtime runner stopped before its initial empty full inventory"
        );
        assert!(
            Instant::now() < deadline,
            "production scanner did not publish an initial empty accepted full inventory"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_ready_health(handle: &super::SignedRuntimeCutoverHandle) {
    let client = reqwest::Client::new();
    let url = format!("http://{}/healthz", handle.addr);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let response = client.get(&url).send().await.unwrap();
        if response.status() == StatusCode::OK {
            assert_eq!(
                response.text().await.unwrap(),
                "signed Runtime inventory attested"
            );
            return;
        }
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !handle.runner_task.is_finished(),
            "production signed Runtime runner stopped before nonempty full readiness"
        );
        assert!(
            Instant::now() < deadline,
            "production scanner did not open health after a nonempty full inventory"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[cfg(target_os = "linux")]
async fn next_observation_barrier(
    reached: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    handle: &super::SignedRuntimeCutoverHandle,
    phase: &'static str,
) {
    match tokio::time::timeout(Duration::from_secs(30), reached.recv()).await {
        Ok(Some(())) => {}
        Ok(None) => panic!(
            "production observation barrier closed unexpectedly during {phase}; runner_finished={}",
            handle.runner_task.is_finished()
        ),
        Err(_) => panic!(
            "production loop did not reach its observation barrier during {phase}; runner_finished={}",
            handle.runner_task.is_finished()
        ),
    }
    assert!(
        !handle.runner_task.is_finished(),
        "production runner stopped at its observation barrier during {phase}"
    );
}

#[cfg(target_os = "linux")]
async fn hold_after_exact_root_process_observation(
    context: &ControlContext,
    node_id: &Id,
    cat_id: &Id,
    handle: &super::SignedRuntimeCutoverHandle,
    reached: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    resume: &tokio::sync::mpsc::UnboundedSender<()>,
    phase: &'static str,
) -> String {
    loop {
        next_observation_barrier(reached, handle, phase).await;
        let fingerprint = cats_control_plane::testsupport::runtime_spine_state_fingerprint(
            &context.server.state.store,
            node_id.clone(),
        )
        .await;
        let value: serde_json::Value = serde_json::from_str(&fingerprint).unwrap();
        if value["inventory"].is_object() {
            let full: NodeObservation =
                serde_json::from_value(value["inventory"]["full_observation"].clone()).unwrap();
            if matches!(
                full.runtimes.as_slice(),
                [runtime]
                    if &runtime.cat_id == cat_id
                        && matches!(runtime.step, ReconcileStep::ProvisionRootImage { .. })
                        && matches!(runtime.processes.as_slice(), [process]
                            if process.state == ProcessState::Running
                                && process.control_handshake
                                    == ControlHandshakeEvidence::Verified)
            ) {
                return fingerprint;
            }
        }
        resume
            .send(())
            .expect("production observation barrier resume receiver dropped");
    }
}

#[cfg(target_os = "linux")]
async fn shutdown_cutover(mut handle: super::SignedRuntimeCutoverHandle, context: &'static str) {
    handle.request_runner_shutdown();
    super::join_result((&mut handle.runner_task).await, context).unwrap();
    drop(handle);
}

#[cfg(target_os = "linux")]
struct InstalledScanCursor {
    session: SessionBinding,
    desired: DesiredReadSnapshot,
    heartbeat_sequence: u64,
    inventory_epoch: u64,
}

#[cfg(target_os = "linux")]
impl InstalledScanCursor {
    fn after(
        session: &AgentSession,
        desired: DesiredReadSnapshot,
        observation: &NodeObservation,
    ) -> Self {
        let binding = SessionBinding {
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
        };
        assert_eq!(desired.session, binding);
        assert_eq!(observation.node_id, binding.node_id);
        assert_eq!(observation.node_boot_id, binding.node_boot_id);
        assert_eq!(observation.agent_instance_id, binding.agent_instance_id);
        assert_eq!(observation.agent_session_epoch, binding.agent_session_epoch);
        Self {
            session: binding,
            desired,
            heartbeat_sequence: observation.heartbeat_sequence.get(),
            inventory_epoch: observation.inventory_epoch.get(),
        }
    }

    fn next(&mut self) -> RuntimeSpineFullScan {
        self.heartbeat_sequence = self
            .heartbeat_sequence
            .checked_add(1)
            .expect("teardown heartbeat sequence overflow");
        self.inventory_epoch = self
            .inventory_epoch
            .checked_add(1)
            .expect("teardown inventory epoch overflow");
        RuntimeSpineFullScan {
            session: self.session.clone(),
            heartbeat_sequence: Sequence::new(self.heartbeat_sequence).unwrap(),
            inventory_epoch: Epoch::new(self.inventory_epoch).unwrap(),
            desired: self.desired.clone(),
        }
    }
}

#[cfg(target_os = "linux")]
async fn next_installed_process_scan(
    scanner: &Arc<dyn RuntimeInventoryScanner>,
    cursor: &mut InstalledScanCursor,
) -> Option<(NodeObservation, NodeGlobalManagedProcessAdmission)> {
    let coordinates = cursor.next();
    let scan = RuntimeInventoryScanContext::for_test(
        coordinates.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    let scanner = Arc::clone(scanner);
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::task::spawn_blocking(move || scanner.scan_complete(scan)),
    )
    .await
    .expect("installed teardown scan exceeded its outer deadline")
    .expect("installed teardown scan worker panicked")
    .expect("installed teardown scan failed");
    match outcome {
        RuntimeInventoryScanOutcome::Complete(inventory) => Some(
            inventory
                .bind_node_global_process_for_test(coordinates)
                .expect("bind installed teardown scan through production observation projection"),
        ),
        RuntimeInventoryScanOutcome::Incomplete { .. } => None,
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_installed_root_process_state(
    scanner: &Arc<dyn RuntimeInventoryScanner>,
    cursor: &mut InstalledScanCursor,
    cat_id: &Id,
    expect_live: bool,
) -> (NodeObservation, NodeGlobalManagedProcessAdmission) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some((observation, admission)) = next_installed_process_scan(scanner, cursor).await {
            let matching = admission
                .root_control(cat_id)
                .is_some_and(|(_, exact)| exact.is_some() == expect_live);
            if matching {
                return (observation, admission);
            }
        }
        assert!(
            Instant::now() < deadline,
            "installed scanner did not observe root process live={expect_live}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(target_os = "linux")]
struct ExactRootProcessFixture<'a> {
    control: &'a ControlContext,
    state_path: &'a std::path::Path,
    authority: Arc<PostgresVolumeDataAuthority>,
    blob_store: Arc<FixedImageBlob>,
    aws: &'a HermeticAwsBoundary,
    cat_id: &'a Id,
}

#[cfg(target_os = "linux")]
impl ExactRootProcessFixture<'_> {
    async fn retire(
        self,
        session: &AgentSession,
        desired: DesiredReadSnapshot,
        last_observation: &NodeObservation,
    ) {
        let state = StateDirectory::unanchored(self.state_path.to_path_buf());
        let launch = production_authorized_blockd_launch(self.control, &state, self.aws);
        let probe = production_installed_probe_config(
            state.clone(),
            self.authority,
            self.blob_store,
            launch.clone(),
        );
        let scanner = installed_clean_slate_scanner(
            probe.clone(),
            AdmissionCellRegistry::for_state_directory(&state),
            None,
        )
        .expect("compose installed teardown scanner");
        let ports = installed_root_process_effect_ports(probe)
            .expect("compose installed teardown retirement bridge");
        let process = PlatformSystemdRootProvisionProcessPort::platform(
            RootProvisionSystemdConfig::new(launch).unwrap(),
            state.clone(),
        );
        let mut cursor = InstalledScanCursor::after(session, desired, last_observation);

        let (live_observation, live_admission) =
            wait_for_installed_root_process_state(&scanner, &mut cursor, self.cat_id, true).await;
        assert!(live_observation.residue.is_empty());
        let (expected, exact) = live_admission
            .root_control(self.cat_id)
            .expect("fresh installed scan omitted the root-process expectation");
        let expected = expected.clone();
        let exact = exact
            .cloned()
            .expect("fresh installed scan did not seal the exact live root process");
        let stop_context = RuntimeDesiredEffectContext::for_test_with_node_global_process(
            state.clone(),
            Instant::now() + Duration::from_secs(10),
            live_admission,
        );
        assert!(matches!(
            process.stop_exact(exact, &stop_context).unwrap(),
            RootProvisionProcessStop::Submitted | RootProvisionProcessStop::AlreadyAbsent
        ));

        let (absent_observation, absent_admission) =
            wait_for_installed_root_process_state(&scanner, &mut cursor, self.cat_id, false).await;
        assert!(absent_observation.residue.is_empty());
        let (absent_expected, absent_exact) = absent_admission
            .root_control(self.cat_id)
            .expect("post-stop full scan omitted the root-process expectation");
        assert_eq!(absent_expected, &expected);
        assert!(absent_exact.is_none());
        let absent_runtime = absent_observation
            .runtimes
            .iter()
            .find(|runtime| &runtime.cat_id == self.cat_id)
            .expect("post-stop full scan omitted the checkpointed Cat");
        assert!(absent_runtime.processes.is_empty());
        let retire_context = RuntimeDesiredEffectContext::for_test_with_node_global_process(
            state.clone(),
            Instant::now() + Duration::from_secs(10),
            absent_admission,
        );
        assert_eq!(
            ports
                .retirement
                .retire_absent_socket_owner(&expected, &retire_context)
                .unwrap(),
            ManagedBlockdSocketOwnerRetirement::Retired
        );

        let (terminal_observation, terminal_admission) =
            wait_for_installed_root_process_state(&scanner, &mut cursor, self.cat_id, false).await;
        assert!(terminal_observation.residue.is_empty());
        let (terminal_expected, terminal_exact) = terminal_admission
            .root_control(self.cat_id)
            .expect("terminal full scan omitted the root-process expectation");
        assert_eq!(terminal_expected, &expected);
        assert!(terminal_exact.is_none());
        assert!(terminal_observation
            .runtimes
            .iter()
            .find(|runtime| &runtime.cat_id == self.cat_id)
            .is_some_and(|runtime| runtime.processes.is_empty()));

        let blockd_root =
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed();
        let blockd_entries = std::fs::read_dir(blockd_root.path().as_str())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            blockd_entries.is_empty(),
            "terminal audit found managed blockd owner residue"
        );
        let intent_entries = std::fs::read_dir(state.path().join(BLOCKD_SOCKET_INTENT_NAMESPACE))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            intent_entries.is_empty(),
            "terminal audit found managed blockd intent residue"
        );
    }
}

#[cfg(target_os = "linux")]
fn checkpoint_file_identity(path: &std::path::Path) -> (u64, u64, u64, i64, i64, i64, i64) {
    let metadata = std::fs::metadata(path).expect("stat Runtime checkpoint");
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(target_os = "linux")]
fn fingerprint_i64(fingerprint: &str, row: &str, field: &str) -> i64 {
    serde_json::from_str::<serde_json::Value>(fingerprint).unwrap()[row][field]
        .as_i64()
        .unwrap()
}

#[cfg(target_os = "linux")]
fn expected_image_head(
    blob: &FixedImageBlob,
    desired: &DesiredRuntimeSpec,
    root_size_bytes: u64,
) -> RemoteHead {
    let manifest = decode_image_manifest(&blob.body, &desired.runtime.boot_image_digest).unwrap();
    let identity = cats_blockd::format::image_root_identity(&manifest, root_size_bytes).unwrap();
    RemoteHead {
        generation: Generation::new(1).unwrap(),
        root_hash: Some(Sha256Digest::from_bytes(identity.root_hash)),
        root_object_id: Some(AsciiText::new(identity.root_object_id).unwrap()),
    }
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

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Linux real systemd PID 1; quality.sh linux runs it explicitly"]
async fn postgres_control_and_production_cutover_reconcile_one_created_cat_across_restart() {
    let context = ControlContext::spawn().await;
    let provisioner = Ed25519KeyPair::from_seed_unchecked(&RFC8032_TEST_SEED).unwrap();
    let identity = node_identity(&production_node_signer());

    let provision = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("cccccccccccccccccccccccccccccccc"),
        node_id: identity.node_id.clone(),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(identity.clone()),
            placement_policy: Box::new(production_e2e_placement_policy(
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

    // Retired shared-bearer Node/worker routes stay ordinary 404s and their
    // joined fallback handlers cannot mutate the signed A20 session/inventory
    // rows before the production Agent starts. Both historically privileged
    // bearer tokens are powerless here. This proof is intentionally scoped to
    // these awaited requests: the public router's `ui::not_found` fallback
    // constructs its response inline and does not spawn background work. The
    // PostgreSQL lock is not a claim about an arbitrary future detached writer.
    let before_retired_routes = cats_control_plane::testsupport::runtime_spine_state_fingerprint(
        &context.server.state.store,
        identity.node_id.clone(),
    )
    .await;
    let before_retired_route_facts =
        cats_control_plane::testsupport::runtime_cutover_acceptance_facts(
            &context.server.state.store,
            identity.node_id.clone(),
        )
        .await;
    let retired_route_write_barrier =
        cats_control_plane::testsupport::RuntimeSchemaWriteBarrierForTest::acquire(
            &context.control_store_url,
        )
        .await;
    // Calibrate the negative result against real INSERT/UPDATE/DELETE attempts
    // before trusting a set of read-only 404 responses as zero-write evidence.
    retired_route_write_barrier.calibrate_dml_blocked().await;
    let empty_spine: serde_json::Value = serde_json::from_str(&before_retired_routes).unwrap();
    for row in ["session", "desired", "receive", "inventory"] {
        assert!(empty_spine[row].is_null(), "unexpected pre-Agent {row} row");
    }
    assert_eq!(empty_spine["cat_observations"].as_i64(), Some(0));
    for path in [
        "/v1/nodes/register",
        "/v1/nodes/heartbeat",
        // Inventory was historically heartbeat-coupled. Keep the tempting
        // standalone compatibility alias retired as well.
        "/v1/nodes/inventory",
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
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(
                    &json_body(response, StatusCode::NOT_FOUND).await
                )
                .unwrap(),
                serde_json::json!({"code": "not_found", "message": "route not found"}),
                "legacy route {path} did not use the ordinary public 404 fallback"
            );
        }
    }
    assert_eq!(
        cats_control_plane::testsupport::runtime_spine_state_fingerprint(
            &context.server.state.store,
            identity.node_id.clone(),
        )
        .await,
        before_retired_routes
    );
    assert_eq!(
        cats_control_plane::testsupport::runtime_cutover_acceptance_facts(
            &context.server.state.store,
            identity.node_id.clone(),
        )
        .await,
        before_retired_route_facts,
        "retired routes mutated a production or retired-product authority table"
    );
    retired_route_write_barrier.finish_unchanged().await;

    let state_parent = tempfile::Builder::new()
        .prefix("cpg")
        .tempdir_in("/tmp")
        .unwrap();
    let state_path = state_parent.path().join("state");
    let aws = HermeticAwsBoundary::start().await;
    let authority =
        Arc::new(PostgresVolumeDataAuthority::connect(&context.control_store_url, None).unwrap());
    // Model Control and Node as independent clients of the same immutable S3
    // object. Control's Cat-create validation must not be mistaken for a read
    // by the installed Node scanner/effect composition.
    let node_image_blob = Arc::new(FixedImageBlob {
        key: context.image_blob.key.clone(),
        body: context.image_blob.body.clone(),
        reads: AtomicUsize::new(0),
    });
    let first_registration =
        production_registration(identity.clone(), state_path.clone(), &context.release);
    let (first_observation_barrier, mut first_observations, first_observation_resume) =
        super::RuntimeObservationBarrierForTest::channel();
    let first = super::spawn_signed_runtime_cutover(production_cutover_config(
        &context,
        first_registration,
        authority.clone(),
        node_image_blob.clone(),
        &aws,
        first_observation_barrier,
    ))
    .await
    .unwrap();
    let (initial_session, initial_inventory_epoch) =
        wait_for_initial_empty_inventory(&context, &state_path, &identity, &first).await;
    next_observation_barrier(
        &mut first_observations,
        &first,
        "initial empty accepted observation",
    )
    .await;
    first_observation_resume
        .send(())
        .expect("resume production loop after its initial empty observation");
    let initial_health = context
        .http
        .get(format!("http://{}/healthz", first.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        initial_health.text().await.unwrap(),
        "signed Runtime inventory is not attested"
    );

    let uncordon = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("dddddddddddddddddddddddddddddddd"),
        node_id: identity.node_id.clone(),
        mutation: RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision: Epoch::new(1).unwrap(),
            placement_policy: Box::new(production_e2e_placement_policy(
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
    assert_eq!(
        node_image_blob.reads.load(Ordering::SeqCst),
        0,
        "installed Node composition read an image before any Desired existed"
    );
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
        .header(
            "Idempotency-Key",
            "runtime-production-cross-component-create",
        )
        .body(CAT_CREATE_BODY.to_vec())
        .send()
        .await
        .unwrap();
    let create_body = json_body(create, StatusCode::ACCEPTED).await;
    let created = decode_cat_create_v2_accepted_response(&create_body).unwrap();
    let create_request: CatCreateV2Request = serde_json::from_slice(CAT_CREATE_BODY).unwrap();
    assert!(
        context.image_blob.reads.load(Ordering::SeqCst) > 0,
        "Control Cat-create did not validate the immutable image manifest"
    );

    let first_accepted_process = hold_after_exact_root_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &first,
        &mut first_observations,
        &first_observation_resume,
        "first cutover exact root-process observation",
    )
    .await;
    wait_for_ready_health(&first).await;
    let (checkpoint_bytes, checkpoint) =
        wait_for_provision_root_checkpoint(&state_path, &created.cat_id, &first).await;
    shutdown_cutover(first, "join first production cross-component cutover").await;
    let checkpoint_path = runtime_checkpoint_path(
        &state_path.join(PRODUCTION_CHECKPOINT_NAMESPACE),
        &created.cat_id,
    );
    let first_checkpoint_identity = checkpoint_file_identity(&checkpoint_path);
    assert!(
        node_image_blob.reads.load(Ordering::SeqCst) > 0,
        "installed Node scanner/effect never read the Cat-create image manifest"
    );

    let first_fingerprint = first_accepted_process;
    assert_eq!(
        fingerprint_i64(&first_fingerprint, "inventory", "agent_session_epoch"),
        1
    );
    let first_inventory_epoch = fingerprint_i64(&first_fingerprint, "inventory", "inventory_epoch");
    assert!(first_inventory_epoch > i64::try_from(initial_inventory_epoch.get()).unwrap());
    let first_fingerprint: serde_json::Value = serde_json::from_str(&first_fingerprint).unwrap();
    let first_session: AgentSession =
        serde_json::from_value(first_fingerprint["session"]["record"].clone()).unwrap();
    let first_full: NodeObservation =
        serde_json::from_value(first_fingerprint["inventory"]["full_observation"].clone()).unwrap();
    let first_assigned: DesiredReadSnapshot =
        serde_json::from_value(first_fingerprint["inventory"]["assigned_snapshot"].clone())
            .unwrap();
    let [first_runtime] = first_full.runtimes.as_slice() else {
        panic!("accepted production inventory must contain exactly the created Cat")
    };
    let [first_root_process] = first_runtime.processes.as_slice() else {
        panic!("accepted production inventory must contain one root-provision process")
    };
    let first_root_process = first_root_process.clone();
    let [desired] = first_assigned.desired_specs.as_slice() else {
        panic!("accepted production inventory must bind exactly the created Cat")
    };
    assert_same_session_lineage(&first_session, &initial_session);
    assert_eq!(
        first_full.agent_session_epoch,
        initial_session.agent_session_epoch
    );
    assert_eq!(desired.workspace_id.as_str(), workspace.id);
    assert_eq!(desired.version, ContractVersion::V1);
    assert_eq!(desired.cat_id, created.cat_id);
    assert_eq!(desired.desired_revision.get(), 1);
    assert_eq!(desired.target, RuntimeTarget::Running);
    assert_eq!(desired.placement.kind, AssignedKind::Assigned);
    assert_eq!(desired.placement.node_id, identity.node_id);
    assert_eq!(desired.placement.placement_epoch, Epoch::new(1).unwrap());
    assert_eq!(desired.transition, RuntimeTransition::CancelAndDrain);
    assert_eq!(desired.runtime.vcpus, create_request.vcpus);
    assert_eq!(desired.runtime.memory_bytes, create_request.memory_bytes);
    assert_eq!(
        desired.runtime.boot_image_digest,
        create_request.boot_image_digest
    );
    assert_eq!(
        desired.runtime.guest_config_digest,
        guest_config_digest(&context.release).unwrap()
    );
    assert_eq!(
        desired.runtime.network_config.kind,
        IsolatedIpv4Kind::IsolatedIpv4
    );
    let network_suffix = desired
        .runtime
        .network_config
        .network_id
        .as_str()
        .strip_prefix("net_")
        .expect("Cat-create network id must use the canonical net_ prefix");
    assert_eq!(network_suffix.len(), 32);
    assert!(network_suffix
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(desired.runtime.network_config.prefix_length, 30);
    let gateway: std::net::Ipv4Addr = desired
        .runtime
        .network_config
        .gateway_ipv4
        .as_str()
        .parse()
        .unwrap();
    let guest: std::net::Ipv4Addr = desired
        .runtime
        .network_config
        .guest_ipv4
        .as_str()
        .parse()
        .unwrap();
    let gateway = u32::from(gateway);
    let guest = u32::from(guest);
    assert_eq!(
        gateway & 0xffff_0000,
        u32::from(std::net::Ipv4Addr::new(10, 241, 0, 0)),
        "Cat-create network escaped the provisioned Node /16"
    );
    assert!(
        gateway > u32::from(std::net::Ipv4Addr::new(10, 241, 0, 1)),
        "Cat-create reused the reserved Node pool subnet"
    );
    assert_eq!(gateway & 0b11, 1, "gateway is not the /30 gateway slot");
    assert_eq!(guest, gateway + 1, "Guest is not the /30 guest slot");
    assert_eq!(
        desired.runtime.network_config.guest_mac.as_str(),
        format!(
            "02:ca:{:02x}:{:02x}:{:02x}:{:02x}",
            (guest >> 24) & 0xff,
            (guest >> 16) & 0xff,
            (guest >> 8) & 0xff,
            guest & 0xff
        )
    );
    assert_eq!(spec_digest(desired).unwrap(), desired.spec_digest);
    let [endpoint] = desired.endpoints.as_slice() else {
        panic!("Cat-create must publish exactly one default HTTP endpoint")
    };
    let endpoint_suffix = endpoint.endpoint_id.as_str().strip_prefix("ep_").unwrap();
    assert_eq!(endpoint_suffix.len(), 32);
    assert!(endpoint_suffix
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(
        endpoint.hostname.as_str(),
        format!("runtime-spine-app-{endpoint_suffix}.cats.run")
    );
    assert_eq!(endpoint.route_epoch, Epoch::new(1).unwrap());
    assert_eq!(endpoint.protocol, HttpProtocol::Http);
    assert_eq!(endpoint.target_port, 8080);
    let [root] = desired.volumes.as_slice() else {
        panic!("Cat-create must publish exactly one Root volume intent")
    };
    assert_eq!(root.disk_kind, DiskKind::Root);
    assert_eq!(root.access, VolumeAccess::ReadWriteOnce);
    assert_eq!(root.size_bytes, create_request.root_size_bytes);
    assert_eq!(root.durability, Durability::Strict);
    assert_eq!(root.guest_device.serial.as_str(), "cats-root");
    assert_eq!(root.guest_device.slot, 0);
    assert_eq!(root.disposition, VolumeDisposition::Retain);
    assert!(root.mount.is_none());
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &root.acquire
    else {
        panic!("Cat-create Root must use a normal A22 acquire")
    };

    let ReconcileStep::ProvisionRootImage {
        scope_id,
        control_socket_path,
        process_identity_token,
        volume_id,
        attachment_id,
        attachment_epoch,
        size_bytes,
        boot_image_digest,
        expected_blank_head,
        expected_provisioned_head,
        ..
    } = &checkpoint.step
    else {
        unreachable!("waiter returned another checkpoint step")
    };
    assert_eq!(checkpoint.cat_id, desired.cat_id);
    assert_eq!(checkpoint.node_id, desired.placement.node_id);
    assert_eq!(
        checkpoint.placement_epoch,
        desired.placement.placement_epoch
    );
    assert_eq!(checkpoint.desired_revision, desired.desired_revision);
    assert_eq!(checkpoint.spec_digest, desired.spec_digest);
    assert_eq!(volume_id, &root.volume_id);
    assert_eq!(attachment_id, &root.attachment_id);
    assert_eq!(size_bytes, &root.size_bytes);
    assert_eq!(boot_image_digest, &desired.runtime.boot_image_digest);
    assert_eq!(
        expected_blank_head,
        &RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    );
    assert_eq!(
        expected_provisioned_head,
        &expected_image_head(node_image_blob.as_ref(), desired, root.size_bytes)
    );
    let [observed_volume] = checkpoint.volumes.as_slice() else {
        panic!("single-Root Cat checkpoint must retain exactly one Volume")
    };
    assert_eq!(&observed_volume.volume_id, volume_id);
    assert_eq!(
        observed_volume.volume_intent_id.as_ref(),
        Some(&root.volume_intent_id)
    );
    assert_eq!(observed_volume.disk_id.as_ref(), Some(&root.disk_id));
    assert_eq!(observed_volume.disk_kind, ObservedDiskKind::Root);
    assert_eq!(observed_volume.size_bytes, Some(root.size_bytes));
    assert_eq!(observed_volume.durability, Some(root.durability));
    assert!(matches!(
        &observed_volume.authority,
        VolumeAuthorityEvidence::Owned {
            attachment_id: observed_attachment,
            attachment_epoch: observed_epoch,
            head,
        } if observed_attachment == attachment_id
            && observed_epoch == attachment_epoch
            && head == expected_blank_head
    ));
    let [lineage] = observed_volume.local_lineages.as_slice() else {
        panic!("A22 checkpoint must retain one exact Root lineage")
    };
    assert_eq!(lineage.attachment_id, *attachment_id);
    assert_eq!(lineage.attachment_epoch, *attachment_epoch);
    assert_eq!(
        lineage.acquire_origin,
        AcquireOrigin::Normal {
            transition_id: transition_id.clone(),
        }
    );
    assert_eq!(lineage.node_id, desired.placement.node_id);
    assert_eq!(lineage.placement_epoch, desired.placement.placement_epoch);
    assert_eq!(lineage.pending_pack_count.get(), 0);
    assert!(!lineage.fenced);
    assert_eq!(lineage.state, LocalLineageState::Active);

    // This is the concrete adapter used by noded, reading the exact same PG
    // volume_records row written by the signed A22 Control transaction.
    let acquired = authority.load_volume(volume_id).unwrap();
    assert_eq!(acquired.lease_owner.as_ref(), Some(attachment_id));
    assert_eq!(acquired.lease_epoch, *attachment_epoch);
    let LastVolumeTransition::NormalAcquire { request, result } =
        acquired.last_transition.as_ref().unwrap()
    else {
        panic!("production reconciliation did not persist a NormalAcquire")
    };
    assert_eq!(&request.volume_id, volume_id);
    assert_eq!(&request.attachment_id, attachment_id);
    assert_eq!(&request.transition_id, transition_id);
    assert_eq!(&request.expected_unowned_epoch, expected_unowned_epoch);
    assert_eq!(request.desired_revision, checkpoint.desired_revision);
    assert_eq!(request.placement_epoch, checkpoint.placement_epoch);
    assert_eq!(request.lease_duration_ms, 60_000);
    assert_eq!(result.resulting_epoch, *attachment_epoch);
    assert_eq!(&result.volume_id, volume_id);
    assert_eq!(&result.transition_id, transition_id);
    assert_eq!(&result.attachment_id, attachment_id);
    assert_eq!(result.resulting_head, acquired.head);
    assert!(matches!(
        acquired.lease_expires_at,
        Some(current) if current >= result.lease_expires_at
    ));
    let inventory = authority
        .load_node_volume_inventory(
            &identity.node_id,
            &std::collections::BTreeSet::from([volume_id.clone()]),
        )
        .unwrap();
    let owned = inventory
        .records
        .iter()
        .find(|candidate| candidate.volume.volume_id == *volume_id)
        .unwrap();
    let binding = owned.binding.as_ref().unwrap();
    assert_eq!(binding.owner_node_id, identity.node_id);
    assert_eq!(binding.attachment_id, *attachment_id);
    assert_eq!(binding.attachment_epoch, *attachment_epoch);
    let first_volume_row = cats_control_plane::testsupport::runtime_volume_row_fingerprint(
        &context.server.state.store,
        volume_id.clone(),
    )
    .await;

    let first_facts = cats_control_plane::testsupport::runtime_cutover_acceptance_facts(
        &context.server.state.store,
        identity.node_id.clone(),
    )
    .await;
    assert_eq!(first_facts.node_identity_count, 1);
    assert_eq!(first_facts.node_credential_lineage_count, 1);
    assert_eq!(first_facts.node_policy_count, 1);
    assert_eq!(first_facts.node_authority_apply_count, 2);
    assert_eq!(first_facts.registration_attempt_count, 1);
    assert_eq!(first_facts.current_session_count, 1);
    assert_eq!(first_facts.desired_read_state_count, 1);
    assert_eq!(first_facts.observation_receive_state_count, 1);
    assert_eq!(first_facts.admission_inventory_state_count, 1);
    assert_eq!(first_facts.current_cat_observation_count, 1);
    assert_eq!(first_facts.cat_record_count, 1);
    assert_eq!(first_facts.disk_record_count, 1);
    assert_eq!(first_facts.volume_record_count, 1);
    assert_eq!(first_facts.desired_spec_count, 1);
    assert_eq!(first_facts.endpoint_record_count, 1);
    assert_eq!(first_facts.hostname_lookup_count, 1);
    assert_eq!(first_facts.runtime_operation_count, 1);
    assert_eq!(first_facts.api_result_count, 1);
    assert_eq!(first_facts.retired_node_count, 0);
    assert_eq!(first_facts.retired_cat_count, 0);
    assert_eq!(first_facts.stored_api_response_body, Some(create_body));
    assert_eq!(first_facts.stored_persistent_disk_response_body, None);
    let first_observation_id = first_full.observation_id;

    let restarted_registration =
        production_registration(identity.clone(), state_path.clone(), &context.release);
    let (restart_observation_barrier, mut restart_observations, restart_observation_resume) =
        super::RuntimeObservationBarrierForTest::channel();
    let restarted = super::spawn_signed_runtime_cutover(production_cutover_config(
        &context,
        restarted_registration,
        authority.clone(),
        node_image_blob.clone(),
        &aws,
        restart_observation_barrier,
    ))
    .await
    .unwrap();
    let restart_fingerprint = hold_after_exact_root_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &restarted,
        &mut restart_observations,
        &restart_observation_resume,
        "restarted cutover exact root-process observation",
    )
    .await;
    shutdown_cutover(
        restarted,
        "join restarted production cross-component cutover",
    )
    .await;

    let restart_fingerprint: serde_json::Value =
        serde_json::from_str(&restart_fingerprint).unwrap();
    let restarted_session: AgentSession =
        serde_json::from_value(restart_fingerprint["session"]["record"].clone()).unwrap();
    let restarted_full: NodeObservation =
        serde_json::from_value(restart_fingerprint["inventory"]["full_observation"].clone())
            .unwrap();
    let restarted_assigned: DesiredReadSnapshot =
        serde_json::from_value(restart_fingerprint["inventory"]["assigned_snapshot"].clone())
            .unwrap();
    assert_eq!(
        restarted_session.agent_session_epoch,
        Epoch::new(2).unwrap()
    );
    assert_ne!(
        restarted_session.agent_instance_id,
        initial_session.agent_instance_id
    );
    assert_eq!(restarted_full.node_id, restarted_session.node_id);
    assert_eq!(restarted_full.node_boot_id, restarted_session.node_boot_id);
    assert_eq!(
        restarted_full.agent_instance_id,
        restarted_session.agent_instance_id
    );
    assert_eq!(
        restarted_full.agent_session_epoch,
        restarted_session.agent_session_epoch
    );
    assert_ne!(restarted_full.observation_id, first_observation_id);
    assert!(restarted_full.complete_inventory);
    assert!(restarted_full.residue.is_empty());
    assert_eq!(
        restarted_assigned.desired_specs.as_slice(),
        std::slice::from_ref(desired)
    );
    let [restarted_runtime] = restarted_full.runtimes.as_slice() else {
        panic!("restart full inventory must contain exactly the created Cat")
    };
    assert_eq!(restarted_runtime.cat_id, desired.cat_id);
    assert_eq!(restarted_runtime.step, checkpoint.step);
    let [root_process] = restarted_runtime.processes.as_slice() else {
        panic!("joined restart effect did not produce one root-provision process proof")
    };
    assert_eq!(
        root_process, &first_root_process,
        "Agent restart replaced rather than adopted the retained root-provision process"
    );
    assert!(root_process.process_id > 0);
    assert!(root_process.process_start_time_ticks.get() > 0);
    assert_eq!(
        root_process.executable_path.as_str(),
        "/opt/cats/bin/cats-blockd"
    );
    assert_eq!(root_process.scope_id, *scope_id);
    assert_eq!(root_process.control_socket_path, *control_socket_path);
    assert_eq!(root_process.state, ProcessState::Running);
    assert_eq!(
        root_process.control_handshake,
        ControlHandshakeEvidence::Verified
    );
    assert_eq!(root_process.observed_vm_shape, None);
    assert_eq!(
        root_process.role,
        ProcessRole::Blockd {
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: *attachment_epoch,
        }
    );
    assert_eq!(
        root_process.ownership_token,
        OwnershipTokenEvidence::Valid {
            ownership_token: process_identity_token.clone(),
        }
    );
    assert_eq!(
        restarted_runtime.applied_desired.as_ref(),
        Some(&AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        })
    );
    assert!(restarted_runtime
        .conditions
        .iter()
        .any(|condition| matches!(
            condition,
            Condition::Progressing {
                reason: ProgressingReason::ReconcileStep { step }
            } if step == &checkpoint.step
        )));
    assert!(restarted_runtime
        .conditions
        .iter()
        .all(|condition| !matches!(
            condition,
            Condition::Blocked { .. }
                | Condition::Degraded { .. }
                | Condition::Quarantined { .. }
                | Condition::PreconditionFailed { .. }
                | Condition::DataLossPossible { .. }
        )));
    let CheckpointEvidence::Valid {
        content_digest,
        cat_id,
        node_id,
        desired_revision,
        spec_digest: observed_spec_digest,
        placement_epoch,
        step,
        ..
    } = &restarted_runtime.checkpoint
    else {
        panic!("restart did not inventory the durable ProvisionRootImage checkpoint")
    };
    assert_eq!(
        content_digest,
        &checkpoint_content_digest(&checkpoint).unwrap()
    );
    assert_eq!(cat_id, &desired.cat_id);
    assert_eq!(node_id, &desired.placement.node_id);
    assert_eq!(desired_revision, &desired.desired_revision);
    assert_eq!(observed_spec_digest, &desired.spec_digest);
    assert_eq!(placement_epoch, &desired.placement.placement_epoch);
    assert_eq!(step.as_ref(), &checkpoint.step);
    assert_eq!(
        std::fs::read(&checkpoint_path).unwrap(),
        checkpoint_bytes,
        "restart must not republish the durable A22 successor checkpoint"
    );
    assert_eq!(
        checkpoint_file_identity(&checkpoint_path),
        first_checkpoint_identity,
        "restart rewrote the same-value durable A22 successor checkpoint"
    );
    assert_eq!(
        authority.load_volume(volume_id).unwrap(),
        acquired,
        "restart must not repeat or renew the settled A22 authority mutation"
    );
    assert_eq!(
        cats_control_plane::testsupport::runtime_volume_row_fingerprint(
            &context.server.state.store,
            volume_id.clone(),
        )
        .await,
        first_volume_row,
        "restart performed a same-value PostgreSQL UPDATE of the settled A22 row"
    );

    // The runner has joined. Rebuild the installed production scanner and
    // process ports, bind a fresh full scan through production observation
    // coordinates, stop only its exact retained process proof, prove absence
    // in a successor full scan, retire the managed owner/intent through the
    // real bridge, and finish with another full physical audit. Only after
    // all of that may the credential/object-store tripwires be disarmed.
    ExactRootProcessFixture {
        control: &context,
        state_path: &state_path,
        authority: authority.clone(),
        blob_store: node_image_blob.clone(),
        aws: &aws,
        cat_id: &created.cat_id,
    }
    .retire(&restarted_session, restarted_assigned, &restarted_full)
    .await;
    // The production child opened the configured aws-s3 adapter, but this
    // control-only attach prefix must stop before the first object operation.
    aws.shutdown().await;

    let successor = production_registration(identity, state_path, &context.release);
    drop(successor);
    drop(authority);
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
        "/v1/nodes/inventory",
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

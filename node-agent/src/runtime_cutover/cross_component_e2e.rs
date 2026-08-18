//! PostgreSQL-backed acceptance across the production Control composition and
//! the signed Node Runtime spine. The portable case stops at a recording
//! `RefreshInventory` seam. The Linux case uses the installed scanner,
//! production signed effects and PID-1 process ownership through an authorized
//! serving blockd, then drives its native vhost-user frontend without launching
//! a Guest or VMM.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
#[cfg(target_os = "linux")]
use cats_api::agent_registration::{
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
    REGISTRATION_METHOD, REGISTRATION_PATH,
};
#[cfg(target_os = "linux")]
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse, DurabilityStatus};
use cats_api::cat_create::decode_cat_create_v2_accepted_response;
#[cfg(target_os = "linux")]
use cats_api::cat_create::CatCreateV2Request;
use cats_api::requests::ListResponse;
use cats_api::runtime_node_authority::{
    runtime_node_authority_signed_request, PROVISIONER_CREDENTIAL_ID_HEADER,
    PROVISIONER_SIGNATURE_HEADER, RUNTIME_NODE_AUTHORITY_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_agent_session, decode_runtime_checkpoint, decode_runtime_node_authority_apply_result,
    encode_runtime_node_authority_apply, guest_config_digest, key_ring_digest,
    AgentRegistrationAttempt, AgentSession, AllocatableMemoryBytes, AllocatableVcpus,
    AppliedDesiredEvidence, CheckpointEvidence, CheckpointRouteGate, Condition, ContractVersion,
    CredentialBinding, DesiredReadSnapshot, DesiredRuntimeSpec, Epoch, GuestIpv4Pool,
    GuestIpv4PoolKind, GuestTransportEvidence, HostPath, HttpProtocol, Id, InventorySource,
    Ipv4Address, KeyId, LifecycleAdmission, NodeBootId, NodeIdentity, NodeIdentityState,
    NodePlacementPolicy, NodeTransportTarget, ObservedRouteGate, ObservedRuntimeStatus,
    RandomId128, ReadyReason, ReconcileStep, Revision, RouteGateBinding, RouteGateState,
    RuntimeLaunch, RuntimeNodeAuthorityApply, RuntimeNodeAuthorityMutation,
    RuntimeNodeAuthorityOutcome, RuntimePlacementBlockFrontend, RuntimePlacementCapabilities,
    RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport, RuntimePlacementVmm,
    RuntimeSchedulingState, RuntimeTarget, Sequence, Sha256Digest, StableState, UnixMillis,
    WarmSnapshotEvidence,
};
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, spawn_with_gateway_machine, Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_metering::SqliteUsageStore;
use cats_network::route_v2::{
    gateway_machine_clients_for_test, BoxedGatewayTunnel, ControlMachineTarget, GatewayIngress,
    GatewayIngressConfig, GatewayNodeRouteV2Error, RouteCache, RouteCacheConfig, TunnelConnector,
    TunnelFuture,
};
use cats_storage::{
    encode_image_manifest, image_manifest_key, BlobError, BlobStore, ImageManifestV1,
    LowerHexSha256, IMAGE_MANIFEST_MAX_BYTES,
};
use reqwest::{Response, StatusCode};
use ring::signature::Ed25519KeyPair;

#[cfg(target_os = "linux")]
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, encode_agent_registration_attempt, inventory_digest, spec_digest,
    AcquireOrigin, AdmissionInventoryAttestation, AsciiText, AssignedKind,
    ControlHandshakeEvidence, DiskKind, Durability, Generation, IsolatedIpv4Kind,
    LastVolumeTransition, LocalLineageState, NodeObservation, ObservationAcceptance,
    ObservationInventoryAcceptance, ObservedDevice, ObservedDiskKind, ObservedNetwork,
    OwnershipTokenEvidence, PrepareDeviceFrontend, PreparedDeviceInput, ProcessEvidence,
    ProcessRole, ProcessState, ProgressingReason, RemoteHead, RuntimeCheckpoint,
    RuntimeNetworkIdentity, RuntimeTransition, SessionBinding, VolumeAccess, VolumeAcquire,
    VolumeAuthorityEvidence, VolumeDisposition,
};
#[cfg(target_os = "linux")]
use cats_metadata_store_postgres::PostgresVolumeDataAuthority;
#[cfg(target_os = "linux")]
use cats_object_store_aws_s3::{AwsS3BlobStore, AwsS3Config};
#[cfg(target_os = "linux")]
use cats_storage::authority::{
    AuthorizedServingAttachment, RuntimeVolumeInventoryAuthority, VolumeDataAuthority,
};
#[cfg(target_os = "linux")]
use cats_storage::{decode_image_manifest, AdapterConfig, AdapterSelection};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
#[cfg(target_os = "linux")]
use std::process::Command;

use crate::agent_registration::AgentRegistrationConfig;
#[cfg(target_os = "linux")]
use crate::ch::{BlockPath, ChConfig, ChNetwork};
use crate::route_grant_v2::{RouteGrantV2KeyRing, RouteGrantV2Verifier};
use crate::route_v2_machine::{RouteV2MachineConfig, RouteV2MachineListener};
#[cfg(target_os = "linux")]
use crate::runtime::reconciliation::{
    current_kernel_node_boot_id, installed_clean_slate_scanner,
    installed_root_process_effect_ports, retire_absent_serving_socket_owner_for_test,
    runtime_checkpoint_path, AuthorizedBlockdLaunchConfig, BlockdSocketIntentStore,
    InstalledCleanSlateProbeConfig, ManagedBlockdSocketOwnerRetirement,
    NodeGlobalManagedProcessAdmission, RetainedManagedBlockdSocketRoot,
    RetainedManagedVmmLaunchRoot, RetainedManagedVmmSocketRoot, RootProvisionSystemdConfig,
    VmmSocketReceiptStore, AUTHORIZED_SERVING_FILE, BLOCKD_SOCKET_INTENT_NAMESPACE, IDENTITY_FILE,
    INSTALLED_VMM_SOCKET_ROOT, VMM_LAUNCH_FILE_NAMESPACE,
};
use crate::runtime::reconciliation::{
    AdmissionCell, AdmissionCellRegistry, AdmissionGatePort as _, AdmissionSnapshot,
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
#[cfg(target_os = "linux")]
const RELAXED_CAT_CREATE_BODY: &[u8] = br#"{"name":"runtime-spine-app","boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vcpus":2,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"relaxed"}"#;
const ROUTE_V2_KID: &str = "2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99";
const ROUTE_RUNTIME_INCARNATION: &str = "00000000000000000000000000005151";
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
        Self::spawn_inner(false).await
    }

    async fn spawn_route_v2() -> Self {
        Self::spawn_inner(true).await
    }

    async fn spawn_inner(route_v2: bool) -> Self {
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
        let config = Config {
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
            production_cutover_operator_trust_bundle:
                cats_control_plane::testsupport::test_production_cutover_operator_trust_bundle(),
            route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
            admin_token: ADMIN_TOKEN.into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 120_000,
            reconcile_interval_ms: 60_000,
            auto_tier_policy: AutoTierPolicy::default(),
            oci_deploy_sync_wait_ms: 5_000,
        };
        let server = if route_v2 {
            spawn_with_gateway_machine(
                config,
                cats_control_plane::testsupport::route_v2_gateway_machine_config("127.0.0.1:0")
                    .unwrap(),
            )
            .await
            .unwrap()
        } else {
            spawn(config).await.unwrap()
        };
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
struct RouteReadyScanner {
    records: Mutex<Vec<ScanRecord>>,
}

impl crate::runtime_spine::inventory_scanner_sealed::Sealed for RouteReadyScanner {}

impl RuntimeInventoryScanner for RouteReadyScanner {
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
        let kid = KeyId::new(ROUTE_V2_KID).context("Route v2 fixture kid is invalid")?;
        let ring_version = Epoch::new(1).context("Route v2 fixture ring version is invalid")?;
        let ring_digest = key_ring_digest(ring_version, std::slice::from_ref(&kid))?;
        let runtimes = coordinates
            .desired
            .desired_specs
            .iter()
            .map(route_ready_runtime)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(RuntimeInventoryScanOutcome::Complete(Box::new(
            CompleteRuntimeInventory::from_validated_coverage(
                coverage.finish()?,
                UnixMillis::new(1_900_000_006_000).unwrap(),
                RuntimeInventoryKeyRing::Loaded {
                    version: ring_version,
                    digest: ring_digest,
                    kids: vec![kid],
                },
                runtimes,
                Vec::new(),
                BTreeSet::new(),
            ),
        )))
    }
}

fn route_runtime_launch(runtime_incarnation: &RandomId128) -> RuntimeLaunch {
    let mut launch = decode_runtime_checkpoint(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
    )))
    .unwrap()
    .runtime_launch;
    let RuntimeLaunch::Present(identity) = &mut launch else {
        unreachable!("fixed StartRuntime checkpoint retains its launch identity")
    };
    identity.runtime_incarnation = runtime_incarnation.clone();
    identity.scope_id =
        Id::new(format!("cats-vmm-{}.service", runtime_incarnation.as_str())).unwrap();
    launch
}

fn route_ready_runtime(desired: &DesiredRuntimeSpec) -> anyhow::Result<ObservedRuntimeStatus> {
    let endpoint = desired
        .endpoints
        .first()
        .context("Route v2 fixture Desired lacks its default Endpoint")?;
    let incarnation = random(ROUTE_RUNTIME_INCARNATION);
    let step = ReconcileStep::Stable {
        state: StableState::Running,
    };
    Ok(ObservedRuntimeStatus {
        cat_id: desired.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: RuntimeTarget::Running,
        }),
        runtime_incarnation: Some(incarnation.clone()),
        stable_state: Some(StableState::Running),
        step: step.clone(),
        checkpoint: CheckpointEvidence::Valid {
            checkpoint_path: HostPath::new("/var/lib/cats/checkpoints/cat-route-e2e.json")
                .expect("test checkpoint path is valid"),
            content_digest: Sha256Digest::from_bytes([0x51; 32]),
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement_epoch: desired.placement.placement_epoch,
            runtime_incarnation: Some(incarnation.clone()),
            runtime_launch: Box::new(route_runtime_launch(&incarnation)),
            stable_state: Some(StableState::Running),
            step: Box::new(step),
            require_idle: Box::new(
                cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
            ),
            updated_at_unix_ms: UnixMillis::new(1).unwrap(),
        },
        processes: Vec::new(),
        volumes: Vec::new(),
        mounts: Vec::new(),
        networks: Vec::new(),
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission: LifecycleAdmission::Open,
        routes: vec![ObservedRouteGate {
            binding: RouteGateBinding {
                workspace_id: desired.workspace_id.clone(),
                endpoint_id: endpoint.endpoint_id.clone(),
                hostname: endpoint.hostname.clone(),
                cat_id: desired.cat_id.clone(),
                node_id: desired.placement.node_id.clone(),
                runtime_incarnation: incarnation,
                route_epoch: endpoint.route_epoch,
                protocol: endpoint.protocol,
                target_port: endpoint.target_port,
            },
            gate: RouteGateState::Active,
            active_guards: 0,
            cancellation_pending: false,
            instance_count: 1,
        }],
        platform_guards: 0,
        conditions: vec![Condition::Ready {
            reason: ReadyReason::PostconditionSatisfied {
                target: RuntimeTarget::Running,
            },
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
        Ok(RuntimeDesiredEffectOutcome::refresh_inventory())
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random(value: &str) -> RandomId128 {
    RandomId128::new(value).unwrap()
}

/// blockd's serving-handoff reader rejects sticky/world-writable ancestry
/// (production state lives under /var/lib/cats), so the E2E state scratch
/// cannot sit under /tmp. The gate's ext4 target volume and the native
/// build host's relocated cargo target both satisfy the ancestor contract.
#[cfg(target_os = "linux")]
fn safe_state_scratch_parent() -> std::path::PathBuf {
    if let Some(directory) = std::env::var_os("CATS_LINUX_TARGET_DIRECTORY")
        .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
    {
        let base = std::path::Path::new(&directory).join("cutover-e2e-state-tmp");
        if std::fs::create_dir_all(&base).is_ok() {
            return base;
        }
    }
    std::path::PathBuf::from("/tmp")
}

fn node_identity(signer: &Ed25519RequestSigner) -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node_cross_component_a"),
        provider_scope: cats_api::runtime_reconciliation::ProviderScope {
            provider: Id::new("test_provider").unwrap(),
            partition: Id::new("test_partition").unwrap(),
            account_id: Id::new("test_account").unwrap(),
            region: Id::new("test_region").unwrap(),
        },
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
    let deadlines = RuntimeSpineDeadlinePolicy::new(
        cats_test_support::poll_bound(),
        cats_test_support::poll_bound(),
    )
    .unwrap()
    .deadlines_from(Instant::now())
    .unwrap();
    // Strictly wider than the step deadlines so a stuck step settles inside
    // the runner and reports precisely, instead of tripping this wrapper.
    tokio::time::timeout(
        cats_test_support::poll_bound() + Duration::from_secs(10),
        runner.run_once_with_deadlines(deadlines),
    )
    .await
    .expect("Runtime spine step exceeded its test deadline")
    .unwrap()
}

async fn route_v2_public_http_request(
    address: std::net::SocketAddr,
    hostname: &str,
    path: &str,
) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        cats_test_support::poll_bound(),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("public Gateway HTTP response exceeded its test deadline")
    .unwrap();
    response
}

async fn route_v2_read_http_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt as _;

    tokio::time::timeout(cats_test_support::poll_bound(), async {
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0, "connection closed before its HTTP head");
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return bytes;
            }
            assert!(bytes.len() <= 32 * 1024, "HTTP head exceeded test bound");
        }
    })
    .await
    .expect("HTTP head exceeded its test deadline")
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
async fn register_replacement_agent_session(
    context: &ControlContext,
    identity: &NodeIdentity,
    previous: &AgentSession,
) -> AgentSession {
    let signer = production_node_signer();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: previous.node_boot_id.clone(),
        agent_instance_id: random("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        registration_attempt_id: random("ffffffffffffffffffffffffffffffff"),
        guest_config_digest: previous.guest_config_digest.clone(),
        expected_agent_session_epoch: Some(previous.agent_session_epoch),
    };
    assert_ne!(attempt.agent_instance_id, previous.agent_instance_id);
    let body = encode_agent_registration_attempt(&attempt).unwrap();
    let proof = signer.sign(REGISTRATION_METHOD, REGISTRATION_PATH, &body);
    let response = context
        .http
        .post(format!(
            "{}{}",
            context.server.base_url(),
            REGISTRATION_PATH
        ))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
        .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
        .header(NODE_SIGNATURE_HEADER, proof.signature)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let replacement = decode_agent_session(&response.bytes().await.unwrap()).unwrap();
    let expected_epoch = Epoch::new(
        previous
            .agent_session_epoch
            .get()
            .checked_add(1)
            .expect("replacement AgentSession epoch exhausted"),
    )
    .unwrap();
    validate_registered_replacement(&replacement, &attempt, expected_epoch).unwrap();

    let fingerprint = cats_control_plane::testsupport::runtime_spine_state_fingerprint(
        &context.server.state.store,
        attempt.node_id.clone(),
    )
    .await;
    let fingerprint: serde_json::Value = serde_json::from_str(&fingerprint).unwrap();
    let current: AgentSession =
        serde_json::from_value(fingerprint["session"]["record"].clone()).unwrap();
    validate_registered_replacement(&current, &attempt, expected_epoch).unwrap();
    validate_current_session_renewal(&current, &replacement).unwrap();
    replacement
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
        && state.token_requests == state.role_requests
        && state.role_requests == state.credential_requests
    {
        state.token_requests += 1;
        HermeticImdsReply::Token
    } else if common_request_is_exact
        && method == axum::http::Method::GET
        && path_and_query == "/latest/meta-data/iam/security-credentials/"
        && exact_header(headers, token_header.clone(), IMDS_TOKEN)
        && headers.get(&ttl_header).is_none()
        && state.token_requests == state.role_requests + 1
        && state.role_requests == state.credential_requests
    {
        state.role_requests += 1;
        HermeticImdsReply::Role
    } else if common_request_is_exact
        && method == axum::http::Method::GET
        && path_and_query == IMDS_CREDENTIAL_PATH
        && exact_header(headers, token_header, IMDS_TOKEN)
        && headers.get(&ttl_header).is_none()
        && state.token_requests == state.role_requests
        && state.role_requests == state.credential_requests + 1
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
    axum::extract::State(state): axum::extract::State<Arc<HermeticS3State>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    const BUCKET_PREFIX: &str = "/cats-cross-component/";
    const MAX_OBJECT_BYTES: usize = 16 << 20;
    let (parts, body) = request.into_parts();
    let target = parts.uri.to_string();
    record_s3_request(&mut state.requests.lock().unwrap(), &parts.method, &target);
    let Some(key) = parts.uri.path().strip_prefix(BUCKET_PREFIX) else {
        return (
            StatusCode::BAD_REQUEST,
            "request escaped the hermetic bucket",
        )
            .into_response();
    };
    if key.is_empty() || parts.uri.query().is_some() {
        return (StatusCode::BAD_REQUEST, "unsupported hermetic S3 request").into_response();
    }
    let body = match axum::body::to_bytes(body, MAX_OBJECT_BYTES).await {
        Ok(body) => body.to_vec(),
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "object exceeds test bound").into_response()
        }
    };
    match parts.method {
        axum::http::Method::GET => match state.objects.lock().unwrap().get(key).cloned() {
            Some(value) => (StatusCode::OK, value).into_response(),
            None => (StatusCode::NOT_FOUND, Vec::new()).into_response(),
        },
        axum::http::Method::HEAD => {
            let status = if state.objects.lock().unwrap().contains_key(key) {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            (status, Vec::<u8>::new()).into_response()
        }
        axum::http::Method::PUT => {
            if !state.publishes_enabled.load(Ordering::SeqCst) {
                state.rejected_puts.fetch_add(1, Ordering::SeqCst);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "publishing disabled by test",
                )
                    .into_response();
            }
            let mut objects = state.objects.lock().unwrap();
            match objects.get(key) {
                Some(existing) if existing == &body => {
                    (StatusCode::PRECONDITION_FAILED, Vec::<u8>::new()).into_response()
                }
                Some(_) => (StatusCode::PRECONDITION_FAILED, Vec::<u8>::new()).into_response(),
                None => {
                    objects.insert(key.to_owned(), body);
                    (StatusCode::OK, Vec::<u8>::new()).into_response()
                }
            }
        }
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported hermetic S3 method",
        )
            .into_response(),
    }
}

#[cfg(target_os = "linux")]
fn record_s3_request(requests: &mut Vec<String>, method: &axum::http::Method, target: &str) {
    requests.push(format!("{method} {target}"));
}

#[cfg(target_os = "linux")]
fn hermetic_s3_wire_key(key: &str) -> String {
    let mut encoded = String::new();
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(target_os = "linux")]
struct HermeticAwsBoundary {
    imds: Arc<Mutex<HermeticImdsState>>,
    s3: Arc<HermeticS3State>,
    s3_endpoint: String,
    imds_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    s3_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    imds_task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    s3_task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    added_imds_address: bool,
}

#[cfg(target_os = "linux")]
struct HermeticS3State {
    requests: Mutex<Vec<String>>,
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    publishes_enabled: AtomicBool,
    rejected_puts: AtomicUsize,
}

#[cfg(target_os = "linux")]
impl HermeticAwsBoundary {
    async fn start(image_key: &str, image_manifest: &[u8]) -> Self {
        let image_object_key = hermetic_s3_wire_key(&format!("{AWS_PREFIX}/{image_key}"));
        let mut boundary = Self {
            imds: Arc::new(Mutex::new(HermeticImdsState::default())),
            s3: Arc::new(HermeticS3State {
                requests: Mutex::new(Vec::new()),
                objects: Mutex::new(BTreeMap::from([(
                    image_object_key,
                    image_manifest.to_vec(),
                )])),
                publishes_enabled: AtomicBool::new(true),
                rejected_puts: AtomicUsize::new(0),
            }),
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
        let s3 = Arc::clone(&boundary.s3);
        boundary.s3_task = Some(tokio::spawn(async move {
            axum::serve(
                s3_listener,
                axum::Router::new()
                    .fallback(hermetic_s3_handler)
                    .with_state(s3),
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

    fn set_publishes_enabled(&self, enabled: bool) {
        self.s3.publishes_enabled.store(enabled, Ordering::SeqCst);
    }

    fn put_request_count(&self) -> usize {
        self.s3
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.starts_with("PUT "))
            .count()
    }

    fn assert_exact_boundary(&self) {
        let imds = self.imds.lock().unwrap();
        assert_eq!(imds.token_requests, 2, "IMDSv2 token request cardinality");
        assert_eq!(imds.role_requests, 2, "IMDS role request cardinality");
        assert_eq!(
            imds.credential_requests, 2,
            "IMDS credential request cardinality"
        );
        assert!(
            imds.violations.is_empty(),
            "strict IMDSv2 boundary violations: {:?}",
            imds.violations
        );
        let s3_requests = self.s3.requests.lock().unwrap();
        assert!(
            s3_requests
                .iter()
                .any(|request| request.starts_with("PUT ")),
            "production blockd never published through the hermetic S3 boundary: {s3_requests:?}"
        );
        assert!(
            self.s3.rejected_puts.load(Ordering::SeqCst) > 0,
            "Relaxed pending-pack characterization never observed a rejected publish"
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
        // the IMDS cardinality, rejected-outage PUT and successful publication
        // transcript are settled.
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
        s3: Arc::new(HermeticS3State {
            requests: Mutex::new(Vec::new()),
            objects: Mutex::new(BTreeMap::new()),
            publishes_enabled: AtomicBool::new(false),
            rejected_puts: AtomicUsize::new(0),
        }),
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
        object_write_gateway: None,
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
fn production_ch_config(context: &ControlContext) -> ChConfig {
    ChConfig {
        block_direct: false,
        vmm_launcher_bin: "/opt/cats/bin/cats-vmm-launcher".into(),
        ch_bin: "/opt/cats/bin/cloud-hypervisor".into(),
        kernel: "/opt/cats/release/guest/vmlinuz".into(),
        initramfs: None,
        boot_contract: None,
        cmdline: context.release.kernel_cmdline.as_str().to_owned(),
        seed_image: None,
        // The focused gate exercises the native vhost-user process path
        // with an independent userspace frontend, without depending on a
        // host kernel NBD module or device pool.
        block_path: BlockPath::VhostUser,
        vhost_user_queues: 1,
        vhost_user_queue_size: 256,
        nbd_client_bin: "/usr/sbin/nbd-client".into(),
        nbd_devices: 64,
        ip_bin: "/usr/sbin/ip".into(),
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
    // The production loop's inventory scan acknowledges the installed
    // route-v2 ring; without a machine config the observation carries no
    // ring ACK and the G3 gate refuses to make the Node Schedulable.
    let route_public_key = cats_api::route_grant_v2::RouteGrantV2PublicKey::from_public_key_pem(
        include_bytes!("../../../tests/fixtures/route_grant_v2_public_ed25519.pem"),
    )
    .unwrap();
    assert_eq!(route_public_key.kid().as_str(), ROUTE_V2_KID);
    let route_ring =
        RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![route_public_key]).unwrap();
    let route_v2_machine = RouteV2MachineConfig::for_test(
        "127.0.0.1:0".to_owned(),
        registration.identity().node_id.clone(),
        include_bytes!("../../../control-plane/tests/fixtures/gateway_machine_ca_certificate.pem"),
        include_bytes!(
            "../../../control-plane/tests/fixtures/gateway_machine_server_certificate.pem"
        ),
        include_bytes!(
            "../../../control-plane/tests/fixtures/gateway_machine_server_private_key.pem"
        ),
        Arc::new(RouteGrantV2Verifier::new(route_ring)),
    )
    .unwrap();
    super::SignedRuntimeCutoverConfig {
        listen: "127.0.0.1:0".into(),
        route_v2_machine: Some(route_v2_machine),
        control_plane_url: context.server.base_url(),
        agent_registration: registration,
        ch_config: production_ch_config(context),
        authorized_blockd_launch,
        guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
        metering_cgroup_root: None,
        // This cross-component run predates the ObjectWrite Gateway and keeps
        // the pre-composition behavior: attachments carry no object-write
        // credential, so every publish path stays the direct object store.
        object_write_gateway: None,
        volume_data_authority: data_authority,
        volume_inventory_authority: inventory_authority,
        blob_store,
        volume_lease_duration_ms: 60_000,
        deadline_policy: RuntimeSpineDeadlinePolicy::new(
            cats_test_support::poll_bound(),
            cats_test_support::poll_bound(),
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
    let deadline = Instant::now() + cats_test_support::poll_bound();
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

fn validate_same_session_lineage(
    current: &AgentSession,
    durable_registration: &AgentSession,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        current.version == durable_registration.version
            && current.node_id == durable_registration.node_id
            && current.immutable_host_id == durable_registration.immutable_host_id
            && current.node_boot_id == durable_registration.node_boot_id
            && current.agent_instance_id == durable_registration.agent_instance_id
            && current.agent_session_epoch == durable_registration.agent_session_epoch
            && current.registration_attempt_id == durable_registration.registration_attempt_id
            && current.guest_config_digest == durable_registration.guest_config_digest,
        "current AgentSession immutable lineage differs from its durable registration"
    );
    Ok(())
}

fn validate_current_session_renewal(
    current: &AgentSession,
    durable_registration: &AgentSession,
) -> anyhow::Result<()> {
    validate_same_session_lineage(current, durable_registration)?;
    anyhow::ensure!(
        current.lease_deadline_unix_ms >= durable_registration.lease_deadline_unix_ms,
        "current AgentSession regressed the durable registration deadline"
    );
    Ok(())
}

fn validate_current_session_observation(
    current: &AgentSession,
    durable_registration: &AgentSession,
    acceptance_deadline: UnixMillis,
) -> anyhow::Result<()> {
    validate_current_session_renewal(current, durable_registration)?;
    anyhow::ensure!(
        current.lease_deadline_unix_ms == acceptance_deadline,
        "current AgentSession deadline is not bound to the same observation acceptance"
    );
    Ok(())
}

fn validate_registered_replacement(
    replacement: &AgentSession,
    attempt: &AgentRegistrationAttempt,
    expected_epoch: Epoch,
) -> anyhow::Result<()> {
    let attempt_epoch = attempt
        .expected_agent_session_epoch
        .and_then(|epoch| epoch.get().checked_add(1))
        .and_then(Epoch::new);
    anyhow::ensure!(
        attempt_epoch == Some(expected_epoch)
            && replacement.version == attempt.version
            && replacement.node_id == attempt.node_id
            && replacement.immutable_host_id == attempt.immutable_host_id
            && replacement.node_boot_id == attempt.node_boot_id
            && replacement.agent_instance_id == attempt.agent_instance_id
            && replacement.agent_session_epoch == expected_epoch
            && replacement.registration_attempt_id == attempt.registration_attempt_id
            && replacement.guest_config_digest == attempt.guest_config_digest,
        "replacement AgentSession is not bound to the complete submitted registration attempt"
    );
    Ok(())
}

fn durable_registration_fixture() -> AgentSession {
    decode_agent_session(
        br#"{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","immutable_host_id":"host_a","lease_deadline_unix_ms":1720000060000,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","registration_attempt_id":"55555555555555555555555555555555","version":1}"#,
    )
    .unwrap()
}

#[test]
fn same_session_lineage_allows_control_lease_renewal() {
    let durable_registration = durable_registration_fixture();
    let mut renewed_current = durable_registration.clone();
    renewed_current.lease_deadline_unix_ms = UnixMillis::new(1_720_000_065_000).unwrap();

    validate_current_session_observation(
        &renewed_current,
        &durable_registration,
        renewed_current.lease_deadline_unix_ms,
    )
    .unwrap();
}

#[test]
fn current_session_observation_rejects_deadline_regression() {
    let durable_registration = durable_registration_fixture();
    let mut regressed_current = durable_registration.clone();
    regressed_current.lease_deadline_unix_ms = UnixMillis::new(1_720_000_059_999).unwrap();

    let error = validate_current_session_observation(
        &regressed_current,
        &durable_registration,
        regressed_current.lease_deadline_unix_ms,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("regressed the durable registration deadline"),
        "unexpected validation error: {error:#}"
    );
}

#[test]
fn current_session_observation_rejects_registration_attempt_mismatch() {
    let durable_registration = durable_registration_fixture();
    let mut wrong_attempt = durable_registration.clone();
    wrong_attempt.registration_attempt_id = random("66666666666666666666666666666666");

    let error = validate_current_session_observation(
        &wrong_attempt,
        &durable_registration,
        wrong_attempt.lease_deadline_unix_ms,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("immutable lineage"),
        "unexpected validation error: {error:#}"
    );
}

#[test]
fn replacement_session_rejects_wrong_attempt_node_boot_or_digest() {
    let session = durable_registration_fixture();
    let attempt = AgentRegistrationAttempt {
        version: session.version,
        node_id: session.node_id.clone(),
        immutable_host_id: session.immutable_host_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        registration_attempt_id: session.registration_attempt_id.clone(),
        guest_config_digest: session.guest_config_digest.clone(),
        expected_agent_session_epoch: Some(Epoch::new(1).unwrap()),
    };
    validate_registered_replacement(&session, &attempt, Epoch::new(2).unwrap()).unwrap();

    let reject = |candidate: &AgentSession, field: &str| {
        let error = validate_registered_replacement(candidate, &attempt, Epoch::new(2).unwrap())
            .unwrap_err();
        assert!(
            error.to_string().contains("submitted registration attempt"),
            "wrong {field} produced an unexpected validation error: {error:#}"
        );
    };

    let mut wrong_attempt = session.clone();
    wrong_attempt.registration_attempt_id = random("66666666666666666666666666666666");
    reject(&wrong_attempt, "registration attempt");

    let mut wrong_node = session.clone();
    wrong_node.node_id = id("node_b");
    reject(&wrong_node, "node");

    let mut wrong_boot = session.clone();
    wrong_boot.node_boot_id = NodeBootId::new("77777777777777777777777777777777").unwrap();
    reject(&wrong_boot, "boot");

    let mut wrong_digest = session;
    wrong_digest.guest_config_digest = Sha256Digest::from_bytes([0x88; 32]);
    reject(&wrong_digest, "guest digest");
}

#[cfg(target_os = "linux")]
async fn wait_for_initial_empty_inventory(
    context: &ControlContext,
    state_path: &std::path::Path,
    identity: &NodeIdentity,
    handle: &super::SignedRuntimeCutoverHandle,
) -> (AgentSession, AgentSession, Epoch) {
    let deadline = Instant::now() + cats_test_support::poll_bound();
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
            validate_same_session_lineage(&session, &durable_session).unwrap();
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

            validate_current_session_observation(
                &session,
                &durable_session,
                acceptance.lease_deadline_unix_ms,
            )
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
            return (session, durable_session, full.inventory_epoch);
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
    let deadline = Instant::now() + cats_test_support::poll_bound();
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
    match tokio::time::timeout(cats_test_support::poll_bound(), reached.recv()).await {
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
async fn next_local_contract_stop(
    steps: &mut tokio::sync::mpsc::UnboundedReceiver<super::RuntimeEffectStepForTest>,
    cat_id: &Id,
    phase: &'static str,
) {
    // Every effect round re-validates the running serving writer before its
    // step logic, so a round that fails closed may first re-emit the exact
    // adoption event for this same Cat; skip that re-validation noise.
    let event = loop {
        let event = tokio::time::timeout(cats_test_support::poll_bound(), steps.recv())
            .await
            .unwrap_or_else(|_| panic!("production effect did not settle during {phase}"))
            .unwrap_or_else(|| panic!("production effect-step observer closed during {phase}"));
        if event
            != (super::RuntimeEffectStepForTest::ServingAdopted {
                cat_id: cat_id.clone(),
            })
        {
            break event;
        }
    };
    assert_eq!(
        event,
        super::RuntimeEffectStepForTest::Stopped {
            cat_id: cat_id.clone(),
            reason: crate::runtime_spine::RuntimeDesiredEffectStopReason::LocalContract,
        },
        "production effect did not fail closed on the exact local contract during {phase}"
    );
}

#[cfg(target_os = "linux")]
async fn next_serving_adopted(
    steps: &mut tokio::sync::mpsc::UnboundedReceiver<super::RuntimeEffectStepForTest>,
    cat_id: &Id,
    phase: &'static str,
) {
    let event = tokio::time::timeout(cats_test_support::poll_bound(), steps.recv())
        .await
        .unwrap_or_else(|_| panic!("serving adoption did not settle during {phase}"))
        .unwrap_or_else(|| panic!("serving-adoption observer closed during {phase}"));
    assert_eq!(
        event,
        super::RuntimeEffectStepForTest::ServingAdopted {
            cat_id: cat_id.clone(),
        },
        "production serving stage did not reach its exact Ok(None) adoption during {phase}"
    );
}

#[cfg(target_os = "linux")]
async fn next_refresh_inventory(
    steps: &mut tokio::sync::mpsc::UnboundedReceiver<super::RuntimeEffectStepForTest>,
    cat_id: &Id,
    phase: &'static str,
) {
    let event = tokio::time::timeout(cats_test_support::poll_bound(), steps.recv())
        .await
        .unwrap_or_else(|_| panic!("production effect did not settle during {phase}"))
        .unwrap_or_else(|| panic!("production effect-step observer closed during {phase}"));
    assert_eq!(
        event,
        super::RuntimeEffectStepForTest::RefreshInventory {
            cat_id: cat_id.clone(),
        },
        "production effect did not require a fresh full inventory during {phase}"
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
async fn hold_after_exact_serving_process_observation(
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
            if let [runtime] = full.runtimes.as_slice() {
                if &runtime.cat_id == cat_id {
                    if let ReconcileStep::PrepareDevice { devices }
                    | ReconcileStep::PrepareNetwork { devices, .. } = &runtime.step
                    {
                        if let ([device], [process]) =
                            (devices.as_slice(), runtime.processes.as_slice())
                        {
                            let process_matches = process.state == ProcessState::Running
                                && process.control_handshake == ControlHandshakeEvidence::Verified
                                && process.scope_id == device.serving_process.scope_id
                                && process.control_socket_path
                                    == device.serving_process.control_socket_path
                                && process.executable_path
                                    == device.serving_process.executable_path
                                && process.ownership_token
                                    == OwnershipTokenEvidence::Valid {
                                        ownership_token: device
                                            .serving_process
                                            .process_identity_token
                                            .clone(),
                                    }
                                && process.role
                                    == ProcessRole::Blockd {
                                        volume_id: device.volume_id.clone(),
                                        attachment_id: device.attachment_id.clone(),
                                        attachment_epoch: device.attachment_epoch,
                                    };
                            let lineage_matches = matches!(runtime.volumes.as_slice(), [volume]
                                if volume.volume_id == device.volume_id
                                    && matches!(volume.local_lineages.as_slice(), [lineage]
                                        if lineage.attachment_id == device.attachment_id
                                            && lineage.attachment_epoch == device.attachment_epoch
                                            && lineage.state == LocalLineageState::Active));
                            if process_matches && lineage_matches {
                                return fingerprint;
                            }
                        }
                    }
                }
            }
        }
        resume
            .send(())
            .expect("production observation barrier resume receiver dropped");
    }
}

#[cfg(target_os = "linux")]
fn blockd_control_command(control_socket: &HostPath, command: BlockdControlCommand) -> String {
    use std::io::{BufRead as _, BufReader, Write as _};

    let mut stream = std::os::unix::net::UnixStream::connect(control_socket.as_str())
        .expect("connect exact serving blockd control socket");
    stream
        .set_read_timeout(Some(cats_test_support::poll_bound()))
        .unwrap();
    stream
        .set_write_timeout(Some(cats_test_support::poll_bound()))
        .unwrap();
    writeln!(stream, "{}", command.as_wire()).unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    match BlockdControlResponse::parse_wire(&response).unwrap() {
        BlockdControlResponse::Ok(payload) => payload,
        BlockdControlResponse::Error(message) => {
            panic!("serving blockd {command} failed: {message}")
        }
    }
}

#[cfg(target_os = "linux")]
fn serving_status(control_socket: &HostPath) -> DurabilityStatus {
    serde_json::from_str(&blockd_control_command(
        control_socket,
        BlockdControlCommand::Status,
    ))
    .expect("decode exact serving blockd status")
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Retained for the wire-expressible fault-injection redesign tracked in
// DEFERRED.md.
#[allow(dead_code)]
enum ServingObservationFault {
    WrongAcquireOrigin,
    WrongAuthorityHead,
}

#[cfg(target_os = "linux")]
struct FaultInjectingServingScanner {
    installed: Arc<dyn RuntimeInventoryScanner>,
    cat_id: Id,
    volume_id: Id,
    armed: Mutex<Option<ServingObservationFault>>,
    applied: AtomicUsize,
}

#[cfg(target_os = "linux")]
impl FaultInjectingServingScanner {
    fn new(installed: Arc<dyn RuntimeInventoryScanner>, cat_id: Id, volume_id: Id) -> Self {
        Self {
            installed,
            cat_id,
            volume_id,
            armed: Mutex::new(None),
            applied: AtomicUsize::new(0),
        }
    }

    // Retained for the wire-expressible fault-injection redesign tracked in
    // DEFERRED.md; the current negatives are descoped because the wire
    // contract already rejects them client-side.
    #[allow(dead_code)]
    fn arm(&self, fault: ServingObservationFault) {
        let mut armed = self.armed.lock().unwrap();
        assert!(
            armed.replace(fault).is_none(),
            "scanner fault already armed"
        );
    }

    fn applied(&self) -> usize {
        self.applied.load(Ordering::SeqCst)
    }
}

#[cfg(target_os = "linux")]
impl crate::runtime_spine::inventory_scanner_sealed::Sealed for FaultInjectingServingScanner {}

#[cfg(target_os = "linux")]
impl RuntimeInventoryScanner for FaultInjectingServingScanner {
    fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
        let mut outcome = self.installed.scan_complete(context)?;
        let fault = self.armed.lock().unwrap().take();
        let Some(fault) = fault else {
            return Ok(outcome);
        };
        let RuntimeInventoryScanOutcome::Complete(inventory) = &mut outcome else {
            anyhow::bail!("armed serving observation fault reached an incomplete installed scan")
        };
        let runtime = inventory
            .runtimes_mut_for_test()
            .iter_mut()
            .find(|runtime| runtime.cat_id == self.cat_id)
            .context("armed serving observation fault lacks its Cat")?;
        let volume = runtime
            .volumes
            .iter_mut()
            .find(|volume| volume.volume_id == self.volume_id)
            .context("armed serving observation fault lacks its Volume")?;
        let [lineage] = volume.local_lineages.as_mut_slice() else {
            anyhow::bail!("armed serving observation fault lacks one exact lineage")
        };
        match fault {
            ServingObservationFault::WrongAcquireOrigin => {
                lineage.acquire_origin = AcquireOrigin::Takeover {
                    authorization_id: id("wrong_origin_authorization"),
                };
            }
            ServingObservationFault::WrongAuthorityHead => {
                let VolumeAuthorityEvidence::Owned { head, .. } = &mut volume.authority else {
                    anyhow::bail!("armed authority-head fault lacks Owned authority")
                };
                let wrong =
                    Generation::new(head.generation.get().checked_add(1).context(
                        "armed authority-head fault exhausted the generation coordinate",
                    )?)
                    .context("armed authority-head fault exceeded the wire generation range")?;
                head.generation = wrong;
                lineage.local_durable_generation = wrong;
                lineage.remote_durable_generation = wrong;
            }
        }
        self.applied.fetch_add(1, Ordering::SeqCst);
        Ok(outcome)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct AcceptedFullFingerprint {
    session: AgentSession,
    acceptance: ObservationAcceptance,
    attestation: AdmissionInventoryAttestation,
    assigned: DesiredReadSnapshot,
    full: NodeObservation,
}

#[cfg(target_os = "linux")]
impl AcceptedFullFingerprint {
    fn decode(fingerprint: &str) -> Self {
        let value: serde_json::Value = serde_json::from_str(fingerprint).unwrap();
        Self {
            session: serde_json::from_value(value["session"]["record"].clone()).unwrap(),
            acceptance: serde_json::from_value(value["receive"]["acceptance"].clone()).unwrap(),
            attestation: serde_json::from_value(value["inventory"]["attestation"].clone()).unwrap(),
            assigned: serde_json::from_value(value["inventory"]["assigned_snapshot"].clone())
                .unwrap(),
            full: serde_json::from_value(value["inventory"]["full_observation"].clone()).unwrap(),
        }
    }

    fn session_binding(&self) -> SessionBinding {
        SessionBinding {
            node_id: self.session.node_id.clone(),
            node_boot_id: self.session.node_boot_id.clone(),
            agent_instance_id: self.session.agent_instance_id.clone(),
            agent_session_epoch: self.session.agent_session_epoch,
        }
    }
}

#[cfg(target_os = "linux")]
fn host_link_named(tap_name: &Id) -> bool {
    let output = Command::new("/usr/sbin/ip")
        .args(["-j", "-d", "link", "show"])
        .output()
        .expect("inspect complete Host link inventory");
    assert!(
        output.status.success(),
        "ip failed to inspect Host links: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let links: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("decode complete Host link inventory");
    links.as_array().unwrap().iter().any(|link| {
        link.get("ifname").and_then(serde_json::Value::as_str) == Some(tap_name.as_str())
    })
}

#[cfg(target_os = "linux")]
fn observed_network(identity: &RuntimeNetworkIdentity) -> ObservedNetwork {
    ObservedNetwork {
        kind: identity.network_config.kind,
        network_id: identity.network_config.network_id.clone(),
        guest_mac: identity.network_config.guest_mac.clone(),
        guest_ipv4: identity.network_config.guest_ipv4.clone(),
        prefix_length: identity.network_config.prefix_length,
        gateway_ipv4: identity.network_config.gateway_ipv4.clone(),
        tap_name: identity.tap_name.clone(),
        ownership_token: OwnershipTokenEvidence::Valid {
            ownership_token: identity.ownership_token.clone(),
        },
    }
}

#[cfg(target_os = "linux")]
struct ExactHostNetworkCleanup {
    config: ChConfig,
    network: ChNetwork,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl ExactHostNetworkCleanup {
    fn new(context: &ControlContext, identity: &RuntimeNetworkIdentity) -> Self {
        Self {
            config: production_ch_config(context),
            network: ChNetwork {
                tap: identity.tap_name.as_str().to_owned(),
                ownership_token: identity.ownership_token.clone(),
                config: identity.network_config.clone(),
            },
            armed: true,
        }
    }

    fn remove(mut self) {
        crate::ch::remove_network(&self.config, &self.network)
            .expect("remove exact focused-test Host TAP");
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for ExactHostNetworkCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = crate::ch::remove_network(&self.config, &self.network);
        }
    }
}

#[cfg(target_os = "linux")]
fn assert_reserved_network_absent(
    snapshot: &AcceptedFullFingerprint,
    cat_id: &Id,
    identity: &RuntimeNetworkIdentity,
    expected_process: &ProcessEvidence,
    phase: &'static str,
) {
    assert!(
        snapshot.full.residue.is_empty(),
        "{phase} reported physical residue"
    );
    let [runtime] = snapshot.full.runtimes.as_slice() else {
        panic!("{phase} did not contain exactly one Runtime")
    };
    assert_eq!(&runtime.cat_id, cat_id, "{phase} reported another Cat");
    assert!(
        runtime.networks.is_empty(),
        "{phase} observed a reserved TAP before the validated physical effect"
    );
    assert_eq!(
        runtime.processes.as_slice(),
        std::slice::from_ref(expected_process),
        "{phase} changed the serving PID/start evidence"
    );
    assert!(
        !host_link_named(&identity.tap_name),
        "{phase} left the reserved Host TAP present"
    );
}

#[cfg(target_os = "linux")]
fn assert_current_signed_full_envelope(
    snapshot: &AcceptedFullFingerprint,
    durable_registration: &AgentSession,
    expected_desired: &DesiredRuntimeSpec,
) {
    validate_current_session_observation(
        &snapshot.session,
        durable_registration,
        snapshot.acceptance.lease_deadline_unix_ms,
    )
    .unwrap();
    let expected_session = SessionBinding {
        node_id: durable_registration.node_id.clone(),
        node_boot_id: durable_registration.node_boot_id.clone(),
        agent_instance_id: durable_registration.agent_instance_id.clone(),
        agent_session_epoch: durable_registration.agent_session_epoch,
    };
    assert_eq!(snapshot.acceptance.version, ContractVersion::V1);
    assert_eq!(snapshot.acceptance.session, expected_session);
    assert_eq!(
        snapshot.acceptance.observation_id,
        snapshot.full.observation_id
    );
    assert_eq!(
        snapshot.acceptance.heartbeat_sequence,
        snapshot.full.heartbeat_sequence
    );
    assert_eq!(
        snapshot.acceptance.inventory,
        ObservationInventoryAcceptance::Full {
            attestation: snapshot.attestation.clone(),
        }
    );
    assert_eq!(snapshot.attestation.version, ContractVersion::V1);
    assert_eq!(snapshot.attestation.node_id, expected_session.node_id);
    assert_eq!(
        snapshot.attestation.agent_session_epoch,
        expected_session.agent_session_epoch
    );
    assert_eq!(
        snapshot.attestation.inventory_epoch,
        snapshot.full.inventory_epoch
    );
    assert_eq!(
        snapshot.full.inventory_digest,
        Some(snapshot.attestation.inventory_digest.clone())
    );
    assert_eq!(
        snapshot.full.inventory_digest,
        Some(inventory_digest(&snapshot.full).unwrap())
    );
    assert_eq!(
        snapshot.full.inventory_read_position,
        Some(snapshot.attestation.inventory_read_position)
    );
    assert_eq!(snapshot.assigned.version, ContractVersion::V1);
    assert_eq!(snapshot.assigned.session, expected_session);
    assert_eq!(
        snapshot.assigned.read_position,
        snapshot.attestation.inventory_read_position
    );
    assert_eq!(
        snapshot.assigned.desired_specs.as_slice(),
        std::slice::from_ref(expected_desired)
    );
    assert!(snapshot.full.complete_inventory);
    assert_eq!(snapshot.full.node_id, expected_session.node_id);
    assert_eq!(snapshot.full.node_boot_id, expected_session.node_boot_id);
    assert_eq!(
        snapshot.full.agent_instance_id,
        expected_session.agent_instance_id
    );
    assert_eq!(
        snapshot.full.agent_session_epoch,
        expected_session.agent_session_epoch
    );
}

#[cfg(target_os = "linux")]
// Keep every adoption coordinate explicit at each call site: omitting one is
// exactly the false-positive failure this acceptance oracle guards against.
#[allow(clippy::too_many_arguments)]
fn validate_exact_serving_full_observation(
    snapshot: &AcceptedFullFingerprint,
    expected_identity: &NodeIdentity,
    durable_registration: &AgentSession,
    expected_desired: &DesiredRuntimeSpec,
    expected_checkpoint_path: &std::path::Path,
    expected_checkpoint: &RuntimeCheckpoint,
    expected_process: &ProcessEvidence,
    expected_device: &PreparedDeviceInput,
    expected_authority_head: &RemoteHead,
    expected_local_generation: Generation,
    expected_remote_generation: Generation,
    expected_pending_packs: u64,
) -> anyhow::Result<()> {
    validate_current_session_observation(
        &snapshot.session,
        durable_registration,
        snapshot.acceptance.lease_deadline_unix_ms,
    )
    .context("accepted serving observation has invalid AgentSession renewal evidence")?;
    let current_session = snapshot.session_binding();
    anyhow::ensure!(
        snapshot.session.version == ContractVersion::V1
            && snapshot.session.node_id == expected_identity.node_id
            && snapshot.session.immutable_host_id == expected_identity.immutable_host_id
            && snapshot.session.guest_config_digest == expected_desired.runtime.guest_config_digest,
        "accepted full fingerprint is not bound to the current Agent session"
    );
    anyhow::ensure!(
        snapshot.acceptance.version == ContractVersion::V1
            && snapshot.acceptance.session == current_session
            && snapshot.acceptance.observation_id == snapshot.full.observation_id
            && snapshot.acceptance.heartbeat_sequence == snapshot.full.heartbeat_sequence
            && snapshot.acceptance.inventory
                == ObservationInventoryAcceptance::Full {
                    attestation: snapshot.attestation.clone(),
                },
        "accepted full fingerprint has a stale or partial acceptance"
    );
    anyhow::ensure!(
        snapshot.attestation.version == ContractVersion::V1
            && snapshot.attestation.node_id == current_session.node_id
            && snapshot.attestation.agent_session_epoch == current_session.agent_session_epoch
            && snapshot.attestation.inventory_epoch == snapshot.full.inventory_epoch
            && snapshot.full.inventory_digest.as_ref()
                == Some(&snapshot.attestation.inventory_digest)
            && snapshot.full.inventory_digest == Some(inventory_digest(&snapshot.full)?)
            && snapshot.full.inventory_read_position
                == Some(snapshot.attestation.inventory_read_position)
            && snapshot.assigned.read_position == snapshot.attestation.inventory_read_position,
        "full inventory attestation coordinates are not exact"
    );
    anyhow::ensure!(
        snapshot.assigned.version == ContractVersion::V1
            && snapshot.assigned.session == current_session
            && snapshot.assigned.desired_specs.as_slice() == std::slice::from_ref(expected_desired),
        "accepted full fingerprint is not bound to the exact assigned Desired"
    );
    anyhow::ensure!(
        snapshot.full.version == ContractVersion::V1
            && snapshot.full.complete_inventory
            && snapshot.full.node_id == current_session.node_id
            && snapshot.full.node_boot_id == current_session.node_boot_id
            && snapshot.full.agent_instance_id == current_session.agent_instance_id
            && snapshot.full.agent_session_epoch == current_session.agent_session_epoch
            && snapshot.full.inventory_epoch.get() > 0
            && snapshot.full.inventory_read_position.is_some()
            && snapshot.full.residue.is_empty(),
        "serving observation is not a complete, residue-free current-session inventory"
    );

    let [runtime] = snapshot.full.runtimes.as_slice() else {
        anyhow::bail!("serving observation must contain exactly one Runtime")
    };
    let network_projection_is_exact = match &expected_checkpoint.step {
        ReconcileStep::PrepareDevice { .. } => runtime.networks.is_empty(),
        ReconcileStep::PrepareNetwork { network, .. } => {
            runtime.networks.is_empty() || runtime.networks == vec![observed_network(network)]
        }
        _ => false,
    };
    anyhow::ensure!(
        runtime.cat_id == expected_desired.cat_id
            && runtime.applied_desired.as_ref()
                == Some(&AppliedDesiredEvidence {
                    desired_revision: expected_desired.desired_revision,
                    spec_digest: expected_desired.spec_digest.clone(),
                    placement: expected_desired.placement.clone(),
                    target: expected_desired.target,
                })
            && runtime.runtime_incarnation == expected_checkpoint.runtime_incarnation
            && runtime.stable_state == expected_checkpoint.stable_state
            && runtime.step == expected_checkpoint.step
            && runtime.mounts.is_empty()
            && network_projection_is_exact
            && runtime.guest_transport == GuestTransportEvidence::Unavailable
            && runtime.warm_snapshot == WarmSnapshotEvidence::Absent
            && runtime.lifecycle_admission == LifecycleAdmission::Closed
            && runtime.routes.is_empty()
            && runtime.platform_guards == 0,
        "serving Runtime projection is not the exact pre-launch checkpoint"
    );
    anyhow::ensure!(
        runtime
            .conditions
            .iter()
            .any(|condition| matches!(condition,
            Condition::Progressing {
                reason: ProgressingReason::ReconcileStep { step }
            } if step == &expected_checkpoint.step))
            && runtime.conditions.iter().all(|condition| !matches!(
                condition,
                Condition::Blocked { .. }
                    | Condition::Quarantined { .. }
                    | Condition::Degraded { .. }
                    | Condition::PreconditionFailed { .. }
                    | Condition::DataLossPossible { .. }
            )),
        "serving Runtime is blocked, quarantined, or lacks exact progress evidence"
    );
    let CheckpointEvidence::Valid {
        checkpoint_path,
        content_digest,
        version,
        cat_id,
        node_id,
        desired_revision,
        spec_digest: observed_spec_digest,
        placement_epoch,
        runtime_incarnation,
        runtime_launch,
        stable_state,
        step,
        require_idle,
        updated_at_unix_ms,
    } = &runtime.checkpoint
    else {
        anyhow::bail!("serving Runtime lacks a valid checkpoint digest")
    };
    anyhow::ensure!(
        std::path::Path::new(checkpoint_path.as_str()) == expected_checkpoint_path
            && content_digest == &checkpoint_content_digest(expected_checkpoint)?
            && *version == expected_checkpoint.version
            && cat_id == &expected_checkpoint.cat_id
            && node_id == &expected_checkpoint.node_id
            && *desired_revision == expected_checkpoint.desired_revision
            && observed_spec_digest == &expected_checkpoint.spec_digest
            && *placement_epoch == expected_checkpoint.placement_epoch
            && runtime_incarnation == &expected_checkpoint.runtime_incarnation
            && runtime_launch.as_ref() == &expected_checkpoint.runtime_launch
            && stable_state == &expected_checkpoint.stable_state
            && step.as_ref() == &expected_checkpoint.step
            && require_idle.as_ref() == &expected_checkpoint.require_idle
            && *updated_at_unix_ms == expected_checkpoint.updated_at_unix_ms,
        "serving checkpoint evidence is not the exact durable checkpoint"
    );

    anyhow::ensure!(
        runtime.processes.as_slice() == std::slice::from_ref(expected_process)
            && expected_process.process_id > 0
            && expected_process.process_start_time_ticks.get() > 0
            && expected_process.state == ProcessState::Running
            && expected_process.control_handshake == ControlHandshakeEvidence::Verified
            && expected_process.scope_id == expected_device.serving_process.scope_id
            && expected_process.control_socket_path
                == expected_device.serving_process.control_socket_path
            && expected_process.executable_path == expected_device.serving_process.executable_path
            && expected_process.ownership_token
                == OwnershipTokenEvidence::Valid {
                    ownership_token: expected_device
                        .serving_process
                        .process_identity_token
                        .clone(),
                }
            && expected_process.role
                == ProcessRole::Blockd {
                    volume_id: expected_device.volume_id.clone(),
                    attachment_id: expected_device.attachment_id.clone(),
                    attachment_epoch: expected_device.attachment_epoch,
                },
        "serving process is not the exact retained PID/start/role/epoch/token"
    );

    let [intent] = expected_desired.volumes.as_slice() else {
        anyhow::bail!("focused serving Desired must contain exactly one volume")
    };
    let [volume] = runtime.volumes.as_slice() else {
        anyhow::bail!("serving observation must contain exactly one volume")
    };
    anyhow::ensure!(
        intent.access == VolumeAccess::ReadWriteOnce
            && intent.disposition == VolumeDisposition::Retain
            && intent.mount.is_none()
            && expected_device.volume_intent_id == intent.volume_intent_id
            && expected_device.disk_id == intent.disk_id
            && expected_device.volume_id == intent.volume_id
            && expected_device.disk_kind == intent.disk_kind
            && expected_device.attachment_id == intent.attachment_id
            && expected_device.size_bytes == intent.size_bytes
            && expected_device.durability == intent.durability
            && expected_device.guest_device == intent.guest_device
            && match (&intent.acquire, &expected_device.acquire_origin) {
                (
                    VolumeAcquire::Normal { transition_id, .. },
                    AcquireOrigin::Normal {
                        transition_id: origin,
                    },
                ) => transition_id == origin,
                (
                    VolumeAcquire::Takeover { authorization_id },
                    AcquireOrigin::Takeover {
                        authorization_id: origin,
                    },
                ) => authorization_id == origin,
                _ => false,
            },
        "prepared serving device is not the complete Desired volume contract"
    );
    anyhow::ensure!(
        volume.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
            && volume.disk_id.as_ref() == Some(&intent.disk_id)
            && volume.volume_id == intent.volume_id
            && volume.disk_kind
                == match intent.disk_kind {
                    DiskKind::Root => ObservedDiskKind::Root,
                    DiskKind::Persistent => ObservedDiskKind::Persistent,
                }
            && volume.size_bytes == Some(intent.size_bytes)
            && volume.durability == Some(intent.durability)
            && volume.authority
                == VolumeAuthorityEvidence::Owned {
                    attachment_id: expected_device.attachment_id.clone(),
                    attachment_epoch: expected_device.attachment_epoch,
                    head: expected_authority_head.clone(),
                },
        "observed volume IDs/kind/size/durability/Owned authority are not exact"
    );
    let [lineage] = volume.local_lineages.as_slice() else {
        anyhow::bail!("serving observation must contain one exact local lineage")
    };
    anyhow::ensure!(
        lineage.attachment_id == expected_device.attachment_id
            && lineage.attachment_epoch == expected_device.attachment_epoch
            && lineage.acquire_origin == expected_device.acquire_origin
            && lineage.node_id == expected_desired.placement.node_id
            && lineage.placement_epoch == expected_desired.placement.placement_epoch
            && lineage.local_durable_generation == expected_local_generation
            && lineage.remote_durable_generation == expected_remote_generation
            && lineage.data_directory == expected_device.serving_process.data_directory
            && lineage.pending_pack_count.get() == expected_pending_packs
            && !lineage.fenced
            && lineage.state == LocalLineageState::Active,
        "local lineage origin/node/placement/data-dir/fence/generations are not exact"
    );
    let [observed_device] = volume.devices.as_slice() else {
        anyhow::bail!("serving observation must contain one exact frontend device")
    };
    anyhow::ensure!(
        matches!((&expected_device.frontend, observed_device),
            (PrepareDeviceFrontend::VhostUserBlk { socket_path, .. }, ObservedDevice::VhostUserBlk {
                guest_device,
                socket_path: observed_socket,
                ownership_token: OwnershipTokenEvidence::Valid { ownership_token },
            }) if guest_device == &expected_device.guest_device
                && observed_socket == socket_path
                && ownership_token == &expected_device.ownership_token),
        "serving frontend attachment/token is not exact"
    );
    Ok(())
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
        Instant::now() + cats_test_support::poll_bound(),
    );
    let scanner = Arc::clone(scanner);
    // Strictly wider than the scan-context deadline so a stuck scan settles
    // as an Incomplete outcome instead of tripping this wrapper.
    let outcome = tokio::time::timeout(
        cats_test_support::poll_bound() + Duration::from_secs(10),
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
async fn wait_for_installed_serving_process_state(
    scanner: &Arc<dyn RuntimeInventoryScanner>,
    cursor: &mut InstalledScanCursor,
    cat_id: &Id,
    volume_id: &Id,
    expect_live: bool,
) -> (NodeObservation, NodeGlobalManagedProcessAdmission) {
    let deadline = Instant::now() + cats_test_support::poll_bound();
    loop {
        if let Some((observation, admission)) = next_installed_process_scan(scanner, cursor).await {
            let matching = admission
                .serving_blockd(cat_id, volume_id)
                .is_some_and(|(_, exact)| exact.is_some() == expect_live);
            if matching {
                return (observation, admission);
            }
        }
        assert!(
            Instant::now() < deadline,
            "installed scanner did not observe serving process live={expect_live}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
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
async fn postgres_control_and_production_cutover_adopts_serving_relaxed_pending_pack_across_restart(
) {
    // The uncordon below crosses the G3 gate: Schedulable requires the Node's
    // accepted inventory to acknowledge the published route-v2 ring, which
    // exists only when the control spawns with the route-v2 machine.
    let context = ControlContext::spawn_route_v2().await;
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
        .tempdir_in(safe_state_scratch_parent())
        .unwrap();
    let state_path = state_parent.path().join("state");
    let aws = HermeticAwsBoundary::start(&context.image_blob.key, &context.image_blob.body).await;
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
    let (initial_session, initial_durable_registration, initial_inventory_epoch) =
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
    {
        let admission_workspace =
            cats_api::runtime_reconciliation::Id::new(workspace.id.clone()).unwrap();
        tokio::task::block_in_place(|| {
            cats_control_plane::testsupport::begin_production_qualification_for_product_test(
                &context.server.state.store,
                &admission_workspace,
            );
        });
    }
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
        .body(RELAXED_CAT_CREATE_BODY.to_vec())
        .send()
        .await
        .unwrap();
    let create_body = json_body(create, StatusCode::ACCEPTED).await;
    let created = decode_cat_create_v2_accepted_response(&create_body).unwrap();
    let create_request: CatCreateV2Request =
        serde_json::from_slice(RELAXED_CAT_CREATE_BODY).unwrap();
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
    let first_acceptance: ObservationAcceptance =
        serde_json::from_value(first_fingerprint["receive"]["acceptance"].clone()).unwrap();
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
    validate_current_session_observation(
        &first_session,
        &initial_durable_registration,
        first_acceptance.lease_deadline_unix_ms,
    )
    .unwrap();
    assert!(
        first_session.lease_deadline_unix_ms >= initial_session.lease_deadline_unix_ms,
        "first assigned observation regressed the initial accepted deadline"
    );
    assert_eq!(
        first_session.lease_deadline_unix_ms, first_acceptance.lease_deadline_unix_ms,
        "first assigned Control deadline is not bound to its observation receipt"
    );
    assert_eq!(
        first_acceptance.observation_id, first_full.observation_id,
        "first assigned acceptance is not bound to its full observation"
    );
    assert_eq!(
        first_acceptance.heartbeat_sequence, first_full.heartbeat_sequence,
        "first assigned acceptance is not bound to its heartbeat sequence"
    );
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
    assert_eq!(
        create_request.durability,
        Durability::Relaxed,
        "the N6 restart-adoption fixture must exercise unique Relaxed pending data"
    );
    assert_eq!(root.durability, create_request.durability);
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
    let restarted_state = StateDirectory::unanchored(state_path.clone());
    let restarted_launch = production_authorized_blockd_launch(&context, &restarted_state, &aws);
    let restarted_probe = production_installed_probe_config(
        restarted_state.clone(),
        authority.clone(),
        node_image_blob.clone(),
        restarted_launch,
    );
    let restarted_installed = installed_clean_slate_scanner(
        restarted_probe,
        AdmissionCellRegistry::for_state_directory(&restarted_state),
        None,
    )
    .unwrap();
    let faulting_scanner = Arc::new(FaultInjectingServingScanner::new(
        restarted_installed,
        created.cat_id.clone(),
        volume_id.clone(),
    ));
    let restarted_scanner: Arc<dyn RuntimeInventoryScanner> = faulting_scanner.clone();
    let (
        restart_observation_barrier,
        mut restart_observations,
        restart_observation_resume,
        mut restart_effect_steps,
        restart_effect_dispatches,
    ) = super::RuntimeObservationBarrierForTest::channel_with_effect_steps();
    let restarted = super::spawn_signed_runtime_cutover_with_scanner(
        production_cutover_config(
            &context,
            restarted_registration,
            authority.clone(),
            node_image_blob.clone(),
            &aws,
            restart_observation_barrier,
        ),
        Some(restarted_scanner),
        None,
    )
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

    let restarted_durable_registration = decode_agent_session(
        &std::fs::read(state_path.join(crate::agent_registration::SESSION_RELATIVE_PATH)).unwrap(),
    )
    .unwrap();
    let restart_admission = AcceptedFullFingerprint::decode(&restart_fingerprint);
    assert_current_signed_full_envelope(
        &restart_admission,
        &restarted_durable_registration,
        desired,
    );
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

    // Let the adopted Root control process finish the immutable image handoff,
    // then stop at an accepted full inventory which proves the exact serving
    // process. This is the first point where Guest I/O is authorized.
    restart_observation_resume
        .send(())
        .expect("resume adopted Root process toward serving handoff");
    let serving_fingerprint = hold_after_exact_serving_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &restarted,
        &mut restart_observations,
        &restart_observation_resume,
        "adopted cutover exact serving-process observation",
    )
    .await;
    let prepare_device_admission = AcceptedFullFingerprint::decode(&serving_fingerprint);
    let serving_fingerprint: serde_json::Value =
        serde_json::from_str(&serving_fingerprint).unwrap();
    let serving_full: NodeObservation =
        serde_json::from_value(serving_fingerprint["inventory"]["full_observation"].clone())
            .unwrap();
    let serving_assigned: DesiredReadSnapshot =
        serde_json::from_value(serving_fingerprint["inventory"]["assigned_snapshot"].clone())
            .unwrap();
    let [serving_desired] = serving_assigned.desired_specs.as_slice() else {
        panic!("serving assignment must contain exactly the created Desired")
    };
    let serving_desired = serving_desired.clone();
    assert_current_signed_full_envelope(
        &prepare_device_admission,
        &restarted_durable_registration,
        &serving_desired,
    );
    let [serving_runtime] = serving_full.runtimes.as_slice() else {
        panic!("serving inventory must contain exactly the created Cat")
    };
    let ReconcileStep::PrepareDevice { devices } = &serving_runtime.step else {
        panic!("serving inventory did not retain PrepareDevice")
    };
    let [prepared] = devices.as_slice() else {
        panic!("single-Root Cat must retain one prepared serving device")
    };
    let prepared = prepared.clone();
    let [serving_process] = serving_runtime.processes.as_slice() else {
        panic!("serving inventory must prove exactly one blockd writer")
    };
    let serving_process = serving_process.clone();
    assert_eq!(prepared.durability, Durability::Relaxed);
    let PrepareDeviceFrontend::VhostUserBlk {
        socket_path,
        queues,
        queue_size,
    } = &prepared.frontend
    else {
        panic!("focused N6 acceptance requires the native vhost-user frontend")
    };
    let prepare_device_checkpoint_bytes = std::fs::read(&checkpoint_path).unwrap();
    let prepare_device_checkpoint =
        decode_runtime_checkpoint(&prepare_device_checkpoint_bytes).unwrap();
    assert_eq!(prepare_device_checkpoint.step, serving_runtime.step);
    let prepare_device_checkpoint_identity = checkpoint_file_identity(&checkpoint_path);
    let serving_authority_before_tail = authority.load_volume(&prepared.volume_id).unwrap();
    assert_eq!(
        serving_authority_before_tail.last_transition,
        acquired.last_transition
    );

    // Establish the exact publisher-clean predecessor for the physical
    // mismatch probes. At this point the retained writer has no pending pack
    // and both local/remote generations still equal the checkpointed head.
    // This first unmodified effect proves only the PrepareDevice ->
    // PrepareNetwork reservation CAS; the calibrated physical TAP positive
    // follows both negative admissions below.
    validate_exact_serving_full_observation(
        &prepare_device_admission,
        &identity,
        &restarted_durable_registration,
        &serving_desired,
        &checkpoint_path,
        &prepare_device_checkpoint,
        &serving_process,
        &prepared,
        &serving_authority_before_tail.head,
        serving_authority_before_tail.head.generation,
        serving_authority_before_tail.head.generation,
        0,
    )
    .unwrap();
    assert_eq!(faulting_scanner.applied(), 0);
    while restart_effect_steps.try_recv().is_ok() {}
    let prepare_network_row = cats_control_plane::testsupport::runtime_volume_row_fingerprint(
        &context.server.state.store,
        prepared.volume_id.clone(),
    )
    .await;
    let prepare_network_puts = aws.put_request_count();
    let prepare_network_dispatches = restart_effect_dispatches.load(Ordering::SeqCst);

    restart_observation_resume
        .send(())
        .expect("resume clean PrepareDevice admission into PrepareNetwork");
    let prepare_network_admission_fingerprint = hold_after_exact_serving_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &restarted,
        &mut restart_observations,
        &restart_observation_resume,
        "production PrepareNetwork accepted observation",
    )
    .await;
    next_serving_adopted(
        &mut restart_effect_steps,
        &created.cat_id,
        "clean PrepareDevice serving adoption",
    )
    .await;
    next_refresh_inventory(
        &mut restart_effect_steps,
        &created.cat_id,
        "clean PrepareDevice positive control",
    )
    .await;
    assert_eq!(
        restart_effect_dispatches.load(Ordering::SeqCst),
        prepare_network_dispatches + 1,
        "clean current-session admission did not cross the runner dispatch boundary"
    );
    let prepare_network_checkpoint_bytes = std::fs::read(&checkpoint_path).unwrap();
    let prepare_network_checkpoint =
        decode_runtime_checkpoint(&prepare_network_checkpoint_bytes).unwrap();
    let ReconcileStep::PrepareNetwork {
        network: reserved_network,
        ..
    } = &prepare_network_checkpoint.step
    else {
        panic!("positive control did not persist PrepareNetwork")
    };
    let reserved_network = reserved_network.clone();
    assert_ne!(
        prepare_network_checkpoint_bytes, prepare_device_checkpoint_bytes,
        "positive control did not persist its PrepareNetwork successor"
    );
    assert_ne!(
        checkpoint_file_identity(&checkpoint_path),
        prepare_device_checkpoint_identity,
        "positive control did not atomically replace its PrepareDevice checkpoint"
    );
    assert_eq!(
        cats_control_plane::testsupport::runtime_volume_row_fingerprint(
            &context.server.state.store,
            prepared.volume_id.clone(),
        )
        .await,
        prepare_network_row,
        "PrepareNetwork checkpoint publication mutated PostgreSQL Volume authority"
    );
    assert_eq!(aws.put_request_count(), prepare_network_puts);
    assert!(std::path::Path::new(&format!("/proc/{}", serving_process.process_id)).exists());

    // The wrong-origin / wrong-head faulting negatives were descoped: the
    // NodeObservation wire contract pins a device-phase runtime's lineage
    // origin and authority head to the observed step, so neither fault is
    // expressible on the wire (the earlier contract layer subsumes the
    // effect-layer LocalContract stop this section originally asserted).
    // The scanner-side fail-closed rejection is exercised by the wire
    // contract tests; re-designing wire-expressible negatives is tracked in
    // DEFERRED.md.
    let prepare_network_admission =
        AcceptedFullFingerprint::decode(&prepare_network_admission_fingerprint);
    assert_current_signed_full_envelope(
        &prepare_network_admission,
        &restarted_durable_registration,
        &serving_desired,
    );
    assert_eq!(
        prepare_network_admission.full.runtimes[0].processes,
        vec![serving_process.clone()]
    );
    assert_reserved_network_absent(
        &prepare_network_admission,
        &created.cat_id,
        &reserved_network,
        &serving_process,
        "clean PrepareNetwork admission before dispatch",
    );
    validate_exact_serving_full_observation(
        &prepare_network_admission,
        &identity,
        &restarted_durable_registration,
        &serving_desired,
        &checkpoint_path,
        &prepare_network_checkpoint,
        &serving_process,
        &prepared,
        &serving_authority_before_tail.head,
        serving_authority_before_tail.head.generation,
        serving_authority_before_tail.head.generation,
        0,
    )
    .unwrap();

    // Resume the clean full observation, require the installed effect to
    // publish the TAP, and accept a successor scan that proves the exact
    // reserved identity. This fails if PrepareNetwork always returns
    // LocalContract or never creates the TAP.
    let clean_prepare_network_checkpoint_bytes = std::fs::read(&checkpoint_path).unwrap();
    let clean_prepare_network_checkpoint_identity = checkpoint_file_identity(&checkpoint_path);
    let clean_prepare_network_row =
        cats_control_plane::testsupport::runtime_volume_row_fingerprint(
            &context.server.state.store,
            prepared.volume_id.clone(),
        )
        .await;
    let clean_prepare_network_authority = authority.load_volume(&prepared.volume_id).unwrap();
    let clean_prepare_network_puts = aws.put_request_count();
    let clean_prepare_network_dispatches = restart_effect_dispatches.load(Ordering::SeqCst);
    let exact_network_cleanup = ExactHostNetworkCleanup::new(&context, &reserved_network);
    restart_observation_resume
        .send(())
        .expect("resume exact clean PrepareNetwork admission into TAP effect");
    let exact_network_fingerprint = hold_after_exact_serving_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &restarted,
        &mut restart_observations,
        &restart_observation_resume,
        "production exact TAP successor after mismatch rejections",
    )
    .await;
    next_serving_adopted(
        &mut restart_effect_steps,
        &created.cat_id,
        "clean PrepareNetwork serving adoption",
    )
    .await;
    next_refresh_inventory(
        &mut restart_effect_steps,
        &created.cat_id,
        "clean PrepareNetwork physical positive control",
    )
    .await;
    assert_eq!(
        restart_effect_dispatches.load(Ordering::SeqCst),
        clean_prepare_network_dispatches + 1,
        "clean PrepareNetwork admission did not cross the runner dispatch boundary"
    );

    let exact_network = AcceptedFullFingerprint::decode(&exact_network_fingerprint);
    assert_current_signed_full_envelope(
        &exact_network,
        &restarted_durable_registration,
        &serving_desired,
    );
    validate_exact_serving_full_observation(
        &exact_network,
        &identity,
        &restarted_durable_registration,
        &serving_desired,
        &checkpoint_path,
        &prepare_network_checkpoint,
        &serving_process,
        &prepared,
        &serving_authority_before_tail.head,
        serving_authority_before_tail.head.generation,
        serving_authority_before_tail.head.generation,
        0,
    )
    .unwrap();
    let [exact_network_runtime] = exact_network.full.runtimes.as_slice() else {
        panic!("exact TAP successor did not contain one Runtime")
    };
    assert_eq!(
        exact_network_runtime.networks,
        vec![observed_network(&reserved_network)],
        "successor installed scan did not prove the exact reserved TAP"
    );
    assert_eq!(
        exact_network_runtime.processes,
        vec![serving_process.clone()],
        "clean PrepareNetwork effect changed the serving PID/start"
    );
    // Calibrate the same complete Host-link probe whose earlier negative
    // results prove that neither faulty admission published this reserved TAP.
    assert!(host_link_named(&reserved_network.tap_name));
    assert!(exact_network.full.inventory_epoch > prepare_network_admission.full.inventory_epoch);
    assert_eq!(faulting_scanner.applied(), 0);
    assert_eq!(
        std::fs::read(&checkpoint_path).unwrap(),
        clean_prepare_network_checkpoint_bytes,
        "physical TAP publication rewrote the PrepareNetwork checkpoint"
    );
    assert_eq!(
        checkpoint_file_identity(&checkpoint_path),
        clean_prepare_network_checkpoint_identity,
        "physical TAP publication replaced the PrepareNetwork checkpoint"
    );
    assert_eq!(aws.put_request_count(), clean_prepare_network_puts);
    assert_eq!(
        cats_control_plane::testsupport::runtime_volume_row_fingerprint(
            &context.server.state.store,
            prepared.volume_id.clone(),
        )
        .await,
        clean_prepare_network_row,
        "physical TAP publication mutated PostgreSQL Volume authority"
    );
    assert_eq!(
        authority.load_volume(&prepared.volume_id).unwrap(),
        clean_prepare_network_authority,
        "physical TAP publication changed exact Volume authority"
    );
    assert!(std::path::Path::new(&format!("/proc/{}", serving_process.process_id)).exists());

    let serving_checkpoint_bytes = clean_prepare_network_checkpoint_bytes;
    let serving_checkpoint = prepare_network_checkpoint;
    let serving_checkpoint_identity = clean_prepare_network_checkpoint_identity;

    // A successful Relaxed FLUSH must become unique Host data while remote
    // publication is unavailable. The independent frontend speaks real
    // vhost-user/virtio-blk; it is not a control-socket shortcut.
    aws.set_publishes_enabled(false);
    let mut frontend = cats_blockd::test_vhost_user_frontend::Frontend::connect(
        std::path::Path::new(socket_path.as_str()),
        usize::from(*queues),
        *queue_size,
        1,
        false,
    )
    .expect("connect independent vhost-user frontend to serving blockd");
    let payload = (0..4096_u32)
        .map(|index| ((index * 17 + 29) % 251) as u8)
        .collect::<Vec<_>>();
    assert_eq!(
        frontend
            .write_at(8, &payload)
            .expect("write through real vhost-user queue")
            .status,
        cats_blockd::test_vhost_user_frontend::STATUS_OK
    );
    assert_eq!(
        frontend
            .flush()
            .expect("Relaxed FLUSH through real vhost-user queue")
            .status,
        cats_blockd::test_vhost_user_frontend::STATUS_OK
    );
    let read_back = frontend
        .read_at(8, payload.len())
        .expect("read back Relaxed write through real vhost-user queue");
    assert_eq!(
        read_back.status,
        cats_blockd::test_vhost_user_frontend::STATUS_OK
    );
    assert_eq!(read_back.data, payload);
    let dirty_deadline = Instant::now() + cats_test_support::poll_bound();
    let dirty_status = loop {
        let status = serving_status(&prepared.serving_process.control_socket_path);
        if status.local_durable_generation > status.remote_durable_generation
            && status.unpublished_generations > 0
            && aws.s3.rejected_puts.load(Ordering::SeqCst) > 0
        {
            break status;
        }
        assert!(
            Instant::now() < dirty_deadline,
            "Relaxed write did not remain as a rejected unpublished pack: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(dirty_status.volume_id, prepared.volume_id.as_str());
    assert_eq!(dirty_status.attachment_id, prepared.attachment_id.as_str());
    assert_eq!(
        dirty_status.attachment_epoch,
        Some(prepared.attachment_epoch)
    );
    assert_eq!(dirty_status.mode, "relaxed");
    assert_eq!(dirty_status.guest_io_enabled, Some(true));
    assert_eq!(
        dirty_status.scope_id.as_ref(),
        Some(&prepared.serving_process.scope_id)
    );
    assert_eq!(
        dirty_status.process_identity_token.as_ref(),
        Some(&prepared.serving_process.process_identity_token)
    );
    assert_eq!(
        dirty_status.device_ownership_token.as_ref(),
        Some(&prepared.ownership_token)
    );
    assert_eq!(
        authority.load_volume(&prepared.volume_id).unwrap().head,
        serving_authority_before_tail.head,
        "failed background publication must not advance remote authority"
    );

    // Restart the production Agent composition, releasing its workers and
    // Host-global lock while the PID1-owned per-Cat service retains the pack.
    // Survival under an actual `systemctl restart cats-noded` additionally
    // depends on N5's service/cgroup ownership gate; N6 deliberately does not
    // duplicate that large PID1 fixture here.
    shutdown_cutover(
        restarted,
        "join serving production cutover before restart adoption",
    )
    .await;
    assert!(std::path::Path::new(&format!("/proc/{}", serving_process.process_id)).exists());

    let adopting_registration =
        production_registration(identity.clone(), state_path.clone(), &context.release);
    let (
        adopting_barrier,
        mut adopting_observations,
        adopting_resume,
        mut adopting_effect_steps,
        adopting_effect_dispatches,
    ) = super::RuntimeObservationBarrierForTest::channel_with_effect_steps();
    let mut adopting = super::spawn_signed_runtime_cutover(production_cutover_config(
        &context,
        adopting_registration,
        authority.clone(),
        node_image_blob.clone(),
        &aws,
        adopting_barrier,
    ))
    .await
    .unwrap();
    let adopted_fingerprint = hold_after_exact_serving_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &adopting,
        &mut adopting_observations,
        &adopting_resume,
        "restarted cutover exact serving-process adoption",
    )
    .await;
    let adopted = AcceptedFullFingerprint::decode(&adopted_fingerprint);
    let adopted_durable_session = decode_agent_session(
        &std::fs::read(state_path.join(crate::agent_registration::SESSION_RELATIVE_PATH)).unwrap(),
    )
    .unwrap();
    assert_current_signed_full_envelope(&adopted, &adopted_durable_session, &serving_desired);
    assert_eq!(adopted.session.agent_session_epoch, Epoch::new(3).unwrap());
    assert_ne!(
        adopted.session.agent_instance_id,
        restarted_session.agent_instance_id
    );
    let dirty_local_generation = Generation::new(
        u64::try_from(dirty_status.local_durable_generation)
            .expect("dirty local generation is nonnegative"),
    )
    .unwrap();
    let dirty_remote_generation = Generation::new(
        u64::try_from(dirty_status.remote_durable_generation)
            .expect("dirty remote generation is nonnegative"),
    )
    .unwrap();
    let dirty_pending_packs = u64::try_from(dirty_status.unpublished_generations).unwrap();
    validate_exact_serving_full_observation(
        &adopted,
        &identity,
        &adopted_durable_session,
        &serving_desired,
        &checkpoint_path,
        &serving_checkpoint,
        &serving_process,
        &prepared,
        &serving_authority_before_tail.head,
        dirty_local_generation,
        dirty_remote_generation,
        dirty_pending_packs,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&checkpoint_path).unwrap(),
        serving_checkpoint_bytes
    );
    assert_eq!(
        checkpoint_file_identity(&checkpoint_path),
        serving_checkpoint_identity,
        "restart rewrote the exact pre-launch checkpoint"
    );

    let authority_after_adoption = authority.load_volume(&prepared.volume_id).unwrap();
    assert_eq!(
        authority_after_adoption.lease_owner,
        serving_authority_before_tail.lease_owner
    );
    assert_eq!(
        authority_after_adoption.lease_epoch,
        serving_authority_before_tail.lease_epoch
    );
    assert_eq!(
        authority_after_adoption.head,
        serving_authority_before_tail.head
    );
    assert_eq!(
        authority_after_adoption.last_transition, serving_authority_before_tail.last_transition,
        "restart repeated normal acquire or stole its own attachment"
    );
    let adopted_dirty_status = serving_status(&prepared.serving_process.control_socket_path);
    assert_eq!(
        adopted_dirty_status.local_durable_generation,
        dirty_status.local_durable_generation
    );
    assert_eq!(
        adopted_dirty_status.remote_durable_generation,
        dirty_status.remote_durable_generation
    );
    assert_eq!(
        adopted_dirty_status.unpublished_generations,
        dirty_status.unpublished_generations
    );

    // Release the observation barrier and require Agent3's signed production
    // loop to consume this exact dirty admission, run a real Desired effect,
    // and publish a successor full observation. The pre-launch network effect
    // correctly stops on R < L; it must not stop/recreate/quarantine the
    // serving writer or rewrite its checkpoint while unique packs exist.
    adopting_resume
        .send(())
        .expect("resume Agent3 for one production dirty Desired/effect round");
    let dirty_successor_fingerprint = hold_after_exact_serving_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &adopting,
        &mut adopting_observations,
        &adopting_resume,
        "production dirty successor observation",
    )
    .await;
    let dirty_successor = AcceptedFullFingerprint::decode(&dirty_successor_fingerprint);
    next_serving_adopted(
        &mut adopting_effect_steps,
        &created.cat_id,
        "dirty restarted serving adoption",
    )
    .await;
    next_local_contract_stop(
        &mut adopting_effect_steps,
        &created.cat_id,
        "production dirty Desired/effect round",
    )
    .await;
    validate_exact_serving_full_observation(
        &dirty_successor,
        &identity,
        &adopted_durable_session,
        &serving_desired,
        &checkpoint_path,
        &serving_checkpoint,
        &serving_process,
        &prepared,
        &serving_authority_before_tail.head,
        dirty_local_generation,
        dirty_remote_generation,
        dirty_pending_packs,
    )
    .unwrap();
    assert!(dirty_successor.full.inventory_epoch > adopted.full.inventory_epoch);
    assert!(dirty_successor.full.heartbeat_sequence > adopted.full.heartbeat_sequence);
    assert!(dirty_successor.assigned.request_sequence > adopted.assigned.request_sequence);
    assert_eq!(
        std::fs::read(&checkpoint_path).unwrap(),
        serving_checkpoint_bytes,
        "dirty production effect rewrote the exact pre-launch checkpoint"
    );
    assert_eq!(
        checkpoint_file_identity(&checkpoint_path),
        serving_checkpoint_identity,
        "dirty production effect replaced the exact pre-launch checkpoint"
    );
    assert_eq!(
        authority
            .load_volume(&prepared.volume_id)
            .unwrap()
            .last_transition,
        authority_after_adoption.last_transition,
        "dirty production effect repeated acquire or stole the writer"
    );

    // Restore object publication without an out-of-band Drain. The retained
    // production blockd publisher owns R -> L. Agent3 then consumes the dirty
    // accepted observation and produces a clean successor full inventory,
    // still at the same process/checkpoint/attachment epoch.
    aws.set_publishes_enabled(true);
    let publish_deadline = Instant::now() + cats_test_support::poll_bound();
    let drained = loop {
        let status = serving_status(&prepared.serving_process.control_socket_path);
        if status.remote_durable_generation == status.local_durable_generation
            && status.unpublished_generations == 0
            && status.unpublished_bytes == 0
        {
            break status;
        }
        assert!(
            Instant::now() < publish_deadline,
            "production Relaxed publisher did not settle the retained tail: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(
        drained.local_durable_generation,
        dirty_status.local_durable_generation
    );
    assert_eq!(
        drained.remote_durable_generation,
        drained.local_durable_generation
    );
    assert_eq!(drained.unpublished_generations, 0);
    assert_eq!(drained.unpublished_bytes, 0);
    let authority_after_drain = authority.load_volume(&prepared.volume_id).unwrap();
    assert_eq!(
        authority_after_drain.lease_owner,
        authority_after_adoption.lease_owner
    );
    assert_eq!(
        authority_after_drain.lease_epoch,
        authority_after_adoption.lease_epoch
    );
    assert_eq!(
        authority_after_drain.last_transition,
        authority_after_adoption.last_transition
    );
    assert_eq!(
        i64::try_from(authority_after_drain.head.generation.get()).unwrap(),
        drained.remote_durable_generation
    );

    adopting_resume
        .send(())
        .expect("resume Agent3 for production clean successor scan");
    let clean_fingerprint = hold_after_exact_serving_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &adopting,
        &mut adopting_observations,
        &adopting_resume,
        "production clean successor observation",
    )
    .await;
    let clean = AcceptedFullFingerprint::decode(&clean_fingerprint);
    next_local_contract_stop(
        &mut adopting_effect_steps,
        &created.cat_id,
        "production publisher-clean successor round",
    )
    .await;
    let clean_generation = Generation::new(
        u64::try_from(drained.local_durable_generation)
            .expect("clean durable generation is nonnegative"),
    )
    .unwrap();
    validate_exact_serving_full_observation(
        &clean,
        &identity,
        &adopted_durable_session,
        &serving_desired,
        &checkpoint_path,
        &serving_checkpoint,
        &serving_process,
        &prepared,
        &authority_after_drain.head,
        clean_generation,
        clean_generation,
        0,
    )
    .unwrap();
    assert!(clean.full.inventory_epoch > dirty_successor.full.inventory_epoch);
    assert_eq!(
        std::fs::read(&checkpoint_path).unwrap(),
        serving_checkpoint_bytes
    );
    assert_eq!(
        checkpoint_file_identity(&checkpoint_path),
        serving_checkpoint_identity
    );

    // Consume the first accepted R == L observation. The production serving
    // effect must now durably advance the bounded checkpoint to the publisher
    // head and demand a fresh full inventory. It must not replace the retained
    // writer or its attachment while closing this stale launch coordinate.
    let current_session_dispatches = adopting_effect_dispatches.load(Ordering::SeqCst);
    adopting_resume
        .send(())
        .expect("resume current Agent3 clean admission into production effect");
    let terminal_clean_fingerprint = hold_after_exact_serving_process_observation(
        &context,
        &identity.node_id,
        &created.cat_id,
        &adopting,
        &mut adopting_observations,
        &adopting_resume,
        "production terminal current-session clean observation",
    )
    .await;
    next_refresh_inventory(
        &mut adopting_effect_steps,
        &created.cat_id,
        "publisher-clean checkpoint progression",
    )
    .await;
    assert_eq!(
        adopting_effect_dispatches.load(Ordering::SeqCst),
        current_session_dispatches + 1,
        "publisher-clean admission did not reach effect dispatch"
    );
    let progressed_checkpoint_bytes = std::fs::read(&checkpoint_path).unwrap();
    let progressed_checkpoint = decode_runtime_checkpoint(&progressed_checkpoint_bytes).unwrap();
    let progressed_checkpoint_identity = checkpoint_file_identity(&checkpoint_path);
    assert_ne!(
        progressed_checkpoint_bytes, serving_checkpoint_bytes,
        "publisher-clean effect did not durably advance the checkpoint"
    );
    assert_ne!(
        progressed_checkpoint_identity, serving_checkpoint_identity,
        "publisher-clean effect did not atomically replace the checkpoint"
    );
    let ReconcileStep::PrepareNetwork {
        devices: progressed_devices,
        ..
    } = &progressed_checkpoint.step
    else {
        panic!("publisher-clean successor changed the checkpoint phase")
    };
    let [progressed_prepared] = progressed_devices.as_slice() else {
        panic!("publisher-clean successor lost its single prepared device")
    };
    assert_eq!(
        progressed_prepared.expected_head,
        authority_after_drain.head
    );
    assert_eq!(
        progressed_prepared.serving_process, prepared.serving_process,
        "publisher-clean checkpoint changed the serving process identity"
    );
    assert_eq!(
        progressed_prepared.attachment_epoch, prepared.attachment_epoch,
        "publisher-clean checkpoint changed the attachment epoch"
    );
    let terminal_clean = AcceptedFullFingerprint::decode(&terminal_clean_fingerprint);
    validate_exact_serving_full_observation(
        &terminal_clean,
        &identity,
        &adopted_durable_session,
        &serving_desired,
        &checkpoint_path,
        &progressed_checkpoint,
        &serving_process,
        progressed_prepared,
        &authority_after_drain.head,
        clean_generation,
        clean_generation,
        0,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&checkpoint_path).unwrap(),
        progressed_checkpoint_bytes
    );
    assert_eq!(
        checkpoint_file_identity(&checkpoint_path),
        progressed_checkpoint_identity
    );

    // Replace the current AgentSession in Control while Agent3 is held after
    // an accepted full scan. Its next signed Desired read must fail as stale
    // before any effect can consume that admission. The replacement is sent
    // directly through the real signed registration endpoint so the active
    // process's durable session file remains independent epoch-3 evidence.
    let stale_session_row = cats_control_plane::testsupport::runtime_volume_row_fingerprint(
        &context.server.state.store,
        prepared.volume_id.clone(),
    )
    .await;
    let stale_session_puts = aws.put_request_count();
    let stale_session_dispatches = adopting_effect_dispatches.load(Ordering::SeqCst);
    let replacement_session =
        register_replacement_agent_session(&context, &identity, &terminal_clean.session).await;
    assert_eq!(
        replacement_session.agent_session_epoch,
        Epoch::new(4).unwrap()
    );
    let still_durable_agent3 = decode_agent_session(
        &std::fs::read(state_path.join(crate::agent_registration::SESSION_RELATIVE_PATH)).unwrap(),
    )
    .unwrap();
    validate_current_session_observation(
        &terminal_clean.session,
        &still_durable_agent3,
        terminal_clean.acceptance.lease_deadline_unix_ms,
    )
    .unwrap();
    adopting_resume
        .send(())
        .expect("resume stale Agent3 after signed session replacement");
    let stale_error =
        tokio::time::timeout(cats_test_support::poll_bound(), &mut adopting.runner_task)
            .await
            .expect("stale Agent3 did not terminate after session replacement")
            .expect("join stale Agent3 production runner")
            .expect_err("stale Agent3 unexpectedly continued into a Desired effect");
    assert!(
        format!("{stale_error:#}").contains("signed Runtime session was rejected"),
        "unexpected stale-session runner result: {stale_error:#}"
    );
    assert_eq!(
        adopting_effect_dispatches.load(Ordering::SeqCst),
        stale_session_dispatches,
        "stale AgentSession crossed the runner effect-dispatch boundary"
    );
    assert_eq!(
        std::fs::read(&checkpoint_path).unwrap(),
        progressed_checkpoint_bytes
    );
    assert_eq!(
        checkpoint_file_identity(&checkpoint_path),
        progressed_checkpoint_identity
    );
    assert_eq!(aws.put_request_count(), stale_session_puts);
    assert_eq!(
        cats_control_plane::testsupport::runtime_volume_row_fingerprint(
            &context.server.state.store,
            prepared.volume_id.clone(),
        )
        .await,
        stale_session_row
    );
    assert!(std::path::Path::new(&format!("/proc/{}", serving_process.process_id)).exists());

    // Rebuild the installed scanner after Agent3 has failed closed so the
    // later hard-stop absence scan uses a cursor strictly after the last clean
    // accepted full observation.
    let state = StateDirectory::unanchored(state_path.clone());
    let launch = production_authorized_blockd_launch(&context, &state, &aws);
    let probe = production_installed_probe_config(
        state.clone(),
        authority.clone(),
        node_image_blob.clone(),
        launch,
    );
    let scanner = installed_clean_slate_scanner(
        probe.clone(),
        AdmissionCellRegistry::for_state_directory(&state),
        None,
    )
    .unwrap();
    let ports = installed_root_process_effect_ports(probe).unwrap();
    let mut cursor = InstalledScanCursor::after(
        &terminal_clean.session,
        terminal_clean.assigned.clone(),
        &terminal_clean.full,
    );
    let (stale_session_live, _) = wait_for_installed_serving_process_state(
        &scanner,
        &mut cursor,
        &created.cat_id,
        &prepared.volume_id,
        true,
    )
    .await;
    let stale_session_runtime = stale_session_live
        .runtimes
        .iter()
        .find(|runtime| runtime.cat_id == created.cat_id)
        .expect("stale-session verification scan omitted the Cat");
    assert_eq!(
        stale_session_runtime.processes,
        vec![serving_process.clone()],
        "session replacement changed the serving PID/start before any effect"
    );

    // Dropping the restarted production composition leaves the independently
    // owned per-Cat unit intact. The exact lifecycle hard stop then kills that
    // unit's complete control-group; a successor full sweep supplies the
    // absence authority used for cleanup.
    drop(adopting);
    assert!(std::path::Path::new(&format!("/proc/{}", serving_process.process_id)).exists());
    let stop = Command::new("systemctl")
        .args(["stop", prepared.serving_process.scope_id.as_str()])
        .output()
        .expect("hard-stop exact per-Cat serving unit");
    assert!(
        stop.status.success(),
        "systemctl stop failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );
    let (absent_observation, absent_admission) = wait_for_installed_serving_process_state(
        &scanner,
        &mut cursor,
        &created.cat_id,
        &prepared.volume_id,
        false,
    )
    .await;
    assert!(
        !std::path::Path::new(&format!("/proc/{}", serving_process.process_id)).exists(),
        "hard stop left the exact serving PID alive"
    );
    assert!(
        absent_observation.residue.is_empty(),
        "unexpected residue: {:?}",
        absent_observation.residue
    );
    let (absent_expected, absent_exact) = absent_admission
        .serving_blockd(&created.cat_id, &prepared.volume_id)
        .expect("post-stop scan omitted serving expectation");
    assert!(absent_exact.is_none());
    let absent_expected = absent_expected.clone();
    let retire_context = RuntimeDesiredEffectContext::for_test_with_node_global_process(
        state.clone(),
        Instant::now() + Duration::from_secs(10),
        absent_admission,
    );
    assert_eq!(
        retire_absent_serving_socket_owner_for_test(
            ports.serving.as_ref(),
            &absent_expected,
            &retire_context,
        )
        .unwrap(),
        ManagedBlockdSocketOwnerRetirement::Retired
    );
    drop(frontend);

    // Reconstruct the acknowledged dirty sector after the retained writer is
    // gone. The new engine starts with no cache or pending-pack directory (it
    // receives only the immutable lineage identity required to open the exact
    // grant) and reads through an independent S3 client plus the PostgreSQL
    // authority; none of the stopped writer's data files are reachable.
    let remote_cache_parent = tempfile::Builder::new()
        .prefix("cats-n6-remote-only")
        .tempdir_in(safe_state_scratch_parent())
        .unwrap();
    let remote_cache = remote_cache_parent.path().join("empty-cache");
    assert!(
        !remote_cache.exists(),
        "remote-only cache was not initially empty"
    );
    std::fs::create_dir(&remote_cache).unwrap();
    std::fs::copy(
        std::path::Path::new(prepared.serving_process.data_directory.as_str()).join(IDENTITY_FILE),
        remote_cache.join(IDENTITY_FILE),
    )
    .unwrap();
    assert!(!remote_cache.join("cache.data").exists());
    assert!(!remote_cache
        .join(cats_api::blockd::PENDING_PACK_DIR)
        .exists());
    let mut authorized_attachment: AuthorizedServingAttachment = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(prepared.serving_process.data_directory.as_str())
                .join(AUTHORIZED_SERVING_FILE),
        )
        .unwrap(),
    )
    .unwrap();
    // AUTHORIZED_SERVING_FILE is the immutable acquire-time blank grant by
    // design (the handoff artifacts carry the provisioned authority); it must
    // still name the exact head its own acquire result minted.
    {
        let cats_storage::authority::AuthorizedServingAcquire::Normal { result, .. } =
            &authorized_attachment.acquire
        else {
            panic!("immutable acquire grant lost its normal acquire origin")
        };
        assert_eq!(
            authorized_attachment.head, result.resulting_head,
            "immutable acquire grant lost its acquire-origin head"
        );
    }
    // The immutable artifact supplies lineage and acquire authority; the
    // independently reread PostgreSQL record supplies the later exact head.
    authorized_attachment.head = authority_after_drain.head.clone();
    // The S3 store and engine own blocking runtimes; construct, attach,
    // read and drop them off the async test executor.
    let remote_s3_endpoint = aws.s3_endpoint.clone();
    let remote_volume_id = prepared.volume_id.as_str().to_owned();
    let remote_attachment_id = prepared.attachment_id.as_str().to_owned();
    let remote_cache_path = remote_cache.clone();
    let remote_authority = authority.clone();
    let payload_len = payload.len();
    let remote_payload = tokio::task::spawn_blocking(move || {
        let remote_blob: Arc<dyn BlobStore> = Arc::new(
            AwsS3BlobStore::new(AwsS3Config {
                endpoint: remote_s3_endpoint,
                bucket: "cats-cross-component".to_owned(),
                region: AWS_REGION.to_owned(),
                access_key: "AKIAHERMETICCATS".to_owned(),
                secret_key: "hermetic-secret-access-key".to_owned(),
                session_token: Some("hermetic-session-token".to_owned()),
                prefix: AWS_PREFIX.to_owned(),
            })
            .unwrap(),
        );
        let mut remote_cfg = cats_blockd::engine::EngineConfig::new(
            &remote_volume_id,
            &remote_cache_path,
            &remote_attachment_id,
        );
        remote_cfg.durability = cats_blockd::engine::DurabilityMode::Relaxed {
            drain_interval_ms: 0,
        };
        remote_cfg.lease_ttl_ms = 60_000;
        let remote_engine = cats_blockd::engine::ChunkEngine::attach_authorized_serving(
            remote_cfg,
            authorized_attachment,
            remote_blob,
            remote_authority,
        )
        .expect("reconstruct publisher-clean attachment from remote authority");
        let mut remote_payload = vec![0u8; payload_len];
        remote_engine
            .read(8 * 512, &mut remote_payload)
            .expect("hydrate dirty sector from remote objects into empty cache");
        drop(remote_engine);
        remote_payload
    })
    .await
    .expect("join remote-only reconstruction");
    assert_eq!(
        remote_payload, payload,
        "remote-only reconstruction lost the acknowledged dirty sector"
    );
    let authority_after_remote_read = authority.load_volume(&prepared.volume_id).unwrap();
    assert_eq!(
        authority_after_remote_read.lease_owner,
        authority_after_drain.lease_owner
    );
    assert_eq!(
        authority_after_remote_read.lease_epoch,
        authority_after_drain.lease_epoch
    );
    assert_eq!(authority_after_remote_read.head, authority_after_drain.head);

    let blockd_root = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed();
    assert!(
        std::fs::read_dir(blockd_root.path().as_str())
            .unwrap()
            .next()
            .is_none(),
        "terminal audit found a managed blockd owner or orphan child"
    );
    assert!(
        std::fs::read_dir(state.path().join(BLOCKD_SOCKET_INTENT_NAMESPACE))
            .unwrap()
            .next()
            .is_none(),
        "terminal audit found a managed blockd intent"
    );
    exact_network_cleanup.remove();
    assert!(
        !host_link_named(&reserved_network.tap_name),
        "terminal audit found the exact focused-test Host TAP"
    );

    // One strictly later full production scan is the terminal absence oracle.
    // The assigned Cat remains represented by its bounded checkpoint, but its
    // complete physical inventory and the Node-global residue set are empty.
    let (terminal_inventory, _) = loop {
        if let Some(complete) = next_installed_process_scan(&scanner, &mut cursor).await {
            break complete;
        }
    };
    assert!(terminal_inventory.complete_inventory);
    assert!(terminal_inventory.residue.is_empty());
    let [terminal_runtime] = terminal_inventory.runtimes.as_slice() else {
        panic!("terminal full inventory lost its assigned Cat projection")
    };
    assert_eq!(terminal_runtime.cat_id, created.cat_id);
    assert!(terminal_runtime.processes.is_empty());
    assert!(terminal_runtime.mounts.is_empty());
    assert!(terminal_runtime.networks.is_empty());
    assert!(terminal_runtime
        .volumes
        .iter()
        .all(|volume| volume.devices.is_empty()));

    aws.shutdown().await;

    let successor = production_registration(identity, state_path, &context.release);
    drop(successor);
    drop(authority);
    context.server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_control_node_route_v2_mtls_serves_http_ws_and_rejects_closed_stale_epoch() {
    use cats_api::route_grant_v2::{RouteAdmissionV2Reason, RouteGrantV2PublicKey};
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio::io::AsyncWriteExt as _;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    use tokio_tungstenite::tungstenite::Message;

    let guest = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind the Cat-create v2 fixed target port");
    let guest_accepts = Arc::new(AtomicUsize::new(0));
    let guest_accepts_task = Arc::clone(&guest_accepts);
    let (guest_shutdown, mut guest_shutdown_rx) = tokio::sync::oneshot::channel();
    let guest_task = tokio::spawn(async move {
        let (mut http, _) = guest.accept().await.unwrap();
        guest_accepts_task.fetch_add(1, Ordering::SeqCst);
        let head = route_v2_read_http_head(&mut http).await;
        assert!(std::str::from_utf8(&head)
            .unwrap()
            .starts_with("GET /http HTTP/1.1\r\n"));
        http.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong")
            .await
            .unwrap();
        drop(http);

        let (websocket, _) = guest.accept().await.unwrap();
        guest_accepts_task.fetch_add(1, Ordering::SeqCst);
        let mut websocket = tokio_tungstenite::accept_async(websocket).await.unwrap();
        let payload = websocket.next().await.unwrap().unwrap();
        assert_eq!(payload, Message::Text("ws-payload".into()));
        websocket.send(payload).await.unwrap();
        let _ = websocket.next().await;
        drop(websocket);

        tokio::select! {
            _ = &mut guest_shutdown_rx => {}
            accepted = guest.accept() => {
                let _ = accepted.unwrap();
                guest_accepts_task.fetch_add(1, Ordering::SeqCst);
                panic!("closed or stale-epoch request reached the Guest listener");
            }
        }
    });

    let route_public_key = RouteGrantV2PublicKey::from_public_key_pem(include_bytes!(
        "../../../tests/fixtures/route_grant_v2_public_ed25519.pem"
    ))
    .unwrap();
    assert_eq!(route_public_key.kid().as_str(), ROUTE_V2_KID);
    let route_ring =
        RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![route_public_key]).unwrap();
    let node_directory = tempfile::tempdir().unwrap();
    let registry = AdmissionCellRegistry::new(node_directory.path().join("checkpoints"));
    let node_config = RouteV2MachineConfig::for_test(
        "127.0.0.1:0".to_owned(),
        id("node_cross_component_a"),
        include_bytes!("../../../control-plane/tests/fixtures/gateway_machine_ca_certificate.pem"),
        include_bytes!(
            "../../../control-plane/tests/fixtures/gateway_machine_server_certificate.pem"
        ),
        include_bytes!(
            "../../../control-plane/tests/fixtures/gateway_machine_server_private_key.pem"
        ),
        Arc::new(RouteGrantV2Verifier::new(route_ring)),
    )
    .unwrap();
    let mut node_listener = RouteV2MachineListener::spawn(node_config, Arc::clone(&registry))
        .await
        .unwrap();

    let context = ControlContext::spawn_route_v2().await;
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
        NodeBootId::new("22222222222222222222222222222222").unwrap(),
        &context.release,
    )
    .unwrap();
    let node_transport_target =
        NodeTransportTarget::new(format!("https://localhost:{}", node_listener.addr().port()))
            .unwrap();
    let mut cordoned_policy =
        placement_policy(&context.release, 1, RuntimeSchedulingState::Cordoned);
    cordoned_policy.node_transport_target = node_transport_target.clone();
    let provision = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("cccccccccccccccccccccccccccccccc"),
        node_id: identity.node_id.clone(),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(identity.clone()),
            placement_policy: Box::new(cordoned_policy),
        },
    };
    assert_eq!(
        apply_node_authority(&context, &provisioner, &provision).await,
        RuntimeNodeAuthorityOutcome::Provisioned
    );
    let session = tokio::time::timeout(
        cats_test_support::poll_bound(),
        registration.register_until_session(&context.server.base_url()),
    )
    .await
    .expect("A19 registration did not complete")
    .unwrap();

    let scanner = Arc::new(RouteReadyScanner::default());
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
    let ready_observation = next_step(&mut runner).await;
    assert!(
        matches!(
            ready_observation,
            RuntimeSpineRunStep::ObservationAccepted { .. }
        ),
        "unexpected ready-observation step: {ready_observation:?}"
    );
    assert!(scanner.records.lock().unwrap()[0]
        .desired
        .desired_specs
        .is_empty());

    let mut schedulable_policy =
        placement_policy(&context.release, 2, RuntimeSchedulingState::Schedulable);
    schedulable_policy.node_transport_target = node_transport_target;
    let uncordon = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random("dddddddddddddddddddddddddddddddd"),
        node_id: identity.node_id.clone(),
        mutation: RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision: Epoch::new(1).unwrap(),
            placement_policy: Box::new(schedulable_policy),
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
    {
        let admission_workspace =
            cats_api::runtime_reconciliation::Id::new(workspace.id.clone()).unwrap();
        tokio::task::block_in_place(|| {
            cats_control_plane::testsupport::begin_production_qualification_for_product_test(
                &context.server.state.store,
                &admission_workspace,
            );
        });
    }
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
        .header("Idempotency-Key", "route-v2-cross-component-create")
        .body(CAT_CREATE_BODY.to_vec())
        .send()
        .await
        .unwrap();
    let created =
        decode_cat_create_v2_accepted_response(&json_body(create, StatusCode::ACCEPTED).await)
            .unwrap();

    assert!(matches!(
        next_step(&mut runner).await,
        RuntimeSpineRunStep::DesiredAccepted
    ));
    runner.shutdown().await.unwrap();
    let mut runner = RuntimeSpineRunner::new_with_desired_effects(
        registration.runtime_state_directory(),
        session,
        client,
        scanner.clone(),
        effect,
    )
    .unwrap();
    let ready_observation = next_step(&mut runner).await;
    assert!(
        matches!(
            ready_observation,
            RuntimeSpineRunStep::ObservationAccepted { .. }
        ),
        "unexpected ready-observation step: {ready_observation:?}"
    );
    let desired = {
        let records = scanner.records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].desired.desired_specs.len(), 1);
        records[1].desired.desired_specs[0].clone()
    };
    assert_eq!(desired.cat_id, created.cat_id);
    let endpoint = desired.endpoints.first().unwrap().clone();
    assert_eq!(endpoint.protocol, HttpProtocol::Http);
    assert_eq!(endpoint.target_port, 8080);

    let incarnation = random(ROUTE_RUNTIME_INCARNATION);
    let active_route = CheckpointRouteGate {
        binding: RouteGateBinding {
            workspace_id: desired.workspace_id.clone(),
            endpoint_id: endpoint.endpoint_id.clone(),
            hostname: endpoint.hostname.clone(),
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            runtime_incarnation: incarnation.clone(),
            route_epoch: endpoint.route_epoch,
            protocol: endpoint.protocol,
            target_port: endpoint.target_port,
        },
        gate: RouteGateState::Active,
    };
    let active_snapshot = AdmissionSnapshot::new(
        desired.desired_revision,
        desired.spec_digest.clone(),
        desired.placement.clone(),
        Some(incarnation),
        LifecycleAdmission::Open,
        vec![active_route],
    )
    .with_guest_ipv4(Ipv4Address::new("127.0.0.1").unwrap());
    let admission_cell = AdmissionCell::new(active_snapshot).unwrap();
    registry
        .insert_cell_for_machine_test(desired.cat_id.clone(), Arc::clone(&admission_cell))
        .unwrap();

    let control_machine_addr = context
        .server
        .gateway_machine_addr
        .expect("Route v2 Control machine listener is running");
    let control_target =
        ControlMachineTarget::new(format!("https://localhost:{}", control_machine_addr.port()))
            .unwrap();
    let (resolver, node_client) = gateway_machine_clients_for_test(control_target).unwrap();
    let node_errors = Arc::new(Mutex::new(Vec::<GatewayNodeRouteV2Error>::new()));
    let connector_errors = Arc::clone(&node_errors);
    let connector: TunnelConnector = Arc::new(move |route| {
        let client = node_client.clone();
        let errors = Arc::clone(&connector_errors);
        Box::pin(async move {
            let outcome = client.open_tunnel(&route).await;
            if let Err(error) = &outcome {
                errors.lock().unwrap().push(error.clone());
            }
            outcome.map(|tunnel| Box::new(tunnel) as BoxedGatewayTunnel)
        }) as TunnelFuture
    });
    let cache = RouteCache::new(RouteCacheConfig::default(), resolver).unwrap();
    let gateway = GatewayIngress::new(GatewayIngressConfig::default(), cache, connector).unwrap();
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    let (gateway_shutdown, gateway_shutdown_rx) = tokio::sync::oneshot::channel();
    let gateway_task = tokio::spawn(async move {
        gateway
            .serve(gateway_listener, async move {
                let _ = gateway_shutdown_rx.await;
            })
            .await
    });

    let hostname = endpoint.hostname.as_str().to_owned();
    let http = route_v2_public_http_request(gateway_addr, &hostname, "/http").await;
    assert!(
        http.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "unexpected public HTTP response {:?}; Node errors: {:?}",
        String::from_utf8_lossy(&http),
        node_errors.lock().unwrap()
    );
    assert!(http.ends_with(b"\r\n\r\npong"));

    let websocket_request = format!("ws://{hostname}/ws").into_client_request().unwrap();
    let websocket_tcp = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let (mut websocket, websocket_response) =
        tokio_tungstenite::client_async(websocket_request, websocket_tcp)
            .await
            .unwrap();
    assert_eq!(websocket_response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(admission_cell.active_guards(&endpoint.endpoint_id), Some(1));
    websocket
        .send(Message::Text("ws-payload".into()))
        .await
        .unwrap();
    assert_eq!(
        websocket.next().await.unwrap().unwrap(),
        Message::Text("ws-payload".into())
    );
    websocket.close(None).await.unwrap();
    drop(websocket);
    let guard_deadline = Instant::now() + cats_test_support::poll_bound();
    while admission_cell.active_guards(&endpoint.endpoint_id) != Some(0) {
        assert!(
            Instant::now() < guard_deadline,
            "WebSocket tunnel retained its admission guard after public close"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(guest_accepts.load(Ordering::SeqCst), 2);

    let expected = admission_cell.snapshot();
    let mut closed_route = expected.endpoints()[0].clone();
    closed_route.gate = RouteGateState::Closed;
    let closed = AdmissionSnapshot::new(
        expected.applied_desired_revision(),
        expected.spec_digest().clone(),
        expected.placement().clone(),
        expected.runtime_incarnation().cloned(),
        expected.lifecycle_admission(),
        vec![closed_route],
    )
    .with_guest_ipv4(expected.guest_ipv4().cloned().unwrap());
    admission_cell
        .port()
        .close_gate(&expected, &closed, &endpoint.endpoint_id)
        .unwrap();
    let gate_closed = route_v2_public_http_request(gateway_addr, &hostname, "/closed").await;
    assert!(gate_closed.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(node_errors.lock().unwrap().iter().any(|error| matches!(
        error,
        GatewayNodeRouteV2Error::Admission(failure)
            if failure.reason == RouteAdmissionV2Reason::GateClosed && !failure.guard_acquired
    )));
    assert_eq!(guest_accepts.load(Ordering::SeqCst), 2);

    let mut successor_route = closed.endpoints()[0].clone();
    successor_route.binding.route_epoch =
        Epoch::new(successor_route.binding.route_epoch.get() + 1).unwrap();
    successor_route.gate = RouteGateState::Active;
    let successor = AdmissionSnapshot::new(
        Revision::new(closed.applied_desired_revision().get() + 1).unwrap(),
        Sha256Digest::from_bytes([0x77; 32]),
        closed.placement().clone(),
        closed.runtime_incarnation().cloned(),
        LifecycleAdmission::Open,
        vec![successor_route],
    )
    .with_guest_ipv4(closed.guest_ipv4().cloned().unwrap());
    admission_cell
        .port()
        .install_gate(&closed, &successor, &endpoint.endpoint_id)
        .unwrap();
    let stale_epoch = route_v2_public_http_request(gateway_addr, &hostname, "/stale").await;
    assert!(stale_epoch.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(node_errors.lock().unwrap().iter().any(|error| matches!(
        error,
        GatewayNodeRouteV2Error::Admission(failure)
            if failure.reason == RouteAdmissionV2Reason::BindingMismatch
                && !failure.guard_acquired
    )));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        guest_accepts.load(Ordering::SeqCst),
        2,
        "closed and stale-epoch requests must be rejected before Guest connect"
    );

    let _ = gateway_shutdown.send(());
    gateway_task.await.unwrap().unwrap();
    node_listener.shutdown().await.unwrap();
    runner.shutdown().await.unwrap();
    context.server.shutdown().await.unwrap();
    let _ = guest_shutdown.send(());
    guest_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_control_and_restarted_node_runner_reach_one_recorded_cat_effect() {
    let context = ControlContext::spawn_route_v2().await;
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
        cats_test_support::poll_bound(),
        registration.register_until_session(&context.server.base_url()),
    )
    .await
    .expect("A19 registration did not complete")
    .unwrap();
    assert_eq!(session.node_id, identity.node_id);

    let scanner = Arc::new(RouteReadyScanner::default());
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
            service_ready: false,
            ..
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
    {
        let admission_workspace =
            cats_api::runtime_reconciliation::Id::new(workspace.id.clone()).unwrap();
        tokio::task::block_in_place(|| {
            cats_control_plane::testsupport::begin_production_qualification_for_product_test(
                &context.server.state.store,
                &admission_workspace,
            );
        });
    }
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
            service_ready: true,
            ..
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

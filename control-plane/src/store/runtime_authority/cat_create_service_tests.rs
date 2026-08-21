use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_inventory::{
    full_inventory_digest, RuntimeInventoryBody, RuntimeInventoryReport,
};
use cats_api::runtime_lifecycle::{
    decode_immutable_runtime_config, decode_lifecycle_command_envelope, LifecycleCommand,
    LifecyclePredecessor, RuntimeNetworkConfig, RuntimeVolumeAuthorityInput,
    RuntimeVolumeGuestBinding,
};
use cats_api::runtime_reconciliation::{
    guest_config_digest, AgentRegistrationAttempt, AllocatableMemoryBytes, AllocatableVcpus,
    AsciiText, ContractVersion, CredentialBinding, Durability, Epoch, GuestIpv4Pool,
    GuestIpv4PoolKind, GuestRuntimeProfileReceipt, Id, Ipv4Address, NodeBootId, NodeIdentity,
    NodeIdentityState, NodePlacementPolicy, NodeTransportTarget, ProviderScope, RandomId128,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeSchedulingState, Sequence,
    SessionBinding, Sha256Digest, UnixMillis,
};

use super::cat_create_service::{
    parse_authorized_cat_create, CatCreateHttpFields, CatCreateManifestResolver,
    CatCreatePlacementMutation, CatCreatePlacementOutcome, CatCreatePlacementPlanner,
    CatCreatePlan, CatCreatePlanRequest, CatCreateService, ServiceFuture, ValidatedImageManifest,
    CAT_CREATE_MAX_BODY_BYTES, CAT_CREATE_TOTAL_DEADLINE,
};
use super::placement_planner::PlacementTargetSnapshot;
use super::product_identity::ProductIdentitySource;
use super::runtime_spine::RuntimeInventoryOutcome;
use crate::store::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy, Result, Store};

const BOOT_DIGEST: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn fields(key: &str) -> CatCreateHttpFields {
    CatCreateHttpFields {
        content_type: vec![b"application/json".to_vec()],
        content_encoding: Vec::new(),
        if_match: Vec::new(),
        idempotency_key: vec![key.as_bytes().to_vec()],
    }
}

fn body(name: &str, root_size_bytes: u64) -> Vec<u8> {
    format!(
        r#"{{"boot_image_digest":"{BOOT_DIGEST}","durability":"strict","memory_bytes":2147483648,"name":"{name}","root_size_bytes":{root_size_bytes},"vcpus":2}}"#
    )
    .into_bytes()
}

pub(crate) fn ingress(
    workspace: &Id,
    name: &str,
    key: &str,
) -> super::cat_create_service::AuthorizedCatCreateIngress {
    ingress_with_size(workspace, name, key, 4_194_304)
}

fn ingress_with_size(
    workspace: &Id,
    name: &str,
    key: &str,
    root_size_bytes: u64,
) -> super::cat_create_service::AuthorizedCatCreateIngress {
    ingress_with_size_at(workspace, name, key, root_size_bytes, Instant::now())
}

fn ingress_with_size_at(
    workspace: &Id,
    name: &str,
    key: &str,
    root_size_bytes: u64,
    headers_received_at: Instant,
) -> super::cat_create_service::AuthorizedCatCreateIngress {
    parse_authorized_cat_create(
        workspace,
        headers_received_at,
        format!("/v1/workspaces/{workspace}/cats").as_bytes(),
        &fields(key),
        &body(name, root_size_bytes),
    )
    .unwrap()
}

#[test]
fn strict_ingress_matches_the_frozen_fingerprint_vector() {
    let workspace = id("ws_01");
    let parsed = parse_authorized_cat_create(
        &workspace,
        Instant::now(),
        b"/v1/workspaces/ws_01/cats",
        &fields("  retry-key  "),
        &body("app", 4_294_967_296),
    )
    .unwrap();
    assert_eq!(parsed.idempotency().idempotency_key.as_str(), "retry-key");
    assert_eq!(
        parsed.idempotency().request_fingerprint.as_str(),
        "sha256:8745422e60778a889e8a85f9a45a7cadbbd57d71ba412417bf02daaedcb0f76c"
    );
}

#[test]
fn ingress_rejects_envelope_path_and_closed_dto_drift() {
    let workspace = id("ws_01");
    let path = b"/v1/workspaces/ws_01/cats";
    let valid_body = body("app", 4_194_304);
    let mut cases = Vec::new();

    let mut wrong_type = fields("key");
    wrong_type.content_type = vec![b"application/json; charset=utf-8".to_vec()];
    cases.push((path.as_slice(), wrong_type, valid_body.clone()));
    let mut missing_type = fields("key");
    missing_type.content_type.clear();
    cases.push((path.as_slice(), missing_type, valid_body.clone()));
    let mut duplicate_type = fields("key");
    duplicate_type
        .content_type
        .push(b"application/json".to_vec());
    cases.push((path.as_slice(), duplicate_type, valid_body.clone()));
    let mut encoded = fields("key");
    encoded.content_encoding = vec![b"gzip".to_vec()];
    cases.push((path.as_slice(), encoded, valid_body.clone()));
    let mut duplicate_identity = fields("key");
    duplicate_identity.content_encoding = vec![b"identity".to_vec(), b"identity".to_vec()];
    cases.push((path.as_slice(), duplicate_identity, valid_body.clone()));
    let mut if_match = fields("key");
    if_match.if_match = vec![b"1".to_vec()];
    cases.push((path.as_slice(), if_match, valid_body.clone()));
    let mut duplicate_key = fields("key");
    duplicate_key.idempotency_key.push(b"other".to_vec());
    cases.push((path.as_slice(), duplicate_key, valid_body.clone()));
    let mut missing_key = fields("key");
    missing_key.idempotency_key.clear();
    cases.push((path.as_slice(), missing_key, valid_body.clone()));
    let mut empty_key = fields("key");
    empty_key.idempotency_key = vec![b" \t ".to_vec()];
    cases.push((path.as_slice(), empty_key, valid_body.clone()));
    let mut oversized_key = fields("key");
    oversized_key.idempotency_key = vec![vec![b'a'; 513]];
    cases.push((path.as_slice(), oversized_key, valid_body.clone()));
    let mut non_printable_key = fields("key");
    non_printable_key.idempotency_key = vec![vec![b'a', 0x1f]];
    cases.push((path.as_slice(), non_printable_key, valid_body.clone()));

    for (raw_path, headers, raw_body) in cases {
        assert!(parse_authorized_cat_create(
            &workspace,
            Instant::now(),
            raw_path,
            &headers,
            &raw_body,
        )
        .is_err());
    }
    for raw_path in [
        b"/v1/workspaces/ws_01/cats?x=1".as_slice(),
        b"/v1/workspaces/ws_01/cats?".as_slice(),
        b"/v1/workspaces/%77s_01/cats".as_slice(),
        b"/v1/workspaces/ws_other/cats".as_slice(),
    ] {
        assert!(parse_authorized_cat_create(
            &workspace,
            Instant::now(),
            raw_path,
            &fields("key"),
            &valid_body,
        )
        .is_err());
    }

    let valid_text = String::from_utf8(valid_body.clone()).unwrap();
    let duplicate = valid_body
        .iter()
        .position(|byte| *byte == b'}')
        .map(|index| {
            let mut value = valid_body[..index].to_vec();
            value.extend_from_slice(b",\"vcpus\":3}");
            value
        })
        .unwrap();
    let unknown = valid_text
        .clone()
        .replace("}", ",\"image\":\"ubuntu\"}")
        .into_bytes();
    let null = valid_text
        .clone()
        .replace("\"vcpus\":2", "\"vcpus\":null")
        .into_bytes();
    let float = valid_text
        .clone()
        .replace("\"vcpus\":2", "\"vcpus\":2.0")
        .into_bytes();
    let negative_zero = valid_text
        .clone()
        .replace("\"vcpus\":2", "\"vcpus\":-0")
        .into_bytes();
    let exponent = valid_text
        .clone()
        .replace("\"vcpus\":2", "\"vcpus\":1e0")
        .into_bytes();
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend_from_slice(&valid_body);
    let legacy = br#"{"name":"app","image":"ubuntu-24.04"}"#.to_vec();
    let mut invalid_bodies = vec![
        duplicate,
        unknown,
        null,
        float,
        negative_zero,
        exponent,
        bom,
        legacy,
    ];
    let mut value: serde_json::Value = serde_json::from_slice(&valid_body).unwrap();
    for field in [
        "boot_image_digest",
        "durability",
        "memory_bytes",
        "name",
        "root_size_bytes",
        "vcpus",
    ] {
        let removed = value.as_object_mut().unwrap().remove(field).unwrap();
        invalid_bodies.push(serde_json::to_vec(&value).unwrap());
        value
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), removed);
    }
    for invalid_name in ["", "App", "-app", "app-", &"a".repeat(31)] {
        invalid_bodies.push(body(invalid_name, 4_194_304));
    }
    for invalid in invalid_bodies {
        assert!(parse_authorized_cat_create(
            &workspace,
            Instant::now(),
            path,
            &fields("key"),
            &invalid,
        )
        .is_err());
    }
}

#[test]
fn ingress_enforces_the_body_cap_before_decode() {
    let workspace = id("ws_01");
    let path = b"/v1/workspaces/ws_01/cats";
    let mut below = body("app", 4_194_304);
    below.resize(CAT_CREATE_MAX_BODY_BYTES - 1, b' ');
    assert_eq!(below.len(), CAT_CREATE_MAX_BODY_BYTES - 1);
    parse_authorized_cat_create(&workspace, Instant::now(), path, &fields("key"), &below).unwrap();

    let mut exact = body("app", 4_194_304);
    exact.resize(CAT_CREATE_MAX_BODY_BYTES, b' ');
    assert_eq!(exact.len(), CAT_CREATE_MAX_BODY_BYTES);
    parse_authorized_cat_create(&workspace, Instant::now(), path, &fields("key"), &exact).unwrap();

    exact.push(b' ');
    assert!(
        parse_authorized_cat_create(&workspace, Instant::now(), path, &fields("key"), &exact,)
            .is_err()
    );
}

struct FakeManifestResolver {
    calls: AtomicUsize,
    size_bytes: u64,
}

impl CatCreateManifestResolver for FakeManifestResolver {
    fn resolve<'a>(
        &'a self,
        boot_image_digest: &'a Sha256Digest,
    ) -> ServiceFuture<'a, ValidatedImageManifest> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = ValidatedImageManifest {
            boot_image_digest: boot_image_digest.clone(),
            size_bytes: self.size_bytes,
        };
        Box::pin(async move { Ok(result) })
    }
}

struct FakePlanner {
    calls: AtomicUsize,
    last_request: Mutex<Option<CatCreatePlanRequest>>,
    replace_network_id: bool,
    retire_node: bool,
    target: Mutex<PlacementTargetSnapshot>,
}

pub(crate) fn placement_policy(
    node_id: &Id,
    guest_config_digest: &Sha256Digest,
) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        policy_revision: Epoch::new(1).unwrap(),
        scheduling_state: RuntimeSchedulingState::Schedulable,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: guest_config_digest.clone(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.0.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
    }
}

impl CatCreatePlacementPlanner for FakePlanner {
    fn plan<'a>(
        &'a self,
        request: &'a CatCreatePlanRequest,
        _absolute_deadline: Instant,
    ) -> ServiceFuture<'a, CatCreatePlacementOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_request.lock().unwrap() = Some(request.clone());
        let network_id = if self.replace_network_id {
            id("net_ffffffffffffffffffffffffffffffff")
        } else {
            request.network_id.clone()
        };
        let node_state = if self.retire_node {
            NodeIdentityState::Retired
        } else {
            NodeIdentityState::Provisioned
        };
        let mut target = self.target.lock().unwrap().clone();
        target.node_identity.state = node_state;
        let policy = placement_policy(
            &target.node_identity.node_id,
            &target.agent_session.guest_config_digest,
        );
        target.policy = policy.clone();
        let network_config =
            super::placement_planner::allocate_network_for_test(&policy, &network_id);
        Box::pin(async move {
            Ok(CatCreatePlacementOutcome::Planned(CatCreatePlan {
                target,
                mutation: CatCreatePlacementMutation {
                    cat_id: request.cat_id.clone(),
                    placement_epoch: Epoch::new(1).unwrap(),
                    vcpus: request.vcpus,
                    memory_bytes: request.memory_bytes,
                    network_config,
                },
            }))
        })
    }
}

#[derive(Default)]
struct SequentialIdentities(AtomicU64);

impl ProductIdentitySource for SequentialIdentities {
    fn random_id(&self) -> Result<RandomId128> {
        let value = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(RandomId128::new(format!("{value:032x}")).unwrap())
    }
}

struct PausingIdentities {
    next: AtomicU64,
    batch_ready: Mutex<Option<mpsc::Sender<()>>>,
    release_batch: Mutex<mpsc::Receiver<()>>,
}

impl ProductIdentitySource for PausingIdentities {
    fn random_id(&self) -> Result<RandomId128> {
        let value = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        if value == 9 {
            if let Some(ready) = self.batch_ready.lock().unwrap().take() {
                ready.send(()).unwrap();
            }
            self.release_batch.lock().unwrap().recv().unwrap();
        }
        Ok(RandomId128::new(format!("{value:032x}")).unwrap())
    }
}

fn release_receipt() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::from_bytes([3; 32]),
        initramfs_digest: Some(Sha256Digest::from_bytes([4; 32])),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

pub(crate) fn establish_empty_target(
    store: &Store,
    release: &GuestRuntimeProfileReceipt,
) -> PlacementTargetSnapshot {
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node_a"),
        provider_scope: ProviderScope {
            provider: id("test_provider"),
            partition: id("test_partition"),
            account_id: id("test_account"),
            region: id("test_region"),
        },
        immutable_host_id: id("host_a"),
        credential_id: id("credential_a"),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([9; 32]),
        },
        state_path_id: id("state_path_a"),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let registration_policy =
        AgentSessionRegistrationPolicy::from_release_receipt(release).unwrap();
    store.provision_node_identity(&identity).unwrap();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
        agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
        registration_attempt_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
        guest_config_digest: guest_config_digest(release).unwrap(),
        expected_agent_session_epoch: None,
    };
    let agent_session = match store
        .register_agent_session(&authenticated, &attempt, &registration_policy)
        .unwrap()
    {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("AgentSession registration rejected: {rejection:?}")
        }
    };
    let session = SessionBinding {
        node_id: agent_session.node_id.clone(),
        node_boot_id: agent_session.node_boot_id.clone(),
        agent_instance_id: agent_session.agent_instance_id.clone(),
        agent_session_epoch: agent_session.agent_session_epoch,
    };
    let mut full_report = RuntimeInventoryReport {
        version: ContractVersion::V1,
        session,
        report_id: RandomId128::new("44444444444444444444444444444444").unwrap(),
        sequence: Sequence::new(1).unwrap(),
        collected_at_unix_ms: UnixMillis::new(1).unwrap(),
        inventory: RuntimeInventoryBody::Full {
            inventory_epoch: Epoch::new(1).unwrap(),
            scan_id: RandomId128::new("55555555555555555555555555555555").unwrap(),
            inventory_digest: Sha256Digest::from_bytes([0; 32]),
            cats: Vec::new(),
            unattributed_artifacts: Vec::new(),
        },
    };
    let digest = full_inventory_digest(&full_report).unwrap();
    let RuntimeInventoryBody::Full {
        inventory_digest, ..
    } = &mut full_report.inventory
    else {
        unreachable!()
    };
    *inventory_digest = digest;
    match store
        .runtime_accept_inventory(&authenticated, &full_report)
        .unwrap()
    {
        RuntimeInventoryOutcome::Accepted(_) => {}
        RuntimeInventoryOutcome::Rejected(rejection) => {
            panic!("full inventory rejected: {rejection:?}")
        }
    }
    let inventory = store
        .load_current_full_inventory(&identity.node_id)
        .unwrap()
        .unwrap();
    let policy = placement_policy(&identity.node_id, &agent_session.guest_config_digest);
    PlacementTargetSnapshot {
        policy,
        node_identity: identity,
        agent_session,
        inventory_attestation: inventory.attestation.clone(),
        full_inventory_report: inventory.full_report,
        active_host_fence_event: None,
        evaluated_at_unix_ms: inventory.attestation.accepted_at_unix_ms,
    }
}

fn bootstrap_workspace(store: &Store, slug: &str) -> Id {
    store
        .ensure_configured_accounts(&BTreeMap::from([(slug.to_owned(), format!("org_{slug}"))]))
        .unwrap();
    let workspace: String = store
        .with(|client| {
            client
                .query_one(
                    "SELECT w.id FROM workspaces w JOIN accounts a ON a.id=w.account_id
                      WHERE a.slug=$1 AND w.is_default",
                    &[&slug],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    id(workspace)
}

fn service_fixture(
    slug: &str,
) -> (
    tokio::runtime::Runtime,
    Arc<Store>,
    Id,
    Arc<FakeManifestResolver>,
    Arc<FakePlanner>,
    CatCreateService,
) {
    let url = crate::testsupport::isolated_control_store_url();
    service_fixture_at(&url, slug)
}

fn service_fixture_at(
    url: &str,
    slug: &str,
) -> (
    tokio::runtime::Runtime,
    Arc<Store>,
    Id,
    Arc<FakeManifestResolver>,
    Arc<FakePlanner>,
    CatCreateService,
) {
    let store = Arc::new(Store::connect(url, None).unwrap());
    let workspace = bootstrap_workspace(&store, slug);
    crate::testsupport::begin_production_qualification_for_product_test(&store, &workspace);
    let release = release_receipt();
    let target = establish_empty_target(store.as_ref(), &release);
    store
        .authority_transaction(|transaction| {
            super::placement_policy::insert_policy_for_test(transaction, &target.policy)
        })
        .unwrap();
    let manifests = Arc::new(FakeManifestResolver {
        calls: AtomicUsize::new(0),
        size_bytes: 1,
    });
    let planner = Arc::new(FakePlanner {
        calls: AtomicUsize::new(0),
        last_request: Mutex::new(None),
        replace_network_id: false,
        retire_node: false,
        target: Mutex::new(target),
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let service = CatCreateService::new(
        store.clone(),
        manifests.clone(),
        planner.clone(),
        Arc::new(SequentialIdentities::default()),
        &release,
    )
    .unwrap();
    (runtime, store, workspace, manifests, planner, service)
}

pub(crate) fn disk_name_race_fixture_at(
    url: &str,
    slug: &str,
) -> (tokio::runtime::Runtime, Arc<Store>, Id, CatCreateService) {
    let (runtime, store, workspace, _manifests, _planner, service) = service_fixture_at(url, slug);
    (runtime, store, workspace, service)
}

#[test]
fn service_builds_the_complete_candidate_and_replays_before_external_reads() {
    let (runtime, store, workspace, manifests, planner, service) = service_fixture("f2c-replay");
    let first = runtime
        .block_on(service.create(ingress(&workspace, "app", "same-key")))
        .unwrap();
    assert_eq!(first.http_status, 202);
    assert_eq!(first.content_type, Some("application/json"));
    assert_eq!(
        first.response_body,
        br#"{"cat_id":"cat_00000000000000000000000000000001","operation_id":"op_00000000000000000000000000000006"}"#
    );
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 1);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 1);
    let plan_request = planner.last_request.lock().unwrap().clone().unwrap();
    assert_eq!(
        plan_request.cat_id.as_str(),
        "cat_00000000000000000000000000000001"
    );
    assert_eq!(plan_request.vcpus, 2);
    assert_eq!(plan_request.memory_bytes, 2_147_483_648);
    assert_eq!(plan_request.root_size_bytes, 4_194_304);
    assert_eq!(plan_request.durability, Durability::Strict);
    assert_eq!(plan_request.boot_image_digest.as_str(), BOOT_DIGEST);
    assert_eq!(
        plan_request.guest_config_digest,
        guest_config_digest(&release_receipt()).unwrap()
    );
    assert_eq!(
        plan_request.network_id.as_str(),
        "net_00000000000000000000000000000008"
    );

    let replay = runtime
        .block_on(service.create(ingress(&workspace, "app", "same-key")))
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 1);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 1);

    assert!(runtime
        .block_on(service.create(ingress(&workspace, "other", "same-key")))
        .is_err());
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 1);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 1);

    let counts: Vec<i64> = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM disk_records),
                        (SELECT count(*) FROM volume_records),
                        (SELECT count(*) FROM cat_runtime_configs),
                        (SELECT count(*) FROM endpoint_records),
                        (SELECT count(*) FROM hostname_endpoint_lookups),
                        (SELECT count(*) FROM runtime_operations),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (0..8).map(|index| row.get(index)).collect())
        })
        .unwrap();
    assert_eq!(counts, vec![1; 8]);

    let (config_bytes, operation_bytes): (Vec<u8>, Vec<u8>) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT config.canonical_config_bytes,
                            operation.canonical_request_bytes
                       FROM cat_records cat
                       JOIN cat_runtime_configs config
                         ON config.config_id=cat.current_runtime_config_id
                       JOIN runtime_operations operation
                         ON operation.cat_id=cat.cat_id
                      WHERE cat.cat_id='cat_00000000000000000000000000000001'",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    let config = decode_immutable_runtime_config(&config_bytes).unwrap();
    assert_eq!(
        config.config_id.as_str(),
        "cfg_00000000000000000000000000000005"
    );
    assert_eq!(config.vcpus, 2);
    assert_eq!(config.memory_bytes, 2_147_483_648);
    assert_eq!(config.boot_image_digest.as_str(), BOOT_DIGEST);
    assert_eq!(
        config.guest_runtime_profile_digest,
        plan_request.guest_config_digest
    );
    let RuntimeNetworkConfig::IsolatedIpv4 {
        network_id,
        guest_mac,
        guest_ipv4,
        prefix_length,
        gateway_ipv4,
    } = &config.network_config;
    assert_eq!(network_id, &plan_request.network_id);
    assert_eq!(guest_mac.as_str(), "02:ca:0a:00:28:aa");
    assert_eq!(guest_ipv4.as_str(), "10.0.40.170");
    assert_eq!(*prefix_length, 30);
    assert_eq!(gateway_ipv4.as_str(), "10.0.40.169");
    let [root] = config.volumes.as_slice() else {
        panic!("Genesis config must contain exactly one Root volume")
    };
    assert_eq!(
        root.disk_id.as_str(),
        "disk_00000000000000000000000000000003"
    );
    assert_eq!(
        root.volume_id.as_str(),
        "vol_00000000000000000000000000000004"
    );
    assert_eq!(root.durability, Durability::Strict);
    assert_eq!(root.size_bytes, 4_194_304);
    assert_eq!(root.guest_device_serial.as_str(), "cats-root");
    assert_eq!(root.guest_device_slot, 0);
    assert_eq!(root.guest_binding, RuntimeVolumeGuestBinding::RootBoot);

    let operation = decode_lifecycle_command_envelope(&operation_bytes).unwrap();
    assert_eq!(
        operation.operation_id.as_str(),
        "op_00000000000000000000000000000006"
    );
    assert_eq!(operation.workspace_id, workspace);
    assert_eq!(
        operation.cat_id.as_str(),
        "cat_00000000000000000000000000000001"
    );
    assert_eq!(operation.node_id.as_str(), "node_a");
    assert_eq!(operation.placement_identity.placement_epoch.get(), 1);
    assert_eq!(operation.runtime_config(), &config);
    assert!(matches!(
        &operation.predecessor,
        LifecyclePredecessor::Genesis {
            cat_creation_id,
            target_placement,
        } if cat_creation_id.as_str() == "creation_00000000000000000000000000000002"
            && target_placement.node_id.as_str() == "node_a"
            && target_placement.placement_epoch.get() == 1
    ));
    let LifecycleCommand::Start(start) = &operation.command else {
        panic!("Genesis Operation must be Start")
    };
    let [authority] = start.volume_authorities.as_slice() else {
        panic!("Genesis Start must carry one exact Root authority")
    };
    assert_eq!(authority.volume_id, root.volume_id);
    assert_eq!(authority.disk_id, root.disk_id);
    assert!(matches!(
        &authority.authority,
        RuntimeVolumeAuthorityInput::NormalUnowned {
            expected_unowned_epoch,
            transition_id,
        } if expected_unowned_epoch.get() == 0
            && transition_id.as_str() == "00000000000000000000000000000009"
    ));

    let product_projection: (String, String, String, i64, Option<String>, Option<String>) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT disk.disk_id, volume.volume_id, endpoint.hostname,
                            endpoint.route_epoch, cat.lifecycle_head_operation_id,
                            cat.stable_state
                       FROM cat_records cat
                       JOIN disk_records disk ON disk.root_cat_id=cat.cat_id
                       JOIN volume_records volume ON volume.volume_id=disk.volume_id
                       JOIN endpoint_records endpoint ON endpoint.cat_id=cat.cat_id",
                    &[],
                )
                .map(|row| {
                    (
                        row.get(0),
                        row.get(1),
                        row.get(2),
                        row.get(3),
                        row.get(4),
                        row.get(5),
                    )
                })
        })
        .unwrap();
    assert_eq!(
        product_projection,
        (
            "disk_00000000000000000000000000000003".to_owned(),
            "vol_00000000000000000000000000000004".to_owned(),
            "app-00000000000000000000000000000007.cats.run".to_owned(),
            1,
            None,
            None,
        )
    );
}

#[test]
fn service_persists_only_the_fixed_name_conflict_result() {
    let (runtime, _store, workspace, manifests, planner, service) = service_fixture("f2c-name");
    runtime
        .block_on(service.create(ingress(&workspace, "app", "first")))
        .unwrap();
    let conflict = runtime
        .block_on(service.create(ingress(&workspace, "app", "second")))
        .unwrap();
    assert_eq!(conflict.http_status, 409);
    assert_eq!(
        conflict.response_body,
        br#"{"code":"already_exists","message":"cat name already exists"}"#
    );
    let replay = runtime
        .block_on(service.create(ingress(&workspace, "app", "second")))
        .unwrap();
    assert_eq!(replay, conflict);
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 2);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn candidate_collision_is_retryable_and_the_same_key_uses_a_fresh_whole_batch() {
    let (runtime, store, workspace, manifests, planner, service) =
        service_fixture("f2c-candidate-retry");
    // Seed the colliding ID through the same complete product transaction.
    // The former test-only `insert_cat` wrote only the immutable JSON
    // projection and stopped satisfying the clean-slate Cat/config foreign
    // key shape, so its failure no longer characterized candidate retry.
    let seed_manifests: Arc<dyn CatCreateManifestResolver> = manifests.clone();
    let seed_planner: Arc<dyn CatCreatePlacementPlanner> = planner.clone();
    let seed = CatCreateService::new(
        Arc::clone(&store),
        seed_manifests,
        seed_planner,
        Arc::new(SequentialIdentities::default()),
        &release_receipt(),
    )
    .unwrap();
    runtime
        .block_on(seed.create(ingress(&workspace, "seed-collision", "seed-key")))
        .unwrap();
    manifests.calls.store(0, Ordering::SeqCst);
    planner.calls.store(0, Ordering::SeqCst);
    *planner.last_request.lock().unwrap() = None;

    let first = runtime
        .block_on(service.create(ingress(&workspace, "app", "same-key")))
        .unwrap_err();
    assert_eq!(first.error_code(), cats_api::error::ErrorCode::Unavailable);
    let result_rows: i64 = store
        .with(|client| {
            client
                .query_one(
                    "SELECT count(*) FROM api_idempotency_results
                      WHERE authenticated_workspace_id=$1 AND idempotency_key='same-key'",
                    &[&workspace.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(result_rows, 0);

    let retry = runtime
        .block_on(service.create(ingress(&workspace, "app", "same-key")))
        .unwrap();
    assert_eq!(retry.http_status, 202);
    assert_eq!(
        retry.response_body,
        br#"{"cat_id":"cat_0000000000000000000000000000000a","operation_id":"op_0000000000000000000000000000000f"}"#
    );
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 2);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn pre_commit_deadline_waits_for_rollback_and_leaves_no_cached_result() {
    let url = crate::testsupport::isolated_control_store_url();
    let (runtime, store, workspace, _manifests, _planner, service) =
        service_fixture_at(&url, "a23-precommit-deadline");
    store
        .with(|client| client.batch_execute("SET statement_timeout='8s'; SET lock_timeout='8s'"))
        .unwrap();
    let mut blocker = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut blocker_tx = blocker.transaction().unwrap();
    super::cat_create_service::lock_cat_create_text(
        &mut blocker_tx,
        "cat-name",
        workspace.as_str(),
        "app",
    )
    .unwrap();

    let headers_received_at = Instant::now()
        // Leave enough time for the shared bounded Store executor under the
        // full parallel suite. The test-only session timeouts above remain
        // longer, so the service's PRE_COMMIT cancellation is the cause.
        .checked_sub(CAT_CREATE_TOTAL_DEADLINE - Duration::from_secs(6))
        .unwrap();
    let error = runtime
        .block_on(service.create(ingress_with_size_at(
            &workspace,
            "app",
            "deadline-key",
            4_194_304,
            headers_received_at,
        )))
        .unwrap_err();
    assert_eq!(error.error_code(), cats_api::error::ErrorCode::Unavailable);
    drop(blocker_tx);

    let counts: (i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(counts, (0, 0));

    let retry = runtime
        .block_on(service.create(ingress(&workspace, "app", "deadline-key")))
        .unwrap();
    assert_eq!(retry.http_status, 202);
    let replay = runtime
        .block_on(service.create(ingress(&workspace, "app", "deadline-key")))
        .unwrap();
    assert_eq!(replay, retry);
    let committed_counts: (i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(committed_counts, (1, 1));
}

#[test]
fn definite_commit_retry_reenters_the_absolute_deadline() {
    let url = crate::testsupport::isolated_control_store_url();
    let (runtime, store, workspace, _manifests, _planner, service) =
        service_fixture_at(&url, "a23-commit-retry-deadline");
    store
        .with(|client| {
            client.batch_execute(
                "CREATE SEQUENCE a23_commit_retry_attempt;
                 CREATE FUNCTION a23_block_retry_before_commit() RETURNS trigger AS $$
                 DECLARE attempted BOOLEAN;
                 BEGIN
                   SELECT is_called INTO attempted
                     FROM a23_commit_retry_attempt;
                   IF attempted THEN
                     PERFORM pg_sleep(5);
                   END IF;
                   RETURN NEW;
                 END;
                 $$ LANGUAGE plpgsql;
                 CREATE TRIGGER a23_block_retry_before_commit
                   BEFORE INSERT ON runtime_operations
                   FOR EACH ROW EXECUTE FUNCTION a23_block_retry_before_commit();
                 CREATE FUNCTION a23_fail_first_commit() RETURNS trigger AS $$
                 BEGIN
                   IF nextval('a23_commit_retry_attempt') = 1 THEN
                     RAISE EXCEPTION 'retry exact create' USING ERRCODE='40001';
                   END IF;
                   RETURN NEW;
                 END;
                 $$ LANGUAGE plpgsql;
                 CREATE CONSTRAINT TRIGGER a23_fail_first_commit
                   AFTER INSERT ON runtime_operations
                   DEFERRABLE INITIALLY DEFERRED
                   FOR EACH ROW EXECUTE FUNCTION a23_fail_first_commit();",
            )
        })
        .unwrap();
    let headers_received_at = Instant::now()
        .checked_sub(CAT_CREATE_TOTAL_DEADLINE - Duration::from_millis(1_500))
        .unwrap();
    let started = Instant::now();
    let error = runtime
        .block_on(service.create(ingress_with_size_at(
            &workspace,
            "app",
            "retry-deadline",
            4_194_304,
            headers_received_at,
        )))
        .unwrap_err();
    assert_eq!(error.error_code(), cats_api::error::ErrorCode::Unavailable);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "a definite commit retry ignored the original absolute deadline"
    );
    let counts: (i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(counts, (0, 0));
}

#[test]
fn committed_response_loss_resolves_the_exact_durable_result() {
    let (runtime, store, workspace, manifests, planner, service) =
        service_fixture("a23-commit-response-loss");
    store.inject_committed_response_loss_once();

    let first = runtime
        .block_on(service.create(ingress(&workspace, "app", "lost-response")))
        .unwrap();
    assert_eq!(first.http_status, 202);
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 1);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 1);
    let replay = runtime
        .block_on(service.create(ingress(&workspace, "app", "lost-response")))
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 1);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn committed_owner_survives_handler_abort_and_shutdown_waits_for_resolution() {
    let url = crate::testsupport::isolated_control_store_url();
    let (runtime, store, workspace, manifests, planner, service) =
        service_fixture_at(&url, "a23-commit-owner-abort");
    store.inject_committed_response_loss_once_after(Duration::from_millis(1_500));
    let observer = Store::connect(&url, None).unwrap();
    let service = Arc::new(service);
    let request = ingress(&workspace, "app", "owner-abort");
    let handler = runtime.spawn({
        let service = Arc::clone(&service);
        async move { service.create(request).await }
    });

    runtime.block_on(async {
        tokio::time::timeout(cats_test_support::poll_bound(), async {
            loop {
                let count: i64 = observer
                    .with(|client| {
                        client
                            .query_one("SELECT count(*) FROM api_idempotency_results", &[])
                            .map(|row| row.get(0))
                    })
                    .unwrap();
                if count == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the real PostgreSQL commit must become visible");
        assert!(
            !handler.is_finished(),
            "the injected response-loss delay must retain the request"
        );
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());

        let shutdown = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.shutdown_commit_resolutions().await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !shutdown.is_finished(),
            "shutdown returned while the detached commit owner was unresolved"
        );
        tokio::time::timeout(cats_test_support::poll_bound(), shutdown)
            .await
            .expect("commit resolution must converge")
            .unwrap()
            .unwrap();

        let rejected = service
            .create(ingress(&workspace, "app", "owner-abort"))
            .await
            .unwrap_err();
        assert!(matches!(
            rejected,
            super::cat_create_service::CatCreateServiceError::TemporarilyUnavailable
        ));
    });
    assert_eq!(manifests.calls.load(Ordering::SeqCst), 1);
    assert_eq!(planner.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn queued_pre_commit_owner_is_cancelled_when_its_handler_is_aborted() {
    let (runtime, store, workspace, manifests, planner, _service) =
        service_fixture("a23-queued-pre-owner-abort");
    let (batch_ready_tx, batch_ready_rx) = mpsc::channel();
    let (release_batch_tx, release_batch_rx) = mpsc::channel();
    let service = Arc::new(
        CatCreateService::new(
            store.clone(),
            manifests,
            planner,
            Arc::new(PausingIdentities {
                next: AtomicU64::new(0),
                batch_ready: Mutex::new(Some(batch_ready_tx)),
                release_batch: Mutex::new(release_batch_rx),
            }),
            &release_receipt(),
        )
        .unwrap(),
    );
    let handler = runtime.spawn({
        let service = Arc::clone(&service);
        let request = ingress(&workspace, "app", "queued-pre-abort");
        async move { service.create(request).await }
    });
    batch_ready_rx
        .recv_timeout(cats_test_support::poll_bound())
        .expect("the request must finish its fresh identity batch");

    // Hold this exact Store's one-connection lane only after fast replay has
    // missed. Releasing the ninth identity then lets this request plan and
    // register its PRE_COMMIT owner behind that bounded lane without starving
    // unrelated Store instances in concurrently running tests.
    let (blocker_started_tx, blocker_started_rx) = mpsc::channel();
    let (release_blocker_tx, release_blocker_rx) = mpsc::channel();
    let blocker = runtime.spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .execute(move |_| {
                    blocker_started_tx.send(()).unwrap();
                    release_blocker_rx.recv().unwrap();
                    Ok(())
                })
                .await
        }
    });
    blocker_started_rx
        .recv_timeout(cats_test_support::poll_bound())
        .expect("the same-Store lane blocker must start");
    release_batch_tx.send(()).unwrap();
    let registered = Instant::now();
    while service.active_commit_resolutions() != 1 {
        assert!(registered.elapsed() < cats_test_support::poll_bound());
        std::thread::yield_now();
    }
    assert!(!handler.is_finished());
    handler.abort();
    assert!(runtime.block_on(handler).unwrap_err().is_cancelled());

    // The commit owner must observe the dropped request token and remove its
    // still-queued Store operation. Shutdown therefore resolves while the
    // connection lane remains blocked; releasing it is not part of the oracle.
    runtime
        .block_on(async {
            tokio::time::timeout(
                cats_test_support::poll_bound(),
                service.shutdown_commit_resolutions(),
            )
            .await
        })
        .expect("queued PRE_COMMIT ownership must resolve without a Store worker")
        .unwrap();

    release_blocker_tx.send(()).unwrap();
    runtime.block_on(blocker).unwrap().unwrap();
    let counts: (i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(counts, (0, 0));
}

#[test]
fn fast_replay_lookup_lock_timeout_is_unavailable_and_has_no_side_effect() {
    let url = crate::testsupport::isolated_control_store_url();
    let (runtime, store, workspace, _manifests, _planner, service) =
        service_fixture_at(&url, "a23-fast-lookup-timeout");
    let mut blocker = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut blocker_tx = blocker.transaction().unwrap();
    blocker_tx
        .batch_execute("LOCK TABLE api_idempotency_results IN ACCESS EXCLUSIVE MODE")
        .unwrap();

    let started = Instant::now();
    let error = runtime
        .block_on(service.create(ingress(&workspace, "app", "locked-fast-lookup")))
        .unwrap_err();
    assert_eq!(error.error_code(), cats_api::error::ErrorCode::Unavailable);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the configured PostgreSQL lock timeout did not bound fast replay lookup"
    );
    blocker_tx.rollback().unwrap();

    let counts: (i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(counts, (0, 0));
}

#[test]
fn post_commit_resolver_waits_for_the_original_api_key_owner() {
    let url = crate::testsupport::isolated_control_store_url();
    let (_runtime, _store, workspace, _manifests, _planner, _service) =
        service_fixture_at(&url, "a23-commit-resolution-lock");
    let ingress = ingress(&workspace, "app", "resolution-lock");
    let request = ingress.idempotency().clone();
    let mut blocker = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut blocker_tx = blocker.transaction().unwrap();
    blocker_tx
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                current_schema() || ':api-result:' || $1 || ':' || $2 || ':' || $3,
                0::BIGINT
             ))",
            &[
                &request.authenticated_workspace_id.as_str(),
                &request.canonical_route.as_str(),
                &request.idempotency_key.as_str(),
            ],
        )
        .unwrap();

    let (done_tx, done_rx) = mpsc::channel();
    let resolver = std::thread::spawn(move || {
        let store = Store::connect(&url, None).unwrap();
        done_tx
            .send(store.covered_api_result_after_commit(&request))
            .unwrap();
    });
    assert!(
        done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "a resolver must not treat a pre-visibility miss as definite rollback"
    );
    blocker_tx.commit().unwrap();
    assert!(done_rx
        .recv_timeout(cats_test_support::poll_bound())
        .unwrap()
        .unwrap()
        .is_none());
    resolver.join().unwrap();
}

#[test]
fn service_rounds_root_size_to_the_chunk_boundary() {
    let (runtime, store, workspace, _manifests, _planner, service) = service_fixture("f2c-round");
    runtime
        .block_on(service.create(ingress_with_size(&workspace, "rounded", "round", 4_194_305)))
        .unwrap();
    let size_bytes: i64 = store
        .with(|client| {
            client
                .query_one("SELECT size_bytes FROM volume_records", &[])
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(size_bytes, 8_388_608);
}

#[test]
fn invalid_manifest_or_planner_binding_has_no_store_side_effect() {
    let (runtime, store, workspace, _manifests, base_planner, _service) =
        service_fixture("f2c-invalid");
    let target = base_planner.target.lock().unwrap().clone();
    let oversized = Arc::new(FakeManifestResolver {
        calls: AtomicUsize::new(0),
        size_bytes: 8_388_608,
    });
    let planner = Arc::new(FakePlanner {
        calls: AtomicUsize::new(0),
        last_request: Mutex::new(None),
        replace_network_id: false,
        retire_node: false,
        target: Mutex::new(target.clone()),
    });
    let service = CatCreateService::new(
        store.clone(),
        oversized,
        planner.clone(),
        Arc::new(SequentialIdentities::default()),
        &release_receipt(),
    )
    .unwrap();
    assert!(runtime
        .block_on(service.create(ingress(&workspace, "small", "manifest")))
        .is_err());
    assert_eq!(planner.calls.load(Ordering::SeqCst), 0);

    let wrong_planner = Arc::new(FakePlanner {
        calls: AtomicUsize::new(0),
        last_request: Mutex::new(None),
        replace_network_id: true,
        retire_node: false,
        target: Mutex::new(target.clone()),
    });
    let service = CatCreateService::new(
        store.clone(),
        Arc::new(FakeManifestResolver {
            calls: AtomicUsize::new(0),
            size_bytes: 1,
        }),
        wrong_planner,
        Arc::new(SequentialIdentities::default()),
        &release_receipt(),
    )
    .unwrap();
    assert!(runtime
        .block_on(service.create(ingress(&workspace, "wrong-net", "planner")))
        .is_err());

    let retired_planner = Arc::new(FakePlanner {
        calls: AtomicUsize::new(0),
        last_request: Mutex::new(None),
        replace_network_id: false,
        retire_node: true,
        target: Mutex::new(target),
    });
    let service = CatCreateService::new(
        store.clone(),
        Arc::new(FakeManifestResolver {
            calls: AtomicUsize::new(0),
            size_bytes: 1,
        }),
        retired_planner,
        Arc::new(SequentialIdentities::default()),
        &release_receipt(),
    )
    .unwrap();
    assert!(runtime
        .block_on(service.create(ingress(&workspace, "retired", "retired")))
        .is_err());
    let rows: i64 = store
        .with(|client| {
            client
                .query_one("SELECT count(*) FROM cat_records", &[])
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(rows, 0);
}

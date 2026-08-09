use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use cats_api::runtime_reconciliation::{
    AdmissionInventoryAttestation, AgentSession, AsciiText, ContractVersion, CredentialBinding,
    Epoch, GuestRuntimeProfileReceipt, Id, Ipv4Address, MacAddress, NetworkConfig, NodeBootId,
    NodeIdentity, NodeIdentityState, RandomId128, Sequence, Sha256Digest, UnixMillis,
};

use super::cat_create_service::{
    parse_authorized_cat_create, CatCreateHttpFields, CatCreateIdentitySource,
    CatCreateManifestResolver, CatCreatePlacementPlanner, CatCreatePlan, CatCreatePlanRequest,
    CatCreateService, ServiceFuture, ValidatedImageManifest, CAT_CREATE_MAX_BODY_BYTES,
};
use crate::store::{Result, Store};

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

fn ingress(
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
    parse_authorized_cat_create(
        workspace,
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
    let mut duplicate_type = fields("key");
    duplicate_type
        .content_type
        .push(b"application/json".to_vec());
    cases.push((path.as_slice(), duplicate_type, valid_body.clone()));
    let mut encoded = fields("key");
    encoded.content_encoding = vec![b"gzip".to_vec()];
    cases.push((path.as_slice(), encoded, valid_body.clone()));
    let mut if_match = fields("key");
    if_match.if_match = vec![b"1".to_vec()];
    cases.push((path.as_slice(), if_match, valid_body.clone()));
    let mut duplicate_key = fields("key");
    duplicate_key.idempotency_key.push(b"other".to_vec());
    cases.push((path.as_slice(), duplicate_key, valid_body.clone()));

    for (raw_path, headers, raw_body) in cases {
        assert!(parse_authorized_cat_create(&workspace, raw_path, &headers, &raw_body).is_err());
    }
    for raw_path in [
        b"/v1/workspaces/ws_01/cats?x=1".as_slice(),
        b"/v1/workspaces/%77s_01/cats".as_slice(),
        b"/v1/workspaces/ws_other/cats".as_slice(),
    ] {
        assert!(
            parse_authorized_cat_create(&workspace, raw_path, &fields("key"), &valid_body).is_err()
        );
    }

    let duplicate = valid_body
        .iter()
        .position(|byte| *byte == b'}')
        .map(|index| {
            let mut value = valid_body[..index].to_vec();
            value.extend_from_slice(b",\"vcpus\":3}");
            value
        })
        .unwrap();
    let unknown = String::from_utf8(valid_body.clone())
        .unwrap()
        .replace("}", ",\"image\":\"ubuntu\"}")
        .into_bytes();
    let null = String::from_utf8(valid_body.clone())
        .unwrap()
        .replace("\"vcpus\":2", "\"vcpus\":null")
        .into_bytes();
    let float = String::from_utf8(valid_body.clone())
        .unwrap()
        .replace("\"vcpus\":2", "\"vcpus\":2.0")
        .into_bytes();
    let legacy = br#"{"name":"app","image":"ubuntu-24.04"}"#.to_vec();
    for invalid in [duplicate, unknown, null, float, legacy] {
        assert!(parse_authorized_cat_create(&workspace, path, &fields("key"), &invalid).is_err());
    }
}

#[test]
fn ingress_enforces_the_body_cap_before_decode() {
    let workspace = id("ws_01");
    let path = b"/v1/workspaces/ws_01/cats";
    let mut exact = body("app", 4_194_304);
    exact.resize(CAT_CREATE_MAX_BODY_BYTES, b' ');
    assert_eq!(exact.len(), CAT_CREATE_MAX_BODY_BYTES);
    parse_authorized_cat_create(&workspace, path, &fields("key"), &exact).unwrap();

    exact.push(b' ');
    assert!(parse_authorized_cat_create(&workspace, path, &fields("key"), &exact).is_err());
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
    replace_network_id: bool,
    retire_node: bool,
}

impl CatCreatePlacementPlanner for FakePlanner {
    fn plan<'a>(&'a self, request: &'a CatCreatePlanRequest) -> ServiceFuture<'a, CatCreatePlan> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let network_id = if self.replace_network_id {
            id("net_ffffffffffffffffffffffffffffffff")
        } else {
            request.network_id.clone()
        };
        let guest_config_digest = request.guest_config_digest.clone();
        let node_state = if self.retire_node {
            NodeIdentityState::Retired
        } else {
            NodeIdentityState::Provisioned
        };
        Box::pin(async move {
            Ok(CatCreatePlan {
                node_identity: NodeIdentity {
                    version: ContractVersion::V1,
                    node_id: id("node_a"),
                    immutable_host_id: id("host_a"),
                    credential_id: id("credential_a"),
                    credential_binding: CredentialBinding::PublicKey {
                        public_key_spki_sha256: Sha256Digest::from_bytes([5; 32]),
                    },
                    state_path_id: id("state_path_a"),
                    state: node_state,
                },
                agent_session: AgentSession {
                    version: ContractVersion::V1,
                    node_id: id("node_a"),
                    immutable_host_id: id("host_a"),
                    node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
                    agent_instance_id: RandomId128::new("22222222222222222222222222222222")
                        .unwrap(),
                    agent_session_epoch: Epoch::new(1).unwrap(),
                    registration_attempt_id: RandomId128::new("33333333333333333333333333333333")
                        .unwrap(),
                    guest_config_digest,
                    lease_deadline_unix_ms: UnixMillis::new(10_000).unwrap(),
                },
                admission_inventory: AdmissionInventoryAttestation {
                    version: ContractVersion::V1,
                    node_id: id("node_a"),
                    agent_session_epoch: Epoch::new(1).unwrap(),
                    inventory_epoch: Epoch::new(1).unwrap(),
                    inventory_digest: Sha256Digest::from_bytes([6; 32]),
                    inventory_read_position: Sequence::new(1).unwrap(),
                    accepted_at_unix_ms: UnixMillis::new(1).unwrap(),
                },
                network_config: NetworkConfig {
                    kind: cats_api::runtime_reconciliation::IsolatedIpv4Kind::IsolatedIpv4,
                    network_id,
                    guest_mac: MacAddress::new("02:00:00:00:00:01").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                },
            })
        })
    }
}

#[derive(Default)]
struct SequentialIdentities(AtomicU64);

impl CatCreateIdentitySource for SequentialIdentities {
    fn random_id(&self) -> Result<RandomId128> {
        let value = self.0.fetch_add(1, Ordering::SeqCst) + 1;
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
    let store = Arc::new(Store::connect(&url, None).unwrap());
    let workspace = bootstrap_workspace(&store, slug);
    let manifests = Arc::new(FakeManifestResolver {
        calls: AtomicUsize::new(0),
        size_bytes: 1,
    });
    let planner = Arc::new(FakePlanner {
        calls: AtomicUsize::new(0),
        replace_network_id: false,
        retire_node: false,
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
        &release_receipt(),
    )
    .unwrap();
    (runtime, store, workspace, manifests, planner, service)
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
                        (SELECT count(*) FROM desired_runtime_specs),
                        (SELECT count(*) FROM endpoint_records),
                        (SELECT count(*) FROM hostname_desired_lookups),
                        (SELECT count(*) FROM runtime_operations),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (0..8).map(|index| row.get(index)).collect())
        })
        .unwrap();
    assert_eq!(counts, vec![1; 8]);
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
    let (runtime, store, workspace, _manifests, _planner, _service) =
        service_fixture("f2c-invalid");
    let oversized = Arc::new(FakeManifestResolver {
        calls: AtomicUsize::new(0),
        size_bytes: 8_388_608,
    });
    let planner = Arc::new(FakePlanner {
        calls: AtomicUsize::new(0),
        replace_network_id: false,
        retire_node: false,
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
        replace_network_id: true,
        retire_node: false,
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
        replace_network_id: false,
        retire_node: true,
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

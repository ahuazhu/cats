//! Real PostgreSQL acceptance tests for covered Cat create.

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    spec_digest, AsciiText, AssignedKind, AssignedPlacement, ContractVersion, DesiredRuntimeSpec,
    DiskKind, Durability, Epoch, FenceEpoch, Generation, GuestDeviceIdentity, Id, Ipv4Address,
    IsolatedIpv4Kind, MacAddress, NetworkConfig, RandomId128, Revision, RuntimeConfig,
    RuntimeTarget, RuntimeTransition, Sha256Digest, UnixMillis, VolumeAccess, VolumeAcquire,
    VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::{
    LastVolumeTransition, RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord,
};
use sha2::{Digest, Sha256};

use super::product::{
    api_request_fingerprint, encode_cat_create_accepted_response,
    encode_cat_name_conflict_response, ApiIdempotencyRequest, CandidateCollision,
    CatCreateCandidate, CatCreateEnvelopes, CoveredCatCreateError, CoveredCatCreateRequest,
    DiskAdminState, DiskRecord, DiskRecordCandidate, DiskRole, ExactContentType, ExactHttpResponse,
    IfMatchFingerprint, PersistentDiskInitialization,
};
use super::product_rows::{insert_disk, load_disk_by_id_for_update};
use super::rows::insert_volume;
use crate::store::{internal, DsnSource, Store};

const ROUTE: &str = "POST /v1/workspaces/{workspace}/cats";

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn random_id(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn generation(value: u64) -> Generation {
    Generation::new(value).unwrap()
}

fn epoch(value: u64) -> Epoch {
    Epoch::new(value).unwrap()
}

fn fence_epoch(value: u64) -> FenceEpoch {
    FenceEpoch::new(value).unwrap()
}

fn revision(value: u64) -> Revision {
    Revision::new(value).unwrap()
}

fn unix_millis(value: u64) -> UnixMillis {
    UnixMillis::new(value).unwrap()
}

fn blank_volume(volume_id: &str) -> VolumeRecord {
    VolumeRecord {
        volume_id: id(volume_id),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: RemoteHead {
            generation: generation(0),
            root_hash: None,
            root_object_id: None,
        },
        lease_owner: None,
        lease_epoch: fence_epoch(0),
        lease_expires_at: None,
        last_transition: None,
    }
}

fn persistent_disk(
    workspace_id: &Id,
    disk_id: &str,
    name: &str,
    volume: &VolumeRecord,
    initialization: PersistentDiskInitialization,
) -> DiskRecord {
    DiskRecord {
        disk_id: id(disk_id),
        workspace_id: workspace_id.clone(),
        name: id(name),
        volume_id: volume.volume_id.clone(),
        size_bytes: volume.size_bytes,
        durability: volume.durability,
        created_at: unix_millis(123),
        admin_state: DiskAdminState::Active,
        role: DiskRole::Persistent {
            initialization: Box::new(initialization),
        },
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

fn stores() -> (String, Store, Store, Id) {
    let url = crate::testsupport::isolated_control_store_url();
    let first = Store::connect(&url, None).unwrap();
    let second = Store::connect(&url, None).unwrap();
    let workspace = bootstrap_workspace(&first, "f2a");
    (url, first, second, workspace)
}

fn with_application_name(url: &str, application_name: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}application_name={application_name}")
}

fn request(
    workspace: &Id,
    name: &str,
    sequence: u64,
    idempotency_key: &str,
) -> CoveredCatCreateRequest {
    let cat_id = id(format!("cat_{sequence}"));
    let disk_id = id(format!("disk_{sequence}"));
    let volume_id = id(format!("volume_{sequence}"));
    let operation_id = id(format!("op_{sequence}"));
    let size_bytes = 4 * 1024 * 1024;
    let volume = VolumeRecord {
        volume_id: volume_id.clone(),
        size_bytes,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: RemoteHead {
            generation: generation(0),
            root_hash: None,
            root_object_id: None,
        },
        lease_owner: None,
        lease_epoch: fence_epoch(0),
        lease_expires_at: None,
        last_transition: None,
    };
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: workspace.clone(),
        cat_id: cat_id.clone(),
        desired_revision: revision(1),
        target: RuntimeTarget::Running,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: id(format!("node_{sequence}")),
            placement_epoch: epoch(1),
        },
        runtime: RuntimeConfig {
            vcpus: 1,
            memory_bytes: 256 * 1024 * 1024,
            boot_image_digest: Sha256Digest::from_bytes([1; 32]),
            guest_config_digest: Sha256Digest::from_bytes([2; 32]),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id(format!("network_{sequence}")),
                guest_mac: MacAddress::new("02:00:00:00:00:01").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
            },
        },
        volumes: vec![VolumeIntent {
            volume_intent_id: id(format!("volume-intent_{sequence}")),
            disk_id: disk_id.clone(),
            volume_id: volume_id.clone(),
            attachment_id: id(format!("attachment_{sequence}")),
            size_bytes,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id(format!("root-device_{sequence}")),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: random_id(10_000 + u128::from(sequence)),
                expected_unowned_epoch: fence_epoch(0),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        }],
        endpoints: Vec::new(),
        transition: RuntimeTransition::CancelAndDrain,
        spec_digest: Sha256Digest::from_bytes([0; 32]),
    };
    desired.spec_digest = spec_digest(&desired).unwrap();

    let raw_body = format!(r#"{{"name":"{name}"}}"#);
    let idempotency = ApiIdempotencyRequest {
        authenticated_workspace_id: workspace.clone(),
        canonical_route: AsciiText::new(ROUTE).unwrap(),
        idempotency_key: AsciiText::new(idempotency_key).unwrap(),
        request_fingerprint: api_request_fingerprint(
            workspace,
            &AsciiText::new(ROUTE).unwrap(),
            format!("/v1/workspaces/{workspace}/cats").as_bytes(),
            IfMatchFingerprint::Absent,
            raw_body.as_bytes(),
        )
        .unwrap(),
    };
    let accepted = ExactHttpResponse::new(
        202,
        Some(ExactContentType::ApplicationJson),
        encode_cat_create_accepted_response(&cat_id, &operation_id).unwrap(),
    )
    .unwrap();
    let conflict = ExactHttpResponse::new(
        409,
        Some(ExactContentType::ApplicationJson),
        encode_cat_name_conflict_response(),
    )
    .unwrap();
    CoveredCatCreateRequest {
        idempotency,
        candidate: CatCreateCandidate {
            cat_id: cat_id.clone(),
            workspace_id: workspace.clone(),
            name: id(name),
            root_disk: DiskRecordCandidate {
                disk_id: disk_id.clone(),
                workspace_id: workspace.clone(),
                name: disk_id.clone(),
                volume_id,
                size_bytes,
                durability: VolumeDurability::Strict,
                admin_state: DiskAdminState::Active,
                role: DiskRole::Root {
                    cat_id: cat_id.clone(),
                },
            },
            volume,
            desired,
            operation_id: operation_id.clone(),
        },
        envelopes: CatCreateEnvelopes::new(accepted, cat_id, operation_id, conflict).unwrap(),
    }
}

fn counts(store: &Store) -> [i64; 6] {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM disk_records),
                        (SELECT count(*) FROM volume_records),
                        (SELECT count(*) FROM desired_runtime_specs),
                        (SELECT count(*) FROM runtime_operations),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| {
                    [
                        row.get(0),
                        row.get(1),
                        row.get(2),
                        row.get(3),
                        row.get(4),
                        row.get(5),
                    ]
                })
        })
        .unwrap()
}

fn refresh_candidate_contract(request: &mut CoveredCatCreateRequest) {
    request.candidate.desired.spec_digest = spec_digest(&request.candidate.desired).unwrap();
    let accepted = ExactHttpResponse::new(
        202,
        Some(ExactContentType::ApplicationJson),
        encode_cat_create_accepted_response(
            &request.candidate.cat_id,
            &request.candidate.operation_id,
        )
        .unwrap(),
    )
    .unwrap();
    let conflict = ExactHttpResponse::new(
        409,
        Some(ExactContentType::ApplicationJson),
        encode_cat_name_conflict_response(),
    )
    .unwrap();
    request.envelopes = CatCreateEnvelopes::new(
        accepted,
        request.candidate.cat_id.clone(),
        request.candidate.operation_id.clone(),
        conflict,
    )
    .unwrap();
}

fn candidate_row_count(store: &Store, request: &CoveredCatCreateRequest) -> i64 {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records WHERE cat_id=$1) +
                        (SELECT count(*) FROM disk_records WHERE disk_id=$2) +
                        (SELECT count(*) FROM volume_records WHERE volume_id=$3) +
                        (SELECT count(*) FROM desired_runtime_specs WHERE cat_id=$1) +
                        (SELECT count(*) FROM runtime_operations WHERE operation_id=$4)",
                    &[
                        &request.candidate.cat_id.as_str(),
                        &request.candidate.root_disk.disk_id.as_str(),
                        &request.candidate.volume.volume_id.as_str(),
                        &request.candidate.operation_id.as_str(),
                    ],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn failed_request_artifact_count(store: &Store, request: &CoveredCatCreateRequest) -> i64 {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records
                          WHERE workspace_id=$1 AND name=$2) +
                        (SELECT count(*) FROM api_idempotency_results
                          WHERE authenticated_workspace_id=$1
                            AND canonical_route=$3 AND idempotency_key=$4)",
                    &[
                        &request.candidate.workspace_id.as_str(),
                        &request.candidate.name.as_str(),
                        &request.idempotency.canonical_route.as_str(),
                        &request.idempotency.idempotency_key.as_str(),
                    ],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn assert_invalid_bundle_writes_nothing(
    store: &Store,
    request: &CoveredCatCreateRequest,
    label: &str,
) {
    let error = store.create_cat_covered(request).unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal, "{label}");
    assert_eq!(candidate_row_count(store, request), 0, "{label}");
    assert_eq!(failed_request_artifact_count(store, request), 0, "{label}");
}

fn error_code(error: CoveredCatCreateError) -> ErrorCode {
    match error {
        CoveredCatCreateError::Store(error) => error.code,
        CoveredCatCreateError::CandidateCollision(kind) => {
            panic!("expected Store error, observed candidate collision {kind:?}")
        }
    }
}

fn into_api_error(error: CoveredCatCreateError) -> cats_api::error::ApiError {
    match error {
        CoveredCatCreateError::Store(error) => error,
        CoveredCatCreateError::CandidateCollision(kind) => {
            internal(format!("unexpected candidate collision in test: {kind:?}"))
        }
    }
}

fn delete_created_bundle(store: &Store, request: &CoveredCatCreateRequest) {
    store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "DELETE FROM runtime_operations WHERE operation_id=$1",
                &[&request.candidate.operation_id.as_str()],
            )?;
            transaction.execute(
                "DELETE FROM desired_runtime_specs WHERE cat_id=$1",
                &[&request.candidate.cat_id.as_str()],
            )?;
            transaction.execute(
                "DELETE FROM disk_records WHERE disk_id=$1",
                &[&request.candidate.root_disk.disk_id.as_str()],
            )?;
            transaction.execute(
                "DELETE FROM cat_records WHERE cat_id=$1",
                &[&request.candidate.cat_id.as_str()],
            )?;
            transaction.execute(
                "DELETE FROM volume_records WHERE volume_id=$1",
                &[&request.candidate.volume.volume_id.as_str()],
            )?;
            transaction.commit()
        })
        .unwrap();
}

#[test]
fn fingerprint_and_response_fixed_vectors_match_byte_for_byte() {
    let fingerprint = api_request_fingerprint(
        &id("ws_01"),
        &AsciiText::new("POST /v1/workspaces/{workspace}/disks").unwrap(),
        b"/v1/workspaces/ws_01/disks",
        IfMatchFingerprint::Absent,
        br#"{"durability":"strict","name":"data","size_bytes":1073741824}"#,
    )
    .unwrap();
    assert_eq!(
        fingerprint.as_str(),
        "sha256:5069be7db8918e6a363d4d842224d9437a9eba202965ccc372838579b3b4ecbe"
    );
    let generation_fingerprint = api_request_fingerprint(
        &id("ws_01"),
        &AsciiText::new("POST /v1/workspaces/{workspace}/disks/{disk}/actions/{verb}").unwrap(),
        b"/v1/workspaces/ws_01/disks/disk_01/actions/mount?note=a%2Fb",
        IfMatchFingerprint::Generation(generation(7)),
        b"{\n  \"cat_id\": \"cat_01\",\n  \"mount_at\": \"/data\"\n}",
    )
    .unwrap();
    assert_eq!(
        generation_fingerprint.as_str(),
        "sha256:d07a08a0b37fbf5b6ee2022a6561f9441a186d516fd4316c5cce9068401bd6b7"
    );

    let accepted = encode_cat_create_accepted_response(&id("cat_01"), &id("op_01")).unwrap();
    assert_eq!(accepted, br#"{"cat_id":"cat_01","operation_id":"op_01"}"#);
    assert!(!accepted
        .windows(b"phase".len())
        .any(|window| window == b"phase"));
    assert_eq!(accepted.len(), 42);
    assert_eq!(
        Sha256Digest::from_bytes(Sha256::digest(&accepted).into()).as_str(),
        "sha256:9ff23d30170e1a81a16e5cdc847c79af292a48b2da3ce2764749320b8826bfda"
    );
    let conflict = encode_cat_name_conflict_response();
    assert_eq!(conflict.len(), 61);
    assert_eq!(
        Sha256Digest::from_bytes(Sha256::digest(&conflict).into()).as_str(),
        "sha256:38f397c0f602012a22d578aec019b53c40b42e5e01611e1264be45fac3eb421e"
    );
}

#[test]
fn persistent_disk_closed_codec_round_trips_both_states_and_detects_projection_drift() {
    let (_url, store, _second, workspace) = stores();
    let uninitialized_volume = blank_volume("volume_persistent_blank");
    let initialized_volume = blank_volume("volume_persistent_initialized");
    let token = random_id(7001);
    let filesystem_uuid = random_id(7002);
    let initialized_head = RemoteHead {
        generation: generation(1),
        root_hash: Some(Sha256Digest::from_bytes([7; 32])),
        root_object_id: Some(AsciiText::new("root-object-1").unwrap()),
    };
    let uninitialized = persistent_disk(
        &workspace,
        "disk_persistent_blank",
        "persistent-blank",
        &uninitialized_volume,
        PersistentDiskInitialization::Uninitialized {
            initialization_token: token.clone(),
            filesystem_uuid: filesystem_uuid.clone(),
            expected_blank_head: uninitialized_volume.head.clone(),
        },
    );
    let initialized = persistent_disk(
        &workspace,
        "disk_persistent_initialized",
        "persistent-initialized",
        &initialized_volume,
        PersistentDiskInitialization::Initialized {
            initialization_token: token,
            filesystem_uuid,
            expected_blank_head: initialized_volume.head.clone(),
            initialized_head,
            initialized_at: unix_millis(456),
        },
    );

    store
        .authority_transaction(|transaction| {
            insert_volume(transaction, &uninitialized_volume)?;
            insert_disk(transaction, &uninitialized)?;
            insert_volume(transaction, &initialized_volume)?;
            insert_disk(transaction, &initialized)?;
            assert_eq!(
                load_disk_by_id_for_update(transaction, &uninitialized.disk_id)?,
                Some(uninitialized.clone())
            );
            assert_eq!(
                load_disk_by_id_for_update(transaction, &initialized.disk_id)?,
                Some(initialized.clone())
            );
            Ok(())
        })
        .unwrap();

    let initialization_kinds: Vec<String> = store
        .with(|client| {
            client
                .query(
                    "SELECT record #>> '{role,initialization,kind}'
                       FROM disk_records ORDER BY disk_id",
                    &[],
                )
                .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
        })
        .unwrap();
    assert_eq!(
        initialization_kinds,
        ["uninitialized".to_owned(), "initialized".to_owned()]
    );

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE disk_records SET initialized_at=initialized_at+1 WHERE disk_id=$1",
                    &[&initialized.disk_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .authority_transaction(|transaction| {
            load_disk_by_id_for_update(transaction, &initialized.disk_id).map(|_| ())
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn first_create_and_lost_response_replay_are_exact_and_atomic() {
    let (_url, store, _second, workspace) = stores();
    let request = request(&workspace, "demo", 1, "key-1");
    assert!(store
        .cat_create_result_fast_lookup(&request.idempotency)
        .unwrap()
        .is_none());
    let first = store.create_cat_covered(&request).unwrap();
    assert_eq!(first.http_status, 202);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1]);
    let replay = store.create_cat_covered(&request).unwrap();
    assert_eq!(replay, first);
    assert_eq!(
        store
            .cat_create_result_fast_lookup(&request.idempotency)
            .unwrap(),
        Some(first.clone())
    );
    let times: (i64, i64, i64, i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT c.created_at, d.created_at, o.created_at, o.updated_at, r.created_at
                       FROM cat_records c
                       JOIN disk_records d ON d.root_cat_id=c.cat_id
                       JOIN runtime_operations o ON o.cat_id=c.cat_id
                       JOIN api_idempotency_results r
                         ON r.authenticated_workspace_id=c.workspace_id",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
        })
        .unwrap();
    assert_eq!(times, (times.0, times.0, times.0, times.0, times.0));

    delete_created_bundle(&store, &request);
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 1]);
    assert_eq!(store.create_cat_covered(&request).unwrap(), first);
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 1]);
}

#[test]
fn same_key_different_fingerprint_conflicts_before_candidate_reads() {
    let (_url, store, _second, workspace) = stores();
    let first = request(&workspace, "demo", 1, "same-key");
    store.create_cat_covered(&first).unwrap();
    let mut changed = request(&workspace, "different", 2, "same-key");
    changed.idempotency.request_fingerprint = Sha256Digest::from_bytes([9; 32]);
    let error = store.create_cat_covered(&changed).unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Conflict);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1]);
}

#[test]
fn idempotency_scope_isolated_by_workspace_and_canonical_route() {
    let (_url, store, _second, first_workspace) = stores();
    let second_workspace = bootstrap_workspace(&store, "scope-two");
    let first = request(&first_workspace, "first", 1, "shared-key");
    let second = request(&second_workspace, "second", 2, "shared-key");
    let mut third = request(&first_workspace, "third", 3, "shared-key");
    third.idempotency.canonical_route =
        AsciiText::new("POST /v1/workspaces/{workspace}/cats/import").unwrap();
    third.idempotency.request_fingerprint = api_request_fingerprint(
        &first_workspace,
        &third.idempotency.canonical_route,
        format!("/v1/workspaces/{first_workspace}/cats/import").as_bytes(),
        IfMatchFingerprint::Absent,
        br#"{"name":"third"}"#,
    )
    .unwrap();

    assert_eq!(store.create_cat_covered(&first).unwrap().http_status, 202);
    assert_eq!(store.create_cat_covered(&second).unwrap().http_status, 202);
    assert_eq!(store.create_cat_covered(&third).unwrap().http_status, 202);
    assert_eq!(counts(&store), [3, 3, 3, 3, 3, 3]);
}

#[test]
fn fast_miss_same_key_race_commits_only_one_candidate_bundle() {
    let (_url, first, second, workspace) = stores();
    let first_request = request(&workspace, "demo", 1, "same-key");
    let mut second_request = request(&workspace, "demo", 2, "same-key");
    second_request.idempotency.request_fingerprint =
        first_request.idempotency.request_fingerprint.clone();
    assert!(first
        .cat_create_result_fast_lookup(&first_request.idempotency)
        .unwrap()
        .is_none());
    assert!(second
        .cat_create_result_fast_lookup(&second_request.idempotency)
        .unwrap()
        .is_none());
    let saved_first = first_request.clone();
    let saved_second = second_request.clone();
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_worker = std::thread::spawn(move || {
        first_barrier.wait();
        first.create_cat_covered(&first_request)
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.create_cat_covered(&second_request)
    });
    barrier.wait();
    let first_result = first_worker.join().unwrap().unwrap();
    let second_result = second_worker.join().unwrap().unwrap();
    assert_eq!(first_result, second_result);

    let observer = Store::connect(&_url, None).unwrap();
    assert_eq!(counts(&observer), [1, 1, 1, 1, 1, 1]);
    let loser = if first_result.response_body
        == encode_cat_create_accepted_response(
            &saved_first.candidate.cat_id,
            &saved_first.candidate.operation_id,
        )
        .unwrap()
    {
        &saved_second
    } else {
        &saved_first
    };
    assert_eq!(candidate_row_count(&observer, loser), 0);
}

#[test]
fn every_persisted_candidate_identity_collision_is_typed_and_rolls_back() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "original", 1, "original-key");
    store.create_cat_covered(&original).unwrap();

    let mut cat_collision = request(&workspace, "new-cat-name", 2, "cat-collision");
    cat_collision.candidate.cat_id = original.candidate.cat_id.clone();
    cat_collision.candidate.desired.cat_id = original.candidate.cat_id.clone();
    cat_collision.candidate.root_disk.role = DiskRole::Root {
        cat_id: original.candidate.cat_id.clone(),
    };
    refresh_candidate_contract(&mut cat_collision);

    let mut disk_collision = request(&workspace, "new-disk-name", 3, "disk-collision");
    disk_collision.candidate.root_disk.disk_id = original.candidate.root_disk.disk_id.clone();
    disk_collision.candidate.root_disk.name = original.candidate.root_disk.disk_id.clone();
    disk_collision.candidate.desired.volumes[0].disk_id =
        original.candidate.root_disk.disk_id.clone();
    refresh_candidate_contract(&mut disk_collision);

    let mut volume_collision = request(&workspace, "new-volume-name", 4, "volume-collision");
    volume_collision.candidate.volume.volume_id = original.candidate.volume.volume_id.clone();
    volume_collision.candidate.root_disk.volume_id = original.candidate.volume.volume_id.clone();
    volume_collision.candidate.desired.volumes[0].volume_id =
        original.candidate.volume.volume_id.clone();
    refresh_candidate_contract(&mut volume_collision);

    let mut operation_collision = request(&workspace, "new-op-name", 5, "operation-collision");
    operation_collision.candidate.operation_id = original.candidate.operation_id.clone();
    refresh_candidate_contract(&mut operation_collision);

    for (request, expected) in [
        (&cat_collision, CandidateCollision::CatId),
        (&disk_collision, CandidateCollision::DiskIdOrName),
        (&volume_collision, CandidateCollision::VolumeId),
        (&operation_collision, CandidateCollision::OperationId),
    ] {
        let error = store.create_cat_covered(request).unwrap_err();
        assert!(matches!(
            error,
            CoveredCatCreateError::CandidateCollision(kind) if kind == expected
        ));
        assert_eq!(failed_request_artifact_count(&store, request), 0);
        assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1]);
    }
}

#[test]
fn root_disk_generated_name_collision_with_persistent_disk_is_typed_and_rolls_back() {
    let (_url, store, _second, workspace) = stores();
    let create = request(&workspace, "new-cat", 2, "name-collision");
    let existing_volume = blank_volume("existing_persistent_volume");
    let existing_disk = persistent_disk(
        &workspace,
        "existing_persistent_disk",
        create.candidate.root_disk.disk_id.as_str(),
        &existing_volume,
        PersistentDiskInitialization::Uninitialized {
            initialization_token: random_id(8101),
            filesystem_uuid: random_id(8102),
            expected_blank_head: existing_volume.head.clone(),
        },
    );
    store
        .authority_transaction(|transaction| {
            insert_volume(transaction, &existing_volume)?;
            insert_disk(transaction, &existing_disk)
        })
        .unwrap();

    let error = store.create_cat_covered(&create).unwrap_err();
    assert!(matches!(
        error,
        CoveredCatCreateError::CandidateCollision(CandidateCollision::DiskIdOrName)
    ));
    assert_eq!(candidate_row_count(&store, &create), 0);
    assert_eq!(failed_request_artifact_count(&store, &create), 0);
    assert_eq!(counts(&store), [0, 1, 1, 0, 0, 0]);
}

#[test]
fn corrupt_collision_row_is_not_reported_as_retryable_candidate_collision() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "original", 1, "original-key");
    store.create_cat_covered(&original).unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE cat_records SET record=record || '{\"unexpected\":true}'::jsonb
                      WHERE cat_id=$1",
                    &[&original.candidate.cat_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();

    let mut collision = request(&workspace, "different-name", 2, "collision-key");
    collision.candidate.cat_id = original.candidate.cat_id.clone();
    collision.candidate.desired.cat_id = original.candidate.cat_id.clone();
    collision.candidate.root_disk.role = DiskRole::Root {
        cat_id: original.candidate.cat_id.clone(),
    };
    refresh_candidate_contract(&mut collision);

    let error = store.create_cat_covered(&collision).unwrap_err();
    assert!(matches!(error, CoveredCatCreateError::Store(_)));
    assert_eq!(failed_request_artifact_count(&store, &collision), 0);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1]);
}

#[test]
fn two_keys_same_name_commit_one_bundle_and_one_durable_409() {
    let (_url, first, second, workspace) = stores();
    let first_request = request(&workspace, "same-name", 1, "key-a");
    let second_request = request(&workspace, "same-name", 2, "key-b");
    let saved_first = first_request.clone();
    let saved_second = second_request.clone();
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_worker = std::thread::spawn(move || {
        first_barrier.wait();
        first.create_cat_covered(&first_request)
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.create_cat_covered(&second_request)
    });
    barrier.wait();
    let first_result = first_worker.join().unwrap().unwrap();
    let second_result = second_worker.join().unwrap().unwrap();
    let statuses = [first_result.http_status, second_result.http_status];
    assert!(statuses.contains(&202));
    assert!(statuses.contains(&409));

    let observer = Store::connect(&_url, None).unwrap();
    assert_eq!(counts(&observer), [1, 1, 1, 1, 1, 2]);
    let (winner, loser, loser_result) = if first_result.http_status == 202 {
        (&saved_first, &saved_second, second_result)
    } else {
        (&saved_second, &saved_first, first_result)
    };
    delete_created_bundle(&observer, winner);
    assert_eq!(observer.create_cat_covered(loser).unwrap(), loser_result);
    assert_eq!(counts(&observer), [0, 0, 0, 0, 0, 2]);
}

#[test]
fn invalid_response_bytes_and_cross_workspace_bundle_write_nothing() {
    let (_url, store, _second, workspace) = stores();
    let invalid_accepted =
        ExactHttpResponse::new(202, Some(ExactContentType::ApplicationJson), b"{}".to_vec())
            .unwrap();
    let conflict = ExactHttpResponse::new(
        409,
        Some(ExactContentType::ApplicationJson),
        encode_cat_name_conflict_response(),
    )
    .unwrap();
    assert_eq!(
        CatCreateEnvelopes::new(invalid_accepted, id("cat_bad"), id("op_bad"), conflict)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0]);

    let accepted = ExactHttpResponse::new(
        202,
        Some(ExactContentType::ApplicationJson),
        encode_cat_create_accepted_response(&id("cat_bad"), &id("op_bad")).unwrap(),
    )
    .unwrap();
    let invalid_conflict = ExactHttpResponse::new(
        409,
        Some(ExactContentType::ApplicationJson),
        br#"{"code":"already_exists"}"#.to_vec(),
    )
    .unwrap();
    assert_eq!(
        CatCreateEnvelopes::new(accepted, id("cat_bad"), id("op_bad"), invalid_conflict)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0]);

    let other_workspace = bootstrap_workspace(&store, "other");
    let mut cross_workspace = request(&other_workspace, "demo", 1, "cross-workspace");
    cross_workspace.idempotency.authenticated_workspace_id = workspace;
    let error = store.create_cat_covered(&cross_workspace).unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0]);
}

#[test]
fn every_invalid_initial_root_shape_rolls_back_without_a_result() {
    let (_url, store, _second, workspace) = stores();

    let mut wrong_disk_name = request(&workspace, "wrong-disk-name", 10, "invalid-name");
    wrong_disk_name.candidate.root_disk.name = id("not-the-disk-id");

    let mut deleting = request(&workspace, "deleting", 11, "invalid-deleting");
    deleting.candidate.volume.admin_state = VolumeAdminState::Deleting {
        delete_id: id("delete_11"),
    };

    let mut nonzero_epoch = request(&workspace, "nonzero-epoch", 12, "invalid-epoch");
    nonzero_epoch.candidate.volume.lease_epoch = fence_epoch(1);

    let mut owned = request(&workspace, "owned", 13, "invalid-owner");
    owned.candidate.volume.lease_owner = Some(id("existing_attachment"));
    owned.candidate.volume.lease_epoch = fence_epoch(1);
    owned.candidate.volume.lease_expires_at = Some(unix_millis(999));

    let mut nonblank = request(&workspace, "nonblank", 14, "invalid-head");
    nonblank.candidate.volume.head = RemoteHead {
        generation: generation(1),
        root_hash: Some(Sha256Digest::from_bytes([14; 32])),
        root_object_id: Some(AsciiText::new("root-object-14").unwrap()),
    };

    let mut prior_transition = request(&workspace, "transition", 15, "invalid-transition");
    prior_transition.candidate.volume.last_transition = Some(LastVolumeTransition::Takeover {
        authorization_id: id("authorization_15"),
    });

    let mut takeover = request(&workspace, "takeover", 16, "invalid-takeover");
    takeover.candidate.desired.volumes[0].acquire = VolumeAcquire::Takeover {
        authorization_id: id("authorization_16"),
    };
    refresh_candidate_contract(&mut takeover);

    let mut wrong_expected_epoch = request(
        &workspace,
        "wrong-acquire-epoch",
        17,
        "invalid-acquire-epoch",
    );
    wrong_expected_epoch.candidate.desired.volumes[0].acquire = VolumeAcquire::Normal {
        transition_id: random_id(17_017),
        expected_unowned_epoch: fence_epoch(1),
    };
    refresh_candidate_contract(&mut wrong_expected_epoch);

    for (label, request) in [
        ("Root Disk name", &wrong_disk_name),
        ("Deleting Volume", &deleting),
        ("nonzero Volume epoch", &nonzero_epoch),
        ("owned Volume", &owned),
        ("nonblank Volume", &nonblank),
        ("prior Volume transition", &prior_transition),
        ("takeover acquire", &takeover),
        ("nonzero normal expected epoch", &wrong_expected_epoch),
    ] {
        assert_invalid_bundle_writes_nothing(&store, request, label);
    }
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0]);
}

#[test]
fn every_query_projection_drift_fails_closed_without_a_409_result() {
    for (table, mutation) in [
        (
            "cat_records",
            "UPDATE cat_records SET created_at=created_at+1",
        ),
        (
            "disk_records",
            "UPDATE disk_records SET created_at=created_at+1",
        ),
        (
            "desired_runtime_specs",
            "UPDATE desired_runtime_specs SET node_id='wrong-node'",
        ),
        (
            "runtime_operations",
            "UPDATE runtime_operations SET node_id='wrong-node'",
        ),
    ] {
        let (_url, store, _second, workspace) = stores();
        let original = request(&workspace, "demo", 1, "original");
        store.create_cat_covered(&original).unwrap();
        store.with(|client| client.batch_execute(mutation)).unwrap();

        let conflict = request(&workspace, "demo", 2, "would-conflict");
        let error = store.create_cat_covered(&conflict).unwrap_err();
        assert_eq!(error_code(error), ErrorCode::Internal, "table {table}");
        assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1], "table {table}");
    }
}

#[test]
fn self_valid_rows_with_a_missing_operation_are_not_a_name_conflict() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store.create_cat_covered(&original).unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "DELETE FROM runtime_operations WHERE operation_id=$1",
                    &[&original.candidate.operation_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();

    let conflict = request(&workspace, "demo", 2, "would-conflict");
    let error = store.create_cat_covered(&conflict).unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [1, 1, 1, 1, 0, 1]);
}

#[test]
fn every_closed_json_row_corruption_fails_closed_without_a_409_result() {
    for table in [
        "cat_records",
        "disk_records",
        "desired_runtime_specs",
        "runtime_operations",
    ] {
        let (_url, store, _second, workspace) = stores();
        let original = request(&workspace, "demo", 1, "original");
        store.create_cat_covered(&original).unwrap();
        let sql = format!("UPDATE {table} SET record=record || '{{\"unexpected\":true}}'::jsonb");
        store.with(|client| client.batch_execute(&sql)).unwrap();

        let conflict = request(&workspace, "demo", 2, "would-conflict");
        let error = store.create_cat_covered(&conflict).unwrap_err();
        assert_eq!(error_code(error), ErrorCode::Internal, "table {table}");
        assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1], "table {table}");
    }
}

#[test]
fn corrupt_api_result_fails_both_fast_and_transactional_reads_closed() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store.create_cat_covered(&original).unwrap();
    store
        .with(|client| {
            client.batch_execute(
                "ALTER TABLE api_idempotency_results
                   DROP CONSTRAINT api_idempotency_results_content_type_check;
                 UPDATE api_idempotency_results SET content_type='text/plain';",
            )
        })
        .unwrap();

    let fast = store
        .cat_create_result_fast_lookup(&original.idempotency)
        .unwrap_err();
    assert_eq!(fast.code, ErrorCode::Internal);
    let transactional = store.create_cat_covered(&original).unwrap_err();
    assert_eq!(error_code(transactional), ErrorCode::Internal);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1]);
}

#[test]
fn serialization_retry_replays_the_whole_create_without_half_rows() {
    let (_url, store, _second, workspace) = stores();
    store
        .with(|client| {
            client.batch_execute(
                "CREATE SEQUENCE f2a_serialization_attempt;
                 CREATE FUNCTION f2a_fail_first_operation() RETURNS trigger AS $$
                 BEGIN
                   IF nextval('f2a_serialization_attempt') = 1 THEN
                     RAISE EXCEPTION 'retry whole create' USING ERRCODE='40001';
                   END IF;
                   RETURN NEW;
                 END;
                 $$ LANGUAGE plpgsql;
                 CREATE TRIGGER f2a_fail_first_operation
                   BEFORE INSERT ON runtime_operations
                   FOR EACH ROW EXECUTE FUNCTION f2a_fail_first_operation();",
            )
        })
        .unwrap();
    let create = request(&workspace, "demo", 1, "retry");
    let result = store.create_cat_covered(&create).unwrap();
    assert_eq!(result.http_status, 202);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1]);
    let attempts: i64 = store
        .with(|client| {
            client
                .query_one("SELECT last_value FROM f2a_serialization_attempt", &[])
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(attempts, 2);
}

#[test]
fn failure_after_four_business_inserts_rolls_everything_back() {
    let (_url, store, _second, workspace) = stores();
    store
        .with(|client| {
            client.batch_execute(
                "CREATE FUNCTION f2a_reject_operation() RETURNS trigger AS $$
                 BEGIN
                   RAISE EXCEPTION 'injected operation persistence failure';
                 END;
                 $$ LANGUAGE plpgsql;
                 CREATE TRIGGER f2a_reject_operation
                   BEFORE INSERT ON runtime_operations
                   FOR EACH ROW EXECUTE FUNCTION f2a_reject_operation();",
            )
        })
        .unwrap();
    let create = request(&workspace, "demo", 1, "rollback");
    let error = store.create_cat_covered(&create).unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0]);
}

#[test]
fn concurrent_destroy_after_name_peek_cannot_be_cached_as_409() {
    const APPLICATION_NAME: &str = "cats-f2a-destroy-race";
    let (url, seed, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    seed.create_cat_covered(&original).unwrap();
    let conflict = request(&workspace, "demo", 2, "would-conflict");
    let conflict_store =
        Store::connect(&with_application_name(&url, APPLICATION_NAME), None).unwrap();

    let mut destroy_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut destroy = destroy_client.transaction().unwrap();
    destroy
        .query_one(
            "SELECT volume_id FROM volume_records WHERE volume_id=$1 FOR UPDATE",
            &[&original.candidate.volume.volume_id.as_str()],
        )
        .unwrap();

    let worker = std::thread::spawn(move || conflict_store.create_cat_covered(&conflict));
    let mut observed_wait = false;
    for _ in 0..200 {
        observed_wait = seed
            .with(|client| {
                client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1 FROM pg_stat_activity
                             WHERE application_name=$1
                               AND wait_event_type='Lock'
                        )",
                        &[&APPLICATION_NAME],
                    )
                    .map(|row| row.get(0))
            })
            .unwrap();
        if observed_wait {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        observed_wait,
        "name-conflict transaction never reached Volume lock"
    );

    destroy
        .execute(
            "DELETE FROM runtime_operations WHERE operation_id=$1",
            &[&original.candidate.operation_id.as_str()],
        )
        .unwrap();
    destroy
        .execute(
            "DELETE FROM desired_runtime_specs WHERE cat_id=$1",
            &[&original.candidate.cat_id.as_str()],
        )
        .unwrap();
    destroy
        .execute(
            "DELETE FROM disk_records WHERE disk_id=$1",
            &[&original.candidate.root_disk.disk_id.as_str()],
        )
        .unwrap();
    destroy
        .execute(
            "DELETE FROM cat_records WHERE cat_id=$1",
            &[&original.candidate.cat_id.as_str()],
        )
        .unwrap();
    destroy
        .execute(
            "DELETE FROM volume_records WHERE volume_id=$1",
            &[&original.candidate.volume.volume_id.as_str()],
        )
        .unwrap();
    destroy.commit().unwrap();

    let error = worker.join().unwrap().unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&seed), [0, 0, 0, 0, 0, 1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_started_create_finishes_physical_transaction_and_replays() {
    const APPLICATION_NAME: &str = "cats-f2a-cancel";
    let url = crate::testsupport::isolated_control_store_url();
    let named_url = with_application_name(&url, APPLICATION_NAME);
    let first = Arc::new(
        Store::connect_from_async(DsnSource::Literal(named_url), None)
            .await
            .unwrap(),
    );
    let second = Arc::new(Store::connect(&url, None).unwrap());
    let workspace = bootstrap_workspace(&first, "cancel");
    let create = request(&workspace, "demo", 1, "cancel-key");

    let blocker_url = url.clone();
    let blocker_workspace = workspace.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let mut client = postgres::Client::connect(&blocker_url, postgres::NoTls).unwrap();
        let mut transaction = client.transaction().unwrap();
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended(
                    current_schema() || ':cat-name:' || $1 || ':' || $2,
                    0::BIGINT
                 ))",
                &[&blocker_workspace.as_str(), &"demo"],
            )
            .unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        transaction.rollback().unwrap();
    });
    locked_rx.recv().unwrap();

    let worker_store = Arc::clone(&first);
    let worker_request = create.clone();
    let task = tokio::spawn(async move {
        worker_store
            .execute(move |store| {
                store
                    .create_cat_covered(&worker_request)
                    .map_err(into_api_error)
            })
            .await
    });
    let mut observed_wait = false;
    for _ in 0..200 {
        observed_wait = second
            .with(|client| {
                client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1 FROM pg_stat_activity
                             WHERE application_name=$1
                               AND wait_event_type='Lock'
                        )",
                        &[&APPLICATION_NAME],
                    )
                    .map(|row| row.get(0))
            })
            .unwrap();
        if observed_wait {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(observed_wait, "started create never waited on CatNameLock");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    release_tx.send(()).unwrap();

    let replay_request = create.clone();
    let replay = second
        .execute(move |store| {
            store
                .create_cat_covered(&replay_request)
                .map_err(into_api_error)
        })
        .await
        .unwrap();
    blocker.join().unwrap();
    assert_eq!(replay.http_status, 202);
    assert_eq!(counts(&second), [1, 1, 1, 1, 1, 1]);

    let mut settled = false;
    for _ in 0..200 {
        let state: Option<String> = second
            .with(|client| {
                client
                    .query_opt(
                        "SELECT state FROM pg_stat_activity WHERE application_name=$1",
                        &[&APPLICATION_NAME],
                    )
                    .map(|row| row.map(|row| row.get(0)))
            })
            .unwrap();
        if state.as_deref().is_none_or(|state| state == "idle") {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(settled, "cancelled create left an idle transaction");
}

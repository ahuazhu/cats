//! Real PostgreSQL acceptance tests for covered Cat create.

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, encode_operation, spec_digest, AsciiText, AssignedKind,
    AssignedPlacement, ContractVersion, DesiredRuntimeSpec, DiskKind, Durability, EndpointIntent,
    Epoch, Ext4MountIntent, FenceEpoch, FilesystemInitialization, Generation, GuestDeviceIdentity,
    Hostname, HttpProtocol, Id, Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig,
    Operation, OperationPhase, OperationTerminal, RandomId128, Revision, RuntimeConfig,
    RuntimeTarget, RuntimeTransition, Sha256Digest, UnixMillis, VolumeAccess, VolumeAcquire,
    VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::{
    LastVolumeTransition, RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord,
};
use postgres::error::SqlState;
use sha2::{Digest, Sha256};

use super::cat_create_service::CatCreatePlacementMutation;
use super::product::{
    api_request_fingerprint, candidate_matches_placement_mutation,
    encode_cat_create_accepted_response, encode_cat_name_conflict_response,
    persistent_initialization_matches_mount, ApiIdempotencyRequest, CandidateCollision,
    CatCreateCandidate, CatCreateEnvelopes, CoveredCatCreateError, CoveredCatCreateRequest,
    DiskAdminState, DiskRecord, DiskRecordCandidate, DiskRole, EndpointRecord,
    EndpointRecordCandidate, ExactContentType, ExactHttpResponse, HostnameDesiredLocation,
    HostnameDesiredLookup, IfMatchFingerprint, PersistentDiskInitialization,
};
use super::product_rows::{
    insert_disk, insert_endpoint, insert_hostname_lookup, insert_operation,
    load_disk_by_id_for_update, load_operation_by_cat_revision_unlocked,
};
use super::rows::{database_now, insert_volume};
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

pub(super) fn bootstrap_workspace(store: &Store, slug: &str) -> Id {
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

pub(super) fn with_application_name(url: &str, application_name: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}application_name={application_name}")
}

pub(super) fn request(
    workspace: &Id,
    name: &str,
    sequence: u64,
    idempotency_key: &str,
) -> CoveredCatCreateRequest {
    let cat_id = id(format!("cat_{sequence}"));
    let disk_id = id(format!("disk_{sequence}"));
    let volume_id = id(format!("volume_{sequence}"));
    let operation_id = id(format!("op_{sequence}"));
    let endpoint_suffix = format!("{sequence:032x}");
    let endpoint_id = id(format!("ep_{endpoint_suffix}"));
    let hostname = Hostname::new(format!("{name}-{endpoint_suffix}.cats.run")).unwrap();
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
                serial: id("cats-root"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: random_id(10_000 + u128::from(sequence)),
                expected_unowned_epoch: fence_epoch(0),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        }],
        endpoints: vec![EndpointIntent {
            endpoint_id: endpoint_id.clone(),
            hostname: hostname.clone(),
            route_epoch: epoch(1),
            protocol: HttpProtocol::Http,
            target_port: 8080,
        }],
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
            endpoint: EndpointRecordCandidate {
                endpoint_id: endpoint_id.clone(),
                workspace_id: workspace.clone(),
                cat_id: cat_id.clone(),
                name: id("web"),
            },
            hostname_lookup: HostnameDesiredLookup {
                hostname,
                workspace_id: workspace.clone(),
                cat_id: cat_id.clone(),
                endpoint_id,
                desired_revision: revision(1),
            },
            operation_id: operation_id.clone(),
        },
        envelopes: CatCreateEnvelopes::new(accepted, cat_id, operation_id, conflict).unwrap(),
    }
}

#[test]
fn placement_mutation_binding_rejects_every_candidate_drift() {
    let covered = request(&id("ws_mutation"), "app", 1, "mutation-key");
    let candidate = &covered.candidate;
    let exact = CatCreatePlacementMutation {
        cat_id: candidate.cat_id.clone(),
        desired_revision: candidate.desired.desired_revision,
        placement_epoch: candidate.desired.placement.placement_epoch,
        vcpus: candidate.desired.runtime.vcpus,
        memory_bytes: candidate.desired.runtime.memory_bytes,
        network_config: candidate.desired.runtime.network_config.clone(),
    };
    assert!(candidate_matches_placement_mutation(candidate, &exact));

    let mut drift = exact.clone();
    drift.cat_id = id("cat_other");
    assert!(!candidate_matches_placement_mutation(candidate, &drift));
    let mut drift = exact.clone();
    drift.desired_revision = revision(2);
    assert!(!candidate_matches_placement_mutation(candidate, &drift));
    let mut drift = exact.clone();
    drift.placement_epoch = epoch(2);
    assert!(!candidate_matches_placement_mutation(candidate, &drift));
    let mut drift = exact.clone();
    drift.vcpus = drift.vcpus.saturating_add(1);
    assert!(!candidate_matches_placement_mutation(candidate, &drift));
    let mut drift = exact.clone();
    drift.memory_bytes = drift.memory_bytes.saturating_add(1);
    assert!(!candidate_matches_placement_mutation(candidate, &drift));
    let mut drift = exact;
    drift.network_config.network_id = id("network_other");
    assert!(!candidate_matches_placement_mutation(candidate, &drift));
}

pub(super) fn counts(store: &Store) -> [i64; 8] {
    store
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
                .map(|row| {
                    [
                        row.get(0),
                        row.get(1),
                        row.get(2),
                        row.get(3),
                        row.get(4),
                        row.get(5),
                        row.get(6),
                        row.get(7),
                    ]
                })
        })
        .unwrap()
}

pub(super) fn refresh_candidate_contract(request: &mut CoveredCatCreateRequest) {
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

fn advance_current_endpoints(
    store: &Store,
    original: &CoveredCatCreateRequest,
    replacement: Option<(Id, Id, Hostname)>,
    operation_id: Id,
) -> DesiredRuntimeSpec {
    let mut desired = original.candidate.desired.clone();
    desired.desired_revision = revision(2);
    desired.endpoints = replacement
        .as_ref()
        .map(|(endpoint_id, _name, hostname)| {
            vec![EndpointIntent {
                endpoint_id: endpoint_id.clone(),
                hostname: hostname.clone(),
                route_epoch: epoch(1),
                protocol: HttpProtocol::Http,
                target_port: 8080,
            }]
        })
        .unwrap_or_default();
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(&desired).unwrap();
    let desired_json = String::from_utf8(encode_desired_runtime_spec(&desired).unwrap()).unwrap();

    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            let now_pg = i64::try_from(now.get()).unwrap();
            let mut previous = load_operation_by_cat_revision_unlocked(
                transaction,
                &original.candidate.cat_id,
                revision(1),
            )?
            .ok_or_else(|| internal("test setup lost the initial Operation"))?;
            previous.phase = OperationPhase::Superseded;
            previous.terminal = Some(OperationTerminal::Superseded {
                superseded_by_revision: desired.desired_revision,
                superseded_by_operation_id: operation_id.clone(),
                completed_at_unix_ms: now,
            });
            previous.updated_at_unix_ms = now;
            let previous_json = String::from_utf8(encode_operation(&previous).unwrap()).unwrap();
            assert_eq!(
                transaction.execute(
                    "UPDATE runtime_operations
                        SET record=$1::TEXT::jsonb,
                            phase='superseded',
                            terminal_kind='superseded',
                            updated_at=$2
                      WHERE operation_id=$3",
                    &[&previous_json, &now_pg, &previous.operation_id.as_str(),],
                )?,
                1
            );
            assert_eq!(
                transaction.execute(
                    "DELETE FROM hostname_desired_lookups WHERE cat_id=$1",
                    &[&original.candidate.cat_id.as_str()],
                )?,
                1
            );
            assert_eq!(
                transaction.execute(
                    "UPDATE desired_runtime_specs
                        SET record=$1::TEXT::jsonb,
                            desired_revision=$2,
                            spec_digest=$3
                      WHERE cat_id=$4",
                    &[
                        &desired_json,
                        &2_i64,
                        &desired.spec_digest.as_str(),
                        &desired.cat_id.as_str(),
                    ],
                )?,
                1
            );

            if let Some((endpoint_id, name, hostname)) = &replacement {
                insert_endpoint(
                    transaction,
                    &EndpointRecord {
                        endpoint_id: endpoint_id.clone(),
                        workspace_id: desired.workspace_id.clone(),
                        cat_id: desired.cat_id.clone(),
                        name: name.clone(),
                        created_at: now,
                    },
                )?;
                insert_hostname_lookup(
                    transaction,
                    &HostnameDesiredLookup {
                        hostname: hostname.clone(),
                        workspace_id: desired.workspace_id.clone(),
                        cat_id: desired.cat_id.clone(),
                        endpoint_id: endpoint_id.clone(),
                        desired_revision: desired.desired_revision,
                    },
                )?;
            }

            insert_operation(
                transaction,
                &Operation {
                    version: ContractVersion::V1,
                    operation_id: operation_id.clone(),
                    workspace_id: desired.workspace_id.clone(),
                    cat_id: desired.cat_id.clone(),
                    desired_revision: desired.desired_revision,
                    desired_spec_digest: desired.spec_digest.clone(),
                    placement: desired.placement.clone(),
                    target: desired.target,
                    phase: OperationPhase::Pending,
                    terminal: None,
                    created_at_unix_ms: now,
                    updated_at_unix_ms: now,
                },
            )
        })
        .unwrap();
    desired
}

fn rewrite_current_desired_and_operation(
    store: &Store,
    desired: &DesiredRuntimeSpec,
    lookup_rewrite: Option<(Hostname, HostnameDesiredLookup)>,
) {
    let desired_json = String::from_utf8(encode_desired_runtime_spec(desired).unwrap()).unwrap();
    store
        .authority_transaction(|transaction| {
            let mut operation = load_operation_by_cat_revision_unlocked(
                transaction,
                &desired.cat_id,
                desired.desired_revision,
            )?
            .ok_or_else(|| internal("test setup lost the current Operation"))?;
            operation.desired_spec_digest = desired.spec_digest.clone();
            let operation_json = String::from_utf8(encode_operation(&operation).unwrap()).unwrap();
            assert_eq!(
                transaction.execute(
                    "UPDATE desired_runtime_specs
                        SET record=$1::TEXT::jsonb, spec_digest=$2
                      WHERE cat_id=$3",
                    &[
                        &desired_json,
                        &desired.spec_digest.as_str(),
                        &desired.cat_id.as_str(),
                    ],
                )?,
                1
            );
            assert_eq!(
                transaction.execute(
                    "UPDATE runtime_operations
                        SET record=$1::TEXT::jsonb, desired_spec_digest=$2
                      WHERE operation_id=$3",
                    &[
                        &operation_json,
                        &operation.desired_spec_digest.as_str(),
                        &operation.operation_id.as_str(),
                    ],
                )?,
                1
            );
            if let Some((old_hostname, lookup)) = &lookup_rewrite {
                let lookup_json = serde_json::to_string(lookup).unwrap();
                assert_eq!(
                    transaction.execute(
                        "UPDATE hostname_desired_lookups
                            SET hostname=$1, record=$2::TEXT::jsonb
                          WHERE hostname=$3",
                        &[
                            &lookup.hostname.as_str(),
                            &lookup_json,
                            &old_hostname.as_str(),
                        ],
                    )?,
                    1
                );
            }
            Ok(())
        })
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
                        (SELECT count(*) FROM endpoint_records WHERE endpoint_id=$4) +
                        (SELECT count(*) FROM hostname_desired_lookups WHERE hostname=$5) +
                        (SELECT count(*) FROM runtime_operations WHERE operation_id=$6)",
                    &[
                        &request.candidate.cat_id.as_str(),
                        &request.candidate.root_disk.disk_id.as_str(),
                        &request.candidate.volume.volume_id.as_str(),
                        &request.candidate.endpoint.endpoint_id.as_str(),
                        &request.candidate.hostname_lookup.hostname.as_str(),
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
    let error = store
        .create_cat_covered_without_admission_for_product_test(request)
        .unwrap_err();
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
        CoveredCatCreateError::PlacementStale => {
            panic!("expected Store error, observed placement stale")
        }
    }
}

fn into_api_error(error: CoveredCatCreateError) -> cats_api::error::ApiError {
    match error {
        CoveredCatCreateError::Store(error) => error,
        CoveredCatCreateError::CandidateCollision(kind) => {
            internal(format!("unexpected candidate collision in test: {kind:?}"))
        }
        CoveredCatCreateError::PlacementStale => internal("unexpected placement stale in test"),
    }
}

fn delete_created_bundle(store: &Store, request: &CoveredCatCreateRequest) {
    store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "DELETE FROM hostname_desired_lookups WHERE hostname=$1",
                &[&request.candidate.hostname_lookup.hostname.as_str()],
            )?;
            transaction.execute(
                "DELETE FROM runtime_operations WHERE operation_id=$1",
                &[&request.candidate.operation_id.as_str()],
            )?;
            transaction.execute(
                "DELETE FROM desired_runtime_specs WHERE cat_id=$1",
                &[&request.candidate.cat_id.as_str()],
            )?;
            transaction.execute(
                "DELETE FROM endpoint_records WHERE endpoint_id=$1",
                &[&request.candidate.endpoint.endpoint_id.as_str()],
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
    let (url, store, _second, workspace) = stores();
    let uninitialized_volume = blank_volume("volume_persistent_blank");
    let initialized_volume = blank_volume("volume_persistent_initialized");
    let uninitialized_token = random_id(7001);
    let uninitialized_filesystem_uuid = random_id(7002);
    let initialized_token = random_id(7003);
    let initialized_filesystem_uuid = random_id(7004);
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
            initialization_token: uninitialized_token,
            filesystem_uuid: uninitialized_filesystem_uuid,
            expected_blank_head: uninitialized_volume.head.clone(),
        },
    );
    let initialized = persistent_disk(
        &workspace,
        "disk_persistent_initialized",
        "persistent-initialized",
        &initialized_volume,
        PersistentDiskInitialization::Initialized {
            initialization_token: initialized_token,
            filesystem_uuid: initialized_filesystem_uuid,
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

    let mut raw_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    for (label, sql, disk_id) in [
        (
            "missing initialization kind",
            "UPDATE disk_records SET initialization_kind=NULL WHERE disk_id=$1",
            uninitialized.disk_id.as_str(),
        ),
        (
            "missing blank generation",
            "UPDATE disk_records SET expected_blank_generation=NULL WHERE disk_id=$1",
            uninitialized.disk_id.as_str(),
        ),
        (
            "missing initialized generation",
            "UPDATE disk_records SET initialized_generation=NULL WHERE disk_id=$1",
            initialized.disk_id.as_str(),
        ),
        (
            "missing initialized timestamp",
            "UPDATE disk_records SET initialized_at=NULL WHERE disk_id=$1",
            initialized.disk_id.as_str(),
        ),
    ] {
        let error = raw_client.execute(sql, &[&disk_id]).unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION), "{label}");
    }
    let unchanged: (Option<String>, Option<i64>, Option<i64>, Option<i64>) = raw_client
        .query_one(
            "SELECT initialization_kind, expected_blank_generation,
                    initialized_generation, initialized_at
               FROM disk_records WHERE disk_id=$1",
            &[&initialized.disk_id.as_str()],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(
        unchanged,
        (Some("initialized".to_owned()), Some(0), Some(1), Some(456))
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
fn persistent_initialization_f0_closes_desired_variant_and_head_drift() {
    let blank = blank_volume("volume_f0").head;
    let token = random_id(7_101);
    let filesystem_uuid = random_id(7_102);
    let initialized = RemoteHead {
        generation: generation(1),
        root_hash: Some(Sha256Digest::from_bytes([8; 32])),
        root_object_id: Some(AsciiText::new("roots/1").unwrap()),
    };
    let uninitialized = PersistentDiskInitialization::Uninitialized {
        initialization_token: token.clone(),
        filesystem_uuid: filesystem_uuid.clone(),
        expected_blank_head: blank.clone(),
    };
    let initialize_mount = Ext4MountIntent {
        filesystem_uuid: filesystem_uuid.clone(),
        mount_path: cats_api::runtime_reconciliation::HostPath::new("/data").unwrap(),
        initialization: FilesystemInitialization::Initialize {
            initialization_token: token.clone(),
            expected_blank_head: blank.clone(),
        },
    };
    assert!(persistent_initialization_matches_mount(
        &uninitialized,
        &blank,
        Some(&initialize_mount),
    ));
    assert!(!persistent_initialization_matches_mount(
        &uninitialized,
        &initialized,
        Some(&initialize_mount),
    ));

    let initialized_state = PersistentDiskInitialization::Initialized {
        initialization_token: token.clone(),
        filesystem_uuid: filesystem_uuid.clone(),
        expected_blank_head: blank.clone(),
        initialized_head: initialized.clone(),
        initialized_at: unix_millis(7_103),
    };
    let existing_mount = Ext4MountIntent {
        filesystem_uuid,
        mount_path: cats_api::runtime_reconciliation::HostPath::new("/data").unwrap(),
        initialization: FilesystemInitialization::Existing,
    };
    assert!(persistent_initialization_matches_mount(
        &initialized_state,
        &initialized,
        Some(&initialize_mount),
    ));
    assert!(persistent_initialization_matches_mount(
        &initialized_state,
        &initialized,
        Some(&existing_mount),
    ));
    let advanced = RemoteHead {
        generation: generation(2),
        root_hash: Some(Sha256Digest::from_bytes([9; 32])),
        root_object_id: Some(AsciiText::new("roots/2").unwrap()),
    };
    assert!(persistent_initialization_matches_mount(
        &initialized_state,
        &advanced,
        Some(&initialize_mount),
    ));
    assert!(persistent_initialization_matches_mount(
        &initialized_state,
        &advanced,
        Some(&existing_mount),
    ));
    let same_generation_foreign = RemoteHead {
        generation: initialized.generation,
        root_hash: Some(Sha256Digest::from_bytes([10; 32])),
        root_object_id: Some(AsciiText::new("roots/foreign").unwrap()),
    };
    assert!(!persistent_initialization_matches_mount(
        &initialized_state,
        &same_generation_foreign,
        Some(&existing_mount),
    ));
    assert!(!persistent_initialization_matches_mount(
        &initialized_state,
        &same_generation_foreign,
        Some(&initialize_mount),
    ));
    let mut wrong_initialize_mount = initialize_mount;
    wrong_initialize_mount.initialization = FilesystemInitialization::Initialize {
        initialization_token: random_id(7_104),
        expected_blank_head: blank,
    };
    assert!(!persistent_initialization_matches_mount(
        &initialized_state,
        &advanced,
        Some(&wrong_initialize_mount),
    ));
}

#[test]
fn first_create_and_lost_response_replay_are_exact_and_atomic() {
    let (url, store, _second, workspace) = stores();
    let request = request(&workspace, "demo", 1, "key-1");
    assert!(store
        .covered_api_result_fast_lookup(&request.idempotency)
        .unwrap()
        .is_none());
    let first = store
        .create_cat_covered_without_admission_for_product_test(&request)
        .unwrap();
    assert_eq!(first.http_status, 202);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
    assert_eq!(
        store
            .locate_hostname_desired(&request.candidate.hostname_lookup.hostname)
            .unwrap(),
        Some(HostnameDesiredLocation {
            cat_id: request.candidate.cat_id.clone(),
            endpoint_id: request.candidate.endpoint.endpoint_id.clone(),
            desired_revision: revision(1),
        })
    );
    assert!(store
        .locate_hostname_desired(&Hostname::new("absent.cats.run").unwrap())
        .unwrap()
        .is_none());
    let replay = store
        .create_cat_covered_without_admission_for_product_test(&request)
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(
        store
            .covered_api_result_fast_lookup(&request.idempotency)
            .unwrap(),
        Some(first.clone())
    );
    let times: (i64, i64, i64, i64, i64, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT c.created_at, d.created_at, e.created_at,
                            o.created_at, o.updated_at, r.created_at
                       FROM cat_records c
                       JOIN disk_records d ON d.root_cat_id=c.cat_id
                       JOIN endpoint_records e ON e.cat_id=c.cat_id AND e.name='web'
                       JOIN runtime_operations o ON o.cat_id=c.cat_id
                       JOIN api_idempotency_results r
                         ON r.authenticated_workspace_id=c.workspace_id",
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
        times,
        (times.0, times.0, times.0, times.0, times.0, times.0)
    );

    let mut raw_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let error = raw_client
        .execute(
            "UPDATE runtime_operations SET phase='succeeded', terminal_kind=NULL
              WHERE operation_id=$1",
            &[&request.candidate.operation_id.as_str()],
        )
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    let phase: String = raw_client
        .query_one(
            "SELECT phase FROM runtime_operations WHERE operation_id=$1",
            &[&request.candidate.operation_id.as_str()],
        )
        .map(|row| row.get(0))
        .unwrap();
    assert_eq!(phase, "pending");

    delete_created_bundle(&store, &request);
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&request)
            .unwrap(),
        first
    );
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn same_key_different_fingerprint_conflicts_before_candidate_reads() {
    let (_url, store, _second, workspace) = stores();
    let first = request(&workspace, "demo", 1, "same-key");
    store
        .create_cat_covered_without_admission_for_product_test(&first)
        .unwrap();
    let mut changed = request(&workspace, "different", 2, "same-key");
    changed.idempotency.request_fingerprint = Sha256Digest::from_bytes([9; 32]);
    let error = store
        .create_cat_covered_without_admission_for_product_test(&changed)
        .unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Conflict);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
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

    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&first)
            .unwrap()
            .http_status,
        202
    );
    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&second)
            .unwrap()
            .http_status,
        202
    );
    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&third)
            .unwrap()
            .http_status,
        202
    );
    assert_eq!(counts(&store), [3, 3, 3, 3, 3, 3, 3, 3]);
}

#[test]
fn fast_miss_same_key_race_commits_only_one_candidate_bundle() {
    let (_url, first, second, workspace) = stores();
    let first_request = request(&workspace, "demo", 1, "same-key");
    let mut second_request = request(&workspace, "demo", 2, "same-key");
    second_request.idempotency.request_fingerprint =
        first_request.idempotency.request_fingerprint.clone();
    assert!(first
        .covered_api_result_fast_lookup(&first_request.idempotency)
        .unwrap()
        .is_none());
    assert!(second
        .covered_api_result_fast_lookup(&second_request.idempotency)
        .unwrap()
        .is_none());
    let saved_first = first_request.clone();
    let saved_second = second_request.clone();
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_worker = std::thread::spawn(move || {
        first_barrier.wait();
        first.create_cat_covered_without_admission_for_product_test(&first_request)
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.create_cat_covered_without_admission_for_product_test(&second_request)
    });
    barrier.wait();
    let first_result = first_worker.join().unwrap().unwrap();
    let second_result = second_worker.join().unwrap().unwrap();
    assert_eq!(first_result, second_result);

    let observer = Store::connect(&_url, None).unwrap();
    assert_eq!(counts(&observer), [1, 1, 1, 1, 1, 1, 1, 1]);
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
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();

    let mut cat_collision = request(&workspace, "new-cat-name", 2, "cat-collision");
    cat_collision.candidate.cat_id = original.candidate.cat_id.clone();
    cat_collision.candidate.desired.cat_id = original.candidate.cat_id.clone();
    cat_collision.candidate.endpoint.cat_id = original.candidate.cat_id.clone();
    cat_collision.candidate.hostname_lookup.cat_id = original.candidate.cat_id.clone();
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

    let mut network_collision = request(&workspace, "new-network-name", 7, "network-collision");
    network_collision
        .candidate
        .desired
        .runtime
        .network_config
        .network_id = original
        .candidate
        .desired
        .runtime
        .network_config
        .network_id
        .clone();
    refresh_candidate_contract(&mut network_collision);

    let mut endpoint_collision = request(&workspace, "new-endpoint-name", 6, "endpoint-collision");
    endpoint_collision.candidate.endpoint.endpoint_id =
        original.candidate.endpoint.endpoint_id.clone();
    endpoint_collision.candidate.hostname_lookup.endpoint_id =
        original.candidate.endpoint.endpoint_id.clone();
    endpoint_collision.candidate.desired.endpoints[0].endpoint_id =
        original.candidate.endpoint.endpoint_id.clone();
    let endpoint_suffix = original
        .candidate
        .endpoint
        .endpoint_id
        .as_str()
        .strip_prefix("ep_")
        .unwrap();
    let endpoint_collision_hostname =
        Hostname::new(format!("new-endpoint-name-{endpoint_suffix}.cats.run")).unwrap();
    endpoint_collision.candidate.hostname_lookup.hostname = endpoint_collision_hostname.clone();
    endpoint_collision.candidate.desired.endpoints[0].hostname = endpoint_collision_hostname;
    refresh_candidate_contract(&mut endpoint_collision);

    for (request, expected) in [
        (&cat_collision, CandidateCollision::CatId),
        (&disk_collision, CandidateCollision::DiskIdOrName),
        (&volume_collision, CandidateCollision::VolumeId),
        (&endpoint_collision, CandidateCollision::EndpointIdOrName),
        (&operation_collision, CandidateCollision::OperationId),
        (&network_collision, CandidateCollision::NetworkId),
    ] {
        let error = store
            .create_cat_covered_without_admission_for_product_test(request)
            .unwrap_err();
        assert!(matches!(
            error,
            CoveredCatCreateError::CandidateCollision(kind) if kind == expected
        ));
        assert_eq!(failed_request_artifact_count(&store, request), 0);
        assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
    }
}

#[test]
fn concurrent_cross_node_network_identity_commits_have_exactly_one_winner() {
    let (_url, first, second, workspace) = stores();
    let first_request = request(&workspace, "network-a", 101, "network-key-a");
    let mut second_request = request(&workspace, "network-b", 102, "network-key-b");
    second_request
        .candidate
        .desired
        .runtime
        .network_config
        .network_id = first_request
        .candidate
        .desired
        .runtime
        .network_config
        .network_id
        .clone();
    refresh_candidate_contract(&mut second_request);

    let saved_first = first_request.clone();
    let saved_second = second_request.clone();
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_worker = std::thread::spawn(move || {
        first_barrier.wait();
        first.create_cat_covered_without_admission_for_product_test(&first_request)
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.create_cat_covered_without_admission_for_product_test(&second_request)
    });
    barrier.wait();
    let first_result = first_worker.join().unwrap();
    let second_result = second_worker.join().unwrap();

    let observer = Store::connect(&_url, None).unwrap();
    let (winner, loser, loser_error) = match (first_result, second_result) {
        (Ok(result), Err(error)) => {
            assert_eq!(result.http_status, 202);
            (&saved_first, &saved_second, error)
        }
        (Err(error), Ok(result)) => {
            assert_eq!(result.http_status, 202);
            (&saved_second, &saved_first, error)
        }
        results => panic!("expected one network winner and one collision: {results:?}"),
    };
    assert!(matches!(
        loser_error,
        CoveredCatCreateError::CandidateCollision(CandidateCollision::NetworkId)
    ));
    assert_eq!(candidate_row_count(&observer, winner), 7);
    assert_eq!(candidate_row_count(&observer, loser), 0);
    assert_eq!(counts(&observer), [1, 1, 1, 1, 1, 1, 1, 1]);
}

#[test]
fn hostname_is_globally_unique_within_and_across_workspaces() {
    let (_url, store, _second, workspace) = stores();
    let other_workspace = bootstrap_workspace(&store, "hostname-other");
    let original = request(&workspace, "original", 1, "original-key");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();

    let same_workspace = request(&workspace, "same-workspace", 2, "same-workspace-key");
    let occupied_hostname = same_workspace.candidate.hostname_lookup.hostname.clone();
    let mut occupied_desired = original.candidate.desired.clone();
    occupied_desired.endpoints[0].hostname = occupied_hostname.clone();
    occupied_desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    occupied_desired.spec_digest = spec_digest(&occupied_desired).unwrap();
    let mut occupied_lookup = original.candidate.hostname_lookup.clone();
    occupied_lookup.hostname = occupied_hostname;
    rewrite_current_desired_and_operation(
        &store,
        &occupied_desired,
        Some((
            original.candidate.hostname_lookup.hostname.clone(),
            occupied_lookup,
        )),
    );

    let cross_workspace = request(&other_workspace, "same-workspace", 2, "cross-workspace-key");

    for candidate in [&same_workspace, &cross_workspace] {
        assert!(matches!(
            store
                .create_cat_covered_without_admission_for_product_test(candidate)
                .unwrap_err(),
            CoveredCatCreateError::CandidateCollision(CandidateCollision::Hostname)
        ));
        assert_eq!(failed_request_artifact_count(&store, candidate), 0);
    }
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
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

    let error = store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap_err();
    assert!(matches!(
        error,
        CoveredCatCreateError::CandidateCollision(CandidateCollision::DiskIdOrName)
    ));
    assert_eq!(candidate_row_count(&store, &create), 0);
    assert_eq!(failed_request_artifact_count(&store, &create), 0);
    assert_eq!(counts(&store), [0, 1, 1, 0, 0, 0, 0, 0]);
}

#[test]
fn corrupt_collision_row_is_not_reported_as_retryable_candidate_collision() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "original", 1, "original-key");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();
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
    collision.candidate.endpoint.cat_id = original.candidate.cat_id.clone();
    collision.candidate.hostname_lookup.cat_id = original.candidate.cat_id.clone();
    collision.candidate.root_disk.role = DiskRole::Root {
        cat_id: original.candidate.cat_id.clone(),
    };
    refresh_candidate_contract(&mut collision);

    let error = store
        .create_cat_covered_without_admission_for_product_test(&collision)
        .unwrap_err();
    assert!(matches!(error, CoveredCatCreateError::Store(_)));
    assert_eq!(failed_request_artifact_count(&store, &collision), 0);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
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
        first.create_cat_covered_without_admission_for_product_test(&first_request)
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.create_cat_covered_without_admission_for_product_test(&second_request)
    });
    barrier.wait();
    let first_result = first_worker.join().unwrap().unwrap();
    let second_result = second_worker.join().unwrap().unwrap();
    let statuses = [first_result.http_status, second_result.http_status];
    assert!(statuses.contains(&202));
    assert!(statuses.contains(&409));

    let observer = Store::connect(&_url, None).unwrap();
    assert_eq!(counts(&observer), [1, 1, 1, 1, 1, 1, 1, 2]);
    let (winner, loser, loser_result) = if first_result.http_status == 202 {
        (&saved_first, &saved_second, second_result)
    } else {
        (&saved_second, &saved_first, first_result)
    };
    delete_created_bundle(&observer, winner);
    assert_eq!(
        observer
            .create_cat_covered_without_admission_for_product_test(loser)
            .unwrap(),
        loser_result
    );
    assert_eq!(counts(&observer), [0, 0, 0, 0, 0, 0, 0, 2]);
}

#[test]
fn removed_default_endpoint_with_no_lookup_remains_a_durable_name_conflict() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();
    advance_current_endpoints(&store, &original, None, id("op_without_endpoints"));

    assert!(store
        .locate_hostname_desired(&original.candidate.hostname_lookup.hostname)
        .unwrap()
        .is_none());
    let conflict = request(&workspace, "demo", 2, "after-endpoint-removal");
    let first = store
        .create_cat_covered_without_admission_for_product_test(&conflict)
        .unwrap();
    assert_eq!(first.http_status, 409);
    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&conflict)
            .unwrap(),
        first
    );
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 0, 2, 2]);
}

#[test]
fn non_default_current_binding_is_closed_and_corruption_is_not_cached_as_409() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();
    let replacement_hostname =
        Hostname::new("api-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.cats.run").unwrap();
    let mut current = advance_current_endpoints(
        &store,
        &original,
        Some((
            id("ep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            id("api"),
            replacement_hostname.clone(),
        )),
        id("op_api_endpoint"),
    );

    let valid_conflict = request(&workspace, "demo", 2, "valid-non-default");
    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&valid_conflict)
            .unwrap()
            .http_status,
        409
    );

    current.endpoints[0].hostname =
        Hostname::new("drift-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.cats.run").unwrap();
    current.spec_digest = Sha256Digest::from_bytes([0; 32]);
    current.spec_digest = spec_digest(&current).unwrap();
    rewrite_current_desired_and_operation(&store, &current, None);
    let lookup_error = store
        .locate_hostname_desired(&replacement_hostname)
        .unwrap_err();
    assert_eq!(lookup_error.code, ErrorCode::Internal);

    let corrupt_conflict = request(&workspace, "demo", 3, "corrupt-non-default");
    let error = store
        .create_cat_covered_without_admission_for_product_test(&corrupt_conflict)
        .unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [1, 1, 1, 1, 2, 1, 2, 2]);
}

#[test]
fn residual_lookup_outside_current_desired_fails_closed_without_a_409() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();
    let mut corrupt = original.candidate.desired.clone();
    corrupt.endpoints.clear();
    corrupt.spec_digest = Sha256Digest::from_bytes([0; 32]);
    corrupt.spec_digest = spec_digest(&corrupt).unwrap();
    rewrite_current_desired_and_operation(&store, &corrupt, None);

    let conflict = request(&workspace, "demo", 2, "residual-lookup");
    let error = store
        .create_cat_covered_without_admission_for_product_test(&conflict)
        .unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
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
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 0]);

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
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 0]);

    let other_workspace = bootstrap_workspace(&store, "other");
    let mut cross_workspace = request(&other_workspace, "demo", 1, "cross-workspace");
    cross_workspace.idempotency.authenticated_workspace_id = workspace;
    let error = store
        .create_cat_covered_without_admission_for_product_test(&cross_workspace)
        .unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 0]);
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
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn every_invalid_default_endpoint_binding_rolls_back_without_a_result() {
    let (_url, store, _second, workspace) = stores();

    let mut wrong_owner = request(&workspace, "wrong-owner", 30, "endpoint-owner");
    wrong_owner.candidate.endpoint.workspace_id = id("ws_wrong");

    let mut wrong_name = request(&workspace, "wrong-name", 31, "endpoint-name");
    wrong_name.candidate.endpoint.name = id("not-web");

    let mut wrong_lookup_endpoint = request(&workspace, "wrong-lookup", 32, "endpoint-lookup");
    wrong_lookup_endpoint.candidate.hostname_lookup.endpoint_id = id("ep_wrong");

    let mut wrong_lookup_revision = request(&workspace, "wrong-revision", 33, "endpoint-revision");
    wrong_lookup_revision
        .candidate
        .hostname_lookup
        .desired_revision = revision(2);

    let mut missing = request(&workspace, "missing", 34, "endpoint-missing");
    missing.candidate.desired.endpoints.clear();
    refresh_candidate_contract(&mut missing);

    let mut duplicate = request(&workspace, "duplicate", 35, "endpoint-duplicate");
    duplicate.candidate.desired.endpoints.push(EndpointIntent {
        endpoint_id: id("ep_ffffffffffffffffffffffffffffffff"),
        hostname: Hostname::new("duplicate-ffffffffffffffffffffffffffffffff.cats.run").unwrap(),
        route_epoch: epoch(1),
        protocol: HttpProtocol::Http,
        target_port: 8080,
    });
    refresh_candidate_contract(&mut duplicate);

    let mut wrong_hostname = request(&workspace, "wrong-hostname", 36, "endpoint-hostname");
    wrong_hostname.candidate.hostname_lookup.hostname =
        Hostname::new("different-00000000000000000000000000000000.cats.run").unwrap();

    let mut wrong_epoch = request(&workspace, "wrong-epoch", 37, "endpoint-epoch");
    wrong_epoch.candidate.desired.endpoints[0].route_epoch = epoch(2);
    refresh_candidate_contract(&mut wrong_epoch);

    let mut wrong_port = request(&workspace, "wrong-port", 38, "endpoint-port");
    wrong_port.candidate.desired.endpoints[0].target_port = 8081;
    refresh_candidate_contract(&mut wrong_port);

    for (label, candidate) in [
        ("Endpoint owner", &wrong_owner),
        ("Endpoint management name", &wrong_name),
        ("lookup Endpoint", &wrong_lookup_endpoint),
        ("lookup revision", &wrong_lookup_revision),
        ("missing default Endpoint", &missing),
        ("multiple initial Endpoints", &duplicate),
        ("lookup hostname", &wrong_hostname),
        ("initial route epoch", &wrong_epoch),
        ("initial target port", &wrong_port),
    ] {
        assert_invalid_bundle_writes_nothing(&store, candidate, label);
    }
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn every_self_consistent_wrong_initial_projection_rolls_back() {
    let (_url, store, _second, workspace) = stores();

    let mut wrong_revision = request(&workspace, "wrong-revision", 40, "projection-revision");
    wrong_revision.candidate.desired.desired_revision = revision(2);
    wrong_revision.candidate.hostname_lookup.desired_revision = revision(2);
    refresh_candidate_contract(&mut wrong_revision);

    let mut wrong_target = request(&workspace, "wrong-target", 41, "projection-target");
    wrong_target.candidate.desired.target = RuntimeTarget::Cold;
    refresh_candidate_contract(&mut wrong_target);

    let mut wrong_placement = request(&workspace, "wrong-placement", 42, "projection-placement");
    wrong_placement.candidate.desired.placement.placement_epoch = epoch(2);
    refresh_candidate_contract(&mut wrong_placement);

    let mut wrong_transition = request(&workspace, "wrong-transition", 43, "projection-transition");
    wrong_transition.candidate.desired.desired_revision = revision(2);
    wrong_transition.candidate.hostname_lookup.desired_revision = revision(2);
    wrong_transition.candidate.desired.target = RuntimeTarget::Suspended;
    wrong_transition.candidate.desired.transition = RuntimeTransition::RequireIdle {
        attempt_id: random_id(43_001),
        source_revision: revision(1),
        source_runtime_incarnation: random_id(43_002),
    };
    refresh_candidate_contract(&mut wrong_transition);

    let mut wrong_serial = request(&workspace, "wrong-serial", 44, "projection-serial");
    wrong_serial.candidate.desired.volumes[0]
        .guest_device
        .serial = id("not-cats-root");
    refresh_candidate_contract(&mut wrong_serial);

    let mut wrong_slot = request(&workspace, "wrong-slot", 45, "projection-slot");
    wrong_slot.candidate.desired.volumes[0].guest_device.slot = 1;
    assert!(spec_digest(&wrong_slot.candidate.desired).is_err());

    let mut wrong_hostname = request(&workspace, "wrong-hostname", 46, "projection-hostname");
    let self_consistent_wrong_hostname =
        Hostname::new("other-00000000000000000000000000000046.cats.run").unwrap();
    wrong_hostname.candidate.desired.endpoints[0].hostname = self_consistent_wrong_hostname.clone();
    wrong_hostname.candidate.hostname_lookup.hostname = self_consistent_wrong_hostname;
    refresh_candidate_contract(&mut wrong_hostname);

    let mut wrong_endpoint_id = request(
        &workspace,
        "wrong-endpoint-id",
        47,
        "projection-endpoint-id",
    );
    let uppercase_endpoint_id = id("ep_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    wrong_endpoint_id.candidate.endpoint.endpoint_id = uppercase_endpoint_id.clone();
    wrong_endpoint_id.candidate.hostname_lookup.endpoint_id = uppercase_endpoint_id.clone();
    wrong_endpoint_id.candidate.desired.endpoints[0].endpoint_id = uppercase_endpoint_id;
    refresh_candidate_contract(&mut wrong_endpoint_id);

    for (label, candidate) in [
        ("revision", &wrong_revision),
        ("target", &wrong_target),
        ("placement epoch", &wrong_placement),
        ("transition", &wrong_transition),
        ("Root serial", &wrong_serial),
        ("hostname projection", &wrong_hostname),
        ("Endpoint suffix", &wrong_endpoint_id),
    ] {
        assert_invalid_bundle_writes_nothing(&store, candidate, label);
    }
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 0]);
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
            "endpoint_records",
            "UPDATE endpoint_records SET created_at=created_at+1",
        ),
        (
            "hostname_desired_lookups",
            "UPDATE hostname_desired_lookups
                SET hostname='projection-drift-00000000000000000000000000000000.cats.run'",
        ),
        (
            "runtime_operations",
            "UPDATE runtime_operations SET node_id='wrong-node'",
        ),
    ] {
        let (_url, store, _second, workspace) = stores();
        let original = request(&workspace, "demo", 1, "original");
        store
            .create_cat_covered_without_admission_for_product_test(&original)
            .unwrap();
        store.with(|client| client.batch_execute(mutation)).unwrap();

        let conflict = request(&workspace, "demo", 2, "would-conflict");
        let error = store
            .create_cat_covered_without_admission_for_product_test(&conflict)
            .unwrap_err();
        assert_eq!(error_code(error), ErrorCode::Internal, "table {table}");
        assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1], "table {table}");
    }
}

#[test]
fn self_consistent_illegal_root_identity_or_timestamp_never_becomes_a_409() {
    for drift in ["Root name", "created timestamp"] {
        let (url, store, _second, workspace) = stores();
        let original = request(&workspace, "demo", 1, "original");
        store
            .create_cat_covered_without_admission_for_product_test(&original)
            .unwrap();
        let mut raw_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let changed = if drift == "Root name" {
            let ddl_error = raw_client
                .execute(
                    "UPDATE disk_records
                        SET name=$1,
                            record=jsonb_set(record, '{name}', to_jsonb($1::TEXT), FALSE)
                      WHERE disk_id=$2",
                    &[
                        &"corrupt_root_name",
                        &original.candidate.root_disk.disk_id.as_str(),
                    ],
                )
                .unwrap_err();
            assert_eq!(ddl_error.code(), Some(&SqlState::CHECK_VIOLATION));
            // Simulate a stored row written while the DDL backstop was absent;
            // both JSONB and its projection remain internally consistent.
            raw_client
                .batch_execute(
                    "DO $$
                     DECLARE target_constraint TEXT;
                     BEGIN
                       SELECT conname INTO STRICT target_constraint
                         FROM pg_constraint
                        WHERE conrelid='disk_records'::regclass
                          AND contype='c'
                          AND pg_get_constraintdef(oid) LIKE '%root_cat_id%';
                       EXECUTE format(
                         'ALTER TABLE disk_records DROP CONSTRAINT %I',
                         target_constraint
                       );
                     END $$;",
                )
                .unwrap();
            raw_client
                .execute(
                    "UPDATE disk_records
                        SET name=$1,
                            record=jsonb_set(record, '{name}', to_jsonb($1::TEXT), FALSE)
                      WHERE disk_id=$2",
                    &[
                        &"corrupt_root_name",
                        &original.candidate.root_disk.disk_id.as_str(),
                    ],
                )
                .unwrap()
        } else {
            raw_client
                .execute(
                    "UPDATE disk_records
                        SET created_at=created_at+1,
                            record=jsonb_set(
                              record, '{created_at}', to_jsonb(created_at+1), FALSE
                            )
                      WHERE disk_id=$1",
                    &[&original.candidate.root_disk.disk_id.as_str()],
                )
                .unwrap()
        };
        assert_eq!(changed, 1, "{drift}");

        let conflict = request(&workspace, "demo", 2, "would-conflict");
        let error = store
            .create_cat_covered_without_admission_for_product_test(&conflict)
            .unwrap_err();
        assert_eq!(error_code(error), ErrorCode::Internal, "{drift}");
        assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1], "{drift}");
    }
}

#[test]
fn self_valid_rows_with_a_missing_operation_are_not_a_name_conflict() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();
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
    let error = store
        .create_cat_covered_without_admission_for_product_test(&conflict)
        .unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 0, 1]);
}

#[test]
fn every_closed_json_row_corruption_fails_closed_without_a_409_result() {
    for table in [
        "cat_records",
        "disk_records",
        "desired_runtime_specs",
        "endpoint_records",
        "hostname_desired_lookups",
        "runtime_operations",
    ] {
        let (_url, store, _second, workspace) = stores();
        let original = request(&workspace, "demo", 1, "original");
        store
            .create_cat_covered_without_admission_for_product_test(&original)
            .unwrap();
        let sql = format!("UPDATE {table} SET record=record || '{{\"unexpected\":true}}'::jsonb");
        store.with(|client| client.batch_execute(&sql)).unwrap();

        let conflict = request(&workspace, "demo", 2, "would-conflict");
        let error = store
            .create_cat_covered_without_admission_for_product_test(&conflict)
            .unwrap_err();
        assert_eq!(error_code(error), ErrorCode::Internal, "table {table}");
        assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1], "table {table}");
    }
}

#[test]
fn hostname_lookup_fails_closed_when_current_desired_revision_drifts() {
    let (url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();

    let mut drifted = original.candidate.desired.clone();
    drifted.desired_revision = revision(2);
    drifted.spec_digest = Sha256Digest::from_bytes([0; 32]);
    drifted.spec_digest = spec_digest(&drifted).unwrap();
    let encoded = String::from_utf8(encode_desired_runtime_spec(&drifted).unwrap()).unwrap();

    let mut raw_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    // Simulate a row written while the cross-revision DDL backstop was absent.
    // The Desired JSON and projections remain internally self-consistent, so
    // only the lookup/current-Desired cross-check can reject it.
    raw_client
        .batch_execute(
            "DO $$
             DECLARE target_constraint TEXT;
             BEGIN
               SELECT conname INTO STRICT target_constraint
                 FROM pg_constraint
                WHERE conrelid='hostname_desired_lookups'::regclass
                  AND confrelid='desired_runtime_specs'::regclass
                  AND contype='f';
               EXECUTE format(
                 'ALTER TABLE hostname_desired_lookups DROP CONSTRAINT %I',
                 target_constraint
               );
             END $$;",
        )
        .unwrap();
    raw_client
        .execute(
            "UPDATE desired_runtime_specs
                SET record=$1::TEXT::jsonb,
                    desired_revision=$2,
                    spec_digest=$3
              WHERE cat_id=$4",
            &[
                &encoded,
                &2_i64,
                &drifted.spec_digest.as_str(),
                &drifted.cat_id.as_str(),
            ],
        )
        .unwrap();

    let lookup_error = store
        .locate_hostname_desired(&original.candidate.hostname_lookup.hostname)
        .unwrap_err();
    assert_eq!(lookup_error.code, ErrorCode::Internal);

    let conflict = request(&workspace, "demo", 2, "would-conflict");
    let conflict_error = store
        .create_cat_covered_without_admission_for_product_test(&conflict)
        .unwrap_err();
    assert_eq!(error_code(conflict_error), ErrorCode::Internal);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
}

#[test]
fn corrupt_api_result_fails_both_fast_and_transactional_reads_closed() {
    let (_url, store, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();
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
        .covered_api_result_fast_lookup(&original.idempotency)
        .unwrap_err();
    assert_eq!(fast.code, ErrorCode::Internal);
    let transactional = store
        .create_cat_covered_without_admission_for_product_test(&original)
        .unwrap_err();
    assert_eq!(error_code(transactional), ErrorCode::Internal);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
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
    let result = store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    assert_eq!(result.http_status, 202);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
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
fn failure_after_endpoint_and_lookup_inserts_rolls_everything_back() {
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
    let error = store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap_err();
    assert_eq!(error_code(error), ErrorCode::Internal);
    assert_eq!(counts(&store), [0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn cat_create_does_not_read_or_write_legacy_endpoint_and_route_rows() {
    let (_url, store, _second, workspace) = stores();
    store
        .with(|client| {
            client.batch_execute(
                "INSERT INTO endpoints (
                    id, cat_id, name, hostname, target_port, protocol, wake_policy
                 ) VALUES (
                    'legacy_endpoint', 'legacy_cat', 'legacy_name',
                    'legacy.example.invalid', 4321, 'legacy_protocol', 'legacy_wake'
                 );
                 INSERT INTO routes (
                    hostname, cat_id, node_id, gateway_url, target_port, epoch, state
                 ) VALUES (
                    'legacy.example.invalid', 'legacy_cat', 'legacy_node',
                    'https://legacy.example.invalid', 4321, 77, 'legacy_state'
                 );",
            )
        })
        .unwrap();
    let before: (String, String) = store
        .with(|client| {
            let endpoint = client
                .query_one(
                    "SELECT to_jsonb(e)::TEXT FROM endpoints e WHERE id='legacy_endpoint'",
                    &[],
                )?
                .get(0);
            let route = client
                .query_one(
                    "SELECT to_jsonb(r)::TEXT FROM routes r
                      WHERE hostname='legacy.example.invalid'",
                    &[],
                )?
                .get(0);
            Ok((endpoint, route))
        })
        .unwrap();

    let create = request(&workspace, "demo", 1, "legacy-sentinel");
    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&create)
            .unwrap()
            .http_status,
        202
    );

    let after: (String, String) = store
        .with(|client| {
            let endpoint = client
                .query_one(
                    "SELECT to_jsonb(e)::TEXT FROM endpoints e WHERE id='legacy_endpoint'",
                    &[],
                )?
                .get(0);
            let route = client
                .query_one(
                    "SELECT to_jsonb(r)::TEXT FROM routes r
                      WHERE hostname='legacy.example.invalid'",
                    &[],
                )?
                .get(0);
            Ok((endpoint, route))
        })
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
}

#[test]
fn cat_create_remains_independent_when_legacy_endpoint_tables_are_absent() {
    let (_url, store, _second, workspace) = stores();
    store
        .with(|client| client.batch_execute("DROP TABLE routes; DROP TABLE endpoints;"))
        .unwrap();

    let create = request(&workspace, "demo", 1, "legacy-absent");
    assert_eq!(
        store
            .create_cat_covered_without_admission_for_product_test(&create)
            .unwrap()
            .http_status,
        202
    );
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 1, 1, 1]);
}

#[test]
fn concurrent_destroy_after_name_peek_cannot_be_cached_as_409() {
    const APPLICATION_NAME: &str = "cats-f2a-destroy-race";
    let (url, seed, _second, workspace) = stores();
    let original = request(&workspace, "demo", 1, "original");
    seed.create_cat_covered_without_admission_for_product_test(&original)
        .unwrap();
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

    let worker = std::thread::spawn(move || {
        conflict_store.create_cat_covered_without_admission_for_product_test(&conflict)
    });
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
            "DELETE FROM hostname_desired_lookups WHERE hostname=$1",
            &[&original.candidate.hostname_lookup.hostname.as_str()],
        )
        .unwrap();
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
            "DELETE FROM endpoint_records WHERE endpoint_id=$1",
            &[&original.candidate.endpoint.endpoint_id.as_str()],
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
    assert_eq!(counts(&seed), [0, 0, 0, 0, 0, 0, 0, 1]);
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
                    .create_cat_covered_without_admission_for_product_test(&worker_request)
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
                .create_cat_covered_without_admission_for_product_test(&replay_request)
                .map_err(into_api_error)
        })
        .await
        .unwrap();
    blocker.join().unwrap();
    assert_eq!(replay.http_status, 202);
    assert_eq!(counts(&second), [1, 1, 1, 1, 1, 1, 1, 1]);

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

//! Real PostgreSQL acceptance tests for covered Cat create.

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, encode_operation, guest_config_digest, spec_digest,
    AllocatableMemoryBytes, AllocatableVcpus, AsciiText, AssignedKind, AssignedPlacement,
    ContractVersion, CredentialBinding, DesiredRuntimeSpec, DiskKind, Durability, EndpointIntent,
    Epoch, Ext4MountIntent, FenceEpoch, FilesystemInitialization, Generation, GuestDeviceIdentity,
    GuestIpv4Pool, GuestIpv4PoolKind, GuestRuntimeProfileReceipt, Hostname, HttpProtocol, Id,
    Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig, NodeIdentity, NodeIdentityState,
    NodePlacementPolicy, NodeTransportTarget, OperationPhase, OperationTerminal, RandomId128,
    Revision, RuntimeConfig, RuntimePlacementBlockFrontend, RuntimePlacementCapabilities,
    RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport, RuntimePlacementVmm,
    RuntimeSchedulingState, RuntimeTarget, RuntimeTransition, Sha256Digest, UnixMillis,
    VolumeAccess, VolumeAcquire, VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::{
    begin_delete, complete_disposable_root_delete, complete_normal_delete,
    consume_disposable_root_delete, normal_acquire, AuthorizationRecord, AuthorizationState,
    BeginDeleteRequest, DeleteCompletionReceipt, DisposableDeleteIsolationBasis,
    DisposableRootDeleteAuthorization,
    HostFenceEvent, HostFenceEventState, HostIsolationState, LastVolumeTransition, NodeBootId,
    NormalAcquireRequest, RemoteHead, VolumeAdminState, VolumeAuthorization, VolumeDurability,
    VolumeRecord,
};
use postgres::error::SqlState;
use sha2::{Digest, Sha256};

use super::cat_create_service::CatCreatePlacementMutation;
use super::covered_commit::CoveredCommitCancellation;
use super::placement_planner::{allocate_network_for_test, PlacementTargetSnapshot};
use super::placement_policy::{insert_policy_on_store_for_test, update_policy_for_test};
use super::product::{
    api_request_fingerprint, candidate_matches_placement_mutation,
    encode_cat_create_accepted_response, encode_cat_name_conflict_response,
    persistent_initialization_matches_mount, ApiIdempotencyRequest, CandidateCollision,
    CatCreateCandidate, CatCreateEnvelopes, CatRecord, CoveredCatCreateError,
    CoveredCatCreateRequest, CoveredDesiredMutationError, CoveredDesiredMutationRequest,
    DesiredMutationCommit, DiskAdminState, DiskRecord, DiskRecordCandidate, DiskRole,
    EndpointRecord, EndpointRecordCandidate, ExactContentType, ExactHttpResponse,
    HostnameDesiredLocation, HostnameDesiredLookup, IfMatchFingerprint,
    PersistentDiskInitialization, RuntimeOperationRead,
};
use super::product_reads::{ProductPageRead, ProductRead};
use super::product_rows::{
    insert_cat, insert_disk, insert_endpoint, insert_hostname_lookup, insert_operation,
    load_disk_by_id_for_update, load_operation_by_cat_revision_unlocked,
    operation_by_workspace_candidates_sql,
};
use super::rows::{
    database_now, insert_authorization, insert_delete_completion, insert_event, insert_volume,
    update_authorization,
};
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

fn node_identity(node_id: &Id, discriminator: u8) -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        immutable_host_id: id(format!("host_{discriminator}")),
        credential_id: id(format!("credential_{discriminator}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([discriminator; 32]),
        },
        state_path_id: id(format!("state_path_{discriminator}")),
        state: NodeIdentityState::Provisioned,
    }
}

fn desired_mutation_request(
    expected: &DesiredRuntimeSpec,
    desired: DesiredRuntimeSpec,
    operation_id: &str,
    key: &str,
    placement_snapshots: Vec<PlacementTargetSnapshot>,
    active_guest_digest: Sha256Digest,
    endpoint_records: Vec<EndpointRecordCandidate>,
) -> CoveredDesiredMutationRequest {
    let operation_id = id(operation_id);
    let route = AsciiText::new("POST /v1/workspaces/{workspace}/cats/{cat}/actions/runtime-target")
        .unwrap();
    let raw_path = format!(
        "/v1/workspaces/{}/cats/{}/actions/runtime-target",
        expected.workspace_id, expected.cat_id
    );
    let target = match desired.target {
        RuntimeTarget::Running => "running",
        RuntimeTarget::Suspended => "suspended",
        RuntimeTarget::Warm => "warm",
        RuntimeTarget::Cold => "cold",
        RuntimeTarget::Deleted => "deleted",
    };
    let raw_body = format!(r#"{{"target":"{target}"}}"#);
    CoveredDesiredMutationRequest {
        idempotency: ApiIdempotencyRequest {
            authenticated_workspace_id: expected.workspace_id.clone(),
            canonical_route: route.clone(),
            idempotency_key: AsciiText::new(key).unwrap(),
            request_fingerprint: api_request_fingerprint(
                &expected.workspace_id,
                &route,
                raw_path.as_bytes(),
                IfMatchFingerprint::Absent,
                raw_body.as_bytes(),
            )
            .unwrap(),
        },
        expected_current: expected.clone(),
        desired,
        operation_id,
        placement_snapshots,
        active_guest_digest,
        endpoint_records,
    }
}

fn commit_desired_mutation(
    store: &Store,
    request: &CoveredDesiredMutationRequest,
) -> std::result::Result<DesiredMutationCommit, CoveredDesiredMutationError> {
    let (_cancellation, state) = CoveredCommitCancellation::new(
        "Desired mutation test",
        Instant::now() + Duration::from_secs(30),
    );
    store.commit_desired_mutation_covered(request, &state)
}

fn mutation_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::from_bytes([21; 32]),
        initramfs_digest: Some(Sha256Digest::from_bytes([22; 32])),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn mutation_policy(node_id: &Id, digest: &Sha256Digest, discriminator: u8) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        policy_revision: epoch(1),
        scheduling_state: RuntimeSchedulingState::Schedulable,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: digest.clone(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new(format!("10.{discriminator}.0.0")).unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new(format!(
            "https://node-{discriminator}.internal:7301"
        ))
        .unwrap(),
    }
}

fn prepare_mutation_node(
    store: &Store,
    create: &mut CoveredCatCreateRequest,
    discriminator: u8,
) -> (
    NodeIdentity,
    NodePlacementPolicy,
    GuestRuntimeProfileReceipt,
) {
    let release = mutation_release();
    let digest = guest_config_digest(&release).unwrap();
    let identity = node_identity(&create.candidate.desired.placement.node_id, discriminator);
    let policy = mutation_policy(&identity.node_id, &digest, discriminator);
    create.candidate.desired.runtime.guest_config_digest = digest;
    create.candidate.desired.runtime.network_config = allocate_network_for_test(
        &policy,
        &create.candidate.desired.runtime.network_config.network_id,
    );
    refresh_candidate_contract(create);
    store.provision_node_identity(&identity).unwrap();
    insert_policy_on_store_for_test(store, &policy).unwrap();
    (identity, policy, release)
}

fn refresh_mutation_target(
    store: &Store,
    identity: &NodeIdentity,
    policy: &NodePlacementPolicy,
    release: &GuestRuntimeProfileReceipt,
    number: u128,
) -> PlacementTargetSnapshot {
    PlacementTargetSnapshot {
        policy: policy.clone(),
        admission: super::runtime_spine_tests::refresh_assigned_admission_for_test(
            store, identity, release, number,
        ),
        active_host_fence_event: None,
    }
}

fn active_host_fence_event(
    target: &PlacementTargetSnapshot,
    discriminator: u128,
) -> HostFenceEvent {
    HostFenceEvent {
        event_id: id(format!("fence_event_{discriminator}")),
        provider: id("test_provider"),
        immutable_host_id: target.admission.node_identity.immutable_host_id.clone(),
        node_id: target.admission.node_identity.node_id.clone(),
        expected_node_boot_id: NodeBootId::new(
            target
                .admission
                .agent_session
                .node_boot_id
                .as_str()
                .to_owned(),
        )
        .unwrap(),
        expected_agent_session_epoch: target.admission.agent_session.agent_session_epoch,
        fence_attempt_id: id(format!("fence_attempt_{discriminator}")),
        isolation_state: HostIsolationState::Isolated,
        observed_at: unix_millis(123),
        state: HostFenceEventState::Active,
    }
}

fn advance_target(current: &DesiredRuntimeSpec, target: RuntimeTarget) -> DesiredRuntimeSpec {
    let mut desired = current.clone();
    desired.desired_revision = revision(current.desired_revision.get() + 1);
    desired.target = target;
    if current.target != RuntimeTarget::Running && target == RuntimeTarget::Running {
        for endpoint in &mut desired.endpoints {
            endpoint.route_epoch = epoch(endpoint.route_epoch.get().checked_add(1).unwrap());
        }
    }
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(&desired).unwrap();
    desired
}

fn default_endpoint_record(create: &CoveredCatCreateRequest) -> EndpointRecordCandidate {
    create.candidate.endpoint.clone()
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
            guest_config_digest: guest_config_digest(&mutation_release()).unwrap(),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id(format!("network_{sequence}")),
                guest_mac: MacAddress::new("02:ca:0a:01:00:06").unwrap(),
                guest_ipv4: Ipv4Address::new("10.1.0.6").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.1.0.5").unwrap(),
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

pub(crate) fn create_runtime_operation_for_api_test(store: &Store, workspace: &Id) -> Id {
    let create = request(
        workspace,
        "operation-cancellation",
        9_999,
        "operation-cancellation",
    );
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    create.candidate.operation_id
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

#[test]
fn desired_mutation_cas_supersedes_exact_pending_history_and_skips_empty_revision() {
    let (_url, store, _second, workspace) = stores();
    let mut create = request(&workspace, "desired-cas", 1, "desired-cas-create");
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let active_digest = guest_config_digest(&release).unwrap();
    let revision_two = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    let colliding = desired_mutation_request(
        &create.candidate.desired,
        revision_two.clone(),
        create.candidate.operation_id.as_str(),
        "desired-cas-operation-collision",
        Vec::new(),
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &colliding),
        Err(CoveredDesiredMutationError::CandidateCollision(
            CandidateCollision::OperationId
        ))
    ));
    let second = desired_mutation_request(
        &create.candidate.desired,
        revision_two.clone(),
        "op_revision_2",
        "desired-cas-2",
        Vec::new(),
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    let DesiredMutationCommit::Changed(second_result) =
        commit_desired_mutation(&store, &second).unwrap()
    else {
        panic!("revision 2 must be a real mutation");
    };
    assert_eq!(second_result.http_status, 202);
    assert_eq!(
        second_result.response_body,
        br#"{"desired_revision":2,"operation_id":"op_revision_2"}"#
    );
    let DesiredMutationCommit::Replayed(replayed_second) =
        commit_desired_mutation(&store, &second).unwrap()
    else {
        panic!("same API key must replay the exact committed mutation response");
    };
    assert_eq!(replayed_second, second_result);

    let revision_three = advance_target(&revision_two, RuntimeTarget::Running);
    let revision_two_target = refresh_mutation_target(&store, &identity, &policy, &release, 102);
    let third = desired_mutation_request(
        &revision_two,
        revision_three.clone(),
        "op_revision_3",
        "desired-cas-3",
        vec![revision_two_target],
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &third).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));

    let stale = desired_mutation_request(
        &create.candidate.desired,
        revision_two,
        "op_stale_revision_2",
        "desired-cas-stale",
        Vec::new(),
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &stale),
        Err(CoveredDesiredMutationError::Stale)
    ));

    let semantically_identical = advance_target(&revision_three, RuntimeTarget::Running);
    let no_op = desired_mutation_request(
        &revision_three,
        semantically_identical,
        "op_must_not_exist",
        "desired-cas-no-op",
        Vec::new(),
        active_digest,
        vec![default_endpoint_record(&create)],
    );
    let DesiredMutationCommit::Converged(no_op_result) =
        commit_desired_mutation(&store, &no_op).unwrap()
    else {
        panic!("an identical full target must not manufacture revision 4");
    };
    assert_eq!(no_op_result.http_status, 200);
    assert_eq!(
        no_op_result.response_body,
        br#"{"desired_revision":3,"converged":true}"#
    );

    store
        .authority_transaction(|transaction| {
            let current = super::product_rows::load_desired_for_update(
                transaction,
                &create.candidate.cat_id,
            )?
            .unwrap();
            assert_eq!(current, revision_three);
            let first = load_operation_by_cat_revision_unlocked(
                transaction,
                &create.candidate.cat_id,
                revision(1),
            )?
            .unwrap();
            let second = load_operation_by_cat_revision_unlocked(
                transaction,
                &create.candidate.cat_id,
                revision(2),
            )?
            .unwrap();
            let third = load_operation_by_cat_revision_unlocked(
                transaction,
                &create.candidate.cat_id,
                revision(3),
            )?
            .unwrap();
            assert!(matches!(
                first.terminal,
                Some(OperationTerminal::Superseded {
                    superseded_by_revision,
                    ref superseded_by_operation_id,
                    ..
                }) if superseded_by_revision == revision(2)
                    && superseded_by_operation_id == &id("op_revision_2")
            ));
            assert!(matches!(
                second.terminal,
                Some(OperationTerminal::Superseded {
                    superseded_by_revision,
                    ref superseded_by_operation_id,
                    ..
                }) if superseded_by_revision == revision(3)
                    && superseded_by_operation_id == &id("op_revision_3")
            ));
            assert_eq!(third.phase, OperationPhase::Pending);
            assert!(load_operation_by_cat_revision_unlocked(
                transaction,
                &create.candidate.cat_id,
                revision(4),
            )?
            .is_none());
            Ok(())
        })
        .unwrap();
}

#[test]
fn desired_mutation_enforces_epoch_and_capacity_but_rejects_uncovered_cross_node_volumes() {
    let (_url, store, _second, workspace) = stores();
    let mut create = request(&workspace, "placement-epoch", 1, "placement-epoch-create");
    let (source, source_policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let active_digest = guest_config_digest(&release).unwrap();
    let target_node = id("node_target");
    let target = node_identity(&target_node, 2);
    let target_policy = mutation_policy(&target_node, &active_digest, 2);
    store.provision_node_identity(&target).unwrap();
    insert_policy_on_store_for_test(&store, &target_policy).unwrap();
    let source_target = refresh_mutation_target(&store, &source, &source_policy, &release, 201);
    let destination_target =
        refresh_mutation_target(&store, &target, &target_policy, &release, 202);

    let mut missing_epoch = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    missing_epoch.placement.node_id = target_node.clone();
    missing_epoch.runtime.network_config.network_id = id("network_missing_epoch");
    missing_epoch.spec_digest = spec_digest(&missing_epoch).unwrap();
    let invalid_move = desired_mutation_request(
        &create.candidate.desired,
        missing_epoch,
        "op_missing_epoch",
        "placement-epoch-missing",
        vec![source_target.clone(), destination_target.clone()],
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &invalid_move),
        Err(CoveredDesiredMutationError::Store(ref error))
            if error.code == ErrorCode::Internal
    ));

    let mut spurious_epoch = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    spurious_epoch.placement.placement_epoch = epoch(2);
    spurious_epoch.spec_digest = spec_digest(&spurious_epoch).unwrap();
    let invalid_same_node = desired_mutation_request(
        &create.candidate.desired,
        spurious_epoch,
        "op_spurious_epoch",
        "placement-epoch-spurious",
        vec![source_target.clone()],
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &invalid_same_node),
        Err(CoveredDesiredMutationError::Store(ref error))
            if error.code == ErrorCode::Internal
    ));

    let mut oversized = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    oversized.runtime.vcpus = 9;
    oversized.spec_digest = spec_digest(&oversized).unwrap();
    let oversized_request = desired_mutation_request(
        &create.candidate.desired,
        oversized,
        "op_oversized_shape",
        "placement-oversized-shape",
        vec![source_target.clone()],
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    assert_stale_mutation_wrote_nothing(&store, &oversized_request);

    let target_network = id("network_target");
    let expected_network = allocate_network_for_test(&target_policy, &target_network);
    let mut arbitrary_network =
        allocate_network_for_test(&target_policy, &id("network_arbitrary_slot"));
    arbitrary_network.network_id = target_network.clone();
    assert_ne!(arbitrary_network, expected_network);
    let mut invalid_network_move = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    invalid_network_move.placement.node_id = target_node.clone();
    invalid_network_move.placement.placement_epoch = epoch(2);
    invalid_network_move.runtime.network_config = arbitrary_network;
    invalid_network_move.spec_digest = spec_digest(&invalid_network_move).unwrap();
    let invalid_network_request = desired_mutation_request(
        &create.candidate.desired,
        invalid_network_move,
        "op_arbitrary_network",
        "placement-arbitrary-network",
        vec![source_target.clone(), destination_target.clone()],
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    assert_cross_node_volume_guard_rejected_without_writes(&store, &invalid_network_request);

    let mut moved = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    moved.placement.node_id = target_node;
    moved.placement.placement_epoch = epoch(2);
    moved.runtime.network_config = expected_network;
    moved.spec_digest = spec_digest(&moved).unwrap();
    let request = desired_mutation_request(
        &create.candidate.desired,
        moved.clone(),
        "op_move",
        "placement-epoch-move",
        vec![source_target, destination_target],
        active_digest,
        vec![default_endpoint_record(&create)],
    );
    assert_cross_node_volume_guard_rejected_without_writes(&store, &request);
}

#[test]
fn two_replicas_racing_from_one_revision_commit_exactly_one_successor() {
    let (url, first, second, workspace) = stores();
    let mut create = request(&workspace, "replica-race", 1, "replica-race-create");
    let (_identity, _policy, release) = prepare_mutation_node(&first, &mut create, 1);
    first
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let active_digest = guest_config_digest(&release).unwrap();
    let cold = desired_mutation_request(
        &create.candidate.desired,
        advance_target(&create.candidate.desired, RuntimeTarget::Cold),
        "op_race_cold",
        "replica-race-cold",
        Vec::new(),
        active_digest.clone(),
        vec![default_endpoint_record(&create)],
    );
    let warm = desired_mutation_request(
        &create.candidate.desired,
        advance_target(&create.candidate.desired, RuntimeTarget::Warm),
        "op_race_warm",
        "replica-race-warm",
        Vec::new(),
        active_digest,
        vec![default_endpoint_record(&create)],
    );
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        commit_desired_mutation(&first, &cold)
    });
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        commit_desired_mutation(&second, &warm)
    });
    barrier.wait();
    let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(DesiredMutationCommit::Changed(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(CoveredDesiredMutationError::Stale)))
            .count(),
        1
    );

    let observer = Store::connect(&url, None).unwrap();
    let (revision, pending, result_count): (i64, i64, i64) = observer
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT desired_revision FROM desired_runtime_specs WHERE cat_id=$1),
                        (SELECT count(*) FROM runtime_operations WHERE cat_id=$1 AND phase='pending'),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[&create.candidate.cat_id.as_str()],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
        })
        .unwrap();
    assert_eq!(revision, 2);
    assert_eq!(pending, 1);
    assert_eq!(result_count, 2, "Cat-create plus the one winning mutation");
}

fn wait_for_advisory_lock_wait(store: &Store, application_name: &str) {
    for _ in 0..200 {
        let waiting = store
            .with(|client| {
                client
                    .query_one(
                        "SELECT EXISTS(
                            SELECT 1 FROM pg_stat_activity
                             WHERE application_name=$1 AND wait_event_type='Lock'
                        )",
                        &[&application_name],
                    )
                    .map(|row| row.get::<_, bool>(0))
            })
            .unwrap();
        if waiting {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("{application_name} did not reach its calibrated advisory-lock wait");
}

#[test]
fn two_cats_exchanging_hostnames_lock_the_old_and_new_union_without_deadlock() {
    let (url, setup, _unused, workspace) = stores();
    let mut first_create = request(&workspace, "hostname-swap-a", 1, "hostname-swap-a-create");
    let (_first_identity, _first_policy, release) =
        prepare_mutation_node(&setup, &mut first_create, 1);
    setup
        .create_cat_covered_without_admission_for_product_test(&first_create)
        .unwrap();
    let mut second_create = request(&workspace, "hostname-swap-b", 2, "hostname-swap-b-create");
    let (_second_identity, _second_policy, _second_release) =
        prepare_mutation_node(&setup, &mut second_create, 2);
    setup
        .create_cat_covered_without_admission_for_product_test(&second_create)
        .unwrap();

    let mut first_desired = first_create.candidate.desired.clone();
    first_desired.desired_revision = revision(2);
    first_desired.endpoints[0].hostname = second_create.candidate.desired.endpoints[0]
        .hostname
        .clone();
    first_desired.endpoints[0].route_epoch = epoch(2);
    first_desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    first_desired.spec_digest = spec_digest(&first_desired).unwrap();
    let first_mutation = desired_mutation_request(
        &first_create.candidate.desired,
        first_desired,
        "op_hostname_swap_a",
        "hostname-swap-a-mutation",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&first_create)],
    );

    let mut second_desired = second_create.candidate.desired.clone();
    second_desired.desired_revision = revision(2);
    second_desired.endpoints[0].hostname =
        first_create.candidate.desired.endpoints[0].hostname.clone();
    second_desired.endpoints[0].route_epoch = epoch(2);
    second_desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    second_desired.spec_digest = spec_digest(&second_desired).unwrap();
    let second_mutation = desired_mutation_request(
        &second_create.candidate.desired,
        second_desired,
        "op_hostname_swap_b",
        "hostname-swap-b-mutation",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&second_create)],
    );

    let first_application = "a1-hostname-swap-first";
    let second_application = "a1-hostname-swap-second";
    let first = Store::connect(&with_application_name(&url, first_application), None).unwrap();
    let second = Store::connect(&with_application_name(&url, second_application), None).unwrap();
    // A non-canonical old->new cycle would hit the two-second covered lock
    // timeout before PostgreSQL's deliberately-larger deadlock detector.
    first
        .with(|client| client.batch_execute("SET deadlock_timeout='10s'"))
        .unwrap();
    second
        .with(|client| client.batch_execute("SET deadlock_timeout='10s'"))
        .unwrap();
    let observer = Store::connect(&url, None).unwrap();
    let holder = Store::connect(&url, None).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_hostname = first_create.candidate.desired.endpoints[0].hostname.clone();
    let holder_thread = std::thread::spawn(move || {
        holder
            .authority_transaction(move |transaction| {
                transaction.query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended(
                        current_schema() || ':runtime-authority:hostname:' || $1,
                        0::BIGINT
                    ))",
                    &[&first_hostname.as_str()],
                )?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();

    let first_thread = std::thread::spawn(move || commit_desired_mutation(&first, &first_mutation));
    wait_for_advisory_lock_wait(&observer, first_application);
    let second_thread =
        std::thread::spawn(move || commit_desired_mutation(&second, &second_mutation));
    wait_for_advisory_lock_wait(&observer, second_application);
    release_tx.send(()).unwrap();

    let first_outcome = first_thread.join().unwrap();
    let second_outcome = second_thread.join().unwrap();
    holder_thread.join().unwrap();
    assert!(matches!(
        first_outcome,
        Err(CoveredDesiredMutationError::CandidateCollision(
            CandidateCollision::Hostname
        ))
    ));
    assert!(matches!(
        second_outcome,
        Err(CoveredDesiredMutationError::CandidateCollision(
            CandidateCollision::Hostname
        ))
    ));
}

#[test]
fn desired_mutation_commits_a_same_node_runtime_shape_with_recomputed_capacity() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "runtime-shape", 1, "runtime-shape-create");
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let target = refresh_mutation_target(&store, &identity, &policy, &release, 351);
    let mut resized = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    resized.runtime.vcpus = 2;
    resized.runtime.memory_bytes = 512 * 1024 * 1024;
    resized.spec_digest = Sha256Digest::from_bytes([0; 32]);
    resized.spec_digest = spec_digest(&resized).unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        resized.clone(),
        "op_runtime_shape",
        "runtime-shape-mutation",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &mutation).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    let current = store
        .authority_transaction(|transaction| {
            super::product_rows::load_desired_for_update(transaction, &resized.cat_id)
        })
        .unwrap()
        .unwrap();
    assert_eq!(current, resized);
}

fn assert_stale_mutation_wrote_nothing(store: &Store, request: &CoveredDesiredMutationRequest) {
    assert!(matches!(
        commit_desired_mutation(store, request),
        Err(CoveredDesiredMutationError::Stale)
    ));
    store
        .authority_transaction(|transaction| {
            let current = super::product_rows::load_desired_for_update(
                transaction,
                &request.expected_current.cat_id,
            )?
            .unwrap();
            assert_eq!(current, request.expected_current);
            assert!(super::product_rows::load_operation_for_update(
                transaction,
                &request.operation_id,
            )?
            .is_none());
            assert!(super::product_rows::load_api_result_for_update(
                transaction,
                &request.idempotency,
            )?
            .is_none());
            Ok(())
        })
        .unwrap();
}

fn assert_desired_mutation_artifacts_absent(
    store: &Store,
    request: &CoveredDesiredMutationRequest,
) {
    store
        .authority_transaction(|transaction| {
            let current = super::product_rows::load_desired_for_update(
                transaction,
                &request.expected_current.cat_id,
            )?
            .unwrap();
            assert_eq!(current, request.expected_current);
            assert!(super::product_rows::load_operation_for_update(
                transaction,
                &request.operation_id,
            )?
            .is_none());
            assert!(super::product_rows::load_api_result_for_update(
                transaction,
                &request.idempotency,
            )?
            .is_none());
            Ok(())
        })
        .unwrap();
}

fn assert_cross_node_volume_guard_rejected_without_writes(
    store: &Store,
    request: &CoveredDesiredMutationRequest,
) {
    let error = commit_desired_mutation(store, request).unwrap_err();
    assert!(matches!(
        error,
        CoveredDesiredMutationError::Store(ref error)
            if error.message.contains("cross-Node volume authority")
    ));
    store
        .authority_transaction(|transaction| {
            let current = super::product_rows::load_desired_for_update(
                transaction,
                &request.expected_current.cat_id,
            )?
            .unwrap();
            assert_eq!(current, request.expected_current);
            assert!(super::product_rows::load_operation_for_update(
                transaction,
                &request.operation_id,
            )?
            .is_none());
            assert!(super::product_rows::load_api_result_for_update(
                transaction,
                &request.idempotency,
            )?
            .is_none());
            Ok(())
        })
        .unwrap();
}

#[test]
fn desired_mutation_rejects_policy_change_after_planning_without_any_commit_artifact() {
    let (url, planner, _unused, workspace) = stores();
    let mut create = request(&workspace, "policy-drift", 1, "policy-drift-create");
    let (identity, policy, release) = prepare_mutation_node(&planner, &mut create, 1);
    planner
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let target = refresh_mutation_target(&planner, &identity, &policy, &release, 401);
    let mut resized = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    resized.runtime.vcpus = 2;
    resized.spec_digest = Sha256Digest::from_bytes([0; 32]);
    resized.spec_digest = spec_digest(&resized).unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        resized,
        "op_policy_drift",
        "policy-drift-mutation",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );

    let writer = Store::connect(&url, None).unwrap();
    let mut next_policy = policy.clone();
    next_policy.policy_revision = epoch(2);
    next_policy.scheduling_state = RuntimeSchedulingState::Cordoned;
    writer
        .authority_transaction(|transaction| {
            update_policy_for_test(transaction, &policy, &next_policy)
        })
        .unwrap();

    assert_stale_mutation_wrote_nothing(&planner, &mutation);
}

#[test]
fn desired_target_only_does_not_consume_replaced_session_or_full_admission() {
    let (url, planner, _unused, workspace) = stores();
    let mut create = request(&workspace, "session-drift", 1, "session-drift-create");
    let (identity, policy, release) = prepare_mutation_node(&planner, &mut create, 1);
    planner
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let target = refresh_mutation_target(&planner, &identity, &policy, &release, 501);
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        advance_target(&create.candidate.desired, RuntimeTarget::Cold),
        "op_session_drift",
        "session-drift-mutation",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );

    let writer = Store::connect(&url, None).unwrap();
    super::runtime_spine_tests::replace_agent_session_for_test(
        &writer,
        &target.admission,
        &release,
        502,
    );

    assert!(matches!(
        commit_desired_mutation(&planner, &mutation).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
}

#[test]
fn desired_stop_survives_a_partial_heartbeat_and_active_release_rotation() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "partial-stop", 1, "partial-stop-create");
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let target = refresh_mutation_target(&store, &identity, &policy, &release, 551);
    super::runtime_spine_tests::accept_partial_heartbeat_for_test(&store, &target.admission);

    let stopped = advance_target(&create.candidate.desired, RuntimeTarget::Suspended);
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        stopped.clone(),
        "op_partial_stop",
        "partial-stop-mutation",
        Vec::new(),
        Sha256Digest::from_bytes([0xee; 32]),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &mutation).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    let current = store
        .authority_transaction(|transaction| {
            super::product_rows::load_desired_for_update(transaction, &stopped.cat_id)
        })
        .unwrap();
    assert_eq!(current, Some(stopped));
}

#[test]
fn desired_route_close_survives_an_aged_full_inventory_receipt() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(
        &workspace,
        "stale-route-close",
        1,
        "stale-route-close-create",
    );
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    refresh_mutation_target(&store, &identity, &policy, &release, 561);
    store
        .authority_transaction(|transaction| {
            super::runtime_spine::age_volume_mutation_admission_for_test(
                transaction,
                &identity.node_id,
            )
        })
        .unwrap();

    let mut closed = create.candidate.desired.clone();
    closed.desired_revision = revision(2);
    closed.endpoints.clear();
    closed.spec_digest = Sha256Digest::from_bytes([0; 32]);
    closed.spec_digest = spec_digest(&closed).unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        closed.clone(),
        "op_stale_route_close",
        "stale-route-close-mutation",
        Vec::new(),
        Sha256Digest::from_bytes([0xdd; 32]),
        Vec::new(),
    );
    assert!(matches!(
        commit_desired_mutation(&store, &mutation).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    assert!(store
        .locate_hostname_desired(&create.candidate.hostname_lookup.hostname)
        .unwrap()
        .is_none());
}

#[test]
fn desired_endpoint_successor_closes_new_changed_and_unchanged_route_epochs() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "route-successor", 1, "route-successor-create");
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let current = &create.candidate.desired;

    let target = refresh_mutation_target(&store, &identity, &policy, &release, 562);
    let mut stale_global_rebind = advance_target(current, RuntimeTarget::Running);
    stale_global_rebind.runtime.vcpus = 2;
    stale_global_rebind.spec_digest = Sha256Digest::from_bytes([0; 32]);
    stale_global_rebind.spec_digest = spec_digest(&stale_global_rebind).unwrap();
    let stale_global_rebind = desired_mutation_request(
        current,
        stale_global_rebind,
        "op_route_global_rebind_stale",
        "route-global-rebind-stale",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    let error = commit_desired_mutation(&store, &stale_global_rebind).unwrap_err();
    assert!(matches!(
        error,
        CoveredDesiredMutationError::Store(ref error)
            if error.message.contains("global Running rebind must advance every retained Endpoint route epoch exactly once")
    ));
    assert_desired_mutation_artifacts_absent(&store, &stale_global_rebind);

    let mut churned = advance_target(current, RuntimeTarget::Running);
    churned.endpoints[0].route_epoch = epoch(2);
    churned.spec_digest = Sha256Digest::from_bytes([0; 32]);
    churned.spec_digest = spec_digest(&churned).unwrap();
    let churned = desired_mutation_request(
        current,
        churned,
        "op_route_churned",
        "route-churned",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    let error = commit_desired_mutation(&store, &churned).unwrap_err();
    assert!(matches!(
        error,
        CoveredDesiredMutationError::Store(ref error)
            if error.message.contains("unchanged Endpoint binding must preserve route epoch")
    ));
    assert_desired_mutation_artifacts_absent(&store, &churned);

    for (route_epoch, operation_id, key) in [
        (1, "op_route_stale_binding", "route-stale-binding"),
        (3, "op_route_skipped_binding", "route-skipped-binding"),
    ] {
        let mut changed = advance_target(current, RuntimeTarget::Running);
        changed.endpoints[0].target_port = 8081;
        changed.endpoints[0].route_epoch = epoch(route_epoch);
        changed.spec_digest = Sha256Digest::from_bytes([0; 32]);
        changed.spec_digest = spec_digest(&changed).unwrap();
        let changed = desired_mutation_request(
            current,
            changed,
            operation_id,
            key,
            Vec::new(),
            guest_config_digest(&release).unwrap(),
            vec![default_endpoint_record(&create)],
        );
        let error = commit_desired_mutation(&store, &changed).unwrap_err();
        assert!(matches!(
            error,
            CoveredDesiredMutationError::Store(ref error)
                if error.message.contains("changed Endpoint binding must advance route epoch exactly once")
        ));
        assert_desired_mutation_artifacts_absent(&store, &changed);
    }

    let mut changed = advance_target(current, RuntimeTarget::Running);
    changed.endpoints[0].target_port = 8081;
    changed.endpoints[0].route_epoch = epoch(2);
    changed.spec_digest = Sha256Digest::from_bytes([0; 32]);
    changed.spec_digest = spec_digest(&changed).unwrap();
    let changed = desired_mutation_request(
        current,
        changed.clone(),
        "op_route_exact_binding",
        "route-exact-binding",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &changed).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    assert_eq!(
        store
            .authority_transaction(|transaction| {
                super::product_rows::load_desired_for_update(transaction, &current.cat_id)
            })
            .unwrap(),
        Some(changed.desired)
    );
}

#[test]
fn desired_new_endpoint_starts_at_epoch_one() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "route-new", 1, "route-new-create");
    let (_identity, _policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let current = &create.candidate.desired;
    let endpoint_id = id("ep_ffffffffffffffffffffffffffffffff");
    let hostname = Hostname::new("route-new-extra.cats.run").unwrap();
    let record = EndpointRecordCandidate {
        endpoint_id: endpoint_id.clone(),
        workspace_id: current.workspace_id.clone(),
        cat_id: current.cat_id.clone(),
        name: id("extra"),
    };

    let successor = |route_epoch| {
        let mut desired = advance_target(current, RuntimeTarget::Running);
        desired.endpoints.push(EndpointIntent {
            endpoint_id: endpoint_id.clone(),
            hostname: hostname.clone(),
            route_epoch: epoch(route_epoch),
            protocol: HttpProtocol::Http,
            target_port: 9090,
        });
        desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    };
    let invalid = desired_mutation_request(
        current,
        successor(2),
        "op_route_new_wrong_epoch",
        "route-new-wrong-epoch",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create), record.clone()],
    );
    let error = commit_desired_mutation(&store, &invalid).unwrap_err();
    assert!(matches!(
        error,
        CoveredDesiredMutationError::Store(ref error)
            if error.message.contains("new Endpoint route epoch must start at one")
    ));
    assert_desired_mutation_artifacts_absent(&store, &invalid);

    let desired = successor(1);
    let valid = desired_mutation_request(
        current,
        desired.clone(),
        "op_route_new",
        "route-new",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create), record.clone()],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &valid).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    assert_eq!(desired.endpoints[1].route_epoch, epoch(1));

    let mut removed = desired.clone();
    removed.desired_revision = revision(3);
    removed.endpoints.pop();
    removed.spec_digest = Sha256Digest::from_bytes([0; 32]);
    removed.spec_digest = spec_digest(&removed).unwrap();
    let remove = desired_mutation_request(
        &desired,
        removed.clone(),
        "op_route_remove",
        "route-remove",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &remove).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));

    let mut reused = removed.clone();
    reused.desired_revision = revision(4);
    reused.endpoints.push(desired.endpoints[1].clone());
    reused.spec_digest = Sha256Digest::from_bytes([0; 32]);
    reused.spec_digest = spec_digest(&reused).unwrap();
    let reused = desired_mutation_request(
        &removed,
        reused,
        "op_route_reuse",
        "route-reuse",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create), record],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &reused),
        Err(CoveredDesiredMutationError::CandidateCollision(
            CandidateCollision::EndpointIdOrName
        ))
    ));
    assert_desired_mutation_artifacts_absent(&store, &reused);
}

#[test]
fn desired_non_running_to_running_burns_the_old_route_epoch() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "route-reopen", 1, "route-reopen-create");
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let cold = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    let stop = desired_mutation_request(
        &create.candidate.desired,
        cold.clone(),
        "op_route_reopen_stop",
        "route-reopen-stop",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &stop).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    let target = refresh_mutation_target(&store, &identity, &policy, &release, 565);

    let mut stale_epoch = advance_target(&cold, RuntimeTarget::Running);
    stale_epoch.endpoints[0].route_epoch = cold.endpoints[0].route_epoch;
    stale_epoch.spec_digest = Sha256Digest::from_bytes([0; 32]);
    stale_epoch.spec_digest = spec_digest(&stale_epoch).unwrap();
    let stale_epoch = desired_mutation_request(
        &cold,
        stale_epoch,
        "op_route_reopen_stale",
        "route-reopen-stale",
        vec![target.clone()],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    let error = commit_desired_mutation(&store, &stale_epoch).unwrap_err();
    assert!(matches!(
        error,
        CoveredDesiredMutationError::Store(ref error)
            if error.message.contains("non-Running to Running must advance every retained Endpoint route epoch exactly once")
    ));
    assert_desired_mutation_artifacts_absent(&store, &stale_epoch);

    let reopened = advance_target(&cold, RuntimeTarget::Running);
    let valid = desired_mutation_request(
        &cold,
        reopened.clone(),
        "op_route_reopen",
        "route-reopen",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &valid).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    assert_eq!(reopened.endpoints[0].route_epoch, epoch(2));
}

#[test]
fn desired_delete_without_volume_intents_does_not_consume_full_admission() {
    let (url, store, _unused, workspace) = stores();
    let mut create = request(
        &workspace,
        "source-only-delete",
        1,
        "source-only-delete-create",
    );
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let mut current = create.candidate.desired.clone();
    current.volumes.clear();
    current.spec_digest = Sha256Digest::from_bytes([0; 32]);
    current.spec_digest = spec_digest(&current).unwrap();
    rewrite_current_desired_and_operation(&store, &current, None);
    let target = refresh_mutation_target(&store, &identity, &policy, &release, 571);
    let writer = Store::connect(&url, None).unwrap();
    super::runtime_spine_tests::replace_agent_session_for_test(
        &writer,
        &target.admission,
        &release,
        572,
    );

    let deleted = advance_target(&current, RuntimeTarget::Deleted);
    let mutation = desired_mutation_request(
        &current,
        deleted.clone(),
        "op_source_only_delete",
        "source-only-delete-mutation",
        Vec::new(),
        Sha256Digest::from_bytes([0xcc; 32]),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &mutation).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
}

#[test]
fn desired_source_only_rejects_a_retired_assigned_node_as_corruption_without_writes() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(
        &workspace,
        "source-only-retired",
        1,
        "source-only-retired-create",
    );
    let (identity, _policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    store.retire_node_identity(&identity.node_id).unwrap();

    let stopped = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        stopped,
        "op_source_only_retired",
        "source-only-retired",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    let error = commit_desired_mutation(&store, &mutation).unwrap_err();
    assert!(matches!(
        error,
        CoveredDesiredMutationError::Store(ref error)
            if error.code == ErrorCode::Internal
    ));
    assert_desired_mutation_artifacts_absent(&store, &mutation);
}

#[test]
fn desired_reactivation_still_requires_fresh_full_admission_after_session_replacement() {
    let (url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "stale-start", 1, "stale-start-create");
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let cold = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    let stop = desired_mutation_request(
        &create.candidate.desired,
        cold.clone(),
        "op_stale_start_stop",
        "stale-start-stop",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &stop).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
    let target = refresh_mutation_target(&store, &identity, &policy, &release, 581);
    let writer = Store::connect(&url, None).unwrap();
    super::runtime_spine_tests::replace_agent_session_for_test(
        &writer,
        &target.admission,
        &release,
        582,
    );

    for (runtime_target, operation_id, key) in [
        (
            RuntimeTarget::Suspended,
            "op_stale_suspended_rebuild",
            "stale-suspended-rebuild",
        ),
        (
            RuntimeTarget::Running,
            "op_stale_start",
            "stale-start-mutation",
        ),
    ] {
        let start = desired_mutation_request(
            &cold,
            advance_target(&cold, runtime_target),
            operation_id,
            key,
            vec![target.clone()],
            guest_config_digest(&release).unwrap(),
            vec![default_endpoint_record(&create)],
        );
        assert_stale_mutation_wrote_nothing(&store, &start);
    }
}

#[test]
fn desired_same_node_reactivation_rejects_a_cordoned_target_without_writes() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(
        &workspace,
        "cordoned-reactivation",
        1,
        "cordoned-reactivation-create",
    );
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let cold = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    let stop = desired_mutation_request(
        &create.candidate.desired,
        cold.clone(),
        "op_cordoned_reactivation_stop",
        "cordoned-reactivation-stop",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &stop).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));

    let mut cordoned = policy.clone();
    cordoned.policy_revision = epoch(2);
    cordoned.scheduling_state = RuntimeSchedulingState::Cordoned;
    store
        .authority_transaction(|transaction| {
            update_policy_for_test(transaction, &policy, &cordoned)
        })
        .unwrap();
    let target = refresh_mutation_target(&store, &identity, &cordoned, &release, 583);
    let mutation = desired_mutation_request(
        &cold,
        advance_target(&cold, RuntimeTarget::Running),
        "op_cordoned_reactivation",
        "cordoned-reactivation",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert_stale_mutation_wrote_nothing(&store, &mutation);
}

#[test]
fn desired_same_node_reactivation_rejects_an_active_host_fence_without_writes() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(
        &workspace,
        "fenced-reactivation",
        1,
        "fenced-reactivation-create",
    );
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let cold = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    let stop = desired_mutation_request(
        &create.candidate.desired,
        cold.clone(),
        "op_fenced_reactivation_stop",
        "fenced-reactivation-stop",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert!(matches!(
        commit_desired_mutation(&store, &stop).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));

    let mut target = refresh_mutation_target(&store, &identity, &policy, &release, 584);
    let event = active_host_fence_event(&target, 584);
    store
        .authority_transaction(|transaction| {
            transaction.query_one(
                "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE",
                &[&identity.node_id.as_str()],
            )?;
            insert_event(transaction, &event)
        })
        .unwrap();
    target.active_host_fence_event = Some(event);
    let mutation = desired_mutation_request(
        &cold,
        advance_target(&cold, RuntimeTarget::Running),
        "op_fenced_reactivation",
        "fenced-reactivation",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    assert_stale_mutation_wrote_nothing(&store, &mutation);
}

#[test]
fn desired_mutation_pre_commit_cancellation_writes_nothing() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "desired-cancel", 1, "desired-cancel-create");
    let (_identity, _policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        advance_target(&create.candidate.desired, RuntimeTarget::Cold),
        "op_desired_cancelled",
        "desired-cancelled",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    let (cancellation, state) = CoveredCommitCancellation::new(
        "Desired mutation cancellation test",
        Instant::now() + Duration::from_secs(30),
    );
    assert!(cancellation.cancel_before_commit());
    assert!(matches!(
        store.commit_desired_mutation_covered(&mutation, &state),
        Err(CoveredDesiredMutationError::Store(ref error))
            if error.code == ErrorCode::Unavailable
    ));
    assert_desired_mutation_artifacts_absent(&store, &mutation);
}

#[test]
fn desired_mutation_lock_wait_is_bounded_before_commit_and_writes_nothing() {
    let (_url, store, holder, workspace) = stores();
    let mut create = request(
        &workspace,
        "desired-lock-wait",
        1,
        "desired-lock-wait-create",
    );
    let (identity, _policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        advance_target(&create.candidate.desired, RuntimeTarget::Cold),
        "op_desired_lock_wait",
        "desired-lock-wait",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    let locked = Arc::new(Barrier::new(2));
    let release_lock = Arc::new(Barrier::new(2));
    let holder_locked = Arc::clone(&locked);
    let holder_release = Arc::clone(&release_lock);
    let node_id = identity.node_id.clone();
    let holder_thread = std::thread::spawn(move || {
        holder
            .authority_transaction(|transaction| {
                transaction.query_one(
                    "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE",
                    &[&node_id.as_str()],
                )?;
                holder_locked.wait();
                holder_release.wait();
                Ok(())
            })
            .unwrap();
    });
    locked.wait();

    let (_cancellation, state) = CoveredCommitCancellation::new(
        "Desired mutation lock-wait test",
        Instant::now() + Duration::from_millis(300),
    );
    assert!(matches!(
        store.commit_desired_mutation_covered(&mutation, &state),
        Err(CoveredDesiredMutationError::Store(ref error))
            if error.code == ErrorCode::Unavailable
    ));
    assert!(!state.commit_was_sent());
    release_lock.wait();
    holder_thread.join().unwrap();
    assert_desired_mutation_artifacts_absent(&store, &mutation);
}

#[test]
fn desired_placement_cancellation_stops_before_a_later_a20_relation_wait() {
    const APPLICATION_NAME: &str = "cats-a1-a20-cancel";
    let (url, setup, _unused, workspace) = stores();
    let mut create = request(&workspace, "a20-cancel", 1, "a20-cancel-create");
    let (identity, policy, release) = prepare_mutation_node(&setup, &mut create, 1);
    setup
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let target = refresh_mutation_target(&setup, &identity, &policy, &release, 590);
    let mut resized = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    resized.runtime.vcpus = 2;
    resized.spec_digest = Sha256Digest::from_bytes([0; 32]);
    resized.spec_digest = spec_digest(&resized).unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        resized,
        "op_a20_cancel",
        "a20-cancel",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );

    // Keep a later A20 read blocked independently from the session read. Once
    // cancellation is requested and the session relation is released, the
    // propagated CoveredCommitState checkpoint must abort before reaching this
    // second wait.
    // Open every connection before either relation is locked: Store startup
    // itself verifies the complete schema and must not become part of the
    // cancellation choreography below.
    let inventory_holder = Store::connect(&url, None).unwrap();
    let session_holder = Store::connect(&url, None).unwrap();
    let worker = Store::connect(&with_application_name(&url, APPLICATION_NAME), None).unwrap();
    let observer = Store::connect(&url, None).unwrap();
    let (inventory_locked_tx, inventory_locked_rx) = mpsc::channel();
    let (inventory_release_tx, inventory_release_rx) = mpsc::channel();
    let inventory_thread = std::thread::spawn(move || {
        inventory_holder
            .authority_transaction(move |transaction| {
                transaction.batch_execute(
                    "LOCK TABLE runtime_admission_inventory_states IN ACCESS EXCLUSIVE MODE",
                )?;
                inventory_locked_tx.send(()).unwrap();
                inventory_release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    inventory_locked_rx.recv().unwrap();

    let (session_locked_tx, session_locked_rx) = mpsc::channel();
    let (session_release_tx, session_release_rx) = mpsc::channel();
    let session_thread = std::thread::spawn(move || {
        session_holder
            .authority_transaction(move |transaction| {
                transaction
                    .batch_execute("LOCK TABLE current_agent_sessions IN ACCESS EXCLUSIVE MODE")?;
                session_locked_tx.send(()).unwrap();
                session_release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    session_locked_rx.recv().unwrap();

    let (cancellation, state) = CoveredCommitCancellation::new(
        "Desired placement cancellation test",
        Instant::now() + Duration::from_secs(30),
    );
    let worker_state = state.clone();
    let worker_mutation = mutation.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let worker_thread = std::thread::spawn(move || {
        result_tx
            .send(worker.commit_desired_mutation_covered(&worker_mutation, &worker_state))
            .unwrap();
    });
    wait_for_advisory_lock_wait(&observer, APPLICATION_NAME);
    assert!(cancellation.cancel_before_commit());
    session_release_tx.send(()).unwrap();

    let prompt = result_rx.recv_timeout(Duration::from_secs(1));
    inventory_release_tx.send(()).unwrap();
    session_thread.join().unwrap();
    inventory_thread.join().unwrap();
    let outcome = match prompt {
        Ok(outcome) => outcome,
        Err(_) => {
            let _ = result_rx.recv_timeout(Duration::from_secs(5));
            worker_thread.join().unwrap();
            panic!("cancelled placement mutation reached the later A20 inventory wait");
        }
    };
    worker_thread.join().unwrap();
    assert!(matches!(
        outcome,
        Err(CoveredDesiredMutationError::Store(ref error))
            if error.code == ErrorCode::Unavailable
    ));
    assert!(!state.commit_was_sent());
    assert_desired_mutation_artifacts_absent(&setup, &mutation);
}

#[test]
fn desired_mutation_commit_response_loss_resolves_and_replays_exact_result() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(
        &workspace,
        "desired-response-loss",
        1,
        "desired-response-loss-create",
    );
    let (_identity, _policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        advance_target(&create.candidate.desired, RuntimeTarget::Cold),
        "op_desired_response_loss",
        "desired-response-loss",
        Vec::new(),
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );
    let (_cancellation, state) = CoveredCommitCancellation::new(
        "Desired mutation response-loss test",
        Instant::now() + Duration::from_secs(30),
    );
    store.inject_committed_response_loss_once();
    assert!(matches!(
        store.commit_desired_mutation_covered(&mutation, &state),
        Err(CoveredDesiredMutationError::Store(ref error))
            if error.code == ErrorCode::Unavailable
    ));
    assert!(state.commit_was_sent());
    let resolved = store
        .covered_api_result_after_commit(&mutation.idempotency)
        .unwrap()
        .expect("committed mutation result must resolve behind its API-key lock");
    let DesiredMutationCommit::Replayed(replayed) =
        commit_desired_mutation(&store, &mutation).unwrap()
    else {
        panic!("same API key must replay after an ambiguous commit response");
    };
    assert_eq!(replayed, resolved);
}

#[test]
fn desired_mutation_rejects_assigned_set_change_after_planning_without_any_commit_artifact() {
    let (url, planner, _unused, workspace) = stores();
    let mut create = request(&workspace, "assigned-drift", 1, "assigned-drift-create");
    let (identity, policy, release) = prepare_mutation_node(&planner, &mut create, 1);
    planner
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let target = refresh_mutation_target(&planner, &identity, &policy, &release, 601);
    let mut resized = advance_target(&create.candidate.desired, RuntimeTarget::Cold);
    resized.runtime.memory_bytes += 4096;
    resized.spec_digest = Sha256Digest::from_bytes([0; 32]);
    resized.spec_digest = spec_digest(&resized).unwrap();
    let mutation = desired_mutation_request(
        &create.candidate.desired,
        resized,
        "op_assigned_drift",
        "assigned-drift-mutation",
        vec![target],
        guest_config_digest(&release).unwrap(),
        vec![default_endpoint_record(&create)],
    );

    let writer = Store::connect(&url, None).unwrap();
    let mut concurrent = request(
        &workspace,
        "assigned-drift-other",
        2,
        "assigned-drift-other-create",
    );
    concurrent.candidate.desired.placement.node_id = identity.node_id.clone();
    concurrent.candidate.desired.runtime.network_config = allocate_network_for_test(
        &policy,
        &concurrent
            .candidate
            .desired
            .runtime
            .network_config
            .network_id,
    );
    refresh_candidate_contract(&mut concurrent);
    writer
        .create_cat_covered_without_admission_for_product_test(&concurrent)
        .unwrap();

    assert_stale_mutation_wrote_nothing(&planner, &mutation);
}

fn assert_volume_guard_rejected_without_writes(
    store: &Store,
    request: &CoveredDesiredMutationRequest,
    label: &str,
) {
    let error = commit_desired_mutation(store, request).unwrap_err();
    let CoveredDesiredMutationError::Store(error) = error else {
        panic!("{label}: volume mutation did not reach the typed Store guard");
    };
    assert_eq!(error.code, ErrorCode::Internal, "{label}");
    assert_eq!(
        error.message,
        "covered Desired mutation candidate is inconsistent: volume intent changes require covered VolumeRecord and Disk authority",
        "{label}"
    );
    store
        .authority_transaction(|transaction| {
            let current = super::product_rows::load_desired_for_update(
                transaction,
                &request.expected_current.cat_id,
            )?
            .unwrap();
            assert_eq!(current, request.expected_current, "{label}");
            assert!(super::product_rows::load_operation_for_update(
                transaction,
                &request.operation_id,
            )?
            .is_none(), "{label}");
            assert!(super::product_rows::load_api_result_for_update(
                transaction,
                &request.idempotency,
            )?
            .is_none(), "{label}");
            Ok(())
        })
        .unwrap();
}

fn current_with_persistent_volume(
    store: &Store,
    create: &CoveredCatCreateRequest,
) -> DesiredRuntimeSpec {
    let volume = blank_volume("volume-guard-persistent");
    let initialization_token = random_id(0x7100);
    let filesystem_uuid = random_id(0x7101);
    let disk = persistent_disk(
        &create.candidate.workspace_id,
        "disk-guard-persistent",
        "guard-persistent",
        &volume,
        PersistentDiskInitialization::Uninitialized {
            initialization_token: initialization_token.clone(),
            filesystem_uuid: filesystem_uuid.clone(),
            expected_blank_head: volume.head.clone(),
        },
    );
    store
        .authority_transaction(|transaction| {
            insert_volume(transaction, &volume)?;
            insert_disk(transaction, &disk)
        })
        .unwrap();

    let mut desired = create.candidate.desired.clone();
    desired.volumes.push(VolumeIntent {
        volume_intent_id: id("volume-intent_z"),
        disk_id: disk.disk_id,
        volume_id: volume.volume_id,
        attachment_id: id("attachment-guard-persistent"),
        size_bytes: volume.size_bytes,
        disk_kind: DiskKind::Persistent,
        access: VolumeAccess::ReadWriteOnce,
        durability: Durability::Strict,
        guest_device: GuestDeviceIdentity {
            serial: id("cats-persistent"),
            slot: 1,
        },
        acquire: VolumeAcquire::Normal {
            transition_id: random_id(0x7102),
            expected_unowned_epoch: fence_epoch(0),
        },
        disposition: VolumeDisposition::Retain,
        mount: Some(Ext4MountIntent {
            filesystem_uuid,
            mount_path: cats_api::runtime_reconciliation::HostPath::new("/data").unwrap(),
            initialization: FilesystemInitialization::Initialize {
                initialization_token,
                expected_blank_head: volume.head,
            },
        }),
    });
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(&desired).unwrap();
    encode_desired_runtime_spec(&desired).expect("Persistent current Desired is codec-valid");
    rewrite_current_desired_and_operation(store, &desired, None);
    desired
}

#[test]
fn desired_mutation_rejects_every_uncovered_volume_intent_change_without_any_commit_artifact() {
    let (_url, store, _unused, workspace) = stores();
    let mut create = request(&workspace, "volume-closed", 1, "volume-closed-create");
    let (identity, policy, release) = prepare_mutation_node(&store, &mut create, 1);
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    let current = current_with_persistent_volume(&store, &create);
    let target = refresh_mutation_target(&store, &identity, &policy, &release, 701);
    let active_digest = guest_config_digest(&release).unwrap();

    let mut candidates = Vec::new();
    let mut removed = current.clone();
    removed.desired_revision = revision(2);
    removed.volumes.pop();
    candidates.push(("remove-persistent", removed));

    let mut added = current.clone();
    added.desired_revision = revision(2);
    let mut extra = added.volumes[1].clone();
    extra.volume_intent_id = id("volume-intent_zz");
    extra.disk_id = id("disk-extra");
    extra.volume_id = id("volume-extra");
    extra.attachment_id = id("attachment-extra");
    extra.disk_kind = DiskKind::Persistent;
    extra.guest_device.serial = id("cats-extra");
    extra.guest_device.slot = 2;
    extra.acquire = VolumeAcquire::Normal {
        transition_id: random_id(0x7000),
        expected_unowned_epoch: fence_epoch(0),
    };
    extra.mount = Some(Ext4MountIntent {
        filesystem_uuid: random_id(0x7001),
        mount_path: cats_api::runtime_reconciliation::HostPath::new("/extra").unwrap(),
        initialization: FilesystemInitialization::Existing,
    });
    added.volumes.push(extra);
    candidates.push(("add-persistent", added));

    let mut attachment = current.clone();
    attachment.desired_revision = revision(2);
    attachment.volumes[1].attachment_id = id("attachment-replaced");
    candidates.push(("attachment", attachment));

    let mut disposition = current.clone();
    disposition.desired_revision = revision(2);
    disposition.target = RuntimeTarget::Deleted;
    disposition.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
        delete_id: id("delete-volume-closed"),
    };
    disposition.volumes[1].disposition = VolumeDisposition::DetachRetained;
    candidates.push(("disposition", disposition));

    let mut size = current.clone();
    size.desired_revision = revision(2);
    size.volumes[1].size_bytes += 4096;
    candidates.push(("size", size));

    let mut authority = current.clone();
    authority.desired_revision = revision(2);
    authority.volumes[1].acquire = VolumeAcquire::Normal {
        transition_id: random_id(0xfeed),
        expected_unowned_epoch: fence_epoch(1),
    };
    candidates.push(("authority", authority));

    for (index, (label, mut desired)) in candidates.into_iter().enumerate() {
        desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
        desired.spec_digest = spec_digest(&desired)
            .unwrap_or_else(|error| panic!("{label}: successor digest rejected: {error}"));
        encode_desired_runtime_spec(&desired)
            .unwrap_or_else(|error| panic!("{label}: successor is not codec-valid: {error}"));
        let request = desired_mutation_request(
            &current,
            desired,
            &format!("op_volume_closed_{label}"),
            &format!("volume-closed-{index}"),
            vec![target.clone()],
            active_digest.clone(),
            vec![default_endpoint_record(&create)],
        );
        assert_volume_guard_rejected_without_writes(&store, &request, label);
    }
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
    let release = mutation_release();
    let active_digest = guest_config_digest(&release).unwrap();
    assert_eq!(desired.runtime.guest_config_digest, active_digest);
    let identity = node_identity(&desired.placement.node_id, 201);
    let policy = mutation_policy(&identity.node_id, &active_digest, 1);
    store.provision_node_identity(&identity).unwrap();
    insert_policy_on_store_for_test(store, &policy).unwrap();
    let endpoints = replacement
        .map(|(endpoint_id, name, _hostname)| {
            vec![EndpointRecordCandidate {
                endpoint_id,
                workspace_id: desired.workspace_id.clone(),
                cat_id: desired.cat_id.clone(),
                name,
            }]
        })
        .unwrap_or_default();
    let mutation = desired_mutation_request(
        &original.candidate.desired,
        desired.clone(),
        operation_id.as_str(),
        &format!("advance-endpoints-{operation_id}"),
        Vec::new(),
        active_digest,
        endpoints,
    );
    assert!(matches!(
        commit_desired_mutation(store, &mutation).unwrap(),
        DesiredMutationCommit::Changed(_)
    ));
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
    assert_eq!(counts(&store), [1, 1, 1, 1, 1, 0, 2, 3]);
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
    assert_eq!(counts(&store), [1, 1, 1, 1, 2, 1, 2, 3]);
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
fn runtime_operation_exact_get_is_workspace_qualified_and_projection_closed() {
    let (_url, store, _second, workspace) = stores();
    let create = request(&workspace, "operation-read", 1, "operation-read");
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();

    let RuntimeOperationRead::Found(operation) = store
        .get_runtime_operation(&workspace, &create.candidate.operation_id)
        .unwrap()
    else {
        panic!("created runtime Operation was not readable");
    };
    assert_eq!(operation.operation_id, create.candidate.operation_id);
    assert_eq!(operation.workspace_id, workspace);
    assert_eq!(
        store
            .get_runtime_operation(&id("ws_other"), &operation.operation_id)
            .unwrap(),
        RuntimeOperationRead::NotFound
    );

    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_operations SET updated_at=updated_at+1
                  WHERE operation_id=$1",
                &[&operation.operation_id.as_str()],
            )
        })
        .unwrap();
    assert_eq!(
        store
            .get_runtime_operation(&workspace, &operation.operation_id)
            .unwrap(),
        RuntimeOperationRead::Corrupt
    );
}

#[test]
fn runtime_operation_exact_get_reaches_all_scalar_and_record_key_combinations() {
    for drift in [
        "record keys",
        "scalar operation",
        "scalar workspace",
        "both scalar keys",
    ] {
        let (_url, store, _second, workspace) = stores();
        let create = request(&workspace, "operation-key-drift", 1, "operation-key-drift");
        store
            .create_cat_covered_without_admission_for_product_test(&create)
            .unwrap();
        let operation_id = create.candidate.operation_id.clone();
        store
            .with(|client| {
                match drift {
                    "record keys" => {
                        client.execute(
                            "UPDATE runtime_operations
                                SET record=jsonb_set(
                                    jsonb_set(
                                        record, '{workspace_id}',
                                        to_jsonb('ws_record_drift'::TEXT), FALSE
                                    ),
                                    '{operation_id}',
                                    to_jsonb('op_record_drift'::TEXT), FALSE
                                )
                              WHERE operation_id=$1",
                            &[&operation_id.as_str()],
                        )?;
                    }
                    "scalar operation" => {
                        client.execute(
                            "UPDATE runtime_operations
                                SET operation_id='op_scalar_drift'
                              WHERE operation_id=$1",
                            &[&operation_id.as_str()],
                        )?;
                    }
                    "scalar workspace" | "both scalar keys" => {
                        client
                            .batch_execute("ALTER TABLE runtime_operations DISABLE TRIGGER ALL")?;
                        let scalar_operation_id = if drift == "both scalar keys" {
                            "op_scalar_drift"
                        } else {
                            operation_id.as_str()
                        };
                        client.execute(
                            "UPDATE runtime_operations
                                SET workspace_id='ws_scalar_drift', operation_id=$2
                              WHERE operation_id=$1",
                            &[&operation_id.as_str(), &scalar_operation_id],
                        )?;
                        client
                            .batch_execute("ALTER TABLE runtime_operations ENABLE TRIGGER ALL")?;
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })
            .unwrap();

        assert_eq!(
            store
                .get_runtime_operation(&workspace, &operation_id)
                .unwrap(),
            RuntimeOperationRead::Corrupt,
            "{drift} drift escaped the workspace-qualified reachability set"
        );
    }
}

#[test]
fn runtime_cat_list_reaches_all_scalar_and_record_workspace_id_combinations() {
    for drift in [
        "scalar workspace and scalar ID",
        "scalar workspace and record ID",
        "record workspace and scalar ID",
        "record workspace and record ID",
    ] {
        let (_url, store, _second, workspace) = stores();
        let foreign_workspace = bootstrap_workspace(&store, "f2b");
        let create = request(&workspace, "cat-list-key-drift", 1, "cat-list-key-drift");
        store
            .create_cat_covered_without_admission_for_product_test(&create)
            .unwrap();
        let cat_id = create.candidate.cat_id.clone();
        let (listed_workspace, after) = match drift {
            "scalar workspace and scalar ID" => {
                store
                    .with(|client| {
                        client.execute(
                            "UPDATE cat_records
                                SET record=jsonb_set(
                                    record, '{name}', to_jsonb('corrupt_name'::TEXT), FALSE
                                )
                              WHERE cat_id=$1",
                            &[&cat_id.as_str()],
                        )
                    })
                    .unwrap();
                (workspace.clone(), None)
            }
            "scalar workspace and record ID" => {
                store
                    .with(|client| {
                        client.execute(
                            "UPDATE cat_records
                                SET record=jsonb_set(
                                    record, '{cat_id}', to_jsonb('cat_zz'::TEXT), FALSE
                                )
                              WHERE cat_id=$1",
                            &[&cat_id.as_str()],
                        )
                    })
                    .unwrap();
                (workspace.clone(), Some(id("cat_zy")))
            }
            "record workspace and scalar ID" => {
                store
                    .with(|client| {
                        client.execute(
                            "UPDATE cat_records
                                SET record=jsonb_set(
                                    record, '{workspace_id}', to_jsonb($2::TEXT), FALSE
                                )
                              WHERE cat_id=$1",
                            &[&cat_id.as_str(), &foreign_workspace.as_str()],
                        )
                    })
                    .unwrap();
                (foreign_workspace.clone(), None)
            }
            "record workspace and record ID" => {
                store
                    .with(|client| {
                        client.execute(
                            "UPDATE cat_records
                                SET record=jsonb_set(
                                    jsonb_set(
                                        record, '{workspace_id}', to_jsonb($2::TEXT), FALSE
                                    ),
                                    '{cat_id}', to_jsonb('cat_zz'::TEXT), FALSE
                                )
                              WHERE cat_id=$1",
                            &[&cat_id.as_str(), &foreign_workspace.as_str()],
                        )
                    })
                    .unwrap();
                (foreign_workspace, Some(id("cat_zy")))
            }
            _ => unreachable!(),
        };

        assert_eq!(
            store
                .list_runtime_cats(&listed_workspace, after.as_ref(), 1)
                .unwrap(),
            ProductPageRead::Corrupt,
            "{drift} candidate escaped the bounded list reachability set"
        );
    }
}

fn sweep_completed_root_for_product_read(
    store: &Store,
    create: &CoveredCatCreateRequest,
) -> VolumeRecord {
    let mut desired = create.candidate.desired.clone();
    let root = desired.volumes.first().unwrap().clone();
    let delete_id = id("delete_product_read");
    desired.target = RuntimeTarget::Deleted;
    desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
        delete_id: delete_id.clone(),
    };
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(&desired).unwrap();

    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &root.acquire
    else {
        panic!("initial Cat Root must use normal acquire")
    };
    let (owned, _) = normal_acquire(
        &create.candidate.volume,
        &NormalAcquireRequest {
            volume_id: root.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: root.attachment_id.clone(),
            expected_unowned_epoch: *expected_unowned_epoch,
            desired_revision: desired.desired_revision,
            placement_epoch: desired.placement.placement_epoch,
            lease_duration_ms: 30_000,
        },
        unix_millis(10_000),
    )
    .unwrap();
    let original = AuthorizationRecord {
        authorization: VolumeAuthorization::DisposableRootDelete(
            DisposableRootDeleteAuthorization {
                authorization_id: id("authorization_product_read"),
                authorized_node_id: desired.placement.node_id.clone(),
                delete_id,
                disk_id: root.disk_id.clone(),
                volume_id: root.volume_id.clone(),
                cat_id: desired.cat_id.clone(),
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                expected_attachment_id: root.attachment_id.clone(),
                expected_epoch: owned.lease_epoch,
                expected_head: owned.head.clone(),
                isolation_basis: DisposableDeleteIsolationBasis::RuntimeStopped {
                    node_id: desired.placement.node_id.clone(),
                    agent_session_epoch: epoch(1),
                    runtime_incarnation: random_id(91),
                    observation_id: random_id(92),
                },
                not_after: unix_millis(50_000),
            },
        ),
        state: AuthorizationState::Unconsumed,
    };
    let (deleting, consumed, _) = consume_disposable_root_delete(
        &owned,
        None,
        &original,
        &id("authorization_product_read"),
        unix_millis(20_000),
    )
    .unwrap();
    let completion =
        complete_disposable_root_delete(&deleting, &consumed, unix_millis(40_000)).unwrap();
    let desired_json = String::from_utf8(encode_desired_runtime_spec(&desired).unwrap()).unwrap();

    store
        .authority_transaction(|transaction| {
            assert_eq!(
                transaction.execute(
                    "UPDATE desired_runtime_specs
                        SET record=$2::TEXT::jsonb, spec_digest=$3, target='deleted'
                      WHERE cat_id=$1",
                    &[
                        &desired.cat_id.as_str(),
                        &desired_json,
                        &desired.spec_digest.as_str(),
                    ],
                )?,
                1
            );
            insert_authorization(transaction, &original)?;
            update_authorization(transaction, &original, &consumed)?;
            insert_delete_completion(transaction, &completion)?;
            assert_eq!(
                transaction.execute(
                    "DELETE FROM disk_records WHERE disk_id=$1",
                    &[&root.disk_id.as_str()],
                )?,
                1
            );
            assert_eq!(
                transaction.execute(
                    "DELETE FROM volume_records WHERE volume_id=$1",
                    &[&root.volume_id.as_str()],
                )?,
                1
            );
            Ok(())
        })
        .unwrap();
    deleting
}

fn sweep_completed_normal_root_for_product_read(
    store: &Store,
    create: &CoveredCatCreateRequest,
) -> DeleteCompletionReceipt {
    let mut desired = create.candidate.desired.clone();
    let root = desired.volumes.first().unwrap().clone();
    let delete_id = id("delete_normal_product_read");
    desired.target = RuntimeTarget::Deleted;
    desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
        delete_id: delete_id.clone(),
    };
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(&desired).unwrap();

    let (deleting, _) = begin_delete(
        &create.candidate.volume,
        &BeginDeleteRequest {
            delete_id,
            disk_id: root.disk_id.clone(),
            volume_id: root.volume_id.clone(),
            expected_unowned_epoch: create.candidate.volume.lease_epoch,
            expected_head: create.candidate.volume.head.clone(),
        },
    )
    .unwrap();
    let completion = complete_normal_delete(&deleting, unix_millis(40_000)).unwrap();
    let desired_json = String::from_utf8(encode_desired_runtime_spec(&desired).unwrap()).unwrap();

    store
        .authority_transaction(|transaction| {
            assert_eq!(
                transaction.execute(
                    "UPDATE desired_runtime_specs
                        SET record=$2::TEXT::jsonb, spec_digest=$3, target='deleted'
                      WHERE cat_id=$1",
                    &[
                        &desired.cat_id.as_str(),
                        &desired_json,
                        &desired.spec_digest.as_str(),
                    ],
                )?,
                1
            );
            insert_delete_completion(transaction, &completion)?;
            assert_eq!(
                transaction.execute(
                    "DELETE FROM disk_records WHERE disk_id=$1",
                    &[&root.disk_id.as_str()],
                )?,
                1
            );
            assert_eq!(
                transaction.execute(
                    "DELETE FROM volume_records WHERE volume_id=$1",
                    &[&root.volume_id.as_str()],
                )?,
                1
            );
            Ok(())
        })
        .unwrap();
    completion
}

#[test]
fn runtime_cat_read_accepts_completed_disposable_root_sweep() {
    let (_url, store, _second, workspace) = stores();
    let create = request(&workspace, "deleted-read", 1, "deleted-read");
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    sweep_completed_root_for_product_read(&store, &create);

    let ProductRead::Found(cat) = store
        .get_runtime_cat(&workspace, &create.candidate.cat_id)
        .unwrap()
    else {
        panic!("closed disposable Root completion graph was rejected")
    };
    assert_eq!(cat.desired.target, RuntimeTarget::Deleted);
    assert_eq!(cat.desired.root_disk_id, create.candidate.root_disk.disk_id);
}

#[test]
fn runtime_cat_read_accepts_exact_completed_normal_root_sweep() {
    let (_url, store, _second, workspace) = stores();
    let create = request(&workspace, "normal-deleted-read", 1, "normal-deleted-read");
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    sweep_completed_normal_root_for_product_read(&store, &create);

    let ProductRead::Found(cat) = store
        .get_runtime_cat(&workspace, &create.candidate.cat_id)
        .unwrap()
    else {
        panic!("closed normal Root completion was rejected")
    };
    assert_eq!(cat.desired.target, RuntimeTarget::Deleted);
    assert_eq!(cat.desired.root_disk_id, create.candidate.root_disk.disk_id);
}

#[test]
fn runtime_cat_read_rejects_drifted_or_duplicate_normal_root_completion() {
    for (index, corruption) in [
        "request-tuple",
        "scalar-projection",
        "conflicting-completion",
        "hidden-record-duplicate",
    ]
    .into_iter()
    .enumerate()
    {
        let (_url, store, _second, workspace) = stores();
        let fixture_name = format!("normal-completion-corrupt-{index}");
        let create = request(&workspace, &fixture_name, 1, &fixture_name);
        store
            .create_cat_covered_without_admission_for_product_test(&create)
            .unwrap();
        let completion = sweep_completed_normal_root_for_product_read(&store, &create);
        let DeleteCompletionReceipt::Normal { request, .. } = &completion else {
            unreachable!()
        };

        if corruption == "conflicting-completion" {
            let mut conflicting = completion.clone();
            let DeleteCompletionReceipt::Normal { request, .. } = &mut conflicting else {
                unreachable!()
            };
            request.delete_id = id("delete_conflicting_normal_completion");
            request.volume_id = id("volume_conflicting_normal_completion");
            store
                .authority_transaction(|transaction| {
                    insert_delete_completion(transaction, &conflicting)
                })
                .unwrap();
        } else {
            store
                .with(|client| {
                    match corruption {
                        "request-tuple" => client.execute(
                            "UPDATE delete_completion_receipts
                            SET disk_id='disk_wrong_normal',
                                record=jsonb_set(
                                    record, '{request,disk_id}',
                                    to_jsonb('disk_wrong_normal'::TEXT), FALSE
                                )
                          WHERE delete_id=$1",
                            &[&request.delete_id.as_str()],
                        )?,
                        "scalar-projection" => client.execute(
                            "UPDATE delete_completion_receipts
                            SET disk_id='disk_wrong_projection'
                          WHERE delete_id=$1",
                            &[&request.delete_id.as_str()],
                        )?,
                        "hidden-record-duplicate" => client.execute(
                            "INSERT INTO delete_completion_receipts (
                            delete_id, record, kind, disk_id, volume_id,
                            authorization_id, prior_attachment_id,
                            deleting_epoch, head_generation, head_root_hash,
                            head_root_object_id, completed_at
                         ) SELECT
                            'delete_hidden_normal_duplicate', record, kind,
                            'disk_hidden_normal_duplicate',
                            'volume_hidden_normal_duplicate', authorization_id,
                            prior_attachment_id, deleting_epoch, head_generation,
                            head_root_hash, head_root_object_id, completed_at
                           FROM delete_completion_receipts WHERE delete_id=$1",
                            &[&request.delete_id.as_str()],
                        )?,
                        _ => unreachable!(),
                    };
                    Ok(())
                })
                .unwrap();
        }

        assert_eq!(
            store
                .get_runtime_cat(&workspace, &create.candidate.cat_id)
                .unwrap(),
            ProductRead::Corrupt,
            "{corruption} completion escaped exact Normal validation"
        );
    }
}

#[test]
fn runtime_cat_read_rejects_all_residual_disposable_root_volume_reachability() {
    for (index, reachability) in [
        "scalar-volume-id",
        "record-volume-id",
        "scalar-delete-id",
        "record-delete-id",
        "duplicate-record-volume-id",
    ]
    .into_iter()
    .enumerate()
    {
        let (_url, store, _second, workspace) = stores();
        let fixture_name = format!("residual-volume-{index}");
        let create = request(&workspace, &fixture_name, 1, &fixture_name);
        store
            .create_cat_covered_without_admission_for_product_test(&create)
            .unwrap();
        let residual = sweep_completed_root_for_product_read(&store, &create);
        let replacement_volume_id = format!("volume_residual_{index}");
        let replacement_delete_id = format!("delete_residual_{index}");

        store
            .authority_transaction(|transaction| {
                insert_volume(transaction, &residual)?;
                let changed = match reachability {
                    "scalar-volume-id" => transaction.execute(
                        "UPDATE volume_records
                            SET record=jsonb_set(
                                record, '{volume_id}', to_jsonb($2::TEXT), FALSE
                            )
                          WHERE volume_id=$1",
                        &[&residual.volume_id.as_str(), &replacement_volume_id],
                    )?,
                    "record-volume-id" => transaction.execute(
                        "UPDATE volume_records SET volume_id=$2 WHERE volume_id=$1",
                        &[&residual.volume_id.as_str(), &replacement_volume_id],
                    )?,
                    "scalar-delete-id" => transaction.execute(
                        "UPDATE volume_records
                            SET volume_id=$2,
                                record=jsonb_set(
                                    jsonb_set(
                                        record, '{volume_id}', to_jsonb($2::TEXT), FALSE
                                    ),
                                    '{admin_state,delete_id}', to_jsonb($3::TEXT), FALSE
                                )
                          WHERE volume_id=$1",
                        &[
                            &residual.volume_id.as_str(),
                            &replacement_volume_id,
                            &replacement_delete_id,
                        ],
                    )?,
                    "record-delete-id" => transaction.execute(
                        "UPDATE volume_records
                            SET volume_id=$2, delete_id=$3,
                                record=jsonb_set(
                                    record, '{volume_id}', to_jsonb($2::TEXT), FALSE
                                )
                          WHERE volume_id=$1",
                        &[
                            &residual.volume_id.as_str(),
                            &replacement_volume_id,
                            &replacement_delete_id,
                        ],
                    )?,
                    "duplicate-record-volume-id" => {
                        let changed = transaction.execute(
                            "UPDATE volume_records SET volume_id=$2 WHERE volume_id=$1",
                            &[&residual.volume_id.as_str(), &replacement_volume_id],
                        )?;
                        assert_eq!(changed, 1);
                        insert_volume(transaction, &residual)?;
                        transaction.execute(
                            "UPDATE volume_records SET volume_id=$2 WHERE volume_id=$1",
                            &[&residual.volume_id.as_str(), &replacement_delete_id],
                        )?
                    }
                    _ => unreachable!(),
                };
                assert_eq!(changed, 1);
                Ok(())
            })
            .unwrap();

        assert_eq!(
            store
                .get_runtime_cat(&workspace, &create.candidate.cat_id)
                .unwrap(),
            ProductRead::Corrupt,
            "{reachability} residual escaped the completed Root absence proof"
        );
    }
}

#[test]
fn runtime_cat_read_rejects_incomplete_duplicate_or_drifted_delete_graphs() {
    for (index, (case, mutation)) in [
        ("missing-authorization", "DELETE FROM volume_authorizations"),
        (
            "authorization-projection-drift",
            "UPDATE volume_authorizations
                SET desired_revision=desired_revision+1",
        ),
        (
            "completion-projection-drift",
            "UPDATE delete_completion_receipts
                SET deleting_epoch=deleting_epoch+1",
        ),
        (
            "duplicate-authorization-identity",
            "INSERT INTO volume_authorizations (
                authorization_id, record, kind, authorized_node_id,
                host_fence_event_id, volume_id, state, desired_revision,
                placement_epoch, lease_duration_ms, not_after, consumed_at
             ) SELECT
                'authorization_product_read_duplicate', record, kind,
                authorized_node_id, host_fence_event_id, volume_id, state,
                desired_revision, placement_epoch, lease_duration_ms,
                not_after, consumed_at
               FROM volume_authorizations",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (_url, store, _second, workspace) = stores();
        let fixture_name = format!("graph-{index}");
        let create = request(&workspace, &fixture_name, 1, &fixture_name);
        store
            .create_cat_covered_without_admission_for_product_test(&create)
            .unwrap();
        sweep_completed_root_for_product_read(&store, &create);
        store.with(|client| client.batch_execute(mutation)).unwrap();

        assert_eq!(
            store
                .get_runtime_cat(&workspace, &create.candidate.cat_id)
                .unwrap(),
            ProductRead::Corrupt,
            "{case} escaped the closed disposable Root authority graph"
        );
    }
}

#[test]
fn runtime_cat_read_does_not_treat_a_projection_hidden_root_row_as_swept() {
    let (_url, store, _second, workspace) = stores();
    let create = request(&workspace, "hidden-root", 1, "hidden-root");
    store
        .create_cat_covered_without_admission_for_product_test(&create)
        .unwrap();
    sweep_completed_root_for_product_read(&store, &create);

    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: id("cat_sibling"),
                    workspace_id: workspace.clone(),
                    name: id("sibling"),
                    created_at: now,
                },
            )?;
            insert_volume(transaction, &create.candidate.volume)?;
            insert_disk(
                transaction,
                &DiskRecord {
                    disk_id: create.candidate.root_disk.disk_id.clone(),
                    workspace_id: create.candidate.root_disk.workspace_id.clone(),
                    name: create.candidate.root_disk.name.clone(),
                    volume_id: create.candidate.root_disk.volume_id.clone(),
                    size_bytes: create.candidate.root_disk.size_bytes,
                    durability: create.candidate.root_disk.durability,
                    created_at: now,
                    admin_state: create.candidate.root_disk.admin_state.clone(),
                    role: create.candidate.root_disk.role.clone(),
                },
            )?;
            assert_eq!(
                transaction.execute(
                    "UPDATE disk_records SET root_cat_id='cat_sibling'
                      WHERE disk_id=$1",
                    &[&create.candidate.root_disk.disk_id.as_str()],
                )?,
                1
            );
            Ok(())
        })
        .unwrap();

    assert_eq!(
        store
            .get_runtime_cat(&workspace, &create.candidate.cat_id)
            .unwrap(),
        ProductRead::Corrupt,
        "a Root row hidden from the scalar Cat selector was mistaken for a completed sweep"
    );
}

#[test]
fn runtime_operation_exact_get_rejects_duplicates_but_ignores_foreign_and_missing_rows() {
    let (_url, store, _second, workspace) = stores();
    let first = request(&workspace, "operation-first", 1, "operation-first");
    let second = request(&workspace, "operation-second", 2, "operation-second");
    store
        .create_cat_covered_without_admission_for_product_test(&first)
        .unwrap();
    store
        .create_cat_covered_without_admission_for_product_test(&second)
        .unwrap();

    let foreign_workspace = bootstrap_workspace(&store, "operation-foreign");
    let foreign = request(
        &foreign_workspace,
        "operation-foreign",
        3,
        "operation-foreign",
    );
    store
        .create_cat_covered_without_admission_for_product_test(&foreign)
        .unwrap();
    assert_eq!(
        store
            .get_runtime_operation(&workspace, &foreign.candidate.operation_id)
            .unwrap(),
        RuntimeOperationRead::NotFound
    );
    assert_eq!(
        store
            .get_runtime_operation(&workspace, &id("op_missing"))
            .unwrap(),
        RuntimeOperationRead::NotFound
    );

    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_operations
                    SET record=jsonb_set(
                        record, '{operation_id}', to_jsonb($2::TEXT), FALSE
                    )
                  WHERE operation_id=$1",
                &[
                    &second.candidate.operation_id.as_str(),
                    &first.candidate.operation_id.as_str(),
                ],
            )
        })
        .unwrap();
    assert_eq!(
        store
            .get_runtime_operation(&workspace, &first.candidate.operation_id)
            .unwrap(),
        RuntimeOperationRead::Corrupt
    );
}

#[test]
fn runtime_operation_exact_get_has_four_bounded_workspace_indexes() {
    let (_url, store, _second, workspace) = stores();
    let operation_id = id("op_plan_probe");
    let plan = store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.batch_execute("SET LOCAL enable_seqscan=off")?;
            let rows = transaction.query(
                &format!(
                    "EXPLAIN (COSTS OFF) {}",
                    operation_by_workspace_candidates_sql()
                ),
                &[&workspace.as_str(), &operation_id.as_str()],
            )?;
            Ok(rows
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<Vec<_>>()
                .join("\n"))
        })
        .unwrap();

    for index in [
        "runtime_operations_lookup_scalar_scalar",
        "runtime_operations_lookup_scalar_record",
        "runtime_operations_lookup_record_scalar",
        "runtime_operations_lookup_record_record",
    ] {
        assert!(
            plan.contains(index),
            "workspace-qualified selector did not use {index}:\n{plan}"
        );
    }
    assert!(
        !plan.contains("Seq Scan on runtime_operations"),
        "runtime Operation lookup planned an unbounded scan:\n{plan}"
    );
    assert_eq!(
        operation_by_workspace_candidates_sql()
            .matches("LIMIT 2")
            .count(),
        4,
        "every indexed projection branch must retain its own candidate bound"
    );
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

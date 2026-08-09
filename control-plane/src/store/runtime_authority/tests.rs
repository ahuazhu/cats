use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, guest_config_digest, inventory_digest, spec_digest,
    AgentRegistrationAttempt, AgentSession, AppliedDesiredEvidence, AsciiText as RuntimeAsciiText,
    AssignedKind, AssignedPlacement, CheckpointEvidence, CleanupRelease, CleanupTarget,
    ContractErrorDetail, ContractVersion, CredentialBinding, DesiredReadRequest,
    DesiredRuntimeSpec, DiskKind, GuestDeviceIdentity, GuestRuntimeProfileReceipt,
    GuestTransportEvidence, Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission, LocalLineageState,
    LocalVolumeLineage, MacAddress, NetworkConfig, NodeBootId, NodeIdentity, NodeIdentityState,
    NodeObservation, ObservedDiskKind, ObservedRuntimeStatus, ObservedVolume, Operation,
    OperationPhase, ReconcileStep, RuntimeConfig, RuntimeTarget, RuntimeTransition,
    RuntimeVolumeAuthorizationRejection, RuntimeVolumeTransition,
    RuntimeVolumeTransitionEvidenceRequest, RuntimeVolumeTransitionOutcome,
    RuntimeVolumeTransitionPreconditionProblem, RuntimeVolumeTransitionRequest, Sequence,
    SessionBinding, VolumeAccess, VolumeAcquire, VolumeAcquireRequest, VolumeAuthorityEvidence,
    VolumeDisposition, VolumeIntent, VolumeReleaseReplay, WarmSnapshotEvidence, WireU64,
};
use cats_storage::authority::{
    complete_disposable_root_delete, consume_disposable_root_delete, AsciiText, AuthorityError,
    AuthorizationRecord, AuthorizationState, DeleteCompletionReceipt,
    DisposableDeleteIsolationBasis, DisposableRootDeleteAuthorization, Epoch, FenceEpoch,
    Generation, HostFenceEvent, HostFenceEventState, HostIsolationState, Id, NormalAcquireRequest,
    RandomId128, ReleaseRequest, RemoteHead, Revision, Sha256Digest, UnixMillis, VolumeAdminState,
    VolumeAuthorization, VolumeDurability, VolumeRecord, VolumeTakeoverAuthorization,
};

use super::product::{CatRecord, DiskAdminState, DiskRecord, DiskRole};
use super::product_rows::{
    insert_cat, insert_desired, insert_disk, insert_operation, load_desired_for_update,
    load_disk_by_id_for_update,
};
use super::rows::{
    database_now, insert_authorization, insert_delete_completion, insert_event, insert_volume,
    load_active_event_by_node_unlocked, load_authorization_for_update,
    load_delete_completion_for_update, load_event_for_update, load_volume_for_update,
    update_authorization, update_event, update_volume,
};
use super::runtime_spine::{
    age_volume_mutation_admission_for_test, PlacementAdmissionLoad, PlacementAdmissionRejection,
    RuntimeSpineOutcome,
};
use super::volume_transition_auth::{
    authenticate_evidence_context_in, RuntimeTakeoverConsumeRequest, VolumeTransitionStoreOutcome,
    VolumeTransitionStoreRejection,
};
use super::volume_transition_evidence::{
    load_volume_transition_evidence_in, VolumeTransitionEvidenceLoad,
};
use crate::store::agent_sessions::{
    load_identity_by_node_for_update, rotate_public_key_identity_in, AgentRegistrationOutcome,
    AgentSessionRegistrationPolicy,
};
use crate::store::transaction::{authority_transaction_attempts, AuthorityTransactionError};
use crate::store::{metrics_snapshot, AuthorityRequestContext, Store};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random_id(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn revision(value: u64) -> Revision {
    Revision::new(value).unwrap()
}

fn epoch(value: u64) -> Epoch {
    Epoch::new(value).unwrap()
}

fn fence_epoch(value: u64) -> FenceEpoch {
    FenceEpoch::new(value).unwrap()
}

fn generation(value: u64) -> Generation {
    Generation::new(value).unwrap()
}

fn unix_millis(value: u64) -> UnixMillis {
    UnixMillis::new(value).unwrap()
}

fn boot_id(value: u128) -> NodeBootId {
    NodeBootId::new(format!("{value:032x}")).unwrap()
}

fn runtime_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::from_bytes([1; 32]),
        initramfs_digest: Some(Sha256Digest::from_bytes([2; 32])),
        kernel_cmdline: RuntimeAsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

#[derive(Clone)]
struct TransitionNode {
    authenticated: AuthenticatedNodeCredential,
    session: SessionBinding,
    active_guest_config_digest: Sha256Digest,
}

fn transition_node(store: &Store, node_id: &str) -> TransitionNode {
    let suffix = if node_id == "node-new" { 9 } else { 10 };
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(node_id),
        immutable_host_id: id(&format!("host-{suffix}")),
        credential_id: id(&format!("credential-{suffix}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([suffix; 32]),
        },
        state_path_id: id(&format!("state-path-{suffix}")),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let release = runtime_release();
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&release).unwrap();
    store.provision_node_identity(&identity).unwrap();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id,
        immutable_host_id: identity.immutable_host_id,
        node_boot_id: boot_id(41),
        agent_instance_id: random_id(42),
        registration_attempt_id: random_id(43),
        guest_config_digest: policy.approved_guest_config_digest().clone(),
        expected_agent_session_epoch: None,
    };
    let session = match store
        .register_agent_session(&authenticated, &attempt, &policy)
        .unwrap()
    {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("transition AgentSession was rejected: {rejection:?}")
        }
    };
    TransitionNode {
        authenticated,
        session: session_binding(&session),
        active_guest_config_digest: guest_config_digest(&release).unwrap(),
    }
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn takeover_desired(
    workspace_id: &Id,
    node: &TransitionNode,
    authorization: &VolumeTakeoverAuthorization,
    volume: &VolumeRecord,
) -> DesiredRuntimeSpec {
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: workspace_id.clone(),
        cat_id: id("cat-1"),
        desired_revision: authorization.desired_revision,
        target: RuntimeTarget::Running,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: node.session.node_id.clone(),
            placement_epoch: authorization.new_placement_epoch,
        },
        runtime: RuntimeConfig {
            vcpus: 1,
            memory_bytes: 512 * 1024 * 1024,
            boot_image_digest: Sha256Digest::from_bytes([31; 32]),
            guest_config_digest: node.active_guest_config_digest.clone(),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id("network-1"),
                guest_mac: MacAddress::new("02:ca:0a:00:00:02").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
            },
        },
        volumes: vec![VolumeIntent {
            volume_intent_id: id("volume-intent-1"),
            disk_id: id("disk-1"),
            volume_id: volume.volume_id.clone(),
            attachment_id: authorization.new_attachment_id.clone(),
            size_bytes: volume.size_bytes,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: volume.durability,
            guest_device: GuestDeviceIdentity {
                serial: id("root-device-1"),
                slot: 0,
            },
            acquire: VolumeAcquire::Takeover {
                authorization_id: authorization.authorization_id.clone(),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        }],
        endpoints: Vec::new(),
        transition: RuntimeTransition::CancelAndDrain,
        spec_digest: Sha256Digest::from_bytes([0; 32]),
    };
    desired.spec_digest = spec_digest(&desired).unwrap();
    desired
}

fn takeover_runtime_status(desired: &DesiredRuntimeSpec) -> ObservedRuntimeStatus {
    ObservedRuntimeStatus {
        cat_id: desired.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        }),
        runtime_incarnation: None,
        stable_state: None,
        step: ReconcileStep::InspectInventory {
            inventory_epoch: epoch(1),
        },
        checkpoint: CheckpointEvidence::Missing {
            checkpoint_path: cats_api::runtime_reconciliation::HostPath::new(
                "/var/lib/cats/runtime/cat-1.json",
            )
            .unwrap(),
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
        conditions: Vec::new(),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test fixture spells every current Desired transition binding explicitly"
)]
fn transition_desired(
    workspace_id: &Id,
    node: &TransitionNode,
    volume: &VolumeRecord,
    target: RuntimeTarget,
    desired_revision: Revision,
    placement_epoch: Epoch,
    attachment_id: Id,
    acquire: VolumeAcquire,
    disposition: VolumeDisposition,
) -> DesiredRuntimeSpec {
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: workspace_id.clone(),
        cat_id: id("cat-1"),
        desired_revision,
        target,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: node.session.node_id.clone(),
            placement_epoch,
        },
        runtime: RuntimeConfig {
            vcpus: 1,
            memory_bytes: 512 * 1024 * 1024,
            boot_image_digest: Sha256Digest::from_bytes([31; 32]),
            guest_config_digest: node.active_guest_config_digest.clone(),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id("network-1"),
                guest_mac: MacAddress::new("02:ca:0a:00:00:02").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
            },
        },
        volumes: vec![VolumeIntent {
            volume_intent_id: id("volume-intent-1"),
            disk_id: id("disk-1"),
            volume_id: volume.volume_id.clone(),
            attachment_id,
            size_bytes: volume.size_bytes,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: volume.durability,
            guest_device: GuestDeviceIdentity {
                serial: id("root-device-1"),
                slot: 0,
            },
            acquire,
            disposition,
            mount: None,
        }],
        endpoints: Vec::new(),
        transition: RuntimeTransition::CancelAndDrain,
        spec_digest: Sha256Digest::from_bytes([0; 32]),
    };
    desired.spec_digest = spec_digest(&desired).unwrap();
    desired
}

fn observed_runtime_with_volumes(
    desired: &DesiredRuntimeSpec,
    runtime_incarnation: Option<RandomId128>,
    volumes: Vec<ObservedVolume>,
) -> ObservedRuntimeStatus {
    let mut runtime = takeover_runtime_status(desired);
    runtime.runtime_incarnation = runtime_incarnation;
    runtime.volumes = volumes;
    runtime
}

fn observed_owned_volume(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeRecord,
    origin: cats_api::runtime_reconciliation::AcquireOrigin,
    local_generation: Generation,
    remote_generation: Generation,
) -> ObservedVolume {
    let intent = desired.volumes.first().unwrap();
    ObservedVolume {
        volume_intent_id: Some(intent.volume_intent_id.clone()),
        disk_id: Some(intent.disk_id.clone()),
        volume_id: intent.volume_id.clone(),
        disk_kind: ObservedDiskKind::Root,
        size_bytes: Some(intent.size_bytes),
        durability: Some(intent.durability),
        authority: VolumeAuthorityEvidence::Owned {
            attachment_id: intent.attachment_id.clone(),
            attachment_epoch: volume.lease_epoch,
            head: volume.head.clone(),
        },
        local_lineages: vec![LocalVolumeLineage {
            attachment_id: intent.attachment_id.clone(),
            attachment_epoch: volume.lease_epoch,
            acquire_origin: origin,
            node_id: desired.placement.node_id.clone(),
            placement_epoch: desired.placement.placement_epoch,
            local_durable_generation: local_generation,
            remote_durable_generation: remote_generation,
            data_directory: cats_api::runtime_reconciliation::HostPath::new(
                "/var/lib/cats/volumes/volume-1",
            )
            .unwrap(),
            pending_pack_count: WireU64::new(0).unwrap(),
            fenced: false,
            state: LocalLineageState::Active,
        }],
        devices: Vec::new(),
    }
}

fn prepare_a22_runtime(
    store: &Store,
    node: &TransitionNode,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeRecord,
    runtime: ObservedRuntimeStatus,
    operation_required: bool,
) -> super::runtime_spine::PlacementAdmissionSnapshot {
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: desired.cat_id.clone(),
                    workspace_id: desired.workspace_id.clone(),
                    name: id("cat-1"),
                    created_at: now,
                },
            )?;
            insert_disk(
                transaction,
                &DiskRecord {
                    disk_id: id("disk-1"),
                    workspace_id: desired.workspace_id.clone(),
                    name: id("disk-1"),
                    volume_id: volume.volume_id.clone(),
                    size_bytes: volume.size_bytes,
                    durability: volume.durability,
                    created_at: now,
                    admin_state: DiskAdminState::Active,
                    role: DiskRole::Root {
                        cat_id: desired.cat_id.clone(),
                    },
                },
            )?;
            insert_desired(transaction, desired)?;
            if operation_required {
                insert_operation(
                    transaction,
                    &Operation {
                        version: ContractVersion::V1,
                        operation_id: id("operation-1"),
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
                )?;
            }
            Ok(())
        })
        .unwrap();

    let desired_read = match store
        .runtime_desired_read(
            &node.authenticated,
            &DesiredReadRequest {
                version: ContractVersion::V1,
                session: node.session.clone(),
                request_sequence: Sequence::new(1).unwrap(),
            },
        )
        .unwrap()
    {
        RuntimeSpineOutcome::Accepted(snapshot) => snapshot,
        RuntimeSpineOutcome::Rejected(rejection) => {
            panic!("A22 Desired read rejected: {rejection:?}")
        }
    };
    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: random_id(91),
        node_id: node.session.node_id.clone(),
        node_boot_id: node.session.node_boot_id.clone(),
        agent_instance_id: node.session.agent_instance_id.clone(),
        agent_session_epoch: node.session.agent_session_epoch,
        heartbeat_sequence: Sequence::new(1).unwrap(),
        observed_at_unix_ms: unix_millis(1),
        complete_inventory: true,
        inventory_epoch: epoch(1),
        inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
        inventory_read_position: Some(desired_read.read_position),
        key_ring_version: None,
        key_ring_digest: None,
        loaded_kids: Vec::new(),
        runtimes: vec![runtime],
        residue: Vec::new(),
    };
    observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
    match store
        .runtime_accept_observation(&node.authenticated, &observation)
        .unwrap()
    {
        RuntimeSpineOutcome::Accepted(_) => {}
        RuntimeSpineOutcome::Rejected(rejection) => {
            panic!("A22 full observation rejected: {rejection:?}")
        }
    }
    match store
        .load_placement_admission_snapshot(&node.session.node_id, &node.active_guest_config_digest)
        .unwrap()
    {
        PlacementAdmissionLoad::Accepted(snapshot) => *snapshot,
        PlacementAdmissionLoad::Rejected(rejection) => {
            panic!("A22 admission unexpectedly rejected: {rejection:?}")
        }
    }
}

fn prepare_takeover_runtime(
    store: &Store,
    node: &TransitionNode,
    authorization_id: &Id,
) -> DesiredRuntimeSpec {
    let authorization = stored_authorization(store, authorization_id);
    let VolumeAuthorization::Takeover(payload) = authorization.authorization else {
        panic!("takeover runtime fixture requires a takeover authorization")
    };
    let volume = stored_volume(store, &payload.volume_id);
    let workspace = super::product_tests::bootstrap_workspace(store, "a22-takeover");
    let desired = takeover_desired(&workspace, node, &payload, &volume);
    store
        .authority_transaction(|transaction| {
            if let Some(current) = load_desired_for_update(transaction, &desired.cat_id)? {
                if current != desired {
                    return Err(AuthorityError::BackendUnknown.into());
                }
                return Ok(());
            }
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: desired.cat_id.clone(),
                    workspace_id: workspace.clone(),
                    name: id("cat-1"),
                    created_at: now,
                },
            )?;
            insert_disk(
                transaction,
                &DiskRecord {
                    disk_id: id("disk-1"),
                    workspace_id: workspace.clone(),
                    name: id("disk-1"),
                    volume_id: volume.volume_id.clone(),
                    size_bytes: volume.size_bytes,
                    durability: volume.durability,
                    created_at: now,
                    admin_state: DiskAdminState::Active,
                    role: DiskRole::Root {
                        cat_id: desired.cat_id.clone(),
                    },
                },
            )?;
            insert_desired(transaction, &desired)
        })
        .unwrap();

    match store
        .load_placement_admission_snapshot(&node.session.node_id, &node.active_guest_config_digest)
        .unwrap()
    {
        PlacementAdmissionLoad::Accepted(snapshot) => {
            assert!(snapshot.assigned_desired_specs.contains(&desired));
            return desired;
        }
        PlacementAdmissionLoad::Rejected(PlacementAdmissionRejection::InventoryMissing) => {}
        PlacementAdmissionLoad::Rejected(rejection) => {
            panic!("takeover admission unexpectedly rejected: {rejection:?}")
        }
    }

    let desired_read = match store
        .runtime_desired_read(
            &node.authenticated,
            &DesiredReadRequest {
                version: ContractVersion::V1,
                session: node.session.clone(),
                request_sequence: Sequence::new(1).unwrap(),
            },
        )
        .unwrap()
    {
        RuntimeSpineOutcome::Accepted(snapshot) => snapshot,
        RuntimeSpineOutcome::Rejected(rejection) => {
            panic!("takeover Desired read rejected: {rejection:?}")
        }
    };
    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: random_id(91),
        node_id: node.session.node_id.clone(),
        node_boot_id: node.session.node_boot_id.clone(),
        agent_instance_id: node.session.agent_instance_id.clone(),
        agent_session_epoch: node.session.agent_session_epoch,
        heartbeat_sequence: Sequence::new(1).unwrap(),
        observed_at_unix_ms: unix_millis(1),
        complete_inventory: true,
        inventory_epoch: epoch(1),
        inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
        inventory_read_position: Some(desired_read.read_position),
        key_ring_version: None,
        key_ring_digest: None,
        loaded_kids: Vec::new(),
        runtimes: vec![takeover_runtime_status(&desired)],
        residue: Vec::new(),
    };
    observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
    match store
        .runtime_accept_observation(&node.authenticated, &observation)
        .unwrap()
    {
        RuntimeSpineOutcome::Accepted(_) => {}
        RuntimeSpineOutcome::Rejected(rejection) => {
            panic!("takeover full observation rejected: {rejection:?}")
        }
    }
    desired
}

fn takeover_consume_request(
    node: &TransitionNode,
    desired: &DesiredRuntimeSpec,
    authorization_id: &Id,
) -> RuntimeTakeoverConsumeRequest {
    RuntimeTakeoverConsumeRequest {
        session: node.session.clone(),
        cat_id: desired.cat_id.clone(),
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        authorization_id: authorization_id.clone(),
    }
}

fn transition_request(
    node: &TransitionNode,
    desired: &DesiredRuntimeSpec,
    transition: RuntimeVolumeTransition,
) -> RuntimeVolumeTransitionRequest {
    RuntimeVolumeTransitionRequest {
        version: ContractVersion::V1,
        session: node.session.clone(),
        cat_id: desired.cat_id.clone(),
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        transition,
    }
}

fn execute_transition(
    store: &Store,
    node: &TransitionNode,
    request: &RuntimeVolumeTransitionRequest,
) -> crate::store::Result<
    VolumeTransitionStoreOutcome<cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess>,
> {
    store.runtime_volume_transition(
        &node.authenticated,
        request,
        &node.active_guest_config_digest,
        &AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5)),
    )
}

fn execute_transition_with_empty_snapshot_authority(
    store: &Store,
    node: &TransitionNode,
    request: &RuntimeVolumeTransitionRequest,
) -> crate::store::Result<
    VolumeTransitionStoreOutcome<cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess>,
> {
    store.runtime_volume_transition_with_empty_snapshot_authority_for_test(
        &node.authenticated,
        request,
        &node.active_guest_config_digest,
        &AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5)),
    )
}

pub(crate) fn prepare_a22_http_normal_fixture(
    store: &Store,
    authenticated: AuthenticatedNodeCredential,
    session: SessionBinding,
    active_guest_config_digest: Sha256Digest,
) -> RuntimeVolumeTransitionRequest {
    let node = TransitionNode {
        authenticated,
        session,
        active_guest_config_digest,
    };
    let volume = unowned_volume();
    seed_volume(store, &volume);
    let workspace = super::product_tests::bootstrap_workspace(store, "a22-http-normal");
    let desired = transition_desired(
        &workspace,
        &node,
        &volume,
        RuntimeTarget::Running,
        revision(11),
        epoch(3),
        id("attachment-normal"),
        VolumeAcquire::Normal {
            transition_id: random_id(2),
            expected_unowned_epoch: fence_epoch(7),
        },
        VolumeDisposition::Retain,
    );
    prepare_a22_runtime(
        store,
        &node,
        &desired,
        &volume,
        takeover_runtime_status(&desired),
        false,
    );
    transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Normal {
                volume_id: volume.volume_id,
                transition_id: random_id(2),
                attachment_id: id("attachment-normal"),
                expected_unowned_epoch: fence_epoch(7),
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                lease_duration_ms: 30_000,
            },
        },
    )
}

pub(crate) fn prepare_a22_http_takeover_fixture(
    store: &Store,
    authenticated: AuthenticatedNodeCredential,
    session: SessionBinding,
    active_guest_config_digest: Sha256Digest,
) -> RuntimeVolumeTransitionRequest {
    let node = TransitionNode {
        authenticated,
        session,
        active_guest_config_digest,
    };
    let owned = acquire_owned_volume(store);
    let event = host_fence_event(HostFenceEventState::Active);
    let mut authorization = takeover_authorization(&owned);
    let VolumeAuthorization::Takeover(payload) = &mut authorization.authorization else {
        unreachable!()
    };
    payload.authorized_node_id = node.session.node_id.clone();
    seed_takeover(store, &event, &authorization);
    let desired = prepare_takeover_runtime(store, &node, &id("takeover-auth-1"));
    transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Takeover {
                authorization_id: id("takeover-auth-1"),
            },
        },
    )
}

fn evidence_request(node_id: &str) -> RuntimeVolumeTransitionEvidenceRequest {
    evidence_request_for(node_id, "takeover-auth-1")
}

fn evidence_request_for(
    node_id: &str,
    authorization_id: &str,
) -> RuntimeVolumeTransitionEvidenceRequest {
    RuntimeVolumeTransitionEvidenceRequest {
        version: ContractVersion::V1,
        session: SessionBinding {
            node_id: id(node_id),
            node_boot_id: boot_id(41),
            agent_instance_id: random_id(42),
            agent_session_epoch: epoch(1),
        },
        authorization_id: id(authorization_id),
    }
}

fn head(value: u64) -> RemoteHead {
    RemoteHead {
        generation: generation(value),
        root_hash: (value > 0).then(|| Sha256Digest::new(format!("sha256:{value:064x}")).unwrap()),
        root_object_id: (value > 0).then(|| AsciiText::new(format!("roots/{value}")).unwrap()),
    }
}

fn unowned_volume() -> VolumeRecord {
    VolumeRecord {
        volume_id: id("volume-1"),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: head(4),
        lease_owner: None,
        lease_epoch: fence_epoch(7),
        lease_expires_at: None,
        last_transition: None,
    }
}

fn acquire_request(
    transition: u128,
    attachment: &str,
    expected_epoch: u64,
) -> NormalAcquireRequest {
    NormalAcquireRequest {
        volume_id: id("volume-1"),
        transition_id: random_id(transition),
        attachment_id: id(attachment),
        expected_unowned_epoch: fence_epoch(expected_epoch),
        desired_revision: revision(11),
        placement_epoch: epoch(3),
        lease_duration_ms: 30_000,
    }
}

fn host_fence_event(state: HostFenceEventState) -> HostFenceEvent {
    HostFenceEvent {
        event_id: id("fence-event-1"),
        provider: id("provider-1"),
        immutable_host_id: id("host-1"),
        node_id: id("node-old"),
        expected_node_boot_id: cats_storage::authority::NodeBootId::new(format!("{:032x}", 1))
            .unwrap(),
        expected_agent_session_epoch: epoch(8),
        fence_attempt_id: id("fence-attempt-1"),
        isolation_state: HostIsolationState::Isolated,
        observed_at: unix_millis(12_000),
        state,
    }
}

fn takeover_authorization(volume: &VolumeRecord) -> AuthorizationRecord {
    AuthorizationRecord {
        authorization: VolumeAuthorization::Takeover(VolumeTakeoverAuthorization {
            authorization_id: id("takeover-auth-1"),
            authorized_node_id: id("node-new"),
            host_fence_event_id: id("fence-event-1"),
            volume_id: volume.volume_id.clone(),
            expected_attachment_id: volume.lease_owner.clone().unwrap(),
            expected_epoch: volume.lease_epoch,
            new_attachment_id: id("attachment-new"),
            desired_revision: revision(12),
            new_placement_epoch: epoch(4),
            lease_duration_ms: 30_000,
            not_after: unix_millis(i64::MAX.unsigned_abs()),
        }),
        state: AuthorizationState::Unconsumed,
    }
}

fn disposable_authorization(volume: &VolumeRecord) -> AuthorizationRecord {
    AuthorizationRecord {
        authorization: VolumeAuthorization::DisposableRootDelete(
            DisposableRootDeleteAuthorization {
                authorization_id: id("delete-auth-1"),
                authorized_node_id: id("node-new"),
                delete_id: id("delete-1"),
                disk_id: id("disk-1"),
                volume_id: volume.volume_id.clone(),
                cat_id: id("cat-1"),
                desired_revision: revision(12),
                placement_epoch: epoch(4),
                expected_attachment_id: volume.lease_owner.clone().unwrap(),
                expected_epoch: volume.lease_epoch,
                expected_head: volume.head.clone(),
                isolation_basis: DisposableDeleteIsolationBasis::RuntimeStopped {
                    node_id: id("node-new"),
                    agent_session_epoch: epoch(3),
                    runtime_incarnation: random_id(51),
                    observation_id: random_id(52),
                },
                not_after: unix_millis(50_000),
            },
        ),
        state: AuthorizationState::Unconsumed,
    }
}

fn store_pair() -> (String, Store, Store) {
    let url = crate::testsupport::isolated_control_store_url();
    let first = Store::connect(&url, None).unwrap();
    let second = Store::connect(&url, None).unwrap();
    (url, first, second)
}

fn seed_volume(store: &Store, record: &VolumeRecord) {
    store
        .authority_transaction(|transaction| insert_volume(transaction, record))
        .unwrap();
}

fn seed_takeover(store: &Store, event: &HostFenceEvent, authorization: &AuthorizationRecord) {
    store
        .authority_transaction(|transaction| {
            insert_event(transaction, event)?;
            insert_authorization(transaction, authorization)
        })
        .unwrap();
}

fn stored_volume(store: &Store, volume_id: &Id) -> VolumeRecord {
    store
        .authority_transaction(|transaction| {
            Ok(load_volume_for_update(transaction, volume_id)?.unwrap())
        })
        .unwrap()
}

fn stored_authorization(store: &Store, authorization_id: &Id) -> AuthorizationRecord {
    store
        .authority_transaction(|transaction| {
            Ok(load_authorization_for_update(transaction, authorization_id)?.unwrap())
        })
        .unwrap()
}

fn stored_event(store: &Store, event_id: &Id) -> HostFenceEvent {
    store
        .authority_transaction(|transaction| {
            Ok(load_event_for_update(transaction, event_id)?.unwrap())
        })
        .unwrap()
}

#[test]
fn canonical_active_fence_cannot_be_hidden_by_projection_drift() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let event = host_fence_event(HostFenceEventState::Active);
    store
        .authority_transaction(|transaction| insert_event(transaction, &event))
        .unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE host_fence_events SET state='rejoined' WHERE event_id=$1",
                &[&event.event_id.as_str()],
            )
        })
        .unwrap();

    let error = store
        .authority_transaction(|transaction| {
            load_active_event_by_node_unlocked(transaction, &event.node_id)
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

fn stored_authorization_row(store: &Store, authorization_id: &Id) -> String {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT to_jsonb(volume_authorizations)::text
                       FROM volume_authorizations
                      WHERE authorization_id=$1",
                    &[&authorization_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn stored_volume_row(store: &Store, volume_id: &Id) -> String {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT to_jsonb(volume_records)::text
                       FROM volume_records
                      WHERE volume_id=$1",
                    &[&volume_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn stored_takeover_graph(store: &Store) -> String {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT jsonb_build_object(
                         'event', (SELECT to_jsonb(row) FROM host_fence_events row
                                    WHERE event_id='fence-event-1'),
                         'authorization', (SELECT to_jsonb(row) FROM volume_authorizations row
                                            WHERE authorization_id='takeover-auth-1'),
                         'volume', (SELECT to_jsonb(row) FROM volume_records row
                                    WHERE volume_id='volume-1'),
                         'disk', (SELECT to_jsonb(row) FROM disk_records row
                                  WHERE disk_id='disk-1'),
                         'desired', (SELECT to_jsonb(row) FROM desired_runtime_specs row
                                     WHERE cat_id='cat-1')
                     )::text",
                    &[],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn rewrite_desired_in(
    transaction: &mut postgres::Transaction<'_>,
    desired: &DesiredRuntimeSpec,
) -> Result<(), AuthorityTransactionError> {
    let encoded = String::from_utf8(encode_desired_runtime_spec(desired).unwrap()).unwrap();
    let revision = i64::try_from(desired.desired_revision.get()).unwrap();
    let placement_epoch = i64::try_from(desired.placement.placement_epoch.get()).unwrap();
    let target = match desired.target {
        RuntimeTarget::Running => "running",
        RuntimeTarget::Suspended => "suspended",
        RuntimeTarget::Warm => "warm",
        RuntimeTarget::Cold => "cold",
        RuntimeTarget::Deleted => "deleted",
    };
    assert_eq!(
        transaction.execute(
            "UPDATE desired_runtime_specs
                SET record=$1::TEXT::jsonb,
                    desired_revision=$2,
                    spec_digest=$3,
                    target=$4,
                    node_id=$5,
                    placement_epoch=$6
              WHERE cat_id=$7",
            &[
                &encoded,
                &revision,
                &desired.spec_digest.as_str(),
                &target,
                &desired.placement.node_id.as_str(),
                &placement_epoch,
                &desired.cat_id.as_str(),
            ],
        )?,
        1
    );
    Ok(())
}

fn moved_takeover_desired(
    current: &DesiredRuntimeSpec,
    destination_node_id: &Id,
) -> DesiredRuntimeSpec {
    let mut moved = current.clone();
    moved.desired_revision = revision(current.desired_revision.get() + 1);
    moved.placement.node_id = destination_node_id.clone();
    moved.placement.placement_epoch = epoch(current.placement.placement_epoch.get() + 1);
    moved.volumes[0].attachment_id = id("attachment-after-move");
    moved.volumes[0].acquire = VolumeAcquire::Takeover {
        authorization_id: id("takeover-auth-after-move"),
    };
    moved.spec_digest = Sha256Digest::from_bytes([0; 32]);
    moved.spec_digest = spec_digest(&moved).unwrap();
    moved
}

fn lock_node_identities_in_order(
    transaction: &mut postgres::Transaction<'_>,
    node_ids: &[Id],
) -> Result<(), AuthorityTransactionError> {
    let mut sorted = node_ids.to_vec();
    sorted.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    sorted.dedup();
    for node_id in sorted {
        assert!(load_identity_by_node_for_update(transaction, &node_id)?.is_some());
    }
    Ok(())
}

fn acquire_owned_volume(store: &Store) -> VolumeRecord {
    seed_volume(store, &unowned_volume());
    store
        .acquire_volume_authority(&acquire_request(1, "attachment-old", 7))
        .unwrap();
    stored_volume(store, &id("volume-1"))
}

fn consume_takeover_as(
    store: &Store,
    authorization_id: &Id,
    authorized_node_id: &Id,
) -> crate::store::Result<cats_storage::authority::TakeoverResult> {
    let node = transition_node(store, authorized_node_id.as_str());
    consume_takeover_with_node(store, authorization_id, &node)
}

fn consume_takeover_outcome_with_node(
    store: &Store,
    authorization_id: &Id,
    node: &TransitionNode,
) -> crate::store::Result<VolumeTransitionStoreOutcome<cats_storage::authority::TakeoverResult>> {
    let desired = prepare_takeover_runtime(store, node, authorization_id);
    store.runtime_consume_volume_takeover(
        &node.authenticated,
        &takeover_consume_request(node, &desired, authorization_id),
        &node.active_guest_config_digest,
    )
}

fn consume_takeover_with_node(
    store: &Store,
    authorization_id: &Id,
    node: &TransitionNode,
) -> crate::store::Result<cats_storage::authority::TakeoverResult> {
    match consume_takeover_outcome_with_node(store, authorization_id, node)? {
        VolumeTransitionStoreOutcome::Accepted(result) => Ok(result),
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            panic!("authenticated takeover was rejected before authority: {rejection:?}")
        }
    }
}

fn load_evidence(
    transaction: &mut postgres::Transaction<'_>,
    node: &TransitionNode,
    request: &RuntimeVolumeTransitionEvidenceRequest,
) -> Result<VolumeTransitionEvidenceLoad, AuthorityTransactionError> {
    let context = match authenticate_evidence_context_in(
        transaction,
        &node.authenticated,
        &request.session,
        &node.active_guest_config_digest,
    )? {
        VolumeTransitionStoreOutcome::Accepted(context) => context,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            panic!("evidence authentication prefix was rejected: {rejection:?}")
        }
    };
    load_volume_transition_evidence_in(context, request)
}

fn load_evidence_public(
    store: &Store,
    node: &TransitionNode,
    request: &RuntimeVolumeTransitionEvidenceRequest,
) -> crate::store::Result<VolumeTransitionEvidenceLoad> {
    match store.runtime_volume_transition_evidence(
        &node.authenticated,
        request,
        &node.active_guest_config_digest,
    )? {
        VolumeTransitionStoreOutcome::Accepted(load) => Ok(load),
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            panic!("evidence Store entrypoint was rejected: {rejection:?}")
        }
    }
}

#[test]
fn persisted_volume_replays_lost_result_and_rejects_reused_id() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    seed_volume(&store, &unowned_volume());
    let request = acquire_request(1, "attachment-old", 7);

    // Simulate a commit response that the caller lost by discarding it.
    let first = store.acquire_volume_authority(&request).unwrap();
    let replay = store.acquire_volume_authority(&request).unwrap();
    assert_eq!(replay, first);

    let before = stored_volume(&store, &request.volume_id);
    let changed = NormalAcquireRequest {
        attachment_id: id("attachment-other"),
        ..request
    };
    let error = store.acquire_volume_authority(&changed).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(stored_volume(&store, &changed.volume_id), before);
}

#[test]
fn malformed_json_and_projection_mismatch_fail_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let volume = unowned_volume();
    seed_volume(&store, &volume);
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records SET size_bytes=size_bytes+1 WHERE volume_id=$1",
                    &[&volume.volume_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .acquire_volume_authority(&acquire_request(1, "attachment-old", 7))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET size_bytes=$2,
                            record=record || '{\"unexpected\":true}'::jsonb
                      WHERE volume_id=$1",
                    &[
                        &volume.volume_id.as_str(),
                        &i64::try_from(volume.size_bytes).unwrap(),
                    ],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .acquire_volume_authority(&acquire_request(2, "attachment-old", 7))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn expired_foreign_owner_stays_owned_but_exact_owner_can_renew() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET lease_expires_at=1,
                            record=jsonb_set(record, '{lease_expires_at}', '1'::jsonb)
                      WHERE volume_id=$1",
                    &[&owned.volume_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();

    let error = store
        .acquire_volume_authority(&acquire_request(2, "attachment-new", 8))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);

    let renewed = store
        .renew_volume_authority(&cats_storage::authority::RenewLeaseRequest {
            volume_id: owned.volume_id.clone(),
            attachment_id: id("attachment-old"),
            expected_epoch: fence_epoch(8),
            lease_duration_ms: 30_000,
        })
        .unwrap();
    assert_eq!(renewed.epoch, fence_epoch(8));
    assert!(renewed.lease_expires_at.get() > 1);
}

#[test]
fn release_reacquire_fences_a_late_release() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let old_release = ReleaseRequest {
        volume_id: owned.volume_id.clone(),
        transition_id: random_id(2),
        attachment_id: id("attachment-old"),
        expected_epoch: fence_epoch(8),
    };
    let released = store.release_volume_authority(&old_release).unwrap();
    assert_eq!(released.resulting_epoch, fence_epoch(9));
    store
        .acquire_volume_authority(&acquire_request(3, "attachment-new", 9))
        .unwrap();
    let before = stored_volume(&store, &owned.volume_id);

    let error = store.release_volume_authority(&old_release).unwrap_err();
    assert_eq!(error.code, ErrorCode::StaleEpoch);
    assert_eq!(stored_volume(&store, &owned.volume_id), before);
}

#[test]
fn two_store_sessions_cannot_both_acquire_one_volume() {
    let (_url, first, second) = store_pair();
    seed_volume(&first, &unowned_volume());
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_worker = std::thread::spawn(move || {
        first_barrier.wait();
        first.acquire_volume_authority(&acquire_request(1, "attachment-a", 7))
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.acquire_volume_authority(&acquire_request(2, "attachment-b", 7))
    });
    barrier.wait();
    let outcomes = [first_worker.join().unwrap(), second_worker.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|error| error.code == ErrorCode::Conflict)
            .count(),
        1
    );
}

#[test]
fn a22_normal_acquire_commits_once_and_replays_after_response_loss() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let volume = unowned_volume();
    seed_volume(&store, &volume);
    let node = transition_node(&store, "node-new");
    let workspace = super::product_tests::bootstrap_workspace(&store, "a22-normal");
    let desired = transition_desired(
        &workspace,
        &node,
        &volume,
        RuntimeTarget::Running,
        revision(11),
        epoch(3),
        id("attachment-normal"),
        VolumeAcquire::Normal {
            transition_id: random_id(2),
            expected_unowned_epoch: fence_epoch(7),
        },
        VolumeDisposition::Retain,
    );
    prepare_a22_runtime(
        &store,
        &node,
        &desired,
        &volume,
        takeover_runtime_status(&desired),
        false,
    );
    let request = transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Normal {
                volume_id: volume.volume_id.clone(),
                transition_id: random_id(2),
                attachment_id: id("attachment-normal"),
                expected_unowned_epoch: fence_epoch(7),
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                lease_duration_ms: 30_000,
            },
        },
    );

    store.inject_request_committed_response_loss_once_after(Duration::ZERO);
    let lost = execute_transition(&store, &node, &request).unwrap_err();
    assert_eq!(lost.code, ErrorCode::Unavailable);
    let committed = stored_volume(&store, &volume.volume_id);
    assert_eq!(committed.lease_owner, Some(id("attachment-normal")));
    assert_eq!(committed.lease_epoch, fence_epoch(8));

    let first = execute_transition(&store, &node, &request).unwrap();
    let second = execute_transition(&store, &node, &request).unwrap();
    assert_eq!(first, second);
    let VolumeTransitionStoreOutcome::Accepted(success) = first else {
        panic!("normal acquire replay was rejected")
    };
    let RuntimeVolumeTransitionOutcome::LeaseGranted { grant } = success.outcome else {
        panic!("normal acquire returned the wrong outcome")
    };
    assert_eq!(grant.attachment_id, id("attachment-normal"));
    assert_eq!(grant.attachment_epoch, fence_epoch(8));
    assert_eq!(stored_volume(&store, &volume.volume_id), committed);
}

#[test]
fn a22_takeover_union_consumes_and_replays_the_exact_authorization() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
    let request = transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Takeover {
                authorization_id: id("takeover-auth-1"),
            },
        },
    );

    let first = execute_transition(&store, &node, &request).unwrap();
    let second = execute_transition(&store, &node, &request).unwrap();
    assert_eq!(first, second);
    let VolumeTransitionStoreOutcome::Accepted(success) = first else {
        panic!("takeover union was rejected")
    };
    let RuntimeVolumeTransitionOutcome::LeaseGranted { grant } = success.outcome else {
        panic!("takeover returned the wrong outcome")
    };
    assert_eq!(grant.attachment_id, id("attachment-new"));
    assert_eq!(grant.attachment_epoch, fence_epoch(9));
    assert!(matches!(
        stored_authorization(&store, &id("takeover-auth-1")).state,
        AuthorizationState::Consumed(_)
    ));
}

#[test]
fn a22_release_uses_full_physical_evidence_and_exactly_replays() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let node = transition_node(&store, "node-new");
    let workspace = super::product_tests::bootstrap_workspace(&store, "a22-release");
    let desired = transition_desired(
        &workspace,
        &node,
        &owned,
        RuntimeTarget::Cold,
        revision(11),
        epoch(3),
        id("attachment-old"),
        VolumeAcquire::Normal {
            transition_id: random_id(1),
            expected_unowned_epoch: fence_epoch(7),
        },
        VolumeDisposition::Retain,
    );
    let observed = observed_owned_volume(
        &desired,
        &owned,
        cats_api::runtime_reconciliation::AcquireOrigin::Normal {
            transition_id: random_id(1),
        },
        owned.head.generation,
        owned.head.generation,
    );
    let admission = prepare_a22_runtime(
        &store,
        &node,
        &desired,
        &owned,
        observed_runtime_with_volumes(&desired, None, vec![observed]),
        false,
    );
    let request = transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::Release {
            cleanup: CleanupRelease {
                target: CleanupTarget::Volume {
                    volume_id: owned.volume_id.clone(),
                    attachment_id: id("attachment-old"),
                    attachment_epoch: fence_epoch(8),
                },
                inventory_session: node.session.clone(),
                inventory_epoch: admission.inventory_attestation.inventory_epoch,
                inventory_read_position: admission.inventory_attestation.inventory_read_position,
                desired_read_position: admission.desired_read_position,
                volume_release: Some(VolumeReleaseReplay {
                    release_transition_id: random_id(2),
                    generation: owned.head.generation,
                    disposition: VolumeDisposition::Retain,
                }),
            },
        },
    );

    let first = execute_transition(&store, &node, &request).unwrap();
    let second = execute_transition(&store, &node, &request).unwrap();
    assert_eq!(first, second);
    let VolumeTransitionStoreOutcome::Accepted(success) = first else {
        panic!("release was rejected")
    };
    let RuntimeVolumeTransitionOutcome::Released { release } = success.outcome else {
        panic!("release returned the wrong outcome")
    };
    assert_eq!(release.released_attachment_id, id("attachment-old"));
    assert_eq!(release.resulting_epoch, fence_epoch(9));
    let released = stored_volume(&store, &owned.volume_id);
    assert_eq!(released.lease_owner, None);
    assert_eq!(released.lease_epoch, fence_epoch(9));
}

#[test]
fn a22_disposable_consume_updates_volume_disk_and_receipt_atomically() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let node = transition_node(&store, "node-new");
    let workspace = super::product_tests::bootstrap_workspace(&store, "a22-disposable");
    let desired = transition_desired(
        &workspace,
        &node,
        &owned,
        RuntimeTarget::Deleted,
        revision(12),
        epoch(4),
        id("attachment-old"),
        VolumeAcquire::Normal {
            transition_id: random_id(1),
            expected_unowned_epoch: fence_epoch(7),
        },
        VolumeDisposition::DeleteDisposableRoot {
            delete_id: id("delete-1"),
        },
    );
    let observed = observed_owned_volume(
        &desired,
        &owned,
        cats_api::runtime_reconciliation::AcquireOrigin::Normal {
            transition_id: random_id(1),
        },
        generation(5),
        owned.head.generation,
    );
    prepare_a22_runtime(
        &store,
        &node,
        &desired,
        &owned,
        observed_runtime_with_volumes(&desired, Some(random_id(51)), vec![observed]),
        true,
    );
    let authorization = AuthorizationRecord {
        authorization: VolumeAuthorization::DisposableRootDelete(
            DisposableRootDeleteAuthorization {
                authorization_id: id("delete-auth-1"),
                authorized_node_id: node.session.node_id.clone(),
                delete_id: id("delete-1"),
                disk_id: id("disk-1"),
                volume_id: owned.volume_id.clone(),
                cat_id: desired.cat_id.clone(),
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                expected_attachment_id: id("attachment-old"),
                expected_epoch: fence_epoch(8),
                expected_head: owned.head.clone(),
                isolation_basis: DisposableDeleteIsolationBasis::RuntimeStopped {
                    node_id: node.session.node_id.clone(),
                    agent_session_epoch: node.session.agent_session_epoch,
                    runtime_incarnation: random_id(51),
                    observation_id: random_id(91),
                },
                not_after: unix_millis(i64::MAX.unsigned_abs()),
            },
        ),
        state: AuthorizationState::Unconsumed,
    };
    store
        .authority_transaction(|transaction| insert_authorization(transaction, &authorization))
        .unwrap();
    let request = transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::DeleteDisposableRoot {
            authorization_id: id("delete-auth-1"),
        },
    );

    let before_volume = stored_volume(&store, &owned.volume_id);
    let before_authorization = stored_authorization(&store, &id("delete-auth-1"));
    let unavailable = execute_transition(&store, &node, &request).unwrap_err();
    assert_eq!(unavailable.code, ErrorCode::Internal);
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("delete-auth-1")),
        before_authorization
    );

    let first = execute_transition_with_empty_snapshot_authority(&store, &node, &request).unwrap();
    let second = execute_transition_with_empty_snapshot_authority(&store, &node, &request).unwrap();
    assert_eq!(first, second);
    let VolumeTransitionStoreOutcome::Accepted(success) = first else {
        panic!("disposable delete was rejected")
    };
    let RuntimeVolumeTransitionOutcome::DisposableRootDeleting { receipt } = success.outcome else {
        panic!("disposable delete returned the wrong outcome")
    };
    assert_eq!(receipt.authorization_id, id("delete-auth-1"));
    assert_eq!(receipt.resulting_epoch, fence_epoch(9));
    assert!(matches!(
        stored_volume(&store, &owned.volume_id).admin_state,
        VolumeAdminState::Deleting { ref delete_id } if delete_id == &id("delete-1")
    ));
    let disk = store
        .authority_transaction(|transaction| {
            Ok(load_disk_by_id_for_update(transaction, &id("disk-1"))?.unwrap())
        })
        .unwrap();
    assert_eq!(
        disk.admin_state,
        DiskAdminState::Deleting {
            delete_id: id("delete-1")
        }
    );
    assert!(matches!(
        stored_authorization(&store, &id("delete-auth-1")).state,
        AuthorizationState::Consumed(_)
    ));
}

#[test]
fn takeover_wrong_tuple_has_zero_side_effect_and_exact_request_replays() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let mut wrong = takeover_authorization(&owned);
    let VolumeAuthorization::Takeover(payload) = &mut wrong.authorization else {
        unreachable!()
    };
    payload.expected_attachment_id = id("wrong-attachment");
    seed_takeover(&store, &event, &wrong);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));
    let before_volume = stored_volume(&store, &owned.volume_id);
    let before_authorization = stored_authorization(&store, &id("takeover-auth-1"));
    assert_eq!(
        store
            .runtime_consume_volume_takeover(
                &node.authenticated,
                &request,
                &node.active_guest_config_digest,
            )
            .unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                authorization_id: id("takeover-auth-1"),
                reason: RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            }
        )
    );
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("takeover-auth-1")),
        before_authorization
    );

    // Replace only the rejected fixture, then prove exact replay while the
    // complete current mutation context still exists.
    store
        .with(|client| {
            client
                .execute(
                    "DELETE FROM volume_authorizations WHERE authorization_id=$1",
                    &[&"takeover-auth-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let valid = takeover_authorization(&before_volume);
    store
        .authority_transaction(|transaction| insert_authorization(transaction, &valid))
        .unwrap();
    let first = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap();
    assert!(matches!(first, VolumeTransitionStoreOutcome::Accepted(_)));
    assert_eq!(
        store
            .runtime_consume_volume_takeover(
                &node.authenticated,
                &request,
                &node.active_guest_config_digest,
            )
            .unwrap(),
        first
    );
}

#[test]
fn evidence_snapshot_returns_the_exact_consumed_takeover_bundle() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();

    let node = transition_node(&store, "node-new");
    let request = evidence_request("node-new");
    let loaded = store
        .authority_locking_read_snapshot(|transaction| {
            let isolation: String = transaction
                .query_one("SHOW transaction_isolation", &[])?
                .get(0);
            let read_only: String = transaction
                .query_one("SHOW transaction_read_only", &[])?
                .get(0);
            assert_eq!(isolation, "repeatable read");
            assert_eq!(read_only, "off");
            load_evidence(transaction, &node, &request)
        })
        .unwrap();
    let VolumeTransitionEvidenceLoad::Available(success) = loaded else {
        panic!("authorized evidence unexpectedly unavailable")
    };
    assert_eq!(success.authorization_id, request.authorization_id);
    assert_eq!(success.session, request.session);
    assert_eq!(
        success.authorization,
        stored_authorization(&store, &id("takeover-auth-1"))
    );
    assert_eq!(
        success.current_volume,
        Some(stored_volume(&store, &owned.volume_id))
    );
    assert_eq!(success.delete_completion, None);
    assert_eq!(success.direct_successor_authorization, None);
}

#[test]
fn evidence_snapshot_rejects_a_future_consumption_timestamp() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();
    let node = transition_node(&store, "node-new");

    let db_now = store.authority_locking_read_snapshot(database_now).unwrap();
    let future = unix_millis(db_now.get() + 60_000);
    let future_not_after = unix_millis(db_now.get() + 180_000);
    let mut corrupted = stored_authorization(&store, &id("takeover-auth-1"));
    let VolumeAuthorization::Takeover(authorization) = &mut corrupted.authorization else {
        unreachable!()
    };
    authorization.not_after = future_not_after;
    let AuthorizationState::Consumed(receipt) = &mut corrupted.state else {
        unreachable!()
    };
    let cats_storage::authority::AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_mut()
    else {
        unreachable!()
    };
    receipt.consumed_at = future;
    let record_json = serde_json::to_string(&corrupted).unwrap();
    let future = i64::try_from(future.get()).unwrap();
    let future_not_after = i64::try_from(future_not_after.get()).unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=$2::TEXT::jsonb, consumed_at=$3, not_after=$4
                      WHERE authorization_id=$1",
                    &[&"takeover-auth-1", &record_json, &future, &future_not_after],
                )
                .map(|_| ())
        })
        .unwrap();

    let request = evidence_request("node-new");
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn evidence_access_predicate_hides_wrong_node_before_protected_decode() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let wrong_node = transition_node(&store, "node-other");

    // Calibrate the query with the known authorized Node before corrupting the
    // protected payload. This makes the negative isolation assertion prove
    // the access predicate rather than a typo in the fixture.
    let request = evidence_request("node-new");
    assert!(matches!(
        load_evidence_public(&store, &node, &request).unwrap(),
        VolumeTransitionEvidenceLoad::Available(_)
    ));
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=record || '{\"unexpected\":true}'::jsonb
                      WHERE authorization_id=$1",
                    &[&"takeover-auth-1"],
                )
                .map(|_| ())
        })
        .unwrap();

    let wrong_request = evidence_request("node-other");
    let wrong = load_evidence_public(&store, &wrong_node, &wrong_request).unwrap();
    assert_eq!(
        wrong,
        VolumeTransitionEvidenceLoad::Unavailable {
            authorization_id: id("takeover-auth-1")
        }
    );
    let error = load_evidence_public(&store, &node, &request).unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn evidence_rejects_wrong_credential_lineage_before_protected_rows() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let request = evidence_request("node-new");

    // First calibrate the public Store entrypoint with the exact active
    // lineage. Then corrupt the protected row: a wrong proof binding must
    // still stop at identity admission and never expose that corruption.
    assert!(matches!(
        load_evidence_public(&store, &node, &request).unwrap(),
        VolumeTransitionEvidenceLoad::Available(_)
    ));
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=record || '{\"unexpected\":true}'::jsonb
                      WHERE authorization_id=$1",
                    &[&"takeover-auth-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let wrong = AuthenticatedNodeCredential::new(
        node.authenticated.credential_id().clone(),
        CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([77; 32]),
        },
    );
    let outcome = store
        .runtime_volume_transition_evidence(&wrong, &request, &node.active_guest_config_digest)
        .unwrap();
    assert_eq!(
        outcome,
        VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::IdentityNotEligible)
    );
}

#[test]
fn evidence_share_locks_hold_credential_rotation_until_snapshot_commit() {
    let (_url, seed, reader) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let node = transition_node(&seed, "node-new");
    let request = evidence_request("node-new");

    let reader_node = node.clone();
    let reader_request = request.clone();
    let (prefix_tx, prefix_rx) = mpsc::channel();
    let (finish_read_tx, finish_read_rx) = mpsc::channel();
    let reader_worker = std::thread::spawn(move || {
        reader.authority_locking_read_snapshot(move |transaction| {
            let context = match authenticate_evidence_context_in(
                transaction,
                &reader_node.authenticated,
                &reader_request.session,
                &reader_node.active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    panic!("evidence prefix rejected: {rejection:?}")
                }
            };
            prefix_tx.send(()).unwrap();
            finish_read_rx.recv().unwrap();
            load_volume_transition_evidence_in(context, &reader_request)
        })
    });
    prefix_rx.recv().unwrap();

    let rotator = Store::connect_from(&seed.dsn, None).unwrap();
    let (rotation_started_tx, rotation_started_rx) = mpsc::channel();
    let (rotation_finished_tx, rotation_finished_rx) = mpsc::channel();
    let rotation_worker = std::thread::spawn(move || {
        let outcome = rotator.authority_transaction(|transaction| {
            rotation_started_tx.send(()).unwrap();
            let current = load_identity_by_node_for_update(transaction, &id("node-new"))?
                .expect("transition NodeIdentity exists");
            let committed_at = database_now(transaction)?;
            rotate_public_key_identity_in(
                transaction,
                &current,
                &id("credential-rotated"),
                &Sha256Digest::from_bytes([88; 32]),
                committed_at,
            )?;
            Ok(())
        });
        rotation_finished_tx.send(outcome).unwrap();
    });
    rotation_started_rx.recv().unwrap();
    assert!(
        rotation_finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err(),
        "credential rotation passed the evidence transaction's share locks"
    );

    finish_read_tx.send(()).unwrap();
    assert!(matches!(
        reader_worker.join().unwrap().unwrap(),
        VolumeTransitionEvidenceLoad::Available(_)
    ));
    rotation_finished_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("rotation finishes after evidence commit")
        .unwrap();
    rotation_worker.join().unwrap();

    let old = seed
        .runtime_volume_transition_evidence(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap();
    assert_eq!(
        old,
        VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::IdentityNotEligible)
    );
    let rotated = AuthenticatedNodeCredential::new(
        id("credential-rotated"),
        CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([88; 32]),
        },
    );
    assert!(matches!(
        seed.runtime_volume_transition_evidence(
            &rotated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap(),
        VolumeTransitionStoreOutcome::Accepted(VolumeTransitionEvidenceLoad::Available(_))
    ));
}

#[test]
fn authenticated_takeover_response_loss_replays_the_committed_receipt() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));

    store.inject_committed_response_loss_once();
    let error = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    let committed_volume = stored_volume(&store, &owned.volume_id);
    assert_eq!(committed_volume.lease_owner, Some(id("attachment-new")));
    assert!(matches!(
        stored_authorization(&store, &id("takeover-auth-1")).state,
        AuthorizationState::Consumed(_)
    ));

    let replay = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap();
    let VolumeTransitionStoreOutcome::Accepted(replay) = replay else {
        panic!("committed takeover replay was rejected")
    };
    assert_eq!(replay.resulting_epoch, committed_volume.lease_epoch);
    assert_eq!(replay.resulting_head, committed_volume.head);
    assert_eq!(replay.attachment_id, id("attachment-new"));
}

#[test]
fn stale_preplanned_takeover_is_closed_before_any_authority_write() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
    let mut request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));
    request.desired_revision = revision(desired.desired_revision.get() - 1);
    let before_volume = stored_volume_row(&store, &owned.volume_id);
    let before_authorization = stored_authorization_row(&store, &id("takeover-auth-1"));

    let outcome = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap();
    assert!(matches!(
        outcome,
        VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(
            *error,
            ContractErrorDetail::StaleRevision {
                presented_revision,
                current_revision,
                ..
            } if presented_revision == request.desired_revision
                && current_revision == desired.desired_revision
        )
    ));
    assert_eq!(stored_volume_row(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&store, &id("takeover-auth-1")),
        before_authorization
    );
}

#[test]
fn stale_takeover_inventory_is_a_closed_zero_write_precondition() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));
    store
        .authority_transaction(|transaction| {
            age_volume_mutation_admission_for_test(transaction, &node.session.node_id)
        })
        .unwrap();
    let before_volume = stored_volume_row(&store, &owned.volume_id);
    let before_authorization = stored_authorization_row(&store, &id("takeover-auth-1"));

    assert_eq!(
        store
            .runtime_consume_volume_takeover(
                &node.authenticated,
                &request,
                &node.active_guest_config_digest,
            )
            .unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::TransitionPreconditionFailed {
                cat_id: desired.cat_id,
                problem: RuntimeVolumeTransitionPreconditionProblem::InventoryStale,
            }
        )
    );
    assert_eq!(stored_volume_row(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&store, &id("takeover-auth-1")),
        before_authorization
    );
}

#[test]
fn request_intent_mismatch_is_409_but_stored_disk_cross_binding_is_fatal() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));
    let before_volume = stored_volume_row(&store, &owned.volume_id);
    let before_authorization = stored_authorization_row(&store, &id("takeover-auth-1"));

    let mut wrong_intent = request.clone();
    wrong_intent.authorization_id = id("takeover-auth-not-current");
    assert_eq!(
        store
            .runtime_consume_volume_takeover(
                &node.authenticated,
                &wrong_intent,
                &node.active_guest_config_digest,
            )
            .unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::TransitionPreconditionFailed {
                cat_id: desired.cat_id.clone(),
                problem: RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
            }
        )
    );
    assert_eq!(stored_volume_row(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&store, &id("takeover-auth-1")),
        before_authorization
    );

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE disk_records
                        SET record=jsonb_set(record, '{size_bytes}', to_jsonb(size_bytes + 1)),
                            size_bytes=size_bytes + 1
                      WHERE disk_id=$1",
                    &[&"disk-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(stored_volume_row(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&store, &id("takeover-auth-1")),
        before_authorization
    );
}

#[test]
fn referenced_takeover_graph_corruption_is_fatal_and_never_mutates_authority() {
    #[derive(Debug, Clone, Copy)]
    enum Corruption {
        MissingAuthorization,
        HiddenAuthorizationIntentProjection,
        AuthorizationIntentCrossBinding,
        MissingDisk,
    }

    for corruption in [
        Corruption::MissingAuthorization,
        Corruption::HiddenAuthorizationIntentProjection,
        Corruption::AuthorizationIntentCrossBinding,
        Corruption::MissingDisk,
    ] {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let owned = acquire_owned_volume(&store);
        let event = host_fence_event(HostFenceEventState::Active);
        let authorization = takeover_authorization(&owned);
        seed_takeover(&store, &event, &authorization);
        let node = transition_node(&store, "node-new");
        let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
        let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));

        store
            .with(|client| {
                let changed = match corruption {
                    Corruption::MissingAuthorization => client.execute(
                        "DELETE FROM volume_authorizations WHERE authorization_id=$1",
                        &[&"takeover-auth-1"],
                    )?,
                    Corruption::HiddenAuthorizationIntentProjection => client.execute(
                        "UPDATE volume_authorizations
                            SET volume_id='volume-other'
                          WHERE authorization_id=$1",
                        &[&"takeover-auth-1"],
                    )?,
                    Corruption::AuthorizationIntentCrossBinding => client.execute(
                        "UPDATE volume_authorizations
                            SET record=jsonb_set(
                                record,
                                '{authorization,new_attachment_id}',
                                to_jsonb('attachment-other'::text)
                            )
                          WHERE authorization_id=$1",
                        &[&"takeover-auth-1"],
                    )?,
                    Corruption::MissingDisk => {
                        client.execute("DELETE FROM disk_records WHERE disk_id=$1", &[&"disk-1"])?
                    }
                };
                assert_eq!(changed, 1, "corruption probe did not match: {corruption:?}");
                Ok(())
            })
            .unwrap();
        let before = stored_takeover_graph(&store);

        let error = store
            .runtime_consume_volume_takeover(
                &node.authenticated,
                &request,
                &node.active_guest_config_digest,
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Internal, "{corruption:?}");
        assert_eq!(stored_takeover_graph(&store), before, "{corruption:?}");
    }
}

#[test]
fn expired_takeover_is_a_closed_zero_write_authorization_rejection() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let mut authorization = takeover_authorization(&owned);
    let VolumeAuthorization::Takeover(payload) = &mut authorization.authorization else {
        unreachable!()
    };
    payload.not_after = unix_millis(1);
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));
    let before_volume = stored_volume_row(&store, &owned.volume_id);
    let before_authorization = stored_authorization_row(&store, &id("takeover-auth-1"));

    assert_eq!(
        store
            .runtime_consume_volume_takeover(
                &node.authenticated,
                &request,
                &node.active_guest_config_digest,
            )
            .unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                authorization_id: id("takeover-auth-1"),
                reason: RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            }
        )
    );
    assert_eq!(stored_volume_row(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&store, &id("takeover-auth-1")),
        before_authorization
    );
}

#[test]
fn desired_move_winning_the_pg_barrier_rejects_takeover_with_zero_writes() {
    let (url, seed, consumer) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let node = transition_node(&seed, "node-new");
    let desired = prepare_takeover_runtime(&seed, &node, &id("takeover-auth-1"));
    let destination = transition_node(&seed, "node-other");
    let moved = moved_takeover_desired(&desired, &destination.session.node_id);
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));
    let before_volume = stored_volume_row(&seed, &owned.volume_id);
    let before_authorization = stored_authorization_row(&seed, &id("takeover-auth-1"));

    let mover = Store::connect(&url, None).unwrap();
    let move_nodes = vec![node.session.node_id.clone(), destination.session.node_id];
    let moved_for_worker = moved.clone();
    let (move_locked_tx, move_locked_rx) = mpsc::channel();
    let (finish_move_tx, finish_move_rx) = mpsc::channel();
    let mover_worker = std::thread::spawn(move || {
        mover.authority_transaction(move |transaction| {
            lock_node_identities_in_order(transaction, &move_nodes)?;
            move_locked_tx.send(()).unwrap();
            finish_move_rx.recv().unwrap();
            rewrite_desired_in(transaction, &moved_for_worker)
        })
    });
    move_locked_rx.recv().unwrap();

    let (consume_done_tx, consume_done_rx) = mpsc::channel();
    let consumer_worker = std::thread::spawn(move || {
        consume_done_tx
            .send(consumer.runtime_consume_volume_takeover(
                &node.authenticated,
                &request,
                &node.active_guest_config_digest,
            ))
            .unwrap();
    });
    assert!(
        consume_done_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err(),
        "takeover did not wait behind the Desired mover's NodeIdentity lock"
    );
    finish_move_tx.send(()).unwrap();
    mover_worker.join().unwrap().unwrap();

    let outcome = consume_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("takeover did not resume after the Desired move")
        .unwrap();
    assert!(matches!(
        outcome,
        VolumeTransitionStoreOutcome::Rejected(VolumeTransitionStoreRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(*error, ContractErrorDetail::AssignedSetChanged { .. })
    ));
    consumer_worker.join().unwrap();
    assert_eq!(stored_volume_row(&seed, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&seed, &id("takeover-auth-1")),
        before_authorization
    );
    assert_eq!(
        seed.authority_transaction(|transaction| {
            Ok(load_desired_for_update(transaction, &moved.cat_id)?.unwrap())
        })
        .unwrap(),
        moved
    );
}

#[test]
fn takeover_winning_the_pg_barrier_serializes_before_desired_move() {
    let (url, seed, consumer) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let node = transition_node(&seed, "node-new");
    let desired = prepare_takeover_runtime(&seed, &node, &id("takeover-auth-1"));
    let destination = transition_node(&seed, "node-other");
    let moved = moved_takeover_desired(&desired, &destination.session.node_id);
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));

    // Pause the real Store transaction only after its authenticated prefix
    // owns NodeIdentity. The one competing PG session must then block on that
    // same row before it can supersede/move Desired.
    let (prefix_locked_tx, prefix_locked_rx) = mpsc::channel();
    let (finish_consume_tx, finish_consume_rx) = mpsc::channel();
    let (consume_done_tx, consume_done_rx) = mpsc::channel();
    let consumer_worker = std::thread::spawn(move || {
        consume_done_tx
            .send(consumer.runtime_consume_volume_takeover_with_checkpoint(
                &node.authenticated,
                &request,
                &node.active_guest_config_digest,
                move || {
                    prefix_locked_tx.send(()).unwrap();
                    finish_consume_rx.recv().unwrap();
                    Ok(())
                },
            ))
            .unwrap();
    });
    prefix_locked_rx.recv().unwrap();

    let mover = Store::connect(&url, None).unwrap();
    let move_nodes = vec![id("node-new"), destination.session.node_id.clone()];
    let moved_for_worker = moved.clone();
    let (move_done_tx, move_done_rx) = mpsc::channel();
    let mover_worker = std::thread::spawn(move || {
        move_done_tx
            .send(mover.authority_transaction(move |transaction| {
                lock_node_identities_in_order(transaction, &move_nodes)?;
                rewrite_desired_in(transaction, &moved_for_worker)
            }))
            .unwrap();
    });
    assert!(
        move_done_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err(),
        "Desired mover passed the takeover transaction's NodeIdentity lock"
    );

    finish_consume_tx.send(()).unwrap();
    let outcome = consume_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("takeover did not resume after the HostFence barrier")
        .unwrap();
    assert!(matches!(outcome, VolumeTransitionStoreOutcome::Accepted(_)));
    move_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Desired move did not resume after takeover commit")
        .unwrap();
    consumer_worker.join().unwrap();
    mover_worker.join().unwrap();

    let committed = stored_volume(&seed, &owned.volume_id);
    assert_eq!(committed.lease_owner, Some(id("attachment-new")));
    assert!(matches!(
        stored_authorization(&seed, &id("takeover-auth-1")).state,
        AuthorizationState::Consumed(_)
    ));
    assert_eq!(
        seed.authority_transaction(|transaction| {
            Ok(load_desired_for_update(transaction, &moved.cat_id)?.unwrap())
        })
        .unwrap(),
        moved
    );
}

#[test]
fn evidence_snapshot_rejects_missing_direct_successor_and_split_completion() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();
    let node = transition_node(&store, "node-new");
    let request = evidence_request("node-new");

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET record=jsonb_set(record, '{last_transition,authorization_id}',
                                             '\"missing-auth\"'::jsonb),
                            last_transition_id='missing-auth'
                      WHERE volume_id=$1",
                    &[&"volume-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_records
                        SET record=jsonb_set(record, '{last_transition,authorization_id}',
                                             '\"takeover-auth-1\"'::jsonb),
                            last_transition_id='takeover-auth-1'
                      WHERE volume_id=$1",
                    &[&"volume-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let current = stored_volume(&store, &id("volume-1"));
    let completion = DeleteCompletionReceipt::Normal {
        request: cats_storage::authority::BeginDeleteRequest {
            delete_id: id("delete-split"),
            disk_id: id("disk-1"),
            volume_id: current.volume_id.clone(),
            expected_unowned_epoch: current.lease_epoch,
            expected_head: current.head.clone(),
        },
        deleting_epoch: fence_epoch(current.lease_epoch.get() + 1),
        deleting_head: current.head,
        completed_at: unix_millis(40_000),
    };
    store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &completion))
        .unwrap();
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn takeover_authorized_node_is_immutable_and_wrong_caller_has_zero_writes() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let wrong_node = transition_node(&store, "node-other");
    let desired = prepare_takeover_runtime(&store, &wrong_node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&wrong_node, &desired, &id("takeover-auth-1"));
    let before_volume = stored_volume(&store, &owned.volume_id);
    let before_authorization = stored_authorization(&store, &id("takeover-auth-1"));

    assert_eq!(
        store
            .runtime_consume_volume_takeover(
                &wrong_node.authenticated,
                &request,
                &wrong_node.active_guest_config_digest,
            )
            .unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                authorization_id: id("takeover-auth-1"),
                reason: RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            }
        )
    );
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("takeover-auth-1")),
        before_authorization
    );
}

#[test]
fn wrong_node_rejects_before_corrupt_foreign_authority_locks_or_decode() {
    let (url, seed, consumer) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let wrong_node = transition_node(&seed, "node-other");
    let desired = prepare_takeover_runtime(&seed, &wrong_node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&wrong_node, &desired, &id("takeover-auth-1"));

    // Keep every bounded scalar route projection intact while making the
    // protected payload undecodable. A wrong Node must never reach it.
    seed.with(|client| {
        client
            .execute(
                "UPDATE volume_authorizations
                    SET record=record || '{\"unexpected\":true}'::jsonb
                  WHERE authorization_id=$1",
                &[&"takeover-auth-1"],
            )
            .map(|_| ())
    })
    .unwrap();
    let before_volume = stored_volume_row(&seed, &owned.volume_id);
    let before_authorization = stored_authorization_row(&seed, &id("takeover-auth-1"));

    let blocker = Store::connect(&url, None).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocker_worker = std::thread::spawn(move || {
        blocker.with(move |client| {
            let mut transaction = client.transaction()?;
            transaction.query_one(
                "SELECT event_id FROM host_fence_events WHERE event_id=$1 FOR UPDATE",
                &[&"fence-event-1"],
            )?;
            transaction.query_one(
                "SELECT authorization_id
                   FROM volume_authorizations
                  WHERE authorization_id=$1 FOR UPDATE",
                &[&"takeover-auth-1"],
            )?;
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            transaction.rollback()
        })
    });
    locked_rx.recv().unwrap();

    let (finished_tx, finished_rx) = mpsc::channel();
    let consumer_worker = std::thread::spawn(move || {
        let result = consumer.runtime_consume_volume_takeover(
            &wrong_node.authenticated,
            &request,
            &wrong_node.active_guest_config_digest,
        );
        finished_tx.send(result).unwrap();
    });
    let outcome = finished_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("wrong-Node routing touched the locked foreign authority graph")
        .unwrap();
    assert_eq!(
        outcome,
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                authorization_id: id("takeover-auth-1"),
                reason: RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            }
        )
    );
    assert_eq!(stored_volume_row(&seed, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&seed, &id("takeover-auth-1")),
        before_authorization
    );

    release_tx.send(()).unwrap();
    blocker_worker.join().unwrap().unwrap();
    consumer_worker.join().unwrap();
}

#[test]
fn evidence_snapshot_returns_disposable_completion_after_rows_are_gone() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let original = disposable_authorization(&owned);
    store
        .authority_transaction(|transaction| insert_authorization(transaction, &original))
        .unwrap();
    let (deleting, consumed, _) = consume_disposable_root_delete(
        &owned,
        None,
        &original,
        &id("delete-auth-1"),
        unix_millis(20_000),
    )
    .unwrap();
    store
        .authority_transaction(|transaction| {
            update_volume(transaction, &deleting)?;
            update_authorization(transaction, &original, &consumed)
        })
        .unwrap();
    let completion =
        complete_disposable_root_delete(&deleting, &consumed, unix_millis(40_000)).unwrap();
    store
        .authority_transaction(|transaction| {
            insert_delete_completion(transaction, &completion)?;
            transaction.execute(
                "DELETE FROM volume_records WHERE volume_id=$1",
                &[&owned.volume_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();

    let node = transition_node(&store, "node-new");
    let request = evidence_request_for("node-new", "delete-auth-1");
    let loaded = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap();
    let VolumeTransitionEvidenceLoad::Available(success) = loaded else {
        panic!("disposable evidence unexpectedly unavailable")
    };
    assert_eq!(success.current_volume, None);
    assert_eq!(success.delete_completion, Some(completion));
    assert_eq!(success.authorization, consumed);
    assert_eq!(success.direct_successor_authorization, None);
}

#[test]
fn evidence_snapshot_detects_duplicate_completion_rows_even_without_schema_guard() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    let result = consume_takeover_as(&store, &id("takeover-auth-1"), &id("node-new")).unwrap();
    let node = transition_node(&store, "node-new");
    store
        .with(|client| {
            client.batch_execute(
                "ALTER TABLE delete_completion_receipts
                   DROP CONSTRAINT delete_completion_receipts_volume_id_key",
            )
        })
        .unwrap();
    store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "DELETE FROM disk_records WHERE volume_id=$1",
                &[&owned.volume_id.as_str()],
            )?;
            transaction
                .execute(
                    "DELETE FROM volume_records WHERE volume_id=$1",
                    &[&owned.volume_id.as_str()],
                )
                .map(|_| ())?;
            transaction.commit()
        })
        .unwrap();
    for (delete_id, disk_id, completed_at) in [
        ("delete-a", "disk-a", 40_000),
        ("delete-b", "disk-b", 40_001),
    ] {
        let expected_unowned_epoch = fence_epoch(result.resulting_epoch.get() + 1);
        let completion = DeleteCompletionReceipt::Normal {
            request: cats_storage::authority::BeginDeleteRequest {
                delete_id: id(delete_id),
                disk_id: id(disk_id),
                volume_id: owned.volume_id.clone(),
                expected_unowned_epoch,
                expected_head: result.resulting_head.clone(),
            },
            deleting_epoch: fence_epoch(expected_unowned_epoch.get() + 1),
            deleting_head: result.resulting_head.clone(),
            completed_at: unix_millis(completed_at),
        };
        store
            .authority_transaction(|transaction| insert_delete_completion(transaction, &completion))
            .unwrap();
    }

    let request = evidence_request("node-new");
    let error = store
        .authority_locking_read_snapshot(|transaction| load_evidence(transaction, &node, &request))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn evidence_repeatable_read_never_mixes_takeover_before_and_after_images() {
    let (_url, seed, reader) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let node = transition_node(&seed, "node-new");

    let request = evidence_request("node-new");
    let reader_request = request.clone();
    let reader_node = node.clone();
    let (snapshot_tx, snapshot_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        reader.authority_locking_read_snapshot(move |transaction| {
            // Authenticate and establish the RR snapshot before allowing the
            // writer to commit. The unforgeable context carries that one DB
            // time into the evidence loader.
            let context = match authenticate_evidence_context_in(
                transaction,
                &reader_node.authenticated,
                &reader_request.session,
                &reader_node.active_guest_config_digest,
            )? {
                VolumeTransitionStoreOutcome::Accepted(context) => context,
                VolumeTransitionStoreOutcome::Rejected(rejection) => {
                    panic!("evidence prefix rejected: {rejection:?}")
                }
            };
            snapshot_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            load_volume_transition_evidence_in(context, &reader_request)
        })
    });
    snapshot_rx.recv().unwrap();
    let writer = Store::connect_from(&seed.dsn, None).unwrap();
    let writer_node = node.clone();
    let (consume_finished_tx, consume_finished_rx) = mpsc::channel();
    let consume_worker = std::thread::spawn(move || {
        consume_finished_tx
            .send(consume_takeover_with_node(
                &writer,
                &id("takeover-auth-1"),
                &writer_node,
            ))
            .unwrap();
    });
    assert!(
        consume_finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err(),
        "takeover mutation passed the evidence transaction's identity share lock"
    );
    continue_tx.send(()).unwrap();

    let VolumeTransitionEvidenceLoad::Available(before) = worker.join().unwrap().unwrap() else {
        panic!("pre-commit snapshot unexpectedly unavailable")
    };
    assert!(matches!(
        before.authorization.state,
        AuthorizationState::Unconsumed
    ));
    assert_eq!(before.current_volume, Some(owned));
    consume_finished_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("takeover finishes after evidence snapshot commits")
        .unwrap();
    consume_worker.join().unwrap();

    let VolumeTransitionEvidenceLoad::Available(after) =
        load_evidence_public(&seed, &node, &request).unwrap()
    else {
        panic!("post-commit snapshot unexpectedly unavailable")
    };
    assert!(matches!(
        after.authorization.state,
        AuthorizationState::Consumed(_)
    ));
    assert_eq!(
        after.current_volume.unwrap().lease_owner,
        Some(id("attachment-new"))
    );
}

#[test]
fn corrupted_authorization_payload_fails_closed_without_writes() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    let authorization_id = id("takeover-auth-1");
    seed_takeover(&store, &event, &authorization);
    let node = transition_node(&store, "node-new");
    let desired = prepare_takeover_runtime(&store, &node, &authorization_id);
    let request = takeover_consume_request(&node, &desired, &authorization_id);

    // Attachment identities are intentionally not duplicated as projections.
    // Make the closed JSONB payload internally invalid while every projection
    // remains valid and unchanged.
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE volume_authorizations
                        SET record=jsonb_set(
                            record,
                            '{authorization,new_attachment_id}',
                            record #> '{authorization,expected_attachment_id}'
                        )
                      WHERE authorization_id=$1",
                    &[&authorization_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();

    let before_volume = stored_volume(&store, &owned.volume_id);
    let before_event = stored_event(&store, &event.event_id);
    let before_authorization = stored_authorization_row(&store, &authorization_id);

    let error = store
        .runtime_consume_volume_takeover(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(stored_event(&store, &event.event_id), before_event);
    assert_eq!(
        stored_authorization_row(&store, &authorization_id),
        before_authorization
    );
}

#[test]
fn rejoin_event_lock_serializes_before_unconsumed_takeover() {
    let (_url, seed, consumer) = store_pair();
    let owned = acquire_owned_volume(&seed);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&seed, &event, &authorization);
    let node = transition_node(&seed, "node-new");
    let desired = prepare_takeover_runtime(&seed, &node, &id("takeover-auth-1"));
    let request = takeover_consume_request(&node, &desired, &id("takeover-auth-1"));

    let rejoin = Store::connect_from(&seed.dsn, None).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let rejoin_worker = std::thread::spawn(move || {
        rejoin.authority_transaction(move |transaction| {
            let mut event = load_event_for_update(transaction, &id("fence-event-1"))?.unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            event.state = HostFenceEventState::Rejoined;
            update_event(transaction, &event)
        })
    });
    locked_rx.recv().unwrap();
    let consume_worker = std::thread::spawn(move || {
        consumer.runtime_consume_volume_takeover(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
    });
    release_tx.send(()).unwrap();
    rejoin_worker.join().unwrap().unwrap();
    assert_eq!(
        consume_worker.join().unwrap().unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                authorization_id: id("takeover-auth-1"),
                reason: RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            }
        )
    );
    assert_eq!(stored_volume(&seed, &owned.volume_id), owned);
    assert!(matches!(
        stored_authorization(&seed, &id("takeover-auth-1")).state,
        AuthorizationState::Unconsumed
    ));
}

#[test]
fn delete_completion_codec_is_exactly_idempotent() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let receipt = DeleteCompletionReceipt::Normal {
        request: cats_storage::authority::BeginDeleteRequest {
            delete_id: id("delete-1"),
            disk_id: id("disk-1"),
            volume_id: id("volume-1"),
            expected_unowned_epoch: fence_epoch(7),
            expected_head: head(4),
        },
        deleting_epoch: fence_epoch(8),
        deleting_head: head(4),
        completed_at: unix_millis(20_000),
    };
    store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &receipt))
        .unwrap();
    store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &receipt))
        .unwrap();
    let stored = store
        .authority_transaction(|transaction| {
            Ok(load_delete_completion_for_update(transaction, &id("delete-1"))?.unwrap())
        })
        .unwrap();
    assert_eq!(stored, receipt);

    let DeleteCompletionReceipt::Normal {
        request,
        deleting_epoch,
        deleting_head,
        ..
    } = &receipt
    else {
        unreachable!()
    };
    let changed = DeleteCompletionReceipt::Normal {
        request: request.clone(),
        deleting_epoch: *deleting_epoch,
        deleting_head: deleting_head.clone(),
        completed_at: unix_millis(20_001),
    };
    let error = store
        .authority_transaction(|transaction| insert_delete_completion(transaction, &changed))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
}

#[test]
fn serialization_and_deadlock_errors_retry_the_whole_closure_with_a_bound() {
    for sqlstate in ["40001", "40P01"] {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let value = store
            .authority_transaction(|transaction| {
                let attempt = observed.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    transaction.batch_execute(&format!(
                        "DO $$ BEGIN RAISE EXCEPTION 'retry' USING ERRCODE='{sqlstate}'; END $$"
                    ))?;
                }
                Ok(42_u64)
            })
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let error = store
        .authority_transaction::<()>(|transaction| {
            observed.fetch_add(1, Ordering::SeqCst);
            transaction.batch_execute(
                "DO $$ BEGIN RAISE EXCEPTION 'retry' USING ERRCODE='40001'; END $$",
            )?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        authority_transaction_attempts()
    );
}

#[test]
fn transient_connection_loss_reconnects_and_replays_the_whole_closure() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let value = store
        .authority_transaction(|transaction| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                transaction.batch_execute("SELECT pg_terminate_backend(pg_backend_pid())")?;
            }
            Ok(42_u64)
        })
        .unwrap();
    assert_eq!(value, 42);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_an_active_authority_call_leaves_no_idle_transaction() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Arc::new(Store::connect(&url, None).unwrap());
    seed_volume(&store, &unowned_volume());
    let observer = Store::connect(&url, None).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_store = Arc::clone(&store);
    let task = tokio::spawn(async move {
        worker_store
            .execute(move |store| {
                store.authority_transaction::<()>(move |transaction| {
                    let pid: i32 = transaction
                        .query_one("SELECT pg_backend_pid()", &[])?
                        .try_get(0)?;
                    load_volume_for_update(transaction, &id("volume-1"))?.unwrap();
                    locked_tx.send(pid).unwrap();
                    release_rx.recv().unwrap();
                    Err(AuthorityTransactionError::Domain(
                        cats_storage::authority::AuthorityError::InvalidAuthorization,
                    ))
                })
            })
            .await
    });
    let pid = tokio::task::spawn_blocking(move || locked_rx.recv().unwrap())
        .await
        .unwrap();
    task.abort();
    release_tx.send(()).unwrap();

    let mut released = false;
    for _ in 0..200 {
        let lock_is_free = observer
            .with(|client| {
                client
                    .query_opt(
                        "SELECT volume_id FROM volume_records
                          WHERE volume_id='volume-1' FOR UPDATE NOWAIT",
                        &[],
                    )
                    .map(|_| ())
            })
            .is_ok();
        let state = observer
            .with(|client| {
                client
                    .query_opt("SELECT state FROM pg_stat_activity WHERE pid=$1", &[&pid])
                    .map(|row| row.map(|row| row.get::<_, String>(0)))
            })
            .unwrap();
        if lock_is_free && state.as_deref().is_none_or(|value| value == "idle") {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        released,
        "cancelled call retained a lock or idle transaction"
    );
}

#[test]
fn authority_metrics_have_only_fixed_low_cardinality_labels() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let mut body = String::new();
    metrics_snapshot(&store).append_prometheus(&mut body);
    for label in [
        "outcome=\"committed\"",
        "outcome=\"domain_rejected\"",
        "outcome=\"backend_failed\"",
        "reason=\"serialization\"",
        "reason=\"deadlock\"",
        "reason=\"connection\"",
    ] {
        assert!(
            body.contains(label),
            "missing fixed authority label {label}"
        );
    }
    assert!(!body.contains("volume-1"));
    assert!(!body.contains("takeover-auth-1"));
}

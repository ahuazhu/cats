use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    decode_runtime_checkpoint, encode_desired_runtime_spec, guest_config_digest, inventory_digest,
    residue_acquisition_digest, spec_digest, AcquireOrigin, AgentRegistrationAttempt, AgentSession,
    AppliedDesiredEvidence, AsciiText as RuntimeAsciiText, AssignedKind, AssignedPlacement,
    AuthorizedServingAcquire, CheckpointEvidence, CleanupRelease, CleanupTarget,
    ContractErrorDetail, ContractVersion, ControlHandshakeEvidence, CredentialBinding,
    DesiredReadRequest, DesiredRuntimeSpec, DiskKind, Ext4MountIntent, FilesystemInitialization,
    GuestDeviceIdentity, GuestRuntimeProfileReceipt, GuestTransportEvidence, HostPath, Ipv4Address,
    IsolatedIpv4Kind, LifecycleAdmission, LocalLineageState, LocalVolumeLineage, MacAddress,
    MountAccess, NetworkConfig, NodeBootId, NodeIdentity, NodeIdentityState, NodeObservation,
    NodeResidue, ObservedDevice, ObservedDiskKind, ObservedMount, ObservedRuntimeStatus,
    ObservedVolume, Operation, OperationPhase, OwnershipTokenEvidence, PersistentFilesystemBinding,
    ProcessEvidence, ProcessRole, ProcessState, ReconcileStep, ResidueAuthorityRetentionReason,
    ResidueDataDirectoryLineage, ResidueReclaimProof, RuntimeCheckpoint, RuntimeConfig,
    RuntimeResidueAuthorityOutcome, RuntimeResidueAuthorityRequest, RuntimeTarget,
    RuntimeTransition, RuntimeVolumeAuthorizationRejection, RuntimeVolumeTransition,
    RuntimeVolumeTransitionEvidenceRequest, RuntimeVolumeTransitionOutcome,
    RuntimeVolumeTransitionPreconditionProblem, RuntimeVolumeTransitionRequest, Sequence,
    SessionBinding, VolumeAccess, VolumeAcquire, VolumeAcquireRequest, VolumeAuthorityEvidence,
    VolumeDisposition, VolumeIntent, VolumeReleaseReplay, WarmSnapshotEvidence, WireU64,
};
use cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot;
use cats_storage::authority::{
    complete_disposable_root_delete, consume_disposable_root_delete, normal_acquire, AsciiText,
    AuthorityError, AuthorizationConsumedReceipt, AuthorizationRecord, AuthorizationState,
    DeleteCompletionReceipt, DisposableDeleteIsolationBasis, DisposableRootDeleteAuthorization,
    Epoch, FenceEpoch, Generation, HostFenceEvent, HostFenceEventState, HostIsolationState, Id,
    NormalAcquireRequest, NormalAcquireResult, RandomId128, ReleaseRequest, RemoteHead, Revision,
    Sha256Digest, TakeoverConsumedReceipt, UnixMillis, VolumeAdminState, VolumeAuthorization,
    VolumeDurability, VolumeOwnerBinding, VolumeRecord, VolumeTakeoverAuthorization,
};

use super::product::{
    CatRecord, DiskAdminState, DiskRecord, DiskRole, DiskSnapshotRecord,
    PersistentDiskInitialization,
};
use super::product_rows::{
    insert_cat, insert_desired, insert_disk, insert_disk_snapshot, insert_operation,
    load_desired_for_update, load_disk_by_id_for_update,
};
use super::residue_authority::load_runtime_residue_authority_in;
use super::rows::{
    database_now, disposable_root_authorization_candidates_sql, insert_authorization,
    insert_delete_completion, insert_event, insert_volume, load_active_event_by_node_unlocked,
    load_authorization_for_update, load_delete_completion_for_update, load_event_for_update,
    load_stored_volume_for_update, load_volume_for_update, update_authorization, update_event,
    update_volume_owner, volume_has_disposable_root_authorization_for_delete,
};
use super::runtime_spine::{
    age_volume_mutation_admission_for_test, PlacementAdmissionLoad, PlacementAdmissionRejection,
    RuntimeSpineOutcome,
};
use super::volume_transition_auth::{
    authenticate_evidence_context_in, release_disposition_matches_current,
    RuntimeTakeoverConsumeRequest, VolumeTransitionStoreOutcome, VolumeTransitionStoreRejection,
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

fn commit_initialized_checkpoint(
    desired: &DesiredRuntimeSpec,
    root_volume: &VolumeRecord,
    persistent_volume: &VolumeRecord,
    filesystem: &PersistentFilesystemBinding,
) -> RuntimeCheckpoint {
    let root = &desired.volumes[0];
    let persistent = &desired.volumes[1];
    let runtime_incarnation = filesystem.runtime_incarnation.clone();
    let vmm_scope = format!("cats-vmm-{}.service", runtime_incarnation.as_str());
    let root_process_token = random_id(6_001);
    let root_device_token = random_id(6_002);
    let persistent_process_token = random_id(6_003);
    let persistent_device_token = random_id(6_004);
    let vmm_token = random_id(6_005);
    let network_token = random_id(6_006);
    let socket_root = ManagedBlockdSocketRoot::installed();
    let root_sockets = socket_root.serving_paths(&root_device_token).unwrap();
    let persistent_sockets = socket_root.serving_paths(&persistent_device_token).unwrap();
    let origin = |intent: &VolumeIntent| match &intent.acquire {
        VolumeAcquire::Normal { transition_id, .. } => serde_json::json!({
            "kind": "normal",
            "transition_id": transition_id,
        }),
        VolumeAcquire::Takeover { authorization_id } => serde_json::json!({
            "kind": "takeover",
            "authorization_id": authorization_id,
        }),
    };
    let artifact = |path: &str, length: u64, digest: Sha256Digest| {
        serde_json::json!({
            "path": path,
            "length": length,
            "content_sha256": digest,
        })
    };
    let root_device = serde_json::json!({
        "volume_intent_id": root.volume_intent_id,
        "disk_id": root.disk_id,
        "volume_id": root.volume_id,
        "disk_kind": "root",
        "attachment_id": root.attachment_id,
        "attachment_epoch": root_volume.lease_epoch,
        "acquire_origin": origin(root),
        "expected_head": root_volume.head,
        "size_bytes": root.size_bytes,
        "durability": root.durability,
        "guest_device": root.guest_device,
        "ownership_token": root_device_token,
        "serving_authority": {
            "kind": "direct_authorized_attachment",
            "authorization": {
                "path": "/var/lib/cats/attachments/root.json",
                "device": 1,
                "inode": 11,
                "length": 512,
                "content_sha256": Sha256Digest::from_bytes([11; 32]),
            },
            "purpose": "existing_root",
        },
        "serving_process": {
            "scope_id": "cats-root-serving",
            "control_socket_path": root_sockets.control_socket(),
            "data_directory": "/var/lib/cats/volumes/root",
            "executable_path": "/usr/bin/cats-blockd",
            "process_identity_token": root_process_token,
        },
        "frontend": {
            "kind": "vhost_user_blk",
            "socket_path": root_sockets.io_socket(),
            "queues": 1,
            "queue_size": 256,
        },
    });
    let expected_blank_head = match &filesystem.initialization {
        FilesystemInitialization::Initialize {
            expected_blank_head,
            ..
        } => expected_blank_head,
        FilesystemInitialization::Existing => {
            panic!("commit_initialized fixture requires Initialize")
        }
    };
    let persistent_device = serde_json::json!({
        "volume_intent_id": persistent.volume_intent_id,
        "disk_id": persistent.disk_id,
        "volume_id": persistent.volume_id,
        "disk_kind": "persistent",
        "attachment_id": persistent.attachment_id,
        "attachment_epoch": persistent_volume.lease_epoch,
        "acquire_origin": origin(persistent),
        "expected_head": expected_blank_head,
        "size_bytes": persistent.size_bytes,
        "durability": persistent.durability,
        "guest_device": persistent.guest_device,
        "ownership_token": persistent_device_token,
        "serving_authority": {
            "kind": "direct_authorized_attachment",
            "authorization": {
                "path": "/var/lib/cats/attachments/data.json",
                "device": 1,
                "inode": 12,
                "length": 512,
                "content_sha256": Sha256Digest::from_bytes([12; 32]),
            },
            "purpose": "persistent_uninitialized",
        },
        "serving_process": {
            "scope_id": "cats-data-serving",
            "control_socket_path": persistent_sockets.control_socket(),
            "data_directory": "/var/lib/cats/volumes/data",
            "executable_path": "/usr/bin/cats-blockd",
            "process_identity_token": persistent_process_token,
        },
        "frontend": {
            "kind": "vhost_user_blk",
            "socket_path": persistent_sockets.io_socket(),
            "queues": 1,
            "queue_size": 256,
        },
    });
    let observed_process = |volume_id: &Id,
                            attachment_id: &Id,
                            attachment_epoch: FenceEpoch,
                            scope_id: &str,
                            socket: &str,
                            token: &RandomId128,
                            process_id: u32| {
        serde_json::json!({
            "role": {
                "kind": "blockd",
                "volume_id": volume_id,
                "attachment_id": attachment_id,
                "attachment_epoch": attachment_epoch,
            },
            "process_id": process_id,
            "process_start_time_ticks": u64::from(process_id) + 1_000,
            "executable_path": "/usr/bin/cats-blockd",
            "scope_id": scope_id,
            "control_socket_path": socket,
            "state": "running",
            "ownership_token": {"kind": "valid", "ownership_token": token},
            "control_handshake": {"kind": "verified"},
            "observed_vm_shape": null,
        })
    };
    let observed_volume = |intent: &VolumeIntent,
                           volume: &VolumeRecord,
                           disk_kind: &str,
                           data_directory: &str,
                           socket: &str,
                           token: &RandomId128| {
        serde_json::json!({
            "volume_intent_id": intent.volume_intent_id,
            "disk_id": intent.disk_id,
            "volume_id": intent.volume_id,
            "disk_kind": disk_kind,
            "size_bytes": intent.size_bytes,
            "durability": intent.durability,
            "authority": {
                "kind": "owned",
                "attachment_id": intent.attachment_id,
                "attachment_epoch": volume.lease_epoch,
                "head": volume.head,
            },
            "local_lineages": [{
                "attachment_id": intent.attachment_id,
                "attachment_epoch": volume.lease_epoch,
                "acquire_origin": origin(intent),
                "node_id": desired.placement.node_id,
                "placement_epoch": desired.placement.placement_epoch,
                "local_durable_generation": volume.head.generation,
                "remote_durable_generation": volume.head.generation,
                "data_directory": data_directory,
                "pending_pack_count": 0,
                "fenced": false,
                "state": "active",
            }],
            "devices": [{
                "kind": "vhost_user_blk",
                "guest_device": intent.guest_device,
                "socket_path": socket,
                "ownership_token": {"kind": "valid", "ownership_token": token},
            }],
        })
    };
    let filesystem_step = serde_json::json!({
        "kind": "commit_initialized",
        "filesystem": filesystem,
        "new_remote_head": persistent_volume.head,
    });
    let network = serde_json::json!({
        "network_config": desired.runtime.network_config,
        "tap_name": "cats0001",
        "ownership_token": network_token,
    });
    let checkpoint = serde_json::json!({
        "version": 1,
        "cat_id": desired.cat_id,
        "node_id": desired.placement.node_id,
        "placement_epoch": desired.placement.placement_epoch,
        "desired_revision": desired.desired_revision,
        "spec_digest": desired.spec_digest,
        "runtime_incarnation": runtime_incarnation,
        "runtime_launch": {
            "kind": "present",
            "identity": {
                "runtime_incarnation": filesystem.runtime_incarnation,
                "scope_id": vmm_scope,
                "launcher_executable": artifact(
                    "/usr/libexec/cats-vmm-launcher",
                    1_024,
                    Sha256Digest::from_bytes([3; 32]),
                ),
                "boot": {
                    "vmm_executable": artifact(
                        "/usr/bin/cloud-hypervisor",
                        2_048,
                        Sha256Digest::from_bytes([4; 32]),
                    ),
                    "kernel": artifact(
                        "/opt/cats/guest/vmlinuz",
                        4_096,
                        Sha256Digest::from_bytes([1; 32]),
                    ),
                    "initramfs": artifact(
                        "/opt/cats/guest/initramfs.img",
                        4_096,
                        Sha256Digest::from_bytes([2; 32]),
                    ),
                    "kernel_cmdline": "console=hvc0 root=/dev/vda",
                },
                "process_identity_token": vmm_token,
                "vcpus": desired.runtime.vcpus,
                "memory_bytes": desired.runtime.memory_bytes,
                "boot_image_digest": desired.runtime.boot_image_digest,
                "guest_config_digest": desired.runtime.guest_config_digest,
                "api_socket_path": "/run/cats/vmm-api.sock",
                "vsock_socket_path": "/run/cats/vmm-vsock.sock",
                "guest_cid": 3,
                "memory_file_path": "/var/lib/cats/runtime-memory.bin",
                "serial_log_path": "/var/log/cats/runtime-serial.log",
                "vmm_log_path": "/var/log/cats/runtime-vmm.log",
                "network": network,
                "devices": [root_device, persistent_device],
            },
        },
        "stable_state": null,
        "step": filesystem_step,
        "processes": [{
            "role": {"kind": "vmm", "runtime_incarnation": filesystem.runtime_incarnation},
            "process_id": 7_001,
            "process_start_time_ticks": 8_001,
            "executable_path": "/usr/bin/cloud-hypervisor",
            "scope_id": vmm_scope,
            "control_socket_path": "/run/cats/vmm-api.sock",
            "state": "running",
            "ownership_token": {"kind": "valid", "ownership_token": vmm_token},
            "control_handshake": {"kind": "verified"},
            "observed_vm_shape": {
                "vcpus": desired.runtime.vcpus,
                "memory_bytes": desired.runtime.memory_bytes,
                "boot_image_digest": desired.runtime.boot_image_digest,
                "guest_config_digest": desired.runtime.guest_config_digest,
            },
        }, observed_process(
            &persistent.volume_id,
            &persistent.attachment_id,
            persistent_volume.lease_epoch,
            "cats-data-serving",
            persistent_sockets.control_socket().as_str(),
            &persistent_process_token,
            7_003,
        ), observed_process(
            &root.volume_id,
            &root.attachment_id,
            root_volume.lease_epoch,
            "cats-root-serving",
            root_sockets.control_socket().as_str(),
            &root_process_token,
            7_002,
        )],
        "volumes": [observed_volume(
            persistent,
            persistent_volume,
            "persistent",
            "/var/lib/cats/volumes/data",
            persistent_sockets.io_socket().as_str(),
            &persistent_device_token,
        ), observed_volume(
            root,
            root_volume,
            "root",
            "/var/lib/cats/volumes/root",
            root_sockets.io_socket().as_str(),
            &root_device_token,
        )],
        "mounts": [],
        "networks": [{
            "kind": "isolated_ipv4",
            "network_id": desired.runtime.network_config.network_id,
            "guest_mac": desired.runtime.network_config.guest_mac,
            "guest_ipv4": desired.runtime.network_config.guest_ipv4,
            "prefix_length": desired.runtime.network_config.prefix_length,
            "gateway_ipv4": desired.runtime.network_config.gateway_ipv4,
            "tap_name": "cats0001",
            "ownership_token": {"kind": "valid", "ownership_token": network_token},
        }],
        "guest_transport": {
            "kind": "vsock_ready",
            "runtime_incarnation": filesystem.runtime_incarnation,
            "guest_cid": 3,
            "guest_port": 5_000,
            "guest_agent_protocol_version": 1,
            "guest_boot_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        },
        "warm_snapshot": {"kind": "absent"},
        "lifecycle_admission": "closed",
        "route_gates": [],
        "require_idle": {"kind": "not_applicable"},
        "updated_at_unix_ms": 1,
    });
    let checkpoint = decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    let launch = checkpoint
        .runtime_launch
        .identity()
        .expect("commit_initialized fixture retains one VMM launch");
    for (device_token, volume_id, control_socket, io_socket) in [
        (
            &root_device_token,
            &root.volume_id,
            root_sockets.control_socket(),
            root_sockets.io_socket(),
        ),
        (
            &persistent_device_token,
            &persistent.volume_id,
            persistent_sockets.control_socket(),
            persistent_sockets.io_socket(),
        ),
    ] {
        let device = launch
            .devices
            .iter()
            .find(|device| &device.ownership_token == device_token)
            .expect("fixture launch retains the mapped device owner");
        assert_eq!(device.serving_process.control_socket_path, *control_socket);
        let cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk {
            socket_path,
            ..
        } = &device.frontend
        else {
            panic!("commit_initialized fixture device must be vhost-user-blk")
        };
        assert_eq!(socket_path, io_socket);

        let process = checkpoint
            .processes
            .iter()
            .find(|process| {
                matches!(
                    &process.role,
                    ProcessRole::Blockd {
                        volume_id: observed,
                        ..
                    } if observed == volume_id
                )
            })
            .expect("fixture observes the mapped serving process");
        assert_eq!(process.control_socket_path, *control_socket);

        let observed_device = checkpoint
            .volumes
            .iter()
            .find(|volume| &volume.volume_id == volume_id)
            .and_then(|volume| {
                volume.devices.iter().find(|device| {
                    matches!(
                        device,
                        ObservedDevice::VhostUserBlk {
                            ownership_token: OwnershipTokenEvidence::Valid { ownership_token },
                            ..
                        } if ownership_token == device_token
                    )
                })
            })
            .expect("fixture observes the mapped vhost-user device");
        let ObservedDevice::VhostUserBlk { socket_path, .. } = observed_device else {
            unreachable!()
        };
        assert_eq!(socket_path, io_socket);
    }
    checkpoint
}

fn commit_initialized_runtime_status(checkpoint: &RuntimeCheckpoint) -> ObservedRuntimeStatus {
    ObservedRuntimeStatus {
        cat_id: checkpoint.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: checkpoint.node_id.clone(),
                placement_epoch: checkpoint.placement_epoch,
            },
            target: RuntimeTarget::Running,
        }),
        runtime_incarnation: checkpoint.runtime_incarnation.clone(),
        stable_state: checkpoint.stable_state,
        step: checkpoint.step.clone(),
        checkpoint: CheckpointEvidence::Valid {
            checkpoint_path: HostPath::new("/var/lib/cats/checkpoints/cat-1.json").unwrap(),
            content_digest: Sha256Digest::from_bytes([77; 32]),
            version: checkpoint.version,
            cat_id: checkpoint.cat_id.clone(),
            node_id: checkpoint.node_id.clone(),
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            placement_epoch: checkpoint.placement_epoch,
            runtime_incarnation: checkpoint.runtime_incarnation.clone(),
            runtime_launch: Box::new(checkpoint.runtime_launch.clone()),
            stable_state: checkpoint.stable_state,
            step: Box::new(checkpoint.step.clone()),
            require_idle: Box::new(checkpoint.require_idle.clone()),
            updated_at_unix_ms: checkpoint.updated_at_unix_ms,
        },
        processes: checkpoint.processes.clone(),
        volumes: checkpoint.volumes.clone(),
        mounts: checkpoint.mounts.clone(),
        networks: checkpoint.networks.clone(),
        guest_transport: checkpoint.guest_transport.clone(),
        warm_snapshot: checkpoint.warm_snapshot.clone(),
        lifecycle_admission: checkpoint.lifecycle_admission,
        routes: Vec::new(),
        platform_guards: 0,
        conditions: Vec::new(),
    }
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

fn observed_unowned_volume(desired: &DesiredRuntimeSpec, volume: &VolumeRecord) -> ObservedVolume {
    let intent = desired.volumes.first().unwrap();
    ObservedVolume {
        volume_intent_id: Some(intent.volume_intent_id.clone()),
        disk_id: Some(intent.disk_id.clone()),
        volume_id: intent.volume_id.clone(),
        disk_kind: match intent.disk_kind {
            DiskKind::Root => ObservedDiskKind::Root,
            DiskKind::Persistent => ObservedDiskKind::Persistent,
        },
        size_bytes: Some(intent.size_bytes),
        durability: Some(intent.durability),
        authority: VolumeAuthorityEvidence::Unowned {
            attachment_epoch: volume.lease_epoch,
            head: volume.head.clone(),
        },
        local_lineages: Vec::new(),
        devices: Vec::new(),
    }
}

fn observed_blockd_process(
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: FenceEpoch,
    suffix: u32,
) -> ProcessEvidence {
    ProcessEvidence {
        role: ProcessRole::Blockd {
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch,
        },
        process_id: 4_000 + suffix,
        process_start_time_ticks: WireU64::new(u64::from(9_000 + suffix)).unwrap(),
        executable_path: cats_api::runtime_reconciliation::HostPath::new("/usr/bin/cats-blockd")
            .unwrap(),
        scope_id: id(&format!("cats-blockd-{suffix}")),
        control_socket_path: cats_api::runtime_reconciliation::HostPath::new(format!(
            "/run/cats/blockd-{suffix}.sock"
        ))
        .unwrap(),
        state: ProcessState::Running,
        ownership_token: OwnershipTokenEvidence::Valid {
            ownership_token: random_id(u128::from(4_000 + suffix)),
        },
        control_handshake: ControlHandshakeEvidence::Verified,
        observed_vm_shape: None,
    }
}

fn observed_mount(volume_id: &Id) -> ObservedMount {
    ObservedMount {
        volume_id: volume_id.clone(),
        guest_device: GuestDeviceIdentity {
            serial: id("foreign-root-device"),
            slot: 0,
        },
        source_path: cats_api::runtime_reconciliation::HostPath::new("/dev/foreign-volume")
            .unwrap(),
        filesystem_uuid: random_id(7_001),
        mount_path: cats_api::runtime_reconciliation::HostPath::new("/mnt/foreign-volume").unwrap(),
        access: MountAccess::ReadWrite,
        instance_count: 1,
    }
}

fn orphan_runtime_with_volume_evidence(
    template: &ObservedRuntimeStatus,
    volumes: Vec<ObservedVolume>,
    processes: Vec<ProcessEvidence>,
) -> ObservedRuntimeStatus {
    let mut orphan = template.clone();
    orphan.cat_id = id("cat-orphan");
    orphan.applied_desired = None;
    orphan.runtime_incarnation = None;
    orphan.stable_state = None;
    orphan.checkpoint = CheckpointEvidence::Missing {
        checkpoint_path: cats_api::runtime_reconciliation::HostPath::new(
            "/var/lib/cats/runtime/cat-orphan.json",
        )
        .unwrap(),
    };
    orphan.processes = processes;
    orphan.volumes = volumes;
    orphan.mounts.clear();
    orphan.networks.clear();
    orphan.routes.clear();
    orphan
}

fn prepare_a22_runtime(
    store: &Store,
    node: &TransitionNode,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeRecord,
    runtime: ObservedRuntimeStatus,
    operation_required: bool,
) -> super::runtime_spine::PlacementAdmissionSnapshot {
    prepare_a22_runtime_with_inventory(
        store,
        node,
        desired,
        volume,
        vec![runtime],
        Vec::new(),
        operation_required,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the full-inventory fixture keeps every accepted authority source explicit"
)]
fn prepare_a22_runtime_with_inventory(
    store: &Store,
    node: &TransitionNode,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeRecord,
    runtimes: Vec<ObservedRuntimeStatus>,
    residue: Vec<NodeResidue>,
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
        runtimes,
        residue,
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

fn release_transition_request(
    node: &TransitionNode,
    desired: &DesiredRuntimeSpec,
    admission: &super::runtime_spine::PlacementAdmissionSnapshot,
    volume: &VolumeRecord,
    disposition: VolumeDisposition,
) -> RuntimeVolumeTransitionRequest {
    transition_request(
        node,
        desired,
        RuntimeVolumeTransition::Release {
            cleanup: CleanupRelease {
                target: CleanupTarget::Volume {
                    volume_id: volume.volume_id.clone(),
                    attachment_id: volume.lease_owner.clone().unwrap(),
                    attachment_epoch: volume.lease_epoch,
                },
                inventory_session: node.session.clone(),
                inventory_epoch: admission.inventory_attestation.inventory_epoch,
                inventory_read_position: admission.inventory_attestation.inventory_read_position,
                desired_read_position: admission.desired_read_position,
                volume_release: Some(VolumeReleaseReplay {
                    release_transition_id: random_id(2),
                    generation: volume.head.generation,
                    disposition,
                }),
            },
        },
    )
}

fn prepare_root_delete_release_fixture(
    store: &Store,
    volume: &VolumeRecord,
) -> (
    TransitionNode,
    DesiredRuntimeSpec,
    super::runtime_spine::PlacementAdmissionSnapshot,
    RuntimeVolumeTransitionRequest,
) {
    let node = transition_node(store, "node-new");
    let workspace = super::product_tests::bootstrap_workspace(store, "a22-root-release");
    let desired = transition_desired(
        &workspace,
        &node,
        volume,
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
        volume,
        cats_api::runtime_reconciliation::AcquireOrigin::Normal {
            transition_id: random_id(1),
        },
        volume.head.generation,
        volume.head.generation,
    );
    let admission = prepare_a22_runtime(
        store,
        &node,
        &desired,
        volume,
        observed_runtime_with_volumes(&desired, None, vec![observed]),
        true,
    );
    let request = release_transition_request(
        &node,
        &desired,
        &admission,
        volume,
        VolumeDisposition::DeleteDisposableRoot {
            delete_id: id("delete-1"),
        },
    );
    (node, desired, admission, request)
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

#[test]
fn a22_release_target_disk_kind_and_disposition_matrix_is_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let node = transition_node(&store, "node-new");
    let volume = unowned_volume();
    let workspace = id("workspace-matrix");
    let base = transition_desired(
        &workspace,
        &node,
        &volume,
        RuntimeTarget::Cold,
        revision(1),
        epoch(1),
        id("attachment-matrix"),
        VolumeAcquire::Normal {
            transition_id: random_id(1),
            expected_unowned_epoch: volume.lease_epoch,
        },
        VolumeDisposition::Retain,
    );
    for target in [
        RuntimeTarget::Running,
        RuntimeTarget::Suspended,
        RuntimeTarget::Warm,
        RuntimeTarget::Cold,
        RuntimeTarget::Deleted,
    ] {
        for disk_kind in [DiskKind::Root, DiskKind::Persistent] {
            for disposition in [
                VolumeDisposition::Retain,
                VolumeDisposition::DetachRetained,
                VolumeDisposition::DeleteDisposableRoot {
                    delete_id: id("delete-matrix"),
                },
            ] {
                let mut desired = base.clone();
                desired.target = target;
                desired.volumes[0].disk_kind = disk_kind;
                desired.volumes[0].disposition = disposition.clone();
                let expected = matches!(
                    (target, disk_kind, &disposition),
                    (
                        RuntimeTarget::Cold,
                        DiskKind::Root | DiskKind::Persistent,
                        VolumeDisposition::Retain,
                    ) | (
                        RuntimeTarget::Deleted,
                        DiskKind::Persistent,
                        VolumeDisposition::DetachRetained,
                    ) | (
                        RuntimeTarget::Deleted,
                        DiskKind::Root,
                        VolumeDisposition::DeleteDisposableRoot { .. },
                    )
                );
                assert_eq!(
                    release_disposition_matches_current(&desired, &desired.volumes[0]),
                    expected,
                    "unexpected release matrix decision for {target:?}/{disk_kind:?}/{disposition:?}"
                );
            }
        }
    }
}

fn normal_acquire_fixture(
    store: &Store,
    workspace_suffix: &str,
) -> (
    VolumeRecord,
    TransitionNode,
    DesiredRuntimeSpec,
    RuntimeVolumeTransitionRequest,
) {
    let volume = unowned_volume();
    seed_volume(store, &volume);
    let node = transition_node(store, "node-new");
    let workspace = super::product_tests::bootstrap_workspace(store, workspace_suffix);
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
        observed_runtime_with_volumes(
            &desired,
            None,
            vec![observed_unowned_volume(&desired, &volume)],
        ),
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
    (volume, node, desired, request)
}

fn blank_commit_volume(volume_id: &str) -> VolumeRecord {
    VolumeRecord {
        volume_id: id(volume_id),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: head(0),
        lease_owner: None,
        lease_epoch: fence_epoch(0),
        lease_expires_at: None,
        last_transition: None,
    }
}

fn acquire_commit_volume(
    blank: &VolumeRecord,
    attachment_id: &Id,
    transition_id: &RandomId128,
) -> VolumeRecord {
    let (mut owned, _) = normal_acquire(
        blank,
        &NormalAcquireRequest {
            volume_id: blank.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: attachment_id.clone(),
            expected_unowned_epoch: blank.lease_epoch,
            desired_revision: revision(11),
            placement_epoch: epoch(3),
            lease_duration_ms: 30_000,
        },
        unix_millis(1_000),
    )
    .unwrap();
    owned.head = head(1);
    owned
}

fn commit_initialized_fixture(
    store: &Store,
    workspace_suffix: &str,
) -> (
    TransitionNode,
    DesiredRuntimeSpec,
    RuntimeVolumeTransitionRequest,
    PersistentFilesystemBinding,
    VolumeRecord,
) {
    let node = transition_node(store, "node-new");
    let workspace = super::product_tests::bootstrap_workspace(store, workspace_suffix);
    let root_blank = blank_commit_volume("volume-root");
    let persistent_blank = blank_commit_volume("volume-data");
    let root_transition = random_id(8_001);
    let persistent_transition = random_id(8_002);
    let root_attachment = id("attachment-root");
    let persistent_attachment = id("attachment-data");
    let root_volume = acquire_commit_volume(&root_blank, &root_attachment, &root_transition);
    let persistent_volume = acquire_commit_volume(
        &persistent_blank,
        &persistent_attachment,
        &persistent_transition,
    );
    let initialization_token = random_id(8_003);
    let filesystem_uuid = random_id(8_004);

    let mut desired = transition_desired(
        &workspace,
        &node,
        &root_volume,
        RuntimeTarget::Running,
        revision(11),
        epoch(3),
        root_attachment.clone(),
        VolumeAcquire::Normal {
            transition_id: root_transition,
            expected_unowned_epoch: root_blank.lease_epoch,
        },
        VolumeDisposition::Retain,
    );
    desired.volumes[0].volume_intent_id = id("intent-a-root");
    desired.volumes[0].disk_id = id("disk-root");
    desired.volumes[0].guest_device.serial = id("cats-root");
    desired.volumes.push(VolumeIntent {
        volume_intent_id: id("intent-z-data"),
        disk_id: id("disk-data"),
        volume_id: persistent_volume.volume_id.clone(),
        attachment_id: persistent_attachment.clone(),
        size_bytes: persistent_volume.size_bytes,
        disk_kind: DiskKind::Persistent,
        access: VolumeAccess::ReadWriteOnce,
        durability: persistent_volume.durability,
        guest_device: GuestDeviceIdentity {
            serial: id("cats-data"),
            slot: 1,
        },
        acquire: VolumeAcquire::Normal {
            transition_id: persistent_transition,
            expected_unowned_epoch: persistent_blank.lease_epoch,
        },
        disposition: VolumeDisposition::Retain,
        mount: Some(Ext4MountIntent {
            filesystem_uuid: filesystem_uuid.clone(),
            mount_path: HostPath::new("/data").unwrap(),
            initialization: FilesystemInitialization::Initialize {
                initialization_token: initialization_token.clone(),
                expected_blank_head: persistent_blank.head.clone(),
            },
        }),
    });
    desired.spec_digest = spec_digest(&desired).unwrap();
    let filesystem = PersistentFilesystemBinding {
        runtime_incarnation: random_id(8_005),
        volume_intent_id: id("intent-z-data"),
        disk_id: id("disk-data"),
        volume_id: persistent_volume.volume_id.clone(),
        attachment_id: persistent_attachment.clone(),
        attachment_epoch: persistent_volume.lease_epoch,
        size_bytes: persistent_volume.size_bytes,
        guest_device: GuestDeviceIdentity {
            serial: id("cats-data"),
            slot: 1,
        },
        filesystem_uuid: filesystem_uuid.clone(),
        mount_path: HostPath::new("/data").unwrap(),
        initialization: FilesystemInitialization::Initialize {
            initialization_token: initialization_token.clone(),
            expected_blank_head: persistent_blank.head.clone(),
        },
    };
    let checkpoint =
        commit_initialized_checkpoint(&desired, &root_volume, &persistent_volume, &filesystem);
    let runtime = commit_initialized_runtime_status(&checkpoint);

    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_volume(transaction, &root_blank)?;
            update_volume_owner(
                transaction,
                &root_volume,
                Some(&VolumeOwnerBinding {
                    volume_id: root_volume.volume_id.clone(),
                    owner_node_id: node.session.node_id.clone(),
                    attachment_id: root_attachment.clone(),
                    attachment_epoch: root_volume.lease_epoch,
                }),
            )?;
            insert_volume(transaction, &persistent_blank)?;
            update_volume_owner(
                transaction,
                &persistent_volume,
                Some(&VolumeOwnerBinding {
                    volume_id: persistent_volume.volume_id.clone(),
                    owner_node_id: node.session.node_id.clone(),
                    attachment_id: persistent_attachment.clone(),
                    attachment_epoch: persistent_volume.lease_epoch,
                }),
            )?;
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
                    disk_id: id("disk-root"),
                    workspace_id: workspace.clone(),
                    name: id("disk-root"),
                    volume_id: root_volume.volume_id.clone(),
                    size_bytes: root_volume.size_bytes,
                    durability: root_volume.durability,
                    created_at: now,
                    admin_state: DiskAdminState::Active,
                    role: DiskRole::Root {
                        cat_id: desired.cat_id.clone(),
                    },
                },
            )?;
            insert_disk(
                transaction,
                &DiskRecord {
                    disk_id: id("disk-data"),
                    workspace_id: workspace.clone(),
                    name: id("disk-data"),
                    volume_id: persistent_volume.volume_id.clone(),
                    size_bytes: persistent_volume.size_bytes,
                    durability: persistent_volume.durability,
                    created_at: now,
                    admin_state: DiskAdminState::Active,
                    role: DiskRole::Persistent {
                        initialization: Box::new(PersistentDiskInitialization::Uninitialized {
                            initialization_token: initialization_token.clone(),
                            filesystem_uuid: filesystem_uuid.clone(),
                            expected_blank_head: persistent_blank.head.clone(),
                        }),
                    },
                },
            )?;
            insert_desired(transaction, &desired)
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
            panic!("commit_initialized Desired read rejected: {rejection:?}")
        }
    };
    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: random_id(8_006),
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
            panic!("commit_initialized observation rejected: {rejection:?}")
        }
    }

    let request = transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::CommitInitialized {
            filesystem: Box::new(filesystem.clone()),
            new_remote_head: persistent_volume.head.clone(),
        },
    );
    (node, desired, request, filesystem, persistent_volume)
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
        observed_runtime_with_volumes(
            &desired,
            None,
            vec![observed_unowned_volume(&desired, &volume)],
        ),
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

fn residue_authority_request(
    node: &TransitionNode,
    desired: &DesiredRuntimeSpec,
    local_generation: u64,
    remote_generation: u64,
) -> RuntimeResidueAuthorityRequest {
    let transition_id = random_id(1);
    let acquisition = AuthorizedServingAcquire::Normal {
        request: acquire_request(1, "attachment-old", 7),
        result: NormalAcquireResult {
            volume_id: id("volume-1"),
            transition_id: transition_id.clone(),
            attachment_id: id("attachment-old"),
            resulting_epoch: fence_epoch(8),
            resulting_head: head(4),
            lease_expires_at: unix_millis(40_000),
        },
    };
    RuntimeResidueAuthorityRequest {
        version: ContractVersion::V1,
        session: node.session.clone(),
        lineage: ResidueDataDirectoryLineage {
            workspace_id: desired.workspace_id.clone(),
            cat_id: id("cat-1"),
            disk_id: id("disk-1"),
            disk_kind: DiskKind::Root,
            volume_id: id("volume-1"),
            attachment_id: id("attachment-old"),
            attachment_epoch: fence_epoch(8),
            acquire_origin: AcquireOrigin::Normal { transition_id },
            node_id: node.session.node_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            placement_epoch: epoch(3),
            acquisition_digest: residue_acquisition_digest(&acquisition).unwrap(),
            acquisition,
            local_durable_generation: generation(local_generation),
            remote_durable_generation: generation(remote_generation),
            remote_head: head(remote_generation),
            pending_pack_count: WireU64::new(local_generation.saturating_sub(remote_generation))
                .unwrap(),
            fenced: true,
        },
    }
}

fn prepare_residue_product_snapshot(
    store: &Store,
    node: &TransitionNode,
    volume: &VolumeRecord,
    desired_revision: Revision,
    placement_epoch: Epoch,
) -> DesiredRuntimeSpec {
    let workspace = super::product_tests::bootstrap_workspace(store, "residue-authority");
    let desired = transition_desired(
        &workspace,
        node,
        volume,
        RuntimeTarget::Running,
        desired_revision,
        placement_epoch,
        id("attachment-old"),
        VolumeAcquire::Normal {
            transition_id: random_id(1),
            expected_unowned_epoch: fence_epoch(7),
        },
        VolumeDisposition::Retain,
    );
    store
        .authority_transaction(|transaction| {
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
    desired
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
            insert_authorization(transaction, authorization)?;
            let VolumeAuthorization::Takeover(payload) = &authorization.authorization else {
                panic!("takeover fixture requires a takeover authorization")
            };
            let stored = load_stored_volume_for_update(transaction, &payload.volume_id)?.unwrap();
            let owner_binding = VolumeOwnerBinding {
                volume_id: stored.record.volume_id.clone(),
                owner_node_id: event.node_id.clone(),
                attachment_id: stored.record.lease_owner.clone().unwrap(),
                attachment_epoch: stored.record.lease_epoch,
            };
            update_volume_owner(transaction, &stored.record, Some(&owner_binding))
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

pub(crate) fn stored_volume_for_a22_http_test(store: &Store, volume_id: &Id) -> VolumeRecord {
    stored_volume(store, volume_id)
}

fn stored_volume_owner(store: &Store, volume_id: &Id) -> Option<VolumeOwnerBinding> {
    store
        .authority_transaction(|transaction| {
            Ok(load_stored_volume_for_update(transaction, volume_id)?
                .unwrap()
                .owner_binding)
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

#[test]
fn database_rejects_a_partial_or_extra_volume_owner_binding() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let before = stored_volume_row(&store, &owned.volume_id);
    for replacement in [
        "owner_binding - 'attachment_id'",
        "owner_binding || '{\"unexpected\":true}'::jsonb",
    ] {
        let sql =
            format!("UPDATE volume_records SET owner_binding={replacement} WHERE volume_id=$1");
        assert!(store
            .with(|client| client.execute(&sql, &[&owned.volume_id.as_str()]))
            .is_err());
        assert_eq!(stored_volume_row(&store, &owned.volume_id), before);
    }
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

fn stored_disposable_graph(store: &Store) -> String {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT jsonb_build_object(
                         'event', (SELECT to_jsonb(row) FROM host_fence_events row
                                    WHERE event_id='fence-event-1'),
                         'authorization', (SELECT to_jsonb(row) FROM volume_authorizations row
                                            WHERE authorization_id='delete-auth-1'),
                         'volume', (SELECT to_jsonb(row) FROM volume_records row
                                    WHERE volume_id='volume-1'),
                         'disk', (SELECT to_jsonb(row) FROM disk_records row
                                  WHERE disk_id='disk-1')
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
        .acquire_volume_authority(&id("node-new"), &acquire_request(1, "attachment-old", 7))
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

fn load_residue_authority(
    transaction: &mut postgres::Transaction<'_>,
    node: &TransitionNode,
    request: &RuntimeResidueAuthorityRequest,
) -> Result<
    Box<cats_api::runtime_reconciliation::RuntimeResidueAuthoritySuccess>,
    AuthorityTransactionError,
> {
    let context = match authenticate_evidence_context_in(
        transaction,
        &node.authenticated,
        &request.session,
        &node.active_guest_config_digest,
    )? {
        VolumeTransitionStoreOutcome::Accepted(context) => context,
        VolumeTransitionStoreOutcome::Rejected(rejection) => {
            panic!("residue authority authentication prefix was rejected: {rejection:?}")
        }
    };
    load_runtime_residue_authority_in(context, request)
}

#[test]
fn persisted_volume_replays_lost_result_and_rejects_reused_id() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    seed_volume(&store, &unowned_volume());
    let request = acquire_request(1, "attachment-old", 7);

    // Simulate a commit response that the caller lost by discarding it.
    let first = store
        .acquire_volume_authority(&id("node-a"), &request)
        .unwrap();
    let replay = store
        .acquire_volume_authority(&id("node-a"), &request)
        .unwrap();
    assert_eq!(replay, first);

    let before = stored_volume(&store, &request.volume_id);
    let changed = NormalAcquireRequest {
        attachment_id: id("attachment-other"),
        ..request
    };
    let error = store
        .acquire_volume_authority(&id("node-a"), &changed)
        .unwrap_err();
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
        .acquire_volume_authority(&id("node-a"), &acquire_request(1, "attachment-old", 7))
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
        .acquire_volume_authority(&id("node-a"), &acquire_request(2, "attachment-old", 7))
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
        .acquire_volume_authority(&id("node-b"), &acquire_request(2, "attachment-new", 8))
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
        .acquire_volume_authority(&id("node-b"), &acquire_request(3, "attachment-new", 9))
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
        first.acquire_volume_authority(&id("node-a"), &acquire_request(1, "attachment-a", 7))
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.acquire_volume_authority(&id("node-b"), &acquire_request(2, "attachment-b", 7))
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
fn a22_cancellation_between_final_check_and_commit_claim_rolls_back_every_write() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let (volume, node, _desired, request) =
        normal_acquire_fixture(&store, "a22-cancel-before-commit");
    let before = stored_volume_row(&store, &volume.volume_id);
    let observer = Store::connect(&url, None).unwrap();
    let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    context.pause_before_commit_claim_for_test(Arc::clone(&entered), Arc::clone(&release));
    let worker_context = context.clone();
    let worker = std::thread::spawn(move || {
        store.runtime_volume_transition(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
            &worker_context,
        )
    });

    entered.wait();
    context.cancel();
    release.wait();
    let error = worker.join().unwrap().unwrap_err();

    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(!context.commit_was_attempted());
    assert_eq!(stored_volume_row(&observer, &volume.volume_id), before);
}

#[test]
fn a22_commit_claim_wins_cancellation_and_response_loss_replays_exactly() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let (volume, node, _desired, request) = normal_acquire_fixture(&store, "a22-commit-wins");
    let observer = Store::connect(&url, None).unwrap();
    let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    context.pause_after_commit_claim_for_test(Arc::clone(&entered), Arc::clone(&release));
    store.inject_request_committed_response_loss_once_after(Duration::ZERO);
    let worker_context = context.clone();
    let worker_node = node.clone();
    let worker_request = request.clone();
    let worker = std::thread::spawn(move || {
        store.runtime_volume_transition(
            &worker_node.authenticated,
            &worker_request,
            &worker_node.active_guest_config_digest,
            &worker_context,
        )
    });

    entered.wait();
    assert!(context.commit_was_attempted());
    context.cancel();
    release.wait();
    let lost = worker.join().unwrap().unwrap_err();

    assert_eq!(lost.code, ErrorCode::Unavailable);
    let committed = stored_volume(&observer, &volume.volume_id);
    assert_eq!(committed.lease_owner, Some(id("attachment-normal")));
    assert_eq!(committed.lease_epoch, fence_epoch(8));
    let first = execute_transition(&observer, &node, &request).unwrap();
    let second = execute_transition(&observer, &node, &request).unwrap();
    assert_eq!(first, second);
    let VolumeTransitionStoreOutcome::Accepted(success) = first else {
        panic!("normal acquire replay was rejected")
    };
    let RuntimeVolumeTransitionOutcome::LeaseGranted { grant } = success.outcome else {
        panic!("normal acquire returned the wrong outcome")
    };
    assert_eq!(grant.attachment_id, id("attachment-normal"));
    assert_eq!(grant.attachment_epoch, fence_epoch(8));
    assert_eq!(stored_volume(&observer, &volume.volume_id), committed);
}

#[test]
fn a22_normal_acquire_commits_once_and_replays_after_response_loss() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let (volume, node, desired, request) = normal_acquire_fixture(&store, "a22-normal");

    store.inject_request_committed_response_loss_once_after(Duration::ZERO);
    let lost = execute_transition(&store, &node, &request).unwrap_err();
    assert_eq!(lost.code, ErrorCode::Unavailable);
    let committed = stored_volume(&store, &volume.volume_id);
    assert_eq!(committed.lease_owner, Some(id("attachment-normal")));
    assert_eq!(committed.lease_epoch, fence_epoch(8));
    assert_eq!(
        stored_volume_owner(&store, &volume.volume_id),
        Some(VolumeOwnerBinding {
            volume_id: volume.volume_id.clone(),
            owner_node_id: node.session.node_id.clone(),
            attachment_id: id("attachment-normal"),
            attachment_epoch: fence_epoch(8),
        })
    );

    let desired_read = match store
        .runtime_desired_read(
            &node.authenticated,
            &DesiredReadRequest {
                version: ContractVersion::V1,
                session: node.session.clone(),
                request_sequence: Sequence::new(2).unwrap(),
            },
        )
        .unwrap()
    {
        RuntimeSpineOutcome::Accepted(snapshot) => snapshot,
        RuntimeSpineOutcome::Rejected(rejection) => {
            panic!("fresh replay Desired read rejected: {rejection:?}")
        }
    };
    let mut observed = observed_owned_volume(
        &desired,
        &committed,
        cats_api::runtime_reconciliation::AcquireOrigin::Normal {
            transition_id: random_id(2),
        },
        committed.head.generation,
        committed.head.generation,
    );
    observed.local_lineages.clear();
    let mut fresh = NodeObservation {
        version: ContractVersion::V1,
        observation_id: random_id(92),
        node_id: node.session.node_id.clone(),
        node_boot_id: node.session.node_boot_id.clone(),
        agent_instance_id: node.session.agent_instance_id.clone(),
        agent_session_epoch: node.session.agent_session_epoch,
        heartbeat_sequence: Sequence::new(2).unwrap(),
        observed_at_unix_ms: unix_millis(2),
        complete_inventory: true,
        inventory_epoch: epoch(2),
        inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
        inventory_read_position: Some(desired_read.read_position),
        key_ring_version: None,
        key_ring_digest: None,
        loaded_kids: Vec::new(),
        runtimes: vec![observed_runtime_with_volumes(
            &desired,
            None,
            vec![observed],
        )],
        residue: Vec::new(),
    };
    fresh.inventory_digest = Some(inventory_digest(&fresh).unwrap());
    assert!(matches!(
        store
            .runtime_accept_observation(&node.authenticated, &fresh)
            .unwrap(),
        RuntimeSpineOutcome::Accepted(_)
    ));

    let before_replay = stored_volume_row(&store, &volume.volume_id);
    let original_expiry = committed.lease_expires_at.unwrap();

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
    assert_eq!(grant.lease_expires_at, original_expiry);
    assert_eq!(stored_volume(&store, &volume.volume_id), committed);
    assert_eq!(stored_volume_row(&store, &volume.volume_id), before_replay);
}

#[test]
fn a22_commit_initialized_is_atomic_idempotent_and_conflict_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let (node, desired, request, filesystem, volume) =
        commit_initialized_fixture(&store, "a22-commit-initialized");

    store.inject_request_committed_response_loss_once_after(Duration::ZERO);
    let lost = execute_transition(&store, &node, &request).unwrap_err();
    assert_eq!(lost.code, ErrorCode::Unavailable);
    let committed = store
        .authority_transaction(|transaction| {
            Ok(load_disk_by_id_for_update(transaction, &filesystem.disk_id)?.unwrap())
        })
        .unwrap();
    let DiskRole::Persistent { initialization } = &committed.role else {
        panic!("PersistentDisk changed role during initialization")
    };
    let PersistentDiskInitialization::Initialized {
        initialization_token,
        filesystem_uuid,
        expected_blank_head,
        initialized_head,
        initialized_at,
    } = initialization.as_ref()
    else {
        panic!("response loss did not leave the initialization commit durable")
    };
    assert_eq!(initialization_token, &random_id(8_003));
    assert_eq!(filesystem_uuid, &random_id(8_004));
    assert_eq!(expected_blank_head, &head(0));
    assert_eq!(initialized_head, &volume.head);
    let first_initialized_at = *initialized_at;

    let first = execute_transition(&store, &node, &request).unwrap();
    let second = execute_transition(&store, &node, &request).unwrap();
    assert_eq!(first, second);
    let VolumeTransitionStoreOutcome::Accepted(success) = first else {
        panic!("exact initialization replay was rejected")
    };
    let RuntimeVolumeTransitionOutcome::PersistentInitialized { receipt } = success.outcome else {
        panic!("initialization replay returned another outcome")
    };
    assert_eq!(receipt.disk_id, filesystem.disk_id);
    assert_eq!(receipt.volume_id, filesystem.volume_id);
    assert_eq!(receipt.initialized_head, volume.head);
    assert_eq!(receipt.initialized_at, first_initialized_at);
    assert_eq!(
        store
            .authority_transaction(|transaction| {
                Ok(load_disk_by_id_for_update(transaction, &filesystem.disk_id)?.unwrap())
            })
            .unwrap(),
        committed,
    );

    let mut conflict = request.clone();
    let RuntimeVolumeTransition::CommitInitialized {
        new_remote_head, ..
    } = &mut conflict.transition
    else {
        unreachable!()
    };
    *new_remote_head = head(2);
    assert!(matches!(
        execute_transition(&store, &node, &conflict).unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::TransitionPreconditionFailed {
                problem: RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
                ..
            }
        )
    ));

    // Initialize is the durable intent spanning its one-time Disk CAS. The
    // same current Desired remains valid for the later Mount/Ready tail; an
    // exact lease replay therefore stays idempotent after initialization.
    let post_commit_acquire_replay = transition_request(
        &node,
        &desired,
        RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Normal {
                volume_id: volume.volume_id.clone(),
                transition_id: random_id(8_002),
                attachment_id: filesystem.attachment_id.clone(),
                expected_unowned_epoch: fence_epoch(0),
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                lease_duration_ms: 30_000,
            },
        },
    );
    let before = stored_volume_row(&store, &volume.volume_id);
    let VolumeTransitionStoreOutcome::Accepted(success) =
        execute_transition(&store, &node, &post_commit_acquire_replay).unwrap()
    else {
        panic!("post-initialization lease replay rejected its current Initialize Desired")
    };
    assert!(matches!(
        success.outcome,
        RuntimeVolumeTransitionOutcome::LeaseGranted { .. }
    ));
    assert_eq!(stored_volume_row(&store, &volume.volume_id), before);
}

#[test]
fn a22_commit_initialized_two_exact_writers_converge_to_one_receipt() {
    let url = crate::testsupport::isolated_control_store_url();
    let first_store = Store::connect(&url, None).unwrap();
    let second_store = Store::connect(&url, None).unwrap();
    let (node, _desired, request, filesystem, _volume) =
        commit_initialized_fixture(&first_store, "a22-commit-initialized-writers");
    let barrier = Arc::new(Barrier::new(3));
    let spawn = |store: Store| {
        let barrier = Arc::clone(&barrier);
        let node = node.clone();
        let request = request.clone();
        std::thread::spawn(move || {
            barrier.wait();
            execute_transition(&store, &node, &request).unwrap()
        })
    };
    let first = spawn(first_store);
    let second = spawn(second_store);
    barrier.wait();
    let first = first.join().unwrap();
    let second = second.join().unwrap();
    assert_eq!(first, second);
    let VolumeTransitionStoreOutcome::Accepted(success) = first else {
        panic!("first exact initialization writer was rejected")
    };
    let RuntimeVolumeTransitionOutcome::PersistentInitialized { receipt } = success.outcome else {
        panic!("initialization writer returned another outcome")
    };
    assert_eq!(receipt.disk_id, filesystem.disk_id);
}

#[test]
fn a22_commit_initialized_rejects_authority_drift_after_observation() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let (node, _desired, request, filesystem, volume) =
        commit_initialized_fixture(&store, "a22-commit-initialized-drift");
    let before_disk = store
        .authority_transaction(|transaction| {
            Ok(load_disk_by_id_for_update(transaction, &filesystem.disk_id)?.unwrap())
        })
        .unwrap();

    let mut advanced = volume.clone();
    advanced.head = head(2);
    store
        .authority_transaction(|transaction| {
            let stored =
                load_stored_volume_for_update(transaction, &filesystem.volume_id)?.unwrap();
            update_volume_owner(transaction, &advanced, stored.owner_binding.as_ref())
        })
        .unwrap();

    assert!(matches!(
        execute_transition(&store, &node, &request).unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::TransitionPreconditionFailed {
                problem: RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
                ..
            }
        )
    ));
    assert_eq!(stored_volume(&store, &filesystem.volume_id), advanced);
    assert_eq!(
        store
            .authority_transaction(|transaction| {
                Ok(load_disk_by_id_for_update(transaction, &filesystem.disk_id)?.unwrap())
            })
            .unwrap(),
        before_disk,
    );
}

#[test]
fn a22_commit_initialized_rejects_a_replaced_agent_session() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let (node, _desired, request, filesystem, _volume) =
        commit_initialized_fixture(&store, "a22-commit-initialized-session");
    let before_disk = store
        .authority_transaction(|transaction| {
            Ok(load_disk_by_id_for_update(transaction, &filesystem.disk_id)?.unwrap())
        })
        .unwrap();
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&runtime_release()).unwrap();
    let replacement = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: node.session.node_id.clone(),
        immutable_host_id: id("host-9"),
        node_boot_id: boot_id(51),
        agent_instance_id: random_id(52),
        registration_attempt_id: random_id(53),
        guest_config_digest: policy.approved_guest_config_digest().clone(),
        expected_agent_session_epoch: Some(node.session.agent_session_epoch),
    };
    assert!(matches!(
        store
            .register_agent_session(&node.authenticated, &replacement, &policy)
            .unwrap(),
        AgentRegistrationOutcome::Registered(_)
    ));

    assert!(matches!(
        execute_transition(&store, &node, &request).unwrap(),
        VolumeTransitionStoreOutcome::Rejected(_)
    ));
    assert_eq!(
        store
            .authority_transaction(|transaction| {
                Ok(load_disk_by_id_for_update(transaction, &filesystem.disk_id)?.unwrap())
            })
            .unwrap(),
        before_disk,
    );
}

#[test]
fn a22_normal_acquire_rejects_incomplete_or_cross_runtime_volume_authority() {
    #[derive(Clone, Copy)]
    enum PhysicalConflict {
        OwnedWithoutLineage,
        OtherRuntimeVolume,
        OtherRuntimeBlockd,
        ResidueControlSocket,
    }

    for conflict in [
        PhysicalConflict::OwnedWithoutLineage,
        PhysicalConflict::OtherRuntimeVolume,
        PhysicalConflict::OtherRuntimeBlockd,
        PhysicalConflict::ResidueControlSocket,
    ] {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let volume = unowned_volume();
        seed_volume(&store, &volume);
        let node = transition_node(&store, "node-new");
        let workspace = super::product_tests::bootstrap_workspace(&store, "a22-normal-index");
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
        let mut observed = observed_unowned_volume(&desired, &volume);
        let mut target = observed_runtime_with_volumes(&desired, None, vec![observed.clone()]);
        let mut runtimes = vec![target.clone()];
        let mut residue = Vec::new();
        match conflict {
            PhysicalConflict::OwnedWithoutLineage => {
                observed.authority = VolumeAuthorityEvidence::Owned {
                    attachment_id: id("attachment-normal"),
                    attachment_epoch: fence_epoch(8),
                    head: volume.head.clone(),
                };
                target.volumes = vec![observed];
                runtimes = vec![target];
            }
            PhysicalConflict::OtherRuntimeVolume => {
                runtimes.push(orphan_runtime_with_volume_evidence(
                    &target,
                    vec![observed],
                    Vec::new(),
                ));
            }
            PhysicalConflict::OtherRuntimeBlockd => {
                runtimes.push(orphan_runtime_with_volume_evidence(
                    &target,
                    Vec::new(),
                    vec![observed_blockd_process(
                        &volume.volume_id,
                        &id("attachment-other"),
                        fence_epoch(8),
                        1,
                    )],
                ));
            }
            PhysicalConflict::ResidueControlSocket => {
                residue.push(NodeResidue::ControlSocket {
                    socket_path: cats_api::runtime_reconciliation::HostPath::new(
                        "/run/cats/orphan-volume.sock",
                    )
                    .unwrap(),
                    role_hint: Some(ProcessRole::Blockd {
                        volume_id: volume.volume_id.clone(),
                        attachment_id: id("attachment-other"),
                        attachment_epoch: fence_epoch(8),
                    }),
                    ownership_token: OwnershipTokenEvidence::Missing,
                });
            }
        }
        prepare_a22_runtime_with_inventory(
            &store, &node, &desired, &volume, runtimes, residue, false,
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
        let before = stored_volume(&store, &volume.volume_id);
        assert_eq!(
            execute_transition(&store, &node, &request).unwrap(),
            VolumeTransitionStoreOutcome::Rejected(
                VolumeTransitionStoreRejection::TransitionPreconditionFailed {
                    cat_id: desired.cat_id,
                    problem: RuntimeVolumeTransitionPreconditionProblem::VolumeIntentMismatch,
                }
            )
        );
        assert_eq!(stored_volume(&store, &volume.volume_id), before);
    }
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
    assert_eq!(
        stored_volume_owner(&store, &owned.volume_id),
        Some(VolumeOwnerBinding {
            volume_id: owned.volume_id.clone(),
            owner_node_id: node.session.node_id.clone(),
            attachment_id: id("attachment-new"),
            attachment_epoch: fence_epoch(9),
        })
    );
    assert!(matches!(
        stored_authorization(&store, &id("takeover-auth-1")).state,
        AuthorizationState::Consumed(_)
    ));
}

#[test]
fn a22_takeover_rejects_an_authorization_for_a_different_current_owner() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let event = host_fence_event(HostFenceEventState::Active);
    let authorization = takeover_authorization(&owned);
    seed_takeover(&store, &event, &authorization);
    store
        .authority_transaction(|transaction| {
            let stored = load_stored_volume_for_update(transaction, &owned.volume_id)?.unwrap();
            let binding = VolumeOwnerBinding {
                volume_id: stored.record.volume_id.clone(),
                owner_node_id: id("other-unfenced-node"),
                attachment_id: id("attachment-old"),
                attachment_epoch: owned.lease_epoch,
            };
            update_volume_owner(transaction, &stored.record, Some(&binding))
        })
        .unwrap();
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
    let before = stored_takeover_graph(&store);

    assert_eq!(
        execute_transition(&store, &node, &request).unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                authorization_id: id("takeover-auth-1"),
                reason: RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
            }
        )
    );
    assert_eq!(stored_takeover_graph(&store), before);
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
    assert_eq!(stored_volume_owner(&store, &owned.volume_id), None);
}

#[test]
fn a22_release_rejects_duplicate_or_other_runtime_writers() {
    #[derive(Clone, Copy)]
    enum PhysicalConflict {
        OtherRuntimeVolume,
        OtherRuntimeBlockd,
    }

    for conflict in [
        PhysicalConflict::OtherRuntimeVolume,
        PhysicalConflict::OtherRuntimeBlockd,
    ] {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let owned = acquire_owned_volume(&store);
        let node = transition_node(&store, "node-new");
        let workspace = super::product_tests::bootstrap_workspace(&store, "a22-release-index");
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
        let target = observed_runtime_with_volumes(&desired, None, vec![observed.clone()]);
        let orphan = match conflict {
            PhysicalConflict::OtherRuntimeVolume => {
                let mut duplicate = observed;
                duplicate.local_lineages[0].data_directory =
                    cats_api::runtime_reconciliation::HostPath::new(
                        "/var/lib/cats/volumes/volume-1-duplicate",
                    )
                    .unwrap();
                orphan_runtime_with_volume_evidence(&target, vec![duplicate], Vec::new())
            }
            PhysicalConflict::OtherRuntimeBlockd => orphan_runtime_with_volume_evidence(
                &target,
                Vec::new(),
                vec![observed_blockd_process(
                    &owned.volume_id,
                    &id("attachment-old"),
                    owned.lease_epoch,
                    2,
                )],
            ),
        };
        let admission = prepare_a22_runtime_with_inventory(
            &store,
            &node,
            &desired,
            &owned,
            vec![target, orphan],
            Vec::new(),
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
                        attachment_epoch: owned.lease_epoch,
                    },
                    inventory_session: node.session.clone(),
                    inventory_epoch: admission.inventory_attestation.inventory_epoch,
                    inventory_read_position: admission
                        .inventory_attestation
                        .inventory_read_position,
                    desired_read_position: admission.desired_read_position,
                    volume_release: Some(VolumeReleaseReplay {
                        release_transition_id: random_id(2),
                        generation: owned.head.generation,
                        disposition: VolumeDisposition::Retain,
                    }),
                },
            },
        );
        let before = stored_volume(&store, &owned.volume_id);
        assert_eq!(
            execute_transition(&store, &node, &request).unwrap(),
            VolumeTransitionStoreOutcome::Rejected(
                VolumeTransitionStoreRejection::TransitionPreconditionFailed {
                    cat_id: desired.cat_id,
                    problem: RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
                }
            )
        );
        assert_eq!(stored_volume(&store, &owned.volume_id), before);
    }
}

#[test]
fn a22_root_release_ignores_a_historical_consumed_takeover() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let (node, _desired, _admission, request) = prepare_root_delete_release_fixture(&store, &owned);

    let mut event = host_fence_event(HostFenceEventState::Active);
    event.event_id = id("historical-fence-event");
    let original = AuthorizationRecord {
        authorization: VolumeAuthorization::Takeover(VolumeTakeoverAuthorization {
            authorization_id: id("historical-takeover"),
            authorized_node_id: node.session.node_id.clone(),
            host_fence_event_id: event.event_id.clone(),
            volume_id: owned.volume_id.clone(),
            expected_attachment_id: id("historical-attachment-old"),
            expected_epoch: fence_epoch(5),
            new_attachment_id: id("historical-attachment-new"),
            desired_revision: revision(9),
            new_placement_epoch: epoch(2),
            lease_duration_ms: 30_000,
            not_after: unix_millis(100_000),
        }),
        state: AuthorizationState::Unconsumed,
    };
    let consumed = AuthorizationRecord {
        authorization: original.authorization.clone(),
        state: AuthorizationState::Consumed(Box::new(AuthorizationConsumedReceipt::Takeover(
            TakeoverConsumedReceipt {
                authorization_id: id("historical-takeover"),
                host_fence_event_id: event.event_id.clone(),
                volume_id: owned.volume_id.clone(),
                new_attachment_id: id("historical-attachment-new"),
                resulting_epoch: fence_epoch(6),
                resulting_head: owned.head.clone(),
                consumed_at: unix_millis(1_000),
            },
        ))),
    };
    store
        .authority_transaction(|transaction| {
            insert_event(transaction, &event)?;
            insert_authorization(transaction, &original)?;
            update_authorization(transaction, &original, &consumed)
        })
        .unwrap();

    let outcome = execute_transition(&store, &node, &request).unwrap();
    assert!(matches!(
        outcome,
        VolumeTransitionStoreOutcome::Accepted(
            cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess {
                outcome: RuntimeVolumeTransitionOutcome::Released { .. },
                ..
            }
        )
    ));
}

#[test]
fn a22_root_release_validates_product_and_cleanup_before_fresh_branch_conflict() {
    #[derive(Clone, Copy)]
    enum EarlierFailure {
        ProductCorruption,
        CleanupMismatch,
    }

    for failure in [
        EarlierFailure::ProductCorruption,
        EarlierFailure::CleanupMismatch,
    ] {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let owned = acquire_owned_volume(&store);
        let (node, desired, _admission, mut request) =
            prepare_root_delete_release_fixture(&store, &owned);
        let authorization = disposable_authorization(&owned);
        store
            .authority_transaction(|transaction| insert_authorization(transaction, &authorization))
            .unwrap();
        let before = stored_volume(&store, &owned.volume_id);

        match failure {
            EarlierFailure::ProductCorruption => {
                store
                    .authority_transaction(|transaction| {
                        transaction.execute(
                            "UPDATE disk_records
                                SET record=jsonb_set(
                                    record,
                                    '{volume_id}',
                                    '\"corrupt-volume\"'::jsonb
                                )
                              WHERE disk_id=$1",
                            &[&"disk-1"],
                        )?;
                        Ok(())
                    })
                    .unwrap();
                let error = execute_transition(&store, &node, &request).unwrap_err();
                assert_eq!(error.code, ErrorCode::Internal);
            }
            EarlierFailure::CleanupMismatch => {
                let RuntimeVolumeTransition::Release { cleanup } = &mut request.transition else {
                    unreachable!()
                };
                cleanup.inventory_epoch = epoch(2);
                assert_eq!(
                    execute_transition(&store, &node, &request).unwrap(),
                    VolumeTransitionStoreOutcome::Rejected(
                        VolumeTransitionStoreRejection::TransitionPreconditionFailed {
                            cat_id: desired.cat_id,
                            problem:
                                RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
                        }
                    )
                );
            }
        }
        assert_eq!(stored_volume(&store, &owned.volume_id), before);
        assert_eq!(
            stored_authorization(&store, &id("delete-auth-1")),
            authorization
        );
    }
}

#[test]
fn a22_root_release_fails_closed_on_nested_current_authorization_corruption() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let (node, _desired, _admission, request) = prepare_root_delete_release_fixture(&store, &owned);
    let authorization = disposable_authorization(&owned);
    store
        .authority_transaction(|transaction| insert_authorization(transaction, &authorization))
        .unwrap();
    store
        .authority_transaction(|transaction| {
            let changed = transaction.execute(
                "UPDATE volume_authorizations
                    SET record=jsonb_set(
                        record,
                        '{authorization,delete_id}',
                        to_jsonb($2::text)
                    )
                  WHERE authorization_id=$1",
                &[&"delete-auth-1", &"corrupt-delete-lineage"],
            )?;
            assert_eq!(changed, 1);
            Ok(())
        })
        .unwrap();
    let before_volume = stored_volume_row(&store, &owned.volume_id);
    let before_authorization = stored_authorization_row(&store, &id("delete-auth-1"));

    let error = execute_transition(&store, &node, &request).unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(stored_volume_row(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization_row(&store, &id("delete-auth-1")),
        before_authorization
    );
}

#[test]
fn a22_root_release_fails_closed_when_current_authorization_projection_drifts() {
    #[derive(Clone, Copy, Debug)]
    enum ProjectionDrift {
        DesiredRevision,
        PlacementEpoch,
        VolumeId,
    }

    for drift in [
        ProjectionDrift::DesiredRevision,
        ProjectionDrift::PlacementEpoch,
        ProjectionDrift::VolumeId,
    ] {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let owned = acquire_owned_volume(&store);
        let (node, _desired, _admission, request) =
            prepare_root_delete_release_fixture(&store, &owned);
        let authorization = disposable_authorization(&owned);
        store
            .authority_transaction(|transaction| insert_authorization(transaction, &authorization))
            .unwrap();
        store
            .authority_transaction(|transaction| {
                let changed = match drift {
                    ProjectionDrift::DesiredRevision => transaction.execute(
                        "UPDATE volume_authorizations
                            SET desired_revision=11
                          WHERE authorization_id=$1",
                        &[&"delete-auth-1"],
                    )?,
                    ProjectionDrift::PlacementEpoch => transaction.execute(
                        "UPDATE volume_authorizations
                            SET placement_epoch=3
                          WHERE authorization_id=$1",
                        &[&"delete-auth-1"],
                    )?,
                    ProjectionDrift::VolumeId => transaction.execute(
                        "UPDATE volume_authorizations
                            SET volume_id='projection-drift-volume'
                          WHERE authorization_id=$1",
                        &[&"delete-auth-1"],
                    )?,
                };
                assert_eq!(changed, 1, "failed to install {drift:?}");
                Ok(())
            })
            .unwrap();
        let before_volume = stored_volume_row(&store, &owned.volume_id);
        let before_authorization = stored_authorization_row(&store, &id("delete-auth-1"));

        let error = execute_transition(&store, &node, &request).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::Internal,
            "wrong result for {drift:?}"
        );
        assert_eq!(
            stored_volume_row(&store, &owned.volume_id),
            before_volume,
            "Volume changed for {drift:?}"
        );
        assert_eq!(
            stored_authorization_row(&store, &id("delete-auth-1")),
            before_authorization,
            "authorization changed for {drift:?}"
        );
    }
}

#[test]
fn a22_disposable_authorization_scope_stays_indexed_with_large_history() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let (_node, _desired, _admission, _request) =
        prepare_root_delete_release_fixture(&store, &owned);
    let history_event = host_fence_event(HostFenceEventState::Active);
    store
        .authority_transaction(|transaction| {
            insert_event(transaction, &history_event)?;
            transaction.execute(
                "INSERT INTO volume_authorizations (
                    authorization_id, record, kind, authorized_node_id,
                    host_fence_event_id, volume_id, state, desired_revision,
                    placement_epoch, lease_duration_ms, not_after, consumed_at
                 )
                 SELECT 'history-auth-' || lpad(entry::text, 8, '0'),
                        jsonb_build_object('unrelated_history', entry),
                        CASE WHEN entry % 2 = 0
                             THEN 'takeover'
                             ELSE 'disposable_root_delete'
                         END,
                        'history-node',
                        CASE WHEN entry % 2 = 0 THEN $2::text ELSE NULL END,
                        $1, 'unconsumed',
                        100 + entry % 97, 100 + entry % 89,
                        CASE WHEN entry % 2 = 0 THEN 30000 ELSE NULL END,
                        9223372036854775807, NULL
                   FROM generate_series(1, 100000) AS entry",
                &[&owned.volume_id.as_str(), &history_event.event_id.as_str()],
            )?;
            transaction.batch_execute("ANALYZE volume_authorizations")?;
            Ok(())
        })
        .unwrap();

    let explain_scope = || {
        store
            .authority_transaction(|transaction| {
                let rows = transaction.query(
                    &format!(
                        "EXPLAIN (COSTS OFF) {}",
                        disposable_root_authorization_candidates_sql()
                    ),
                    &[&owned.volume_id.as_str(), &12_i64, &4_i64, &"delete-1"],
                )?;
                Ok(rows
                    .into_iter()
                    .map(|row| row.get::<_, String>(0))
                    .collect::<Vec<_>>()
                    .join("\n"))
            })
            .unwrap()
    };
    let assert_indexed = |phase: &str, plan: &str| {
        assert!(
            plan.contains("volume_authorizations_record_authorization"),
            "{phase} canonical selector did not plan through its GIN index:\n{plan}"
        );
        assert!(
            plan.contains("volume_authorizations_disposable_scope"),
            "{phase} scalar selector did not plan through its ordered partial index:\n{plan}"
        );
        assert!(
            !plan.contains("Seq Scan on volume_authorizations"),
            "{phase} selector planned a sequential scan:\n{plan}"
        );
    };
    let missing_plan = explain_scope();
    assert_indexed("missing", &missing_plan);

    let missing = store
        .authority_transaction(|transaction| {
            transaction.batch_execute("SET LOCAL statement_timeout='250ms'")?;
            volume_has_disposable_root_authorization_for_delete(
                transaction,
                &owned.volume_id,
                &id("delete-1"),
                revision(12),
                epoch(4),
            )
        })
        .unwrap();
    assert!(!missing);

    let authorization = disposable_authorization(&owned);
    store
        .authority_transaction(|transaction| insert_authorization(transaction, &authorization))
        .unwrap();
    let healthy = store
        .authority_transaction(|transaction| {
            transaction.batch_execute("SET LOCAL statement_timeout='250ms'")?;
            volume_has_disposable_root_authorization_for_delete(
                transaction,
                &owned.volume_id,
                &id("delete-1"),
                revision(12),
                epoch(4),
            )
        })
        .unwrap();
    assert!(
        healthy,
        "a row found by both candidate arms was not deduplicated"
    );
    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "UPDATE volume_authorizations
                    SET desired_revision=11
                  WHERE authorization_id=$1",
                &[&"delete-auth-1"],
            )?;
            Ok(())
        })
        .unwrap();
    let drifted_plan = explain_scope();
    assert_indexed("drifted current", &drifted_plan);
    let error = store
        .authority_transaction(|transaction| {
            transaction.batch_execute("SET LOCAL statement_timeout='250ms'")?;
            volume_has_disposable_root_authorization_for_delete(
                transaction,
                &owned.volume_id,
                &id("delete-1"),
                revision(12),
                epoch(4),
            )
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn a22_release_accepts_a_persisted_cleanup_cursor_behind_the_latest_desired_read() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let (node, _desired, admission, request) = prepare_root_delete_release_fixture(&store, &owned);
    let latest = match store
        .runtime_desired_read(
            &node.authenticated,
            &DesiredReadRequest {
                version: ContractVersion::V1,
                session: node.session.clone(),
                request_sequence: Sequence::new(2).unwrap(),
            },
        )
        .unwrap()
    {
        RuntimeSpineOutcome::Accepted(snapshot) => snapshot,
        RuntimeSpineOutcome::Rejected(rejection) => {
            panic!("second Desired read rejected: {rejection:?}")
        }
    };
    assert!(latest.read_position > admission.desired_read_position);

    let outcome = execute_transition(&store, &node, &request).unwrap();
    assert!(matches!(
        outcome,
        VolumeTransitionStoreOutcome::Accepted(
            cats_api::runtime_reconciliation::RuntimeVolumeTransitionSuccess {
                outcome: RuntimeVolumeTransitionOutcome::Released { .. },
                ..
            }
        )
    ));
}

#[test]
fn a22_disposable_consume_uses_node_wide_physical_authority_for_both_isolation_bases() {
    #[derive(Debug, Clone, Copy)]
    enum IsolationBasis {
        RuntimeStopped,
        HostFenceEvent,
    }

    #[derive(Debug, Clone, Copy)]
    enum PhysicalConflict {
        None,
        ForeignAuthorityOwner,
        ForeignRuntimeVolume,
        ForeignRuntimeBlockd,
        ForeignRuntimeMount,
        Residue,
    }

    for basis in [
        IsolationBasis::RuntimeStopped,
        IsolationBasis::HostFenceEvent,
    ] {
        for conflict in [
            PhysicalConflict::None,
            PhysicalConflict::ForeignAuthorityOwner,
            PhysicalConflict::ForeignRuntimeVolume,
            PhysicalConflict::ForeignRuntimeBlockd,
            PhysicalConflict::ForeignRuntimeMount,
            PhysicalConflict::Residue,
        ] {
            let store =
                Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
            let owned = acquire_owned_volume(&store);
            let node = transition_node(&store, "node-new");
            let workspace =
                super::product_tests::bootstrap_workspace(&store, "a22-disposable-physical");
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
            let mut observed = observed_owned_volume(
                &desired,
                &owned,
                cats_api::runtime_reconciliation::AcquireOrigin::Normal {
                    transition_id: random_id(1),
                },
                generation(5),
                owned.head.generation,
            );
            if matches!(basis, IsolationBasis::HostFenceEvent) {
                observed.local_lineages.clear();
            }
            let runtime_incarnation =
                matches!(basis, IsolationBasis::RuntimeStopped).then(|| random_id(51));
            let target = observed_runtime_with_volumes(
                &desired,
                runtime_incarnation,
                vec![observed.clone()],
            );
            let mut runtimes = vec![target.clone()];
            let mut residue = Vec::new();
            match conflict {
                PhysicalConflict::None | PhysicalConflict::ForeignAuthorityOwner => {}
                PhysicalConflict::ForeignRuntimeVolume => {
                    let mut foreign = observed;
                    foreign.local_lineages.clear();
                    runtimes.push(orphan_runtime_with_volume_evidence(
                        &target,
                        vec![foreign],
                        Vec::new(),
                    ));
                }
                PhysicalConflict::ForeignRuntimeBlockd => {
                    runtimes.push(orphan_runtime_with_volume_evidence(
                        &target,
                        Vec::new(),
                        vec![observed_blockd_process(
                            &owned.volume_id,
                            &id("attachment-foreign"),
                            owned.lease_epoch,
                            71,
                        )],
                    ));
                }
                PhysicalConflict::ForeignRuntimeMount => {
                    let mut orphan =
                        orphan_runtime_with_volume_evidence(&target, Vec::new(), Vec::new());
                    orphan.mounts.push(observed_mount(&owned.volume_id));
                    runtimes.push(orphan);
                }
                PhysicalConflict::Residue => {
                    residue.push(NodeResidue::ControlSocket {
                        socket_path: cats_api::runtime_reconciliation::HostPath::new(
                            "/run/cats/foreign-volume.sock",
                        )
                        .unwrap(),
                        role_hint: Some(ProcessRole::Blockd {
                            volume_id: owned.volume_id.clone(),
                            attachment_id: id("attachment-foreign"),
                            attachment_epoch: owned.lease_epoch,
                        }),
                        ownership_token: OwnershipTokenEvidence::Missing,
                    });
                }
            }
            prepare_a22_runtime_with_inventory(
                &store, &node, &desired, &owned, runtimes, residue, true,
            );

            let mut authorization = disposable_authorization(&owned);
            let VolumeAuthorization::DisposableRootDelete(payload) =
                &mut authorization.authorization
            else {
                unreachable!()
            };
            payload.authorized_node_id = node.session.node_id.clone();
            payload.cat_id = desired.cat_id.clone();
            payload.desired_revision = desired.desired_revision;
            payload.placement_epoch = desired.placement.placement_epoch;
            payload.isolation_basis = match basis {
                IsolationBasis::RuntimeStopped => DisposableDeleteIsolationBasis::RuntimeStopped {
                    node_id: node.session.node_id.clone(),
                    agent_session_epoch: node.session.agent_session_epoch,
                    runtime_incarnation: random_id(51),
                    observation_id: random_id(91),
                },
                IsolationBasis::HostFenceEvent => DisposableDeleteIsolationBasis::HostFenceEvent {
                    event_id: id("fence-event-1"),
                },
            };
            payload.not_after = unix_millis(i64::MAX.unsigned_abs());
            let event = matches!(basis, IsolationBasis::HostFenceEvent)
                .then(|| host_fence_event(HostFenceEventState::Active));
            store
                .authority_transaction(|transaction| {
                    if let Some(event) = event.as_ref() {
                        insert_event(transaction, event)?;
                        let stored =
                            load_stored_volume_for_update(transaction, &owned.volume_id)?.unwrap();
                        let binding = VolumeOwnerBinding {
                            volume_id: stored.record.volume_id.clone(),
                            owner_node_id: event.node_id.clone(),
                            attachment_id: id("attachment-old"),
                            attachment_epoch: owned.lease_epoch,
                        };
                        update_volume_owner(transaction, &stored.record, Some(&binding))?;
                    }
                    insert_authorization(transaction, &authorization)
                })
                .unwrap();
            if matches!(conflict, PhysicalConflict::ForeignAuthorityOwner) {
                store
                    .authority_transaction(|transaction| {
                        let stored =
                            load_stored_volume_for_update(transaction, &owned.volume_id)?.unwrap();
                        let binding = VolumeOwnerBinding {
                            volume_id: stored.record.volume_id.clone(),
                            owner_node_id: id("foreign-owner-node"),
                            attachment_id: id("attachment-old"),
                            attachment_epoch: owned.lease_epoch,
                        };
                        update_volume_owner(transaction, &stored.record, Some(&binding))
                    })
                    .unwrap();
            }
            let request = transition_request(
                &node,
                &desired,
                RuntimeVolumeTransition::DeleteDisposableRoot {
                    authorization_id: id("delete-auth-1"),
                },
            );

            if matches!(conflict, PhysicalConflict::None) {
                assert!(
                    matches!(
                        execute_transition(&store, &node, &request).unwrap(),
                        VolumeTransitionStoreOutcome::Accepted(_)
                    ),
                    "valid {basis:?} fixture was rejected"
                );
                continue;
            }

            let before = stored_disposable_graph(&store);
            assert_eq!(
                execute_transition(&store, &node, &request).unwrap(),
                VolumeTransitionStoreOutcome::Rejected(
                    VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                        authorization_id: id("delete-auth-1"),
                        reason: RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
                    }
                ),
                "wrong result for {basis:?}/{conflict:?}"
            );
            assert_eq!(
                stored_disposable_graph(&store),
                before,
                "authority graph changed for {basis:?}/{conflict:?}"
            );
        }
    }
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
    let before_disk = store
        .authority_transaction(|transaction| {
            Ok(load_disk_by_id_for_update(transaction, &id("disk-1"))?.unwrap())
        })
        .unwrap();
    let snapshot = DiskSnapshotRecord {
        snapshot_id: id("snapshot-1"),
        disk_id: id("disk-1"),
        volume_id: owned.volume_id.clone(),
        size_bytes: owned.size_bytes,
        head: owned.head.clone(),
        created_at: unix_millis(1),
    };
    store
        .authority_transaction(|transaction| insert_disk_snapshot(transaction, &snapshot))
        .unwrap();
    assert_eq!(
        execute_transition(&store, &node, &request).unwrap(),
        VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::VolumeAuthorizationRejected {
                authorization_id: id("delete-auth-1"),
                reason: RuntimeVolumeAuthorizationRejection::SnapshotInUse,
            }
        )
    );
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("delete-auth-1")),
        before_authorization
    );
    assert_eq!(
        store
            .authority_transaction(|transaction| {
                Ok(load_disk_by_id_for_update(transaction, &id("disk-1"))?.unwrap())
            })
            .unwrap(),
        before_disk
    );

    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "UPDATE disk_snapshot_records
                    SET record=jsonb_set(record, '{volume_id}', '\"other-volume\"'::jsonb)
                  WHERE snapshot_id=$1",
                &[&snapshot.snapshot_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();
    let corrupt = execute_transition(&store, &node, &request).unwrap_err();
    assert_eq!(corrupt.code, ErrorCode::Internal);
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("delete-auth-1")),
        before_authorization
    );
    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "DELETE FROM disk_snapshot_records WHERE snapshot_id=$1",
                &[&snapshot.snapshot_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();

    let mut size_mismatch = snapshot.clone();
    size_mismatch.snapshot_id = id("snapshot-size-mismatch");
    size_mismatch.size_bytes = size_mismatch.size_bytes.checked_add(1).unwrap();
    store
        .authority_transaction(|transaction| insert_disk_snapshot(transaction, &size_mismatch))
        .unwrap();
    let corrupt = execute_transition(&store, &node, &request).unwrap_err();
    assert_eq!(corrupt.code, ErrorCode::Internal);
    assert_eq!(stored_volume(&store, &owned.volume_id), before_volume);
    assert_eq!(
        stored_authorization(&store, &id("delete-auth-1")),
        before_authorization
    );
    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "DELETE FROM disk_snapshot_records WHERE snapshot_id=$1",
                &[&size_mismatch.snapshot_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();

    let first = execute_transition(&store, &node, &request).unwrap();
    let second = execute_transition(&store, &node, &request).unwrap();
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
    assert_eq!(stored_volume_owner(&store, &owned.volume_id), None);
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
            update_volume_owner(transaction, &deleting, None)?;
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
fn residue_authority_snapshot_returns_only_exact_ordinary_release_proof() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let owned_binding = stored_volume_owner(&store, &owned.volume_id).unwrap();
    let node = transition_node(&store, "node-new");
    let desired = prepare_residue_product_snapshot(&store, &node, &owned, revision(11), epoch(3));
    let (released, _) = cats_storage::authority::release(
        &owned,
        &ReleaseRequest {
            volume_id: owned.volume_id.clone(),
            transition_id: random_id(90),
            attachment_id: id("attachment-old"),
            expected_epoch: owned.lease_epoch,
        },
    )
    .unwrap();
    store
        .authority_transaction(|transaction| update_volume_owner(transaction, &released, None))
        .unwrap();

    let request = residue_authority_request(&node, &desired, 4, 4);
    let disabled = store
        .runtime_residue_authority(
            &node.authenticated,
            &request,
            &node.active_guest_config_digest,
        )
        .expect_err("the Proposed Store entrypoint must be mechanically disabled");
    assert_eq!(disabled.code, ErrorCode::NotFound);
    let response = store
        .authority_locking_read_snapshot(|transaction| {
            load_residue_authority(transaction, &node, &request)
        })
        .unwrap();
    assert_eq!(response.session, request.session);
    assert_eq!(response.lineage, request.lineage);
    assert_eq!(
        response.outcome,
        RuntimeResidueAuthorityOutcome::Reclaimable {
            proof: Box::new(ResidueReclaimProof::OrdinaryRelease {
                current_volume: released,
            }),
        }
    );
    let replay = store
        .authority_locking_read_snapshot(|transaction| {
            load_residue_authority(transaction, &node, &request)
        })
        .unwrap();
    assert_eq!(
        response, replay,
        "response loss must be an exact read replay"
    );

    let existing_other_workspace =
        super::product_tests::bootstrap_workspace(&store, "residue-authority-other");
    let mut mismatches = Vec::new();
    let mut mismatch = request.clone();
    mismatch.lineage.workspace_id = existing_other_workspace;
    mismatches.push(("existing cross-workspace", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.workspace_id = id("workspace-missing");
    mismatches.push(("missing workspace", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.cat_id = id("cat-missing");
    mismatches.push(("Cat", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.disk_id = id("disk-missing");
    mismatches.push(("Disk", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.volume_id = id("volume-missing");
    let AuthorizedServingAcquire::Normal {
        request: acquire_request,
        result: acquire_result,
    } = &mut mismatch.lineage.acquisition
    else {
        unreachable!("fixture is a normal acquisition")
    };
    acquire_request.volume_id = mismatch.lineage.volume_id.clone();
    acquire_result.volume_id = mismatch.lineage.volume_id.clone();
    mismatch.lineage.acquisition_digest =
        residue_acquisition_digest(&mismatch.lineage.acquisition).unwrap();
    mismatches.push(("Volume", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.desired_revision = revision(12);
    mismatches.push(("Desired revision", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.spec_digest = Sha256Digest::from_bytes([44; 32]);
    mismatches.push(("Desired digest", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.placement.placement_epoch = epoch(4);
    mismatches.push(("current placement", mismatch));
    let mut mismatch = request.clone();
    mismatch.lineage.node_id = id("node-other");
    mismatch.lineage.placement.node_id = id("node-other");
    mismatches.push(("Node", mismatch));
    let mut mismatch = request.clone();
    let other_transition = random_id(2);
    mismatch.lineage.acquire_origin = AcquireOrigin::Normal {
        transition_id: other_transition.clone(),
    };
    let AuthorizedServingAcquire::Normal {
        request: acquire_request,
        result: acquire_result,
    } = &mut mismatch.lineage.acquisition
    else {
        unreachable!("fixture is a normal acquisition")
    };
    acquire_request.transition_id = other_transition.clone();
    acquire_result.transition_id = other_transition;
    mismatch.lineage.acquisition_digest =
        residue_acquisition_digest(&mismatch.lineage.acquisition).unwrap();
    mismatches.push(("acquisition receipt", mismatch));

    let mut indistinguishable_error = None;
    for (coordinate, mismatch) in mismatches {
        let error = store
            .authority_locking_read_snapshot(|transaction| {
                load_residue_authority(transaction, &node, &mismatch)
            })
            .expect_err("a cross-bound residue request must fail closed");
        assert_eq!(error.code, ErrorCode::Internal);
        let signature = (error.code, error.message);
        if let Some(expected) = &indistinguishable_error {
            assert_eq!(
                &signature, expected,
                "{coordinate} mismatch exposed a distinguishable authority error"
            );
        } else {
            indistinguishable_error = Some(signature);
        }
    }

    store
        .authority_transaction(|transaction| {
            update_volume_owner(transaction, &owned, Some(&owned_binding))
        })
        .unwrap();
    let response = store
        .authority_locking_read_snapshot(|transaction| {
            load_residue_authority(transaction, &node, &request)
        })
        .unwrap();
    assert_eq!(
        response.outcome,
        RuntimeResidueAuthorityOutcome::Retained {
            reason: ResidueAuthorityRetentionReason::CurrentOrNewerOwner,
        }
    );
}

#[test]
fn residue_authority_disposable_tail_requires_the_consumed_completion_pair() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let owned = acquire_owned_volume(&store);
    let node = transition_node(&store, "node-new");
    let desired = prepare_residue_product_snapshot(&store, &node, &owned, revision(12), epoch(4));
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
    let completion =
        complete_disposable_root_delete(&deleting, &consumed, unix_millis(40_000)).unwrap();
    store
        .authority_transaction(|transaction| {
            update_volume_owner(transaction, &deleting, None)?;
            update_authorization(transaction, &original, &consumed)?;
            insert_delete_completion(transaction, &completion)?;
            transaction.execute("DELETE FROM disk_records WHERE disk_id=$1", &[&"disk-1"])?;
            transaction.execute(
                "DELETE FROM volume_records WHERE volume_id=$1",
                &[&owned.volume_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();
    let request = residue_authority_request(&node, &desired, 6, 4);
    let response = store
        .authority_locking_read_snapshot(|transaction| {
            load_residue_authority(transaction, &node, &request)
        })
        .unwrap();
    assert!(matches!(
        response.outcome,
        RuntimeResidueAuthorityOutcome::Reclaimable { proof }
            if matches!(proof.as_ref(), ResidueReclaimProof::DisposableRootDeleteCompletion { .. })
    ));

    let mut wrong_delete = completion.clone();
    let DeleteCompletionReceipt::DisposableRoot { delete_id, .. } = &mut wrong_delete else {
        unreachable!("fixture is a disposable-root completion")
    };
    *delete_id = id("delete-other");
    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "DELETE FROM delete_completion_receipts WHERE volume_id=$1",
                &[&owned.volume_id.as_str()],
            )?;
            insert_delete_completion(transaction, &wrong_delete)
        })
        .unwrap();
    let response = store
        .authority_locking_read_snapshot(|transaction| {
            load_residue_authority(transaction, &node, &request)
        })
        .unwrap();
    assert!(matches!(
        response.outcome,
        RuntimeResidueAuthorityOutcome::Retained { .. }
    ));

    let mut before_consumption = completion.clone();
    let DeleteCompletionReceipt::DisposableRoot { completed_at, .. } = &mut before_consumption
    else {
        unreachable!("fixture is a disposable-root completion")
    };
    *completed_at = unix_millis(19_999);
    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "DELETE FROM delete_completion_receipts WHERE volume_id=$1",
                &[&owned.volume_id.as_str()],
            )?;
            insert_delete_completion(transaction, &before_consumption)
        })
        .unwrap();
    let response = store
        .authority_locking_read_snapshot(|transaction| {
            load_residue_authority(transaction, &node, &request)
        })
        .unwrap();
    assert!(matches!(
        response.outcome,
        RuntimeResidueAuthorityOutcome::Retained { .. }
    ));
    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "DELETE FROM delete_completion_receipts WHERE volume_id=$1",
                &[&owned.volume_id.as_str()],
            )?;
            insert_delete_completion(transaction, &completion)
        })
        .unwrap();

    store
        .with(|client| {
            client
                .execute(
                    "DELETE FROM volume_authorizations WHERE authorization_id=$1",
                    &[&"delete-auth-1"],
                )
                .map(|_| ())
        })
        .unwrap();
    let response = store
        .authority_locking_read_snapshot(|transaction| {
            load_residue_authority(transaction, &node, &request)
        })
        .unwrap();
    assert_eq!(
        response.outcome,
        RuntimeResidueAuthorityOutcome::Retained {
            reason: ResidueAuthorityRetentionReason::DeleteIncomplete,
        }
    );
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

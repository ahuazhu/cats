//! PostgreSQL acceptance for terminal-Cold PersistentDisk config mutation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::persistent_disk::{
    decode_persistent_disk_binding_v2_committed_response, PersistentDiskBindingV2Request,
    PERSISTENT_DISK_BINDING_CONFLICT_BODY, PERSISTENT_DISK_BINDING_NOT_FOUND_BODY,
    PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
};
use cats_api::runtime_inventory::{
    full_inventory_digest, RuntimeInventoryBody, RuntimeInventoryReport,
};
use cats_api::runtime_lifecycle::{
    decode_immutable_runtime_config, decode_lifecycle_command_envelope,
    encode_lifecycle_command_response, lifecycle_terminal_result_digest, ColdResult, ColdSpec,
    ColdVolumeDisposition, CommandFailedResult, CommandFailureReason, ExecutionAbsenceProof,
    ImmutableRuntimeConfig, LifecycleCommand, LifecycleCommandEnvelope, LifecycleOperation,
    LifecycleOperationState, LifecyclePredecessor, LifecycleResultCommitRequest,
    LifecycleTerminalResult, NodeResult, RetainedEvidence, RuntimeVolumeAuthorityInput,
    RuntimeVolumeGuestBinding, StartSource, StartSpec, StartVolumeAuthority, VolumeTerminalReceipt,
};
use cats_api::runtime_reconciliation::{
    AgentSession, AllocatableMemoryBytes, AllocatableVcpus, ContractVersion, Epoch, FenceEpoch,
    GuestIpv4Pool, GuestIpv4PoolKind, Id, Ipv4Address, NodePlacementPolicy, NodeTransportTarget,
    RandomId128, ReleaseRequest, RuntimePlacementBlockFrontend, RuntimePlacementCapabilities,
    RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport, RuntimePlacementVmm,
    RuntimeSchedulingState, Sequence, SessionBinding, VolumeTransitionSource, WireU64,
};
use cats_storage::authority::{
    release_with_source, RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord,
};
use cats_storage::lifecycle_volume::{
    CommandNormalReleaseReceipt, CommandVolumeDurabilityProof, LifecycleVolumeCommandScope,
    LifecycleVolumeTarget,
};

use super::lifecycle_commands::{LifecycleCommandAdmission, LifecycleResultCommitOutcome};
use super::lifecycle_commands_tests::{
    acquire_genesis_start_volume, digest, fence_epoch, generation, genesis_start, id, millis,
    register_node, register_node_with_credential_digest, runtime_config as base_runtime_config,
    seed_cat, test_store, workspace_id,
};
use super::product::{
    CatRecord, DiskAdminState, DiskRecord, DiskRole, PersistentDiskInitialization,
};
use super::product_identity::ProductIdentitySource;
use super::product_mutation_service::{
    parse_authorized_persistent_disk_binding, parse_authorized_product_mutation,
    PersistentDiskBindingAction, ProductMutation, ProductMutationHttpFields,
    ProductMutationHttpResult, ProductMutationService,
};
use super::product_rows::insert_disk;
use super::rows::{
    database_now, insert_command_normal_release_receipt, insert_volume,
    load_stored_volume_for_update, update_volume_owner,
};
use super::runtime_spine::RuntimeInventoryOutcome;
use crate::store::{Result, Store};

#[derive(Default)]
struct SequentialIdentities(AtomicU64);

impl ProductIdentitySource for SequentialIdentities {
    fn random_id(&self) -> Result<RandomId128> {
        let value = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(RandomId128::new(format!("{value:032x}")).unwrap())
    }
}

fn absence_proof(value: u8) -> ExecutionAbsenceProof {
    ExecutionAbsenceProof {
        stop_fence_receipt_digest: digest(value),
        admission_closed_receipt_digest: digest(value + 1),
        dedicated_scope_absence_receipt_digest: digest(value + 2),
        frontend_absence_receipt_digest: digest(value + 3),
        restart_source_absence_receipt_digest: digest(value + 4),
    }
}

fn same_node_cold(
    head: &LifecycleOperation,
    operation_id: impl Into<String>,
    config: &ImmutableRuntimeConfig,
) -> LifecycleCommandEnvelope {
    let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &head.state
    else {
        panic!("Cold fixture requires a terminal predecessor")
    };
    LifecycleCommandEnvelope::new(
        id(operation_id),
        head.workspace_id.clone(),
        head.cat_id.clone(),
        head.node_id.clone(),
        head.placement_identity.clone(),
        config.clone(),
        Some(head.operation_id.clone()),
        LifecyclePredecessor::SameNode {
            operation_id: head.operation_id.clone(),
            terminal_result_kind: terminal.kind(),
            terminal_result_digest: terminal_result_digest.clone(),
            node_id: head.node_id.clone(),
            placement_identity: head.placement_identity.clone(),
        },
        LifecycleCommand::Cold(ColdSpec {
            grace_deadline_unix_ms: millis(30_000),
            convergence_deadline_unix_ms: millis(60_000),
        }),
    )
    .unwrap()
}

fn same_node_start_from_cold(
    head: &LifecycleOperation,
    operation_id: impl Into<String>,
    config: &ImmutableRuntimeConfig,
    expected_unowned_epoch: FenceEpoch,
) -> LifecycleCommandEnvelope {
    let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &head.state
    else {
        panic!("Start fixture requires a terminal Cold predecessor")
    };
    let volume = &config.volumes[0];
    LifecycleCommandEnvelope::new(
        id(operation_id),
        head.workspace_id.clone(),
        head.cat_id.clone(),
        head.node_id.clone(),
        head.placement_identity.clone(),
        config.clone(),
        Some(head.operation_id.clone()),
        LifecyclePredecessor::SameNode {
            operation_id: head.operation_id.clone(),
            terminal_result_kind: terminal.kind(),
            terminal_result_digest: terminal_result_digest.clone(),
            node_id: head.node_id.clone(),
            placement_identity: head.placement_identity.clone(),
        },
        LifecycleCommand::Start(Box::new(StartSpec {
            volume_authorities: vec![StartVolumeAuthority {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                    expected_unowned_epoch,
                    transition_id: RandomId128::new("dddddddddddddddddddddddddddddddd".to_owned())
                        .unwrap(),
                },
            }],
            source: StartSource::SameNodeCold,
            effect_deadline_unix_ms: millis(90_000),
        })),
    )
    .unwrap()
}

/// Use real command admission and exact storage authority transitions, then
/// terminalize Cold with a contract-valid response. The direct terminal write
/// intentionally avoids coupling these product tests to the command-scoped
/// receipt HTTP fixture; production settlement independently tests receipts.
fn seed_terminal_cold(
    store: &Store,
    workspace: &Id,
    cat: &Id,
    discriminator: u8,
) -> (ImmutableRuntimeConfig, LifecycleOperation) {
    let node = id(format!("node-{cat}"));
    let (authenticated, session) = register_node(store, &node);
    seed_terminal_cold_on_node(
        store,
        workspace,
        cat,
        discriminator,
        &node,
        &authenticated,
        &session,
    )
}

fn seed_terminal_cold_on_node(
    store: &Store,
    workspace: &Id,
    cat: &Id,
    discriminator: u8,
    node: &Id,
    authenticated: &AuthenticatedNodeCredential,
    session: &AgentSession,
) -> (ImmutableRuntimeConfig, LifecycleOperation) {
    let creation = id(format!("creation-{cat}"));
    let seeded_config = base_runtime_config(cat);
    let config = ImmutableRuntimeConfig::new(
        seeded_config.config_id.clone(),
        seeded_config.boot_image_digest.clone(),
        seeded_config.vcpus,
        seeded_config.memory_bytes,
        session.guest_config_digest.clone(),
        seeded_config.network_config.clone(),
        seeded_config.volumes.clone(),
    )
    .unwrap();
    let config_bytes = cats_api::runtime_lifecycle::encode_immutable_runtime_config(&config)
        .expect("placement-aligned fixture config must encode");
    let root = &config.volumes[0];
    let volume = VolumeRecord {
        volume_id: root.volume_id.clone(),
        size_bytes: root.size_bytes,
        durability: root.durability,
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
    let disk = DiskRecord {
        disk_id: root.disk_id.clone(),
        workspace_id: workspace.clone(),
        name: root.disk_id.clone(),
        volume_id: root.volume_id.clone(),
        size_bytes: root.size_bytes,
        durability: root.durability,
        created_at: millis(1),
        admin_state: DiskAdminState::Active,
        role: DiskRole::Root {
            cat_id: cat.clone(),
        },
    };
    store
        .authority_transaction(|transaction| {
            let cat_record = CatRecord {
                cat_id: cat.clone(),
                workspace_id: workspace.clone(),
                name: id(format!("test-{cat}")),
                created_at: millis(1),
            };
            let cat_json = serde_json::to_string(&cat_record).unwrap();
            transaction.execute(
                "INSERT INTO cat_records (
                    cat_id, record, workspace_id, name, cat_creation_id,
                    lifecycle_head_operation_id, stable_state,
                    effective_runtime_ready_operation_id, runtime_incarnation,
                    current_runtime_config_id, current_runtime_config_sha256,
                    created_at, deleted_at
                 ) VALUES ($1,$2::TEXT::jsonb,$3,$4,$5,NULL,NULL,NULL,NULL,$6,$7,1,NULL)",
                &[
                    &cat.as_str(),
                    &cat_json,
                    &workspace.as_str(),
                    &cat_record.name.as_str(),
                    &creation.as_str(),
                    &config.config_id.as_str(),
                    &config.config_digest.as_str(),
                ],
            )?;
            transaction.execute(
                "INSERT INTO cat_runtime_configs (
                    config_id, workspace_id, cat_id, canonical_config_bytes,
                    canonical_config_sha256, created_at_unix_ms
                 ) VALUES ($1,$2,$3,$4,$5,1)",
                &[
                    &config.config_id.as_str(),
                    &workspace.as_str(),
                    &cat.as_str(),
                    &config_bytes,
                    &config.config_digest.as_str(),
                ],
            )?;
            insert_volume(transaction, &volume)?;
            insert_disk(transaction, &disk)
        })
        .unwrap();
    let start = genesis_start(
        workspace,
        node,
        cat,
        &creation,
        &format!("operation-start-{cat}"),
        &config,
    );
    assert!(matches!(
        store.admit_lifecycle_command(workspace, &start).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let root = &config.volumes[0];
    let attachment_id = id(format!("attachment-cold-{cat}"));
    let (acquire, start_grant_digest) = acquire_genesis_start_volume(
        store,
        authenticated,
        session,
        &start,
        &config,
        attachment_id.clone(),
    );
    let acquired_epoch = acquire.resulting_epoch;
    let start_response = cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
        &start,
        NodeResult::StartFailed(Box::new(CommandFailedResult {
            reason: CommandFailureReason::CapacityUnavailable,
            not_running: absence_proof(discriminator),
            retained_evidence: RetainedEvidence {
                artifact_manifest_digest: digest(discriminator.saturating_add(5)),
                adoptable_count: 0,
                gc_candidate_count: 0,
                retained_authority_or_data_count: 1,
                quarantined_count: 0,
            },
            retained_volume_receipts: vec![VolumeTerminalReceipt {
                volume_id: root.volume_id.clone(),
                disk_id: root.disk_id.clone(),
                disk_role: root.disk_role,
                attachment_id: attachment_id.clone(),
                attachment_epoch: acquire.resulting_epoch,
                local_durable_generation: acquire.resulting_head.generation,
                remote_durable_generation: acquire.resulting_head.generation,
                authority_receipt_digest: Some(start_grant_digest),
            }],
        })),
    )
    .unwrap();
    let start_commit = LifecycleResultCommitRequest::new(session, start_response).unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: failed_start,
        ..
    } = store
        .commit_lifecycle_result(authenticated, &start_commit)
        .unwrap()
    else {
        panic!("StartFailed fixture did not settle")
    };

    let cold = same_node_cold(&failed_start, format!("operation-cold-{cat}"), &config);
    assert!(matches!(
        store.admit_lifecycle_command(workspace, &cold).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let (normal_release_receipt_digest, released_epoch) = store
        .authority_transaction(|transaction| {
            let current = load_stored_volume_for_update(transaction, &root.volume_id)?
                .expect("Cold fixture Volume disappeared before release");
            let release_request = ReleaseRequest {
                volume_id: root.volume_id.clone(),
                transition_id: RandomId128::new(format!(
                    "{:032x}",
                    u128::from(discriminator) + 1_000
                ))
                .unwrap(),
                attachment_id: attachment_id.clone(),
                expected_epoch: acquired_epoch,
            };
            let (released, release_result) = release_with_source(
                &current.record,
                &VolumeTransitionSource::Lifecycle {
                    operation_id: cold.operation_id.clone(),
                    request_fingerprint: cold.request_fingerprint.clone(),
                },
                &release_request,
            )?;
            update_volume_owner(transaction, &released, None)?;
            let receipt = CommandNormalReleaseReceipt {
                durability: CommandVolumeDurabilityProof {
                    scope: LifecycleVolumeCommandScope {
                        operation_id: cold.operation_id.clone(),
                        request_fingerprint: cold.request_fingerprint.clone(),
                        cat_id: cat.clone(),
                        node_id: node.clone(),
                        placement_identity: cold.placement_identity.clone(),
                    },
                    volume: LifecycleVolumeTarget {
                        disk_id: root.disk_id.clone(),
                        disk_role: root.disk_role,
                        volume_id: root.volume_id.clone(),
                        attachment_id: attachment_id.clone(),
                        attachment_epoch: acquired_epoch,
                    },
                    remote_head: released.head.clone(),
                    local_durable_generation: released.head.generation,
                    remote_durable_generation: released.head.generation,
                    pending_pack_count: WireU64::new(0).unwrap(),
                },
                request: release_request,
                result: release_result.clone(),
            };
            let digest =
                insert_command_normal_release_receipt(transaction, &cold, &released, &receipt)?;
            Ok((digest, release_result.resulting_epoch))
        })
        .unwrap();
    let response = cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
        &cold,
        NodeResult::Cold(Box::new(ColdResult {
            runtime_config_digest: config.config_digest.clone(),
            execution_absence: absence_proof(discriminator.saturating_add(10)),
            volume_dispositions: vec![ColdVolumeDisposition::NormallyReleased {
                normal_release_receipt_digest: normal_release_receipt_digest.clone(),
                volume: Box::new(VolumeTerminalReceipt {
                    volume_id: root.volume_id.clone(),
                    disk_id: root.disk_id.clone(),
                    disk_role: root.disk_role,
                    attachment_id,
                    attachment_epoch: acquired_epoch,
                    local_durable_generation: generation(0),
                    remote_durable_generation: generation(0),
                    authority_receipt_digest: Some(normal_release_receipt_digest),
                }),
            }],
            local_recovery_dependency_absent_digest: digest(discriminator.saturating_add(16)),
        })),
    )
    .unwrap();
    let canonical_result = encode_lifecycle_command_response(&response).unwrap();
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(response),
    };
    let terminal_digest = lifecycle_terminal_result_digest(&terminal).unwrap();
    store
        .authority_transaction(|transaction| {
            let terminal_at = database_now(transaction)?;
            let terminal_at = i64::try_from(terminal_at.get()).unwrap();
            let updated = transaction.execute(
                "UPDATE runtime_operations
                    SET state='terminal', terminal_source='node_result',
                        terminal_result_kind='cold', canonical_result_bytes=$2,
                        canonical_result_sha256=$3, terminal_at_unix_ms=$4
                  WHERE operation_id=$1 AND state='unresolved'",
                &[
                    &cold.operation_id.as_str(),
                    &canonical_result,
                    &terminal_digest.as_str(),
                    &terminal_at,
                ],
            )?;
            assert_eq!(updated, 1);
            let projected = transaction.execute(
                "UPDATE cat_records
                    SET lifecycle_head_operation_id=$2, stable_state='cold',
                        effective_runtime_ready_operation_id=NULL,
                        runtime_incarnation=NULL
                  WHERE workspace_id=$1 AND cat_id=$3
                    AND lifecycle_head_operation_id=$4
                    AND current_runtime_config_id=$5
                    AND current_runtime_config_sha256=$6
                    AND deleted_at IS NULL",
                &[
                    &workspace.as_str(),
                    &cold.operation_id.as_str(),
                    &cat.as_str(),
                    &failed_start.operation_id.as_str(),
                    &config.config_id.as_str(),
                    &config.config_digest.as_str(),
                ],
            )?;
            assert_eq!(projected, 1);
            Ok(())
        })
        .unwrap();
    let head = store
        .lifecycle_operation(workspace, &cold.operation_id)
        .unwrap()
        .unwrap();
    assert!(matches!(
        &head.state,
        LifecycleOperationState::Terminal {
            terminal,
            ..
        } if matches!(terminal.as_ref(), LifecycleTerminalResult::NodeResult { response }
            if matches!(&response.result, NodeResult::Cold(_)))
    ));
    assert_eq!(current_volume_epoch(store, &root.volume_id), released_epoch);
    (config, head)
}

fn establish_placement_target(
    store: &Store,
    authenticated: &AuthenticatedNodeCredential,
    session: &AgentSession,
    discriminator: u8,
) {
    let policy = NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: session.node_id.clone(),
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
            guest_config_digest: session.guest_config_digest.clone(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new(format!(
            "https://node-{discriminator}.internal:7301"
        ))
        .unwrap(),
    };
    store
        .authority_transaction(|transaction| {
            super::placement_policy::insert_policy_for_test(transaction, &policy)
        })
        .unwrap();

    let session_binding = SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    };
    let random = |offset: u8| {
        RandomId128::new(format!("{:02x}", discriminator.wrapping_add(offset)).repeat(16)).unwrap()
    };
    let mut report = RuntimeInventoryReport {
        version: ContractVersion::V1,
        session: session_binding,
        report_id: random(1),
        sequence: Sequence::new(1).unwrap(),
        collected_at_unix_ms: millis(1),
        inventory: RuntimeInventoryBody::Full {
            inventory_epoch: Epoch::new(1).unwrap(),
            scan_id: random(2),
            inventory_digest: digest(0),
            cats: Vec::new(),
            unattributed_artifacts: Vec::new(),
        },
    };
    let computed = full_inventory_digest(&report).unwrap();
    let RuntimeInventoryBody::Full {
        inventory_digest, ..
    } = &mut report.inventory
    else {
        unreachable!()
    };
    *inventory_digest = computed;
    assert!(matches!(
        store
            .runtime_accept_inventory(authenticated, &report)
            .unwrap(),
        RuntimeInventoryOutcome::Accepted(_)
    ));
}

fn blank_volume(volume_id: impl Into<String>) -> VolumeRecord {
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

fn seed_persistent_disk(
    store: &Store,
    workspace: &Id,
    disk_id: &str,
    disk_name: &str,
    volume_id: &str,
    token: u128,
    filesystem_uuid: u128,
) -> DiskRecord {
    let volume = blank_volume(volume_id);
    let disk = DiskRecord {
        disk_id: id(disk_id),
        workspace_id: workspace.clone(),
        name: id(disk_name),
        volume_id: volume.volume_id.clone(),
        size_bytes: volume.size_bytes,
        durability: volume.durability,
        created_at: millis(1),
        admin_state: DiskAdminState::Active,
        role: DiskRole::Persistent {
            initialization: Box::new(PersistentDiskInitialization::Uninitialized {
                initialization_token: RandomId128::new(format!("{token:032x}")).unwrap(),
                filesystem_uuid: RandomId128::new(format!("{filesystem_uuid:032x}")).unwrap(),
                expected_blank_head: volume.head.clone(),
            }),
        },
    };
    store
        .authority_transaction(|transaction| {
            insert_volume(transaction, &volume)?;
            insert_disk(transaction, &disk)
        })
        .unwrap();
    disk
}

fn service(store: Arc<Store>) -> ProductMutationService {
    ProductMutationService::new(
        store,
        Arc::new(SequentialIdentities::default()),
        digest(200),
    )
}

fn binding_fields(key: &str) -> ProductMutationHttpFields {
    ProductMutationHttpFields {
        content_type: vec![b"application/json".to_vec()],
        content_encoding: Vec::new(),
        if_match: Vec::new(),
        idempotency_key: vec![key.as_bytes().to_vec()],
    }
}

fn lifecycle_ingress(
    workspace: &Id,
    cat: &Id,
    key: &str,
    action: super::product_mutation_service::CatLifecycleAction,
) -> super::product_mutation_service::AuthorizedProductMutationIngress {
    let verb = match action {
        super::product_mutation_service::CatLifecycleAction::Run => "run",
        super::product_mutation_service::CatLifecycleAction::Suspend => "suspend",
        super::product_mutation_service::CatLifecycleAction::Warm => "warm",
        super::product_mutation_service::CatLifecycleAction::Cold => "cold",
        super::product_mutation_service::CatLifecycleAction::Destroy => "destroy",
    };
    let path = format!("/v1/workspaces/{workspace}/cats/{cat}/actions/{verb}");
    parse_authorized_product_mutation(
        workspace,
        Some(cat.as_str()),
        Instant::now(),
        path.as_bytes(),
        &ProductMutationHttpFields {
            content_type: Vec::new(),
            content_encoding: Vec::new(),
            if_match: Vec::new(),
            idempotency_key: vec![key.as_bytes().to_vec()],
        },
        b"",
        ProductMutation::Lifecycle(action),
    )
    .unwrap()
}

fn unresolved_command(store: &Store, cat: &Id) -> LifecycleCommandEnvelope {
    let bytes: Vec<u8> = store
        .with(|client| {
            client
                .query_one(
                    "SELECT canonical_request_bytes
                       FROM runtime_operations
                      WHERE cat_id=$1 AND state='unresolved'",
                    &[&cat.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    decode_lifecycle_command_envelope(&bytes).unwrap()
}

fn binding_ingress(
    workspace: &Id,
    disk_id: &Id,
    cat_id: &Id,
    mount_path: &str,
    key: &str,
    action: PersistentDiskBindingAction,
) -> super::product_mutation_service::AuthorizedProductMutationIngress {
    let body = serde_json::to_vec(&PersistentDiskBindingV2Request {
        cat_id: cat_id.clone(),
        mount_path: cats_api::runtime_reconciliation::HostPath::new(mount_path).unwrap(),
    })
    .unwrap();
    let path = format!(
        "/v1/workspaces/{workspace}/disks/{disk_id}/actions/{}",
        action.as_str()
    );
    parse_authorized_persistent_disk_binding(
        workspace,
        disk_id.as_str(),
        Instant::now(),
        path.as_bytes(),
        &binding_fields(key),
        &body,
        action,
    )
    .unwrap()
}

fn binding_ingress_for_exact_disk_role_test(
    workspace: &Id,
    disk_id: &Id,
    cat_id: &Id,
    mount_path: &str,
    key: &str,
) -> super::product_mutation_service::AuthorizedProductMutationIngress {
    let request = PersistentDiskBindingV2Request {
        cat_id: cat_id.clone(),
        mount_path: cats_api::runtime_reconciliation::HostPath::new(mount_path).unwrap(),
    };
    let body = serde_json::to_vec(&request).unwrap();
    let path = format!("/v1/workspaces/{workspace}/disks/{disk_id}/actions/attach");
    parse_authorized_product_mutation(
        workspace,
        None,
        Instant::now(),
        path.as_bytes(),
        &binding_fields(key),
        &body,
        ProductMutation::PersistentDiskBinding {
            action: PersistentDiskBindingAction::Attach,
            disk_id: disk_id.clone(),
            request,
        },
    )
    .unwrap()
}

fn current_config(store: &Store, cat: &Id) -> ImmutableRuntimeConfig {
    let bytes: Vec<u8> = store
        .with(|client| {
            client
                .query_one(
                    "SELECT config.canonical_config_bytes
                       FROM cat_records cat
                       JOIN cat_runtime_configs config
                         ON config.workspace_id=cat.workspace_id
                        AND config.cat_id=cat.cat_id
                        AND config.config_id=cat.current_runtime_config_id
                        AND config.canonical_config_sha256=cat.current_runtime_config_sha256
                      WHERE cat.cat_id=$1",
                    &[&cat.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    decode_immutable_runtime_config(&bytes).unwrap()
}

fn current_volume_epoch(store: &Store, volume_id: &Id) -> FenceEpoch {
    store
        .authority_transaction(|transaction| {
            Ok(load_stored_volume_for_update(transaction, volume_id)?
                .expect("test Volume disappeared")
                .record
                .lease_epoch)
        })
        .unwrap()
}

fn count_rows(store: &Store, table: &str, cat: &Id) -> i64 {
    let sql = match table {
        "configs" => "SELECT count(*) FROM cat_runtime_configs WHERE cat_id=$1",
        "operations" => "SELECT count(*) FROM runtime_operations WHERE cat_id=$1",
        _ => panic!("unsupported count table"),
    };
    store
        .with(|client| {
            client
                .query_one(sql, &[&cat.as_str()])
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

fn assert_status(result: &ProductMutationHttpResult, status: u16, body: &[u8]) {
    assert_eq!(result.http_status, status);
    assert_eq!(result.content_type, Some("application/json"));
    assert_eq!(result.response_body, body);
}

#[test]
fn two_attaches_then_exact_detach_advance_only_config_and_replay_byte_exact() {
    let store = Arc::new(test_store());
    let workspace = workspace_id(&store, "binding-config-chain");
    crate::testsupport::begin_production_qualification_for_product_test(&store, &workspace);
    let cat = id("cat_binding_config_chain");
    let (source, cold_head) = seed_terminal_cold(&store, &workspace, &cat, 20);
    let first = seed_persistent_disk(
        &store,
        &workspace,
        "disk_binding_first",
        "disk_name_first",
        "volume_binding_first",
        1,
        101,
    );
    let second = seed_persistent_disk(
        &store,
        &workspace,
        "disk_binding_second",
        "disk_name_second",
        "volume_binding_second",
        2,
        102,
    );
    let operation_count = count_rows(&store, "operations", &cat);
    let config_count = count_rows(&store, "configs", &cat);
    let service = service(Arc::clone(&store));
    let runtime = runtime();

    let attach_first = binding_ingress(
        &workspace,
        &first.disk_id,
        &cat,
        "/srv/first",
        "attach-first",
        PersistentDiskBindingAction::Attach,
    );
    let committed_first = runtime
        .block_on(service.mutate(attach_first.clone()))
        .unwrap();
    assert_eq!(committed_first.http_status, 200);
    assert_eq!(
        runtime.block_on(service.mutate(attach_first)).unwrap(),
        committed_first
    );
    let first_response =
        decode_persistent_disk_binding_v2_committed_response(&committed_first.response_body)
            .unwrap();
    assert_eq!(first_response.cat_id, cat);
    assert_eq!(first_response.disk_id, first.disk_id);

    let committed_second = runtime
        .block_on(service.mutate(binding_ingress(
            &workspace,
            &second.disk_id,
            &cat,
            "/srv/second",
            "attach-second",
            PersistentDiskBindingAction::Attach,
        )))
        .unwrap();
    assert_eq!(committed_second.http_status, 200);

    let wrong_detach = runtime
        .block_on(service.mutate(binding_ingress(
            &workspace,
            &first.disk_id,
            &cat,
            "/srv/wrong",
            "detach-wrong",
            PersistentDiskBindingAction::Detach,
        )))
        .unwrap();
    assert_status(&wrong_detach, 409, PERSISTENT_DISK_BINDING_CONFLICT_BODY);

    let detach_first = binding_ingress(
        &workspace,
        &first.disk_id,
        &cat,
        "/srv/first",
        "detach-first",
        PersistentDiskBindingAction::Detach,
    );
    let detached = runtime
        .block_on(service.mutate(detach_first.clone()))
        .unwrap();
    assert_eq!(detached.http_status, 200);
    assert_eq!(
        runtime.block_on(service.mutate(detach_first)).unwrap(),
        detached
    );

    let current = current_config(&store, &cat);
    assert_eq!(
        current.config_id,
        decode_persistent_disk_binding_v2_committed_response(&detached.response_body)
            .unwrap()
            .runtime_config_id
    );
    assert_eq!(
        current.config_digest,
        decode_persistent_disk_binding_v2_committed_response(&detached.response_body)
            .unwrap()
            .runtime_config_digest
    );
    assert_eq!(current.volumes.len(), 2);
    assert!(current.volumes.iter().any(|volume| {
        volume.disk_id == source.volumes[0].disk_id
            && matches!(volume.guest_binding, RuntimeVolumeGuestBinding::RootBoot)
    }));
    assert!(!current
        .volumes
        .iter()
        .any(|volume| volume.disk_id == first.disk_id));
    assert!(current.volumes.iter().any(|volume| {
        volume.disk_id == second.disk_id
            && matches!(
                &volume.guest_binding,
                RuntimeVolumeGuestBinding::PersistentExt4 {
                    filesystem_uuid,
                    mount_path,
                } if filesystem_uuid.as_str() == format!("{:032x}", 102)
                    && mount_path.as_str() == "/srv/second"
            )
    }));
    assert_eq!(count_rows(&store, "operations", &cat), operation_count);
    assert_eq!(count_rows(&store, "configs", &cat), config_count + 3);
    assert_eq!(
        store
            .lifecycle_operation(&workspace, &cold_head.operation_id)
            .unwrap()
            .unwrap(),
        cold_head
    );
}

#[test]
fn missing_cold_unresolved_root_disk_name_and_non_cold_head_fail_closed_without_config_write() {
    let store = Arc::new(test_store());
    let workspace = workspace_id(&store, "binding-preconditions");
    crate::testsupport::begin_production_qualification_for_product_test(&store, &workspace);
    let not_cold_cat = id("cat_binding_not_cold");
    let creation = id("creation-binding-not-cold");
    seed_cat(&store, &workspace, &not_cold_cat, &creation);
    let disk = seed_persistent_disk(
        &store,
        &workspace,
        "disk_binding_precondition",
        "disk_binding_alias",
        "volume_binding_precondition",
        11,
        111,
    );
    let service = service(Arc::clone(&store));
    let runtime = runtime();
    let before = count_rows(&store, "configs", &not_cold_cat);
    let not_cold_ingress = binding_ingress(
        &workspace,
        &disk.disk_id,
        &not_cold_cat,
        "/srv/data",
        "not-cold",
        PersistentDiskBindingAction::Attach,
    );
    let not_cold = runtime
        .block_on(service.mutate(not_cold_ingress.clone()))
        .unwrap();
    assert_status(&not_cold, 412, PERSISTENT_DISK_BINDING_PRECONDITION_BODY);
    assert_eq!(
        runtime.block_on(service.mutate(not_cold_ingress)).unwrap(),
        not_cold
    );
    assert_eq!(count_rows(&store, "configs", &not_cold_cat), before);

    let cold_cat = id("cat_binding_unresolved");
    let (cold_config, cold_head) = seed_terminal_cold(&store, &workspace, &cold_cat, 40);
    let root_rejected = runtime
        .block_on(service.mutate(binding_ingress_for_exact_disk_role_test(
            &workspace,
            &cold_config.volumes[0].disk_id,
            &cold_cat,
            "/srv/root",
            "root-role",
        )))
        .unwrap();
    assert_status(
        &root_rejected,
        412,
        PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
    );

    let alias = id("disk_binding_alias");
    let name_does_not_resolve = runtime
        .block_on(service.mutate(binding_ingress(
            &workspace,
            &alias,
            &cold_cat,
            "/srv/data",
            "name-alias",
            PersistentDiskBindingAction::Attach,
        )))
        .unwrap();
    assert_status(
        &name_does_not_resolve,
        404,
        PERSISTENT_DISK_BINDING_NOT_FOUND_BODY,
    );

    let non_cold_head = cold_head
        .expected_predecessor_operation_id
        .as_ref()
        .expect("Cold fixture must have its StartFailed predecessor");
    store
        .authority_transaction(|transaction| {
            assert_eq!(
                transaction.execute(
                    "UPDATE cat_records SET lifecycle_head_operation_id=$1 WHERE cat_id=$2",
                    &[&non_cold_head.as_str(), &cold_cat.as_str()],
                )?,
                1
            );
            Ok(())
        })
        .unwrap();
    let wrong_head = runtime
        .block_on(service.mutate(binding_ingress(
            &workspace,
            &disk.disk_id,
            &cold_cat,
            "/srv/data",
            "non-cold-head",
            PersistentDiskBindingAction::Attach,
        )))
        .unwrap();
    assert_status(&wrong_head, 412, PERSISTENT_DISK_BINDING_PRECONDITION_BODY);
    store
        .authority_transaction(|transaction| {
            assert_eq!(
                transaction.execute(
                    "UPDATE cat_records SET lifecycle_head_operation_id=$1 WHERE cat_id=$2",
                    &[&cold_head.operation_id.as_str(), &cold_cat.as_str()],
                )?,
                1
            );
            Ok(())
        })
        .unwrap();

    let unresolved = same_node_start_from_cold(
        &cold_head,
        "operation-binding-unresolved",
        &cold_config,
        current_volume_epoch(&store, &cold_config.volumes[0].volume_id),
    );
    assert!(matches!(
        store
            .admit_lifecycle_command(&workspace, &unresolved)
            .unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let cold_before = count_rows(&store, "configs", &cold_cat);
    let blocked = runtime
        .block_on(service.mutate(binding_ingress(
            &workspace,
            &disk.disk_id,
            &cold_cat,
            "/srv/data",
            "unresolved",
            PersistentDiskBindingAction::Attach,
        )))
        .unwrap();
    assert_status(&blocked, 412, PERSISTENT_DISK_BINDING_PRECONDITION_BODY);
    assert_eq!(count_rows(&store, "configs", &cold_cat), cold_before);
}

#[test]
fn concurrent_cats_competing_for_one_disk_have_exactly_one_winner() {
    let store = Arc::new(test_store());
    let workspace = workspace_id(&store, "binding-disk-race");
    crate::testsupport::begin_production_qualification_for_product_test(&store, &workspace);
    let first_cat = id("cat_binding_race_first");
    let second_cat = id("cat_binding_race_second");
    let node = id("node-binding-disk-race");
    let (authenticated, session) = register_node(&store, &node);
    seed_terminal_cold_on_node(
        &store,
        &workspace,
        &first_cat,
        60,
        &node,
        &authenticated,
        &session,
    );
    seed_terminal_cold_on_node(
        &store,
        &workspace,
        &second_cat,
        90,
        &node,
        &authenticated,
        &session,
    );
    let disk = seed_persistent_disk(
        &store,
        &workspace,
        "disk_binding_race",
        "disk_binding_race_name",
        "volume_binding_race",
        21,
        121,
    );
    let service = Arc::new(service(Arc::clone(&store)));
    let first = binding_ingress(
        &workspace,
        &disk.disk_id,
        &first_cat,
        "/srv/data",
        "race-first",
        PersistentDiskBindingAction::Attach,
    );
    let second = binding_ingress(
        &workspace,
        &disk.disk_id,
        &second_cat,
        "/srv/data",
        "race-second",
        PersistentDiskBindingAction::Attach,
    );
    let runtime = runtime();
    let (first_result, second_result) =
        runtime.block_on(async { tokio::join!(service.mutate(first), service.mutate(second)) });
    let first_result = first_result.unwrap();
    let second_result = second_result.unwrap();
    let mut statuses = [first_result.http_status, second_result.http_status];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 409]);
    let memberships = [&first_cat, &second_cat]
        .into_iter()
        .filter(|cat| {
            current_config(&store, cat)
                .volumes
                .iter()
                .any(|volume| volume.disk_id == disk.disk_id)
        })
        .count();
    assert_eq!(memberships, 1);
}

#[test]
fn concurrent_same_cat_attaches_serialize_without_lost_current_config_update() {
    let store = Arc::new(test_store());
    let workspace = workspace_id(&store, "binding-cat-race");
    crate::testsupport::begin_production_qualification_for_product_test(&store, &workspace);
    let cat = id("cat_binding_same_cat_race");
    seed_terminal_cold(&store, &workspace, &cat, 120);
    let first = seed_persistent_disk(
        &store,
        &workspace,
        "disk_binding_same_cat_first",
        "disk_same_cat_name_first",
        "volume_binding_same_cat_first",
        31,
        131,
    );
    let second = seed_persistent_disk(
        &store,
        &workspace,
        "disk_binding_same_cat_second",
        "disk_same_cat_name_second",
        "volume_binding_same_cat_second",
        32,
        132,
    );
    let service = Arc::new(service(Arc::clone(&store)));
    let first_ingress = binding_ingress(
        &workspace,
        &first.disk_id,
        &cat,
        "/srv/first",
        "same-cat-first",
        PersistentDiskBindingAction::Attach,
    );
    let second_ingress = binding_ingress(
        &workspace,
        &second.disk_id,
        &cat,
        "/srv/second",
        "same-cat-second",
        PersistentDiskBindingAction::Attach,
    );
    let runtime = runtime();
    let (first_result, second_result) = runtime.block_on(async {
        tokio::join!(
            service.mutate(first_ingress),
            service.mutate(second_ingress)
        )
    });
    assert_eq!(first_result.unwrap().http_status, 200);
    assert_eq!(second_result.unwrap().http_status, 200);
    let current = current_config(&store, &cat);
    assert_eq!(current.volumes.len(), 3);
    assert!(current
        .volumes
        .iter()
        .any(|volume| volume.disk_id == first.disk_id));
    assert!(current
        .volumes
        .iter()
        .any(|volume| volume.disk_id == second.disk_id));
}

fn exercise_cold_config_mutations_then_start(cross_node: bool) {
    let suffix = if cross_node {
        "binding-start-cross"
    } else {
        "binding-start-same"
    };
    let store = Arc::new(test_store());
    let workspace = workspace_id(&store, suffix);
    crate::testsupport::begin_production_qualification_for_product_test(&store, &workspace);
    let cat = id(format!("cat_{suffix}"));
    let source_node = id(format!("node_z_{suffix}"));
    let (source_authenticated, source_session) = register_node(&store, &source_node);
    let (cold_config, cold_head) = seed_terminal_cold_on_node(
        &store,
        &workspace,
        &cat,
        150,
        &source_node,
        &source_authenticated,
        &source_session,
    );
    establish_placement_target(&store, &source_authenticated, &source_session, 150);

    let expected_target_node = if cross_node {
        let target_node = id(format!("node_a_{suffix}"));
        let (target_authenticated, target_session) =
            register_node_with_credential_digest(&store, &target_node, digest(83));
        establish_placement_target(&store, &target_authenticated, &target_session, 180);
        target_node
    } else {
        source_node.clone()
    };

    let first = seed_persistent_disk(
        &store,
        &workspace,
        &format!("disk_{suffix}_first"),
        &format!("disk_name_{suffix}_first"),
        &format!("volume_{suffix}_first"),
        61,
        161,
    );
    let second = seed_persistent_disk(
        &store,
        &workspace,
        &format!("disk_{suffix}_second"),
        &format!("disk_name_{suffix}_second"),
        &format!("volume_{suffix}_second"),
        62,
        162,
    );
    let service = service(Arc::clone(&store));
    let runtime = runtime();
    for (disk, mount, key, action) in [
        (
            &first,
            "/srv/first",
            "attach-first-before-start",
            PersistentDiskBindingAction::Attach,
        ),
        (
            &second,
            "/srv/second",
            "attach-second-before-start",
            PersistentDiskBindingAction::Attach,
        ),
        (
            &first,
            "/srv/first",
            "detach-first-before-start",
            PersistentDiskBindingAction::Detach,
        ),
    ] {
        let result = runtime
            .block_on(service.mutate(binding_ingress(
                &workspace,
                &disk.disk_id,
                &cat,
                mount,
                key,
                action,
            )))
            .unwrap();
        assert_eq!(result.http_status, 200);
    }
    let pre_start_config = current_config(&store, &cat);
    assert_eq!(pre_start_config.volumes.len(), 2);
    assert!(pre_start_config
        .volumes
        .iter()
        .any(|volume| volume.volume_id == cold_config.volumes[0].volume_id));
    assert!(pre_start_config
        .volumes
        .iter()
        .any(|volume| volume.volume_id == second.volume_id));
    assert!(!pre_start_config
        .volumes
        .iter()
        .any(|volume| volume.volume_id == first.volume_id));

    let run = runtime
        .block_on(service.mutate(lifecycle_ingress(
            &workspace,
            &cat,
            "run-after-config-mutations",
            super::product_mutation_service::CatLifecycleAction::Run,
        )))
        .unwrap();
    assert_eq!(run.http_status, 202);
    let command = unresolved_command(&store, &cat);
    assert_eq!(command.node_id, expected_target_node);
    assert_eq!(command.runtime_config.volumes, pre_start_config.volumes);
    assert_eq!(current_config(&store, &cat), *command.runtime_config);

    let LifecycleCommand::Start(spec) = &command.command else {
        panic!("accepted successor is not Start")
    };
    assert_eq!(
        spec.volume_authorities.len(),
        command.runtime_config.volumes.len()
    );
    for (volume, authority) in command
        .runtime_config
        .volumes
        .iter()
        .zip(&spec.volume_authorities)
    {
        assert_eq!(authority.volume_id, volume.volume_id);
        assert_eq!(authority.disk_id, volume.disk_id);
        let RuntimeVolumeAuthorityInput::NormalUnowned {
            expected_unowned_epoch,
            ..
        } = &authority.authority
        else {
            panic!("Cold successor inferred a non-NormalUnowned authority")
        };
        assert_eq!(
            *expected_unowned_epoch,
            current_volume_epoch(&store, &volume.volume_id)
        );
    }

    if cross_node {
        assert_eq!(spec.source, StartSource::ColdHandoff);
        let LifecyclePredecessor::CrossNodeColdHandoff {
            cold_operation_id,
            volume_disposition_receipts,
            ..
        } = &command.predecessor
        else {
            panic!("cross-Node Start omitted its Cold handoff")
        };
        assert_eq!(cold_operation_id, &cold_head.operation_id);
        assert_eq!(volume_disposition_receipts.len(), cold_config.volumes.len());
        assert_ne!(
            volume_disposition_receipts.len(),
            command.runtime_config.volumes.len(),
            "old Cold receipts must not be rewritten to match the new config"
        );
    } else {
        assert_eq!(spec.source, StartSource::SameNodeCold);
        assert!(matches!(
            &command.predecessor,
            LifecyclePredecessor::SameNode { operation_id, .. }
                if operation_id == &cold_head.operation_id
        ));
    }
}

#[test]
fn cold_attach_detach_chain_admits_same_node_start_from_latest_config() {
    exercise_cold_config_mutations_then_start(false);
}

#[test]
fn cold_attach_detach_chain_admits_cross_node_handoff_from_latest_config() {
    exercise_cold_config_mutations_then_start(true);
}

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use cats_api::runtime_inventory::{
    full_inventory_digest, ObservedCatRuntimeTelemetry, ObservedCommandJournal,
    ObservedRuntimePhysicalState, ObservedVolumeAttachment, ObservedVolumeWatermark,
    ObservedVolumeWatermarkSummary, RuntimeInventoryAcceptanceKind, RuntimeInventoryBody,
    RuntimeInventoryReport,
};
use cats_api::runtime_lifecycle::{
    ColdSpec, CommandFailedResult, CommandFailureReason, ExecutionAbsenceProof,
    ImmutableRuntimeConfig, LifecycleCommand, LifecycleCommandEnvelope, LifecycleCommandKind,
    LifecycleCommandResponse, LifecycleOperation, LifecycleOperationState, LifecyclePredecessor,
    LifecycleResultCommitRequest, NodeResult, RetainedEvidence, RuntimeVolumeAuthorityInput,
    RuntimeVolumeConfig, RuntimeVolumeGuestBinding, StartSource, StartSpec, StartVolumeAuthority,
    VolumeTerminalReceipt,
};
use cats_api::runtime_lifecycle_volume::{
    encode_persistent_initialization_commit_receipt, LifecyclePersistentGuestFilesystemState,
    LifecyclePersistentInitializationBinding, LifecyclePersistentInitializationCommitRequest,
    LifecyclePersistentInitializationFlushDrainReceipt,
    LifecyclePersistentInitializationGuestProbe, LifecyclePersistentInitializationInspectRequest,
    LifecyclePersistentInitializationState, LifecycleStartVolumeAction, LifecycleStartVolumeBatch,
    LifecycleStartVolumeGrantAuthority as WireStartGrantAuthority, LifecycleStoredStartVolumeGrant,
    LifecycleVolumeDurabilityProof, LifecycleVolumeStrongStopEvidence,
    LifecycleVolumeTarget as WireLifecycleVolumeTarget,
};
use cats_api::runtime_reconciliation::{
    AsciiText, ContractVersion, Durability, Epoch, FenceEpoch, Generation, RemoteHead, Sequence,
    WireU64,
};
use cats_storage::authority::{VolumeAdminState, VolumeRecord};
use cats_storage::lifecycle_volume::{
    ColdCommandVolumeSet, CommandNormalReleaseInput, CommandVolumeDurabilityProof,
    LifecycleVolumeCommandScope, LifecycleVolumeTarget,
};

use super::lifecycle_commands::{LifecycleCommandAdmission, LifecycleResultCommitOutcome};
use super::lifecycle_commands_tests::{
    digest, genesis_start, id, millis, placement, random, register_node, replace_session,
    runtime_config, seed_cat, session_binding, workspace_id,
};
use super::lifecycle_volume_transitions::{
    LifecycleVolumeTransition, LifecycleVolumeTransitionApplied, LifecycleVolumeTransitionOutcome,
    LifecycleVolumeTransitionRejection, LifecycleVolumeTransitionRequest,
    RequestedVolumeDispositionInput, StoredVolumeDisposition,
};
use super::placement_planner::runtime_config_placement_claims;
use super::product::{
    CatRecord, DiskAdminState, DiskRecord, DiskRole as ProductDiskRole,
    PersistentDiskInitialization,
};
use super::product_rows::{insert_disk, load_disk_by_id_for_update};
use super::rows::{
    insert_volume, load_command_normal_release_receipt_for_update,
    load_command_start_volume_grant_receipt_for_update, load_stored_volume_for_update,
    update_volume_owner,
};
use super::runtime_spine::RuntimeInventoryOutcome;
use crate::store::Store;

struct ColdFixture {
    authenticated: cats_api::agent_registration::AuthenticatedNodeCredential,
    request: LifecycleVolumeTransitionRequest,
}

struct PersistentInitializationFixture {
    authenticated: cats_api::agent_registration::AuthenticatedNodeCredential,
    session: cats_api::runtime_reconciliation::AgentSession,
    operation: LifecycleCommandEnvelope,
    binding: LifecyclePersistentInitializationBinding,
    initialization_token: cats_api::runtime_reconciliation::RandomId128,
    filesystem_uuid: cats_api::runtime_reconciliation::RandomId128,
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).unwrap(),
        root_hash: None,
        root_object_id: None,
    }
}

fn initialized_head(value: u64) -> RemoteHead {
    RemoteHead {
        generation: Generation::new(value).unwrap(),
        root_hash: Some(digest(u8::try_from(value).unwrap())),
        root_object_id: Some(AsciiText::new(format!("roots/{value}")).unwrap()),
    }
}

fn setup_persistent_initialization(store: &Store, suffix: &str) -> PersistentInitializationFixture {
    setup_persistent_initialization_with_lease(store, suffix, WireU64::new(60_000).unwrap())
}

fn setup_persistent_initialization_with_lease(
    store: &Store,
    suffix: &str,
    lease_duration_ms: WireU64,
) -> PersistentInitializationFixture {
    let workspace = workspace_id(store, suffix);
    let node = id(format!("node-{suffix}"));
    let cat = id(format!("cat-{suffix}"));
    let creation = id(format!("creation-{suffix}"));
    let base = runtime_config(&cat);
    let root = base.volumes[0].clone();
    let initialization_token = random(210);
    let filesystem_uuid = random(211);
    let persistent = RuntimeVolumeConfig {
        volume_id: id(format!("volume-z-{cat}")),
        disk_id: id(format!("disk-z-{cat}")),
        disk_role: cats_api::runtime_lifecycle::DiskRole::Persistent,
        size_bytes: 16 * 1024 * 1024,
        durability: Durability::Strict,
        guest_device_serial: id("persistent-data"),
        guest_device_slot: 1,
        guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
            filesystem_uuid: filesystem_uuid.clone(),
            mount_path: AsciiText::new("/data").unwrap(),
        },
    };
    let config = ImmutableRuntimeConfig::new(
        id(format!("config-persistent-{cat}")),
        base.boot_image_digest,
        base.vcpus,
        base.memory_bytes,
        base.guest_runtime_profile_digest,
        base.network_config,
        vec![root.clone(), persistent.clone()],
    )
    .unwrap();
    let config_bytes =
        cats_api::runtime_lifecycle::encode_immutable_runtime_config(&config).unwrap();
    let cat_record = CatRecord {
        cat_id: cat.clone(),
        workspace_id: workspace.clone(),
        name: id(format!("test-{cat}")),
        created_at: millis(1),
    };
    let root_volume = VolumeRecord {
        volume_id: root.volume_id.clone(),
        size_bytes: root.size_bytes,
        durability: root.durability,
        admin_state: VolumeAdminState::Active,
        head: blank_head(),
        lease_owner: None,
        lease_epoch: FenceEpoch::new(0).unwrap(),
        lease_expires_at: None,
        last_transition: None,
    };
    let persistent_volume = VolumeRecord {
        volume_id: persistent.volume_id.clone(),
        size_bytes: persistent.size_bytes,
        durability: persistent.durability,
        admin_state: VolumeAdminState::Active,
        head: blank_head(),
        lease_owner: None,
        lease_epoch: FenceEpoch::new(0).unwrap(),
        lease_expires_at: None,
        last_transition: None,
    };
    let root_disk = DiskRecord {
        disk_id: root.disk_id.clone(),
        workspace_id: workspace.clone(),
        name: root.disk_id.clone(),
        volume_id: root.volume_id.clone(),
        size_bytes: root.size_bytes,
        durability: root.durability,
        created_at: millis(1),
        admin_state: DiskAdminState::Active,
        role: ProductDiskRole::Root {
            cat_id: cat.clone(),
        },
    };
    let persistent_disk = DiskRecord {
        disk_id: persistent.disk_id.clone(),
        workspace_id: workspace.clone(),
        name: id(format!("data-{suffix}")),
        volume_id: persistent.volume_id.clone(),
        size_bytes: persistent.size_bytes,
        durability: persistent.durability,
        created_at: millis(1),
        admin_state: DiskAdminState::Active,
        role: ProductDiskRole::Persistent {
            initialization: Box::new(PersistentDiskInitialization::Uninitialized {
                initialization_token: initialization_token.clone(),
                filesystem_uuid: filesystem_uuid.clone(),
                expected_blank_head: blank_head(),
            }),
        },
    };
    let placement_claims = runtime_config_placement_claims(&config).unwrap();
    store
        .authority_transaction(|transaction| {
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
                    canonical_config_sha256, placement_vcpus,
                    placement_memory_bytes, placement_network_id,
                    placement_ipv4_pool_base, placement_ipv4_slot, placement_disk_ids,
                    placement_volume_ids, created_at_unix_ms
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1)",
                &[
                    &config.config_id.as_str(),
                    &workspace.as_str(),
                    &cat.as_str(),
                    &config_bytes,
                    &config.config_digest.as_str(),
                    &placement_claims.vcpus,
                    &placement_claims.memory_bytes,
                    &placement_claims.network_id.as_str(),
                    &placement_claims.ipv4_pool_base,
                    &placement_claims.isolated_ipv4_slot,
                    &placement_claims.disk_ids,
                    &placement_claims.volume_ids,
                ],
            )?;
            insert_volume(transaction, &root_volume)?;
            insert_volume(transaction, &persistent_volume)?;
            insert_disk(transaction, &root_disk)?;
            insert_disk(transaction, &persistent_disk)?;
            Ok(())
        })
        .unwrap();

    let operation = LifecycleCommandEnvelope::new(
        id(format!("operation-start-{suffix}")),
        workspace,
        cat.clone(),
        node.clone(),
        placement(&node),
        config.clone(),
        None,
        LifecyclePredecessor::Genesis {
            cat_creation_id: creation,
            target_placement: placement(&node),
        },
        LifecycleCommand::Start(Box::new(StartSpec {
            volume_authorities: config
                .volumes
                .iter()
                .enumerate()
                .map(|(index, volume)| StartVolumeAuthority {
                    volume_id: volume.volume_id.clone(),
                    disk_id: volume.disk_id.clone(),
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                        transition_id: random(220 + u8::try_from(index).unwrap()),
                    },
                })
                .collect(),
            source: StartSource::Genesis,
            effect_deadline_unix_ms: millis(120_000),
        })),
    )
    .unwrap();
    assert!(matches!(
        store
            .admit_lifecycle_command(&operation.workspace_id, &operation)
            .unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let (authenticated, session) = register_node(store, &node);
    let scope = LifecycleVolumeCommandScope {
        operation_id: operation.operation_id.clone(),
        request_fingerprint: operation.request_fingerprint.clone(),
        cat_id: cat,
        node_id: node,
        placement_identity: operation.placement_identity.clone(),
    };
    let LifecycleCommand::Start(spec) = &operation.command else {
        unreachable!()
    };
    let actions = config
        .volumes
        .iter()
        .zip(&spec.volume_authorities)
        .enumerate()
        .map(|(index, (volume, authority))| {
            let RuntimeVolumeAuthorityInput::NormalUnowned {
                expected_unowned_epoch,
                transition_id,
            } = &authority.authority
            else {
                unreachable!()
            };
            LifecycleStartVolumeAction::NormalAcquire {
                volume: volume.clone(),
                expected_unowned_epoch: *expected_unowned_epoch,
                transition_id: transition_id.clone(),
                requested_attachment_id: id(format!("attachment-{index}-{suffix}")),
                lease_duration_ms,
            }
        })
        .collect();
    let start = LifecycleVolumeTransitionRequest {
        session: session_binding(&session),
        transition: LifecycleVolumeTransition::StartVolumes {
            scope: scope.clone(),
            batch: LifecycleStartVolumeBatch {
                scope: super::lifecycle_volume_transitions::scope_to_wire(&scope),
                grant_sequence: WireU64::new(0).unwrap(),
                renewal_lease_duration_ms: lease_duration_ms,
                actions,
            },
        },
    };
    let start_outcome = store
        .apply_lifecycle_volume_transition(&authenticated, &start)
        .unwrap();
    let applied = match start_outcome {
        LifecycleVolumeTransitionOutcome::Applied(applied) => *applied,
        other => panic!("Persistent fixture failed to acquire: {other:?}"),
    };
    let LifecycleVolumeTransitionApplied::StartVolumesReady { grants, .. } = applied else {
        panic!("Persistent fixture returned the wrong result")
    };
    let persistent_grant = grants
        .into_iter()
        .find(|grant| grant.receipt.volume.volume_id == persistent.volume_id)
        .unwrap();
    let binding = LifecyclePersistentInitializationBinding {
        scope: super::lifecycle_volume_transitions::scope_to_wire(&scope),
        runtime_config_id: config.config_id.clone(),
        runtime_config_digest: config.config_digest.clone(),
        volume: persistent,
        start_grant: LifecycleStoredStartVolumeGrant {
            receipt: persistent_grant.receipt,
            receipt_digest: persistent_grant.receipt_digest,
        },
    };
    PersistentInitializationFixture {
        authenticated,
        session,
        operation,
        binding,
        initialization_token,
        filesystem_uuid,
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

fn failed_start(retained_volume_receipts: Vec<VolumeTerminalReceipt>) -> NodeResult {
    NodeResult::StartFailed(Box::new(CommandFailedResult {
        reason: CommandFailureReason::CapacityUnavailable,
        not_running: absence_proof(40),
        retained_evidence: RetainedEvidence {
            artifact_manifest_digest: digest(50),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 1,
            quarantined_count: 0,
        },
        retained_volume_receipts,
    }))
}

fn same_node_cold(
    head: &LifecycleOperation,
    operation_id: &str,
    config: &ImmutableRuntimeConfig,
) -> LifecycleCommandEnvelope {
    let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &head.state
    else {
        panic!("Cold predecessor must be terminal")
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

fn setup_cold(store: &Store, suffix: &str) -> ColdFixture {
    let workspace = workspace_id(store, suffix);
    let node = id(format!("node-{suffix}"));
    let cat = id(format!("cat-{suffix}"));
    let creation = id(format!("creation-{suffix}"));
    let config = seed_cat(store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        &format!("operation-start-{suffix}"),
        &config,
    );
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &start).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let (authenticated, session) = register_node(store, &node);
    let config_volume = &config.volumes[0];
    let LifecycleCommand::Start(start_spec) = &start.command else {
        unreachable!()
    };
    let RuntimeVolumeAuthorityInput::NormalUnowned {
        expected_unowned_epoch,
        transition_id,
    } = &start_spec.volume_authorities[0].authority
    else {
        panic!("Genesis fixture must use normal acquire")
    };
    let attachment_id = id(format!("attachment-{suffix}"));
    let start_scope = LifecycleVolumeCommandScope {
        operation_id: start.operation_id.clone(),
        request_fingerprint: start.request_fingerprint.clone(),
        cat_id: cat.clone(),
        node_id: node.clone(),
        placement_identity: placement(&node),
    };
    let start_request = LifecycleVolumeTransitionRequest {
        session: session_binding(&session),
        transition: LifecycleVolumeTransition::StartVolumes {
            scope: start_scope.clone(),
            batch: LifecycleStartVolumeBatch {
                scope: super::lifecycle_volume_transitions::scope_to_wire(&start_scope),
                grant_sequence: WireU64::new(0).unwrap(),
                renewal_lease_duration_ms: WireU64::new(30_000).unwrap(),
                actions: vec![LifecycleStartVolumeAction::NormalAcquire {
                    volume: config_volume.clone(),
                    expected_unowned_epoch: *expected_unowned_epoch,
                    transition_id: transition_id.clone(),
                    requested_attachment_id: attachment_id.clone(),
                    lease_duration_ms: WireU64::new(30_000).unwrap(),
                }],
            },
        },
    };
    let first_start = store
        .apply_lifecycle_volume_transition(&authenticated, &start_request)
        .unwrap();
    let LifecycleVolumeTransitionOutcome::Applied(first_start_applied) = &first_start else {
        panic!("Start volume acquire failed: {first_start:?}")
    };
    let LifecycleVolumeTransitionApplied::StartVolumesReady {
        grant_sequence,
        grants,
    } = first_start_applied.as_ref()
    else {
        panic!("Start volume acquire returned the wrong result: {first_start:?}")
    };
    assert_eq!(*grant_sequence, WireU64::new(0).unwrap());
    let WireStartGrantAuthority::NormalAcquire { result, .. } = &grants[0].receipt.authority else {
        unreachable!()
    };
    let acquired_epoch = result.resulting_epoch;
    let mut retained_volume_receipt = VolumeTerminalReceipt {
        volume_id: config_volume.volume_id.clone(),
        disk_id: config_volume.disk_id.clone(),
        disk_role: config_volume.disk_role,
        attachment_id: attachment_id.clone(),
        attachment_epoch: acquired_epoch,
        local_durable_generation: result.resulting_head.generation,
        remote_durable_generation: result.resulting_head.generation,
        authority_receipt_digest: Some(grants[0].receipt_digest.clone()),
    };
    // Lost-response replay is exact and never extends the lease.
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&authenticated, &start_request)
            .unwrap(),
        first_start
    );
    store
        .authority_transaction(|transaction| {
            let stored = load_command_start_volume_grant_receipt_for_update(
                transaction,
                &start.operation_id,
                &config_volume.volume_id,
                0,
            )?
            .expect("Start authority mutation and receipt must commit together");
            assert_eq!(stored.receipt_digest, grants[0].receipt_digest);
            Ok(())
        })
        .unwrap();
    let renew_request = LifecycleVolumeTransitionRequest {
        session: session_binding(&session),
        transition: LifecycleVolumeTransition::StartVolumes {
            scope: start_scope.clone(),
            batch: LifecycleStartVolumeBatch {
                scope: super::lifecycle_volume_transitions::scope_to_wire(&start_scope),
                grant_sequence: WireU64::new(1).unwrap(),
                renewal_lease_duration_ms: WireU64::new(40_000).unwrap(),
                actions: vec![LifecycleStartVolumeAction::RenewSameNode {
                    volume: config_volume.clone(),
                    attachment_id: attachment_id.clone(),
                    attachment_epoch: acquired_epoch,
                    lease_duration_ms: WireU64::new(40_000).unwrap(),
                }],
            },
        },
    };
    let first_renew = store
        .apply_lifecycle_volume_transition(&authenticated, &renew_request)
        .unwrap();
    assert!(matches!(
        &first_renew,
        LifecycleVolumeTransitionOutcome::Applied(applied)
            if matches!(applied.as_ref(), LifecycleVolumeTransitionApplied::StartVolumesReady {
                grant_sequence,
                grants,
            } if *grant_sequence == WireU64::new(1).unwrap()
                && matches!(grants[0].receipt.authority, WireStartGrantAuthority::RenewSameNode { .. }))
    ));
    let LifecycleVolumeTransitionOutcome::Applied(renewed) = &first_renew else {
        unreachable!()
    };
    let LifecycleVolumeTransitionApplied::StartVolumesReady { grants, .. } = renewed.as_ref()
    else {
        unreachable!()
    };
    retained_volume_receipt.authority_receipt_digest = Some(grants[0].receipt_digest.clone());
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&authenticated, &renew_request)
            .unwrap(),
        first_renew
    );
    let mut skipped = renew_request.clone();
    let LifecycleVolumeTransition::StartVolumes { batch, .. } = &mut skipped.transition else {
        unreachable!()
    };
    batch.grant_sequence = WireU64::new(3).unwrap();
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&authenticated, &skipped)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::InvalidCommandBinding
        )
    );
    let commit = LifecycleResultCommitRequest::new(
        &session,
        LifecycleCommandResponse::new(&start, failed_start(vec![retained_volume_receipt])).unwrap(),
    )
    .unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: start_head,
        ..
    } = store
        .commit_lifecycle_result(&authenticated, &commit)
        .unwrap()
    else {
        panic!("Start failure did not become the Cat head")
    };
    let cold = same_node_cold(&start_head, &format!("operation-cold-{suffix}"), &config);
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &cold).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));

    let scope = LifecycleVolumeCommandScope {
        operation_id: cold.operation_id.clone(),
        request_fingerprint: cold.request_fingerprint.clone(),
        cat_id: cat.clone(),
        node_id: node.clone(),
        placement_identity: placement(&node),
    };
    let target = LifecycleVolumeTarget {
        disk_id: config_volume.disk_id.clone(),
        disk_role: config_volume.disk_role,
        volume_id: config_volume.volume_id.clone(),
        attachment_id,
        attachment_epoch: acquired_epoch,
    };
    let proof = CommandVolumeDurabilityProof {
        scope: scope.clone(),
        volume: target.clone(),
        remote_head: RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        },
        local_durable_generation: Generation::new(0).unwrap(),
        remote_durable_generation: Generation::new(0).unwrap(),
        pending_pack_count: WireU64::new(0).unwrap(),
    };
    let mut full = RuntimeInventoryReport {
        version: ContractVersion::V1,
        session: session_binding(&session),
        report_id: random(93),
        sequence: Sequence::new(1).unwrap(),
        collected_at_unix_ms: millis(20_000),
        inventory: RuntimeInventoryBody::Full {
            inventory_epoch: Epoch::new(1).unwrap(),
            scan_id: random(94),
            inventory_digest: digest(0),
            cats: vec![ObservedCatRuntimeTelemetry {
                cat_id: cat.clone(),
                observed_placement: placement(&node),
                observed_command_journal: Some(ObservedCommandJournal::Executing {
                    operation_id: cold.operation_id.clone(),
                    command_kind: LifecycleCommandKind::Cold,
                    request_fingerprint: cold.request_fingerprint.clone(),
                    journal_digest: digest(95),
                }),
                observed_physical_state: ObservedRuntimePhysicalState::Absent,
                observed_runtime_incarnation: None,
                observed_artifact_manifest_digest: digest(96),
                observed_artifact_classifications: Vec::new(),
                observed_volumes: vec![ObservedVolumeWatermarkSummary {
                    volume_id: target.volume_id.clone(),
                    disk_id: target.disk_id.clone(),
                    disk_role: target.disk_role,
                    observed_attachment: ObservedVolumeAttachment::Owned {
                        owner_node_id: node.clone(),
                        attachment_id: target.attachment_id.clone(),
                        attachment_epoch: target.attachment_epoch,
                    },
                    observed_watermark: ObservedVolumeWatermark::Known {
                        local_durable_generation: proof.local_durable_generation,
                        remote_durable_generation: proof.remote_durable_generation,
                    },
                }],
                observed_conditions: Vec::new(),
            }],
            unattributed_artifacts: Vec::new(),
        },
    };
    let computed = full_inventory_digest(&full).unwrap();
    let RuntimeInventoryBody::Full {
        inventory_digest, ..
    } = &mut full.inventory
    else {
        unreachable!()
    };
    *inventory_digest = computed;
    let RuntimeInventoryOutcome::Accepted(acceptance) = store
        .runtime_accept_inventory(&authenticated, &full)
        .unwrap()
    else {
        panic!("post-stop Full was rejected")
    };
    let RuntimeInventoryAcceptanceKind::Full { attestation } = acceptance.inventory else {
        unreachable!()
    };
    ColdFixture {
        authenticated,
        request: LifecycleVolumeTransitionRequest {
            session: session_binding(&session),
            transition: LifecycleVolumeTransition::ColdRelease {
                command: ColdCommandVolumeSet {
                    scope,
                    volumes: vec![target.identity()],
                },
                volumes: vec![RequestedVolumeDispositionInput::OwnedRelease(Box::new(
                    CommandNormalReleaseInput {
                        durability: proof,
                        transition_id: random(92),
                    },
                ))],
                strong_stop: Box::new(LifecycleVolumeStrongStopEvidence {
                    execution_absence: absence_proof(100),
                    post_stop_inventory_attestation: *attestation,
                }),
            },
        },
    }
}

fn request_scope(request: &LifecycleVolumeTransitionRequest) -> &LifecycleVolumeCommandScope {
    let LifecycleVolumeTransition::ColdRelease { command, .. } = &request.transition else {
        panic!("fixture must contain Cold")
    };
    &command.scope
}

fn request_volume(request: &LifecycleVolumeTransitionRequest) -> &LifecycleVolumeTarget {
    let LifecycleVolumeTransition::ColdRelease { volumes, .. } = &request.transition else {
        panic!("fixture must contain Cold")
    };
    let RequestedVolumeDispositionInput::OwnedRelease(input) = &volumes[0] else {
        panic!("fixture must contain an Owned release")
    };
    &input.durability.volume
}

#[test]
fn cold_release_is_atomic_persists_exact_receipt_and_replays_after_response_loss() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let fixture = setup_cold(&store, "volume-receipt");

    let mut malformed = fixture.request.clone();
    let LifecycleVolumeTransition::ColdRelease { volumes, .. } = &mut malformed.transition else {
        unreachable!()
    };
    let RequestedVolumeDispositionInput::OwnedRelease(input) = &mut volumes[0] else {
        unreachable!()
    };
    input.durability.pending_pack_count = WireU64::new(1).unwrap();
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &malformed)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::AuthorityRejected
        )
    );
    let target = request_volume(&fixture.request);
    store
        .authority_transaction(|transaction| {
            let current = load_stored_volume_for_update(transaction, &target.volume_id)?
                .expect("malformed proof must retain the Volume");
            assert_eq!(
                current.record.lease_owner.as_ref(),
                Some(&target.attachment_id)
            );
            assert!(load_command_normal_release_receipt_for_update(
                transaction,
                &request_scope(&fixture.request).operation_id,
                &target.volume_id,
            )?
            .is_none());
            Ok(())
        })
        .unwrap();

    let first = store
        .apply_lifecycle_volume_transition(&fixture.authenticated, &fixture.request)
        .unwrap();
    let LifecycleVolumeTransitionOutcome::Applied(first_applied) = &first else {
        panic!("valid Cold release was rejected: {first:?}")
    };
    let LifecycleVolumeTransitionApplied::ColdReleased { dispositions } = first_applied.as_ref()
    else {
        panic!("valid Cold release returned the wrong result: {first:?}")
    };
    assert_eq!(dispositions.len(), 1);
    let StoredVolumeDisposition::NormallyReleased(release) = &dispositions[0] else {
        unreachable!()
    };
    let first_digest = release.receipt_digest.clone();
    store
        .authority_transaction(|transaction| {
            let current = load_stored_volume_for_update(transaction, &target.volume_id)?
                .expect("Cold retains the Volume row");
            assert!(current.record.lease_owner.is_none());
            assert!(current.owner_binding.is_none());
            let stored = load_command_normal_release_receipt_for_update(
                transaction,
                &request_scope(&fixture.request).operation_id,
                &target.volume_id,
            )?
            .expect("release and immutable receipt must commit together");
            assert_eq!(stored.receipt_digest, first_digest);
            assert_eq!(stored.receipt, release.receipt);
            Ok(())
        })
        .unwrap();

    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &fixture.request)
            .unwrap(),
        first
    );

    let mut cross_operation = fixture.request.clone();
    let LifecycleVolumeTransition::ColdRelease {
        command, volumes, ..
    } = &mut cross_operation.transition
    else {
        unreachable!()
    };
    command.scope.request_fingerprint = digest(201);
    let RequestedVolumeDispositionInput::OwnedRelease(input) = &mut volumes[0] else {
        unreachable!()
    };
    input.durability.scope.request_fingerprint = digest(201);
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &cross_operation)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::InvalidCommandBinding
        )
    );
}

#[test]
fn persistent_initialization_signed_vertical_replays_across_session_replacement() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let fixture = setup_persistent_initialization_with_lease(
        &store,
        "persistent-init",
        WireU64::new(1).unwrap(),
    );
    thread::sleep(Duration::from_millis(10));
    let latest_grant_is_expired = store
        .authority_transaction(|transaction| {
            Ok(transaction
                .query_one(
                    "SELECT lease_expires_at <
                                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                       FROM volume_records WHERE volume_id=$1",
                    &[&fixture.binding.volume.volume_id.as_str()],
                )?
                .get::<_, bool>(0))
        })
        .unwrap();
    assert!(latest_grant_is_expired);
    let scope = LifecycleVolumeCommandScope {
        operation_id: fixture.operation.operation_id.clone(),
        request_fingerprint: fixture.operation.request_fingerprint.clone(),
        cat_id: fixture.operation.cat_id.clone(),
        node_id: fixture.operation.node_id.clone(),
        placement_identity: fixture.operation.placement_identity.clone(),
    };
    let inspect = LifecycleVolumeTransitionRequest {
        session: session_binding(&fixture.session),
        transition: LifecycleVolumeTransition::InspectPersistentInitialization {
            scope: scope.clone(),
            inspect: Box::new(LifecyclePersistentInitializationInspectRequest {
                binding: Box::new(fixture.binding.clone()),
            }),
        },
    };
    assert!(matches!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &inspect)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Applied(applied) if matches!(
            applied.as_ref(),
            LifecycleVolumeTransitionApplied::PersistentInitializationInspected { inspection }
                if matches!(
            inspection.initialization,
            LifecyclePersistentInitializationState::Uninitialized {
                ref initialization_token,
                ref filesystem_uuid,
                ref expected_blank_head,
            } if initialization_token == &fixture.initialization_token
                && filesystem_uuid == &fixture.filesystem_uuid
                && expected_blank_head == &blank_head()
        ))
    ));

    let new_head = initialized_head(1);
    let (owner, attachment_id, attachment_epoch) = store
        .authority_transaction(|transaction| {
            let mut stored =
                load_stored_volume_for_update(transaction, &fixture.binding.volume.volume_id)?
                    .unwrap();
            stored.record.head = new_head.clone();
            let owner = stored.owner_binding.clone().unwrap();
            update_volume_owner(transaction, &stored.record, Some(&owner))?;
            Ok((
                owner,
                stored.record.lease_owner.clone().unwrap(),
                stored.record.lease_epoch,
            ))
        })
        .unwrap();
    let before_receipt_count = store
        .authority_transaction(|transaction| {
            Ok(transaction
                .query_one(
                    "SELECT count(*)::BIGINT FROM lifecycle_volume_receipts
                      WHERE operation_id=$1",
                    &[&fixture.operation.operation_id.as_str()],
                )?
                .get::<_, i64>(0))
        })
        .unwrap();
    assert_eq!(before_receipt_count, 2);
    let commit_payload = LifecyclePersistentInitializationCommitRequest {
        binding: Box::new(fixture.binding.clone()),
        format_plan_digest: digest(236),
        initialization_token: fixture.initialization_token.clone(),
        filesystem_uuid: fixture.filesystem_uuid.clone(),
        expected_blank_head: blank_head(),
        initialized_head: new_head.clone(),
        guest_probe: Box::new(LifecyclePersistentInitializationGuestProbe {
            challenge: random(230),
            runtime_incarnation: random(231),
            guest_device_serial: fixture.binding.volume.guest_device_serial.clone(),
            guest_device_slot: fixture.binding.volume.guest_device_slot,
            device_major: 252,
            device_minor: 1,
            size_bytes: fixture.binding.volume.size_bytes,
            filesystem_uuid: fixture.filesystem_uuid.clone(),
            filesystem_state: LifecyclePersistentGuestFilesystemState::ExactExt4Unmounted,
            guest_response_digest: digest(232),
        }),
        flush_drain: Box::new(LifecyclePersistentInitializationFlushDrainReceipt {
            guest_flush_challenge: random(233),
            guest_flush_response_digest: digest(234),
            blockd_drain_receipt_digest: digest(235),
            durability: LifecycleVolumeDurabilityProof {
                scope: fixture.binding.scope.clone(),
                volume: WireLifecycleVolumeTarget {
                    disk_id: fixture.binding.volume.disk_id.clone(),
                    disk_role: cats_api::runtime_lifecycle::DiskRole::Persistent,
                    volume_id: fixture.binding.volume.volume_id.clone(),
                    attachment_id,
                    attachment_epoch,
                },
                remote_head: new_head.clone(),
                local_durable_generation: new_head.generation,
                remote_durable_generation: new_head.generation,
                pending_pack_count: WireU64::new(0).unwrap(),
            },
        }),
    };
    let commit = LifecycleVolumeTransitionRequest {
        session: session_binding(&fixture.session),
        transition: LifecycleVolumeTransition::CommitPersistentInitialization {
            scope: scope.clone(),
            commit: Box::new(commit_payload.clone()),
        },
    };
    let first = store
        .apply_lifecycle_volume_transition(&fixture.authenticated, &commit)
        .unwrap();
    let LifecycleVolumeTransitionOutcome::Applied(first_applied) = &first else {
        panic!("valid initialization was rejected: {first:?}")
    };
    let LifecycleVolumeTransitionApplied::PersistentInitializationCommitted { committed } =
        first_applied.as_ref()
    else {
        panic!("valid initialization returned the wrong result: {first:?}")
    };
    let first_initialized_at = committed.receipt.initialized_at;
    store
        .authority_transaction(|transaction| {
            let disk =
                load_disk_by_id_for_update(transaction, &fixture.binding.volume.disk_id)?.unwrap();
            assert!(matches!(
                disk.role,
                ProductDiskRole::Persistent { initialization }
                    if matches!(
                        initialization.as_ref(),
                        PersistentDiskInitialization::Initialized {
                            initialized_at,
                            initialized_head,
                            commit,
                            ..
                        } if *initialized_at == first_initialized_at
                            && initialized_head == &new_head
                            && commit.as_ref() == committed.as_ref()
                    )
            ));
            let count = transaction
                .query_one(
                    "SELECT count(*)::BIGINT FROM lifecycle_volume_receipts
                      WHERE operation_id=$1",
                    &[&fixture.operation.operation_id.as_str()],
                )?
                .get::<_, i64>(0);
            assert_eq!(count, before_receipt_count);
            Ok(())
        })
        .unwrap();

    let replacement = replace_session(&store, &fixture.authenticated, &fixture.session);
    let replay = LifecycleVolumeTransitionRequest {
        session: session_binding(&replacement),
        transition: LifecycleVolumeTransition::CommitPersistentInitialization {
            scope: scope.clone(),
            commit: Box::new(commit_payload.clone()),
        },
    };
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &replay)
            .unwrap(),
        first
    );

    let expected_commit_bytes =
        encode_persistent_initialization_commit_receipt(&committed.receipt).unwrap();
    let persisted_commit = store
        .authority_transaction(|transaction| {
            let row = transaction.query_one(
                "SELECT record::text,
                        initialization_commit_receipt_bytes,
                        initialization_commit_receipt_digest,
                        initialized_at
                   FROM disk_records WHERE disk_id=$1",
                &[&fixture.binding.volume.disk_id.as_str()],
            )?;
            Ok((
                row.get::<_, String>(0),
                row.get::<_, Vec<u8>>(1),
                row.get::<_, String>(2),
                row.get::<_, i64>(3),
            ))
        })
        .unwrap();
    assert_eq!(persisted_commit.1, expected_commit_bytes);
    assert_eq!(persisted_commit.2, committed.receipt_digest.as_str());
    assert_eq!(
        u64::try_from(persisted_commit.3).unwrap(),
        first_initialized_at.get()
    );

    let conflicting_payloads = [
        {
            let mut changed = commit_payload.clone();
            changed.format_plan_digest = digest(237);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.challenge = random(238);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.runtime_incarnation = random(239);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.guest_device_serial = id("persistent-init-other-device");
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.guest_device_slot += 1;
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.device_major += 1;
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.device_minor += 1;
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.size_bytes += 4096;
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.filesystem_uuid = random(244);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.guest_probe.guest_response_digest = digest(240);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.flush_drain.guest_flush_challenge = random(241);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.flush_drain.guest_flush_response_digest = digest(242);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.flush_drain.blockd_drain_receipt_digest = digest(243);
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.flush_drain.durability.volume.attachment_id =
                id("persistent-init-other-attachment");
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.flush_drain.durability.volume.attachment_epoch = FenceEpoch::new(2).unwrap();
            changed
        },
        {
            let mut changed = commit_payload.clone();
            let changed_head = initialized_head(2);
            changed.initialized_head = changed_head.clone();
            changed.flush_drain.durability.remote_head = changed_head.clone();
            changed.flush_drain.durability.local_durable_generation = changed_head.generation;
            changed.flush_drain.durability.remote_durable_generation = changed_head.generation;
            changed
        },
        {
            let mut changed = commit_payload.clone();
            changed.flush_drain.durability.pending_pack_count = WireU64::new(1).unwrap();
            changed
        },
    ];
    for changed in conflicting_payloads {
        let conflicting = LifecycleVolumeTransitionRequest {
            session: session_binding(&replacement),
            transition: LifecycleVolumeTransition::CommitPersistentInitialization {
                scope: scope.clone(),
                commit: Box::new(changed),
            },
        };
        assert_eq!(
            store
                .apply_lifecycle_volume_transition(&fixture.authenticated, &conflicting)
                .unwrap(),
            LifecycleVolumeTransitionOutcome::Rejected(
                LifecycleVolumeTransitionRejection::AuthorityRejected
            )
        );
        let unchanged = store
            .authority_transaction(|transaction| {
                let row = transaction.query_one(
                    "SELECT record::text,
                            initialization_commit_receipt_bytes,
                            initialization_commit_receipt_digest,
                            initialized_at
                       FROM disk_records WHERE disk_id=$1",
                    &[&fixture.binding.volume.disk_id.as_str()],
                )?;
                Ok((
                    row.get::<_, String>(0),
                    row.get::<_, Vec<u8>>(1),
                    row.get::<_, String>(2),
                    row.get::<_, i64>(3),
                ))
            })
            .unwrap();
        assert_eq!(unchanged, persisted_commit);
    }
    let after_conflict_receipt_count = store
        .authority_transaction(|transaction| {
            Ok(transaction
                .query_one(
                    "SELECT count(*)::BIGINT FROM lifecycle_volume_receipts
                      WHERE operation_id=$1",
                    &[&fixture.operation.operation_id.as_str()],
                )?
                .get::<_, i64>(0))
        })
        .unwrap();
    assert_eq!(after_conflict_receipt_count, before_receipt_count);
    assert!(store
        .authority_transaction(|transaction| {
            transaction.execute(
                "UPDATE disk_records
                    SET initialization_commit_receipt_bytes=$2
                  WHERE disk_id=$1",
                &[&fixture.binding.volume.disk_id.as_str(), &Vec::<u8>::new()],
            )?;
            Ok(())
        })
        .is_err());
    assert!(store
        .authority_transaction(|transaction| {
            transaction.execute(
                "UPDATE disk_records
                    SET initialization_commit_receipt_digest='not-a-digest'
                  WHERE disk_id=$1",
                &[&fixture.binding.volume.disk_id.as_str()],
            )?;
            Ok(())
        })
        .is_err());

    let later_head = initialized_head(2);
    store
        .authority_transaction(|transaction| {
            let mut stored =
                load_stored_volume_for_update(transaction, &fixture.binding.volume.volume_id)?
                    .unwrap();
            stored.record.head = later_head.clone();
            update_volume_owner(transaction, &stored.record, Some(&owner))?;
            Ok(())
        })
        .unwrap();
    let later_inspect = LifecycleVolumeTransitionRequest {
        session: session_binding(&replacement),
        transition: LifecycleVolumeTransition::InspectPersistentInitialization {
            scope: scope.clone(),
            inspect: Box::new(LifecyclePersistentInitializationInspectRequest {
                binding: Box::new(fixture.binding.clone()),
            }),
        },
    };
    assert!(matches!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &later_inspect)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Applied(applied) if matches!(
            applied.as_ref(),
            LifecycleVolumeTransitionApplied::PersistentInitializationInspected { inspection }
                if inspection.current_head == later_head
            && matches!(
                inspection.initialization,
                LifecyclePersistentInitializationState::Initialized { initialized_at, .. }
                    if initialized_at == first_initialized_at
            )
        )
    ));
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &replay)
            .unwrap(),
        first
    );

    let mut wrong_uuid_payload = commit_payload.clone();
    wrong_uuid_payload.guest_probe.filesystem_uuid = random(240);
    let wrong_uuid = LifecycleVolumeTransitionRequest {
        session: session_binding(&replacement),
        transition: LifecycleVolumeTransition::CommitPersistentInitialization {
            scope: scope.clone(),
            commit: Box::new(wrong_uuid_payload),
        },
    };
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &wrong_uuid)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::AuthorityRejected
        )
    );
    let mut partial_payload = commit_payload;
    partial_payload.flush_drain.durability.pending_pack_count = WireU64::new(1).unwrap();
    let partial = LifecycleVolumeTransitionRequest {
        session: session_binding(&replacement),
        transition: LifecycleVolumeTransition::CommitPersistentInitialization {
            scope,
            commit: Box::new(partial_payload),
        },
    };
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &partial)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::AuthorityRejected
        )
    );
    store
        .authority_transaction(|transaction| {
            let stored =
                load_stored_volume_for_update(transaction, &fixture.binding.volume.volume_id)?
                    .unwrap();
            let mut drifted_owner = owner.clone();
            drifted_owner.owner_node_id = id("node-owner-drift");
            update_volume_owner(transaction, &stored.record, Some(&drifted_owner))?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &replay)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::AuthorityRejected
        )
    );
    let disk_after_owner_drift = store
        .authority_transaction(|transaction| {
            let row = transaction.query_one(
                "SELECT record::text,
                        initialization_commit_receipt_bytes,
                        initialization_commit_receipt_digest,
                        initialized_at
                   FROM disk_records WHERE disk_id=$1",
                &[&fixture.binding.volume.disk_id.as_str()],
            )?;
            Ok((
                row.get::<_, String>(0),
                row.get::<_, Vec<u8>>(1),
                row.get::<_, String>(2),
                row.get::<_, i64>(3),
            ))
        })
        .unwrap();
    assert_eq!(disk_after_owner_drift, persisted_commit);
}

#[test]
fn persistent_initialization_renewed_grant_replays_original_blank_lineage() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let fixture = setup_persistent_initialization(&store, "persistent-init-renewed");
    let scope = LifecycleVolumeCommandScope {
        operation_id: fixture.operation.operation_id.clone(),
        request_fingerprint: fixture.operation.request_fingerprint.clone(),
        cat_id: fixture.operation.cat_id.clone(),
        node_id: fixture.operation.node_id.clone(),
        placement_identity: fixture.operation.placement_identity.clone(),
    };
    let initialized = initialized_head(1);
    let persistent_owner = store
        .authority_transaction(|transaction| {
            let mut stored =
                load_stored_volume_for_update(transaction, &fixture.binding.volume.volume_id)?
                    .unwrap();
            stored.record.head = initialized.clone();
            let owner = stored.owner_binding.clone().unwrap();
            update_volume_owner(transaction, &stored.record, Some(&owner))?;
            Ok(owner)
        })
        .unwrap();
    let renewal_actions = store
        .authority_transaction(|transaction| {
            fixture
                .operation
                .runtime_config
                .volumes
                .iter()
                .map(|volume| {
                    let stored = load_stored_volume_for_update(transaction, &volume.volume_id)?
                        .expect("initial Start owns every configured Volume");
                    let owner = stored
                        .owner_binding
                        .expect("initial Start has a closed owner binding");
                    Ok(LifecycleStartVolumeAction::RenewSameNode {
                        volume: volume.clone(),
                        attachment_id: owner.attachment_id,
                        attachment_epoch: owner.attachment_epoch,
                        lease_duration_ms: WireU64::new(90_000).unwrap(),
                    })
                })
                .collect::<crate::store::transaction::AuthorityTxResult<Vec<_>>>()
        })
        .unwrap();
    let renewal = LifecycleVolumeTransitionRequest {
        session: session_binding(&fixture.session),
        transition: LifecycleVolumeTransition::StartVolumes {
            scope: scope.clone(),
            batch: LifecycleStartVolumeBatch {
                scope: super::lifecycle_volume_transitions::scope_to_wire(&scope),
                grant_sequence: WireU64::new(1).unwrap(),
                renewal_lease_duration_ms: WireU64::new(90_000).unwrap(),
                actions: renewal_actions,
            },
        },
    };
    let renewal_outcome = store
        .apply_lifecycle_volume_transition(&fixture.authenticated, &renewal)
        .unwrap();
    let renewal_applied = match renewal_outcome {
        LifecycleVolumeTransitionOutcome::Applied(applied) => *applied,
        other => panic!("same-owner renewal failed: {other:?}"),
    };
    let LifecycleVolumeTransitionApplied::StartVolumesReady { grants, .. } = renewal_applied else {
        panic!("same-owner renewal returned the wrong result")
    };
    let persistent_grant = grants
        .into_iter()
        .find(|grant| grant.receipt.volume.volume_id == fixture.binding.volume.volume_id)
        .unwrap();
    let WireStartGrantAuthority::RenewSameNode {
        serving_acquire,
        result,
        ..
    } = &persistent_grant.receipt.authority
    else {
        panic!("renewal returned a non-renew authority")
    };
    let cats_api::runtime_lifecycle_volume::LifecycleServingAcquire::Normal {
        result: original_acquire,
        ..
    } = serving_acquire.as_ref();
    assert_eq!(original_acquire.resulting_head, blank_head());
    assert_eq!(result.resulting_head, initialized);

    let mut renewed_binding = fixture.binding.clone();
    renewed_binding.start_grant = LifecycleStoredStartVolumeGrant {
        receipt: persistent_grant.receipt,
        receipt_digest: persistent_grant.receipt_digest,
    };
    let commit_payload = LifecyclePersistentInitializationCommitRequest {
        binding: Box::new(renewed_binding.clone()),
        format_plan_digest: digest(247),
        initialization_token: fixture.initialization_token.clone(),
        filesystem_uuid: fixture.filesystem_uuid.clone(),
        expected_blank_head: blank_head(),
        initialized_head: initialized.clone(),
        guest_probe: Box::new(LifecyclePersistentInitializationGuestProbe {
            challenge: random(248),
            runtime_incarnation: random(249),
            guest_device_serial: renewed_binding.volume.guest_device_serial.clone(),
            guest_device_slot: renewed_binding.volume.guest_device_slot,
            device_major: 252,
            device_minor: 1,
            size_bytes: renewed_binding.volume.size_bytes,
            filesystem_uuid: fixture.filesystem_uuid.clone(),
            filesystem_state: LifecyclePersistentGuestFilesystemState::ExactExt4Unmounted,
            guest_response_digest: digest(250),
        }),
        flush_drain: Box::new(LifecyclePersistentInitializationFlushDrainReceipt {
            guest_flush_challenge: random(251),
            guest_flush_response_digest: digest(252),
            blockd_drain_receipt_digest: digest(253),
            durability: LifecycleVolumeDurabilityProof {
                scope: renewed_binding.scope.clone(),
                volume: WireLifecycleVolumeTarget {
                    disk_id: renewed_binding.volume.disk_id.clone(),
                    disk_role: cats_api::runtime_lifecycle::DiskRole::Persistent,
                    volume_id: renewed_binding.volume.volume_id.clone(),
                    attachment_id: persistent_owner.attachment_id.clone(),
                    attachment_epoch: persistent_owner.attachment_epoch,
                },
                remote_head: initialized.clone(),
                local_durable_generation: initialized.generation,
                remote_durable_generation: initialized.generation,
                pending_pack_count: WireU64::new(0).unwrap(),
            },
        }),
    };
    let mut stale_grant_payload = commit_payload.clone();
    stale_grant_payload.binding = Box::new(fixture.binding.clone());
    let stale_grant_commit = LifecycleVolumeTransitionRequest {
        session: session_binding(&fixture.session),
        transition: LifecycleVolumeTransition::CommitPersistentInitialization {
            scope: scope.clone(),
            commit: Box::new(stale_grant_payload),
        },
    };
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &stale_grant_commit)
            .unwrap(),
        LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::AuthorityRejected
        )
    );
    let commit = LifecycleVolumeTransitionRequest {
        session: session_binding(&fixture.session),
        transition: LifecycleVolumeTransition::CommitPersistentInitialization {
            scope: scope.clone(),
            commit: Box::new(commit_payload.clone()),
        },
    };
    let first = store
        .apply_lifecycle_volume_transition(&fixture.authenticated, &commit)
        .unwrap();
    let LifecycleVolumeTransitionOutcome::Applied(first_applied) = &first else {
        panic!("renewed initialization commit failed: {first:?}")
    };
    let LifecycleVolumeTransitionApplied::PersistentInitializationCommitted { committed } =
        first_applied.as_ref()
    else {
        panic!("renewed initialization commit returned the wrong result: {first:?}")
    };
    assert_eq!(committed.receipt.request.as_ref(), &commit_payload);
    let replacement = replace_session(&store, &fixture.authenticated, &fixture.session);
    let replay = LifecycleVolumeTransitionRequest {
        session: session_binding(&replacement),
        transition: LifecycleVolumeTransition::CommitPersistentInitialization {
            scope,
            commit: Box::new(commit_payload),
        },
    };
    assert_eq!(
        store
            .apply_lifecycle_volume_transition(&fixture.authenticated, &replay)
            .unwrap(),
        first
    );
    store
        .authority_transaction(|transaction| {
            let disk =
                load_disk_by_id_for_update(transaction, &renewed_binding.volume.disk_id)?.unwrap();
            assert!(matches!(
                disk.role,
                ProductDiskRole::Persistent { initialization }
                    if matches!(
                        initialization.as_ref(),
                        PersistentDiskInitialization::Initialized { commit, .. }
                            if commit.as_ref() == committed.as_ref()
                    )
            ));
            let count = transaction
                .query_one(
                    "SELECT count(*)::BIGINT FROM lifecycle_volume_receipts
                      WHERE operation_id=$1",
                    &[&fixture.operation.operation_id.as_str()],
                )?
                .get::<_, i64>(0);
            assert_eq!(count, 4);
            Ok(())
        })
        .unwrap();
}

#[test]
fn cat_then_operation_lock_order_does_not_deadlock_route_serialization() {
    let url = crate::testsupport::isolated_control_store_url();
    let transition_store = Store::connect(&url, None).unwrap();
    let route_store = Store::connect(&url, None).unwrap();
    let fixture = setup_cold(&transition_store, "volume-lock-order");
    let cat_id = request_scope(&fixture.request).cat_id.clone();
    let operation_id = request_scope(&fixture.request).operation_id.clone();
    let (cat_locked_tx, cat_locked_rx) = mpsc::channel();
    let (transition_started_tx, transition_started_rx) = mpsc::channel();
    let (operation_locked_tx, operation_locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let route = thread::spawn(move || {
        route_store
            .authority_transaction(move |transaction| {
                transaction.batch_execute("SET LOCAL lock_timeout='1s'")?;
                transaction.query_one(
                    "SELECT cat_id FROM cat_records WHERE cat_id=$1 FOR UPDATE",
                    &[&cat_id.as_str()],
                )?;
                cat_locked_tx.send(()).unwrap();
                transition_started_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                // Give the competing Store enough time to reach its first
                // authoritative row lock. An Operation-first implementation
                // now holds Operation while waiting for this Cat and causes
                // the bounded lock below to fail; Cat-first holds no inverse
                // lock and lets this transaction progress.
                thread::sleep(Duration::from_millis(200));
                transaction.query_one(
                    "SELECT operation_id FROM runtime_operations
                      WHERE operation_id=$1 FOR UPDATE",
                    &[&operation_id.as_str()],
                )?;
                operation_locked_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(())
            })
            .unwrap();
    });

    cat_locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let authenticated = fixture.authenticated.clone();
    let request = fixture.request.clone();
    let transition = thread::spawn(move || {
        transition_started_tx.send(()).unwrap();
        transition_store.apply_lifecycle_volume_transition(&authenticated, &request)
    });
    operation_locked_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("Cat owner must acquire Operation without an inverse-lock deadlock");
    release_tx.send(()).unwrap();
    route.join().unwrap();
    assert!(matches!(
        transition.join().unwrap().unwrap(),
        LifecycleVolumeTransitionOutcome::Applied(applied)
            if matches!(applied.as_ref(), LifecycleVolumeTransitionApplied::ColdReleased { .. })
    ));
}

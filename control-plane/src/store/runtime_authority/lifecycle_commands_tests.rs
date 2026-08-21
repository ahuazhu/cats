use std::collections::BTreeMap;
use std::time::Duration;

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_lifecycle::{
    ColdResult, ColdSpec, ColdVolumeDisposition, CommandFailedResult, CommandFailureReason,
    DiskRole, ExecutionAbsenceProof, ImmutableRuntimeConfig, LifecycleCommand,
    LifecycleCommandEnvelope, LifecycleCommandPollRequest, LifecycleOperation,
    LifecycleOperationState, LifecyclePredecessor, NodeResult, PlacementIdentity, RetainedEvidence,
    RuntimeNetworkConfig, RuntimeReadyResult, RuntimeVolumeAuthorityInput, RuntimeVolumeConfig,
    RuntimeVolumeGuestBinding, StartSource, StartSpec, StartVolumeAuthority, StopSpec,
    SuspendAdmissionPolicy, SuspendSpec, SuspendedResult, VolumeTerminalReceipt,
};
use cats_api::runtime_lifecycle_volume::{
    LifecycleStartVolumeAction, LifecycleStartVolumeBatch, LifecycleStartVolumeGrantAuthority,
};
use cats_api::runtime_reconciliation::{
    guest_config_digest, AgentRegistrationAttempt, AgentSession, ContractVersion,
    CredentialBinding, Durability, Epoch, FenceEpoch, Generation, GuestRuntimeProfileReceipt, Id,
    Ipv4Address, MacAddress, NodeBootId, NodeIdentity, NodeIdentityState, NormalAcquireResult,
    ProviderScope, RandomId128, RemoteHead, Sequence, SessionBinding, Sha256Digest, UnixMillis,
    VolumeAdminState, VolumeRecord, WireU64,
};
use cats_storage::lifecycle_volume::LifecycleVolumeCommandScope;

use super::lifecycle_commands::{
    load_lifecycle_admission_context_in, LifecycleAdmissionRejection, LifecycleCommandAdmission,
    LifecycleCommandPollOutcome, LifecyclePollRejection, LifecycleResultCommitOutcome,
    LifecycleResultCommitRejection, LifecycleSessionRejection, LifecycleStableState,
};
use super::lifecycle_volume_transitions::{
    scope_to_wire, LifecycleVolumeTransition, LifecycleVolumeTransitionApplied,
    LifecycleVolumeTransitionOutcome, LifecycleVolumeTransitionRequest,
};
use super::placement_planner::runtime_config_placement_claims;
use super::product::{
    CatRecord, DiskAdminState as ProductDiskAdminState, DiskRecord, DiskRole as ProductDiskRole,
};
use super::product_rows::insert_disk;
use super::rows::insert_volume;
use crate::store::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy, Store};

pub(super) fn id(value: impl Into<String>) -> Id {
    Id::new(value.into()).unwrap()
}

pub(super) fn random(value: u8) -> RandomId128 {
    RandomId128::new(format!("{value:02x}").repeat(16)).unwrap()
}

pub(super) fn digest(value: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([value; 32])
}

pub(super) fn millis(value: u64) -> UnixMillis {
    UnixMillis::new(value).unwrap()
}

pub(super) fn epoch(value: u64) -> Epoch {
    Epoch::new(value).unwrap()
}

pub(super) fn fence_epoch(value: u64) -> FenceEpoch {
    FenceEpoch::new(value).unwrap()
}

pub(super) fn generation(value: u64) -> Generation {
    Generation::new(value).unwrap()
}

pub(super) fn test_store() -> Store {
    Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap()
}

pub(super) fn workspace_id(store: &Store, slug: &str) -> Id {
    let organization = format!("org-{slug}");
    store
        .ensure_configured_accounts(&BTreeMap::from([(slug.to_owned(), organization.clone())]))
        .unwrap();
    let account = store
        .account_for_organization(&organization)
        .unwrap()
        .unwrap();
    id(store
        .workspaces_for_account(&account.id)
        .unwrap()
        .into_iter()
        .find(|workspace| workspace.is_default)
        .unwrap()
        .id)
}

pub(super) fn placement(node_id: &Id) -> PlacementIdentity {
    PlacementIdentity {
        node_id: node_id.clone(),
        placement_epoch: epoch(1),
    }
}

pub(super) fn runtime_config(cat_id: &Id) -> ImmutableRuntimeConfig {
    ImmutableRuntimeConfig::new(
        id(format!("config-{cat_id}")),
        digest(2),
        1,
        512 * 1024 * 1024,
        digest(3),
        RuntimeNetworkConfig::IsolatedIpv4 {
            network_id: id("network-lifecycle-test"),
            guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
            guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
            prefix_length: 30,
            gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
        },
        vec![RuntimeVolumeConfig {
            volume_id: id(format!("volume-{cat_id}")),
            disk_id: id(format!("disk-{cat_id}")),
            disk_role: DiskRole::Root,
            size_bytes: 8 * 1024 * 1024,
            durability: Durability::Strict,
            guest_device_serial: id("root-boot"),
            guest_device_slot: 0,
            guest_binding: RuntimeVolumeGuestBinding::RootBoot,
        }],
    )
    .unwrap()
}

pub(super) fn seed_cat(
    store: &Store,
    workspace_id: &Id,
    cat_id: &Id,
    creation_id: &Id,
) -> ImmutableRuntimeConfig {
    let config = runtime_config(cat_id);
    let config_bytes =
        cats_api::runtime_lifecycle::encode_immutable_runtime_config(&config).unwrap();
    let slot = &config.volumes[0];
    let volume = VolumeRecord {
        volume_id: slot.volume_id.clone(),
        size_bytes: slot.size_bytes,
        durability: slot.durability,
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
        disk_id: slot.disk_id.clone(),
        workspace_id: workspace_id.clone(),
        name: slot.disk_id.clone(),
        volume_id: slot.volume_id.clone(),
        size_bytes: slot.size_bytes,
        durability: slot.durability,
        created_at: millis(1),
        admin_state: ProductDiskAdminState::Active,
        role: ProductDiskRole::Root {
            cat_id: cat_id.clone(),
        },
    };
    let placement_claims = runtime_config_placement_claims(&config).unwrap();
    store
        .authority_transaction(|transaction| {
            let cat = CatRecord {
                cat_id: cat_id.clone(),
                workspace_id: workspace_id.clone(),
                name: id(format!("test-{cat_id}")),
                created_at: millis(1),
            };
            let cat_json = serde_json::to_string(&cat).unwrap();
            transaction.execute(
                "INSERT INTO cat_records (
                    cat_id, record, workspace_id, name, cat_creation_id,
                    lifecycle_head_operation_id, stable_state,
                    effective_runtime_ready_operation_id, runtime_incarnation,
                    current_runtime_config_id, current_runtime_config_sha256,
                    created_at, deleted_at
                 ) VALUES ($1,$2::TEXT::jsonb,$3,$4,$5,NULL,NULL,NULL,NULL,$6,$7,1,NULL)",
                &[
                    &cat_id.as_str(),
                    &cat_json,
                    &workspace_id.as_str(),
                    &cat.name.as_str(),
                    &creation_id.as_str(),
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
                    &workspace_id.as_str(),
                    &cat_id.as_str(),
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
            insert_volume(transaction, &volume)?;
            insert_disk(transaction, &disk)?;
            Ok(())
        })
        .unwrap();
    config
}

pub(super) fn genesis_start(
    workspace_id: &Id,
    node_id: &Id,
    cat_id: &Id,
    creation_id: &Id,
    operation_id: &str,
    config: &ImmutableRuntimeConfig,
) -> LifecycleCommandEnvelope {
    let volume = &config.volumes[0];
    LifecycleCommandEnvelope::new(
        id(operation_id),
        workspace_id.clone(),
        cat_id.clone(),
        node_id.clone(),
        placement(node_id),
        config.clone(),
        None,
        LifecyclePredecessor::Genesis {
            cat_creation_id: creation_id.clone(),
            target_placement: placement(node_id),
        },
        LifecycleCommand::Start(Box::new(StartSpec {
            volume_authorities: vec![StartVolumeAuthority {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                    expected_unowned_epoch: fence_epoch(0),
                    transition_id: random(20),
                },
            }],
            source: StartSource::Genesis,
            effect_deadline_unix_ms: millis(20_000),
        })),
    )
    .unwrap()
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
        panic!("successor requires a terminal head")
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

fn same_node_stop(
    head: &LifecycleOperation,
    operation_id: &str,
    config: &ImmutableRuntimeConfig,
) -> LifecycleCommandEnvelope {
    let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &head.state
    else {
        panic!("successor requires a terminal head")
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
        LifecycleCommand::Stop(StopSpec {
            grace_deadline_unix_ms: millis(30_000),
        }),
    )
    .unwrap()
}

pub(super) fn same_node_suspend(
    head: &LifecycleOperation,
    operation_id: &str,
    config: &ImmutableRuntimeConfig,
) -> LifecycleCommandEnvelope {
    let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &head.state
    else {
        panic!("successor requires a terminal head")
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
        LifecycleCommand::Suspend(SuspendSpec {
            admission_policy: SuspendAdmissionPolicy::CloseAndDrain,
            grace_deadline_unix_ms: millis(30_000),
        }),
    )
    .unwrap()
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

fn start_failed(reason: CommandFailureReason) -> NodeResult {
    start_failed_with_receipts(reason, Vec::new())
}

fn start_failed_with_receipts(
    reason: CommandFailureReason,
    retained_volume_receipts: Vec<VolumeTerminalReceipt>,
) -> NodeResult {
    let retained_count = u16::try_from(retained_volume_receipts.len()).unwrap();
    NodeResult::StartFailed(Box::new(CommandFailedResult {
        reason,
        not_running: absence_proof(40),
        retained_evidence: RetainedEvidence {
            artifact_manifest_digest: digest(50),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: retained_count,
            quarantined_count: 0,
        },
        retained_volume_receipts,
    }))
}

fn guest_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: digest(70),
        initramfs_digest: Some(digest(71)),
        kernel_cmdline: cats_api::runtime_reconciliation::AsciiText::new(
            "console=hvc0 root=/dev/vda",
        )
        .unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn registered(outcome: AgentRegistrationOutcome) -> AgentSession {
    match outcome {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => panic!("registration: {rejection:?}"),
    }
}

pub(super) fn register_node(
    store: &Store,
    node_id: &Id,
) -> (AuthenticatedNodeCredential, AgentSession) {
    register_node_with_credential_digest(store, node_id, digest(80))
}

pub(super) fn register_node_with_credential_digest(
    store: &Store,
    node_id: &Id,
    public_key_spki_sha256: Sha256Digest,
) -> (AuthenticatedNodeCredential, AgentSession) {
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        provider_scope: ProviderScope {
            provider: id("test-provider"),
            partition: id("test-partition"),
            account_id: id("test-account"),
            region: id("test-region"),
        },
        immutable_host_id: id(format!("host-{node_id}")),
        credential_id: id(format!("credential-{node_id}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256,
        },
        state_path_id: id(format!("state-path-{node_id}")),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    store.provision_node_identity(&identity).unwrap();
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&guest_release()).unwrap();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id,
        immutable_host_id: identity.immutable_host_id,
        node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
        agent_instance_id: random(81),
        registration_attempt_id: random(82),
        guest_config_digest: guest_config_digest(&guest_release()).unwrap(),
        expected_agent_session_epoch: None,
    };
    let session = registered(
        store
            .register_agent_session(&authenticated, &attempt, &policy)
            .unwrap(),
    );
    (authenticated, session)
}

pub(super) fn replace_session(
    store: &Store,
    authenticated: &AuthenticatedNodeCredential,
    current: &AgentSession,
) -> AgentSession {
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&guest_release()).unwrap();
    registered(
        store
            .register_agent_session(
                authenticated,
                &AgentRegistrationAttempt {
                    version: ContractVersion::V1,
                    node_id: current.node_id.clone(),
                    immutable_host_id: current.immutable_host_id.clone(),
                    node_boot_id: current.node_boot_id.clone(),
                    agent_instance_id: random(83),
                    registration_attempt_id: random(84),
                    guest_config_digest: guest_config_digest(&guest_release()).unwrap(),
                    expected_agent_session_epoch: Some(current.agent_session_epoch),
                },
                &policy,
            )
            .unwrap(),
    )
}

pub(super) fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

pub(super) fn acquire_genesis_start_volume(
    store: &Store,
    authenticated: &AuthenticatedNodeCredential,
    session: &AgentSession,
    start: &LifecycleCommandEnvelope,
    config: &ImmutableRuntimeConfig,
    attachment_id: Id,
) -> (NormalAcquireResult, Sha256Digest) {
    acquire_genesis_start_volume_with_lease(
        store,
        authenticated,
        session,
        start,
        config,
        attachment_id,
        60_000,
    )
}

fn acquire_genesis_start_volume_with_lease(
    store: &Store,
    authenticated: &AuthenticatedNodeCredential,
    session: &AgentSession,
    start: &LifecycleCommandEnvelope,
    config: &ImmutableRuntimeConfig,
    attachment_id: Id,
    lease_duration_ms: u64,
) -> (NormalAcquireResult, Sha256Digest) {
    let LifecycleCommand::Start(spec) = &start.command else {
        panic!("Genesis fixture must be a Start command")
    };
    let authority = &spec.volume_authorities[0];
    let RuntimeVolumeAuthorityInput::NormalUnowned {
        expected_unowned_epoch,
        transition_id,
    } = &authority.authority
    else {
        panic!("Genesis fixture must use normal acquire")
    };
    let slot = &config.volumes[0];
    let scope = LifecycleVolumeCommandScope {
        operation_id: start.operation_id.clone(),
        request_fingerprint: start.request_fingerprint.clone(),
        cat_id: start.cat_id.clone(),
        node_id: start.node_id.clone(),
        placement_identity: start.placement_identity.clone(),
    };
    let request = LifecycleVolumeTransitionRequest {
        session: session_binding(session),
        transition: LifecycleVolumeTransition::StartVolumes {
            scope: scope.clone(),
            batch: LifecycleStartVolumeBatch {
                scope: scope_to_wire(&scope),
                grant_sequence: WireU64::new(0).unwrap(),
                renewal_lease_duration_ms: WireU64::new(lease_duration_ms).unwrap(),
                actions: vec![LifecycleStartVolumeAction::NormalAcquire {
                    volume: slot.clone(),
                    expected_unowned_epoch: *expected_unowned_epoch,
                    transition_id: transition_id.clone(),
                    requested_attachment_id: attachment_id,
                    lease_duration_ms: WireU64::new(lease_duration_ms).unwrap(),
                }],
            },
        },
    };
    let outcome = store
        .apply_lifecycle_volume_transition(authenticated, &request)
        .unwrap();
    let applied = match outcome {
        LifecycleVolumeTransitionOutcome::Applied(applied) => *applied,
        other => panic!("Genesis fixture Start authority failed: {other:?}"),
    };
    let LifecycleVolumeTransitionApplied::StartVolumesReady { grants, .. } = applied else {
        panic!("Genesis fixture Start authority returned the wrong result")
    };
    let grant = grants.into_iter().next().unwrap();
    let LifecycleStartVolumeGrantAuthority::NormalAcquire { result, .. } = grant.receipt.authority
    else {
        panic!("Genesis fixture returned a non-acquire grant")
    };
    (result, grant.receipt_digest)
}

#[test]
fn runtime_ready_rejects_an_exact_but_expired_volume_lease() {
    let store = test_store();
    let workspace = workspace_id(&store, "runtime-ready-expired-volume-lease");
    let node = id("node-runtime-ready-expired-volume-lease");
    let cat = id("cat-runtime-ready-expired-volume-lease");
    let creation = id("creation-runtime-ready-expired-volume-lease");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-runtime-ready-expired-volume-lease",
        &config,
    );
    store.admit_lifecycle_command(&workspace, &start).unwrap();
    let (authenticated, session) = register_node(&store, &node);
    let slot = &config.volumes[0];
    let attachment_id = id("attachment-runtime-ready-expired-volume-lease");
    let (acquire, grant_digest) = acquire_genesis_start_volume_with_lease(
        &store,
        &authenticated,
        &session,
        &start,
        &config,
        attachment_id.clone(),
        1,
    );

    std::thread::sleep(Duration::from_millis(20));

    let commit = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: random(190),
                runtime_config_digest: config.config_digest.clone(),
                execution_receipt_digest: digest(191),
                guest_ready_receipt_digest: digest(192),
                volume_receipts: vec![VolumeTerminalReceipt {
                    volume_id: slot.volume_id.clone(),
                    disk_id: slot.disk_id.clone(),
                    disk_role: slot.disk_role,
                    attachment_id,
                    attachment_epoch: acquire.resulting_epoch,
                    local_durable_generation: acquire.resulting_head.generation,
                    remote_durable_generation: acquire.resulting_head.generation,
                    authority_receipt_digest: Some(grant_digest),
                }],
            })),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store
            .commit_lifecycle_result(&authenticated, &commit)
            .unwrap(),
        LifecycleResultCommitOutcome::Rejected(LifecycleResultCommitRejection::InvalidContract)
    );
}

pub(super) struct RunningLifecycleFixture {
    pub(super) authenticated: AuthenticatedNodeCredential,
    pub(super) session: AgentSession,
    pub(super) running_head: LifecycleOperation,
    pub(super) runtime_incarnation: RandomId128,
    pub(super) volume_receipt: VolumeTerminalReceipt,
}

/// Settle an already-admitted Genesis Start with exact volume authority and a
/// RuntimeReady terminal. Route Store tests reuse this fixture so they exercise
/// the real lifecycle projection instead of manufacturing Cat-row readiness.
pub(super) fn settle_genesis_runtime_ready(
    store: &Store,
    node_id: &Id,
    start: &LifecycleCommandEnvelope,
    config: &ImmutableRuntimeConfig,
) -> RunningLifecycleFixture {
    let (authenticated, session) = register_node(store, node_id);
    settle_genesis_runtime_ready_in_session(store, &authenticated, &session, start, config)
}

pub(super) fn settle_genesis_runtime_ready_in_session(
    store: &Store,
    authenticated: &AuthenticatedNodeCredential,
    session: &AgentSession,
    start: &LifecycleCommandEnvelope,
    config: &ImmutableRuntimeConfig,
) -> RunningLifecycleFixture {
    let slot = &config.volumes[0];
    let attachment_id = id(format!("attachment-{}", start.cat_id));
    let (acquire, grant_digest) = acquire_genesis_start_volume(
        store,
        authenticated,
        session,
        start,
        config,
        attachment_id.clone(),
    );
    let runtime_incarnation = random(90);
    let volume_receipt = VolumeTerminalReceipt {
        volume_id: slot.volume_id.clone(),
        disk_id: slot.disk_id.clone(),
        disk_role: slot.disk_role,
        attachment_id,
        attachment_epoch: acquire.resulting_epoch,
        local_durable_generation: acquire.resulting_head.generation,
        remote_durable_generation: acquire.resulting_head.generation,
        authority_receipt_digest: Some(grant_digest),
    };
    let commit = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            start,
            NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: runtime_incarnation.clone(),
                runtime_config_digest: config.config_digest.clone(),
                execution_receipt_digest: digest(91),
                guest_ready_receipt_digest: digest(92),
                volume_receipts: vec![volume_receipt.clone()],
            })),
        )
        .unwrap(),
    )
    .unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: running_head,
        ..
    } = store
        .commit_lifecycle_result(authenticated, &commit)
        .unwrap()
    else {
        panic!("RuntimeReady did not settle")
    };
    RunningLifecycleFixture {
        authenticated: authenticated.clone(),
        session: session.clone(),
        running_head,
        runtime_incarnation,
        volume_receipt,
    }
}

#[test]
fn exact_replay_and_second_command_do_not_supersede_unresolved_start() {
    let store = test_store();
    let workspace = workspace_id(&store, "lifecycle-lane");
    let node = id("node-lifecycle-lane");
    let cat = id("cat-lifecycle-lane");
    let creation = id("creation-cat-lifecycle-lane");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-start",
        &config,
    );
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &start).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &start).unwrap(),
        LifecycleCommandAdmission::ExactReplay(_)
    ));
    let second = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-second",
        &config,
    );
    assert_eq!(
        store.admit_lifecycle_command(&workspace, &second).unwrap(),
        LifecycleCommandAdmission::Rejected(
            LifecycleAdmissionRejection::LifecycleOperationInProgress {
                operation_id: id("operation-start"),
                command_kind: cats_api::runtime_lifecycle::LifecycleCommandKind::Start,
            }
        )
    );
}

#[test]
fn poll_authenticates_current_session_and_renews_lease_without_observation() {
    let store = test_store();
    let workspace = workspace_id(&store, "lifecycle-poll");
    let node = id("node-lifecycle-poll");
    let cat = id("cat-lifecycle-poll");
    let creation = id("creation-cat-lifecycle-poll");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let command = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-start",
        &config,
    );
    store.admit_lifecycle_command(&workspace, &command).unwrap();
    let (authenticated, session) = register_node(&store, &node);
    let before: i64 = store
        .with(|client| {
            client
                .query_one(
                    "SELECT lease_deadline_unix_ms FROM current_agent_sessions
                      WHERE node_id=$1",
                    &[&node.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    let poll = LifecycleCommandPollRequest {
        version: ContractVersion::V1,
        session: session_binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    std::thread::sleep(Duration::from_millis(2));
    let LifecycleCommandPollOutcome::Batch(batch) = store
        .poll_lifecycle_commands(&authenticated, &poll)
        .unwrap()
    else {
        panic!("current session poll rejected")
    };
    assert_eq!(batch.commands, vec![command]);
    let after: i64 = store
        .with(|client| {
            client
                .query_one(
                    "SELECT lease_deadline_unix_ms FROM current_agent_sessions
                      WHERE node_id=$1",
                    &[&node.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert!(after > before);
    let mut wrong = poll;
    wrong.session.agent_session_epoch = epoch(2);
    assert!(matches!(
        store
            .poll_lifecycle_commands(&authenticated, &wrong)
            .unwrap(),
        LifecycleCommandPollOutcome::Rejected(LifecyclePollRejection::Session(
            LifecycleSessionRejection::WrongSession { .. }
        ))
    ));
}

#[test]
fn corrupt_sibling_operation_does_not_block_healthy_cat_poll_or_settlement() {
    let store = test_store();
    let workspace = workspace_id(&store, "lifecycle-poll-corrupt-sibling");
    let node = id("node-lifecycle-poll-corrupt-sibling");
    let corrupt_cat = id("cat-a-lifecycle-poll-corrupt-sibling");
    let healthy_cat = id("cat-b-lifecycle-poll-corrupt-sibling");
    let corrupt_creation = id("creation-cat-a-lifecycle-poll-corrupt-sibling");
    let healthy_creation = id("creation-cat-b-lifecycle-poll-corrupt-sibling");
    let corrupt_config = seed_cat(&store, &workspace, &corrupt_cat, &corrupt_creation);
    let healthy_config = seed_cat(&store, &workspace, &healthy_cat, &healthy_creation);
    let corrupt_command = genesis_start(
        &workspace,
        &node,
        &corrupt_cat,
        &corrupt_creation,
        "operation-a-lifecycle-poll-corrupt-sibling",
        &corrupt_config,
    );
    let healthy_command = genesis_start(
        &workspace,
        &node,
        &healthy_cat,
        &healthy_creation,
        "operation-b-lifecycle-poll-corrupt-sibling",
        &healthy_config,
    );
    for command in [&corrupt_command, &healthy_command] {
        assert!(matches!(
            store.admit_lifecycle_command(&workspace, command).unwrap(),
            LifecycleCommandAdmission::Admitted(_)
        ));
    }
    seed_corrupt_poll_prefix(&store, &workspace, &node, 63);

    let malformed_request = b"{}".to_vec();
    store
        .with(|client| {
            client.batch_execute("ALTER TABLE runtime_operations DISABLE TRIGGER USER")?;
            let update = client.execute(
                "UPDATE runtime_operations
                    SET canonical_request_bytes=$2
                  WHERE operation_id=$1",
                &[&corrupt_command.operation_id.as_str(), &malformed_request],
            );
            let enable = client.batch_execute("ALTER TABLE runtime_operations ENABLE TRIGGER USER");
            update?;
            enable?;
            Ok(())
        })
        .unwrap();

    let (authenticated, session) = register_node(&store, &node);
    let poll = LifecycleCommandPollRequest {
        version: ContractVersion::V1,
        session: session_binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let LifecycleCommandPollOutcome::Batch(batch) = store
        .poll_lifecycle_commands(&authenticated, &poll)
        .unwrap()
    else {
        panic!("current session poll rejected")
    };
    assert_eq!(batch.commands, vec![healthy_command.clone()]);

    let slot = &healthy_config.volumes[0];
    let attachment_id = id("attachment-b-lifecycle-poll-corrupt-sibling");
    let (acquire, grant_digest) = acquire_genesis_start_volume(
        &store,
        &authenticated,
        &session,
        &healthy_command,
        &healthy_config,
        attachment_id.clone(),
    );
    let runtime_incarnation = random(91);
    let response = cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
        &healthy_command,
        NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
            runtime_incarnation: runtime_incarnation.clone(),
            runtime_config_digest: healthy_config.config_digest.clone(),
            execution_receipt_digest: digest(92),
            guest_ready_receipt_digest: digest(93),
            volume_receipts: vec![VolumeTerminalReceipt {
                volume_id: slot.volume_id.clone(),
                disk_id: slot.disk_id.clone(),
                disk_role: slot.disk_role,
                attachment_id,
                attachment_epoch: acquire.resulting_epoch,
                local_durable_generation: acquire.resulting_head.generation,
                remote_durable_generation: acquire.resulting_head.generation,
                authority_receipt_digest: Some(grant_digest),
            }],
        })),
    )
    .unwrap();
    let commit =
        cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(&session, response).unwrap();
    assert!(matches!(
        store
            .commit_lifecycle_result(&authenticated, &commit)
            .unwrap(),
        LifecycleResultCommitOutcome::Stored { .. }
    ));

    store
        .with(|client| {
            let corrupt = client.query_one(
                "SELECT state, canonical_request_bytes
                   FROM runtime_operations WHERE operation_id=$1",
                &[&corrupt_command.operation_id.as_str()],
            )?;
            assert_eq!(corrupt.get::<_, String>(0), "unresolved");
            assert_eq!(corrupt.get::<_, Vec<u8>>(1), malformed_request);
            let healthy_state: String = client
                .query_one(
                    "SELECT state FROM runtime_operations WHERE operation_id=$1",
                    &[&healthy_command.operation_id.as_str()],
                )?
                .get(0);
            assert_eq!(healthy_state, "terminal");
            let corrupt_projection = client.query_one(
                "SELECT lifecycle_head_operation_id, stable_state,
                        effective_runtime_ready_operation_id, runtime_incarnation
                   FROM cat_records WHERE cat_id=$1",
                &[&corrupt_cat.as_str()],
            )?;
            assert_eq!(corrupt_projection.get::<_, Option<String>>(0), None);
            assert_eq!(corrupt_projection.get::<_, Option<String>>(1), None);
            assert_eq!(corrupt_projection.get::<_, Option<String>>(2), None);
            assert_eq!(corrupt_projection.get::<_, Option<String>>(3), None);
            let healthy_projection = client.query_one(
                "SELECT lifecycle_head_operation_id, stable_state,
                        effective_runtime_ready_operation_id, runtime_incarnation
                   FROM cat_records WHERE cat_id=$1",
                &[&healthy_cat.as_str()],
            )?;
            assert_eq!(
                healthy_projection.get::<_, Option<String>>(0).as_deref(),
                Some(healthy_command.operation_id.as_str())
            );
            assert_eq!(
                healthy_projection.get::<_, Option<String>>(1).as_deref(),
                Some("running")
            );
            assert_eq!(
                healthy_projection.get::<_, Option<String>>(2).as_deref(),
                Some(healthy_command.operation_id.as_str())
            );
            assert_eq!(
                healthy_projection.get::<_, Option<String>>(3).as_deref(),
                Some(runtime_incarnation.as_str())
            );
            Ok(())
        })
        .unwrap();
}

fn seed_corrupt_poll_prefix(store: &Store, workspace: &Id, node: &Id, count: usize) {
    store
        .authority_transaction(|transaction| {
            for index in 0..count {
                let suffix = format!("{index:03}");
                let cat_id = format!("cat-a-{suffix}-lifecycle-poll-corrupt-prefix");
                let cat_name = format!("test-a-{suffix}-lifecycle-poll-corrupt-prefix");
                let creation_id = format!("creation-a-{suffix}-lifecycle-poll-corrupt-prefix");
                let config_id = format!("config-a-{suffix}-lifecycle-poll-corrupt-prefix");
                let operation_id = format!("operation-a-{suffix}-lifecycle-poll-corrupt-prefix");
                let record = serde_json::json!({
                    "cat_id": cat_id,
                    "workspace_id": workspace.as_str(),
                    "name": cat_name,
                })
                .to_string();
                let config_digest = digest(210);
                transaction.execute(
                    "INSERT INTO cat_records (
                        cat_id, record, workspace_id, name, cat_creation_id,
                        lifecycle_head_operation_id, stable_state,
                        effective_runtime_ready_operation_id, runtime_incarnation,
                        current_runtime_config_id, current_runtime_config_sha256,
                        created_at, deleted_at
                     ) VALUES (
                        $1,$2::TEXT::jsonb,$3,$4,$5,NULL,NULL,NULL,NULL,$6,$7,1,NULL
                     )",
                    &[
                        &cat_id,
                        &record,
                        &workspace.as_str(),
                        &cat_name,
                        &creation_id,
                        &config_id,
                        &config_digest.as_str(),
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO cat_runtime_configs (
                        config_id, workspace_id, cat_id, canonical_config_bytes,
                        canonical_config_sha256, placement_vcpus,
                        placement_memory_bytes, placement_network_id,
                        placement_ipv4_pool_base, placement_ipv4_slot, placement_disk_ids,
                        placement_volume_ids, created_at_unix_ms
                     ) VALUES (
                        $1,$2,$3,$4,$5,1,536870912,$6,0,1,
                        ARRAY[$7]::TEXT[],ARRAY[$8]::TEXT[],1
                     )",
                    &[
                        &config_id,
                        &workspace.as_str(),
                        &cat_id,
                        &&b"{}"[..],
                        &config_digest.as_str(),
                        &format!("network-a-{suffix}-lifecycle-poll-corrupt-prefix"),
                        &format!("disk-a-{suffix}-lifecycle-poll-corrupt-prefix"),
                        &format!("volume-a-{suffix}-lifecycle-poll-corrupt-prefix"),
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO runtime_operations (
                        operation_id, workspace_id, cat_id, node_id,
                        placement_epoch, command_kind, canonical_request_bytes,
                        canonical_request_sha256, runtime_config_id,
                        runtime_config_sha256,
                        expected_predecessor_operation_id, predecessor_kind,
                        expected_predecessor_result_kind,
                        expected_predecessor_result_sha256, state,
                        terminal_source, terminal_result_kind,
                        canonical_result_bytes, canonical_result_sha256,
                        created_at_unix_ms, terminal_at_unix_ms
                     ) VALUES (
                        $1,$2,$3,$4,1,'start',$5,$6,$7,$8,
                        NULL,'genesis',NULL,NULL,'unresolved',
                        NULL,NULL,NULL,NULL,1,NULL
                     )",
                    &[
                        &operation_id,
                        &workspace.as_str(),
                        &cat_id,
                        &node.as_str(),
                        &&b"{}"[..],
                        &digest(211).as_str(),
                        &config_id,
                        &config_digest.as_str(),
                    ],
                )?;
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn terminal_result_is_immutable_and_replacement_agent_replays_same_bytes() {
    let store = test_store();
    let workspace = workspace_id(&store, "lifecycle-result");
    let node = id("node-lifecycle-result");
    let cat = id("cat-lifecycle-result");
    let creation = id("creation-cat-lifecycle-result");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let command = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-start",
        &config,
    );
    store.admit_lifecycle_command(&workspace, &command).unwrap();
    let (authenticated, first) = register_node(&store, &node);
    let response = cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
        &command,
        start_failed(CommandFailureReason::CapacityUnavailable),
    )
    .unwrap();
    let commit =
        cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(&first, response.clone())
            .unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: failed_head,
        ..
    } = store
        .commit_lifecycle_result(&authenticated, &commit)
        .unwrap()
    else {
        panic!("empty retained StartFailed did not settle against pristine authority")
    };
    let replacement = replace_session(&store, &authenticated, &first);
    let replay =
        cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(&replacement, response)
            .unwrap();
    assert!(matches!(
        store
            .commit_lifecycle_result(&authenticated, &replay)
            .unwrap(),
        LifecycleResultCommitOutcome::ExactReplay { .. }
    ));
    let conflicting = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &replacement,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &command,
            start_failed(CommandFailureReason::ImageUnavailable),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store
            .commit_lifecycle_result(&authenticated, &conflicting)
            .unwrap(),
        LifecycleResultCommitOutcome::Rejected(
            LifecycleResultCommitRejection::ConflictingTerminalResult {
                operation_id: id("operation-start")
            }
        )
    );

    let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &failed_head.state
    else {
        unreachable!()
    };
    let LifecycleCommand::Start(failed_spec) = &command.command else {
        unreachable!()
    };
    let retry = LifecycleCommandEnvelope::new(
        id("operation-retry-empty-retained"),
        workspace.clone(),
        cat,
        node.clone(),
        placement(&node),
        config.clone(),
        Some(failed_head.operation_id.clone()),
        LifecyclePredecessor::SameNode {
            operation_id: failed_head.operation_id.clone(),
            terminal_result_kind: terminal.kind(),
            terminal_result_digest: terminal_result_digest.clone(),
            node_id: node.clone(),
            placement_identity: placement(&node),
        },
        LifecycleCommand::Start(Box::new(StartSpec {
            volume_authorities: failed_spec.volume_authorities.clone(),
            source: StartSource::SameNodeRetry,
            effect_deadline_unix_ms: millis(60_000),
        })),
    )
    .unwrap();
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &retry).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
}

#[test]
fn start_failed_settlement_requires_exact_receipt_for_every_acquired_volume() {
    let store = test_store();
    let workspace = workspace_id(&store, "start-failed-retained-authority");
    let node = id("node-start-failed-retained-authority");
    let cat = id("cat-start-failed-retained-authority");
    let creation = id("creation-start-failed-retained-authority");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-start-failed-retained-authority",
        &config,
    );
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &start).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let (authenticated, session) = register_node(&store, &node);
    let slot = &config.volumes[0];
    let attachment_id = id("attachment-start-failed-retained-authority");
    let (acquire, grant_digest) = acquire_genesis_start_volume(
        &store,
        &authenticated,
        &session,
        &start,
        &config,
        attachment_id.clone(),
    );
    let exact_receipt = VolumeTerminalReceipt {
        volume_id: slot.volume_id.clone(),
        disk_id: slot.disk_id.clone(),
        disk_role: slot.disk_role,
        attachment_id,
        attachment_epoch: acquire.resulting_epoch,
        local_durable_generation: acquire.resulting_head.generation,
        remote_durable_generation: acquire.resulting_head.generation,
        authority_receipt_digest: Some(grant_digest),
    };

    let empty = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            start_failed(CommandFailureReason::CapacityUnavailable),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store
            .commit_lifecycle_result(&authenticated, &empty)
            .unwrap(),
        LifecycleResultCommitOutcome::Rejected(LifecycleResultCommitRejection::InvalidContract)
    );

    let mut tampered_receipt = exact_receipt.clone();
    tampered_receipt.authority_receipt_digest = Some(digest(251));
    let tampered = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            start_failed_with_receipts(
                CommandFailureReason::CapacityUnavailable,
                vec![tampered_receipt],
            ),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store
            .commit_lifecycle_result(&authenticated, &tampered)
            .unwrap(),
        LifecycleResultCommitOutcome::Rejected(LifecycleResultCommitRejection::InvalidContract)
    );

    let exact = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            start_failed_with_receipts(
                CommandFailureReason::CapacityUnavailable,
                vec![exact_receipt.clone()],
            ),
        )
        .unwrap(),
    )
    .unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: failed_head,
        ..
    } = store
        .commit_lifecycle_result(&authenticated, &exact)
        .unwrap()
    else {
        panic!("exact retained StartFailed did not settle")
    };
    let LifecycleOperationState::Terminal {
        terminal,
        terminal_result_digest,
    } = &failed_head.state
    else {
        unreachable!()
    };
    let retry = LifecycleCommandEnvelope::new(
        id("operation-retry-after-start-failed-retained-authority"),
        workspace.clone(),
        cat,
        node.clone(),
        placement(&node),
        config.clone(),
        Some(failed_head.operation_id.clone()),
        LifecyclePredecessor::SameNode {
            operation_id: failed_head.operation_id.clone(),
            terminal_result_kind: terminal.kind(),
            terminal_result_digest: terminal_result_digest.clone(),
            node_id: node.clone(),
            placement_identity: placement(&node),
        },
        LifecycleCommand::Start(Box::new(StartSpec {
            volume_authorities: vec![StartVolumeAuthority {
                volume_id: slot.volume_id.clone(),
                disk_id: slot.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::SameNodeOwned {
                    attachment_id: exact_receipt.attachment_id,
                    attachment_epoch: exact_receipt.attachment_epoch,
                },
            }],
            source: StartSource::SameNodeRetry,
            effect_deadline_unix_ms: millis(60_000),
        })),
    )
    .unwrap();
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &retry).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
}

#[test]
fn suspended_incarnation_survives_settlement_and_store_reopen() {
    let store_url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&store_url, None).unwrap();
    let workspace = workspace_id(&store, "lifecycle-suspended-incarnation");
    let node = id("node-lifecycle-suspended-incarnation");
    let cat = id("cat-lifecycle-suspended-incarnation");
    let creation = id("creation-cat-lifecycle-suspended-incarnation");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-start",
        &config,
    );
    store.admit_lifecycle_command(&workspace, &start).unwrap();
    let (authenticated, session) = register_node(&store, &node);
    let slot = &config.volumes[0];
    let attachment_id = id("attachment-suspended-incarnation");
    let (acquire, grant_digest) = acquire_genesis_start_volume(
        &store,
        &authenticated,
        &session,
        &start,
        &config,
        attachment_id.clone(),
    );
    let runtime_incarnation = random(90);
    let owned_receipt = VolumeTerminalReceipt {
        volume_id: slot.volume_id.clone(),
        disk_id: slot.disk_id.clone(),
        disk_role: slot.disk_role,
        attachment_id: attachment_id.clone(),
        attachment_epoch: acquire.resulting_epoch,
        local_durable_generation: acquire.resulting_head.generation,
        remote_durable_generation: acquire.resulting_head.generation,
        authority_receipt_digest: Some(grant_digest),
    };
    let mut wrong_receipt = owned_receipt.clone();
    wrong_receipt.authority_receipt_digest = Some(digest(250));
    let wrong_start_commit = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: random(90),
                runtime_config_digest: config.config_digest.clone(),
                execution_receipt_digest: digest(91),
                guest_ready_receipt_digest: digest(92),
                volume_receipts: vec![wrong_receipt],
            })),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store
            .commit_lifecycle_result(&authenticated, &wrong_start_commit)
            .unwrap(),
        LifecycleResultCommitOutcome::Rejected(LifecycleResultCommitRejection::InvalidContract)
    );
    let start_commit = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: runtime_incarnation.clone(),
                runtime_config_digest: config.config_digest.clone(),
                execution_receipt_digest: digest(91),
                guest_ready_receipt_digest: digest(92),
                volume_receipts: vec![owned_receipt.clone()],
            })),
        )
        .unwrap(),
    )
    .unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: running_head,
        ..
    } = store
        .commit_lifecycle_result(&authenticated, &start_commit)
        .unwrap()
    else {
        panic!("RuntimeReady did not settle")
    };

    let suspend = same_node_suspend(&running_head, "operation-suspend", &config);
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &suspend).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let suspend_commit = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &suspend,
            NodeResult::Suspended(Box::new(SuspendedResult {
                runtime_incarnation: runtime_incarnation.clone(),
                runtime_config_digest: config.config_digest.clone(),
                pause_receipt_digest: digest(93),
                local_durability_receipts: vec![owned_receipt],
            })),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store
            .commit_lifecycle_result(&authenticated, &suspend_commit)
            .unwrap(),
        LifecycleResultCommitOutcome::Stored { .. }
    ));

    drop(store);
    let reopened = Store::connect(&store_url, None).unwrap();
    let context = reopened
        .authority_transaction(|transaction| {
            load_lifecycle_admission_context_in(transaction, &workspace, &cat)
        })
        .unwrap()
        .expect("Suspended Cat remains readable");
    assert_eq!(context.stable_state, Some(LifecycleStableState::Suspended));
    assert_eq!(context.runtime_incarnation, Some(runtime_incarnation));
    assert_eq!(context.effective_runtime_ready_operation_id, None);
    assert_eq!(
        context.lifecycle_head.unwrap().operation_id,
        id("operation-suspend")
    );
}

#[test]
fn stop_admission_does_not_depend_on_decoding_volume_authority() {
    let store = test_store();
    let workspace = workspace_id(&store, "lifecycle-stop-corrupt-volume");
    let node = id("node-lifecycle-stop-corrupt-volume");
    let cat = id("cat-lifecycle-stop-corrupt-volume");
    let creation = id("creation-cat-lifecycle-stop-corrupt-volume");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-start",
        &config,
    );
    store.admit_lifecycle_command(&workspace, &start).unwrap();
    let (authenticated, session) = register_node(&store, &node);
    let start_commit = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            start_failed(CommandFailureReason::VolumeAuthorityRejected),
        )
        .unwrap(),
    )
    .unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: head, ..
    } = store
        .commit_lifecycle_result(&authenticated, &start_commit)
        .unwrap()
    else {
        panic!("Start failure did not settle")
    };

    let volume_id = config.volumes[0].volume_id.as_str();
    store
        .with(|client| {
            client.execute(
                "UPDATE volume_records SET record='{}'::jsonb WHERE volume_id=$1",
                &[&volume_id],
            )
        })
        .unwrap();

    let stop = same_node_stop(&head, "operation-stop", &config);
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &stop).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
}

#[test]
fn cold_rejects_opaque_node_digest_without_exact_authority_ledger() {
    let store = test_store();
    let workspace = workspace_id(&store, "lifecycle-cold-receipt");
    let node = id("node-lifecycle-cold-receipt");
    let cat = id("cat-lifecycle-cold-receipt");
    let creation = id("creation-cat-lifecycle-cold-receipt");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-start",
        &config,
    );
    store.admit_lifecycle_command(&workspace, &start).unwrap();
    let (authenticated, session) = register_node(&store, &node);
    let start_commit = cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(
        &session,
        cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
            &start,
            start_failed(CommandFailureReason::CapacityUnavailable),
        )
        .unwrap(),
    )
    .unwrap();
    let LifecycleResultCommitOutcome::Stored {
        operation: head, ..
    } = store
        .commit_lifecycle_result(&authenticated, &start_commit)
        .unwrap()
    else {
        panic!("Start failure did not settle")
    };
    let cold = same_node_cold(&head, "operation-cold", &config);
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &cold).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let slot = &config.volumes[0];
    let response = cats_api::runtime_lifecycle::LifecycleCommandResponse::new(
        &cold,
        NodeResult::Cold(Box::new(ColdResult {
            runtime_config_digest: config.config_digest.clone(),
            execution_absence: absence_proof(90),
            volume_dispositions: vec![ColdVolumeDisposition::NormallyReleased {
                volume: Box::new(VolumeTerminalReceipt {
                    volume_id: slot.volume_id.clone(),
                    disk_id: slot.disk_id.clone(),
                    disk_role: DiskRole::Root,
                    attachment_id: id("fabricated-attachment"),
                    attachment_epoch: fence_epoch(1),
                    local_durable_generation: generation(0),
                    remote_durable_generation: generation(0),
                    authority_receipt_digest: Some(digest(99)),
                }),
                normal_release_receipt_digest: digest(99),
            }],
            local_recovery_dependency_absent_digest: digest(100),
        })),
    )
    .unwrap();
    let commit =
        cats_api::runtime_lifecycle::LifecycleResultCommitRequest::new(&session, response).unwrap();
    assert_eq!(
        store
            .commit_lifecycle_result(&authenticated, &commit)
            .unwrap(),
        LifecycleResultCommitOutcome::Rejected(LifecycleResultCommitRejection::InvalidContract)
    );
    assert!(matches!(
        store
            .lifecycle_operation(&workspace, &id("operation-cold"))
            .unwrap()
            .unwrap()
            .state,
        LifecycleOperationState::Unresolved
    ));
}

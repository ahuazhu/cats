use cats_api::error::ErrorCode;
use cats_api::runtime_host_loss_recovery::{
    HostLossRecoveryApplyV1, HostLossRecoveryDiscoveryOutcomeV1, HostLossRecoveryDiscoveryV1,
    HostLossRecoveryExpectedAssignedCatV1, HostLossRecoveryExpectedSourceInventoryV1,
    HostLossRecoveryTerminalOutcomeV1,
};
use cats_api::runtime_reconciliation::{
    AsciiText, ContractVersion, DesiredRuntimeSpec, FleetPolicyPrincipal, Id, NodeIdentity,
    RandomId128, WireU64,
};
use cats_storage::host_fence::{
    HostFenceAuthorityBindingsV1, HostFenceAuthorityHostBindingV1, HostFenceBinding,
};
use cats_storage::object_write_authority::{
    complete_object_writer_cutoff, empty_terminal_prefix_sha256, ObjectWriteAuthority,
    ObjectWriteAuthorityState, ObjectWriterIdentity,
};
use cats_storage::trusted_host_recovery::{
    TrustedHostFenceRecoveryAttemptStateV1, TrustedHostFenceSourceInventoryV1,
};

use super::host_fence_commit_tests::{add_second_recovery_cat, recovery_fixture, RecoveryFixture};
use super::host_fence_provider_queue::{evidence_sha256, HostFenceProviderQueueStateV1};
use super::host_fence_provider_queue_tests::terminal_evidence;
use super::host_fence_recovery_batch::require_product_mutation_unblocked_in;
use super::product_rows::{load_desired_for_update, load_operation_for_update};
use super::rows::database_now;

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn text(value: impl Into<String>) -> AsciiText {
    AsciiText::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn principal() -> FleetPolicyPrincipal {
    FleetPolicyPrincipal::WorkosFleetAdministrator {
        subject: id("fleet-admin-subject"),
        organization_id: id("fleet-admin-organization"),
    }
}

fn authority_bindings(identity: &NodeIdentity) -> HostFenceAuthorityBindingsV1 {
    HostFenceAuthorityBindingsV1 {
        version: ContractVersion::V1,
        provider_scope: identity.provider_scope.clone(),
        network_quarantine_boundary_id: text("network-quarantine-boundary"),
        object_store_scope_id: text("test-object-store/chunks"),
        workload_principal_id: text("test-object-write-gateway-principal"),
        hosts: vec![HostFenceAuthorityHostBindingV1 {
            immutable_host_id: identity.immutable_host_id.clone(),
            node_id: identity.node_id.clone(),
        }],
    }
}

fn open_writer(
    fixture: &RecoveryFixture,
    authority_id: &str,
    object_provider_scope: cats_api::runtime_reconciliation::ProviderScope,
    workload_principal_id: AsciiText,
    object_store_scope_id: AsciiText,
) -> ObjectWriteAuthority {
    ObjectWriteAuthority {
        writer: ObjectWriterIdentity {
            authority_id: id(authority_id),
            host_provider_scope: fixture.old_identity.provider_scope.clone(),
            immutable_host_id: fixture.old_identity.immutable_host_id.clone(),
            node_id: fixture.old_identity.node_id.clone(),
            object_provider_scope,
            workload_principal_id,
            object_store_scope_id,
        },
        state: ObjectWriteAuthorityState::Open,
        max_accepted_sequence: WireU64::new(0).unwrap(),
        terminal_prefix_sequence: WireU64::new(0).unwrap(),
        terminal_prefix_sha256: empty_terminal_prefix_sha256(),
    }
}

fn insert_writer_authority(fixture: &RecoveryFixture, authority: &ObjectWriteAuthority) {
    let writer = &authority.writer;
    let record = serde_json::to_string(authority).unwrap();
    fixture
        .store
        .with(|client| {
            client.execute(
                "INSERT INTO object_write_authorities (
                    writer_authority_id, record, host_provider, host_partition,
                    host_account_id, host_region, immutable_host_id, node_id,
                    object_provider, object_partition, object_account_id,
                    object_region, workload_principal_id, object_store_scope_id,
                    state, max_accepted_sequence, terminal_prefix_sequence,
                    terminal_prefix_sha256
                 ) VALUES (
                    $1,$2::TEXT::jsonb,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                    $13,$14,'open',0,0,$15
                 )",
                &[
                    &writer.authority_id.as_str(),
                    &record,
                    &writer.host_provider_scope.provider.as_str(),
                    &writer.host_provider_scope.partition.as_str(),
                    &writer.host_provider_scope.account_id.as_str(),
                    &writer.host_provider_scope.region.as_str(),
                    &writer.immutable_host_id.as_str(),
                    &writer.node_id.as_str(),
                    &writer.object_provider_scope.provider.as_str(),
                    &writer.object_provider_scope.partition.as_str(),
                    &writer.object_provider_scope.account_id.as_str(),
                    &writer.object_provider_scope.region.as_str(),
                    &writer.workload_principal_id.as_str(),
                    &writer.object_store_scope_id.as_str(),
                    &authority.terminal_prefix_sha256.as_str(),
                ],
            )
        })
        .unwrap();
}

fn insert_open_writer(fixture: &RecoveryFixture, bindings: &HostFenceAuthorityBindingsV1) {
    let authority = open_writer(
        fixture,
        "owa1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        bindings.provider_scope.clone(),
        bindings.workload_principal_id.clone(),
        bindings.object_store_scope_id.clone(),
    );
    insert_writer_authority(fixture, &authority);
}

fn expected_cat(desired: &DesiredRuntimeSpec) -> HostLossRecoveryExpectedAssignedCatV1 {
    HostLossRecoveryExpectedAssignedCatV1 {
        workspace_id: desired.workspace_id.clone(),
        cat_id: desired.cat_id.clone(),
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement_epoch: desired.placement.placement_epoch,
        expected_runtime_incarnation: None,
    }
}

struct BatchFixture {
    fixture: RecoveryFixture,
    second_desired: DesiredRuntimeSpec,
    second_operation: cats_api::runtime_reconciliation::Operation,
    bindings: HostFenceAuthorityBindingsV1,
    apply: HostLossRecoveryApplyV1,
}

fn batch_fixture(slug: &str) -> BatchFixture {
    let fixture = recovery_fixture(slug);
    let second = add_second_recovery_cat(&fixture);
    let bindings = authority_bindings(&fixture.old_identity);
    insert_open_writer(&fixture, &bindings);
    let mut expected_assigned = vec![
        expected_cat(&fixture.request.expected_current_desired),
        expected_cat(&second.expected_current_desired),
    ];
    expected_assigned.sort_by(|left, right| left.cat_id.as_str().cmp(right.cat_id.as_str()));
    let apply = HostLossRecoveryApplyV1 {
        version: ContractVersion::V1,
        apply_id: random(700),
        source_node_id: fixture.old_identity.node_id.clone(),
        expected_node_boot_id: fixture.old_session.node_boot_id.clone(),
        expected_agent_session_epoch: fixture.old_session.agent_session_epoch,
        expected_source_inventory: HostLossRecoveryExpectedSourceInventoryV1::Unavailable,
        expected_assigned,
    };
    BatchFixture {
        fixture,
        second_desired: second.expected_current_desired,
        second_operation: second.expected_old_operation,
        bindings,
        apply,
    }
}

fn recovery_binding(fixture: &BatchFixture, fence_attempt_id: Id) -> HostFenceBinding {
    HostFenceBinding {
        provider_scope: fixture.fixture.old_identity.provider_scope.clone(),
        immutable_host_id: fixture.fixture.old_identity.immutable_host_id.clone(),
        node_id: fixture.fixture.old_identity.node_id.clone(),
        expected_node_boot_id: fixture.fixture.old_session.node_boot_id.clone(),
        expected_agent_session_epoch: fixture.fixture.old_session.agent_session_epoch,
        fence_attempt_id,
    }
}

fn seal_provider_terminal(fixture: &BatchFixture, binding: &HostFenceBinding) {
    let queue = fixture
        .fixture
        .store
        .get_host_fence_provider_attempt_v1(binding)
        .unwrap()
        .unwrap();
    assert!(matches!(
        queue.state,
        HostFenceProviderQueueStateV1::Pending
    ));
    let authority: ObjectWriteAuthority = fixture
        .fixture
        .store
        .with(|client| {
            client
                .query_one(
                    "SELECT record::text FROM object_write_authorities
                      WHERE writer_authority_id=$1",
                    &[&queue.request.object_writer.writer_authority_id.as_str()],
                )
                .map(|row| serde_json::from_str(&row.get::<_, String>(0)).unwrap())
        })
        .unwrap();
    let cutoff_at = match authority.state {
        ObjectWriteAuthorityState::CutoffPending {
            cutoff_effective_at_unix_ms,
            ..
        } => cutoff_effective_at_unix_ms,
        state => panic!("expected cutoff-pending writer, got {state:?}"),
    };
    let (_, receipt) = complete_object_writer_cutoff(&authority, cutoff_at).unwrap();
    let evidence = terminal_evidence(&queue.request, receipt);
    let evidence_bytes = serde_json::to_vec(&evidence).unwrap();
    let evidence_sha256 = evidence_sha256(&evidence_bytes);
    let lease = i64::try_from(evidence.completed_at_unix_ms.get() + 60_000).unwrap();
    let completed = i64::try_from(evidence.completed_at_unix_ms.get()).unwrap();
    fixture
        .fixture
        .store
        .with(|client| {
            client.execute(
                "UPDATE host_fence_provider_queue_v1 SET
                    state='claimed', worker_id='worker-c3-test',
                    claim_attempt_token='11111111111111111111111111111111',
                    claim_duration_ms=60000, claim_generation=1,
                    claim_lease_expires_at_unix_ms=$2
                  WHERE fence_attempt_id=$1 AND state='pending'",
                &[&binding.fence_attempt_id.as_str(), &lease],
            )?;
            client.execute(
                "UPDATE host_fence_provider_queue_v1 SET
                    state='terminal', evidence_bytes=$2,
                    evidence_sha256=$3, completed_at_unix_ms=$4
                  WHERE fence_attempt_id=$1 AND state='claimed'",
                &[
                    &binding.fence_attempt_id.as_str(),
                    &evidence_bytes,
                    &evidence_sha256.as_str(),
                    &completed,
                ],
            )
        })
        .unwrap();
    while fixture
        .fixture
        .store
        .authority_transaction(database_now)
        .unwrap()
        < evidence.completed_at_unix_ms
    {
        std::thread::yield_now();
    }
}

#[test]
fn two_cat_begin_is_one_sealed_attempt_and_exact_response_loss_replay() {
    let fixture = batch_fixture("host-recovery-batch-begin");
    let first = fixture
        .fixture
        .store
        .begin_trusted_host_fence_recovery_attempt_v1(
            &principal(),
            &fixture.apply,
            &fixture.bindings,
        )
        .unwrap();
    let replay = fixture
        .fixture
        .store
        .begin_trusted_host_fence_recovery_attempt_v1(
            &principal(),
            &fixture.apply,
            &fixture.bindings,
        )
        .unwrap();
    assert_eq!(first, replay);

    let binding = recovery_binding(&fixture, first.fence_attempt_id.clone());
    let record = fixture
        .fixture
        .store
        .get_trusted_host_fence_recovery_attempt_v1(&binding)
        .unwrap()
        .unwrap();
    assert_eq!(record.attempt.assigned_cats.len(), 2);
    assert!(matches!(
        record.attempt.source_inventory,
        TrustedHostFenceSourceInventoryV1::Unavailable { .. }
    ));
    assert!(matches!(
        record.state,
        TrustedHostFenceRecoveryAttemptStateV1::ProviderPending
    ));
    let counts: (i64, i64, i64, String) = fixture
        .fixture
        .store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM trusted_host_fence_recovery_attempts_v1),
                        (SELECT count(*) FROM trusted_host_fence_recovery_attempt_cats_v1),
                        (SELECT count(*) FROM host_fence_provider_queue_v1),
                        (SELECT state FROM object_write_authorities)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        })
        .unwrap();
    assert_eq!(counts, (1, 2, 1, "cutoff_pending".into()));

    let discovery = HostLossRecoveryDiscoveryV1 {
        version: ContractVersion::V1,
        apply_id: fixture.apply.apply_id.clone(),
        source_node_id: fixture.apply.source_node_id.clone(),
        fence_attempt_id: first.fence_attempt_id,
    };
    let discovered = fixture
        .fixture
        .store
        .discover_trusted_host_fence_recovery_v1(&discovery)
        .unwrap()
        .unwrap();
    assert!(matches!(
        discovered.outcome,
        HostLossRecoveryDiscoveryOutcomeV1::Pending
    ));

    let mut changed_artifact = fixture.bindings.clone();
    changed_artifact.network_quarantine_boundary_id = text("changed-network-boundary");
    let error = fixture
        .fixture
        .store
        .begin_trusted_host_fence_recovery_attempt_v1(
            &principal(),
            &fixture.apply,
            &changed_artifact,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
}

#[test]
fn two_open_writer_parents_reject_before_queue_or_cutoff() {
    let fixture = batch_fixture("host-recovery-two-open-writers");
    // The clean v16 catalog prevents this state. Dropping only the isolated
    // fixture index characterizes the Store's fail-closed behavior for a
    // preexisting/corrupt catalog instead of relying on DDL alone.
    fixture
        .fixture
        .store
        .with(|client| client.batch_execute("DROP INDEX object_write_one_open_authority_per_host"))
        .unwrap();
    let mut foreign_scope = fixture.bindings.provider_scope.clone();
    foreign_scope.region = id("foreign-region");
    let foreign = open_writer(
        &fixture.fixture,
        "owa1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        foreign_scope,
        text("foreign-object-writer-principal"),
        text("foreign-object-store/chunks"),
    );
    insert_writer_authority(&fixture.fixture, &foreign);

    let error = fixture
        .fixture
        .store
        .begin_trusted_host_fence_recovery_attempt_v1(
            &principal(),
            &fixture.apply,
            &fixture.bindings,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    let counts: (i64, i64, i64) = fixture
        .fixture
        .store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM trusted_host_fence_recovery_attempts_v1),
                        (SELECT count(*) FROM host_fence_provider_queue_v1),
                        (SELECT count(*) FROM object_write_authorities WHERE state='open')",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
        })
        .unwrap();
    assert_eq!(counts, (0, 0, 2));
}

#[test]
fn terminal_unsafe_attempt_blocks_both_cats_with_zero_recovery_writes() {
    let fixture = batch_fixture("host-recovery-batch-blocked");
    let applied = fixture
        .fixture
        .store
        .begin_trusted_host_fence_recovery_attempt_v1(
            &principal(),
            &fixture.apply,
            &fixture.bindings,
        )
        .unwrap();
    let binding = recovery_binding(&fixture, applied.fence_attempt_id.clone());
    seal_provider_terminal(&fixture, &binding);
    let blocked = fixture
        .fixture
        .store
        .observe_trusted_host_fence_provider_terminal_v1(&binding)
        .unwrap();
    let replay = fixture
        .fixture
        .store
        .observe_trusted_host_fence_provider_terminal_v1(&binding)
        .unwrap();
    assert_eq!(blocked, replay);
    assert!(matches!(
        blocked.state,
        TrustedHostFenceRecoveryAttemptStateV1::Blocked { .. }
    ));

    let discovery = HostLossRecoveryDiscoveryV1 {
        version: ContractVersion::V1,
        apply_id: fixture.apply.apply_id.clone(),
        source_node_id: fixture.apply.source_node_id.clone(),
        fence_attempt_id: applied.fence_attempt_id.clone(),
    };
    let discovered = fixture
        .fixture
        .store
        .discover_trusted_host_fence_recovery_v1(&discovery)
        .unwrap()
        .unwrap();
    let HostLossRecoveryDiscoveryOutcomeV1::Terminal { receipt, .. } = discovered.outcome else {
        panic!("unsafe Host recovery did not return a terminal receipt")
    };
    assert!(matches!(
        receipt.outcome,
        HostLossRecoveryTerminalOutcomeV1::Blocked { .. }
    ));

    fixture
        .fixture
        .store
        .authority_transaction(|transaction| {
            assert_eq!(
                load_desired_for_update(
                    transaction,
                    &fixture.fixture.request.expected_current_desired.cat_id,
                )?
                .unwrap(),
                fixture.fixture.request.expected_current_desired
            );
            assert_eq!(
                load_desired_for_update(transaction, &fixture.second_desired.cat_id)?.unwrap(),
                fixture.second_desired
            );
            assert_eq!(
                load_operation_for_update(
                    transaction,
                    &fixture.fixture.request.expected_old_operation.operation_id,
                )?
                .unwrap(),
                fixture.fixture.request.expected_old_operation
            );
            assert_eq!(
                load_operation_for_update(transaction, &fixture.second_operation.operation_id)?
                    .unwrap(),
                fixture.second_operation
            );
            assert!(require_product_mutation_unblocked_in(
                transaction,
                &fixture.fixture.old_identity.node_id,
            )
            .is_err());
            Ok(())
        })
        .unwrap();
    let authority_counts: (i64, i64, i64, String, i64) = fixture
        .fixture
        .store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM host_fence_events),
                        (SELECT count(*) FROM volume_authorizations),
                        (SELECT count(*) FROM trusted_host_fence_recovery_commits_v1),
                        (SELECT state FROM node_identities WHERE node_id=$1),
                        (SELECT count(*) FROM current_agent_sessions WHERE node_id=$1)",
                    &[&fixture.fixture.old_identity.node_id.as_str()],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
        })
        .unwrap();
    assert_eq!(authority_counts, (0, 0, 0, "provisioned".into(), 1));

    let exact_apply_replay = fixture
        .fixture
        .store
        .begin_trusted_host_fence_recovery_attempt_v1(
            &principal(),
            &fixture.apply,
            &fixture.bindings,
        )
        .unwrap();
    assert_eq!(exact_apply_replay, applied);
}

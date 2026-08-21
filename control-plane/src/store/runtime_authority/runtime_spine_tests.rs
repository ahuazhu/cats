//! PostgreSQL characterization tests for telemetry-only runtime inventory.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_inventory::{
    full_inventory_digest, ObservedArtifactClassification, ObservedCatRuntimeTelemetry,
    ObservedRuntimeCondition, ObservedRuntimeConditionKind, ObservedRuntimePhysicalState,
    RuntimeInventoryBody, RuntimeInventoryErrorDetail, RuntimeInventoryReport,
};
use cats_api::runtime_lifecycle::PlacementIdentity;
use cats_api::runtime_reconciliation::{
    guest_config_digest, AgentRegistrationAttempt, AgentSession, AsciiText, ContractVersion,
    CredentialBinding, Epoch, GuestRuntimeProfileReceipt, Id, NodeBootId, NodeIdentity,
    NodeIdentityState, ProviderScope, RandomId128, Sequence, SessionBinding, Sha256Digest,
    UnixMillis,
};

use super::runtime_spine::{
    runtime_full_inventory_is_fresh_at, RuntimeInventoryOutcome, RuntimeTelemetrySourceKind,
    PLACEMENT_INVENTORY_MAX_AGE_MS,
};
use crate::store::{
    AgentRegistrationOutcome, AgentSessionRegistrationPolicy, AuthorityRequestContext, Store,
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn digest(value: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([value; 32])
}

fn release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: digest(1),
        initramfs_digest: Some(digest(2)),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

struct Fixture {
    store: Store,
    identity: NodeIdentity,
    authenticated: AuthenticatedNodeCredential,
    policy: AgentSessionRegistrationPolicy,
    session: AgentSession,
    cat_id: Id,
}

fn fixture() -> Fixture {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node_inventory"),
        provider_scope: ProviderScope {
            provider: id("test_provider"),
            partition: id("test_partition"),
            account_id: id("test_account"),
            region: id("test_region"),
        },
        immutable_host_id: id("host_inventory"),
        credential_id: id("credential_inventory"),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(9),
        },
        state_path_id: id("state_path_inventory"),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&release()).unwrap();
    store.provision_node_identity(&identity).unwrap();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
        agent_instance_id: random(2),
        registration_attempt_id: random(3),
        guest_config_digest: guest_config_digest(&release()).unwrap(),
        expected_agent_session_epoch: None,
    };
    let session = registered(
        store
            .register_agent_session(&authenticated, &attempt, &policy)
            .unwrap(),
    );
    let cat_id = id("cat_inventory");
    seed_unresolved_operation(&store, &cat_id, &identity.node_id);
    Fixture {
        store,
        identity,
        authenticated,
        policy,
        session,
        cat_id,
    }
}

fn registered(outcome: AgentRegistrationOutcome) -> AgentSession {
    match outcome {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("AgentSession registration rejected: {rejection:?}")
        }
    }
}

fn seed_unresolved_operation(store: &Store, cat_id: &Id, node_id: &Id) {
    let request_digest = digest(20);
    let config_digest = digest(21);
    store
        .ensure_configured_accounts(&BTreeMap::from([(
            "inventory".to_owned(),
            "org_inventory".to_owned(),
        )]))
        .unwrap();
    let account = store
        .account_for_organization("org_inventory")
        .unwrap()
        .unwrap();
    let workspace_id = store
        .workspaces_for_account(&account.id)
        .unwrap()
        .into_iter()
        .find(|workspace| workspace.is_default)
        .unwrap()
        .id;
    store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "INSERT INTO cat_records (
                    cat_id, record, workspace_id, name, cat_creation_id,
                    lifecycle_head_operation_id, stable_state,
                    effective_runtime_ready_operation_id, runtime_incarnation,
                    current_runtime_config_id, current_runtime_config_sha256,
                    created_at, deleted_at
                 ) VALUES (
                    $1, jsonb_build_object(
                        'cat_id', $1::TEXT,
                        'workspace_id', $2::TEXT,
                        'name', 'inventory-cat'
                    ), $2, 'inventory-cat',
                    'creation_inventory', NULL, NULL, NULL, NULL,
                    'config_inventory', $3, 1, NULL
                 )",
                &[&cat_id.as_str(), &workspace_id, &config_digest.as_str()],
            )?;
            transaction.execute(
                "INSERT INTO cat_runtime_configs (
                    config_id, workspace_id, cat_id, canonical_config_bytes,
                    canonical_config_sha256, placement_vcpus,
                    placement_memory_bytes, placement_network_id,
                    placement_ipv4_pool_base, placement_ipv4_slot, placement_disk_ids,
                    placement_volume_ids, created_at_unix_ms
                 ) VALUES (
                    'config_inventory', $1, $2, $3, $4,
                    1, 1024, 'network_inventory', 0, 1,
                    ARRAY['disk_inventory']::TEXT[],
                    ARRAY['volume_inventory']::TEXT[], 1
                 )",
                &[
                    &workspace_id,
                    &cat_id.as_str(),
                    &&b"{}"[..],
                    &config_digest.as_str(),
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
                    'operation_inventory', $3, $1, $2,
                    1, 'start', $4, $5, 'config_inventory', $6,
                    NULL, 'genesis', NULL, NULL, 'unresolved', NULL,
                    NULL, NULL, NULL, 1, NULL
                 )",
                &[
                    &cat_id.as_str(),
                    &node_id.as_str(),
                    &workspace_id,
                    &&b"{}"[..],
                    &request_digest.as_str(),
                    &config_digest.as_str(),
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
}

fn operation_snapshot(store: &Store) -> String {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT to_jsonb(operation_row)::text
                       FROM runtime_operations AS operation_row
                      WHERE operation_id='operation_inventory'",
                    &[],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

fn observed_cat(
    node_id: &Id,
    cat_id: &Id,
    state: ObservedRuntimePhysicalState,
) -> ObservedCatRuntimeTelemetry {
    ObservedCatRuntimeTelemetry {
        cat_id: cat_id.clone(),
        observed_placement: PlacementIdentity {
            node_id: node_id.clone(),
            placement_epoch: Epoch::new(1).unwrap(),
        },
        observed_command_journal: None,
        observed_physical_state: state,
        observed_runtime_incarnation: None,
        observed_artifact_manifest_digest: digest(30),
        observed_artifact_classifications: vec![
            ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: id("artifact_inventory"),
                evidence_digest: digest(31),
            },
        ],
        observed_volumes: Vec::new(),
        observed_conditions: vec![ObservedRuntimeCondition {
            kind: ObservedRuntimeConditionKind::Degraded,
            evidence_digest: digest(32),
        }],
    }
}

fn full_report(
    session: &AgentSession,
    sequence: u64,
    inventory_epoch: u64,
    report_id: u128,
    cats: Vec<ObservedCatRuntimeTelemetry>,
) -> RuntimeInventoryReport {
    let mut report = RuntimeInventoryReport {
        version: ContractVersion::V1,
        session: binding(session),
        report_id: random(report_id),
        sequence: Sequence::new(sequence).unwrap(),
        collected_at_unix_ms: UnixMillis::new(100 + sequence).unwrap(),
        inventory: RuntimeInventoryBody::Full {
            inventory_epoch: Epoch::new(inventory_epoch).unwrap(),
            scan_id: random(report_id + 100),
            inventory_digest: digest(0),
            cats,
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
    report
}

fn partial_report(
    session: &AgentSession,
    sequence: u64,
    inventory_epoch: u64,
    report_id: u128,
    cats: Vec<ObservedCatRuntimeTelemetry>,
) -> RuntimeInventoryReport {
    RuntimeInventoryReport {
        version: ContractVersion::V1,
        session: binding(session),
        report_id: random(report_id),
        sequence: Sequence::new(sequence).unwrap(),
        collected_at_unix_ms: UnixMillis::new(100 + sequence).unwrap(),
        inventory: RuntimeInventoryBody::Partial {
            inventory_epoch: Epoch::new(inventory_epoch).unwrap(),
            cats,
        },
    }
}

fn accepted<T>(outcome: RuntimeInventoryOutcome<T>) -> T {
    match outcome {
        RuntimeInventoryOutcome::Accepted(value) => value,
        RuntimeInventoryOutcome::Rejected(rejection) => {
            panic!("runtime inventory rejected: {rejection:?}")
        }
    }
}

#[test]
fn corrupt_operation_cannot_block_sibling_telemetry_or_session_renewal() {
    let fixture = fixture();
    let before = operation_snapshot(&fixture.store);
    let lease_before: i64 = fixture
        .store
        .with(|client| {
            client
                .query_one(
                    "SELECT lease_deadline_unix_ms FROM current_agent_sessions
                      WHERE node_id=$1",
                    &[&fixture.identity.node_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(2));
    let sibling_cat_id = id("cat_inventory_sibling");
    let report = full_report(
        &fixture.session,
        1,
        1,
        10,
        vec![
            observed_cat(
                &fixture.identity.node_id,
                &fixture.cat_id,
                ObservedRuntimePhysicalState::Absent,
            ),
            observed_cat(
                &fixture.identity.node_id,
                &sibling_cat_id,
                ObservedRuntimePhysicalState::StoppedRetained,
            ),
        ],
    );

    let acceptance = accepted(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &report)
            .unwrap(),
    );

    assert_eq!(operation_snapshot(&fixture.store), before);
    let full = fixture
        .store
        .load_current_full_inventory(&fixture.identity.node_id)
        .unwrap()
        .unwrap();
    assert_eq!(full.full_report, report);
    assert_eq!(full.attestation.source_report_id, acceptance.report_id);
    assert!(runtime_full_inventory_is_fresh_at(
        &full,
        &fixture.session,
        full.attestation.accepted_at_unix_ms,
        PLACEMENT_INVENTORY_MAX_AGE_MS,
    )
    .unwrap());
    let freshness_boundary = UnixMillis::new(
        full.attestation
            .accepted_at_unix_ms
            .get()
            .checked_add(PLACEMENT_INVENTORY_MAX_AGE_MS)
            .unwrap(),
    )
    .unwrap();
    assert!(!runtime_full_inventory_is_fresh_at(
        &full,
        &fixture.session,
        freshness_boundary,
        PLACEMENT_INVENTORY_MAX_AGE_MS,
    )
    .unwrap());
    let current = fixture
        .store
        .load_current_cat_telemetry(&fixture.identity.node_id, &fixture.cat_id)
        .unwrap()
        .unwrap();
    assert_eq!(current.source_kind, RuntimeTelemetrySourceKind::Full);
    assert_eq!(current.telemetry.cat_id, fixture.cat_id);
    assert_eq!(
        fixture
            .store
            .load_current_cat_telemetry(&fixture.identity.node_id, &sibling_cat_id)
            .unwrap()
            .unwrap()
            .telemetry
            .cat_id,
        sibling_cat_id
    );
    let lease_after: i64 = fixture
        .store
        .with(|client| {
            client
                .query_one(
                    "SELECT lease_deadline_unix_ms FROM current_agent_sessions
                      WHERE node_id=$1",
                    &[&fixture.identity.node_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert!(lease_after > lease_before);
}

#[test]
fn partial_updates_only_full_members_and_never_replaces_attestation() {
    let fixture = fixture();
    let before_operation = operation_snapshot(&fixture.store);
    let full = full_report(
        &fixture.session,
        1,
        1,
        20,
        vec![observed_cat(
            &fixture.identity.node_id,
            &fixture.cat_id,
            ObservedRuntimePhysicalState::Absent,
        )],
    );
    accepted(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &full)
            .unwrap(),
    );
    let attested = fixture
        .store
        .load_current_full_inventory(&fixture.identity.node_id)
        .unwrap()
        .unwrap();

    let partial = partial_report(
        &fixture.session,
        2,
        1,
        21,
        vec![observed_cat(
            &fixture.identity.node_id,
            &fixture.cat_id,
            ObservedRuntimePhysicalState::StoppedRetained,
        )],
    );
    accepted(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &partial)
            .unwrap(),
    );
    assert_eq!(
        fixture
            .store
            .load_current_full_inventory(&fixture.identity.node_id)
            .unwrap()
            .unwrap(),
        attested
    );
    assert_eq!(
        fixture
            .store
            .load_current_cat_telemetry(&fixture.identity.node_id, &fixture.cat_id)
            .unwrap()
            .unwrap()
            .source_kind,
        RuntimeTelemetrySourceKind::Partial
    );

    let foreign_cat = id("cat_not_in_full");
    let expanding = partial_report(
        &fixture.session,
        3,
        1,
        22,
        vec![observed_cat(
            &fixture.identity.node_id,
            &foreign_cat,
            ObservedRuntimePhysicalState::Absent,
        )],
    );
    assert!(matches!(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &expanding)
            .unwrap(),
        RuntimeInventoryOutcome::Rejected(
            RuntimeInventoryErrorDetail::PartialCatNotInFullInventory { cat_id, .. }
        ) if cat_id == foreign_cat
    ));
    assert!(fixture
        .store
        .load_current_cat_telemetry(&fixture.identity.node_id, &foreign_cat)
        .unwrap()
        .is_none());
    assert_eq!(operation_snapshot(&fixture.store), before_operation);
}

#[test]
fn malformed_stale_and_wrong_session_reports_cannot_change_an_operation() {
    let fixture = fixture();
    let before = operation_snapshot(&fixture.store);
    let mut malformed = full_report(&fixture.session, 1, 1, 30, Vec::new());
    let RuntimeInventoryBody::Full {
        inventory_digest, ..
    } = &mut malformed.inventory
    else {
        unreachable!()
    };
    *inventory_digest = digest(99);
    assert!(matches!(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &malformed)
            .unwrap(),
        RuntimeInventoryOutcome::Rejected(RuntimeInventoryErrorDetail::MalformedPayload)
    ));

    let accepted_full = full_report(&fixture.session, 1, 1, 31, Vec::new());
    accepted(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &accepted_full)
            .unwrap(),
    );
    let stale_epoch = full_report(&fixture.session, 2, 1, 32, Vec::new());
    assert!(matches!(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &stale_epoch)
            .unwrap(),
        RuntimeInventoryOutcome::Rejected(RuntimeInventoryErrorDetail::StaleInventoryEpoch { .. })
    ));

    let mut wrong_session = partial_report(&fixture.session, 2, 1, 33, Vec::new());
    wrong_session.session.agent_instance_id = random(999);
    assert!(matches!(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &wrong_session)
            .unwrap(),
        RuntimeInventoryOutcome::Rejected(RuntimeInventoryErrorDetail::WrongSession { .. })
    ));
    assert_eq!(operation_snapshot(&fixture.store), before);
}

#[test]
fn rejected_inventory_releases_db_locks_for_the_lifecycle_lane() {
    let fixture = fixture();
    let partial_without_full = partial_report(&fixture.session, 1, 1, 40, Vec::new());
    let request_context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(10));
    assert!(matches!(
        fixture
            .store
            .runtime_accept_inventory_for_request(
                &fixture.authenticated,
                &partial_without_full,
                &request_context,
            )
            .unwrap(),
        RuntimeInventoryOutcome::Rejected(RuntimeInventoryErrorDetail::MissingFullInventory { .. })
    ));

    // A definite rejection rolls its transaction back. The command lane can
    // immediately lock its unresolved Operation; telemetry owns no queue,
    // row state, or settlement dependency in that lane.
    fixture
        .store
        .with(|client| {
            let mut transaction = client.transaction()?;
            let row = transaction.query_one(
                "SELECT state FROM runtime_operations
                  WHERE operation_id='operation_inventory' FOR UPDATE NOWAIT",
                &[],
            )?;
            assert_eq!(row.get::<_, String>("state"), "unresolved");
            transaction.rollback()
        })
        .unwrap();
}

#[test]
fn replacement_session_rejects_old_reports_without_touching_operation() {
    let fixture = fixture();
    let before = operation_snapshot(&fixture.store);
    let replacement_attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: fixture.identity.node_id.clone(),
        immutable_host_id: fixture.identity.immutable_host_id.clone(),
        node_boot_id: NodeBootId::new("22222222222222222222222222222222").unwrap(),
        agent_instance_id: random(50),
        registration_attempt_id: random(51),
        guest_config_digest: fixture.policy.approved_guest_config_digest().clone(),
        expected_agent_session_epoch: Some(fixture.session.agent_session_epoch),
    };
    registered(
        fixture
            .store
            .register_agent_session(
                &fixture.authenticated,
                &replacement_attempt,
                &fixture.policy,
            )
            .unwrap(),
    );
    let old = full_report(&fixture.session, 1, 1, 52, Vec::new());
    assert!(matches!(
        fixture
            .store
            .runtime_accept_inventory(&fixture.authenticated, &old)
            .unwrap(),
        RuntimeInventoryOutcome::Rejected(RuntimeInventoryErrorDetail::StaleSession { .. })
    ));
    assert_eq!(operation_snapshot(&fixture.store), before);
}

//! Real PostgreSQL acceptance tests for the A20 runtime spine.

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use cats_api::runtime_reconciliation::{
    decode_operation, encode_admission_inventory_attestation, encode_agent_session,
    encode_desired_read_snapshot, encode_node_observation, inventory_digest, spec_digest,
    AgentRegistrationAttempt, AgentSession, AppliedDesiredEvidence, AsciiText, AssignedKind,
    AssignedPlacement, BlockedReason, CheckpointEvidence, Condition, ContractErrorDetail,
    ContractVersion, CredentialBinding, DesiredRuntimeSpec, Epoch, GuestRuntimeProfileReceipt,
    GuestTransportEvidence, Id, InventorySource, Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission,
    MacAddress, NetworkConfig, NodeBootId, NodeIdentity, NodeIdentityState, NodeObservation,
    ObservationInventoryAcceptance, ObservedRuntimeStatus, Operation, OperationFailure,
    OperationPhase, OperationTerminal, PlacementRejectionReason, PreconditionFailureReason,
    QuarantineReason, RandomId128, ReadyReason, ReconcileStep, Revision, RuntimeConfig,
    RuntimeTarget, RuntimeTransition, Sequence, SessionBinding, Sha256Digest, StableState,
    UnixMillis, WarmSnapshotEvidence,
};

use super::product::CatRecord;
use super::product_rows::{insert_cat, insert_desired, insert_operation};
use super::rows::database_now;
use super::runtime_spine::{
    lock_placement_admission_for_desired_mutation, PlacementAdmissionLoad,
    PlacementAdmissionRejection, RouteRuntimeLoad, RouteRuntimeRejection, RuntimeSpineOutcome,
    RuntimeSpineRejection,
};
use crate::store::agent_sessions::{
    AgentRegistrationOutcome, AgentSessionRegistrationPolicy, AuthenticatedNodeCredential,
};
use crate::store::Store;

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn boot(value: u128) -> NodeBootId {
    NodeBootId::new(format!("{value:032x}")).unwrap()
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
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

fn fixture() -> (
    Store,
    NodeIdentity,
    AuthenticatedNodeCredential,
    AgentSessionRegistrationPolicy,
    AgentSession,
) {
    let url = crate::testsupport::isolated_control_store_url();
    fixture_at(&url)
}

fn fixture_at(
    url: &str,
) -> (
    Store,
    NodeIdentity,
    AuthenticatedNodeCredential,
    AgentSessionRegistrationPolicy,
    AgentSession,
) {
    let store = Store::connect(url, None).unwrap();
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node_a"),
        immutable_host_id: id("host_a"),
        credential_id: id("credential_a"),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(9),
        },
        state_path_id: id("state_path_a"),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let policy =
        AgentSessionRegistrationPolicy::from_release_receipt(&release(), Duration::from_secs(120))
            .unwrap();
    store.provision_node_identity(&identity).unwrap();
    let attempt = registration_attempt(&identity, 1, None, policy.approved_guest_config_digest());
    let session = registered(
        store
            .register_agent_session(&authenticated, &attempt, &policy)
            .unwrap(),
    );
    (store, identity, authenticated, policy, session)
}

fn numbered_identity(index: usize) -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(format!("node_{index:03}")),
        immutable_host_id: id(format!("host_{index:03}")),
        credential_id: id(format!("credential_{index:03}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(u8::try_from(index).unwrap()),
        },
        state_path_id: id(format!("state_path_{index:03}")),
        state: NodeIdentityState::Provisioned,
    }
}

fn registration_attempt(
    identity: &NodeIdentity,
    number: u128,
    expected_epoch: Option<Epoch>,
    guest_config_digest: &Sha256Digest,
) -> AgentRegistrationAttempt {
    AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: boot(number),
        agent_instance_id: random(number + 100),
        registration_attempt_id: random(number + 200),
        guest_config_digest: guest_config_digest.clone(),
        expected_agent_session_epoch: expected_epoch,
    }
}

fn registered(outcome: AgentRegistrationOutcome) -> AgentSession {
    match outcome {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("registration rejected: {rejection:?}")
        }
    }
}

fn overwrite_current_session(
    client: &mut impl postgres::GenericClient,
    session: &AgentSession,
) -> std::result::Result<u64, postgres::Error> {
    let record = String::from_utf8(encode_agent_session(session).unwrap()).unwrap();
    let epoch = i64::try_from(session.agent_session_epoch.get()).unwrap();
    let deadline = i64::try_from(session.lease_deadline_unix_ms.get()).unwrap();
    client.execute(
        "UPDATE current_agent_sessions SET
            record=$2::TEXT::jsonb, immutable_host_id=$3, node_boot_id=$4,
            agent_instance_id=$5, agent_session_epoch=$6,
            registration_attempt_id=$7, guest_config_digest=$8,
            lease_deadline_unix_ms=$9
          WHERE node_id=$1",
        &[
            &session.node_id.as_str(),
            &record,
            &session.immutable_host_id.as_str(),
            &session.node_boot_id.as_str(),
            &session.agent_instance_id.as_str(),
            &epoch,
            &session.registration_attempt_id.as_str(),
            &session.guest_config_digest.as_str(),
            &deadline,
        ],
    )
}

fn binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn db_now(store: &Store) -> UnixMillis {
    let value = store
        .with(|client| {
            client
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
                    &[],
                )
                .map(|row| row.get::<_, i64>(0))
        })
        .unwrap();
    UnixMillis::new(u64::try_from(value).unwrap()).unwrap()
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

fn current_desired(workspace_id: &Id, node_id: &Id) -> DesiredRuntimeSpec {
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: workspace_id.clone(),
        cat_id: id("cat_settlement"),
        desired_revision: Revision::new(1).unwrap(),
        target: RuntimeTarget::Running,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: node_id.clone(),
            placement_epoch: Epoch::new(3).unwrap(),
        },
        runtime: RuntimeConfig {
            vcpus: 1,
            memory_bytes: 512 * 1024 * 1024,
            boot_image_digest: digest(3),
            guest_config_digest: digest(4),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id("net_settlement"),
                guest_mac: MacAddress::new("02:00:00:00:00:01").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
            },
        },
        volumes: Vec::new(),
        endpoints: Vec::new(),
        transition: RuntimeTransition::CancelAndDrain,
        spec_digest: digest(0),
    };
    desired.spec_digest = spec_digest(&desired).unwrap();
    desired
}

fn insert_pending_operation(store: &Store, desired: &DesiredRuntimeSpec) {
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: desired.cat_id.clone(),
                    workspace_id: desired.workspace_id.clone(),
                    name: id("settlement"),
                    created_at: now,
                },
            )?;
            insert_desired(transaction, desired)?;
            insert_operation(
                transaction,
                &Operation {
                    version: ContractVersion::V1,
                    operation_id: id("op_settlement"),
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
}

fn settlement_runtime(
    desired: &DesiredRuntimeSpec,
    rejected_node_id: &Id,
) -> ObservedRuntimeStatus {
    let runtime_incarnation = random(777);
    let step = ReconcileStep::Stable {
        state: StableState::Running,
    };
    ObservedRuntimeStatus {
        cat_id: desired.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        }),
        runtime_incarnation: Some(runtime_incarnation.clone()),
        stable_state: Some(StableState::Running),
        step: step.clone(),
        checkpoint: CheckpointEvidence::Valid {
            checkpoint_path: cats_api::runtime_reconciliation::HostPath::new(
                "/var/lib/cats/settlement.json",
            )
            .unwrap(),
            content_digest: digest(6),
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement_epoch: desired.placement.placement_epoch,
            runtime_incarnation: Some(runtime_incarnation),
            stable_state: Some(StableState::Running),
            step: Box::new(step),
            require_idle: Box::new(
                cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
            ),
            updated_at_unix_ms: UnixMillis::new(1).unwrap(),
        },
        processes: Vec::new(),
        volumes: Vec::new(),
        mounts: Vec::new(),
        networks: Vec::new(),
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission: LifecycleAdmission::Open,
        routes: Vec::new(),
        platform_guards: 0,
        conditions: vec![
            Condition::Ready {
                reason: ReadyReason::PostconditionSatisfied {
                    target: RuntimeTarget::Running,
                },
            },
            Condition::PreconditionFailed {
                reason: PreconditionFailureReason::MustBeCold {
                    observed_state: Some(StableState::Running),
                },
            },
            Condition::PreconditionFailed {
                reason: PreconditionFailureReason::PlacementRejected {
                    node_id: rejected_node_id.clone(),
                    placement_epoch: desired.placement.placement_epoch,
                    reason: PlacementRejectionReason::InsufficientMemory,
                },
            },
            Condition::Quarantined {
                reason: QuarantineReason::CheckpointCorrupt {
                    raw_content_digest: digest(8),
                },
            },
        ],
    }
}

fn orphan_runtime(session: &AgentSession, blocked: bool) -> ObservedRuntimeStatus {
    ObservedRuntimeStatus {
        cat_id: id("cat_orphan"),
        applied_desired: Some(cats_api::runtime_reconciliation::AppliedDesiredEvidence {
            desired_revision: cats_api::runtime_reconciliation::Revision::new(1).unwrap(),
            spec_digest: digest(7),
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: session.node_id.clone(),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            target: RuntimeTarget::Cold,
        }),
        runtime_incarnation: None,
        stable_state: None,
        step: ReconcileStep::InspectInventory {
            inventory_epoch: Epoch::new(1).unwrap(),
        },
        checkpoint: CheckpointEvidence::Missing {
            checkpoint_path: cats_api::runtime_reconciliation::HostPath::new(
                "/var/lib/cats/orphan.json",
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
        conditions: blocked
            .then(|| Condition::Blocked {
                reason: BlockedReason::IncompleteInventory {
                    unavailable_sources: vec![InventorySource::Process],
                },
            })
            .into_iter()
            .collect(),
    }
}

fn observation(
    store: &Store,
    session: &AgentSession,
    sequence: u64,
    inventory_epoch: u64,
    complete: bool,
    read_position: Option<Sequence>,
    runtimes: Vec<ObservedRuntimeStatus>,
) -> NodeObservation {
    let mut value = NodeObservation {
        version: ContractVersion::V1,
        observation_id: random(1_000 + u128::from(sequence)),
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
        heartbeat_sequence: Sequence::new(sequence).unwrap(),
        observed_at_unix_ms: db_now(store),
        complete_inventory: complete,
        inventory_epoch: Epoch::new(inventory_epoch).unwrap(),
        inventory_digest: complete.then(|| digest(0)),
        inventory_read_position: read_position,
        key_ring_version: None,
        key_ring_digest: None,
        loaded_kids: Vec::new(),
        runtimes,
        residue: Vec::new(),
    };
    if complete {
        value.inventory_digest = Some(inventory_digest(&value).unwrap());
    }
    value
}

fn accepted<T>(outcome: RuntimeSpineOutcome<T>) -> T {
    match outcome {
        RuntimeSpineOutcome::Accepted(value) => value,
        RuntimeSpineOutcome::Rejected(rejection) => panic!("runtime spine rejected: {rejection:?}"),
    }
}

#[test]
fn provisioned_node_id_pages_are_bounded_and_tolerate_a_concurrent_retire() {
    let url = crate::testsupport::isolated_control_store_url();
    let (first_store, existing, _, _, _) = fixture_at(&url);
    for index in 0..65 {
        first_store
            .provision_node_identity(&numbered_identity(index))
            .unwrap();
    }

    let first = first_store.list_provisioned_node_ids_after(None).unwrap();
    assert_eq!(first.node_ids.len(), 64);
    assert_eq!(first.node_ids.first(), Some(&id("node_000")));
    assert_eq!(first.node_ids.last(), Some(&id("node_063")));
    assert_eq!(first.next_after, Some(id("node_063")));
    let exact = first_store
        .list_provisioned_node_ids_after(Some(&id("node_001")))
        .unwrap();
    assert_eq!(exact.node_ids.len(), 64);
    assert_eq!(exact.node_ids.first(), Some(&id("node_002")));
    assert_eq!(exact.node_ids.last(), Some(&existing.node_id));
    assert_eq!(exact.next_after, None);

    // Each page is an intentionally invalidatable read plan. A second Store
    // retiring the look-ahead identity between snapshots removes it from the
    // next page without duplicating or reordering the remaining candidate.
    let second_store = Store::connect(&url, None).unwrap();
    second_store.retire_node_identity(&id("node_064")).unwrap();
    let second = first_store
        .list_provisioned_node_ids_after(first.next_after.as_ref())
        .unwrap();
    assert_eq!(second.node_ids, vec![existing.node_id]);
    assert_eq!(second.next_after, None);
}

#[test]
fn provisioned_node_id_page_strictly_decodes_every_returned_projection() {
    let (store, identity, _, _, _) = fixture();
    store
        .with(|client| {
            client.execute(
                "UPDATE node_identities
                    SET record=jsonb_set(record, '{immutable_host_id}', '\"corrupt_host\"')
                  WHERE node_id=$1",
                &[&identity.node_id.as_str()],
            )
        })
        .unwrap();

    assert!(store.list_provisioned_node_ids_after(None).is_err());
}

#[test]
fn desired_inventory_replay_partial_replacement_and_read_snapshots_are_closed() {
    let (store, identity, authenticated, policy, session1) = fixture();
    let request1 = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session1),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot1 = accepted(
        store
            .runtime_desired_read(&authenticated, &request1)
            .unwrap(),
    );
    assert_eq!(snapshot1.read_position.get(), 1);
    assert_eq!(
        accepted(
            store
                .runtime_desired_read(&authenticated, &request1)
                .unwrap()
        ),
        snapshot1
    );

    let in_progress = cats_api::runtime_reconciliation::DesiredReadRequest {
        request_sequence: Sequence::new(2).unwrap(),
        ..request1.clone()
    };
    assert!(matches!(
        store.runtime_desired_read(&authenticated, &in_progress).unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError {
                error,
                ..
            }
        )) if matches!(*error, ContractErrorDetail::DesiredReadInProgress { request_sequence, .. } if request_sequence.get() == 2)
    ));

    let full1 = observation(
        &store,
        &session1,
        10,
        1,
        true,
        Some(snapshot1.read_position),
        vec![orphan_runtime(&session1, false)],
    );
    let acceptance1 = accepted(
        store
            .runtime_accept_observation(&authenticated, &full1)
            .unwrap(),
    );
    assert_eq!(
        accepted(
            store
                .runtime_accept_observation(&authenticated, &full1)
                .unwrap()
        ),
        acceptance1
    );

    let mut conflicting = full1.clone();
    conflicting.observation_id = random(9_999);
    conflicting.inventory_digest = Some(inventory_digest(&conflicting).unwrap());
    assert!(matches!(
        store.runtime_accept_observation(&authenticated, &conflicting).unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(*error, ContractErrorDetail::ObservationSequenceConflict { .. })
    ));

    let partial = observation(
        &store,
        &session1,
        12,
        1,
        false,
        None,
        vec![orphan_runtime(&session1, true)],
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &partial)
            .unwrap(),
    );
    let source: String = store
        .with(|client| {
            client
                .query_one(
                    "SELECT source_kind FROM runtime_current_cat_observations
                      WHERE node_id='node_a' AND cat_id='cat_orphan'",
                    &[],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(source, "partial");
    assert!(matches!(
        store
            .load_route_runtime_snapshot(
                &identity.node_id,
                &id("cat_orphan"),
                policy.approved_guest_config_digest(),
            )
            .unwrap(),
        RouteRuntimeLoad::Accepted(_)
    ));

    let snapshot2 = accepted(
        store
            .runtime_desired_read(&authenticated, &in_progress)
            .unwrap(),
    );
    assert_eq!(snapshot2.read_position.get(), 2);
    let full2 = observation(
        &store,
        &session1,
        20,
        2,
        true,
        Some(snapshot2.read_position),
        Vec::new(),
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full2)
            .unwrap(),
    );
    let rows: i64 = store
        .with(|client| {
            client
                .query_one(
                    "SELECT count(*) FROM runtime_current_cat_observations WHERE node_id='node_a'",
                    &[],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(rows, 0);
    assert!(matches!(
        store
            .load_route_runtime_snapshot(
                &identity.node_id,
                &id("cat_orphan"),
                policy.approved_guest_config_digest(),
            )
            .unwrap(),
        RouteRuntimeLoad::Rejected(RouteRuntimeRejection::RuntimeMissing)
    ));

    let attempt2 = registration_attempt(
        &identity,
        2,
        Some(session1.agent_session_epoch),
        policy.approved_guest_config_digest(),
    );
    let session2 = registered(
        store
            .register_agent_session(&authenticated, &attempt2, &policy)
            .unwrap(),
    );
    assert!(matches!(
        store.runtime_desired_read(&authenticated, &request1).unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(*error, ContractErrorDetail::StaleSession { .. })
    ));
    assert!(matches!(
        store
            .load_placement_admission_snapshot(
                &identity.node_id,
                policy.approved_guest_config_digest(),
            )
            .unwrap(),
        PlacementAdmissionLoad::Rejected(PlacementAdmissionRejection::InventorySessionReplaced)
    ));
    let new_request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session2),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot3 = accepted(
        store
            .runtime_desired_read(&authenticated, &new_request)
            .unwrap(),
    );
    assert_eq!(snapshot3.read_position.get(), 3);
    let new_partial = observation(&store, &session2, 1, 1, false, None, Vec::new());
    assert!(matches!(
        store.runtime_accept_observation(&authenticated, &new_partial).unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(*error, ContractErrorDetail::MissingInventoryAttestation { .. })
    ));
    let new_full = observation(
        &store,
        &session2,
        2,
        1,
        true,
        Some(snapshot3.read_position),
        Vec::new(),
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &new_full)
            .unwrap(),
    );
    let admission = store
        .load_placement_admission_snapshot(&identity.node_id, policy.approved_guest_config_digest())
        .unwrap();
    assert!(matches!(admission, PlacementAdmissionLoad::Accepted(_)));
}

#[test]
fn operation_settlement_validates_every_reason_then_selects_first_terminal_atomically() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let workspace = bootstrap_workspace(&store, "f3c-settlement");
    let desired = current_desired(&workspace, &identity.node_id);
    insert_pending_operation(&store, &desired);
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );

    let invalid = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        vec![settlement_runtime(&desired, &id("node_wrong"))],
    );
    let rejection = store
        .runtime_accept_observation(&authenticated, &invalid)
        .unwrap();
    assert!(matches!(
        rejection,
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(
            *error,
            ContractErrorDetail::MalformedPayload { ref json_pointer, .. }
                if json_pointer.as_str() == "/runtimes/0/conditions/2/reason/node_id"
        )
    ));
    let (phase, receive_rows): (String, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT phase FROM runtime_operations WHERE operation_id='op_settlement'),
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id='node_a')",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(phase, "pending");
    assert_eq!(receive_rows, 0);

    let valid = observation(
        &store,
        &session,
        2,
        1,
        true,
        Some(snapshot.read_position),
        vec![settlement_runtime(&desired, &identity.node_id)],
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &valid)
            .unwrap(),
    );
    let operation_json: String = store
        .with(|client| {
            client
                .query_one(
                    "SELECT record::text FROM runtime_operations WHERE operation_id='op_settlement'",
                    &[],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    let operation = decode_operation(operation_json.as_bytes()).unwrap();
    assert_eq!(operation.phase, OperationPhase::Failed);
    assert!(matches!(
        operation.terminal,
        Some(OperationTerminal::Failed { error, .. })
            if matches!(
                *error,
                OperationFailure::PreconditionFailed {
                    reason: PreconditionFailureReason::MustBeCold {
                        observed_state: Some(StableState::Running)
                    }
                }
            )
    ));
}

#[test]
fn non_attested_pending_operation_still_rejects_wrong_placement() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let workspace = bootstrap_workspace(&store, "f3c-extra-placement");
    let mut desired = current_desired(&workspace, &id("node_b"));
    desired.spec_digest = spec_digest(&desired).unwrap();
    insert_pending_operation(&store, &desired);
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    assert!(snapshot.desired_specs.is_empty());
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        vec![settlement_runtime(&desired, &desired.placement.node_id)],
    );
    assert!(matches!(
        store.runtime_accept_observation(&authenticated, &full).unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(
            error.as_ref(),
            ContractErrorDetail::WrongPlacement { expected, presented, .. }
                if expected.node_id == id("node_b") && presented.node_id == identity.node_id
        )
    ));
    let state: (String, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT phase FROM runtime_operations WHERE operation_id='op_settlement'),
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id='node_a')",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(state, ("pending".to_owned(), 0));
}

#[test]
fn partial_settles_operation_for_cat_that_was_an_orphan_in_the_full_snapshot() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let workspace = bootstrap_workspace(&store, "f3c-partial-settlement");
    let desired = current_desired(&workspace, &identity.node_id);
    let runtime = settlement_runtime(&desired, &identity.node_id);
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        vec![runtime.clone()],
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap(),
    );
    insert_pending_operation(&store, &desired);
    let partial = observation(&store, &session, 2, 1, false, None, vec![runtime]);
    accepted(
        store
            .runtime_accept_observation(&authenticated, &partial)
            .unwrap(),
    );
    let phase: String = store
        .with(|client| {
            client
                .query_one(
                    "SELECT phase FROM runtime_operations WHERE operation_id='op_settlement'",
                    &[],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(phase, "failed");
}

#[test]
fn operation_time_rollback_is_fatal_before_any_observation_write() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let workspace = bootstrap_workspace(&store, "f3c-operation-clock");
    let desired = current_desired(&workspace, &identity.node_id);
    insert_pending_operation(&store, &desired);
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let future = i64::try_from(db_now(&store).get() + 600_000).unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_operations
                    SET updated_at=$1,
                        record=jsonb_set(record, '{updated_at_unix_ms}', to_jsonb($1::BIGINT), FALSE)
                  WHERE operation_id='op_settlement'",
                &[&future],
            )
        })
        .unwrap();
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        vec![settlement_runtime(&desired, &identity.node_id)],
    );
    assert_eq!(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap_err()
            .code,
        cats_api::error::ErrorCode::Internal
    );
    let state: (String, i64) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT phase FROM runtime_operations WHERE operation_id='op_settlement'),
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id='node_a')",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(state, ("pending".to_owned(), 0));
}

#[test]
fn cursor_expiry_and_projection_corruption_are_zero_write_and_fail_closed() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let mut snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let now = db_now(&store);
    snapshot.issued_at_unix_ms = UnixMillis::new(now.get().saturating_sub(1)).unwrap();
    snapshot.expires_at_unix_ms = now;
    let snapshot_json =
        String::from_utf8(encode_desired_read_snapshot(&snapshot).unwrap()).unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_desired_read_states
                    SET response=$2::TEXT::jsonb, issued_at_unix_ms=$3,
                        expires_at_unix_ms=$4
                  WHERE node_id=$1",
                &[
                    &identity.node_id.as_str(),
                    &snapshot_json,
                    &i64::try_from(snapshot.issued_at_unix_ms.get()).unwrap(),
                    &i64::try_from(snapshot.expires_at_unix_ms.get()).unwrap(),
                ],
            )
        })
        .unwrap();
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );
    assert!(matches!(
        store.runtime_accept_observation(&authenticated, &full).unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(*error, ContractErrorDetail::InventoryReadPositionExpired { .. })
    ));
    let state: (i64, Option<String>) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id=$1),
                        (SELECT consumed_observation_id FROM runtime_desired_read_states WHERE node_id=$1)",
                    &[&identity.node_id.as_str()],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap();
    assert_eq!(state, (0, None));

    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_desired_read_states
                    SET last_request_sequence=last_request_sequence+1
                  WHERE node_id=$1",
                &[&identity.node_id.as_str()],
            )
        })
        .unwrap();
    let error = store
        .runtime_desired_read(&authenticated, &request)
        .unwrap_err();
    assert_eq!(error.code, cats_api::error::ErrorCode::Internal);
}

#[test]
fn read_position_and_inventory_epoch_exhaustion_fail_closed() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let request1 = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot1 = accepted(
        store
            .runtime_desired_read(&authenticated, &request1)
            .unwrap(),
    );
    let full1 = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot1.read_position),
        Vec::new(),
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full1)
            .unwrap(),
    );
    let request2 = cats_api::runtime_reconciliation::DesiredReadRequest {
        request_sequence: Sequence::new(2).unwrap(),
        ..request1.clone()
    };
    let snapshot2 = accepted(
        store
            .runtime_desired_read(&authenticated, &request2)
            .unwrap(),
    );
    let mut exhausted = snapshot2;
    exhausted.read_position = Sequence::new(i64::MAX as u64).unwrap();
    let exhausted_json =
        String::from_utf8(encode_desired_read_snapshot(&exhausted).unwrap()).unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_desired_read_states
                    SET response=$2::TEXT::jsonb, read_position_high_water=$3,
                        consumed_observation_id=$4, consumed_heartbeat_sequence=$5
                  WHERE node_id=$1",
                &[
                    &identity.node_id.as_str(),
                    &exhausted_json,
                    &i64::MAX,
                    &full1.observation_id.as_str(),
                    &1_i64,
                ],
            )
        })
        .unwrap();
    let request3 = cats_api::runtime_reconciliation::DesiredReadRequest {
        request_sequence: Sequence::new(3).unwrap(),
        ..request1
    };
    assert_eq!(
        store
            .runtime_desired_read(&authenticated, &request3)
            .unwrap_err()
            .code,
        cats_api::error::ErrorCode::Internal
    );

    let (store, identity, authenticated, _policy, session) = fixture();
    let request1 = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot1 = accepted(
        store
            .runtime_desired_read(&authenticated, &request1)
            .unwrap(),
    );
    let mut full1 = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot1.read_position),
        Vec::new(),
    );
    let acceptance1 = accepted(
        store
            .runtime_accept_observation(&authenticated, &full1)
            .unwrap(),
    );
    let request2 = cats_api::runtime_reconciliation::DesiredReadRequest {
        request_sequence: Sequence::new(2).unwrap(),
        ..request1
    };
    let snapshot2 = accepted(
        store
            .runtime_desired_read(&authenticated, &request2)
            .unwrap(),
    );
    full1.inventory_epoch = Epoch::new(i64::MAX as u64).unwrap();
    full1.inventory_digest = Some(inventory_digest(&full1).unwrap());
    let ObservationInventoryAcceptance::Full { mut attestation } = acceptance1.inventory else {
        panic!("full observation returned partial acceptance")
    };
    attestation.inventory_epoch = full1.inventory_epoch;
    attestation.inventory_digest = full1.inventory_digest.clone().unwrap();
    let observation_json = String::from_utf8(encode_node_observation(&full1).unwrap()).unwrap();
    let attestation_json =
        String::from_utf8(encode_admission_inventory_attestation(&attestation).unwrap()).unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_admission_inventory_states
                    SET attestation=$2::TEXT::jsonb, full_observation=$3::TEXT::jsonb,
                        inventory_epoch=$4, inventory_digest=$5
                  WHERE node_id=$1",
                &[
                    &identity.node_id.as_str(),
                    &attestation_json,
                    &observation_json,
                    &i64::MAX,
                    &attestation.inventory_digest.as_str(),
                ],
            )
        })
        .unwrap();
    let exhausted_full = observation(
        &store,
        &session,
        2,
        i64::MAX as u64,
        true,
        Some(snapshot2.read_position),
        Vec::new(),
    );
    assert_eq!(
        store
            .runtime_accept_observation(&authenticated, &exhausted_full)
            .unwrap_err()
            .code,
        cats_api::error::ErrorCode::Internal
    );
}

#[test]
fn assigned_set_change_after_cursor_is_rejected_before_inventory_membership() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let workspace = bootstrap_workspace(&store, "f3c-assigned-change");
    let desired = current_desired(&workspace, &identity.node_id);
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: desired.cat_id.clone(),
                    workspace_id: workspace.clone(),
                    name: id("changed"),
                    created_at: now,
                },
            )?;
            insert_desired(transaction, &desired)
        })
        .unwrap();
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );
    assert!(matches!(
        store.runtime_accept_observation(&authenticated, &full).unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(*error, ContractErrorDetail::AssignedSetChanged { .. })
    ));
    let receive_rows: i64 = store
        .with(|client| {
            client
                .query_one(
                    "SELECT count(*) FROM runtime_observation_receive_states WHERE node_id=$1",
                    &[&identity.node_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(receive_rows, 0);
}

#[test]
fn cross_document_receipt_corruption_fails_closed() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap(),
    );
    let corrupted_digest = digest(99);
    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_observation_receive_states
                    SET acceptance=jsonb_set(
                        acceptance,
                        '{inventory,attestation,inventory_digest}',
                        to_jsonb($2::TEXT), FALSE)
                  WHERE node_id=$1",
                &[&identity.node_id.as_str(), &corrupted_digest.as_str()],
            )
        })
        .unwrap();
    assert_eq!(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap_err()
            .code,
        cats_api::error::ErrorCode::Internal
    );

    let (store, identity, authenticated, policy, session) = fixture();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap(),
    );
    let changed_position = i64::try_from(snapshot.read_position.get() + 1).unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_admission_inventory_states
                    SET assigned_snapshot=jsonb_set(
                        assigned_snapshot, '{read_position}', to_jsonb($2::BIGINT), FALSE)
                  WHERE node_id=$1",
                &[&identity.node_id.as_str(), &changed_position],
            )
        })
        .unwrap();
    assert_eq!(
        store
            .load_placement_admission_snapshot(
                &identity.node_id,
                policy.approved_guest_config_digest(),
            )
            .unwrap_err()
            .code,
        cats_api::error::ErrorCode::Internal
    );
}

#[test]
fn corrupt_admission_cursor_causality_blocks_partial_and_replacement_full() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let workspace = bootstrap_workspace(&store, "f3c-corrupt-causality");
    let desired = current_desired(&workspace, &identity.node_id);
    insert_pending_operation(&store, &desired);
    let request1 = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot1 = accepted(
        store
            .runtime_desired_read(&authenticated, &request1)
            .unwrap(),
    );
    let mut runtime = settlement_runtime(&desired, &identity.node_id);
    runtime.conditions = vec![Condition::Blocked {
        reason: BlockedReason::IncompleteInventory {
            unavailable_sources: vec![InventorySource::Process],
        },
    }];
    let full1 = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot1.read_position),
        vec![runtime.clone()],
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full1)
            .unwrap(),
    );
    let request2 = cats_api::runtime_reconciliation::DesiredReadRequest {
        request_sequence: Sequence::new(2).unwrap(),
        ..request1
    };
    let snapshot2 = accepted(
        store
            .runtime_desired_read(&authenticated, &request2)
            .unwrap(),
    );
    let before: (i64, i64, i64, String, String) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id=$1),
                        (SELECT count(*) FROM runtime_current_cat_observations WHERE node_id=$1),
                        (SELECT lease_deadline_unix_ms FROM current_agent_sessions WHERE node_id=$1),
                        (SELECT phase FROM runtime_operations WHERE cat_id=$2),
                        (SELECT record::text FROM runtime_operations WHERE cat_id=$2)",
                    &[&identity.node_id.as_str(), &desired.cat_id.as_str()],
                )
                .map(|row| {
                    (
                        row.get(0),
                        row.get(1),
                        row.get(2),
                        row.get(3),
                        row.get(4),
                    )
                })
        })
        .unwrap();
    assert_eq!(before.0, 1);
    assert_eq!(before.1, 1);
    assert_eq!(before.3, "pending");

    // Keep the JSON/scalar projection equal while moving accepted_at exactly
    // to cursor expiry. The shared row decoder must reject the broken strict
    // `issued <= accepted < expires` receipt before either request can write.
    let corrupt_accepted_at = i64::try_from(snapshot1.expires_at_unix_ms.get()).unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_admission_inventory_states
                    SET attestation=jsonb_set(
                            attestation, '{accepted_at_unix_ms}', to_jsonb($2::BIGINT), FALSE),
                        accepted_at_unix_ms=$2
                  WHERE node_id=$1",
                &[&identity.node_id.as_str(), &corrupt_accepted_at],
            )
        })
        .unwrap();

    let partial = observation(&store, &session, 2, 1, false, None, Vec::new());
    assert_eq!(
        store
            .runtime_accept_observation(&authenticated, &partial)
            .unwrap_err()
            .code,
        cats_api::error::ErrorCode::Internal
    );
    let full2 = observation(
        &store,
        &session,
        2,
        2,
        true,
        Some(snapshot2.read_position),
        vec![runtime],
    );
    assert_eq!(
        store
            .runtime_accept_observation(&authenticated, &full2)
            .unwrap_err()
            .code,
        cats_api::error::ErrorCode::Internal
    );

    let after: (i64, i64, i64, String, String) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id=$1),
                        (SELECT count(*) FROM runtime_current_cat_observations WHERE node_id=$1),
                        (SELECT lease_deadline_unix_ms FROM current_agent_sessions WHERE node_id=$1),
                        (SELECT phase FROM runtime_operations WHERE cat_id=$2),
                        (SELECT record::text FROM runtime_operations WHERE cat_id=$2)",
                    &[&identity.node_id.as_str(), &desired.cat_id.as_str()],
                )
                .map(|row| {
                    (
                        row.get(0),
                        row.get(1),
                        row.get(2),
                        row.get(3),
                        row.get(4),
                    )
                })
        })
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn desired_mutation_coordination_helper_revalidates_exact_admission_facts() {
    let (store, identity, authenticated, policy, session) = fixture();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap(),
    );
    let planned = match store
        .load_placement_admission_snapshot(&identity.node_id, policy.approved_guest_config_digest())
        .unwrap()
    {
        PlacementAdmissionLoad::Accepted(snapshot) => *snapshot,
        PlacementAdmissionLoad::Rejected(rejection) => {
            panic!("admission unexpectedly rejected: {rejection:?}")
        }
    };
    assert!(matches!(
        store
            .authority_transaction(|transaction| {
                lock_placement_admission_for_desired_mutation(
                    transaction,
                    &planned,
                    policy.approved_guest_config_digest(),
                )
            })
            .unwrap(),
        PlacementAdmissionLoad::Accepted(_)
    ));

    let mut changed = planned;
    changed.inventory_attestation.inventory_digest = digest(88);
    assert_eq!(
        store
            .authority_transaction(|transaction| {
                lock_placement_admission_for_desired_mutation(
                    transaction,
                    &changed,
                    policy.approved_guest_config_digest(),
                )
            })
            .unwrap(),
        PlacementAdmissionLoad::Rejected(PlacementAdmissionRejection::AdmissionChanged)
    );
}

#[test]
fn session_replacement_committed_while_identity_is_locked_is_never_read_from_an_old_snapshot() {
    let url = crate::testsupport::isolated_control_store_url();
    let (store, identity, authenticated, policy, session1) = fixture_at(&url);
    let attempt2 = registration_attempt(
        &identity,
        2,
        Some(session1.agent_session_epoch),
        policy.approved_guest_config_digest(),
    );
    let session2 = registered(
        store
            .register_agent_session(&authenticated, &attempt2, &policy)
            .unwrap(),
    );
    // Both immutable attempt rows now exist. Put session 1 back so the
    // waiting request's first statement can establish the stale state that a
    // REPEATABLE READ mutation would incorrectly retain after the lock wait.
    store
        .with(|client| overwrite_current_session(client, &session1))
        .unwrap();

    let replacer = Store::connect(&url, None).unwrap();
    let replacement_identity = identity.node_id.clone();
    let replacement_session = session2.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let replacer_thread = std::thread::spawn(move || {
        replacer
            .with(move |client| {
                let mut transaction = client.transaction()?;
                transaction.query_one(
                    "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE",
                    &[&replacement_identity.as_str()],
                )?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                overwrite_current_session(&mut transaction, &replacement_session)?;
                transaction.commit()
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();

    let requester = Store::connect(&url, None).unwrap();
    let requester_pid: i32 = requester
        .with(|client| {
            client
                .query_one("SELECT pg_backend_pid()", &[])
                .map(|row| row.get(0))
        })
        .unwrap();
    let requester_authenticated = authenticated.clone();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session1),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let requester_thread = std::thread::spawn(move || {
        requester.runtime_desired_read(&requester_authenticated, &request)
    });
    let observer = Store::connect(&url, None).unwrap();
    let mut waiting_on_identity = false;
    for _ in 0..200 {
        let wait_event: Option<String> = observer
            .with(|client| {
                client
                    .query_opt(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                        &[&requester_pid],
                    )
                    .map(|row| row.and_then(|row| row.get(0)))
            })
            .unwrap();
        if wait_event.as_deref() == Some("Lock") {
            waiting_on_identity = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(waiting_on_identity, "request never waited on NodeIdentity");
    release_tx.send(()).unwrap();
    replacer_thread.join().unwrap();

    assert!(matches!(
        requester_thread.join().unwrap().unwrap(),
        RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
            cats_api::runtime_reconciliation::ContractError { error, .. }
        )) if matches!(*error, ContractErrorDetail::StaleSession { .. })
    ));
    let desired_rows: i64 = store
        .with(|client| {
            client
                .query_one(
                    "SELECT count(*) FROM runtime_desired_read_states WHERE node_id=$1",
                    &[&identity.node_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(desired_rows, 0);
}

#[test]
fn two_control_plane_instances_commit_once_and_exact_replay_the_loser() {
    let url = crate::testsupport::isolated_control_store_url();
    let (issuer, _identity, authenticated, _policy, session) = fixture_at(&url);
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        issuer
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let full = observation(
        &issuer,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );
    let first = Store::connect(&url, None).unwrap();
    let second = Store::connect(&url, None).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first_authenticated = authenticated.clone();
    let second_authenticated = authenticated.clone();
    let first_observation = full.clone();
    let second_observation = full.clone();
    let first_worker = std::thread::spawn(move || {
        first_barrier.wait();
        first.runtime_accept_observation(&first_authenticated, &first_observation)
    });
    let second_worker = std::thread::spawn(move || {
        second_barrier.wait();
        second.runtime_accept_observation(&second_authenticated, &second_observation)
    });
    barrier.wait();
    let first_acceptance = accepted(first_worker.join().unwrap().unwrap());
    let second_acceptance = accepted(second_worker.join().unwrap().unwrap());
    assert_eq!(first_acceptance, second_acceptance);

    let state: (i64, i64, i64) = issuer
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id='node_a'),
                        (SELECT count(*) FROM runtime_admission_inventory_states WHERE node_id='node_a'),
                        (SELECT count(*) FROM runtime_desired_read_states
                          WHERE node_id='node_a' AND consumed_observation_id IS NOT NULL)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
        })
        .unwrap();
    assert_eq!(state, (1, 1, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_active_submission_is_recovered_by_exact_response_loss_replay() {
    let url = crate::testsupport::isolated_control_store_url();
    let (issuer, _identity, authenticated, _policy, session) = fixture_at(&url);
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(
        issuer
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let full = observation(
        &issuer,
        &session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );

    let blocker = Store::connect(&url, None).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let node_id = session.node_id.clone();
    let blocker_thread = std::thread::spawn(move || {
        blocker
            .with(move |client| {
                let mut transaction = client.transaction()?;
                transaction.query_one(
                    "SELECT node_id FROM current_agent_sessions WHERE node_id=$1 FOR UPDATE",
                    &[&node_id.as_str()],
                )?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                transaction.rollback()
            })
            .unwrap();
    });
    tokio::task::spawn_blocking(move || locked_rx.recv().unwrap())
        .await
        .unwrap();

    let submission_store = Arc::new(Store::connect(&url, None).unwrap());
    let submission_pid: i32 = submission_store
        .with(|client| {
            client
                .query_one("SELECT pg_backend_pid()", &[])
                .map(|row| row.get(0))
        })
        .unwrap();
    let worker_store = Arc::clone(&submission_store);
    let worker_authenticated = authenticated.clone();
    let worker_observation = full.clone();
    let task = tokio::spawn(async move {
        worker_store
            .execute(move |store| {
                store.runtime_accept_observation(&worker_authenticated, &worker_observation)
            })
            .await
    });

    let observer = Store::connect(&url, None).unwrap();
    let mut waiting_on_lock = false;
    for _ in 0..200 {
        let wait_event: Option<String> = observer
            .with(|client| {
                client
                    .query_opt(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                        &[&submission_pid],
                    )
                    .map(|row| row.and_then(|row| row.get(0)))
            })
            .unwrap();
        if wait_event.as_deref() == Some("Lock") {
            waiting_on_lock = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        waiting_on_lock,
        "submission never entered the blocked transaction"
    );
    task.abort();
    release_tx.send(()).unwrap();
    blocker_thread.join().unwrap();

    let mut committed_deadline = None;
    for _ in 0..200 {
        committed_deadline = observer
            .with(|client| {
                client
                    .query_opt(
                        "SELECT lease_deadline_unix_ms FROM current_agent_sessions s
                          WHERE node_id=$1 AND EXISTS (
                            SELECT 1 FROM runtime_observation_receive_states r
                             WHERE r.node_id=s.node_id)",
                        &[&session.node_id.as_str()],
                    )
                    .map(|row| row.map(|row| row.get::<_, i64>(0)))
            })
            .unwrap();
        if committed_deadline.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let committed_deadline = committed_deadline.expect("cancelled active submission committed");
    accepted(
        issuer
            .runtime_accept_observation(&authenticated, &full)
            .unwrap(),
    );
    let after_replay: (i64, i64, i64) = observer
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM runtime_observation_receive_states WHERE node_id=$1),
                        (SELECT count(*) FROM runtime_admission_inventory_states WHERE node_id=$1),
                        (SELECT lease_deadline_unix_ms FROM current_agent_sessions WHERE node_id=$1)",
                    &[&session.node_id.as_str()],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
        })
        .unwrap();
    assert_eq!(after_replay, (1, 1, committed_deadline));
}

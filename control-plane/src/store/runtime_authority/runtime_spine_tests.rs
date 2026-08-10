//! Real PostgreSQL acceptance tests for the A20 runtime spine.

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ErrorCode;
use cats_api::route_grant_v2::{
    decode_route_resolve_v2_rejection, decode_route_resolve_v2_success,
    encode_route_resolve_v2_request, RouteResolveV2RejectionCode, RouteResolveV2Request,
    ROUTE_RESOLVE_V2_PATH, ROUTE_V2_JSON_CONTENT_TYPE,
};
use cats_api::runtime_reconciliation::{
    decode_operation, encode_admission_inventory_attestation, encode_agent_session,
    encode_desired_read_snapshot, encode_node_observation, guest_config_digest, inventory_digest,
    key_ring_digest, spec_digest, AgentRegistrationAttempt, AgentSession, AllocatableMemoryBytes,
    AllocatableVcpus, AppliedDesiredEvidence, AsciiText, AssignedKind, AssignedPlacement,
    BlockedReason, CheckpointEvidence, Condition, ContractErrorDetail, ContractVersion,
    ControlHandshakeEvidence, CredentialBinding, DesiredRuntimeSpec, EndpointIntent, Epoch,
    GuestBootId, GuestIpv4Pool, GuestIpv4PoolKind, GuestRuntimeProfileReceipt,
    GuestTransportEvidence, HostPath, Hostname, HttpProtocol, Id, InventorySource, Ipv4Address,
    IsolatedIpv4Kind, KeyId, LifecycleAdmission, MacAddress, NetworkConfig, NodeBootId,
    NodeIdentity, NodeIdentityState, NodeObservation, NodePlacementPolicy, NodeTransportTarget,
    ObservationInventoryAcceptance, ObservedNetwork, ObservedRouteGate, ObservedRuntimeStatus,
    ObservedVmShape, Operation, OperationFailure, OperationPhase, OperationTerminal,
    OwnershipTokenEvidence, PlacementRejectionReason, PreconditionFailureReason, ProcessEvidence,
    ProcessRole, ProcessState, QuarantineReason, RandomId128, ReadyReason, ReconcileStep, Revision,
    RouteGateBinding, RouteGateState, RuntimeConfig, RuntimePlacementBlockFrontend,
    RuntimePlacementCapabilities, RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport,
    RuntimePlacementVmm, RuntimeSchedulingState, RuntimeTarget, RuntimeTransition, Sequence,
    SessionBinding, Sha256Digest, StableState, UnixMillis, WarmSnapshotEvidence, WireU64,
};

use super::placement_policy::insert_policy_on_store_for_test;
use super::product::{CatRecord, EndpointRecord, HostnameDesiredLookup};
use super::product_rows::{
    insert_cat, insert_desired, insert_endpoint, insert_hostname_lookup, insert_operation,
};
use super::route_signer::{RouteGrantV2AuthorityLoad, RouteGrantV2AuthorityRejection};
use super::rows::database_now;
use super::runtime_spine::{
    lock_placement_admission_for_desired_mutation, PlacementAdmissionLoad,
    PlacementAdmissionRejection, RouteRuntimeLoad, RouteRuntimeRejection, RuntimeSpineOutcome,
    RuntimeSpineRejection,
};
use crate::store::agent_sessions::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy};
use crate::store::AuthorityRequestContext;
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

fn route_placement_policy(node_id: &Id, guest_config_digest: &Sha256Digest) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        policy_revision: Epoch::new(1).unwrap(),
        scheduling_state: RuntimeSchedulingState::Cordoned,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: guest_config_digest.clone(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
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
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&release()).unwrap();
    store.provision_node_identity(&identity).unwrap();
    let attempt = registration_attempt(&identity, 1, None, policy.approved_guest_config_digest());
    let session = registered(
        store
            .register_agent_session(&authenticated, &attempt, &policy)
            .unwrap(),
    );
    (store, identity, authenticated, policy, session)
}

fn desired_read_raw_rows(store: &Store) -> String {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT COALESCE(
                         jsonb_agg(to_jsonb(state_row) ORDER BY state_row.node_id),
                         '[]'::jsonb
                     )::text
                       FROM runtime_desired_read_states AS state_row",
                    &[],
                )
                .map(|row| row.get(0))
        })
        .unwrap()
}

#[test]
fn cancellation_after_commit_ownership_still_commits_and_exact_retry_recovers() {
    let url = crate::testsupport::isolated_control_store_url();
    let (store, _identity, authenticated, _policy, session) = fixture_at(&url);
    let observer = Store::connect(&url, None).unwrap();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    store.inject_committed_response_loss_once();
    let first_context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    first_context.pause_after_commit_claim_for_test(Arc::clone(&entered), Arc::clone(&release));
    let worker_context = first_context.clone();
    let worker_authenticated = authenticated.clone();
    let worker_request = request.clone();
    let worker = std::thread::spawn(move || {
        store.runtime_desired_read_for_request(
            &worker_authenticated,
            &worker_request,
            &worker_context,
        )
    });

    entered.wait();
    assert!(first_context.commit_was_attempted());
    // This is the same cancellation edge used by the A20 handler deadline
    // and CancelRequestOnDrop after the blocking worker owns COMMIT send.
    first_context.cancel();
    assert!(first_context.commit_was_attempted());
    release.wait();
    let error = worker.join().unwrap().unwrap_err();

    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(
        first_context.commit_was_attempted(),
        "the HTTP owner must close an unknown COMMIT response"
    );

    let retry_context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
    let replay = accepted(
        observer
            .runtime_desired_read_for_request(&authenticated, &request, &retry_context)
            .unwrap(),
    );
    assert_eq!(replay.request_sequence, request.request_sequence);
    assert!(replay.desired_specs.is_empty());
}

#[test]
fn cancellation_before_definite_commit_reset_prevents_retry_without_any_row_change() {
    let url = crate::testsupport::isolated_control_store_url();
    let (store, _identity, authenticated, _policy, session) = fixture_at(&url);
    store
        .with(|client| {
            client.batch_execute(
                "CREATE SEQUENCE a20_operation_attempts;
                 CREATE SEQUENCE a20_commit_attempts;
                 CREATE FUNCTION count_a20_operation_for_test()
                 RETURNS trigger LANGUAGE plpgsql AS $$
                 BEGIN
                   PERFORM nextval('a20_operation_attempts');
                   RETURN NEW;
                 END
                 $$;
                 CREATE TRIGGER count_a20_operation_for_test
                   BEFORE INSERT ON runtime_desired_read_states
                   FOR EACH ROW EXECUTE FUNCTION count_a20_operation_for_test();
                 CREATE FUNCTION fail_a20_commit_for_test()
                 RETURNS trigger LANGUAGE plpgsql AS $$
                 BEGIN
                   PERFORM nextval('a20_commit_attempts');
                   RAISE EXCEPTION 'injected definite COMMIT failure'
                     USING ERRCODE = '40001';
                 END
                 $$;
                 CREATE CONSTRAINT TRIGGER fail_a20_commit_for_test
                   AFTER INSERT ON runtime_desired_read_states
                   DEFERRABLE INITIALLY DEFERRED
                   FOR EACH ROW EXECUTE FUNCTION fail_a20_commit_for_test();",
            )
        })
        .unwrap();
    let before = desired_read_raw_rows(&store);
    let observer = Store::connect(&url, None).unwrap();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    context.pause_before_definite_commit_reset_for_test(Arc::clone(&entered), Arc::clone(&release));
    let worker_context = context.clone();
    let worker = std::thread::spawn(move || {
        store.runtime_desired_read_for_request(&authenticated, &request, &worker_context)
    });

    entered.wait();
    assert!(context.commit_was_attempted());
    assert_eq!(desired_read_raw_rows(&observer), before);
    context.cancel();
    assert!(context.commit_was_attempted());
    release.wait();
    let error = worker.join().unwrap().unwrap_err();

    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(!context.commit_was_attempted());
    assert_eq!(desired_read_raw_rows(&observer), before);
    let attempts: (i64, bool, i64, bool) = observer
        .with(|client| {
            let row = client.query_one(
                "SELECT operation.last_value, operation.is_called,
                        commit_attempt.last_value, commit_attempt.is_called
                   FROM a20_operation_attempts AS operation
                   CROSS JOIN a20_commit_attempts AS commit_attempt",
                &[],
            )?;
            Ok((row.get(0), row.get(1), row.get(2), row.get(3)))
        })
        .unwrap();
    assert_eq!(attempts, (1, true, 1, true));
}

#[test]
fn cancelling_a_started_http_authority_request_rolls_back_before_commit() {
    let url = crate::testsupport::isolated_control_store_url();
    let (store, _identity, authenticated, _policy, session) = fixture_at(&url);
    store
        .with(|client| {
            client.batch_execute(
                "CREATE OR REPLACE FUNCTION pause_runtime_desired_insert()
                 RETURNS trigger AS $$
                 BEGIN
                   PERFORM pg_sleep(0.5);
                   RETURN NEW;
                 END;
                 $$ LANGUAGE plpgsql;
                 CREATE TRIGGER pause_runtime_desired_insert
                   BEFORE INSERT ON runtime_desired_read_states
                   FOR EACH ROW EXECUTE FUNCTION pause_runtime_desired_insert();",
            )
        })
        .unwrap();
    let backend_pid: i32 = store
        .with(|client| Ok(client.query_one("SELECT pg_backend_pid()", &[])?.get(0)))
        .unwrap();
    let observer = Store::connect(&url, None).unwrap();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let context = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
    let worker_context = context.clone();
    let worker = std::thread::spawn(move || {
        store.runtime_desired_read_for_request(&authenticated, &request, &worker_context)
    });

    let wait_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let sleeping = observer
            .with(|client| {
                Ok(client
                    .query_opt(
                        "SELECT 1 FROM pg_stat_activity
                           WHERE pid=$1 AND wait_event='PgSleep'
                             AND query LIKE '%runtime_desired_read_states%'",
                        &[&backend_pid],
                    )?
                    .is_some())
            })
            .unwrap();
        if sleeping {
            break;
        }
        assert!(
            Instant::now() < wait_deadline,
            "request never reached the pre-commit trigger"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    context.cancel();

    let error = worker.join().unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    let row_count: i64 = observer
        .with(|client| {
            Ok(client
                .query_one("SELECT count(*) FROM runtime_desired_read_states", &[])?
                .get(0))
        })
        .unwrap();
    assert_eq!(
        row_count, 0,
        "cancelled request committed after its caller left"
    );
}

#[test]
fn authority_request_uses_its_remaining_deadline_as_the_postgres_timeout() {
    let url = crate::testsupport::isolated_control_store_url();
    let (store, _identity, authenticated, _policy, session) = fixture_at(&url);
    store
        .with(|client| {
            client.batch_execute(
                "CREATE OR REPLACE FUNCTION pause_runtime_desired_until_deadline()
                 RETURNS trigger AS $$
                 BEGIN
                   PERFORM pg_sleep(1);
                   RETURN NEW;
                 END;
                 $$ LANGUAGE plpgsql;
                 CREATE TRIGGER pause_runtime_desired_until_deadline
                   BEFORE INSERT ON runtime_desired_read_states
                   FOR EACH ROW EXECUTE FUNCTION pause_runtime_desired_until_deadline();",
            )
        })
        .unwrap();
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let context = AuthorityRequestContext::new(Instant::now() + Duration::from_millis(100));
    let started = Instant::now();
    let error = store
        .runtime_desired_read_for_request(&authenticated, &request, &context)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(
        started.elapsed() < Duration::from_millis(750),
        "the request must not inherit the ordinary five-second statement timeout"
    );
    let row_count: i64 = store
        .with(|client| {
            Ok(client
                .query_one("SELECT count(*) FROM runtime_desired_read_states", &[])?
                .get(0))
        })
        .unwrap();
    assert_eq!(row_count, 0);
}

fn numbered_identity(index: usize) -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(format!("node_{index:03}")),
        immutable_host_id: id(format!("host_{index:03}")),
        credential_id: id(format!("credential_{index:03}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(u8::try_from(index + 100).unwrap()),
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

pub(crate) fn establish_empty_admission(
    store: &Store,
    release: &GuestRuntimeProfileReceipt,
) -> super::runtime_spine::PlacementAdmissionSnapshot {
    establish_empty_admission_for(store, release, "a", 1)
}

pub(super) fn establish_empty_admission_for(
    store: &Store,
    release: &GuestRuntimeProfileReceipt,
    suffix: &str,
    number: u128,
) -> super::runtime_spine::PlacementAdmissionSnapshot {
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(format!("node_{suffix}")),
        immutable_host_id: id(format!("host_{suffix}")),
        credential_id: id(format!("credential_{suffix}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(u8::try_from(number).unwrap()),
        },
        state_path_id: id(format!("state_path_{suffix}")),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(release).unwrap();
    store.provision_node_identity(&identity).unwrap();
    let attempt = registration_attempt(
        &identity,
        number,
        None,
        policy.approved_guest_config_digest(),
    );
    let session = registered(
        store
            .register_agent_session(&authenticated, &attempt, &policy)
            .unwrap(),
    );
    accept_empty_admission(store, &identity, &authenticated, &policy, &session)
}

fn accept_empty_admission(
    store: &Store,
    identity: &NodeIdentity,
    authenticated: &AuthenticatedNodeCredential,
    policy: &AgentSessionRegistrationPolicy,
    session: &AgentSession,
) -> super::runtime_spine::PlacementAdmissionSnapshot {
    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let snapshot = accepted(store.runtime_desired_read(authenticated, &request).unwrap());
    let full = observation(
        store,
        session,
        1,
        1,
        true,
        Some(snapshot.read_position),
        Vec::new(),
    );
    accepted(
        store
            .runtime_accept_observation(authenticated, &full)
            .unwrap(),
    );
    match store
        .load_placement_admission_snapshot(&identity.node_id, policy.approved_guest_config_digest())
        .unwrap()
    {
        PlacementAdmissionLoad::Accepted(snapshot) => *snapshot,
        PlacementAdmissionLoad::Rejected(rejection) => {
            panic!("empty admission unexpectedly rejected: {rejection:?}")
        }
    }
}

fn bind_create_to_admission(
    request: &mut super::product::CoveredCatCreateRequest,
    admission: &super::runtime_spine::PlacementAdmissionSnapshot,
    active_guest_digest: &Sha256Digest,
) {
    request.candidate.desired.placement.node_id = admission.node_identity.node_id.clone();
    request.candidate.desired.runtime.guest_config_digest = active_guest_digest.clone();
    super::product_tests::refresh_candidate_contract(request);
}

fn covered_error_code(error: super::product::CoveredCatCreateError) -> cats_api::error::ErrorCode {
    match error {
        super::product::CoveredCatCreateError::Store(error) => error.code,
        super::product::CoveredCatCreateError::CandidateCollision(_) => {
            cats_api::error::ErrorCode::Internal
        }
        super::product::CoveredCatCreateError::PlacementStale => {
            cats_api::error::ErrorCode::Unavailable
        }
    }
}

#[test]
fn stale_plan_is_ignored_only_for_a_closed_existing_name_conflict() {
    let url = crate::testsupport::isolated_control_store_url();
    let (store, identity, authenticated, policy, session) = fixture_at(&url);
    let admission = accept_empty_admission(&store, &identity, &authenticated, &policy, &session);
    let active_guest_digest = policy.approved_guest_config_digest().clone();
    let workspace = super::product_tests::bootstrap_workspace(&store, "stale-plan-conflict");
    let mut occupied = super::product_tests::request(&workspace, "occupied", 1, "occupy");
    bind_create_to_admission(&mut occupied, &admission, &active_guest_digest);
    assert_eq!(
        store
            .create_cat_covered_with_admission(&occupied, &admission, &active_guest_digest,)
            .unwrap()
            .http_status,
        202
    );

    let replacement = registration_attempt(
        &identity,
        2,
        Some(session.agent_session_epoch),
        &active_guest_digest,
    );
    registered(
        store
            .register_agent_session(&authenticated, &replacement, &policy)
            .unwrap(),
    );

    let mut conflict = super::product_tests::request(&workspace, "occupied", 2, "conflict");
    bind_create_to_admission(&mut conflict, &admission, &active_guest_digest);
    let result = store
        .create_cat_covered_with_admission(&conflict, &admission, &active_guest_digest)
        .unwrap();
    assert_eq!(result.http_status, 409);
    assert_eq!(
        result.response_body,
        br#"{"code":"already_exists","message":"cat name already exists"}"#
    );
    assert_eq!(
        super::product_tests::counts(&store),
        [1, 1, 1, 1, 1, 1, 1, 2]
    );
}

#[test]
fn free_name_revalidates_after_a_concurrent_session_replacement() {
    const CREATE_APPLICATION: &str = "cats-f2d-create-admission-race";
    let url = crate::testsupport::isolated_control_store_url();
    let (store, identity, authenticated, policy, session) = fixture_at(&url);
    let admission = accept_empty_admission(&store, &identity, &authenticated, &policy, &session);
    let active_guest_digest = policy.approved_guest_config_digest().clone();
    let workspace = super::product_tests::bootstrap_workspace(&store, "admission-race");
    let mut create = super::product_tests::request(&workspace, "free", 1, "create");
    bind_create_to_admission(&mut create, &admission, &active_guest_digest);

    let mut blocker_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut blocker = blocker_client.transaction().unwrap();
    blocker
        .query_one(
            "SELECT node_id FROM current_agent_sessions WHERE node_id=$1 FOR UPDATE",
            &[&identity.node_id.as_str()],
        )
        .unwrap();

    // Calibrate the NOWAIT probe while only the session row is blocked: the
    // independent NodeIdentity row must still be immediately lockable.
    let mut probe = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut calibration = probe.transaction().unwrap();
    calibration
        .query_one(
            "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE NOWAIT",
            &[&identity.node_id.as_str()],
        )
        .unwrap();
    calibration.rollback().unwrap();

    let replacement_store = Store::connect(&url, None).unwrap();
    let replacement_authenticated = authenticated.clone();
    let replacement_policy = policy.clone();
    let replacement = registration_attempt(
        &identity,
        2,
        Some(session.agent_session_epoch),
        &active_guest_digest,
    );
    let replacement_worker = std::thread::spawn(move || {
        replacement_store.register_agent_session(
            &replacement_authenticated,
            &replacement,
            &replacement_policy,
        )
    });

    let mut identity_locked = false;
    for _ in 0..200 {
        let mut transaction = probe.transaction().unwrap();
        match transaction.query_one(
            "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE NOWAIT",
            &[&identity.node_id.as_str()],
        ) {
            Ok(_) => transaction.rollback().unwrap(),
            Err(error) if error.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) => {
                identity_locked = true;
                transaction.rollback().unwrap();
                break;
            }
            Err(error) => panic!("NodeIdentity lock probe failed: {error}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        identity_locked,
        "session replacement never acquired the NodeIdentity coordination lock"
    );

    let create_store = Store::connect(
        &super::product_tests::with_application_name(&url, CREATE_APPLICATION),
        None,
    )
    .unwrap();
    let create_admission = admission.clone();
    let create_digest = active_guest_digest.clone();
    let create_worker = std::thread::spawn(move || {
        create_store.create_cat_covered_with_admission(&create, &create_admission, &create_digest)
    });

    let observer = Store::connect(&url, None).unwrap();
    let mut create_waiting = false;
    for _ in 0..200 {
        create_waiting = observer
            .with(|client| {
                client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1 FROM pg_stat_activity
                             WHERE application_name=$1 AND wait_event_type='Lock'
                        )",
                        &[&CREATE_APPLICATION],
                    )
                    .map(|row| row.get(0))
            })
            .unwrap();
        if create_waiting {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(create_waiting, "Cat create never waited on NodeIdentity");

    blocker.commit().unwrap();
    registered(replacement_worker.join().unwrap().unwrap());
    let error = create_worker.join().unwrap().unwrap_err();
    assert_eq!(
        covered_error_code(error),
        cats_api::error::ErrorCode::Unavailable
    );
    assert_eq!(
        super::product_tests::counts(&observer),
        [0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn full_observation_committing_first_invalidates_an_empty_create_plan() {
    const CREATE_APPLICATION: &str = "cats-f2d-create-after-observation";
    let url = crate::testsupport::isolated_control_store_url();
    let (store, identity, authenticated, policy, session) = fixture_at(&url);
    let admission = accept_empty_admission(&store, &identity, &authenticated, &policy, &session);
    let active_guest_digest = policy.approved_guest_config_digest().clone();
    let next_read = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(2).unwrap(),
    };
    let next_snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &next_read)
            .unwrap(),
    );
    assert!(next_snapshot.desired_specs.is_empty());
    let next_full = observation(
        &store,
        &session,
        2,
        2,
        true,
        Some(next_snapshot.read_position),
        Vec::new(),
    );
    let workspace = super::product_tests::bootstrap_workspace(&store, "observation-first");
    let mut create = super::product_tests::request(&workspace, "free", 1, "create");
    bind_create_to_admission(&mut create, &admission, &active_guest_digest);

    let mut blocker_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut blocker = blocker_client.transaction().unwrap();
    blocker
        .query_one(
            "SELECT node_id FROM current_agent_sessions WHERE node_id=$1 FOR UPDATE",
            &[&identity.node_id.as_str()],
        )
        .unwrap();

    let observation_store = Store::connect(&url, None).unwrap();
    let observation_authenticated = authenticated.clone();
    let observation_worker = std::thread::spawn(move || {
        observation_store.runtime_accept_observation(&observation_authenticated, &next_full)
    });

    let mut probe = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut identity_locked = false;
    for _ in 0..200 {
        let mut transaction = probe.transaction().unwrap();
        match transaction.query_one(
            "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE NOWAIT",
            &[&identity.node_id.as_str()],
        ) {
            Ok(_) => transaction.rollback().unwrap(),
            Err(error) if error.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) => {
                identity_locked = true;
                transaction.rollback().unwrap();
                break;
            }
            Err(error) => panic!("NodeIdentity lock probe failed: {error}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        identity_locked,
        "full observation never locked NodeIdentity"
    );

    let create_store = Store::connect(
        &super::product_tests::with_application_name(&url, CREATE_APPLICATION),
        None,
    )
    .unwrap();
    let create_admission = admission.clone();
    let create_digest = active_guest_digest.clone();
    let create_worker = std::thread::spawn(move || {
        create_store.create_cat_covered_with_admission(&create, &create_admission, &create_digest)
    });
    let observer = Store::connect(&url, None).unwrap();
    let mut create_waiting = false;
    for _ in 0..200 {
        create_waiting = observer
            .with(|client| {
                client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1 FROM pg_stat_activity
                             WHERE application_name=$1 AND wait_event_type='Lock'
                        )",
                        &[&CREATE_APPLICATION],
                    )
                    .map(|row| row.get(0))
            })
            .unwrap();
        if create_waiting {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(create_waiting, "Cat create never waited on NodeIdentity");

    blocker.commit().unwrap();
    accepted(observation_worker.join().unwrap().unwrap());
    let error = create_worker.join().unwrap().unwrap_err();
    assert_eq!(
        covered_error_code(error),
        cats_api::error::ErrorCode::Unavailable
    );
    assert_eq!(
        super::product_tests::counts(&observer),
        [0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn create_committing_first_makes_the_old_empty_cursor_fail_closed() {
    const OBSERVATION_APPLICATION: &str = "cats-f2d-observation-after-create";
    let url = crate::testsupport::isolated_control_store_url();
    let (store, identity, authenticated, policy, session) = fixture_at(&url);
    let admission = accept_empty_admission(&store, &identity, &authenticated, &policy, &session);
    let active_guest_digest = policy.approved_guest_config_digest().clone();
    let next_read = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(2).unwrap(),
    };
    let empty_snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &next_read)
            .unwrap(),
    );
    assert!(empty_snapshot.desired_specs.is_empty());
    let old_empty_full = observation(
        &store,
        &session,
        2,
        2,
        true,
        Some(empty_snapshot.read_position),
        Vec::new(),
    );
    let workspace = super::product_tests::bootstrap_workspace(&store, "create-first");
    let mut create = super::product_tests::request(&workspace, "free", 1, "create");
    bind_create_to_admission(&mut create, &admission, &active_guest_digest);

    let mut blocker_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut blocker = blocker_client.transaction().unwrap();
    blocker
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                current_schema() || ':runtime-authority:' || 'volume' || ':' || $1,
                0::BIGINT
             ))",
            &[&create.candidate.volume.volume_id.as_str()],
        )
        .unwrap();

    let create_store = Store::connect(&url, None).unwrap();
    let create_admission = admission.clone();
    let create_digest = active_guest_digest.clone();
    let create_worker = std::thread::spawn(move || {
        create_store.create_cat_covered_with_admission(&create, &create_admission, &create_digest)
    });

    let mut probe = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut identity_locked = false;
    for _ in 0..200 {
        let mut transaction = probe.transaction().unwrap();
        match transaction.query_one(
            "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE NOWAIT",
            &[&identity.node_id.as_str()],
        ) {
            Ok(_) => transaction.rollback().unwrap(),
            Err(error) if error.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) => {
                identity_locked = true;
                transaction.rollback().unwrap();
                break;
            }
            Err(error) => panic!("NodeIdentity lock probe failed: {error}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(identity_locked, "Cat create never locked NodeIdentity");

    let observation_store = Store::connect(
        &super::product_tests::with_application_name(&url, OBSERVATION_APPLICATION),
        None,
    )
    .unwrap();
    let observation_authenticated = authenticated.clone();
    let observation_worker = std::thread::spawn(move || {
        observation_store.runtime_accept_observation(&observation_authenticated, &old_empty_full)
    });
    let observer = Store::connect(&url, None).unwrap();
    let mut observation_waiting = false;
    for _ in 0..200 {
        observation_waiting = observer
            .with(|client| {
                client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1 FROM pg_stat_activity
                             WHERE application_name=$1 AND wait_event_type='Lock'
                        )",
                        &[&OBSERVATION_APPLICATION],
                    )
                    .map(|row| row.get(0))
            })
            .unwrap();
        if observation_waiting {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        observation_waiting,
        "full observation never waited on NodeIdentity"
    );

    blocker.commit().unwrap();
    assert_eq!(create_worker.join().unwrap().unwrap().http_status, 202);
    let assigned_nodes: Vec<String> = observer
        .with(|client| {
            client
                .query(
                    "SELECT node_id FROM desired_runtime_specs ORDER BY cat_id",
                    &[],
                )
                .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
        })
        .unwrap();
    assert_eq!(assigned_nodes, vec![identity.node_id.to_string()]);
    let observation_outcome = observation_worker.join().unwrap().unwrap();
    assert!(
        matches!(
            &observation_outcome,
            RuntimeSpineOutcome::Rejected(RuntimeSpineRejection::Contract(
                cats_api::runtime_reconciliation::ContractError { error, .. }
            )) if matches!(error.as_ref(), ContractErrorDetail::AssignedSetChanged { .. })
        ),
        "unexpected observation outcome: {observation_outcome:?}"
    );
    assert_eq!(
        super::product_tests::counts(&observer),
        [1, 1, 1, 1, 1, 1, 1, 1]
    );
}

#[test]
fn free_name_rejects_candidate_plan_binding_drift_without_writes() {
    let url = crate::testsupport::isolated_control_store_url();
    let (store, identity, authenticated, policy, session) = fixture_at(&url);
    let admission = accept_empty_admission(&store, &identity, &authenticated, &policy, &session);
    let active_guest_digest = policy.approved_guest_config_digest().clone();
    let workspace = super::product_tests::bootstrap_workspace(&store, "candidate-binding");

    let mut wrong_node = super::product_tests::request(&workspace, "wrong-node", 1, "wrong-node");
    bind_create_to_admission(&mut wrong_node, &admission, &active_guest_digest);
    wrong_node.candidate.desired.placement.node_id = id("different_node");
    super::product_tests::refresh_candidate_contract(&mut wrong_node);
    let error = store
        .create_cat_covered_with_admission(&wrong_node, &admission, &active_guest_digest)
        .unwrap_err();
    assert_eq!(
        covered_error_code(error),
        cats_api::error::ErrorCode::Internal
    );

    let mut wrong_digest =
        super::product_tests::request(&workspace, "wrong-digest", 2, "wrong-digest");
    bind_create_to_admission(&mut wrong_digest, &admission, &active_guest_digest);
    wrong_digest.candidate.desired.runtime.guest_config_digest = digest(77);
    super::product_tests::refresh_candidate_contract(&mut wrong_digest);
    let error = store
        .create_cat_covered_with_admission(&wrong_digest, &admission, &active_guest_digest)
        .unwrap_err();
    assert_eq!(
        covered_error_code(error),
        cats_api::error::ErrorCode::Internal
    );
    assert_eq!(
        super::product_tests::counts(&store),
        [0, 0, 0, 0, 0, 0, 0, 0]
    );
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
    assert_eq!(exact.next_after, Some(existing.node_id.clone()));
    let eof = first_store
        .list_provisioned_node_ids_after(exact.next_after.as_ref())
        .unwrap();
    assert!(eof.node_ids.is_empty());
    assert_eq!(eof.next_after, None);

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
fn signed_liveness_uses_the_renewed_session_and_exact_replay_does_not_renew_again() {
    let (store, identity, authenticated, _policy, session) = fixture();
    let initial = store.list_runtime_node_liveness_after(None).unwrap();
    assert_eq!(initial.nodes.len(), 1);
    assert_eq!(initial.nodes[0].node_id, identity.node_id);
    assert!(initial.nodes[0].live);
    assert_eq!(
        initial.nodes[0].lease_deadline_unix_ms,
        Some(session.lease_deadline_unix_ms)
    );
    assert_eq!(initial.nodes[0].last_accepted_observation_at_unix_ms, None);

    // Ensure the fixed 60-second candidate is observably later than the
    // registration transaction's initial deadline.
    std::thread::sleep(Duration::from_millis(10));
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
    let acceptance = accepted(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap(),
    );
    assert!(acceptance.lease_deadline_unix_ms > session.lease_deadline_unix_ms);

    let renewed = store.list_runtime_node_liveness_after(None).unwrap();
    assert_eq!(renewed.nodes.len(), 1);
    assert!(renewed.nodes[0].live);
    assert_eq!(
        renewed.nodes[0].lease_deadline_unix_ms,
        Some(acceptance.lease_deadline_unix_ms)
    );
    assert_eq!(
        renewed.nodes[0].last_accepted_observation_at_unix_ms,
        Some(acceptance.accepted_at_unix_ms)
    );

    assert_eq!(
        accepted(
            store
                .runtime_accept_observation(&authenticated, &full)
                .unwrap()
        ),
        acceptance
    );
    let after_replay = store.list_runtime_node_liveness_after(None).unwrap();
    assert_eq!(
        after_replay.nodes[0].lease_deadline_unix_ms,
        renewed.nodes[0].lease_deadline_unix_ms
    );
    assert_eq!(
        after_replay.nodes[0].last_accepted_observation_at_unix_ms,
        renewed.nodes[0].last_accepted_observation_at_unix_ms
    );
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
fn admission_overflow_is_fatal_before_missing_session_or_stale_plan_rejection() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let planned = establish_empty_admission(&store, &release);
    let identity = planned.node_identity.clone();
    let active_guest_digest = guest_config_digest(&release).unwrap();
    let workspace = bootstrap_workspace(&store, "admission-overflow");
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            for index in 0..=super::runtime_spine::MAX_ASSIGNED_SPECS {
                let mut desired = current_desired(&workspace, &identity.node_id);
                desired.cat_id = id(format!("cat_overflow_{index:04}"));
                desired.runtime.network_config.network_id = id(format!("net_overflow_{index:04}"));
                desired.spec_digest = spec_digest(&desired).unwrap();
                insert_cat(
                    transaction,
                    &CatRecord {
                        cat_id: desired.cat_id.clone(),
                        workspace_id: workspace.clone(),
                        name: id(format!("overflow-{index:04}")),
                        created_at: now,
                    },
                )?;
                insert_desired(transaction, &desired)?;
            }
            transaction.execute(
                "DELETE FROM current_agent_sessions WHERE node_id=$1",
                &[&identity.node_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();

    let error = store
        .load_placement_admission_snapshot(&identity.node_id, &active_guest_digest)
        .unwrap_err();
    assert_eq!(error.code, cats_api::error::ErrorCode::Internal);

    let error = store
        .authority_transaction(|transaction| {
            lock_placement_admission_for_desired_mutation(
                transaction,
                &planned,
                &active_guest_digest,
            )
        })
        .unwrap_err();
    assert_eq!(error.code, cats_api::error::ErrorCode::Internal);
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

fn route_ready_runtime(desired: &DesiredRuntimeSpec) -> ObservedRuntimeStatus {
    let endpoint = desired.endpoints.first().unwrap();
    let incarnation = random(0x5151);
    let step = ReconcileStep::Stable {
        state: StableState::Running,
    };
    ObservedRuntimeStatus {
        cat_id: desired.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: RuntimeTarget::Running,
        }),
        runtime_incarnation: Some(incarnation.clone()),
        stable_state: Some(StableState::Running),
        step: step.clone(),
        checkpoint: CheckpointEvidence::Valid {
            checkpoint_path: HostPath::new("/var/lib/cats/checkpoints/cat_route.json").unwrap(),
            content_digest: digest(0x51),
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement_epoch: desired.placement.placement_epoch,
            runtime_incarnation: Some(incarnation.clone()),
            stable_state: Some(StableState::Running),
            step: Box::new(step),
            require_idle: Box::new(
                cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
            ),
            updated_at_unix_ms: UnixMillis::new(1).unwrap(),
        },
        processes: vec![ProcessEvidence {
            role: ProcessRole::Vmm {
                runtime_incarnation: incarnation.clone(),
            },
            process_id: 101,
            process_start_time_ticks: WireU64::new(1).unwrap(),
            executable_path: HostPath::new("/usr/bin/cloud-hypervisor").unwrap(),
            scope_id: id("cats-route.service"),
            control_socket_path: HostPath::new("/run/cats/route/vmm.sock").unwrap(),
            state: ProcessState::Running,
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: random(0x5152),
            },
            control_handshake: ControlHandshakeEvidence::Verified,
            observed_vm_shape: Some(ObservedVmShape {
                vcpus: desired.runtime.vcpus,
                memory_bytes: desired.runtime.memory_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                guest_config_digest: desired.runtime.guest_config_digest.clone(),
            }),
        }],
        volumes: Vec::new(),
        mounts: Vec::new(),
        networks: vec![ObservedNetwork {
            kind: desired.runtime.network_config.kind,
            network_id: desired.runtime.network_config.network_id.clone(),
            guest_mac: desired.runtime.network_config.guest_mac.clone(),
            guest_ipv4: desired.runtime.network_config.guest_ipv4.clone(),
            prefix_length: desired.runtime.network_config.prefix_length,
            gateway_ipv4: desired.runtime.network_config.gateway_ipv4.clone(),
            tap_name: id("tap-route"),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: random(0x5153),
            },
        }],
        guest_transport: GuestTransportEvidence::VsockReady {
            runtime_incarnation: incarnation.clone(),
            guest_cid: 3,
            guest_port: 5000,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_boot_id: GuestBootId::new("51515151515151515151515151515151").unwrap(),
        },
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission: LifecycleAdmission::Open,
        routes: vec![ObservedRouteGate {
            binding: RouteGateBinding {
                workspace_id: desired.workspace_id.clone(),
                endpoint_id: endpoint.endpoint_id.clone(),
                hostname: endpoint.hostname.clone(),
                cat_id: desired.cat_id.clone(),
                node_id: desired.placement.node_id.clone(),
                runtime_incarnation: incarnation,
                route_epoch: endpoint.route_epoch,
                protocol: endpoint.protocol,
                target_port: endpoint.target_port,
            },
            gate: RouteGateState::Active,
            active_guards: 0,
            cancellation_pending: false,
            instance_count: 1,
        }],
        platform_guards: 0,
        conditions: vec![Condition::Ready {
            reason: ReadyReason::PostconditionSatisfied {
                target: RuntimeTarget::Running,
            },
        }],
    }
}

async fn gateway_test_tls_stream(
    address: std::net::SocketAddr,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use rustls::pki_types::pem::PemObject as _;

    let ca = include_bytes!("../../../tests/fixtures/gateway_machine_ca_certificate.pem");
    let client_certificate =
        include_bytes!("../../../tests/fixtures/gateway_machine_client_certificate.pem");
    let client_private_key =
        include_bytes!("../../../tests/fixtures/gateway_machine_client_private_key.pem");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from_pem_slice(ca).unwrap())
        .unwrap();
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(client_certificate)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from_pem_slice(client_private_key).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(
        certificates,
        rustls::pki_types::PrivateKeyDer::Pkcs8(private_key),
    )
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap()
}

async fn gateway_test_http_request(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    request: &[u8],
) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    stream.write_all(request).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut response = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(
                count > 0,
                "Gateway machine connection closed before its response"
            );
            response.extend_from_slice(&chunk[..count]);
            let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&response[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                })
                .expect("Gateway response must carry Content-Length");
            if response.len() >= header_end + content_length {
                assert_eq!(response.len(), header_end + content_length);
                break response;
            }
        }
    })
    .await
    .expect("Gateway machine listener did not answer within the request deadline")
}

fn gateway_test_http_status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn route_signer_snapshot_closes_hostname_runtime_and_ring_in_one_authority_read() {
    let (store, identity, authenticated, policy, session) = fixture();
    let store = Arc::new(store);
    insert_policy_on_store_for_test(
        &store,
        &route_placement_policy(&identity.node_id, policy.approved_guest_config_digest()),
    )
    .unwrap();
    let workspace = bootstrap_workspace(&store, "route-v2-snapshot");
    let endpoint_id = id("ep_route");
    let hostname = Hostname::new("route.cats.run").unwrap();
    let mut desired = current_desired(&workspace, &identity.node_id);
    desired.runtime.guest_config_digest = policy.approved_guest_config_digest().clone();
    desired.endpoints = vec![EndpointIntent {
        endpoint_id: endpoint_id.clone(),
        hostname: hostname.clone(),
        route_epoch: Epoch::new(7).unwrap(),
        protocol: HttpProtocol::Http,
        target_port: 8080,
    }];
    desired.spec_digest = spec_digest(&desired).unwrap();
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: desired.cat_id.clone(),
                    workspace_id: workspace.clone(),
                    name: id("route-cat"),
                    created_at: now,
                },
            )?;
            insert_endpoint(
                transaction,
                &EndpointRecord {
                    endpoint_id: endpoint_id.clone(),
                    workspace_id: workspace.clone(),
                    cat_id: desired.cat_id.clone(),
                    name: id("web"),
                    created_at: now,
                },
            )?;
            insert_desired(transaction, &desired)?;
            insert_hostname_lookup(
                transaction,
                &HostnameDesiredLookup {
                    hostname: hostname.clone(),
                    workspace_id: workspace.clone(),
                    cat_id: desired.cat_id.clone(),
                    endpoint_id: endpoint_id.clone(),
                    desired_revision: desired.desired_revision,
                },
            )
        })
        .unwrap();

    let request = cats_api::runtime_reconciliation::DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding(&session),
        request_sequence: Sequence::new(1).unwrap(),
    };
    let desired_snapshot = accepted(
        store
            .runtime_desired_read(&authenticated, &request)
            .unwrap(),
    );
    let route_signer = Arc::new(
        crate::route_grant_v2::RouteGrantV2Signer::from_ed25519_pem(
            include_bytes!("../../../../tests/fixtures/route_grant_v2_private_ed25519.pem"),
            include_bytes!("../../../../tests/fixtures/route_grant_v2_public_ed25519.pem"),
            120,
        )
        .unwrap(),
    );
    let signer_reference_bytes = br#"{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:7c7e324d7be6c6ee71735c900ce1041de63af7cc08fb39b6800853f966e81e34"}"#;
    let signer_ring_bytes = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}"#;
    let signer_reference =
        cats_api::route_grant_v2::decode_route_grant_v2_signer_reference(signer_reference_bytes)
            .unwrap();
    let signer_ring =
        cats_api::route_grant_v2::decode_route_grant_v2_public_key_ring(signer_ring_bytes).unwrap();
    let installed_signing_authority =
        crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority::from_authority_artifacts(
            &signer_reference,
            signer_reference_bytes,
            &signer_ring,
            Some(include_bytes!(
                "../../../../tests/fixtures/route_grant_v2_private_ed25519.pem"
            )),
            120,
        )
        .unwrap();
    assert_eq!(
        installed_signing_authority.signer().unwrap().kid(),
        route_signer.kid()
    );
    store
        .install_route_grant_v2_signer_authority(&installed_signing_authority)
        .unwrap();
    let gateway_spki = cats_api::runtime_reconciliation::Base64UrlNoPad::new(
        "MCowBQYDK2VwAyEAFqokynUVEeIXMF7pBwDCDQn6N97Q4hJUz7DUbPlbJu8",
    )
    .unwrap();
    let initial_gateway_authority =
        cats_api::gateway_workload_identity::GatewayWorkloadIdentityAuthority {
            version: ContractVersion::V1,
            authority_id: id("gateway_authority_route_test"),
            fleet_id: id("fleet_route_test"),
            policy_revision: Epoch::new(1).unwrap(),
            expected_previous: None,
            credentials: vec![
                cats_api::gateway_workload_identity::GatewayWorkloadCredentialPolicy {
                    credential_id: id("gateway_credential_route_test"),
                    public_key_spki: gateway_spki.clone(),
                    scope:
                        cats_api::gateway_workload_identity::GatewayWorkloadCredentialScope::Fleet,
                },
            ],
        };
    store
        .install_gateway_workload_identity_authority(&initial_gateway_authority)
        .unwrap();
    let gateway_peer_digest =
        cats_api::runtime_reconciliation::canonical_ed25519_spki_sha256(&gateway_spki).unwrap();
    let signer_binding = Arc::new(installed_signing_authority.binding().clone());
    let active_kid = route_signer.kid().clone();
    let ring_version = Epoch::new(3).unwrap();
    let mut full = observation(
        &store,
        &session,
        1,
        1,
        true,
        Some(desired_snapshot.read_position),
        vec![route_ready_runtime(&desired)],
    );
    full.key_ring_version = Some(ring_version);
    full.loaded_kids = vec![active_kid.clone()];
    full.key_ring_digest = Some(key_ring_digest(ring_version, &full.loaded_kids).unwrap());
    full.inventory_digest = Some(inventory_digest(&full).unwrap());
    accepted(
        store
            .runtime_accept_observation(&authenticated, &full)
            .unwrap(),
    );

    let snapshot = match store
        .load_route_grant_v2_authority(
            &hostname,
            &active_kid,
            policy.approved_guest_config_digest(),
        )
        .unwrap()
    {
        RouteGrantV2AuthorityLoad::Ready(snapshot) => *snapshot,
        rejection => panic!("route snapshot unexpectedly rejected: {rejection:?}"),
    };
    assert_eq!(snapshot.workspace_id, workspace);
    assert_eq!(snapshot.endpoint_id, endpoint_id);
    assert_eq!(snapshot.cat_id, desired.cat_id);
    assert_eq!(snapshot.node_id, identity.node_id);
    assert_eq!(snapshot.route_epoch.get(), 7);
    assert_eq!(snapshot.target_port, 8080);
    assert_eq!(
        snapshot.node_transport_target.as_str(),
        "https://node-a.internal:7301"
    );
    assert!(snapshot.evaluated_at_unix_ms.get() > 0);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        use axum::routing::post;
        use axum::{Extension, Router};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let service = Arc::new(
            crate::api::route_resolve_v2::RouteResolveV2Service::for_test(
                Arc::clone(&store),
                Arc::clone(&route_signer),
                policy.approved_guest_config_digest().clone(),
            ),
        );
        let unauthenticated = Router::new()
            .route(
                ROUTE_RESOLVE_V2_PATH,
                post(crate::api::route_resolve_v2::resolve)
                    .fallback(crate::api::route_resolve_v2::resolve),
            )
            .layer(Extension(Arc::clone(&service)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, unauthenticated).await });

        // Deliberately omit the declared body and add a forged identity
        // header. A prompt 401 proves production authentication cannot be
        // constructed by HTTP and precedes body read and Store access.
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!(
                    "POST {ROUTE_RESOLVE_V2_PATH} HTTP/1.1\r\nHost: {address}\r\n\
                     X-Cats-Gateway-SPKI: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\n\
                     Content-Length: 100\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut raw))
            .await
            .expect("unauthenticated resolve waited for the body")
            .unwrap();
        let status = std::str::from_utf8(&raw).unwrap().lines().next().unwrap();
        assert!(status.contains(" 401 "), "unexpected response: {status}");
        server.abort();
        let _ = server.await;

        let signerless_service = Arc::new(
            crate::api::route_resolve_v2::RouteResolveV2Service::without_signer_for_test(
                Arc::clone(&store),
                policy.approved_guest_config_digest().clone(),
            ),
        );
        let signerless = Router::new()
            .route(
                ROUTE_RESOLVE_V2_PATH,
                post(crate::api::route_resolve_v2::resolve)
                    .fallback(crate::api::route_resolve_v2::resolve),
            )
            .layer(Extension(
                crate::api::route_resolve_v2::AuthenticatedGatewayPrincipal::for_test(),
            ))
            .layer(Extension(signerless_service));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, signerless).await });

        // Even the explicit authenticated test router must fail before the
        // body and Store when the independent Route v2 signer is absent.
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!(
                    "POST {ROUTE_RESOLVE_V2_PATH} HTTP/1.1\r\nHost: {address}\r\n\
                     Content-Length: 100\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut raw))
            .await
            .expect("signerless resolve waited for the body")
            .unwrap();
        let status = std::str::from_utf8(&raw).unwrap().lines().next().unwrap();
        assert!(status.contains(" 503 "), "unexpected response: {status}");
        server.abort();
        let _ = server.await;

        let authenticated = Router::new()
            .route(
                ROUTE_RESOLVE_V2_PATH,
                post(crate::api::route_resolve_v2::resolve)
                    .fallback(crate::api::route_resolve_v2::resolve),
            )
            .layer(Extension(
                crate::api::route_resolve_v2::AuthenticatedGatewayPrincipal::for_test(),
            ))
            .layer(Extension(Arc::clone(&service)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, authenticated).await });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let request =
            encode_route_resolve_v2_request(&RouteResolveV2Request::new(hostname.clone())).unwrap();
        let response = client
            .post(format!("http://{address}{ROUTE_RESOLVE_V2_PATH}"))
            .header(reqwest::header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, ROUTE_V2_JSON_CONTENT_TYPE)
            .body(request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response.headers()[reqwest::header::CACHE_CONTROL],
            "no-store"
        );
        let success = decode_route_resolve_v2_success(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(success.endpoint_id, endpoint_id);
        assert_eq!(
            success.node_transport_target.as_str(),
            "https://node-a.internal:7301"
        );
        assert!(!success.opaque_grant.is_empty());

        let missing = encode_route_resolve_v2_request(&RouteResolveV2Request::new(
            Hostname::new("missing.cats.run").unwrap(),
        ))
        .unwrap();
        let response = client
            .post(format!("http://{address}{ROUTE_RESOLVE_V2_PATH}"))
            .header(reqwest::header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, ROUTE_V2_JSON_CONTENT_TYPE)
            .body(missing)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            decode_route_resolve_v2_rejection(&response.bytes().await.unwrap())
                .unwrap()
                .code,
            RouteResolveV2RejectionCode::NotFound
        );

        // Every standard conditional request header is rejected before the
        // admission lane and therefore before Store access. Exhausting all
        // permits turns an accidental pass-through into a visible 503.
        let exhausted = service.exhaust_admission_for_test();
        for conditional in [
            "if-match",
            "if-none-match",
            "if-modified-since",
            "if-unmodified-since",
            "if-range",
        ] {
            let body =
                encode_route_resolve_v2_request(&RouteResolveV2Request::new(hostname.clone()))
                    .unwrap();
            let response = client
                .post(format!("http://{address}{ROUTE_RESOLVE_V2_PATH}"))
                .header(reqwest::header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
                .header(reqwest::header::ACCEPT, ROUTE_V2_JSON_CONTENT_TYPE)
                .header(conditional, "test")
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::BAD_REQUEST,
                "conditional header {conditional} reached admission"
            );
        }
        drop(exhausted);

        let authenticated_request = |hostname: Hostname| {
            let body =
                encode_route_resolve_v2_request(&RouteResolveV2Request::new(hostname)).unwrap();
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri(ROUTE_RESOLVE_V2_PATH)
                .header(axum::http::header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
                .header(axum::http::header::ACCEPT, ROUTE_V2_JSON_CONTENT_TYPE)
                .body(axum::body::Body::from(body))
                .unwrap();
            request
                .extensions_mut()
                .insert(crate::api::route_resolve_v2::AuthenticatedGatewayPrincipal::for_test());
            request
        };

        // The handler's two-second deadline may expire while an already
        // started Store closure is still running. The shared lease keeps that
        // request active until the closure itself settles.
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        service.pause_store_after_start_for_test(Arc::clone(&entered), Arc::clone(&release));
        let timed_service = Arc::clone(&service);
        let timed_hostname = hostname.clone();
        let timed = tokio::spawn(async move {
            crate::api::route_resolve_v2::resolve(
                Extension(timed_service),
                authenticated_request(timed_hostname),
            )
            .await
        });
        let entered_wait = tokio::task::spawn_blocking(move || {
            entered.wait();
        });
        tokio::time::timeout(Duration::from_secs(1), entered_wait)
            .await
            .expect("Store closure did not start")
            .unwrap();
        assert_eq!(service.active_requests_for_test(), 1);
        let response = tokio::time::timeout(Duration::from_secs(3), timed)
            .await
            .expect("Route v2 handler did not enforce its deadline")
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(service.active_requests_for_test(), 1);
        tokio::task::spawn_blocking(move || {
            release.wait();
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while service.active_requests_for_test() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed-out Store closure did not settle");

        // Cancellation drops the handler's owner but not the Store owner's
        // lease. Graceful shutdown must wait for that final owner and then
        // observe an exact active count of zero.
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        service.pause_store_after_start_for_test(Arc::clone(&entered), Arc::clone(&release));
        let cancelled_service = Arc::clone(&service);
        let cancelled_hostname = hostname.clone();
        let cancelled = tokio::spawn(async move {
            crate::api::route_resolve_v2::resolve(
                Extension(cancelled_service),
                authenticated_request(cancelled_hostname),
            )
            .await
        });
        let entered_wait = tokio::task::spawn_blocking(move || {
            entered.wait();
        });
        tokio::time::timeout(Duration::from_secs(1), entered_wait)
            .await
            .expect("cancelled Store closure did not start")
            .unwrap();
        assert_eq!(service.active_requests_for_test(), 1);
        let shutdown_service = Arc::clone(&service);
        let shutdown = tokio::spawn(async move { shutdown_service.shutdown_for_test().await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert_eq!(service.active_requests_for_test(), 1);
        tokio::task::spawn_blocking(move || {
            release.wait();
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown did not join the cancelled Store closure")
            .unwrap()
            .unwrap();
        assert_eq!(service.active_requests_for_test(), 0);

        let production_signerless = Arc::new(
            crate::api::route_resolve_v2::RouteResolveV2Service::for_gateway_machine(
                Arc::clone(&store),
                None,
                Arc::clone(&signer_binding),
                policy.approved_guest_config_digest().clone(),
                8,
                8,
            ),
        );
        let mut signerless_request = axum::http::Request::builder()
            .method("POST")
            .uri(ROUTE_RESOLVE_V2_PATH)
            .header(axum::http::header::CONTENT_LENGTH, "100")
            .body(axum::body::Body::empty())
            .unwrap();
        signerless_request.extensions_mut().insert(
            crate::api::route_resolve_v2::VerifiedGatewayTlsPeer::from_verified_spki_sha256(
                gateway_peer_digest.clone(),
            ),
        );
        let signerless_response = tokio::time::timeout(
            Duration::from_secs(1),
            crate::api::route_resolve_v2::resolve(
                Extension(Arc::clone(&production_signerless)),
                signerless_request,
            ),
        )
        .await
        .expect("authenticated signerless request read its declared body");
        assert_eq!(
            signerless_response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        production_signerless.shutdown().await.unwrap();

        // Compose the production machine service and real TLS/h1 listener over
        // the same real-PG authority. This is not the test-principal bypass.
        let machine_service = Arc::new(
            crate::api::route_resolve_v2::RouteResolveV2Service::for_gateway_machine(
                Arc::clone(&store),
                Some(Arc::clone(&route_signer)),
                Arc::clone(&signer_binding),
                policy.approved_guest_config_digest().clone(),
                8,
                8,
            ),
        );
        let machine_tls = crate::gateway_machine::GatewayMachineTlsConfig::from_pem_for_test(
            include_bytes!("../../../tests/fixtures/gateway_machine_ca_certificate.pem"),
            include_bytes!("../../../tests/fixtures/gateway_machine_server_certificate.pem"),
            include_bytes!("../../../tests/fixtures/gateway_machine_server_private_key.pem"),
        )
        .unwrap();
        let readiness = Arc::new(crate::server::ReadinessLatch::new());
        let machine_listener = crate::gateway_machine::GatewayMachineListener::spawn(
            "127.0.0.1:0",
            machine_tls,
            Arc::clone(&machine_service),
            Arc::clone(&readiness),
        )
        .await
        .unwrap();
        let mut machine_stream = gateway_test_tls_stream(machine_listener.addr()).await;
        let machine_body =
            encode_route_resolve_v2_request(&RouteResolveV2Request::new(hostname.clone())).unwrap();
        let machine_request = format!(
            "POST {ROUTE_RESOLVE_V2_PATH} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: {ROUTE_V2_JSON_CONTENT_TYPE}\r\n\
             Accept: {ROUTE_V2_JSON_CONTENT_TYPE}\r\n\
             Content-Length: {}\r\n\r\n{}",
            machine_body.len(),
            std::str::from_utf8(&machine_body).unwrap(),
        );
        let machine_response =
            gateway_test_http_request(&mut machine_stream, machine_request.as_bytes()).await;
        assert_eq!(gateway_test_http_status(&machine_response), 200);
        let machine_body_start = machine_response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let machine_success =
            decode_route_resolve_v2_success(&machine_response[machine_body_start..]).unwrap();
        assert_eq!(machine_success.endpoint_id, endpoint_id);

        // A well-formed but non-current local descriptor cannot sign. The
        // exact binding comparison occurs only in the final shared snapshot.
        let mut stale_reference = signer_reference.clone();
        stale_reference.deployment_id = id("route_deployment_stale");
        let stale_reference_bytes =
            cats_api::route_grant_v2::encode_route_grant_v2_signer_reference(&stale_reference)
                .unwrap();
        let stale_binding = Arc::new(
            super::route_signing_authority::RouteGrantV2SignerBinding::from_authority_artifacts(
                &stale_reference,
                &stale_reference_bytes,
                &signer_ring,
            )
            .unwrap(),
        );
        let stale_service = Arc::new(
            crate::api::route_resolve_v2::RouteResolveV2Service::for_gateway_machine(
                Arc::clone(&store),
                Some(Arc::clone(&route_signer)),
                stale_binding,
                policy.approved_guest_config_digest().clone(),
                8,
                8,
            ),
        );
        let mut stale_request = axum::http::Request::builder()
            .method("POST")
            .uri(ROUTE_RESOLVE_V2_PATH)
            .header(axum::http::header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
            .header(axum::http::header::ACCEPT, ROUTE_V2_JSON_CONTENT_TYPE)
            .body(axum::body::Body::from(machine_body.clone()))
            .unwrap();
        stale_request.extensions_mut().insert(
            crate::api::route_resolve_v2::VerifiedGatewayTlsPeer::from_verified_spki_sha256(
                gateway_peer_digest.clone(),
            ),
        );
        let stale_response = crate::api::route_resolve_v2::resolve(
            Extension(Arc::clone(&stale_service)),
            stale_request,
        )
        .await;
        assert_eq!(
            stale_response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        stale_service.shutdown().await.unwrap();

        // Scope shrink is observed by the next request on the same TLS
        // keepalive connection. Pre-body auth still succeeds, but the
        // hostname-derived Workspace check in the final snapshot returns 401.
        let mut scoped_gateway_authority = initial_gateway_authority.clone();
        scoped_gateway_authority.policy_revision = Epoch::new(2).unwrap();
        scoped_gateway_authority.expected_previous = Some(
            cats_api::gateway_workload_identity::GatewayWorkloadIdentityExpectedPrevious {
                policy_revision: initial_gateway_authority.policy_revision,
                policy_sha256: initial_gateway_authority.digest().unwrap(),
            },
        );
        scoped_gateway_authority.credentials[0].scope =
            cats_api::gateway_workload_identity::GatewayWorkloadCredentialScope::Workspaces {
                workspace_ids: vec![id("workspace_not_route")],
            };
        let scoped_install = scoped_gateway_authority.clone();
        store
            .execute(move |store| {
                store.install_gateway_workload_identity_authority(&scoped_install)
            })
            .await
            .unwrap();
        let scoped_response =
            gateway_test_http_request(&mut machine_stream, machine_request.as_bytes()).await;
        assert_eq!(gateway_test_http_status(&scoped_response), 401);

        // Durable empty-set revocation is checked again before body read on
        // that same TLS connection; declaring but withholding a body must not
        // delay the authentication failure.
        let mut disabled_gateway_authority = scoped_gateway_authority.clone();
        disabled_gateway_authority.policy_revision = Epoch::new(3).unwrap();
        disabled_gateway_authority.expected_previous = Some(
            cats_api::gateway_workload_identity::GatewayWorkloadIdentityExpectedPrevious {
                policy_revision: scoped_gateway_authority.policy_revision,
                policy_sha256: scoped_gateway_authority.digest().unwrap(),
            },
        );
        disabled_gateway_authority.credentials.clear();
        store
            .execute(move |store| {
                store.install_gateway_workload_identity_authority(&disabled_gateway_authority)
            })
            .await
            .unwrap();
        let revoked_request = format!(
            "POST {ROUTE_RESOLVE_V2_PATH} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Length: 100\r\n\r\n"
        );
        let revoked_response =
            gateway_test_http_request(&mut machine_stream, revoked_request.as_bytes()).await;
        assert_eq!(gateway_test_http_status(&revoked_response), 401);
        drop(machine_stream);
        machine_listener.shutdown().await.unwrap();
        assert!(readiness.is_ready());

        server.abort();
        let _ = server.await;
    });

    let unknown = KeyId::new("b".repeat(64)).unwrap();
    assert_eq!(
        store
            .load_route_grant_v2_authority(
                &hostname,
                &unknown,
                policy.approved_guest_config_digest(),
            )
            .unwrap(),
        RouteGrantV2AuthorityLoad::Rejected(RouteGrantV2AuthorityRejection::Unavailable)
    );

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE runtime_node_placement_policies
                        SET record=jsonb_set(record, '{policy_revision}', '2'::jsonb),
                            policy_revision=2,
                            node_transport_target='https://node-b.internal:7301'",
                    &[],
                )
                .map(|_| ())
        })
        .unwrap();
    assert!(store
        .load_route_grant_v2_authority(
            &hostname,
            &active_kid,
            policy.approved_guest_config_digest(),
        )
        .is_err());
}

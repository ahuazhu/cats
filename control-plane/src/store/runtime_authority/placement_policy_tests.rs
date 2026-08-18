//! Real PostgreSQL acceptance tests for the A23 authority core.

use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, guest_config_digest, runtime_provisioner_active_set_digest,
    AllocatableMemoryBytes, AllocatableVcpus, AsciiText, Base64UrlNoPad, ContractVersion,
    CredentialBinding, Epoch, FleetPolicyPrincipal, GuestIpv4Pool, GuestIpv4PoolKind,
    GuestRuntimeProfileReceipt, Id, Ipv4Address, NodeIdentity, NodeIdentityState,
    NodePlacementPolicy, NodeTransportTarget, PublicKeyCredentialBinding, RandomId128,
    RuntimeNodeAuthorityApply, RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome,
    RuntimeNodeAuthorityStoredOutcome, RuntimePlacementBlockFrontend, RuntimePlacementCapabilities,
    RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport, RuntimePlacementVmm,
    RuntimeProvisionerActiveSet, RuntimeProvisionerCredential, RuntimeProvisionerExpectedPrevious,
    RuntimeProvisionerTrustBundle, RuntimeSchedulingState, Sha256Digest,
};

use super::host_fence_recovery_batch_tests::active_host_recovery_fixture;
use super::placement_policy::RuntimeNodeAuthorityApplyStoreOutcome;
use super::route_signing_authority_tests::install_initial_signer_for_test;
use super::runtime_spine_tests::{
    accept_ring_admission_for_test, refresh_assigned_admission_for_test,
};
use crate::store::{AuthorityRequestContext, Store};

const SPKI_A: &str = "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const SPKI_B: &str = "MCowBQYDK2VwAyEAPUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw";

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn guest_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: digest(1),
        initramfs_digest: Some(digest(2)),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn credential(name: &str, spki: &str) -> RuntimeProvisionerCredential {
    RuntimeProvisionerCredential {
        credential_id: id(name),
        public_key_spki: Base64UrlNoPad::new(spki).unwrap(),
    }
}

fn active_set(credentials: Vec<RuntimeProvisionerCredential>) -> RuntimeProvisionerActiveSet {
    RuntimeProvisionerActiveSet {
        version: ContractVersion::V1,
        deployment_id: id("deployment_a"),
        credentials,
    }
}

fn trust(
    revision: u64,
    credentials: Vec<RuntimeProvisionerCredential>,
    previous: Option<&RuntimeProvisionerActiveSet>,
) -> RuntimeProvisionerTrustBundle {
    RuntimeProvisionerTrustBundle {
        version: ContractVersion::V1,
        deployment_id: id("deployment_a"),
        trust_revision: Epoch::new(revision).unwrap(),
        expected_previous: previous.map(|active| RuntimeProvisionerExpectedPrevious {
            trust_revision: Epoch::new(revision - 1).unwrap(),
            active_set_sha256: runtime_provisioner_active_set_digest(active).unwrap(),
        }),
        credentials,
    }
}

fn principal(credential: &RuntimeProvisionerCredential) -> FleetPolicyPrincipal {
    FleetPolicyPrincipal::DeploymentProvisioner {
        deployment_id: id("deployment_a"),
        credential_id: credential.credential_id.clone(),
        public_key_spki: credential.public_key_spki.clone(),
        public_key_spki_sha256: canonical_ed25519_spki_sha256(&credential.public_key_spki).unwrap(),
    }
}

fn identity() -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node_a"),
        provider_scope: cats_api::runtime_reconciliation::ProviderScope {
            provider: id("test_provider"),
            partition: id("test_partition"),
            account_id: id("test_account"),
            region: id("test_region"),
        },
        immutable_host_id: id("host_a"),
        credential_id: id("credential_a"),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(6),
        },
        state_path_id: id("state_path_a"),
        state: NodeIdentityState::Provisioned,
    }
}

fn policy(revision: u64, state: RuntimeSchedulingState, memory: u64) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: id("node_a"),
        policy_revision: Epoch::new(revision).unwrap(),
        scheduling_state: state,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(memory).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: guest_config_digest(&guest_release()).unwrap(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
    }
}

fn provision(apply_id: u128) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(apply_id),
        node_id: id("node_a"),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(identity()),
            placement_policy: Box::new(policy(1, RuntimeSchedulingState::Cordoned, 16 << 30)),
        },
    }
}

fn provision_on_host(
    apply_id: u128,
    node_id: &str,
    immutable_host_id: &str,
    provider_scope: cats_api::runtime_reconciliation::ProviderScope,
) -> RuntimeNodeAuthorityApply {
    let mut apply = provision(apply_id);
    apply.node_id = id(node_id);
    let RuntimeNodeAuthorityMutation::Provision {
        node_identity,
        placement_policy,
    } = &mut apply.mutation
    else {
        unreachable!();
    };
    node_identity.node_id = id(node_id);
    node_identity.provider_scope = provider_scope;
    node_identity.immutable_host_id = id(immutable_host_id);
    node_identity.credential_id = Id::new(format!("credential-{node_id}")).unwrap();
    node_identity.credential_binding = CredentialBinding::PublicKey {
        public_key_spki_sha256: digest(u8::try_from(apply_id).unwrap()),
    };
    node_identity.state_path_id = Id::new(format!("state-path-{node_id}")).unwrap();
    placement_policy.node_id = id(node_id);
    placement_policy.node_transport_target =
        NodeTransportTarget::new(format!("https://{node_id}.internal:7301")).unwrap();
    apply
}

fn update(
    apply_id: u128,
    expected: u64,
    state: RuntimeSchedulingState,
    memory: u64,
) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(apply_id),
        node_id: id("node_a"),
        mutation: RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision: Epoch::new(expected).unwrap(),
            placement_policy: Box::new(policy(expected + 1, state, memory)),
        },
    }
}

fn stored(outcome: RuntimeNodeAuthorityApplyStoreOutcome) -> RuntimeNodeAuthorityStoredOutcome {
    match outcome {
        RuntimeNodeAuthorityApplyStoreOutcome::Stored(outcome) => outcome,
        other => panic!("expected stored outcome, got {other:?}"),
    }
}

fn assert_applied(
    outcome: RuntimeNodeAuthorityApplyStoreOutcome,
    expected: RuntimeNodeAuthorityOutcome,
) {
    match stored(outcome) {
        RuntimeNodeAuthorityStoredOutcome::Applied { response } => {
            assert_eq!(response.outcome, expected);
        }
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed => {
            panic!("expected applied outcome")
        }
    }
}

fn pause_apply_commit(store: &Store, url: &str, barrier_key: i64) -> postgres::Client {
    store
        .with(|client| {
            client.batch_execute(&format!(
                "CREATE FUNCTION runtime_node_authority_pause_commit_for_test()
                   RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN
                     PERFORM pg_advisory_lock({barrier_key});
                     PERFORM pg_advisory_unlock({barrier_key});
                     RETURN NEW;
                   END
                   $$;
                 REVOKE ALL ON FUNCTION runtime_node_authority_pause_commit_for_test()
                   FROM PUBLIC;
                 CREATE CONSTRAINT TRIGGER runtime_node_authority_pause_commit_for_test
                   AFTER INSERT ON runtime_node_authority_apply_records
                   DEFERRABLE INITIALLY DEFERRED
                   FOR EACH ROW EXECUTE FUNCTION runtime_node_authority_pause_commit_for_test()"
            ))
        })
        .unwrap();
    let mut barrier = postgres::Client::connect(url, postgres::NoTls).unwrap();
    barrier
        .query_one("SELECT pg_advisory_lock($1)", &[&barrier_key])
        .unwrap();
    barrier
}

fn release_apply_commit(barrier: &mut postgres::Client, barrier_key: i64) {
    assert!(barrier
        .query_one("SELECT pg_advisory_unlock($1)", &[&barrier_key])
        .unwrap()
        .get::<_, bool>(0));
}

fn wait_for_commit_attempt(request: &AuthorityRequestContext) {
    let started = std::time::Instant::now();
    while !request.commit_was_attempted() {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "writer did not enter PostgreSQL COMMIT"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn backend_pid(store: &Store) -> i32 {
    store
        .with(|client| Ok(client.query_one("SELECT pg_backend_pid()", &[])?.get(0)))
        .unwrap()
}

fn wait_for_advisory_lock_wait(store: &Store, backend_pid: i32) {
    let started = std::time::Instant::now();
    loop {
        let waiting = store
            .with(|client| {
                Ok(client
                    .query_one(
                        "SELECT EXISTS (
                           SELECT 1 FROM pg_locks
                            WHERE pid=$1 AND locktype='advisory' AND NOT granted
                         )",
                        &[&backend_pid],
                    )?
                    .get::<_, bool>(0))
            })
            .unwrap();
        if waiting {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "resolver backend did not wait on the apply-ID advisory lock"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn trust_revisions_are_exact_forward_cas_and_retired_keys_never_return() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    let b = credential("provisioner_b", SPKI_B);
    let active1 = active_set(vec![a.clone()]);
    let revision1 = trust(1, active1.credentials.clone(), None);
    store
        .install_runtime_provisioner_trust_bundle(&revision1)
        .unwrap();
    store
        .install_runtime_provisioner_trust_bundle(&revision1)
        .unwrap();

    let active2 = active_set(vec![a.clone(), b.clone()]);
    let revision2 = trust(2, active2.credentials.clone(), Some(&active1));
    store
        .install_runtime_provisioner_trust_bundle(&revision2)
        .unwrap();
    let active3 = active_set(vec![b.clone()]);
    let revision3 = trust(3, active3.credentials.clone(), Some(&active2));
    store
        .install_runtime_provisioner_trust_bundle(&revision3)
        .unwrap();

    let reintroduce = trust(4, vec![a, b], Some(&active3));
    assert!(store
        .install_runtime_provisioner_trust_bundle(&reintroduce)
        .is_err());
    assert!(store
        .install_runtime_provisioner_trust_bundle(&revision2)
        .is_err());

    store
        .with(|client| {
            let pointer = client.query_one(
                "SELECT current_trust_revision, current_active_set_sha256
                   FROM runtime_provisioner_deployment_identity WHERE singleton",
                &[],
            )?;
            assert_eq!(pointer.get::<_, i64>(0), 3);
            assert_eq!(
                pointer.get::<_, String>(1),
                runtime_provisioner_active_set_digest(&active3)
                    .unwrap()
                    .as_str()
            );
            let rows = client.query(
                "SELECT credential_id, state FROM runtime_provisioner_credential_lineage
                  ORDER BY credential_id",
                &[],
            )?;
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].get::<_, String>(1), "retired");
            assert_eq!(rows[1].get::<_, String>(1), "active");
            Ok(())
        })
        .unwrap();
}

#[test]
fn apply_replay_preconditions_policy_and_credential_lineage_are_atomic() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    let initial_active = active_set(vec![a.clone()]);
    store
        .install_runtime_provisioner_trust_bundle(&trust(
            1,
            initial_active.credentials.clone(),
            None,
        ))
        .unwrap();
    let actor = principal(&a);

    let create = provision(1);
    assert_applied(
        store.apply_runtime_node_authority(&actor, &create).unwrap(),
        RuntimeNodeAuthorityOutcome::Provisioned,
    );
    assert_eq!(
        store
            .load_node_transport_target_for_test(&id("node_a"))
            .unwrap()
            .unwrap()
            .as_str(),
        "https://node-a.internal:7301"
    );
    assert_applied(
        store.apply_runtime_node_authority(&actor, &create).unwrap(),
        RuntimeNodeAuthorityOutcome::Provisioned,
    );
    let mut conflict = create.clone();
    if let RuntimeNodeAuthorityMutation::Provision {
        placement_policy, ..
    } = &mut conflict.mutation
    {
        placement_policy.allocatable_memory_bytes = AllocatableMemoryBytes::new(8 << 30).unwrap();
    }
    assert_eq!(
        store
            .apply_runtime_node_authority(&actor, &conflict)
            .unwrap(),
        RuntimeNodeAuthorityApplyStoreOutcome::ApplyIdConflict
    );

    let current_ring = install_initial_signer_for_test(&store);
    let unacked_enable = update(40, 1, RuntimeSchedulingState::Schedulable, 16 << 30);
    assert_eq!(
        stored(
            store
                .apply_runtime_node_authority(&actor, &unacked_enable)
                .unwrap()
        ),
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
    );
    let admission = refresh_assigned_admission_for_test(&store, &identity(), &guest_release(), 41);
    let admission = accept_ring_admission_for_test(&store, &admission, &current_ring, 2, 2);
    let enable = update(2, 1, RuntimeSchedulingState::Schedulable, 16 << 30);
    assert_applied(
        store.apply_runtime_node_authority(&actor, &enable).unwrap(),
        RuntimeNodeAuthorityOutcome::PolicyUpdated,
    );
    let mut illegal_target_rotation = update(8, 2, RuntimeSchedulingState::Schedulable, 16 << 30);
    let RuntimeNodeAuthorityMutation::UpdatePolicy {
        placement_policy, ..
    } = &mut illegal_target_rotation.mutation
    else {
        panic!("test request is not a policy update");
    };
    placement_policy.node_transport_target =
        NodeTransportTarget::new("https://node-b.internal:7301").unwrap();
    assert_eq!(
        stored(
            store
                .apply_runtime_node_authority(&actor, &illegal_target_rotation)
                .unwrap()
        ),
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
    );
    assert_eq!(
        store
            .load_node_transport_target_for_test(&id("node_a"))
            .unwrap()
            .unwrap()
            .as_str(),
        "https://node-a.internal:7301"
    );
    let illegal_resize = update(3, 2, RuntimeSchedulingState::Schedulable, 32 << 30);
    assert_eq!(
        stored(
            store
                .apply_runtime_node_authority(&actor, &illegal_resize)
                .unwrap()
        ),
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
    );
    let cordon = update(4, 2, RuntimeSchedulingState::Cordoned, 16 << 30);
    assert_applied(
        store.apply_runtime_node_authority(&actor, &cordon).unwrap(),
        RuntimeNodeAuthorityOutcome::PolicyUpdated,
    );
    let resize = update(5, 3, RuntimeSchedulingState::Cordoned, 32 << 30);
    assert_applied(
        store.apply_runtime_node_authority(&actor, &resize).unwrap(),
        RuntimeNodeAuthorityOutcome::PolicyUpdated,
    );
    let mut rotate_target = update(9, 4, RuntimeSchedulingState::Cordoned, 32 << 30);
    let RuntimeNodeAuthorityMutation::UpdatePolicy {
        placement_policy, ..
    } = &mut rotate_target.mutation
    else {
        panic!("test request is not a policy update");
    };
    placement_policy.node_transport_target =
        NodeTransportTarget::new("https://node-b.internal:7301").unwrap();
    assert_applied(
        store
            .apply_runtime_node_authority(&actor, &rotate_target)
            .unwrap(),
        RuntimeNodeAuthorityOutcome::PolicyUpdated,
    );
    assert_eq!(
        store
            .load_node_transport_target_for_test(&id("node_a"))
            .unwrap()
            .unwrap()
            .as_str(),
        "https://node-b.internal:7301"
    );
    assert_eq!(
        stored(
            store
                .apply_runtime_node_authority(&actor, &illegal_resize)
                .unwrap()
        ),
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
    );

    store
        .with(|client| {
            client
                .execute(
                    "DELETE FROM current_agent_sessions
                      WHERE node_id=$1 AND agent_session_epoch=$2",
                    &[
                        &admission.agent_session.node_id.as_str(),
                        &i64::try_from(admission.agent_session.agent_session_epoch.get()).unwrap(),
                    ],
                )
                .map(|changed| assert_eq!(changed, 1))
        })
        .unwrap();

    let rotate = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(6),
        node_id: id("node_a"),
        mutation: RuntimeNodeAuthorityMutation::RotateCredential {
            expected_policy_revision: Epoch::new(5).unwrap(),
            expected_credential_id: id("credential_a"),
            expected_credential_binding: PublicKeyCredentialBinding::PublicKey {
                public_key_spki_sha256: digest(6),
            },
            new_credential_id: id("credential_b"),
            new_credential_binding: PublicKeyCredentialBinding::PublicKey {
                public_key_spki_sha256: digest(8),
            },
        },
    };
    assert_applied(
        store.apply_runtime_node_authority(&actor, &rotate).unwrap(),
        RuntimeNodeAuthorityOutcome::CredentialRotated,
    );
    assert_eq!(
        store
            .load_node_transport_target_for_test(&id("node_a"))
            .unwrap()
            .unwrap()
            .as_str(),
        "https://node-b.internal:7301"
    );
    let retire = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(7),
        node_id: id("node_a"),
        mutation: RuntimeNodeAuthorityMutation::Retire {
            expected_policy_revision: Epoch::new(5).unwrap(),
            expected_credential_id: id("credential_b"),
            expected_credential_binding: PublicKeyCredentialBinding::PublicKey {
                public_key_spki_sha256: digest(8),
            },
        },
    };
    assert_applied(
        store.apply_runtime_node_authority(&actor, &retire).unwrap(),
        RuntimeNodeAuthorityOutcome::Retired,
    );
    assert_eq!(
        store
            .load_node_transport_target_for_test(&id("node_a"))
            .unwrap(),
        None
    );
    assert_applied(
        store.apply_runtime_node_authority(&actor, &create).unwrap(),
        RuntimeNodeAuthorityOutcome::Provisioned,
    );

    store
        .with(|client| {
            let identity = client.query_one(
                "SELECT credential_id, credential_lineage_state, state
                   FROM node_identities WHERE node_id='node_a'",
                &[],
            )?;
            assert_eq!(identity.get::<_, String>(0), "credential_b");
            assert_eq!(identity.get::<_, String>(1), "retired");
            assert_eq!(identity.get::<_, String>(2), "retired");
            let lineage = client.query(
                "SELECT credential_id, state FROM runtime_node_credential_lineage
                  ORDER BY credential_id",
                &[],
            )?;
            assert_eq!(lineage.len(), 2);
            assert_eq!(lineage[0].get::<_, String>(1), "retired");
            assert_eq!(lineage[1].get::<_, String>(1), "retired");
            let target = client.query_one(
                "SELECT record->>'node_transport_target', node_transport_target
                   FROM runtime_node_placement_policies WHERE node_id='node_a'",
                &[],
            )?;
            assert_eq!(target.get::<_, String>(0), "https://node-b.internal:7301");
            assert_eq!(target.get::<_, String>(1), "https://node-b.internal:7301");
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records",
                        &[],
                    )?
                    .get::<_, i64>(0),
                10
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn retired_provisioner_is_rejected_before_replay_or_new_apply() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    let b = credential("provisioner_b", SPKI_B);
    let active1 = active_set(vec![a.clone()]);
    store
        .install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
        .unwrap();
    let create = provision(11);
    assert_applied(
        store
            .apply_runtime_node_authority(&principal(&a), &create)
            .unwrap(),
        RuntimeNodeAuthorityOutcome::Provisioned,
    );
    store
        .install_runtime_provisioner_trust_bundle(&trust(2, vec![b.clone()], Some(&active1)))
        .unwrap();

    assert_eq!(
        store
            .apply_runtime_node_authority(&principal(&a), &create)
            .unwrap(),
        RuntimeNodeAuthorityApplyStoreOutcome::AuthenticationFailed
    );
    assert_applied(
        store
            .apply_runtime_node_authority(&principal(&b), &create)
            .unwrap(),
        RuntimeNodeAuthorityOutcome::Provisioned,
    );
    let stale = update(12, 1, RuntimeSchedulingState::Schedulable, 16 << 30);
    assert_eq!(
        store
            .apply_runtime_node_authority(&principal(&a), &stale)
            .unwrap(),
        RuntimeNodeAuthorityApplyStoreOutcome::AuthenticationFailed
    );
    store
        .with(|client| {
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records",
                        &[],
                    )?
                    .get::<_, i64>(0),
                1
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn provisioner_retirement_and_apply_share_locks_define_both_race_orders() {
    let url = crate::testsupport::isolated_control_store_url();
    let seed = Store::connect(&url, None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    let b = credential("provisioner_b", SPKI_B);
    let active_one = active_set(vec![a.clone()]);
    seed.install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
        .unwrap();
    const COMMIT_BARRIER: i64 = 8_023_004_023_772;
    let mut commit_barrier = pause_apply_commit(&seed, &url, COMMIT_BARRIER);
    let request = provision(19);
    let writer_request = request.clone();
    let actor = principal(&a);
    let writer = Store::connect(&url, None).unwrap();
    let request_context = AuthorityRequestContext::new(
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    );
    let writer_observer = request_context.clone();
    let writer = std::thread::spawn(move || {
        writer
            .apply_runtime_node_authority_request(&actor, &writer_request, &request_context)
            .unwrap()
    });
    wait_for_commit_attempt(&writer_observer);

    let retirement = Store::connect(&url, None).unwrap();
    let next = trust(2, vec![b.clone()], Some(&active_one));
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let retirement = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx
            .send(retirement.install_runtime_provisioner_trust_bundle(&next))
            .unwrap();
    });
    started_rx.recv().unwrap();
    assert!(
        matches!(
            result_rx.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "retirement passed the apply's trust share locks before its result commit"
    );
    release_apply_commit(&mut commit_barrier, COMMIT_BARRIER);
    let committed = writer.join().unwrap();
    assert_applied(committed.clone(), RuntimeNodeAuthorityOutcome::Provisioned);
    result_rx
        .recv_timeout(cats_test_support::poll_bound())
        .unwrap()
        .unwrap();
    retirement.join().unwrap();
    let verifier = Store::connect(&url, None).unwrap();
    assert_eq!(
        verifier
            .apply_runtime_node_authority(&principal(&a), &request)
            .unwrap(),
        RuntimeNodeAuthorityApplyStoreOutcome::AuthenticationFailed
    );
    assert_eq!(
        verifier
            .apply_runtime_node_authority(&principal(&b), &request)
            .unwrap(),
        committed
    );

    let retire_first_url = crate::testsupport::isolated_control_store_url();
    let retire_first = Store::connect(&retire_first_url, None).unwrap();
    retire_first
        .install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
        .unwrap();
    retire_first
        .install_runtime_provisioner_trust_bundle(&trust(2, vec![b], Some(&active_one)))
        .unwrap();
    assert_eq!(
        retire_first
            .apply_runtime_node_authority(&principal(&a), &provision(18))
            .unwrap(),
        RuntimeNodeAuthorityApplyStoreOutcome::AuthenticationFailed
    );
    retire_first
        .with(|client| {
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records",
                        &[],
                    )?
                    .get::<_, i64>(0),
                0
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn ambiguous_resolver_waits_for_apply_reservation_then_distinguishes_commit_and_rollback() {
    let url = crate::testsupport::isolated_control_store_url();
    let seed = Store::connect(&url, None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    seed.install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
        .unwrap();
    // Hold a database-wide test lock that an INITIALLY DEFERRED trigger takes
    // only while PostgreSQL is executing COMMIT. This puts the writer beyond
    // AuthorityRequestContext::begin_commit while its transaction (and A23
    // apply-ID reservation) is deliberately still unsettled.
    const COMMIT_BARRIER: i64 = 8_023_004_023_771;
    let mut commit_barrier = pause_apply_commit(&seed, &url, COMMIT_BARRIER);
    let request = provision(20);
    let actor = principal(&a);
    let writer = Store::connect(&url, None).unwrap();
    let resolver = Store::connect(&url, None).unwrap();
    let resolver_pid = backend_pid(&resolver);
    let resolver_monitor = Store::connect(&url, None).unwrap();
    let request_context = AuthorityRequestContext::new(
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    );
    let writer_observer = request_context.clone();
    let writer_request = request.clone();
    let writer = std::thread::spawn(move || {
        writer
            .apply_runtime_node_authority_request(&actor, &writer_request, &request_context)
            .unwrap()
    });
    wait_for_commit_attempt(&writer_observer);

    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let resolver_request = request.clone();
    let resolver_thread = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx
            .send(
                resolver
                    .resolve_runtime_node_authority_apply(&resolver_request)
                    .unwrap(),
            )
            .unwrap();
    });
    started_rx.recv().unwrap();
    wait_for_advisory_lock_wait(&resolver_monitor, resolver_pid);
    assert_eq!(
        result_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "resolver returned before the original apply reservation settled"
    );
    release_apply_commit(&mut commit_barrier, COMMIT_BARRIER);
    let committed = writer.join().unwrap();
    assert_eq!(
        result_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap(),
        Some(committed)
    );
    resolver_thread.join().unwrap();

    let rollback_url = crate::testsupport::isolated_control_store_url();
    let rollback_writer = Store::connect(&rollback_url, None).unwrap();
    let rollback_resolver = Store::connect(&rollback_url, None).unwrap();
    let rollback_resolver_pid = backend_pid(&rollback_resolver);
    let rollback_monitor = Store::connect(&rollback_url, None).unwrap();
    let rollback_request = provision(21);
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let writer_entered = Arc::clone(&entered);
    let writer_release = Arc::clone(&release);
    let apply_id = rollback_request.apply_id.to_string();
    let writer = std::thread::spawn(move || {
        rollback_writer
            .rollback_runtime_node_authority_reservation_for_test(
                &apply_id,
                &writer_entered,
                &writer_release,
            )
            .unwrap();
    });
    entered.wait();
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let resolver_thread = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx
            .send(
                rollback_resolver
                    .resolve_runtime_node_authority_apply(&rollback_request)
                    .unwrap(),
            )
            .unwrap();
    });
    started_rx.recv().unwrap();
    wait_for_advisory_lock_wait(&rollback_monitor, rollback_resolver_pid);
    assert_eq!(
        result_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "resolver returned None before the original reservation rolled back"
    );
    release.wait();
    writer.join().unwrap();
    assert_eq!(
        result_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap(),
        None
    );
    resolver_thread.join().unwrap();
}

#[test]
fn deferred_lineage_fk_rejects_a_partial_retirement_at_commit() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    store
        .install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
        .unwrap();
    store
        .apply_runtime_node_authority(&principal(&a), &provision(21))
        .unwrap();

    store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "UPDATE runtime_node_credential_lineage
                    SET state='retired', retired_at_unix_ms=first_committed_at_unix_ms
                  WHERE credential_id='credential_a'",
                &[],
            )?;
            assert!(transaction.commit().is_err());
            let state = client
                .query_one(
                    "SELECT state FROM runtime_node_credential_lineage
                      WHERE credential_id='credential_a'",
                    &[],
                )?
                .get::<_, String>(0);
            assert_eq!(state, "active");
            Ok(())
        })
        .unwrap();
}

#[test]
fn policy_projection_and_trust_active_set_corruption_fail_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    let initial = trust(1, vec![a.clone()], None);
    store
        .install_runtime_provisioner_trust_bundle(&initial)
        .unwrap();
    store
        .apply_runtime_node_authority(&principal(&a), &provision(31))
        .unwrap();

    store
        .with(|client| {
            client.execute(
                "UPDATE runtime_node_placement_policies
                    SET policy_revision=2, guest_config_digest=$1
                  WHERE node_id='node_a'",
                &[&digest(9).as_str()],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(store
        .apply_runtime_node_authority(
            &principal(&a),
            &update(32, 1, RuntimeSchedulingState::Schedulable, 16 << 30),
        )
        .is_err());
    store
        .with(|client| {
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records",
                        &[],
                    )?
                    .get::<_, i64>(0),
                1
            );
            client.batch_execute(
                "ALTER TABLE runtime_provisioner_credential_lineage DISABLE TRIGGER USER",
            )?;
            client.execute(
                "UPDATE runtime_provisioner_credential_lineage
                    SET public_key_spki=$2, public_key_spki_sha256=$3
                  WHERE credential_id=$1",
                &[
                    &a.credential_id.as_str(),
                    &SPKI_B,
                    &canonical_ed25519_spki_sha256(&Base64UrlNoPad::new(SPKI_B).unwrap())
                        .unwrap()
                        .as_str(),
                ],
            )?;
            client.batch_execute(
                "ALTER TABLE runtime_provisioner_credential_lineage ENABLE TRIGGER USER",
            )?;
            Ok(())
        })
        .unwrap();
    assert!(store
        .install_runtime_provisioner_trust_bundle(&initial)
        .is_err());
}

#[test]
fn provision_rejects_dot_state_path_components_and_exactly_replays_rejection() {
    for (index, component) in [".", ".."].into_iter().enumerate() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let a = credential("provisioner_a", SPKI_A);
        store
            .install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
            .unwrap();
        let mut request = provision(40 + u128::try_from(index).unwrap());
        let RuntimeNodeAuthorityMutation::Provision { node_identity, .. } = &mut request.mutation
        else {
            unreachable!();
        };
        node_identity.state_path_id = id(component);

        let first = store
            .apply_runtime_node_authority(&principal(&a), &request)
            .unwrap();
        assert_eq!(
            stored(first.clone()),
            RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
        );
        assert_eq!(
            store
                .apply_runtime_node_authority(&principal(&a), &request)
                .unwrap(),
            first
        );
        store
            .with(|client| {
                for table in [
                    "node_identities",
                    "runtime_node_placement_policies",
                    "runtime_node_credential_lineage",
                ] {
                    let count = client
                        .query_one(&format!("SELECT count(*) FROM {table}"), &[])?
                        .get::<_, i64>(0);
                    assert_eq!(count, 0, "{table} was written for {component:?}");
                }
                assert_eq!(
                    client
                        .query_one(
                            "SELECT count(*) FROM runtime_node_authority_apply_records",
                            &[],
                        )?
                        .get::<_, i64>(0),
                    1
                );
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn provider_principal_provision_is_a_persisted_precondition_not_malformed_or_applied() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    store
        .install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
        .unwrap();
    let mut request = provision(50);
    let RuntimeNodeAuthorityMutation::Provision { node_identity, .. } = &mut request.mutation
    else {
        unreachable!();
    };
    node_identity.credential_binding = CredentialBinding::ProviderPrincipal {
        provider: id("provider_a"),
        principal: cats_api::runtime_reconciliation::AsciiText::new("principal-a").unwrap(),
    };
    cats_api::runtime_reconciliation::encode_runtime_node_authority_apply(&request).unwrap();

    let first = store
        .apply_runtime_node_authority(&principal(&a), &request)
        .unwrap();
    assert_eq!(
        stored(first.clone()),
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
    );
    assert_eq!(
        store
            .apply_runtime_node_authority(&principal(&a), &request)
            .unwrap(),
        first
    );
    store
        .with(|client| {
            assert_eq!(
                client
                    .query_one("SELECT count(*) FROM node_identities", &[])?
                    .get::<_, i64>(0),
                0
            );
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records",
                        &[],
                    )?
                    .get::<_, i64>(0),
                1
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn concurrent_host_state_reuse_has_one_applied_winner_and_one_durable_rejection() {
    let url = crate::testsupport::isolated_control_store_url();
    let seed = Store::connect(&url, None).unwrap();
    let a = credential("provisioner_a", SPKI_A);
    seed.install_runtime_provisioner_trust_bundle(&trust(1, vec![a.clone()], None))
        .unwrap();
    let actor = principal(&a);
    let mut first = provision(60);
    let mut second = provision(61);
    second.node_id = id("node_b");
    let RuntimeNodeAuthorityMutation::Provision {
        node_identity,
        placement_policy,
    } = &mut second.mutation
    else {
        unreachable!();
    };
    node_identity.node_id = id("node_b");
    node_identity.credential_id = id("credential_b");
    node_identity.credential_binding = CredentialBinding::PublicKey {
        public_key_spki_sha256: digest(8),
    };
    // The exact Host/state-path pair deliberately remains node_a's pair.
    placement_policy.node_id = id("node_b");
    // Keep both requests otherwise independent so the Host/state-path
    // uniqueness barrier is the only deciding fact.
    if let RuntimeNodeAuthorityMutation::Provision { node_identity, .. } = &mut first.mutation {
        node_identity.credential_binding = CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(6),
        };
    }

    let barrier = Arc::new(Barrier::new(2));
    let handles = [first, second].map(|request| {
        let url = url.clone();
        let actor = actor.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let store = Store::connect(&url, None).unwrap();
            barrier.wait();
            store
                .apply_runtime_node_authority(&actor, &request)
                .unwrap()
        })
    });
    let outcomes = handles.map(|handle| stored(handle.join().unwrap()));
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RuntimeNodeAuthorityStoredOutcome::Applied { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                **outcome == RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
            })
            .count(),
        1
    );
    seed.with(|client| {
        assert_eq!(
            client
                .query_one("SELECT count(*) FROM node_identities", &[])?
                .get::<_, i64>(0),
            1
        );
        assert_eq!(
            client
                .query_one(
                    "SELECT count(*) FROM runtime_node_authority_apply_records",
                    &[],
                )?
                .get::<_, i64>(0),
            2
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn active_recovery_seals_fresh_provision_on_the_same_physical_host_only() {
    let fixture = active_host_recovery_fixture("host-recovery-provision-barrier");
    let store = &fixture.fixture.store;
    let provisioner = credential("host_recovery_provisioner", SPKI_A);
    store
        .install_runtime_provisioner_trust_bundle(&trust(1, vec![provisioner.clone()], None))
        .unwrap();
    let actor = principal(&provisioner);
    let source_scope = fixture.fixture.old_identity.provider_scope.clone();
    let source_host = fixture
        .fixture
        .old_identity
        .immutable_host_id
        .as_str()
        .to_owned();

    // This is a fresh Node ID and a fresh state path, so a Node-scoped or
    // Host/state-path-scoped barrier cannot catch it.  The physical Host
    // recovery barrier must reject it before any apply or authority row is
    // written.
    let same_host = provision_on_host(
        80,
        "node-recovery-bypass",
        &source_host,
        source_scope.clone(),
    );
    let error = store
        .apply_runtime_node_authority(&actor, &same_host)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    store
        .with(|client| {
            for (table, column) in [
                ("node_identities", "node_id"),
                ("runtime_node_placement_policies", "node_id"),
                ("runtime_node_credential_lineage", "node_id"),
            ] {
                let count = client
                    .query_one(
                        &format!("SELECT count(*) FROM {table} WHERE {column}=$1"),
                        &[&same_host.node_id.as_str()],
                    )?
                    .get::<_, i64>(0);
                assert_eq!(count, 0, "{table} changed for rejected same-Host provision");
            }
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records
                          WHERE apply_id=$1",
                        &[&same_host.apply_id.as_str()],
                    )?
                    .get::<_, i64>(0),
                0
            );
            Ok(())
        })
        .unwrap();

    // The scope key is exact: recovery of one immutable Host must not stop
    // normal provisioning on another Host in the same provider scope.
    let other_host = provision_on_host(
        81,
        "node-other-physical-host",
        "host-other-physical-host",
        source_scope,
    );
    assert_applied(
        store
            .apply_runtime_node_authority(&actor, &other_host)
            .unwrap(),
        RuntimeNodeAuthorityOutcome::Provisioned,
    );
}

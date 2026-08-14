use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    guest_config_digest, spec_digest, AgentRegistrationAttempt, AgentSession, AsciiText,
    AssignedKind, AssignedPlacement, AuthorizationRecord, AuthorizationState, ContractVersion,
    CredentialBinding, DesiredRuntimeSpec, DiskKind, Epoch, FenceEpoch, Generation,
    GuestDeviceIdentity, GuestRuntimeProfileReceipt, Id, Ipv4Address, IsolatedIpv4Kind, MacAddress,
    NetworkConfig, NodeBootId, NodeIdentity, NodeIdentityState, NormalAcquireRequest, Operation,
    OperationFailure, OperationPhase, OperationTerminal, ProviderScope, RandomId128, RemoteHead,
    Revision, RuntimeConfig, RuntimeTarget, RuntimeTransition, Sha256Digest, UnixMillis,
    VolumeAccess, VolumeAcquire, VolumeAdminState, VolumeAuthorization, VolumeDisposition,
    VolumeDurability, VolumeIntent, VolumeRecord, VolumeTakeoverAuthorization, WireU64,
};
use cats_storage::authority::{normal_acquire, VolumeOwnerBinding};
use cats_storage::host_fence::{
    host_fence_effect_token, host_fence_provider_attempt_id, HostExecutionCutoffEvidence,
    HostFenceBinding, HostFenceProviderEvidence, ObjectWriteCutoffEvidence,
    ObjectWriterFenceTarget, QuarantinedNetworkInterfaceEvidence, WorkloadNetworkCutoffEvidence,
    HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
};
use cats_storage::trusted_host_fence::{trusted_host_fence_event_v1, TrustedHostFenceEventV1};

use super::host_fence_commit::{TrustedHostFenceRecoveryCommitV1, TrustedTakeoverAuthorizationV1};
use super::product::CatRecord;
use super::product_rows::{
    insert_cat, insert_desired, insert_operation, load_desired_for_update,
    load_operation_for_update,
};
use super::rows::{
    database_now, insert_volume, load_authorization_for_update, load_stored_volume_for_update,
    update_volume_owner,
};
use crate::store::agent_sessions::{
    load_current_session_for_update, load_identity_by_node_for_update,
    lock_exact_credential_lineage, AgentRegistrationOutcome, AgentSessionRegistrationPolicy,
    CredentialLineageState,
};
use crate::store::Store;

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn text(value: &str) -> AsciiText {
    AsciiText::new(value).unwrap()
}

fn random_id(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn boot_id(value: u128) -> NodeBootId {
    NodeBootId::new(format!("{value:032x}")).unwrap()
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

fn time(value: u64) -> UnixMillis {
    UnixMillis::new(value).unwrap()
}

fn before(now: UnixMillis, delta: u64) -> UnixMillis {
    time(now.get().checked_sub(delta).unwrap())
}

fn provider_scope() -> ProviderScope {
    ProviderScope {
        provider: id("test-provider"),
        partition: id("test-partition"),
        account_id: id("test-account"),
        region: id("test-region"),
    }
}

fn runtime_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::from_bytes([1; 32]),
        initramfs_digest: Some(Sha256Digest::from_bytes([2; 32])),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn node_identity(node: &str, host: &str, discriminator: u8) -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(node),
        provider_scope: provider_scope(),
        immutable_host_id: id(host),
        credential_id: id(format!("credential-{discriminator}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([discriminator; 32]),
        },
        state_path_id: id(format!("state-path-{discriminator}")),
        state: NodeIdentityState::Provisioned,
    }
}

fn register_old_session(store: &Store, identity: &NodeIdentity) -> AgentSession {
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&runtime_release()).unwrap();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: boot_id(1),
        agent_instance_id: random_id(2),
        registration_attempt_id: random_id(3),
        guest_config_digest: policy.approved_guest_config_digest().clone(),
        expected_agent_session_epoch: None,
    };
    match store
        .register_agent_session(&authenticated, &attempt, &policy)
        .unwrap()
    {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("old AgentSession was rejected: {rejection:?}")
        }
    }
}

fn framed(values: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(&u64::try_from(value.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}

fn terminal_event(
    old_identity: &NodeIdentity,
    session: &AgentSession,
    committed_at: UnixMillis,
) -> TrustedHostFenceEventV1 {
    let binding = HostFenceBinding {
        provider_scope: old_identity.provider_scope.clone(),
        immutable_host_id: old_identity.immutable_host_id.clone(),
        node_id: old_identity.node_id.clone(),
        expected_node_boot_id: session.node_boot_id.clone(),
        expected_agent_session_epoch: session.agent_session_epoch,
        fence_attempt_id: id("fence-attempt-1"),
    };
    let writer = ObjectWriterFenceTarget {
        writer_authority_id: id("writer-authority-1"),
        provider_scope: old_identity.provider_scope.clone(),
        workload_principal_id: text("workload-principal-1"),
        object_store_scope_id: text("object-store-scope-1"),
    };
    let object_target = framed(&[
        writer.writer_authority_id.as_str().as_bytes(),
        writer.provider_scope.provider.as_str().as_bytes(),
        writer.provider_scope.partition.as_str().as_bytes(),
        writer.provider_scope.account_id.as_str().as_bytes(),
        writer.provider_scope.region.as_str().as_bytes(),
        writer.workload_principal_id.as_str().as_bytes(),
        writer.object_store_scope_id.as_str().as_bytes(),
    ]);
    let boundary = text("quarantine-boundary-1");
    let interface_id = id("interface-1");
    let evidence = HostFenceProviderEvidence {
        version: HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
        binding: binding.clone(),
        object_write_cutoff:
            ObjectWriteCutoffEvidence::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                binding: binding.clone(),
                object_writer: writer,
                effect_token: host_fence_effect_token(
                    &binding,
                    b"object-write-cutoff",
                    &object_target,
                )
                .unwrap(),
                provider_attempt_id: host_fence_provider_attempt_id(
                    &binding,
                    b"object-write-cutoff",
                    &object_target,
                )
                .unwrap(),
                cutoff_receipt_id: text("cutoff-receipt-1"),
                cutoff_effective_at_unix_ms: before(committed_at, 40),
                cutoff_sequence: WireU64::new(4).unwrap(),
                accepted_put_terminal_receipt_id: text("terminal-receipt-1"),
                accepted_puts_terminal_at_unix_ms: before(committed_at, 30),
                terminal_sequence: WireU64::new(4).unwrap(),
                terminal_prefix_sha256: Sha256Digest::from_bytes([4; 32]),
                successful_put_visibility_receipt_id: text("visibility-receipt-1"),
                successful_puts_visible_at_unix_ms: before(committed_at, 20),
            },
        execution_cutoff: HostExecutionCutoffEvidence::HostDestroyed {
            immutable_host_id: binding.immutable_host_id.clone(),
            effect_token: host_fence_effect_token(
                &binding,
                b"host-execution-cutoff",
                binding.immutable_host_id.as_str().as_bytes(),
            )
            .unwrap(),
            provider_attempt_id: host_fence_provider_attempt_id(
                &binding,
                b"host-execution-cutoff",
                binding.immutable_host_id.as_str().as_bytes(),
            )
            .unwrap(),
            authoritative_observation_id: text("execution-observation-1"),
            observed_at_unix_ms: before(committed_at, 10),
        },
        network_cutoff: WorkloadNetworkCutoffEvidence::WorkloadInterfacesQuarantined {
            immutable_host_id: binding.immutable_host_id.clone(),
            quarantine_policy_id: id(boundary.as_str()),
            boundary_effect_token: host_fence_effect_token(
                &binding,
                b"network-boundary-cutoff",
                boundary.as_str().as_bytes(),
            )
            .unwrap(),
            boundary_provider_attempt_id: host_fence_provider_attempt_id(
                &binding,
                b"network-boundary-cutoff",
                boundary.as_str().as_bytes(),
            )
            .unwrap(),
            policy_observation_id: text("policy-observation-1"),
            policy_observed_at_unix_ms: before(committed_at, 10),
            interfaces: vec![QuarantinedNetworkInterfaceEvidence {
                interface_id: interface_id.clone(),
                effect_token: host_fence_effect_token(
                    &binding,
                    b"network-interface-cutoff",
                    interface_id.as_str().as_bytes(),
                )
                .unwrap(),
                provider_attempt_id: host_fence_provider_attempt_id(
                    &binding,
                    b"network-interface-cutoff",
                    interface_id.as_str().as_bytes(),
                )
                .unwrap(),
            }],
            authoritative_observation_id: text("network-observation-1"),
            observed_at_unix_ms: before(committed_at, 10),
        },
        completed_at_unix_ms: before(committed_at, 10),
    };
    trusted_host_fence_event_v1(evidence, committed_at).unwrap()
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: generation(0),
        root_hash: None,
        root_object_id: None,
    }
}

fn desired(
    workspace_id: &Id,
    node_id: &Id,
    volume: &VolumeRecord,
    normal_transition_id: &RandomId128,
) -> DesiredRuntimeSpec {
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: workspace_id.clone(),
        cat_id: id("cat-host-recovery"),
        desired_revision: revision(1),
        target: RuntimeTarget::Running,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: node_id.clone(),
            placement_epoch: epoch(1),
        },
        runtime: RuntimeConfig {
            vcpus: 1,
            memory_bytes: 512 * 1024 * 1024,
            boot_image_digest: Sha256Digest::from_bytes([31; 32]),
            guest_config_digest: guest_config_digest(&runtime_release()).unwrap(),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id("network-host-recovery"),
                guest_mac: MacAddress::new("02:ca:0a:00:00:02").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
            },
        },
        volumes: vec![VolumeIntent {
            volume_intent_id: id("intent-root"),
            disk_id: id("disk-root"),
            volume_id: volume.volume_id.clone(),
            attachment_id: volume.lease_owner.clone().unwrap(),
            size_bytes: volume.size_bytes,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: volume.durability,
            guest_device: GuestDeviceIdentity {
                serial: id("root-device"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: normal_transition_id.clone(),
                expected_unowned_epoch: fence_epoch(0),
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

struct RecoveryFixture {
    store: Store,
    request: TrustedHostFenceRecoveryCommitV1,
    current_volume: VolumeRecord,
}

fn recovery_fixture(slug: &str) -> RecoveryFixture {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let workspace_id = super::product_tests::bootstrap_workspace(&store, slug);
    let old_identity = node_identity("node-old", "host-old", 7);
    let new_identity = node_identity("node-new", "host-new", 8);
    store.provision_node_identity(&old_identity).unwrap();
    store.provision_node_identity(&new_identity).unwrap();
    let session = register_old_session(&store, &old_identity);
    let now = store.authority_transaction(database_now).unwrap();

    let blank = VolumeRecord {
        volume_id: id("volume-root"),
        size_bytes: 4 * 1024 * 1024,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: blank_head(),
        lease_owner: None,
        lease_epoch: fence_epoch(0),
        lease_expires_at: None,
        last_transition: None,
    };
    let transition_id = random_id(10);
    let normal_request = NormalAcquireRequest {
        volume_id: blank.volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: id("attachment-old"),
        expected_unowned_epoch: blank.lease_epoch,
        desired_revision: revision(1),
        placement_epoch: epoch(1),
        lease_duration_ms: 60_000,
    };
    let (current_volume, _) = normal_acquire(&blank, &normal_request, before(now, 1)).unwrap();
    let current_desired = desired(
        &workspace_id,
        &old_identity.node_id,
        &current_volume,
        &transition_id,
    );
    let event = terminal_event(&old_identity, &session, now);
    let authorization_id = id("takeover-authorization-1");
    let new_attachment_id = id("attachment-new");
    let mut replacement_desired = current_desired.clone();
    replacement_desired.desired_revision = revision(2);
    replacement_desired.placement.node_id = new_identity.node_id.clone();
    replacement_desired.placement.placement_epoch = epoch(2);
    replacement_desired.volumes[0].attachment_id = new_attachment_id.clone();
    replacement_desired.volumes[0].acquire = VolumeAcquire::Takeover {
        authorization_id: authorization_id.clone(),
    };
    replacement_desired.spec_digest = spec_digest(&replacement_desired).unwrap();

    let authorization = AuthorizationRecord {
        authorization: VolumeAuthorization::Takeover(VolumeTakeoverAuthorization {
            authorization_id,
            authorized_node_id: new_identity.node_id.clone(),
            host_fence_event_id: event.event_id.clone(),
            volume_id: current_volume.volume_id.clone(),
            expected_attachment_id: current_volume.lease_owner.clone().unwrap(),
            expected_epoch: current_volume.lease_epoch,
            expected_head: current_volume.head.clone(),
            new_attachment_id,
            desired_revision: replacement_desired.desired_revision,
            new_placement_epoch: replacement_desired.placement.placement_epoch,
            lease_duration_ms: 60_000,
            not_after: time(now.get().checked_add(60_000).unwrap()),
        }),
        state: AuthorizationState::Unconsumed,
    };
    let operation_created = before(now, 1);
    let expected_old_operation = Operation {
        version: ContractVersion::V1,
        operation_id: id("operation-old"),
        workspace_id: workspace_id.clone(),
        cat_id: current_desired.cat_id.clone(),
        desired_revision: current_desired.desired_revision,
        desired_spec_digest: current_desired.spec_digest.clone(),
        placement: current_desired.placement.clone(),
        target: current_desired.target,
        phase: OperationPhase::Pending,
        terminal: None,
        created_at_unix_ms: operation_created,
        updated_at_unix_ms: operation_created,
    };
    let mut settled_old_operation = expected_old_operation.clone();
    settled_old_operation.phase = OperationPhase::Failed;
    settled_old_operation.terminal = Some(OperationTerminal::Failed {
        error: Box::new(OperationFailure::HostLost {
            node_id: old_identity.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            host_fence_event_id: event.event_id.clone(),
        }),
        completed_at_unix_ms: now,
    });
    settled_old_operation.updated_at_unix_ms = now;
    let recovery_operation = Operation {
        version: ContractVersion::V1,
        operation_id: id("operation-recovery"),
        workspace_id: workspace_id.clone(),
        cat_id: replacement_desired.cat_id.clone(),
        desired_revision: replacement_desired.desired_revision,
        desired_spec_digest: replacement_desired.spec_digest.clone(),
        placement: replacement_desired.placement.clone(),
        target: replacement_desired.target,
        phase: OperationPhase::Pending,
        terminal: None,
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    };

    store
        .authority_transaction(|transaction| {
            insert_volume(transaction, &blank)?;
            update_volume_owner(
                transaction,
                &current_volume,
                Some(&VolumeOwnerBinding {
                    volume_id: current_volume.volume_id.clone(),
                    owner_node_id: old_identity.node_id.clone(),
                    attachment_id: current_volume.lease_owner.clone().unwrap(),
                    attachment_epoch: current_volume.lease_epoch,
                }),
            )?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: current_desired.cat_id.clone(),
                    workspace_id: workspace_id.clone(),
                    name: id("host-recovery-cat"),
                    created_at: operation_created,
                },
            )?;
            insert_desired(transaction, &current_desired)?;
            insert_operation(transaction, &expected_old_operation)
        })
        .unwrap();

    RecoveryFixture {
        store,
        request: TrustedHostFenceRecoveryCommitV1 {
            terminal_event: event,
            expected_old_node_id: old_identity.node_id,
            expected_old_node_boot_id: session.node_boot_id,
            expected_old_agent_session_epoch: session.agent_session_epoch,
            expected_current_desired: current_desired,
            takeover_authorizations: vec![TrustedTakeoverAuthorizationV1 {
                expected_current_volume: current_volume.clone(),
                authorization,
            }],
            replacement_desired,
            expected_old_operation,
            settled_old_operation,
            recovery_operation,
        },
        current_volume,
    }
}

fn output_counts(store: &Store) -> (i64, i64, i64) {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM host_fence_events WHERE state='terminal_v1'),
                        (SELECT count(*) FROM volume_authorizations WHERE kind='takeover'),
                        (SELECT count(*) FROM trusted_host_fence_recovery_commits_v1)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
        })
        .unwrap()
}

#[test]
fn terminal_fence_recovery_commits_once_and_exact_replay_returns_the_receipt() {
    let fixture = recovery_fixture("host-recovery-success");
    let first = fixture
        .store
        .commit_trusted_host_fence_recovery_v1(&fixture.request)
        .unwrap();
    let replay = fixture
        .store
        .commit_trusted_host_fence_recovery_v1(&fixture.request)
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(output_counts(&fixture.store), (1, 1, 1));

    fixture
        .store
        .authority_transaction(|transaction| {
            let retired = load_identity_by_node_for_update(
                transaction,
                &fixture.request.expected_old_node_id,
            )?
            .unwrap();
            assert_eq!(retired.state, NodeIdentityState::Retired);
            assert_eq!(
                lock_exact_credential_lineage(transaction, &retired)?,
                Some(CredentialLineageState::Retired)
            );
            assert!(load_current_session_for_update(
                transaction,
                &fixture.request.expected_old_node_id,
            )?
            .is_none());
            Ok(())
        })
        .unwrap();

    fixture
        .store
        .authority_transaction(|transaction| {
            let desired =
                load_desired_for_update(transaction, &fixture.request.replacement_desired.cat_id)?
                    .unwrap();
            let old_operation = load_operation_for_update(
                transaction,
                &fixture.request.expected_old_operation.operation_id,
            )?
            .unwrap();
            let recovery_operation = load_operation_for_update(
                transaction,
                &fixture.request.recovery_operation.operation_id,
            )?
            .unwrap();
            let authorization = load_authorization_for_update(
                transaction,
                &match &fixture.request.takeover_authorizations[0]
                    .authorization
                    .authorization
                {
                    VolumeAuthorization::Takeover(value) => value.authorization_id.clone(),
                    VolumeAuthorization::DisposableRootDelete(_) => unreachable!(),
                },
            )?
            .unwrap();
            let volume =
                load_stored_volume_for_update(transaction, &fixture.current_volume.volume_id)?
                    .unwrap();
            assert_eq!(desired, fixture.request.replacement_desired);
            assert_eq!(old_operation, fixture.request.settled_old_operation);
            assert_eq!(recovery_operation, fixture.request.recovery_operation);
            assert_eq!(
                authorization,
                fixture.request.takeover_authorizations[0].authorization
            );
            assert_eq!(volume.record, fixture.current_volume);
            assert_eq!(
                volume.owner_binding.unwrap().owner_node_id,
                fixture.request.expected_old_node_id
            );
            Ok(())
        })
        .unwrap();

    let rejoin = fixture.store.with(|client| {
        client.execute(
            "UPDATE host_fence_events SET state='rejoined' WHERE event_id=$1",
            &[&fixture.request.terminal_event.event_id.as_str()],
        )
    });
    assert_eq!(rejoin.unwrap_err().code, ErrorCode::Conflict);
    let state: String = fixture
        .store
        .with(|client| {
            client
                .query_one(
                    "SELECT state FROM host_fence_events WHERE event_id=$1",
                    &[&fixture.request.terminal_event.event_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(state, "terminal_v1");
}

#[test]
fn stale_node_owner_binding_rejects_the_whole_recovery_without_side_effects() {
    let fixture = recovery_fixture("host-recovery-stale-owner");
    fixture
        .store
        .authority_transaction(|transaction| {
            update_volume_owner(
                transaction,
                &fixture.current_volume,
                Some(&VolumeOwnerBinding {
                    volume_id: fixture.current_volume.volume_id.clone(),
                    owner_node_id: id("node-foreign"),
                    attachment_id: fixture.current_volume.lease_owner.clone().unwrap(),
                    attachment_epoch: fixture.current_volume.lease_epoch,
                }),
            )
        })
        .unwrap();

    let error = fixture
        .store
        .commit_trusted_host_fence_recovery_v1(&fixture.request)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(output_counts(&fixture.store), (0, 0, 0));
    fixture
        .store
        .authority_transaction(|transaction| {
            assert_eq!(
                load_desired_for_update(
                    transaction,
                    &fixture.request.expected_current_desired.cat_id,
                )?
                .unwrap(),
                fixture.request.expected_current_desired
            );
            assert_eq!(
                load_operation_for_update(
                    transaction,
                    &fixture.request.expected_old_operation.operation_id,
                )?
                .unwrap(),
                fixture.request.expected_old_operation
            );
            assert!(load_operation_for_update(
                transaction,
                &fixture.request.recovery_operation.operation_id,
            )?
            .is_none());
            Ok(())
        })
        .unwrap();
}

#[test]
fn provisional_object_cutoff_is_rejected_before_any_authority_row_is_written() {
    let mut fixture = recovery_fixture("host-recovery-provisional");
    let ObjectWriteCutoffEvidence::PrincipalCutoffWithAcceptedPutTerminalBarrier {
        terminal_sequence,
        ..
    } = &mut fixture
        .request
        .terminal_event
        .provider_evidence
        .object_write_cutoff;
    *terminal_sequence = WireU64::new(3).unwrap();

    let error = fixture
        .store
        .commit_trusted_host_fence_recovery_v1(&fixture.request)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(output_counts(&fixture.store), (0, 0, 0));
}

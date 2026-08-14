use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_reconciliation::{
    guest_config_digest, spec_digest, AgentRegistrationAttempt, AgentSession, AsciiText,
    AssignedKind, AssignedPlacement, ContractVersion, CredentialBinding, DesiredRuntimeSpec,
    DiskKind, Epoch, FenceEpoch, Generation, GuestDeviceIdentity, GuestRuntimeProfileReceipt, Id,
    Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig, NodeBootId, NodeIdentity,
    NodeIdentityState, NormalAcquireRequest, Operation, OperationPhase, ProviderScope, RandomId128,
    RemoteHead, Revision, RuntimeConfig, RuntimeTarget, RuntimeTransition, Sha256Digest,
    UnixMillis, VolumeAccess, VolumeAcquire, VolumeAdminState, VolumeDisposition, VolumeDurability,
    VolumeIntent, VolumeRecord,
};
use cats_storage::authority::{normal_acquire, VolumeOwnerBinding};

use super::product::CatRecord;
use super::product_rows::{insert_cat, insert_desired, insert_operation};
use super::rows::{database_now, insert_volume, update_volume_owner};
use crate::store::agent_sessions::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy};
use crate::store::Store;

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
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

pub(super) struct RecoveryFixture {
    pub(super) store: Store,
    pub(super) current_desired: DesiredRuntimeSpec,
    pub(super) expected_old_operation: Operation,
    pub(super) current_volume: VolumeRecord,
    pub(super) old_identity: NodeIdentity,
    pub(super) old_session: AgentSession,
}

pub(super) struct RecoveryCatFixture {
    pub(super) expected_current_desired: DesiredRuntimeSpec,
    pub(super) expected_old_operation: Operation,
}

pub(super) fn recovery_fixture(slug: &str) -> RecoveryFixture {
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
        current_desired,
        expected_old_operation,
        current_volume,
        old_identity,
        old_session: session,
    }
}

pub(super) fn add_second_recovery_cat(fixture: &RecoveryFixture) -> RecoveryCatFixture {
    let now = fixture.store.authority_transaction(database_now).unwrap();
    let mut blank = fixture.current_volume.clone();
    blank.volume_id = id("volume-root-second");
    blank.head = blank_head();
    blank.lease_owner = None;
    blank.lease_epoch = fence_epoch(0);
    blank.lease_expires_at = None;
    blank.last_transition = None;

    let transition_id = random_id(110);
    let normal_request = NormalAcquireRequest {
        volume_id: blank.volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: id("attachment-old-second"),
        expected_unowned_epoch: blank.lease_epoch,
        desired_revision: revision(1),
        placement_epoch: epoch(1),
        lease_duration_ms: 60_000,
    };
    let (current_volume, _) = normal_acquire(&blank, &normal_request, before(now, 1)).unwrap();

    let mut current_desired = fixture.current_desired.clone();
    current_desired.cat_id = id("cat-host-recovery-second");
    current_desired.volumes[0].volume_intent_id = id("intent-root-second");
    current_desired.volumes[0].disk_id = id("disk-root-second");
    current_desired.volumes[0].volume_id = current_volume.volume_id.clone();
    current_desired.volumes[0].attachment_id = current_volume.lease_owner.clone().unwrap();
    current_desired.volumes[0].guest_device.serial = id("root-device-second");
    current_desired.volumes[0].acquire = VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch: fence_epoch(0),
    };
    current_desired.spec_digest = spec_digest(&current_desired).unwrap();

    let mut expected_old_operation = fixture.expected_old_operation.clone();
    expected_old_operation.operation_id = id("operation-old-second");
    expected_old_operation.cat_id = current_desired.cat_id.clone();
    expected_old_operation.desired_spec_digest = current_desired.spec_digest.clone();

    fixture
        .store
        .authority_transaction(|transaction| {
            insert_volume(transaction, &blank)?;
            update_volume_owner(
                transaction,
                &current_volume,
                Some(&VolumeOwnerBinding {
                    volume_id: current_volume.volume_id.clone(),
                    owner_node_id: fixture.old_identity.node_id.clone(),
                    attachment_id: current_volume.lease_owner.clone().unwrap(),
                    attachment_epoch: current_volume.lease_epoch,
                }),
            )?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: current_desired.cat_id.clone(),
                    workspace_id: current_desired.workspace_id.clone(),
                    name: id("host-recovery-cat-second"),
                    created_at: expected_old_operation.created_at_unix_ms,
                },
            )?;
            insert_desired(transaction, &current_desired)?;
            insert_operation(transaction, &expected_old_operation)
        })
        .unwrap();

    RecoveryCatFixture {
        expected_current_desired: current_desired,
        expected_old_operation,
    }
}

fn singular_shape_covers_complete_assigned_set(singular_cat: &Id, assigned: &[Id]) -> bool {
    assigned.len() == 1 && assigned.first() == Some(singular_cat)
}

#[test]
fn singular_recovery_shape_cannot_cover_a_two_cat_host() {
    // This is deliberately a pure structural characterization. There is no
    // singular production request type, decoder, Store writer, or DDL table.
    let first = id("cat-first");
    let assigned = vec![first.clone(), id("cat-second")];
    assert!(!singular_shape_covers_complete_assigned_set(
        &first, &assigned
    ));
}

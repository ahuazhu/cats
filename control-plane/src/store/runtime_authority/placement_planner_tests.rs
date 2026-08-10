//! Real PostgreSQL acceptance tests for the A23 first-fit planner.

use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    guest_config_digest, spec_digest, AllocatableMemoryBytes, AllocatableVcpus, AsciiText,
    AssignedKind, AssignedPlacement, ContractVersion, CredentialBinding, DesiredRuntimeSpec,
    Durability, Epoch, GuestIpv4Pool, GuestIpv4PoolKind, GuestRuntimeProfileReceipt, Id,
    Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig, NodeIdentity, NodeIdentityState,
    NodePlacementPolicy, NodeTransportTarget, Revision, RuntimeConfig,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeSchedulingState, RuntimeTarget,
    RuntimeTransition, Sha256Digest,
};

use super::cat_create_service::CatCreatePlanRequest;
use super::placement_planner::{CatCreatePlacementLoad, PlacementCandidateRejection};
use super::product::CatRecord;
use super::product_rows::{insert_cat, insert_desired};
use super::rows::database_now;
use crate::store::Store;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
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

fn policy(
    node_id: &Id,
    revision: u64,
    state: RuntimeSchedulingState,
    memory_bytes: u64,
    guest_digest: &Sha256Digest,
) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        policy_revision: Epoch::new(revision).unwrap(),
        scheduling_state: state,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(memory_bytes).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: guest_digest.clone(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://runtime-node.internal:7301")
            .unwrap(),
    }
}

fn request(guest_digest: &Sha256Digest) -> CatCreatePlanRequest {
    CatCreatePlanRequest {
        cat_id: id("cat_77777777777777777777777777777777"),
        vcpus: 2,
        memory_bytes: 2 << 30,
        root_size_bytes: 4 << 20,
        durability: Durability::Strict,
        boot_image_digest: digest(3),
        guest_config_digest: guest_digest.clone(),
        network_id: id("net_77777777777777777777777777777777"),
    }
}

fn desired(
    workspace_id: &Id,
    node_id: &Id,
    guest_digest: &Sha256Digest,
    suffix: &str,
    guest_ipv4: &str,
    gateway_ipv4: &str,
    guest_mac: &str,
) -> DesiredRuntimeSpec {
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: workspace_id.clone(),
        cat_id: id(&format!("cat_{suffix}")),
        desired_revision: Revision::new(1).unwrap(),
        target: RuntimeTarget::Running,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: node_id.clone(),
            placement_epoch: Epoch::new(1).unwrap(),
        },
        runtime: RuntimeConfig {
            vcpus: 1,
            memory_bytes: 512 << 20,
            boot_image_digest: digest(3),
            guest_config_digest: guest_digest.clone(),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id("net_reused_identity"),
                guest_mac: MacAddress::new(guest_mac).unwrap(),
                guest_ipv4: Ipv4Address::new(guest_ipv4).unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new(gateway_ipv4).unwrap(),
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

#[test]
fn planner_scans_keyset_in_c_order_and_selects_first_eligible_node() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    let a = super::runtime_spine_tests::establish_empty_admission_for(&store, &release, "a", 1);
    let b = super::runtime_spine_tests::establish_empty_admission_for(&store, &release, "b", 2);
    let policy_a = policy(
        &a.node_identity.node_id,
        1,
        RuntimeSchedulingState::Cordoned,
        16 << 30,
        &guest_digest,
    );
    let policy_b = policy(
        &b.node_identity.node_id,
        1,
        RuntimeSchedulingState::Schedulable,
        16 << 30,
        &guest_digest,
    );
    store
        .authority_transaction(|transaction| {
            super::placement_policy::insert_policy_for_test(transaction, &policy_a)?;
            super::placement_policy::insert_policy_for_test(transaction, &policy_b)
        })
        .unwrap();

    let plan = match store
        .plan_cat_create_placement(&request(&guest_digest))
        .unwrap()
    {
        CatCreatePlacementLoad::Planned(plan) => *plan,
        other => panic!("planner did not find node_b: {other:?}"),
    };
    assert_eq!(plan.target.policy, policy_b);
    assert_eq!(
        plan.target.admission.node_identity.node_id.as_str(),
        "node_b"
    );
    assert!(plan.target.active_host_fence_event.is_none());
    assert_eq!(
        plan.mutation.network_config.network_id.as_str(),
        "net_77777777777777777777777777777777"
    );
}

#[test]
fn planner_returns_bounded_ordinary_rejections_without_writing() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    let admission = super::runtime_spine_tests::establish_empty_admission(&store, &release);
    let cordoned = policy(
        &admission.node_identity.node_id,
        1,
        RuntimeSchedulingState::Cordoned,
        16 << 30,
        &guest_digest,
    );
    store
        .authority_transaction(|transaction| {
            super::placement_policy::insert_policy_for_test(transaction, &cordoned)
        })
        .unwrap();

    let unavailable = store
        .plan_cat_create_placement(&request(&guest_digest))
        .unwrap();
    assert_eq!(
        unavailable,
        CatCreatePlacementLoad::Unavailable {
            first_rejection: Some((
                admission.node_identity.node_id.clone(),
                PlacementCandidateRejection::PolicyCordoned,
            )),
        }
    );

    let tiny = policy(
        &admission.node_identity.node_id,
        2,
        RuntimeSchedulingState::Schedulable,
        1 << 30,
        &guest_digest,
    );
    store
        .authority_transaction(|transaction| {
            super::placement_policy::update_policy_for_test(transaction, &cordoned, &tiny)
        })
        .unwrap();
    let unavailable = store
        .plan_cat_create_placement(&request(&guest_digest))
        .unwrap();
    assert_eq!(
        unavailable,
        CatCreatePlacementLoad::Unavailable {
            first_rejection: Some((
                admission.node_identity.node_id,
                PlacementCandidateRejection::InsufficientMemory,
            )),
        }
    );
    let result_rows: i64 = store
        .with(|client| {
            client
                .query_one("SELECT count(*) FROM api_idempotency_results", &[])
                .map(|row| row.get(0))
        })
        .unwrap();
    assert_eq!(result_rows, 0);
}

#[test]
fn stored_assigned_corruption_is_fatal_before_missing_admission_can_skip_the_node() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    let admission = super::runtime_spine_tests::establish_empty_admission(&store, &release);
    let initial_policy = policy(
        &admission.node_identity.node_id,
        1,
        RuntimeSchedulingState::Schedulable,
        16 << 30,
        &guest_digest,
    );
    let workspace = super::product_tests::bootstrap_workspace(&store, "planner-corrupt");
    let desired_a = desired(
        &workspace,
        &admission.node_identity.node_id,
        &guest_digest,
        "duplicate_network_a",
        "10.240.0.6",
        "10.240.0.5",
        "02:ca:0a:f0:00:06",
    );
    let desired_b = desired(
        &workspace,
        &admission.node_identity.node_id,
        &guest_digest,
        "duplicate_network_b",
        "10.240.0.10",
        "10.240.0.9",
        "02:ca:0a:f0:00:0a",
    );
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            for (name, desired) in [("duplicate-a", &desired_a), ("duplicate-b", &desired_b)] {
                insert_cat(
                    transaction,
                    &CatRecord {
                        cat_id: desired.cat_id.clone(),
                        workspace_id: workspace.clone(),
                        name: id(name),
                        created_at: now,
                    },
                )?;
                insert_desired(transaction, desired)?;
            }
            super::placement_policy::insert_policy_for_test(transaction, &initial_policy)?;
            transaction.execute(
                "DELETE FROM current_agent_sessions WHERE node_id=$1",
                &[&admission.node_identity.node_id.as_str()],
            )?;
            Ok(())
        })
        .unwrap();

    let error = store
        .plan_cat_create_placement(&request(&guest_digest))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn canonical_assignment_cannot_be_hidden_by_node_projection_drift() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    let admission = super::runtime_spine_tests::establish_empty_admission(&store, &release);
    let current_policy = policy(
        &admission.node_identity.node_id,
        1,
        RuntimeSchedulingState::Schedulable,
        16 << 30,
        &guest_digest,
    );
    let workspace = super::product_tests::bootstrap_workspace(&store, "planner-hidden-desired");
    let hidden = desired(
        &workspace,
        &admission.node_identity.node_id,
        &guest_digest,
        "hidden_assignment",
        "10.240.0.6",
        "10.240.0.5",
        "02:ca:0a:f0:00:06",
    );
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: hidden.cat_id.clone(),
                    workspace_id: workspace.clone(),
                    name: id("hidden-assignment"),
                    created_at: now,
                },
            )?;
            insert_desired(transaction, &hidden)?;
            super::placement_policy::insert_policy_for_test(transaction, &current_policy)
        })
        .unwrap();
    store
        .with(|client| {
            client.execute(
                "UPDATE desired_runtime_specs SET node_id='node_z' WHERE cat_id=$1",
                &[&hidden.cat_id.as_str()],
            )
        })
        .unwrap();

    let error = store
        .plan_cat_create_placement(&request(&guest_digest))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn global_network_identity_collision_is_detected_before_first_fit() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    let admission_a =
        super::runtime_spine_tests::establish_empty_admission_for(&store, &release, "a", 1);
    let admission_b =
        super::runtime_spine_tests::establish_empty_admission_for(&store, &release, "b", 2);
    let policy_a = policy(
        &admission_a.node_identity.node_id,
        1,
        RuntimeSchedulingState::Schedulable,
        16 << 30,
        &guest_digest,
    );
    let policy_b = policy(
        &admission_b.node_identity.node_id,
        1,
        RuntimeSchedulingState::Schedulable,
        16 << 30,
        &guest_digest,
    );
    let workspace = super::product_tests::bootstrap_workspace(&store, "planner-global-network");
    let mut occupied = desired(
        &workspace,
        &admission_b.node_identity.node_id,
        &guest_digest,
        "occupied_on_larger_node",
        "10.240.0.6",
        "10.240.0.5",
        "02:ca:0a:f0:00:06",
    );
    occupied.runtime.network_config.network_id = request(&guest_digest).network_id;
    occupied.spec_digest = spec_digest(&occupied).unwrap();
    store
        .authority_transaction(|transaction| {
            let now = database_now(transaction)?;
            insert_cat(
                transaction,
                &CatRecord {
                    cat_id: occupied.cat_id.clone(),
                    workspace_id: workspace.clone(),
                    name: id("occupied-on-node-b"),
                    created_at: now,
                },
            )?;
            insert_desired(transaction, &occupied)?;
            super::placement_policy::insert_policy_for_test(transaction, &policy_a)?;
            super::placement_policy::insert_policy_for_test(transaction, &policy_b)
        })
        .unwrap();

    assert_eq!(
        store
            .plan_cat_create_placement(&request(&guest_digest))
            .unwrap(),
        CatCreatePlacementLoad::CandidateIdentityCollision
    );
    let counts = super::product_tests::counts(&store);
    assert_eq!(counts, [1, 0, 0, 1, 0, 0, 0, 0]);
}

#[test]
fn first_fit_stops_before_a_larger_corrupt_identity_in_the_same_page() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    let admission =
        super::runtime_spine_tests::establish_empty_admission_for(&store, &release, "a", 1);
    let initial_policy = policy(
        &admission.node_identity.node_id,
        1,
        RuntimeSchedulingState::Schedulable,
        16 << 30,
        &guest_digest,
    );
    store
        .authority_transaction(|transaction| {
            super::placement_policy::insert_policy_for_test(transaction, &initial_policy)
        })
        .unwrap();

    for index in 0_u8..64 {
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: id(&format!("node_b{index:03}")),
            immutable_host_id: id(&format!("host_b{index:03}")),
            credential_id: id(&format!("credential_b{index:03}")),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: digest(index.saturating_add(100)),
            },
            state_path_id: id(&format!("state_path_b{index:03}")),
            state: NodeIdentityState::Provisioned,
        };
        store.provision_node_identity(&identity).unwrap();
    }
    store
        .with(|client| {
            client.execute(
                "UPDATE node_identities
                    SET record=jsonb_set(record, '{immutable_host_id}', '\"corrupt_host\"')
                  WHERE node_id='node_b000'",
                &[],
            )
        })
        .unwrap();

    let plan = store
        .plan_cat_create_placement(&request(&guest_digest))
        .unwrap();
    assert!(matches!(plan, CatCreatePlacementLoad::Planned(_)));

    let cordoned = policy(
        &admission.node_identity.node_id,
        2,
        RuntimeSchedulingState::Cordoned,
        16 << 30,
        &guest_digest,
    );
    store
        .authority_transaction(|transaction| {
            super::placement_policy::update_policy_for_test(transaction, &initial_policy, &cordoned)
        })
        .unwrap();
    let error = store
        .plan_cat_create_placement(&request(&guest_digest))
        .unwrap_err();
    assert_eq!(error.code, cats_api::error::ErrorCode::Internal);
}

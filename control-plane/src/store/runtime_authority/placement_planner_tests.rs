//! PostgreSQL acceptance tests for clean-slate atomic lifecycle placement.

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_inventory::{
    full_inventory_digest, RuntimeInventoryBody, RuntimeInventoryReport,
};
use cats_api::runtime_lifecycle::RuntimeNetworkConfig;
use cats_api::runtime_reconciliation::{
    guest_config_digest, AgentRegistrationAttempt, AllocatableMemoryBytes, AllocatableVcpus,
    AsciiText, ContractVersion, CredentialBinding, Durability, Epoch, GuestIpv4Pool,
    GuestIpv4PoolKind, GuestRuntimeProfileReceipt, Id, Ipv4Address, NodeBootId, NodeIdentity,
    NodeIdentityState, NodePlacementPolicy, NodeTransportTarget, ProviderScope, RandomId128,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeSchedulingState, Sequence,
    SessionBinding, Sha256Digest, UnixMillis,
};

use super::cat_create_service::CatCreatePlanRequest;
use super::placement_planner::{CatCreatePlacementLoad, PlacementCandidateRejection};
use super::runtime_spine::RuntimeInventoryOutcome;
use crate::store::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy, Store};

fn id(value: impl Into<String>) -> Id {
    Id::new(value.into()).unwrap()
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

fn policy(
    node_id: &Id,
    state: RuntimeSchedulingState,
    guest_digest: &Sha256Digest,
) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        policy_revision: Epoch::new(1).unwrap(),
        scheduling_state: state,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
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

fn request(guest_digest: &Sha256Digest, network_id: &str) -> CatCreatePlanRequest {
    CatCreatePlanRequest {
        cat_id: id("cat_77777777777777777777777777777777"),
        vcpus: 2,
        memory_bytes: 2 << 30,
        root_size_bytes: 4 << 20,
        durability: Durability::Strict,
        boot_image_digest: digest(3),
        guest_config_digest: guest_digest.clone(),
        network_id: id(network_id),
    }
}

fn establish_node(
    store: &Store,
    release: &GuestRuntimeProfileReceipt,
    suffix: &str,
    identity_byte: u8,
    scheduling_state: RuntimeSchedulingState,
    submit_full_inventory: bool,
) -> Id {
    let node_id = id(format!("node_{suffix}"));
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        provider_scope: ProviderScope {
            provider: id("test_provider"),
            partition: id("test_partition"),
            account_id: id("test_account"),
            region: id("test_region"),
        },
        immutable_host_id: id(format!("host_{suffix}")),
        credential_id: id(format!("credential_{suffix}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(identity_byte),
        },
        state_path_id: id(format!("state_path_{suffix}")),
        state: NodeIdentityState::Provisioned,
    };
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let registration_policy =
        AgentSessionRegistrationPolicy::from_release_receipt(release).unwrap();
    store.provision_node_identity(&identity).unwrap();
    let random = |offset: u8| {
        RandomId128::new(format!("{:02x}", identity_byte.wrapping_add(offset)).repeat(16)).unwrap()
    };
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: NodeBootId::new(format!("{:02x}", identity_byte).repeat(16)).unwrap(),
        agent_instance_id: random(1),
        registration_attempt_id: random(2),
        guest_config_digest: guest_config_digest(release).unwrap(),
        expected_agent_session_epoch: None,
    };
    let session = match store
        .register_agent_session(&authenticated, &attempt, &registration_policy)
        .unwrap()
    {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("AgentSession registration rejected: {rejection:?}")
        }
    };
    let placement_policy = policy(&node_id, scheduling_state, &session.guest_config_digest);
    store
        .authority_transaction(|transaction| {
            super::placement_policy::insert_policy_for_test(transaction, &placement_policy)
        })
        .unwrap();

    if submit_full_inventory {
        let mut report = RuntimeInventoryReport {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: session.node_id.clone(),
                node_boot_id: session.node_boot_id.clone(),
                agent_instance_id: session.agent_instance_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
            },
            report_id: random(3),
            sequence: Sequence::new(1).unwrap(),
            collected_at_unix_ms: UnixMillis::new(1).unwrap(),
            inventory: RuntimeInventoryBody::Full {
                inventory_epoch: Epoch::new(1).unwrap(),
                scan_id: random(4),
                inventory_digest: digest(0),
                cats: Vec::new(),
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
        assert!(matches!(
            store
                .runtime_accept_inventory(&authenticated, &report)
                .unwrap(),
            RuntimeInventoryOutcome::Accepted(_)
        ));
    }
    node_id
}

#[test]
fn planner_scans_in_c_order_and_selects_the_first_fresh_eligible_node() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    establish_node(
        &store,
        &release,
        "a",
        10,
        RuntimeSchedulingState::Cordoned,
        true,
    );
    let selected = establish_node(
        &store,
        &release,
        "b",
        20,
        RuntimeSchedulingState::Schedulable,
        true,
    );

    let plan = match store
        .plan_cat_create_placement(&request(&guest_digest, "net_planner_first_fit"))
        .unwrap()
    {
        CatCreatePlacementLoad::Planned(plan) => *plan,
        other => panic!("planner did not find the eligible Node: {other:?}"),
    };
    assert_eq!(plan.target.node_identity.node_id, selected);
    let RuntimeNetworkConfig::IsolatedIpv4 { network_id, .. } = &plan.mutation.network_config;
    assert_eq!(network_id.as_str(), "net_planner_first_fit");
}

#[test]
fn planner_requires_a_fresh_session_bound_full_inventory() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let release = release();
    let guest_digest = guest_config_digest(&release).unwrap();
    let node = establish_node(
        &store,
        &release,
        "missing_inventory",
        30,
        RuntimeSchedulingState::Schedulable,
        false,
    );

    assert_eq!(
        store
            .plan_cat_create_placement(&request(&guest_digest, "net_missing_inventory"))
            .unwrap(),
        CatCreatePlacementLoad::Unavailable {
            first_rejection: Some((
                node,
                PlacementCandidateRejection::MissingOrStaleFullInventory,
            )),
        }
    );
}

#[test]
fn planner_rejects_a_network_identity_retained_in_config_history() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let workspace = super::lifecycle_commands_tests::workspace_id(&store, "planner-network");
    let cat = id("cat_planner_network_history");
    let creation = id("creation_planner_network_history");
    let config = super::lifecycle_commands_tests::seed_cat(&store, &workspace, &cat, &creation);
    let RuntimeNetworkConfig::IsolatedIpv4 { network_id, .. } = &config.network_config;

    assert_eq!(
        store
            .plan_cat_create_placement(&request(
                &config.guest_runtime_profile_digest,
                network_id.as_str(),
            ))
            .unwrap(),
        CatCreatePlacementLoad::CandidateIdentityCollision
    );
}

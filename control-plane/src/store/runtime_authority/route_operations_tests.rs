use cats_api::runtime_inventory::{
    full_inventory_digest, RuntimeInventoryBody, RuntimeInventoryReport,
};
use cats_api::runtime_lifecycle::{
    LifecycleCommandResponse, LifecycleResultCommitRequest, NodeResult, SuspendedResult,
};
use cats_api::runtime_reconciliation::{
    AllocatableMemoryBytes, AllocatableVcpus, ContractVersion, Epoch, GuestIpv4Pool,
    GuestIpv4PoolKind, Hostname, Id, Ipv4Address, NodePlacementPolicy, NodeTransportTarget,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeSchedulingState, Sequence,
    UnixMillis,
};
use cats_api::runtime_route::{
    RouteCommand, RouteCommandPollRequest, RouteCommandResponse, RouteNodeResult, RouteNodeRingAck,
    RouteResultCommitRequest, RouteServingResult,
};

use super::lifecycle_commands::{LifecycleCommandAdmission, LifecycleResultCommitOutcome};
use super::lifecycle_commands_tests::{
    digest, genesis_start, id, random, same_node_suspend, seed_cat, session_binding,
    settle_genesis_runtime_ready, workspace_id,
};
use super::placement_policy::insert_policy_on_store_for_test;
use super::placement_policy_tests::install_initial_signer_for_test;
use super::route_operations::{
    RouteCommandPollOutcome, RouteResultCommitOutcome, ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS,
};
use super::route_signer::{RouteGrantV2AuthorityLoad, RouteGrantV2AuthorityRejection};
use super::runtime_spine::RuntimeInventoryOutcome;
use crate::store::Store;

#[derive(Debug, PartialEq, Eq)]
struct EndpointRouteProjection {
    route_epoch: i64,
    route_head_operation_id: Option<String>,
    effective_serving_operation_id: Option<String>,
}

#[test]
fn endpoint_metadata_drives_enable_and_lifecycle_close_burns_every_affected_lane() {
    let store = super::lifecycle_commands_tests::test_store();
    let workspace = workspace_id(&store, "atomic-route-controller-close");
    let node = id("node-atomic-route-controller-close");
    let cat = id("cat-atomic-route-controller-close");
    let creation = id("creation-atomic-route-controller-close");
    let config = seed_cat(&store, &workspace, &cat, &creation);
    let start = genesis_start(
        &workspace,
        &node,
        &cat,
        &creation,
        "operation-route-start",
        &config,
    );
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &start).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let running = settle_genesis_runtime_ready(&store, &node, &start, &config);
    insert_route_policy(&store, &node);
    accept_full_inventory(&store, &running.authenticated, &running.session);
    let ring = install_initial_signer_for_test(&store);
    let active_kid = ring.keys[0].kid.clone();
    let ring_ack = RouteNodeRingAck::new(
        session_binding(&running.session),
        random(103),
        Sequence::new(1).unwrap(),
        ring.ring_version,
        ring.keys.iter().map(|entry| entry.kid.clone()).collect(),
    )
    .unwrap();

    let serving_endpoint = id("endpoint-route-serving");
    let late_endpoint = id("endpoint-route-late-serving");
    insert_bound_endpoint(
        &store,
        &workspace,
        &cat,
        &serving_endpoint,
        "serving.route.test",
        8080,
    );
    insert_bound_endpoint(
        &store,
        &workspace,
        &cat,
        &late_endpoint,
        "late.route.test",
        8081,
    );

    let page = store
        .reconcile_route_controller_page(None, ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS)
        .unwrap();
    assert_eq!(page.examined, 2);
    assert_eq!(page.mutations, 2);
    let RouteCommandPollOutcome::Batch(batch) = store
        .poll_route_commands(
            &running.authenticated,
            &RouteCommandPollRequest::new(
                &running.session,
                Sequence::new(1).unwrap(),
                Some(ring_ack),
            )
            .unwrap(),
        )
        .unwrap()
    else {
        panic!("current AgentSession Route poll was rejected")
    };
    assert_eq!(batch.commands.len(), 2);
    assert!(batch
        .commands
        .iter()
        .all(|command| command.command == RouteCommand::Enable));
    assert!(batch.commands.iter().all(|command| {
        command
            .binding
            .effective_runtime_ready
            .source_lifecycle_operation_id
            == running.running_head.operation_id
            && command.binding.effective_runtime_ready.runtime_incarnation
                == running.runtime_incarnation
            && command.binding.admission_session.agent_session_epoch
                == running.session.agent_session_epoch
    }));

    let serving_command = command_for_endpoint(&batch.commands, &serving_endpoint);
    let late_command = command_for_endpoint(&batch.commands, &late_endpoint);
    let serving_result_commit = serving_commit(&running.session, serving_command, 100);
    assert!(matches!(
        store
            .commit_route_result(&running.authenticated, &serving_result_commit)
            .unwrap(),
        RouteResultCommitOutcome::Stored { .. }
    ));
    let serving_before_close = endpoint_route_projection(&store, &serving_endpoint);
    assert_eq!(serving_before_close.route_epoch, 1);
    assert_eq!(
        serving_before_close
            .effective_serving_operation_id
            .as_deref(),
        Some(serving_command.operation_id.as_str())
    );
    let RouteGrantV2AuthorityLoad::Ready(signable) = store
        .load_route_grant_v2_authority(
            &Hostname::new("serving.route.test").unwrap(),
            &active_kid,
            &digest(104),
        )
        .unwrap()
    else {
        panic!("exact RuntimeReady, Serving, Full and ring ACK were not signable")
    };
    assert_eq!(signable.endpoint_id, serving_endpoint);
    assert_eq!(signable.runtime_incarnation, running.runtime_incarnation);

    let suspend = same_node_suspend(&running.running_head, "operation-route-suspend", &config);
    assert!(matches!(
        store.admit_lifecycle_command(&workspace, &suspend).unwrap(),
        LifecycleCommandAdmission::Admitted(_)
    ));
    let blocked_page = store
        .reconcile_route_controller_page(None, ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS)
        .unwrap();
    assert_eq!(blocked_page.mutations, 0);
    assert_eq!(
        store
            .load_route_grant_v2_authority(
                &Hostname::new("serving.route.test").unwrap(),
                &active_kid,
                &digest(105),
            )
            .unwrap(),
        RouteGrantV2AuthorityLoad::Rejected(RouteGrantV2AuthorityRejection::Pending)
    );

    // The Enable linearized before lifecycle acceptance, but its late Serving
    // receipt cannot become authority after the Cat lane accepted Suspend.
    let late_commit = serving_commit(&running.session, late_command, 101);
    assert!(matches!(
        store
            .commit_route_result(&running.authenticated, &late_commit)
            .unwrap(),
        RouteResultCommitOutcome::Superseded { .. }
    ));
    assert_eq!(
        endpoint_route_projection(&store, &late_endpoint),
        EndpointRouteProjection {
            route_epoch: 2,
            route_head_operation_id: Some(late_command.operation_id.to_string()),
            effective_serving_operation_id: None,
        }
    );

    let suspend_commit = LifecycleResultCommitRequest::new(
        &running.session,
        LifecycleCommandResponse::new(
            &suspend,
            NodeResult::Suspended(Box::new(SuspendedResult {
                runtime_incarnation: running.runtime_incarnation,
                runtime_config_digest: config.config_digest.clone(),
                pause_receipt_digest: digest(102),
                local_durability_receipts: vec![running.volume_receipt],
            })),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store
            .commit_lifecycle_result(&running.authenticated, &suspend_commit)
            .unwrap(),
        LifecycleResultCommitOutcome::Stored { .. }
    ));

    // The terminal lifecycle close clears the already-effective Serving lane
    // and burns it once. The lane invalidated by the late result is not burned
    // a second time.
    assert_eq!(
        endpoint_route_projection(&store, &serving_endpoint),
        EndpointRouteProjection {
            route_epoch: 2,
            route_head_operation_id: Some(serving_command.operation_id.to_string()),
            effective_serving_operation_id: None,
        }
    );
    assert_eq!(
        endpoint_route_projection(&store, &late_endpoint).route_epoch,
        2
    );
    assert_eq!(
        store
            .reconcile_route_controller_page(None, ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS)
            .unwrap()
            .mutations,
        0
    );
}

fn command_for_endpoint<'a>(
    commands: &'a [cats_api::runtime_route::RouteCommandEnvelope],
    endpoint_id: &Id,
) -> &'a cats_api::runtime_route::RouteCommandEnvelope {
    commands
        .iter()
        .find(|command| &command.binding.endpoint_id == endpoint_id)
        .expect("controller omitted Endpoint command")
}

fn serving_commit(
    session: &cats_api::runtime_reconciliation::AgentSession,
    command: &cats_api::runtime_route::RouteCommandEnvelope,
    receipt: u8,
) -> RouteResultCommitRequest {
    RouteResultCommitRequest::new(
        session,
        RouteCommandResponse::new(
            command,
            RouteNodeResult::Serving(RouteServingResult {
                binding: command.binding.clone(),
                admission_cell_receipt_digest: digest(receipt),
            }),
        )
        .unwrap(),
    )
    .unwrap()
}

fn insert_bound_endpoint(
    store: &Store,
    workspace_id: &Id,
    cat_id: &Id,
    endpoint_id: &Id,
    hostname: &str,
    target_port: i32,
) {
    store
        .authority_transaction(|transaction| {
            transaction.execute(
                "INSERT INTO endpoint_records (
                    endpoint_id, record, workspace_id, cat_id, name,
                    binding_state, hostname, protocol, target_port, route_epoch,
                    route_head_operation_id, effective_serving_operation_id,
                    created_at, updated_at_unix_ms
                 ) VALUES (
                    $1, jsonb_build_object(
                        'endpoint_id', $1::TEXT, 'workspace_id', $2::TEXT,
                        'cat_id', $3::TEXT, 'name', $4::TEXT),
                    $2, $3, $4, 'bound', $5, 'http', $6, 1,
                    NULL, NULL, 1, 1
                 )",
                &[
                    &endpoint_id.as_str(),
                    &workspace_id.as_str(),
                    &cat_id.as_str(),
                    &format!("test-{endpoint_id}"),
                    &hostname,
                    &target_port,
                ],
            )?;
            transaction.execute(
                "INSERT INTO hostname_endpoint_lookups (
                    hostname, workspace_id, cat_id, endpoint_id
                 ) VALUES ($1,$2,$3,$4)",
                &[
                    &hostname,
                    &workspace_id.as_str(),
                    &cat_id.as_str(),
                    &endpoint_id.as_str(),
                ],
            )?;
            Ok(())
        })
        .unwrap();
}

fn insert_route_policy(store: &Store, node_id: &Id) {
    insert_policy_on_store_for_test(
        store,
        &NodePlacementPolicy {
            version: ContractVersion::V1,
            node_id: node_id.clone(),
            policy_revision: Epoch::new(1).unwrap(),
            scheduling_state: RuntimeSchedulingState::Schedulable,
            allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
            allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
            capabilities: RuntimePlacementCapabilities {
                vmm: RuntimePlacementVmm::CloudHypervisor,
                block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
                guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
                guest_transport: RuntimePlacementGuestTransport::Vsock,
                guest_agent_protocol_version: ContractVersion::V1,
                guest_config_digest: digest(106),
            },
            guest_ipv4_pool: GuestIpv4Pool {
                kind: GuestIpv4PoolKind::PrivateIpv4_16,
                network_address: Ipv4Address::new("10.240.0.0").unwrap(),
                prefix_length: 16,
            },
            node_transport_target: NodeTransportTarget::new("https://route-node.internal:7301")
                .unwrap(),
        },
    )
    .unwrap();
}

fn accept_full_inventory(
    store: &Store,
    authenticated: &cats_api::agent_registration::AuthenticatedNodeCredential,
    session: &cats_api::runtime_reconciliation::AgentSession,
) {
    let mut report = RuntimeInventoryReport {
        version: ContractVersion::V1,
        session: session_binding(session),
        report_id: random(107),
        sequence: Sequence::new(1).unwrap(),
        collected_at_unix_ms: UnixMillis::new(1).unwrap(),
        inventory: RuntimeInventoryBody::Full {
            inventory_epoch: Epoch::new(1).unwrap(),
            scan_id: random(108),
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
            .runtime_accept_inventory(authenticated, &report)
            .unwrap(),
        RuntimeInventoryOutcome::Accepted(_)
    ));
}

fn endpoint_route_projection(store: &Store, endpoint_id: &Id) -> EndpointRouteProjection {
    store
        .authority_transaction(|transaction| {
            let row = transaction.query_one(
                "SELECT route_epoch, route_head_operation_id,
                        effective_serving_operation_id
                   FROM endpoint_records WHERE endpoint_id=$1",
                &[&endpoint_id.as_str()],
            )?;
            Ok(EndpointRouteProjection {
                route_epoch: row.try_get("route_epoch")?,
                route_head_operation_id: row.try_get("route_head_operation_id")?,
                effective_serving_operation_id: row.try_get("effective_serving_operation_id")?,
            })
        })
        .unwrap()
}

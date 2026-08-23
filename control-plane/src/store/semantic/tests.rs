use std::sync::{Arc, Barrier};

use super::*;

fn store_and_url() -> (Store, String) {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    seed_workspace(&store);
    (store, url)
}

fn seed_workspace(store: &Store) {
    store
        .with(|client| {
            client.batch_execute(
                "INSERT INTO accounts (
                    id,slug,display_name,kind,workos_organization_id,billing_account_id,
                    personal_owner_user_id,status,created_at
                 ) VALUES (
                    'acct_semantic','semantic','Semantic','organization','org_semantic',
                    'billing_semantic',NULL,'active',1
                 );
                 INSERT INTO workspaces (id,account_id,slug,display_name,is_default,created_at)
                 VALUES ('ws_semantic','acct_semantic','default','Default',TRUE,1);",
            )
        })
        .unwrap();
}

fn registration<'a>(node_id: &'a str, endpoint: &'a str) -> NodeRegistration<'a> {
    registration_with_identity(node_id, endpoint, "worker-a", "i-semantic-a")
}

fn registration_with_identity<'a>(
    node_id: &'a str,
    endpoint: &'a str,
    node_name: &'a str,
    instance_id: &'a str,
) -> NodeRegistration<'a> {
    NodeRegistration {
        node_id,
        node_name,
        control_endpoint: endpoint,
        vendor: "aws",
        region: "us-east-1",
        zone: "us-east-1a",
        instance_id,
        machine_type: "m7i.large",
        node_version: "1.0.0",
        reset_completed: false,
    }
}

fn create_running_cat(store: &Store, cat_id: &str, slug: &str) -> CatRecord {
    let request = NewCat {
        cat_id,
        workspace_id: "ws_semantic",
        cat_slug: slug,
        node_id: "node-a",
        cpu_count: 2,
        memory_bytes: 1 << 30,
        boot_image: "sha256:image",
    };
    let CreateCatOutcome::Created(created) = store.create_semantic_cat(request).unwrap() else {
        panic!("new semantic Cat must be created")
    };
    assert_eq!(created.current_action, Some(CatAction::Create));
    store
        .finish_semantic_cat_action(
            cat_id,
            FinishCatAction {
                expected_action: CatAction::Create,
                expected_node_id: Some("node-a"),
                final_state: CatState::Running,
                final_node_id: Some("node-a"),
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap()
}

fn register_node(store: &Store) {
    assert!(matches!(
        store
            .register_semantic_node(registration("node-a", "http://10.0.0.1:8443"))
            .unwrap(),
        RegisterNodeOutcome::Registered(_)
    ));
}

fn register_second_node(store: &Store) {
    assert!(matches!(
        store
            .register_semantic_node(registration_with_identity(
                "node-b",
                "http://10.0.0.2:8443",
                "worker-b",
                "i-semantic-b",
            ))
            .unwrap(),
        RegisterNodeOutcome::Registered(_)
    ));
}

fn register_third_node(store: &Store) {
    assert!(matches!(
        store
            .register_semantic_node(registration_with_identity(
                "node-c",
                "http://10.0.0.3:8443",
                "worker-c",
                "i-semantic-c",
            ))
            .unwrap(),
        RegisterNodeOutcome::Registered(_)
    ));
}

fn admit_cat(
    store: &Store,
    cat_id: &str,
    cat_slug: &str,
    cpu_count: i64,
    memory_bytes: i64,
) -> CatWithMounts {
    let AdmitCatCreateOutcome::Created(cat) = store
        .admit_semantic_cat_create(AtomicCatCreate {
            cat_id,
            workspace_id: "ws_semantic",
            cat_slug,
            cpu_count,
            memory_bytes,
            boot_image: "sha256:image",
            mounts: &[],
        })
        .unwrap()
    else {
        panic!("new atomic Cat must be admitted")
    };
    cat
}

fn create_running_cat_on(
    store: &Store,
    cat_id: &str,
    slug: &str,
    node_id: &str,
    cpu_count: i64,
    memory_bytes: i64,
) -> CatRecord {
    let CreateCatOutcome::Created(created) = store
        .create_semantic_cat(NewCat {
            cat_id,
            workspace_id: "ws_semantic",
            cat_slug: slug,
            node_id,
            cpu_count,
            memory_bytes,
            boot_image: "sha256:image",
        })
        .unwrap()
    else {
        panic!("new semantic Cat must be created")
    };
    assert_eq!(created.current_action, Some(CatAction::Create));
    store
        .finish_semantic_cat_action(
            cat_id,
            FinishCatAction {
                expected_action: CatAction::Create,
                expected_node_id: Some(node_id),
                final_state: CatState::Running,
                final_node_id: Some(node_id),
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap()
}

#[test]
fn atomic_create_balances_equal_shapes_and_counts_in_progress_reservations() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);

    let placements = (0..4)
        .map(|index| {
            let cat_id = format!("cat-balanced-{index}");
            let slug = format!("balanced-{index}");
            admit_cat(&store, &cat_id, &slug, 2, 1 << 30)
                .cat
                .current_action_node_id
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert_eq!(placements, ["node-a", "node-b", "node-a", "node-b"]);
}

#[test]
fn atomic_create_uses_committed_shape_and_skips_non_running_nodes() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    create_running_cat_on(&store, "cat-heavy-a", "heavy-a", "node-a", 8, 8 << 30);

    let selected = admit_cat(&store, "cat-light", "light", 1, 1 << 30);
    assert_eq!(
        selected.cat.current_action_node_id.as_deref(),
        Some("node-b")
    );

    store
        .transition_semantic_node_status("node-b", &[NodeStatus::Running], NodeStatus::Draining)
        .unwrap()
        .unwrap();
    let selected = admit_cat(&store, "cat-after-drain", "after-drain", 1, 1 << 30);
    assert_eq!(
        selected.cat.current_action_node_id.as_deref(),
        Some("node-a")
    );
}

#[test]
fn destroy_preempts_an_in_progress_create_on_its_reserved_node() {
    let (store, _) = store_and_url();
    register_node(&store);
    let creating = admit_cat(
        &store,
        "cat-destroy-creating",
        "destroy-creating",
        2,
        1 << 30,
    );
    assert_eq!(creating.cat.state, None);
    assert_eq!(creating.cat.current_action, Some(CatAction::Create));
    assert_eq!(
        creating.cat.current_action_node_id.as_deref(),
        Some("node-a")
    );

    let AdmitCatActionOutcome::Acquired(destroy) = store
        .admit_semantic_cat_action(
            SemanticCatSelector::Id("cat-destroy-creating"),
            CatAction::Destroy,
        )
        .unwrap()
    else {
        panic!("destroy must replace the in-progress create claim")
    };
    assert_eq!(destroy.cat.state, Some(CatState::Failure));
    assert_eq!(destroy.cat.current_action, Some(CatAction::Destroy));
    assert_eq!(
        destroy.cat.current_action_node_id.as_deref(),
        Some("node-a")
    );

    // Simulate Control exiting after the replacement claim commits but
    // before it dispatches to noded. A later elected scanner must rediscover
    // the exact Destroy lane and its inherited Node.
    let pending = store.list_pending_semantic_destroy_claims(0, 32).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].cat.cat_id, "cat-destroy-creating");
    assert_eq!(pending[0].cat.current_action, Some(CatAction::Destroy));
    assert_eq!(
        pending[0].cat.current_action_node_id.as_deref(),
        Some("node-a")
    );

    assert!(store
        .finish_semantic_cat_action(
            "cat-destroy-creating",
            FinishCatAction {
                expected_action: CatAction::Create,
                expected_node_id: Some("node-a"),
                final_state: CatState::Running,
                final_node_id: Some("node-a"),
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .is_none());

    let destroyed = store
        .finish_semantic_cat_action(
            "cat-destroy-creating",
            FinishCatAction {
                expected_action: CatAction::Destroy,
                expected_node_id: Some("node-a"),
                final_state: CatState::Destroyed,
                final_node_id: None,
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .expect("destroy owns the replacement claim");
    assert_eq!(destroyed.state, Some(CatState::Destroyed));
    assert!(store
        .list_pending_semantic_destroy_claims(0, 32)
        .unwrap()
        .is_empty());
}

#[test]
fn failed_destroy_recovery_rotates_behind_an_untried_claim() {
    let (store, _) = store_and_url();
    register_node(&store);
    let cat_ids = ["cat-rotate-a", "cat-rotate-b", "cat-rotate-c"];
    for cat_id in cat_ids {
        let slug = cat_id.trim_start_matches("cat-");
        admit_cat(&store, cat_id, slug, 1, 1 << 30);
        assert!(matches!(
            store
                .admit_semantic_cat_action(SemanticCatSelector::Id(cat_id), CatAction::Destroy,)
                .unwrap(),
            AdmitCatActionOutcome::Acquired(_)
        ));
    }
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE cats SET updated_at=(SELECT MAX(created_at) FROM cats)",
                    &[],
                )
                .map(|_| ())
        })
        .unwrap();

    let first = store.list_pending_semantic_destroy_claims(0, 2).unwrap();
    assert_eq!(first.len(), 2);
    let first_ids = first
        .iter()
        .map(|cat| cat.cat.cat_id.as_str())
        .collect::<Vec<_>>();
    let untried = cat_ids
        .into_iter()
        .find(|cat_id| !first_ids.contains(cat_id))
        .expect("one claim must remain outside the first bounded page");
    for cat in first {
        assert!(store
            .rotate_pending_semantic_destroy_claim(
                &cat.cat.cat_id,
                cat.cat.current_action_node_id.as_deref(),
            )
            .unwrap());
    }

    let second = store.list_pending_semantic_destroy_claims(0, 2).unwrap();
    assert_eq!(second[0].cat.cat_id, untried);
}

#[test]
fn cold_run_and_offline_recovery_share_the_least_loaded_policy() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    register_third_node(&store);
    create_running_cat_on(&store, "cat-load-a", "load-a", "node-a", 4, 1 << 30);
    create_running_cat_on(&store, "cat-load-b", "load-b", "node-b", 4, 1 << 30);
    create_running_cat_on(&store, "cat-cold", "cold", "node-a", 1, 1 << 30);

    let AdmitCatActionOutcome::Acquired(cold) = store
        .admit_semantic_cat_action(SemanticCatSelector::Id("cat-cold"), CatAction::Cold)
        .unwrap()
    else {
        panic!("running Cat must acquire Cold")
    };
    store
        .finish_semantic_cat_action(
            "cat-cold",
            FinishCatAction {
                expected_action: CatAction::Cold,
                expected_node_id: cold.cat.current_action_node_id.as_deref(),
                final_state: CatState::Cold,
                final_node_id: None,
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap();
    let AdmitCatActionOutcome::Acquired(run) = store
        .admit_semantic_cat_action(SemanticCatSelector::Id("cat-cold"), CatAction::Run)
        .unwrap()
    else {
        panic!("Cold Cat must acquire Run")
    };
    assert_eq!(run.cat.current_action_node_id.as_deref(), Some("node-c"));

    create_running_cat_on(
        &store,
        "cat-recovery-source",
        "recovery-source",
        "node-a",
        1,
        1 << 30,
    );
    store
        .transition_semantic_node_status("node-a", &[NodeStatus::Running], NodeStatus::Offline)
        .unwrap()
        .unwrap();
    let ClaimSemanticCatRecoveryOutcome::Claimed(claim) = store
        .claim_semantic_cat_recovery("node-a", "cat-recovery-source")
        .unwrap()
    else {
        panic!("offline Cat must receive a recovery claim")
    };
    assert_eq!(claim.target_node_id, "node-c");
}

#[test]
fn planned_drain_claims_are_retryable_balanced_and_settle_on_the_exact_failure_side() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    register_third_node(&store);
    for index in 0..3 {
        create_running_cat_on(
            &store,
            &format!("cat-drain-{index}"),
            &format!("drain-{index}"),
            "node-a",
            2,
            1 << 30,
        );
    }
    store
        .transition_semantic_node_status("node-a", &[NodeStatus::Running], NodeStatus::Draining)
        .unwrap()
        .unwrap();

    let ClaimSemanticCatRecoveryOutcome::Claimed(source_failure) = store
        .claim_semantic_cat_drain("node-a", "cat-drain-0")
        .unwrap()
    else {
        panic!("draining Cat must receive a relocation claim")
    };
    assert_eq!(source_failure.target_node_id, "node-b");
    assert_eq!(source_failure.cat.cat.state, Some(CatState::Running));
    assert_eq!(source_failure.cat.cat.node_id.as_deref(), Some("node-a"));
    assert_eq!(
        source_failure.cat.cat.current_action_node_id.as_deref(),
        Some("node-b")
    );
    assert!(matches!(
        store
            .admit_semantic_cat_action(SemanticCatSelector::Id("cat-drain-0"), CatAction::Run,)
            .unwrap(),
        AdmitCatActionOutcome::Busy(_)
    ));
    assert!(matches!(
        store
            .claim_semantic_cat_drain("node-a", "cat-drain-0")
            .unwrap(),
        ClaimSemanticCatRecoveryOutcome::AlreadyClaimed(ref retry)
            if retry.target_node_id == "node-b"
    ));

    let ClaimSemanticCatRecoveryOutcome::Claimed(target_failure) = store
        .claim_semantic_cat_drain("node-a", "cat-drain-1")
        .unwrap()
    else {
        panic!("second draining Cat must receive a relocation claim")
    };
    assert_eq!(target_failure.target_node_id, "node-c");
    let ClaimSemanticCatRecoveryOutcome::Claimed(recovered) = store
        .claim_semantic_cat_drain("node-a", "cat-drain-2")
        .unwrap()
    else {
        panic!("third draining Cat must receive a relocation claim")
    };
    assert_eq!(recovered.target_node_id, "node-b");
    store
        .transition_semantic_node_status("node-b", &[NodeStatus::Running], NodeStatus::Draining)
        .unwrap()
        .unwrap();
    assert!(matches!(
        store
            .claim_semantic_cat_drain("node-a", "cat-drain-2")
            .unwrap(),
        ClaimSemanticCatRecoveryOutcome::AlreadyClaimed(ref retry)
            if retry.target_node_id == "node-b"
    ));

    let source_failed = store
        .finish_semantic_cat_recovery(
            SemanticCatRecoverySettlement {
                cat_id: "cat-drain-0",
                source_node_id: "node-a",
                target_node_id: "node-b",
                target_state: CatState::Running,
            },
            SemanticCatRecoveryResult::FailedOnSource {
                code: "flush_failed",
                message: "source did not reach Cold",
            },
        )
        .unwrap()
        .expect("source failure settlement");
    assert_eq!(source_failed.cat.state, Some(CatState::Failure));
    assert_eq!(source_failed.cat.node_id.as_deref(), Some("node-a"));

    let target_failed = store
        .finish_semantic_cat_recovery(
            SemanticCatRecoverySettlement {
                cat_id: "cat-drain-1",
                source_node_id: "node-a",
                target_node_id: "node-c",
                target_state: CatState::Running,
            },
            SemanticCatRecoveryResult::Failed {
                code: "guest_start_failed",
                message: "target did not become Ready",
            },
        )
        .unwrap()
        .expect("target failure settlement");
    assert_eq!(target_failed.cat.state, Some(CatState::Failure));
    assert_eq!(target_failed.cat.node_id.as_deref(), Some("node-c"));

    let settled = store
        .finish_semantic_cat_recovery(
            SemanticCatRecoverySettlement {
                cat_id: "cat-drain-2",
                source_node_id: "node-a",
                target_node_id: "node-b",
                target_state: CatState::Running,
            },
            SemanticCatRecoveryResult::Recovered,
        )
        .unwrap()
        .expect("successful drain settlement");
    assert_eq!(settled.cat.state, Some(CatState::Running));
    assert_eq!(settled.cat.node_id.as_deref(), Some("node-b"));
    let replayed = store
        .finish_semantic_cat_recovery(
            SemanticCatRecoverySettlement {
                cat_id: "cat-drain-2",
                source_node_id: "node-a",
                target_node_id: "node-b",
                target_state: CatState::Running,
            },
            SemanticCatRecoveryResult::Recovered,
        )
        .unwrap()
        .expect("exact drain settlement replay");
    assert_eq!(replayed.cat, settled.cat);
}

#[test]
fn planned_drain_does_not_replace_an_existing_lifecycle_action() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    create_running_cat(&store, "cat-drain-busy", "drain-busy");
    assert!(matches!(
        store
            .try_begin_semantic_cat_action("cat-drain-busy", CatAction::Suspend, Some("node-a"),)
            .unwrap(),
        BeginCatActionOutcome::Acquired(_)
    ));
    store
        .transition_semantic_node_status("node-a", &[NodeStatus::Running], NodeStatus::Draining)
        .unwrap()
        .unwrap();

    let ClaimSemanticCatRecoveryOutcome::Busy(busy) = store
        .claim_semantic_cat_drain("node-a", "cat-drain-busy")
        .unwrap()
    else {
        panic!("planned drain must not replace a live lifecycle action")
    };
    assert_eq!(busy.cat.current_action, Some(CatAction::Suspend));
    assert_eq!(busy.cat.current_action_node_id.as_deref(), Some("node-a"));

    let current = store
        .find_semantic_cat_by_id("cat-drain-busy")
        .unwrap()
        .expect("busy Cat remains present");
    assert_eq!(current.current_action, Some(CatAction::Suspend));
    assert_eq!(current.current_action_node_id.as_deref(), Some("node-a"));
}

#[test]
fn planned_drain_blocks_on_an_inflight_placement_reserved_before_cordon() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    let admitted = admit_cat(&store, "cat-drain-reserved", "drain-reserved", 2, 1 << 30);
    assert_eq!(admitted.cat.state, None);
    assert_eq!(admitted.cat.current_action, Some(CatAction::Create));
    assert_eq!(
        admitted.cat.current_action_node_id.as_deref(),
        Some("node-a")
    );
    assert_eq!(admitted.cat.node_id, None);

    store
        .transition_semantic_node_status("node-a", &[NodeStatus::Running], NodeStatus::Draining)
        .unwrap()
        .unwrap();

    let candidates = store.list_semantic_node_drain_cats("node-a").unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].cat.cat_id, "cat-drain-reserved");
    assert_eq!(
        store.list_semantic_draining_nodes_with_cats().unwrap(),
        ["node-a"]
    );
    let ClaimSemanticCatRecoveryOutcome::Busy(busy) = store
        .claim_semantic_cat_drain("node-a", "cat-drain-reserved")
        .unwrap()
    else {
        panic!("drain must wait for the placement admitted before cordon")
    };
    assert_eq!(busy.cat.current_action, Some(CatAction::Create));
    assert_eq!(busy.cat.current_action_node_id.as_deref(), Some("node-a"));
}

#[test]
fn concurrent_atomic_creates_reserve_an_even_distribution() {
    let (store, url) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    let barrier = Arc::new(Barrier::new(9));
    let stores = (0..8)
        .map(|_| Store::connect(&url, None).unwrap())
        .collect::<Vec<_>>();
    let handles = stores
        .into_iter()
        .enumerate()
        .map(|(index, store)| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let cat_id = format!("cat-concurrent-{index}");
                let slug = format!("concurrent-{index}");
                barrier.wait();
                admit_cat(&store, &cat_id, &slug, 2, 1 << 30)
                    .cat
                    .current_action_node_id
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let mut placements = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    placements.sort_unstable();

    assert_eq!(placements[..4], ["node-a"; 4]);
    assert_eq!(placements[4..], ["node-b"; 4]);
}

#[test]
fn ingress_publish_and_withdraw_are_scenario_idempotent() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);

    let CreateCatOutcome::Created(created) = store
        .create_semantic_cat(NewCat {
            cat_id: "cat-ingress",
            workspace_id: "ws_semantic",
            cat_slug: "ingress",
            node_id: "node-a",
            cpu_count: 2,
            memory_bytes: 1 << 30,
            boot_image: "sha256:image",
        })
        .unwrap()
    else {
        panic!("new semantic Cat must be created")
    };
    assert_eq!(created.current_action, Some(CatAction::Create));

    let PublishCatIngressOutcome::Published(target) = store
        .publish_semantic_cat_ingress("cat-ingress", "node-a")
        .unwrap()
    else {
        panic!("Ready create target must publish")
    };
    assert_eq!(target.node_id, "node-a");
    assert!(matches!(
        store
            .publish_semantic_cat_ingress("cat-ingress", "node-a")
            .unwrap(),
        PublishCatIngressOutcome::AlreadyPublished(CatIngressTargetRecord { node_id, .. })
            if node_id == "node-a"
    ));
    assert!(matches!(
        store
            .publish_semantic_cat_ingress("cat-ingress", "node-b")
            .unwrap(),
        PublishCatIngressOutcome::Conflict(CatIngressTargetRecord { node_id, .. })
            if node_id == "node-a"
    ));
    assert!(matches!(
        store
            .withdraw_semantic_cat_ingress("cat-ingress", "node-b")
            .unwrap(),
        WithdrawCatIngressOutcome::Conflict(CatIngressTargetRecord { node_id, .. })
            if node_id == "node-a"
    ));
    assert_eq!(
        store
            .resolve_semantic_cat_ingress("cat-ingress")
            .unwrap()
            .unwrap()
            .node_id,
        "node-a"
    );

    store
        .finish_semantic_cat_action(
            "cat-ingress",
            FinishCatAction {
                expected_action: CatAction::Create,
                expected_node_id: Some("node-a"),
                final_state: CatState::Running,
                final_node_id: Some("node-a"),
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .withdraw_semantic_cat_ingress("cat-ingress", "node-a")
            .unwrap(),
        WithdrawCatIngressOutcome::CatNotWithdrawing
    );
    assert!(matches!(
        store
            .try_begin_semantic_cat_action("cat-ingress", CatAction::Suspend, Some("node-a"),)
            .unwrap(),
        BeginCatActionOutcome::Acquired(_)
    ));
    assert_eq!(
        store
            .withdraw_semantic_cat_ingress("cat-ingress", "node-a")
            .unwrap(),
        WithdrawCatIngressOutcome::Withdrawn
    );
    assert_eq!(
        store
            .withdraw_semantic_cat_ingress("cat-ingress", "node-a")
            .unwrap(),
        WithdrawCatIngressOutcome::AlreadyWithdrawn
    );
    assert!(store
        .resolve_semantic_cat_ingress("cat-ingress")
        .unwrap()
        .is_none());

    store
        .finish_semantic_cat_action(
            "cat-ingress",
            FinishCatAction {
                expected_action: CatAction::Suspend,
                expected_node_id: Some("node-a"),
                final_state: CatState::Suspended,
                final_node_id: Some("node-a"),
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        store
            .try_begin_semantic_cat_action("cat-ingress", CatAction::Run, Some("node-a"))
            .unwrap(),
        BeginCatActionOutcome::Acquired(_)
    ));
    store
        .finish_semantic_cat_action(
            "cat-ingress",
            FinishCatAction {
                expected_action: CatAction::Run,
                expected_node_id: Some("node-a"),
                final_state: CatState::Running,
                final_node_id: Some("node-a"),
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap();
    // A response-loss retry may publish after the Running settlement.
    assert!(matches!(
        store
            .publish_semantic_cat_ingress("cat-ingress", "node-a")
            .unwrap(),
        PublishCatIngressOutcome::Published(_)
    ));
}

#[test]
fn ingress_publish_rejects_a_cat_that_is_not_ready_for_that_node() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    create_running_cat(&store, "cat-ready-ingress", "ready-ingress");

    assert!(matches!(
        store
            .publish_semantic_cat_ingress("cat-ready-ingress", "node-b")
            .unwrap(),
        PublishCatIngressOutcome::CatNotReady
    ));
    assert!(matches!(
        store
            .publish_semantic_cat_ingress("cat-missing", "node-a")
            .unwrap(),
        PublishCatIngressOutcome::CatNotFound
    ));
    assert!(matches!(
        store
            .withdraw_semantic_cat_ingress("cat-missing", "node-a")
            .unwrap(),
        WithdrawCatIngressOutcome::CatNotFound
    ));

    let CreateCatOutcome::Created(_) = store
        .create_semantic_cat(NewCat {
            cat_id: "cat-offline-target",
            workspace_id: "ws_semantic",
            cat_slug: "offline-target",
            node_id: "node-b",
            cpu_count: 2,
            memory_bytes: 1 << 30,
            boot_image: "sha256:image",
        })
        .unwrap()
    else {
        panic!("new semantic Cat must be created")
    };
    store
        .transition_semantic_node_status("node-b", &[NodeStatus::Running], NodeStatus::Offline)
        .unwrap()
        .unwrap();
    assert!(matches!(
        store
            .publish_semantic_cat_ingress("cat-offline-target", "node-b")
            .unwrap(),
        PublishCatIngressOutcome::NodeNotRunning
    ));

    assert!(matches!(
        store
            .publish_semantic_cat_ingress("cat-ready-ingress", "node-a")
            .unwrap(),
        PublishCatIngressOutcome::Published(_)
    ));
    store
        .transition_semantic_node_status("node-a", &[NodeStatus::Running], NodeStatus::Offline)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .withdraw_semantic_cat_ingress("cat-ready-ingress", "node-a")
            .unwrap(),
        WithdrawCatIngressOutcome::Withdrawn
    );
}

#[test]
fn concurrent_ingress_publication_has_one_current_target() {
    let (store, url) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    let CreateCatOutcome::Created(_) = store
        .create_semantic_cat(NewCat {
            cat_id: "cat-ingress-race",
            workspace_id: "ws_semantic",
            cat_slug: "ingress-race",
            node_id: "node-a",
            cpu_count: 2,
            memory_bytes: 1 << 30,
            boot_image: "sha256:image",
        })
        .unwrap()
    else {
        panic!("new semantic Cat must be created")
    };

    let start = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for node_id in ["node-a", "node-b"] {
        let url = url.clone();
        let start = Arc::clone(&start);
        threads.push(std::thread::spawn(move || {
            let store = Store::connect(&url, None).unwrap();
            start.wait();
            store
                .publish_semantic_cat_ingress("cat-ingress-race", node_id)
                .unwrap()
        }));
    }
    start.wait();
    let outcomes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PublishCatIngressOutcome::Published(_)))
            .count(),
        1
    );
    assert_eq!(
        store
            .resolve_semantic_cat_ingress("cat-ingress-race")
            .unwrap()
            .unwrap()
            .node_id,
        "node-a"
    );
}

#[test]
fn destroyed_cat_releases_slug_without_changing_historical_identity() {
    let (store, _) = store_and_url();
    register_node(&store);
    create_running_cat(&store, "cat-old", "web");

    assert!(matches!(
        store
            .try_begin_semantic_cat_action("cat-old", CatAction::Destroy, Some("node-a"))
            .unwrap(),
        BeginCatActionOutcome::Acquired(_)
    ));
    let destroyed = store
        .finish_semantic_cat_action(
            "cat-old",
            FinishCatAction {
                expected_action: CatAction::Destroy,
                expected_node_id: Some("node-a"),
                final_state: CatState::Destroyed,
                final_node_id: None,
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(destroyed.state, Some(CatState::Destroyed));
    assert!(store
        .find_current_semantic_cat("ws_semantic", "web")
        .unwrap()
        .is_none());

    let replacement = NewCat {
        cat_id: "cat-new",
        workspace_id: "ws_semantic",
        cat_slug: "web",
        node_id: "node-a",
        cpu_count: 4,
        memory_bytes: 2 << 30,
        boot_image: "sha256:new-image",
    };
    assert!(matches!(
        store.create_semantic_cat(replacement).unwrap(),
        CreateCatOutcome::Created(CatRecord { cat_id, .. }) if cat_id == "cat-new"
    ));
    assert_eq!(
        store
            .find_semantic_cat_by_id("cat-old")
            .unwrap()
            .unwrap()
            .state,
        Some(CatState::Destroyed)
    );
}

#[test]
fn cat_action_claim_is_one_winner_across_store_connections() {
    let (store, url) = store_and_url();
    register_node(&store);
    create_running_cat(&store, "cat-race", "race");

    let start = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let url = url.clone();
        let start = Arc::clone(&start);
        threads.push(std::thread::spawn(move || {
            let store = Store::connect(&url, None).unwrap();
            start.wait();
            store
                .try_begin_semantic_cat_action("cat-race", CatAction::Suspend, Some("node-a"))
                .unwrap()
        }));
    }
    start.wait();
    let outcomes: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, BeginCatActionOutcome::Acquired(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, BeginCatActionOutcome::SameActionInProgress(_)))
            .count(),
        1
    );

    assert!(matches!(
        store
            .try_begin_semantic_cat_action("cat-race", CatAction::Cold, Some("node-a"))
            .unwrap(),
        BeginCatActionOutcome::Busy(_)
    ));
}

#[test]
fn heartbeat_uses_database_receipt_time_and_cannot_mutate_control_endpoint() {
    let (store, _) = store_and_url();
    register_node(&store);
    let heartbeat = NodeHeartbeat {
        node_id: "node-a",
        node_reported_at: Some(1),
        reported_status: NodeStatus::Running,
        total_cpu: 8,
        cpu_utilized: 2.5,
        total_memory: 16 << 30,
        memory_utilized: 3 << 30,
        running_cat_count: 2,
        suspended_cat_count: 1,
        warm_cat_count: 0,
    };
    let (status, recorded) = store.record_semantic_node_heartbeat(heartbeat).unwrap();
    assert_eq!(status, NodeStatus::Running);
    assert_eq!(recorded.node_reported_at, Some(1));
    assert!(recorded.last_heartbeat_at > 1_000_000_000_000);
    assert_eq!(
        store
            .find_semantic_node("node-a")
            .unwrap()
            .unwrap()
            .control_endpoint,
        "http://10.0.0.1:8443"
    );

    assert!(matches!(
        store
            .register_semantic_node(registration("node-a", "http://10.0.0.2:8443"))
            .unwrap(),
        RegisterNodeOutcome::RegistrationUpdated(NodeRecord { control_endpoint, .. })
            if control_endpoint == "http://10.0.0.2:8443"
    ));
    let mut conflicting = registration("node-a", "http://10.0.0.3:8443");
    conflicting.node_name = "renamed-by-heartbeat";
    assert!(matches!(
        store.register_semantic_node(conflicting).unwrap(),
        RegisterNodeOutcome::IdentityConflict(_)
    ));
}

#[test]
fn persistent_disk_is_rwo_and_slug_is_reusable_after_delete() {
    let (store, _) = store_and_url();
    register_node(&store);
    create_running_cat(&store, "cat-disk", "disk-owner");
    assert!(matches!(
        store
            .try_begin_semantic_cat_action("cat-disk", CatAction::Cold, Some("node-a"))
            .unwrap(),
        BeginCatActionOutcome::Acquired(_)
    ));
    store
        .finish_semantic_cat_action(
            "cat-disk",
            FinishCatAction {
                expected_action: CatAction::Cold,
                expected_node_id: Some("node-a"),
                final_state: CatState::Cold,
                final_node_id: None,
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .unwrap();

    let disk = NewPersistentDisk {
        disk_id: "disk-old",
        workspace_id: "ws_semantic",
        disk_slug: "data",
        size_bytes: 100 << 30,
        volume_id: "vol-old",
        filesystem_uuid: "11111111111111111111111111111111",
        disk_format: "ext4",
    };
    assert!(matches!(
        store.create_semantic_persistent_disk(disk).unwrap(),
        CreatePersistentDiskOutcome::Created(_)
    ));
    store
        .complete_semantic_persistent_disk_create(
            "disk-old",
            "vol-old",
            "11111111111111111111111111111111",
            100 << 30,
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        store
            .attach_semantic_disk("binding-a", "cat-disk", "disk-old", "/data")
            .unwrap(),
        AttachDiskOutcome::Attached(_)
    ));
    assert_eq!(
        store.delete_semantic_persistent_disk("disk-old").unwrap(),
        DeletePersistentDiskOutcome::Attached
    );
    assert_eq!(
        store.detach_semantic_disk("cat-disk", "disk-old").unwrap(),
        DetachDiskOutcome::Detached
    );
    assert!(matches!(
        store.delete_semantic_persistent_disk("disk-old").unwrap(),
        DeletePersistentDiskOutcome::Deleting(_)
    ));
    store
        .complete_semantic_persistent_disk_delete("disk-old", "vol-old")
        .unwrap()
        .unwrap();
    let replacement = NewPersistentDisk {
        disk_id: "disk-new",
        workspace_id: "ws_semantic",
        disk_slug: "data",
        size_bytes: 200 << 30,
        volume_id: "vol-new",
        filesystem_uuid: "22222222222222222222222222222222",
        disk_format: "ext4",
    };
    assert!(matches!(
        store.create_semantic_persistent_disk(replacement).unwrap(),
        CreatePersistentDiskOutcome::Created(PersistentDiskRecord { disk_id, .. })
            if disk_id == "disk-new"
    ));
}

#[test]
fn atomic_create_persists_full_mount_config_and_retries_by_semantics() {
    let (store, _) = store_and_url();
    register_node(&store);
    assert!(matches!(
        store
            .create_semantic_persistent_disk(NewPersistentDisk {
                disk_id: "disk-atomic",
                workspace_id: "ws_semantic",
                disk_slug: "data",
                size_bytes: 100 << 30,
                volume_id: "vol-atomic",
                filesystem_uuid: "33333333333333333333333333333333",
                disk_format: "ext4",
            })
            .unwrap(),
        CreatePersistentDiskOutcome::Created(_)
    ));
    store
        .complete_semantic_persistent_disk_create(
            "disk-atomic",
            "vol-atomic",
            "33333333333333333333333333333333",
            100 << 30,
        )
        .unwrap()
        .unwrap();

    let mounts = [NewCatMount {
        binding_id: "binding-atomic",
        disk_id: "disk-atomic",
        mount_path: "/data",
    }];
    let request = AtomicCatCreate {
        cat_id: "cat-atomic",
        workspace_id: "ws_semantic",
        cat_slug: "atomic",
        cpu_count: 2,
        memory_bytes: 1 << 30,
        boot_image: "sha256:image",
        mounts: &mounts,
    };
    let AdmitCatCreateOutcome::Created(created) =
        store.admit_semantic_cat_create(request.clone()).unwrap()
    else {
        panic!("first atomic create must win")
    };
    assert_eq!(created.mounts.len(), 1);
    assert_eq!(created.mounts[0].disk_id, "disk-atomic");
    assert_eq!(created.mounts[0].disk_slug, "data");

    let retry_mounts = [NewCatMount {
        binding_id: "binding-retry-is-ignored",
        disk_id: "disk-atomic",
        mount_path: "/data",
    }];
    assert!(matches!(
        store
            .admit_semantic_cat_create(AtomicCatCreate {
                cat_id: "cat-retry-is-ignored",
                mounts: &retry_mounts,
                ..request.clone()
            })
            .unwrap(),
        AdmitCatCreateOutcome::SameAction(CatWithMounts { cat, .. })
            if cat.cat_id == "cat-atomic"
    ));
    assert!(matches!(
        store
            .admit_semantic_cat_create(AtomicCatCreate {
                cat_id: "cat-conflict",
                cpu_count: 4,
                mounts: &retry_mounts,
                ..request
            })
            .unwrap(),
        AdmitCatCreateOutcome::ConfigurationConflict(_)
    ));
}

#[test]
fn rejected_atomic_mount_rolls_back_cat_and_binding_together() {
    let (store, _) = store_and_url();
    register_node(&store);
    let missing = [NewCatMount {
        binding_id: "binding-missing",
        disk_id: "disk-missing",
        mount_path: "/data",
    }];
    assert!(matches!(
        store
            .admit_semantic_cat_create(AtomicCatCreate {
                cat_id: "cat-rollback",
                workspace_id: "ws_semantic",
                cat_slug: "rollback",
                cpu_count: 2,
                memory_bytes: 1 << 30,
                boot_image: "sha256:image",
                mounts: &missing,
            })
            .unwrap(),
        AdmitCatCreateOutcome::MountRejected { code, .. } if code == "disk_not_found"
    ));
    assert!(store
        .find_current_semantic_cat("ws_semantic", "rollback")
        .unwrap()
        .is_none());
    assert!(store
        .list_semantic_disk_bindings("cat-rollback")
        .unwrap()
        .is_empty());
}

#[test]
fn registration_starts_liveness_clock_and_offline_cas_rejects_racing_heartbeat() {
    let (store, _) = store_and_url();
    register_node(&store);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let candidate = store
        .list_stale_semantic_nodes(1)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.node_id == "node-a")
        .expect("registration heartbeat must age into stale detection");

    store
        .record_semantic_node_heartbeat(NodeHeartbeat {
            node_id: "node-a",
            node_reported_at: Some(1),
            reported_status: NodeStatus::Running,
            total_cpu: 8,
            cpu_utilized: 1.0,
            total_memory: 16 << 30,
            memory_utilized: 2 << 30,
            running_cat_count: 0,
            suspended_cat_count: 0,
            warm_cat_count: 0,
        })
        .unwrap();
    assert!(!store
        .mark_semantic_node_offline_if_heartbeat_unchanged(&candidate)
        .unwrap());
    assert_eq!(
        store.find_semantic_node("node-a").unwrap().unwrap().status,
        NodeStatus::Running
    );

    std::thread::sleep(std::time::Duration::from_millis(5));
    let fresh = store
        .list_stale_semantic_nodes(1)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.node_id == "node-a")
        .expect("fresh heartbeat eventually becomes stale");
    assert!(store
        .mark_semantic_node_offline_if_heartbeat_unchanged(&fresh)
        .unwrap());
    assert_eq!(
        store.find_semantic_node("node-a").unwrap().unwrap().status,
        NodeStatus::Offline
    );
}

#[test]
fn completed_node_reset_stays_closed_until_current_cats_are_recovered() {
    let (store, _) = store_and_url();
    register_node(&store);
    register_second_node(&store);
    create_running_cat(&store, "cat-reset-recovery", "reset-recovery");

    let mut completed = registration("node-a", "http://10.0.0.1:8443");
    completed.reset_completed = true;
    assert!(matches!(
        store.register_semantic_node(completed.clone()).unwrap(),
        RegisterNodeOutcome::ResetRequired(NodeRecord {
            status: NodeStatus::ResetRequired,
            ..
        })
    ));

    let ClaimSemanticCatRecoveryOutcome::Claimed(claim) = store
        .claim_semantic_cat_recovery("node-a", "cat-reset-recovery")
        .unwrap()
    else {
        panic!("reset Node Cat must receive a recovery claim")
    };
    assert_eq!(claim.target_node_id, "node-b");
    store
        .finish_semantic_cat_recovery(
            SemanticCatRecoverySettlement {
                cat_id: "cat-reset-recovery",
                source_node_id: "node-a",
                target_node_id: "node-b",
                target_state: CatState::Running,
            },
            SemanticCatRecoveryResult::Recovered,
        )
        .unwrap()
        .expect("settle recovered Cat away from reset Node");

    assert!(matches!(
        store.register_semantic_node(completed).unwrap(),
        RegisterNodeOutcome::RegistrationUpdated(NodeRecord {
            status: NodeStatus::Running,
            ..
        })
    ));
}

#[test]
fn completed_node_reset_reopens_when_only_failed_cats_remain() {
    let (store, _) = store_and_url();
    register_node(&store);
    let CreateCatOutcome::Created(created) = store
        .create_semantic_cat(NewCat {
            cat_id: "cat-reset-failure",
            workspace_id: "ws_semantic",
            cat_slug: "reset-failure",
            node_id: "node-a",
            cpu_count: 2,
            memory_bytes: 1 << 30,
            boot_image: "sha256:image",
        })
        .unwrap()
    else {
        panic!("new semantic Cat must be created")
    };
    assert_eq!(created.current_action, Some(CatAction::Create));
    let failed = store
        .finish_semantic_cat_action(
            "cat-reset-failure",
            FinishCatAction {
                expected_action: CatAction::Create,
                expected_node_id: Some("node-a"),
                final_state: CatState::Failure,
                final_node_id: Some("node-a"),
                error_code: Some("image_unavailable"),
                error_message: Some("image unavailable"),
            },
        )
        .unwrap()
        .expect("settle failed Cat on its selected Node");
    assert_eq!(failed.state, Some(CatState::Failure));

    let mut completed = registration("node-a", "http://10.0.0.1:8443");
    completed.reset_completed = true;
    assert!(matches!(
        store.register_semantic_node(completed).unwrap(),
        RegisterNodeOutcome::RegistrationUpdated(NodeRecord {
            status: NodeStatus::Running,
            ..
        })
    ));
    let retained = store
        .find_semantic_cat_by_id("cat-reset-failure")
        .unwrap()
        .expect("failed Cat remains available for explicit destroy");
    assert_eq!(retained.state, Some(CatState::Failure));
    assert_eq!(retained.node_id.as_deref(), Some("node-a"));
}

#[test]
fn offline_recovery_claim_replaces_old_lane_and_exactly_moves_placement() {
    let (store, _) = store_and_url();
    register_node(&store);
    assert!(matches!(
        store
            .register_semantic_node(NodeRegistration {
                node_id: "node-b",
                node_name: "worker-b",
                control_endpoint: "http://10.0.0.2:8443",
                vendor: "aws",
                region: "us-east-1",
                zone: "us-east-1b",
                instance_id: "i-semantic-b",
                machine_type: "m7i.large",
                node_version: "1.0.0",
                reset_completed: false,
            })
            .unwrap(),
        RegisterNodeOutcome::Registered(_)
    ));
    create_running_cat(&store, "cat-recovery", "recovery");

    assert!(matches!(
        store
            .try_begin_semantic_cat_action("cat-recovery", CatAction::Cold, Some("node-a"))
            .unwrap(),
        BeginCatActionOutcome::Acquired(_)
    ));
    assert!(store
        .transition_semantic_node_status("node-a", &[NodeStatus::Running], NodeStatus::Offline,)
        .unwrap()
        .is_some());

    let ClaimSemanticCatRecoveryOutcome::Claimed(claim) = store
        .claim_semantic_cat_recovery("node-a", "cat-recovery")
        .unwrap()
    else {
        panic!("offline Cat must receive one recovery claim")
    };
    assert_eq!(claim.target_state, CatState::Running);
    assert_eq!(claim.target_node_id, "node-b");
    assert_eq!(claim.cat.cat.node_id.as_deref(), Some("node-a"));
    assert_eq!(claim.cat.cat.current_action, Some(CatAction::Run));
    assert_eq!(
        claim.cat.cat.current_action_node_id.as_deref(),
        Some("node-b")
    );

    assert!(matches!(
        store
            .claim_semantic_cat_recovery("node-a", "cat-recovery")
            .unwrap(),
        ClaimSemanticCatRecoveryOutcome::AlreadyClaimed(retry)
            if retry.target_node_id == "node-b"
    ));
    assert!(store
        .finish_semantic_cat_action(
            "cat-recovery",
            FinishCatAction {
                expected_action: CatAction::Cold,
                expected_node_id: Some("node-a"),
                final_state: CatState::Cold,
                final_node_id: None,
                error_code: None,
                error_message: None,
            },
        )
        .unwrap()
        .is_none());

    let recovered = store
        .finish_semantic_cat_recovery(
            SemanticCatRecoverySettlement {
                cat_id: "cat-recovery",
                source_node_id: "node-a",
                target_node_id: "node-b",
                target_state: CatState::Running,
            },
            SemanticCatRecoveryResult::Recovered,
        )
        .unwrap()
        .expect("exact recovery claim must settle");
    assert_eq!(recovered.cat.state, Some(CatState::Running));
    assert_eq!(recovered.cat.node_id.as_deref(), Some("node-b"));
    assert_eq!(recovered.cat.current_action, None);

    assert!(store
        .finish_semantic_cat_recovery(
            SemanticCatRecoverySettlement {
                cat_id: "cat-recovery",
                source_node_id: "node-a",
                target_node_id: "node-b",
                target_state: CatState::Running,
            },
            SemanticCatRecoveryResult::Recovered,
        )
        .unwrap()
        .is_none());
}

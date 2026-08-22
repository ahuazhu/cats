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
    NodeRegistration {
        node_id,
        node_name: "worker-a",
        control_endpoint: endpoint,
        vendor: "aws",
        region: "us-east-1",
        zone: "us-east-1a",
        instance_id: "i-semantic-a",
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
    };
    assert!(matches!(
        store.create_semantic_persistent_disk(disk).unwrap(),
        CreatePersistentDiskOutcome::Created(_)
    ));
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
        DeletePersistentDiskOutcome::Deleted(_)
    ));
    let replacement = NewPersistentDisk {
        disk_id: "disk-new",
        workspace_id: "ws_semantic",
        disk_slug: "data",
        size_bytes: 200 << 30,
    };
    assert!(matches!(
        store.create_semantic_persistent_disk(replacement).unwrap(),
        CreatePersistentDiskOutcome::Created(PersistentDiskRecord { disk_id, .. })
            if disk_id == "disk-new"
    ));
}

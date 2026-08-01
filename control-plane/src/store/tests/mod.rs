use super::*;
use cats_api::guest::GuestWorkLease;
use cats_api::requests::NodeWorkStatusRequest;
use std::sync::Arc;

/// Seed one configured Account and return its default Workspace.
fn bootstrap_workspace(store: &Store, account_slug: &str) -> WorkspaceRecord {
    store
        .ensure_configured_accounts(&BTreeMap::from([(
            account_slug.to_string(),
            format!("org_{account_slug}"),
        )]))
        .unwrap();
    let account = store
        .account_for_organization(&format!("org_{account_slug}"))
        .unwrap()
        .unwrap();
    default_workspace_for_account_id(store, &account.id)
}

fn default_workspace_for_account_id(store: &Store, account_id: &str) -> WorkspaceRecord {
    store
        .workspaces_for_account(account_id)
        .unwrap()
        .into_iter()
        .find(|workspace| workspace.is_default)
        .unwrap()
}

#[test]
fn workspaces_in_one_account_share_its_billing_account() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let mappings = BTreeMap::from([
        ("acme".to_string(), "org_acme".to_string()),
        ("other".to_string(), "org_other".to_string()),
    ]);
    store.ensure_configured_accounts(&mappings).unwrap();
    store.ensure_configured_accounts(&mappings).unwrap();

    let acme = store.account_for_organization("org_acme").unwrap().unwrap();
    let other = store
        .account_for_organization("org_other")
        .unwrap()
        .unwrap();
    let default = default_workspace_for_account_id(&store, &acme.id);
    let sibling = store
        .create_workspace(&acme.id, "sibling", "Sibling")
        .unwrap();
    let other_default = default_workspace_for_account_id(&store, &other.id);
    assert_eq!(default.account_id, sibling.account_id);
    assert_ne!(default.account_id, other_default.account_id);
    assert!(default.is_default);
    assert!(!sibling.is_default);
    assert_eq!(
        store.billing_account_id_for_workspace(&default.id).unwrap(),
        store.billing_account_id_for_workspace(&sibling.id).unwrap()
    );
    assert!(store
        .billing_account_id_for_workspace(&default.id)
        .unwrap()
        .starts_with("billing_account/account/"));
    assert_ne!(
        store.billing_account_id_for_workspace(&default.id).unwrap(),
        store
            .billing_account_id_for_workspace(&other_default.id)
            .unwrap()
    );
    assert_eq!(
        store.workspaces_for_account(&acme.id).unwrap().len(),
        2,
        "re-running account seeding must not add a second default workspace"
    );
}
#[test]
fn renaming_a_workspace_keeps_resource_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let default = bootstrap_workspace(&store, "acme");
    let sibling = store
        .create_workspace(&default.account_id, "sibling", "Sibling")
        .unwrap();

    let (cat, disks, operation) = store
        .create_cat(
            &default,
            "stable-owner",
            "test",
            1,
            256,
            1 << 20,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    let renamed = store
        .update_workspace(&default.id, Some("renamed"), None)
        .unwrap();
    assert_eq!(renamed.id, default.id);
    assert_eq!(renamed.slug, "renamed");
    assert_eq!(
        store.get_cat(&default.id, &cat.id).unwrap().workspace_id,
        default.id
    );
    assert!(disks.iter().all(|disk| disk.workspace_id == default.id));
    assert_eq!(operation.workspace_id, default.id);
    assert!(
        store
            .with(|conn| {
                conn.execute(
                    "UPDATE cats SET workspace_id=?2 WHERE id=?1",
                    params![cat.id, sibling.id],
                )
                .map(|_| ())
            })
            .is_err(),
        "a Cat must not be movable between workspaces"
    );
}

#[test]
fn the_same_name_is_free_in_a_second_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let default = bootstrap_workspace(&store, "acme");
    let sibling = store
        .create_workspace(&default.account_id, "sibling", "Sibling")
        .unwrap();
    store
        .create_cat(
            &default,
            "shared",
            "test",
            1,
            256,
            1 << 20,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    store
        .create_cat(
            &sibling,
            "shared",
            "test",
            1,
            256,
            1 << 20,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    assert!(store
        .create_cat(
            &default,
            "shared",
            "test",
            1,
            256,
            1 << 20,
            true,
            None,
            None,
            DiskDurability::Strict
        )
        .is_err());
    assert_eq!(store.list_cats(&default.id).unwrap().len(), 1);
    assert_eq!(store.list_cats(&sibling.id).unwrap().len(), 1);
}

#[test]
fn migrates_a_v1_database_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    let cat_id = {
        let store = Store::open(&path).unwrap();
        let workspace = bootstrap_workspace(&store, "acme");
        let (cat, _, _) = store
            .create_cat(
                &workspace,
                "web",
                "test",
                1,
                256,
                1 << 20,
                true,
                None,
                None,
                DiskDurability::Strict,
            )
            .unwrap();
        cat.id
    };
    {
        // Reshape the file into the v1 schema: no expiry column, no disk
        // durability column, stamp 1.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("ALTER TABLE cats DROP COLUMN expires_at_unix")
            .unwrap();
        conn.execute_batch("ALTER TABLE disks DROP COLUMN durability")
            .unwrap();
        conn.pragma_update(None, "user_version", 1_i64).unwrap();
    }

    let store = Store::open(&path).unwrap();
    let cat = store.must_get_cat_by_id(&cat_id).unwrap();
    assert_eq!(
        cat.expires_at_unix, None,
        "v1 rows surface as never-expiring"
    );
    let disks = store.list_disks_for_cat(&cat_id).unwrap();
    assert!(
        disks.iter().all(|d| d.durability == DiskDurability::Strict),
        "v1 disks keep the semantics they were created under"
    );
    {
        let conn = Connection::open(&path).unwrap();
        let stamped: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stamped, SCHEMA_VERSION);
    }
    // The migrated column is writable like a natively-v2 one.
    store.set_expiry(&cat_id, Some(12345)).unwrap();
    assert_eq!(
        store.must_get_cat_by_id(&cat_id).unwrap().expires_at_unix,
        Some(12345)
    );
}

#[test]
fn an_idempotency_record_outlives_the_cat_it_created() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let workspace = bootstrap_workspace(&store, "acme");

    let (cat, _, op) = store
        .create_cat(
            &workspace,
            "web",
            "ubuntu-24.04",
            1,
            512,
            1 << 30,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    let route = "POST /cats acme/web";
    store.idempotency_store("k1", route, &op.id).unwrap();

    store.delete_cat_row(&cat.id).unwrap();

    // The record still resolves to an operation, but its cat is gone — the
    // state that used to make a replay answer 404 for good.
    let op_id = store.idempotency_lookup("k1", route).unwrap().unwrap();
    let stale = store.find_operation(&op_id).unwrap().unwrap();
    assert!(store.find_cat_by_id(&stale.resource_id).unwrap().is_none());

    store.idempotency_forget("k1", route).unwrap();
    assert!(store.idempotency_lookup("k1", route).unwrap().is_none());
}

#[test]
fn absolute_expiry_selects_only_due_undeleted_cats() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let workspace = bootstrap_workspace(&store, "acme");
    let past = now_unix() - 60;
    let future = now_unix() + 3600;

    let (expired, _, _) = store
        .create_cat(
            &workspace,
            "expired",
            "test",
            1,
            256,
            1 << 20,
            true,
            None,
            Some(past),
            DiskDurability::Strict,
        )
        .unwrap();
    let (fresh, _, _) = store
        .create_cat(
            &workspace,
            "fresh",
            "test",
            1,
            256,
            1 << 20,
            true,
            None,
            Some(future),
            DiskDurability::Strict,
        )
        .unwrap();
    let (forever, _, _) = store
        .create_cat(
            &workspace,
            "forever",
            "test",
            1,
            256,
            1 << 20,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    assert_eq!(expired.expires_at_unix, Some(past));

    assert_eq!(
        store.expired_cat_candidates().unwrap(),
        vec![expired.id.clone()]
    );

    // Renewal takes the Cat out of the reap set; clearing does too.
    store.set_expiry(&expired.id, Some(future)).unwrap();
    assert!(store.expired_cat_candidates().unwrap().is_empty());
    store.set_expiry(&expired.id, Some(past)).unwrap();
    store.set_expiry(&fresh.id, None).unwrap();
    assert_eq!(
        store.expired_cat_candidates().unwrap(),
        vec![expired.id.clone()]
    );

    // A Cat already converging to Deleted is not re-deleted every tick.
    store
        .set_desired(&expired.id, DesiredState::Deleted, None, "cat.expire")
        .unwrap();
    assert!(store.expired_cat_candidates().unwrap().is_empty());
    let _ = forever;
}

#[test]
fn workspace_tokens_resolve_only_while_active() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("control.db")).unwrap();
    let workspace = bootstrap_workspace(&store, "automation");
    let token = store
        .create_workspace_token(&workspace.id, "CI preview", "sha256-example")
        .unwrap();

    assert_eq!(
        store
            .active_workspace_for_token_hash("sha256-example")
            .unwrap(),
        Some(workspace.id.clone())
    );
    assert_eq!(
        store.workspace_tokens(&workspace.id).unwrap(),
        vec![token.clone()]
    );

    store
        .revoke_workspace_token(&workspace.id, &token.id)
        .unwrap();
    assert_eq!(
        store
            .active_workspace_for_token_hash("sha256-example")
            .unwrap(),
        None
    );
    assert!(store.workspace_tokens(&workspace.id).unwrap().is_empty());
}

#[test]
fn concurrent_personal_provision_has_one_identity_and_grant_claim() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("control.db")).unwrap());
    let mut threads = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        threads.push(std::thread::spawn(move || {
            store
                .ensure_personal_account("user_one", "org_personal_one", "one@example.com")
                .unwrap()
        }));
    }
    let rows = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(rows
        .iter()
        .all(|(account, workspace)| account.id == rows[0].0.id && workspace.id == rows[0].1.id));
    let account = &rows[0].0;
    assert_eq!(
        store
            .signup_grant_state("user_one", "signup-2026-10usd", &account.billing_account_id,)
            .unwrap(),
        SignupGrantState::Pending
    );
    store
        .mark_signup_grant_applied("user_one", "signup-2026-10usd", &account.billing_account_id)
        .unwrap();
    assert_eq!(
        store
            .signup_grant_state("user_one", "signup-2026-10usd", &account.billing_account_id,)
            .unwrap(),
        SignupGrantState::Applied
    );
    assert!(store
        .signup_grant_state(
            "user_one",
            "signup-2026-10usd",
            "billing_account/account/another",
        )
        .is_err());
}

#[test]
fn refuses_a_database_stamped_with_another_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    drop(Store::open(&path).unwrap());
    {
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
    }

    let Err(error) = Store::open(&path) else {
        panic!("a database from another schema version must not open");
    };
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(
        error
            .to_string()
            .contains(&format!("requires {SCHEMA_VERSION}")),
        "the operator needs to see the required schema version, got: {error}"
    );
    // A database this build wrote itself keeps opening.
    assert!(Store::open(&dir.path().join("fresh.db")).is_ok());

    // The dev shape points the usage store at the control-plane file. Its
    // tables must not read as a stale control-plane schema.
    let shared = dir.path().join("shared.db");
    {
        let conn = Connection::open(&shared).unwrap();
        conn.execute_batch("CREATE TABLE usage_checkpoints (event_id TEXT PRIMARY KEY);")
            .unwrap();
    }
    assert!(
        Store::open(&shared).is_ok(),
        "a foreign table in the same file is not an old control-plane schema"
    );
}

#[test]
fn every_cat_gets_a_default_public_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = store
        .create_cat(
            &workspace,
            "legacy",
            "ubuntu",
            1,
            512,
            1 << 20,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();

    let endpoints = store.endpoints_for_cat(&cat.id).unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].name, DEFAULT_ENDPOINT_NAME);
    assert_eq!(endpoints[0].target_port, DEFAULT_ENDPOINT_PORT);
    assert!(
        endpoints[0].hostname.ends_with(".cats.run"),
        "the default endpoint must live in the public one-label namespace, got {}",
        endpoints[0].hostname
    );
    assert!(
        endpoints[0].hostname.starts_with("legacy-"),
        "the hostname keeps the Cat name plus an opaque suffix, got {}",
        endpoints[0].hostname
    );
}

#[test]
fn a_cordoned_node_stays_unschedulable_across_a_lost_recovery_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    store
        .register_node("node_a", "http://node", "http://gateway", 4, 8192)
        .unwrap();
    store.set_node_state("node_a", NodeState::Cordoned).unwrap();

    store.set_node_state("node_a", NodeState::Lost).unwrap();
    store
        .register_node("node_a", "http://node-new", "http://gateway", 4, 8192)
        .unwrap();
    assert_eq!(
        store.get_node("node_a").unwrap().state,
        NodeState::Lost,
        "registration alone cannot prove preserved Cat claims are alive"
    );

    let telemetry = NodeTelemetry {
        observed_cats: 2,
        allocated_cpus: 3,
        allocated_memory_mib: 2048,
        ..NodeTelemetry::default()
    };
    store.heartbeat_node("node_a", Some(&telemetry)).unwrap();
    let stored = store.get_node("node_a").unwrap().telemetry.unwrap();
    assert_eq!(stored.observed_cats, 2);
    assert_eq!(stored.allocated_cpus, 3);
    assert_eq!(stored.allocated_memory_mib, 2048);
    assert_eq!(store.get_node("node_a").unwrap().state, NodeState::Lost);
    assert!(store.recover_lost_node("node_a").unwrap());
    assert_eq!(store.get_node("node_a").unwrap().state, NodeState::Cordoned);
}

#[test]
fn a_fenced_node_identity_cannot_reregister_or_heartbeat_back_to_ready() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    store
        .register_node("node_a", "http://node", "http://gateway", 4, 8192)
        .unwrap();
    store.set_node_state("node_a", NodeState::Fenced).unwrap();

    store
        .register_node("node_a", "http://node-new", "http://gateway", 4, 8192)
        .unwrap();
    store.heartbeat_node("node_a", None).unwrap();
    store.set_node_state("node_a", NodeState::Ready).unwrap();
    assert_eq!(store.get_node("node_a").unwrap().state, NodeState::Fenced);
}

#[test]
fn last_guest_work_release_is_immediately_suspend_eligible() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = store
        .create_cat(
            &workspace,
            "worker",
            "test",
            1,
            256,
            1024 * 1024,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    assert!(cat.auto_suspend);
    let endpoints = store.endpoints_for_cat(&cat.id).unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].name, DEFAULT_ENDPOINT_NAME);
    assert_eq!(endpoints[0].target_port, DEFAULT_ENDPOINT_PORT);
    assert!(endpoints[0].hostname.starts_with("worker-"));
    assert!(endpoints[0].hostname.ends_with(".cats.run"));
    let default_id = endpoints[0].id.clone();
    let updated = store
        .create_endpoint(
            &cat,
            DEFAULT_ENDPOINT_NAME,
            3000,
            "http",
            WakePolicy::NoWake,
        )
        .unwrap();
    assert_eq!(updated.id, default_id);
    assert_eq!(updated.target_port, 3000);
    assert_eq!(updated.wake_policy, WakePolicy::NoWake);
    assert_eq!(store.endpoints_for_cat(&cat.id).unwrap().len(), 1);
    let (route, _) = store.resolve_route(&updated.hostname).unwrap();
    assert_eq!(route.target_port, 3000);
    assert_eq!(route.epoch, 1);
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store.set_observed(&cat.id, ObservedState::Running).unwrap();
    let status = |sequence, leases| NodeWorkStatusRequest {
        node_id: "node-1".into(),
        cat_id: cat.id.clone(),
        generation: 1,
        guest_source_epoch: "guest-boot-1".into(),
        guest_lease_sequence: sequence,
        leases,
    };
    store
        .ingest_guest_work(&status(
            1,
            vec![GuestWorkLease {
                id: "lease-1".into(),
                label: "user-job".into(),
                remaining_ttl_ms: 5_000,
            }],
        ))
        .unwrap();
    assert!(store.try_auto_suspend(&cat.id, 5_000).unwrap().is_none());
    assert_eq!(
        store.work_status(&cat.id, 5_000).unwrap().reason,
        "active_work"
    );

    store.ingest_guest_work(&status(2, vec![])).unwrap();
    let operation = store
        .try_auto_suspend(&cat.id, 5_000)
        .unwrap()
        .expect("last release should trigger suspend without an idle timer");
    assert_eq!(operation.kind, "cat.auto_suspend");
    let sleeping = store.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(sleeping.desired_state, DesiredState::Suspended);
    assert_eq!(sleeping.generation, 2);
}

#[test]
fn concurrent_placement_cannot_overcommit_a_node() {
    // Placement used to be a read of the node's free capacity followed by a
    // separate write, which only holds up while one Cat is placed at a time.
    // The reconcile loop now runs flows concurrently, so this is the property
    // that keeps it honest.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("control.db")).unwrap());
    let workspace = bootstrap_workspace(&store, "alpha");
    // Room for exactly 4 of these Cats: 8 cpus / 8192 MiB, 2 cpus each.
    store
        .register_node("node-1", "http://node", "http://gateway", 8, 8192)
        .unwrap();
    let mut ids = Vec::new();
    for n in 0..10 {
        let (cat, _, _) = store
            .create_cat(
                &workspace,
                &format!("web{n}"),
                "test",
                2,
                1024,
                1 << 20,
                true,
                None,
                None,
                DiskDurability::Strict,
            )
            .unwrap();
        ids.push(cat.id);
    }

    let now = now_ms();
    // All ten threads release together, so a read-then-write implementation
    // has the widest possible window to place two Cats in the same slot.
    let gate = std::sync::Barrier::new(ids.len());
    let placed: Vec<Option<Node>> = std::thread::scope(|scope| {
        let handles: Vec<_> = ids
            .iter()
            .map(|id| {
                let store = store.clone();
                let gate = &gate;
                scope.spawn(move || {
                    gate.wait();
                    store.claim_node_for(id, 2, 1024, 60_000, now).unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // 8 cpus / 2 per Cat = 4, and 8192 MiB / 1024 = 8, so cpus binds first.
    let winners = placed.iter().filter(|p| p.is_some()).count();
    assert_eq!(winners, 4, "node was overcommitted or underfilled");
    let on_node = store.cats_on_node("node-1").unwrap();
    assert_eq!(on_node.len(), 4);
    assert_eq!(on_node.iter().map(|c| c.spec.cpus).sum::<u32>(), 8);
    assert!(on_node.iter().map(|c| c.spec.memory_mib).sum::<u64>() <= 8192);
}

#[test]
fn gateway_work_blocks_auto_suspend_and_wake_is_singleflight() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = store
        .create_cat(
            &workspace,
            "web",
            "test",
            1,
            256,
            1024 * 1024,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store.set_observed(&cat.id, ObservedState::Running).unwrap();
    store.set_auto_suspend(&cat.id, true).unwrap();
    store
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 0,
            leases: vec![],
        })
        .unwrap();
    let lease = store
        .acquire_work(&cat.id, WorkKind::Gateway, "request-1", "GET /", 5_000)
        .unwrap();
    assert!(store.try_auto_suspend(&cat.id, 5_000).unwrap().is_none());
    store.release_work(&lease.id).unwrap();
    store.try_auto_suspend(&cat.id, 5_000).unwrap().unwrap();

    let first = store.ensure_desired_running(&cat.id).unwrap();
    let second = store.ensure_desired_running(&cat.id).unwrap();
    assert!(first.is_some());
    assert!(second.is_none());
    assert_eq!(store.must_get_cat_by_id(&cat.id).unwrap().generation, 3);
}

#[test]
fn guest_work_cancels_an_inflight_suspend_without_generation_drift() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("control.db")).unwrap();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = store
        .create_cat(
            &workspace,
            "racer",
            "test",
            1,
            256,
            1024 * 1024,
            true,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store.set_observed(&cat.id, ObservedState::Running).unwrap();
    store.set_auto_suspend(&cat.id, true).unwrap();
    let report = |sequence, leases| NodeWorkStatusRequest {
        node_id: "node-1".into(),
        cat_id: cat.id.clone(),
        generation: 1,
        guest_source_epoch: "guest-boot-1".into(),
        guest_lease_sequence: sequence,
        leases,
    };
    store.ingest_guest_work(&report(0, vec![])).unwrap();
    let auto = store.try_auto_suspend(&cat.id, 5_000).unwrap().unwrap();
    assert_eq!(auto.resource_generation, 2);
    store
        .set_observed(&cat.id, ObservedState::Suspending)
        .unwrap();

    assert!(store
        .ingest_guest_work(&report(
            1,
            vec![GuestWorkLease {
                id: "late-job".into(),
                label: "late-job".into(),
                remaining_ttl_ms: 5_000,
            }],
        ))
        .unwrap());
    store.cancel_rejected_suspend(&cat.id, 2).unwrap();
    let running = store.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(running.desired_state, DesiredState::Running);
    assert_eq!(running.observed_state, ObservedState::Running);
    assert_eq!(running.generation, 2);
    assert_eq!(
        store.get_operation(&auto.id).unwrap().phase,
        OperationPhase::Failed
    );
}

#[test]
fn automatic_deeper_tiers_use_persisted_state_age_and_respect_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    let cat_id;
    {
        let store = Store::open(&path).unwrap();
        let workspace = bootstrap_workspace(&store, "alpha");
        let (cat, _, _) = store
            .create_cat(
                &workspace,
                "sleeper",
                "test",
                1,
                256,
                1024 * 1024,
                true,
                None,
                None,
                DiskDurability::Strict,
            )
            .unwrap();
        cat_id = cat.id.clone();
        let suspend = store
            .set_desired(&cat.id, DesiredState::Suspended, None, "cat.suspend")
            .unwrap();
        store
            .set_observed(&cat.id, ObservedState::Suspended)
            .unwrap();
        store.finish_operation(&suspend.id, None).unwrap();
        store
            .with(|conn| {
                conn.execute(
                    "UPDATE cats SET observed_state_since_ms=?2 WHERE id=?1",
                    params![cat.id, now_ms() - 2_000],
                )
                .map(|_| ())
            })
            .unwrap();

        let candidates = store
            .auto_tier_candidates(Some(1_000), Some(1_000))
            .unwrap();
        assert_eq!(candidates, vec![cat.id.clone()]);
        let warm = store
            .try_auto_tier(&cat.id, Some(1_000), Some(1_000))
            .unwrap()
            .expect("an old Suspended Cat should move toward Warm");
        assert_eq!(warm.kind, "cat.auto_warm");
        assert_eq!(
            store.must_get_cat_by_id(&cat.id).unwrap().desired_state,
            DesiredState::Warm
        );
        store.set_observed(&cat.id, ObservedState::Warm).unwrap();
        store.finish_operation(&warm.id, None).unwrap();
        store
            .with(|conn| {
                conn.execute(
                    "UPDATE cats SET observed_state_since_ms=?2 WHERE id=?1",
                    params![cat.id, now_ms() - 2_000],
                )
                .map(|_| ())
            })
            .unwrap();
    }

    // Reopening the control-plane database must not reset the Warm timer.
    let store = Store::open(&path).unwrap();
    let lease = store
        .acquire_work(&cat_id, WorkKind::Gateway, "request-1", "GET /", 5_000)
        .unwrap();
    assert!(store
        .try_auto_tier(&cat_id, Some(1_000), Some(1_000))
        .unwrap()
        .is_none());
    store.release_work(&lease.id).unwrap();
    let cold = store
        .try_auto_tier(&cat_id, Some(1_000), Some(1_000))
        .unwrap()
        .expect("an old inactive Warm Cat should move toward Cold");
    assert_eq!(cold.kind, "cat.auto_cold");
    let cat = store.must_get_cat_by_id(&cat_id).unwrap();
    assert_eq!(cat.desired_state, DesiredState::Cold);
    assert_eq!(cat.observed_state, ObservedState::Warm);
}

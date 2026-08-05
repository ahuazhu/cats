use super::*;
use cats_api::guest::GuestWorkLease;
use cats_api::nodejob::{job_id, NodeJob, NodeJobAction, StopCatDisposition, SuspendWorkFence};
use cats_api::requests::NodeWorkStatusRequest;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct ActiveSingletonGuard {
    active: Arc<AtomicUsize>,
    drop_delay: std::time::Duration,
}

impl Drop for ActiveSingletonGuard {
    fn drop(&mut self) {
        if !self.drop_delay.is_zero() {
            std::thread::sleep(self.drop_delay);
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Fresh store on an isolated schema of the disposable test server.
fn test_store() -> Store {
    Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap()
}

/// Two process-shaped stores sharing one schema. Unlike cloning an `Arc<Store>`,
/// this does not serialize calls through the same in-process connection mutex.
fn test_store_pair() -> (Store, Store) {
    let url = crate::testsupport::isolated_control_store_url();
    (
        Store::connect(&url, None).unwrap(),
        Store::connect(&url, None).unwrap(),
    )
}

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

/// The Cat shape these tests use unless the test is itself about a different
/// spec: 1 vCPU, 256 MiB, a 1 MiB root disk, auto-suspend on, no extra disk,
/// no expiry, strict durability.
fn create_test_cat(
    store: &Store,
    workspace: &WorkspaceRecord,
    name: &str,
) -> Result<(Cat, Vec<Disk>, Operation)> {
    create_test_cat_expiring(store, workspace, name, None)
}

fn create_test_cat_expiring(
    store: &Store,
    workspace: &WorkspaceRecord,
    name: &str,
    expires_at_unix: Option<i64>,
) -> Result<(Cat, Vec<Disk>, Operation)> {
    store.create_cat(
        workspace,
        name,
        "test",
        1,
        256,
        1 << 20,
        true,
        None,
        expires_at_unix,
        DiskDurability::Strict,
    )
}

#[test]
fn workspaces_in_one_account_share_its_billing_account() {
    let store = test_store();
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
    let store = test_store();
    let default = bootstrap_workspace(&store, "acme");
    let sibling = store
        .create_workspace(&default.account_id, "sibling", "Sibling")
        .unwrap();

    let (cat, disks, operation) = create_test_cat(&store, &default, "stable-owner").unwrap();
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
            .with(|client| {
                client
                    .execute(
                        "UPDATE cats SET workspace_id=$2 WHERE id=$1",
                        &[&cat.id, &sibling.id],
                    )
                    .map(|_| ())
            })
            .is_err(),
        "a Cat must not be movable between workspaces"
    );
}

#[test]
fn the_same_name_is_free_in_a_second_workspace() {
    let store = test_store();
    let default = bootstrap_workspace(&store, "acme");
    let sibling = store
        .create_workspace(&default.account_id, "sibling", "Sibling")
        .unwrap();
    create_test_cat(&store, &default, "shared").unwrap();
    create_test_cat(&store, &sibling, "shared").unwrap();
    assert!(create_test_cat(&store, &default, "shared").is_err());
    assert_eq!(store.list_cats(&default.id).unwrap().len(), 1);
    assert_eq!(store.list_cats(&sibling.id).unwrap().len(), 1);
}

#[test]
fn state_survives_a_reconnect() {
    let url = crate::testsupport::isolated_control_store_url();
    let cat_id = {
        let store = Store::connect(&url, None).unwrap();
        let workspace = bootstrap_workspace(&store, "acme");
        let (cat, _, _) = create_test_cat(&store, &workspace, "web").unwrap();
        cat.id
    };

    // A second connect is a control-plane restart: everything written before
    // it must still be there, and the re-run DDL must not disturb it.
    let store = Store::connect(&url, None).unwrap();
    let cat = store.must_get_cat_by_id(&cat_id).unwrap();
    assert_eq!(cat.name, "web");
    let disks = store.list_disks_for_cat(&cat_id).unwrap();
    assert!(!disks.is_empty(), "the root disk survives the restart");
    store.set_expiry(&cat_id, Some(12345)).unwrap();
    assert_eq!(
        store.must_get_cat_by_id(&cat_id).unwrap().expires_at_unix,
        Some(12345)
    );
}

#[test]
fn schema_v1_upgrades_in_place_with_lifecycle_provenance_and_observed_generation() {
    let url = crate::testsupport::isolated_control_store_url();
    let cat_id;
    let unproven_cat_id;
    {
        let store = Store::connect(&url, None).unwrap();
        let workspace = bootstrap_workspace(&store, "schema-v1");
        let (cat, _, create) = create_test_cat(&store, &workspace, "schema-v1-cat").unwrap();
        cat_id = cat.id.clone();
        store
            .register_node(
                "legacy-node",
                "http://node",
                "http://gateway",
                4,
                8192,
                false,
            )
            .unwrap();
        store.set_placement(&cat.id, Some("legacy-node")).unwrap();
        store.set_observed(&cat.id, ObservedState::Running).unwrap();
        store.finish_operation(&create.id, None).unwrap();
        store
            .publish_routes(&cat.id, "legacy-node", "http://gateway")
            .unwrap();
        let (unproven, _, _) = create_test_cat(&store, &workspace, "running-before-route").unwrap();
        unproven_cat_id = unproven.id.clone();
        store
            .set_placement(&unproven.id, Some("legacy-node"))
            .unwrap();
        store
            .set_observed(&unproven.id, ObservedState::Running)
            .unwrap();
        store
            .with(|client| {
                client.batch_execute(
                    "ALTER TABLE cats DROP COLUMN lifecycle_dispatch_json;
                     ALTER TABLE cats DROP COLUMN observed_generation;
                     UPDATE control_schema_version SET version=1 WHERE singleton",
                )
            })
            .unwrap();
        assert_eq!(
            store.must_get_cat_by_id(&cat.id).unwrap().name,
            "schema-v1-cat"
        );
    }

    let upgraded = Store::connect(&url, None).unwrap();
    let version: i64 = upgraded
        .with(|client| {
            client
                .query_one(
                    "SELECT version FROM control_schema_version WHERE singleton",
                    &[],
                )?
                .try_get(0)
        })
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);
    let marker: Option<String> = upgraded
        .with(|client| {
            client
                .query_one(
                    "SELECT lifecycle_dispatch_json FROM cats WHERE id=$1",
                    &[&cat_id],
                )?
                .try_get(0)
        })
        .unwrap();
    assert!(marker.is_none());
    let observed_generation: i64 = upgraded
        .with(|client| {
            client
                .query_one(
                    "SELECT observed_generation FROM cats WHERE id=$1",
                    &[&cat_id],
                )?
                .try_get(0)
        })
        .unwrap();
    assert_eq!(observed_generation, 1);
    assert_eq!(
        upgraded.observed_generation(&unproven_cat_id).unwrap(),
        0,
        "a legacy Running write before route publication is not physical proof"
    );
    assert!(upgraded
        .cats_needing_work()
        .unwrap()
        .iter()
        .any(|cat| cat.id == unproven_cat_id));
    assert!(
        upgraded
            .cats_needing_work()
            .unwrap()
            .into_iter()
            .all(|cat| cat.name != "schema-v1-cat"),
        "rolling upgrade scheduled a no-op lifecycle alignment"
    );
    let (route, state) = upgraded
        .resolve_route(
            &upgraded
                .endpoints_for_cat(&cat_id)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
                .hostname,
        )
        .unwrap();
    assert_eq!(route.gateway_url, "http://gateway");
    assert_eq!(state, "active");
}

#[test]
fn reconnect_rereads_a_dsn_file() {
    let first_url = crate::testsupport::isolated_control_store_url();
    let second_url = crate::testsupport::isolated_control_store_url();
    // Prepare both databases before changing the source underneath a Store.
    // Credential rotation keeps the database fixed, but two schemas make the
    // source actually used by the reconnect externally visible.
    drop(Store::connect(&second_url, None).unwrap());

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control-postgres-url");
    std::fs::write(&path, format!("{first_url}\n")).unwrap();
    let store = Store::connect_from(&DsnSource::File(path.clone()), None).unwrap();
    let workspace = bootstrap_workspace(&store, "first");
    create_test_cat(&store, &workspace, "only-in-first").unwrap();

    std::fs::write(&path, format!("{second_url}\n")).unwrap();
    let old_client = store.client.lock().unwrap().take();
    drop(old_client);

    assert!(
        store.list_cats(&workspace.id).unwrap().is_empty(),
        "the reconnect must use the newly rendered DSN"
    );
}

#[test]
fn a_dropped_postgres_session_reconnects_without_losing_committed_state() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let workspace = bootstrap_workspace(&store, "acme");
    let (cat, _, _) = create_test_cat(&store, &workspace, "survivor").unwrap();
    let backend_pid: i32 = store
        .with(|client| client.query_one("SELECT pg_backend_pid()", &[])?.try_get(0))
        .unwrap();

    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    assert!(admin
        .query_one("SELECT pg_terminate_backend($1)", &[&backend_pid])
        .unwrap()
        .try_get::<_, bool>(0)
        .unwrap());

    // The request whose connection was severed may fail. The next request
    // must open a fresh session and observe every earlier commit.
    let _ = store.list_cats(&workspace.id);
    let recovered = store.list_cats(&workspace.id).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].id, cat.id);
}

#[test]
fn dsn_file_errors_do_not_expose_credential_contents() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing-postgres-url");
    let error = DsnSource::File(missing.clone()).resolve().unwrap_err();
    assert!(error.to_string().contains(&missing.display().to_string()));

    let empty = directory.path().join("empty-postgres-url");
    std::fs::write(&empty, "  \n").unwrap();
    let error = DsnSource::File(empty.clone()).resolve().unwrap_err();
    assert!(error.to_string().contains(&empty.display().to_string()));
    assert!(!error.to_string().contains("postgres://"));
}

#[test]
fn heartbeat_reported_inventory_round_trips_and_diffs_orphans() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "acme");
    let (cat, _, _) = create_test_cat(&store, &workspace, "assigned").unwrap();
    store
        .register_node("node_a", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node_a")).unwrap();

    let hb = |cat_id: &str| HeartbeatCat {
        cat_id: cat_id.into(),
        generation: 3,
        state: ObservedState::Running,
    };
    assert!(
        store
            .heartbeat_node("node_a", None, &[hb(&cat.id), hb("cat_orphan1")])
            .unwrap(),
        "the first report differs from never-reported"
    );
    assert!(
        !store
            .heartbeat_node("node_a", None, &[hb("cat_orphan1"), hb(&cat.id)])
            .unwrap(),
        "the same inventory in a different order is not a change"
    );

    let orphans = store.orphan_reported_cats("node_a").unwrap();
    assert_eq!(orphans.len(), 1, "the assigned Cat is not an orphan");
    assert_eq!(orphans[0].cat_id, "cat_orphan1");
    assert_eq!(orphans[0].generation, 3);
    assert_eq!(store.node_summary("node_a").unwrap().orphan_cats, 1);

    assert!(
        store
            .heartbeat_node("node_a", None, &[hb(&cat.id)])
            .unwrap(),
        "dropping the orphan is a change"
    );
    assert!(store.orphan_reported_cats("node_a").unwrap().is_empty());
    assert_eq!(store.node_summary("node_a").unwrap().orphan_cats, 0);

    // Re-registration wipes the report: the fresh agent has said nothing yet.
    store
        .register_node(
            "node_a",
            "http://node-new",
            "http://gateway",
            4,
            8192,
            false,
        )
        .unwrap();
    assert!(store.reported_cats("node_a").unwrap().is_empty());

    assert!(
        store.heartbeat_node("node_missing", None, &[]).is_err(),
        "a heartbeat for an unregistered node is refused"
    );
}

#[test]
fn an_idempotency_record_outlives_the_cat_it_created() {
    let store = test_store();
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
fn two_store_instances_linearize_create_and_action_idempotency() {
    let (first, second) = test_store_pair();
    let workspace = bootstrap_workspace(&first, "replicas");
    let create_gate = std::sync::Barrier::new(2);
    let create = |store: &Store| {
        create_gate.wait();
        store
            .create_cat_idempotent(
                &workspace,
                "one",
                "test",
                1,
                256,
                1 << 20,
                true,
                None,
                None,
                DiskDurability::Strict,
                "create-key",
                "POST /cats replicas/one",
            )
            .unwrap()
    };
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| create(&first));
        let right = scope.spawn(|| create(&second));
        (left.join().unwrap(), right.join().unwrap())
    });
    assert_eq!(left.0.id, right.0.id);
    assert_eq!(left.2.id, right.2.id);
    assert_eq!(first.list_cats(&workspace.id).unwrap().len(), 1);

    let action_gate = std::sync::Barrier::new(2);
    let act = |store: &Store| {
        action_gate.wait();
        store
            .set_desired_idempotent(
                &left.0.id,
                DesiredState::Cold,
                None,
                "cat.stop",
                "stop-key",
                "POST /cats/one/actions/stop",
            )
            .unwrap()
    };
    let (left_action, right_action) = std::thread::scope(|scope| {
        let left_action = scope.spawn(|| act(&first));
        let right_action = scope.spawn(|| act(&second));
        (left_action.join().unwrap(), right_action.join().unwrap())
    });
    assert_eq!(left_action.id, right_action.id);
    assert_eq!(first.must_get_cat_by_id(&left.0.id).unwrap().generation, 2);
}

#[test]
fn oci_owner_lock_distinguishes_a_live_replica_from_a_dead_one() {
    let (first, second) = test_store_pair();
    let workspace = bootstrap_workspace(&first, "replicas");
    let (cat, _, _) = create_test_cat(&first, &workspace, "oci").unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));

    let (record_id, operation_id, lease) =
        match first.claim_oci_deployment(&cat, "server", &digest).unwrap() {
            OciDeploymentClaim::Claimed {
                record_id,
                operation,
                lease,
            } => (record_id, operation.id, lease),
            _ => panic!("the first replica must own the new deployment"),
        };
    assert_eq!(
        second.fail_interrupted_oci_deployments().unwrap(),
        0,
        "a live task's session lock must protect it from another replica's reaper"
    );
    match second
        .claim_oci_deployment(&cat, "server", &digest)
        .unwrap()
    {
        OciDeploymentClaim::AlreadyRunning { operation, .. } => {
            assert_eq!(operation.id, operation_id)
        }
        _ => panic!("the second replica must join the live deployment"),
    }

    drop(lease);
    assert_eq!(second.fail_interrupted_oci_deployments().unwrap(), 1);
    assert_eq!(
        second.get_operation(&operation_id).unwrap().phase,
        OperationPhase::Failed
    );

    let replacement_operation = match second
        .claim_oci_deployment(&cat, "server", &digest)
        .unwrap()
    {
        OciDeploymentClaim::Claimed { operation, .. } => operation,
        _ => panic!("the identity must be retryable after its owner disappears"),
    };
    assert_ne!(replacement_operation.id, operation_id);
    let stale_result = OciDeployment {
        app: "server".into(),
        image_digest: digest.clone(),
        manifest_digest: digest,
        service: "cats-oci-server.service".into(),
        active: true,
    };
    assert!(!first
        .succeed_oci_deployment(&record_id, &operation_id, &stale_result)
        .unwrap());
}

#[test]
fn singleton_roles_elect_independently_and_release_on_session_drop() {
    let (first, second) = test_store_pair();
    let mut first_reconciler = first.singleton_session(SingletonRole::Reconciler).unwrap();
    let mut second_reconciler = second.singleton_session(SingletonRole::Reconciler).unwrap();
    let mut second_billing = second
        .singleton_session(SingletonRole::BillingEnforcer)
        .unwrap();

    assert!(first_reconciler.try_acquire().unwrap());
    assert!(!second_reconciler.try_acquire().unwrap());
    assert!(
        second_billing.try_acquire().unwrap(),
        "one role's leader must not make every other role a hot standby"
    );

    drop(first_reconciler);
    assert!(
        second_reconciler.try_acquire().unwrap(),
        "PostgreSQL must release leadership with the owner session"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn singleton_task_cancellation_aborts_old_leader_before_failover() {
    let (first, second) = test_store_pair();
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(AtomicUsize::new(0));

    let first_task =
        crate::server::spawn_singleton_task(Arc::new(first), SingletonRole::Reconciler, {
            let active = active.clone();
            let max_active = max_active.clone();
            let starts = starts.clone();
            move || {
                let active = active.clone();
                let max_active = max_active.clone();
                let starts = starts.clone();
                async move {
                    starts.fetch_add(1, Ordering::SeqCst);
                    let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(now_active, Ordering::SeqCst);
                    let _active = ActiveSingletonGuard {
                        active,
                        // Widen the cancellation window: the advisory lock
                        // must stay held until this delayed destructor ends.
                        drop_delay: std::time::Duration::from_millis(500),
                    };
                    std::future::pending::<()>().await;
                }
            }
        });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while starts.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first replica should acquire leadership");

    let second_task =
        crate::server::spawn_singleton_task(Arc::new(second), SingletonRole::Reconciler, {
            let active = active.clone();
            let max_active = max_active.clone();
            let starts = starts.clone();
            move || {
                let active = active.clone();
                let max_active = max_active.clone();
                let starts = starts.clone();
                async move {
                    starts.fetch_add(1, Ordering::SeqCst);
                    let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(now_active, Ordering::SeqCst);
                    let _active = ActiveSingletonGuard {
                        active,
                        drop_delay: std::time::Duration::ZERO,
                    };
                    std::future::pending::<()>().await;
                }
            }
        });
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 1, "the standby must not run");

    first_task.abort();
    let _ = first_task.await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while starts.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the standby should take over after leader cancellation");

    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert_eq!(
        max_active.load(Ordering::SeqCst),
        1,
        "the old role must stop before the replacement starts"
    );
    second_task.abort();
    let _ = second_task.await;
}

#[test]
fn absolute_expiry_selects_only_due_undeleted_cats() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "acme");
    let past = now_unix() - 60;
    let future = now_unix() + 3600;

    let (expired, _, _) =
        create_test_cat_expiring(&store, &workspace, "expired", Some(past)).unwrap();
    let (fresh, _, _) =
        create_test_cat_expiring(&store, &workspace, "fresh", Some(future)).unwrap();
    let (forever, _, _) = create_test_cat(&store, &workspace, "forever").unwrap();
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
    let store = test_store();
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
    let store = Arc::new(test_store());
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
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    {
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin
            .execute(
                "UPDATE control_schema_version SET version = $1",
                &[&(SCHEMA_VERSION + 1)],
            )
            .unwrap();
    }

    let Err(error) = Store::connect(&url, None) else {
        panic!("a database from another schema version must not open");
    };
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(
        error
            .to_string()
            .contains(&format!("requires {SCHEMA_VERSION}")),
        "the operator needs to see the required schema version, got: {error}"
    );
    // A schema this build wrote itself keeps opening.
    assert!(Store::connect(&crate::testsupport::isolated_control_store_url(), None).is_ok());

    // The control database is shared with the storage MetadataStore's tables.
    // A foreign table alongside is not an old control-plane schema.
    let shared = crate::testsupport::isolated_control_store_url();
    {
        let mut admin = postgres::Client::connect(&shared, postgres::NoTls).unwrap();
        admin
            .batch_execute("CREATE TABLE usage_checkpoints (event_id TEXT PRIMARY KEY);")
            .unwrap();
    }
    assert!(
        Store::connect(&shared, None).is_ok(),
        "a foreign table in the same database is not an old control-plane schema"
    );
}

#[test]
fn every_cat_gets_a_default_public_endpoint() {
    let store = test_store();
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
    let store = test_store();
    store
        .register_node("node_a", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_node_state("node_a", NodeState::Cordoned).unwrap();

    store.set_node_state("node_a", NodeState::Lost).unwrap();
    store
        .register_node(
            "node_a",
            "http://node-new",
            "http://gateway",
            4,
            8192,
            false,
        )
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
    store
        .heartbeat_node("node_a", Some(&telemetry), &[])
        .unwrap();
    let stored = store.get_node("node_a").unwrap().telemetry.unwrap();
    assert_eq!(stored.observed_cats, 2);
    assert_eq!(stored.allocated_cpus, 3);
    assert_eq!(stored.allocated_memory_mib, 2048);
    assert_eq!(store.get_node("node_a").unwrap().state, NodeState::Lost);
    assert!(store.recover_lost_node("node_a").unwrap());
    assert_eq!(store.get_node("node_a").unwrap().state, NodeState::Cordoned);
}

#[test]
fn a_fresh_initially_cordoned_node_is_excluded_from_placement() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = create_test_cat(&store, &workspace, "waiting").unwrap();

    store
        .register_node("node_a", "http://node", "http://gateway", 4, 8192, true)
        .unwrap();
    assert_eq!(store.get_node("node_a").unwrap().state, NodeState::Cordoned);
    assert!(
        store
            .claim_node_for(&cat.id, 1, 256, 60_000, now_ms())
            .unwrap()
            .is_none(),
        "an initially-cordoned node must never enter placement"
    );

    store.set_node_state("node_a", NodeState::Ready).unwrap();
    assert_eq!(
        store
            .claim_node_for(&cat.id, 1, 256, 60_000, now_ms())
            .unwrap()
            .map(|node| node.id),
        Some("node_a".into()),
        "explicit administrator admission makes the validated node schedulable"
    );
}

#[test]
fn initially_cordoned_only_applies_to_a_new_node_registration() {
    let store = test_store();

    store
        .register_node(
            "node_ready",
            "http://node",
            "http://gateway",
            4,
            8192,
            false,
        )
        .unwrap();
    assert_eq!(
        store.get_node("node_ready").unwrap().state,
        NodeState::Ready,
        "an unflagged fresh registration retains the existing behavior"
    );

    store
        .register_node(
            "node_cordoned",
            "http://node",
            "http://gateway",
            4,
            8192,
            true,
        )
        .unwrap();
    store
        .register_node(
            "node_cordoned",
            "http://node-new",
            "http://gateway",
            4,
            8192,
            false,
        )
        .unwrap();
    assert_eq!(
        store.get_node("node_cordoned").unwrap().state,
        NodeState::Cordoned,
        "an unflagged re-registration must not undo the control-plane cordon"
    );

    store
        .set_node_state("node_cordoned", NodeState::Ready)
        .unwrap();
    store
        .register_node(
            "node_cordoned",
            "http://node-newer",
            "http://gateway",
            4,
            8192,
            true,
        )
        .unwrap();
    assert_eq!(
        store.get_node("node_cordoned").unwrap().state,
        NodeState::Ready,
        "the bootstrap flag must not re-cordon a node an administrator admitted"
    );
}

#[test]
fn a_fenced_node_identity_cannot_reregister_or_heartbeat_back_to_ready() {
    let store = test_store();
    store
        .register_node("node_a", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_node_state("node_a", NodeState::Fenced).unwrap();

    store
        .register_node(
            "node_a",
            "http://node-new",
            "http://gateway",
            4,
            8192,
            false,
        )
        .unwrap();
    store.heartbeat_node("node_a", None, &[]).unwrap();
    store.set_node_state("node_a", NodeState::Ready).unwrap();
    assert_eq!(store.get_node("node_a").unwrap().state, NodeState::Fenced);
}

#[test]
fn last_guest_work_release_is_immediately_suspend_eligible() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = create_test_cat(&store, &workspace, "worker").unwrap();
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
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store
        .set_observed_for_generation(&cat.id, ObservedState::Running, 1)
        .unwrap();
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
    let (first, second) = test_store_pair();
    let stores = [Arc::new(first), Arc::new(second)];
    let workspace = bootstrap_workspace(&stores[0], "alpha");
    // Room for exactly 4 of these Cats: 8 cpus / 8192 MiB, 2 cpus each.
    stores[0]
        .register_node("node-1", "http://node", "http://gateway", 8, 8192, false)
        .unwrap();
    let mut ids = Vec::new();
    for n in 0..10 {
        let (cat, _, _) = stores[0]
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
            .enumerate()
            .map(|(index, id)| {
                let store = stores[index % stores.len()].clone();
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
    let on_node = stores[0].cats_on_node("node-1").unwrap();
    assert_eq!(on_node.len(), 4);
    assert_eq!(on_node.iter().map(|c| c.spec.cpus).sum::<u32>(), 8);
    assert!(on_node.iter().map(|c| c.spec.memory_mib).sum::<u64>() <= 8192);
}

#[test]
fn cordon_linearizes_after_a_placement_that_already_observed_ready() {
    let url = crate::testsupport::isolated_control_store_url();
    let placement = Store::connect(&url, None).unwrap();
    let cordoner = Store::connect(&url, None).unwrap();
    let observer = Store::connect(&url, None).unwrap();
    let workspace = bootstrap_workspace(&placement, "linearize-cordon");
    placement
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    let (cat, _, _) = create_test_cat(&placement, &workspace, "waiter").unwrap();

    placement
        .with(|client| {
            client.batch_execute("SET statement_timeout='15s'; SET lock_timeout='15s'")?;
            client.query_one(
                "SELECT set_config('application_name', $1, false)",
                &[&"q150-placement-waiter"],
            )?;
            Ok(())
        })
        .unwrap();
    cordoner
        .with(|client| {
            client.batch_execute("SET statement_timeout='15s'; SET lock_timeout='15s'")?;
            client.query_one(
                "SELECT set_config('application_name', $1, false)",
                &[&"q150-cordon-waiter"],
            )?;
            Ok(())
        })
        .unwrap();

    // Pause the production claim at its real UPDATE, after it selected this
    // Ready node. pg_stat_activity's PgSleep wait is the positive oracle that
    // the claim reached that point; the timeout below is only a deadlock guard.
    observer
        .with(|client| {
            client.batch_execute(
                "CREATE FUNCTION q150_pause_real_claim() RETURNS trigger
                   LANGUAGE plpgsql AS $$
                   BEGIN
                     IF OLD.node_id IS NULL AND NEW.node_id = 'node-1' THEN
                       PERFORM pg_sleep(5);
                     END IF;
                     RETURN NEW;
                   END
                   $$;
                 CREATE TRIGGER q150_pause_real_claim
                   BEFORE UPDATE OF node_id ON cats
                   FOR EACH ROW EXECUTE FUNCTION q150_pause_real_claim();",
            )
        })
        .unwrap();

    let (placement_result_tx, placement_result_rx) = std::sync::mpsc::channel();
    let (cordon_result_tx, cordon_result_rx) = std::sync::mpsc::channel();
    let mut placement_sleep_seen = false;
    let mut cordon_wait_seen = false;
    let mut probe_error = None;
    let mut early_placement_result = None;
    let mut early_cordon_result = None;

    std::thread::scope(|scope| {
        let cat_id = cat.id.clone();
        let placement_store = &placement;
        let placement_worker = scope.spawn(move || {
            placement_result_tx
                .send(placement_store.claim_node_for(&cat_id, 1, 256, 60_000, now_ms()))
                .unwrap();
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        loop {
            if let Ok(result) = placement_result_rx.try_recv() {
                early_placement_result = Some(result);
                break;
            }
            match observer.with(|client| {
                client
                    .query_one(
                        "SELECT COUNT(*)
                           FROM pg_stat_activity
                          WHERE application_name=$1
                            AND wait_event_type='Timeout'
                            AND wait_event='PgSleep'",
                        &[&"q150-placement-waiter"],
                    )
                    .and_then(|row| row.try_get::<_, i64>(0))
            }) {
                Ok(1) => {
                    placement_sleep_seen = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => {
                    probe_error = Some(format!("placement probe failed: {error}"));
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let cordon_worker = scope.spawn(|| {
            cordon_result_tx
                .send(cordoner.set_node_state("node-1", NodeState::Cordoned))
                .unwrap();
        });

        // This is a positive synchronization oracle, not a scheduling-delay
        // assertion: PostgreSQL must show the exact cordoner session queued on
        // an advisory lock before the older placement is allowed to commit.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        loop {
            if let Ok(result) = cordon_result_rx.try_recv() {
                early_cordon_result = Some(result);
                break;
            }
            match observer.with(|client| {
                client
                    .query_one(
                        "SELECT COUNT(*)
                           FROM pg_locks AS locks
                           JOIN pg_stat_activity AS activity
                             ON activity.pid=locks.pid
                          WHERE activity.application_name=$1
                            AND locks.locktype='advisory'
                            AND NOT locks.granted",
                        &[&"q150-cordon-waiter"],
                    )
                    .and_then(|row| row.try_get::<_, i64>(0))
            }) {
                Ok(1) => {
                    cordon_wait_seen = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => {
                    probe_error = Some(format!("cordon probe failed: {error}"));
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        placement_worker.join().unwrap();
        cordon_worker.join().unwrap();
    });

    observer
        .with(|client| {
            client.batch_execute(
                "DROP TRIGGER IF EXISTS q150_pause_real_claim ON cats;
                 DROP FUNCTION IF EXISTS q150_pause_real_claim();",
            )
        })
        .unwrap();

    assert!(probe_error.is_none(), "{}", probe_error.unwrap_or_default());
    assert!(
        placement_sleep_seen,
        "the real claim never reached its guarded node_id update"
    );
    assert!(
        cordon_wait_seen,
        "cordon returned without waiting for an older Ready placement"
    );
    let placed = match early_placement_result {
        Some(result) => result,
        None => placement_result_rx.recv().unwrap(),
    }
    .unwrap();
    let cordoned = match early_cordon_result {
        Some(result) => result,
        None => cordon_result_rx.recv().unwrap(),
    };
    cordoned.unwrap();
    assert_eq!(placed.unwrap().id, "node-1");

    assert_eq!(
        placement.must_get_cat_by_id(&cat.id).unwrap().node_id,
        Some("node-1".into()),
        "the placement that linearized first remains visible to drain"
    );
    assert_eq!(
        placement.get_node("node-1").unwrap().state,
        NodeState::Cordoned,
        "cordon linearizes after the already-authorized placement"
    );
}

#[test]
fn gateway_work_blocks_auto_suspend_and_wake_is_singleflight() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = create_test_cat(&store, &workspace, "web").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store
        .set_observed_for_generation(&cat.id, ObservedState::Running, 1)
        .unwrap();
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
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = create_test_cat(&store, &workspace, "racer").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store
        .set_observed_for_generation(&cat.id, ObservedState::Running, 1)
        .unwrap();
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
fn late_old_generation_result_cannot_clear_or_complete_the_new_dispatch() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "dispatch-cas");
    let (cat, _, create) = create_test_cat(&store, &workspace, "dispatch-cas").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store
        .set_observed_for_generation(&cat.id, ObservedState::Running, 1)
        .unwrap();
    store.finish_operation(&create.id, None).unwrap();

    let suspend = store
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.suspend")
        .unwrap();
    let old_job = NodeJob {
        job_id: job_id(&cat.id, 2, "suspend_cat"),
        cat_generation: 2,
        action: NodeJobAction::SuspendCat {
            cat_id: cat.id.clone(),
            work_fence: Some(SuspendWorkFence {
                control_work_version: 17,
                guest_lease_sequence: 29,
            }),
        },
    };
    let old = store
        .begin_lifecycle_dispatch(
            &cat.id,
            "node-1",
            ObservedState::Running,
            ObservedState::Suspending,
            ObservedState::Suspended,
            old_job,
        )
        .unwrap()
        .unwrap();
    let persisted = store.lifecycle_dispatch(&cat.id).unwrap().unwrap();
    assert_eq!(persisted.job.job_id, old.job.job_id);
    assert!(matches!(
        persisted.job.action,
        NodeJobAction::SuspendCat {
            work_fence: Some(SuspendWorkFence {
                control_work_version: 17,
                guest_lease_sequence: 29,
            }),
            ..
        }
    ));

    let resume = store
        .set_desired(&cat.id, DesiredState::Running, None, "cat.resume")
        .unwrap();
    assert_eq!(resume.resource_generation, 3);
    assert_eq!(
        store.get_operation(&suspend.id).unwrap().phase,
        OperationPhase::Failed,
        "superseded generation stayed active"
    );
    assert!(store
        .settle_lifecycle_dispatch(&old, ObservedState::Suspended, true, None, None, false,)
        .unwrap());
    assert_eq!(
        store.get_operation(&resume.id).unwrap().phase,
        OperationPhase::Pending
    );

    let new_job = NodeJob {
        job_id: job_id(&cat.id, 3, "resume_cat"),
        cat_generation: 3,
        action: NodeJobAction::ResumeCat {
            cat_id: cat.id.clone(),
        },
    };
    let new = store
        .begin_lifecycle_dispatch(
            &cat.id,
            "node-1",
            ObservedState::Suspended,
            ObservedState::Starting,
            ObservedState::Running,
            new_job,
        )
        .unwrap()
        .unwrap();
    assert!(
        !store
            .settle_lifecycle_dispatch(
                &old,
                ObservedState::Suspended,
                true,
                None,
                Some(("stale-node", "http://stale-gateway")),
                false,
            )
            .unwrap(),
        "late gen2 response cleared the gen3 marker"
    );
    assert_eq!(
        store
            .lifecycle_dispatch(&cat.id)
            .unwrap()
            .unwrap()
            .dispatch_id,
        new.dispatch_id
    );
    assert_eq!(
        store.get_operation(&resume.id).unwrap().phase,
        OperationPhase::Pending
    );
    let stale_route_count: i64 = store
        .with(|client| {
            client
                .query_one(
                    "SELECT COUNT(*) FROM routes
                      WHERE cat_id=$1 AND gateway_url='http://stale-gateway'",
                    &[&cat.id],
                )?
                .try_get(0)
        })
        .unwrap();
    assert_eq!(
        stale_route_count, 0,
        "late result republished a stale route"
    );

    assert!(store
        .settle_lifecycle_dispatch(
            &new,
            ObservedState::Running,
            true,
            None,
            Some(("node-1", "http://gateway")),
            false,
        )
        .unwrap());
    assert_eq!(
        store.get_operation(&resume.id).unwrap().phase,
        OperationPhase::Succeeded
    );
}

#[test]
fn confirmed_fence_atomically_clears_every_host_claim() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "fenced-cat-atomic");
    let (cat, _, _) = create_test_cat(&store, &workspace, "fenced-cat-atomic").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store.set_observed(&cat.id, ObservedState::Running).unwrap();
    store
        .publish_routes(&cat.id, "node-1", "http://gateway")
        .unwrap();
    let suspend = store
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.suspend")
        .unwrap();
    let _dispatch = store
        .begin_lifecycle_dispatch(
            &cat.id,
            "node-1",
            ObservedState::Running,
            ObservedState::Suspending,
            ObservedState::Suspended,
            NodeJob {
                job_id: job_id(&cat.id, suspend.resource_generation, "suspend_cat"),
                cat_generation: suspend.resource_generation,
                action: NodeJobAction::SuspendCat {
                    cat_id: cat.id.clone(),
                    work_fence: None,
                },
            },
        )
        .unwrap()
        .unwrap();

    assert!(store.converge_fenced_cat(&cat.id, "node-1").unwrap());
    let converged = store.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(converged.observed_state, ObservedState::Cold);
    assert!(converged.node_id.is_none());
    assert_eq!(
        store.observed_generation(&cat.id).unwrap(),
        suspend.resource_generation
    );
    assert!(store.lifecycle_dispatch(&cat.id).unwrap().is_none());
    let (route_node, gateway, route_state): (Option<String>, Option<String>, String) = store
        .with(|client| {
            let row = client.query_one(
                "SELECT node_id, gateway_url, state FROM routes WHERE cat_id=$1",
                &[&cat.id],
            )?;
            Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))
        })
        .unwrap();
    assert!(route_node.is_none());
    assert!(gateway.is_none());
    assert_eq!(route_state, "unbound");

    // A stale retry after reassignment cannot revoke the successor's claim.
    store.set_placement(&cat.id, Some("node-2")).unwrap();
    assert!(!store.converge_fenced_cat(&cat.id, "node-1").unwrap());
    assert_eq!(
        store
            .must_get_cat_by_id(&cat.id)
            .unwrap()
            .node_id
            .as_deref(),
        Some("node-2")
    );
}

#[test]
fn repeated_same_desired_coalesces_without_inventing_a_node_generation() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "same-desired");
    let (cat, _, create) = create_test_cat(&store, &workspace, "same-desired").unwrap();
    store
        .set_observed_for_generation(&cat.id, ObservedState::Running, 1)
        .unwrap();
    store.finish_operation(&create.id, None).unwrap();

    let repeated = store
        .set_desired(&cat.id, DesiredState::Running, None, "cat.start")
        .unwrap();
    assert_eq!(repeated.resource_generation, 1);
    assert_eq!(repeated.phase, OperationPhase::Succeeded);
    assert_eq!(store.must_get_cat_by_id(&cat.id).unwrap().generation, 1);

    store.set_observed(&cat.id, ObservedState::Failed).unwrap();
    let retry = store
        .set_desired(&cat.id, DesiredState::Running, None, "cat.start")
        .unwrap();
    assert_eq!(retry.resource_generation, 2);
    assert_eq!(retry.phase, OperationPhase::Pending);
}

#[test]
fn generation_split_is_scheduled_and_same_desired_does_not_claim_success() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "generation-split-work");
    let (cat, _, create) = create_test_cat(&store, &workspace, "generation-split-work").unwrap();
    store.finish_operation(&create.id, None).unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET observed_state='running', desired_state='running',
                            generation=2, observed_generation=1
                      WHERE id=$1",
                    &[&cat.id],
                )
                .map(|_| ())
        })
        .unwrap();

    assert!(store
        .cats_needing_work()
        .unwrap()
        .iter()
        .any(|candidate| candidate.id == cat.id));
    let repeated = store
        .set_desired(&cat.id, DesiredState::Running, None, "cat.start")
        .unwrap();
    assert_eq!(repeated.resource_generation, 2);
    assert_eq!(repeated.phase, OperationPhase::Pending);
}

#[test]
fn automatic_tiers_require_exact_markerless_physical_convergence() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "auto-generation-split");
    let (cat, _, _) = create_test_cat(&store, &workspace, "auto-generation-split").unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET desired_state='suspended', observed_state='suspended',
                            generation=2, observed_generation=1,
                            observed_state_since_ms=$2
                      WHERE id=$1",
                    &[&cat.id, &(now_ms() - 10_000)],
                )
                .map(|_| ())
        })
        .unwrap();
    assert!(store
        .auto_tier_candidates(Some(1), Some(1))
        .unwrap()
        .is_empty());
    assert!(store
        .try_auto_tier(&cat.id, Some(1), Some(1))
        .unwrap()
        .is_none());

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE cats
                        SET desired_state='running', observed_state='running',
                            observed_generation=generation,
                            lifecycle_dispatch_json='{}'
                      WHERE id=$1",
                    &[&cat.id],
                )
                .map(|_| ())
        })
        .unwrap();
    assert!(!store.auto_suspend_candidates().unwrap().contains(&cat.id));
    assert!(store.try_auto_suspend(&cat.id, 5_000).unwrap().is_none());
}

#[test]
fn global_provenance_activation_linearizes_against_legacy_begin() {
    let (legacy_store, activation_store) = test_store_pair();
    let workspace = bootstrap_workspace(&legacy_store, "provenance-activation-race");
    let (cat, _, create) =
        create_test_cat(&legacy_store, &workspace, "provenance-activation-race").unwrap();
    legacy_store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    legacy_store.set_placement(&cat.id, Some("node-1")).unwrap();
    legacy_store
        .set_observed_for_generation(&cat.id, ObservedState::Running, 1)
        .unwrap();
    legacy_store.finish_operation(&create.id, None).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let cat_id = cat.id.clone();
    let (legacy, activation) = std::thread::scope(|scope| {
        let legacy_barrier = barrier.clone();
        let legacy_store = &legacy_store;
        let cat_id = &cat_id;
        let legacy = scope.spawn(move || {
            legacy_barrier.wait();
            legacy_store.begin_legacy_lifecycle(
                cat_id,
                "node-1",
                1,
                ObservedState::Running,
                ObservedState::Suspending,
            )
        });
        let activation_barrier = barrier.clone();
        let activation_store = &activation_store;
        let activation = scope.spawn(move || {
            activation_barrier.wait();
            activation_store.activate_lifecycle_provenance_writes()
        });
        (legacy.join().unwrap().unwrap(), activation.join().unwrap())
    });

    match legacy {
        LegacyLifecycleBegin::GateEnabled => {
            activation.unwrap();
            assert!(legacy_store.lifecycle_provenance_writes_enabled().unwrap());
            assert_eq!(
                legacy_store
                    .must_get_cat_by_id(&cat.id)
                    .unwrap()
                    .observed_state,
                ObservedState::Running
            );
        }
        LegacyLifecycleBegin::Begun => {
            assert!(activation.is_err());
            assert!(!legacy_store.lifecycle_provenance_writes_enabled().unwrap());
            assert_eq!(
                legacy_store
                    .must_get_cat_by_id(&cat.id)
                    .unwrap()
                    .observed_state,
                ObservedState::Suspending
            );
        }
        LegacyLifecycleBegin::Stale => panic!("race lost without either legal writer"),
    }
}

#[test]
fn global_provenance_activation_rejects_active_lifecycle_work() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "provenance-activation-active");
    let (cat, _, create) =
        create_test_cat(&store, &workspace, "provenance-activation-active").unwrap();
    assert!(store.activate_lifecycle_provenance_writes().is_err());
    assert!(!store.lifecycle_provenance_writes_enabled().unwrap());
    assert_eq!(
        store.must_get_cat_by_id(&cat.id).unwrap().observed_state,
        ObservedState::Creating
    );
    store.finish_operation(&create.id, None).unwrap();
    store
        .with(|client| {
            client
                .execute(
                    "UPDATE cats SET desired_state='running', observed_state='running',
                        generation=2, observed_generation=1 WHERE id=$1",
                    &[&cat.id],
                )
                .map(|_| ())
        })
        .unwrap();
    assert!(store.activate_lifecycle_provenance_writes().is_err());
    assert!(!store.lifecycle_provenance_writes_enabled().unwrap());
}

#[test]
fn automatic_deeper_tiers_use_persisted_state_age_and_respect_work() {
    let url = crate::testsupport::isolated_control_store_url();
    let cat_id;
    {
        let store = Store::connect(&url, None).unwrap();
        let workspace = bootstrap_workspace(&store, "alpha");
        let (cat, _, _) = create_test_cat(&store, &workspace, "sleeper").unwrap();
        cat_id = cat.id.clone();
        let suspend = store
            .set_desired(&cat.id, DesiredState::Suspended, None, "cat.suspend")
            .unwrap();
        store
            .set_observed_for_generation(
                &cat.id,
                ObservedState::Suspended,
                suspend.resource_generation,
            )
            .unwrap();
        store.finish_operation(&suspend.id, None).unwrap();
        store
            .with(|client| {
                client
                    .execute(
                        "UPDATE cats SET observed_state_since_ms=$2 WHERE id=$1",
                        &[&cat.id, &(now_ms() - 2_000)],
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
        store
            .set_observed_for_generation(&cat.id, ObservedState::Warm, warm.resource_generation)
            .unwrap();
        store.finish_operation(&warm.id, None).unwrap();
        store
            .with(|client| {
                client
                    .execute(
                        "UPDATE cats SET observed_state_since_ms=$2 WHERE id=$1",
                        &[&cat.id, &(now_ms() - 2_000)],
                    )
                    .map(|_| ())
            })
            .unwrap();
    }

    // Reconnecting to the control-plane database must not reset the Warm timer.
    let store = Store::connect(&url, None).unwrap();
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

fn place_running_cat(store: &Store, cat: &Cat, node_id: &str) {
    store
        .register_node(node_id, "http://node", "http://gateway", 8, 16_384, false)
        .unwrap();
    store.set_placement(&cat.id, Some(node_id)).unwrap();
    store
        .publish_routes(&cat.id, node_id, "http://gateway")
        .unwrap();
    store
        .set_observed_for_generation(&cat.id, ObservedState::Running, cat.generation)
        .unwrap();
}

#[test]
fn destroy_dispatch_is_terminal_and_authorizes_exact_cleanup_only() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "destroy-authority");
    let (cat, disks, _) = create_test_cat(&store, &workspace, "destroy-authority").unwrap();
    place_running_cat(&store, &cat, "destroy-node");
    let delete = store
        .set_desired(&cat.id, DesiredState::Deleted, None, "cat.delete")
        .unwrap();
    let dispatch = store
        .begin_lifecycle_dispatch(
            &cat.id,
            "destroy-node",
            ObservedState::Running,
            ObservedState::Stopping,
            ObservedState::Cold,
            NodeJob {
                job_id: job_id(&cat.id, delete.resource_generation, "stop_cat"),
                cat_generation: delete.resource_generation,
                action: NodeJobAction::StopCat {
                    cat_id: cat.id.clone(),
                    disposition: StopCatDisposition::Destroy {
                        disposable_root_disk_ids: vec![cat.root_disk_id.clone()],
                        retained_persistent_disk_ids: Vec::new(),
                    },
                },
            },
        )
        .unwrap()
        .unwrap();
    assert!(store
        .set_desired(&cat.id, DesiredState::Running, None, "cat.start")
        .is_err());
    assert!(store.ensure_desired_running(&cat.id).is_err());
    assert!(store
        .settle_lifecycle_dispatch(&dispatch, ObservedState::Cold, false, None, None, true,)
        .unwrap());
    assert_eq!(
        store
            .lifecycle_dispatch(&cat.id)
            .unwrap()
            .unwrap()
            .dispatch_id,
        dispatch.dispatch_id
    );
    let mut stale = dispatch.clone();
    stale.dispatch_id.push_str("-stale");
    assert!(!store.claim_destroy_cleanup(&stale).unwrap());
    assert!(store.claim_destroy_cleanup(&dispatch).unwrap());
    assert!(!store.delete_cat_if_destroy_authorized(&stale).unwrap());
    for disk in disks {
        store.unbind_disk(&disk.id).unwrap();
        store.delete_disk_row(&disk.id).unwrap();
    }
    assert!(store.delete_cat_if_destroy_authorized(&dispatch).unwrap());
    assert!(store.find_cat_by_id(&cat.id).unwrap().is_none());
}

#[test]
fn hot_disk_changes_have_zero_side_effects_under_every_lifecycle_marker() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "hot-change-marker");
    for (name, action, transitional, target) in [
        (
            "start-marker",
            NodeJobAction::StartCat {
                cat_id: String::new(),
                image: "test".into(),
                cpus: 1,
                memory_mib: 256,
                volumes: Vec::new(),
            },
            ObservedState::Starting,
            ObservedState::Running,
        ),
        (
            "suspend-marker",
            NodeJobAction::SuspendCat {
                cat_id: String::new(),
                work_fence: None,
            },
            ObservedState::Suspending,
            ObservedState::Suspended,
        ),
        (
            "warm-marker",
            NodeJobAction::WarmCat {
                cat_id: String::new(),
            },
            ObservedState::Warming,
            ObservedState::Warm,
        ),
    ] {
        let (cat, _, _) = create_test_cat(&store, &workspace, name).unwrap();
        let node_id = format!("node-{name}");
        place_running_cat(&store, &cat, &node_id);
        let disk = store
            .create_disk(
                &workspace,
                &format!("disk-{name}"),
                1 << 22,
                DiskDurability::Strict,
            )
            .unwrap();
        let action = match action {
            NodeJobAction::StartCat {
                image,
                cpus,
                memory_mib,
                volumes,
                ..
            } => NodeJobAction::StartCat {
                cat_id: cat.id.clone(),
                image,
                cpus,
                memory_mib,
                volumes,
            },
            NodeJobAction::SuspendCat { work_fence, .. } => NodeJobAction::SuspendCat {
                cat_id: cat.id.clone(),
                work_fence,
            },
            NodeJobAction::WarmCat { .. } => NodeJobAction::WarmCat {
                cat_id: cat.id.clone(),
            },
            _ => unreachable!(),
        };
        store
            .begin_lifecycle_dispatch(
                &cat.id,
                &node_id,
                ObservedState::Running,
                transitional,
                target,
                NodeJob {
                    job_id: job_id(&cat.id, cat.generation, action.kind()),
                    cat_generation: cat.generation,
                    action,
                },
            )
            .unwrap();
        assert!(store
            .bind_disk_for_hot_change(&disk.id, &cat.id, "/data")
            .is_err());
        assert!(store
            .get_disk(&workspace.id, &disk.id)
            .unwrap()
            .bound_cat_id
            .is_none());
    }
}

#[test]
fn delayed_heartbeat_cannot_cross_fence_or_reassignment() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "heartbeat-cas");
    let (cat, _, _) = create_test_cat(&store, &workspace, "heartbeat-cas").unwrap();
    place_running_cat(&store, &cat, "old-node");
    store.set_node_state("old-node", NodeState::Fenced).unwrap();
    let delayed = HeartbeatCat {
        cat_id: cat.id.clone(),
        generation: cat.generation,
        state: ObservedState::Suspended,
    };
    assert!(!store
        .apply_heartbeat_observation("old-node", &delayed)
        .unwrap());
    assert_eq!(
        store.must_get_cat_by_id(&cat.id).unwrap().observed_state,
        ObservedState::Running
    );
    assert!(store.converge_fenced_cat(&cat.id, "old-node").unwrap());
    place_running_cat(&store, &cat, "new-node");
    assert!(!store
        .apply_heartbeat_observation("old-node", &delayed)
        .unwrap());
    let current = store.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(current.node_id.as_deref(), Some("new-node"));
    assert_eq!(current.observed_state, ObservedState::Running);
}

#[test]
fn per_node_fence_session_lock_serializes_independent_replicas() {
    let (first, second) = test_store_pair();
    let held = first.node_fence_lease("same-node").unwrap().unwrap();
    assert!(second.node_fence_lease("same-node").unwrap().is_none());
    drop(held);
    assert!(second.node_fence_lease("same-node").unwrap().is_some());
}

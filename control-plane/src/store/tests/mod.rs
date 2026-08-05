use super::*;
use cats_api::guest::GuestWorkLease;
use cats_api::requests::NodeWorkStatusRequest;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct ActiveSingletonGuard(Arc<AtomicUsize>);

impl Drop for ActiveSingletonGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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
        .register_node("node_a", "http://node", "http://gateway", 4, 8192)
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
        .register_node("node_a", "http://node-new", "http://gateway", 4, 8192)
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
                    let _active = ActiveSingletonGuard(active);
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
                    let _active = ActiveSingletonGuard(active);
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
fn a_fenced_node_identity_cannot_reregister_or_heartbeat_back_to_ready() {
    let store = test_store();
    store
        .register_node("node_a", "http://node", "http://gateway", 4, 8192)
        .unwrap();
    store.set_node_state("node_a", NodeState::Fenced).unwrap();

    store
        .register_node("node_a", "http://node-new", "http://gateway", 4, 8192)
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
    let (first, second) = test_store_pair();
    let stores = [Arc::new(first), Arc::new(second)];
    let workspace = bootstrap_workspace(&stores[0], "alpha");
    // Room for exactly 4 of these Cats: 8 cpus / 8192 MiB, 2 cpus each.
    stores[0]
        .register_node("node-1", "http://node", "http://gateway", 8, 8192)
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
fn gateway_work_blocks_auto_suspend_and_wake_is_singleflight() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = create_test_cat(&store, &workspace, "web").unwrap();
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
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = create_test_cat(&store, &workspace, "racer").unwrap();
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
            .set_observed(&cat.id, ObservedState::Suspended)
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
        store.set_observed(&cat.id, ObservedState::Warm).unwrap();
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

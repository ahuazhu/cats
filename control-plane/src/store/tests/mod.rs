use super::*;
use cats_api::guest::GuestWorkLease;
use cats_api::requests::NodeWorkStatusRequest;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};

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

/// Serialize only tests that intentionally leave one PostgreSQL session
/// waiting on another. Their internal worker threads still run concurrently;
/// this gate prevents unrelated structural-lock fixtures from consuming each
/// other's test-only lock timeout under the default parallel test runner.
/// Recovering a poisoned guard lets every later test report its own result.
fn serialize_structural_postgres_lock_test() -> std::sync::MutexGuard<'static, ()> {
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match GATE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn concurrency_store(url: &str) -> Store {
    let store = Store::connect(url, None).unwrap();
    store
        .with(|client| client.batch_execute("SET statement_timeout='15s'; SET lock_timeout='15s'"))
        .unwrap();
    store
}

fn backend_pid(store: &Store) -> i32 {
    store
        .with(|client| client.query_one("SELECT pg_backend_pid()", &[])?.try_get(0))
        .unwrap()
}

fn wait_until_blocked_by(observer: &Store, waiter_pid: i32, blocker_pid: i32) -> bool {
    for _ in 0..500 {
        let blocked = observer
            .with(|client| {
                client
                    .query_one(
                        "SELECT $2::INTEGER = ANY(pg_blocking_pids($1::INTEGER))",
                        &[&waiter_pid, &blocker_pid],
                    )?
                    .try_get(0)
            })
            .unwrap();
        if blocked {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

fn hold_work_sources_table(store: Store) -> (std::thread::JoinHandle<()>, mpsc::Sender<()>, i32) {
    let blocker_pid = backend_pid(&store);
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocker = std::thread::spawn(move || {
        store
            .enter(move |client| {
                let client = client?;
                let mut tx = client.transaction().map_err(internal)?;
                tx.batch_execute("LOCK TABLE cat_work_sources IN ACCESS EXCLUSIVE MODE")
                    .map_err(internal)?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                tx.commit().map_err(internal)
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();
    (blocker, release_tx, blocker_pid)
}

fn seed_expired_guest_lease(store: &Store, cat_id: &str) {
    store
        .with(|client| {
            client
                .execute(
                    "INSERT INTO cat_work_leases
                     (id, cat_id, kind, owner_id, label, expires_at_ms, source_epoch)
                     VALUES ($1,$2,'guest','expired-owner','expired',$3,'guest-boot-1')",
                    &[&format!("expired-{cat_id}"), &cat_id, &(now_ms() - 1)],
                )
                .map(|_| ())
        })
        .unwrap();
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
fn read_only_schema_verifier_requires_exact_preexisting_shape_without_repair() {
    let url = crate::testsupport::isolated_control_store_url();
    let dsn = DsnSource::Literal(url.clone());
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let schema: String = admin
        .query_one("SELECT current_schema()", &[])
        .unwrap()
        .get(0);

    let absent_error = Store::verify_existing_schema(&dsn, None, &schema).unwrap_err();
    assert_eq!(absent_error.code, ErrorCode::FailedPrecondition);
    assert!(absent_error.to_string().contains("refusing installation"));
    let marker_absent: bool = admin
        .query_one("SELECT to_regclass('control_schema_version') IS NULL", &[])
        .unwrap()
        .get(0);
    assert!(marker_absent, "read-only verification must not install DDL");

    drop(Store::connect_from(&dsn, None).unwrap());
    Store::verify_existing_schema(&dsn, None, &schema).unwrap();
    let wrong_schema_error = Store::verify_existing_schema(&dsn, None, "cats_wrong").unwrap_err();
    assert_eq!(wrong_schema_error.code, ErrorCode::FailedPrecondition);
    assert!(wrong_schema_error
        .to_string()
        .contains("expected exact schema"));

    admin
        .batch_execute(
            "ALTER TABLE route_v2_rotation_operator_authority
                 DROP CONSTRAINT route_v2_rotation_operator_trust_sha_ck",
        )
        .unwrap();
    let drift_error = Store::verify_existing_schema(&dsn, None, &schema).unwrap_err();
    assert_eq!(drift_error.code, ErrorCode::FailedPrecondition);
    assert!(
        drift_error
            .to_string()
            .contains("route_v2_rotation_operator_trust_sha_ck"),
        "{drift_error}"
    );
    let constraint_absent: bool = admin
        .query_one(
            "SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_constraint constraint_row
                  JOIN pg_class source ON source.oid=constraint_row.conrelid
                  JOIN pg_namespace namespace_row ON namespace_row.oid=source.relnamespace
                 WHERE namespace_row.nspname=current_schema()
                   AND constraint_row.conname='route_v2_rotation_operator_trust_sha_ck')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(
        constraint_absent,
        "read-only verification must not repair drift"
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
    let mut first_reconciler = first
        .singleton_session(SingletonRole::RuntimeSweeper)
        .unwrap();
    let mut second_reconciler = second.singleton_session(SingletonRole::Reconciler).unwrap();
    let mut second_billing = second
        .singleton_session(SingletonRole::BillingEnforcer)
        .unwrap();

    assert!(first_reconciler.try_acquire().unwrap());
    assert!(
        !second_reconciler.try_acquire().unwrap(),
        "retired Controller and production sweeper must share one exclusion lock"
    );
    assert!(
        second_billing.try_acquire().unwrap(),
        "one role's leader must not make every other role a hot standby"
    );

    drop(first_reconciler);
    // Client destruction closes the session, but PostgreSQL may observe the
    // standby query before it processes that close. Poll the lock authority
    // instead of treating Rust Drop completion as synchronous server state.
    let release_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if second_reconciler.try_acquire().unwrap() {
            break;
        }
        assert!(
            std::time::Instant::now() < release_deadline,
            "PostgreSQL must release leadership within the session cleanup bound"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn singleton_task_cancellation_aborts_old_leader_before_failover() {
    let (first, second) = test_store_pair();
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(AtomicUsize::new(0));

    let first_task =
        crate::server::spawn_singleton_task(Arc::new(first), SingletonRole::BillingEnforcer, {
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
        crate::server::spawn_singleton_task(Arc::new(second), SingletonRole::BillingEnforcer, {
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
            .contains(&format!("version {SCHEMA_VERSION}")),
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
fn refuses_an_old_stamp_without_repairing_its_shape() {
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    {
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin
            .batch_execute(
                "ALTER TABLE nodes DROP COLUMN route_grant_public_key_sha256;
                 DROP TABLE route_grant_rollout_state;
                 UPDATE control_schema_version SET version = 1;",
            )
            .unwrap();
    }

    let Err(error) = Store::connect(&url, None) else {
        panic!("an old stamp must fail closed");
    };
    assert_eq!(error.code, ErrorCode::FailedPrecondition);

    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let stamped: i64 = admin
        .query_one(
            "SELECT version FROM control_schema_version WHERE singleton",
            &[],
        )
        .unwrap()
        .get(0);
    let route_table: Option<String> = admin
        .query_one("SELECT to_regclass('route_grant_rollout_state')::TEXT", &[])
        .unwrap()
        .get(0);
    let route_column: bool = admin
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                 WHERE table_schema=current_schema()
                   AND table_name='nodes'
                   AND column_name='route_grant_public_key_sha256'
             )",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(stamped, 1);
    assert!(route_table.is_none());
    assert!(!route_column);
}

#[test]
fn refuses_current_stamp_without_node_transport_target_projection() {
    assert_eq!(SCHEMA_VERSION, 15);
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    {
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin
            .batch_execute(
                "ALTER TABLE runtime_node_placement_policies
                    DROP COLUMN node_transport_target;",
            )
            .unwrap();
    }

    let Err(error) = Store::connect(&url, None) else {
        panic!("a stamped schema missing the transport target projection must fail closed");
    };
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error
        .to_string()
        .contains(&format!("version {SCHEMA_VERSION}")));

    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let column_still_absent: bool = admin
        .query_one(
            "SELECT NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                 WHERE table_schema=current_schema()
                   AND table_name='runtime_node_placement_policies'
                   AND column_name='node_transport_target')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(
        column_still_absent,
        "startup must not repair a stamped schema"
    );
}

#[test]
fn refuses_unstamped_partial_control_schema_without_adding_tables() {
    let url = crate::testsupport::isolated_control_store_url();
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    admin
        .batch_execute("CREATE TABLE volume_records (volume_id TEXT PRIMARY KEY)")
        .unwrap();

    let Err(error) = Store::connect(&url, None) else {
        panic!("partial schema must fail closed");
    };
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    let stamp: Option<String> = admin
        .query_one("SELECT to_regclass('control_schema_version')::TEXT", &[])
        .unwrap()
        .get(0);
    let accounts: Option<String> = admin
        .query_one("SELECT to_regclass('accounts')::TEXT", &[])
        .unwrap()
        .get(0);
    assert!(stamp.is_none());
    assert!(accounts.is_none());
}

#[test]
fn refuses_current_stamp_with_a_partial_shape_without_repairing_it() {
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    admin
        .batch_execute("DROP TABLE delete_completion_receipts")
        .unwrap();

    let Err(error) = Store::connect(&url, None) else {
        panic!("partial schema must fail closed");
    };
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    let table: Option<String> = admin
        .query_one(
            "SELECT to_regclass('delete_completion_receipts')::TEXT",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(table.is_none(), "startup must not repair a stamped schema");
}

#[test]
fn refuses_current_stamp_with_missing_authority_catalog_barriers() {
    for ddl in [
        "ALTER TABLE node_identities
             DROP CONSTRAINT node_identity_current_public_key_lineage",
        "DROP INDEX runtime_node_one_active_credential",
        "DROP TRIGGER runtime_node_apply_is_immutable
             ON runtime_node_authority_apply_records",
        "ALTER TABLE node_identities
             DROP CONSTRAINT node_identity_current_public_key_lineage;
         ALTER TABLE node_identities
             ADD CONSTRAINT node_identity_current_public_key_lineage
             FOREIGN KEY (
                 credential_id, node_id, credential_public_key_spki_sha256,
                 credential_lineage_state)
             REFERENCES runtime_node_credential_lineage(
                 node_id, credential_id, public_key_spki_sha256, state)
             DEFERRABLE INITIALLY DEFERRED",
        "ALTER TABLE runtime_node_credential_lineage
             DROP CONSTRAINT runtime_node_credential_lineage_node_id_fkey;
         ALTER TABLE runtime_node_credential_lineage
             ADD CONSTRAINT runtime_node_credential_lineage_node_id_fkey
             FOREIGN KEY (node_id) REFERENCES node_identities(node_id)
             ON UPDATE CASCADE ON DELETE CASCADE
             DEFERRABLE INITIALLY DEFERRED",
        "CREATE SCHEMA shadow_authority;
         CREATE TABLE shadow_authority.runtime_node_credential_lineage (
             node_id TEXT NOT NULL,
             credential_id TEXT NOT NULL,
             public_key_spki_sha256 TEXT NOT NULL,
             state TEXT NOT NULL,
             UNIQUE (node_id, credential_id, public_key_spki_sha256, state)
         );
         INSERT INTO shadow_authority.runtime_node_credential_lineage
             (node_id, credential_id, public_key_spki_sha256, state)
         SELECT node_id, credential_id, public_key_spki_sha256, state
           FROM runtime_node_credential_lineage;
         ALTER TABLE node_identities
             DROP CONSTRAINT node_identity_current_public_key_lineage;
         ALTER TABLE node_identities
             ADD CONSTRAINT node_identity_current_public_key_lineage
             FOREIGN KEY (
                 node_id, credential_id, credential_public_key_spki_sha256,
                 credential_lineage_state)
             REFERENCES shadow_authority.runtime_node_credential_lineage(
                 node_id, credential_id, public_key_spki_sha256, state)
             DEFERRABLE INITIALLY DEFERRED",
        "CREATE OR REPLACE FUNCTION control_runtime_node_apply_is_immutable()
             RETURNS TRIGGER LANGUAGE plpgsql AS $$
             BEGIN
                 RETURN OLD;
             END;
             $$",
        "DROP TRIGGER runtime_node_apply_is_immutable
             ON runtime_node_authority_apply_records;
         CREATE TRIGGER runtime_node_apply_is_immutable
             BEFORE UPDATE OR DELETE ON runtime_node_authority_apply_records
             FOR EACH STATEMENT
             EXECUTE FUNCTION control_runtime_node_apply_is_immutable()",
        "DROP TRIGGER runtime_node_apply_is_immutable
             ON runtime_node_authority_apply_records;
         CREATE TRIGGER runtime_node_apply_is_immutable
             BEFORE UPDATE OR DELETE ON runtime_node_authority_apply_records
             FOR EACH ROW WHEN (false)
             EXECUTE FUNCTION control_runtime_node_apply_is_immutable()",
        "DROP TRIGGER runtime_node_policy_update
             ON runtime_node_placement_policies;
         CREATE TRIGGER runtime_node_policy_update
             BEFORE UPDATE OF record ON runtime_node_placement_policies
             FOR EACH ROW
             EXECUTE FUNCTION control_runtime_node_policy_update()",
        "ALTER TABLE runtime_node_placement_policies
             DROP CONSTRAINT runtime_node_placement_policies_node_transport_target_check",
        "ALTER TABLE runtime_node_placement_policies
             DROP CONSTRAINT runtime_node_placement_policies_node_transport_target_check;
         ALTER TABLE runtime_node_placement_policies
             ADD CONSTRAINT runtime_node_placement_policies_node_transport_target_check
             CHECK (node_transport_target LIKE 'https://%')",
    ] {
        let url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).unwrap());
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let current_schema: String = admin
            .query_one("SELECT current_schema()", &[])
            .unwrap()
            .get(0);
        let ddl = ddl.replace("shadow_authority", &format!("{current_schema}_shadow"));
        admin.batch_execute(&ddl).unwrap();

        let Err(error) = Store::connect(&url, None) else {
            panic!("a stamped schema missing {ddl:?} must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(
            error.to_string().contains("authority catalog object"),
            "operator must see the catalog mismatch, got: {error}"
        );
    }
}

#[test]
fn refuses_missing_or_replaced_authorization_indexes_without_repair() {
    for (index, ddl, expected_fragment) in [
        (
            "volume_authorizations_record_authorization",
            "DROP INDEX volume_authorizations_record_authorization",
            None,
        ),
        (
            "volume_authorizations_record_authorization",
            "DROP INDEX volume_authorizations_record_authorization;
             CREATE INDEX volume_authorizations_record_authorization
                 ON volume_authorizations(volume_id)",
            Some("USING btree (volume_id)"),
        ),
        (
            "volume_authorizations_disposable_scope",
            "DROP INDEX volume_authorizations_disposable_scope",
            None,
        ),
        (
            "volume_authorizations_disposable_scope",
            "DROP INDEX volume_authorizations_disposable_scope;
             CREATE INDEX volume_authorizations_disposable_scope
                 ON volume_authorizations(
                     volume_id, placement_epoch, desired_revision,
                     authorization_id COLLATE \"C\"
                 ) WHERE kind='disposable_root_delete'",
            Some("volume_id, placement_epoch, desired_revision"),
        ),
    ] {
        let url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).unwrap());
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin.batch_execute(ddl).unwrap();

        let Err(error) = Store::connect(&url, None) else {
            panic!("a stamped schema with a changed authorization index must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(
            error.to_string().contains(index),
            "operator must see the changed index name, got: {error}"
        );
        let definition: Option<String> = admin
            .query_one("SELECT pg_get_indexdef(to_regclass($1))", &[&index])
            .unwrap()
            .get(0);
        match expected_fragment {
            Some(fragment) => assert!(
                definition
                    .as_deref()
                    .is_some_and(|value| value.contains(fragment)),
                "startup repaired or replaced the deliberately wrong index: {definition:?}"
            ),
            None => assert!(
                definition.is_none(),
                "startup recreated a deliberately dropped index: {definition:?}"
            ),
        }
    }
}

#[test]
fn refuses_expression_index_with_wrong_catalog_collation_without_repair() {
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let changed = admin
        .execute(
            "UPDATE pg_index
                SET indcollation=(
                    'pg_catalog.\"POSIX\"'::regcollation::OID::TEXT
                )::OIDVECTOR
              WHERE indexrelid='volume_records_record_volume'::regclass",
            &[],
        )
        .unwrap();
    assert_eq!(changed, 1);

    let Err(error) = Store::connect(&url, None) else {
        panic!("a stamped expression index with wrong collation must fail closed");
    };
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(
        error.to_string().contains("volume_records_record_volume"),
        "operator must see the wrong expression index, got: {error}"
    );
}

#[test]
fn refuses_missing_runtime_operation_lookup_indexes_without_repair() {
    for index in [
        "runtime_operations_lookup_scalar_scalar",
        "runtime_operations_lookup_scalar_record",
        "runtime_operations_lookup_record_scalar",
        "runtime_operations_lookup_record_record",
    ] {
        let url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).unwrap());
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin.batch_execute(&format!("DROP INDEX {index}")).unwrap();

        let Err(error) = Store::connect(&url, None) else {
            panic!("a stamped schema missing {index} must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains(index), "{error}");
        let definition: Option<String> = admin
            .query_one("SELECT pg_get_indexdef(to_regclass($1))", &[&index])
            .unwrap()
            .get(0);
        assert!(
            definition.is_none(),
            "startup recreated deliberately dropped {index}: {definition:?}"
        );
    }
}

#[test]
fn refuses_missing_or_weakened_volume_owner_constraints_without_repair() {
    for (constraint, ddl, expected_definition) in [
        (
            "volume_records_owner_present_check",
            "ALTER TABLE volume_records
                 DROP CONSTRAINT volume_records_owner_present_check",
            None,
        ),
        (
            "volume_records_owner_node_present_check",
            "ALTER TABLE volume_records
                 DROP CONSTRAINT volume_records_owner_node_present_check;
             ALTER TABLE volume_records
                 ADD CONSTRAINT volume_records_owner_node_present_check
                 CHECK (owner_binding IS NULL OR owner_node_id IS NOT NULL)",
            Some("owner_binding IS NULL"),
        ),
        (
            "volume_records_owner_binding_check",
            "ALTER TABLE volume_records
                 DROP CONSTRAINT volume_records_owner_binding_check;
             ALTER TABLE volume_records
                 ADD CONSTRAINT volume_records_owner_binding_check
                 CHECK (owner_binding IS NULL OR jsonb_typeof(owner_binding)='object')",
            Some("jsonb_typeof(owner_binding)"),
        ),
    ] {
        let url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).unwrap());
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin.batch_execute(ddl).unwrap();

        let Err(error) = Store::connect(&url, None) else {
            panic!("a stamped schema with a changed Volume owner constraint must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains(constraint), "{error}");
        let definition: Option<String> = admin
            .query_opt(
                "SELECT pg_get_constraintdef(catalog_constraint.oid, FALSE)
                   FROM pg_constraint catalog_constraint
                   JOIN pg_class source ON source.oid=catalog_constraint.conrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                  WHERE source_namespace.nspname=current_schema()
                    AND source.relname='volume_records'
                    AND catalog_constraint.conname=$1",
                &[&constraint],
            )
            .unwrap()
            .map(|row| row.get(0));
        match expected_definition {
            Some(fragment) => assert!(
                definition
                    .as_deref()
                    .is_some_and(|value| value.contains(fragment)),
                "startup repaired or replaced the deliberately weak constraint: {definition:?}"
            ),
            None => assert!(
                definition.is_none(),
                "startup recreated a deliberately dropped constraint: {definition:?}"
            ),
        }
    }
}

#[test]
fn gateway_check_constraints_are_exact_and_current_stamp_rejects_drift() {
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let gateway_constraints = super::schema::REQUIRED_CHECK_CONSTRAINTS
        .iter()
        .filter(|(table, _, _)| table.starts_with("route_v2_gateway_"))
        .collect::<Vec<_>>();
    assert_eq!(gateway_constraints.len(), 22);
    for (table, constraint, expected_definition) in gateway_constraints {
        let definition: String = admin
            .query_one(
                "SELECT pg_get_constraintdef(catalog_constraint.oid, FALSE)
                   FROM pg_constraint catalog_constraint
                   JOIN pg_class source ON source.oid=catalog_constraint.conrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                  WHERE source_namespace.nspname=current_schema()
                    AND source.relname=$1 AND catalog_constraint.conname=$2",
                &[table, constraint],
            )
            .unwrap()
            .get(0);
        assert_eq!(&definition, expected_definition, "{constraint}");
    }

    for (constraint, ddl, expected_definition) in [
        (
            "route_v2_gateway_credential_first_revision_ck",
            "ALTER TABLE route_v2_gateway_credential_lineage
                 DROP CONSTRAINT route_v2_gateway_credential_first_revision_ck",
            None,
        ),
        (
            "route_v2_gateway_current_scope_ck",
            "ALTER TABLE route_v2_gateway_current_credentials
                 DROP CONSTRAINT route_v2_gateway_current_scope_ck;
             ALTER TABLE route_v2_gateway_current_credentials
                 ADD CONSTRAINT route_v2_gateway_current_scope_ck
                 CHECK (scope IS NOT NULL)",
            Some("scope IS NOT NULL"),
        ),
    ] {
        let drift_url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&drift_url, None).unwrap());
        let mut drift_admin = postgres::Client::connect(&drift_url, postgres::NoTls).unwrap();
        drift_admin.batch_execute(ddl).unwrap();
        let Err(error) = Store::connect(&drift_url, None) else {
            panic!("a current stamp with changed {constraint} must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains(constraint), "{error}");
        let definition: Option<String> = drift_admin
            .query_opt(
                "SELECT pg_get_constraintdef(catalog_constraint.oid, FALSE)
                   FROM pg_constraint catalog_constraint
                   JOIN pg_class source ON source.oid=catalog_constraint.conrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                  WHERE source_namespace.nspname=current_schema()
                    AND catalog_constraint.conname=$1",
                &[&constraint],
            )
            .unwrap()
            .map(|row| row.get(0));
        match expected_definition {
            Some(fragment) => assert!(
                definition
                    .as_deref()
                    .is_some_and(|value| value.contains(fragment)),
                "startup repaired the weakened constraint: {definition:?}"
            ),
            None => assert!(
                definition.is_none(),
                "startup recreated the dropped constraint: {definition:?}"
            ),
        }
    }
}

#[test]
fn route_v2_signer_catalog_is_exact_and_current_stamp_rejects_drift() {
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let signer_constraints = super::schema::REQUIRED_CHECK_CONSTRAINTS
        .iter()
        .filter(|(table, _, _)| {
            matches!(
                *table,
                "route_v2_signing_authority"
                    | "route_v2_signer_revisions"
                    | "route_v2_signer_key_lineage"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(signer_constraints.len(), 27);
    for (table, constraint, expected_definition) in signer_constraints {
        let definition: String = admin
            .query_one(
                "SELECT pg_get_constraintdef(catalog_constraint.oid, FALSE)
                   FROM pg_constraint catalog_constraint
                   JOIN pg_class source ON source.oid=catalog_constraint.conrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                  WHERE source_namespace.nspname=current_schema()
                    AND source.relname=$1 AND catalog_constraint.conname=$2",
                &[table, constraint],
            )
            .unwrap()
            .get(0);
        assert_eq!(&definition, expected_definition, "{constraint}");
    }

    for (catalog_object, ddl) in [
        (
            "route_v2_signing_authority_current_revision_fkey",
            "ALTER TABLE route_v2_signing_authority
                 DROP CONSTRAINT route_v2_signing_authority_current_revision_fkey",
        ),
        (
            "route_v2_signer_revision_is_immutable",
            "ALTER TABLE route_v2_signer_revisions
                 DISABLE TRIGGER route_v2_signer_revision_is_immutable",
        ),
        (
            "route_v2_signing_authority_selection_ck",
            "ALTER TABLE route_v2_signing_authority
                 DROP CONSTRAINT route_v2_signing_authority_selection_ck;
             ALTER TABLE route_v2_signing_authority
                 ADD CONSTRAINT route_v2_signing_authority_selection_ck
                 CHECK (signer_state IN ('active', 'disabled'))",
        ),
    ] {
        let drift_url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&drift_url, None).unwrap());
        let mut drift_admin = postgres::Client::connect(&drift_url, postgres::NoTls).unwrap();
        drift_admin.batch_execute(ddl).unwrap();
        let Err(error) = Store::connect(&drift_url, None) else {
            panic!("a current stamp with changed {catalog_object} must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains(catalog_object), "{error}");
    }
}

#[test]
fn route_v2_rotation_catalog_is_exact_and_current_stamp_rejects_drift() {
    fn is_rotation_table(table: &str) -> bool {
        matches!(
            table,
            "route_v2_rotation_operator_authority"
                | "route_v2_rotation_operator_credentials"
                | "route_v2_signing_command_receipts"
                | "route_v2_public_ring_deliveries"
        )
    }

    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let check_constraints = super::schema::REQUIRED_CHECK_CONSTRAINTS
        .iter()
        .filter(|(table, _, _)| is_rotation_table(table))
        .collect::<Vec<_>>();
    assert_eq!(check_constraints.len(), 32);
    for (table, constraint, expected_definition) in check_constraints {
        let definition: String = admin
            .query_one(
                "SELECT pg_get_constraintdef(catalog_constraint.oid, FALSE)
                   FROM pg_constraint catalog_constraint
                   JOIN pg_class source ON source.oid=catalog_constraint.conrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                  WHERE source_namespace.nspname=current_schema()
                    AND source.relname=$1 AND catalog_constraint.conname=$2",
                &[table, constraint],
            )
            .unwrap()
            .get(0);
        assert_eq!(&definition, expected_definition, "{constraint}");
    }

    let foreign_keys = super::schema::REQUIRED_FOREIGN_KEYS
        .iter()
        .filter(|(table, _, _)| is_rotation_table(table))
        .collect::<Vec<_>>();
    assert_eq!(foreign_keys.len(), 5);
    for (table, constraint, expected_definition) in foreign_keys {
        let definition: String = admin
            .query_one(
                "SELECT pg_get_constraintdef(catalog_constraint.oid, FALSE)
                   FROM pg_constraint catalog_constraint
                   JOIN pg_class source ON source.oid=catalog_constraint.conrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                  WHERE source_namespace.nspname=current_schema()
                    AND source.relname=$1 AND catalog_constraint.conname=$2",
                &[table, constraint],
            )
            .unwrap()
            .get(0);
        assert_eq!(&definition, expected_definition, "{constraint}");
    }

    for (catalog_object, ddl) in [
        (
            "route_v2_rotation_operator_release_sha_ck",
            "ALTER TABLE route_v2_rotation_operator_authority
                 DROP CONSTRAINT route_v2_rotation_operator_release_sha_ck;
             ALTER TABLE route_v2_rotation_operator_authority
                 ADD CONSTRAINT route_v2_rotation_operator_release_sha_ck
                 CHECK (release_commit_sha <> '')",
        ),
        (
            "route_v2_rotation_operator_credential_authority_fkey",
            "ALTER TABLE route_v2_rotation_operator_credentials
                 DROP CONSTRAINT route_v2_rotation_operator_credential_authority_fkey",
        ),
        (
            "route_v2_rotation_operator_identity_key",
            "ALTER TABLE route_v2_rotation_operator_authority
                 DROP CONSTRAINT route_v2_rotation_operator_identity_key;
             CREATE INDEX route_v2_rotation_operator_identity_key
                 ON route_v2_rotation_operator_authority(
                     authority_id, route_deployment_id,
                     release_commit_sha, trust_sha256)",
        ),
        (
            "route_v2_public_ring_delivery_is_immutable",
            "ALTER TABLE route_v2_public_ring_deliveries
                 DISABLE TRIGGER route_v2_public_ring_delivery_is_immutable",
        ),
    ] {
        let drift_url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&drift_url, None).unwrap());
        let mut drift_admin = postgres::Client::connect(&drift_url, postgres::NoTls).unwrap();
        drift_admin.batch_execute(ddl).unwrap();
        let Err(error) = Store::connect(&drift_url, None) else {
            panic!("a current stamp with changed {catalog_object} must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains(catalog_object), "{error}");
    }
}

#[test]
fn refuses_missing_or_replaced_volume_primary_key_without_repair() {
    for (ddl, expected_index_fragment) in [
        (
            "ALTER TABLE volume_records DROP CONSTRAINT volume_records_pkey CASCADE",
            None,
        ),
        (
            "ALTER TABLE volume_records DROP CONSTRAINT volume_records_pkey CASCADE;
             CREATE UNIQUE INDEX volume_records_pkey ON volume_records(volume_id)",
            Some("CREATE UNIQUE INDEX"),
        ),
    ] {
        let url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).unwrap());
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin.batch_execute(ddl).unwrap();

        let Err(error) = Store::connect(&url, None) else {
            panic!("a stamped schema with a changed Volume primary key must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains("volume_records_pkey"), "{error}");
        let definition: Option<String> = admin
            .query_one(
                "SELECT pg_get_indexdef(to_regclass('volume_records_pkey'))",
                &[],
            )
            .unwrap()
            .get(0);
        match expected_index_fragment {
            Some(fragment) => assert!(
                definition
                    .as_deref()
                    .is_some_and(|value| value.contains(fragment)),
                "startup repaired the deliberately non-primary unique index: {definition:?}"
            ),
            None => assert!(
                definition.is_none(),
                "startup recreated the deliberately dropped primary key: {definition:?}"
            ),
        }
    }
}

#[test]
fn refuses_missing_or_replaced_persistent_disk_identity_indexes_without_repair() {
    for (index, ddl, expected_fragment) in [
        (
            "disk_records_initialization_token_unique",
            "DROP INDEX disk_records_initialization_token_unique",
            None,
        ),
        (
            "disk_records_initialization_token_unique",
            "DROP INDEX disk_records_initialization_token_unique;
             CREATE INDEX disk_records_initialization_token_unique
                 ON disk_records(initialization_token)
                 WHERE role_kind='persistent'",
            Some("CREATE INDEX"),
        ),
        (
            "disk_records_filesystem_uuid_unique",
            "DROP INDEX disk_records_filesystem_uuid_unique",
            None,
        ),
        (
            "disk_records_filesystem_uuid_unique",
            "DROP INDEX disk_records_filesystem_uuid_unique;
             CREATE UNIQUE INDEX disk_records_filesystem_uuid_unique
                 ON disk_records(filesystem_uuid)
                 WHERE role_kind='root'",
            Some("role_kind = 'root'::text"),
        ),
    ] {
        let url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).unwrap());
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin.batch_execute(ddl).unwrap();

        let Err(error) = Store::connect(&url, None) else {
            panic!("a stamped schema with changed {index} must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains(index), "{error}");
        let definition: Option<String> = admin
            .query_one("SELECT pg_get_indexdef(to_regclass($1))", &[&index])
            .unwrap()
            .get(0);
        match expected_fragment {
            Some(fragment) => assert!(
                definition
                    .as_deref()
                    .is_some_and(|value| value.contains(fragment)),
                "startup repaired deliberately changed {index}: {definition:?}"
            ),
            None => assert!(
                definition.is_none(),
                "startup recreated deliberately dropped {index}: {definition:?}"
            ),
        }
    }
}

#[test]
fn refuses_missing_or_replaced_volume_owner_indexes_without_repair() {
    for (index, ddl, expected_fragment) in [
        (
            "volume_records_owner_node",
            "DROP INDEX volume_records_owner_node",
            None,
        ),
        (
            "volume_records_owner_node",
            "DROP INDEX volume_records_owner_node;
             CREATE INDEX volume_records_owner_node
                 ON volume_records(volume_id, owner_node_id)
                 WHERE owner_node_id IS NOT NULL",
            Some("volume_id, owner_node_id"),
        ),
        (
            "volume_records_owner_binding_node",
            "DROP INDEX volume_records_owner_binding_node",
            None,
        ),
        (
            "volume_records_owner_binding_node",
            "DROP INDEX volume_records_owner_binding_node;
             CREATE INDEX volume_records_owner_binding_node
                 ON volume_records(owner_node_id, volume_id)
                 WHERE owner_node_id IS NOT NULL",
            Some("owner_node_id, volume_id"),
        ),
    ] {
        let url = crate::testsupport::isolated_control_store_url();
        drop(Store::connect(&url, None).unwrap());
        let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        admin.batch_execute(ddl).unwrap();

        let Err(error) = Store::connect(&url, None) else {
            panic!("a stamped schema with a changed Volume owner index must fail closed");
        };
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.to_string().contains(index), "{error}");
        let definition: Option<String> = admin
            .query_one("SELECT pg_get_indexdef(to_regclass($1))", &[&index])
            .unwrap()
            .get(0);
        match expected_fragment {
            Some(fragment) => assert!(
                definition
                    .as_deref()
                    .is_some_and(|value| value.contains(fragment)),
                "startup repaired or replaced the deliberately wrong index: {definition:?}"
            ),
            None => assert!(
                definition.is_none(),
                "startup recreated a deliberately dropped index: {definition:?}"
            ),
        }
    }
}

#[test]
fn concurrent_first_connections_create_one_exact_schema() {
    let url = crate::testsupport::isolated_control_store_url();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let url = url.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            Store::connect(&url, None)
        }));
    }
    barrier.wait();
    for worker in workers {
        drop(worker.join().unwrap().unwrap());
    }

    let store = Store::connect(&url, None).unwrap();
    let stamped = store
        .with(|client| {
            client
                .query_one(
                    "SELECT version FROM control_schema_version WHERE singleton",
                    &[],
                )
                .map(|row| row.get::<_, i64>(0))
        })
        .unwrap();
    assert_eq!(stamped, SCHEMA_VERSION);
}

#[test]
fn route_grant_legacy_admission_phase_closes_once_and_rejects_downgrades() {
    let store = test_store();
    let expected = "a".repeat(64);
    store
        .register_node(
            "legacy-existing",
            "http://node",
            "http://gateway",
            4,
            8192,
            false,
        )
        .unwrap();
    store
        .register_node_with_admission(
            "legacy-existing",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, None, &expected),
        )
        .unwrap();
    assert_eq!(
        store.get_node("legacy-existing").unwrap().state,
        NodeState::Ready,
        "the one-time additive rollout must preserve an already-Ready legacy Node"
    );

    store
        .register_node_with_admission(
            "fresh-legacy",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, None, &expected),
        )
        .unwrap();
    assert_eq!(
        store.get_node("fresh-legacy").unwrap().state,
        NodeState::Cordoned
    );

    store
        .register_node_with_admission(
            "keyed",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, Some(&expected), &expected),
        )
        .unwrap();
    store
        .register_node_with_admission(
            "keyed",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, None, &expected),
        )
        .unwrap();
    assert_eq!(
        store.get_node("keyed").unwrap().state,
        NodeState::Cordoned,
        "a keyed Node must never downgrade through the legacy exception"
    );

    store
        .register_node_with_admission(
            "legacy-existing",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, Some(&expected), &expected),
        )
        .unwrap();
    let phase_open: bool = store
        .with(|client| {
            client
                .query_one(
                    "SELECT legacy_admission_open FROM route_grant_rollout_state WHERE singleton",
                    &[],
                )?
                .try_get(0)
        })
        .unwrap();
    assert!(
        !phase_open,
        "the completed legacy phase did not close durably"
    );

    // Simulate an old binary recreating a Ready row after the phase closed.
    // Its next admission-aware registration must fail closed, and no later
    // registration is allowed to reopen the persisted phase.
    store
        .register_node(
            "late-legacy",
            "http://node",
            "http://gateway",
            4,
            8192,
            false,
        )
        .unwrap();
    store
        .register_node_with_admission(
            "late-legacy",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, None, &expected),
        )
        .unwrap();
    assert_eq!(
        store.get_node("late-legacy").unwrap().state,
        NodeState::Cordoned
    );
    let still_closed: bool = store
        .with(|client| {
            client
                .query_one(
                    "SELECT NOT legacy_admission_open FROM route_grant_rollout_state WHERE singleton",
                    &[],
                )?
                .try_get(0)
        })
        .unwrap();
    assert!(still_closed);
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
fn default_endpoint_update_reuses_the_default_route() {
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
}

#[test]
fn automatic_suspend_is_disabled_for_an_idle_running_cat() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "auto-suspend-disabled");
    let (cat, _, _) = create_test_cat(&store, &workspace, "idle").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store.set_observed(&cat.id, ObservedState::Running).unwrap();
    store
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 1,
            leases: vec![],
        })
        .unwrap();
    let operation_count = store.list_operations(&workspace.id).unwrap().len();

    assert!(store.try_auto_suspend(&cat.id, 5_000).unwrap().is_none());

    let unchanged = store.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(unchanged.desired_state, DesiredState::Running);
    assert_eq!(unchanged.observed_state, ObservedState::Running);
    assert_eq!(unchanged.generation, 1);
    assert_eq!(
        store.list_operations(&workspace.id).unwrap().len(),
        operation_count
    );
}

#[test]
fn concurrent_placement_cannot_overcommit_a_node() {
    let _serial = serialize_structural_postgres_lock_test();
    // Placement used to be a read of the node's free capacity followed by a
    // separate write, which only holds up while one Cat is placed at a time.
    // The reconcile loop now runs flows concurrently, so this is the property
    // that keeps it honest.
    let url = crate::testsupport::isolated_control_store_url();
    let first = concurrency_store(&url);
    let second = concurrency_store(&url);
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
    let _serial = serialize_structural_postgres_lock_test();
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
fn wrong_key_registration_linearizes_after_an_authorized_placement() {
    let _serial = serialize_structural_postgres_lock_test();
    let url = crate::testsupport::isolated_control_store_url();
    let placement = concurrency_store(&url);
    let registrar = concurrency_store(&url);
    let observer = concurrency_store(&url);
    let placement_pid = backend_pid(&placement);
    let registrar_pid = backend_pid(&registrar);
    let workspace = bootstrap_workspace(&placement, "registration-placement");
    placement
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    let (cat, _, _) = create_test_cat(&placement, &workspace, "placed-before-cordon").unwrap();

    let cat_id = cat.id.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let placement_worker = std::thread::spawn(move || {
        placement
            .enter(move |client| {
                let client = client?;
                let mut tx = client.transaction().map_err(internal)?;
                lock_placement(&mut tx).map_err(internal)?;
                let state: String = tx
                    .query_one("SELECT state FROM nodes WHERE id='node-1'", &[])
                    .map_err(internal)?
                    .try_get(0)
                    .map_err(internal)?;
                assert_eq!(state, "ready");
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                tx.execute("UPDATE cats SET node_id='node-1' WHERE id=$1", &[&cat_id])
                    .map_err(internal)?;
                tx.commit().map_err(internal)
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();

    let registration_worker = std::thread::spawn(move || {
        registrar.register_node_with_admission(
            "node-1",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, Some("wrong"), "expected"),
        )
    });
    let blocked = wait_until_blocked_by(&observer, registrar_pid, placement_pid);
    release_tx.send(()).unwrap();
    placement_worker.join().unwrap();
    registration_worker.join().unwrap().unwrap();

    assert!(
        blocked,
        "wrong-key registration did not wait for the placement linearization point"
    );
    assert_eq!(
        observer.must_get_cat_by_id(&cat.id).unwrap().node_id,
        Some("node-1".into())
    );
    assert_eq!(
        observer.get_node("node-1").unwrap().state,
        NodeState::Cordoned,
        "the registration that linearized second failed to close scheduling"
    );
}

#[test]
fn uncordon_rechecks_the_fingerprint_after_a_concurrent_key_change() {
    let _serial = serialize_structural_postgres_lock_test();
    let url = crate::testsupport::isolated_control_store_url();
    let key_changer = concurrency_store(&url);
    let uncordoner = concurrency_store(&url);
    let observer = concurrency_store(&url);
    key_changer
        .register_node_with_admission(
            "node-1",
            "http://node",
            "http://gateway",
            4,
            8192,
            NodeAdmission::for_route_grant(false, Some("expected"), "expected"),
        )
        .unwrap();
    key_changer
        .set_node_state("node-1", NodeState::Cordoned)
        .unwrap();
    let key_changer_pid = backend_pid(&key_changer);
    let uncordoner_pid = backend_pid(&uncordoner);

    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let key_change = std::thread::spawn(move || {
        key_changer
            .enter(move |client| {
                let client = client?;
                let mut tx = client.transaction().map_err(internal)?;
                lock_placement(&mut tx).map_err(internal)?;
                tx.execute(
                    "UPDATE nodes
                        SET state='cordoned', scheduling_disabled=TRUE,
                            route_grant_public_key_sha256='wrong'
                      WHERE id='node-1'",
                    &[],
                )
                .map_err(internal)?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                tx.commit().map_err(internal)
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();

    let uncordon =
        std::thread::spawn(move || uncordoner.uncordon_node_with_route_grant("node-1", "expected"));
    let blocked = wait_until_blocked_by(&observer, uncordoner_pid, key_changer_pid);
    release_tx.send(()).unwrap();
    key_change.join().unwrap();
    let error = uncordon
        .join()
        .unwrap()
        .expect_err("stale uncordon must not overwrite the new verifier identity");

    assert!(blocked, "uncordon did not wait for the verifier transition");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    let node = observer.get_node("node-1").unwrap();
    assert_eq!(node.state, NodeState::Cordoned);
    assert_eq!(node.route_grant_public_key_sha256.as_deref(), Some("wrong"));
}

#[test]
fn gateway_work_lease_can_be_shortened_and_released() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "alpha");
    let (cat, _, _) = create_test_cat(&store, &workspace, "web").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
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
    assert_eq!(
        store.work_status(&cat.id, 5_000).unwrap().active_work_count,
        1
    );
    let shortened = store
        .acquire_work(&cat.id, WorkKind::Gateway, "request-1", "handoff", 100)
        .unwrap();
    assert_eq!(
        shortened.id, lease.id,
        "renewal must not create a lease gap"
    );
    assert!(
        shortened.expires_at_unix_ms <= super::now_ms() + 150,
        "renewal must be able to shorten a wake lease to its handoff window"
    );
    store.release_work(&shortened.id).unwrap();
    assert_eq!(
        store.work_status(&cat.id, 5_000).unwrap().active_work_count,
        0
    );
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
    let auto = store
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.auto_suspend")
        .unwrap();
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
fn guest_work_from_the_retained_runtime_survives_cancel_first_ordering() {
    let store = test_store();
    let workspace = bootstrap_workspace(&store, "cancel-first-guest-work");
    let (cat, _, create) = create_test_cat(&store, &workspace, "cancel-first-guest-work").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store.set_observed(&cat.id, ObservedState::Running).unwrap();
    store.finish_operation(&create.id, None).unwrap();
    assert!(!store
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 0,
            leases: vec![],
        })
        .unwrap());
    let auto = store
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.auto_suspend")
        .unwrap();
    store
        .set_observed(&cat.id, ObservedState::Suspending)
        .unwrap();

    // The Node can return ActivityChanged before its work watcher publishes
    // the sequence that caused the rejection. The runtime was never replaced,
    // so its generation-1 report remains the authoritative Guest source.
    store
        .cancel_rejected_suspend(&cat.id, auto.resource_generation)
        .unwrap();
    assert!(!store
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 1,
            leases: vec![GuestWorkLease {
                id: "late-job".into(),
                label: "late-job".into(),
                remaining_ttl_ms: 30_000,
            }],
        })
        .unwrap());

    let running = store.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(running.desired_state, DesiredState::Running);
    assert_eq!(running.observed_state, ObservedState::Running);
    assert_eq!(running.generation, 2);
    assert_eq!(
        store.get_operation(&auto.id).unwrap().phase,
        OperationPhase::Failed
    );
    assert_eq!(
        store
            .work_status(&cat.id, 60_000)
            .unwrap()
            .active_work_count,
        1
    );

    // A failed auto-suspend from an older generation is not a blanket waiver
    // for later stale reports. Only the current generation's failed operation
    // proves that its immediately preceding runtime was retained.
    let newer = store
        .set_desired(&cat.id, DesiredState::Running, None, "cat.start")
        .unwrap();
    assert_eq!(newer.resource_generation, 3);
    let stale = store
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 2,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 2,
            leases: vec![],
        })
        .expect_err("an older failed auto-suspend must not authorize generation 2 at generation 3");
    assert_eq!(stale.code, ErrorCode::Conflict);
    assert_eq!(stale.message, "work status generation is stale");
}

fn assert_stale_guest_work_cannot_overwrite_lifecycle(
    newer_desired: DesiredState,
    operation_kind: &'static str,
) {
    let _serial = serialize_structural_postgres_lock_test();
    let url = crate::testsupport::isolated_control_store_url();
    let store = concurrency_store(&url);
    let ingest_store = concurrency_store(&url);
    let observer = concurrency_store(&url);
    let lifecycle_pid = backend_pid(&store);
    let guest_pid = backend_pid(&ingest_store);
    let workspace = bootstrap_workspace(&store, "guest-work-cas");
    let (cat, _, create) = create_test_cat(&store, &workspace, "guest-work-cas").unwrap();
    store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    store.set_placement(&cat.id, Some("node-1")).unwrap();
    store.set_observed(&cat.id, ObservedState::Running).unwrap();
    store.finish_operation(&create.id, None).unwrap();
    let suspend = store
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.suspend")
        .unwrap();
    store
        .set_observed(&cat.id, ObservedState::Suspended)
        .unwrap();
    store.finish_operation(&suspend.id, None).unwrap();

    // Hold both the Cat authority and the first table Guest work touches after
    // its Cat read. The table lock makes the old non-locking implementation
    // pause after its stale read; pg_blocking_pids below proves that the fixed
    // implementation instead pauses on this exact lifecycle transaction.
    let cat_id = cat.id.clone();
    let desired = desired_str(newer_desired).to_string();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let lifecycle = std::thread::spawn(move || {
        store
            .enter(move |client| {
                let client = client?;
                let mut tx = client.transaction().map_err(internal)?;
                let row = tx
                    .query_one(
                        "SELECT workspace_id, generation FROM cats WHERE id=$1 FOR UPDATE",
                        &[&cat_id],
                    )
                    .map_err(internal)?;
                let workspace_id: String = row.try_get(0).map_err(internal)?;
                let generation: i64 = row.try_get(1).map_err(internal)?;
                assert_eq!(generation, 2);
                let next = generation + 1;
                tx.execute(
                    "UPDATE cats SET desired_state=$2, generation=$3 WHERE id=$1",
                    &[&cat_id, &desired, &next],
                )
                .map_err(internal)?;
                let operation =
                    Store::insert_operation(&mut tx, &workspace_id, operation_kind, &cat_id, next)?;
                tx.batch_execute("LOCK TABLE cat_work_sources IN ACCESS EXCLUSIVE MODE")
                    .map_err(internal)?;
                locked_tx.send(operation.id).unwrap();
                release_rx.recv().unwrap();
                tx.commit().map_err(internal)
            })
            .unwrap();
    });
    let stop_operation_id = locked_rx.recv().unwrap();

    let report_cat_id = cat.id.clone();
    let guest = std::thread::spawn(move || {
        ingest_store.ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: report_cat_id,
            generation: 2,
            guest_source_epoch: "guest-before-cold".into(),
            guest_lease_sequence: 1,
            leases: vec![GuestWorkLease {
                id: "active-request".into(),
                label: "active-request".into(),
                remaining_ttl_ms: 5_000,
            }],
        })
    });

    let guest_waited_on_the_lifecycle_transaction =
        wait_until_blocked_by(&observer, guest_pid, lifecycle_pid);
    release_tx.send(()).unwrap();
    lifecycle.join().unwrap();
    assert!(
        guest_waited_on_the_lifecycle_transaction,
        "the fixture never established the concurrent Cat-authority window"
    );
    let error = guest
        .join()
        .unwrap()
        .expect_err("a generation-2 Guest report must not supersede committed generation 3");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.message, "work status generation is stale");

    let current = observer.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(current.desired_state, newer_desired);
    assert_eq!(current.generation, 3);
    let operations = observer.pending_operations_for(&cat.id).unwrap();
    assert_eq!(operations.len(), 1, "stale Guest work added an operation");
    assert_eq!(operations[0].id, stop_operation_id);
    assert_eq!(operations[0].kind, operation_kind);
    assert_eq!(operations[0].resource_generation, 3);
    let work_source_count: i64 = observer
        .with(|client| {
            client
                .query_one(
                    "SELECT COUNT(*) FROM cat_work_sources WHERE cat_id=$1",
                    &[&cat.id],
                )?
                .try_get(0)
        })
        .unwrap();
    assert_eq!(
        work_source_count, 0,
        "the rejected stale report must roll back its work source"
    );
}

#[test]
fn stale_guest_work_cannot_overwrite_a_concurrent_cold_generation() {
    assert_stale_guest_work_cannot_overwrite_lifecycle(DesiredState::Cold, "cat.stop");
}

#[test]
fn stale_guest_work_cannot_overwrite_a_concurrent_delete_generation() {
    assert_stale_guest_work_cannot_overwrite_lifecycle(DesiredState::Deleted, "cat.delete");
}

#[test]
fn stale_guest_work_cannot_cancel_a_newer_cold_during_inflight_suspend() {
    let _serial = serialize_structural_postgres_lock_test();
    let url = crate::testsupport::isolated_control_store_url();
    let lifecycle_store = concurrency_store(&url);
    let ingest_store = concurrency_store(&url);
    let observer = concurrency_store(&url);
    let lifecycle_pid = backend_pid(&lifecycle_store);
    let guest_pid = backend_pid(&ingest_store);
    let workspace = bootstrap_workspace(&lifecycle_store, "guest-inflight-cas");
    let (cat, _, create) =
        create_test_cat(&lifecycle_store, &workspace, "guest-inflight-cas").unwrap();
    lifecycle_store
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    lifecycle_store
        .set_placement(&cat.id, Some("node-1"))
        .unwrap();
    lifecycle_store
        .set_observed(&cat.id, ObservedState::Running)
        .unwrap();
    lifecycle_store.finish_operation(&create.id, None).unwrap();
    assert!(!lifecycle_store
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 0,
            leases: vec![],
        })
        .unwrap());
    let auto = lifecycle_store
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.auto_suspend")
        .unwrap();
    assert_eq!(auto.resource_generation, 2);
    lifecycle_store
        .set_observed(&cat.id, ObservedState::Suspending)
        .unwrap();

    // The newer lifecycle transaction wins Cat authority, then holds the work
    // source table solely to make the old stale-read implementation observable.
    let cat_id = cat.id.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let lifecycle = std::thread::spawn(move || {
        lifecycle_store
            .enter(move |client| {
                let client = client?;
                let mut tx = client.transaction().map_err(internal)?;
                let row = tx
                    .query_one(
                        "SELECT workspace_id, generation FROM cats WHERE id=$1 FOR UPDATE",
                        &[&cat_id],
                    )
                    .map_err(internal)?;
                let workspace_id: String = row.try_get(0).map_err(internal)?;
                let generation: i64 = row.try_get(1).map_err(internal)?;
                assert_eq!(generation, 2);
                Store::fail_pending_auto_tier(
                    &mut tx,
                    &cat_id,
                    "superseded by a newer Cat action",
                )?;
                let next = generation + 1;
                tx.execute(
                    "UPDATE cats SET desired_state='cold', generation=$2 WHERE id=$1",
                    &[&cat_id, &next],
                )
                .map_err(internal)?;
                let stop =
                    Store::insert_operation(&mut tx, &workspace_id, "cat.stop", &cat_id, next)?;
                tx.batch_execute("LOCK TABLE cat_work_sources IN ACCESS EXCLUSIVE MODE")
                    .map_err(internal)?;
                locked_tx.send(stop.id).unwrap();
                release_rx.recv().unwrap();
                tx.commit().map_err(internal)
            })
            .unwrap();
    });
    let stop_operation_id = locked_rx.recv().unwrap();

    let report_cat_id = cat.id.clone();
    let guest = std::thread::spawn(move || {
        ingest_store.ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: report_cat_id,
            // The physical runtime never left generation 1 while generation 2
            // was only an in-flight auto-suspend attempt.
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 1,
            leases: vec![GuestWorkLease {
                id: "late-job".into(),
                label: "late-job".into(),
                remaining_ttl_ms: 30_000,
            }],
        })
    });

    let blocked = wait_until_blocked_by(&observer, guest_pid, lifecycle_pid);
    release_tx.send(()).unwrap();
    lifecycle.join().unwrap();
    assert!(blocked, "Guest work never waited on newer Cat authority");
    let error = guest
        .join()
        .unwrap()
        .expect_err("generation-1 Guest work must not cancel committed generation 3");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.message, "work status generation is stale");

    let current = observer.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(current.desired_state, DesiredState::Cold);
    assert_eq!(current.observed_state, ObservedState::Suspending);
    assert_eq!(current.generation, 3);
    assert_eq!(
        observer.get_operation(&auto.id).unwrap().phase,
        OperationPhase::Failed
    );
    let pending = observer.pending_operations_for(&cat.id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, stop_operation_id);
    assert_eq!(pending[0].kind, "cat.stop");
    assert_eq!(pending[0].resource_generation, 3);
    let work = observer.work_status(&cat.id, 60_000).unwrap();
    assert_eq!(work.active_work_count, 0);
    assert!(work.guest_signal_age_ms.is_some());
}

#[test]
fn old_node_guest_work_cannot_cross_a_concurrent_placement_claim() {
    let _serial = serialize_structural_postgres_lock_test();
    let url = crate::testsupport::isolated_control_store_url();
    let placement_store = concurrency_store(&url);
    let ingest_store = concurrency_store(&url);
    let observer = concurrency_store(&url);
    let placement_pid = backend_pid(&placement_store);
    let guest_pid = backend_pid(&ingest_store);
    let workspace = bootstrap_workspace(&placement_store, "guest-work-placement");
    let (cat, _, create) =
        create_test_cat(&placement_store, &workspace, "guest-work-placement").unwrap();
    for node_id in ["node-1", "node-2"] {
        placement_store
            .register_node(node_id, "http://node", "http://gateway", 4, 8192, false)
            .unwrap();
    }
    placement_store
        .set_placement(&cat.id, Some("node-1"))
        .unwrap();
    placement_store
        .set_observed(&cat.id, ObservedState::Running)
        .unwrap();
    placement_store.finish_operation(&create.id, None).unwrap();

    let cat_id = cat.id.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let placement = std::thread::spawn(move || {
        placement_store
            .enter(move |client| {
                let client = client?;
                let mut tx = client.transaction().map_err(internal)?;
                lock_placement(&mut tx).map_err(internal)?;
                let changed = tx
                    .execute("UPDATE cats SET node_id='node-2' WHERE id=$1", &[&cat_id])
                    .map_err(internal)?;
                assert_eq!(changed, 1);
                tx.batch_execute("LOCK TABLE cat_work_sources IN ACCESS EXCLUSIVE MODE")
                    .map_err(internal)?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                tx.commit().map_err(internal)
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();

    let report_cat_id = cat.id.clone();
    let guest = std::thread::spawn(move || {
        ingest_store.ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: report_cat_id,
            generation: 1,
            guest_source_epoch: "guest-before-placement".into(),
            guest_lease_sequence: 1,
            leases: vec![GuestWorkLease {
                id: "active-request".into(),
                label: "active-request".into(),
                remaining_ttl_ms: 5_000,
            }],
        })
    });

    let blocked = wait_until_blocked_by(&observer, guest_pid, placement_pid);
    release_tx.send(()).unwrap();
    placement.join().unwrap();
    assert!(blocked, "Guest report never waited on the placement claim");
    let error = guest
        .join()
        .unwrap()
        .expect_err("the old owning Node must lose after placement changes");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.message, "work status came from a non-owning node");
    assert_eq!(
        observer.must_get_cat_by_id(&cat.id).unwrap().node_id,
        Some("node-2".into())
    );
    let work_source_count: i64 = observer
        .with(|client| {
            client
                .query_one(
                    "SELECT COUNT(*) FROM cat_work_sources WHERE cat_id=$1",
                    &[&cat.id],
                )?
                .try_get(0)
        })
        .unwrap();
    assert_eq!(work_source_count, 0);
}

#[test]
fn guest_work_and_rejected_suspend_cancellation_share_cat_first_lock_order() {
    let _serial = serialize_structural_postgres_lock_test();
    let url = crate::testsupport::isolated_control_store_url();
    let setup = concurrency_store(&url);
    let ingest_store = concurrency_store(&url);
    let cancel_store = concurrency_store(&url);
    let blocker_store = concurrency_store(&url);
    let observer = concurrency_store(&url);
    let guest_pid = backend_pid(&ingest_store);
    let cancel_pid = backend_pid(&cancel_store);
    let workspace = bootstrap_workspace(&setup, "guest-cancel-lock-order");
    let (cat, _, create) = create_test_cat(&setup, &workspace, "guest-cancel-lock-order").unwrap();
    setup
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    setup.set_placement(&cat.id, Some("node-1")).unwrap();
    setup.set_observed(&cat.id, ObservedState::Running).unwrap();
    setup.finish_operation(&create.id, None).unwrap();
    assert!(!setup
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 0,
            leases: vec![],
        })
        .unwrap());
    let auto = setup
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.auto_suspend")
        .unwrap();
    assert_eq!(auto.resource_generation, 2);
    setup
        .set_observed(&cat.id, ObservedState::Suspending)
        .unwrap();
    let auto_generation = auto.resource_generation;

    let (blocker, release_blocker, blocker_pid) = hold_work_sources_table(blocker_store);
    let report_cat_id = cat.id.clone();
    let guest = std::thread::spawn(move || {
        ingest_store.ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: report_cat_id,
            // The runtime still belongs to the generation before auto-suspend.
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 1,
            leases: vec![GuestWorkLease {
                id: "late-job".into(),
                label: "late-job".into(),
                remaining_ttl_ms: 30_000,
            }],
        })
    });
    assert!(
        wait_until_blocked_by(&observer, guest_pid, blocker_pid),
        "Guest work never acquired the Cat before reaching its source row"
    );

    let cancel_cat_id = cat.id.clone();
    let cancel = std::thread::spawn(move || {
        cancel_store.cancel_rejected_suspend(&cancel_cat_id, auto_generation)
    });
    let cancel_waited_on_guest = wait_until_blocked_by(&observer, cancel_pid, guest_pid);
    release_blocker.send(()).unwrap();
    blocker.join().unwrap();
    assert!(
        cancel_waited_on_guest,
        "Suspend cancellation never queued behind Guest Cat authority"
    );
    assert!(guest.join().unwrap().unwrap());
    cancel.join().unwrap().unwrap();

    let current = observer.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(current.desired_state, DesiredState::Running);
    assert_eq!(current.observed_state, ObservedState::Running);
    assert_eq!(current.generation, 2);
    assert_eq!(
        observer.get_operation(&auto.id).unwrap().phase,
        OperationPhase::Failed
    );
    assert_eq!(
        observer
            .work_status(&cat.id, 60_000)
            .unwrap()
            .active_work_count,
        1
    );
}

#[test]
fn guest_work_and_auto_tier_share_cat_first_lock_order() {
    let _serial = serialize_structural_postgres_lock_test();
    let url = crate::testsupport::isolated_control_store_url();
    let setup = concurrency_store(&url);
    let ingest_store = concurrency_store(&url);
    let auto_store = concurrency_store(&url);
    let blocker_store = concurrency_store(&url);
    let observer = concurrency_store(&url);
    let guest_pid = backend_pid(&ingest_store);
    let auto_pid = backend_pid(&auto_store);
    let workspace = bootstrap_workspace(&setup, "guest-auto-tier-lock-order");
    let (cat, _, create) =
        create_test_cat(&setup, &workspace, "guest-auto-tier-lock-order").unwrap();
    setup
        .register_node("node-1", "http://node", "http://gateway", 4, 8192, false)
        .unwrap();
    setup.set_placement(&cat.id, Some("node-1")).unwrap();
    setup.set_observed(&cat.id, ObservedState::Running).unwrap();
    setup.finish_operation(&create.id, None).unwrap();
    let suspend = setup
        .set_desired(&cat.id, DesiredState::Suspended, None, "cat.suspend")
        .unwrap();
    setup
        .set_observed(&cat.id, ObservedState::Suspended)
        .unwrap();
    setup.finish_operation(&suspend.id, None).unwrap();
    setup
        .with(|client| {
            client
                .execute(
                    "UPDATE cats SET observed_state_since_ms=$2 WHERE id=$1",
                    &[&cat.id, &(now_ms() - 2_000)],
                )
                .map(|_| ())
        })
        .unwrap();
    assert!(!setup
        .ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 2,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 0,
            leases: vec![],
        })
        .unwrap());
    seed_expired_guest_lease(&setup, &cat.id);

    let (blocker, release_blocker, blocker_pid) = hold_work_sources_table(blocker_store);
    let report_cat_id = cat.id.clone();
    let guest = std::thread::spawn(move || {
        ingest_store.ingest_guest_work(&NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: report_cat_id,
            generation: 2,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 1,
            leases: vec![GuestWorkLease {
                id: "wake-request".into(),
                label: "wake-request".into(),
                remaining_ttl_ms: 30_000,
            }],
        })
    });
    assert!(
        wait_until_blocked_by(&observer, guest_pid, blocker_pid),
        "Guest work never acquired the Cat before reaching its source row"
    );

    let auto_cat_id = cat.id.clone();
    let auto = std::thread::spawn(move || {
        auto_store.try_auto_tier(&auto_cat_id, Some(1_000), Some(1_000))
    });
    let auto_waited_on_guest = wait_until_blocked_by(&observer, auto_pid, guest_pid);
    release_blocker.send(()).unwrap();
    blocker.join().unwrap();
    assert!(
        auto_waited_on_guest,
        "auto-tier never queued behind Guest Cat authority"
    );
    assert!(guest.join().unwrap().unwrap());
    assert!(auto.join().unwrap().unwrap().is_none());

    let current = observer.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(current.desired_state, DesiredState::Running);
    assert_eq!(current.observed_state, ObservedState::Suspended);
    assert_eq!(current.generation, 3);
    assert_eq!(
        observer
            .work_status(&cat.id, 60_000)
            .unwrap()
            .active_work_count,
        1
    );
    let operations = observer.pending_operations_for(&cat.id).unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].kind, "cat.work_wake");
    assert_eq!(operations[0].resource_generation, 3);
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
        assert!(store
            .auto_tier_candidates(None, Some(1_000))
            .unwrap()
            .is_empty());
        assert!(store
            .try_auto_tier(&cat.id, None, Some(1_000))
            .unwrap()
            .is_none());
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

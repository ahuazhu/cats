//! Isolated control-store metrics contract.
//!
//! This is deliberately its own integration-test binary: the production
//! counters are process-global, so unrelated `api_reconcile` tests must not be
//! able to contribute work while this test measures explicit deltas.

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use cats_api::resources::DiskDurability;
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, spawn_singleton_task, Config, Handle};
use cats_control_plane::store::{
    DsnSource, OciDeploymentClaim, SingletonRole, Store, CONTROL_STORE_BLOCKING_WORKERS,
};
use cats_metering::SqliteUsageStore;

const SERVICE_TOKEN: &str = "store-metrics-service-token";
const ADMIN_TOKEN: &str = "store-metrics-admin-token";

struct MetricsContext {
    _dir: tempfile::TempDir,
    dsn: String,
    control_plane: Handle,
    http: reqwest::Client,
}

impl MetricsContext {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let dsn = cats_control_plane::testsupport::isolated_control_store_url();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("metering.db")).unwrap());
        let config = Config {
            listen: "127.0.0.1:0".to_string(),
            control_store_dsn: DsnSource::Literal(dsn.clone()),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            #[cfg(debug_assertions)]
            retired_storage_meta_for_tests: None,
            image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
            auth_token: SERVICE_TOKEN.to_string(),
            guest_runtime_profile_receipt:
                cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle:
                cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
            production_cutover_operator_trust_bundle:
                cats_control_plane::testsupport::test_production_cutover_operator_trust_bundle(),
            route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
            admin_token: ADMIN_TOKEN.to_string(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 30_000,
            reconcile_interval_ms: 60_000,
            oci_deploy_sync_wait_ms: 5_000,
            auto_tier_policy: AutoTierPolicy::default(),
        };
        let control_plane = spawn(config).await.unwrap();
        Self {
            _dir: dir,
            dsn,
            control_plane,
            http: reqwest::Client::new(),
        }
    }

    fn metrics_url(&self) -> String {
        format!("{}/metrics", self.control_plane.base_url())
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    active: u64,
    queue: u64,
    admission: u64,
    latency_count: u64,
    latency_sum: f64,
    singleton_connections: u64,
    oci_connections: u64,
    database_snapshot_available: u64,
}

fn prometheus_number(body: &str, selector: &str) -> f64 {
    body.lines()
        .find_map(|line| {
            let value = line.strip_prefix(selector)?.strip_prefix(' ')?;
            value.parse().ok()
        })
        .unwrap_or_else(|| panic!("missing numeric Prometheus selector {selector}"))
}

async fn sample(context: &MetricsContext) -> Sample {
    let body = context
        .http
        .get(context.metrics_url())
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    let integer = |selector| prometheus_number(&body, selector) as u64;
    Sample {
        active: integer("cats_control_store_blocking_jobs_active{executor=\"normal\"}"),
        queue: integer("cats_control_store_blocking_queue_depth{executor=\"normal\"}"),
        admission: integer("cats_control_store_admission_depth"),
        latency_count: integer(
            "cats_control_store_request_latency_seconds_count{executor=\"normal\"}",
        ),
        latency_sum: prometheus_number(
            &body,
            "cats_control_store_request_latency_seconds_sum{executor=\"normal\"}",
        ),
        singleton_connections: integer("cats_control_store_connections{kind=\"singleton\"}"),
        oci_connections: integer("cats_control_store_connections{kind=\"oci\"}"),
        database_snapshot_available: integer(
            "cats_control_plane_metrics_database_snapshot_available",
        ),
    }
}

fn delta(after: u64, before: u64, metric: &str) -> u64 {
    after
        .checked_sub(before)
        .unwrap_or_else(|| panic!("{metric} moved backwards: {before} -> {after}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturation_and_connection_lifetimes_report_explicit_deltas() {
    let context = MetricsContext::new().await;
    let load_stores = (0..=CONTROL_STORE_BLOCKING_WORKERS)
        .map(|_| Arc::new(Store::connect(&context.dsn, None).unwrap()))
        .collect::<Vec<_>>();
    let before = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let sample = sample(&context).await;
            if sample.active == 0 && sample.queue == 0 && sample.admission == 0 {
                return sample;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the isolated executor reaches an idle baseline");

    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let dsn = context.dsn.clone();
    let database_lock = std::thread::spawn(move || {
        let mut client = postgres::Client::connect(&dsn, postgres::NoTls).unwrap();
        client
            .batch_execute("BEGIN; LOCK TABLE cats IN ACCESS EXCLUSIVE MODE")
            .unwrap();
        let _ = locked_tx.send(());
        release_rx.recv().unwrap();
        client.batch_execute("ROLLBACK").unwrap();
    });
    locked_rx.await.unwrap();

    let mut blocked = tokio::task::JoinSet::new();
    for store in load_stores {
        blocked.spawn(async move { store.execute(|store| store.list_all_cats()).await });
    }

    let unauthorized = tokio::time::timeout(
        Duration::from_secs(1),
        context
            .http
            .get(context.metrics_url())
            .bearer_auth("invalid-non-database-metrics-credential")
            .send(),
    )
    .await
    .expect("metrics authentication must not wait for the DB lane")
    .unwrap();
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    let during = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let current = sample(&context).await;
            if delta(current.active, before.active, "active")
                >= CONTROL_STORE_BLOCKING_WORKERS as u64
                && delta(current.queue, before.queue, "queue") >= 1
                && delta(current.admission, before.admission, "admission")
                    > CONTROL_STORE_BLOCKING_WORKERS as u64
            {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the scrape must expose the induced saturation");
    assert_eq!(
        delta(during.active, before.active, "active"),
        CONTROL_STORE_BLOCKING_WORKERS as u64
    );
    assert!(delta(during.queue, before.queue, "queue") >= 1);
    assert!(
        delta(during.admission, before.admission, "admission")
            > CONTROL_STORE_BLOCKING_WORKERS as u64
    );
    assert_eq!(during.database_snapshot_available, 0);

    release_tx.send(()).unwrap();
    while let Some(result) = blocked.join_next().await {
        result.unwrap().unwrap();
    }
    database_lock.join().unwrap();

    let after = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let current = sample(&context).await;
            if current.active < during.active
                && current.queue < during.queue
                && current.admission < during.admission
            {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the executor gauges must fall after releasing the lock");
    assert!(
        delta(after.latency_count, before.latency_count, "latency count")
            > CONTROL_STORE_BLOCKING_WORKERS as u64
    );
    assert!(after.latency_sum - before.latency_sum > 0.0);

    let connection_before = sample(&context).await;
    let (role_started_tx, role_started_rx) = tokio::sync::oneshot::channel();
    let role_started_tx = Arc::new(Mutex::new(Some(role_started_tx)));
    let singleton = spawn_singleton_task(
        Arc::clone(&context.control_plane.state.store),
        SingletonRole::UsageProjector,
        move || {
            let role_started_tx = Arc::clone(&role_started_tx);
            async move {
                if let Some(started) = role_started_tx.lock().unwrap().take() {
                    let _ = started.send(());
                }
                std::future::pending::<()>().await;
            }
        },
    );
    tokio::time::timeout(Duration::from_secs(5), role_started_rx)
        .await
        .expect("the extra singleton session must acquire")
        .unwrap();
    let with_singleton = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let current = sample(&context).await;
            if delta(
                current.singleton_connections,
                connection_before.singleton_connections,
                "singleton connections",
            ) >= 1
            {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("singleton connection count must increase by at least one");

    let workspace = context
        .control_plane
        .state
        .store
        .execute(|store| {
            let view = store
                .list_all_workspace_views()?
                .into_iter()
                .find(|workspace| workspace.is_default)
                .expect("bootstrap workspace exists");
            store.workspace_by_id(&view.id)
        })
        .await
        .unwrap();
    let (cat, _, _) = context
        .control_plane
        .state
        .store
        .execute(move |store| {
            store.create_cat(
                &workspace,
                "metrics-connection-lifetime",
                "test",
                1,
                256,
                1 << 20,
                true,
                None,
                None,
                DiskDurability::Strict,
            )
        })
        .await
        .unwrap();
    let claim = context
        .control_plane
        .state
        .store
        .execute(move |store| {
            store.claim_oci_deployment(&cat, "metrics", &format!("sha256:{}", "a".repeat(64)))
        })
        .await
        .unwrap();
    let lease = match claim {
        OciDeploymentClaim::Claimed { lease, .. } => lease,
        _ => panic!("the fixture must create one OCI ownership session"),
    };
    let with_oci = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let current = sample(&context).await;
            if delta(
                current.oci_connections,
                with_singleton.oci_connections,
                "OCI connections",
            ) >= 1
            {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("OCI connection count must increase by at least one");

    drop(lease);
    singleton.abort();
    let _ = singleton.await;
    let released = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let current = sample(&context).await;
            if delta(
                with_oci.singleton_connections,
                current.singleton_connections,
                "released singleton connections",
            ) >= 1
                && delta(
                    with_oci.oci_connections,
                    current.oci_connections,
                    "released OCI connections",
                ) >= 1
            {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both connection counts must fall by at least one after cleanup");
    assert!(
        delta(
            with_oci.singleton_connections,
            released.singleton_connections,
            "released singleton connections",
        ) >= 1
    );
    assert!(
        delta(
            with_oci.oci_connections,
            released.oci_connections,
            "released OCI connections",
        ) >= 1
    );
}

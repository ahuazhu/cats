//! Control-plane contract tests with a stub node agent: reconcile loop,
//! operations, idempotency, RWO enforcement, and explicit node-loss fencing.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use cats_api::agent_registration::{
    Ed25519RequestSigner, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER, REGISTRATION_PATH,
};
use cats_api::billing::BillingBalance;
use cats_api::fleet_verification::{decode_fleet_verification_snapshot, FLEET_VERIFICATION_PATH};
use cats_api::metering::{
    CatUsageCheckpoint, IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse, UsageMetric,
    UsageReport, MAX_USAGE_INGEST_BODY_BYTES, USAGE_CHECKPOINTS_METHOD, USAGE_CHECKPOINTS_PATH,
};
use cats_api::nodejob::{NodeJob, NodeJobAction, NodeJobResult, StopCatDisposition};
use cats_api::requests::*;
use cats_api::resources::*;
use cats_api::runtime_reconciliation::{
    decode_agent_session, decode_desired_read_snapshot, decode_observation_acceptance,
    encode_agent_registration_attempt, encode_desired_read_request, encode_node_observation,
    guest_config_digest, inventory_digest, AgentRegistrationAttempt, ContractVersion,
    CredentialBinding, DesiredReadRequest, Epoch, Id, NodeBootId, NodeIdentity, NodeIdentityState,
    NodeObservation, RandomId128, Sequence, SessionBinding, UnixMillis,
};
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{
    spawn as spawn_production, spawn_for_retired_product_tests as spawn, Config, Handle,
};
use cats_control_plane::store::{DsnSource, OciDeploymentClaim, Store};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::{
    deterministic_event_id, AttributedCheckpoint, IngestOutcome, SqliteUsageStore, UsageAttribution,
};
use cats_storage::MetadataStore;

const SERVICE_TOKEN: &str = "dev-service-token";

struct SignedUsageNode {
    signer: Ed25519RequestSigner,
    session: SessionBinding,
}

async fn reject_unexpected_production_node_call(
    State(calls): State<Arc<AtomicUsize>>,
) -> StatusCode {
    calls.fetch_add(1, Ordering::SeqCst);
    StatusCode::INTERNAL_SERVER_ERROR
}

#[tokio::test]
async fn fleet_verification_route_is_production_admin_only_and_observation_only() {
    let dir = tempfile::tempdir().unwrap();
    let usage: Arc<SqliteUsageStore> =
        Arc::new(SqliteUsageStore::open(&dir.path().join("fleet-control.db")).unwrap());
    let production = spawn_production(Config {
        listen: "127.0.0.1:0".into(),
        control_store_dsn: DsnSource::Literal(
            cats_control_plane::testsupport::isolated_control_store_url(),
        ),
        control_store_ca_file: None,
        usage_store: usage.clone(),
        credit_store: usage,
        retired_storage_meta_for_tests: None,
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        auth_token: SERVICE_TOKEN.into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
        admin_token: "dev-admin-token".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 30_000,
        reconcile_interval_ms: 30_000,
        oci_deploy_sync_wait_ms: 5_000,
        auto_tier_policy: AutoTierPolicy::default(),
    })
    .await
    .unwrap();
    let client = reqwest::Client::new();
    let url = format!("{}{}", production.base_url(), FLEET_VERIFICATION_PATH);

    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(SERVICE_TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let response = client
        .get(&url)
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get_all(reqwest::header::CONTENT_TYPE)
            .iter()
            .map(reqwest::header::HeaderValue::as_bytes)
            .collect::<Vec<_>>(),
        vec![b"application/json".as_slice()]
    );
    assert_eq!(
        response
            .headers()
            .get_all(reqwest::header::CACHE_CONTROL)
            .iter()
            .map(reqwest::header::HeaderValue::as_bytes)
            .collect::<Vec<_>>(),
        vec![b"no-store".as_slice()]
    );
    let snapshot = decode_fleet_verification_snapshot(&response.bytes().await.unwrap()).unwrap();
    assert!(snapshot.nodes.is_empty());
    assert_eq!(snapshot.desired_runtime_count.get(), 0);
    assert_eq!(snapshot.current_runtime_observation_count.get(), 0);
    assert!(snapshot.route_signing_authority.is_none());

    assert_eq!(
        client
            .post(&url)
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    production.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// Stub node agent: accepts every job, tracks "running" cats, heartbeats.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StubNode {
    id: String,
    cats: Arc<Mutex<HashMap<String, ObservedState>>>,
    jobs: Arc<Mutex<Vec<String>>>,
    job_kinds: Arc<Mutex<Vec<String>>>,
    alive: Arc<AtomicBool>,
    /// Held for read while a heartbeat is in flight.
    heartbeat_gate: Arc<tokio::sync::RwLock<()>>,
    exec_attempts: Arc<AtomicUsize>,
    exec_conflicts_remaining: Arc<AtomicUsize>,
    fail_jobs_remaining: Arc<Mutex<HashMap<String, usize>>>,
    /// Apply a StartCat, acquire its disk epochs, then return HTTP 503. This
    /// models the ambiguous boundary where the Host is already serving the
    /// Guest but the control plane never receives the successful job result.
    lose_start_responses_remaining: Arc<AtomicUsize>,
    started_volumes: Arc<Mutex<Vec<(String, String)>>>,
    /// Hold selected lifecycle HTTP responses after their result has been
    /// computed. Successful results are journaled by job id first, matching
    /// NodeRuntime's ambiguous-success boundary during a reconciler handoff;
    /// failed results are deliberately not journaled and are re-executed.
    hold_job_responses_remaining: Arc<Mutex<HashMap<String, usize>>>,
    job_response_ready: Arc<tokio::sync::Notify>,
    job_response_release: Arc<tokio::sync::Notify>,
    applied_lifecycle_jobs: Arc<Mutex<HashMap<String, NodeJobResult>>>,
    stop_dispositions: Arc<Mutex<Vec<StopCatDisposition>>>,
    /// Every OCI deploy that reached this node, as `(cat, app, image)`. The
    /// count is the assertion that matters: a retried or duplicated request
    /// must not produce a second pull, flatten and service restart.
    oci_deploys: Arc<Mutex<Vec<(String, String, String)>>>,
    /// Makes one deploy take longer than the caller's synchronous wait.
    oci_deploy_delay: Arc<Mutex<Duration>>,
    oci_deploy_failures_remaining: Arc<AtomicUsize>,
}

impl StubNode {
    /// Stop heartbeating, and return only once nothing is still in flight.
    ///
    /// Clearing `alive` on its own is not enough. The loop tests it before it
    /// builds the request, so a heartbeat that already passed the test can land
    /// after the caller has moved the node to Lost and quietly revive it --
    /// a complete same-generation heartbeat can recover a Lost node, which is
    /// exactly why the test has to be sure none is outstanding.
    async fn quiesce(&self) {
        self.alive.store(false, Ordering::SeqCst);
        let _idle = self.heartbeat_gate.write().await;
    }

    fn hold_next_job_response(&self, kind: &str) {
        self.hold_job_responses_remaining
            .lock()
            .unwrap()
            .insert(kind.to_string(), 1);
    }

    async fn hold_job_response_if_requested(&self, kind: &str) {
        let should_hold = self
            .hold_job_responses_remaining
            .lock()
            .unwrap()
            .get_mut(kind)
            .is_some_and(|remaining| {
                if *remaining == 0 {
                    false
                } else {
                    *remaining -= 1;
                    true
                }
            });
        if should_hold {
            self.job_response_ready.notify_one();
            self.job_response_release.notified().await;
        }
    }
}

/// Feed the retired Controller's private test model without recreating a Node
/// HTTP authority. The signed spine is exercised separately below; this helper
/// exists only until the old NodeJob product tests are deleted.
async fn record_retired_controller_inventory(
    store: Arc<Store>,
    notify: Arc<tokio::sync::Notify>,
    req: HeartbeatRequest,
) {
    store
        .execute(move |store| {
            let inventory_changed =
                store.heartbeat_node(&req.node_id, req.telemetry.as_ref(), &req.cats)?;
            if inventory_changed {
                let orphans = store.orphan_reported_cats(&req.node_id)?;
                if !orphans.is_empty() {
                    tracing::warn!(
                        node = %req.node_id,
                        orphans = orphans.len(),
                        reported = req.cats.len(),
                        "retired Controller fixture reports unassigned Cats"
                    );
                }
            }
            for reported in &req.cats {
                if let Ok(cat) = store.must_get_cat_by_id(&reported.cat_id) {
                    if cat.generation == reported.generation
                        && cat.node_id.as_deref() == Some(req.node_id.as_str())
                        && cat.observed_state != reported.state
                        && matches!(
                            cat.observed_state,
                            ObservedState::Running
                                | ObservedState::Suspended
                                | ObservedState::Warm
                                | ObservedState::Unknown
                        )
                    {
                        store.set_observed(&cat.id, reported.state)?;
                        notify.notify_one();
                    }
                }
            }
            let node = store.get_node(&req.node_id)?;
            if node.state == NodeState::Lost {
                let claims = store.cats_on_node(&req.node_id)?;
                let required: Vec<&Cat> = claims
                    .iter()
                    .filter(|cat| cat.desired_state != DesiredState::Deleted)
                    .collect();
                let missing = required.iter().any(|cat| {
                    !req.cats.iter().any(|reported| {
                        reported.cat_id == cat.id && reported.generation == cat.generation
                    })
                });
                if !missing && store.recover_lost_node(&req.node_id)? {
                    notify.notify_one();
                }
            }
            Ok(())
        })
        .await
        .unwrap();
}

async fn stub_job(State(node): State<StubNode>, Json(job): Json<NodeJob>) -> Response {
    node.jobs.lock().unwrap().push(job.job_id.clone());
    node.job_kinds
        .lock()
        .unwrap()
        .push(job.action.kind().to_string());
    if matches!(
        &job.action,
        NodeJobAction::SuspendCat { .. }
            | NodeJobAction::WarmCat { .. }
            | NodeJobAction::StopCat { .. }
    ) {
        if let Some(result) = node
            .applied_lifecycle_jobs
            .lock()
            .unwrap()
            .get(&job.job_id)
            .cloned()
        {
            return Json(result).into_response();
        }
    }
    if let NodeJobAction::StopCat { disposition, .. } = &job.action {
        node.stop_dispositions
            .lock()
            .unwrap()
            .push(disposition.clone());
    }
    let kind = job.action.kind().to_string();
    let should_fail = {
        let mut failures = node.fail_jobs_remaining.lock().unwrap();
        failures.get_mut(&kind).is_some_and(|remaining| {
            if *remaining == 0 {
                false
            } else {
                *remaining -= 1;
                true
            }
        })
    };
    if should_fail {
        let observed = node
            .cats
            .lock()
            .unwrap()
            .get(job.action.cat_id())
            .copied()
            .unwrap_or(ObservedState::Failed);
        let result = NodeJobResult::fail(
            job.job_id,
            observed,
            format!("injected {kind} failure"),
            true,
        );
        node.hold_job_response_if_requested(&kind).await;
        return Json(result).into_response();
    }
    let lose_start_response = matches!(&job.action, NodeJobAction::StartCat { .. })
        && node
            .lose_start_responses_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok();
    if lose_start_response {
        let NodeJobAction::StartCat { volumes, .. } = &job.action else {
            unreachable!("checked StartCat above")
        };
        node.started_volumes.lock().unwrap().extend(
            volumes
                .iter()
                .map(|volume| (volume.volume_id.clone(), volume.attachment_id.clone())),
        );
    }
    let (cat_id, observed) = match &job.action {
        NodeJobAction::StartCat { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::StopCat { cat_id, .. } => (cat_id.clone(), ObservedState::Cold),
        NodeJobAction::SuspendCat { cat_id, .. } => (cat_id.clone(), ObservedState::Suspended),
        NodeJobAction::ResumeCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::WarmCat { cat_id } => (cat_id.clone(), ObservedState::Warm),
        NodeJobAction::RestoreCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::AttachDisk { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::DetachDisk { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::SyncCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::CleanupCat { cat_id } => (cat_id.clone(), ObservedState::Cold),
    };
    {
        let mut cats = node.cats.lock().unwrap();
        if observed == ObservedState::Cold {
            cats.remove(&cat_id);
        } else {
            cats.insert(cat_id, observed);
        }
    }
    if lose_start_response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "injected lost StartCat response",
        )
            .into_response()
    } else {
        let result = NodeJobResult::ok(&job.job_id, observed);
        if matches!(
            &job.action,
            NodeJobAction::SuspendCat { .. }
                | NodeJobAction::WarmCat { .. }
                | NodeJobAction::StopCat { .. }
        ) {
            node.applied_lifecycle_jobs
                .lock()
                .unwrap()
                .insert(job.job_id.clone(), result.clone());
            node.hold_job_response_if_requested(&kind).await;
        }
        Json(result).into_response()
    }
}

async fn stub_exec(State(node): State<StubNode>, Json(req): Json<ExecRequest>) -> Response {
    node.exec_attempts.fetch_add(1, Ordering::SeqCst);
    if node
        .exec_conflicts_remaining
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return (
            StatusCode::CONFLICT,
            "activity changed while preparing to suspend",
        )
            .into_response();
    }
    Json(ExecResponse {
        exit_code: 0,
        stdout: req.command.join(" "),
        stderr: String::new(),
    })
    .into_response()
}

/// Stand in for the Guest-side pull, flatten and activation.
///
/// The delay models the part that outran the 60 s edge timeout in production.
/// The request is answered on its own task-local delay rather than a shared
/// lock so a genuinely concurrent second request would be observable in
/// `oci_deploys` rather than serialised behind the first.
async fn stub_deploy_oci(
    State(node): State<StubNode>,
    axum::extract::Path(cat_id): axum::extract::Path<String>,
    Json(req): Json<cats_api::oci::DeployOciRequest>,
) -> Response {
    node.oci_deploys
        .lock()
        .unwrap()
        .push((cat_id, req.app.clone(), req.image.clone()));
    let delay = *node.oci_deploy_delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    if node
        .oci_deploy_failures_remaining
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "injected registry failure").into_response();
    }
    let digest = cats_api::oci::pinned_digest(&req.image).expect("test images are digest-pinned");
    Json(cats_api::oci::OciDeployment {
        app: req.app.clone(),
        image_digest: digest.to_string(),
        manifest_digest: digest.to_string(),
        service: format!("cats-oci-{}.service", req.app),
        active: true,
    })
    .into_response()
}

async fn start_stub_node(cp: &Handle, id: &str) -> StubNode {
    let node = StubNode {
        id: id.to_string(),
        cats: Arc::new(Mutex::new(HashMap::new())),
        jobs: Arc::new(Mutex::new(Vec::new())),
        job_kinds: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(AtomicBool::new(true)),
        heartbeat_gate: Arc::new(tokio::sync::RwLock::new(())),
        exec_attempts: Arc::new(AtomicUsize::new(0)),
        exec_conflicts_remaining: Arc::new(AtomicUsize::new(0)),
        fail_jobs_remaining: Arc::new(Mutex::new(HashMap::new())),
        lose_start_responses_remaining: Arc::new(AtomicUsize::new(0)),
        started_volumes: Arc::new(Mutex::new(Vec::new())),
        hold_job_responses_remaining: Arc::new(Mutex::new(HashMap::new())),
        job_response_ready: Arc::new(tokio::sync::Notify::new()),
        job_response_release: Arc::new(tokio::sync::Notify::new()),
        applied_lifecycle_jobs: Arc::new(Mutex::new(HashMap::new())),
        stop_dispositions: Arc::new(Mutex::new(Vec::new())),
        oci_deploys: Arc::new(Mutex::new(Vec::new())),
        oci_deploy_delay: Arc::new(Mutex::new(Duration::ZERO)),
        oci_deploy_failures_remaining: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/v1/jobs", post(stub_job))
        .route("/v1/cats/{id}/exec", post(stub_exec))
        .route("/v1/cats/{id}/oci-deployments", post(stub_deploy_oci))
        .with_state(node.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    cats_control_plane::testsupport::register_legacy_test_node(
        &cp.state.store,
        id.to_string(),
        format!("http://{addr}"),
        format!("http://{addr}"),
        16,
        32_768,
        cp.state
            .cfg
            .route_grant_signer
            .public_key_sha256()
            .to_string(),
    )
    .await;
    let heartbeat_store = Arc::clone(&cp.state.store);
    let heartbeat_notify = Arc::clone(&cp.state.notify);

    // Heartbeat loop.
    let hb = node.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            // Held across the send so `quiesce` cannot return while a
            // heartbeat is still on its way to the control plane.
            let _in_flight = hb.heartbeat_gate.read().await;
            if !hb.alive.load(Ordering::SeqCst) {
                continue;
            }
            let cats: Vec<HeartbeatCat> = hb
                .cats
                .lock()
                .unwrap()
                .iter()
                .map(|(id, st)| HeartbeatCat {
                    cat_id: id.clone(),
                    generation: 0,
                    state: *st,
                })
                .collect();
            let observed_cats = cats.len() as u64;
            let cat_resources = cats
                .iter()
                .map(|cat| CatResourceTelemetry {
                    cat_id: cat.cat_id.clone(),
                    cpu_usage_cores: Some(0.25),
                    memory_rss_bytes: Some(128 * 1024 * 1024),
                    host_disk_used_bytes: Some(32 * 1024 * 1024),
                    disk_durability: Vec::new(),
                })
                .collect();
            record_retired_controller_inventory(
                Arc::clone(&heartbeat_store),
                Arc::clone(&heartbeat_notify),
                HeartbeatRequest {
                    node_id: hb.id.clone(),
                    cats,
                    telemetry: Some(NodeTelemetry {
                        observed_cats,
                        allocated_cpus: 0,
                        allocated_memory_mib: 0,
                        wake_in_flight: 0,
                        wake_commitment_bytes: 0,
                        wake_peak_in_flight: 0,
                        wake_commitment_budget_bytes: 0,
                        cat_resources,
                        host_logical_cpus: Some(16),
                        host_cpu_usage_percent: Some(12.5),
                        load_average_1m: Some(0.25),
                        host_memory_total_mib: Some(32_768),
                        host_memory_available_mib: Some(24_576),
                        host_disk_total_bytes: Some(100 * 1024 * 1024 * 1024),
                        host_disk_available_bytes: Some(75 * 1024 * 1024 * 1024),
                        leaked_nbd_devices: Some(0),
                        nbd_devices_total: Some(64),
                        unsupervised_runtime_dirs: Some(0),
                        unsupervised_runtime_bytes: Some(0),
                    }),
                },
            )
            .await;
        }
    });
    node
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The bootstrap Account's default Workspace ID. Resource routes key on the
/// immutable ID, so every test resolves it once from the control plane.
fn default_workspace_id(cp: &Handle) -> String {
    cp.state
        .store
        .list_all_workspace_views()
        .unwrap()
        .into_iter()
        .find(|workspace| workspace.is_default)
        .expect("the bootstrap account has a default workspace")
        .id
}

/// Lifecycle/controller tests still exercise the pre-A23 product model. The
/// public POST route now has the strict Desired-runtime contract, so those
/// fixtures create their legacy resource directly instead of weakening the
/// production ingress with a compatibility parser.
fn create_legacy_cat(
    cp: &Handle,
    name: &str,
    idempotency_key: Option<&str>,
) -> Result<CatOperationResponse, cats_api::error::ApiError> {
    let workspace_id = default_workspace_id(cp);
    let workspace = cp.state.store.workspace_scope(&workspace_id)?.workspace;
    let route = format!("test legacy create {workspace_id}/{name}");
    let (cat, _disks, operation) = match idempotency_key {
        Some(key) => cp.state.store.create_cat_idempotent(
            &workspace,
            name,
            "ubuntu-24.04",
            2,
            1024,
            8 << 20,
            true,
            None,
            None,
            Default::default(),
            key,
            &route,
        ),
        None => cp.state.store.create_cat(
            &workspace,
            name,
            "ubuntu-24.04",
            2,
            1024,
            8 << 20,
            true,
            None,
            None,
            Default::default(),
        ),
    }?;
    cp.state.notify.notify_one();
    Ok(CatOperationResponse { operation, cat })
}

struct Ctx {
    _dir: tempfile::TempDir,
    config: Config,
    cp: Handle,
    http: reqwest::Client,
    /// The bootstrap Account's default Workspace; resource routes key on its ID.
    workspace_id: String,
}

impl Ctx {
    async fn new() -> Self {
        Self::new_with_auto_tier(Default::default(), 200).await
    }

    /// Keep tests that deliberately stall lifecycle work isolated from the
    /// independent short-lease node-loss behavior covered elsewhere.
    async fn new_with_stable_node_lease() -> Self {
        Self::new_with_options(Default::default(), 200, 30_000).await
    }

    async fn new_with_auto_tier(
        auto_tier_policy: AutoTierPolicy,
        reconcile_interval_ms: u64,
    ) -> Self {
        Self::new_with_options(auto_tier_policy, reconcile_interval_ms, 3_000).await
    }

    async fn new_with_options(
        auto_tier_policy: AutoTierPolicy,
        reconcile_interval_ms: u64,
        node_lease_timeout_ms: i64,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
        let config = Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: cats_control_plane::store::DsnSource::Literal(
                cats_control_plane::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            credit_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            retired_storage_meta_for_tests: Some(storage_meta),
            image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
            auth_token: SERVICE_TOKEN.into(),
            guest_runtime_profile_receipt:
                cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle:
                cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
            route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
            admin_token: "dev-admin-token".into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: true,
            node_lease_timeout_ms,
            reconcile_interval_ms,
            oci_deploy_sync_wait_ms: 5_000,
            auto_tier_policy,
        };
        let cp = spawn(config.clone()).await.unwrap();
        let workspace_id = default_workspace_id(&cp);
        // These tests run with billing enforcement on. An Organization Account
        // gets no signup grant — only a user's Personal Account does — so the
        // bootstrap Account starts pre-funded the way a real top-up leaves it.
        let ledger = cp
            .state
            .store
            .billing_ledger_for_workspace(&workspace_id)
            .unwrap();
        cp.state
            .credits
            .ensure_account(
                &ledger.billing_account_id,
                &ledger.account_id,
                "USD",
                10_000_000_000,
                1,
            )
            .await
            .unwrap();
        Self {
            _dir: dir,
            config,
            cp,
            http: reqwest::Client::new(),
            workspace_id,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.cp.base_url(), path)
    }

    /// `path` is appended to this context's workspace route.
    fn ws_url(&self, path: &str) -> String {
        format!(
            "{}/v1/workspaces/{}{}",
            self.cp.base_url(),
            self.workspace_id,
            path
        )
    }

    /// `GET` as the workspace admin, asserting success before decoding. Used by
    /// the call sites that treat a non-2xx as a test failure rather than a
    /// value; tests that assert on a status code build the request themselves.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: String) -> T {
        self.http
            .get(url)
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn record_retired_inventory(&self, request: HeartbeatRequest) {
        record_retired_controller_inventory(
            Arc::clone(&self.cp.state.store),
            Arc::clone(&self.cp.state.notify),
            request,
        )
        .await;
    }

    async fn record_retired_work(&self, request: NodeWorkStatusRequest) {
        let cat_id = request.cat_id.clone();
        let should_wake = self
            .cp
            .state
            .store
            .execute(move |store| store.ingest_guest_work(&request))
            .await
            .unwrap();
        if should_wake {
            self.cp.state.notify.notify_one();
        } else {
            self.cp
                .state
                .controller
                .maybe_auto_suspend(&cat_id)
                .await
                .unwrap();
        }
    }

    async fn register_usage_node(&self, node_id: &str) -> SignedUsageNode {
        static NEXT_REGISTRATION: AtomicUsize = AtomicUsize::new(1);
        let unique = NEXT_REGISTRATION.fetch_add(1, Ordering::Relaxed) as u128;
        let signer = Ed25519RequestSigner::from_pkcs8_pem(
            Id::new(format!("credential_{node_id}")).unwrap(),
            include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
        )
        .unwrap();
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: Id::new(node_id).unwrap(),
            immutable_host_id: Id::new(format!("host_{node_id}")).unwrap(),
            credential_id: signer.credential_id().clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: Id::new(format!("state_{node_id}")).unwrap(),
            state: NodeIdentityState::Provisioned,
        };
        cats_control_plane::testsupport::provision_node_identity(
            &self.cp.state.store,
            identity.clone(),
        )
        .await;
        let attempt = AgentRegistrationAttempt {
            version: ContractVersion::V1,
            node_id: identity.node_id,
            immutable_host_id: identity.immutable_host_id,
            node_boot_id: NodeBootId::new(format!("{unique:032x}")).unwrap(),
            agent_instance_id: RandomId128::new(format!("{:032x}", unique + 1)).unwrap(),
            registration_attempt_id: RandomId128::new(format!("{:032x}", unique + 2)).unwrap(),
            guest_config_digest: guest_config_digest(
                &cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
            )
            .unwrap(),
            expected_agent_session_epoch: None,
        };
        let body = encode_agent_registration_attempt(&attempt).unwrap();
        let proof = signer.sign("POST", REGISTRATION_PATH, &body);
        let response = self
            .http
            .post(self.url(REGISTRATION_PATH))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.bytes().await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "AgentSession registration failed: {}",
            String::from_utf8_lossy(&body)
        );
        let session = decode_agent_session(&body).unwrap();
        SignedUsageNode {
            signer,
            session: SessionBinding {
                node_id: session.node_id,
                node_boot_id: session.node_boot_id,
                agent_instance_id: session.agent_instance_id,
                agent_session_epoch: session.agent_session_epoch,
            },
        }
    }

    async fn post_signed_usage(
        &self,
        node: &SignedUsageNode,
        request: &IngestUsageCheckpointsRequest,
    ) -> reqwest::Response {
        let body = serde_json::to_vec(request).unwrap();
        let proof = node
            .signer
            .sign(USAGE_CHECKPOINTS_METHOD, USAGE_CHECKPOINTS_PATH, &body);
        self.http
            .post(self.url(USAGE_CHECKPOINTS_PATH))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn post_signed_usage_json(
        &self,
        node: &SignedUsageNode,
        request: &IngestUsageCheckpointsRequest,
    ) -> IngestUsageCheckpointsResponse {
        self.post_signed_usage(node, request)
            .await
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn wait_observed(&self, name: &str, want: ObservedState) -> Cat {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let cat: Cat = self
                .http
                .get(self.ws_url(&format!("/cats/{name}")))
                .bearer_auth("dev-admin-token")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if cat.observed_state == want {
                return cat;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting {want:?} for {name}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_operation(&self, op_id: &str) -> Operation {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let op: Operation = self
                .http
                .get(self.url(&format!("/v1/operations/{op_id}")))
                .bearer_auth("dev-admin-token")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if op.phase.is_terminal() {
                return op;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "operation {op_id} never finished"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn create_cat(&self, name: &str, idem: Option<&str>) -> CatOperationResponse {
        create_legacy_cat(&self.cp, name, idem).unwrap()
    }

    async fn action(&self, name: &str, verb: &str) -> CatOperationResponse {
        let resp = self
            .http
            .post(self.ws_url(&format!("/cats/{name}/actions/{verb}")))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202, "{verb} not accepted");
        resp.json().await.unwrap()
    }
}

#[tokio::test]
async fn embedded_public_user_and_admin_sites_are_served_without_credentials() {
    let ctx = Ctx::new().await;
    let assets = [
        ("/", "text/html", "Cats — Durable Linux Cloud Workspaces"),
        ("/zh-CN/", "text/html", "Cats — 持久化 Linux 云端工作空间"),
        ("/docs/", "text/html", "Cats documentation | Cats Docs"),
        ("/zh-CN/docs/", "text/html", "Cats 使用文档 | Cats Docs"),
        ("/user/", "text/html", "data-i18n=\"user.meta.title\""),
        ("/admin/", "text/html", "data-i18n=\"admin.meta.title\""),
        ("/assets/public.css", "text/css", ".docs-layout"),
        ("/assets/cats-mark.svg", "image/svg+xml", "Cats"),
        ("/ui/styles.css", "text/css", ".app-shell"),
        ("/ui/i18n.js", "text/javascript", "navigator.languages"),
        (
            "/ui/common.js",
            "text/javascript",
            "export async function request",
        ),
        ("/ui/user.js", "text/javascript", "initializeAuth"),
        ("/ui/admin.js", "text/javascript", "initializeAuth"),
    ];

    for (path, content_type, marker) in assets {
        let response = ctx.http.get(ctx.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "failed to serve {path}");
        assert!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with(content_type)),
            "wrong content type for {path}"
        );
        assert!(
            response.headers().contains_key("content-security-policy"),
            "missing CSP for {path}"
        );
        let body = response.text().await.unwrap();
        assert!(body.contains(marker), "missing marker in {path}");
        for secret in ["dev-token", "dev-admin-token", SERVICE_TOKEN] {
            assert!(!body.contains(secret), "{path} embeds credential {secret}");
        }
    }

    let user_html = ctx
        .http
        .get(ctx.url("/user/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!user_html.contains("Project Token"));
    assert!(!user_html.contains("token-login-section"));
    assert!(!user_html.contains("CAT STATUS"));
    assert!(user_html.contains("login-screen is-hidden"));
    assert!(user_html.contains("noindex, nofollow, noarchive"));
    assert!(user_html.contains("/assets/cats-mark.svg"));

    let response = ctx
        .http
        .get(ctx.url("/"))
        .header("Host", "ops.cats.run")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let admin_html = response.text().await.unwrap();
    assert!(admin_html.contains("data-i18n=\"admin.meta.title\""));
    assert!(!admin_html.contains("Administrator Token"));
    assert!(!admin_html.contains("FLEET HEALTH"));
    assert!(admin_html.contains("login-screen is-hidden"));
    assert!(admin_html.contains("noindex, nofollow, noarchive"));

    let auth_config = ctx.http.get(ctx.url("/auth/config")).send().await.unwrap();
    assert_eq!(auth_config.status(), StatusCode::OK);
    assert_eq!(
        auth_config
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let auth_config: serde_json::Value = auth_config.json().await.unwrap();
    assert_eq!(auth_config["workos_enabled"], false);
    assert!(auth_config.get("token_login_enabled").is_none());
}

#[tokio::test]
async fn public_docs_are_bilingual_crawlable_and_complete_without_a_session() {
    let ctx = Ctx::new().await;
    let slugs = [
        "getting-started",
        "cats-lifecycle",
        "storage-disks",
        "endpoints",
        "cli-reference",
        "api-reference",
        "runtime-api",
        "console-workspaces",
        "operations-troubleshooting",
    ];

    for slug in slugs {
        for (prefix, lang) in [("", "en"), ("/zh-CN", "zh-CN")] {
            let path = format!("{prefix}/docs/{slug}/");
            let response = ctx.http.get(ctx.url(&path)).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "failed to serve {path}");
            assert_eq!(
                response
                    .headers()
                    .get("content-language")
                    .and_then(|value| value.to_str().ok()),
                Some(lang),
                "wrong locale for {path}"
            );
            assert!(
                response
                    .headers()
                    .get("cache-control")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.starts_with("public")),
                "public page is not cacheable: {path}"
            );
            let html = response.text().await.unwrap();
            for marker in [
                "<meta name=\"description\"",
                "<meta name=\"robots\" content=\"index, follow",
                "<link rel=\"canonical\" href=\"https://cats.run/",
                "hreflang=\"en\"",
                "hreflang=\"zh-CN\"",
                "hreflang=\"x-default\"",
                "application/ld+json",
                "og:image",
                "<article class=\"doc-content\">",
            ] {
                assert!(html.contains(marker), "{path} is missing {marker}");
            }
            for secret in ["dev-token", "dev-admin-token", SERVICE_TOKEN] {
                assert!(!html.contains(secret), "{path} embeds credential {secret}");
            }
        }
    }

    let missing = ctx
        .http
        .get(ctx.url("/zh-CN/docs/not-a-real-page/"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert!(missing.text().await.unwrap().contains("noindex, nofollow"));

    let robots = ctx.http.get(ctx.url("/robots.txt")).send().await.unwrap();
    assert_eq!(robots.status(), StatusCode::OK);
    let robots = robots.text().await.unwrap();
    assert!(robots.contains("Disallow: /auth"));
    assert!(robots.contains("Sitemap: https://cats.run/sitemap.xml"));
    let ops_robots = ctx
        .http
        .get(ctx.url("/robots.txt"))
        .header("Host", "ops.cats.run")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(ops_robots, "User-agent: *\nDisallow: /\n");

    let sitemap = ctx.http.get(ctx.url("/sitemap.xml")).send().await.unwrap();
    assert_eq!(sitemap.status(), StatusCode::OK);
    assert!(sitemap
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/xml")));
    let sitemap = sitemap.text().await.unwrap();
    assert!(sitemap.contains("https://cats.run/docs/getting-started/"));
    assert!(sitemap.contains("https://cats.run/zh-CN/docs/getting-started/"));
    assert!(!sitemap.contains("admin-guide"));
    assert!(sitemap.contains("xmlns:xhtml="));

    for path in ["/docs/admin-guide/", "/zh-CN/docs/admin-guide/"] {
        let response = ctx.http.get(ctx.url(path)).send().await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} leaked from the ops site"
        );
    }

    for (path, lang, title) in [
        ("/docs/", "en", "Fleet administrator guide | Cats Ops"),
        ("/zh-CN/docs/", "zh-CN", "Fleet 管理员指南 | Cats Ops"),
    ] {
        let response = ctx
            .http
            .get(ctx.url(path))
            .header("Host", "ops.cats.run")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-language")
                .and_then(|value| value.to_str().ok()),
            Some(lang)
        );
        assert_eq!(
            response
                .headers()
                .get("x-robots-tag")
                .and_then(|value| value.to_str().ok()),
            Some("noindex, nofollow, noarchive")
        );
        let html = response.text().await.unwrap();
        assert!(html.contains(title));
        assert!(html.contains("/v1/admin/nodes"));
        assert!(html.contains("ops.cats.run"));
    }

    let image = ctx
        .http
        .get(ctx.url("/assets/cats-og.png"))
        .send()
        .await
        .unwrap();
    assert_eq!(image.status(), StatusCode::OK);
    assert_eq!(
        image
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("image/png")
    );
    assert!(image.bytes().await.unwrap().len() > 10_000);
}

#[tokio::test]
async fn create_converges_and_idempotency_replays() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;

    let created = ctx.create_cat("dev", Some("key-1")).await;
    assert!(created.cat.auto_suspend);
    let op = ctx.wait_operation(&created.operation.id).await;
    assert_eq!(op.phase, OperationPhase::Succeeded);
    let cat = ctx.wait_observed("dev", ObservedState::Running).await;
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));

    // Same idempotency key: same operation, no duplicate cat.
    let replay = ctx.create_cat("dev", Some("key-1")).await;
    assert_eq!(replay.operation.id, created.operation.id);
    // A different key with the same name conflicts in the legacy fixture too.
    let error = create_legacy_cat(&ctx.cp, "dev", Some("different-key")).unwrap_err();
    assert_eq!(error.code, cats_api::error::ErrorCode::AlreadyExists);

    // Unauthenticated requests are rejected.
    let resp = ctx.http.get(ctx.ws_url("/cats")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_api_replicas_linearize_create_start_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let control_store_url = cats_control_plane::testsupport::isolated_control_store_url();
    let usage: Arc<SqliteUsageStore> =
        Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap());
    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
    let config = Config {
        listen: "127.0.0.1:0".into(),
        control_store_dsn: cats_control_plane::store::DsnSource::Literal(control_store_url),
        control_store_ca_file: None,
        usage_store: usage.clone(),
        credit_store: usage,
        retired_storage_meta_for_tests: Some(storage_meta),
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        auth_token: SERVICE_TOKEN.into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
        admin_token: "dev-admin-token".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 3_000,
        reconcile_interval_ms: 25,
        oci_deploy_sync_wait_ms: 5_000,
        auto_tier_policy: Default::default(),
    };
    let first = spawn(config.clone()).await.unwrap();
    let node = start_stub_node(&first, "node_a").await;
    let second = spawn(config).await.unwrap();
    let workspace_id = default_workspace_id(&first);
    let http = reqwest::Client::new();
    let cats_path = format!("/v1/workspaces/{workspace_id}/cats");
    let (created_first, created_second) = std::thread::scope(|scope| {
        let first_create =
            scope.spawn(|| create_legacy_cat(&first, "replicated", Some("replica-create")));
        let second_create =
            scope.spawn(|| create_legacy_cat(&second, "replicated", Some("replica-create")));
        (
            first_create.join().unwrap().unwrap(),
            second_create.join().unwrap().unwrap(),
        )
    });
    assert_eq!(created_first.cat.id, created_second.cat.id);
    assert_eq!(created_first.operation.id, created_second.operation.id);
    assert_eq!(first.state.store.list_cats(&workspace_id).unwrap().len(), 1);

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let cat = first
                .state
                .store
                .must_get_cat_by_id(&created_first.cat.id)
                .unwrap();
            if cat.observed_state == ObservedState::Running {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the elected reconciler should place and start the Cat");

    let action_path = format!("{cats_path}/{}/actions/start", created_first.cat.id);
    let start_first = http
        .post(format!("{}{action_path}", first.base_url()))
        .bearer_auth("dev-admin-token")
        .header("Idempotency-Key", "replica-start")
        .send();
    let start_second = http
        .post(format!("{}{action_path}", second.base_url()))
        .bearer_auth("dev-admin-token")
        .header("Idempotency-Key", "replica-start")
        .send();
    let (started_first, started_second) = tokio::join!(start_first, start_second);
    let started_first = started_first.unwrap();
    let started_second = started_second.unwrap();
    assert_eq!(started_first.status(), StatusCode::ACCEPTED);
    assert_eq!(started_second.status(), StatusCode::ACCEPTED);
    let started_first: CatOperationResponse = started_first.json().await.unwrap();
    let started_second: CatOperationResponse = started_second.json().await.unwrap();
    assert_eq!(started_first.operation.id, started_second.operation.id);
    assert_eq!(started_first.operation.resource_generation, 2);

    let delete_path = format!("{cats_path}/{}", created_first.cat.id);
    let delete_first = http
        .delete(format!("{}{delete_path}", first.base_url()))
        .bearer_auth("dev-admin-token")
        .header("Idempotency-Key", "replica-delete")
        .send();
    let delete_second = http
        .delete(format!("{}{delete_path}", second.base_url()))
        .bearer_auth("dev-admin-token")
        .header("Idempotency-Key", "replica-delete")
        .send();
    let (deleted_first, deleted_second) = tokio::join!(delete_first, delete_second);
    let deleted_first = deleted_first.unwrap();
    let deleted_second = deleted_second.unwrap();
    assert_eq!(deleted_first.status(), StatusCode::ACCEPTED);
    assert_eq!(deleted_second.status(), StatusCode::ACCEPTED);
    let deleted_first: CatOperationResponse = deleted_first.json().await.unwrap();
    let deleted_second: CatOperationResponse = deleted_second.json().await.unwrap();
    assert_eq!(deleted_first.operation.id, deleted_second.operation.id);
    assert_eq!(deleted_first.operation.resource_generation, 3);

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if first
                .state
                .store
                .find_cat_by_id(&created_first.cat.id)
                .unwrap()
                .is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the elected reconciler should delete the Cat once");
    assert_eq!(
        node.job_kinds
            .lock()
            .unwrap()
            .iter()
            .filter(|kind| kind.as_str() == "start_cat")
            .count(),
        1,
        "cross-replica replay must not dispatch a duplicate start"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciler_handoff_replays_persisted_suspending_with_the_same_job() {
    let dir = tempfile::tempdir().unwrap();
    let control_store_url = cats_control_plane::testsupport::isolated_control_store_url();
    let usage: Arc<SqliteUsageStore> =
        Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap());
    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
    let config = Config {
        listen: "127.0.0.1:0".into(),
        control_store_dsn: cats_control_plane::store::DsnSource::Literal(control_store_url),
        control_store_ca_file: None,
        usage_store: usage.clone(),
        credit_store: usage,
        retired_storage_meta_for_tests: Some(storage_meta),
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        auth_token: SERVICE_TOKEN.into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
        admin_token: "dev-admin-token".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 30_000,
        reconcile_interval_ms: 25,
        oci_deploy_sync_wait_ms: 5_000,
        auto_tier_policy: Default::default(),
    };
    let first = spawn(config.clone()).await.unwrap();
    let node = start_stub_node(&first, "node_suspend_handoff").await;
    let workspace_id = default_workspace_id(&first);
    let http = reqwest::Client::new();
    let cats_path = format!("/v1/workspaces/{workspace_id}/cats");
    let created = create_legacy_cat(&first, "handoff-suspend", None).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let cat = first
                .state
                .store
                .must_get_cat_by_id(&created.cat.id)
                .unwrap();
            if cat.observed_state == ObservedState::Running {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("first reconciler should start the Cat");

    // Keep heartbeats from publishing the node's already-applied state. The
    // database must remain at the exact ambiguous boundary the replacement
    // reconciler inherits: desired Suspended, observed Suspending.
    node.quiesce().await;
    node.hold_next_job_response("suspend_cat");
    let suspended: CatOperationResponse = http
        .post(format!(
            "{}{cats_path}/{}/actions/suspend",
            first.base_url(),
            created.cat.id
        ))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), node.job_response_ready.notified())
        .await
        .expect("the first leader never dispatched SuspendCat");
    let transitional = first
        .state
        .store
        .must_get_cat_by_id(&created.cat.id)
        .unwrap();
    assert_eq!(transitional.desired_state, DesiredState::Suspended);
    assert_eq!(transitional.observed_state, ObservedState::Suspending);
    assert_eq!(
        first
            .state
            .store
            .get_operation(&suspended.operation.id)
            .unwrap()
            .phase,
        OperationPhase::Pending
    );

    // A second replica starts while the old leader is still waiting for the
    // response, then takes the PostgreSQL singleton lock after that task is
    // aborted. The node has already journaled success, so replaying the same
    // deterministic job returns without applying SuspendCat twice.
    let second = spawn(config).await.unwrap();
    first.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let cat = second
                .state
                .store
                .must_get_cat_by_id(&created.cat.id)
                .unwrap();
            let operation = second
                .state
                .store
                .get_operation(&suspended.operation.id)
                .unwrap();
            if cat.observed_state == ObservedState::Suspended
                && operation.phase == OperationPhase::Succeeded
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("replacement reconciler did not recover persisted Suspending");

    let suspend_jobs: Vec<_> = node
        .jobs
        .lock()
        .unwrap()
        .iter()
        .filter(|job_id| job_id.contains("_suspend_cat"))
        .cloned()
        .collect();
    assert_eq!(suspend_jobs.len(), 2, "handoff did not replay SuspendCat");
    assert_eq!(
        suspend_jobs[0], suspend_jobs[1],
        "handoff changed the deterministic SuspendCat job id"
    );
    assert_eq!(
        node.applied_lifecycle_jobs.lock().unwrap().len(),
        1,
        "the node applied the replayed SuspendCat twice"
    );
    node.job_response_release.notify_waiters();
}

async fn wait_for_persisted_transition(
    cp: &Handle,
    cat_id: &str,
    operation_id: &str,
    observed: ObservedState,
    phase: OperationPhase,
) -> Cat {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let cat = cp.state.store.must_get_cat_by_id(cat_id).unwrap();
            let operation = cp.state.store.get_operation(operation_id).unwrap();
            if cat.observed_state == observed && operation.phase == phase {
                return cat;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("timed out waiting for {cat_id} to reach {observed:?} with operation {phase:?}")
    })
}

fn lifecycle_job_ids(node: &StubNode, action: &str) -> Vec<String> {
    node.jobs
        .lock()
        .unwrap()
        .iter()
        .filter(|job_id| job_id.ends_with(action))
        .cloned()
        .collect()
}

fn assert_one_applied_lifecycle_job(node: &StubNode, action: &str) {
    assert_eq!(
        node.applied_lifecycle_jobs
            .lock()
            .unwrap()
            .keys()
            .filter(|job_id| job_id.ends_with(action))
            .count(),
        1,
        "the node applied {action} more than once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciler_handoff_replays_persisted_warming_success_once() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_warm_handoff").await;
    let created = ctx.create_cat("handoff-warm", None).await;
    ctx.wait_observed("handoff-warm", ObservedState::Running)
        .await;
    let suspend = ctx.action("handoff-warm", "suspend").await;
    ctx.wait_operation(&suspend.operation.id).await;
    let suspended = ctx
        .wait_observed("handoff-warm", ObservedState::Suspended)
        .await;

    node.quiesce().await;
    node.hold_next_job_response("warm_cat");
    let warm = ctx.action("handoff-warm", "warm").await;
    tokio::time::timeout(Duration::from_secs(10), node.job_response_ready.notified())
        .await
        .expect("the first leader never dispatched WarmCat");
    let transitional = ctx
        .cp
        .state
        .store
        .must_get_cat_by_id(&created.cat.id)
        .unwrap();
    assert_eq!(transitional.desired_state, DesiredState::Warm);
    assert_eq!(transitional.observed_state, ObservedState::Warming);
    assert_eq!(transitional.node_id, suspended.node_id);
    assert_eq!(
        ctx.cp
            .state
            .store
            .get_operation(&warm.operation.id)
            .unwrap()
            .phase,
        OperationPhase::Pending
    );

    let second = spawn(ctx.config.clone()).await.unwrap();
    ctx.cp.shutdown().await.unwrap();
    let converged = wait_for_persisted_transition(
        &second,
        &created.cat.id,
        &warm.operation.id,
        ObservedState::Warm,
        OperationPhase::Succeeded,
    )
    .await;
    assert_eq!(converged.node_id, suspended.node_id);

    let jobs = lifecycle_job_ids(&node, "_warm_cat");
    assert_eq!(jobs.len(), 2, "handoff did not replay WarmCat");
    assert!(jobs.iter().all(|job_id| job_id == &jobs[0]));
    assert_one_applied_lifecycle_job(&node, "_warm_cat");
    node.job_response_release.notify_waiters();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciler_handoff_replays_persisted_stopping_success_once() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_stop_handoff").await;
    let created = ctx.create_cat("handoff-stop", None).await;
    let running = ctx
        .wait_observed("handoff-stop", ObservedState::Running)
        .await;

    node.quiesce().await;
    node.hold_next_job_response("stop_cat");
    let stop = ctx.action("handoff-stop", "stop").await;
    tokio::time::timeout(Duration::from_secs(10), node.job_response_ready.notified())
        .await
        .expect("the first leader never dispatched StopCat");
    let transitional = ctx
        .cp
        .state
        .store
        .must_get_cat_by_id(&created.cat.id)
        .unwrap();
    assert_eq!(transitional.desired_state, DesiredState::Cold);
    assert_eq!(transitional.observed_state, ObservedState::Stopping);
    assert_eq!(transitional.node_id, running.node_id);
    assert_eq!(
        ctx.cp
            .state
            .store
            .get_operation(&stop.operation.id)
            .unwrap()
            .phase,
        OperationPhase::Pending
    );

    let second = spawn(ctx.config.clone()).await.unwrap();
    ctx.cp.shutdown().await.unwrap();
    let converged = wait_for_persisted_transition(
        &second,
        &created.cat.id,
        &stop.operation.id,
        ObservedState::Cold,
        OperationPhase::Succeeded,
    )
    .await;
    assert!(converged.node_id.is_none());

    let jobs = lifecycle_job_ids(&node, "_stop_cat");
    assert_eq!(jobs.len(), 2, "handoff did not replay StopCat");
    assert!(jobs.iter().all(|job_id| job_id == &jobs[0]));
    assert_one_applied_lifecycle_job(&node, "_stop_cat");
    node.job_response_release.notify_waiters();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciler_handoff_failed_warm_replay_restores_suspended_source() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_warm_failure_handoff").await;
    let created = ctx.create_cat("handoff-warm-failure", None).await;
    ctx.wait_observed("handoff-warm-failure", ObservedState::Running)
        .await;
    let suspend = ctx.action("handoff-warm-failure", "suspend").await;
    ctx.wait_operation(&suspend.operation.id).await;
    let suspended = ctx
        .wait_observed("handoff-warm-failure", ObservedState::Suspended)
        .await;

    node.quiesce().await;
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("warm_cat".into(), usize::MAX);
    node.hold_next_job_response("warm_cat");
    let warm = ctx.action("handoff-warm-failure", "warm").await;
    tokio::time::timeout(Duration::from_secs(10), node.job_response_ready.notified())
        .await
        .expect("the first leader never reached the failed WarmCat response");
    assert_eq!(
        ctx.cp
            .state
            .store
            .must_get_cat_by_id(&created.cat.id)
            .unwrap()
            .observed_state,
        ObservedState::Warming
    );

    let second = spawn(ctx.config.clone()).await.unwrap();
    ctx.cp.shutdown().await.unwrap();
    let retained = wait_for_persisted_transition(
        &second,
        &created.cat.id,
        &warm.operation.id,
        ObservedState::Suspended,
        OperationPhase::Pending,
    )
    .await;
    assert_eq!(retained.node_id, suspended.node_id);

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("warm_cat".into(), 0);
    wait_for_persisted_transition(
        &second,
        &created.cat.id,
        &warm.operation.id,
        ObservedState::Warm,
        OperationPhase::Succeeded,
    )
    .await;
    let jobs = lifecycle_job_ids(&node, "_warm_cat");
    assert!(jobs.len() >= 3, "failed handoff did not retry WarmCat");
    assert!(jobs.iter().all(|job_id| job_id == &jobs[0]));
    assert_one_applied_lifecycle_job(&node, "_warm_cat");
    node.job_response_release.notify_waiters();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciler_handoff_failed_stop_replay_restores_running_source() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_stop_failure_handoff").await;
    let created = ctx.create_cat("handoff-stop-failure", None).await;
    let running = ctx
        .wait_observed("handoff-stop-failure", ObservedState::Running)
        .await;

    node.quiesce().await;
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), usize::MAX);
    node.hold_next_job_response("stop_cat");
    let stop = ctx.action("handoff-stop-failure", "stop").await;
    tokio::time::timeout(Duration::from_secs(10), node.job_response_ready.notified())
        .await
        .expect("the first leader never reached the failed StopCat response");
    assert_eq!(
        ctx.cp
            .state
            .store
            .must_get_cat_by_id(&created.cat.id)
            .unwrap()
            .observed_state,
        ObservedState::Stopping
    );

    let second = spawn(ctx.config.clone()).await.unwrap();
    ctx.cp.shutdown().await.unwrap();
    let retained = wait_for_persisted_transition(
        &second,
        &created.cat.id,
        &stop.operation.id,
        ObservedState::Running,
        OperationPhase::Pending,
    )
    .await;
    assert_eq!(retained.node_id, running.node_id);

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), 0);
    let cold = wait_for_persisted_transition(
        &second,
        &created.cat.id,
        &stop.operation.id,
        ObservedState::Cold,
        OperationPhase::Succeeded,
    )
    .await;
    assert!(cold.node_id.is_none());
    let jobs = lifecycle_job_ids(&node, "_stop_cat");
    assert!(jobs.len() >= 3, "failed handoff did not retry StopCat");
    assert!(jobs.iter().all(|job_id| job_id == &jobs[0]));
    assert_one_applied_lifecycle_job(&node, "_stop_cat");
    node.job_response_release.notify_waiters();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciler_handoff_finishes_a_converged_operation_without_replaying_node_work() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_converged_operation_handoff").await;
    let created = ctx.create_cat("handoff-converged-operation", None).await;
    let running = ctx
        .wait_observed("handoff-converged-operation", ObservedState::Running)
        .await;
    ctx.wait_operation(&created.operation.id).await;
    assert_eq!(running.generation, created.operation.resource_generation);

    // Simulate the exact crash boundary after the stable Cat row committed but
    // before the matching operation did. Also seed an older operation, a
    // future-generation operation, and an operation whose Cat row is gone so
    // the recovery scan's generation and deletion boundaries are explicit.
    ctx.cp.shutdown().await.unwrap();
    let dsn = match &ctx.config.control_store_dsn {
        DsnSource::Literal(dsn) => dsn.clone(),
        DsnSource::File(_) => panic!("the PostgreSQL test harness must use a literal DSN"),
    };
    let operation_id = created.operation.id.clone();
    let cat_id = created.cat.id.clone();
    let workspace_id = ctx.workspace_id.clone();
    let generation = running.generation;
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&dsn, postgres::NoTls).unwrap();
        client
            .execute(
                "UPDATE operations SET phase='pending' WHERE id=$1",
                &[&operation_id],
            )
            .unwrap();
        for (id, resource_id, resource_generation) in [
            (
                "op_handoff_historical",
                cat_id.as_str(),
                generation.saturating_sub(1),
            ),
            ("op_handoff_future", cat_id.as_str(), generation + 1),
            ("op_handoff_deleted", "cat_handoff_deleted", generation),
        ] {
            client
                .execute(
                    "INSERT INTO operations (
                        id, workspace_id, kind, resource_id, resource_generation,
                        phase, created_at, updated_at
                     ) VALUES ($1,$2,'cat.start',$3,$4,'pending',0,0)",
                    &[&id, &workspace_id, &resource_id, &resource_generation],
                )
                .unwrap();
        }
    })
    .await
    .unwrap();

    let jobs_before_handoff = node.jobs.lock().unwrap().clone();
    let second = spawn(ctx.config.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if second
                .state
                .store
                .get_operation(&created.operation.id)
                .unwrap()
                .phase
                == OperationPhase::Succeeded
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the replacement reconciler left the converged operation pending");

    assert_eq!(
        node.jobs.lock().unwrap().as_slice(),
        jobs_before_handoff.as_slice(),
        "operation recovery repeated already-converged node work"
    );
    assert_eq!(
        second
            .state
            .store
            .get_operation("op_handoff_historical")
            .unwrap()
            .phase,
        OperationPhase::Succeeded,
        "a superseded historical operation should not remain pending forever"
    );
    for operation_id in ["op_handoff_future", "op_handoff_deleted"] {
        assert_eq!(
            second
                .state
                .store
                .get_operation(operation_id)
                .unwrap()
                .phase,
            OperationPhase::Pending,
            "recovery crossed its Cat generation or deletion boundary"
        );
    }
}

#[tokio::test]
async fn lifecycle_stop_start_suspend_resume() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    ctx.wait_observed("dev", ObservedState::Running).await;

    let stop = ctx.action("dev", "stop").await;
    ctx.wait_operation(&stop.operation.id).await;
    let cat = ctx.wait_observed("dev", ObservedState::Cold).await;
    assert!(cat.node_id.is_none(), "placement must clear on stop");
    assert_eq!(
        node.stop_dispositions.lock().unwrap().last(),
        Some(&StopCatDisposition::Cold)
    );

    ctx.action("dev", "start").await;
    ctx.wait_observed("dev", ObservedState::Running).await;

    ctx.action("dev", "suspend").await;
    ctx.wait_observed("dev", ObservedState::Suspended).await;
    ctx.action("dev", "warm").await;
    ctx.wait_observed("dev", ObservedState::Warm).await;
    ctx.action("dev", "resume").await;
    ctx.wait_observed("dev", ObservedState::Running).await;
}

#[tokio::test]
async fn failed_mandatory_stop_drain_retains_source_until_retry_succeeds() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("drain-safe", None).await;
    let running = ctx
        .wait_observed("drain-safe", ObservedState::Running)
        .await;
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), usize::MAX);

    let stop = ctx.action("drain-safe", "stop").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let retained: Cat = ctx
        .http
        .get(ctx.ws_url("/cats/drain-safe"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(
        retained.observed_state,
        ObservedState::Running | ObservedState::Stopping
    ));
    assert_eq!(retained.node_id, running.node_id);

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), 0);
    ctx.wait_operation(&stop.operation.id).await;
    let cold = ctx.wait_observed("drain-safe", ObservedState::Cold).await;
    assert!(cold.node_id.is_none());
}

#[tokio::test]
async fn failed_warm_drain_keeps_the_host_bound_source_for_retry() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("warm-safe", None).await;
    ctx.wait_observed("warm-safe", ObservedState::Running).await;
    ctx.action("warm-safe", "suspend").await;
    let suspended = ctx
        .wait_observed("warm-safe", ObservedState::Suspended)
        .await;
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("warm_cat".into(), usize::MAX);

    let warm = ctx.action("warm-safe", "warm").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let retained: Cat = ctx
        .http
        .get(ctx.ws_url("/cats/warm-safe"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(
        retained.observed_state,
        ObservedState::Suspended | ObservedState::Warming
    ));
    assert_eq!(retained.node_id, suspended.node_id);

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("warm_cat".into(), 0);
    ctx.wait_operation(&warm.operation.id).await;
    ctx.wait_observed("warm-safe", ObservedState::Warm).await;
}

#[tokio::test]
async fn default_auto_suspend_is_inert_on_the_last_guest_work_release() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    let created = ctx.create_cat("worker", None).await;
    ctx.wait_operation(&created.operation.id).await;
    let cat = ctx.wait_observed("worker", ObservedState::Running).await;
    assert!(cat.auto_suspend);

    let report = |sequence, leases| NodeWorkStatusRequest {
        node_id: "node_a".into(),
        cat_id: cat.id.clone(),
        generation: cat.generation,
        guest_source_epoch: "guest-boot-1".into(),
        guest_lease_sequence: sequence,
        leases,
    };
    ctx.record_retired_work(report(
        1,
        vec![cats_api::guest::GuestWorkLease {
            id: "job-1".into(),
            label: "user-training".into(),
            remaining_ttl_ms: 30_000,
        }],
    ))
    .await;

    let enabled: AutoSuspendResponse = ctx.get_json(ctx.ws_url("/cats/worker/auto-suspend")).await;
    assert!(enabled.cat.auto_suspend);
    assert_eq!(enabled.work.reason, "active_work");
    assert_eq!(enabled.work.active_work_count, 1);

    // No CPU/network heuristic is involved: the explicit Guest work lease
    // alone keeps the Cat Running.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        ctx.wait_observed("worker", ObservedState::Running)
            .await
            .observed_state,
        ObservedState::Running
    );

    let operations_before = serde_json::to_value(
        ctx.get_json::<ListResponse<Operation>>(ctx.ws_url("/operations"))
            .await,
    )
    .unwrap();
    let jobs_before = node.jobs.lock().unwrap().clone();
    ctx.record_retired_work(report(2, vec![])).await;
    // The first terminal release has no ResumeRuntime token, so even an
    // explicitly idle Guest must not manufacture lifecycle intent. Wait for
    // several reconcile ticks before comparing the authority-bearing fields.
    tokio::time::sleep(Duration::from_millis(750)).await;
    let unchanged: Cat = ctx.get_json(ctx.ws_url("/cats/worker")).await;
    assert_eq!(unchanged.desired_state, DesiredState::Running);
    assert_eq!(unchanged.observed_state, ObservedState::Running);
    assert_eq!(unchanged.generation, cat.generation);
    assert_eq!(unchanged.node_id, cat.node_id);
    assert_eq!(node.jobs.lock().unwrap().as_slice(), jobs_before.as_slice());
    assert_eq!(
        serde_json::to_value(
            ctx.get_json::<ListResponse<Operation>>(ctx.ws_url("/operations"))
                .await,
        )
        .unwrap(),
        operations_before,
    );
}

#[tokio::test]
async fn automatic_tier_policy_does_not_mutate_a_running_runtime() {
    let ctx = Ctx::new_with_auto_tier(
        AutoTierPolicy {
            warm_after_ms: Some(100),
            cold_after_ms: Some(100),
        },
        20,
    )
    .await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    let created = ctx.create_cat("tiered", None).await;
    ctx.wait_operation(&created.operation.id).await;
    let cat = ctx.wait_observed("tiered", ObservedState::Running).await;
    let operations_before = serde_json::to_value(
        ctx.get_json::<ListResponse<Operation>>(ctx.ws_url("/operations"))
            .await,
    )
    .unwrap();
    let jobs_before = node.jobs.lock().unwrap().clone();

    ctx.record_retired_work(NodeWorkStatusRequest {
        node_id: "node_a".into(),
        cat_id: cat.id.clone(),
        generation: cat.generation,
        guest_source_epoch: "guest-boot-1".into(),
        guest_lease_sequence: 0,
        leases: vec![],
    })
    .await;

    // Both tier deadlines and many 20 ms reconcile intervals pass. With the
    // automatic suspend producer disabled, the policy cannot create the
    // Suspended authority from which Warm or Cold demotion would begin.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let unchanged: Cat = ctx.get_json(ctx.ws_url("/cats/tiered")).await;
    assert_eq!(unchanged.desired_state, DesiredState::Running);
    assert_eq!(unchanged.observed_state, ObservedState::Running);
    assert_eq!(unchanged.generation, cat.generation);
    assert_eq!(unchanged.node_id, cat.node_id);
    assert_eq!(node.jobs.lock().unwrap().as_slice(), jobs_before.as_slice());
    assert_eq!(
        serde_json::to_value(
            ctx.get_json::<ListResponse<Operation>>(ctx.ws_url("/operations"))
                .await,
        )
        .unwrap(),
        operations_before,
    );
}

#[tokio::test]
async fn rwo_second_bind_is_rejected() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("cat-a", None).await;
    ctx.create_cat("cat-b", None).await;
    ctx.wait_observed("cat-a", ObservedState::Running).await;
    ctx.wait_observed("cat-b", ObservedState::Running).await;

    let disk: Disk = ctx
        .http
        .post(ctx.ws_url("/disks"))
        .bearer_auth("dev-admin-token")
        .json(&CreateDiskRequest {
            name: "shared".into(),
            size_bytes: 8 << 20,
            durability: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disk.state, DiskState::Available);

    let mount = |cat: &str| serde_json::json!({ "cat_id": cat, "mount_at": "/data" });
    let r1 = ctx
        .http
        .post(ctx.ws_url("/disks/shared/actions/mount"))
        .bearer_auth("dev-admin-token")
        .json(&mount("cat-a"))
        .send()
        .await
        .unwrap();
    assert!(
        r1.status().is_success(),
        "first mount failed: {}",
        r1.status()
    );

    let r2 = ctx
        .http
        .post(ctx.ws_url("/disks/shared/actions/mount"))
        .bearer_auth("dev-admin-token")
        .json(&mount("cat-b"))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409, "RWO second mount must conflict");

    // Deleting a bound disk is refused; unmount frees it.
    let del = ctx
        .http
        .delete(ctx.ws_url("/disks/shared"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 412);
    let um = ctx
        .http
        .post(ctx.ws_url("/disks/shared/actions/unmount"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert!(um.status().is_success());
    let del = ctx
        .http
        .delete(ctx.ws_url("/disks/shared"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 204);
}

#[tokio::test]
async fn snapshot_requires_the_running_disks_remote_watermark() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("snap-safe", None).await;
    ctx.wait_observed("snap-safe", ObservedState::Running).await;
    let disks: ListResponse<Disk> = ctx
        .http
        .get(ctx.ws_url("/disks"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let root = disks
        .items
        .into_iter()
        .find(|disk| disk.kind == DiskKind::Root)
        .unwrap();

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("sync_cat".into(), 100);
    let failed = ctx
        .http
        .post(ctx.ws_url(&format!("/disks/{}/snapshots", root.id)))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let empty: ListResponse<Snapshot> = ctx
        .http
        .get(ctx.ws_url(&format!("/disks/{}/snapshots", root.id)))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(empty.items.is_empty());

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("sync_cat".into(), 0);
    let created = ctx
        .http
        .post(ctx.ws_url(&format!("/disks/{}/snapshots", root.id)))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    assert!(node
        .jobs
        .lock()
        .unwrap()
        .iter()
        .any(|job| job.contains("_sync_")));
}

#[tokio::test]
async fn ambiguous_start_response_retries_the_same_node_job() {
    let ctx = Ctx::new_with_auto_tier(Default::default(), 1_500).await;
    let source = start_stub_node(&ctx.cp, "node_z").await;
    source
        .lose_start_responses_remaining
        .store(1, Ordering::SeqCst);
    source.quiesce().await;

    ctx.create_cat("ambiguous-start", None).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if !source.started_volumes.lock().unwrap().is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the injected StartCat never presented its disk binding"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // If the control plane treats the missing response as a failed launch, this
    // lexicographically earlier node wins the next placement. A safe retry must
    // retain node_z and replay the same idempotent job there.
    let replacement = start_stub_node(&ctx.cp, "node_a").await;
    let cat = ctx
        .wait_observed("ambiguous-start", ObservedState::Running)
        .await;
    assert_eq!(cat.node_id.as_deref(), Some("node_z"));
    assert_eq!(
        source
            .jobs
            .lock()
            .unwrap()
            .iter()
            .filter(|job| job.contains("_start_cat"))
            .count(),
        2,
        "the deterministic StartCat job should be replayed on its owning node"
    );
    assert!(
        replacement
            .jobs
            .lock()
            .unwrap()
            .iter()
            .all(|job| !job.contains("_start_cat")),
        "an ambiguous launch must not move to another Host"
    );
}

#[tokio::test]
async fn node_loss_preserves_placement_until_fencing_is_explicitly_confirmed() {
    let ctx = Ctx::new().await;
    let node_a = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    let cat = ctx.wait_observed("dev", ObservedState::Running).await;
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));
    ctx.create_cat("doomed", None).await;
    let doomed = ctx.wait_observed("doomed", ObservedState::Running).await;
    assert_eq!(doomed.node_id.as_deref(), Some("node_a"));
    // A second node joins and the first heartbeat stream is interrupted. This
    // is suspicion, not proof that the old runtime has stopped.
    let node_b = start_stub_node(&ctx.cp, "node_b").await;
    node_a.quiesce().await;

    // Heartbeat expiry marks both records unknown/lost but preserves the old
    // placement and storage claim. In particular, it must not start a second
    // Guest or revoke the old block engine's epoch.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if ctx.cp.state.store.get_node("node_a").unwrap().state == NodeState::Lost {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node_a was never marked lost"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let cat = ctx.cp.state.store.must_get_cat_by_id(&cat.id).unwrap();
    assert_eq!(cat.observed_state, ObservedState::Unknown);
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));
    assert!(node_b.cats.lock().unwrap().is_empty());

    // A restarted agent cannot prove that its preserved claims are still
    // running by merely re-registering and sending an empty inventory. Keep
    // the node Lost so an operator can either restore the runtimes in place or
    // explicitly fence the Host; silently making it Ready would strand these
    // Unknown Cats outside both recovery paths.
    let registered = ctx.cp.state.store.get_node("node_a").unwrap();
    cats_control_plane::testsupport::register_legacy_test_node(
        &ctx.cp.state.store,
        registered.id.clone(),
        registered.agent_url.clone(),
        registered.gateway_url.clone(),
        registered.capacity.cpus,
        registered.capacity.memory_mib,
        registered.route_grant_public_key_sha256.clone().unwrap(),
    )
    .await;
    ctx.record_retired_inventory(HeartbeatRequest {
        node_id: "node_a".into(),
        cats: Vec::new(),
        telemetry: None,
    })
    .await;
    assert_eq!(
        ctx.cp.state.store.get_node("node_a").unwrap().state,
        NodeState::Lost
    );
    assert_eq!(
        ctx.cp
            .state
            .store
            .must_get_cat_by_id(&cat.id)
            .unwrap()
            .observed_state,
        ObservedState::Unknown
    );
    assert!(node_b.cats.lock().unwrap().is_empty());

    // If the heartbeat returns before an explicit handoff, ownership recovers
    // in place only after its complete, same-generation inventory proves every
    // preserved claim instead of cold-starting another Guest.
    node_a.alive.store(true, Ordering::SeqCst);
    ctx.record_retired_inventory(HeartbeatRequest {
        node_id: "node_a".into(),
        cats: vec![
            HeartbeatCat {
                cat_id: cat.id.clone(),
                generation: cat.generation,
                state: ObservedState::Running,
            },
            HeartbeatCat {
                cat_id: doomed.id.clone(),
                generation: doomed.generation,
                state: ObservedState::Running,
            },
        ],
        telemetry: None,
    })
    .await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let cat = ctx.cp.state.store.must_get_cat_by_id(&cat.id).unwrap();
        if ctx.cp.state.store.get_node("node_a").unwrap().state == NodeState::Ready
            && cat.observed_state == ObservedState::Running
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node_a did not recover its existing claim"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(node_b.cats.lock().unwrap().is_empty());

    // Lose it again. A false confirmation cannot trigger the destructive
    // handoff; a positive confirmation means an external actor has stopped or
    // isolated the Host, so the control plane may now fence and reschedule.
    node_a.quiesce().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while ctx.cp.state.store.get_node("node_a").unwrap().state != NodeState::Lost {
        assert!(
            std::time::Instant::now() < deadline,
            "node_a was not marked lost a second time"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let delete: CatOperationResponse = ctx
        .http
        .delete(ctx.ws_url("/cats/doomed"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let still_claimed = ctx.cp.state.store.must_get_cat_by_id(&doomed.id).unwrap();
    assert_eq!(still_claimed.desired_state, DesiredState::Deleted);
    assert_eq!(still_claimed.observed_state, ObservedState::Unknown);
    assert_eq!(still_claimed.node_id.as_deref(), Some("node_a"));
    let rejected = ctx
        .http
        .post(ctx.url("/v1/admin/nodes/node_a/actions/fence"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({"confirm_host_stopped_or_isolated": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let fenced = ctx
        .http
        .post(ctx.url("/v1/admin/nodes/node_a/actions/fence"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({"confirm_host_stopped_or_isolated": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(fenced.status(), StatusCode::OK);
    assert_eq!(
        fenced.json::<NodeSummary>().await.unwrap().node.state,
        NodeState::Fenced
    );

    let cat = ctx.wait_observed("dev", ObservedState::Running).await;
    assert_eq!(cat.node_id.as_deref(), Some("node_b"));
    assert_eq!(
        ctx.wait_operation(&delete.operation.id).await.phase,
        OperationPhase::Succeeded
    );
    assert_eq!(
        ctx.http
            .get(ctx.ws_url("/cats/doomed"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn control_plane_startup_grace_preserves_a_reconnecting_host_bound_cat() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("control.db");
    let control_store_url = cats_control_plane::testsupport::isolated_control_store_url();
    let cat_id;
    {
        let store = Store::connect(&control_store_url, None).unwrap();
        store
            .ensure_configured_accounts(&BTreeMap::from([(
                "default".to_string(),
                "local-development".to_string(),
            )]))
            .unwrap();
        let account = store
            .account_for_organization("local-development")
            .unwrap()
            .unwrap();
        let workspace = store
            .workspaces_for_account(&account.id)
            .unwrap()
            .into_iter()
            .find(|workspace| workspace.is_default)
            .unwrap();
        store
            .register_node(
                "node_a",
                "http://127.0.0.1:1",
                "http://gateway.invalid",
                16,
                32_768,
                false,
            )
            .unwrap();
        let (cat, _, _) = store
            .create_cat(
                &workspace,
                "restart-safe",
                "test",
                1,
                256,
                8 << 20,
                true,
                None,
                None,
                cats_api::resources::DiskDurability::Strict,
            )
            .unwrap();
        cat_id = cat.id.clone();
        store.set_placement(&cat_id, Some("node_a")).unwrap();
        store
            .set_desired(&cat_id, DesiredState::Suspended, None, "cat.suspend")
            .unwrap();
        store
            .set_observed(&cat_id, ObservedState::Suspended)
            .unwrap();
    }
    // Make the persisted heartbeat older than the configured Node lease
    // before the new control-plane process starts.
    tokio::time::sleep(Duration::from_millis(2_100)).await;

    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
    let cp = spawn(Config {
        listen: "127.0.0.1:0".into(),
        usage_store: Arc::new(SqliteUsageStore::open(&db_path).unwrap()),
        credit_store: Arc::new(SqliteUsageStore::open(&db_path).unwrap()),
        control_store_dsn: cats_control_plane::store::DsnSource::Literal(control_store_url),
        control_store_ca_file: None,
        retired_storage_meta_for_tests: Some(storage_meta),
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        auth_token: SERVICE_TOKEN.into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
        admin_token: "dev-admin-token".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 2_000,
        reconcile_interval_ms: 10,
        oci_deploy_sync_wait_ms: 5_000,
        auto_tier_policy: Default::default(),
    })
    .await
    .unwrap();

    // The first reconcile sees a stale persisted heartbeat, but must wait one
    // lease interval for the real Node to reconnect.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let cat = cp.state.store.must_get_cat_by_id(&cat_id).unwrap();
    assert_eq!(cat.observed_state, ObservedState::Suspended);
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));
    assert_eq!(
        cp.state.store.get_node("node_a").unwrap().state,
        NodeState::Ready
    );

    for _ in 0..11 {
        cp.state.store.heartbeat_node("node_a", None, &[]).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let cat = cp.state.store.must_get_cat_by_id(&cat_id).unwrap();
    assert_eq!(cat.observed_state, ObservedState::Suspended);
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));
    assert_eq!(
        cp.state.store.get_node("node_a").unwrap().state,
        NodeState::Ready
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_warm_after_physical_completion_keeps_the_durable_replay_boundary() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_warm_post_completion_failure").await;
    let created = ctx.create_cat("warm-post-completion-failure", None).await;
    ctx.wait_observed("warm-post-completion-failure", ObservedState::Running)
        .await;
    let suspend = ctx.action("warm-post-completion-failure", "suspend").await;
    ctx.wait_operation(&suspend.operation.id).await;
    let suspended = ctx
        .wait_observed("warm-post-completion-failure", ObservedState::Suspended)
        .await;

    // Model WarmCat reaching Warm before mandatory final usage retirement
    // fails. The result cannot safely be treated as either a successful Warm
    // or a rollback to Suspended.
    node.cats
        .lock()
        .unwrap()
        .insert(created.cat.id.clone(), ObservedState::Warm);
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("warm_cat".into(), usize::MAX);
    let warm = ctx.action("warm-post-completion-failure", "warm").await;
    let retained = wait_for_persisted_transition(
        &ctx.cp,
        &created.cat.id,
        &warm.operation.id,
        ObservedState::Warming,
        OperationPhase::Pending,
    )
    .await;
    assert_eq!(retained.node_id, suspended.node_id);

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("warm_cat".into(), 0);
    wait_for_persisted_transition(
        &ctx.cp,
        &created.cat.id,
        &warm.operation.id,
        ObservedState::Warm,
        OperationPhase::Succeeded,
    )
    .await;
    let jobs = lifecycle_job_ids(&node, "_warm_cat");
    assert!(jobs.len() >= 2, "failed WarmCat was not replayed");
    assert!(jobs.iter().all(|job_id| job_id == &jobs[0]));
    assert_one_applied_lifecycle_job(&node, "_warm_cat");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_stop_after_physical_completion_keeps_drain_fail_closed() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_stop_post_completion_failure").await;
    let created = ctx.create_cat("stop-post-completion-failure", None).await;
    let running = ctx
        .wait_observed("stop-post-completion-failure", ObservedState::Running)
        .await;

    // Model StopCat reaching Cold before its mandatory remote drain reports a
    // failure. Placement and fencing must remain fail-closed until a retry
    // returns success.
    node.cats
        .lock()
        .unwrap()
        .insert(created.cat.id.clone(), ObservedState::Cold);
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), usize::MAX);
    let stop = ctx.action("stop-post-completion-failure", "stop").await;
    let retained = wait_for_persisted_transition(
        &ctx.cp,
        &created.cat.id,
        &stop.operation.id,
        ObservedState::Stopping,
        OperationPhase::Pending,
    )
    .await;
    assert_eq!(retained.node_id, running.node_id);

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), 0);
    let cold = wait_for_persisted_transition(
        &ctx.cp,
        &created.cat.id,
        &stop.operation.id,
        ObservedState::Cold,
        OperationPhase::Succeeded,
    )
    .await;
    assert!(cold.node_id.is_none());
    let jobs = lifecycle_job_ids(&node, "_stop_cat");
    assert!(jobs.len() >= 2, "failed StopCat was not replayed");
    assert!(jobs.iter().all(|job_id| job_id == &jobs[0]));
    assert_one_applied_lifecycle_job(&node, "_stop_cat");
}

#[tokio::test]
async fn exec_wakes_a_cold_cat() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    ctx.wait_observed("dev", ObservedState::Running).await;
    ctx.action("dev", "stop").await;
    ctx.wait_observed("dev", ObservedState::Cold).await;

    let resp = ctx
        .http
        .post(ctx.ws_url("/cats/dev/exec"))
        .bearer_auth("dev-admin-token")
        .json(&ExecRequest {
            command: vec!["echo".into(), "hi".into()],
            timeout_ms: None,
            env: Default::default(),
            stdin: Vec::new(),
        })
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "exec failed: {}", resp.status());
    let out: ExecResponse = resp.json().await.unwrap();
    assert_eq!(out.stdout, "echo hi");
    ctx.wait_observed("dev", ObservedState::Running).await;
}

#[tokio::test]
async fn a_failed_cat_waits_for_a_new_generation_before_retrying() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("retry-me", None).await;
    let cat = ctx.wait_observed("retry-me", ObservedState::Running).await;
    node.jobs.lock().unwrap().clear();
    node.cats.lock().unwrap().remove(&cat.id);
    ctx.cp.state.store.set_placement(&cat.id, None).unwrap();
    ctx.cp
        .state
        .store
        .set_observed(&cat.id, ObservedState::Failed)
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        node.jobs.lock().unwrap().is_empty(),
        "a terminal failed generation must not hot-loop retries"
    );
    assert_eq!(
        ctx.cp
            .state
            .store
            .must_get_cat_by_id(&cat.id)
            .unwrap()
            .observed_state,
        ObservedState::Failed
    );

    ctx.action("retry-me", "start").await;
    let recovered = ctx.wait_observed("retry-me", ObservedState::Running).await;
    assert!(recovered.generation > cat.generation);
    assert!(node
        .jobs
        .lock()
        .unwrap()
        .iter()
        .any(|job| job.ends_with("_start_cat")));
}

#[tokio::test]
async fn exec_retries_a_transient_suspend_conflict() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    ctx.wait_observed("dev", ObservedState::Running).await;
    node.exec_conflicts_remaining.store(1, Ordering::SeqCst);

    let resp = ctx
        .http
        .post(ctx.ws_url("/cats/dev/exec"))
        .bearer_auth("dev-admin-token")
        .json(&ExecRequest {
            command: vec!["pwd".into()],
            timeout_ms: None,
            env: Default::default(),
            stdin: Vec::new(),
        })
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "exec failed: {}", resp.status());
    let out: ExecResponse = resp.json().await.unwrap();
    assert_eq!(out.stdout, "pwd");
    assert_eq!(node.exec_attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn destroy_deletes_root_disk_and_keeps_persistent() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    ctx.wait_observed("dev", ObservedState::Running).await;
    // Attach a persistent disk.
    ctx.http
        .post(ctx.ws_url("/disks"))
        .bearer_auth("dev-admin-token")
        .json(&CreateDiskRequest {
            name: "keep".into(),
            size_bytes: 8 << 20,
            durability: Default::default(),
        })
        .send()
        .await
        .unwrap();
    ctx.http
        .post(ctx.ws_url("/disks/keep/actions/mount"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({"cat_id": "dev", "mount_at": "/data"}))
        .send()
        .await
        .unwrap();

    let resp = ctx
        .http
        .delete(ctx.ws_url("/cats/dev"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    // Cat vanishes; persistent disk returns to Available; root disk is gone.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let resp = ctx
            .http
            .get(ctx.ws_url("/cats/dev"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap();
        if resp.status() == 404 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "cat never deleted");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let disks: ListResponse<Disk> = ctx
        .http
        .get(ctx.ws_url("/disks"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disks.items.len(), 1);
    assert_eq!(disks.items[0].name, "keep");
    assert_eq!(disks.items[0].state, DiskState::Available);
    let dispositions = node.stop_dispositions.lock().unwrap();
    let Some(StopCatDisposition::Destroy {
        disposable_root_disk_ids,
        retained_persistent_disk_ids,
    }) = dispositions.last()
    else {
        panic!("delete did not dispatch a destroy-specific StopCat");
    };
    assert_eq!(disposable_root_disk_ids.len(), 1);
    assert_eq!(retained_persistent_disk_ids, &[disks.items[0].id.clone()]);
}

#[tokio::test]
async fn static_user_tokens_are_not_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        control_store_dsn: cats_control_plane::store::DsnSource::Literal(
            cats_control_plane::testsupport::isolated_control_store_url(),
        ),
        control_store_ca_file: None,
        usage_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
        credit_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
        retired_storage_meta_for_tests: Some(storage_meta),
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        auth_token: SERVICE_TOKEN.into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
        admin_token: "token-admin".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 3_000,
        reconcile_interval_ms: 200,
        oci_deploy_sync_wait_ms: 5_000,
        auto_tier_policy: Default::default(),
    };
    let cp = spawn(cfg).await.unwrap();
    let workspace_id = default_workspace_id(&cp);
    let cats_url = format!("{}/v1/workspaces/{workspace_id}/cats", cp.base_url());
    let http = reqwest::Client::new();

    let invented_user_token = http
        .get(&cats_url)
        .bearer_auth("token-alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(invented_user_token.status(), StatusCode::UNAUTHORIZED);

    let service_as_user = http
        .get(&cats_url)
        .bearer_auth(SERVICE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(service_as_user.status(), StatusCode::FORBIDDEN);

    let admin_across_workspaces = http
        .get(&cats_url)
        .bearer_auth("token-admin")
        .send()
        .await
        .unwrap();
    assert_eq!(admin_across_workspaces.status(), StatusCode::OK);
}

#[tokio::test]
async fn usage_ingestion_rejects_bodies_above_the_explicit_limit() {
    let ctx = Ctx::new().await;
    let response = ctx
        .http
        .post(ctx.url("/v1/internal/usage/checkpoints"))
        .header("content-type", "application/json")
        .body(vec![b' '; MAX_USAGE_INGEST_BODY_BYTES + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn cumulative_usage_is_idempotent_and_queryable_by_workspace_cat_and_metric() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    let usage_node = ctx.register_usage_node("node_a").await;
    ctx.create_cat("metered", None).await;
    let cat = ctx.wait_observed("metered", ObservedState::Running).await;

    let make_checkpoint =
        |metric: UsageMetric, sequence: u64, observed_at_unix_ms: i64, quantity: u128| {
            let mut checkpoint = CatUsageCheckpoint {
                event_id: String::new(),
                source_id: format!("node/node_a/cat/{}", cat.id),
                source_epoch: "runtime-1".to_string(),
                sequence,
                observed_at_unix_ms,
                cat_id: cat.id.clone(),
                cat_generation: cat.generation,
                metric,
                cumulative_quantity: quantity,
            };
            checkpoint.event_id = deterministic_event_id(&checkpoint);
            checkpoint
        };
    let hour_end = 3_601_000;
    let checkpoints = vec![
        make_checkpoint(UsageMetric::CpuUsec, 0, 1_000, 0),
        make_checkpoint(UsageMetric::MemoryByteMillis, 0, 1_000, 0),
        make_checkpoint(UsageMetric::CpuUsec, 1, hour_end, 3_600_000_000),
        make_checkpoint(
            UsageMetric::MemoryByteMillis,
            1,
            hour_end,
            1_073_741_824 * 3_600_000,
        ),
    ];
    let request = IngestUsageCheckpointsRequest {
        session: usage_node.session.clone(),
        node_id: "node_a".to_string(),
        checkpoints,
    };
    assert_eq!(
        ctx.cp
            .state
            .usage
            .ingest(&AttributedCheckpoint {
                attribution: UsageAttribution {
                    billing_account_id: ctx
                        .cp
                        .state
                        .store
                        .billing_account_id_for_workspace(&ctx.workspace_id)
                        .unwrap(),
                    workspace_id: ctx.workspace_id.clone(),
                    resource_type: "cat".to_string(),
                    resource_id: cat.id.clone(),
                    attributed_cat_id: Some(cat.id.clone()),
                },
                checkpoint: request.checkpoints[0].clone(),
            })
            .await
            .unwrap(),
        IngestOutcome::Accepted
    );
    let first = ctx.post_signed_usage_json(&usage_node, &request).await;
    assert_eq!(first.accepted, 3);
    assert_eq!(first.duplicates, 1);

    let replay = ctx.post_signed_usage_json(&usage_node, &request).await;
    assert_eq!(replay.accepted, 0);
    assert_eq!(replay.duplicates, 4);

    let report_response = ctx
        .http
        .get(ctx.ws_url(&format!(
            "/billing/usage?from_ms=1000&to_ms={hour_end}&cat=metered&detail=true"
        )))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        report_response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let report: UsageReport = report_response.json().await.unwrap();
    assert_eq!(report.status, "provisional");
    assert_eq!(report.amount_nanos, "115000000");
    assert_eq!(report.items.len(), 2);
    assert_eq!(report.cats.len(), 1);
    assert_eq!(report.cats[0].cat_id, cat.id);
    assert_eq!(report.details.len(), 2);
    assert_eq!(report.latest_interval_end_unix_ms, Some(hour_end));

    let balance: BillingBalance = ctx.get_json(ctx.ws_url("/billing/balance")).await;
    assert_eq!(balance.credit_nanos, "10000000000");
    assert_eq!(balance.provisional_usage_nanos, "115000000");
    assert_eq!(balance.available_credit_nanos, "9885000000");
    assert_eq!(
        balance.signup_credit_nanos, "0",
        "an Organization Account is never a signup-grant beneficiary"
    );
    assert!(!balance.stripe_enabled);

    let bucketed: UsageReport = ctx
        .get_json(ctx.ws_url(&format!(
            "/billing/usage?from_ms=1000&to_ms={hour_end}&cat_id={}&bucket_ms=1800000",
            cat.id
        )))
        .await;
    assert_eq!(bucketed.time_buckets.len(), 2);
    assert_eq!(bucketed.time_buckets[0].interval_start_unix_ms, 1_000);
    assert_eq!(bucketed.time_buckets[1].interval_end_unix_ms, hour_end);
    assert_eq!(bucketed.time_buckets[0].amount_nanos, "57500000");
    assert_eq!(bucketed.time_buckets[1].amount_nanos, "57500000");
    assert_eq!(
        bucketed
            .time_buckets
            .iter()
            .map(|bucket| bucket.amount_nanos.parse::<u128>().unwrap())
            .sum::<u128>()
            .to_string(),
        bucketed.amount_nanos
    );

    for query in [
        format!(
            "/billing/usage?from_ms=1000&to_ms={hour_end}&cat_id={}&bucket_ms=1000",
            cat.id
        ),
        format!(
            "/billing/usage?from_ms=1000&to_ms=40000000&cat_id={}&bucket_ms=60000",
            cat.id
        ),
    ] {
        let invalid_bucket = ctx
            .http
            .get(ctx.ws_url(&query))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap();
        assert_eq!(invalid_bucket.status(), StatusCode::BAD_REQUEST);
    }

    // A lifecycle mutation bumps the control-plane generation before the
    // node can submit the previous runtime epoch's final checkpoint.
    ctx.action("metered", "suspend").await;
    let transitioned = ctx.wait_observed("metered", ObservedState::Suspended).await;
    assert!(transitioned.generation > cat.generation);
    let historical = IngestUsageCheckpointsRequest {
        session: usage_node.session.clone(),
        node_id: "node_a".to_string(),
        checkpoints: vec![make_checkpoint(
            UsageMetric::CpuUsec,
            2,
            hour_end + 1_000,
            3_600_000_001,
        )],
    };
    let accepted_historical = ctx.post_signed_usage_json(&usage_node, &historical).await;
    assert_eq!(accepted_historical.accepted, 1);

    let mut future_checkpoint = historical.checkpoints[0].clone();
    future_checkpoint.cat_generation = transitioned.generation + 1;
    future_checkpoint.event_id = deterministic_event_id(&future_checkpoint);
    let future_request = IngestUsageCheckpointsRequest {
        session: usage_node.session.clone(),
        node_id: "node_a".to_string(),
        checkpoints: vec![future_checkpoint],
    };
    let future = ctx.post_signed_usage(&usage_node, &future_request).await;
    assert_eq!(future.status(), StatusCode::CONFLICT);

    let deleted = ctx
        .http
        .delete(ctx.ws_url("/cats/metered"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::ACCEPTED);
    let delete_deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let response = ctx
            .http
            .get(ctx.ws_url("/cats/metered"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap();
        if response.status() == StatusCode::NOT_FOUND {
            break;
        }
        assert!(
            std::time::Instant::now() < delete_deadline,
            "metered Cat never deleted"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let deleted_tail_request = IngestUsageCheckpointsRequest {
        session: usage_node.session.clone(),
        node_id: "node_a".to_string(),
        checkpoints: vec![make_checkpoint(
            UsageMetric::CpuUsec,
            3,
            hour_end + 2_000,
            3_600_000_002,
        )],
    };
    let deleted_tail: IngestUsageCheckpointsResponse = ctx
        .post_signed_usage(&usage_node, &deleted_tail_request)
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deleted_tail.accepted, 1);

    let historical_report: UsageReport = ctx
        .get_json(ctx.ws_url(&format!(
            "/billing/usage?from_ms=1000&to_ms={}&cat_id={}&detail=true",
            hour_end + 3_000,
            cat.id
        )))
        .await;
    assert_eq!(historical_report.cats.len(), 1);
    assert_eq!(historical_report.cats[0].cat_id, cat.id);
    assert_eq!(historical_report.details.len(), 4);
    assert_eq!(
        historical_report
            .details
            .iter()
            .map(|detail| detail.end_sequence)
            .max(),
        Some(3)
    );

    let ambiguous_cat_filter = ctx
        .http
        .get(ctx.ws_url(&format!(
            "/billing/usage?from_ms=1000&to_ms={hour_end}&cat=metered&cat_id={}",
            cat.id
        )))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(ambiguous_cat_filter.status(), StatusCode::BAD_REQUEST);

    let user_query_with_service_credential = ctx
        .http
        .get(ctx.ws_url(&format!("/billing/usage?from_ms=1000&to_ms={hour_end}")))
        .bearer_auth(SERVICE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(
        user_query_with_service_credential.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn exhausted_prepaid_balance_blocks_new_or_waking_compute() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    let usage_node = ctx.register_usage_node("node_a").await;
    ctx.create_cat("spender", None).await;
    let cat = ctx.wait_observed("spender", ObservedState::Running).await;
    let checkpoint = |sequence, observed_at_unix_ms, cumulative_quantity| {
        let mut checkpoint = CatUsageCheckpoint {
            event_id: String::new(),
            source_id: format!("node/node_a/cat/{}", cat.id),
            source_epoch: "expensive-runtime".to_string(),
            sequence,
            observed_at_unix_ms,
            cat_id: cat.id.clone(),
            cat_generation: cat.generation,
            metric: UsageMetric::CpuUsec,
            cumulative_quantity,
        };
        checkpoint.event_id = deterministic_event_id(&checkpoint);
        checkpoint
    };
    let request = IngestUsageCheckpointsRequest {
        session: usage_node.session.clone(),
        node_id: "node_a".to_string(),
        checkpoints: vec![
            checkpoint(0, 1_000, 0),
            checkpoint(1, 720_001_000, 720_000_000_000),
        ],
    };
    let response = ctx.post_signed_usage(&usage_node, &request).await;
    assert_eq!(response.status(), StatusCode::OK);

    ctx.action("spender", "suspend").await;
    ctx.wait_observed("spender", ObservedState::Suspended).await;
    let resume = ctx
        .http
        .post(ctx.ws_url("/cats/spender/actions/resume"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resume.status(), StatusCode::PAYMENT_REQUIRED);
    let body: cats_api::error::ErrorBody = resume.json().await.unwrap();
    assert_eq!(body.code, cats_api::error::ErrorCode::PaymentRequired);

    let create = ctx
        .http
        .post(ctx.ws_url("/cats"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({
            "name": "blocked",
            "image": "ubuntu-24.04",
            "cpus": 1,
            "memory_mib": 512,
            "root_size_bytes": 8 << 20,
            "disk": null
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn every_composition_closes_old_node_ingress_and_accepts_the_signed_spine() {
    let ctx = Ctx::new().await;
    for path in [
        "/v1/nodes/register",
        "/v1/nodes/heartbeat",
        "/v1/nodes/inventory",
        "/v1/nodes/work-status",
    ] {
        let response = ctx
            .http
            .post(ctx.url(path))
            .bearer_auth(SERVICE_TOKEN)
            .json(&serde_json::json!({"node_id": "legacy"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }

    let signer = Ed25519RequestSigner::from_pkcs8_pem(
        Id::new("credential_fixture_node").unwrap(),
        include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
    )
    .unwrap();
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: Id::new("fixture-node").unwrap(),
        immutable_host_id: Id::new("fixture-host").unwrap(),
        credential_id: signer.credential_id().clone(),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: signer.public_key_spki_sha256(),
        },
        state_path_id: Id::new("fixture-state").unwrap(),
        state: NodeIdentityState::Provisioned,
    };
    cats_control_plane::testsupport::provision_node_identity(&ctx.cp.state.store, identity.clone())
        .await;
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id,
        immutable_host_id: identity.immutable_host_id,
        node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
        agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
        registration_attempt_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
        guest_config_digest: guest_config_digest(
            &cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        )
        .unwrap(),
        expected_agent_session_epoch: None,
    };
    let registration_body = encode_agent_registration_attempt(&attempt).unwrap();
    let registration_proof = signer.sign("POST", REGISTRATION_PATH, &registration_body);
    let response = ctx
        .http
        .post(ctx.url(REGISTRATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(NODE_CREDENTIAL_ID_HEADER, registration_proof.credential_id)
        .header(
            NODE_PUBLIC_KEY_SPKI_HEADER,
            registration_proof.public_key_spki,
        )
        .header(NODE_SIGNATURE_HEADER, registration_proof.signature)
        .body(registration_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = decode_agent_session(&response.bytes().await.unwrap()).unwrap();
    let binding = SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    };

    const DESIRED_PATH: &str = "/v1/internal/runtime/desired-reads";
    let desired_body = encode_desired_read_request(&DesiredReadRequest {
        version: ContractVersion::V1,
        session: binding.clone(),
        request_sequence: Sequence::new(1).unwrap(),
    })
    .unwrap();
    let desired_proof = signer.sign("POST", DESIRED_PATH, &desired_body);
    let response = ctx
        .http
        .post(ctx.url(DESIRED_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header(NODE_CREDENTIAL_ID_HEADER, desired_proof.credential_id)
        .header(NODE_PUBLIC_KEY_SPKI_HEADER, desired_proof.public_key_spki)
        .header(NODE_SIGNATURE_HEADER, desired_proof.signature)
        .body(desired_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let desired = decode_desired_read_snapshot(&response.bytes().await.unwrap()).unwrap();
    assert!(desired.desired_specs.is_empty());

    const OBSERVATION_PATH: &str = "/v1/internal/runtime/observations";
    let mut observation = NodeObservation {
        version: ContractVersion::V1,
        observation_id: RandomId128::new("44444444444444444444444444444444").unwrap(),
        node_id: binding.node_id.clone(),
        node_boot_id: binding.node_boot_id.clone(),
        agent_instance_id: binding.agent_instance_id.clone(),
        agent_session_epoch: binding.agent_session_epoch,
        heartbeat_sequence: Sequence::new(1).unwrap(),
        observed_at_unix_ms: UnixMillis::new(1).unwrap(),
        complete_inventory: true,
        inventory_epoch: Epoch::new(1).unwrap(),
        inventory_digest: None,
        inventory_read_position: Some(desired.read_position),
        key_ring_version: None,
        key_ring_digest: None,
        loaded_kids: Vec::new(),
        runtimes: Vec::new(),
        residue: Vec::new(),
    };
    observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
    let observation_body = encode_node_observation(&observation).unwrap();
    let observation_proof = signer.sign("POST", OBSERVATION_PATH, &observation_body);
    let response = ctx
        .http
        .post(ctx.url(OBSERVATION_PATH))
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header(NODE_CREDENTIAL_ID_HEADER, observation_proof.credential_id)
        .header(
            NODE_PUBLIC_KEY_SPKI_HEADER,
            observation_proof.public_key_spki,
        )
        .header(NODE_SIGNATURE_HEADER, observation_proof.signature)
        .body(observation_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let accepted = decode_observation_acceptance(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(accepted.session, binding);
}

#[tokio::test]
async fn production_signed_cutover_never_runs_or_enters_the_legacy_node_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let usage: Arc<SqliteUsageStore> =
        Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap());
    let config = Config {
        listen: "127.0.0.1:0".into(),
        control_store_dsn: DsnSource::Literal(
            cats_control_plane::testsupport::isolated_control_store_url(),
        ),
        control_store_ca_file: None,
        usage_store: usage.clone(),
        credit_store: usage,
        retired_storage_meta_for_tests: None,
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        auth_token: SERVICE_TOKEN.into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
        admin_token: "dev-admin-token".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 30_000,
        reconcile_interval_ms: 10,
        oci_deploy_sync_wait_ms: 5_000,
        auto_tier_policy: AutoTierPolicy::default(),
    };
    let mut legacy_billing = config.clone();
    legacy_billing.billing_enforcement_enabled = true;
    let billing = spawn_production(legacy_billing).await.unwrap();
    billing.shutdown().await.unwrap();
    let production = spawn_production(config.clone()).await.unwrap();
    let workspace_id = default_workspace_id(&production);

    let outbound_calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = listener.local_addr().unwrap();
    let counter = outbound_calls.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .fallback(reject_unexpected_production_node_call)
                .with_state(counter),
        )
        .await
        .ok();
    });
    cats_control_plane::testsupport::register_legacy_test_node(
        &production.state.store,
        "node_cutover_old".into(),
        format!("http://{node_addr}"),
        format!("http://{node_addr}"),
        4,
        4096,
        production
            .state
            .cfg
            .route_grant_signer
            .public_key_sha256()
            .to_string(),
    )
    .await;

    // Seed a pre-cutover row directly. Production HTTP must not create or
    // inspect this authority; the explicit legacy test composition retains
    // those handlers for the older lifecycle suites.
    let workspace = production
        .state
        .store
        .workspace_by_id(&workspace_id)
        .unwrap();
    let (legacy_cat, legacy_disks, legacy_operation) = production
        .state
        .store
        .create_cat(
            &workspace,
            "signed-cutover",
            "ubuntu-24.04",
            1,
            512,
            8 << 20,
            false,
            None,
            None,
            DiskDurability::Strict,
        )
        .unwrap();
    let legacy_disk_id = legacy_disks[0].id.clone();
    let client = reqwest::Client::new();

    // A 10 ms legacy reconcile interval would place and dispatch this row
    // almost immediately. Production owns no such background role.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);
    let cat_before = production
        .state
        .store
        .must_get_cat_by_id(&legacy_cat.id)
        .unwrap();
    assert_eq!(cat_before.node_id, None);
    assert_eq!(cat_before.observed_state, ObservedState::Creating);
    let cat_before_json = serde_json::to_value(&cat_before).unwrap();
    let operations_before = serde_json::to_value(
        production
            .state
            .store
            .list_operations(&workspace_id)
            .unwrap(),
    )
    .unwrap();
    let work_before = production
        .state
        .store
        .work_status(&cat_before.id, 30_000)
        .unwrap();
    let nodes_before = serde_json::to_value(production.state.store.list_nodes().unwrap()).unwrap();

    let workspace_base = format!("{}/v1/workspaces/{workspace_id}", production.base_url());
    let usage_url = format!("{}{}", production.base_url(), USAGE_CHECKPOINTS_PATH);

    // Signed A19 usage ingestion is the one production route that owns this
    // path now. The retired shared bearer must not be accepted as a fallback,
    // and omitting the three A19 proof headers must reach the signed
    // authentication envelope rather than any legacy handler.
    let legacy_bearer = client
        .post(&usage_url)
        .bearer_auth(SERVICE_TOKEN)
        .json(&serde_json::json!({"checkpoints": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(legacy_bearer.status(), StatusCode::BAD_REQUEST);
    let legacy_bearer_error: cats_api::error::ErrorBody = legacy_bearer.json().await.unwrap();
    assert_eq!(
        legacy_bearer_error.code,
        cats_api::error::ErrorCode::InvalidArgument
    );

    let unsigned = client
        .post(&usage_url)
        .json(&serde_json::json!({"checkpoints": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unsigned
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("CatsNodeSignature realm=\"runtime-internal\"")
    );
    let unsigned_error: cats_api::error::ErrorBody = unsigned.json().await.unwrap();
    assert_eq!(
        unsigned_error.code,
        cats_api::error::ErrorCode::Unauthenticated
    );
    assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        serde_json::to_value(
            production
                .state
                .store
                .must_get_cat_by_id(&legacy_cat.id)
                .unwrap()
        )
        .unwrap(),
        cat_before_json
    );
    assert_eq!(
        serde_json::to_value(
            production
                .state
                .store
                .list_operations(&workspace_id)
                .unwrap()
        )
        .unwrap(),
        operations_before
    );

    let closed = vec![
        (
            reqwest::Method::POST,
            format!("{workspace_base}/cats/signed-cutover/exec"),
            Some(serde_json::json!({"command": ["true"]})),
            "dev-admin-token",
        ),
        (
            reqwest::Method::POST,
            format!("{workspace_base}/cats/signed-cutover/oci-deployments"),
            Some(serde_json::json!({
                "app": "server",
                "image": format!("registry.test/app@sha256:{}", "a".repeat(64))
            })),
            "dev-admin-token",
        ),
        (
            reqwest::Method::GET,
            format!("{workspace_base}/cats/signed-cutover/oci-deployments"),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!("{workspace_base}/cats/signed-cutover/auto-suspend"),
            None,
            "dev-admin-token",
        ),
        (
            reqwest::Method::PUT,
            format!("{workspace_base}/cats/signed-cutover/auto-suspend"),
            Some(serde_json::json!({"enabled": true})),
            "dev-admin-token",
        ),
        (
            reqwest::Method::GET,
            format!("{workspace_base}/cats/signed-cutover/expiry"),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::PUT,
            format!("{workspace_base}/cats/signed-cutover/expiry"),
            Some(serde_json::json!({"expires_at_unix": 4_102_444_800_i64})),
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!("{workspace_base}/cats/signed-cutover/work"),
            None,
            "dev-admin-token",
        ),
        (
            reqwest::Method::POST,
            format!("{workspace_base}/disks/old/snapshots"),
            None,
            "dev-admin-token",
        ),
        (
            reqwest::Method::GET,
            format!("{workspace_base}/disks/{legacy_disk_id}/snapshots"),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!(
                "{}/v1/operations/{}",
                production.base_url(),
                legacy_operation.id
            ),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!("{workspace_base}/operations"),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::POST,
            format!(
                "{}/v1/nodes/node_cutover_old/actions/cordon",
                production.base_url()
            ),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!("{}/v1/nodes", production.base_url()),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!("{}/v1/admin/nodes", production.base_url()),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!("{}/v1/admin/nodes/node_cutover_old", production.base_url()),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::DELETE,
            format!("{}/v1/admin/nodes/node_cutover_old", production.base_url()),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!(
                "{}/v1/admin/nodes/node_cutover_old/cats",
                production.base_url()
            ),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::POST,
            format!(
                "{}/v1/admin/nodes/node_cutover_old/actions/fence",
                production.base_url()
            ),
            Some(serde_json::json!({"confirm_host_stopped_or_isolated": true})),
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!("{}/v1/admin/monitoring", production.base_url()),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::GET,
            format!(
                "{}/v1/routes/resolve?hostname=cutover.test",
                production.base_url()
            ),
            None,
            "invalid-before-cutover-gate",
        ),
        (
            reqwest::Method::POST,
            format!(
                "{}/v1/routes/wake?hostname=cutover.test",
                production.base_url()
            ),
            None,
            SERVICE_TOKEN,
        ),
    ];
    for (method, url, body, token) in closed {
        let mut request = client.request(method, &url).bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "legacy runtime entry point stayed reachable: {url}",
        );
    }

    // Product reads are part of the cutover authority. They authenticate as
    // production routes instead of falling through the retired-authority
    // closure, even when a seeded legacy row shares the requested identity.
    for url in [
        format!("{workspace_base}/cats"),
        format!("{workspace_base}/cats/signed-cutover"),
        format!("{workspace_base}/disks"),
        format!("{workspace_base}/disks/{legacy_disk_id}"),
        format!("{workspace_base}/billing/usage?from_ms=0&to_ms=1"),
    ] {
        assert_eq!(
            client
                .get(&url)
                .bearer_auth("invalid-before-cutover-gate")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
            "production product read did not reach its authentication envelope: {url}",
        );
    }

    // Endpoint list and all legacy disk actions left the production method
    // set. They must not be revived merely to preserve a debug-only handler.
    assert_eq!(
        client
            .get(format!("{workspace_base}/cats/signed-cutover/endpoints"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED,
    );
    for url in [
        format!("{workspace_base}/disks/{legacy_disk_id}/actions/resize"),
        format!("{workspace_base}/disks/old/actions/mount"),
        format!("{workspace_base}/disks/old/actions/unmount"),
    ] {
        assert_eq!(
            client
                .post(&url)
                .bearer_auth("dev-admin-token")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND,
            "retired disk action stayed in the production route set: {url}",
        );
    }

    // Production enumerates the four frozen lifecycle methods. A retired or
    // invented action must not be captured by a wildcard V2 handler.
    assert_eq!(
        client
            .post(format!("{workspace_base}/cats/signed-cutover/actions/sync"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
    );

    let strict_disk_create = client
        .post(format!("{workspace_base}/disks"))
        .bearer_auth("dev-admin-token")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", "reject-legacy-disk-create-shape")
        .json(&serde_json::json!({"name": "must-not-create"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        strict_disk_create.status(),
        StatusCode::BAD_REQUEST,
        "the covered PersistentDisk route accepted the retired create shape",
    );

    let metrics = client
        .get(format!("{}/metrics", production.base_url()))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), StatusCode::OK);
    let metrics = metrics.text().await.unwrap();
    assert!(metrics.contains("cats_control_store_blocking_jobs_active"));
    assert!(metrics.contains("cats_control_observation_store_active"));
    assert!(metrics.contains("cats_control_plane_metrics_database_snapshot_available 0"));
    assert!(!metrics.contains("cats_control_plane_cats_total"));
    assert!(!metrics.contains("cats_node_load_average_1m"));

    // Exercise the WebSocket extractor so this proves the handler itself is
    // closed, rather than merely observing a missing Upgrade header.
    let shell = client
        .get(format!(
            "{workspace_base}/cats/signed-cutover/shell?rows=24&cols=80"
        ))
        .bearer_auth("dev-admin-token")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(shell.status(), StatusCode::SERVICE_UNAVAILABLE);

    // The retired shared-bearer routes are absent rather than authenticated
    // fallbacks. Try both credentials and prove the same old rows stayed exact.
    for path in [
        "/v1/nodes/register",
        "/v1/nodes/heartbeat",
        "/v1/nodes/inventory",
        "/v1/nodes/work-status",
        "/v1/internal/work/acquire",
        "/v1/internal/work/release",
    ] {
        for token in [SERVICE_TOKEN, "dev-admin-token"] {
            let response = client
                .post(format!("{}{path}", production.base_url()))
                .bearer_auth(token)
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        serde_json::to_value(
            production
                .state
                .store
                .must_get_cat_by_id(&legacy_cat.id)
                .unwrap()
        )
        .unwrap(),
        cat_before_json
    );
    assert_eq!(
        serde_json::to_value(
            production
                .state
                .store
                .list_operations(&workspace_id)
                .unwrap()
        )
        .unwrap(),
        operations_before
    );
    let work_after = production
        .state
        .store
        .work_status(&legacy_cat.id, 30_000)
        .unwrap();
    assert_eq!(work_after.work_version, work_before.work_version);
    assert_eq!(work_after.active_work_count, work_before.active_work_count);
    assert_eq!(
        serde_json::to_value(production.state.store.list_nodes().unwrap()).unwrap(),
        nodes_before
    );

    // A stranded legacy OCI row is another old runtime owner. Restarting a
    // production replica must leave it untouched rather than running the old
    // in-memory-task reaper.
    let claim_cat = cat_before.clone();
    let (operation_id, lease) = production
        .state
        .store
        .execute(move |store| {
            match store.claim_oci_deployment(
                &claim_cat,
                "legacy-app",
                &format!("sha256:{}", "b".repeat(64)),
            )? {
                OciDeploymentClaim::Claimed {
                    operation, lease, ..
                } => Ok((operation.id, lease)),
                _ => unreachable!("fresh legacy deployment identity"),
            }
        })
        .await
        .unwrap();
    drop(lease);
    let operation_before =
        serde_json::to_value(production.state.store.get_operation(&operation_id).unwrap()).unwrap();
    production.shutdown().await.unwrap();

    let successor = spawn_production(config).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        serde_json::to_value(successor.state.store.get_operation(&operation_id).unwrap()).unwrap(),
        operation_before,
        "production startup converged a legacy OCI row",
    );
    assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);
    successor.shutdown().await.unwrap();
}

#[tokio::test]
async fn admin_can_monitor_and_drain_nodes() {
    let ctx = Ctx::new().await;
    let node_a = start_stub_node(&ctx.cp, "node_a").await;
    let _node_b = start_stub_node(&ctx.cp, "node_b").await;
    ctx.create_cat("drain-me", None).await;
    let cat = ctx.wait_observed("drain-me", ObservedState::Running).await;
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));

    // Wait for at least one telemetry-bearing heartbeat.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let nodes: ListResponse<NodeSummary> = ctx.get_json(ctx.url("/v1/admin/nodes")).await;
        if nodes
            .items
            .iter()
            .all(|summary| summary.node.telemetry.is_some())
        {
            assert_eq!(nodes.items.len(), 2);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "telemetry missing");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let overview: MonitoringOverview = ctx.get_json(ctx.url("/v1/admin/monitoring")).await;
    assert_eq!(overview.nodes.total, 2);
    assert_eq!(overview.cats.running, 1);
    assert_eq!(overview.capacity.total_cpus, 32);
    assert_eq!(overview.capacity.assigned_cpus, 2);
    assert_eq!(overview.usage.logical_cpus, Some(32));
    assert_eq!(overview.usage.cpu_usage_percent, Some(12.5));
    assert_eq!(overview.usage.memory_total_mib, Some(65_536));
    assert_eq!(overview.usage.memory_used_mib, Some(16_384));
    assert_eq!(
        overview.usage.disk_used_bytes,
        Some(50 * 1024 * 1024 * 1024)
    );

    // Per-Cat telemetry rides the heartbeat, and the heartbeat that first
    // carried node-level telemetry can predate the Cat's placement. Waiting
    // only for the node level, as the loop above does, leaves `actual` empty
    // whenever the next heartbeat has not landed yet -- which is most of the
    // time on a loaded machine.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let node_cats: ListResponse<NodeCatSummary> = loop {
        let listed: ListResponse<NodeCatSummary> =
            ctx.get_json(ctx.url("/v1/admin/nodes/node_a/cats")).await;
        if listed
            .items
            .first()
            .is_some_and(|item| item.actual.is_some())
        {
            break listed;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "per-cat telemetry missing"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(node_cats.items.len(), 1);
    assert_eq!(node_cats.items[0].cat.name, "drain-me");
    assert_eq!(node_cats.items[0].requested_disk_bytes, 8 << 20);
    let actual = node_cats.items[0].actual.as_ref().unwrap();
    assert_eq!(actual.cpu_usage_cores, Some(0.25));
    assert_eq!(actual.memory_rss_bytes, Some(128 * 1024 * 1024));
    assert_eq!(actual.host_disk_used_bytes, Some(32 * 1024 * 1024));

    let prometheus = ctx
        .http
        .get(ctx.url("/metrics"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(prometheus.contains("cats_control_plane_cats_running 1"));
    assert!(prometheus.contains("cats_node_load_average_1m{node_id=\"node_a\"} 0.25"));
    assert!(prometheus.contains("cats_node_cpu_usage_percent{node_id=\"node_a\"} 12.5"));
    assert!(prometheus.contains("cats_node_disk_used_bytes{node_id=\"node_a\"} 26843545600"));
    assert!(prometheus.contains("cats_cat_cpu_usage_cores{node_id=\"node_a\",cat_id=\""));
    assert!(prometheus.contains("cats_cat_memory_rss_bytes{node_id=\"node_a\",cat_id=\""));
    assert!(prometheus.contains("cats_cat_host_disk_used_bytes{node_id=\"node_a\",cat_id=\""));

    let drain = ctx
        .http
        .post(ctx.url("/v1/admin/nodes/node_a/actions/drain"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(drain.status(), StatusCode::ACCEPTED);

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let cat: Cat = ctx
            .http
            .get(ctx.ws_url("/cats/drain-me"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let node: NodeSummary = ctx
            .http
            .get(ctx.url("/v1/admin/nodes/node_a"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if cat.observed_state == ObservedState::Running
            && cat.node_id.as_deref() == Some("node_b")
            && node.node.state == NodeState::Cordoned
            && node.assigned_cats == 0
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "drain did not converge"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let uncordon = ctx
        .http
        .post(ctx.url("/v1/admin/nodes/node_a/actions/uncordon"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(uncordon.status(), StatusCode::OK);
    assert_eq!(
        uncordon.json::<NodeSummary>().await.unwrap().node.state,
        NodeState::Ready
    );

    // Cordon records scheduling intent without hiding Lost health. A later
    // registration alone cannot clear Lost; with no preserved claims, the
    // following empty heartbeat is a complete inventory and recovers the Node
    // to Cordoned without silently defeating that intent.
    node_a.quiesce().await;
    ctx.cp
        .state
        .store
        .set_node_state("node_a", NodeState::Lost)
        .unwrap();
    let cordon = ctx
        .http
        .post(ctx.url("/v1/admin/nodes/node_a/actions/cordon"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(cordon.status(), StatusCode::OK);
    assert_eq!(
        cordon.json::<NodeSummary>().await.unwrap().node.state,
        NodeState::Lost
    );
    cats_control_plane::testsupport::register_legacy_test_node(
        &ctx.cp.state.store,
        "node_a".into(),
        "http://127.0.0.1:1".into(),
        "http://gateway.invalid".into(),
        8,
        16_384,
        ctx.cp
            .state
            .cfg
            .route_grant_signer
            .public_key_sha256()
            .to_string(),
    )
    .await;
    ctx.record_retired_inventory(HeartbeatRequest {
        node_id: "node_a".into(),
        cats: Vec::new(),
        telemetry: None,
    })
    .await;
    let node: NodeSummary = ctx
        .http
        .get(ctx.url("/v1/admin/nodes/node_a"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(node.node.state, NodeState::Cordoned);

    let deleted = ctx
        .http
        .delete(ctx.url("/v1/admin/nodes/node_a"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let missing = ctx
        .http
        .get(ctx.url("/v1/admin/nodes/node_a"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// OCI deployments: a deploy outlives its request
//
// Production reached Cats through an ALB whose 60 s idle timeout answered 504
// while the deploy kept running and succeeded. The caller read 504 as a
// transient failure and retried, which restarted a service that had just come
// up. These tests pin the contract that replaced that: the deploy is owned by a
// record keyed on (cat, app, digest), a caller that goes away neither cancels
// nor loses it, and no retry or duplicate produces a second execution.
// ---------------------------------------------------------------------------

const TEST_DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";

fn test_image(digest: &str) -> String {
    format!("registry.test/acme/app@{digest}")
}

impl Ctx {
    /// POST a deploy, returning the status and body without interpreting them.
    async fn deploy_oci_raw(
        &self,
        name: &str,
        app: &str,
        digest: &str,
        wait_ms: Option<u64>,
    ) -> (StatusCode, serde_json::Value) {
        let mut url = self.ws_url(&format!("/cats/{name}/oci-deployments"));
        if let Some(wait_ms) = wait_ms {
            url.push_str(&format!("?wait_ms={wait_ms}"));
        }
        let resp = self
            .http
            .post(url)
            .bearer_auth("dev-admin-token")
            .json(&serde_json::json!({ "app": app, "image": test_image(digest) }))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap())
    }

    /// A running Cat on a stub node, ready to receive deployments.
    async fn running_cat_on_node(&self, name: &str) -> StubNode {
        let node = start_stub_node(&self.cp, "node_a").await;
        self.create_cat(name, None).await;
        self.wait_observed(name, ObservedState::Running).await;
        node
    }

    fn live_control_leases(&self, cat_id: &str) -> usize {
        self.cp
            .state
            .store
            .work_status(cat_id, 3_000)
            .unwrap()
            .leases
            .iter()
            .filter(|lease| lease.kind == WorkKind::Control)
            .count()
    }
}

/// A deploy slower than the caller's wait answers 202, and the operation it
/// hands back reaches Succeeded on its own with the deployment attached.
#[tokio::test]
async fn an_oci_deploy_slower_than_the_wait_answers_an_operation_and_finishes_anyway() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("slow").await;
    // Longer than the 200 ms wait this request asks for, so the answer has to
    // be an operation -- the case that used to become a 504.
    *node.oci_deploy_delay.lock().unwrap() = Duration::from_millis(1_500);

    let (status, body) = ctx
        .deploy_oci_raw("slow", "server", TEST_DIGEST, Some(200))
        .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "a deploy that outruns the wait must be accepted, not failed: {body}"
    );
    let response: OciDeploymentOperationResponse = serde_json::from_value(body).unwrap();
    assert!(
        response.deployment.is_none(),
        "the deployment is not available yet"
    );
    assert_eq!(response.operation.kind, "cat.oci-deploy");

    let finished = ctx.wait_operation(&response.operation.id).await;
    assert_eq!(
        finished.phase,
        OperationPhase::Succeeded,
        "the deploy kept running after the response: {:?}",
        finished.error
    );
    assert_eq!(
        node.oci_deploys.lock().unwrap().len(),
        1,
        "answering 202 must not re-dispatch the deploy"
    );
}

/// The production sequence: the first request's answer is lost, the deploy
/// succeeds in the background, and the retry must return that same deployment
/// without touching the Guest again.
#[tokio::test]
async fn retrying_after_a_lost_answer_replays_the_deployment_instead_of_redeploying() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("retry").await;
    *node.oci_deploy_delay.lock().unwrap() = Duration::from_millis(1_000);

    // First request gives up waiting, exactly as the ALB made the caller do.
    let (status, body) = ctx
        .deploy_oci_raw("retry", "server", TEST_DIGEST, Some(0))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let accepted: OciDeploymentOperationResponse = serde_json::from_value(body).unwrap();
    let finished = ctx.wait_operation(&accepted.operation.id).await;
    assert_eq!(finished.phase, OperationPhase::Succeeded);

    // The retry the caller would have sent on seeing 504.
    let (status, body) = ctx
        .deploy_oci_raw("retry", "server", TEST_DIGEST, None)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a completed deploy replays synchronously: {body}"
    );
    let replayed: cats_api::oci::OciDeployment = serde_json::from_value(body).unwrap();
    assert_eq!(replayed.image_digest, TEST_DIGEST);
    assert_eq!(replayed.service, "cats-oci-server.service");
    assert_eq!(
        node.oci_deploys.lock().unwrap().len(),
        1,
        "the retry must not pull, flatten or restart a second time"
    );
}

/// Two identical requests in flight together must produce one execution.
#[tokio::test]
async fn concurrent_identical_oci_deploys_execute_once() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("concurrent").await;
    *node.oci_deploy_delay.lock().unwrap() = Duration::from_millis(700);

    let (first, second) = tokio::join!(
        ctx.deploy_oci_raw("concurrent", "server", TEST_DIGEST, None),
        ctx.deploy_oci_raw("concurrent", "server", TEST_DIGEST, None),
    );
    for (status, body) in [&first, &second] {
        assert_eq!(
            *status,
            StatusCode::OK,
            "both callers get the result: {body}"
        );
        let deployment: cats_api::oci::OciDeployment =
            serde_json::from_value(body.clone()).unwrap();
        assert_eq!(deployment.image_digest, TEST_DIGEST);
    }
    assert_eq!(
        node.oci_deploys.lock().unwrap().len(),
        1,
        "the second request must join the first, not start its own deploy"
    );
}

/// A different digest for the same app is a different deployment and must run.
#[tokio::test]
async fn a_new_digest_for_the_same_app_is_a_new_deployment() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("redeploy").await;

    let (first, _) = ctx
        .deploy_oci_raw("redeploy", "server", TEST_DIGEST, None)
        .await;
    assert_eq!(first, StatusCode::OK);
    let (second, body) = ctx
        .deploy_oci_raw("redeploy", "server", OTHER_DIGEST, None)
        .await;
    assert_eq!(second, StatusCode::OK);
    let deployment: cats_api::oci::OciDeployment = serde_json::from_value(body).unwrap();
    assert_eq!(deployment.image_digest, OTHER_DIGEST);
    assert_eq!(
        node.oci_deploys.lock().unwrap().len(),
        2,
        "idempotency is keyed on the digest, so new bytes must be deployed"
    );
}

/// A failed deploy is reported as failed, and retrying the same digest is
/// allowed to make progress rather than replaying the failure forever.
#[tokio::test]
async fn a_failed_oci_deploy_can_be_retried_on_the_same_digest() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("recover").await;
    node.oci_deploy_failures_remaining
        .store(1, Ordering::SeqCst);

    let (status, body) = ctx
        .deploy_oci_raw("recover", "server", TEST_DIGEST, None)
        .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a failed deploy must not read as success: {body}"
    );

    let (status, body) = ctx
        .deploy_oci_raw("recover", "server", TEST_DIGEST, None)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same digest must be retryable after a failure: {body}"
    );
    let deployment: cats_api::oci::OciDeployment = serde_json::from_value(body).unwrap();
    assert_eq!(deployment.image_digest, TEST_DIGEST);
    assert_eq!(node.oci_deploys.lock().unwrap().len(), 2);
}

/// Deploying into a Cat that has gone Warm wakes it first, and the deployment
/// that follows is a normal one.
#[tokio::test]
async fn deploying_into_a_warm_cat_wakes_it_first() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("warm").await;
    ctx.action("warm", "warm").await;
    ctx.wait_observed("warm", ObservedState::Warm).await;

    let (status, body) = ctx
        .deploy_oci_raw("warm", "server", TEST_DIGEST, None)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a warm redeploy must wake and deploy: {body}"
    );
    let deployment: cats_api::oci::OciDeployment = serde_json::from_value(body).unwrap();
    assert_eq!(deployment.image_digest, TEST_DIGEST);
    assert_eq!(node.oci_deploys.lock().unwrap().len(), 1);
    assert_eq!(
        ctx.wait_observed("warm", ObservedState::Running)
            .await
            .observed_state,
        ObservedState::Running
    );
}

/// The work lease must not outlive the deploy it protects.
///
/// It used to be released by a call placed after the awaited work, so a
/// cancelled request skipped it and left a one-hour lease pinning the Cat out
/// of auto-suspend. Answering 202 exercises the same path: the request ends
/// while the deploy continues, and the lease must be gone once it finishes.
#[tokio::test]
async fn a_deploy_that_answers_early_still_releases_its_work_lease() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("lease").await;
    *node.oci_deploy_delay.lock().unwrap() = Duration::from_millis(800);

    let cat_id = ctx
        .cp
        .state
        .store
        .get_cat(&ctx.workspace_id, "lease")
        .unwrap()
        .id;

    let (status, body) = ctx
        .deploy_oci_raw("lease", "server", TEST_DIGEST, Some(0))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let accepted: OciDeploymentOperationResponse = serde_json::from_value(body).unwrap();
    assert_eq!(
        ctx.live_control_leases(&cat_id),
        1,
        "the lease must still be held while the deploy runs"
    );

    ctx.wait_operation(&accepted.operation.id).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while ctx.live_control_leases(&cat_id) > 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the deploy finished but its work lease leaked"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// An image without a digest cannot be given an identity, so it must be
/// rejected before any work or record is created.
#[tokio::test]
async fn an_oci_deploy_without_a_pinned_digest_is_rejected() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("unpinned").await;

    let resp = ctx
        .http
        .post(ctx.ws_url("/cats/unpinned/oci-deployments"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({
            "app": "server",
            "image": "registry.test/acme/app:latest"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(node.oci_deploys.lock().unwrap().is_empty());
}

/// A different replica's reaper must not fail a deployment whose owner still
/// has its PostgreSQL session lock. Process-death recovery is covered at the
/// Store boundary, where the owner lease can be dropped deterministically.
#[tokio::test]
async fn a_live_oci_deploy_is_not_failed_by_another_replica_reaper() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("interrupted").await;
    *node.oci_deploy_delay.lock().unwrap() = Duration::from_secs(30);

    let (status, body) = ctx
        .deploy_oci_raw("interrupted", "server", TEST_DIGEST, Some(0))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let accepted: OciDeploymentOperationResponse = serde_json::from_value(body).unwrap();

    // Stand in for a second replica's periodic recovery pass.
    let converged = ctx
        .cp
        .state
        .store
        .fail_interrupted_oci_deployments()
        .unwrap();
    assert_eq!(converged, 0);

    let operation = ctx
        .cp
        .state
        .store
        .get_operation(&accepted.operation.id)
        .unwrap();
    assert_eq!(
        operation.phase,
        OperationPhase::Running,
        "a live owner must not be mistaken for a dead replica"
    );
}

/// A Cat runs one version of an app, so listing its deployments must answer
/// with one row per app -- the one actually activated.
#[tokio::test]
async fn listing_deployments_reports_only_the_current_digest_for_an_app() {
    let ctx = Ctx::new().await;
    let _node = ctx.running_cat_on_node("listed").await;

    ctx.deploy_oci_raw("listed", "server", TEST_DIGEST, None)
        .await;
    ctx.deploy_oci_raw("listed", "server", OTHER_DIGEST, None)
        .await;

    let listed: ListResponse<cats_api::oci::OciDeployment> = ctx
        .http
        .get(ctx.ws_url("/cats/listed/oci-deployments"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let for_app: Vec<_> = listed
        .items
        .iter()
        .filter(|deployment| deployment.app == "server")
        .collect();
    assert_eq!(
        for_app.len(),
        1,
        "one app runs one image; superseded records must not be listed: {:?}",
        listed.items
    );
    assert_eq!(
        for_app[0].image_digest, OTHER_DIGEST,
        "the listed digest must be the one that was activated last"
    );
}

/// Rolling back to a digest that has since been superseded must actually
/// redeploy it. Replaying the old record would report success while the Cat
/// keeps running the newer image.
#[tokio::test]
async fn redeploying_a_superseded_digest_activates_it_again() {
    let ctx = Ctx::new().await;
    let node = ctx.running_cat_on_node("rollback").await;

    ctx.deploy_oci_raw("rollback", "server", TEST_DIGEST, None)
        .await;
    ctx.deploy_oci_raw("rollback", "server", OTHER_DIGEST, None)
        .await;
    let (status, body) = ctx
        .deploy_oci_raw("rollback", "server", TEST_DIGEST, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(
        node.oci_deploys.lock().unwrap().len(),
        3,
        "a superseded digest is no longer deployed, so re-requesting it must \
         reach the Guest instead of replaying a stale record"
    );
    let listed: ListResponse<cats_api::oci::OciDeployment> = ctx
        .http
        .get(ctx.ws_url("/cats/rollback/oci-deployments"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let for_app: Vec<_> = listed
        .items
        .iter()
        .filter(|deployment| deployment.app == "server")
        .collect();
    assert_eq!(for_app.len(), 1);
    assert_eq!(for_app[0].image_digest, TEST_DIGEST);
}

/// A Cat being deleted must not block its Host from recovering.
///
/// Production deadlock: `metal-1` held nine preserved claims, one of which was
/// a Cat with `desired_state = deleted` that the Host had already torn down and
/// so no longer reported. Recovery demanded a complete inventory including that
/// claim, while `reconcile_cat` declines every flow -- the delete included --
/// for a Cat whose node is Lost. Neither side could move, and nothing self
/// healed: the node stayed Lost with its Cats stranded.
#[tokio::test]
async fn a_deleting_cat_does_not_block_its_lost_node_from_recovering() {
    let ctx = Ctx::new().await;
    let node_a = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("keeper", None).await;
    let keeper = ctx.wait_observed("keeper", ObservedState::Running).await;
    ctx.create_cat("going", None).await;
    let going = ctx.wait_observed("going", ObservedState::Running).await;

    // Lose the Host first, so the delete below cannot be dispatched and stays a
    // preserved claim -- the state production was wedged in.
    node_a.quiesce().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while ctx.cp.state.store.get_node("node_a").unwrap().state != NodeState::Lost {
        assert!(
            std::time::Instant::now() < deadline,
            "node_a was never marked lost"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    ctx.http
        .delete(ctx.ws_url("/cats/going"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let deleting = ctx.cp.state.store.must_get_cat_by_id(&going.id).unwrap();
    assert_eq!(deleting.desired_state, DesiredState::Deleted);
    assert_eq!(
        deleting.node_id.as_deref(),
        Some("node_a"),
        "the claim is preserved while the Host is Lost"
    );

    // The Host has already torn this Guest down, so its inventory will never
    // include it again -- absence is the delete succeeding, not an anomaly.
    node_a.cats.lock().unwrap().remove(&going.id);
    node_a.alive.store(true, Ordering::SeqCst);
    ctx.record_retired_inventory(HeartbeatRequest {
        node_id: "node_a".into(),
        cats: vec![HeartbeatCat {
            cat_id: keeper.id.clone(),
            generation: keeper.generation,
            state: ObservedState::Running,
        }],
        telemetry: None,
    })
    .await;

    assert_eq!(
        ctx.cp.state.store.get_node("node_a").unwrap().state,
        NodeState::Ready,
        "a claim whose Cat is being deleted must not hold the node Lost"
    );

    // And once recovered the delete finally converges, which is what makes the
    // deadlock gone rather than merely deferred.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while ctx
        .cp
        .state
        .store
        .find_cat_by_id(&going.id)
        .unwrap()
        .is_some()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the delete never completed after recovery"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        ctx.cp
            .state
            .store
            .must_get_cat_by_id(&keeper.id)
            .unwrap()
            .observed_state,
        ObservedState::Running,
        "recovery must restore the surviving claim, not disturb it"
    );
}

/// A claim the control plane still intends to run must keep holding the node
/// Lost. Narrowing the requirement to non-deleting claims must not weaken the
/// split-brain guard it exists for.
#[tokio::test]
async fn a_running_claim_missing_from_the_inventory_still_holds_the_node_lost() {
    let ctx = Ctx::new().await;
    let node_a = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("reported", None).await;
    let reported = ctx.wait_observed("reported", ObservedState::Running).await;
    ctx.create_cat("omitted", None).await;
    let omitted = ctx.wait_observed("omitted", ObservedState::Running).await;

    node_a.quiesce().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while ctx.cp.state.store.get_node("node_a").unwrap().state != NodeState::Lost {
        assert!(
            std::time::Instant::now() < deadline,
            "node_a was never marked lost"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    ctx.record_retired_inventory(HeartbeatRequest {
        node_id: "node_a".into(),
        cats: vec![HeartbeatCat {
            cat_id: reported.id.clone(),
            generation: reported.generation,
            state: ObservedState::Running,
        }],
        telemetry: None,
    })
    .await;

    assert_eq!(
        ctx.cp.state.store.get_node("node_a").unwrap().state,
        NodeState::Lost,
        "a Cat still meant to be running there is unaccounted for; recovering \
         would resurrect a claim that may have moved on"
    );
    assert_eq!(
        ctx.cp
            .state
            .store
            .must_get_cat_by_id(&omitted.id)
            .unwrap()
            .node_id
            .as_deref(),
        Some("node_a"),
        "the preserved claim must survive for an explicit fence or restore"
    );
}

/// A stop that keeps failing must back off, not spin.
///
/// The failure path restored the Cat's previous observed state and then called
/// `notify_one()`, which woke the reconciler immediately -- so a stop blocked on
/// something external re-dispatched as fast as the loop could run. In production
/// two Cats whose stop was blocked behind a backing-off final usage delivery
/// produced ~288 dispatches per second against one node agent, and a no-op
/// `exec` on an unrelated Cat went from milliseconds to over a minute.
#[tokio::test]
async fn a_persistently_failing_stop_backs_off_instead_of_spinning() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("wedged", None).await;
    let cat = ctx.wait_observed("wedged", ObservedState::Running).await;
    // Requesting the stop bumps the generation, which is part of the job id, so
    // match on the Cat and action rather than a generation captured beforehand.
    let stop_job_suffix = "_stop_cat";
    let cat_job_prefix = format!("job_{}_", cat.id);

    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), usize::MAX);
    ctx.action("wedged", "stop").await;

    // Long enough that an unthrottled retry would be unmistakable: the harness
    // ticks every 200 ms, and the immediate self-notify made it far faster.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let attempts = node
        .jobs
        .lock()
        .unwrap()
        .iter()
        .filter(|id| id.starts_with(&cat_job_prefix) && id.ends_with(stop_job_suffix))
        .count();
    assert!(
        attempts >= 1,
        "the stop must be attempted at least once, got {attempts}"
    );
    assert!(
        attempts <= 5,
        "a failing stop must back off; {attempts} dispatches in 2 s is a hot loop"
    );

    // Backing off must not wedge it: once the dependency recovers, the stop
    // converges without needing a new request.
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), 0);
    let cold = ctx.wait_observed("wedged", ObservedState::Cold).await;
    assert!(cold.node_id.is_none());
}

/// Backoff is per Cat and per generation, so one wedged Cat must not delay an
/// unrelated one -- the reconciler still has to make progress elsewhere.
#[tokio::test]
async fn one_backing_off_cat_does_not_delay_another() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("stuck", None).await;
    ctx.wait_observed("stuck", ObservedState::Running).await;
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), usize::MAX);
    ctx.action("stuck", "stop").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A second Cat created while the first is backing off must still converge.
    ctx.create_cat("healthy", None).await;
    let healthy = ctx.wait_observed("healthy", ObservedState::Running).await;
    assert_eq!(healthy.node_id.as_deref(), Some("node_a"));
}

/// One permanently unacceptable checkpoint must not fail the whole batch.
///
/// A durable outbox delivers an ordered prefix, so a checkpoint the ledger can
/// never accept blocked every checkpoint behind it -- and retrying could not
/// change the answer, so it blocked them forever. Production hit exactly this:
/// a Cat deleted before any checkpoint of its runtime epoch was ingested left
/// no frozen attribution, and the 409 that produced stalled a 111,864-row
/// outbox. That in turn stalled every lifecycle stop, because a stop withholds
/// its result until its final usage is acknowledged, so Cats stopped being able
/// to converge deletions at all.
#[tokio::test]
async fn an_unattributable_checkpoint_is_rejected_without_failing_its_batch() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    let usage_node = ctx.register_usage_node("node_a").await;
    ctx.create_cat("billable", None).await;
    let cat = ctx.wait_observed("billable", ObservedState::Running).await;

    let checkpoint = |cat_id: &str, sequence, observed_at_unix_ms, quantity| {
        let mut checkpoint = CatUsageCheckpoint {
            event_id: String::new(),
            source_id: format!("node/node_a/cat/{cat_id}"),
            source_epoch: "epoch-a".to_string(),
            sequence,
            observed_at_unix_ms,
            cat_id: cat_id.to_string(),
            cat_generation: 1,
            metric: UsageMetric::CpuUsec,
            cumulative_quantity: quantity,
        };
        checkpoint.event_id = deterministic_event_id(&checkpoint);
        checkpoint
    };

    // `cat_vanished` never existed, so it stands in for a Cat deleted before any
    // checkpoint of its epoch was attributed: nothing will ever make it
    // ingestible. It sits at the head, where it used to block the rest.
    let poison = checkpoint("cat_vanished", 0, 1_000, 0);
    let billable_first = checkpoint(&cat.id, 0, 1_000, 0);
    assert_eq!(
        ctx.cp
            .state
            .usage
            .ingest(&AttributedCheckpoint {
                attribution: UsageAttribution {
                    billing_account_id: ctx
                        .cp
                        .state
                        .store
                        .billing_account_id_for_workspace(&ctx.workspace_id)
                        .unwrap(),
                    workspace_id: ctx.workspace_id.clone(),
                    resource_type: "cat".to_string(),
                    resource_id: cat.id.clone(),
                    attributed_cat_id: Some(cat.id.clone()),
                },
                checkpoint: billable_first.clone(),
            })
            .await
            .unwrap(),
        IngestOutcome::Accepted
    );
    let request = IngestUsageCheckpointsRequest {
        session: usage_node.session.clone(),
        node_id: "node_a".to_string(),
        checkpoints: vec![
            poison.clone(),
            billable_first,
            checkpoint(&cat.id, 1, 61_000, 60_000_000),
        ],
    };
    let response = ctx.post_signed_usage(&usage_node, &request).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "one unacceptable checkpoint must not fail the batch behind it"
    );
    let body: IngestUsageCheckpointsResponse = response.json().await.unwrap();
    assert_eq!(
        body.rejected.len(),
        1,
        "the unacceptable checkpoint must be named so the producer stops resending it"
    );
    assert_eq!(body.rejected[0].event_id, poison.event_id);
    assert!(
        body.rejected[0].reason.contains("cat_vanished"),
        "the reason must identify what was dropped: {}",
        body.rejected[0].reason
    );
    assert!(
        body.accepted >= 1,
        "the billable checkpoints behind it must still be ingested, got {}",
        body.accepted
    );

    // And the usage that did land is billed, so rejecting one checkpoint has not
    // quietly discarded the rest of the batch.
    let report = ctx
        .http
        .get(ctx.ws_url("/billing/balance"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(report.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// V1 reverse reconciliation of agent-reported runtimes
// ---------------------------------------------------------------------------

async fn admin_node_summary(ctx: &Ctx, node_id: &str) -> NodeSummary {
    ctx.get_json(ctx.url(&format!("/v1/admin/nodes/{node_id}")))
        .await
}

/// Wait until the node's summary shows exactly `want` orphan runtimes.
async fn wait_orphan_cats(ctx: &Ctx, node_id: &str, want: u64) -> NodeSummary {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let summary = admin_node_summary(ctx, node_id).await;
        if summary.orphan_cats == want {
            return summary;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node {node_id} never reported {want} orphan runtimes, last {}",
            summary.orphan_cats
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Issue #98: 13 orphan runtimes sat in the node's telemetry while every
/// operator surface showed the 3 assigned Cats, and no view compared the two.
/// A Cat the agent reports without a matching assignment must be counted on
/// the node summary, the fleet monitoring overview, and the metrics endpoint.
#[tokio::test]
async fn an_agent_reported_cat_without_an_assignment_is_surfaced_as_an_orphan() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("legit", None).await;
    ctx.wait_observed("legit", ObservedState::Running).await;

    // A runtime the control plane never created: the incident shape.
    node.cats
        .lock()
        .unwrap()
        .insert("cat_orphan1".into(), ObservedState::Running);

    let summary = wait_orphan_cats(&ctx, "node_a", 1).await;
    assert_eq!(
        summary.assigned_cats, 1,
        "the assigned Cat must not count as an orphan"
    );

    let overview: MonitoringOverview = ctx.get_json(ctx.url("/v1/admin/monitoring")).await;
    assert_eq!(
        overview.orphan_cats, 1,
        "the fleet overview must expose the orphan count"
    );

    let prometheus = ctx
        .http
        .get(ctx.url("/metrics"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        prometheus.contains("cats_node_orphan_cats{node_id=\"node_a\"} 1"),
        "metrics must carry the per-node orphan gauge"
    );
}

/// Issue #98: the drain went draining -> cordoned in a minute and left all 13
/// orphans running, because it only enumerated the assignment table. A drain
/// must Cold-stop what the agent reports too, and must not cordon while the
/// agent still reports an orphan.
#[tokio::test]
async fn a_drain_stops_agent_reported_orphans_before_cordoning() {
    let ctx = Ctx::new().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    node.cats
        .lock()
        .unwrap()
        .insert("cat_orphan1".into(), ObservedState::Running);

    // The control plane must have seen the orphan before the drain starts;
    // otherwise an immediate cordon would be indistinguishable from the bug.
    wait_orphan_cats(&ctx, "node_a", 1).await;

    let drain = ctx
        .http
        .post(ctx.url("/v1/admin/nodes/node_a/actions/drain"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(drain.status(), StatusCode::ACCEPTED);

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let summary = admin_node_summary(&ctx, "node_a").await;
        if summary.node.state == NodeState::Cordoned {
            assert_eq!(
                summary.orphan_cats, 0,
                "cordoned must mean the agent no longer reports the orphan"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "drain never cordoned the node"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        node.cats.lock().unwrap().is_empty(),
        "the orphan runtime must actually have been stopped"
    );
    assert!(
        node.jobs
            .lock()
            .unwrap()
            .iter()
            .any(|id| id == "job_cat_orphan1_0_drain_stop_orphan_cat"),
        "the orphan must be stopped by its reported identity"
    );
    assert!(
        node.stop_dispositions
            .lock()
            .unwrap()
            .iter()
            .all(|disposition| matches!(disposition, StopCatDisposition::Cold)),
        "an orphan stop must be Cold: whether it may publish is fencing's call"
    );
}

/// Issue #98: 8 of the 13 orphans were refused by storage fencing
/// (`root CAS conflict`) and can never stop cleanly. The drain must stay
/// visibly open rather than cordon a node that still runs them, and must back
/// off instead of re-dispatching the doomed stop every reconcile tick.
/// Discarding the stale journal is an explicit operator action; the injected
/// recovery below stands in for it.
#[tokio::test]
async fn a_drain_with_an_unstoppable_orphan_stays_draining_and_backs_off() {
    let ctx = Ctx::new_with_stable_node_lease().await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), usize::MAX);
    node.cats
        .lock()
        .unwrap()
        .insert("cat_fenced1".into(), ObservedState::Stopping);
    wait_orphan_cats(&ctx, "node_a", 1).await;

    let drain = ctx
        .http
        .post(ctx.url("/v1/admin/nodes/node_a/actions/drain"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(drain.status(), StatusCode::ACCEPTED);

    // Long enough that an unthrottled retry would be unmistakable: the
    // reconciler ticks every 200 ms.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let summary = admin_node_summary(&ctx, "node_a").await;
    assert_eq!(
        summary.node.state,
        NodeState::Draining,
        "a node still running an unstoppable orphan must not read as cordoned"
    );
    assert_eq!(
        summary.orphan_cats, 1,
        "the unstoppable orphan must stay visible while the drain is open"
    );
    let attempts = node
        .jobs
        .lock()
        .unwrap()
        .iter()
        .filter(|id| id.ends_with("_drain_stop_orphan_cat"))
        .count();
    assert!(
        attempts >= 1,
        "the orphan stop must be attempted at least once"
    );
    assert!(
        attempts <= 5,
        "a failing orphan stop must back off; {attempts} dispatches in 2 s is a hot loop"
    );

    // Once the operator resolves the orphan, the open drain converges without
    // a new request.
    node.fail_jobs_remaining
        .lock()
        .unwrap()
        .insert("stop_cat".into(), 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let summary = admin_node_summary(&ctx, "node_a").await;
        if summary.node.state == NodeState::Cordoned && summary.orphan_cats == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "drain did not converge after the orphan stop recovered"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

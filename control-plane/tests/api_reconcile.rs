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

use cats_api::billing::BillingBalance;
use cats_api::metering::{
    CatUsageCheckpoint, IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse, UsageMetric,
    UsageReport,
};
use cats_api::nodejob::{NodeJob, NodeJobAction, NodeJobResult};
use cats_api::requests::*;
use cats_api::resources::*;
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, Config, Handle};
use cats_control_plane::store::Store;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::{
    deterministic_event_id, AttributedCheckpoint, IngestOutcome, SqliteUsageStore, UsageAttribution,
};
use cats_storage::MetadataStore;

const SERVICE_TOKEN: &str = "dev-service-token";

// ---------------------------------------------------------------------------
// Stub node agent: accepts every job, tracks "running" cats, heartbeats.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StubNode {
    id: String,
    cats: Arc<Mutex<HashMap<String, ObservedState>>>,
    jobs: Arc<Mutex<Vec<String>>>,
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
    started_volume_epochs: Arc<Mutex<Vec<(String, String, i64)>>>,
    storage_meta: Arc<dyn MetadataStore>,
}

impl StubNode {
    /// Stop heartbeating, and return only once nothing is still in flight.
    ///
    /// Clearing `alive` on its own is not enough. The loop tests it before it
    /// builds the request, so a heartbeat that already passed the test can land
    /// after the caller has moved the node to Lost and quietly revive it --
    /// recovering a Lost node on heartbeat is intended behaviour, which is
    /// exactly why the test has to be sure none is outstanding.
    async fn quiesce(&self) {
        self.alive.store(false, Ordering::SeqCst);
        let _idle = self.heartbeat_gate.write().await;
    }
}

async fn stub_job(State(node): State<StubNode>, Json(job): Json<NodeJob>) -> Response {
    node.jobs.lock().unwrap().push(job.job_id.clone());
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
        return Json(NodeJobResult::fail(
            job.job_id,
            observed,
            format!("injected {kind} failure"),
            true,
        ))
        .into_response();
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
        let mut epochs = node.started_volume_epochs.lock().unwrap();
        for volume in volumes {
            let epoch = node
                .storage_meta
                .acquire_lease(&volume.volume_id, &volume.attachment_id, 60_000)
                .unwrap();
            epochs.push((
                volume.volume_id.clone(),
                volume.attachment_id.clone(),
                epoch,
            ));
        }
    }
    let (cat_id, observed) = match &job.action {
        NodeJobAction::StartCat { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::StopCat { cat_id } => (cat_id.clone(), ObservedState::Cold),
        NodeJobAction::SuspendCat { cat_id, .. } => (cat_id.clone(), ObservedState::Suspended),
        NodeJobAction::ResumeCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::WarmCat { cat_id } => (cat_id.clone(), ObservedState::Warm),
        NodeJobAction::RestoreCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::AttachDisk { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::DetachDisk { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::SyncCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::CleanupCat { cat_id } => (cat_id.clone(), ObservedState::Cold),
    };
    let mut cats = node.cats.lock().unwrap();
    if observed == ObservedState::Cold {
        cats.remove(&cat_id);
    } else {
        cats.insert(cat_id, observed);
    }
    if lose_start_response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "injected lost StartCat response",
        )
            .into_response()
    } else {
        Json(NodeJobResult::ok(job.job_id, observed)).into_response()
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

async fn start_stub_node(cp: &Handle, id: &str) -> StubNode {
    let node = StubNode {
        id: id.to_string(),
        cats: Arc::new(Mutex::new(HashMap::new())),
        jobs: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(AtomicBool::new(true)),
        heartbeat_gate: Arc::new(tokio::sync::RwLock::new(())),
        exec_attempts: Arc::new(AtomicUsize::new(0)),
        exec_conflicts_remaining: Arc::new(AtomicUsize::new(0)),
        fail_jobs_remaining: Arc::new(Mutex::new(HashMap::new())),
        lose_start_responses_remaining: Arc::new(AtomicUsize::new(0)),
        started_volume_epochs: Arc::new(Mutex::new(Vec::new())),
        storage_meta: cp.state.storage_meta.clone(),
    };
    let app = Router::new()
        .route("/v1/jobs", post(stub_job))
        .route("/v1/cats/{id}/exec", post(stub_exec))
        .with_state(node.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let client = reqwest::Client::new();
    let base = cp.base_url();
    client
        .post(format!("{base}/v1/nodes/register"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&RegisterNodeRequest {
            node_id: id.to_string(),
            agent_url: format!("http://{addr}"),
            gateway_url: format!("http://{addr}"),
            cpus: 16,
            memory_mib: 32_768,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

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
            let _ = client
                .post(format!("{base}/v1/nodes/heartbeat"))
                .bearer_auth(SERVICE_TOKEN)
                .json(&HeartbeatRequest {
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
                    }),
                })
                .send()
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

struct Ctx {
    _dir: tempfile::TempDir,
    cp: Handle,
    http: reqwest::Client,
    /// The bootstrap Account's default Workspace; resource routes key on its ID.
    workspace_id: String,
}

impl Ctx {
    async fn new() -> Self {
        Self::new_with_auto_tier(Default::default(), 200).await
    }

    async fn new_with_auto_tier(
        auto_tier_policy: AutoTierPolicy,
        reconcile_interval_ms: u64,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
        let cp = spawn(Config {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("control.db"),
            usage_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            credit_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            storage_meta,
            auth_token: SERVICE_TOKEN.into(),
            admin_token: "dev-admin-token".into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: true,
            node_lease_timeout_ms: 3_000,
            reconcile_interval_ms,
            auto_tier_policy,
        })
        .await
        .unwrap();
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
        let mut req = self
            .http
            .post(self.ws_url("/cats"))
            .bearer_auth("dev-admin-token")
            .json(&serde_json::json!({
                "name": name,
                "image": "ubuntu-24.04",
                "cpus": 2,
                "memory_mib": 1024,
                "root_size_bytes": 8 << 20,
                "disk": null
            }));
        if let Some(k) = idem {
            req = req.header("Idempotency-Key", k);
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), 202);
        resp.json().await.unwrap()
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
    // A different key with the same name conflicts.
    let resp = ctx
        .http
        .post(ctx.ws_url("/cats"))
        .bearer_auth("dev-admin-token")
        .json(&CreateCatRequest {
            name: "dev".into(),
            image: "x".into(),
            cpus: 1,
            memory_mib: 256,
            root_size_bytes: 4 << 20,
            auto_suspend: true,
            disk: None,
            expires_at_unix: None,
            durability: Default::default(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Unauthenticated requests are rejected.
    let resp = ctx.http.get(ctx.ws_url("/cats")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn lifecycle_stop_start_suspend_resume() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    ctx.wait_observed("dev", ObservedState::Running).await;

    let stop = ctx.action("dev", "stop").await;
    ctx.wait_operation(&stop.operation.id).await;
    let cat = ctx.wait_observed("dev", ObservedState::Cold).await;
    assert!(cat.node_id.is_none(), "placement must clear on stop");

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
    let ctx = Ctx::new().await;
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
    let ctx = Ctx::new().await;
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
async fn default_auto_suspend_fires_on_the_last_guest_work_release() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("worker", None).await;
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
    ctx.http
        .post(ctx.url("/v1/nodes/work-status"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&report(
            1,
            vec![cats_api::guest::GuestWorkLease {
                id: "job-1".into(),
                label: "user-training".into(),
                remaining_ttl_ms: 30_000,
            }],
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let enabled: AutoSuspendResponse = ctx
        .http
        .get(ctx.ws_url("/cats/worker/auto-suspend"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
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

    ctx.http
        .post(ctx.url("/v1/nodes/work-status"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&report(2, vec![]))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let suspended = ctx.wait_observed("worker", ObservedState::Suspended).await;
    assert_eq!(suspended.desired_state, DesiredState::Suspended);

    let operations: ListResponse<Operation> = ctx
        .http
        .get(ctx.ws_url("/operations"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(operations.items.iter().any(|operation| {
        operation.kind == "cat.auto_suspend" && operation.phase == OperationPhase::Succeeded
    }));
}

#[tokio::test]
async fn automatic_tiers_progress_from_suspended_through_warm_to_cold() {
    let ctx = Ctx::new_with_auto_tier(
        AutoTierPolicy {
            warm_after_ms: Some(100),
            cold_after_ms: Some(100),
        },
        20,
    )
    .await;
    let node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("tiered", None).await;
    let cat = ctx.wait_observed("tiered", ObservedState::Running).await;

    ctx.http
        .post(ctx.url("/v1/nodes/work-status"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&NodeWorkStatusRequest {
            node_id: "node_a".into(),
            cat_id: cat.id.clone(),
            generation: cat.generation,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: 0,
            leases: vec![],
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let cold = ctx.wait_observed("tiered", ObservedState::Cold).await;
    assert_eq!(cold.desired_state, DesiredState::Cold);
    assert!(cold.node_id.is_none());
    assert!(cold.observed_state_since_unix_ms > 0);

    let operations: ListResponse<Operation> = ctx
        .http
        .get(ctx.ws_url("/operations"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    for kind in ["cat.auto_suspend", "cat.auto_warm", "cat.auto_cold"] {
        assert!(
            operations
                .items
                .iter()
                .any(|operation| operation.kind == kind
                    && operation.phase == OperationPhase::Succeeded),
            "missing successful {kind}: {:?}",
            operations
                .items
                .iter()
                .map(|operation| (&operation.kind, operation.phase))
                .collect::<Vec<_>>()
        );
    }
    let jobs = node.jobs.lock().unwrap();
    assert!(jobs.iter().any(|job| job.ends_with("_warm_cat")));
    assert!(jobs.iter().any(|job| job.ends_with("_stop_cat")));
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
async fn ambiguous_start_response_retries_the_same_claim_without_revoking_its_epoch() {
    let ctx = Ctx::new_with_auto_tier(Default::default(), 1_500).await;
    let source = start_stub_node(&ctx.cp, "node_z").await;
    source
        .lose_start_responses_remaining
        .store(1, Ordering::SeqCst);
    source.quiesce().await;

    ctx.create_cat("ambiguous-start", None).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let (volume_id, attachment_id, epoch) = loop {
        if let Some(epoch) = source
            .started_volume_epochs
            .lock()
            .unwrap()
            .first()
            .cloned()
        {
            break epoch;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the injected StartCat never acquired its disk epoch"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

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
    ctx.cp
        .state
        .storage_meta
        .renew_lease(&volume_id, &attachment_id, epoch, 60_000)
        .expect("replaying an ambiguous StartCat must preserve its live disk epoch");
}

#[tokio::test]
async fn node_loss_preserves_claim_until_fencing_is_explicitly_confirmed() {
    let ctx = Ctx::new().await;
    let node_a = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    let cat = ctx.wait_observed("dev", ObservedState::Running).await;
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));
    ctx.create_cat("doomed", None).await;
    let doomed = ctx.wait_observed("doomed", ObservedState::Running).await;
    assert_eq!(doomed.node_id.as_deref(), Some("node_a"));
    let root = ctx
        .cp
        .state
        .store
        .get_disk(&cat.workspace_id, &cat.root_disk_id)
        .unwrap();
    let old_attachment = "old-node-a-attachment";
    let old_epoch = ctx
        .cp
        .state
        .storage_meta
        .acquire_lease(&root.volume_id, old_attachment, 60_000)
        .unwrap();

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
    ctx.cp
        .state
        .storage_meta
        .renew_lease(&root.volume_id, old_attachment, old_epoch, 60_000)
        .expect("heartbeat loss alone must not revoke the old epoch");

    // If the heartbeat returns before an explicit handoff, ownership recovers
    // in place instead of cold-starting another Guest.
    node_a.alive.store(true, Ordering::SeqCst);
    ctx.http
        .post(ctx.url("/v1/nodes/heartbeat"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&HeartbeatRequest {
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
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
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
    ctx.cp
        .state
        .storage_meta
        .renew_lease(&root.volume_id, old_attachment, old_epoch, 60_000)
        .expect("a rejected fence confirmation must leave the claim intact");

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
    assert!(matches!(
        ctx.cp
            .state
            .storage_meta
            .renew_lease(&root.volume_id, old_attachment, old_epoch, 60_000),
        Err(cats_storage::MetaError::Fenced)
    ));
}

#[tokio::test]
async fn control_plane_startup_grace_preserves_a_reconnecting_host_bound_cat() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("control.db");
    let cat_id;
    {
        let store = Store::open(&db_path).unwrap();
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
        db_path,
        storage_meta,
        auth_token: SERVICE_TOKEN.into(),
        admin_token: "dev-admin-token".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 2_000,
        reconcile_interval_ms: 10,
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
        cp.state.store.heartbeat_node("node_a", None).unwrap();
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
    let _node = start_stub_node(&ctx.cp, "node_a").await;
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
}

#[tokio::test]
async fn static_user_tokens_are_not_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        db_path: dir.path().join("control.db"),
        usage_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
        credit_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
        storage_meta,
        auth_token: SERVICE_TOKEN.into(),
        admin_token: "token-admin".into(),
        workos: None,
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 3_000,
        reconcile_interval_ms: 200,
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
async fn cumulative_usage_is_idempotent_and_queryable_by_workspace_cat_and_metric() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
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
    let first: IngestUsageCheckpointsResponse = ctx
        .http
        .post(ctx.url("/v1/internal/usage/checkpoints"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first.accepted, 3);
    assert_eq!(first.duplicates, 1);

    let replay: IngestUsageCheckpointsResponse = ctx
        .http
        .post(ctx.url("/v1/internal/usage/checkpoints"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
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

    let balance: BillingBalance = ctx
        .http
        .get(ctx.ws_url("/billing/balance"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(balance.credit_nanos, "10000000000");
    assert_eq!(balance.provisional_usage_nanos, "115000000");
    assert_eq!(balance.available_credit_nanos, "9885000000");
    assert_eq!(
        balance.signup_credit_nanos, "0",
        "an Organization Account is never a signup-grant beneficiary"
    );
    assert!(!balance.stripe_enabled);

    let bucketed: UsageReport = ctx
        .http
        .get(ctx.ws_url(&format!(
            "/billing/usage?from_ms=1000&to_ms={hour_end}&cat_id={}&bucket_ms=1800000",
            cat.id
        )))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
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
        node_id: "node_a".to_string(),
        checkpoints: vec![make_checkpoint(
            UsageMetric::CpuUsec,
            2,
            hour_end + 1_000,
            3_600_000_001,
        )],
    };
    let accepted_historical: IngestUsageCheckpointsResponse = ctx
        .http
        .post(ctx.url("/v1/internal/usage/checkpoints"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&historical)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(accepted_historical.accepted, 1);

    let mut future_checkpoint = historical.checkpoints[0].clone();
    future_checkpoint.cat_generation = transitioned.generation + 1;
    future_checkpoint.event_id = deterministic_event_id(&future_checkpoint);
    let future = ctx
        .http
        .post(ctx.url("/v1/internal/usage/checkpoints"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&IngestUsageCheckpointsRequest {
            node_id: "node_a".to_string(),
            checkpoints: vec![future_checkpoint],
        })
        .send()
        .await
        .unwrap();
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
    let deleted_tail: IngestUsageCheckpointsResponse = ctx
        .http
        .post(ctx.url("/v1/internal/usage/checkpoints"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&IngestUsageCheckpointsRequest {
            node_id: "node_a".to_string(),
            checkpoints: vec![make_checkpoint(
                UsageMetric::CpuUsec,
                3,
                hour_end + 2_000,
                3_600_000_002,
            )],
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deleted_tail.accepted, 1);

    let historical_report: UsageReport = ctx
        .http
        .get(ctx.ws_url(&format!(
            "/billing/usage?from_ms=1000&to_ms={}&cat_id={}&detail=true",
            hour_end + 3_000,
            cat.id
        )))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
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
    let response = ctx
        .http
        .post(ctx.url("/v1/internal/usage/checkpoints"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&IngestUsageCheckpointsRequest {
            node_id: "node_a".to_string(),
            checkpoints: vec![
                checkpoint(0, 1_000, 0),
                checkpoint(1, 720_001_000, 720_000_000_000),
            ],
        })
        .send()
        .await
        .unwrap();
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
        let nodes: ListResponse<NodeSummary> = ctx
            .http
            .get(ctx.url("/v1/admin/nodes"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
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

    let overview: MonitoringOverview = ctx
        .http
        .get(ctx.url("/v1/admin/monitoring"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
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
        let listed: ListResponse<NodeCatSummary> = ctx
            .http
            .get(ctx.url("/v1/admin/nodes/node_a/cats"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
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

    // Cordon records scheduling intent without hiding Lost health; a later
    // registration recovery must not silently defeat that intent.
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
    let register = ctx
        .http
        .post(ctx.url("/v1/nodes/register"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&RegisterNodeRequest {
            node_id: "node_a".into(),
            agent_url: "http://127.0.0.1:1".into(),
            gateway_url: "http://gateway.invalid".into(),
            cpus: 8,
            memory_mib: 16_384,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(register.status(), StatusCode::NO_CONTENT);
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

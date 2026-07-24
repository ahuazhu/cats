//! Control-plane contract tests with a stub node agent: reconcile loop,
//! operations, idempotency, RWO enforcement, node-loss fencing/rescheduling.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use cats_api::nodejob::{NodeJob, NodeJobAction, NodeJobResult};
use cats_api::requests::*;
use cats_api::resources::*;
use cats_control_plane::controller::AutoTierPolicy;
use cats_control_plane::server::{spawn, Config, Handle};
use cats_control_plane::store::Store;
use cats_metadata_store_sqlite::SqliteMetadataStore;
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
    exec_attempts: Arc<AtomicUsize>,
    exec_conflicts_remaining: Arc<AtomicUsize>,
}

async fn stub_job(State(node): State<StubNode>, Json(job): Json<NodeJob>) -> Json<NodeJobResult> {
    node.jobs.lock().unwrap().push(job.job_id.clone());
    let (cat_id, observed) = match &job.action {
        NodeJobAction::StartCat { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::StopCat { cat_id } => (cat_id.clone(), ObservedState::Cold),
        NodeJobAction::SuspendCat { cat_id, .. } => (cat_id.clone(), ObservedState::Suspended),
        NodeJobAction::ResumeCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::WarmCat { cat_id } => (cat_id.clone(), ObservedState::Warm),
        NodeJobAction::RestoreCat { cat_id } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::AttachDisk { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::DetachDisk { cat_id, .. } => (cat_id.clone(), ObservedState::Running),
        NodeJobAction::CleanupCat { cat_id } => (cat_id.clone(), ObservedState::Cold),
    };
    let mut cats = node.cats.lock().unwrap();
    if observed == ObservedState::Cold {
        cats.remove(&cat_id);
    } else {
        cats.insert(cat_id, observed);
    }
    Json(NodeJobResult::ok(job.job_id, observed))
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
        exec_attempts: Arc::new(AtomicUsize::new(0)),
        exec_conflicts_remaining: Arc::new(AtomicUsize::new(0)),
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

struct Ctx {
    _dir: tempfile::TempDir,
    cp: Handle,
    http: reqwest::Client,
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
            storage_meta,
            auth_token: SERVICE_TOKEN.into(),
            admin_token: "dev-admin-token".into(),
            workos: None,
            node_lease_timeout_ms: 3_000,
            reconcile_interval_ms,
            auto_tier_policy,
        })
        .await
        .unwrap();
        Self {
            _dir: dir,
            cp,
            http: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.cp.base_url(), path)
    }

    async fn wait_observed(&self, name: &str, want: ObservedState) -> Cat {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let cat: Cat = self
                .http
                .get(self.url(&format!("/v1/projects/default/cats/{name}")))
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
            .post(self.url("/v1/projects/default/cats"))
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
            .post(self.url(&format!("/v1/projects/default/cats/{name}/actions/{verb}")))
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
        .post(ctx.url("/v1/projects/default/cats"))
        .bearer_auth("dev-admin-token")
        .json(&CreateCatRequest {
            name: "dev".into(),
            image: "x".into(),
            cpus: 1,
            memory_mib: 256,
            root_size_bytes: 4 << 20,
            auto_suspend: true,
            disk: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Unauthenticated requests are rejected.
    let resp = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .send()
        .await
        .unwrap();
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
        .get(ctx.url("/v1/projects/default/cats/worker/auto-suspend"))
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
        .get(ctx.url("/v1/projects/default/operations"))
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
        .get(ctx.url("/v1/projects/default/operations"))
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
        .post(ctx.url("/v1/projects/default/disks"))
        .bearer_auth("dev-admin-token")
        .json(&CreateDiskRequest {
            name: "shared".into(),
            size_bytes: 8 << 20,
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
        .post(ctx.url("/v1/projects/default/disks/shared/actions/mount"))
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
        .post(ctx.url("/v1/projects/default/disks/shared/actions/mount"))
        .bearer_auth("dev-admin-token")
        .json(&mount("cat-b"))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409, "RWO second mount must conflict");

    // Deleting a bound disk is refused; unmount frees it.
    let del = ctx
        .http
        .delete(ctx.url("/v1/projects/default/disks/shared"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 412);
    let um = ctx
        .http
        .post(ctx.url("/v1/projects/default/disks/shared/actions/unmount"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert!(um.status().is_success());
    let del = ctx
        .http
        .delete(ctx.url("/v1/projects/default/disks/shared"))
        .bearer_auth("dev-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 204);
}

#[tokio::test]
async fn node_loss_fences_and_reschedules() {
    let ctx = Ctx::new().await;
    let node_a = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    let cat = ctx.wait_observed("dev", ObservedState::Running).await;
    assert_eq!(cat.node_id.as_deref(), Some("node_a"));

    // Second node joins; first node dies (heartbeats stop).
    let _node_b = start_stub_node(&ctx.cp, "node_b").await;
    node_a.alive.store(false, Ordering::SeqCst);

    // The cat must converge back to Running on the surviving node.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let cat: Cat = ctx
            .http
            .get(ctx.url("/v1/projects/default/cats/dev"))
            .bearer_auth("dev-admin-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if cat.observed_state == ObservedState::Running && cat.node_id.as_deref() == Some("node_b")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never rescheduled to node_b"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn control_plane_startup_grace_preserves_a_reconnecting_host_bound_cat() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("control.db");
    let cat_id;
    {
        let store = Store::open(&db_path).unwrap();
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
                "default",
                "restart-safe",
                "test",
                1,
                256,
                8 << 20,
                true,
                None,
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
        db_path,
        storage_meta,
        auth_token: SERVICE_TOKEN.into(),
        admin_token: "dev-admin-token".into(),
        workos: None,
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
        .post(ctx.url("/v1/projects/default/cats/dev/exec"))
        .bearer_auth("dev-admin-token")
        .json(&ExecRequest {
            command: vec!["echo".into(), "hi".into()],
            timeout_ms: None,
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
        .post(ctx.url("/v1/projects/default/cats/dev/exec"))
        .bearer_auth("dev-admin-token")
        .json(&ExecRequest {
            command: vec!["pwd".into()],
            timeout_ms: None,
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
        .post(ctx.url("/v1/projects/default/disks"))
        .bearer_auth("dev-admin-token")
        .json(&CreateDiskRequest {
            name: "keep".into(),
            size_bytes: 8 << 20,
        })
        .send()
        .await
        .unwrap();
    ctx.http
        .post(ctx.url("/v1/projects/default/disks/keep/actions/mount"))
        .bearer_auth("dev-admin-token")
        .json(&serde_json::json!({"cat_id": "dev", "mount_at": "/data"}))
        .send()
        .await
        .unwrap();

    let resp = ctx
        .http
        .delete(ctx.url("/v1/projects/default/cats/dev"))
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
            .get(ctx.url("/v1/projects/default/cats/dev"))
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
        .get(ctx.url("/v1/projects/default/disks"))
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
        storage_meta,
        auth_token: SERVICE_TOKEN.into(),
        admin_token: "token-admin".into(),
        workos: None,
        node_lease_timeout_ms: 3_000,
        reconcile_interval_ms: 200,
        auto_tier_policy: Default::default(),
    };
    let cp = spawn(cfg).await.unwrap();
    let http = reqwest::Client::new();

    let old_project_token = http
        .get(format!("{}/v1/projects/alpha/cats", cp.base_url()))
        .bearer_auth("token-alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(old_project_token.status(), StatusCode::UNAUTHORIZED);

    let service_as_user = http
        .get(format!("{}/v1/projects/alpha/cats", cp.base_url()))
        .bearer_auth(SERVICE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(service_as_user.status(), StatusCode::FORBIDDEN);

    let admin_cross_project = http
        .get(format!("{}/v1/projects/alpha/cats", cp.base_url()))
        .bearer_auth("token-admin")
        .send()
        .await
        .unwrap();
    assert_eq!(admin_cross_project.status(), StatusCode::OK);
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

    let node_cats: ListResponse<NodeCatSummary> = ctx
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
            .get(ctx.url("/v1/projects/default/cats/drain-me"))
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
    node_a.alive.store(false, Ordering::SeqCst);
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

//! Control-plane contract tests with a stub node agent: reconcile loop,
//! operations, idempotency, RWO enforcement, node-loss fencing/rescheduling.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

use cats_api::nodejob::{NodeJob, NodeJobAction, NodeJobResult};
use cats_api::requests::*;
use cats_api::resources::*;
use cats_control_plane::server::{spawn, Config, Handle};
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

async fn stub_exec(Json(req): Json<ExecRequest>) -> Json<ExecResponse> {
    Json(ExecResponse {
        exit_code: 0,
        stdout: req.command.join(" "),
        stderr: String::new(),
    })
}

async fn start_stub_node(cp: &Handle, id: &str) -> StubNode {
    let node = StubNode {
        id: id.to_string(),
        cats: Arc::new(Mutex::new(HashMap::new())),
        jobs: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(AtomicBool::new(true)),
    };
    let app = Router::new()
        .route("/v1/jobs", post(stub_job))
        .route(
            "/v1/cats/{id}/exec",
            post(|_: axum::extract::Path<String>, req: Json<ExecRequest>| stub_exec(req)),
        )
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
                        load_average_1m: Some(0.25),
                        host_memory_total_mib: Some(32_768),
                        host_memory_available_mib: Some(24_576),
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
        let dir = tempfile::tempdir().unwrap();
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
        let cp = spawn(Config {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("control.db"),
            storage_meta,
            auth_token: SERVICE_TOKEN.into(),
            admin_token: "dev-admin-token".into(),
            project_tokens: BTreeMap::from([("*".into(), "dev-token".into())]),
            workos: None,
            node_lease_timeout_ms: 3_000,
            reconcile_interval_ms: 200,
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
                .bearer_auth("dev-token")
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
                .bearer_auth("dev-token")
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
            .bearer_auth("dev-token")
            .json(&CreateCatRequest {
                name: name.to_string(),
                image: "ubuntu-24.04".to_string(),
                cpus: 2,
                memory_mib: 1024,
                root_size_bytes: 8 << 20,
                disk: None,
            });
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
            .bearer_auth("dev-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202, "{verb} not accepted");
        resp.json().await.unwrap()
    }
}

#[tokio::test]
async fn embedded_user_and_admin_sites_are_served_without_credentials() {
    let ctx = Ctx::new().await;
    let assets = [
        ("/", "text/html", "用户控制台"),
        ("/user/", "text/html", "用户控制台"),
        ("/admin/", "text/html", "管理员控制台"),
        ("/ui/styles.css", "text/css", ".app-shell"),
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
        .get(ctx.url("/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!user_html.contains("Project Token"));
    assert!(!user_html.contains("token-login-section"));
    assert!(!user_html.contains("CAT STATUS"));

    let response = ctx
        .http
        .get(ctx.url("/"))
        .header("Host", "ops.cats.run")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let admin_html = response.text().await.unwrap();
    assert!(admin_html.contains("管理员控制台"));
    assert!(!admin_html.contains("Administrator Token"));
    assert!(!admin_html.contains("FLEET HEALTH"));

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
async fn create_converges_and_idempotency_replays() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;

    let created = ctx.create_cat("dev", Some("key-1")).await;
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
        .bearer_auth("dev-token")
        .json(&CreateCatRequest {
            name: "dev".into(),
            image: "x".into(),
            cpus: 1,
            memory_mib: 256,
            root_size_bytes: 4 << 20,
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
async fn auto_suspend_fires_on_the_last_guest_work_release() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("worker", None).await;
    let cat = ctx.wait_observed("worker", ObservedState::Running).await;

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
        .put(ctx.url("/v1/projects/default/cats/worker/auto-suspend"))
        .bearer_auth("dev-token")
        .json(&UpdateAutoSuspendRequest { enabled: true })
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
        .bearer_auth("dev-token")
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
        .bearer_auth("dev-token")
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
        .bearer_auth("dev-token")
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
        .bearer_auth("dev-token")
        .json(&mount("cat-b"))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409, "RWO second mount must conflict");

    // Deleting a bound disk is refused; unmount frees it.
    let del = ctx
        .http
        .delete(ctx.url("/v1/projects/default/disks/shared"))
        .bearer_auth("dev-token")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 412);
    let um = ctx
        .http
        .post(ctx.url("/v1/projects/default/disks/shared/actions/unmount"))
        .bearer_auth("dev-token")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert!(um.status().is_success());
    let del = ctx
        .http
        .delete(ctx.url("/v1/projects/default/disks/shared"))
        .bearer_auth("dev-token")
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
            .bearer_auth("dev-token")
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
        .bearer_auth("dev-token")
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
async fn destroy_deletes_root_disk_and_keeps_persistent() {
    let ctx = Ctx::new().await;
    let _node = start_stub_node(&ctx.cp, "node_a").await;
    ctx.create_cat("dev", None).await;
    ctx.wait_observed("dev", ObservedState::Running).await;
    // Attach a persistent disk.
    ctx.http
        .post(ctx.url("/v1/projects/default/disks"))
        .bearer_auth("dev-token")
        .json(&CreateDiskRequest {
            name: "keep".into(),
            size_bytes: 8 << 20,
        })
        .send()
        .await
        .unwrap();
    ctx.http
        .post(ctx.url("/v1/projects/default/disks/keep/actions/mount"))
        .bearer_auth("dev-token")
        .json(&serde_json::json!({"cat_id": "dev", "mount_at": "/data"}))
        .send()
        .await
        .unwrap();

    let resp = ctx
        .http
        .delete(ctx.url("/v1/projects/default/cats/dev"))
        .bearer_auth("dev-token")
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
            .bearer_auth("dev-token")
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
        .bearer_auth("dev-token")
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
async fn project_tokens_scope_user_resources_and_operations() {
    let dir = tempfile::tempdir().unwrap();
    let storage_meta: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("storage-meta.db")).unwrap());
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        db_path: dir.path().join("control.db"),
        storage_meta,
        auth_token: SERVICE_TOKEN.into(),
        admin_token: "token-admin".into(),
        project_tokens: BTreeMap::from([
            ("alpha".to_string(), "token-alpha".to_string()),
            ("beta".to_string(), "token-beta".to_string()),
        ]),
        workos: None,
        node_lease_timeout_ms: 3_000,
        reconcile_interval_ms: 200,
    };
    let cp = spawn(cfg).await.unwrap();
    let http = reqwest::Client::new();

    let create = http
        .post(format!("{}/v1/projects/alpha/cats", cp.base_url()))
        .bearer_auth("token-alpha")
        .json(&CreateCatRequest {
            name: "mine".into(),
            image: "ubuntu-24.04".into(),
            cpus: 1,
            memory_mib: 512,
            root_size_bytes: 8 << 20,
            disk: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let created: CatOperationResponse = create.json().await.unwrap();

    let own = http
        .get(format!("{}/v1/projects/alpha/cats", cp.base_url()))
        .bearer_auth("token-alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), StatusCode::OK);

    let other_project = http
        .get(format!("{}/v1/projects/beta/cats", cp.base_url()))
        .bearer_auth("token-alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(other_project.status(), StatusCode::FORBIDDEN);

    let service_as_user = http
        .get(format!("{}/v1/projects/alpha/cats", cp.base_url()))
        .bearer_auth(SERVICE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(service_as_user.status(), StatusCode::FORBIDDEN);

    let other_operation = http
        .get(format!(
            "{}/v1/operations/{}",
            cp.base_url(),
            created.operation.id
        ))
        .bearer_auth("token-beta")
        .send()
        .await
        .unwrap();
    assert_eq!(other_operation.status(), StatusCode::FORBIDDEN);

    let operations: ListResponse<Operation> = http
        .get(format!("{}/v1/projects/alpha/operations", cp.base_url()))
        .bearer_auth("token-alpha")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(operations.items.len(), 1);
    assert_eq!(operations.items[0].project, "alpha");

    let user_admin = http
        .get(format!("{}/v1/admin/monitoring", cp.base_url()))
        .bearer_auth("token-alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(user_admin.status(), StatusCode::FORBIDDEN);

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
            .bearer_auth("dev-token")
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

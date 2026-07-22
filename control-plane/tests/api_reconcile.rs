//! Control-plane contract tests with a stub node agent: reconcile loop,
//! operations, idempotency, RWO enforcement, node-loss fencing/rescheduling.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};

use cats_api::nodejob::{NodeJob, NodeJobAction, NodeJobResult};
use cats_api::requests::*;
use cats_api::resources::*;
use cats_control_plane::server::{spawn, Config, Handle};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_storage::MetadataStore;

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
        NodeJobAction::SuspendCat { cat_id } => (cat_id.clone(), ObservedState::Suspended),
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
        .bearer_auth("dev-token")
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
            let _ = client
                .post(format!("{base}/v1/nodes/heartbeat"))
                .bearer_auth("dev-token")
                .json(&HeartbeatRequest {
                    node_id: hb.id.clone(),
                    cats,
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
            auth_token: "dev-token".into(),
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

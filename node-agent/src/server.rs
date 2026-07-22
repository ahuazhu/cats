//! Node agent HTTP surface + registration/heartbeat loops.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use cats_api::nodejob::NodeJob;
use cats_api::requests::{
    ExecRequest, ExecResponse, HeartbeatCat, HeartbeatRequest, RegisterNodeRequest,
};
use cats_storage::MetadataStore;

use crate::runtime::{NodeConfig, NodeRuntime};

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub auth_token: String,
    pub gateway_url: String,
    pub cpus: u32,
    pub memory_mib: u64,
    pub heartbeat_ms: u64,
    pub node: NodeConfig,
    pub storage_meta: Arc<dyn MetadataStore>,
}

#[derive(Clone)]
pub struct NodeState {
    pub runtime: Arc<NodeRuntime>,
    pub cfg: Arc<ServerConfig>,
}

pub struct Handle {
    pub addr: std::net::SocketAddr,
    pub state: NodeState,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Handle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn shutdown(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn check_auth(cfg: &ServerConfig, headers: &HeaderMap) -> Result<(), StatusCode> {
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == cfg.auth_token);
    if ok {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn handle_job(
    State(state): State<NodeState>,
    headers: HeaderMap,
    Json(job): Json<NodeJob>,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let runtime = state.runtime.clone();
    let result = tokio::task::spawn_blocking(move || runtime.execute(job)).await;
    match result {
        Ok(res) => Json(res).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn handle_exec(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let runtime = state.runtime.clone();
    let result = tokio::task::spawn_blocking(move || runtime.exec(&cat_id, req.command)).await;
    match result {
        Ok(Ok((exit_code, stdout, stderr))) => Json(ExecResponse {
            exit_code,
            stdout,
            stderr,
        })
        .into_response(),
        Ok(Err(e)) => (StatusCode::CONFLICT, format!("{e:#}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct ProxyQuery {
    path: Option<String>,
}

/// Gateway hop: returns the guest's raw HTTP response bytes. 409 = the cat
/// is not active on this node (stale route: the gateway must re-resolve).
async fn handle_proxy(
    State(state): State<NodeState>,
    Path(cat_id): Path<String>,
    Query(q): Query<ProxyQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(code) = check_auth(&state.cfg, &headers) {
        return code.into_response();
    }
    let runtime = state.runtime.clone();
    let path = q.path.unwrap_or_else(|| "/".to_string());
    let result = tokio::task::spawn_blocking(move || runtime.proxy_get(&cat_id, &path)).await;
    match result {
        Ok(Ok(raw)) => (StatusCode::OK, raw).into_response(),
        Ok(Err(e)) => (StatusCode::CONFLICT, format!("{e:#}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub fn router(state: NodeState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/jobs", post(handle_job))
        .route("/v1/cats/{id}/exec", post(handle_exec))
        .route("/v1/cats/{id}/proxy", get(handle_proxy))
        .with_state(state)
}

/// Start the node agent: HTTP server + registration + heartbeat loop.
pub async fn spawn(cfg: ServerConfig) -> anyhow::Result<Handle> {
    std::fs::create_dir_all(&cfg.node.state_dir)?;
    let cfg = Arc::new(cfg);
    let runtime = Arc::new(NodeRuntime::new(cfg.node.clone(), cfg.storage_meta.clone()));
    let state = NodeState {
        runtime: runtime.clone(),
        cfg: cfg.clone(),
    };

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let app = router(state.clone());
    let server = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("node agent server exited: {e}");
        }
    });

    // Register with the control plane (retry until it is reachable).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let register = RegisterNodeRequest {
        node_id: cfg.node.node_id.clone(),
        agent_url: format!("http://{addr}"),
        gateway_url: cfg.gateway_url.clone(),
        cpus: cfg.cpus,
        memory_mib: cfg.memory_mib,
    };
    let cp = cfg.control_plane_url.trim_end_matches('/').to_string();
    let token = cfg.auth_token.clone();
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let resp = client
                .post(format!("{cp}/v1/nodes/register"))
                .bearer_auth(&token)
                .json(&register)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => break,
                _ if std::time::Instant::now() > deadline => {
                    anyhow::bail!("could not register with control plane at {cp}")
                }
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }
    tracing::info!(node = %cfg.node.node_id, %addr, "node agent registered");

    // Heartbeat loop.
    let hb_state = state.clone();
    let hb_client = client.clone();
    let hb_cp = cp.clone();
    let hb_token = token.clone();
    let interval = Duration::from_millis(cfg.heartbeat_ms);
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let cats: Vec<HeartbeatCat> = hb_state
                .runtime
                .snapshot()
                .into_iter()
                .map(|(cat_id, generation, state)| HeartbeatCat {
                    cat_id,
                    generation,
                    state,
                })
                .collect();
            let _ = hb_client
                .post(format!("{hb_cp}/v1/nodes/heartbeat"))
                .bearer_auth(&hb_token)
                .json(&HeartbeatRequest {
                    node_id: hb_state.cfg.node.node_id.clone(),
                    cats,
                })
                .send()
                .await;
        }
    });

    Ok(Handle {
        addr,
        state,
        tasks: vec![server, heartbeat],
    })
}

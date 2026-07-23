//! Cats edge/node gateway (dev topology: one process plays both roles).
//!
//! Request path (arch doc §9.1, minimal): `Host:` header -> control-plane
//! route resolve (cached briefly) -> node-agent proxy hop. The node agent
//! re-validates possession and answers 409 for stale routes, which makes
//! the gateway re-resolve once — that is the "old epoch fails closed"
//! behavior the E2E suite asserts after a cat moves between nodes.
//! Wake-on-request goes through the control plane's wake endpoint
//! (singleflight there), honoring the endpoint's wake policy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::routing::get;
use axum::Router;

use cats_api::requests::{
    AcquireWorkRequest, AcquireWorkResponse, ProxyHttpRequest, ProxyHttpResponse,
    ReleaseWorkRequest,
};
use cats_api::resources::WorkKind;
use cats_api::resources::{ObservedState, RouteBinding, WakePolicy};

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub auth_token: String,
    /// Route cache TTL; kept tiny so rebinding propagates fast in dev.
    pub cache_ttl_ms: u64,
}

#[derive(Clone, serde::Deserialize)]
struct ResolveResponse {
    binding: RouteBinding,
    state: String,
    observed_state: ObservedState,
    node_agent_url: String,
}

#[derive(Clone)]
struct CachedRoute {
    resolved: ResolveResponse,
    fetched: Instant,
}

#[derive(Clone)]
pub struct Gateway {
    cfg: Arc<GatewayConfig>,
    http: reqwest::Client,
    cache: Arc<Mutex<HashMap<String, CachedRoute>>>,
}

pub struct Handle {
    pub addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Handle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gateway {
    fn cp(&self) -> String {
        self.cfg.control_plane_url.trim_end_matches('/').to_string()
    }

    async fn resolve(&self, hostname: &str, use_cache: bool) -> Result<ResolveResponse, Response> {
        if use_cache {
            let cache = self.cache.lock().unwrap();
            if let Some(hit) = cache.get(hostname) {
                if hit.fetched.elapsed() < Duration::from_millis(self.cfg.cache_ttl_ms) {
                    return Ok(hit.resolved.clone());
                }
            }
        }
        let resp = self
            .http
            .get(format!("{}/v1/routes/resolve", self.cp()))
            .query(&[("hostname", hostname)])
            .bearer_auth(&self.cfg.auth_token)
            .send()
            .await
            .map_err(|e| gw_error(StatusCode::BAD_GATEWAY, format!("resolve failed: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(gw_error(
                StatusCode::NOT_FOUND,
                format!("no route for host {hostname}"),
            ));
        }
        if !resp.status().is_success() {
            return Err(gw_error(
                StatusCode::BAD_GATEWAY,
                format!("resolve status {}", resp.status()),
            ));
        }
        let resolved: ResolveResponse = resp
            .json()
            .await
            .map_err(|e| gw_error(StatusCode::BAD_GATEWAY, format!("bad resolve body: {e}")))?;
        self.cache.lock().unwrap().insert(
            hostname.to_string(),
            CachedRoute {
                resolved: resolved.clone(),
                fetched: Instant::now(),
            },
        );
        Ok(resolved)
    }

    fn invalidate(&self, hostname: &str) {
        self.cache.lock().unwrap().remove(hostname);
    }

    async fn wake(&self, hostname: &str) -> Result<(), Response> {
        let resp = self
            .http
            .post(format!("{}/v1/routes/wake", self.cp()))
            .query(&[("hostname", hostname)])
            .bearer_auth(&self.cfg.auth_token)
            .send()
            .await
            .map_err(|e| gw_error(StatusCode::BAD_GATEWAY, format!("wake failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(gw_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("endpoint is not available (wake status {})", resp.status()),
            ));
        }
        Ok(())
    }

    async fn acquire_request_work(&self, cat_id: &str) -> Result<String, Response> {
        let owner_id = format!("gateway_{}", uuid::Uuid::new_v4().simple());
        let response = self
            .http
            .post(format!("{}/v1/internal/work/acquire", self.cp()))
            .bearer_auth(&self.cfg.auth_token)
            .json(&AcquireWorkRequest {
                cat_id: cat_id.to_string(),
                kind: WorkKind::Gateway,
                owner_id,
                label: "endpoint_request".to_string(),
                ttl_ms: 120_000,
            })
            .send()
            .await
            .map_err(|error| {
                gw_error(
                    StatusCode::BAD_GATEWAY,
                    format!("work acquire failed: {error}"),
                )
            })?;
        if !response.status().is_success() {
            return Err(gw_error(
                StatusCode::BAD_GATEWAY,
                format!("work acquire status {}", response.status()),
            ));
        }
        let acquired: AcquireWorkResponse = response.json().await.map_err(|error| {
            gw_error(
                StatusCode::BAD_GATEWAY,
                format!("bad work acquire body: {error}"),
            )
        })?;
        Ok(acquired.lease.id)
    }

    async fn release_request_work(&self, lease_id: String) {
        let response = self
            .http
            .post(format!("{}/v1/internal/work/release", self.cp()))
            .bearer_auth(&self.cfg.auth_token)
            .json(&ReleaseWorkRequest { lease_id })
            .send()
            .await;
        if let Err(error) = response {
            tracing::warn!(%error, "failed to release gateway work lease; TTL will recover it");
        }
    }

    /// One proxy attempt through the owning node. Ok(None) = stale route.
    async fn try_proxy(
        &self,
        resolved: &ResolveResponse,
        request: &ProxyHttpRequest,
    ) -> Result<Option<Response>, Response> {
        if resolved.node_agent_url.is_empty() {
            return Ok(None);
        }
        let url = format!(
            "{}/v1/cats/{}/proxy",
            resolved.node_agent_url.trim_end_matches('/'),
            resolved.binding.cat_id
        );
        let mut request = request.clone();
        request.target_port = resolved.binding.target_port;
        request.route_epoch = resolved.binding.epoch;
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.cfg.auth_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| gw_error(StatusCode::BAD_GATEWAY, format!("node hop failed: {e}")))?;
        match resp.status() {
            reqwest::StatusCode::OK => {
                let guest: ProxyHttpResponse = resp.json().await.map_err(|e| {
                    gw_error(StatusCode::BAD_GATEWAY, format!("bad node body: {e}"))
                })?;
                let status = StatusCode::from_u16(guest.status).map_err(|e| {
                    gw_error(
                        StatusCode::BAD_GATEWAY,
                        format!("invalid guest status: {e}"),
                    )
                })?;
                let mut response = Response::builder()
                    .status(status)
                    .body(Body::from(guest.body))
                    .expect("response builds");
                for (name, value) in guest.headers {
                    let Ok(name) = HeaderName::try_from(name) else {
                        continue;
                    };
                    let Ok(value) = HeaderValue::try_from(value) else {
                        continue;
                    };
                    response.headers_mut().append(name, value);
                }
                response.headers_mut().insert(
                    "x-cats-route-epoch",
                    HeaderValue::from_str(&resolved.binding.epoch.to_string())
                        .expect("integer is a header value"),
                );
                Ok(Some(response))
            }
            // Stale route: the cat is not active on that node any more.
            reqwest::StatusCode::CONFLICT => Ok(None),
            other => Err(gw_error(
                StatusCode::BAD_GATEWAY,
                format!("node hop status {other}"),
            )),
        }
    }

    async fn handle(&self, hostname: String, request: ProxyHttpRequest) -> Response {
        // Fast path: cached/current route.
        let mut resolved = match self.resolve(&hostname, true).await {
            Ok(r) => r,
            Err(resp) => return resp,
        };

        if (resolved.observed_state != ObservedState::Running || resolved.state != "active")
            && resolved.binding.wake_policy == WakePolicy::NoWake
        {
            return gw_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "endpoint does not wake on request".to_string(),
            );
        }

        // Acquire before wake/proxy. The final release is the event that can
        // immediately drive work_count 1 -> 0 -> Suspended.
        let work_lease = match self.acquire_request_work(&resolved.binding.cat_id).await {
            Ok(lease) => lease,
            Err(response) => return response,
        };

        let response = self
            .handle_with_work(&hostname, &request, &mut resolved)
            .await;
        self.release_request_work(work_lease).await;
        response
    }

    async fn handle_with_work(
        &self,
        hostname: &str,
        request: &ProxyHttpRequest,
        resolved: &mut ResolveResponse,
    ) -> Response {
        // Wake if the cat is not running (policy permitting).
        if resolved.observed_state != ObservedState::Running || resolved.state != "active" {
            if let Err(resp) = self.wake(hostname).await {
                return resp;
            }
            self.invalidate(hostname);
            *resolved = match self.resolve(hostname, false).await {
                Ok(r) => r,
                Err(resp) => return resp,
            };
        }

        // Proxy; on a stale route re-resolve once and retry.
        match self.try_proxy(resolved, request).await {
            Ok(Some(resp)) => resp,
            Err(resp) => resp,
            Ok(None) => {
                self.invalidate(hostname);
                let fresh = match self.resolve(hostname, false).await {
                    Ok(r) => r,
                    Err(resp) => return resp,
                };
                if fresh.observed_state != ObservedState::Running {
                    if fresh.binding.wake_policy == WakePolicy::NoWake {
                        return gw_error(StatusCode::SERVICE_UNAVAILABLE, "endpoint asleep".into());
                    }
                    if let Err(resp) = self.wake(hostname).await {
                        return resp;
                    }
                }
                let retry = match self.resolve(hostname, false).await {
                    Ok(r) => r,
                    Err(resp) => return resp,
                };
                match self.try_proxy(&retry, request).await {
                    Ok(Some(resp)) => resp,
                    Ok(None) => gw_error(
                        StatusCode::CONFLICT,
                        "route kept pointing at a node that does not own the cat".into(),
                    ),
                    Err(resp) => resp,
                }
            }
        }
    }
}

fn gw_error(status: StatusCode, message: String) -> Response {
    (status, message).into_response()
}

async fn entry(State(gw): State<Gateway>, headers: HeaderMap, req: Request<Body>) -> Response {
    let Some(host) = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
    else {
        return gw_error(StatusCode::BAD_REQUEST, "missing Host header".into());
    };
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let method = req.method().as_str().to_string();
    let mut forwarded_headers = Vec::new();
    for (name, value) in &headers {
        if name == "host" || name == "content-length" {
            continue;
        }
        let Ok(value) = value.to_str() else {
            return gw_error(
                StatusCode::BAD_REQUEST,
                format!("header {name} is not valid text"),
            );
        };
        forwarded_headers.push((name.as_str().to_string(), value.to_string()));
    }
    forwarded_headers.push(("x-forwarded-host".to_string(), host.clone()));
    let body = match to_bytes(req.into_body(), MAX_PROXY_REQUEST_BYTES).await {
        Ok(body) => body.to_vec(),
        Err(_) => {
            return gw_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body exceeds {MAX_PROXY_REQUEST_BYTES} bytes"),
            )
        }
    };
    gw.handle(
        host,
        ProxyHttpRequest {
            method,
            path,
            headers: forwarded_headers,
            body,
            // Resolved per attempt so stale-route retry uses the fresh values.
            target_port: 0,
            route_epoch: 0,
        },
    )
    .await
}

const MAX_PROXY_REQUEST_BYTES: usize = 16 * 1024 * 1024;

pub async fn spawn(cfg: GatewayConfig) -> anyhow::Result<Handle> {
    let gw = Gateway {
        cfg: Arc::new(cfg),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?,
        cache: Arc::new(Mutex::new(HashMap::new())),
    };
    let listener = tokio::net::TcpListener::bind(&gw.cfg.listen)
        .await
        .with_context(|| format!("bind {}", gw.cfg.listen))?;
    let addr = listener.local_addr()?;
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .fallback(any(entry))
        .with_state(gw);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("gateway exited: {e}");
        }
    });
    tracing::info!(%addr, "gateway ready");
    Ok(Handle { addr, task })
}

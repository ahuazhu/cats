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
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::routing::get;
use axum::Router;

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

    /// One proxy attempt through the owning node. Ok(None) = stale route.
    async fn try_proxy(
        &self,
        resolved: &ResolveResponse,
        path: &str,
    ) -> Result<Option<Response>, Response> {
        if resolved.node_agent_url.is_empty() {
            return Ok(None);
        }
        let url = format!(
            "{}/v1/cats/{}/proxy",
            resolved.node_agent_url.trim_end_matches('/'),
            resolved.binding.cat_id
        );
        let resp = self
            .http
            .get(url)
            .query(&[("path", path)])
            .bearer_auth(&self.cfg.auth_token)
            .send()
            .await
            .map_err(|e| gw_error(StatusCode::BAD_GATEWAY, format!("node hop failed: {e}")))?;
        match resp.status() {
            reqwest::StatusCode::OK => {
                let raw = resp
                    .bytes()
                    .await
                    .map_err(|e| gw_error(StatusCode::BAD_GATEWAY, e.to_string()))?;
                let (status, body) = parse_guest_http(&raw);
                Ok(Some(
                    Response::builder()
                        .status(status)
                        .header("x-cats-route-epoch", resolved.binding.epoch)
                        .body(Body::from(body))
                        .expect("response builds"),
                ))
            }
            // Stale route: the cat is not active on that node any more.
            reqwest::StatusCode::CONFLICT => Ok(None),
            other => Err(gw_error(
                StatusCode::BAD_GATEWAY,
                format!("node hop status {other}"),
            )),
        }
    }

    async fn handle(&self, hostname: String, path: String) -> Response {
        // Fast path: cached/current route.
        let mut resolved = match self.resolve(&hostname, true).await {
            Ok(r) => r,
            Err(resp) => return resp,
        };

        // Wake if the cat is not running (policy permitting).
        if resolved.observed_state != ObservedState::Running || resolved.state != "active" {
            if resolved.binding.wake_policy == WakePolicy::NoWake {
                return gw_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "endpoint does not wake on request".to_string(),
                );
            }
            if let Err(resp) = self.wake(&hostname).await {
                return resp;
            }
            self.invalidate(&hostname);
            resolved = match self.resolve(&hostname, false).await {
                Ok(r) => r,
                Err(resp) => return resp,
            };
        }

        // Proxy; on a stale route re-resolve once and retry.
        match self.try_proxy(&resolved, &path).await {
            Ok(Some(resp)) => resp,
            Err(resp) => resp,
            Ok(None) => {
                self.invalidate(&hostname);
                let fresh = match self.resolve(&hostname, false).await {
                    Ok(r) => r,
                    Err(resp) => return resp,
                };
                if fresh.observed_state != ObservedState::Running {
                    if fresh.binding.wake_policy == WakePolicy::NoWake {
                        return gw_error(StatusCode::SERVICE_UNAVAILABLE, "endpoint asleep".into());
                    }
                    if let Err(resp) = self.wake(&hostname).await {
                        return resp;
                    }
                }
                let retry = match self.resolve(&hostname, false).await {
                    Ok(r) => r,
                    Err(resp) => return resp,
                };
                match self.try_proxy(&retry, &path).await {
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

/// Parse the guest's raw HTTP/1.1 response into (status, body).
pub fn parse_guest_http(raw: &[u8]) -> (StatusCode, Vec<u8>) {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let Some(pos) = split else {
        return (StatusCode::OK, raw.to_vec());
    };
    let head = String::from_utf8_lossy(&raw[..pos]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);
    (status, raw[pos + 4..].to_vec())
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
    gw.handle(host, path).await
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_http_parsing() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
        let (status, body) = parse_guest_http(raw);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"hello");

        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let (status, body) = parse_guest_http(raw);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());

        // Degenerate payload falls back to 200 + raw bytes.
        let (status, body) = parse_guest_http(b"junk");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"junk");
    }
}

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
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

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

    async fn acquire_request_work(
        &self,
        cat_id: &str,
        owner_id: Option<String>,
    ) -> Result<(String, String), Response> {
        let owner_id =
            owner_id.unwrap_or_else(|| format!("gateway_{}", uuid::Uuid::new_v4().simple()));
        let response = self
            .http
            .post(format!("{}/v1/internal/work/acquire", self.cp()))
            .bearer_auth(&self.cfg.auth_token)
            .json(&AcquireWorkRequest {
                cat_id: cat_id.to_string(),
                kind: WorkKind::Gateway,
                owner_id: owner_id.clone(),
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
        Ok((acquired.lease.id, owner_id))
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
        let work_lease = match self
            .acquire_request_work(&resolved.binding.cat_id, None)
            .await
        {
            Ok((lease, _)) => lease,
            Err(response) => return response,
        };

        let response = self
            .handle_with_work(&hostname, &request, &mut resolved)
            .await;
        self.release_request_work(work_lease).await;
        response
    }

    async fn handle_websocket(
        &self,
        hostname: String,
        path: String,
        headers: HeaderMap,
        ws: WebSocketUpgrade,
    ) -> Response {
        let mut resolved = match self.resolve(&hostname, true).await {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if (resolved.observed_state != ObservedState::Running || resolved.state != "active")
            && resolved.binding.wake_policy == WakePolicy::NoWake
        {
            return gw_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "endpoint does not wake on request".into(),
            );
        }
        let (lease_id, owner_id) = match self
            .acquire_request_work(&resolved.binding.cat_id, None)
            .await
        {
            Ok(lease) => lease,
            Err(response) => return response,
        };
        if resolved.observed_state != ObservedState::Running || resolved.state != "active" {
            if let Err(response) = self.wake(&hostname).await {
                self.release_request_work(lease_id).await;
                return response;
            }
            self.invalidate(&hostname);
            resolved = match self.resolve(&hostname, false).await {
                Ok(resolved) => resolved,
                Err(response) => {
                    self.release_request_work(lease_id).await;
                    return response;
                }
            };
        }
        let mut prepared = self
            .connect_node_websocket(&resolved, &path, &headers, &hostname)
            .await;
        if prepared
            .as_ref()
            .is_err_and(|response| response.status() == StatusCode::CONFLICT)
        {
            self.invalidate(&hostname);
            match self.resolve(&hostname, false).await {
                Ok(fresh) => {
                    resolved = fresh;
                    prepared = self
                        .connect_node_websocket(&resolved, &path, &headers, &hostname)
                        .await;
                }
                Err(response) => prepared = Err(response),
            }
        }
        let (node, response) = match prepared {
            Ok(prepared) => prepared,
            Err(response) => {
                self.release_request_work(lease_id).await;
                return response;
            }
        };
        let selected_protocol = response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let upgrade = if let Some(protocol) = selected_protocol {
            ws.protocols([protocol])
        } else {
            ws
        };
        let gateway = self.clone();
        let cat_id = resolved.binding.cat_id.clone();
        upgrade.on_upgrade(move |client| async move {
            gateway
                .bridge_websocket(client, node, &cat_id, &owner_id)
                .await;
            gateway.release_request_work(lease_id).await;
        })
    }

    async fn connect_node_websocket(
        &self,
        resolved: &ResolveResponse,
        path: &str,
        headers: &HeaderMap,
        hostname: &str,
    ) -> Result<
        (
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            axum::http::Response<Option<Vec<u8>>>,
        ),
        Response,
    > {
        let mut url = reqwest::Url::parse(resolved.node_agent_url.trim_end_matches('/')).map_err(
            |error| {
                gw_error(
                    StatusCode::BAD_GATEWAY,
                    format!("invalid node URL: {error}"),
                )
            },
        )?;
        url.set_scheme(match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => {
                return Err(gw_error(
                    StatusCode::BAD_GATEWAY,
                    "invalid node URL scheme".into(),
                ))
            }
        })
        .map_err(|_| gw_error(StatusCode::BAD_GATEWAY, "invalid node WebSocket URL".into()))?;
        url.set_path(&format!(
            "/v1/cats/{}/proxy-websocket",
            resolved.binding.cat_id
        ));
        url.query_pairs_mut()
            .append_pair("target_port", &resolved.binding.target_port.to_string())
            .append_pair("route_epoch", &resolved.binding.epoch.to_string())
            .append_pair("path", path);
        let forwarded = forwarded_headers(headers, hostname)
            .map_err(|message| gw_error(StatusCode::BAD_REQUEST, message))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&forwarded).expect("header tuples serialize"));
        let mut request = url.as_str().into_client_request().map_err(|error| {
            gw_error(
                StatusCode::BAD_GATEWAY,
                format!("build node WebSocket request: {error}"),
            )
        })?;
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.cfg.auth_token)).map_err(|_| {
                gw_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid service token".into(),
                )
            })?,
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-cats-forwarded-headers"),
            HeaderValue::from_str(&encoded).map_err(|_| {
                gw_error(
                    StatusCode::BAD_REQUEST,
                    "request headers are too large".into(),
                )
            })?,
        );
        if let Some(protocols) = headers.get(header::SEC_WEBSOCKET_PROTOCOL) {
            request
                .headers_mut()
                .insert(header::SEC_WEBSOCKET_PROTOCOL, protocols.clone());
        }
        tokio_tungstenite::connect_async(request)
            .await
            .map_err(|error| match error {
                tokio_tungstenite::tungstenite::Error::Http(response)
                    if response.status() == StatusCode::CONFLICT =>
                {
                    gw_error(StatusCode::CONFLICT, "stale endpoint route".into())
                }
                other => gw_error(
                    StatusCode::BAD_GATEWAY,
                    format!("node WebSocket connection failed: {other}"),
                ),
            })
    }

    async fn bridge_websocket(
        &self,
        client: WebSocket,
        node: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        cat_id: &str,
        owner_id: &str,
    ) {
        let (mut client_sender, mut client_receiver) = client.split();
        let (mut node_sender, mut node_receiver) = node.split();
        let mut renewal = tokio::time::interval(Duration::from_secs(30));
        renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        renewal.tick().await;
        loop {
            tokio::select! {
                incoming = client_receiver.next() => {
                    let Some(Ok(message)) = incoming else { break };
                    let message = match message {
                        Message::Text(data) => tokio_tungstenite::tungstenite::Message::Text(data.to_string().into()),
                        Message::Binary(data) => tokio_tungstenite::tungstenite::Message::Binary(data),
                        Message::Ping(data) => tokio_tungstenite::tungstenite::Message::Ping(data),
                        Message::Pong(data) => tokio_tungstenite::tungstenite::Message::Pong(data),
                        Message::Close(_) => tokio_tungstenite::tungstenite::Message::Close(None),
                    };
                    if node_sender.send(message).await.is_err() {
                        break;
                    }
                }
                outgoing = node_receiver.next() => {
                    let Some(Ok(message)) = outgoing else { break };
                    let message = match message {
                        tokio_tungstenite::tungstenite::Message::Text(data) => Message::Text(data.to_string().into()),
                        tokio_tungstenite::tungstenite::Message::Binary(data) => Message::Binary(data),
                        tokio_tungstenite::tungstenite::Message::Ping(data) => Message::Ping(data),
                        tokio_tungstenite::tungstenite::Message::Pong(data) => Message::Pong(data),
                        tokio_tungstenite::tungstenite::Message::Close(_) => Message::Close(None),
                        tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
                    };
                    if client_sender.send(message).await.is_err() {
                        break;
                    }
                }
                _ = renewal.tick() => {
                    if self
                        .acquire_request_work(cat_id, Some(owner_id.to_string()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = node_sender
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
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

fn forwarded_headers(headers: &HeaderMap, hostname: &str) -> Result<Vec<(String, String)>, String> {
    let mut forwarded = Vec::new();
    for (name, value) in headers {
        if name == header::HOST
            || name == header::CONTENT_LENGTH
            || name.as_str().eq_ignore_ascii_case("x-forwarded-host")
        {
            continue;
        }
        let value = value
            .to_str()
            .map_err(|_| format!("header {name} is not valid text"))?;
        forwarded.push((name.as_str().to_string(), value.to_string()));
    }
    // The public Host resolved this route. Never let a caller-supplied
    // X-Forwarded-Host override it at the Guest boundary.
    forwarded.push(("x-forwarded-host".to_string(), hostname.to_string()));
    Ok(forwarded)
}

async fn entry(State(gw): State<Gateway>, req: Request<Body>) -> Response {
    let (mut parts, body) = req.into_parts();
    let headers = parts.headers.clone();
    let Some(host) = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
    else {
        return gw_error(StatusCode::BAD_REQUEST, "missing Host header".into());
    };
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let method = parts.method.as_str().to_string();
    let is_websocket = headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if is_websocket {
        let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &gw).await {
            Ok(ws) => ws,
            Err(rejection) => return rejection.into_response(),
        };
        return gw.handle_websocket(host, path, headers, ws).await;
    }
    let forwarded_headers = match forwarded_headers(&headers, &host) {
        Ok(headers) => headers,
        Err(message) => return gw_error(StatusCode::BAD_REQUEST, message),
    };
    let body = match to_bytes(body, MAX_PROXY_REQUEST_BYTES).await {
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

#[cfg(test)]
mod tests {
    use super::forwarded_headers;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn public_host_replaces_untrusted_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("preview.cats.run"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("attacker.example"),
        );
        headers.insert("x-request-id", HeaderValue::from_static("request-1"));

        let forwarded = forwarded_headers(&headers, "preview.cats.run").unwrap();
        assert!(!forwarded
            .iter()
            .any(|(_, value)| value == "attacker.example"));
        assert!(forwarded.contains(&(
            "x-forwarded-host".to_string(),
            "preview.cats.run".to_string()
        )));
        assert!(forwarded.contains(&("x-request-id".to_string(), "request-1".to_string())));
    }
}

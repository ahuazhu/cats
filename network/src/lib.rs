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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

use cats_api::requests::{ProxyHttpRequest, ProxyHttpResponse};
use cats_api::resources::{ObservedState, RouteBinding, WakePolicy};

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub auth_token: String,
    /// Route cache TTL; kept tiny so rebinding propagates fast in dev.
    pub cache_ttl_ms: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ResolveResponse {
    binding: RouteBinding,
    state: String,
    observed_state: ObservedState,
    node_agent_url: String,
    route_grant: Option<String>,
    route_grant_expires_at_unix: Option<u64>,
}

#[derive(Clone)]
struct CachedRoute {
    resolved: ResolveResponse,
    fetched: Instant,
}

fn route_is_locally_usable(resolved: &ResolveResponse) -> bool {
    if resolved.state != "active" || resolved.observed_state != ObservedState::Running {
        return resolved.route_grant.is_none() && resolved.route_grant_expires_at_unix.is_none();
    }
    let Some(grant) = resolved.route_grant.as_deref() else {
        return false;
    };
    let Some(expires_at) = resolved.route_grant_expires_at_unix else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    !grant.is_empty() && expires_at > now.as_secs()
}

fn cached_outage_route(cached: Option<&CachedRoute>) -> Option<ResolveResponse> {
    let resolved = &cached?.resolved;
    (resolved.state == "active"
        && resolved.observed_state == ObservedState::Running
        && route_is_locally_usable(resolved))
    .then(|| resolved.clone())
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
        let cached = if use_cache {
            self.cache.lock().unwrap().get(hostname).cloned()
        } else {
            None
        };
        if use_cache {
            if let Some(hit) = &cached {
                if hit.fetched.elapsed() < Duration::from_millis(self.cfg.cache_ttl_ms)
                    && route_is_locally_usable(&hit.resolved)
                {
                    return Ok(hit.resolved.clone());
                }
            }
        }
        let resp = self
            .http
            .get(format!("{}/v1/routes/resolve", self.cp()))
            .query(&[("hostname", hostname)])
            .bearer_auth(&self.cfg.auth_token)
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        let resp = match resp {
            Ok(response) => response,
            Err(error) => {
                if let Some(fallback) = cached_outage_route(cached.as_ref()) {
                    tracing::warn!(
                        hostname,
                        ?fallback.route_grant_expires_at_unix,
                        %error,
                        "control-plane route resolve failed; using bounded cached Route Grant"
                    );
                    return Ok(fallback);
                }
                return Err(gw_error(
                    StatusCode::BAD_GATEWAY,
                    format!("resolve failed: {error}"),
                ));
            }
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(gw_error(
                StatusCode::NOT_FOUND,
                format!("no route for host {hostname}"),
            ));
        }
        if resp.status().is_server_error() {
            if let Some(fallback) = cached_outage_route(cached.as_ref()) {
                tracing::warn!(
                    hostname,
                    status = %resp.status(),
                    ?fallback.route_grant_expires_at_unix,
                    "control-plane route resolve failed; using bounded cached Route Grant"
                );
                return Ok(fallback);
            }
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
        if resolved.state == "active" && resolved.observed_state == ObservedState::Running {
            if !route_is_locally_usable(&resolved) {
                return Err(gw_error(
                    StatusCode::BAD_GATEWAY,
                    "active Running route has no unexpired Route Grant".to_string(),
                ));
            }
        } else if resolved.route_grant.is_some() || resolved.route_grant_expires_at_unix.is_some() {
            return Err(gw_error(
                StatusCode::BAD_GATEWAY,
                "inactive route unexpectedly carried a Route Grant".to_string(),
            ));
        }
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
        request.hostname = resolved.binding.hostname.clone();
        request.route_grant = resolved.route_grant.clone().ok_or_else(|| {
            gw_error(
                StatusCode::BAD_GATEWAY,
                "Running route has no Route Grant".to_string(),
            )
        })?;
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

        self.handle_resolved(&hostname, &request, &mut resolved)
            .await
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
        if resolved.observed_state != ObservedState::Running || resolved.state != "active" {
            if let Err(response) = self.wake(&hostname).await {
                return response;
            }
            self.invalidate(&hostname);
            resolved = match self.resolve(&hostname, false).await {
                Ok(resolved) => resolved,
                Err(response) => return response,
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
            Err(response) => return response,
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
        upgrade.on_upgrade(move |client| async move {
            Self::bridge_websocket(client, node).await;
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
            .append_pair("hostname", hostname)
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
        let route_grant = resolved.route_grant.as_deref().ok_or_else(|| {
            gw_error(
                StatusCode::BAD_GATEWAY,
                "Running route has no Route Grant".to_string(),
            )
        })?;
        request.headers_mut().insert(
            HeaderName::from_static("x-cats-route-grant"),
            HeaderValue::from_str(route_grant).map_err(|_| {
                gw_error(
                    StatusCode::BAD_GATEWAY,
                    "Route Grant is not a valid HTTP header".to_string(),
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
        client: WebSocket,
        node: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) {
        let (mut client_sender, mut client_receiver) = client.split();
        let (mut node_sender, mut node_receiver) = node.split();
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
            }
        }
        let _ = node_sender
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
    }

    async fn handle_resolved(
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
            hostname: String::new(),
            route_grant: String::new(),
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
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use axum::Json;

    #[derive(Clone)]
    enum RouteReply {
        Active,
        Status(StatusCode),
        Malformed,
    }

    async fn route_reply(State(reply): State<Arc<Mutex<RouteReply>>>) -> Response {
        let reply = reply.lock().unwrap().clone();
        match reply {
            RouteReply::Active => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(serde_json::json!({
                    "binding": {
                        "hostname": "dev.cats.run",
                        "workspace_id": "ws_1",
                        "cat_id": "cat_1",
                        "node_id": "node-a",
                        "gateway_url": "http://gateway",
                        "target_port": 8080,
                        "epoch": 7,
                        "wake_policy": "wake_on_request"
                    },
                    "state": "active",
                    "observed_state": "running",
                    "node_agent_url": "http://node-a",
                    "route_grant": "opaque-signed-token",
                    "route_grant_expires_at_unix": now + 60
                }))
                .into_response()
            }
            RouteReply::Status(status) => status.into_response(),
            RouteReply::Malformed => (StatusCode::OK, "not-json").into_response(),
        }
    }

    async fn route_test_gateway(
        reply: Arc<Mutex<RouteReply>>,
    ) -> (Gateway, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v1/routes/resolve", get(route_reply))
            .with_state(reply);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let gateway = Gateway {
            cfg: Arc::new(GatewayConfig {
                listen: "127.0.0.1:0".to_string(),
                control_plane_url: format!("http://{addr}"),
                auth_token: "service-token".to_string(),
                cache_ttl_ms: 0,
            }),
            http: reqwest::Client::new(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        };
        (gateway, task)
    }

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

    #[tokio::test]
    async fn cached_grant_fallback_is_limited_to_transport_or_server_failure() {
        let reply = Arc::new(Mutex::new(RouteReply::Active));
        let (gateway, task) = route_test_gateway(reply.clone()).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();

        *reply.lock().unwrap() = RouteReply::Status(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(gateway.resolve("dev.cats.run", true).await.is_ok());

        *reply.lock().unwrap() = RouteReply::Status(StatusCode::NOT_FOUND);
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::NOT_FOUND
        );

        *reply.lock().unwrap() = RouteReply::Malformed;
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::BAD_GATEWAY
        );

        gateway
            .cache
            .lock()
            .unwrap()
            .get_mut("dev.cats.run")
            .unwrap()
            .resolved
            .route_grant_expires_at_unix = Some(1);
        *reply.lock().unwrap() = RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::BAD_GATEWAY
        );
        task.abort();
    }
}

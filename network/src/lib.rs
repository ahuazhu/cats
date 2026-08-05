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
use std::sync::{Arc, Mutex, OnceLock};
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

#[cfg(not(test))]
const ROUTE_REFRESH_BACKOFF: Duration = Duration::from_secs(1);
#[cfg(test)]
const ROUTE_REFRESH_BACKOFF: Duration = Duration::from_millis(50);
const MAX_ROUTE_CACHE_ENTRIES: usize = 4_096;

#[derive(Debug, Clone)]
enum ResolveFailure {
    Response {
        status: StatusCode,
        message: String,
        retain_cached: bool,
    },
    Superseded,
}

impl ResolveFailure {
    fn response(status: StatusCode, message: impl Into<String>, retain_cached: bool) -> Self {
        Self::Response {
            status,
            message: message.into(),
            retain_cached,
        }
    }

    fn retains_cached_route(&self) -> bool {
        matches!(
            self,
            Self::Response {
                retain_cached: true,
                ..
            }
        )
    }

    fn into_response(self) -> Response {
        match self {
            Self::Response {
                status, message, ..
            } => gw_error(status, message),
            Self::Superseded => gw_error(
                StatusCode::CONFLICT,
                "route refresh was superseded".to_string(),
            ),
        }
    }
}

struct RouteRefresh {
    result: OnceLock<Result<ResolveResponse, ResolveFailure>>,
    ready: tokio::sync::watch::Sender<bool>,
}

impl RouteRefresh {
    fn new() -> Self {
        let (ready, _) = tokio::sync::watch::channel(false);
        Self {
            result: OnceLock::new(),
            ready,
        }
    }

    fn complete(&self, result: Result<ResolveResponse, ResolveFailure>) {
        if self.result.set(result).is_ok() {
            self.ready.send_replace(true);
        }
    }

    async fn wait(&self) -> Result<ResolveResponse, ResolveFailure> {
        if let Some(result) = self.result.get() {
            return result.clone();
        }
        let mut ready = self.ready.subscribe();
        loop {
            if *ready.borrow_and_update() {
                return self
                    .result
                    .get()
                    .expect("ready Route refresh has a result")
                    .clone();
            }
            ready
                .changed()
                .await
                .expect("Route refresh retains its readiness sender");
        }
    }
}

struct RouteCacheEntry {
    cached: Option<CachedRoute>,
    refresh: Option<Arc<RouteRefresh>>,
    retry_after: Instant,
    last_failure: Option<ResolveFailure>,
    generation: u64,
}

impl RouteCacheEntry {
    fn new(now: Instant) -> Self {
        Self {
            cached: None,
            refresh: None,
            retry_after: now,
            last_failure: None,
            generation: 0,
        }
    }
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
    cache: Arc<Mutex<HashMap<String, RouteCacheEntry>>>,
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

    async fn fetch_route(&self, hostname: &str) -> Result<ResolveResponse, ResolveFailure> {
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
                return Err(ResolveFailure::response(
                    StatusCode::BAD_GATEWAY,
                    format!("resolve failed: {error}"),
                    true,
                ));
            }
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ResolveFailure::response(
                StatusCode::NOT_FOUND,
                format!("no route for host {hostname}"),
                false,
            ));
        }
        if resp.status().is_server_error() {
            return Err(ResolveFailure::response(
                StatusCode::BAD_GATEWAY,
                format!("resolve status {}", resp.status()),
                true,
            ));
        }
        if !resp.status().is_success() {
            return Err(ResolveFailure::response(
                StatusCode::BAD_GATEWAY,
                format!("resolve status {}", resp.status()),
                false,
            ));
        }
        let resolved: ResolveResponse = resp.json().await.map_err(|error| {
            ResolveFailure::response(
                StatusCode::BAD_GATEWAY,
                format!("bad resolve body: {error}"),
                false,
            )
        })?;
        if resolved.state == "active" && resolved.observed_state == ObservedState::Running {
            if !route_is_locally_usable(&resolved) {
                return Err(ResolveFailure::response(
                    StatusCode::BAD_GATEWAY,
                    "active Running route has no unexpired Route Grant".to_string(),
                    false,
                ));
            }
        } else if resolved.route_grant.is_some() || resolved.route_grant_expires_at_unix.is_some() {
            return Err(ResolveFailure::response(
                StatusCode::BAD_GATEWAY,
                "inactive route unexpectedly carried a Route Grant".to_string(),
                false,
            ));
        }
        Ok(resolved)
    }

    fn complete_refresh(
        &self,
        hostname: &str,
        generation: u64,
        refresh: &Arc<RouteRefresh>,
        result: Result<ResolveResponse, ResolveFailure>,
    ) {
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();
        let Some(entry) = cache.get_mut(hostname) else {
            refresh.complete(Err(ResolveFailure::Superseded));
            return;
        };
        let is_current = entry.generation == generation
            && entry
                .refresh
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, refresh));
        if !is_current {
            refresh.complete(Err(ResolveFailure::Superseded));
            return;
        }

        match &result {
            Ok(resolved) => {
                entry.cached = Some(CachedRoute {
                    resolved: resolved.clone(),
                    fetched: now,
                });
                entry.last_failure = None;
                entry.retry_after = now;
            }
            Err(error) => {
                if !error.retains_cached_route() {
                    entry.cached = None;
                }
                entry.last_failure = Some(error.clone());
                entry.retry_after = now + ROUTE_REFRESH_BACKOFF;
            }
        }
        entry.refresh = None;
        drop(cache);

        if let Err(error) = &result {
            if error.retains_cached_route() {
                tracing::warn!(
                    hostname,
                    ?error,
                    "control-plane route refresh failed; retaining only the signed cached authority"
                );
            }
        }
        refresh.complete(result);
    }

    async fn run_refresh(
        &self,
        hostname: String,
        generation: u64,
        refresh: Arc<RouteRefresh>,
    ) -> Result<ResolveResponse, ResolveFailure> {
        let result = self.fetch_route(&hostname).await;
        self.complete_refresh(&hostname, generation, &refresh, result);
        refresh.wait().await
    }

    async fn resolve(&self, hostname: &str, use_cache: bool) -> Result<ResolveResponse, Response> {
        enum Action {
            Return(ResolveResponse),
            ReturnAndRefresh(ResolveResponse, Arc<RouteRefresh>, u64),
            Wait(Arc<RouteRefresh>),
            Refresh(Arc<RouteRefresh>, u64),
            Fail(ResolveFailure),
        }

        loop {
            let now = Instant::now();
            let action = {
                let mut cache = self.cache.lock().unwrap();
                if !cache.contains_key(hostname) && cache.len() >= MAX_ROUTE_CACHE_ENTRIES {
                    let evict = cache.iter().find_map(|(hostname, entry)| {
                        entry.refresh.is_none().then(|| hostname.clone())
                    });
                    if let Some(evict) = evict {
                        cache.remove(&evict);
                    } else {
                        return Err(gw_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "route refresh capacity is exhausted".to_string(),
                        ));
                    }
                }
                let entry = cache
                    .entry(hostname.to_string())
                    .or_insert_with(|| RouteCacheEntry::new(now));

                let usable = use_cache
                    .then_some(entry.cached.as_ref())
                    .flatten()
                    .filter(|cached| route_is_locally_usable(&cached.resolved));
                if let Some(cached) = usable {
                    if cached.fetched.elapsed() < Duration::from_millis(self.cfg.cache_ttl_ms) {
                        Action::Return(cached.resolved.clone())
                    } else if let Some(stale) = cached_outage_route(Some(cached)) {
                        if entry.refresh.is_none() && now >= entry.retry_after {
                            let refresh = Arc::new(RouteRefresh::new());
                            entry.refresh = Some(refresh.clone());
                            Action::ReturnAndRefresh(stale, refresh, entry.generation)
                        } else {
                            Action::Return(stale)
                        }
                    } else if let Some(refresh) = &entry.refresh {
                        Action::Wait(refresh.clone())
                    } else if now < entry.retry_after {
                        Action::Fail(entry.last_failure.clone().unwrap_or_else(|| {
                            ResolveFailure::response(
                                StatusCode::BAD_GATEWAY,
                                "route refresh is backing off",
                                false,
                            )
                        }))
                    } else {
                        let refresh = Arc::new(RouteRefresh::new());
                        entry.refresh = Some(refresh.clone());
                        Action::Refresh(refresh, entry.generation)
                    }
                } else if let Some(refresh) = &entry.refresh {
                    Action::Wait(refresh.clone())
                } else if now < entry.retry_after {
                    Action::Fail(entry.last_failure.clone().unwrap_or_else(|| {
                        ResolveFailure::response(
                            StatusCode::BAD_GATEWAY,
                            "route refresh is backing off",
                            false,
                        )
                    }))
                } else {
                    let refresh = Arc::new(RouteRefresh::new());
                    entry.refresh = Some(refresh.clone());
                    Action::Refresh(refresh, entry.generation)
                }
            };

            match action {
                Action::Return(resolved) => return Ok(resolved),
                Action::ReturnAndRefresh(resolved, refresh, generation) => {
                    let gateway = self.clone();
                    let hostname = hostname.to_string();
                    tokio::spawn(async move {
                        let _ = gateway.run_refresh(hostname, generation, refresh).await;
                    });
                    return Ok(resolved);
                }
                Action::Wait(refresh) => match refresh.wait().await {
                    Ok(resolved) => return Ok(resolved),
                    Err(ResolveFailure::Superseded) => continue,
                    Err(error) => return Err(error.into_response()),
                },
                Action::Refresh(refresh, generation) => {
                    match self
                        .run_refresh(hostname.to_string(), generation, refresh)
                        .await
                    {
                        Ok(resolved) => return Ok(resolved),
                        Err(ResolveFailure::Superseded) => continue,
                        Err(error) => return Err(error.into_response()),
                    }
                }
                Action::Fail(error) => return Err(error.into_response()),
            }
        }
    }

    fn invalidate(&self, hostname: &str) {
        let refresh = {
            let mut cache = self.cache.lock().unwrap();
            let entry = cache
                .entry(hostname.to_string())
                .or_insert_with(|| RouteCacheEntry::new(Instant::now()));
            entry.generation = entry.generation.saturating_add(1);
            entry.cached = None;
            entry.retry_after = Instant::now();
            entry.last_failure = None;
            entry.refresh.take()
        };
        if let Some(refresh) = refresh {
            refresh.complete(Err(ResolveFailure::Superseded));
        }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    enum RouteReply {
        Active(&'static str),
        Status(StatusCode),
        Malformed,
        Delayed(Duration, Box<RouteReply>),
    }

    struct RouteServerState {
        reply: Mutex<RouteReply>,
        node_agent_url: Mutex<String>,
        calls: AtomicUsize,
        wake_calls: AtomicUsize,
    }

    impl RouteServerState {
        fn new(reply: RouteReply) -> Self {
            Self {
                reply: Mutex::new(reply),
                node_agent_url: Mutex::new("http://node-a".to_string()),
                calls: AtomicUsize::new(0),
                wake_calls: AtomicUsize::new(0),
            }
        }

        fn set(&self, reply: RouteReply) {
            *self.reply.lock().unwrap() = reply;
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn set_node_agent_url(&self, node_agent_url: String) {
            *self.node_agent_url.lock().unwrap() = node_agent_url;
        }
    }

    async fn route_reply(State(state): State<Arc<RouteServerState>>) -> Response {
        state.calls.fetch_add(1, Ordering::SeqCst);
        let mut reply = state.reply.lock().unwrap().clone();
        while let RouteReply::Delayed(delay, next) = reply {
            tokio::time::sleep(delay).await;
            reply = *next;
        }
        let node_agent_url = state.node_agent_url.lock().unwrap().clone();
        match reply {
            RouteReply::Active(route_grant) => {
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
                    "node_agent_url": node_agent_url,
                    "route_grant": route_grant,
                    "route_grant_expires_at_unix": now + 60
                }))
                .into_response()
            }
            RouteReply::Status(status) => status.into_response(),
            RouteReply::Malformed => (StatusCode::OK, "not-json").into_response(),
            RouteReply::Delayed(_, _) => unreachable!("delays are flattened before response"),
        }
    }

    async fn wake_reply(State(state): State<Arc<RouteServerState>>) -> StatusCode {
        state.wake_calls.fetch_add(1, Ordering::SeqCst);
        StatusCode::NO_CONTENT
    }

    async fn route_test_gateway(
        state: Arc<RouteServerState>,
        cache_ttl_ms: u64,
    ) -> (Gateway, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v1/routes/resolve", get(route_reply))
            .route("/v1/routes/wake", axum::routing::post(wake_reply))
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let gateway = Gateway {
            cfg: Arc::new(GatewayConfig {
                listen: "127.0.0.1:0".to_string(),
                control_plane_url: format!("http://{addr}"),
                auth_token: "service-token".to_string(),
                cache_ttl_ms,
            }),
            http: reqwest::Client::new(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        };
        (gateway, task)
    }

    async fn spawn_mock_node() -> (String, tokio::task::JoinHandle<()>) {
        async fn proxy(Json(request): Json<ProxyHttpRequest>) -> Json<ProxyHttpResponse> {
            assert_eq!(request.route_grant, "grant-1");
            Json(ProxyHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
            })
        }

        async fn websocket(ws: WebSocketUpgrade) -> Response {
            ws.on_upgrade(|mut socket| async move {
                while let Some(Ok(message)) = socket.recv().await {
                    if matches!(message, Message::Close(_)) {
                        break;
                    }
                }
            })
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v1/cats/{id}/proxy", axum::routing::post(proxy))
            .route("/v1/cats/{id}/proxy-websocket", get(websocket));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), task)
    }

    async fn wait_for_calls(state: &RouteServerState, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.calls() < expected {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("control-plane call count reached the expected value");
    }

    async fn wait_for_idle(gateway: &Gateway, hostname: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let refreshing = gateway
                    .cache
                    .lock()
                    .unwrap()
                    .get(hostname)
                    .is_some_and(|entry| entry.refresh.is_some());
                if !refreshing {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("route refresh became idle");
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
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();

        tokio::time::sleep(Duration::from_millis(15)).await;
        state.set(RouteReply::Status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(gateway.resolve("dev.cats.run", true).await.is_ok());
        wait_for_calls(&state, 2).await;
        wait_for_idle(&gateway, "dev.cats.run").await;

        tokio::time::sleep(ROUTE_REFRESH_BACKOFF).await;
        state.set(RouteReply::Status(StatusCode::NOT_FOUND));
        // Stale-while-revalidate may admit this already-authorized request. Once
        // the explicit revocation is observed, the cache fails closed.
        assert!(gateway.resolve("dev.cats.run", true).await.is_ok());
        wait_for_calls(&state, 3).await;
        wait_for_idle(&gateway, "dev.cats.run").await;
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::NOT_FOUND
        );

        tokio::time::sleep(ROUTE_REFRESH_BACKOFF).await;
        state.set(RouteReply::Malformed);
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::BAD_GATEWAY
        );

        tokio::time::sleep(ROUTE_REFRESH_BACKOFF).await;
        state.set(RouteReply::Active("grant-2"));
        gateway.resolve("dev.cats.run", true).await.unwrap();
        gateway
            .cache
            .lock()
            .unwrap()
            .get_mut("dev.cats.run")
            .unwrap()
            .cached
            .as_mut()
            .unwrap()
            .resolved
            .route_grant_expires_at_unix = Some(1);
        state.set(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE));
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

    #[tokio::test]
    async fn stale_route_refresh_is_singleflight_and_never_stalls_requesters() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        state.set(RouteReply::Delayed(
            Duration::from_millis(500),
            Box::new(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE)),
        ));

        let started = Instant::now();
        let requests = (0..64).map(|_| {
            let gateway = gateway.clone();
            async move { gateway.resolve("dev.cats.run", true).await }
        });
        let results = futures_util::future::join_all(requests).await;
        assert!(results.into_iter().all(|result| result.is_ok()));
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "stale authorized requests waited on the two-second control-plane timeout"
        );
        wait_for_calls(&state, 2).await;
        assert_eq!(
            state.calls(),
            2,
            "one priming resolve plus one coalesced refresh is the complete control-plane load"
        );
        task.abort();
    }

    #[tokio::test]
    async fn concurrent_cold_misses_share_one_control_plane_resolve() {
        let state = Arc::new(RouteServerState::new(RouteReply::Delayed(
            Duration::from_millis(100),
            Box::new(RouteReply::Active("grant-1")),
        )));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        let requests = (0..32).map(|_| {
            let gateway = gateway.clone();
            async move { gateway.resolve("dev.cats.run", true).await }
        });
        let results = futures_util::future::join_all(requests).await;
        assert!(results.into_iter().all(|result| result.is_ok()));
        assert_eq!(state.calls(), 1, "cold resolve was not singleflight");
        task.abort();
    }

    #[tokio::test]
    async fn failed_refresh_backs_off_then_recovers_without_extending_expiry() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        state.set(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE));
        gateway.resolve("dev.cats.run", true).await.unwrap();
        wait_for_idle(&gateway, "dev.cats.run").await;

        let before_backoff = state.calls();
        for _ in 0..32 {
            assert!(gateway.resolve("dev.cats.run", true).await.is_ok());
        }
        assert_eq!(
            state.calls(),
            before_backoff,
            "outage backoff still sent one resolve per request"
        );

        tokio::time::sleep(ROUTE_REFRESH_BACKOFF).await;
        state.set(RouteReply::Active("grant-2"));
        gateway.resolve("dev.cats.run", true).await.unwrap();
        wait_for_idle(&gateway, "dev.cats.run").await;
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-2")
        );

        gateway
            .cache
            .lock()
            .unwrap()
            .get_mut("dev.cats.run")
            .unwrap()
            .cached
            .as_mut()
            .unwrap()
            .resolved
            .route_grant_expires_at_unix = Some(1);
        state.set(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::BAD_GATEWAY,
            "an expired signed authority must never use stale-while-revalidate"
        );
        task.abort();
    }

    #[tokio::test]
    async fn invalidation_supersedes_an_inflight_stale_refresh() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        state.set(RouteReply::Delayed(
            Duration::from_millis(150),
            Box::new(RouteReply::Active("obsolete-refresh")),
        ));
        gateway.resolve("dev.cats.run", true).await.unwrap();
        wait_for_calls(&state, 2).await;

        gateway.invalidate("dev.cats.run");
        state.set(RouteReply::Active("fresh-after-conflict"));
        assert_eq!(
            gateway
                .resolve("dev.cats.run", false)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("fresh-after-conflict")
        );
        tokio::time::sleep(Duration::from_millis(175)).await;
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("fresh-after-conflict"),
            "the invalidated background refresh resurrected a stale route"
        );
        task.abort();
    }

    #[tokio::test]
    async fn route_cache_evicts_idle_entries_at_its_untrusted_hostname_bound() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state, 10).await;
        {
            let mut cache = gateway.cache.lock().unwrap();
            for index in 0..MAX_ROUTE_CACHE_ENTRIES {
                cache.insert(
                    format!("unknown-{index}.cats.run"),
                    RouteCacheEntry::new(Instant::now()),
                );
            }
        }

        gateway.resolve("dev.cats.run", true).await.unwrap();
        let cache = gateway.cache.lock().unwrap();
        assert_eq!(cache.len(), MAX_ROUTE_CACHE_ENTRIES);
        assert!(cache.contains_key("dev.cats.run"));
        task.abort();
    }

    #[tokio::test]
    async fn mixed_http_and_websocket_load_stays_fast_and_coalesced_during_outage() {
        let (node_agent_url, node_task) = spawn_mock_node().await;
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        state.set_node_agent_url(node_agent_url);
        let (gateway, control_task) = route_test_gateway(state.clone(), 10).await;
        let gateway_handle = spawn((*gateway.cfg).clone()).await.unwrap();
        let http_url = gateway_handle.base_url();

        let client = reqwest::Client::new();
        let primed = client
            .get(&http_url)
            .header(header::HOST, "dev.cats.run")
            .send()
            .await
            .unwrap();
        assert_eq!(primed.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(15)).await;
        state.set(RouteReply::Delayed(
            Duration::from_secs(1),
            Box::new(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE)),
        ));

        let started = Instant::now();
        let http_requests = (0..32).map(|_| {
            let client = client.clone();
            let http_url = http_url.clone();
            async move {
                client
                    .get(http_url)
                    .header(header::HOST, "dev.cats.run")
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        });
        let websocket_requests = (0..16).map(|_| {
            let mut request = http_url
                .replacen("http://", "ws://", 1)
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_static("dev.cats.run"));
            async move {
                let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
                socket.close(None).await.unwrap();
            }
        });
        let (http_statuses, _) = tokio::join!(
            futures_util::future::join_all(http_requests),
            futures_util::future::join_all(websocket_requests),
        );
        assert!(http_statuses
            .into_iter()
            .all(|status| status == StatusCode::OK));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "mixed data-plane traffic stalled behind the slow control-plane refresh"
        );
        wait_for_calls(&state, 2).await;
        assert_eq!(state.calls(), 2, "mixed traffic multiplied route resolves");
        assert_eq!(
            state.wake_calls.load(Ordering::SeqCst),
            0,
            "Running traffic must not call the wake control operation"
        );

        drop(gateway_handle);
        control_task.abort();
        node_task.abort();
    }
}

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
use aws_sdk_dynamodb::types::AttributeValue;
use axum::body::{to_bytes, Body};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::uri::Authority;
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
use cats_api::route_grant::{
    MAX_ROUTE_GRANT_CLOCK_SKEW_SECONDS, MAX_ROUTE_GRANT_TTL_SECONDS, ROUTE_GRANT_REJECTION_EXPIRED,
    ROUTE_GRANT_REJECTION_HEADER,
};

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub auth_token: String,
    /// Route cache TTL; kept tiny so rebinding propagates fast in dev.
    pub cache_ttl_ms: u64,
    /// Optional regional shared cache for signed Route Grants. Production
    /// supplies a DynamoDB table so any Gateway replica can survive a
    /// control-plane outage after another replica resolved the route.
    pub shared_route_cache_table: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct ResolveResponse {
    binding: RouteBinding,
    state: String,
    observed_state: ObservedState,
    node_agent_url: String,
    route_grant: Option<String>,
    route_grant_issued_at_unix: Option<u64>,
    route_grant_expires_at_unix: Option<u64>,
}

#[derive(Clone)]
enum SharedRouteCache {
    Disabled,
    DynamoDb {
        client: aws_sdk_dynamodb::Client,
        table: String,
    },
    #[cfg(test)]
    Memory(Arc<Mutex<HashMap<String, ResolveResponse>>>),
    #[cfg(test)]
    Hanging,
}

impl SharedRouteCache {
    async fn from_config(cfg: &GatewayConfig) -> anyhow::Result<Self> {
        let Some(table) = cfg.shared_route_cache_table.as_deref() else {
            return Ok(Self::Disabled);
        };
        let table = table.trim();
        anyhow::ensure!(!table.is_empty(), "shared Route cache table is empty");
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_dynamodb::Client::new(&sdk_config);
        // Do not probe DynamoDB here. The shared mirror is an independent
        // continuity path, not a Gateway readiness dependency; every runtime
        // operation is bounded and falls through to a healthy control plane.
        Ok(Self::DynamoDb {
            client,
            table: table.to_string(),
        })
    }

    #[cfg(test)]
    fn memory() -> Self {
        Self::Memory(Arc::new(Mutex::new(HashMap::new())))
    }

    async fn load(&self, hostname: &str) -> anyhow::Result<Option<ResolveResponse>> {
        match self {
            Self::Disabled => Ok(None),
            Self::DynamoDb { client, table } => {
                let output = client
                    .get_item()
                    .table_name(table)
                    .key("hostname", AttributeValue::S(hostname.to_string()))
                    .consistent_read(true)
                    .send()
                    .await
                    .context("load shared signed Route Grant")?;
                let Some(item) = output.item() else {
                    return Ok(None);
                };
                decode_shared_route_record(item).map(Some)
            }
            #[cfg(test)]
            Self::Memory(records) => Ok(records.lock().unwrap().get(hostname).cloned()),
            #[cfg(test)]
            Self::Hanging => std::future::pending().await,
        }
    }

    async fn publish(&self, hostname: &str, resolved: &ResolveResponse) -> anyhow::Result<()> {
        let issued_at = resolved
            .route_grant_issued_at_unix
            .context("shared Route Grant has no issue time")?;
        let expires_at = resolved
            .route_grant_expires_at_unix
            .context("shared Route Grant has no expiry")?;
        match self {
            Self::Disabled => Ok(()),
            Self::DynamoDb { client, table } => {
                let payload = serde_json::to_string(resolved)
                    .context("serialize shared signed Route Grant")?;
                let result = client
                    .put_item()
                    .table_name(table)
                    .item("hostname", AttributeValue::S(hostname.to_string()))
                    .item("payload", AttributeValue::S(payload))
                    .item(
                        "route_epoch",
                        AttributeValue::N(resolved.binding.epoch.to_string()),
                    )
                    .item("issued_at_unix", AttributeValue::N(issued_at.to_string()))
                    .item("expires_at_unix", AttributeValue::N(expires_at.to_string()))
                    .condition_expression(
                        "attribute_not_exists(#hostname) \
                         OR #epoch < :epoch \
                         OR (#epoch = :epoch AND #issued < :issued)",
                    )
                    .expression_attribute_names("#hostname", "hostname")
                    .expression_attribute_names("#epoch", "route_epoch")
                    .expression_attribute_names("#issued", "issued_at_unix")
                    .expression_attribute_values(
                        ":epoch",
                        AttributeValue::N(resolved.binding.epoch.to_string()),
                    )
                    .expression_attribute_values(
                        ":issued",
                        AttributeValue::N(issued_at.to_string()),
                    )
                    .send()
                    .await;
                match result {
                    Ok(_) => Ok(()),
                    Err(error)
                        if error.as_service_error().is_some_and(|service| {
                            service.is_conditional_check_failed_exception()
                        }) =>
                    {
                        // A higher PostgreSQL route epoch, or a later renewal
                        // of the same epoch, already won. The caller may still
                        // use this locally signed response; the shared mirror
                        // must never move route authority backwards.
                        Ok(())
                    }
                    Err(error) => Err(error).context("publish shared signed Route Grant"),
                }
            }
            #[cfg(test)]
            Self::Memory(records) => {
                let mut records = records.lock().unwrap();
                let replace = match records.get(hostname) {
                    None => true,
                    Some(current) => {
                        current.binding.epoch < resolved.binding.epoch
                            || (current.binding.epoch == resolved.binding.epoch
                                && current.route_grant_issued_at_unix.unwrap_or(0) < issued_at)
                    }
                };
                if replace {
                    records.insert(hostname.to_string(), resolved.clone());
                }
                Ok(())
            }
            #[cfg(test)]
            Self::Hanging => std::future::pending().await,
        }
    }
}

fn decode_shared_route_record(
    item: &HashMap<String, AttributeValue>,
) -> anyhow::Result<ResolveResponse> {
    let payload = dynamodb_string(item, "payload")?;
    let resolved: ResolveResponse =
        serde_json::from_str(payload).context("decode shared signed Route Grant")?;
    anyhow::ensure!(
        dynamodb_i64(item, "route_epoch")? == resolved.binding.epoch,
        "shared Route epoch metadata does not match its payload"
    );
    anyhow::ensure!(
        dynamodb_u64(item, "issued_at_unix")?
            == resolved
                .route_grant_issued_at_unix
                .context("shared Route payload has no issue time")?,
        "shared Route issue-time metadata does not match its payload"
    );
    anyhow::ensure!(
        dynamodb_u64(item, "expires_at_unix")?
            == resolved
                .route_grant_expires_at_unix
                .context("shared Route payload has no expiry")?,
        "shared Route expiry metadata does not match its payload"
    );
    Ok(resolved)
}

fn dynamodb_string<'a>(
    item: &'a HashMap<String, AttributeValue>,
    name: &str,
) -> anyhow::Result<&'a str> {
    item.get(name)
        .with_context(|| format!("shared Route record has no {name}"))?
        .as_s()
        .map(String::as_str)
        .map_err(|_| anyhow::anyhow!("shared Route record {name} is not a string"))
}

fn dynamodb_u64(item: &HashMap<String, AttributeValue>, name: &str) -> anyhow::Result<u64> {
    dynamodb_string_number(item, name)?
        .parse()
        .with_context(|| format!("shared Route record {name} is not an unsigned integer"))
}

fn dynamodb_i64(item: &HashMap<String, AttributeValue>, name: &str) -> anyhow::Result<i64> {
    dynamodb_string_number(item, name)?
        .parse()
        .with_context(|| format!("shared Route record {name} is not an integer"))
}

fn dynamodb_string_number<'a>(
    item: &'a HashMap<String, AttributeValue>,
    name: &str,
) -> anyhow::Result<&'a str> {
    item.get(name)
        .with_context(|| format!("shared Route record has no {name}"))?
        .as_n()
        .map(String::as_str)
        .map_err(|_| anyhow::anyhow!("shared Route record {name} is not a number"))
}

#[cfg(test)]
fn unix_now() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
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
#[cfg(not(test))]
const SHARED_ROUTE_CACHE_IO_TIMEOUT: Duration = Duration::from_millis(100);
#[cfg(test)]
const SHARED_ROUTE_CACHE_IO_TIMEOUT: Duration = Duration::from_millis(20);
const MAX_ROUTE_CACHE_ENTRIES: usize = 4_096;
const SHARED_LOOKUP_BARRIER_LIFETIME: Duration =
    Duration::from_secs(MAX_ROUTE_GRANT_TTL_SECONDS + MAX_ROUTE_GRANT_CLOCK_SKEW_SECONDS);

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
    shared_lookup: SharedLookup,
    result: OnceLock<Result<ResolveResponse, ResolveFailure>>,
    ready: tokio::sync::watch::Sender<bool>,
}

impl RouteRefresh {
    fn new(shared_lookup: SharedLookup) -> Self {
        let (ready, _) = tokio::sync::watch::channel(false);
        Self {
            shared_lookup,
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

#[derive(Clone, Copy)]
struct SharedLookupBarrier {
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RouteGrantOrder {
    route_epoch: i64,
    issued_at_unix: u64,
}

impl RouteGrantOrder {
    fn from_resolved(resolved: &ResolveResponse) -> Option<Self> {
        Some(Self {
            route_epoch: resolved.binding.epoch,
            issued_at_unix: resolved.route_grant_issued_at_unix?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedLookup {
    Blocked,
    Any,
    NewerThan(RouteGrantOrder),
}

impl SharedLookup {
    fn accepts(self, resolved: &ResolveResponse) -> bool {
        match self {
            Self::Blocked => false,
            Self::Any => true,
            Self::NewerThan(rejected) => RouteGrantOrder::from_resolved(resolved)
                .is_some_and(|candidate| candidate > rejected),
        }
    }
}

impl SharedLookupBarrier {
    fn after_authoritative_rejection(now: Instant) -> Self {
        Self {
            expires_at: now + SHARED_LOOKUP_BARRIER_LIFETIME,
        }
    }

    fn is_active(self, now: Instant) -> bool {
        now < self.expires_at
    }
}

struct RouteCacheEntry {
    cached: Option<CachedRoute>,
    refresh: Option<Arc<RouteRefresh>>,
    retry_after: Instant,
    last_failure: Option<ResolveFailure>,
    last_failure_lookup: Option<SharedLookup>,
    /// A control-plane negative or non-expiry Node conflict is authoritative
    /// for this replica. Preserve that fact for the longest interval in which
    /// a Grant issued before the rejection could still pass time validation.
    shared_lookup_barrier: Option<SharedLookupBarrier>,
    /// Natural expiry is not a revocation, but the rejected capability must
    /// not be imported again. Only a strictly newer epoch/issue time may pass.
    shared_lookup_floor: Option<RouteGrantOrder>,
    /// Coalesce concurrent Node rejections for the same signed authority. A
    /// late rejection must neither cancel its refresh nor roll back a newer
    /// Route Grant that another request has already installed.
    latest_node_rejection: Option<HandledNodeRejection>,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeRouteRejection {
    StaleRoute,
    ExpiredGrant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HandledNodeRejection {
    order: RouteGrantOrder,
    rejection: NodeRouteRejection,
}

impl HandledNodeRejection {
    fn covers(self, order: RouteGrantOrder, rejection: NodeRouteRejection) -> bool {
        self.order > order
            || (self.order == order
                && (self.rejection == NodeRouteRejection::StaleRoute
                    || rejection == NodeRouteRejection::ExpiredGrant))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeRejectionDisposition {
    Applied,
    AlreadyHandled,
    SupersededByNewerGrant,
}

impl NodeRejectionDisposition {
    fn may_use_cache(self, rejection: NodeRouteRejection) -> bool {
        self == Self::SupersededByNewerGrant || rejection.may_use_newer_shared_grant()
    }
}

impl NodeRouteRejection {
    fn from_headers(headers: &HeaderMap) -> Self {
        if headers
            .get(ROUTE_GRANT_REJECTION_HEADER)
            .and_then(|value| value.to_str().ok())
            == Some(ROUTE_GRANT_REJECTION_EXPIRED)
        {
            Self::ExpiredGrant
        } else {
            Self::StaleRoute
        }
    }

    fn may_use_newer_shared_grant(self) -> bool {
        self == Self::ExpiredGrant
    }
}

enum ProxyAttempt {
    Response(Response),
    Rejected(NodeRouteRejection),
}

impl RouteCacheEntry {
    fn new(now: Instant) -> Self {
        Self {
            cached: None,
            refresh: None,
            retry_after: now,
            last_failure: None,
            last_failure_lookup: None,
            shared_lookup_barrier: None,
            shared_lookup_floor: None,
            latest_node_rejection: None,
            generation: 0,
        }
    }

    fn block_shared_lookup(&mut self, now: Instant) {
        self.shared_lookup_barrier = Some(SharedLookupBarrier::after_authoritative_rejection(now));
        self.shared_lookup_floor = None;
    }

    fn allow_shared_lookup(&mut self) {
        self.shared_lookup_barrier = None;
        self.shared_lookup_floor = None;
    }

    fn allow_only_newer_shared_lookup(&mut self, rejected: &ResolveResponse, now: Instant) {
        if let Some(floor) = RouteGrantOrder::from_resolved(rejected) {
            self.shared_lookup_barrier = None;
            self.shared_lookup_floor = Some(floor);
        } else {
            // Missing signed ordering metadata cannot prove that a peer Grant
            // is newer than the rejected capability, so retain fail-closed
            // behavior even when the Node classified the token as expired.
            self.block_shared_lookup(now);
        }
    }

    #[cfg(test)]
    fn shared_lookup_allowed(&self, now: Instant) -> bool {
        !self
            .shared_lookup_barrier
            .is_some_and(|barrier| barrier.is_active(now))
    }

    fn has_active_shared_lookup_barrier(&self, now: Instant) -> bool {
        self.shared_lookup_barrier
            .is_some_and(|barrier| barrier.is_active(now))
    }

    fn shared_lookup(&self, now: Instant) -> SharedLookup {
        if self.has_active_shared_lookup_barrier(now) {
            SharedLookup::Blocked
        } else if let Some(floor) = self.shared_lookup_floor {
            SharedLookup::NewerThan(floor)
        } else {
            SharedLookup::Any
        }
    }
}

fn route_is_locally_usable(resolved: &ResolveResponse) -> bool {
    if resolved.state != "active" || resolved.observed_state != ObservedState::Running {
        return resolved.route_grant.is_none()
            && resolved.route_grant_issued_at_unix.is_none()
            && resolved.route_grant_expires_at_unix.is_none();
    }
    let Some(grant) = resolved.route_grant.as_deref() else {
        return false;
    };
    let Some(issued_at) = resolved.route_grant_issued_at_unix else {
        return false;
    };
    let Some(expires_at) = resolved.route_grant_expires_at_unix else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    !grant.is_empty()
        && issued_at
            <= now
                .as_secs()
                .saturating_add(MAX_ROUTE_GRANT_CLOCK_SKEW_SECONDS)
        && expires_at > now.as_secs()
        && expires_at > issued_at
        && expires_at - issued_at <= MAX_ROUTE_GRANT_TTL_SECONDS
}

fn cached_outage_route(cached: Option<&CachedRoute>) -> Option<ResolveResponse> {
    let resolved = &cached?.resolved;
    (resolved.state == "active"
        && resolved.observed_state == ObservedState::Running
        && route_is_locally_usable(resolved))
    .then(|| resolved.clone())
}

fn validate_resolved_route(
    hostname: &str,
    resolved: &ResolveResponse,
) -> Result<(), ResolveFailure> {
    let binding_hostname =
        normalize_public_hostname(&resolved.binding.hostname).map_err(|message| {
            ResolveFailure::response(
                StatusCode::BAD_GATEWAY,
                format!("invalid hostname in resolved Route binding: {message}"),
                false,
            )
        })?;
    if binding_hostname != hostname {
        return Err(ResolveFailure::response(
            StatusCode::BAD_GATEWAY,
            format!(
                "resolved Route binding hostname {binding_hostname} does not match requested host {hostname}"
            ),
            false,
        ));
    }
    if resolved.state == "active" && resolved.observed_state == ObservedState::Running {
        if !route_is_locally_usable(resolved) {
            return Err(ResolveFailure::response(
                StatusCode::BAD_GATEWAY,
                "active Running route has no unexpired Route Grant".to_string(),
                false,
            ));
        }
    } else if resolved.route_grant.is_some()
        || resolved.route_grant_issued_at_unix.is_some()
        || resolved.route_grant_expires_at_unix.is_some()
    {
        return Err(ResolveFailure::response(
            StatusCode::BAD_GATEWAY,
            "inactive route unexpectedly carried a Route Grant".to_string(),
            false,
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct Gateway {
    cfg: Arc<GatewayConfig>,
    http: reqwest::Client,
    cache: Arc<Mutex<HashMap<String, RouteCacheEntry>>>,
    shared_cache: SharedRouteCache,
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

    async fn load_shared_route(&self, hostname: &str) -> anyhow::Result<Option<ResolveResponse>> {
        tokio::time::timeout(
            SHARED_ROUTE_CACHE_IO_TIMEOUT,
            self.shared_cache.load(hostname),
        )
        .await
        .context("shared Route cache lookup timed out")?
    }

    async fn publish_shared_route(
        &self,
        hostname: &str,
        resolved: &ResolveResponse,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(
            SHARED_ROUTE_CACHE_IO_TIMEOUT,
            self.shared_cache.publish(hostname, resolved),
        )
        .await
        .context("shared Route cache publication timed out")?
    }

    async fn fetch_route(
        &self,
        hostname: &str,
        shared_lookup: SharedLookup,
    ) -> Result<ResolveResponse, ResolveFailure> {
        if shared_lookup != SharedLookup::Blocked {
            match self.load_shared_route(hostname).await {
                Ok(Some(resolved)) => {
                    let active_running = resolved.state == "active"
                        && resolved.observed_state == ObservedState::Running;
                    match validate_resolved_route(hostname, &resolved) {
                        Ok(()) if active_running && shared_lookup.accepts(&resolved) => {
                            tracing::debug!(
                                hostname,
                                "loaded peer-primed signed Route Grant from shared cache"
                            );
                            return Ok(resolved);
                        }
                        Ok(()) if active_running => {
                            tracing::debug!(
                                hostname,
                                "ignoring a shared signed Route Grant that is not newer than the Node-rejected Grant"
                            );
                        }
                        Ok(()) => {
                            tracing::warn!(
                                hostname,
                                "ignoring a non-Running response in the shared signed-Grant mirror"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(
                                hostname,
                                ?error,
                                "ignoring an unusable response in the shared signed-Grant mirror"
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    // DynamoDB is a second, independent continuity path. A
                    // failure there must not break a healthy control-plane
                    // resolve; losing both paths is a multi-failure event.
                    tracing::warn!(
                        hostname,
                        %error,
                        "shared Route cache lookup failed; resolving through the control plane"
                    );
                }
            }
        }

        let result = self.fetch_control_plane_route(hostname).await;
        match &result {
            Ok(resolved)
                if resolved.state == "active"
                    && resolved.observed_state == ObservedState::Running =>
            {
                if let Err(error) = self.publish_shared_route(hostname, resolved).await {
                    // Serve the locally authorized response: control plane is
                    // healthy, so another replica can independently resolve.
                    // The shared mirror preserves a signed capability; it
                    // never manufactures route authority or revocation on
                    // behalf of PostgreSQL.
                    tracing::warn!(
                        hostname,
                        %error,
                        "failed to replicate signed Route Grant to the shared cache"
                    );
                }
            }
            _ => {}
        }
        result
    }

    async fn fetch_control_plane_route(
        &self,
        hostname: &str,
    ) -> Result<ResolveResponse, ResolveFailure> {
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
        validate_resolved_route(hostname, &resolved)?;
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
                entry.last_failure_lookup = None;
                entry.retry_after = now;
                entry.latest_node_rejection = None;
                if resolved.state == "active" && resolved.observed_state == ObservedState::Running {
                    entry.allow_shared_lookup();
                } else {
                    entry.block_shared_lookup(now);
                }
            }
            Err(error) => {
                if !error.retains_cached_route() {
                    entry.cached = None;
                    entry.block_shared_lookup(now);
                }
                entry.last_failure = Some(error.clone());
                entry.last_failure_lookup = Some(refresh.shared_lookup);
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

    fn start_refresh(
        &self,
        hostname: String,
        generation: u64,
        refresh: Arc<RouteRefresh>,
        shared_lookup: SharedLookup,
    ) {
        // Refresh ownership must not belong to whichever request happened to
        // publish the singleflight state. That request may be cancelled at any
        // await point (client disconnect, timeout, task abort). A Gateway-owned
        // task always completes or supersedes the shared refresh so followers
        // cannot wait forever and abandoned hosts cannot consume the cache.
        let gateway = self.clone();
        tokio::spawn(async move {
            let result = gateway.fetch_route(&hostname, shared_lookup).await;
            gateway.complete_refresh(&hostname, generation, &refresh, result);
        });
    }

    async fn resolve(&self, hostname: &str, use_cache: bool) -> Result<ResolveResponse, Response> {
        enum Action {
            Return(ResolveResponse),
            ReturnAndRefresh(ResolveResponse, Arc<RouteRefresh>, u64),
            Wait(Arc<RouteRefresh>),
            Refresh(
                Arc<RouteRefresh>,
                u64,
                SharedLookup,
                Option<Arc<RouteRefresh>>,
            ),
            Fail(ResolveFailure),
        }

        loop {
            let now = Instant::now();
            let action = {
                let mut cache = self.cache.lock().unwrap();
                if !cache.contains_key(hostname) && cache.len() >= MAX_ROUTE_CACHE_ENTRIES {
                    let evict = cache.iter().find_map(|(hostname, entry)| {
                        (entry.refresh.is_none()
                            && cached_outage_route(entry.cached.as_ref()).is_none()
                            && !entry.has_active_shared_lookup_barrier(now))
                        .then(|| hostname.clone())
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
                            let refresh = Arc::new(RouteRefresh::new(SharedLookup::Blocked));
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
                        let shared_lookup = if use_cache {
                            entry.shared_lookup(now)
                        } else {
                            SharedLookup::Blocked
                        };
                        let refresh = Arc::new(RouteRefresh::new(shared_lookup));
                        entry.refresh = Some(refresh.clone());
                        Action::Refresh(refresh, entry.generation, shared_lookup, None)
                    }
                } else if let Some(refresh) = &entry.refresh {
                    let shared_lookup = if use_cache {
                        entry.shared_lookup(now)
                    } else {
                        SharedLookup::Blocked
                    };
                    if entry.cached.is_some()
                        && refresh.shared_lookup == SharedLookup::Blocked
                        && shared_lookup != SharedLookup::Blocked
                    {
                        let superseded = refresh.clone();
                        entry.generation = entry.generation.saturating_add(1);
                        let refresh = Arc::new(RouteRefresh::new(shared_lookup));
                        entry.refresh = Some(refresh.clone());
                        Action::Refresh(refresh, entry.generation, shared_lookup, Some(superseded))
                    } else {
                        Action::Wait(refresh.clone())
                    }
                } else if now < entry.retry_after {
                    let shared_lookup = if use_cache {
                        entry.shared_lookup(now)
                    } else {
                        SharedLookup::Blocked
                    };
                    if entry.cached.is_some()
                        && entry.last_failure_lookup == Some(SharedLookup::Blocked)
                        && shared_lookup != SharedLookup::Blocked
                    {
                        let refresh = Arc::new(RouteRefresh::new(shared_lookup));
                        entry.refresh = Some(refresh.clone());
                        Action::Refresh(refresh, entry.generation, shared_lookup, None)
                    } else {
                        Action::Fail(entry.last_failure.clone().unwrap_or_else(|| {
                            ResolveFailure::response(
                                StatusCode::BAD_GATEWAY,
                                "route refresh is backing off",
                                false,
                            )
                        }))
                    }
                } else {
                    let shared_lookup = if use_cache {
                        entry.shared_lookup(now)
                    } else {
                        SharedLookup::Blocked
                    };
                    let refresh = Arc::new(RouteRefresh::new(shared_lookup));
                    entry.refresh = Some(refresh.clone());
                    Action::Refresh(refresh, entry.generation, shared_lookup, None)
                }
            };

            match action {
                Action::Return(resolved) => return Ok(resolved),
                Action::ReturnAndRefresh(resolved, refresh, generation) => {
                    self.start_refresh(
                        hostname.to_string(),
                        generation,
                        refresh,
                        SharedLookup::Blocked,
                    );
                    return Ok(resolved);
                }
                Action::Wait(refresh) => match refresh.wait().await {
                    Ok(resolved) => return Ok(resolved),
                    Err(ResolveFailure::Superseded) => continue,
                    Err(error) => return Err(error.into_response()),
                },
                Action::Refresh(refresh, generation, shared_lookup, superseded) => {
                    if let Some(superseded) = superseded {
                        superseded.complete(Err(ResolveFailure::Superseded));
                    }
                    self.start_refresh(
                        hostname.to_string(),
                        generation,
                        refresh.clone(),
                        shared_lookup,
                    );
                    match refresh.wait().await {
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
            let now = Instant::now();
            entry.retry_after = now;
            entry.last_failure = None;
            entry.last_failure_lookup = None;
            entry.block_shared_lookup(now);
            entry.latest_node_rejection = None;
            entry.refresh.take()
        };
        if let Some(refresh) = refresh {
            refresh.complete(Err(ResolveFailure::Superseded));
        }
    }

    fn invalidate_after_node_rejection(
        &self,
        hostname: &str,
        rejected: &ResolveResponse,
        rejection: NodeRouteRejection,
    ) -> NodeRejectionDisposition {
        let (disposition, refresh) = {
            let mut cache = self.cache.lock().unwrap();
            let entry = cache
                .entry(hostname.to_string())
                .or_insert_with(|| RouteCacheEntry::new(Instant::now()));
            let rejected_order = RouteGrantOrder::from_resolved(rejected);
            let cached_is_newer = rejected_order.is_some_and(|rejected_order| {
                entry
                    .cached
                    .as_ref()
                    .and_then(|cached| RouteGrantOrder::from_resolved(&cached.resolved))
                    .is_some_and(|cached_order| cached_order > rejected_order)
            });
            if cached_is_newer {
                return NodeRejectionDisposition::SupersededByNewerGrant;
            }
            if rejected_order.is_some_and(|rejected_order| {
                entry
                    .latest_node_rejection
                    .is_some_and(|handled| handled.covers(rejected_order, rejection))
            }) {
                return NodeRejectionDisposition::AlreadyHandled;
            }

            entry.generation = entry.generation.saturating_add(1);
            entry.cached = None;
            let now = Instant::now();
            entry.retry_after = now;
            entry.last_failure = None;
            entry.last_failure_lookup = None;
            if rejection.may_use_newer_shared_grant() {
                entry.allow_only_newer_shared_lookup(rejected, now);
            } else {
                entry.block_shared_lookup(now);
            }
            entry.latest_node_rejection =
                rejected_order.map(|order| HandledNodeRejection { order, rejection });
            (NodeRejectionDisposition::Applied, entry.refresh.take())
        };
        if let Some(refresh) = refresh {
            refresh.complete(Err(ResolveFailure::Superseded));
        }
        disposition
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

    /// One proxy attempt through the owning node.
    async fn try_proxy(
        &self,
        resolved: &ResolveResponse,
        request: &ProxyHttpRequest,
        hostname: &str,
    ) -> Result<ProxyAttempt, Response> {
        if resolved.node_agent_url.is_empty() {
            return Ok(ProxyAttempt::Rejected(NodeRouteRejection::StaleRoute));
        }
        let url = format!(
            "{}/v1/cats/{}/proxy",
            resolved.node_agent_url.trim_end_matches('/'),
            resolved.binding.cat_id
        );
        let mut request = request.clone();
        request.target_port = resolved.binding.target_port;
        request.route_epoch = resolved.binding.epoch;
        // The public Host selected the cache key and Route binding. Never let a
        // control-plane response substitute another Host at the Node boundary.
        request.hostname = hostname.to_string();
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
                Ok(ProxyAttempt::Response(response))
            }
            // Stale route: the cat is not active on that node any more.
            reqwest::StatusCode::CONFLICT => Ok(ProxyAttempt::Rejected(
                NodeRouteRejection::from_headers(resp.headers()),
            )),
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
        let rejection = prepared.as_ref().err().and_then(|response| {
            (response.status() == StatusCode::CONFLICT)
                .then(|| NodeRouteRejection::from_headers(response.headers()))
        });
        if let Some(rejection) = rejection {
            let disposition = self.invalidate_after_node_rejection(&hostname, &resolved, rejection);
            match self
                .resolve(&hostname, disposition.may_use_cache(rejection))
                .await
            {
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
                    let rejection = NodeRouteRejection::from_headers(response.headers());
                    let mut gateway_response =
                        gw_error(StatusCode::CONFLICT, "stale endpoint route".into());
                    if rejection == NodeRouteRejection::ExpiredGrant {
                        gateway_response.headers_mut().insert(
                            HeaderName::from_static(ROUTE_GRANT_REJECTION_HEADER),
                            HeaderValue::from_static(ROUTE_GRANT_REJECTION_EXPIRED),
                        );
                    }
                    gateway_response
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
        match self.try_proxy(resolved, request, hostname).await {
            Ok(ProxyAttempt::Response(resp)) => resp,
            Err(resp) => resp,
            Ok(ProxyAttempt::Rejected(rejection)) => {
                let disposition =
                    self.invalidate_after_node_rejection(hostname, resolved, rejection);
                let mut retry = match self
                    .resolve(hostname, disposition.may_use_cache(rejection))
                    .await
                {
                    Ok(r) => r,
                    Err(resp) => return resp,
                };
                if retry.observed_state != ObservedState::Running || retry.state != "active" {
                    if retry.binding.wake_policy == WakePolicy::NoWake {
                        return gw_error(StatusCode::SERVICE_UNAVAILABLE, "endpoint asleep".into());
                    }
                    if let Err(resp) = self.wake(hostname).await {
                        return resp;
                    }
                    self.invalidate(hostname);
                    retry = match self.resolve(hostname, false).await {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };
                }
                match self.try_proxy(&retry, request, hostname).await {
                    Ok(ProxyAttempt::Response(resp)) => resp,
                    Ok(ProxyAttempt::Rejected(_)) => gw_error(
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

fn normalize_public_hostname(authority: &str) -> Result<String, String> {
    let authority = authority
        .parse::<Authority>()
        .map_err(|_| "invalid Host authority".to_string())?;
    let hostname = authority.host().trim_end_matches('.');
    if hostname.is_empty() {
        return Err("hostname is empty".to_string());
    }
    Ok(hostname.to_ascii_lowercase())
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
        .and_then(|value| normalize_public_hostname(value).ok())
    else {
        return gw_error(
            StatusCode::BAD_REQUEST,
            "missing or invalid Host header".into(),
        );
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
    let shared_cache = SharedRouteCache::from_config(&cfg).await?;
    let gw = Gateway {
        cfg: Arc::new(cfg),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?,
        cache: Arc::new(Mutex::new(HashMap::new())),
        shared_cache,
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
        ActiveUntil(&'static str, u64),
        Status(StatusCode),
        Malformed,
        Delayed(Duration, Box<RouteReply>),
    }

    struct RouteServerState {
        reply: Mutex<RouteReply>,
        node_agent_url: Mutex<String>,
        binding_hostname: Mutex<String>,
        calls: AtomicUsize,
        wake_calls: AtomicUsize,
    }

    impl RouteServerState {
        fn new(reply: RouteReply) -> Self {
            Self {
                reply: Mutex::new(reply),
                node_agent_url: Mutex::new("http://node-a".to_string()),
                binding_hostname: Mutex::new("dev.cats.run".to_string()),
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

        fn set_binding_hostname(&self, hostname: &str) {
            *self.binding_hostname.lock().unwrap() = hostname.to_string();
        }
    }

    fn active_route_response(
        binding_hostname: String,
        node_agent_url: String,
        route_grant: &str,
        expires_at: u64,
    ) -> Response {
        Json(active_resolved_route(
            binding_hostname,
            node_agent_url,
            route_grant,
            expires_at.saturating_sub(60),
            expires_at,
        ))
        .into_response()
    }

    fn active_resolved_route(
        binding_hostname: String,
        node_agent_url: String,
        route_grant: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> ResolveResponse {
        ResolveResponse {
            binding: RouteBinding {
                hostname: binding_hostname,
                workspace_id: "ws_1".to_string(),
                cat_id: "cat_1".to_string(),
                node_id: "node-a".to_string(),
                gateway_url: "http://gateway".to_string(),
                target_port: 8080,
                epoch: 7,
                wake_policy: WakePolicy::WakeOnRequest,
            },
            state: "active".to_string(),
            observed_state: ObservedState::Running,
            node_agent_url,
            route_grant: Some(route_grant.to_string()),
            route_grant_issued_at_unix: Some(issued_at),
            route_grant_expires_at_unix: Some(expires_at),
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
        let binding_hostname = state.binding_hostname.lock().unwrap().clone();
        match reply {
            RouteReply::Active(route_grant) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                active_route_response(binding_hostname, node_agent_url, route_grant, now + 60)
            }
            RouteReply::ActiveUntil(route_grant, expires_at) => {
                active_route_response(binding_hostname, node_agent_url, route_grant, expires_at)
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
        route_test_gateway_with_shared_cache(state, cache_ttl_ms, SharedRouteCache::Disabled).await
    }

    async fn route_test_gateway_with_shared_cache(
        state: Arc<RouteServerState>,
        cache_ttl_ms: u64,
        shared_cache: SharedRouteCache,
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
                shared_route_cache_table: None,
            }),
            http: reqwest::Client::new(),
            cache: Arc::new(Mutex::new(HashMap::new())),
            shared_cache,
        };
        (gateway, task)
    }

    struct MockNodeState {
        grants: Mutex<Vec<String>>,
    }

    async fn spawn_mock_node() -> (String, Arc<MockNodeState>, tokio::task::JoinHandle<()>) {
        async fn proxy(
            State(state): State<Arc<MockNodeState>>,
            Json(request): Json<ProxyHttpRequest>,
        ) -> Json<ProxyHttpResponse> {
            assert!(matches!(
                request.route_grant.as_str(),
                "grant-1" | "grant-2"
            ));
            assert_eq!(request.hostname, "dev.cats.run");
            state.grants.lock().unwrap().push(request.route_grant);
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
        let state = Arc::new(MockNodeState {
            grants: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route("/v1/cats/{id}/proxy", axum::routing::post(proxy))
            .route("/v1/cats/{id}/proxy-websocket", get(websocket))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), state, task)
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

    #[test]
    fn public_hostname_normalization_is_shared_by_cache_and_node_hops() {
        assert_eq!(
            normalize_public_hostname("DEV.CATS.RUN.:8443").unwrap(),
            "dev.cats.run"
        );
        assert_eq!(
            normalize_public_hostname("dev.cats.run").unwrap(),
            "dev.cats.run"
        );
        assert!(normalize_public_hostname("").is_err());
        assert!(normalize_public_hostname("not a host").is_err());
    }

    #[test]
    fn advertised_grant_lifetime_matches_the_node_verifier_bounds() {
        let now = unix_now().unwrap();
        let route = |issued_at, expires_at| {
            active_resolved_route(
                "dev.cats.run".to_string(),
                "http://node-a".to_string(),
                "grant-1",
                issued_at,
                expires_at,
            )
        };

        assert!(route_is_locally_usable(&route(
            now + MAX_ROUTE_GRANT_CLOCK_SKEW_SECONDS,
            now + 60,
        )));
        assert!(!route_is_locally_usable(&route(
            now + MAX_ROUTE_GRANT_CLOCK_SKEW_SECONDS + 1,
            now + 60,
        )));
        assert!(!route_is_locally_usable(&route(now + 1, now + 1)));
        assert!(!route_is_locally_usable(&route(
            now,
            now + MAX_ROUTE_GRANT_TTL_SECONDS + 1,
        )));
    }

    #[test]
    fn expired_rejection_floor_accepts_only_strictly_newer_shared_authority() {
        let route = |epoch, issued_at| {
            let mut resolved = active_resolved_route(
                "dev.cats.run".to_string(),
                "http://node-a".to_string(),
                "grant",
                issued_at,
                issued_at + 60,
            );
            resolved.binding.epoch = epoch;
            resolved
        };
        let lookup = SharedLookup::NewerThan(RouteGrantOrder {
            route_epoch: 7,
            issued_at_unix: 100,
        });

        assert!(!lookup.accepts(&route(7, 100)));
        assert!(!lookup.accepts(&route(7, 99)));
        assert!(!lookup.accepts(&route(6, 10_000)));
        assert!(lookup.accepts(&route(7, 101)));
        assert!(lookup.accepts(&route(8, 1)));

        let mut missing_signed_order = route(7, 100);
        missing_signed_order.route_grant_issued_at_unix = None;
        let now = Instant::now();
        let mut entry = RouteCacheEntry::new(now);
        entry.allow_only_newer_shared_lookup(&missing_signed_order, now);
        assert_eq!(entry.shared_lookup(now), SharedLookup::Blocked);
    }

    #[test]
    fn stale_rejection_dominates_expiry_for_the_same_grant() {
        let order = RouteGrantOrder {
            route_epoch: 7,
            issued_at_unix: 100,
        };
        let expired = HandledNodeRejection {
            order,
            rejection: NodeRouteRejection::ExpiredGrant,
        };
        let stale = HandledNodeRejection {
            order,
            rejection: NodeRouteRejection::StaleRoute,
        };

        assert!(!expired.covers(order, NodeRouteRejection::StaleRoute));
        assert!(stale.covers(order, NodeRouteRejection::ExpiredGrant));
    }

    #[tokio::test]
    async fn repeated_node_rejection_does_not_supersede_the_existing_refresh() {
        let state = Arc::new(RouteServerState::new(RouteReply::Status(
            StatusCode::SERVICE_UNAVAILABLE,
        )));
        let (gateway, control_task) = route_test_gateway(state, 10).await;
        let rejected = active_resolved_route(
            "dev.cats.run".to_string(),
            "http://node-a".to_string(),
            "grant-1",
            100,
            160,
        );
        gateway.cache.lock().unwrap().insert(
            "dev.cats.run".to_string(),
            RouteCacheEntry {
                cached: Some(CachedRoute {
                    resolved: rejected.clone(),
                    fetched: Instant::now(),
                }),
                refresh: None,
                retry_after: Instant::now(),
                last_failure: None,
                last_failure_lookup: None,
                shared_lookup_barrier: None,
                shared_lookup_floor: None,
                latest_node_rejection: None,
                generation: 0,
            },
        );

        gateway.invalidate_after_node_rejection(
            "dev.cats.run",
            &rejected,
            NodeRouteRejection::ExpiredGrant,
        );
        let refresh = Arc::new(RouteRefresh::new(SharedLookup::NewerThan(
            RouteGrantOrder::from_resolved(&rejected).unwrap(),
        )));
        let generation = {
            let mut cache = gateway.cache.lock().unwrap();
            let entry = cache.get_mut("dev.cats.run").unwrap();
            entry.refresh = Some(refresh.clone());
            entry.generation
        };

        let disposition = gateway.invalidate_after_node_rejection(
            "dev.cats.run",
            &rejected,
            NodeRouteRejection::ExpiredGrant,
        );

        let cache = gateway.cache.lock().unwrap();
        assert_eq!(disposition, NodeRejectionDisposition::AlreadyHandled);
        let entry = cache.get("dev.cats.run").unwrap();
        assert_eq!(entry.generation, generation);
        assert!(entry
            .refresh
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &refresh)));
        assert!(refresh.result.get().is_none());
        control_task.abort();
    }

    #[tokio::test]
    async fn delayed_old_rejection_does_not_invalidate_a_newer_cached_grant() {
        let state = Arc::new(RouteServerState::new(RouteReply::Status(
            StatusCode::SERVICE_UNAVAILABLE,
        )));
        let (gateway, control_task) = route_test_gateway(state, 10).await;
        let rejected = active_resolved_route(
            "dev.cats.run".to_string(),
            "http://node-a".to_string(),
            "grant-1",
            100,
            160,
        );
        let newer = active_resolved_route(
            "dev.cats.run".to_string(),
            "http://node-a".to_string(),
            "grant-2",
            101,
            161,
        );
        gateway.cache.lock().unwrap().insert(
            "dev.cats.run".to_string(),
            RouteCacheEntry {
                cached: Some(CachedRoute {
                    resolved: newer,
                    fetched: Instant::now(),
                }),
                refresh: None,
                retry_after: Instant::now(),
                last_failure: None,
                last_failure_lookup: None,
                shared_lookup_barrier: None,
                shared_lookup_floor: None,
                latest_node_rejection: None,
                generation: 0,
            },
        );

        let disposition = gateway.invalidate_after_node_rejection(
            "dev.cats.run",
            &rejected,
            NodeRouteRejection::StaleRoute,
        );

        let cache = gateway.cache.lock().unwrap();
        assert_eq!(
            disposition,
            NodeRejectionDisposition::SupersededByNewerGrant
        );
        assert!(disposition.may_use_cache(NodeRouteRejection::StaleRoute));
        let entry = cache.get("dev.cats.run").unwrap();
        assert_eq!(entry.generation, 0);
        assert_eq!(
            entry
                .cached
                .as_ref()
                .and_then(|cached| cached.resolved.route_grant.as_deref()),
            Some("grant-2")
        );
        control_task.abort();
    }

    #[tokio::test]
    async fn expired_grant_upgrades_control_plane_only_refresh_and_backoff() {
        let state = Arc::new(RouteServerState::new(RouteReply::Status(
            StatusCode::SERVICE_UNAVAILABLE,
        )));
        let shared_cache = SharedRouteCache::memory();
        let (gateway, control_task) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache.clone()).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired = active_resolved_route(
            "dev.cats.run".to_string(),
            "http://node-a".to_string(),
            "grant-1",
            now.saturating_sub(120),
            now,
        );
        let newer = active_resolved_route(
            "dev.cats.run".to_string(),
            "http://node-a".to_string(),
            "grant-2",
            now,
            now + 60,
        );
        shared_cache.publish("dev.cats.run", &newer).await.unwrap();
        let background_refresh = Arc::new(RouteRefresh::new(SharedLookup::Blocked));
        gateway.cache.lock().unwrap().insert(
            "dev.cats.run".to_string(),
            RouteCacheEntry {
                cached: Some(CachedRoute {
                    resolved: expired.clone(),
                    fetched: Instant::now(),
                }),
                refresh: Some(background_refresh.clone()),
                retry_after: Instant::now(),
                last_failure: None,
                last_failure_lookup: None,
                shared_lookup_barrier: None,
                shared_lookup_floor: None,
                latest_node_rejection: None,
                generation: 0,
            },
        );

        let resolved = tokio::time::timeout(
            Duration::from_millis(200),
            gateway.resolve("dev.cats.run", true),
        )
        .await
        .expect("expired authority must not wait for a control-plane-only background refresh")
        .unwrap();

        assert_eq!(resolved.route_grant.as_deref(), Some("grant-2"));
        assert!(matches!(
            background_refresh.result.get(),
            Some(Err(ResolveFailure::Superseded))
        ));
        assert_eq!(state.calls(), 0);

        {
            let mut cache = gateway.cache.lock().unwrap();
            let entry = cache.get_mut("dev.cats.run").unwrap();
            entry.cached = Some(CachedRoute {
                resolved: expired,
                fetched: Instant::now(),
            });
            entry.refresh = None;
            entry.retry_after = Instant::now() + Duration::from_secs(60);
            entry.last_failure = Some(ResolveFailure::response(
                StatusCode::BAD_GATEWAY,
                "control plane is unavailable".to_string(),
                true,
            ));
            entry.last_failure_lookup = Some(SharedLookup::Blocked);
            entry.allow_shared_lookup();
        }

        let resolved = gateway.resolve("dev.cats.run", true).await.unwrap();
        assert_eq!(resolved.route_grant.as_deref(), Some("grant-2"));
        assert_eq!(state.calls(), 0);
        control_task.abort();
    }

    #[test]
    fn shared_route_record_rejects_malformed_or_inconsistent_metadata() {
        let resolved = active_resolved_route(
            "dev.cats.run".to_string(),
            "http://node-a".to_string(),
            "grant-1",
            100,
            160,
        );
        let valid = HashMap::from([
            (
                "hostname".to_string(),
                AttributeValue::S("dev.cats.run".to_string()),
            ),
            (
                "payload".to_string(),
                AttributeValue::S(serde_json::to_string(&resolved).unwrap()),
            ),
            (
                "route_epoch".to_string(),
                AttributeValue::N("7".to_string()),
            ),
            (
                "issued_at_unix".to_string(),
                AttributeValue::N("100".to_string()),
            ),
            (
                "expires_at_unix".to_string(),
                AttributeValue::N("160".to_string()),
            ),
        ]);

        let decoded = decode_shared_route_record(&valid).unwrap();
        assert_eq!(decoded.binding.epoch, 7);
        assert_eq!(decoded.route_grant.as_deref(), Some("grant-1"));

        for (field, value, expected) in [
            (
                "route_epoch",
                AttributeValue::N("8".to_string()),
                "epoch metadata does not match",
            ),
            (
                "issued_at_unix",
                AttributeValue::N("101".to_string()),
                "issue-time metadata does not match",
            ),
            (
                "expires_at_unix",
                AttributeValue::N("161".to_string()),
                "expiry metadata does not match",
            ),
            (
                "issued_at_unix",
                AttributeValue::N("-1".to_string()),
                "not an unsigned integer",
            ),
            (
                "expires_at_unix",
                AttributeValue::S("160".to_string()),
                "is not a number",
            ),
        ] {
            let mut item = valid.clone();
            item.insert(field.to_string(), value);
            let error = decode_shared_route_record(&item).unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "unexpected {field} error: {error}"
            );
        }

        let mut malformed_payload = valid;
        malformed_payload.insert(
            "payload".to_string(),
            AttributeValue::S("not-json".to_string()),
        );
        assert!(decode_shared_route_record(&malformed_payload)
            .unwrap_err()
            .to_string()
            .contains("decode shared signed Route Grant"));
    }

    #[tokio::test]
    async fn wrong_hostname_binding_fails_before_node_contact_or_route_cache() {
        #[derive(Clone)]
        struct NodeState {
            calls: Arc<AtomicUsize>,
        }

        async fn proxy(State(state): State<NodeState>) -> StatusCode {
            state.calls.fetch_add(1, Ordering::SeqCst);
            StatusCode::OK
        }

        let node_calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_addr = listener.local_addr().unwrap();
        let node_app = Router::new()
            .route("/v1/cats/{id}/proxy", axum::routing::post(proxy))
            .with_state(NodeState {
                calls: node_calls.clone(),
            });
        let node_task = tokio::spawn(async move {
            axum::serve(listener, node_app).await.unwrap();
        });

        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-for-b")));
        state.set_binding_hostname("b.cats.run");
        state.set_node_agent_url(format!("http://{node_addr}"));
        let (gateway, control_task) = route_test_gateway(state, 10).await;
        let response = gateway
            .handle(
                "a.cats.run".to_string(),
                ProxyHttpRequest {
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: Vec::new(),
                    target_port: 0,
                    route_epoch: 0,
                    hostname: String::new(),
                    route_grant: String::new(),
                },
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            node_calls.load(Ordering::SeqCst),
            0,
            "a valid grant for B must not route public Host A to B's Node"
        );
        assert!(
            gateway
                .cache
                .lock()
                .unwrap()
                .get("a.cats.run")
                .is_some_and(|entry| entry.cached.is_none()),
            "the mismatched binding entered A's authorized route cache"
        );
        control_task.abort();
        node_task.abort();
    }

    #[tokio::test]
    async fn mismatched_background_refresh_cannot_replace_the_requested_host() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-for-a")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;

        state.set_binding_hostname("b.cats.run");
        state.set(RouteReply::Active("grant-for-b"));
        assert!(gateway.resolve("dev.cats.run", true).await.is_ok());
        wait_for_calls(&state, 2).await;
        wait_for_idle(&gateway, "dev.cats.run").await;

        let cache = gateway.cache.lock().unwrap();
        assert!(
            cache
                .get("dev.cats.run")
                .is_some_and(|entry| entry.cached.is_none()),
            "background refresh poisoned A with B's binding"
        );
        task.abort();
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
    async fn cold_gateway_replica_uses_peer_primed_route_during_control_plane_outage() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (node_url, node_state, node_task) = spawn_mock_node().await;
        state.set_node_agent_url(node_url);
        let shared_cache = SharedRouteCache::memory();
        let (gateway_a, control_task_a) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache.clone()).await;
        let (gateway_b, control_task_b) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache).await;

        gateway_a.resolve("dev.cats.run", true).await.unwrap();
        state.set(RouteReply::Status(StatusCode::INTERNAL_SERVER_ERROR));

        let response = gateway_b
            .handle(
                "dev.cats.run".to_string(),
                ProxyHttpRequest {
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: Vec::new(),
                    target_port: 0,
                    route_epoch: 0,
                    hostname: String::new(),
                    route_grant: String::new(),
                },
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(node_state.grants.lock().unwrap().as_slice(), ["grant-1"]);

        control_task_a.abort();
        control_task_b.abort();
        node_task.abort();
    }

    #[tokio::test]
    async fn expired_node_rejection_uses_strictly_newer_shared_grant_during_control_outage() {
        const CONCURRENT_REQUESTS: usize = 32;

        struct ExpiringNodeState {
            grants: Mutex<Vec<String>>,
            old_grant_barrier: tokio::sync::Barrier,
        }

        async fn proxy(
            State(state): State<Arc<ExpiringNodeState>>,
            Json(request): Json<ProxyHttpRequest>,
        ) -> Response {
            state
                .grants
                .lock()
                .unwrap()
                .push(request.route_grant.clone());
            if request.route_grant == "grant-1" {
                state.old_grant_barrier.wait().await;
                return (
                    StatusCode::CONFLICT,
                    [(ROUTE_GRANT_REJECTION_HEADER, ROUTE_GRANT_REJECTION_EXPIRED)],
                    "Endpoint Route Grant has expired",
                )
                    .into_response();
            }
            Json(ProxyHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
            })
            .into_response()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_addr = listener.local_addr().unwrap();
        let node_state = Arc::new(ExpiringNodeState {
            grants: Mutex::new(Vec::new()),
            old_grant_barrier: tokio::sync::Barrier::new(CONCURRENT_REQUESTS),
        });
        let node_app = Router::new()
            .route("/v1/cats/{id}/proxy", axum::routing::post(proxy))
            .with_state(node_state.clone());
        let node_task = tokio::spawn(async move {
            axum::serve(listener, node_app).await.unwrap();
        });
        let node_agent_url = format!("http://{node_addr}");

        let state = Arc::new(RouteServerState::new(RouteReply::Status(
            StatusCode::SERVICE_UNAVAILABLE,
        )));
        state.set_node_agent_url(node_agent_url.clone());
        let shared_cache = SharedRouteCache::memory();
        let (gateway, control_task) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache.clone()).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old = active_resolved_route(
            "dev.cats.run".to_string(),
            node_agent_url.clone(),
            "grant-1",
            now.saturating_sub(1),
            now + 59,
        );
        let newer = active_resolved_route(
            "dev.cats.run".to_string(),
            node_agent_url,
            "grant-2",
            now,
            now + 60,
        );
        shared_cache.publish("dev.cats.run", &newer).await.unwrap();
        gateway.cache.lock().unwrap().insert(
            "dev.cats.run".to_string(),
            RouteCacheEntry {
                cached: Some(CachedRoute {
                    resolved: old,
                    fetched: Instant::now(),
                }),
                refresh: None,
                retry_after: Instant::now(),
                last_failure: None,
                last_failure_lookup: None,
                shared_lookup_barrier: None,
                shared_lookup_floor: None,
                latest_node_rejection: None,
                generation: 0,
            },
        );

        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..CONCURRENT_REQUESTS {
            let gateway = gateway.clone();
            requests.spawn(async move {
                gateway
                    .handle(
                        "dev.cats.run".to_string(),
                        ProxyHttpRequest {
                            method: "GET".to_string(),
                            path: "/".to_string(),
                            headers: Vec::new(),
                            body: Vec::new(),
                            target_port: 0,
                            route_epoch: 0,
                            hostname: String::new(),
                            route_grant: String::new(),
                        },
                    )
                    .await
                    .status()
            });
        }
        while let Some(result) = requests.join_next().await {
            assert_eq!(result.unwrap(), StatusCode::OK);
        }

        let grants = node_state.grants.lock().unwrap();
        assert_eq!(grants.len(), CONCURRENT_REQUESTS * 2);
        assert_eq!(
            grants
                .iter()
                .filter(|grant| grant.as_str() == "grant-1")
                .count(),
            CONCURRENT_REQUESTS
        );
        assert_eq!(
            grants
                .iter()
                .filter(|grant| grant.as_str() == "grant-2")
                .count(),
            CONCURRENT_REQUESTS
        );
        assert_eq!(
            state.calls(),
            0,
            "natural expiry should not require the unavailable control plane when a newer peer Grant exists"
        );

        control_task.abort();
        node_task.abort();
    }

    #[tokio::test]
    async fn shared_route_never_extends_the_signed_grant_expiry() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let shared_cache = SharedRouteCache::memory();
        let (gateway_a, control_task_a) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache.clone()).await;
        let (gateway_b, control_task_b) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache.clone()).await;
        gateway_a.resolve("dev.cats.run", true).await.unwrap();

        let SharedRouteCache::Memory(records) = &shared_cache else {
            unreachable!("test uses the in-memory shared cache")
        };
        {
            let mut records = records.lock().unwrap();
            let resolved = records.get_mut("dev.cats.run").unwrap();
            resolved.route_grant_expires_at_unix = Some(1);
        }

        state.set(RouteReply::Status(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(
            gateway_b
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::BAD_GATEWAY
        );

        control_task_a.abort();
        control_task_b.abort();
    }

    #[tokio::test]
    async fn shared_route_order_is_epoch_then_signed_issue_time() {
        let shared_cache = SharedRouteCache::memory();
        let hostname = "dev.cats.run";

        let mut newer_epoch = active_resolved_route(
            hostname.to_string(),
            "http://node-a".to_string(),
            "grant-epoch-8",
            100,
            160,
        );
        newer_epoch.binding.epoch = 8;
        shared_cache.publish(hostname, &newer_epoch).await.unwrap();

        let mut delayed_old_epoch = active_resolved_route(
            hostname.to_string(),
            "http://node-old".to_string(),
            "grant-epoch-7-late",
            10_000,
            10_060,
        );
        delayed_old_epoch.binding.epoch = 7;
        shared_cache
            .publish(hostname, &delayed_old_epoch)
            .await
            .unwrap();

        let loaded = shared_cache.load(hostname).await.unwrap().unwrap();
        assert_eq!(loaded.binding.epoch, 8);
        assert_eq!(loaded.route_grant.as_deref(), Some("grant-epoch-8"));

        let mut renewed_same_epoch = active_resolved_route(
            hostname.to_string(),
            "http://node-a".to_string(),
            "grant-epoch-8-renewed",
            101,
            161,
        );
        renewed_same_epoch.binding.epoch = 8;
        shared_cache
            .publish(hostname, &renewed_same_epoch)
            .await
            .unwrap();

        let mut delayed_same_epoch = active_resolved_route(
            hostname.to_string(),
            "http://node-a".to_string(),
            "grant-epoch-8-delayed",
            100,
            160,
        );
        delayed_same_epoch.binding.epoch = 8;
        shared_cache
            .publish(hostname, &delayed_same_epoch)
            .await
            .unwrap();

        let mut conflicting_same_issue_time = active_resolved_route(
            hostname.to_string(),
            "http://node-a".to_string(),
            "grant-epoch-8-conflict",
            101,
            161,
        );
        conflicting_same_issue_time.binding.epoch = 8;
        shared_cache
            .publish(hostname, &conflicting_same_issue_time)
            .await
            .unwrap();

        let loaded = shared_cache.load(hostname).await.unwrap().unwrap();
        assert_eq!(loaded.binding.epoch, 8);
        assert_eq!(loaded.route_grant.as_deref(), Some("grant-epoch-8-renewed"));
    }

    #[tokio::test]
    async fn stalled_shared_cache_cannot_block_a_healthy_control_plane() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, control_task) =
            route_test_gateway_with_shared_cache(state.clone(), 10, SharedRouteCache::Hanging)
                .await;

        let resolved = tokio::time::timeout(
            Duration::from_millis(250),
            gateway.resolve("dev.cats.run", true),
        )
        .await
        .expect("shared cache I/O has a hard deadline")
        .unwrap();
        assert_eq!(resolved.route_grant.as_deref(), Some("grant-1"));
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);

        control_task.abort();
    }

    #[tokio::test]
    async fn control_plane_negative_does_not_create_shared_route_authority() {
        let state = Arc::new(RouteServerState::new(RouteReply::Status(
            StatusCode::NOT_FOUND,
        )));
        let shared_cache = SharedRouteCache::memory();
        let (gateway, control_task) =
            route_test_gateway_with_shared_cache(state, 10, shared_cache.clone()).await;

        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert!(shared_cache.load("dev.cats.run").await.unwrap().is_none());

        control_task.abort();
    }

    #[tokio::test]
    async fn local_negative_barrier_prevents_shared_grant_reimport() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let shared_cache = SharedRouteCache::memory();
        let (gateway, control_task) =
            route_test_gateway_with_shared_cache(state.clone(), 0, shared_cache.clone()).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        let protected = gateway
            .cache
            .lock()
            .unwrap()
            .get("dev.cats.run")
            .unwrap()
            .cached
            .as_ref()
            .unwrap()
            .clone();

        state.set(RouteReply::Status(StatusCode::NOT_FOUND));
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-1"),
            "the already-authorized request may use stale-while-revalidate"
        );
        wait_for_calls(&state, 2).await;
        wait_for_idle(&gateway, "dev.cats.run").await;

        {
            let mut cache = gateway.cache.lock().unwrap();
            for index in 1..MAX_ROUTE_CACHE_ENTRIES {
                cache.insert(
                    format!("protected-{index}.cats.run"),
                    RouteCacheEntry {
                        cached: Some(protected.clone()),
                        refresh: None,
                        retry_after: Instant::now(),
                        last_failure: None,
                        last_failure_lookup: None,
                        shared_lookup_barrier: None,
                        shared_lookup_floor: None,
                        latest_node_rejection: None,
                        generation: 0,
                    },
                );
            }
        }
        assert_eq!(
            gateway
                .resolve("capacity-probe.example", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a full cache must reject a new hostname instead of evicting a rejection barrier"
        );
        assert!(
            gateway
                .cache
                .lock()
                .unwrap()
                .get("dev.cats.run")
                .unwrap()
                .has_active_shared_lookup_barrier(Instant::now()),
            "capacity pressure evicted the local rejection barrier"
        );
        assert_eq!(
            state.calls(),
            2,
            "capacity rejection must happen before contacting the control plane"
        );

        gateway
            .cache
            .lock()
            .unwrap()
            .get_mut("dev.cats.run")
            .unwrap()
            .retry_after = Instant::now();
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(state.calls(), 3, "the retry must consult the control plane");
        assert_eq!(
            shared_cache
                .load("dev.cats.run")
                .await
                .unwrap()
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-1"),
            "a local negative must not manufacture a global shared tombstone"
        );

        state.set(RouteReply::Active("grant-2"));
        gateway
            .cache
            .lock()
            .unwrap()
            .get_mut("dev.cats.run")
            .unwrap()
            .retry_after = Instant::now();
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-2")
        );
        assert!(
            gateway
                .cache
                .lock()
                .unwrap()
                .get("dev.cats.run")
                .unwrap()
                .shared_lookup_allowed(Instant::now()),
            "a direct active + Running resolve clears the local barrier"
        );

        control_task.abort();
    }

    #[tokio::test]
    async fn expired_negative_barrier_accepts_a_newer_shared_grant() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let shared_cache = SharedRouteCache::memory();
        let (gateway, control_task) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache.clone()).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        gateway.invalidate("dev.cats.run");

        let mut peer_grant = shared_cache.load("dev.cats.run").await.unwrap().unwrap();
        peer_grant.binding.epoch += 1;
        peer_grant.route_grant = Some("grant-2".to_string());
        shared_cache
            .publish("dev.cats.run", &peer_grant)
            .await
            .unwrap();
        gateway
            .cache
            .lock()
            .unwrap()
            .get_mut("dev.cats.run")
            .unwrap()
            .shared_lookup_barrier = Some(SharedLookupBarrier {
            expires_at: Instant::now(),
        });
        state.set(RouteReply::Status(StatusCode::NOT_FOUND));

        let resolved = gateway.resolve("dev.cats.run", true).await.unwrap();
        assert_eq!(resolved.route_grant.as_deref(), Some("grant-2"));
        assert_eq!(
            state.calls(),
            1,
            "an expired safety barrier may use a newer peer-primed Grant without waiting for control-plane recovery"
        );
        assert!(gateway
            .cache
            .lock()
            .unwrap()
            .get("dev.cats.run")
            .unwrap()
            .shared_lookup_allowed(Instant::now()));

        control_task.abort();
    }

    #[tokio::test]
    async fn peer_primed_replica_refreshes_from_control_plane_after_recovery() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let shared_cache = SharedRouteCache::memory();
        let (gateway_a, control_task_a) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache.clone()).await;
        let (gateway_b, control_task_b) =
            route_test_gateway_with_shared_cache(state.clone(), 10, shared_cache).await;
        gateway_a.resolve("dev.cats.run", true).await.unwrap();

        state.set(RouteReply::Status(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(
            gateway_b
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-1")
        );
        tokio::time::sleep(Duration::from_millis(15)).await;

        state.set(RouteReply::Active("grant-2"));
        assert_eq!(
            gateway_b
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-1")
        );
        wait_for_calls(&state, 2).await;
        wait_for_idle(&gateway_b, "dev.cats.run").await;
        assert_eq!(
            gateway_b
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-2")
        );

        control_task_a.abort();
        control_task_b.abort();
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
    async fn cancelled_cold_miss_leader_does_not_strand_followers() {
        let state = Arc::new(RouteServerState::new(RouteReply::Delayed(
            Duration::from_millis(100),
            Box::new(RouteReply::Active("grant-1")),
        )));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        let leader_gateway = gateway.clone();
        let leader =
            tokio::spawn(async move { leader_gateway.resolve("dev.cats.run", true).await });
        wait_for_calls(&state, 1).await;
        leader.abort();

        let follower = tokio::time::timeout(
            Duration::from_secs(1),
            gateway.resolve("dev.cats.run", true),
        )
        .await
        .expect("a cancelled leader must not leave the shared refresh pending")
        .expect("the managed refresh still returns the resolved route");
        assert_eq!(follower.route_grant.as_deref(), Some("grant-1"));
        assert_eq!(
            state.calls(),
            1,
            "the follower must join the managed refresh instead of starting another"
        );
        wait_for_idle(&gateway, "dev.cats.run").await;
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
    async fn unknown_host_flood_cannot_evict_an_unexpired_outage_grant() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        {
            let mut cache = gateway.cache.lock().unwrap();
            for index in 0..(MAX_ROUTE_CACHE_ENTRIES - 1) {
                cache.insert(
                    format!("unresolved-{index}.cats.run"),
                    RouteCacheEntry::new(Instant::now()),
                );
            }
        }

        state.set(RouteReply::Status(StatusCode::NOT_FOUND));
        for index in 0..128 {
            assert_eq!(
                gateway
                    .resolve(&format!("attacker-{index}.example"), true)
                    .await
                    .unwrap_err()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        assert!(
            gateway.cache.lock().unwrap().contains_key("dev.cats.run"),
            "negative cache churn evicted a still-authorized endpoint"
        );

        tokio::time::sleep(Duration::from_millis(15)).await;
        state.set(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(
            gateway
                .resolve("dev.cats.run", true)
                .await
                .unwrap()
                .route_grant
                .as_deref(),
            Some("grant-1"),
            "the real endpoint lost its outage authority before signed expiry"
        );
        wait_for_idle(&gateway, "dev.cats.run").await;
        assert_eq!(gateway.cache.lock().unwrap().len(), MAX_ROUTE_CACHE_ENTRIES);
        task.abort();
    }

    #[tokio::test]
    async fn full_cache_of_unexpired_grants_rejects_an_unknown_host() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        {
            let mut cache = gateway.cache.lock().unwrap();
            let protected = cache
                .get("dev.cats.run")
                .unwrap()
                .cached
                .as_ref()
                .unwrap()
                .clone();
            for index in 1..MAX_ROUTE_CACHE_ENTRIES {
                cache.insert(
                    format!("protected-{index}.cats.run"),
                    RouteCacheEntry {
                        cached: Some(protected.clone()),
                        refresh: None,
                        retry_after: Instant::now(),
                        last_failure: None,
                        last_failure_lookup: None,
                        shared_lookup_barrier: None,
                        shared_lookup_floor: None,
                        latest_node_rejection: None,
                        generation: 0,
                    },
                );
            }
        }

        assert_eq!(
            gateway
                .resolve("unknown.example", true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            state.calls(),
            1,
            "capacity rejection must happen before contacting the control plane"
        );
        assert!(gateway.cache.lock().unwrap().contains_key("dev.cats.run"));
        task.abort();
    }

    #[tokio::test]
    async fn expired_rejection_barrier_releases_cache_capacity() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        let protected = gateway
            .cache
            .lock()
            .unwrap()
            .get("dev.cats.run")
            .unwrap()
            .cached
            .as_ref()
            .unwrap()
            .clone();
        {
            let mut cache = gateway.cache.lock().unwrap();
            cache.clear();
            let now = Instant::now();
            let mut expired = RouteCacheEntry::new(now);
            expired.shared_lookup_barrier = Some(SharedLookupBarrier { expires_at: now });
            cache.insert("expired-barrier.cats.run".to_string(), expired);
            for index in 1..MAX_ROUTE_CACHE_ENTRIES {
                cache.insert(
                    format!("protected-{index}.cats.run"),
                    RouteCacheEntry {
                        cached: Some(protected.clone()),
                        refresh: None,
                        retry_after: now,
                        last_failure: None,
                        last_failure_lookup: None,
                        shared_lookup_barrier: None,
                        shared_lookup_floor: None,
                        latest_node_rejection: None,
                        generation: 0,
                    },
                );
            }
        }

        gateway.resolve("dev.cats.run", true).await.unwrap();
        let cache = gateway.cache.lock().unwrap();
        assert_eq!(cache.len(), MAX_ROUTE_CACHE_ENTRIES);
        assert!(!cache.contains_key("expired-barrier.cats.run"));
        assert!(cache.contains_key("dev.cats.run"));
        assert_eq!(state.calls(), 2);
        task.abort();
    }

    async fn mixed_gateway_batch(
        client: &reqwest::Client,
        http_url: &str,
        http_count: usize,
        websocket_count: usize,
    ) -> (Vec<StatusCode>, Vec<Result<(), StatusCode>>, Duration) {
        let started = Instant::now();
        let http_requests = (0..http_count).map(|_| {
            let client = client.clone();
            let http_url = http_url.to_string();
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
        let websocket_requests = (0..websocket_count).map(|_| {
            let mut request = http_url
                .replacen("http://", "ws://", 1)
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_static("dev.cats.run"));
            async move {
                match tokio_tungstenite::connect_async(request).await {
                    Ok((mut socket, _)) => {
                        socket.close(None).await.unwrap();
                        Ok(())
                    }
                    Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                        Err(response.status())
                    }
                    Err(error) => panic!("unexpected WebSocket failure: {error}"),
                }
            }
        });
        let (http, websocket) = tokio::join!(
            futures_util::future::join_all(http_requests),
            futures_util::future::join_all(websocket_requests),
        );
        (http, websocket, started.elapsed())
    }

    #[tokio::test]
    async fn concurrent_explicit_failures_revoke_stale_authority_after_one_refresh() {
        for (reply, expected_status) in [
            (
                RouteReply::Status(StatusCode::NOT_FOUND),
                StatusCode::NOT_FOUND,
            ),
            (
                RouteReply::Status(StatusCode::UNAUTHORIZED),
                StatusCode::BAD_GATEWAY,
            ),
            (RouteReply::Malformed, StatusCode::BAD_GATEWAY),
        ] {
            let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
            let (gateway, task) = route_test_gateway(state.clone(), 10).await;
            gateway.resolve("dev.cats.run", true).await.unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
            state.set(RouteReply::Delayed(
                Duration::from_millis(100),
                Box::new(reply),
            ));

            let started = Instant::now();
            let requests = (0..64).map(|_| {
                let gateway = gateway.clone();
                async move { gateway.resolve("dev.cats.run", true).await }
            });
            let admitted = futures_util::future::join_all(requests).await;
            assert!(admitted.into_iter().all(|result| result.is_ok()));
            assert!(started.elapsed() < Duration::from_millis(250));
            wait_for_calls(&state, 2).await;
            wait_for_idle(&gateway, "dev.cats.run").await;

            let calls = state.calls();
            let requests = (0..64).map(|_| {
                let gateway = gateway.clone();
                async move { gateway.resolve("dev.cats.run", true).await }
            });
            let rejected = futures_util::future::join_all(requests).await;
            assert!(rejected.into_iter().all(|result| {
                result
                    .expect_err("explicit control-plane response must revoke stale authority")
                    .status()
                    == expected_status
            }));
            assert_eq!(
                state.calls(),
                calls,
                "revoked requests bypassed the per-host failure backoff"
            );
            task.abort();
        }
    }

    #[tokio::test]
    async fn concurrent_transport_failure_retains_only_unexpired_authority() {
        let state = Arc::new(RouteServerState::new(RouteReply::Active("grant-1")));
        let (gateway, control_task) = route_test_gateway(state.clone(), 10).await;
        gateway.resolve("dev.cats.run", true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        control_task.abort();

        let started = Instant::now();
        let requests = (0..64).map(|_| {
            let gateway = gateway.clone();
            async move { gateway.resolve("dev.cats.run", true).await }
        });
        assert!(futures_util::future::join_all(requests)
            .await
            .into_iter()
            .all(|result| result.is_ok()));
        assert!(started.elapsed() < Duration::from_millis(250));
        wait_for_idle(&gateway, "dev.cats.run").await;

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
        let requests = (0..64).map(|_| {
            let gateway = gateway.clone();
            async move { gateway.resolve("dev.cats.run", true).await }
        });
        assert!(futures_util::future::join_all(requests)
            .await
            .into_iter()
            .all(|result| result
                .expect_err("expired authority survived a transport outage")
                .status()
                == StatusCode::BAD_GATEWAY));
        assert_eq!(
            state.calls(),
            1,
            "a dead control plane received phantom calls"
        );
    }

    #[tokio::test]
    async fn mixed_http_and_websocket_load_spans_outage_recovery_and_exact_grant_expiry() {
        let (node_agent_url, node_state, node_task) = spawn_mock_node().await;
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3;
        let deadline = UNIX_EPOCH + Duration::from_secs(expires_at);
        let state = Arc::new(RouteServerState::new(RouteReply::ActiveUntil(
            "grant-1", expires_at,
        )));
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
            Duration::from_millis(300),
            Box::new(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE)),
        ));

        for _ in 0..2 {
            let (http, websocket, elapsed) = mixed_gateway_batch(&client, &http_url, 32, 16).await;
            assert!(http.into_iter().all(|status| status == StatusCode::OK));
            assert!(websocket.into_iter().all(|result| result.is_ok()));
            assert!(
                elapsed < Duration::from_millis(250),
                "slow control-plane refresh stalled authorized data-plane traffic"
            );
        }
        wait_for_calls(&state, 2).await;
        assert_eq!(state.calls(), 2, "one stale refresh was not singleflight");

        tokio::time::sleep(Duration::from_millis(375)).await;
        state.set(RouteReply::ActiveUntil("grant-2", expires_at));
        let (http, websocket, _) = mixed_gateway_batch(&client, &http_url, 32, 16).await;
        assert!(http.into_iter().all(|status| status == StatusCode::OK));
        assert!(websocket.into_iter().all(|result| result.is_ok()));
        wait_for_calls(&state, 3).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        let (http, websocket, _) = mixed_gateway_batch(&client, &http_url, 16, 8).await;
        assert!(http.into_iter().all(|status| status == StatusCode::OK));
        assert!(websocket.into_iter().all(|result| result.is_ok()));
        assert!(
            node_state
                .grants
                .lock()
                .unwrap()
                .iter()
                .any(|grant| grant == "grant-2"),
            "recovered control-plane authority never replaced the outage grant"
        );

        state.set(RouteReply::Delayed(
            Duration::from_millis(150),
            Box::new(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE)),
        ));
        while let Ok(remaining) = deadline.duration_since(SystemTime::now()) {
            if remaining <= Duration::from_millis(300) {
                break;
            }
            let (http, websocket, elapsed) = mixed_gateway_batch(&client, &http_url, 16, 8).await;
            assert!(http.into_iter().all(|status| status == StatusCode::OK));
            assert!(websocket.into_iter().all(|result| result.is_ok()));
            assert!(elapsed < Duration::from_millis(250));
            tokio::time::sleep(Duration::from_millis(40)).await;
        }

        state.set(RouteReply::Status(StatusCode::SERVICE_UNAVAILABLE));
        if let Ok(remaining) = deadline.duration_since(SystemTime::now()) {
            tokio::time::sleep(remaining + Duration::from_millis(175)).await;
        }
        let (http, websocket, elapsed) = mixed_gateway_batch(&client, &http_url, 32, 16).await;
        assert!(
            http.into_iter()
                .all(|status| status == StatusCode::BAD_GATEWAY),
            "HTTP admitted traffic after the advertised grant expiry"
        );
        assert!(websocket.into_iter().all(|result| {
            result.expect_err("WebSocket admitted after grant expiry") == StatusCode::BAD_GATEWAY
        }));
        assert!(elapsed < Duration::from_millis(500));
        assert!(
            state.calls() <= 20,
            "sustained mixed load amplified into {} control-plane calls",
            state.calls()
        );
        assert_eq!(
            state.wake_calls.load(Ordering::SeqCst),
            0,
            "Running traffic must not create wake operations"
        );

        drop(gateway_handle);
        control_task.abort();
        node_task.abort();
    }

    #[tokio::test]
    async fn mixed_http_and_websocket_load_stays_fast_and_coalesced_during_outage() {
        let (node_agent_url, _node_state, node_task) = spawn_mock_node().await;
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

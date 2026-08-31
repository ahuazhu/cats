//! Runtime access orchestration for public Exec and Shell sessions.
//!
//! This lane deliberately stays outside semantic lifecycle action state. It
//! wakes a Cat through the ordinary lifecycle service, then resolves the
//! immutable Cat ID and current Node endpoint again before opening a session.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{
    NodedControlEndpoint, NodedServiceToken, ResourceSlug, SemanticErrorBody, SemanticErrorCode,
    NODED_AUTHORIZATION_HEADER,
};
use cats_api::sessions::{ExecRequest, ExecResponse, MAX_EXEC_RESPONSE_JSON_BYTES};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;

use crate::api::semantic_resources::SemanticResourceFuture;
use crate::semantic_lifecycle;
use crate::store::semantic as db;
use crate::store::Store;

const NODED_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
// Includes noded's bounded exact-peer Guest connect before it accepts the
// internal WebSocket upgrade.
const SHELL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// noded's nominal execution envelope is the requested Guest deadline plus a
// five-second exact-peer handshake, a three-second terminal/kill/reap margin
// and a two-second bounded worker join. An unknown result then retains its
// admission guard for up to ten seconds and has one further second to publish
// the HTTP error, making the wire-observable noded maximum T+21s. Control stays
// nine seconds outside that full envelope so connect and response transit
// cannot manufacture an earlier ambiguous timeout.
const NODE_EXEC_WIRE_RESPONSE_OVERHEAD_SECS: u64 = 21;
const CONTROL_EXEC_CONNECT_RESPONSE_MARGIN_SECS: u64 = 9;
const _: () = assert!(CONTROL_EXEC_CONNECT_RESPONSE_MARGIN_SECS > 0);
const EXEC_TRANSPORT_OVERHEAD: Duration = Duration::from_secs(
    NODE_EXEC_WIRE_RESPONSE_OVERHEAD_SECS + CONTROL_EXEC_CONNECT_RESPONSE_MARGIN_SECS,
);
const MAX_NODED_ERROR_BYTES: usize = 16 * 1024;
pub(crate) const PUBLIC_EXEC_NODE_UNAVAILABLE_MESSAGE: &str =
    "the Exec result may be unknown and must not be retried automatically";
pub(crate) const PUBLIC_SHELL_UNAVAILABLE_MESSAGE: &str = "runtime Shell is unavailable";

pub type NodedShell = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTarget {
    pub cat_id: Id,
    pub endpoint: NodedControlEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCat {
    pub cat_id: String,
    pub state: Option<db::CatState>,
    pub current_action: Option<db::CatAction>,
    pub node_id: Option<String>,
    pub endpoint: Option<String>,
    pub node_status: Option<db::NodeStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStoreError {
    pub message: String,
}

pub trait SessionStore: Send + Sync {
    fn current_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<SessionCat>, SessionStoreError>>;
}

#[derive(Clone)]
pub struct PostgresSessionStore {
    store: Arc<Store>,
}

impl PostgresSessionStore {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl SessionStore for PostgresSessionStore {
    fn current_cat<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: &'a str,
    ) -> SemanticResourceFuture<'a, Result<Option<SessionCat>, SessionStoreError>> {
        let store = Arc::clone(&self.store);
        let workspace_id = workspace_id.to_owned();
        let cat_slug = cat_slug.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let Some(cat) = store.find_current_semantic_cat(&workspace_id, &cat_slug)?
                    else {
                        return Ok(None);
                    };
                    let node = match cat.node_id.as_deref() {
                        Some(node_id) => store.find_semantic_node(node_id)?,
                        None => None,
                    };
                    Ok(Some(SessionCat {
                        cat_id: cat.cat_id,
                        state: cat.state,
                        current_action: cat.current_action,
                        node_id: cat.node_id,
                        endpoint: node.as_ref().map(|node| node.control_endpoint.clone()),
                        node_status: node.map(|node| node.status),
                    }))
                })
                .await
                .map_err(|error| SessionStoreError {
                    message: error.to_string(),
                })
        })
    }
}

pub trait SessionAccessApi: Send + Sync {
    fn prepare<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: ResourceSlug,
    ) -> Pin<Box<dyn Future<Output = Result<SessionTarget, SemanticErrorBody>> + Send + 'a>>;
}

pub trait SessionLifecycleApi: Send + Sync {
    fn run<'a>(
        &'a self,
        cat_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<(), SemanticErrorBody>>;
}

impl<S, N, I> SessionLifecycleApi for semantic_lifecycle::SemanticLifecycleService<S, N, I>
where
    S: semantic_lifecycle::SemanticLifecycleStore,
    N: semantic_lifecycle::NodedClient,
    I: semantic_lifecycle::IngressPort,
{
    fn run<'a>(
        &'a self,
        cat_id: &'a str,
    ) -> SemanticResourceFuture<'a, Result<(), SemanticErrorBody>> {
        Box::pin(async move {
            self.run(semantic_lifecycle::CatSelector::Id(cat_id.to_owned()))
                .await
                .map_err(crate::semantic_resource_service::map_lifecycle_error)
                .map(|_| ())
        })
    }
}

pub struct ProductionSessionAccess<L, S> {
    lifecycle: L,
    store: S,
}

impl<L, S> ProductionSessionAccess<L, S> {
    pub fn new(lifecycle: L, store: S) -> Self {
        Self { lifecycle, store }
    }
}

impl<L, S> SessionAccessApi for ProductionSessionAccess<L, S>
where
    L: SessionLifecycleApi,
    S: SessionStore,
{
    fn prepare<'a>(
        &'a self,
        workspace_id: &'a str,
        cat_slug: ResourceSlug,
    ) -> Pin<Box<dyn Future<Output = Result<SessionTarget, SemanticErrorBody>> + Send + 'a>> {
        Box::pin(async move {
            let before = self
                .store
                .current_cat(workspace_id, cat_slug.as_str())
                .await
                .map_err(store_error)?
                .ok_or_else(cat_not_found)?;
            let expected_cat_id = before.cat_id.clone();

            if before.current_action.is_some() {
                return Err(error(
                    SemanticErrorCode::Busy,
                    "another Cat action is running",
                ));
            }
            if before.state != Some(db::CatState::Running) {
                self.lifecycle.run(&expected_cat_id).await?;
            }

            // Never trust the pre-wake placement. Run may have relocated the
            // Cat, and a concurrently registered Node may have changed its
            // endpoint. This bounded Store read completes before any stream is
            // opened and no PostgreSQL transaction survives it.
            let current = self
                .store
                .current_cat(workspace_id, cat_slug.as_str())
                .await
                .map_err(store_error)?
                .ok_or_else(cat_not_found)?;
            if current.cat_id != expected_cat_id {
                return Err(error(
                    SemanticErrorCode::NodeUnavailable,
                    "the current Cat identity changed while opening the session",
                ));
            }
            target_from_current(current)
        })
    }
}

fn target_from_current(current: SessionCat) -> Result<SessionTarget, SemanticErrorBody> {
    if current.current_action.is_some() {
        return Err(error(
            SemanticErrorCode::Busy,
            "the Cat changed lifecycle state while opening the session",
        ));
    }
    if current.state != Some(db::CatState::Running) {
        return Err(error(
            SemanticErrorCode::InvalidState,
            "the Cat is not Running after wake",
        ));
    }
    if current.node_id.is_none()
        || current.endpoint.is_none()
        || current.node_status != Some(db::NodeStatus::Running)
    {
        return Err(error(
            SemanticErrorCode::NodeUnavailable,
            "the current Cat Node is unavailable",
        ));
    }
    let cat_id = Id::new(current.cat_id)
        .ok_or_else(|| error(SemanticErrorCode::InternalError, "stored Cat ID is invalid"))?;
    let endpoint =
        NodedControlEndpoint::new(current.endpoint.expect("checked above")).ok_or_else(|| {
            error(
                SemanticErrorCode::InternalError,
                "stored Node endpoint is invalid",
            )
        })?;
    Ok(SessionTarget { cat_id, endpoint })
}

#[derive(Clone)]
pub struct SemanticNodedSessionClient {
    http: reqwest::Client,
    token: NodedServiceToken,
    exec_transport_overhead: Duration,
}

impl SemanticNodedSessionClient {
    pub fn new(token: NodedServiceToken) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(NODED_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            token,
            exec_transport_overhead: EXEC_TRANSPORT_OVERHEAD,
        })
    }

    #[cfg(test)]
    fn with_exec_transport_overhead(mut self, overhead: Duration) -> Self {
        self.exec_transport_overhead = overhead;
        self
    }

    /// Dispatches Exec exactly once. A transport timeout or response loss is
    /// reported as ambiguous and is never retried by this client.
    pub async fn exec(
        &self,
        target: &SessionTarget,
        request: &ExecRequest,
    ) -> Result<ExecResponse, SemanticErrorBody> {
        let path = format!("/v1/cats/{}/exec", target.cat_id.as_str());
        let timeout = Duration::from_millis(request.effective_timeout_ms())
            .saturating_add(self.exec_transport_overhead);
        let response = self
            .http
            .post(format!("{}{path}", target.endpoint.as_str()))
            .header(NODED_AUTHORIZATION_HEADER, self.token.authorization_value())
            .header(ACCEPT, "application/json")
            .json(request)
            .timeout(timeout)
            .send()
            .await
            .map_err(ambiguous_exec_transport_error)?;
        let status = response.status();
        let limit = if status.is_success() {
            MAX_EXEC_RESPONSE_JSON_BYTES
        } else {
            MAX_NODED_ERROR_BYTES
        };
        let body = read_bounded(response, limit).await?;
        if !status.is_success() {
            let failure = serde_json::from_slice::<SemanticErrorBody>(&body).unwrap_or_else(|_| {
                error(
                    SemanticErrorCode::NodeUnavailable,
                    format!("noded rejected Exec with HTTP {status}"),
                )
            });
            return Err(normalize_noded_exec_failure(failure));
        }
        let response: ExecResponse = serde_json::from_slice(&body).map_err(|_| {
            ambiguous_exec_protocol_error("noded returned a malformed Exec response")
        })?;
        response.validate().map_err(|error_value| {
            tracing::warn!(error = %error_value, "noded returned an invalid Exec response");
            ambiguous_exec_protocol_error("noded returned an invalid Exec response")
        })?;
        Ok(response)
    }

    pub async fn open_shell(
        &self,
        target: &SessionTarget,
        rows: u16,
        cols: u16,
    ) -> Result<NodedShell, SemanticErrorBody> {
        let scheme = if target.endpoint.as_str().starts_with("https://") {
            "wss://"
        } else {
            "ws://"
        };
        let origin = target
            .endpoint
            .as_str()
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or_else(|| error(SemanticErrorCode::InternalError, "invalid Node endpoint"))?;
        let url = format!(
            "{scheme}{origin}/v1/cats/{}/shell?rows={rows}&cols={cols}",
            target.cat_id.as_str()
        );
        let mut request = url.into_client_request().map_err(|_| {
            error(
                SemanticErrorCode::InternalError,
                "cannot build the noded Shell request",
            )
        })?;
        request.headers_mut().insert(
            NODED_AUTHORIZATION_HEADER,
            HeaderValue::from_str(&self.token.authorization_value()).map_err(|_| {
                error(
                    SemanticErrorCode::InternalError,
                    "cannot encode the noded service credential",
                )
            })?,
        );
        let config = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(cats_api::sessions::MAX_SHELL_MESSAGE_BYTES))
            .max_frame_size(Some(cats_api::sessions::MAX_SHELL_MESSAGE_BYTES));
        let connect = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
        let (socket, _) = tokio::time::timeout(SHELL_HANDSHAKE_TIMEOUT, connect)
            .await
            .map_err(|_| {
                error(
                    SemanticErrorCode::NodeUnavailable,
                    "noded Shell handshake timed out",
                )
            })?
            .map_err(shell_connect_error)?;
        Ok(socket)
    }
}

async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, SemanticErrorBody> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > limit)
    {
        return Err(ambiguous_exec_protocol_error(
            "noded response exceeds the body limit",
        ));
    }
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.starts_with("application/json"))
    {
        return Err(ambiguous_exec_protocol_error("noded response is not JSON"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(ambiguous_exec_transport_error)?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ambiguous_exec_protocol_error(
                "noded response exceeds the body limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn shell_connect_error(error_value: tungstenite::Error) -> SemanticErrorBody {
    match error_value {
        tungstenite::Error::Http(response) => {
            if let Some(body) = response.body() {
                if let Ok(error_body) = serde_json::from_slice::<SemanticErrorBody>(body) {
                    return normalize_noded_shell_failure(error_body);
                }
            }
            error(
                SemanticErrorCode::NodeUnavailable,
                format!("noded rejected Shell with HTTP {}", response.status()),
            )
        }
        other => transport_error(other),
    }
}

fn transport_error(error_value: impl std::fmt::Display) -> SemanticErrorBody {
    tracing::warn!(error = %error_value, "noded session transport failed");
    error(
        SemanticErrorCode::NodeUnavailable,
        "noded session transport failed",
    )
}

fn ambiguous_exec_transport_error(error_value: impl std::fmt::Display) -> SemanticErrorBody {
    tracing::warn!(error = %error_value, "noded Exec dispatch result is ambiguous");
    error(
        SemanticErrorCode::NodeUnavailable,
        "noded Exec dispatch result is unknown and was not retried",
    )
}

fn ambiguous_exec_protocol_error(message: &'static str) -> SemanticErrorBody {
    tracing::warn!(message, "noded Exec response violated the protocol");
    error(
        SemanticErrorCode::NodeUnavailable,
        format!("{message}; result is unknown and was not retried"),
    )
}

fn normalize_noded_exec_failure(failure: SemanticErrorBody) -> SemanticErrorBody {
    normalize_noded_failure(failure, PUBLIC_EXEC_NODE_UNAVAILABLE_MESSAGE)
}

fn normalize_noded_shell_failure(failure: SemanticErrorBody) -> SemanticErrorBody {
    normalize_noded_failure(failure, PUBLIC_SHELL_UNAVAILABLE_MESSAGE)
}

fn normalize_noded_failure(
    failure: SemanticErrorBody,
    unavailable_message: &'static str,
) -> SemanticErrorBody {
    tracing::warn!(
        code = ?failure.code,
        "noded rejected a runtime session"
    );
    match failure.code {
        // These are failures of the private Control-to-noded boundary, not of
        // the authenticated public caller or its current Cat slug. noded
        // unavailable/internal messages may contain Host paths, PIDs or OS
        // errors and therefore never cross the public boundary verbatim.
        SemanticErrorCode::Unauthorized
        | SemanticErrorCode::CatNotFound
        | SemanticErrorCode::NodeResetRequired
        | SemanticErrorCode::ActionCancelled
        | SemanticErrorCode::NodeUnavailable
        | SemanticErrorCode::InternalError => {
            error(SemanticErrorCode::NodeUnavailable, unavailable_message)
        }
        _ => failure,
    }
}

fn store_error(error_value: SessionStoreError) -> SemanticErrorBody {
    error(SemanticErrorCode::InternalError, error_value.message)
}

fn cat_not_found() -> SemanticErrorBody {
    error(SemanticErrorCode::CatNotFound, "Cat was not found")
}

pub(crate) fn error(code: SemanticErrorCode, message: impl Into<String>) -> SemanticErrorBody {
    SemanticErrorBody {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use axum::response::IntoResponse as _;
    use tokio::io::AsyncReadExt;

    use super::*;

    #[derive(Default)]
    struct MockLifecycle {
        runs: Mutex<Vec<String>>,
    }

    impl SessionLifecycleApi for MockLifecycle {
        fn run<'a>(
            &'a self,
            cat_id: &'a str,
        ) -> SemanticResourceFuture<'a, Result<(), SemanticErrorBody>> {
            Box::pin(async move {
                self.runs.lock().expect("runs").push(cat_id.to_owned());
                Ok(())
            })
        }
    }

    struct MockStore {
        results: Mutex<VecDeque<Option<SessionCat>>>,
        reads: AtomicUsize,
    }

    impl MockStore {
        fn new(results: impl IntoIterator<Item = Option<SessionCat>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                reads: AtomicUsize::new(0),
            }
        }
    }

    impl SessionStore for MockStore {
        fn current_cat<'a>(
            &'a self,
            _workspace_id: &'a str,
            _cat_slug: &'a str,
        ) -> SemanticResourceFuture<'a, Result<Option<SessionCat>, SessionStoreError>> {
            Box::pin(async move {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(self.results.lock().expect("results").pop_front().flatten())
            })
        }
    }

    fn cat(
        state: db::CatState,
        action: Option<db::CatAction>,
        node_id: &str,
        endpoint: &str,
    ) -> SessionCat {
        SessionCat {
            cat_id: "cat_01".to_owned(),
            state: Some(state),
            current_action: action,
            node_id: Some(node_id.to_owned()),
            endpoint: Some(endpoint.to_owned()),
            node_status: Some(db::NodeStatus::Running),
        }
    }

    fn slug() -> ResourceSlug {
        ResourceSlug::new("web").expect("slug")
    }

    #[tokio::test]
    async fn wake_re_resolves_immutable_id_and_current_node_endpoint() {
        let lifecycle = MockLifecycle::default();
        let store = MockStore::new([
            Some(cat(
                db::CatState::Cold,
                None,
                "node_old",
                "http://127.0.0.1:3001",
            )),
            Some(cat(
                db::CatState::Running,
                None,
                "node_new",
                "http://127.0.0.1:3002",
            )),
        ]);
        let service = ProductionSessionAccess::new(lifecycle, store);

        let target = service
            .prepare("ws_01", slug())
            .await
            .expect("prepare session");

        assert_eq!(target.cat_id.as_str(), "cat_01");
        assert_eq!(target.endpoint.as_str(), "http://127.0.0.1:3002");
        assert_eq!(
            *service.lifecycle.runs.lock().expect("runs"),
            ["cat_01".to_owned()]
        );
        assert_eq!(service.store.reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unresolved_action_is_busy_and_is_not_replaced_by_run() {
        let lifecycle = MockLifecycle::default();
        let store = MockStore::new([Some(cat(
            db::CatState::Running,
            Some(db::CatAction::Cold),
            "node_01",
            "http://127.0.0.1:3001",
        ))]);
        let service = ProductionSessionAccess::new(lifecycle, store);

        let failure = service
            .prepare("ws_01", slug())
            .await
            .expect_err("active lifecycle action must reject session admission");

        assert_eq!(failure.code, SemanticErrorCode::Busy);
        assert!(service.lifecycle.runs.lock().expect("runs").is_empty());
        assert_eq!(service.store.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn settled_running_cat_is_re_resolved_without_wake() {
        let lifecycle = MockLifecycle::default();
        let running = cat(
            db::CatState::Running,
            None,
            "node_01",
            "http://127.0.0.1:3001",
        );
        let store = MockStore::new([Some(running.clone()), Some(running)]);
        let service = ProductionSessionAccess::new(lifecycle, store);

        service
            .prepare("ws_01", slug())
            .await
            .expect("prepare session");

        assert!(service.lifecycle.runs.lock().expect("runs").is_empty());
        assert_eq!(service.store.reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn slug_replacement_after_wake_cannot_receive_the_session() {
        let lifecycle = MockLifecycle::default();
        let before = cat(
            db::CatState::Cold,
            None,
            "node_old",
            "http://127.0.0.1:3001",
        );
        let mut replacement = cat(
            db::CatState::Running,
            None,
            "node_new",
            "http://127.0.0.1:3002",
        );
        replacement.cat_id = "cat_02".to_owned();
        let store = MockStore::new([Some(before), Some(replacement)]);
        let service = ProductionSessionAccess::new(lifecycle, store);

        let failure = service
            .prepare("ws_01", slug())
            .await
            .expect_err("replacement identity must fail closed");

        assert_eq!(failure.code, SemanticErrorCode::NodeUnavailable);
        assert!(failure.message.contains("identity changed"));
        assert_eq!(
            *service.lifecycle.runs.lock().expect("runs"),
            ["cat_01".to_owned()],
            "wake must address the immutable original Cat ID"
        );
    }

    #[test]
    fn stale_noded_placement_is_not_reported_as_a_missing_public_cat() {
        for code in [
            SemanticErrorCode::CatNotFound,
            SemanticErrorCode::Unauthorized,
            SemanticErrorCode::NodeResetRequired,
            SemanticErrorCode::ActionCancelled,
            SemanticErrorCode::NodeUnavailable,
            SemanticErrorCode::InternalError,
        ] {
            let private_failure = error(code, "vsock /run/cats/vmm-42.pid: Permission denied");
            let exec_failure = normalize_noded_exec_failure(private_failure.clone());
            assert_eq!(exec_failure.code, SemanticErrorCode::NodeUnavailable);
            assert_eq!(exec_failure.message, PUBLIC_EXEC_NODE_UNAVAILABLE_MESSAGE);
            assert!(exec_failure.message.contains("result may be unknown"));
            assert!(exec_failure
                .message
                .contains("must not be retried automatically"));
            assert!(!exec_failure.message.contains("/run/"));
            assert!(!exec_failure.message.contains("pid"));

            let shell_failure = normalize_noded_shell_failure(private_failure);
            assert_eq!(shell_failure.code, SemanticErrorCode::NodeUnavailable);
            assert_eq!(shell_failure.message, PUBLIC_SHELL_UNAVAILABLE_MESSAGE);
            assert!(!shell_failure.message.contains("/run/"));
            assert!(!shell_failure.message.contains("pid"));
        }
        let busy = normalize_noded_exec_failure(error(SemanticErrorCode::Busy, "gate is closing"));
        assert_eq!(busy.code, SemanticErrorCode::Busy);
    }

    #[tokio::test]
    async fn semantic_client_redacts_private_noded_unavailable_and_internal_messages() {
        async fn private_failure(
            axum::extract::Path(cat_id): axum::extract::Path<String>,
        ) -> axum::response::Response {
            let code = if cat_id == "cat_internal" {
                SemanticErrorCode::InternalError
            } else {
                SemanticErrorCode::NodeUnavailable
            };
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(error(
                    code,
                    "connect /run/cats/vmm-4242.pid: Permission denied (os error 13)",
                )),
            )
                .into_response()
        }

        let app = axum::Router::new().route(
            "/v1/cats/{cat_id}/exec",
            axum::routing::post(private_failure),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let client =
            SemanticNodedSessionClient::new(NodedServiceToken::new("x".repeat(32)).expect("token"))
                .expect("client");
        let request = ExecRequest {
            command: vec!["true".to_owned()],
            timeout_ms: Some(1_000),
            env: BTreeMap::new(),
            stdin: Vec::new(),
        };

        for cat_id in ["cat_unavailable", "cat_internal"] {
            let failure = client
                .exec(
                    &SessionTarget {
                        cat_id: Id::new(cat_id).expect("Cat ID"),
                        endpoint: NodedControlEndpoint::new(format!("http://{address}"))
                            .expect("endpoint"),
                    },
                    &request,
                )
                .await
                .expect_err("private noded failure");
            assert_eq!(failure.code, SemanticErrorCode::NodeUnavailable);
            assert_eq!(failure.message, PUBLIC_EXEC_NODE_UNAVAILABLE_MESSAGE);
            assert!(failure.message.contains("result may be unknown"));
            assert!(failure
                .message
                .contains("must not be retried automatically"));
            assert!(!failure.message.contains("/run/"));
            assert!(!failure.message.contains("4242"));
            assert!(!failure.message.contains("os error"));
        }
        server.abort();
    }

    #[test]
    fn malformed_exec_success_is_ambiguous_node_unavailable() {
        let failure = ambiguous_exec_protocol_error("malformed response");
        assert_eq!(failure.code, SemanticErrorCode::NodeUnavailable);
        assert!(failure.message.contains("result is unknown"));
        assert!(failure.message.contains("was not retried"));
    }

    #[test]
    fn control_exec_deadline_is_strictly_outside_node_host_budget() {
        assert_eq!(NODE_EXEC_WIRE_RESPONSE_OVERHEAD_SECS, 21);
        assert_eq!(
            EXEC_TRANSPORT_OVERHEAD,
            Duration::from_secs(
                NODE_EXEC_WIRE_RESPONSE_OVERHEAD_SECS + CONTROL_EXEC_CONNECT_RESPONSE_MARGIN_SECS
            )
        );
        assert!(
            EXEC_TRANSPORT_OVERHEAD > Duration::from_secs(NODE_EXEC_WIRE_RESPONSE_OVERHEAD_SECS),
            "Control must not time out before noded's full wire-observable unknown-result budget"
        );
    }

    #[tokio::test]
    async fn slow_two_hop_exec_allows_near_node_unknown_deadline() {
        const TEST_NODE_WIRE_RESPONSE_OVERHEAD: Duration = Duration::from_millis(210);
        const TEST_CONTROL_RESPONSE_MARGIN: Duration = Duration::from_millis(90);
        const TEST_RESPONSE_DELAY: Duration = Duration::from_millis(205);

        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/v1/cats/{cat_id}/exec",
            axum::routing::post(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    // Model noded returning only near the end of its full
                    // handshake, execution, cleanup and unknown-result guard
                    // retention budget.
                    tokio::time::sleep(TEST_RESPONSE_DELAY).await;
                    axum::Json(ExecResponse {
                        exit_code: 0,
                        stdout: "slow-ok".to_owned(),
                        stderr: String::new(),
                    })
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let client =
            SemanticNodedSessionClient::new(NodedServiceToken::new("x".repeat(32)).expect("token"))
                .expect("client")
                .with_exec_transport_overhead(
                    TEST_NODE_WIRE_RESPONSE_OVERHEAD + TEST_CONTROL_RESPONSE_MARGIN,
                );
        let target = SessionTarget {
            cat_id: Id::new("cat_01").expect("cat ID"),
            endpoint: NodedControlEndpoint::new(format!("http://{address}")).expect("endpoint"),
        };
        let request = ExecRequest {
            command: vec!["true".to_owned()],
            timeout_ms: Some(10),
            env: BTreeMap::new(),
            stdin: Vec::new(),
        };

        let response = client
            .exec(&target, &request)
            .await
            .expect("Control response margin must receive the delayed terminal response");
        server.abort();

        assert_eq!(response.stdout, "slow-ok");
        assert!(TEST_RESPONSE_DELAY < TEST_NODE_WIRE_RESPONSE_OVERHEAD);
        assert!(
            TEST_RESPONSE_DELAY
                < TEST_NODE_WIRE_RESPONSE_OVERHEAD
                    + TEST_CONTROL_RESPONSE_MARGIN
                    + Duration::from_millis(request.effective_timeout_ms())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exec_uses_only_service_auth_and_the_immutable_noded_path() {
        #[derive(Clone)]
        struct Seen(Arc<Mutex<Vec<(String, String, ExecRequest)>>>);

        async fn exec_handler(
            axum::extract::State(seen): axum::extract::State<Seen>,
            axum::extract::Path(cat_id): axum::extract::Path<String>,
            headers: axum::http::HeaderMap,
            axum::Json(request): axum::Json<ExecRequest>,
        ) -> axum::Json<ExecResponse> {
            let authorization = headers
                .get(NODED_AUTHORIZATION_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            seen.0
                .lock()
                .expect("seen")
                .push((cat_id, authorization, request));
            axum::Json(ExecResponse {
                exit_code: 0,
                stdout: "ok".to_owned(),
                stderr: String::new(),
            })
        }

        let seen = Seen(Arc::new(Mutex::new(Vec::new())));
        let app = axum::Router::new()
            .route("/v1/cats/{cat_id}/exec", axum::routing::post(exec_handler))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let token = NodedServiceToken::new("x".repeat(32)).expect("token");
        let authorization = token.authorization_value();
        let client = SemanticNodedSessionClient::new(token).expect("client");
        let target = SessionTarget {
            cat_id: Id::new("cat_01").expect("cat ID"),
            endpoint: NodedControlEndpoint::new(format!("http://{address}")).expect("endpoint"),
        };
        let request = ExecRequest {
            command: vec!["printf".to_owned(), "ok".to_owned()],
            timeout_ms: Some(1_000),
            env: BTreeMap::new(),
            stdin: Vec::new(),
        };

        let response = client.exec(&target, &request).await.expect("Exec response");
        server.abort();

        assert_eq!(response.stdout, "ok");
        assert_eq!(
            *seen.0.lock().expect("seen"),
            [("cat_01".to_owned(), authorization, request)]
        );
    }

    #[tokio::test]
    async fn malformed_noded_success_is_node_unavailable_without_redispatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/v1/cats/{cat_id}/exec",
            axum::routing::post(move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        "{}",
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let client =
            SemanticNodedSessionClient::new(NodedServiceToken::new("x".repeat(32)).expect("token"))
                .expect("client");
        let target = SessionTarget {
            cat_id: Id::new("cat_01").expect("cat ID"),
            endpoint: NodedControlEndpoint::new(format!("http://{address}")).expect("endpoint"),
        };
        let request = ExecRequest {
            command: vec!["true".to_owned()],
            timeout_ms: Some(1_000),
            env: BTreeMap::new(),
            stdin: Vec::new(),
        };

        let failure = client
            .exec(&target, &request)
            .await
            .expect_err("malformed success");
        server.abort();

        assert_eq!(failure.code, SemanticErrorCode::NodeUnavailable);
        assert!(failure.message.contains("result is unknown"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exec_response_json_cap_accepts_exact_and_rejects_content_length_and_chunked_plus_one()
    {
        use std::convert::Infallible;

        async fn response_handler(
            axum::extract::Path(cat_id): axum::extract::Path<String>,
        ) -> axum::response::Response {
            let length = if cat_id == "cat_exact" {
                MAX_EXEC_RESPONSE_JSON_BYTES
            } else {
                MAX_EXEC_RESPONSE_JSON_BYTES + 1
            };
            let response = if cat_id == "cat_chunked_above" {
                let first = axum::body::Bytes::from(vec![b' '; MAX_EXEC_RESPONSE_JSON_BYTES]);
                let second = axum::body::Bytes::from_static(b" ");
                let stream = futures_util::stream::iter([
                    Ok::<_, Infallible>(first),
                    Ok::<_, Infallible>(second),
                ]);
                axum::body::Body::from_stream(stream)
            } else {
                axum::body::Body::from(vec![b' '; length])
            };
            let mut builder = axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header(axum::http::header::CONTENT_TYPE, "application/json");
            if cat_id != "cat_chunked_above" {
                builder = builder.header(axum::http::header::CONTENT_LENGTH, length.to_string());
            }
            builder.body(response).expect("bounded response")
        }

        let app = axum::Router::new().route(
            "/v1/cats/{cat_id}/exec",
            axum::routing::post(response_handler),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let client =
            SemanticNodedSessionClient::new(NodedServiceToken::new("x".repeat(32)).expect("token"))
                .expect("client");
        let request = ExecRequest {
            command: vec!["true".to_owned()],
            timeout_ms: Some(1_000),
            env: BTreeMap::new(),
            stdin: Vec::new(),
        };
        let target = |cat_id: &str| SessionTarget {
            cat_id: Id::new(cat_id).expect("Cat ID"),
            endpoint: NodedControlEndpoint::new(format!("http://{address}")).expect("endpoint"),
        };

        let exact = client
            .exec(&target("cat_exact"), &request)
            .await
            .expect_err("exact cap is read before malformed JSON is classified");
        assert_eq!(exact.code, SemanticErrorCode::NodeUnavailable);
        assert!(exact.message.contains("malformed Exec response"));
        assert!(!exact.message.contains("body limit"));

        for cat_id in ["cat_above", "cat_chunked_above"] {
            let above = client
                .exec(&target(cat_id), &request)
                .await
                .expect_err("plus one byte must exceed the response cap");
            assert_eq!(above.code, SemanticErrorCode::NodeUnavailable);
            assert!(above.message.contains("body limit"));
            assert!(above.message.contains("result is unknown"));
        }
        server.abort();
    }

    #[tokio::test]
    async fn exec_transport_loss_is_unknown_and_never_retried() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = Arc::clone(&accepted);
        let server = tokio::spawn(async move {
            while let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            {
                server_accepted.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                // Drop without an HTTP response after accepting request bytes.
            }
        });
        let token = NodedServiceToken::new("x".repeat(32)).expect("token");
        let client = SemanticNodedSessionClient::new(token).expect("client");
        let target = SessionTarget {
            cat_id: Id::new("cat_01").expect("cat ID"),
            endpoint: NodedControlEndpoint::new(format!("http://{address}")).expect("endpoint"),
        };
        let request = ExecRequest {
            command: vec!["true".to_owned()],
            timeout_ms: Some(1_000),
            env: BTreeMap::new(),
            stdin: Vec::new(),
        };

        let failure = client
            .exec(&target, &request)
            .await
            .expect_err("response loss must be reported");
        server.await.expect("server");

        assert_eq!(failure.code, SemanticErrorCode::NodeUnavailable);
        assert!(failure.message.contains("result is unknown"));
        assert!(failure.message.contains("was not retried"));
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }
}

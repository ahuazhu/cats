//! Bounded synchronous HTTP client for the semantic noded protocol.
//!
//! This client owns transport behavior only. Product lifecycle admission and
//! database settlement remain in the caller so this module cannot become a
//! second lifecycle authority.

use std::future::Future;
use std::time::Duration;

use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{
    noded_cat_action_path, noded_cat_path, CatAction, NodedCatActionRequest, NodedCatListResponse,
    NodedCatResponse, NodedCatView, NodedControlEndpoint, NodedCreateCatRequest, NodedResultStatus,
    NodedServiceToken, SemanticErrorBody, SemanticValidationError, NODED_AUTHORIZATION_HEADER,
    NODED_CATS_PATH, NODED_HEALTH_PATH,
};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::time::Instant;

pub const DEFAULT_NODED_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_NODED_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_NODED_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONFIGURED_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticNodedClientConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for SemanticNodedClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_NODED_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_NODED_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_NODED_MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticNodedClientConfigError {
    ConnectTimeout,
    RequestTimeout,
    MaxResponseBytes,
    HttpClient,
}

impl std::fmt::Display for SemanticNodedClientConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ConnectTimeout => "noded connect_timeout must be positive",
            Self::RequestTimeout => "noded request_timeout must be positive",
            Self::MaxResponseBytes => "noded max_response_bytes must be in 1..=1048576",
            Self::HttpClient => "failed to construct the noded HTTP client",
        })
    }
}

impl std::error::Error for SemanticNodedClientConfigError {}

#[derive(Debug)]
pub enum SemanticNodedClientError {
    Unavailable {
        message: String,
    },
    Timeout,
    Protocol {
        message: String,
    },
    Failed {
        http_status: Option<u16>,
        error: SemanticErrorBody,
    },
}

impl std::fmt::Display for SemanticNodedClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { message } => write!(formatter, "noded is unavailable: {message}"),
            Self::Timeout => formatter.write_str("noded request deadline exceeded"),
            Self::Protocol { message } => write!(formatter, "noded protocol error: {message}"),
            Self::Failed { error, .. } => {
                write!(formatter, "noded rejected or failed the request: {error:?}")
            }
        }
    }
}

impl std::error::Error for SemanticNodedClientError {}

impl SemanticNodedClientError {
    fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }
}

#[derive(Clone)]
pub struct SemanticNodedClient {
    http: reqwest::Client,
    token: NodedServiceToken,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl std::fmt::Debug for SemanticNodedClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SemanticNodedClient")
            .field("token", &self.token)
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl SemanticNodedClient {
    pub fn new(
        token: NodedServiceToken,
        config: SemanticNodedClientConfig,
    ) -> Result<Self, SemanticNodedClientConfigError> {
        if config.connect_timeout.is_zero() {
            return Err(SemanticNodedClientConfigError::ConnectTimeout);
        }
        if config.request_timeout.is_zero() {
            return Err(SemanticNodedClientConfigError::RequestTimeout);
        }
        if !(1..=MAX_CONFIGURED_RESPONSE_BYTES).contains(&config.max_response_bytes) {
            return Err(SemanticNodedClientConfigError::MaxResponseBytes);
        }
        let http = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| SemanticNodedClientConfigError::HttpClient)?;
        Ok(Self {
            http,
            token,
            request_timeout: config.request_timeout,
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub async fn health(
        &self,
        endpoint: &NodedControlEndpoint,
        deadline: Instant,
    ) -> Result<(), SemanticNodedClientError> {
        let request = self.request(Method::GET, endpoint, NODED_HEALTH_PATH, deadline)?;
        let response = self.send(request, deadline).await?;
        let status = response.status();
        let body = self.read_bounded(response, deadline).await?;
        if status.is_success() {
            return Ok(());
        }
        Err(decode_error_response(status, &body)?)
    }

    pub async fn get_cat(
        &self,
        endpoint: &NodedControlEndpoint,
        cat_id: &Id,
        deadline: Instant,
    ) -> Result<NodedCatView, SemanticNodedClientError> {
        let path = noded_cat_path(cat_id).map_err(validation_protocol_error)?;
        let view: NodedCatView = self
            .send_json(Method::GET, endpoint, &path, None::<&()>, deadline)
            .await?;
        view.validate().map_err(validation_protocol_error)?;
        Ok(view)
    }

    pub async fn list_cats(
        &self,
        endpoint: &NodedControlEndpoint,
        deadline: Instant,
    ) -> Result<NodedCatListResponse, SemanticNodedClientError> {
        let list: NodedCatListResponse = self
            .send_json(
                Method::GET,
                endpoint,
                NODED_CATS_PATH,
                None::<&()>,
                deadline,
            )
            .await?;
        list.validate().map_err(validation_protocol_error)?;
        Ok(list)
    }

    pub async fn create_cat(
        &self,
        endpoint: &NodedControlEndpoint,
        cat_id: &Id,
        request: &NodedCreateCatRequest,
        deadline: Instant,
    ) -> Result<NodedCatResponse, SemanticNodedClientError> {
        request.validate().map_err(validation_protocol_error)?;
        let path = noded_cat_path(cat_id).map_err(validation_protocol_error)?;
        let response = self
            .send_json(Method::PUT, endpoint, &path, Some(request), deadline)
            .await?;
        settle_cat_response(response)
    }

    pub async fn cat_action(
        &self,
        endpoint: &NodedControlEndpoint,
        cat_id: &Id,
        action: CatAction,
        request: &NodedCatActionRequest,
        deadline: Instant,
    ) -> Result<NodedCatResponse, SemanticNodedClientError> {
        request
            .validate_for(action)
            .map_err(validation_protocol_error)?;
        let path = noded_cat_action_path(cat_id, action).map_err(validation_protocol_error)?;
        let response = self
            .send_json(Method::POST, endpoint, &path, Some(request), deadline)
            .await?;
        settle_cat_response(response)
    }

    pub async fn destroy_cat(
        &self,
        endpoint: &NodedControlEndpoint,
        cat_id: &Id,
        deadline: Instant,
    ) -> Result<NodedCatResponse, SemanticNodedClientError> {
        let path = noded_cat_path(cat_id).map_err(validation_protocol_error)?;
        let response = self
            .send_json(Method::DELETE, endpoint, &path, None::<&()>, deadline)
            .await?;
        settle_cat_response(response)
    }

    fn request(
        &self,
        method: Method,
        endpoint: &NodedControlEndpoint,
        path: &str,
        deadline: Instant,
    ) -> Result<RequestBuilder, SemanticNodedClientError> {
        let remaining = self.remaining(deadline)?;
        Ok(self
            .http
            .request(method, format!("{}{path}", endpoint.as_str()))
            .header(NODED_AUTHORIZATION_HEADER, self.token.authorization_value())
            .header(ACCEPT, "application/json")
            .timeout(remaining))
    }

    async fn send_json<T, B>(
        &self,
        method: Method,
        endpoint: &NodedControlEndpoint,
        path: &str,
        body: Option<&B>,
        deadline: Instant,
    ) -> Result<T, SemanticNodedClientError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let mut request = self.request(method, endpoint, path, deadline)?;
        if let Some(body) = body {
            let encoded = serde_json::to_vec(body)
                .map_err(|error| Self::serialization_error("request", error))?;
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(encoded);
        }
        let response = self.send(request, deadline).await?;
        let status = response.status();
        require_json_content_type(&response)?;
        let body = self.read_bounded(response, deadline).await?;
        if !status.is_success() {
            return Err(decode_error_response(status, &body)?);
        }
        decode_json(&body, "success response")
    }

    async fn send(
        &self,
        request: RequestBuilder,
        deadline: Instant,
    ) -> Result<Response, SemanticNodedClientError> {
        self.run_until(deadline, request.send()).await
    }

    async fn read_bounded(
        &self,
        mut response: Response,
        deadline: Instant,
    ) -> Result<Vec<u8>, SemanticNodedClientError> {
        if response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(Self::protocol("noded response exceeds the body limit"));
        }
        let mut body = Vec::new();
        loop {
            let chunk = self.run_until(deadline, response.chunk()).await?;
            let Some(chunk) = chunk else {
                break;
            };
            let next_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| Self::protocol("noded response size overflow"))?;
            if next_len > self.max_response_bytes {
                return Err(Self::protocol("noded response exceeds the body limit"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn run_until<T, F>(
        &self,
        deadline: Instant,
        future: F,
    ) -> Result<T, SemanticNodedClientError>
    where
        F: Future<Output = Result<T, reqwest::Error>>,
    {
        self.remaining(deadline)?;
        match tokio::time::timeout_at(deadline, future).await {
            Err(_) => Err(SemanticNodedClientError::Timeout),
            Ok(Err(error)) if error.is_timeout() => Err(SemanticNodedClientError::Timeout),
            Ok(Err(error)) => Err(SemanticNodedClientError::Unavailable {
                message: error.to_string(),
            }),
            Ok(Ok(value)) => Ok(value),
        }
    }

    fn remaining(&self, caller_deadline: Instant) -> Result<Duration, SemanticNodedClientError> {
        let now = Instant::now();
        if caller_deadline <= now {
            return Err(SemanticNodedClientError::Timeout);
        }
        Ok(caller_deadline
            .saturating_duration_since(now)
            .min(self.request_timeout))
    }

    fn serialization_error(label: &str, error: serde_json::Error) -> SemanticNodedClientError {
        Self::protocol(format!("cannot encode {label}: {error}"))
    }

    fn protocol(message: impl Into<String>) -> SemanticNodedClientError {
        SemanticNodedClientError::protocol(message)
    }
}

fn settle_cat_response(
    response: NodedCatResponse,
) -> Result<NodedCatResponse, SemanticNodedClientError> {
    response.validate().map_err(validation_protocol_error)?;
    if response.status == NodedResultStatus::Failed {
        let error = response.error.ok_or_else(|| {
            SemanticNodedClientError::protocol("validated failed response lost its error")
        })?;
        return Err(SemanticNodedClientError::Failed {
            http_status: None,
            error,
        });
    }
    Ok(response)
}

fn validation_protocol_error(error: SemanticValidationError) -> SemanticNodedClientError {
    SemanticNodedClientError::protocol(error.to_string())
}

fn require_json_content_type(response: &Response) -> Result<(), SemanticNodedClientError> {
    let Some(content_type) = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(SemanticNodedClientError::protocol(
            "noded JSON response has no Content-Type",
        ));
    };
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(SemanticNodedClientError::protocol(
            "noded JSON response has the wrong Content-Type",
        ))
    }
}

fn decode_json<T: DeserializeOwned>(
    body: &[u8],
    label: &str,
) -> Result<T, SemanticNodedClientError> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut decoder)
        .map_err(|error| SemanticNodedClientError::protocol(format!("invalid {label}: {error}")))?;
    decoder.end().map_err(|error| {
        SemanticNodedClientError::protocol(format!("trailing bytes in {label}: {error}"))
    })?;
    Ok(value)
}

fn decode_error_response(
    status: StatusCode,
    body: &[u8],
) -> Result<SemanticNodedClientError, SemanticNodedClientError> {
    let error: SemanticErrorBody = decode_json(body, "error response")?;
    Ok(SemanticNodedClientError::Failed {
        http_status: Some(status.as_u16()),
        error,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::{header, Response};
    use axum::routing::any;
    use axum::Router;
    use cats_api::runtime_reconciliation::RandomId128;
    use cats_api::semantic_control::{
        CatState, NodedCatConfig, NodedDiskMount, PersistentDiskFormat, PersistentMountPath,
        SemanticErrorCode, NODED_BEARER_SCHEME,
    };

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SeenRequest {
        method: Method,
        path: String,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct FixtureState {
        seen: Arc<Mutex<Vec<SeenRequest>>>,
    }

    struct Fixture {
        endpoint: NodedControlEndpoint,
        state: FixtureState,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn fixture_handler(
        State(state): State<FixtureState>,
        request: Request,
    ) -> Response<Body> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let authorization = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec();
        state.seen.lock().unwrap().push(SeenRequest {
            method: method.clone(),
            path: path.clone(),
            authorization,
            body,
        });

        let (status, body) = match (method, path.as_str()) {
            (Method::GET, NODED_HEALTH_PATH) => (200, r#"{"status":"ok"}"#.to_owned()),
            (Method::GET, NODED_CATS_PATH) => (200, r#"{"cats":[]}"#.to_owned()),
            (Method::GET, "/v1/cats/cat_01") => (
                200,
                r#"{"cat_id":"cat_01","state":null,"active_action":"create","config":{"cpu":2,"memory_bytes":4096,"boot_image":"image","mounts":[]}}"#.to_owned(),
            ),
            (Method::PUT, "/v1/cats/cat_01")
            | (Method::POST, "/v1/cats/cat_01/actions/run") => (
                200,
                r#"{"status":"ok","cat_id":"cat_01","state":"running","error":null}"#
                    .to_owned(),
            ),
            (Method::DELETE, "/v1/cats/cat_01") => (
                200,
                r#"{"status":"ok","cat_id":"cat_01","state":"destroyed","error":null}"#
                    .to_owned(),
            ),
            _ => (
                404,
                r#"{"code":"cat_not_found","message":"Cat not found"}"#.to_owned(),
            ),
        };
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    async fn fixture(router: Router<FixtureState>) -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = FixtureState::default();
        let application = router.with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, application).await.unwrap();
        });
        Fixture {
            endpoint: NodedControlEndpoint::new(format!("http://{address}")).unwrap(),
            state,
            task,
        }
    }

    fn client_with(max_response_bytes: usize, request_timeout: Duration) -> SemanticNodedClient {
        SemanticNodedClient::new(
            NodedServiceToken::new(TOKEN).unwrap(),
            SemanticNodedClientConfig {
                connect_timeout: Duration::from_millis(100),
                request_timeout,
                max_response_bytes,
            },
        )
        .unwrap()
    }

    fn config() -> NodedCatConfig {
        NodedCatConfig {
            cpu: 2,
            memory_bytes: 4096,
            boot_image: "image".to_owned(),
            mounts: vec![NodedDiskMount {
                disk_id: Id::new("disk_01").unwrap(),
                volume_id: Id::new("vol_01").unwrap(),
                filesystem_uuid: RandomId128::new("1".repeat(32)).unwrap(),
                format: PersistentDiskFormat::Ext4,
                mount_path: PersistentMountPath::new("/data").unwrap(),
            }],
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[tokio::test]
    async fn all_methods_use_exact_paths_bearer_and_shared_wire() {
        let fixture = fixture(Router::new().fallback(any(fixture_handler))).await;
        let client = client_with(64 * 1024, Duration::from_secs(1));
        let cat_id = Id::new("cat_01").unwrap();

        client.health(&fixture.endpoint, deadline()).await.unwrap();
        let creating = client
            .get_cat(&fixture.endpoint, &cat_id, deadline())
            .await
            .unwrap();
        assert_eq!(creating.state, None);
        assert_eq!(creating.active_action, Some(CatAction::Create));
        assert!(client
            .list_cats(&fixture.endpoint, deadline())
            .await
            .unwrap()
            .cats
            .is_empty());
        assert_eq!(
            client
                .create_cat(&fixture.endpoint, &cat_id, &config(), deadline())
                .await
                .unwrap()
                .state,
            CatState::Running
        );
        client
            .cat_action(
                &fixture.endpoint,
                &cat_id,
                CatAction::Run,
                &NodedCatActionRequest {
                    config: Some(config()),
                },
                deadline(),
            )
            .await
            .unwrap();
        client
            .destroy_cat(&fixture.endpoint, &cat_id, deadline())
            .await
            .unwrap();

        let seen = fixture.state.seen.lock().unwrap();
        assert_eq!(seen.len(), 6);
        assert!(seen.iter().all(|request| {
            request.authorization.as_deref() == Some(&format!("{NODED_BEARER_SCHEME} {TOKEN}"))
        }));
        assert_eq!(seen[3].method, Method::PUT);
        assert_eq!(seen[3].path, "/v1/cats/cat_01");
        assert_eq!(
            seen[3].body,
            br#"{"cpu":2,"memory_bytes":4096,"boot_image":"image","mounts":[{"disk_id":"disk_01","volume_id":"vol_01","filesystem_uuid":"11111111111111111111111111111111","format":"ext4","mount_path":"/data"}]}"#
        );
        assert_eq!(seen[4].method, Method::POST);
        assert_eq!(seen[4].path, "/v1/cats/cat_01/actions/run");
        assert_eq!(seen[5].method, Method::DELETE);
        assert!(seen[5].body.is_empty());
    }

    #[tokio::test]
    async fn non_success_and_terminal_failure_are_typed_failed_results() {
        async fn handler(request: Request) -> Response<Body> {
            let body = if request.uri().path().ends_with("/actions/warm") {
                r#"{"status":"failed","cat_id":"cat_01","state":"failure","error":{"code":"guest_warm_failed","message":"snapshot failed"}}"#
            } else {
                r#"{"code":"cat_not_found","message":"Cat not found"}"#
            };
            let status = if request.uri().path().ends_with("/actions/warm") {
                200
            } else {
                404
            };
            Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap()
        }
        let fixture = fixture(Router::new().fallback(any(handler))).await;
        let client = client_with(4096, Duration::from_secs(1));
        let cat_id = Id::new("cat_01").unwrap();

        let missing = client
            .get_cat(&fixture.endpoint, &cat_id, deadline())
            .await
            .unwrap_err();
        assert!(matches!(
            missing,
            SemanticNodedClientError::Failed {
                http_status: Some(404),
                error: SemanticErrorBody {
                    code: SemanticErrorCode::CatNotFound,
                    ..
                }
            }
        ));

        let failed = client
            .cat_action(
                &fixture.endpoint,
                &cat_id,
                CatAction::Warm,
                &NodedCatActionRequest { config: None },
                deadline(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            failed,
            SemanticNodedClientError::Failed {
                http_status: None,
                error: SemanticErrorBody {
                    code: SemanticErrorCode::GuestWarmFailed,
                    ..
                }
            }
        ));
    }

    #[tokio::test]
    async fn absolute_deadline_and_request_timeout_cover_body_read() {
        async fn slow() -> Response<Body> {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"cats":[]}"#))
                .unwrap()
        }
        let fixture = fixture(Router::new().fallback(any(slow))).await;
        let client = client_with(4096, Duration::from_millis(30));

        assert!(matches!(
            client
                .list_cats(&fixture.endpoint, deadline())
                .await
                .unwrap_err(),
            SemanticNodedClientError::Timeout
        ));
        assert!(matches!(
            client
                .health(&fixture.endpoint, Instant::now())
                .await
                .unwrap_err(),
            SemanticNodedClientError::Timeout
        ));
    }

    #[tokio::test]
    async fn oversized_or_malformed_success_is_protocol_error() {
        async fn oversized() -> Response<Body> {
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'x'; 128]))
                .unwrap()
        }
        let oversized_fixture = fixture(Router::new().fallback(any(oversized))).await;
        let client = client_with(64, Duration::from_secs(1));
        assert!(matches!(
            client
                .list_cats(&oversized_fixture.endpoint, deadline())
                .await
                .unwrap_err(),
            SemanticNodedClientError::Protocol { .. }
        ));

        async fn malformed() -> Response<Body> {
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("not-json"))
                .unwrap()
        }
        let malformed_fixture = fixture(Router::new().fallback(any(malformed))).await;
        let client = client_with(4096, Duration::from_secs(1));
        assert!(matches!(
            client
                .list_cats(&malformed_fixture.endpoint, deadline())
                .await
                .unwrap_err(),
            SemanticNodedClientError::Protocol { .. }
        ));
    }

    #[tokio::test]
    async fn connection_failure_is_unavailable_and_token_never_debugs() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            NodedControlEndpoint::new(format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        drop(listener);
        let client = client_with(4096, Duration::from_millis(100));
        assert!(!format!("{client:?}").contains(TOKEN));
        assert!(matches!(
            client.health(&endpoint, deadline()).await.unwrap_err(),
            SemanticNodedClientError::Unavailable { .. }
        ));
    }
}

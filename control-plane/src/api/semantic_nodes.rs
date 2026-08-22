//! Machine-authenticated HTTP surface for semantic Node registration and
//! heartbeat. The shared bearer token is also used for Control -> noded
//! health probes; it never appears in a JSON body.

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use cats_api::error::{ApiError, ErrorBody};
use cats_api::semantic_control::{
    NodeHeartbeatRequest, NodeHeartbeatResponse, NodeRegistrationRequest, NodeRegistrationResponse,
    NodedServiceToken, NODED_AUTHORIZATION_HEADER,
};

use crate::semantic_node::NodeManagementService;
use crate::server::AppState;

pub const CONTROL_NODE_REGISTER_PATH: &str = "/v1/internal/nodes/register";
pub const CONTROL_NODE_HEARTBEAT_PATH: &str = "/v1/internal/nodes/heartbeat";

#[derive(Clone)]
pub struct SemanticNodeHttpState {
    service: Arc<NodeManagementService>,
    service_token: NodedServiceToken,
}

impl SemanticNodeHttpState {
    pub fn new(service: Arc<NodeManagementService>, service_token: NodedServiceToken) -> Self {
        Self {
            service,
            service_token,
        }
    }
}

pub fn routes(state: SemanticNodeHttpState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(CONTROL_NODE_REGISTER_PATH, post(register))
        .route(CONTROL_NODE_HEARTBEAT_PATH, post(heartbeat))
        .layer(Extension(Arc::new(state)))
}

async fn register(
    Extension(state): Extension<Arc<SemanticNodeHttpState>>,
    headers: HeaderMap,
    Json(request): Json<NodeRegistrationRequest>,
) -> Result<Json<NodeRegistrationResponse>, SemanticNodeHttpFailure> {
    authenticate(&headers, &state.service_token)?;
    state
        .service
        .register(request)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn heartbeat(
    Extension(state): Extension<Arc<SemanticNodeHttpState>>,
    headers: HeaderMap,
    Json(request): Json<NodeHeartbeatRequest>,
) -> Result<Json<NodeHeartbeatResponse>, SemanticNodeHttpFailure> {
    authenticate(&headers, &state.service_token)?;
    state
        .service
        .heartbeat(request)
        .await
        .map(Json)
        .map_err(Into::into)
}

fn authenticate(
    headers: &HeaderMap,
    expected: &NodedServiceToken,
) -> Result<(), SemanticNodeHttpFailure> {
    let provided = headers
        .get(NODED_AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(NodedServiceToken::parse_authorization);
    if provided.as_ref() == Some(expected) {
        Ok(())
    } else {
        Err(ApiError::unauthenticated("invalid noded service token").into())
    }
}

struct SemanticNodeHttpFailure(ApiError);

impl From<ApiError> for SemanticNodeHttpFailure {
    fn from(error: ApiError) -> Self {
        Self(error)
    }
}

impl IntoResponse for SemanticNodeHttpFailure {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response =
            (status, Json(ErrorBody::new(self.0.code, self.0.message))).into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn token(value: char) -> NodedServiceToken {
        NodedServiceToken::new(value.to_string().repeat(32)).expect("service token")
    }

    #[test]
    fn service_bearer_is_required_exactly() {
        let expected = token('a');
        let mut headers = HeaderMap::new();
        assert!(authenticate(&headers, &expected).is_err());
        headers.insert(
            NODED_AUTHORIZATION_HEADER,
            HeaderValue::from_str(&token('b').authorization_value()).expect("header"),
        );
        assert!(authenticate(&headers, &expected).is_err());
        headers.insert(
            NODED_AUTHORIZATION_HEADER,
            HeaderValue::from_str(&expected.authorization_value()).expect("header"),
        );
        assert!(authenticate(&headers, &expected).is_ok());
    }
}

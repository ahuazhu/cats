//! Machine-authenticated HTTP surface for semantic Node registration and
//! heartbeat. The shared bearer token is also used for Control -> noded
//! health probes; it never appears in a JSON body.

use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use cats_api::error::{ApiError, ErrorBody};
use cats_api::runtime_reconciliation::Id;
use cats_api::semantic_control::{
    CatState, NodeDrainCatResult, NodeDrainResponse, NodeDrainStatus, NodeHeartbeatRequest,
    NodeHeartbeatResponse, NodeRegistrationRequest, NodeRegistrationResponse, NodedServiceToken,
    CONTROL_NODE_DRAIN_PATH, NODED_AUTHORIZATION_HEADER,
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

    pub(super) fn service_token(&self) -> &NodedServiceToken {
        &self.service_token
    }
}

pub fn routes(state: SemanticNodeHttpState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(CONTROL_NODE_REGISTER_PATH, post(register))
        .route(CONTROL_NODE_HEARTBEAT_PATH, post(heartbeat))
        .route(CONTROL_NODE_DRAIN_PATH, post(drain_node))
        .layer(Extension(Arc::new(state)))
}

async fn drain_node(
    State(app): State<AppState>,
    Extension(state): Extension<Arc<SemanticNodeHttpState>>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> super::ApiResult<Json<NodeDrainResponse>> {
    super::check_admin_auth(&app, &headers).await?;
    let report = state.service.drain_node(node_id).await?;
    let response = drain_response(report)?;
    Ok(Json(response))
}

fn drain_response(
    report: crate::semantic_node_recovery::NodeDrainReport,
) -> Result<NodeDrainResponse, ApiError> {
    let drained = report.is_drained();
    let source_node_id = Id::new(report.source_node_id)
        .ok_or_else(|| ApiError::internal("drain source Node ID is invalid"))?;
    let cats = report
        .cats
        .into_iter()
        .map(|result| {
            let cat_id = Id::new(result.cat_id)
                .ok_or_else(|| ApiError::internal("drain Cat ID is invalid"))?;
            Ok(match result.status {
                crate::semantic_node_recovery::CatDrainStatus::Migrated {
                    target_node_id,
                    state,
                } => NodeDrainCatResult::Migrated {
                    cat_id,
                    target_node_id: Id::new(target_node_id)
                        .ok_or_else(|| ApiError::internal("drain target Node ID is invalid"))?,
                    state: core_state_to_wire(state),
                },
                crate::semantic_node_recovery::CatDrainStatus::Stale => {
                    NodeDrainCatResult::Stale { cat_id }
                }
                crate::semantic_node_recovery::CatDrainStatus::Blocked { code, message } => {
                    NodeDrainCatResult::Blocked {
                        cat_id,
                        code,
                        message,
                    }
                }
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let response = NodeDrainResponse {
        status: if drained {
            NodeDrainStatus::Drained
        } else {
            NodeDrainStatus::Blocked
        },
        source_node_id,
        cats,
    };
    response
        .validate()
        .map_err(|error| ApiError::internal(format!("invalid Node drain response: {error}")))?;
    Ok(response)
}

fn core_state_to_wire(state: crate::semantic_lifecycle::CatState) -> CatState {
    match state {
        crate::semantic_lifecycle::CatState::Running => CatState::Running,
        crate::semantic_lifecycle::CatState::Suspended => CatState::Suspended,
        crate::semantic_lifecycle::CatState::Warm => CatState::Warm,
        crate::semantic_lifecycle::CatState::Cold => CatState::Cold,
        crate::semantic_lifecycle::CatState::Failure => CatState::Failure,
        crate::semantic_lifecycle::CatState::Destroyed => CatState::Destroyed,
    }
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

pub(super) fn authenticate(
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

pub(super) struct SemanticNodeHttpFailure(ApiError);

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

    #[test]
    fn planned_drain_report_maps_to_closed_admin_response() {
        let response = drain_response(crate::semantic_node_recovery::NodeDrainReport {
            source_node_id: "node_source".to_owned(),
            cats: vec![
                crate::semantic_node_recovery::CatDrainResult {
                    cat_id: "cat_moved".to_owned(),
                    status: crate::semantic_node_recovery::CatDrainStatus::Migrated {
                        target_node_id: "node_target".to_owned(),
                        state: crate::semantic_lifecycle::CatState::Suspended,
                    },
                },
                crate::semantic_node_recovery::CatDrainResult {
                    cat_id: "cat_blocked".to_owned(),
                    status: crate::semantic_node_recovery::CatDrainStatus::Blocked {
                        code: "flush_failed".to_owned(),
                        message: "source did not reach Cold".to_owned(),
                    },
                },
            ],
        })
        .expect("valid drain response");

        assert_eq!(response.status, NodeDrainStatus::Blocked);
        assert!(matches!(
            response.cats[0],
            NodeDrainCatResult::Migrated {
                state: CatState::Suspended,
                ..
            }
        ));
        response.validate().unwrap();
    }
}

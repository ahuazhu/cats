use super::*;

// `ensure_running` may wait for 30 seconds. Keep the activation authority
// alive through that complete wait, then shorten the same lease to the small
// Running -> Node activity-guard handoff window before answering the Gateway.
const WAKE_ACTIVATION_LEASE_TTL_MS: u64 = 35_000;
const RUNNING_HANDOFF_LEASE_TTL_MS: u64 = 5_000;

#[derive(serde::Deserialize)]
pub(crate) struct ResolveQuery {
    hostname: String,
}

#[derive(serde::Serialize)]
pub(super) struct ResolveResponse {
    binding: RouteBinding,
    state: String,
    observed_state: ObservedState,
    node_agent_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_grant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_grant_issued_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_grant_expires_at_unix: Option<u64>,
}

pub(super) async fn resolve_route(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<ResolveResponse>> {
    check_service_auth(&state, &headers).await?;
    let (binding, route_state) = state.store.resolve_route(&q.hostname)?;
    let cat = state.store.must_get_cat_by_id(&binding.cat_id)?;
    let node_agent_url = state
        .store
        .list_nodes()?
        .into_iter()
        .find(|n| n.id == binding.node_id)
        .map(|n| n.agent_url)
        .unwrap_or_default();
    let grant = if route_state == "active" && cat.observed_state == ObservedState::Running {
        Some(
            state
                .cfg
                .route_grant_signer
                .issue(&binding, cat.generation)
                .map_err(|error| ApiError::internal(format!("issue route grant: {error:#}")))?,
        )
    } else {
        None
    };
    Ok(Json(ResolveResponse {
        binding,
        state: route_state,
        observed_state: cat.observed_state,
        node_agent_url,
        route_grant: grant.as_ref().map(|grant| grant.token.clone()),
        route_grant_issued_at_unix: grant.as_ref().map(|grant| grant.issued_at_unix),
        route_grant_expires_at_unix: grant.map(|grant| grant.expires_at_unix),
    }))
}

/// Gateway wake entry: waits until the cat backing `hostname` is running.
pub(super) async fn wake_route(state: &AppState, hostname: &str) -> ApiResult<()> {
    let (binding, _) = state.store.resolve_route(hostname)?;
    let cat = state.store.must_get_cat_by_id(&binding.cat_id)?;
    if binding.wake_policy == WakePolicy::NoWake && cat.observed_state != ObservedState::Running {
        return Err(ApiError::unavailable("endpoint does not wake on request").into());
    }
    // This lease belongs to activation, not to the eventual request. Its first
    // lifetime covers the complete bounded wake wait. Once Running is
    // observed, renewing the same owner shortens it to the small control-plane
    // Running -> Node activity-guard handoff window. Normal traffic for an
    // already Running route never calls this endpoint.
    let owner = format!("route_wake_{}", uuid::Uuid::new_v4().simple());
    let activation = state.store.acquire_work(
        &cat.id,
        WorkKind::Gateway,
        &owner,
        "endpoint_activation",
        WAKE_ACTIVATION_LEASE_TTL_MS,
    )?;
    match ensure_running(state, cat).await {
        Ok(_) => {
            state.store.acquire_work(
                &activation.cat_id,
                WorkKind::Gateway,
                &owner,
                "endpoint_activation",
                RUNNING_HANDOFF_LEASE_TTL_MS,
            )?;
            Ok(())
        }
        Err(error) => {
            let _ = state.store.release_work(&activation.id);
            Err(error)
        }
    }
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// Wake handler used by the gateway (`POST /v1/routes/wake?hostname=`).
pub(super) async fn wake_route_handler(
    State(state): State<AppState>,
    Query(q): Query<ResolveQuery>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    wake_route(&state, &q.hostname).await?;
    Ok(StatusCode::NO_CONTENT)
}

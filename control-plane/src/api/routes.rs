use super::*;

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
    Ok(Json(ResolveResponse {
        binding,
        state: route_state,
        observed_state: cat.observed_state,
        node_agent_url,
    }))
}

/// Gateway wake entry: waits until the cat backing `hostname` is running.
pub(super) async fn wake_route(state: &AppState, hostname: &str) -> ApiResult<()> {
    let (binding, _) = state.store.resolve_route(hostname)?;
    let cat = state.store.must_get_cat_by_id(&binding.cat_id)?;
    if binding.wake_policy == WakePolicy::NoWake && cat.observed_state != ObservedState::Running {
        return Err(ApiError::unavailable("endpoint does not wake on request").into());
    }
    ensure_running(state, cat).await?;
    Ok(())
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

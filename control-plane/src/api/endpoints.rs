use super::*;

pub(super) async fn create_endpoint(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<CreateEndpointRequest>,
) -> ApiResult<Json<EndpointResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    if req.name.is_empty()
        || req.name.len() > 24
        || !req
            .name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        || req.name.starts_with('-')
        || req.name.ends_with('-')
    {
        return Err(
            ApiError::invalid("endpoint name must be 1-24 lowercase [a-z0-9-] characters").into(),
        );
    }
    if req.target_port == 0 {
        return Err(ApiError::invalid("endpoint target_port must be non-zero").into());
    }
    if req.protocol != "http" {
        return Err(ApiError::invalid("only http endpoints are currently supported").into());
    }
    let ep = state
        .store
        .execute(move |store| {
            let cat = store.get_cat(&workspace, &cat)?;
            let ep = store.create_endpoint(
                &cat,
                &req.name,
                req.target_port,
                &req.protocol,
                req.wake_policy,
            )?;
            // If the cat is already running, bind the route immediately.
            if let (ObservedState::Running, Some(node_id)) = (cat.observed_state, &cat.node_id) {
                if let Some(node) = store.list_nodes()?.into_iter().find(|n| &n.id == node_id) {
                    store.publish_routes(&cat.id, &node.id, &node.gateway_url)?;
                }
            }
            Ok(ep)
        })
        .await?;
    Ok(Json(EndpointResponse { endpoint: ep }))
}

pub(super) async fn list_endpoints(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Endpoint>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let items = state
        .store
        .execute(move |store| {
            let cat = store.get_cat(&workspace, &cat)?;
            store.endpoints_for_cat(&cat.id)
        })
        .await?;
    Ok(Json(ListResponse { items }))
}

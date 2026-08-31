use super::*;

/// Resolve immutable Workspace identities for an administrator.
///
/// Runtime Node provisioning and semantic registration use separate fleet
/// surfaces; this management surface only lists Workspaces.
pub(super) async fn admin_list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<cats_api::auth::Workspace>>> {
    check_admin_auth(&state, &headers).await?;
    let items = state
        .store
        .execute(|store| store.list_all_workspace_views())
        .await?;
    Ok(Json(ListResponse { items }))
}

/// Export the surviving control-store executor telemetry.
pub(super) async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_metrics_auth(&state, &headers).await?;
    let mut body = String::new();
    crate::store::metrics_snapshot(&state.store).append_prometheus(&mut body);
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response())
}

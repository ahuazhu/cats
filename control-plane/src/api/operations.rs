use super::*;

pub(super) async fn get_operation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Operation>> {
    // Authenticate before looking up an opaque ID so unauthenticated callers
    // cannot use status differences to enumerate operations.
    check_authenticated(&state, &headers).await?;
    let operation = state
        .store
        .execute(move |store| store.get_operation(&id))
        .await?;
    let scope = check_workspace_auth(&state, &headers, &operation.workspace_id).await?;
    if scope.workspace.id != operation.workspace_id {
        return Err(ApiError::internal("operation workspace ownership is inconsistent").into());
    }
    Ok(Json(operation))
}

pub(super) async fn list_operations(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Operation>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let items = state
        .store
        .execute(move |store| store.list_operations(&workspace))
        .await?;
    Ok(Json(ListResponse { items }))
}

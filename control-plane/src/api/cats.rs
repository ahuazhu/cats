use super::*;

pub(super) async fn create_cat(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateCatRequest>,
) -> ApiResult<Response> {
    let scope = check_workspace_auth(&state, &headers, &workspace).await?;
    require_funded(&state, &workspace).await?;
    if req.name.is_empty()
        || !req
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::invalid("cat name must be non-empty [a-z0-9-]").into());
    }
    let route = format!("POST /cats {workspace}/{}", req.name);
    let idempotency_key = idem_key(&headers);
    if req.expires_at_unix.is_some_and(|at| at <= 0) {
        return Err(ApiError::invalid("expires_at_unix must be a positive unix timestamp").into());
    }
    let extra = req
        .disk
        .as_ref()
        .map(|d| (d.name.as_str(), d.size_bytes, d.mount_at.as_str()));
    let (cat, _disks, op) = match idempotency_key {
        Some(key) => state.store.create_cat_idempotent(
            &scope.workspace,
            &req.name,
            &req.image,
            req.cpus,
            req.memory_mib,
            req.root_size_bytes,
            req.auto_suspend,
            extra,
            req.expires_at_unix,
            req.durability,
            &key,
            &route,
        )?,
        None => state.store.create_cat(
            &scope.workspace,
            &req.name,
            &req.image,
            req.cpus,
            req.memory_mib,
            req.root_size_bytes,
            req.auto_suspend,
            extra,
            req.expires_at_unix,
            req.durability,
        )?,
    };
    state.notify.notify_one();
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse { operation: op, cat }),
    )
        .into_response())
}

pub(super) async fn list_cats(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Cat>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(ListResponse {
        items: state.store.list_cats(&workspace)?,
    }))
}

pub(super) async fn get_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Cat>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(state.store.get_cat(&workspace, &cat)?))
}

pub(super) async fn cat_action(
    State(state): State<AppState>,
    Path((workspace, cat, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    if verb == "sync" {
        // Imperative, not a desired-state change: force every attached disk
        // to a remote durable point right now (ADR-0022) and answer once it holds.
        return sync_cat(&state, &cat).await;
    }
    let desired = match verb.as_str() {
        "start" | "resume" => DesiredState::Running,
        "suspend" => DesiredState::Suspended,
        "warm" => DesiredState::Warm,
        "stop" => DesiredState::Cold,
        _ => return Err(ApiError::invalid(format!("unknown action {verb}")).into()),
    };
    if desired == DesiredState::Running {
        require_funded(&state, &workspace).await?;
    }
    let route = format!("POST /cats/{}/actions/{verb}", cat.id);
    let op_kind = format!("cat.{verb}");
    let op = match idem_key(&headers) {
        Some(key) => state.store.set_desired_idempotent(
            &cat.id,
            desired,
            if_match(&headers),
            &op_kind,
            &key,
            &route,
        )?,
        None => state
            .store
            .set_desired(&cat.id, desired, if_match(&headers), &op_kind)?,
    };
    state.notify.notify_one();
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse { operation: op, cat }),
    )
        .into_response())
}

pub(super) async fn delete_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let route = format!("DELETE /cats/{}", cat.id);
    let op = match idem_key(&headers) {
        Some(key) => state.store.set_desired_idempotent(
            &cat.id,
            DesiredState::Deleted,
            if_match(&headers),
            "cat.delete",
            &key,
            &route,
        )?,
        None => state.store.set_desired(
            &cat.id,
            DesiredState::Deleted,
            if_match(&headers),
            "cat.delete",
        )?,
    };
    state.notify.notify_one();
    let cat_snapshot = state.store.must_get_cat_by_id(&cat.id)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CatOperationResponse {
            operation: op,
            cat: cat_snapshot,
        }),
    )
        .into_response())
}

pub(super) async fn get_auto_suspend(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AutoSuspendResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let work = state
        .store
        .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?;
    Ok(Json(AutoSuspendResponse { cat, work }))
}

pub(super) async fn update_auto_suspend(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateAutoSuspendRequest>,
) -> ApiResult<Json<AutoSuspendResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let cat = state.store.set_auto_suspend(&cat.id, request.enabled)?;
    if request.enabled {
        state.controller.maybe_auto_suspend(&cat.id)?;
    }
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    let work = state
        .store
        .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?;
    Ok(Json(AutoSuspendResponse { cat, work }))
}

pub(super) async fn get_expiry(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Cat>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(state.store.get_cat(&workspace, &cat)?))
}

pub(super) async fn update_expiry(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateExpiryRequest>,
) -> ApiResult<Json<Cat>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    if request.expires_at_unix.is_some_and(|at| at <= 0) {
        return Err(ApiError::invalid("expires_at_unix must be a positive unix timestamp").into());
    }
    let cat = state.store.get_cat(&workspace, &cat)?;
    let cat = state.store.set_expiry(&cat.id, request.expires_at_unix)?;
    // An expiry moved into the past should be reaped on the next tick, not on
    // the next unrelated wake-up.
    state.notify.notify_one();
    Ok(Json(cat))
}

pub(super) async fn get_cat_work(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<CatWorkStatus>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    Ok(Json(
        state
            .store
            .work_status(&cat.id, state.cfg.node_lease_timeout_ms)?,
    ))
}

/// Wake a cat for exec/gateway traffic and wait until it reports Running.
pub async fn ensure_running(state: &AppState, cat: Cat) -> ApiResult<Cat> {
    let wake_started = std::time::Instant::now();
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    require_funded(state, &cat.workspace_id).await?;
    if cat.desired_state == DesiredState::Running && cat.observed_state == ObservedState::Running {
        return Ok(cat);
    }
    state.store.ensure_desired_running(&cat.id)?;
    let desired_update_us = wake_started.elapsed().as_micros();
    state.notify.notify_one();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let current = state.store.must_get_cat_by_id(&cat.id)?;
        match current.observed_state {
            ObservedState::Running => {
                tracing::info!(
                    cat = %cat.id,
                    total_us = wake_started.elapsed().as_micros(),
                    desired_update_us,
                    "wake wait timings"
                );
                return Ok(current);
            }
            ObservedState::Failed => {
                return Err(ApiError::unavailable("cat failed to start").into())
            }
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            return Err(ApiError::new(ErrorCode::DeadlineExceeded, "wake timed out").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Disks
// ---------------------------------------------------------------------------

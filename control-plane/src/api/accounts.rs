use super::*;

pub(super) async fn cli_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<cats_api::auth::MeResponse>> {
    let identity = require_cli_identity(&state, &headers).await?;
    if identity.organization_id.is_none() {
        crate::auth::provision_personal_account(&state, &identity.user_id, &identity.user_id)
            .await?;
    }
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    Ok(Json(workos.me(&state.store, &identity).await?))
}

pub(super) async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<cats_api::auth::Workspace>>> {
    let identity = require_cli_identity(&state, &headers).await?;
    if identity.organization_id.is_none() {
        crate::auth::provision_personal_account(&state, &identity.user_id, &identity.user_id)
            .await?;
    }
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    Ok(Json(ListResponse {
        items: workos.workspaces_for(&state.store, &identity).await?,
    }))
}

pub(super) async fn cli_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let identity = require_cli_identity(&state, &headers).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    workos.revoke_cli_session(&identity).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn workspace_response(
    state: &AppState,
    account: &crate::store::AccountRecord,
    workspace_id: &str,
) -> ApiResult<Workspace> {
    let (_, workspaces) = state
        .store
        .account_and_workspace_views(&account.workos_organization_id, None, &[])?
        .ok_or_else(|| ApiError::failed_precondition("account is not active"))?;
    workspaces
        .into_iter()
        .find(|workspace| workspace.id == workspace_id)
        .ok_or_else(|| ApiError::internal("workspace was not visible after mutation").into())
}

pub(super) async fn create_account_workspace(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateWorkspaceRequest>,
) -> ApiResult<Response> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workspace =
        state
            .store
            .create_workspace(&account.id, &request.slug, &request.display_name)?;
    Ok((
        StatusCode::CREATED,
        Json(workspace_response(&state, &account, &workspace.id)?),
    )
        .into_response())
}

pub(super) async fn create_workspace_token(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateWorkspaceTokenRequest>,
) -> ApiResult<Response> {
    check_workspace_token_admin(&state, &headers, &workspace).await?;
    let secret = format!(
        "cats_wst_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let access_token = state.store.create_workspace_token(
        &workspace,
        &request.label,
        &workspace_token_hash(&secret),
    )?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedWorkspaceToken {
            access_token,
            token: secret,
        }),
    )
        .into_response())
}

pub(super) async fn list_workspace_tokens(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<WorkspaceToken>>> {
    check_workspace_token_admin(&state, &headers, &workspace).await?;
    Ok(Json(ListResponse {
        items: state.store.workspace_tokens(&workspace)?,
    }))
}

pub(super) async fn revoke_workspace_token(
    State(state): State<AppState>,
    Path((workspace, token)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_workspace_token_admin(&state, &headers, &workspace).await?;
    state.store.revoke_workspace_token(&workspace, &token)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn update_workspace(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateWorkspaceRequest>,
) -> ApiResult<Json<Workspace>> {
    let existing = state.store.workspace_by_id(&workspace_id)?;
    let (account, _) = require_account_manager(&state, &headers, &existing.account_id).await?;
    let workspace = state.store.update_workspace(
        &workspace_id,
        request.slug.as_deref(),
        request.display_name.as_deref(),
    )?;
    Ok(Json(workspace_response(&state, &account, &workspace.id)?))
}

pub(super) async fn create_account_invitation(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateInvitationRequest>,
) -> ApiResult<Response> {
    let (account, inviter_user_id) = require_account_manager(&state, &headers, &account_id).await?;
    if account.kind == cats_api::auth::AccountKind::Personal {
        return Err(ApiError::failed_precondition(
            "personal accounts do not accept member invitations",
        )
        .into());
    }
    let email = request.email.trim().to_ascii_lowercase();
    if email.len() > 320
        || !email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
    {
        return Err(ApiError::invalid("invitation email is invalid").into());
    }
    if !matches!(request.role_slug.as_str(), "member" | "admin") {
        return Err(ApiError::invalid("role_slug must be member or admin").into());
    }
    let idempotency_key = idem_key(&headers)
        .filter(|key| !key.is_empty() && key.len() <= 255)
        .ok_or_else(|| {
            ApiError::invalid("a non-empty Idempotency-Key of at most 255 bytes is required")
        })?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let invitation = workos
        .send_account_invitation(
            &account,
            &inviter_user_id,
            &email,
            &request.role_slug,
            &idempotency_key,
        )
        .await?;
    state
        .store
        .record_invitation(&invitation, &account.workos_organization_id)?;
    Ok((StatusCode::CREATED, Json(invitation)).into_response())
}

pub(super) async fn list_account_invitations(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<AccountInvitation>>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let items = workos.list_account_invitations(&account).await?;
    for invitation in &items {
        state
            .store
            .record_invitation(invitation, &account.workos_organization_id)?;
    }
    Ok(Json(ListResponse { items }))
}

pub(super) async fn revoke_account_invitation(
    State(state): State<AppState>,
    Path((account_id, invitation_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<AccountInvitation>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let invitation = workos
        .revoke_account_invitation(&account, &invitation_id)
        .await?;
    state
        .store
        .record_invitation(&invitation, &account.workos_organization_id)?;
    Ok(Json(invitation))
}

pub(super) async fn list_account_members(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<AccountMember>>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let items = workos.list_account_members(&account).await?;
    for member in &items {
        state.store.upsert_membership_shadow(
            &member.membership_id,
            &account.id,
            &member.user.id,
            &member.role_slug,
            &member.status,
        )?;
    }
    Ok(Json(ListResponse { items }))
}

pub(super) async fn update_account_member(
    State(state): State<AppState>,
    Path((account_id, membership_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateAccountMemberRequest>,
) -> ApiResult<Json<AccountMember>> {
    let (account, _) = require_account_manager(&state, &headers, &account_id).await?;
    if !matches!(request.role_slug.as_str(), "member" | "admin") {
        return Err(ApiError::invalid("role_slug must be member or admin").into());
    }
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let members = workos.list_account_members(&account).await?;
    let target = members
        .iter()
        .find(|member| member.membership_id == membership_id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "membership not found"))?;
    let active_admins = members
        .iter()
        .filter(|member| member.status == "active" && member.role_slug == "admin")
        .count();
    if target.status == "active"
        && target.role_slug == "admin"
        && request.role_slug != "admin"
        && active_admins <= 1
    {
        return Err(ApiError::failed_precondition(
            "an organization account must retain an active administrator",
        )
        .into());
    }
    let member = workos
        .update_account_member(&account, &membership_id, &request.role_slug)
        .await?;
    state.store.upsert_membership_shadow(
        &member.membership_id,
        &account.id,
        &member.user.id,
        &member.role_slug,
        &member.status,
    )?;
    Ok(Json(member))
}

pub(super) async fn deactivate_account_member(
    State(state): State<AppState>,
    Path((account_id, membership_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let (account, actor_user_id) = require_account_manager(&state, &headers, &account_id).await?;
    let workos = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let members = workos.list_account_members(&account).await?;
    let target = members
        .iter()
        .find(|member| member.membership_id == membership_id)
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "membership not found"))?;
    if target.user.id == actor_user_id {
        return Err(ApiError::failed_precondition(
            "use another account administrator to deactivate your own membership",
        )
        .into());
    }
    let active_admins = members
        .iter()
        .filter(|member| member.status == "active" && member.role_slug == "admin")
        .count();
    if target.role_slug == "admin" && active_admins <= 1 {
        return Err(ApiError::failed_precondition(
            "an organization account must retain an active administrator",
        )
        .into());
    }
    workos
        .deactivate_account_member(&account, &membership_id)
        .await?;
    state.store.upsert_membership_shadow(
        &target.membership_id,
        &account.id,
        &target.user.id,
        &target.role_slug,
        "inactive",
    )?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Cats
// ---------------------------------------------------------------------------

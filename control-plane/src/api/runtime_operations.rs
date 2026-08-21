//! Workspace-qualified read access to atomic lifecycle Operations.

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::Response;
use cats_api::error::{ApiError, ErrorCode};
use cats_api::runtime_lifecycle::{
    LifecycleCommand, LifecycleCommandKind, LifecycleOperation, LifecycleOperationState,
    StartSource, TerminalResultKind,
};
use cats_api::runtime_product_reads::{
    encode_cat_operation_read_v1, CatOperationAction, CatOperationReadV1, CatOperationState,
};
use cats_api::runtime_reconciliation::Id;

use super::{check_workspace_auth, ApiResult};
use crate::server::AppState;

pub(super) async fn get_runtime_operation(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // Authorize the raw Workspace slot before parsing the Operation identity.
    // Percent-decoding an untrusted capture first could let two paths name one
    // authority object with different byte identities.
    let workspace = raw_workspace_segment(&uri).to_owned();
    let scope = check_workspace_auth(&state, &headers, &workspace).await?;
    let workspace_id = Id::new(scope.workspace.id)
        .ok_or_else(|| ApiError::internal("stored workspace ID is invalid"))?;
    let Some(operation) = exact_operation_segment(&uri, &workspace_id) else {
        return Err(ApiError::not_found("operation").into());
    };
    let Some(operation_id) = Id::new(operation.to_owned()) else {
        return Err(ApiError::not_found("operation").into());
    };

    let lookup_workspace_id = workspace_id.clone();
    let lookup_operation_id = operation_id.clone();
    let operation = match state
        .store
        .execute(move |store| store.lifecycle_operation(&lookup_workspace_id, &lookup_operation_id))
        .await
    {
        Ok(Some(operation)) => operation,
        Ok(None) => return Err(ApiError::not_found("operation").into()),
        Err(error) => {
            if error.code == ErrorCode::Internal {
                tracing::error!(
                    workspace_id = %workspace_id,
                    operation_id = %operation_id,
                    error = %error,
                    "atomic lifecycle Operation read found stored authority corruption"
                );
                state.readiness.poison();
            }
            return Err(error.into());
        }
    };

    let Some(operation) = product_operation_projection(&operation)? else {
        // Internal maintenance commands are deliberately outside the product
        // Operation namespace even though they share durable storage.
        return Err(ApiError::not_found("operation").into());
    };
    let body = match encode_cat_operation_read_v1(&operation) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(
                workspace_id = %workspace_id,
                operation_id = %operation_id,
                error = %error,
                "stored atomic lifecycle Operation could not be re-encoded"
            );
            state.readiness.poison();
            return Err(ApiError::internal("stored lifecycle Operation is corrupt").into());
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .map_err(|_| ApiError::internal("could not construct Operation response").into())
}

fn product_operation_projection(
    operation: &LifecycleOperation,
) -> Result<Option<CatOperationReadV1>, ApiError> {
    if operation.command_kind != operation.canonical_request.command.kind() {
        return Err(ApiError::internal(
            "stored lifecycle Operation command kind is inconsistent",
        ));
    }
    let start_source = match &operation.canonical_request.command {
        LifecycleCommand::Start(spec) => Some(spec.source),
        _ => None,
    };
    let Some(action) = product_action(operation.command_kind, start_source) else {
        return Ok(None);
    };
    let terminal_kind = match &operation.state {
        LifecycleOperationState::Unresolved => None,
        LifecycleOperationState::Terminal { terminal, .. } => Some(terminal.kind()),
    };
    let state = product_operation_state(action, terminal_kind);
    let terminal_at_unix_ms = match state {
        CatOperationState::InProgress => None,
        CatOperationState::Succeeded | CatOperationState::Failed => operation.terminal_at_unix_ms,
    };
    if matches!(
        state,
        CatOperationState::Succeeded | CatOperationState::Failed
    ) && terminal_at_unix_ms.is_none()
    {
        return Err(ApiError::internal(
            "stored terminal lifecycle Operation is missing its completion time",
        ));
    }
    Ok(Some(CatOperationReadV1 {
        version: operation.version,
        operation_id: operation.operation_id.clone(),
        workspace_id: operation.workspace_id.clone(),
        cat_id: operation.cat_id.clone(),
        action,
        state,
        created_at_unix_ms: operation.created_at_unix_ms,
        terminal_at_unix_ms,
    }))
}

fn product_action(
    command_kind: LifecycleCommandKind,
    start_source: Option<StartSource>,
) -> Option<CatOperationAction> {
    match command_kind {
        LifecycleCommandKind::Start => Some(if start_source == Some(StartSource::Genesis) {
            CatOperationAction::Create
        } else {
            CatOperationAction::Run
        }),
        LifecycleCommandKind::Suspend => Some(CatOperationAction::Suspend),
        LifecycleCommandKind::Warm => Some(CatOperationAction::Warm),
        LifecycleCommandKind::Cold => Some(CatOperationAction::Cold),
        LifecycleCommandKind::Delete => Some(CatOperationAction::Destroy),
        LifecycleCommandKind::Stop => None,
    }
}

fn product_operation_state(
    action: CatOperationAction,
    terminal_kind: Option<TerminalResultKind>,
) -> CatOperationState {
    let Some(terminal_kind) = terminal_kind else {
        return CatOperationState::InProgress;
    };
    let succeeded = matches!(
        (action, terminal_kind),
        (
            CatOperationAction::Create | CatOperationAction::Run,
            TerminalResultKind::RuntimeReady
        ) | (CatOperationAction::Suspend, TerminalResultKind::Suspended)
            | (CatOperationAction::Warm, TerminalResultKind::Warm)
            | (CatOperationAction::Cold, TerminalResultKind::Cold)
            | (CatOperationAction::Destroy, TerminalResultKind::Deleted)
    );
    if succeeded {
        CatOperationState::Succeeded
    } else {
        CatOperationState::Failed
    }
}

fn raw_workspace_segment(uri: &Uri) -> &str {
    uri.path().split('/').nth(3).unwrap_or("")
}

fn exact_operation_segment<'a>(uri: &'a Uri, workspace_id: &Id) -> Option<&'a str> {
    let mut segments = uri.path().split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (
            Some(""),
            Some("v1"),
            Some("workspaces"),
            Some(workspace),
            Some("operations"),
            Some(operation),
            None,
        ) if workspace == workspace_id.as_str() && !operation.is_empty() => Some(operation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_path_requires_exact_workspace_and_shape() {
        let workspace = Id::new("ws_exact").unwrap();
        let valid: Uri = "/v1/workspaces/ws_exact/operations/op_1".parse().unwrap();
        assert_eq!(exact_operation_segment(&valid, &workspace), Some("op_1"));
        assert_eq!(raw_workspace_segment(&valid), "ws_exact");

        for invalid in [
            "/v1/workspaces/ws_other/operations/op_1",
            "/v1/workspaces/ws_exact/operations/",
            "/v1/workspaces/ws_exact/operations/op_1/extra",
            "/v1/workspaces/ws_exact/operations/op_1/",
        ] {
            let uri: Uri = invalid.parse().unwrap();
            assert_eq!(exact_operation_segment(&uri, &workspace), None, "{invalid}");
        }
    }

    #[test]
    fn product_action_projection_hides_internal_stop_and_renames_run_destroy() {
        assert_eq!(
            product_action(LifecycleCommandKind::Start, Some(StartSource::Genesis)),
            Some(CatOperationAction::Create)
        );
        for source in [
            StartSource::SameNodeSuspended,
            StartSource::SameNodeWarm,
            StartSource::SameNodeCold,
            StartSource::SameNodeRetry,
            StartSource::ColdHandoff,
        ] {
            assert_eq!(
                product_action(LifecycleCommandKind::Start, Some(source)),
                Some(CatOperationAction::Run)
            );
        }
        assert_eq!(
            product_action(LifecycleCommandKind::Delete, None),
            Some(CatOperationAction::Destroy)
        );
        assert_eq!(product_action(LifecycleCommandKind::Stop, None), None);
    }

    #[test]
    fn product_state_exposes_only_progress_success_or_failure() {
        assert_eq!(
            product_operation_state(CatOperationAction::Run, None),
            CatOperationState::InProgress
        );
        assert_eq!(
            product_operation_state(
                CatOperationAction::Run,
                Some(TerminalResultKind::RuntimeReady)
            ),
            CatOperationState::Succeeded
        );
        for internal in [
            TerminalResultKind::StartFailed,
            TerminalResultKind::Killed,
            TerminalResultKind::NeedsIntervention,
            TerminalResultKind::HostLost,
        ] {
            assert_eq!(
                product_operation_state(CatOperationAction::Run, Some(internal)),
                CatOperationState::Failed
            );
        }
    }
}

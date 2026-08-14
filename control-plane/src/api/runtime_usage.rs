//! Signed, session-fenced ingestion into the existing UsageStore.

use std::collections::BTreeMap;
use std::error::Error as _;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cats_api::agent_registration::{
    verify_request_proof, JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER,
    NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::metering::{
    CatUsageCheckpoint, IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse,
    RejectedCheckpoint, UsageCheckpointIngestOutcome, UsageCheckpointIngestResult,
    UsageEpochMarker, MAX_USAGE_CHECKPOINTS_PER_REQUEST, MAX_USAGE_INGEST_BODY_BYTES,
    USAGE_CHECKPOINTS_METHOD, USAGE_CHECKPOINTS_PATH,
};
use cats_api::runtime_reconciliation::{Id, RandomId128, Revision, SessionBinding};
use cats_metering::{
    target_terminal_request_sha256, AttributedCheckpoint, IngestOutcome, RuntimeUsageSourceBinding,
    UsageAttribution, UsageTargetTerminalReceipt, UsageTargetTerminalRequest,
    UsageTerminalPrepareOutcome,
};
use serde::{Deserialize, Serialize};

use crate::server::AppState;
use crate::store::runtime_authority::product_reads::RuntimeUsageCatRead;
use crate::store::runtime_authority::volume_transition_auth::{
    VolumeTransitionStoreOutcome, VolumeTransitionStoreRejection,
};
use crate::store::AuthorityRequestContext;

const HANDLER_DEADLINE: Duration = Duration::from_secs(10);
const NODE_AUTHENTICATE_CHALLENGE: &str = "CatsNodeSignature realm=\"runtime-internal\"";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiscoverSourceTerminalRequest {
    source_id: String,
    source_epoch: String,
}

#[derive(Debug, Serialize)]
struct BeginTargetTerminalResponse {
    state: &'static str,
    request_sha256: String,
}

#[derive(Debug, Serialize)]
struct CompleteTargetTerminalResponse {
    state: &'static str,
    request_sha256: String,
    receipt: Option<UsageTargetTerminalReceipt>,
}

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn discover_source_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DiscoverSourceTerminalRequest>,
) -> Response {
    if let Err(error) = super::check_admin_auth(&state, &headers).await {
        return error.into_response();
    }
    if request.source_id.is_empty() || request.source_epoch.is_empty() {
        return invalid("source_id and source_epoch are required");
    }
    match state
        .usage
        .source_terminal_receipt(&request.source_id, &request.source_epoch)
        .await
    {
        Ok(Some(receipt)) => Json(receipt).into_response(),
        Ok(None) => api_error(ApiError::not_found("usage source terminal receipt")),
        Err(error) => metering_error(error),
    }
}

pub(super) async fn begin_target_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UsageTargetTerminalRequest>,
) -> Response {
    if let Err(error) = super::check_admin_auth(&state, &headers).await {
        return error.into_response();
    }
    let request_sha256 = match target_terminal_request_sha256(&request) {
        Ok(digest) => digest,
        Err(error) => return metering_error(error),
    };
    match state.usage.begin_target_terminal(&request).await {
        Ok(outcome) => Json(BeginTargetTerminalResponse {
            state: match outcome {
                UsageTerminalPrepareOutcome::Prepared => "prepared",
                UsageTerminalPrepareOutcome::ExactReplay => "exact_replay",
            },
            request_sha256,
        })
        .into_response(),
        Err(error) => metering_error(error),
    }
}

pub(super) async fn complete_target_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UsageTargetTerminalRequest>,
) -> Response {
    if let Err(error) = super::check_admin_auth(&state, &headers).await {
        return error.into_response();
    }
    let request_sha256 = match target_terminal_request_sha256(&request) {
        Ok(digest) => digest,
        Err(error) => return metering_error(error),
    };
    match state.usage.complete_target_terminal(&request).await {
        Ok(receipt) => {
            let status = if receipt.is_some() {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            (
                status,
                Json(CompleteTargetTerminalResponse {
                    state: if receipt.is_some() {
                        "terminal"
                    } else {
                        "pending"
                    },
                    request_sha256,
                    receipt,
                }),
            )
                .into_response()
        }
        Err(error) => metering_error(error),
    }
}

pub(super) async fn ingest(State(state): State<AppState>, request: Request<Body>) -> Response {
    let deadline = Instant::now() + HANDLER_DEADLINE;
    let request_context = AuthorityRequestContext::new(deadline);
    let _cancel_on_drop = CancelRequestOnDrop(request_context.clone());

    if request.method().as_str() != USAGE_CHECKPOINTS_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::InvalidArgument,
            "usage checkpoint ingestion requires POST",
            &[(
                header::ALLOW,
                HeaderValue::from_static(USAGE_CHECKPOINTS_METHOD),
            )],
        );
    }
    if request.uri().query().is_some() {
        return invalid("usage checkpoint ingestion does not accept a query");
    }

    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::InvalidArgument,
            "usage checkpoint ingestion requires application/json",
            &[],
        );
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::InvalidArgument,
            "usage checkpoint ingestion does not accept Content-Encoding",
            &[],
        );
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return invalid("usage checkpoint ingestion does not accept Authorization");
    }
    if declared_body_exceeds_limit(&headers, MAX_USAGE_INGEST_BODY_BYTES) {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::InvalidArgument,
            "usage checkpoint request exceeds the wire limit",
            &[],
        );
    }

    let _global_permit = match state.runtime_spine_admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return unavailable("usage checkpoint admission is saturated"),
    };
    let body = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        to_bytes(request.into_body(), MAX_USAGE_INGEST_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(error))
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::InvalidArgument,
                "usage checkpoint request exceeds the wire limit",
                &[],
            );
        }
        Ok(Err(_)) => return internal(),
        Err(_) => return deadline_exceeded(),
    };

    let authenticated = match (
        single_header_text(&headers, NODE_CREDENTIAL_ID_HEADER),
        single_header_text(&headers, NODE_PUBLIC_KEY_SPKI_HEADER),
        single_header_text(&headers, NODE_SIGNATURE_HEADER),
    ) {
        (Some(credential_id), Some(public_key_spki), Some(signature)) => verify_request_proof(
            USAGE_CHECKPOINTS_METHOD,
            USAGE_CHECKPOINTS_PATH,
            &body,
            credential_id,
            public_key_spki,
            signature,
        ),
        _ => Err(cats_api::agent_registration::RequestProofError),
    };
    let authenticated = match authenticated {
        Ok(authenticated) => authenticated,
        Err(_) => return authentication_failed(),
    };
    let request: IngestUsageCheckpointsRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return invalid("usage checkpoint request is malformed"),
    };
    if request.checkpoints.len() > MAX_USAGE_CHECKPOINTS_PER_REQUEST {
        return invalid(format!(
            "at most {MAX_USAGE_CHECKPOINTS_PER_REQUEST} checkpoints are allowed per request"
        ));
    }
    if request.node_id != request.session.node_id.as_str() {
        return conflict("usage checkpoint node_id does not match its AgentSession");
    }
    if let Err(message) = validate_request_terminal_order(&request.checkpoints) {
        return invalid(message);
    }

    let active_guest_digest = state
        .agent_session_registration_policy
        .approved_guest_config_digest()
        .clone();
    let lookup_credential = authenticated.clone();
    let lookup_session = request.session.clone();
    let lookup_context = request_context.clone();
    let store = state.store.clone();
    let authenticated_node = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        store.execute(move |store| {
            store.runtime_node_session_for_request(
                &lookup_credential,
                &lookup_session,
                &active_guest_digest,
                &lookup_context,
            )
        }),
    )
    .await
    {
        Ok(Ok(VolumeTransitionStoreOutcome::Accepted(node_id))) => node_id,
        Ok(Ok(VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::IdentityNotEligible,
        ))) => {
            return error_response(
                StatusCode::FORBIDDEN,
                ErrorCode::PermissionDenied,
                "usage checkpoint identity is not eligible",
                &[],
            )
        }
        Ok(Ok(VolumeTransitionStoreOutcome::Rejected(
            VolumeTransitionStoreRejection::Contract(_),
        ))) => return conflict("usage checkpoint AgentSession is not current"),
        Ok(Ok(VolumeTransitionStoreOutcome::Rejected(_))) => return internal(),
        Ok(Err(error)) if transient_store_error(&error) => {
            return unavailable("usage checkpoint authority is unavailable")
        }
        Ok(Err(_)) => return internal(),
        Err(_) => return deadline_exceeded(),
    };
    if authenticated_node != request.session.node_id {
        return conflict("usage checkpoint identity does not match its AgentSession");
    }
    let _node_permit = match state.runtime_spine_admission.try_node(&authenticated_node) {
        Ok(permit) => permit,
        Err(_) => return unavailable("usage checkpoint Node admission is saturated"),
    };

    match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        ingest_authenticated(&state, request),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => deadline_exceeded(),
    }
}

async fn ingest_authenticated(
    state: &AppState,
    request: IngestUsageCheckpointsRequest,
) -> Response {
    let mut accepted = 0_u64;
    let mut duplicates = 0_u64;
    let mut rejected = Vec::new();
    let mut results = Vec::new();
    for checkpoint in request.checkpoints {
        let expected_source = format!("node/{}/cat/{}", request.node_id, checkpoint.cat_id);
        if checkpoint.source_id != expected_source {
            return invalid(format!("checkpoint source_id must be {expected_source}"));
        }
        let source_binding = match runtime_source_binding(&request.session, &checkpoint) {
            Ok(binding) => binding,
            Err(message) => return invalid(message),
        };
        let source_terminal = match state
            .usage
            .source_terminal_receipt(&checkpoint.source_id, &checkpoint.source_epoch)
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => return metering_error(error),
        };
        if let Some(receipt) = source_terminal {
            if terminal_receipt_matches_checkpoint(&receipt, &source_binding, &checkpoint) {
                duplicates += 1;
                results.push(UsageCheckpointIngestResult {
                    event_id: checkpoint.event_id,
                    outcome: UsageCheckpointIngestOutcome::ExactReplay,
                    reason: None,
                });
            } else {
                let reason = "source epoch already has an immutable terminal receipt".to_owned();
                rejected.push(RejectedCheckpoint {
                    event_id: checkpoint.event_id.clone(),
                    reason: reason.clone(),
                });
                results.push(UsageCheckpointIngestResult {
                    event_id: checkpoint.event_id,
                    outcome: UsageCheckpointIngestOutcome::Rejected,
                    reason: Some(reason),
                });
            }
            continue;
        }
        let frozen_attribution = match state
            .usage
            .source_epoch_attribution(&checkpoint.source_id, &checkpoint.source_epoch)
            .await
        {
            Ok(attribution) => attribution,
            Err(error) => return metering_error(error),
        };
        let cat_id = match Id::new(checkpoint.cat_id.clone()) {
            Some(cat_id) => cat_id,
            None => return invalid("checkpoint cat_id is not canonical"),
        };
        let cat = match state
            .store
            .execute(move |store| store.get_runtime_cat_for_usage(&cat_id))
            .await
        {
            Ok(cat) => cat,
            Err(error) if transient_store_error(&error) => {
                return unavailable("usage attribution authority is unavailable")
            }
            Err(_) => return internal(),
        };
        let generation = match u64::try_from(checkpoint.cat_generation) {
            Ok(generation) => generation,
            Err(_) => return invalid("checkpoint Cat generation must be nonnegative"),
        };
        if let Some(cat) = cat.as_ref() {
            if generation > cat.desired_revision.get() {
                return conflict(format!(
                    "Cat {} checkpoint generation {} is newer than current {}",
                    checkpoint.cat_id,
                    checkpoint.cat_generation,
                    cat.desired_revision.get()
                ));
            }
        }
        let attribution = match select_checkpoint_attribution(
            frozen_attribution,
            cat,
            &checkpoint.cat_id,
            &request.node_id,
        ) {
            Ok(AttributionSelection::Frozen(attribution)) => attribution,
            Ok(AttributionSelection::Current(cat)) => {
                let workspace_id = cat.workspace_id.to_string();
                let billing_account_id =
                    match super::billing_account_id_for_workspace(state, &workspace_id).await {
                        Ok(account) => account,
                        Err(error) => return api_error(error),
                    };
                UsageAttribution {
                    billing_account_id,
                    workspace_id,
                    resource_type: "cat".to_owned(),
                    resource_id: checkpoint.cat_id.clone(),
                    attributed_cat_id: Some(checkpoint.cat_id.clone()),
                }
            }
            Ok(AttributionSelection::DeletedWithoutFrozen) => {
                let reason = format!(
                    "no frozen attribution exists for deleted Cat {} source epoch",
                    checkpoint.cat_id
                );
                tracing::warn!(
                    event = %checkpoint.event_id,
                    cat = %checkpoint.cat_id,
                    source_epoch = %checkpoint.source_epoch,
                    "rejecting an unattributable usage checkpoint; its usage is not billed"
                );
                rejected.push(RejectedCheckpoint {
                    event_id: checkpoint.event_id.clone(),
                    reason: reason.clone(),
                });
                results.push(UsageCheckpointIngestResult {
                    event_id: checkpoint.event_id,
                    outcome: UsageCheckpointIngestOutcome::Rejected,
                    reason: Some(reason),
                });
                continue;
            }
            Err(AttributionSelectionError::StoredAttributionMismatch) => {
                return conflict("stored source-epoch attribution does not match checkpoint Cat")
            }
            Err(AttributionSelectionError::CurrentNodeMismatch) => {
                return conflict(format!(
                    "node {} does not own Cat {}",
                    request.node_id, checkpoint.cat_id
                ))
            }
        };
        let value = AttributedCheckpoint {
            attribution,
            source_binding,
            checkpoint,
        };
        match state.usage.ingest(&value).await {
            Ok(IngestOutcome::Accepted) => {
                accepted += 1;
                results.push(UsageCheckpointIngestResult {
                    event_id: value.checkpoint.event_id.clone(),
                    outcome: UsageCheckpointIngestOutcome::Accepted,
                    reason: None,
                });
            }
            Ok(IngestOutcome::Duplicate) => {
                duplicates += 1;
                results.push(UsageCheckpointIngestResult {
                    event_id: value.checkpoint.event_id.clone(),
                    outcome: UsageCheckpointIngestOutcome::ExactReplay,
                    reason: None,
                });
            }
            Err(error) => return metering_error(error),
        }
    }
    Json(IngestUsageCheckpointsResponse {
        accepted,
        duplicates,
        rejected,
        results,
    })
    .into_response()
}

fn terminal_receipt_matches_checkpoint(
    receipt: &cats_metering::UsageSourceTerminalReceipt,
    source_binding: &RuntimeUsageSourceBinding,
    checkpoint: &CatUsageCheckpoint,
) -> bool {
    receipt.contract_version == 1
        && receipt.source_id == checkpoint.source_id
        && receipt.source_epoch == checkpoint.source_epoch
        && receipt.cat_id == checkpoint.cat_id
        && receipt.source_binding == *source_binding
        && receipt.final_sequence == checkpoint.sequence
        && receipt.final_observed_at_unix_ms == checkpoint.observed_at_unix_ms
        && checkpoint.epoch_marker == UsageEpochMarker::Final
        && receipt.final_events.iter().any(|event| {
            event.event_id == checkpoint.event_id
                && event.metric == checkpoint.metric
                && event.cumulative_quantity == checkpoint.cumulative_quantity
        })
}

fn validate_request_terminal_order(checkpoints: &[CatUsageCheckpoint]) -> Result<(), String> {
    let mut terminals = BTreeMap::<(&str, &str), (u64, i64, &str, i64, Vec<_>)>::new();
    for checkpoint in checkpoints {
        let key = (
            checkpoint.source_id.as_str(),
            checkpoint.source_epoch.as_str(),
        );
        match checkpoint.epoch_marker {
            UsageEpochMarker::Open => {
                if terminals.contains_key(&key) {
                    return Err(format!(
                        "source {}/{} has an open checkpoint after its final marker",
                        checkpoint.source_id, checkpoint.source_epoch
                    ));
                }
            }
            UsageEpochMarker::Final => {
                let terminal = terminals.entry(key).or_insert_with(|| {
                    (
                        checkpoint.sequence,
                        checkpoint.observed_at_unix_ms,
                        checkpoint.cat_id.as_str(),
                        checkpoint.cat_generation,
                        Vec::new(),
                    )
                });
                if terminal.0 != checkpoint.sequence
                    || terminal.1 != checkpoint.observed_at_unix_ms
                    || terminal.2 != checkpoint.cat_id
                    || terminal.3 != checkpoint.cat_generation
                    || terminal.4.contains(&checkpoint.metric)
                    || terminal.4.len() == 2
                {
                    return Err(format!(
                        "source {}/{} final checkpoint set is not one exact CPU/memory sample",
                        checkpoint.source_id, checkpoint.source_epoch
                    ));
                }
                terminal.4.push(checkpoint.metric);
            }
        }
    }
    Ok(())
}

fn runtime_source_binding(
    session: &SessionBinding,
    checkpoint: &CatUsageCheckpoint,
) -> Result<RuntimeUsageSourceBinding, String> {
    let desired_revision = u64::try_from(checkpoint.cat_generation)
        .ok()
        .and_then(Revision::new)
        .ok_or_else(|| "checkpoint Cat generation is not a Desired revision".to_string())?;
    let prefix = format!(
        "session:{}:{}:desired:{}:runtime:",
        session.agent_instance_id,
        session.agent_session_epoch.get(),
        desired_revision.get()
    );
    let remainder = checkpoint
        .source_epoch
        .strip_prefix(&prefix)
        .ok_or_else(|| {
            "checkpoint source_epoch does not bind the current AgentSession and Desired revision"
                .to_string()
        })?;
    let (runtime_incarnation, process_identity) = remainder
        .split_once(":processes:")
        .ok_or_else(|| "checkpoint source_epoch has no runtime process binding".to_string())?;
    let runtime_incarnation =
        RandomId128::new(runtime_incarnation.to_string()).ok_or_else(|| {
            "checkpoint source_epoch runtime incarnation is not canonical".to_string()
        })?;
    if process_identity.is_empty() {
        return Err("checkpoint source_epoch process binding is empty".to_string());
    }
    Ok(RuntimeUsageSourceBinding {
        session: session.clone(),
        desired_revision,
        runtime_incarnation,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum AttributionSelection {
    Frozen(UsageAttribution),
    Current(RuntimeUsageCatRead),
    DeletedWithoutFrozen,
}

#[derive(Debug, PartialEq, Eq)]
enum AttributionSelectionError {
    StoredAttributionMismatch,
    CurrentNodeMismatch,
}

/// Frozen source-epoch attribution remains authoritative after placement changes or deletion.
/// Current placement is consulted only while establishing attribution for a new source epoch.
fn select_checkpoint_attribution(
    frozen_attribution: Option<UsageAttribution>,
    current_cat: Option<RuntimeUsageCatRead>,
    checkpoint_cat_id: &str,
    request_node_id: &str,
) -> Result<AttributionSelection, AttributionSelectionError> {
    if let Some(attribution) = frozen_attribution {
        let workspace_id = current_cat.as_ref().map(|cat| cat.workspace_id.as_str());
        if !cat_attribution_matches(&attribution, checkpoint_cat_id, workspace_id) {
            return Err(AttributionSelectionError::StoredAttributionMismatch);
        }
        return Ok(AttributionSelection::Frozen(attribution));
    }

    let Some(cat) = current_cat else {
        return Ok(AttributionSelection::DeletedWithoutFrozen);
    };
    if cat.node_id.as_str() != request_node_id {
        return Err(AttributionSelectionError::CurrentNodeMismatch);
    }
    Ok(AttributionSelection::Current(cat))
}

fn cat_attribution_matches(
    attribution: &UsageAttribution,
    cat_id: &str,
    workspace_id: Option<&str>,
) -> bool {
    attribution.resource_type == "cat"
        && attribution.resource_id == cat_id
        && attribution.attributed_cat_id.as_deref() == Some(cat_id)
        && workspace_id.is_none_or(|workspace| attribution.workspace_id == workspace)
}

fn transient_store_error(error: &ApiError) -> bool {
    matches!(
        error.code,
        ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
    )
}

fn single_header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn declared_body_exceeds_limit(headers: &HeaderMap, maximum: usize) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_none_or(|length| length > maximum as u64)
}

fn authentication_failed() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        ErrorCode::Unauthenticated,
        "usage checkpoint authentication failed",
        &[(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(NODE_AUTHENTICATE_CHALLENGE),
        )],
    )
}

fn invalid(message: impl Into<String>) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidArgument,
        message,
        &[],
    )
}

fn conflict(message: impl Into<String>) -> Response {
    error_response(StatusCode::CONFLICT, ErrorCode::Conflict, message, &[])
}

fn unavailable(message: impl Into<String>) -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unavailable,
        message,
        &[],
    )
}

fn deadline_exceeded() -> Response {
    error_response(
        StatusCode::GATEWAY_TIMEOUT,
        ErrorCode::DeadlineExceeded,
        "usage checkpoint request exceeded its deadline",
        &[],
    )
}

fn internal() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::Internal,
        "usage checkpoint ingestion failed internally",
        &[],
    )
}

fn api_error(error: ApiError) -> Response {
    let status =
        StatusCode::from_u16(error.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    error_response(status, error.code, error.message, &[])
}

fn metering_error(error: cats_metering::MeteringError) -> Response {
    match error {
        cats_metering::MeteringError::Invalid(message) => invalid(message),
        cats_metering::MeteringError::Conflict(message) => conflict(message),
        other => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            other.to_string(),
            &[],
        ),
    }
}

fn error_response(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let mut response = (status, Json(ErrorBody::new(code, message))).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in extra_headers {
        response.headers_mut().insert(name, value.clone());
    }
    response
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::Revision;

    use super::*;

    fn current_cat(node_id: &str) -> RuntimeUsageCatRead {
        RuntimeUsageCatRead {
            workspace_id: Id::new("workspace_a").unwrap(),
            desired_revision: Revision::new(2).unwrap(),
            node_id: Id::new(node_id).unwrap(),
        }
    }

    fn frozen_attribution() -> UsageAttribution {
        UsageAttribution {
            billing_account_id: "billing_a".to_owned(),
            workspace_id: "workspace_a".to_owned(),
            resource_type: "cat".to_owned(),
            resource_id: "cat_a".to_owned(),
            attributed_cat_id: Some("cat_a".to_owned()),
        }
    }

    #[test]
    fn frozen_attribution_precedes_current_node_ownership() {
        let frozen = frozen_attribution();

        let selected = select_checkpoint_attribution(
            Some(frozen.clone()),
            Some(current_cat("node_b")),
            "cat_a",
            "node_a",
        );

        assert_eq!(selected, Ok(AttributionSelection::Frozen(frozen)));
    }

    #[test]
    fn current_cat_without_frozen_attribution_requires_request_node() {
        let selected =
            select_checkpoint_attribution(None, Some(current_cat("node_b")), "cat_a", "node_a");

        assert_eq!(
            selected,
            Err(AttributionSelectionError::CurrentNodeMismatch)
        );
    }

    #[test]
    fn deleted_cat_without_frozen_attribution_is_rejected() {
        let selected = select_checkpoint_attribution(None, None, "cat_a", "node_a");

        assert_eq!(selected, Ok(AttributionSelection::DeletedWithoutFrozen));
    }

    #[test]
    fn frozen_attribution_must_match_the_current_workspace() {
        let mut frozen = frozen_attribution();
        frozen.workspace_id = "workspace_b".to_owned();

        let selected = select_checkpoint_attribution(
            Some(frozen),
            Some(current_cat("node_a")),
            "cat_a",
            "node_a",
        );

        assert_eq!(
            selected,
            Err(AttributionSelectionError::StoredAttributionMismatch)
        );
    }
}

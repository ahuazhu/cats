//! Trusted ingestion of Node-produced usage checkpoints.
//!
//! Producers report a Cat, a meter and a cumulative integer. They never choose
//! a tenant, a Billing Account or a price. This boundary is where ADR-0011's
//! attribution is frozen: the first checkpoint of a source epoch binds the
//! Workspace and Billing Account that owned the Cat at that moment, and every
//! later checkpoint of the same epoch reuses that frozen binding — so the tail
//! of a destroyed Cat still bills its original owner and can never be
//! re-pointed by a Node.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::routing::post;
use axum::{Json, Router};
use cats_api::error::ApiError;
use cats_api::metering::{
    IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse, RejectedCheckpoint,
    UsageCheckpointIngestOutcome, UsageCheckpointIngestResult, MAX_USAGE_CHECKPOINTS_PER_REQUEST,
    MAX_USAGE_INGEST_BODY_BYTES, USAGE_CHECKPOINTS_PATH,
};
use cats_api::runtime_reconciliation::{RandomId128, Revision};
use cats_metering::{
    AttributedCheckpoint, IngestOutcome, RuntimeUsageSourceBinding, UsageAttribution,
};

use super::semantic_nodes::{authenticate, SemanticNodeHttpFailure, SemanticNodeHttpState};
use crate::server::AppState;

/// `resource_type` for compute metered against a Cat runtime.
const CAT_RESOURCE_TYPE: &str = "cat";

pub(super) fn routes(state: SemanticNodeHttpState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(USAGE_CHECKPOINTS_PATH, post(ingest))
        .layer(axum::extract::DefaultBodyLimit::max(
            MAX_USAGE_INGEST_BODY_BYTES,
        ))
        .layer(Extension(Arc::new(state)))
}

/// Immutable billing ownership of one Cat, resolved once per request.
#[derive(Debug, Clone)]
struct CatAttribution {
    workspace_id: String,
    billing_account_id: String,
}

/// Why a Cat can or cannot open a usage epoch on the reporting Node.
#[derive(Debug, Clone)]
enum CatAttributionLookup {
    Owned(CatAttribution),
    /// No such Cat in this deployment.
    Unknown,
    /// The Cat exists but Control has it somewhere else. The service token is
    /// shared by the whole Node fleet, so identity alone proves nothing about
    /// which Cats a caller may charge; placement is what binds the two.
    NotPlacedHere,
}

async fn ingest(
    State(app): State<AppState>,
    Extension(state): Extension<Arc<SemanticNodeHttpState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<IngestUsageCheckpointsRequest>,
) -> Result<Json<IngestUsageCheckpointsResponse>, SemanticNodeHttpFailure> {
    authenticate(&headers, state.service_token())?;
    if request.checkpoints.len() > MAX_USAGE_CHECKPOINTS_PER_REQUEST {
        return Err(ApiError::invalid(format!(
            "at most {MAX_USAGE_CHECKPOINTS_PER_REQUEST} checkpoints are allowed per request"
        ))
        .into());
    }
    if request.node_id != request.session.node_id.as_str() {
        return Err(
            ApiError::conflict("usage checkpoint node_id does not match its producer").into(),
        );
    }
    let node_id = request.node_id.clone();
    let known_node = {
        let lookup = node_id.clone();
        app.store
            .execute(move |store| store.find_semantic_node(&lookup))
            .await?
    };
    if known_node.is_none() {
        return Err(ApiError::not_found("Node").into());
    }

    let mut response = IngestUsageCheckpointsResponse {
        accepted: 0,
        duplicates: 0,
        rejected: Vec::new(),
        results: Vec::with_capacity(request.checkpoints.len()),
    };
    let mut resolved = BTreeMap::<String, CatAttributionLookup>::new();
    for checkpoint in request.checkpoints {
        let expected_source = format!("node/{node_id}/cat/{}", checkpoint.cat_id);
        if checkpoint.source_id != expected_source {
            return Err(ApiError::invalid(format!(
                "checkpoint source_id must be {expected_source}"
            ))
            .into());
        }
        let Some(runtime_incarnation) = RandomId128::new(checkpoint.source_epoch.clone()) else {
            return Err(ApiError::invalid(
                "checkpoint source_epoch must be the Cat's runtime incarnation",
            )
            .into());
        };
        let Some(desired_revision) = u64::try_from(checkpoint.cat_generation)
            .ok()
            .and_then(Revision::new)
        else {
            return Err(
                ApiError::invalid("checkpoint cat_generation is outside the wire range").into(),
            );
        };

        // A frozen epoch attribution wins over current state: a Cat that has
        // since been destroyed, or moved, must not redirect the money.
        let frozen = app
            .usage
            .source_epoch_attribution(&checkpoint.source_id, &checkpoint.source_epoch)
            .await
            .map_err(metering_error)?;
        let attribution = match frozen {
            Some(attribution) => attribution,
            None => {
                let current = match resolved.get(&checkpoint.cat_id) {
                    Some(cached) => cached.clone(),
                    None => {
                        let lookup =
                            resolve_cat_attribution(&app, &checkpoint.cat_id, &node_id).await?;
                        resolved.insert(checkpoint.cat_id.clone(), lookup.clone());
                        lookup
                    }
                };
                let current = match current {
                    CatAttributionLookup::Owned(attribution) => attribution,
                    // Named, not retried: the ordered batch behind it still
                    // settles and the producer stops resending this event. A
                    // Node whose placement row has not caught up yet loses one
                    // checkpoint, not the epoch, because the next cumulative
                    // sample resolves attribution again from scratch.
                    other => {
                        let reason = match other {
                            CatAttributionLookup::Unknown => {
                                "checkpoint Cat has no billing owner in this deployment"
                            }
                            CatAttributionLookup::NotPlacedHere => {
                                "checkpoint Cat is not placed on the reporting Node"
                            }
                            CatAttributionLookup::Owned(_) => unreachable!("handled above"),
                        }
                        .to_owned();
                        tracing::warn!(
                            node_id = node_id.as_str(),
                            cat_id = checkpoint.cat_id.as_str(),
                            reason = reason.as_str(),
                            "refused a usage checkpoint"
                        );
                        response.rejected.push(RejectedCheckpoint {
                            event_id: checkpoint.event_id.clone(),
                            reason: reason.clone(),
                        });
                        response.results.push(UsageCheckpointIngestResult {
                            event_id: checkpoint.event_id,
                            outcome: UsageCheckpointIngestOutcome::Rejected,
                            reason: Some(reason),
                        });
                        continue;
                    }
                };
                UsageAttribution {
                    billing_account_id: current.billing_account_id,
                    workspace_id: current.workspace_id,
                    resource_type: CAT_RESOURCE_TYPE.to_owned(),
                    resource_id: checkpoint.cat_id.clone(),
                    attributed_cat_id: Some(checkpoint.cat_id.clone()),
                }
            }
        };

        let event_id = checkpoint.event_id.clone();
        let attributed = AttributedCheckpoint {
            checkpoint,
            attribution,
            source_binding: RuntimeUsageSourceBinding {
                session: request.session.clone(),
                desired_revision,
                runtime_incarnation,
            },
        };
        match app.usage.ingest(&attributed).await {
            Ok(IngestOutcome::Accepted) => {
                response.accepted += 1;
                response.results.push(UsageCheckpointIngestResult {
                    event_id,
                    outcome: UsageCheckpointIngestOutcome::Accepted,
                    reason: None,
                });
            }
            Ok(IngestOutcome::Duplicate) => {
                response.duplicates += 1;
                response.results.push(UsageCheckpointIngestResult {
                    event_id,
                    outcome: UsageCheckpointIngestOutcome::ExactReplay,
                    reason: None,
                });
            }
            // A checkpoint the ledger can never accept is named, not retried:
            // the rest of the ordered batch still settles.
            Err(cats_metering::MeteringError::Invalid(message))
            | Err(cats_metering::MeteringError::Conflict(message)) => {
                response.rejected.push(RejectedCheckpoint {
                    event_id: event_id.clone(),
                    reason: message.clone(),
                });
                response.results.push(UsageCheckpointIngestResult {
                    event_id,
                    outcome: UsageCheckpointIngestOutcome::Rejected,
                    reason: Some(message),
                });
            }
            Err(error) => return Err(metering_error(error).into()),
        }
    }
    Ok(Json(response))
}

/// Resolve who pays for a Cat, and prove the reporting Node may charge it.
///
/// `node_id` is accepted from either the settled placement or the Node that
/// currently owns an in-progress action on the Cat: a create publishes its
/// first checkpoint while `cats.node_id` is still NULL, and a planned drain
/// leaves the source settled while the target owns the action. Both of those
/// Nodes really are running the Cat.
async fn resolve_cat_attribution(
    app: &AppState,
    cat_id: &str,
    node_id: &str,
) -> Result<CatAttributionLookup, SemanticNodeHttpFailure> {
    let lookup = cat_id.to_owned();
    let reporter = node_id.to_owned();
    let resolved = app
        .store
        .execute(move |store| {
            let Some(cat) = store.find_semantic_cat_by_id(&lookup)? else {
                return Ok(CatAttributionLookup::Unknown);
            };
            let placed_here = cat.node_id.as_deref() == Some(reporter.as_str())
                || cat.current_action_node_id.as_deref() == Some(reporter.as_str());
            if !placed_here {
                return Ok(CatAttributionLookup::NotPlacedHere);
            }
            let ledger = store.billing_ledger_for_workspace(&cat.workspace_id)?;
            Ok(CatAttributionLookup::Owned(CatAttribution {
                workspace_id: cat.workspace_id,
                billing_account_id: ledger.billing_account_id,
            }))
        })
        .await?;
    Ok(resolved)
}

fn metering_error(error: cats_metering::MeteringError) -> ApiError {
    match error {
        cats_metering::MeteringError::Invalid(message) => ApiError::invalid(message),
        cats_metering::MeteringError::Conflict(message) => ApiError::conflict(message),
        other => ApiError::internal(other.to_string()),
    }
}

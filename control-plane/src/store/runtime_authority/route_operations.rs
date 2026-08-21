//! PostgreSQL mutations for the atomic per-Endpoint Route lane.
//!
//! Callers own the enclosing authority transaction. The lifecycle close path
//! enters here after locking the Cat and exact lifecycle Operation; this
//! module then locks Endpoint rows in canonical ID order before touching any
//! Route Operation. That is the shared Cat -> lifecycle Operation -> Endpoint
//! -> Route Operation lock order.

use cats_api::agent_registration::{AuthenticatedNodeCredential, AGENT_SESSION_LEASE_MS};
use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    AgentSession, ContractVersion, Epoch, Hostname, HttpProtocol, Id, SessionBinding, UnixMillis,
};
use cats_api::runtime_route::{
    encode_route_command_envelope, encode_route_command_response,
    encode_route_control_invalidation, encode_route_node_ring_ack,
    validate_route_command_batch_for_poll, validate_route_command_poll_request,
    validate_route_result_commit_for_command, validate_route_result_commit_request, RouteCommand,
    RouteCommandBatch, RouteCommandPollRequest, RouteCommandPredecessor, RouteCommandResponse,
    RouteControlInvalidation, RouteControlInvalidationReason, RouteNodeResult, RouteOperation,
    RouteOperationState, RouteOperationTerminal, RouteResultCommitRequest, RouteResultStoredAck,
    RouteTerminalResultKind, ROUTE_COMMAND_BATCH_MAX_COMMANDS,
};
use postgres::{Row, Transaction};

use super::lifecycle_commands::{
    authenticate_session, load_lifecycle_route_authority_for_update_in,
    load_lifecycle_route_authority_snapshot_in, LifecycleRouteAuthority, LifecycleSessionRejection,
    LifecycleStableState,
};
use super::pg_codec::PgBigInt;
use super::route_epoch_engine::LifecycleAdmissionCloseOutcome;
use super::route_epoch_engine::{
    plan_atomic_endpoint_route, AtomicEndpointRouteAuthority, AtomicRouteControllerAction,
    AtomicRouteLifecycleAuthority, AtomicRouteLifecycleState, CurrentEndpointBinding,
    RouteEpochInvalidationPlan,
};
use super::route_signer::decode_route_operation_row;
use super::rows::database_now;
use crate::store::agent_sessions::{
    load_current_session_for_update, renew_current_session_deadline,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{internal, Result, Store};

const ROUTE_OPERATION_COLUMNS: &str = "
    operation_id, workspace_id, cat_id, endpoint_id, operation_kind,
    canonical_request_bytes, canonical_request_sha256,
    expected_predecessor_operation_id, expected_predecessor_result_kind,
    expected_predecessor_result_sha256, hostname, protocol, target_port,
    route_epoch, source_lifecycle_operation_id, runtime_incarnation, node_id,
    placement_epoch, node_boot_id, agent_instance_id,
    admission_session_epoch, state, terminal_source, terminal_result_kind,
    canonical_result_bytes, canonical_result_sha256, created_at_unix_ms,
    terminal_at_unix_ms";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteCommandPollOutcome {
    Batch(RouteCommandBatch),
    Rejected(RouteCommandPollRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteCommandPollRejection {
    InvalidContract,
    Session(LifecycleSessionRejection),
    RingAcknowledgementConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteResultCommitOutcome {
    Stored {
        operation: RouteOperation,
        acknowledgement: RouteResultStoredAck,
    },
    ExactReplay {
        operation: RouteOperation,
        acknowledgement: RouteResultStoredAck,
    },
    Superseded {
        operation: RouteOperation,
    },
    Rejected(RouteResultCommitRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteResultCommitRejection {
    InvalidContract,
    Session(LifecycleSessionRejection),
    OperationNotFound,
    OperationNotCurrent { current_operation_id: Option<Id> },
    ConflictingTerminalResult { operation_id: Id },
}

pub(crate) const ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteControllerPage {
    pub(crate) examined: usize,
    pub(crate) mutations: usize,
    pub(crate) failures: usize,
    /// `None` means the ordered scan reached the end and the next pass starts
    /// from the first Endpoint. A full page retains its last exact Endpoint ID.
    pub(crate) next_after_endpoint_id: Option<Id>,
}

#[derive(Debug, Clone)]
struct RouteControllerCandidate {
    workspace_id: Id,
    cat_id: Id,
    endpoint_id: Id,
}

impl Store {
    /// Poll the independent per-Endpoint Route lanes for one authenticated
    /// current AgentSession. A valid public-ring ACK advances its own durable
    /// monotonic row in this same transaction; it never creates lifecycle or
    /// Serving authority.
    pub(crate) fn poll_route_commands(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        poll: &RouteCommandPollRequest,
    ) -> Result<RouteCommandPollOutcome> {
        if validate_route_command_poll_request(poll).is_err() {
            return Ok(RouteCommandPollOutcome::Rejected(
                RouteCommandPollRejection::InvalidContract,
            ));
        }
        self.authority_transaction(|transaction| {
            poll_route_commands_in(transaction, authenticated, poll)
        })
    }

    /// Commit one exact Node AdmissionCell result. The authenticated path
    /// locks credential lineage and AgentSession before entering the Cat ->
    /// lifecycle Operation -> Endpoint -> Route Operation order.
    pub(crate) fn commit_route_result(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        commit: &RouteResultCommitRequest,
    ) -> Result<RouteResultCommitOutcome> {
        if validate_route_result_commit_request(commit).is_err() {
            return Ok(RouteResultCommitOutcome::Rejected(
                RouteResultCommitRejection::InvalidContract,
            ));
        }
        self.authority_transaction(|transaction| {
            commit_route_result_in(transaction, authenticated, commit)
        })
    }

    /// Reconcile one bounded ordered page of Endpoint metadata into the
    /// independent Route command lanes. Candidate discovery is deliberately
    /// non-authoritative; each Endpoint is reloaded under the global
    /// Session -> Cat -> lifecycle Operation -> Endpoint -> Route Operation
    /// lock order before a command or invalidation can commit.
    pub(crate) fn reconcile_route_controller_page(
        &self,
        after_endpoint_id: Option<&Id>,
        limit: usize,
    ) -> Result<RouteControllerPage> {
        if limit == 0 || limit > ROUTE_CONTROLLER_PAGE_MAX_ENDPOINTS {
            return Err(ApiError::failed_precondition(
                "Route controller page limit is outside the closed bound",
            ));
        }
        let candidates = self.authority_transaction(|transaction| {
            list_route_controller_candidates(transaction, after_endpoint_id, limit)
        })?;
        let examined = candidates.len();
        let last = candidates
            .last()
            .map(|candidate| candidate.endpoint_id.clone());
        let mut mutations = 0usize;
        let mut failures = 0usize;
        let mut completed = 0usize;
        let mut first_failure = None;
        for candidate in candidates {
            // Generated outside the retrying transaction closure so an
            // ambiguous PostgreSQL attempt replays one exact operation ID.
            let proposed_operation_id = Id::new(format!("route_{}", uuid::Uuid::new_v4().simple()))
                .ok_or_else(|| ApiError::internal("cannot construct Route operation identity"))?;
            let result = self.authority_transaction(|transaction| {
                reconcile_route_controller_candidate(
                    transaction,
                    &candidate,
                    &proposed_operation_id,
                )
            });
            match result {
                Ok(changed) => {
                    completed = completed.checked_add(1).ok_or_else(|| {
                        ApiError::internal("Route controller completion count overflow")
                    })?;
                    mutations = mutations.checked_add(usize::from(changed)).ok_or_else(|| {
                        ApiError::internal("Route controller mutation count overflow")
                    })?;
                }
                Err(error) => {
                    failures = failures.checked_add(1).ok_or_else(|| {
                        ApiError::internal("Route controller failure count overflow")
                    })?;
                    tracing::warn!(
                        cat_id = %candidate.cat_id,
                        endpoint_id = %candidate.endpoint_id,
                        %error,
                        "one Endpoint Route candidate failed without aborting its sibling page"
                    );
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
        }
        // A backend-wide failure generally affects every candidate. Preserve
        // that signal instead of reporting a successful page. As soon as one
        // independent candidate completed, however, the failed Cat cannot
        // pin the ordered cursor in front of healthy siblings forever.
        if completed == 0 {
            if let Some(error) = first_failure {
                return Err(error);
            }
        }
        Ok(RouteControllerPage {
            examined,
            mutations,
            failures,
            next_after_endpoint_id: (examined == limit).then_some(last).flatten(),
        })
    }
}

fn list_route_controller_candidates(
    transaction: &mut Transaction<'_>,
    after_endpoint_id: Option<&Id>,
    limit: usize,
) -> AuthorityTxResult<Vec<RouteControllerCandidate>> {
    let limit =
        i64::try_from(limit).map_err(|_| corrupt("Route controller page limit overflow"))?;
    transaction
        .query(
            "SELECT workspace_id, cat_id, endpoint_id
               FROM endpoint_records
              WHERE ($1::text IS NULL OR endpoint_id COLLATE \"C\" > $1 COLLATE \"C\")
              ORDER BY endpoint_id COLLATE \"C\" LIMIT $2",
            &[&after_endpoint_id.map(Id::as_str), &limit],
        )?
        .iter()
        .map(|row| {
            Ok(RouteControllerCandidate {
                workspace_id: parse_id(row.try_get("workspace_id")?)?,
                cat_id: parse_id(row.try_get("cat_id")?)?,
                endpoint_id: parse_id(row.try_get("endpoint_id")?)?,
            })
        })
        .collect()
}

fn reconcile_route_controller_candidate(
    transaction: &mut Transaction<'_>,
    candidate: &RouteControllerCandidate,
    proposed_operation_id: &Id,
) -> AuthorityTxResult<bool> {
    // Locate the session before taking the Cat lock. The snapshot is not
    // authority and is revalidated after Session -> Cat are both locked.
    let Some(snapshot) = load_lifecycle_route_authority_snapshot_in(
        transaction,
        &candidate.workspace_id,
        &candidate.cat_id,
    )?
    else {
        return Ok(false);
    };
    let locked_session = match snapshot.current_placement.as_ref() {
        Some(placement) => load_current_session_for_update(transaction, &placement.node_id)?,
        None => None,
    };
    let Some(lifecycle) = load_lifecycle_route_authority_for_update_in(
        transaction,
        &candidate.workspace_id,
        &candidate.cat_id,
    )?
    else {
        return Ok(false);
    };
    if lifecycle
        .current_placement
        .as_ref()
        .map(|value| &value.node_id)
        != snapshot
            .current_placement
            .as_ref()
            .map(|value| &value.node_id)
    {
        // A different Node would require taking a different Session lock
        // after the Cat lock. Defer instead; the next tick restarts in the
        // global lock order.
        return Ok(false);
    }
    let session_binding = match locked_session.as_ref() {
        Some(session) if database_now(transaction)? < session.lease_deadline_unix_ms => {
            Some(agent_session_binding(session))
        }
        Some(_) | None => None,
    };
    let endpoint = load_atomic_endpoint_for_update(transaction, candidate)?;
    let Some(endpoint) = endpoint else {
        return Ok(false);
    };
    let lifecycle = atomic_lifecycle_authority(lifecycle);
    match plan_atomic_endpoint_route(&endpoint, &lifecycle, session_binding.as_ref())
        .map_err(AuthorityTransactionError::Application)?
    {
        AtomicRouteControllerAction::Submit(draft) => {
            insert_route_command(transaction, proposed_operation_id, *draft)?;
            Ok(true)
        }
        AtomicRouteControllerAction::Invalidate(plan) => {
            apply_route_invalidation_plan(transaction, &endpoint, &plan)?;
            Ok(true)
        }
        AtomicRouteControllerAction::Quiescent
        | AtomicRouteControllerAction::AwaitingOperation { .. }
        | AtomicRouteControllerAction::BlockedByLifecycle
        | AtomicRouteControllerAction::RunRequired
        | AtomicRouteControllerAction::Gone
        | AtomicRouteControllerAction::Unavailable => Ok(false),
    }
}

fn atomic_lifecycle_authority(lifecycle: LifecycleRouteAuthority) -> AtomicRouteLifecycleAuthority {
    let state = if lifecycle.deleted_at.is_some() {
        AtomicRouteLifecycleState::Deleted
    } else if lifecycle.stable_state == Some(LifecycleStableState::Running) {
        AtomicRouteLifecycleState::Running
    } else {
        AtomicRouteLifecycleState::NotRunning
    };
    AtomicRouteLifecycleAuthority {
        workspace_id: lifecycle.workspace_id,
        cat_id: lifecycle.cat_id,
        lifecycle_head_operation_id: lifecycle
            .lifecycle_head
            .as_ref()
            .map(|operation| operation.operation_id.clone()),
        state,
        current_placement: lifecycle.current_placement,
        effective_runtime_ready: lifecycle
            .effective_runtime_ready
            .map(|authority| authority.evidence),
        unresolved_leaves_running: lifecycle.unresolved_leaves_running,
    }
}

fn load_atomic_endpoint_for_update(
    transaction: &mut Transaction<'_>,
    candidate: &RouteControllerCandidate,
) -> AuthorityTxResult<Option<AtomicEndpointRouteAuthority>> {
    let locator = RouteOperationLocator {
        workspace_id: candidate.workspace_id.clone(),
        cat_id: candidate.cat_id.clone(),
        endpoint_id: candidate.endpoint_id.clone(),
    };
    let Some(endpoint) = load_endpoint_for_update(transaction, &locator)? else {
        return Ok(None);
    };
    let route_head = endpoint
        .route
        .route_head_operation_id
        .as_ref()
        .map(|operation_id| load_route_operation_for_update(transaction, operation_id))
        .transpose()?
        .flatten();
    if endpoint.route.route_head_operation_id.is_some() && route_head.is_none() {
        return Err(corrupt("Endpoint Route head Operation is missing"));
    }
    let effective_serving = match endpoint.route.effective_serving_operation_id.as_ref() {
        Some(operation_id)
            if endpoint.route.route_head_operation_id.as_ref() == Some(operation_id) =>
        {
            route_head.clone()
        }
        Some(operation_id) => load_route_operation_for_update(transaction, operation_id)?,
        None => None,
    };
    if endpoint.route.effective_serving_operation_id.is_some() && effective_serving.is_none() {
        return Err(corrupt("Endpoint effective Serving Operation is missing"));
    }
    let unresolved_operation = load_unresolved_route_operation_for_update(
        transaction,
        &candidate.workspace_id,
        &candidate.cat_id,
        &candidate.endpoint_id,
    )?;
    let binding = match endpoint.binding_state.as_str() {
        "bound" => Some(CurrentEndpointBinding {
            workspace_id: candidate.workspace_id.clone(),
            cat_id: candidate.cat_id.clone(),
            endpoint_id: candidate.endpoint_id.clone(),
            hostname: Hostname::new(
                endpoint
                    .hostname
                    .ok_or_else(|| corrupt("bound Endpoint lacks hostname"))?,
            )
            .ok_or_else(|| corrupt("stored Endpoint hostname is invalid"))?,
            protocol: match endpoint.protocol.as_deref() {
                Some("http") => HttpProtocol::Http,
                _ => {
                    return Err(corrupt(
                        "stored Endpoint protocol is outside the closed set",
                    ))
                }
            },
            target_port: endpoint
                .target_port
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| corrupt("stored Endpoint target port is invalid"))?,
        }),
        "unbound"
            if endpoint.hostname.is_none()
                && endpoint.protocol.is_none()
                && endpoint.target_port.is_none() =>
        {
            None
        }
        _ => return Err(corrupt("stored Endpoint binding projection is invalid")),
    };
    Ok(Some(AtomicEndpointRouteAuthority {
        workspace_id: candidate.workspace_id.clone(),
        cat_id: candidate.cat_id.clone(),
        endpoint_id: candidate.endpoint_id.clone(),
        binding,
        route_epoch: endpoint.route.route_epoch,
        route_head,
        effective_serving,
        unresolved_operation,
    }))
}

fn load_unresolved_route_operation_for_update(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    endpoint_id: &Id,
) -> AuthorityTxResult<Option<RouteOperation>> {
    let sql = format!(
        "SELECT {ROUTE_OPERATION_COLUMNS} FROM route_operations
          WHERE workspace_id=$1 AND cat_id=$2 AND endpoint_id=$3
            AND state='unresolved'
          ORDER BY operation_id COLLATE \"C\" FOR UPDATE"
    );
    let rows = transaction.query(
        &sql,
        &[
            &workspace_id.as_str(),
            &cat_id.as_str(),
            &endpoint_id.as_str(),
        ],
    )?;
    if rows.len() > 1 {
        return Err(corrupt(
            "Endpoint has more than one unresolved Route Operation",
        ));
    }
    rows.first().map(decode_route_operation_row).transpose()
}

fn insert_route_command(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
    draft: super::route_epoch_engine::AtomicRouteCommandDraft,
) -> AuthorityTxResult<()> {
    let command = draft
        .into_envelope(operation_id.clone())
        .map_err(AuthorityTransactionError::Application)?;
    let canonical = encode_route_command_envelope(&command)
        .map_err(|_| corrupt("cannot encode exact Route command"))?;
    let (predecessor_operation_id, predecessor_result_kind, predecessor_result_digest) =
        match &command.predecessor {
            RouteCommandPredecessor::Genesis => (None, None, None),
            RouteCommandPredecessor::Exact {
                operation_id,
                terminal_result_kind,
                terminal_result_digest,
            } => (
                Some(operation_id.as_str()),
                Some(terminal_result_kind_text(*terminal_result_kind)),
                Some(terminal_result_digest.as_str()),
            ),
        };
    let operation_kind = match command.command {
        RouteCommand::Enable => "enable",
        RouteCommand::Disable => "disable",
    };
    let binding = &command.binding;
    let created_at = database_now(transaction)?;
    let changed = transaction.execute(
        "INSERT INTO route_operations (
            operation_id, workspace_id, cat_id, endpoint_id, operation_kind,
            canonical_request_bytes, canonical_request_sha256,
            expected_predecessor_operation_id, expected_predecessor_result_kind,
            expected_predecessor_result_sha256, hostname, protocol, target_port,
            route_epoch, source_lifecycle_operation_id, runtime_incarnation,
            node_id, placement_epoch, node_boot_id, agent_instance_id,
            admission_session_epoch, state, terminal_source,
            terminal_result_kind, canonical_result_bytes,
            canonical_result_sha256, created_at_unix_ms, terminal_at_unix_ms
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'http',$12,$13,$14,$15,
            $16,$17,$18,$19,$20,'unresolved',NULL,NULL,NULL,NULL,$21,NULL
         )",
        &[
            &command.operation_id.as_str(),
            &binding.workspace_id.as_str(),
            &binding.cat_id.as_str(),
            &binding.endpoint_id.as_str(),
            &operation_kind,
            &canonical,
            &command.request_fingerprint.as_str(),
            &predecessor_operation_id,
            &predecessor_result_kind,
            &predecessor_result_digest,
            &binding.hostname.as_str(),
            &i32::from(binding.target_port),
            &binding.route_epoch.to_pg().map_err(corrupt)?,
            &binding
                .effective_runtime_ready
                .source_lifecycle_operation_id
                .as_str(),
            &binding.effective_runtime_ready.runtime_incarnation.as_str(),
            &binding.placement_identity.node_id.as_str(),
            &binding
                .placement_identity
                .placement_epoch
                .to_pg()
                .map_err(corrupt)?,
            &binding.admission_session.node_boot_id.as_str(),
            &binding.admission_session.agent_instance_id.as_str(),
            &binding
                .admission_session
                .agent_session_epoch
                .to_pg()
                .map_err(corrupt)?,
            &created_at.to_pg().map_err(corrupt)?,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("Route command admission changed no row"));
    }
    Ok(())
}

fn apply_route_invalidation_plan(
    transaction: &mut Transaction<'_>,
    endpoint: &AtomicEndpointRouteAuthority,
    plan: &RouteEpochInvalidationPlan,
) -> AuthorityTxResult<()> {
    if plan.endpoint_id != endpoint.endpoint_id
        || plan.expected_route_epoch != endpoint.route_epoch
        || plan.clear_effective_serving != endpoint.effective_serving.is_some()
    {
        return Err(corrupt(
            "Route invalidation plan drifted from locked Endpoint",
        ));
    }
    let terminalized = match plan.invalidate_unresolved_operation_id.as_ref() {
        Some(operation_id) => {
            let operation = endpoint
                .unresolved_operation
                .as_ref()
                .filter(|operation| &operation.operation_id == operation_id)
                .ok_or_else(|| corrupt("Route invalidation names another unresolved Operation"))?;
            let terminal_at =
                max_unix_millis(database_now(transaction)?, operation.created_at_unix_ms);
            let invalidation = RouteControlInvalidation::new(
                endpoint.endpoint_id.clone(),
                operation.operation_id.clone(),
                plan.reason,
                plan.invalidating_lifecycle_operation_id.clone(),
                plan.replacement_session.clone(),
                plan.resulting_route_epoch,
                terminal_at,
            )
            .map_err(|_| corrupt("cannot encode planned Route invalidation"))?;
            terminalize_with_control_invalidation(
                transaction,
                &LockedUnresolvedRouteOperation {
                    operation_id: operation.operation_id.clone(),
                    route_epoch: operation.canonical_request.binding.route_epoch,
                    created_at_unix_ms: operation.created_at_unix_ms,
                },
                &invalidation,
            )?;
            Some(operation.operation_id.clone())
        }
        None => None,
    };
    let now = database_now(transaction)?;
    update_endpoint_after_invalidation(
        transaction,
        &LockedEndpointRoute {
            endpoint_id: endpoint.endpoint_id.clone(),
            route_epoch: endpoint.route_epoch,
            route_head_operation_id: endpoint
                .route_head
                .as_ref()
                .map(|operation| operation.operation_id.clone()),
            effective_serving_operation_id: endpoint
                .effective_serving
                .as_ref()
                .map(|operation| operation.operation_id.clone()),
        },
        plan.resulting_route_epoch,
        terminalized.as_ref(),
        now,
    )
}

fn agent_session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn poll_route_commands_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    poll: &RouteCommandPollRequest,
) -> AuthorityTxResult<RouteCommandPollOutcome> {
    let session = match authenticate_session(transaction, authenticated, &poll.session)? {
        Ok(session) => session,
        Err(rejection) => {
            return Ok(RouteCommandPollOutcome::Rejected(
                RouteCommandPollRejection::Session(rejection),
            ));
        }
    };
    if cats_api::runtime_route::validate_route_command_poll_for_session(poll, &session).is_err() {
        return Ok(RouteCommandPollOutcome::Rejected(
            RouteCommandPollRejection::InvalidContract,
        ));
    }

    let now = database_now(transaction)?;
    if let Some(ack) = poll.installed_ring_ack.as_ref() {
        if !store_route_ring_ack_in(transaction, ack, now)? {
            return Ok(RouteCommandPollOutcome::Rejected(
                RouteCommandPollRejection::RingAcknowledgementConflict,
            ));
        }
    }

    let candidate_deadline = now
        .get()
        .checked_add(AGENT_SESSION_LEASE_MS)
        .and_then(UnixMillis::new)
        .ok_or_else(|| corrupt("Route poll session lease renewal overflow"))?;
    let renewed_deadline = std::cmp::max(session.lease_deadline_unix_ms, candidate_deadline);
    let session = renew_current_session_deadline(transaction, &session, renewed_deadline)?;
    let page_limit = i64::try_from(ROUTE_COMMAND_BATCH_MAX_COMMANDS)
        .map_err(|_| corrupt("Route command batch limit exceeds PostgreSQL BIGINT"))?;
    let sql = format!(
        "SELECT {ROUTE_OPERATION_COLUMNS} FROM route_operations
          WHERE node_id=$1 AND node_boot_id=$2 AND agent_instance_id=$3
            AND admission_session_epoch=$4 AND state='unresolved'
            AND ($5::text IS NULL OR endpoint_id COLLATE \"C\" > $5 COLLATE \"C\")
          ORDER BY endpoint_id COLLATE \"C\" LIMIT $6"
    );
    let session_epoch = session.agent_session_epoch.to_pg().map_err(corrupt)?;
    let mut commands = Vec::with_capacity(ROUTE_COMMAND_BATCH_MAX_COMMANDS);
    let mut after_endpoint_id: Option<String> = None;
    while commands.len() < ROUTE_COMMAND_BATCH_MAX_COMMANDS {
        let rows = transaction.query(
            &sql,
            &[
                &session.node_id.as_str(),
                &session.node_boot_id.as_str(),
                &session.agent_instance_id.as_str(),
                &session_epoch,
                &after_endpoint_id.as_deref(),
                &page_limit,
            ],
        )?;
        let row_count = rows.len();
        let Some(last_endpoint_id) = rows
            .last()
            .map(|row| row.try_get::<_, String>("endpoint_id"))
            .transpose()?
        else {
            break;
        };
        for row in &rows {
            let operation = match decode_route_operation_row(row) {
                Ok(operation) if matches!(operation.state, RouteOperationState::Unresolved) => {
                    operation
                }
                Ok(_) => {
                    tracing::error!(
                        endpoint_id = row
                            .try_get::<_, String>("endpoint_id")
                            .unwrap_or_else(|_| "<invalid-endpoint-id>".to_owned()),
                        "omitting terminal Route Operation returned by unresolved poll query"
                    );
                    continue;
                }
                Err(error) => {
                    let endpoint_id = row
                        .try_get::<_, String>("endpoint_id")
                        .unwrap_or_else(|_| "<invalid-endpoint-id>".to_owned());
                    tracing::error!(
                        endpoint_id,
                        error = ?error,
                        "omitting corrupt per-Endpoint Route Operation from command poll"
                    );
                    continue;
                }
            };
            commands.push(*operation.canonical_request);
            if commands.len() == ROUTE_COMMAND_BATCH_MAX_COMMANDS {
                break;
            }
        }
        after_endpoint_id = Some(last_endpoint_id);
        if row_count < ROUTE_COMMAND_BATCH_MAX_COMMANDS {
            break;
        }
    }
    let batch = RouteCommandBatch {
        version: ContractVersion::V1,
        session: poll.session.clone(),
        request_sequence: poll.request_sequence,
        commands,
    };
    validate_route_command_batch_for_poll(&batch, poll, &session)
        .map_err(|_| corrupt("stored Route command batch violates its exact poll contract"))?;
    Ok(RouteCommandPollOutcome::Batch(batch))
}

fn store_route_ring_ack_in(
    transaction: &mut Transaction<'_>,
    ack: &cats_api::runtime_route::RouteNodeRingAck,
    accepted_at: UnixMillis,
) -> AuthorityTxResult<bool> {
    let current = transaction.query_opt(
        "SELECT canonical_ack_bytes, ack_id, ack_sequence,
                admission_session_epoch
           FROM route_node_ring_acks WHERE node_id=$1 FOR UPDATE",
        &[&ack.session.node_id.as_str()],
    )?;
    let canonical = encode_route_node_ring_ack(ack)
        .map_err(|_| corrupt("cannot encode exact Route public-ring ACK"))?;
    if let Some(current) = current {
        let current_epoch =
            Epoch::from_pg(current.try_get("admission_session_epoch")?).map_err(corrupt)?;
        let current_sequence =
            cats_api::runtime_reconciliation::Sequence::from_pg(current.try_get("ack_sequence")?)
                .map_err(corrupt)?;
        let current_ack_id: String = current.try_get("ack_id")?;
        let current_bytes: Vec<u8> = current.try_get("canonical_ack_bytes")?;
        if ack.session.agent_session_epoch < current_epoch
            || (ack.session.agent_session_epoch == current_epoch
                && ack.ack_sequence < current_sequence)
            || (ack.session.agent_session_epoch == current_epoch
                && ack.ack_sequence == current_sequence
                && current_bytes != canonical)
            || (ack.session.agent_session_epoch == current_epoch
                && current_ack_id == ack.ack_id.as_str()
                && current_bytes != canonical)
        {
            return Ok(false);
        }
        if ack.session.agent_session_epoch == current_epoch && ack.ack_sequence == current_sequence
        {
            return Ok(true);
        }
    }

    let loaded_kids = serde_json::to_string(&ack.loaded_kids)
        .map_err(|_| corrupt("cannot encode Route public-ring loaded KIDs"))?;
    let accepted_at = accepted_at.to_pg().map_err(corrupt)?;
    let changed = transaction.execute(
        "INSERT INTO route_node_ring_acks (
            node_id, canonical_ack_bytes, canonical_ack_sha256, ack_id,
            ack_sequence, node_boot_id, agent_instance_id,
            admission_session_epoch, ring_version, key_ring_digest,
            loaded_kids, accepted_at_unix_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::TEXT::jsonb,$12)
         ON CONFLICT (node_id) DO UPDATE SET
            canonical_ack_bytes=EXCLUDED.canonical_ack_bytes,
            canonical_ack_sha256=EXCLUDED.canonical_ack_sha256,
            ack_id=EXCLUDED.ack_id, ack_sequence=EXCLUDED.ack_sequence,
            node_boot_id=EXCLUDED.node_boot_id,
            agent_instance_id=EXCLUDED.agent_instance_id,
            admission_session_epoch=EXCLUDED.admission_session_epoch,
            ring_version=EXCLUDED.ring_version,
            key_ring_digest=EXCLUDED.key_ring_digest,
            loaded_kids=EXCLUDED.loaded_kids,
            accepted_at_unix_ms=EXCLUDED.accepted_at_unix_ms",
        &[
            &ack.session.node_id.as_str(),
            &canonical,
            &ack.ack_digest.as_str(),
            &ack.ack_id.as_str(),
            &ack.ack_sequence.to_pg().map_err(corrupt)?,
            &ack.session.node_boot_id.as_str(),
            &ack.session.agent_instance_id.as_str(),
            &ack.session.agent_session_epoch.to_pg().map_err(corrupt)?,
            &ack.ring_version.to_pg().map_err(corrupt)?,
            &ack.key_ring_digest.as_str(),
            &loaded_kids,
            &accepted_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt("Route public-ring ACK upsert changed no row"));
    }
    Ok(true)
}

#[derive(Debug)]
struct RouteOperationLocator {
    workspace_id: Id,
    cat_id: Id,
    endpoint_id: Id,
}

#[derive(Debug)]
struct LockedCurrentEndpoint {
    route: LockedEndpointRoute,
    binding_state: String,
    hostname: Option<String>,
    protocol: Option<String>,
    target_port: Option<i32>,
}

fn commit_route_result_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    commit: &RouteResultCommitRequest,
) -> AuthorityTxResult<RouteResultCommitOutcome> {
    let session = match authenticate_session(transaction, authenticated, &commit.session)? {
        Ok(session) => session,
        Err(rejection) => {
            return Ok(RouteResultCommitOutcome::Rejected(
                RouteResultCommitRejection::Session(rejection),
            ));
        }
    };

    // This first read only locates the Cat serialization row. Every field is
    // revalidated after the authenticated session, Cat, lifecycle,
    // Endpoint, and Route Operation locks are held in that order.
    let Some(locator) =
        load_route_operation_locator_unlocked(transaction, &commit.response.operation_id)?
    else {
        return Ok(RouteResultCommitOutcome::Rejected(
            RouteResultCommitRejection::OperationNotFound,
        ));
    };
    if locator.endpoint_id != commit.response.endpoint_id {
        return Ok(RouteResultCommitOutcome::Rejected(
            RouteResultCommitRejection::InvalidContract,
        ));
    }
    let Some(lifecycle) = load_lifecycle_route_authority_for_update_in(
        transaction,
        &locator.workspace_id,
        &locator.cat_id,
    )?
    else {
        return Err(corrupt("Route Operation references a missing Cat"));
    };
    let Some(endpoint) = load_endpoint_for_update(transaction, &locator)? else {
        return Err(corrupt("Route Operation references a missing Endpoint"));
    };
    let Some(mut operation) =
        load_route_operation_for_update(transaction, &commit.response.operation_id)?
    else {
        return Err(corrupt(
            "Route Operation disappeared after its identity lookup",
        ));
    };
    if operation.endpoint_id != locator.endpoint_id
        || operation.canonical_request.binding.workspace_id != locator.workspace_id
        || operation.canonical_request.binding.cat_id != locator.cat_id
    {
        return Err(corrupt(
            "Route Operation identity changed across Cat/Endpoint serialization",
        ));
    }
    if validate_route_result_commit_for_command(
        commit,
        operation.canonical_request.as_ref(),
        &session,
    )
    .is_err()
    {
        return Ok(RouteResultCommitOutcome::Rejected(
            RouteResultCommitRejection::InvalidContract,
        ));
    }

    if let RouteOperationState::Terminal { terminal } = &operation.state {
        return match terminal.as_ref() {
            RouteOperationTerminal::NodeResult {
                response,
                terminal_result_digest,
            } if response.as_ref() == commit.response.as_ref()
                && terminal_result_digest == &commit.terminal_result_digest =>
            {
                Ok(RouteResultCommitOutcome::ExactReplay {
                    acknowledgement: route_result_stored_ack(
                        &session,
                        commit.response.as_ref(),
                        &commit.terminal_result_digest,
                    ),
                    operation,
                })
            }
            RouteOperationTerminal::ControlInvalidation { .. } => {
                Ok(RouteResultCommitOutcome::Superseded { operation })
            }
            RouteOperationTerminal::NodeResult { .. } => Ok(RouteResultCommitOutcome::Rejected(
                RouteResultCommitRejection::ConflictingTerminalResult {
                    operation_id: commit.response.operation_id.clone(),
                },
            )),
        };
    }

    if !endpoint_predecessor_is_current(&endpoint, operation.canonical_request.as_ref()) {
        return Ok(RouteResultCommitOutcome::Rejected(
            RouteResultCommitRejection::OperationNotCurrent {
                current_operation_id: endpoint.route.route_head_operation_id,
            },
        ));
    }

    // A Serving result that arrives after lifecycle acceptance or Endpoint
    // rebinding is exact evidence that the local Enable may have taken effect,
    // but it can never become current authority. Terminalize it as a Control
    // invalidation and burn the affected current epoch before acknowledging
    // the command as superseded.
    if matches!(commit.response.result, RouteNodeResult::Serving(_))
        && !serving_result_is_current(&endpoint, &lifecycle, commit.response.as_ref())
    {
        let (reason, invalidating_lifecycle_operation_id) =
            stale_serving_invalidation_cause(&endpoint, &lifecycle, commit.response.as_ref())?;
        invalidate_locked_unresolved_route(
            transaction,
            &endpoint.route,
            &operation,
            reason,
            invalidating_lifecycle_operation_id,
            None,
        )?;
        operation = load_route_operation_for_update(transaction, &operation.operation_id)?
            .ok_or_else(|| corrupt("invalidated Route Operation disappeared"))?;
        return Ok(RouteResultCommitOutcome::Superseded { operation });
    }

    let terminal_at = max_unix_millis(database_now(transaction)?, operation.created_at_unix_ms);
    let response_bytes = encode_route_command_response(commit.response.as_ref())
        .map_err(|_| corrupt("cannot encode exact Route command response"))?;
    let changed = transaction.execute(
        "UPDATE route_operations
            SET state='terminal', terminal_source='node_result',
                terminal_result_kind=$2, canonical_result_bytes=$3,
                canonical_result_sha256=$4, terminal_at_unix_ms=$5
          WHERE operation_id=$1 AND state='unresolved'",
        &[
            &operation.operation_id.as_str(),
            &terminal_result_kind_text(commit.response.result.kind()),
            &response_bytes,
            &commit.terminal_result_digest.as_str(),
            &terminal_at.to_pg().map_err(corrupt)?,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "exact unresolved Route Operation update changed no row",
        ));
    }
    update_endpoint_after_node_result(transaction, &endpoint, commit.response.as_ref())?;

    operation.state = RouteOperationState::Terminal {
        terminal: Box::new(RouteOperationTerminal::NodeResult {
            response: commit.response.clone(),
            terminal_result_digest: commit.terminal_result_digest.clone(),
        }),
    };
    operation.terminal_at_unix_ms = Some(terminal_at);
    cats_api::runtime_route::validate_route_operation(&operation)
        .map_err(|_| corrupt("stored Route Operation terminal is invalid"))?;
    Ok(RouteResultCommitOutcome::Stored {
        acknowledgement: route_result_stored_ack(
            &session,
            commit.response.as_ref(),
            &commit.terminal_result_digest,
        ),
        operation,
    })
}

fn load_route_operation_locator_unlocked(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<RouteOperationLocator>> {
    transaction
        .query_opt(
            "SELECT workspace_id, cat_id, endpoint_id FROM route_operations
              WHERE operation_id=$1",
            &[&operation_id.as_str()],
        )?
        .map(|row| {
            Ok(RouteOperationLocator {
                workspace_id: parse_id(row.try_get("workspace_id")?)?,
                cat_id: parse_id(row.try_get("cat_id")?)?,
                endpoint_id: parse_id(row.try_get("endpoint_id")?)?,
            })
        })
        .transpose()
}

fn load_endpoint_for_update(
    transaction: &mut Transaction<'_>,
    locator: &RouteOperationLocator,
) -> AuthorityTxResult<Option<LockedCurrentEndpoint>> {
    transaction
        .query_opt(
            "SELECT workspace_id, cat_id, endpoint_id, binding_state,
                    hostname, protocol, target_port, route_epoch,
                    route_head_operation_id, effective_serving_operation_id
               FROM endpoint_records WHERE endpoint_id=$1 FOR UPDATE",
            &[&locator.endpoint_id.as_str()],
        )?
        .map(|row| {
            if row.try_get::<_, String>("workspace_id")? != locator.workspace_id.as_str()
                || row.try_get::<_, String>("cat_id")? != locator.cat_id.as_str()
            {
                return Err(corrupt("Endpoint identity crosses Route locator scope"));
            }
            Ok(LockedCurrentEndpoint {
                route: decode_locked_endpoint(&row)?,
                binding_state: row.try_get("binding_state")?,
                hostname: row.try_get("hostname")?,
                protocol: row.try_get("protocol")?,
                target_port: row.try_get("target_port")?,
            })
        })
        .transpose()
}

fn load_route_operation_for_update(
    transaction: &mut Transaction<'_>,
    operation_id: &Id,
) -> AuthorityTxResult<Option<RouteOperation>> {
    let sql = format!(
        "SELECT {ROUTE_OPERATION_COLUMNS} FROM route_operations
          WHERE operation_id=$1 FOR UPDATE"
    );
    transaction
        .query_opt(&sql, &[&operation_id.as_str()])?
        .map(|row| decode_route_operation_row(&row))
        .transpose()
}

fn endpoint_predecessor_is_current(
    endpoint: &LockedCurrentEndpoint,
    command: &cats_api::runtime_route::RouteCommandEnvelope,
) -> bool {
    match &command.predecessor {
        RouteCommandPredecessor::Genesis => endpoint.route.route_head_operation_id.is_none(),
        RouteCommandPredecessor::Exact { operation_id, .. } => {
            endpoint.route.route_head_operation_id.as_ref() == Some(operation_id)
        }
    }
}

fn serving_result_is_current(
    endpoint: &LockedCurrentEndpoint,
    lifecycle: &LifecycleRouteAuthority,
    response: &RouteCommandResponse,
) -> bool {
    let binding = response.result.binding();
    lifecycle.deleted_at.is_none()
        && lifecycle.stable_state == Some(LifecycleStableState::Running)
        && !lifecycle.unresolved_leaves_running
        && lifecycle.current_placement.as_ref() == Some(&binding.placement_identity)
        && lifecycle
            .effective_runtime_ready
            .as_ref()
            .is_some_and(|ready| ready.evidence == binding.effective_runtime_ready)
        && endpoint.binding_state == "bound"
        && endpoint.hostname.as_deref() == Some(binding.hostname.as_str())
        && endpoint.protocol.as_deref() == Some("http")
        && endpoint.target_port == Some(i32::from(binding.target_port))
        && endpoint.route.endpoint_id == binding.endpoint_id
        && endpoint.route.route_epoch == binding.route_epoch
}

fn stale_serving_invalidation_cause(
    endpoint: &LockedCurrentEndpoint,
    lifecycle: &LifecycleRouteAuthority,
    response: &RouteCommandResponse,
) -> AuthorityTxResult<(RouteControlInvalidationReason, Option<Id>)> {
    let binding = response.result.binding();
    let endpoint_changed = endpoint.binding_state != "bound"
        || endpoint.hostname.as_deref() != Some(binding.hostname.as_str())
        || endpoint.protocol.as_deref() != Some("http")
        || endpoint.target_port != Some(i32::from(binding.target_port))
        || endpoint.route.route_epoch != binding.route_epoch;
    if endpoint_changed {
        return Ok((RouteControlInvalidationReason::EndpointBindingChanged, None));
    }
    let lifecycle_operation_id = lifecycle
        .unresolved_operation
        .as_ref()
        .map(|operation| operation.operation_id.clone())
        .or_else(|| {
            lifecycle
                .lifecycle_head
                .as_ref()
                .map(|operation| operation.operation_id.clone())
        })
        .ok_or_else(|| corrupt("stale Serving has no lifecycle invalidation anchor"))?;
    Ok((
        RouteControlInvalidationReason::LifecycleCloseAmbiguous,
        Some(lifecycle_operation_id),
    ))
}

fn invalidate_locked_unresolved_route(
    transaction: &mut Transaction<'_>,
    endpoint: &LockedEndpointRoute,
    operation: &RouteOperation,
    reason: RouteControlInvalidationReason,
    invalidating_lifecycle_operation_id: Option<Id>,
    replacement_session: Option<SessionBinding>,
) -> AuthorityTxResult<()> {
    let effect_at_current_epoch = operation.canonical_request.binding.route_epoch
        == endpoint.route_epoch
        || endpoint.effective_serving_operation_id.is_some();
    let resulting_epoch = if effect_at_current_epoch {
        next_epoch(endpoint.route_epoch)?
    } else {
        endpoint.route_epoch
    };
    let terminal_at = max_unix_millis(database_now(transaction)?, operation.created_at_unix_ms);
    let invalidation = RouteControlInvalidation::new(
        endpoint.endpoint_id.clone(),
        operation.operation_id.clone(),
        reason,
        invalidating_lifecycle_operation_id,
        replacement_session,
        resulting_epoch,
        terminal_at,
    )
    .map_err(|_| corrupt("cannot encode stale Route Serving invalidation"))?;
    terminalize_with_control_invalidation(
        transaction,
        &LockedUnresolvedRouteOperation {
            operation_id: operation.operation_id.clone(),
            route_epoch: operation.canonical_request.binding.route_epoch,
            created_at_unix_ms: operation.created_at_unix_ms,
        },
        &invalidation,
    )?;
    update_endpoint_after_invalidation(
        transaction,
        endpoint,
        resulting_epoch,
        Some(&operation.operation_id),
        terminal_at,
    )
}

fn update_endpoint_after_node_result(
    transaction: &mut Transaction<'_>,
    endpoint: &LockedCurrentEndpoint,
    response: &RouteCommandResponse,
) -> AuthorityTxResult<()> {
    let effective_serving = match &response.result {
        RouteNodeResult::Serving(_) => Some(response.operation_id.as_str()),
        RouteNodeResult::Closed(_) => None,
        RouteNodeResult::Rejected(_) => endpoint
            .route
            .effective_serving_operation_id
            .as_ref()
            .map(Id::as_str),
    };
    let now = database_now(transaction)?.to_pg().map_err(corrupt)?;
    let changed = transaction.execute(
        "UPDATE endpoint_records
            SET route_head_operation_id=$2, effective_serving_operation_id=$3,
                updated_at_unix_ms=GREATEST(updated_at_unix_ms, $4)
          WHERE endpoint_id=$1
            AND route_epoch=$5
            AND route_head_operation_id IS NOT DISTINCT FROM $6
            AND effective_serving_operation_id IS NOT DISTINCT FROM $7",
        &[
            &endpoint.route.endpoint_id.as_str(),
            &response.operation_id.as_str(),
            &effective_serving,
            &now,
            &endpoint.route.route_epoch.to_pg().map_err(corrupt)?,
            &endpoint
                .route
                .route_head_operation_id
                .as_ref()
                .map(Id::as_str),
            &endpoint
                .route
                .effective_serving_operation_id
                .as_ref()
                .map(Id::as_str),
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "Endpoint authority changed after its locked Route result validation",
        ));
    }
    Ok(())
}

fn route_result_stored_ack(
    session: &AgentSession,
    response: &RouteCommandResponse,
    terminal_result_digest: &cats_api::runtime_reconciliation::Sha256Digest,
) -> RouteResultStoredAck {
    RouteResultStoredAck {
        version: ContractVersion::V1,
        node_id: session.node_id.clone(),
        endpoint_id: response.endpoint_id.clone(),
        operation_id: response.operation_id.clone(),
        request_fingerprint: response.request_fingerprint.clone(),
        terminal_result_digest: terminal_result_digest.clone(),
    }
}

const fn terminal_result_kind_text(kind: RouteTerminalResultKind) -> &'static str {
    match kind {
        RouteTerminalResultKind::Serving => "serving",
        RouteTerminalResultKind::Closed => "closed",
        RouteTerminalResultKind::Rejected => "rejected",
        RouteTerminalResultKind::Invalidated => "invalidated",
    }
}

#[derive(Debug)]
struct LockedEndpointRoute {
    endpoint_id: Id,
    route_epoch: Epoch,
    route_head_operation_id: Option<Id>,
    effective_serving_operation_id: Option<Id>,
}

#[derive(Debug)]
struct LockedUnresolvedRouteOperation {
    operation_id: Id,
    route_epoch: Epoch,
    created_at_unix_ms: UnixMillis,
}

/// Invalidates every Route effect affected by one accepted lifecycle close.
///
/// `NeverClosed` is the exact SuspendDeclined(Busy) preservation case and is
/// deliberately a zero-query, zero-mutation return. `Closed` and `Ambiguous`
/// clear Serving, terminalize an unresolved command with an exact Control
/// invalidation, and burn the current Endpoint epoch exactly once. A command
/// already stranded on an older burned epoch is invalidated without burning
/// the current epoch again.
///
/// The caller must already hold the Cat row and exact lifecycle Operation row
/// for `(workspace_id, cat_id, lifecycle_operation_id)`.
pub(super) fn invalidate_routes_for_lifecycle_close_in(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    lifecycle_operation_id: &Id,
    outcome: LifecycleAdmissionCloseOutcome,
) -> AuthorityTxResult<usize> {
    if outcome == LifecycleAdmissionCloseOutcome::NeverClosed {
        return Ok(0);
    }

    require_exact_lifecycle_operation(transaction, workspace_id, cat_id, lifecycle_operation_id)?;
    let reason = match outcome {
        LifecycleAdmissionCloseOutcome::Closed => RouteControlInvalidationReason::LifecycleClosed,
        LifecycleAdmissionCloseOutcome::Ambiguous => {
            RouteControlInvalidationReason::LifecycleCloseAmbiguous
        }
        LifecycleAdmissionCloseOutcome::NeverClosed => {
            unreachable!("the exact never-closed outcome returned before acquiring authority locks")
        }
    };
    let database_now = database_now(transaction)?;
    let endpoints = lock_affected_endpoints(transaction, workspace_id, cat_id)?;
    let mut changed = 0usize;

    for endpoint in endpoints {
        let unresolved = lock_unresolved_route_operation(
            transaction,
            workspace_id,
            cat_id,
            &endpoint.endpoint_id,
        )?;
        let effective_epoch = endpoint
            .effective_serving_operation_id
            .as_ref()
            .map(|operation_id| {
                load_exact_effective_serving_epoch(
                    transaction,
                    workspace_id,
                    cat_id,
                    &endpoint.endpoint_id,
                    operation_id,
                )
            })
            .transpose()?;

        // The Endpoint may have been selected just before a concurrent result
        // terminalized its unresolved command. Revalidate under the Endpoint
        // lock and leave an already-closed lane unchanged.
        if unresolved.is_none() && effective_epoch.is_none() {
            continue;
        }

        let effect_at_current_epoch = effective_epoch
            .is_some_and(|epoch| epoch == endpoint.route_epoch)
            || unresolved
                .as_ref()
                .is_some_and(|operation| operation.route_epoch == endpoint.route_epoch);
        let resulting_route_epoch = if effect_at_current_epoch {
            next_epoch(endpoint.route_epoch)?
        } else {
            endpoint.route_epoch
        };

        let terminalized_operation_id = if let Some(operation) = unresolved {
            let terminal_at = max_unix_millis(database_now, operation.created_at_unix_ms);
            let invalidation = RouteControlInvalidation::new(
                endpoint.endpoint_id.clone(),
                operation.operation_id.clone(),
                reason,
                Some(lifecycle_operation_id.clone()),
                None,
                resulting_route_epoch,
                terminal_at,
            )
            .map_err(|_| corrupt("cannot encode lifecycle Route invalidation"))?;
            terminalize_with_control_invalidation(transaction, &operation, &invalidation)?;
            Some(operation.operation_id)
        } else {
            None
        };

        update_endpoint_after_invalidation(
            transaction,
            &endpoint,
            resulting_route_epoch,
            terminalized_operation_id.as_ref(),
            database_now,
        )?;
        changed = changed
            .checked_add(1)
            .ok_or_else(|| corrupt("affected Endpoint count overflow"))?;
    }

    Ok(changed)
}

fn require_exact_lifecycle_operation(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    operation_id: &Id,
) -> AuthorityTxResult<()> {
    let row = transaction.query_opt(
        "SELECT workspace_id, cat_id FROM runtime_operations
          WHERE operation_id=$1 FOR UPDATE",
        &[&operation_id.as_str()],
    )?;
    let Some(row) = row else {
        return Err(corrupt("invalidating lifecycle Operation is missing"));
    };
    if row.try_get::<_, String>("workspace_id")? != workspace_id.as_str()
        || row.try_get::<_, String>("cat_id")? != cat_id.as_str()
    {
        return Err(corrupt(
            "invalidating lifecycle Operation belongs to another Cat",
        ));
    }
    Ok(())
}

fn lock_affected_endpoints(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<Vec<LockedEndpointRoute>> {
    transaction
        .query(
            "SELECT e.endpoint_id, e.route_epoch,
                    e.route_head_operation_id,
                    e.effective_serving_operation_id
               FROM endpoint_records e
              WHERE e.workspace_id=$1 AND e.cat_id=$2
                AND (e.effective_serving_operation_id IS NOT NULL OR EXISTS (
                    SELECT 1 FROM route_operations r
                     WHERE r.endpoint_id=e.endpoint_id
                       AND r.state='unresolved'
                ))
              ORDER BY e.endpoint_id COLLATE \"C\"
              FOR UPDATE OF e",
            &[&workspace_id.as_str(), &cat_id.as_str()],
        )?
        .iter()
        .map(decode_locked_endpoint)
        .collect()
}

fn decode_locked_endpoint(row: &Row) -> AuthorityTxResult<LockedEndpointRoute> {
    Ok(LockedEndpointRoute {
        endpoint_id: parse_id(row.try_get("endpoint_id")?)?,
        route_epoch: Epoch::from_pg(row.try_get("route_epoch")?).map_err(corrupt)?,
        route_head_operation_id: row
            .try_get::<_, Option<String>>("route_head_operation_id")?
            .map(parse_id)
            .transpose()?,
        effective_serving_operation_id: row
            .try_get::<_, Option<String>>("effective_serving_operation_id")?
            .map(parse_id)
            .transpose()?,
    })
}

fn lock_unresolved_route_operation(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    endpoint_id: &Id,
) -> AuthorityTxResult<Option<LockedUnresolvedRouteOperation>> {
    let rows = transaction.query(
        "SELECT operation_id, route_epoch, created_at_unix_ms
           FROM route_operations
          WHERE workspace_id=$1 AND cat_id=$2 AND endpoint_id=$3
            AND state='unresolved'
          ORDER BY operation_id COLLATE \"C\" FOR UPDATE",
        &[
            &workspace_id.as_str(),
            &cat_id.as_str(),
            &endpoint_id.as_str(),
        ],
    )?;
    if rows.len() > 1 {
        return Err(corrupt(
            "Endpoint has more than one unresolved Route Operation",
        ));
    }
    rows.first()
        .map(|row| {
            Ok(LockedUnresolvedRouteOperation {
                operation_id: parse_id(row.try_get("operation_id")?)?,
                route_epoch: Epoch::from_pg(row.try_get("route_epoch")?).map_err(corrupt)?,
                created_at_unix_ms: UnixMillis::from_pg(row.try_get("created_at_unix_ms")?)
                    .map_err(corrupt)?,
            })
        })
        .transpose()
}

fn load_exact_effective_serving_epoch(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    endpoint_id: &Id,
    operation_id: &Id,
) -> AuthorityTxResult<Epoch> {
    let row = transaction.query_opt(
        "SELECT route_epoch, state, terminal_source, terminal_result_kind
           FROM route_operations
          WHERE operation_id=$1 AND workspace_id=$2 AND cat_id=$3
            AND endpoint_id=$4",
        &[
            &operation_id.as_str(),
            &workspace_id.as_str(),
            &cat_id.as_str(),
            &endpoint_id.as_str(),
        ],
    )?;
    let Some(row) = row else {
        return Err(corrupt("effective Serving Route Operation is missing"));
    };
    if row.try_get::<_, String>("state")? != "terminal"
        || row
            .try_get::<_, Option<String>>("terminal_source")?
            .as_deref()
            != Some("node_result")
        || row
            .try_get::<_, Option<String>>("terminal_result_kind")?
            .as_deref()
            != Some("serving")
    {
        return Err(corrupt(
            "effective Serving pointer does not name a Serving terminal",
        ));
    }
    Epoch::from_pg(row.try_get("route_epoch")?).map_err(corrupt)
}

fn terminalize_with_control_invalidation(
    transaction: &mut Transaction<'_>,
    operation: &LockedUnresolvedRouteOperation,
    invalidation: &RouteControlInvalidation,
) -> AuthorityTxResult<()> {
    let bytes = encode_route_control_invalidation(invalidation)
        .map_err(|_| corrupt("cannot encode exact Route invalidation bytes"))?;
    let terminal_at = invalidation
        .invalidated_at_unix_ms
        .to_pg()
        .map_err(corrupt)?;
    let changed = transaction.execute(
        "UPDATE route_operations
            SET state='terminal', terminal_source='control_invalidation',
                terminal_result_kind='invalidated',
                canonical_result_bytes=$2, canonical_result_sha256=$3,
                terminal_at_unix_ms=$4
          WHERE operation_id=$1 AND state='unresolved'",
        &[
            &operation.operation_id.as_str(),
            &bytes,
            &invalidation.invalidation_digest.as_str(),
            &terminal_at,
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "unresolved Route Operation changed before exact invalidation",
        ));
    }
    Ok(())
}

fn update_endpoint_after_invalidation(
    transaction: &mut Transaction<'_>,
    endpoint: &LockedEndpointRoute,
    resulting_route_epoch: Epoch,
    terminalized_operation_id: Option<&Id>,
    database_now: UnixMillis,
) -> AuthorityTxResult<()> {
    let resulting_epoch = resulting_route_epoch.to_pg().map_err(corrupt)?;
    let database_now = database_now.to_pg().map_err(corrupt)?;
    let resulting_head = terminalized_operation_id
        .map(Id::as_str)
        .or_else(|| endpoint.route_head_operation_id.as_ref().map(Id::as_str));
    let changed = transaction.execute(
        "UPDATE endpoint_records
            SET route_epoch=$2, route_head_operation_id=$3,
                effective_serving_operation_id=NULL,
                updated_at_unix_ms=GREATEST(updated_at_unix_ms, $4)
          WHERE endpoint_id=$1 AND route_epoch=$5
            AND route_head_operation_id IS NOT DISTINCT FROM $6
            AND effective_serving_operation_id IS NOT DISTINCT FROM $7",
        &[
            &endpoint.endpoint_id.as_str(),
            &resulting_epoch,
            &resulting_head,
            &database_now,
            &endpoint.route_epoch.to_pg().map_err(corrupt)?,
            &endpoint.route_head_operation_id.as_ref().map(Id::as_str),
            &endpoint
                .effective_serving_operation_id
                .as_ref()
                .map(Id::as_str),
        ],
    )?;
    if changed != 1 {
        return Err(corrupt(
            "Endpoint Route authority changed after its row lock",
        ));
    }
    Ok(())
}

fn next_epoch(epoch: Epoch) -> AuthorityTxResult<Epoch> {
    epoch
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .filter(|next| next.to_pg().is_ok())
        .ok_or_else(|| {
            AuthorityTransactionError::Application(ApiError::failed_precondition(
                "Endpoint route epoch is exhausted",
            ))
        })
}

fn max_unix_millis(left: UnixMillis, right: UnixMillis) -> UnixMillis {
    if left.get() >= right.get() {
        left
    } else {
        right
    }
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("stored Route identifier is invalid"))
}

fn corrupt(error: impl std::fmt::Display) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(internal(format!(
        "atomic Route authority invariant failed: {error}"
    )))
}

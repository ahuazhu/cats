//! Atomic Control-side Endpoint serving lineage.
//!
//! Endpoint metadata and the exact lifecycle projection drive an independent
//! per-Endpoint command lane. Desired and Observation are deliberately absent.

#![allow(
    dead_code,
    reason = "the atomic Route Store/controller integration is composed by this cutover"
)]

use cats_api::error::ApiError;
use cats_api::runtime_lifecycle::{EffectiveRuntimeReady, PlacementIdentity};
use cats_api::runtime_reconciliation::{Epoch, Hostname, HttpProtocol, Id, SessionBinding};
use cats_api::runtime_route::{
    validate_route_command_response_for_command, RouteCommand, RouteCommandEnvelope,
    RouteCommandPredecessor, RouteCommandResponse, RouteControlInvalidationReason, RouteNodeResult,
    RouteOperation as AtomicRouteOperation, RouteOperationState, RouteOperationTerminal,
    RouteServingBinding,
};

use crate::store::Result;

// -------------------------------------------------------------------------
// Atomic lifecycle Route authority (ADR-0056).
// -------------------------------------------------------------------------

/// Product-owned current Endpoint binding. It contains no lifecycle or Node
/// fact; the Route Controller closes those facts when it derives a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentEndpointBinding {
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) endpoint_id: Id,
    pub(crate) hostname: Hostname,
    pub(crate) protocol: HttpProtocol,
    pub(crate) target_port: u16,
}

/// Minimal lifecycle projection consumed by Route. `effective_runtime_ready`
/// may name an older Start when the current head is a never-closed
/// SuspendDeclined(Busy); it is therefore intentionally separate from the
/// current head operation ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicRouteLifecycleState {
    Running,
    NotRunning,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AtomicRouteLifecycleAuthority {
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) lifecycle_head_operation_id: Option<Id>,
    pub(crate) state: AtomicRouteLifecycleState,
    pub(crate) current_placement: Option<PlacementIdentity>,
    pub(crate) effective_runtime_ready: Option<EffectiveRuntimeReady>,
    /// Set in the same Cat-row transaction that accepts Suspend/Warm/Cold/
    /// Stop/Delete. It blocks fresh Enable and signing before any Node effect.
    pub(crate) unresolved_leaves_running: bool,
}

/// Exact persisted Endpoint projection. Pointers contain fully decoded Route
/// Operations; callers must not synthesize authority from scalar columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AtomicEndpointRouteAuthority {
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) endpoint_id: Id,
    pub(crate) binding: Option<CurrentEndpointBinding>,
    pub(crate) route_epoch: Epoch,
    pub(crate) route_head: Option<AtomicRouteOperation>,
    pub(crate) effective_serving: Option<AtomicRouteOperation>,
    pub(crate) unresolved_operation: Option<AtomicRouteOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AtomicRouteCommandDraft {
    pub(crate) binding: RouteServingBinding,
    pub(crate) predecessor: RouteCommandPredecessor,
    pub(crate) command: RouteCommand,
}

impl AtomicRouteCommandDraft {
    pub(crate) fn into_envelope(self, operation_id: Id) -> Result<RouteCommandEnvelope> {
        RouteCommandEnvelope::new(operation_id, self.binding, self.predecessor, self.command)
            .map_err(|_| ApiError::internal("cannot encode exact Route command"))
    }
}

/// One locked Endpoint-row mutation. A binding mutation may already have
/// burned the old epoch; in that case `resulting_route_epoch` equals the
/// current epoch and the plan only clears stale authority/settles an old op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteEpochInvalidationPlan {
    pub(crate) endpoint_id: Id,
    pub(crate) expected_route_epoch: Epoch,
    pub(crate) resulting_route_epoch: Epoch,
    pub(crate) clear_effective_serving: bool,
    pub(crate) invalidate_unresolved_operation_id: Option<Id>,
    pub(crate) reason: RouteControlInvalidationReason,
    pub(crate) invalidating_lifecycle_operation_id: Option<Id>,
    pub(crate) replacement_session: Option<SessionBinding>,
}

impl RouteEpochInvalidationPlan {
    pub(crate) fn burns_epoch(&self) -> bool {
        self.resulting_route_epoch != self.expected_route_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AtomicRouteControllerAction {
    Quiescent,
    AwaitingOperation { operation_id: Id },
    Submit(Box<AtomicRouteCommandDraft>),
    Invalidate(RouteEpochInvalidationPlan),
    BlockedByLifecycle,
    RunRequired,
    Gone,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleAdmissionCloseOutcome {
    NeverClosed,
    Closed,
    Ambiguous,
}

/// Derives the next per-Endpoint Route action from current product metadata,
/// lifecycle projection and AgentSession. Desired and Observation are absent.
pub(crate) fn plan_atomic_endpoint_route(
    endpoint: &AtomicEndpointRouteAuthority,
    lifecycle: &AtomicRouteLifecycleAuthority,
    current_session: Option<&SessionBinding>,
) -> Result<AtomicRouteControllerAction> {
    validate_atomic_route_authority(endpoint, lifecycle)?;

    if lifecycle.state == AtomicRouteLifecycleState::Deleted {
        return Ok(AtomicRouteControllerAction::Gone);
    }
    if lifecycle.unresolved_leaves_running {
        return Ok(AtomicRouteControllerAction::BlockedByLifecycle);
    }
    if lifecycle.state != AtomicRouteLifecycleState::Running {
        return Ok(AtomicRouteControllerAction::RunRequired);
    }
    let (Some(placement), Some(ready)) = (
        lifecycle.current_placement.as_ref(),
        lifecycle.effective_runtime_ready.as_ref(),
    ) else {
        return Err(ApiError::internal(
            "Running lifecycle projection lacks effective RuntimeReady authority",
        ));
    };
    let Some(session) = current_session else {
        return Ok(AtomicRouteControllerAction::Unavailable);
    };
    if session.node_id != placement.node_id {
        return Ok(AtomicRouteControllerAction::Unavailable);
    }

    let Some(current_binding) = endpoint.binding.as_ref() else {
        return plan_unbound_endpoint(endpoint, lifecycle, session);
    };
    let expected = close_serving_binding(
        current_binding,
        endpoint.route_epoch,
        placement,
        ready,
        session,
    );

    if let Some(operation) = &endpoint.effective_serving {
        let serving = exact_serving_response(operation)?;
        if serving.result.binding() == &expected {
            return Ok(AtomicRouteControllerAction::Quiescent);
        }
        let cause = classify_stale_binding(serving.result.binding(), &expected);
        return Ok(AtomicRouteControllerAction::Invalidate(
            plan_endpoint_invalidation(endpoint, lifecycle, current_session, cause)?,
        ));
    }

    if let Some(operation) = &endpoint.unresolved_operation {
        let command = operation.canonical_request.as_ref();
        if command.command == RouteCommand::Enable && command.binding == expected {
            return Ok(AtomicRouteControllerAction::AwaitingOperation {
                operation_id: operation.operation_id.clone(),
            });
        }
        let cause = classify_stale_binding(&command.binding, &expected);
        return Ok(AtomicRouteControllerAction::Invalidate(
            plan_endpoint_invalidation(endpoint, lifecycle, current_session, cause)?,
        ));
    }

    // A retained historical Serving with no effective pointer must first be
    // closed when it names an older binding/epoch. This is how changed and
    // unbound Endpoint metadata automatically drives Disable before Enable.
    if let Some(head) = &endpoint.route_head {
        if let Some(old_binding) = terminal_serving_binding(head)? {
            if old_binding != &expected {
                if old_binding.admission_session != *session
                    || old_binding.placement_identity != *placement
                    || old_binding.effective_runtime_ready != *ready
                {
                    return Ok(AtomicRouteControllerAction::Invalidate(
                        plan_endpoint_invalidation(
                            endpoint,
                            lifecycle,
                            current_session,
                            classify_stale_binding(old_binding, &expected),
                        )?,
                    ));
                }
                return Ok(AtomicRouteControllerAction::Submit(Box::new(
                    AtomicRouteCommandDraft {
                        binding: old_binding.clone(),
                        predecessor: exact_route_predecessor(head)?,
                        command: RouteCommand::Disable,
                    },
                )));
            }
            // A same-epoch Serving cannot become non-effective without an
            // epoch-burn event. Conservatively burn before any fresh Enable.
            return Ok(AtomicRouteControllerAction::Invalidate(
                plan_endpoint_invalidation(
                    endpoint,
                    lifecycle,
                    current_session,
                    RouteControlInvalidationReason::LifecycleCloseAmbiguous,
                )?,
            ));
        }
    }

    Ok(AtomicRouteControllerAction::Submit(Box::new(
        AtomicRouteCommandDraft {
            binding: expected,
            predecessor: route_predecessor(endpoint.route_head.as_ref())?,
            command: RouteCommand::Enable,
        },
    )))
}

fn plan_unbound_endpoint(
    endpoint: &AtomicEndpointRouteAuthority,
    lifecycle: &AtomicRouteLifecycleAuthority,
    current_session: &SessionBinding,
) -> Result<AtomicRouteControllerAction> {
    if endpoint.effective_serving.is_some() || endpoint.unresolved_operation.is_some() {
        return Ok(AtomicRouteControllerAction::Invalidate(
            plan_endpoint_invalidation(
                endpoint,
                lifecycle,
                Some(current_session),
                RouteControlInvalidationReason::EndpointBindingChanged,
            )?,
        ));
    }
    let Some(head) = &endpoint.route_head else {
        return Ok(AtomicRouteControllerAction::Quiescent);
    };
    let Some(old_binding) = terminal_serving_binding(head)? else {
        return Ok(AtomicRouteControllerAction::Quiescent);
    };
    let (Some(placement), Some(ready)) = (
        lifecycle.current_placement.as_ref(),
        lifecycle.effective_runtime_ready.as_ref(),
    ) else {
        return Err(ApiError::internal(
            "Running unbound Endpoint lacks effective RuntimeReady authority",
        ));
    };
    if old_binding.admission_session != *current_session
        || old_binding.placement_identity != *placement
        || old_binding.effective_runtime_ready != *ready
    {
        return Ok(AtomicRouteControllerAction::Invalidate(
            plan_endpoint_invalidation(
                endpoint,
                lifecycle,
                Some(current_session),
                if old_binding.admission_session != *current_session {
                    RouteControlInvalidationReason::AgentSessionReplaced
                } else {
                    RouteControlInvalidationReason::LifecycleCloseAmbiguous
                },
            )?,
        ));
    }
    Ok(AtomicRouteControllerAction::Submit(Box::new(
        AtomicRouteCommandDraft {
            binding: old_binding.clone(),
            predecessor: exact_route_predecessor(head)?,
            command: RouteCommand::Disable,
        },
    )))
}

/// Plans the epoch/pointer half of a Node AdmissionCell close. The sole
/// preserving outcome is the exact never-closed SuspendDeclined proof.
pub(crate) fn plan_lifecycle_route_invalidation(
    endpoints: &[AtomicEndpointRouteAuthority],
    lifecycle_operation_id: &Id,
    outcome: LifecycleAdmissionCloseOutcome,
) -> Result<Vec<RouteEpochInvalidationPlan>> {
    if outcome == LifecycleAdmissionCloseOutcome::NeverClosed {
        return Ok(Vec::new());
    }
    let reason = match outcome {
        LifecycleAdmissionCloseOutcome::Closed => RouteControlInvalidationReason::LifecycleClosed,
        LifecycleAdmissionCloseOutcome::Ambiguous => {
            RouteControlInvalidationReason::LifecycleCloseAmbiguous
        }
        LifecycleAdmissionCloseOutcome::NeverClosed => unreachable!(),
    };
    endpoints
        .iter()
        .filter(|endpoint| endpoint_has_current_or_ambiguous_effect(endpoint))
        .map(|endpoint| {
            plan_invalidation(endpoint, reason, Some(lifecycle_operation_id.clone()), None)
        })
        .collect()
}

/// Session replacement defaults all in-memory gates Closed. Old Serving and
/// pending commands are invalid and each affected current epoch is burned.
pub(crate) fn plan_agent_session_route_invalidation(
    endpoints: &[AtomicEndpointRouteAuthority],
    replacement_session: &SessionBinding,
) -> Result<Vec<RouteEpochInvalidationPlan>> {
    endpoints
        .iter()
        .filter(|endpoint| endpoint_session_differs(endpoint, replacement_session))
        .map(|endpoint| {
            plan_invalidation(
                endpoint,
                RouteControlInvalidationReason::AgentSessionReplaced,
                None,
                Some(replacement_session.clone()),
            )
        })
        .collect()
}

/// Commit-side CAS predicate. A late Serving result is historical evidence
/// only after lifecycle close, binding change, epoch burn or session replace.
pub(crate) fn route_node_result_is_current(
    endpoint: &AtomicEndpointRouteAuthority,
    lifecycle: &AtomicRouteLifecycleAuthority,
    current_session: &SessionBinding,
    command: &RouteCommandEnvelope,
    response: &RouteCommandResponse,
) -> Result<bool> {
    if validate_route_command_response_for_command(response, command).is_err() {
        return Ok(false);
    }
    let Some(unresolved) = &endpoint.unresolved_operation else {
        return Ok(false);
    };
    if unresolved.operation_id != command.operation_id
        || unresolved.request_fingerprint != command.request_fingerprint
        || unresolved.canonical_request.as_ref() != command
        || command.binding.admission_session != *current_session
    {
        return Ok(false);
    }
    match &response.result {
        RouteNodeResult::Serving(_) => {
            if lifecycle.unresolved_leaves_running
                || lifecycle.state != AtomicRouteLifecycleState::Running
            {
                return Ok(false);
            }
            let (Some(binding), Some(placement), Some(ready)) = (
                endpoint.binding.as_ref(),
                lifecycle.current_placement.as_ref(),
                lifecycle.effective_runtime_ready.as_ref(),
            ) else {
                return Ok(false);
            };
            Ok(command.binding
                == close_serving_binding(
                    binding,
                    endpoint.route_epoch,
                    placement,
                    ready,
                    current_session,
                ))
        }
        RouteNodeResult::Closed(_) | RouteNodeResult::Rejected(_) => Ok(true),
    }
}

fn validate_atomic_route_authority(
    endpoint: &AtomicEndpointRouteAuthority,
    lifecycle: &AtomicRouteLifecycleAuthority,
) -> Result<()> {
    if endpoint.workspace_id != lifecycle.workspace_id
        || endpoint.cat_id != lifecycle.cat_id
        || endpoint.binding.as_ref().is_some_and(|binding| {
            binding.workspace_id != endpoint.workspace_id
                || binding.cat_id != endpoint.cat_id
                || binding.endpoint_id != endpoint.endpoint_id
                || binding.target_port == 0
        })
    {
        return Err(ApiError::internal(
            "Endpoint and lifecycle Route authority projections drift",
        ));
    }
    for operation in [
        endpoint.route_head.as_ref(),
        endpoint.effective_serving.as_ref(),
        endpoint.unresolved_operation.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let binding = &operation.canonical_request.binding;
        if operation.endpoint_id != endpoint.endpoint_id
            || binding.workspace_id != endpoint.workspace_id
            || binding.cat_id != endpoint.cat_id
            || binding.endpoint_id != endpoint.endpoint_id
        {
            return Err(ApiError::internal(
                "Route Operation belongs to another Endpoint authority",
            ));
        }
    }
    if endpoint
        .route_head
        .as_ref()
        .is_some_and(|operation| matches!(operation.state, RouteOperationState::Unresolved))
        || endpoint.effective_serving.as_ref().is_some_and(|operation| {
            !matches!(
                operation.state,
                RouteOperationState::Terminal {
                    terminal: ref value
                } if matches!(value.as_ref(), RouteOperationTerminal::NodeResult { response, .. }
                    if matches!(response.result, RouteNodeResult::Serving(_)))
            )
        })
        || endpoint
            .unresolved_operation
            .as_ref()
            .is_some_and(|operation| !matches!(operation.state, RouteOperationState::Unresolved))
    {
        return Err(ApiError::internal("Route current pointers have invalid state"));
    }
    Ok(())
}

fn close_serving_binding(
    endpoint: &CurrentEndpointBinding,
    route_epoch: Epoch,
    placement: &PlacementIdentity,
    ready: &EffectiveRuntimeReady,
    session: &SessionBinding,
) -> RouteServingBinding {
    RouteServingBinding {
        workspace_id: endpoint.workspace_id.clone(),
        endpoint_id: endpoint.endpoint_id.clone(),
        hostname: endpoint.hostname.clone(),
        cat_id: endpoint.cat_id.clone(),
        placement_identity: placement.clone(),
        effective_runtime_ready: ready.clone(),
        route_epoch,
        admission_session: session.clone(),
        protocol: endpoint.protocol,
        target_port: endpoint.target_port,
    }
}

fn route_predecessor(head: Option<&AtomicRouteOperation>) -> Result<RouteCommandPredecessor> {
    head.map_or(
        Ok(RouteCommandPredecessor::Genesis),
        exact_route_predecessor,
    )
}

fn exact_route_predecessor(operation: &AtomicRouteOperation) -> Result<RouteCommandPredecessor> {
    let RouteOperationState::Terminal { terminal } = &operation.state else {
        return Err(ApiError::internal("Route head is not terminal"));
    };
    Ok(RouteCommandPredecessor::Exact {
        operation_id: operation.operation_id.clone(),
        terminal_result_kind: terminal.kind(),
        terminal_result_digest: terminal.digest().clone(),
    })
}

fn exact_serving_response(operation: &AtomicRouteOperation) -> Result<&RouteCommandResponse> {
    let RouteOperationState::Terminal { terminal } = &operation.state else {
        return Err(ApiError::internal("effective Serving is not terminal"));
    };
    let RouteOperationTerminal::NodeResult { response, .. } = terminal.as_ref() else {
        return Err(ApiError::internal(
            "effective Serving names a Control invalidation",
        ));
    };
    if !matches!(response.result, RouteNodeResult::Serving(_)) {
        return Err(ApiError::internal(
            "effective Serving pointer names a non-Serving result",
        ));
    }
    Ok(response)
}

fn terminal_serving_binding(
    operation: &AtomicRouteOperation,
) -> Result<Option<&RouteServingBinding>> {
    let RouteOperationState::Terminal { terminal } = &operation.state else {
        return Err(ApiError::internal("Route head is not terminal"));
    };
    Ok(match terminal.as_ref() {
        RouteOperationTerminal::NodeResult { response, .. }
            if matches!(response.result, RouteNodeResult::Serving(_)) =>
        {
            Some(response.result.binding())
        }
        _ => None,
    })
}

fn classify_stale_binding(
    actual: &RouteServingBinding,
    expected: &RouteServingBinding,
) -> RouteControlInvalidationReason {
    if actual.admission_session != expected.admission_session {
        RouteControlInvalidationReason::AgentSessionReplaced
    } else if actual.workspace_id != expected.workspace_id
        || actual.endpoint_id != expected.endpoint_id
        || actual.hostname != expected.hostname
        || actual.cat_id != expected.cat_id
        || actual.route_epoch != expected.route_epoch
        || actual.protocol != expected.protocol
        || actual.target_port != expected.target_port
    {
        RouteControlInvalidationReason::EndpointBindingChanged
    } else {
        RouteControlInvalidationReason::LifecycleCloseAmbiguous
    }
}

fn plan_endpoint_invalidation(
    endpoint: &AtomicEndpointRouteAuthority,
    lifecycle: &AtomicRouteLifecycleAuthority,
    current_session: Option<&SessionBinding>,
    reason: RouteControlInvalidationReason,
) -> Result<RouteEpochInvalidationPlan> {
    let lifecycle_id = matches!(
        reason,
        RouteControlInvalidationReason::LifecycleClosed
            | RouteControlInvalidationReason::LifecycleCloseAmbiguous
    )
    .then(|| lifecycle.lifecycle_head_operation_id.clone())
    .flatten();
    let replacement_session = (reason == RouteControlInvalidationReason::AgentSessionReplaced)
        .then(|| current_session.cloned())
        .flatten();
    plan_invalidation(endpoint, reason, lifecycle_id, replacement_session)
}

fn plan_invalidation(
    endpoint: &AtomicEndpointRouteAuthority,
    reason: RouteControlInvalidationReason,
    invalidating_lifecycle_operation_id: Option<Id>,
    replacement_session: Option<SessionBinding>,
) -> Result<RouteEpochInvalidationPlan> {
    let must_burn = endpoint_has_effect_at_current_epoch(endpoint);
    let resulting_route_epoch = if must_burn {
        next_epoch(endpoint.route_epoch)?
    } else {
        endpoint.route_epoch
    };
    Ok(RouteEpochInvalidationPlan {
        endpoint_id: endpoint.endpoint_id.clone(),
        expected_route_epoch: endpoint.route_epoch,
        resulting_route_epoch,
        clear_effective_serving: endpoint.effective_serving.is_some(),
        invalidate_unresolved_operation_id: endpoint
            .unresolved_operation
            .as_ref()
            .map(|operation| operation.operation_id.clone()),
        reason,
        invalidating_lifecycle_operation_id,
        replacement_session,
    })
}

fn endpoint_has_current_or_ambiguous_effect(endpoint: &AtomicEndpointRouteAuthority) -> bool {
    endpoint.effective_serving.is_some() || endpoint.unresolved_operation.is_some()
}

fn endpoint_has_effect_at_current_epoch(endpoint: &AtomicEndpointRouteAuthority) -> bool {
    endpoint
        .effective_serving
        .as_ref()
        .is_some_and(|operation| {
            operation.canonical_request.binding.route_epoch == endpoint.route_epoch
        })
        || endpoint
            .unresolved_operation
            .as_ref()
            .is_some_and(|operation| {
                operation.canonical_request.binding.route_epoch == endpoint.route_epoch
            })
}

fn endpoint_session_differs(
    endpoint: &AtomicEndpointRouteAuthority,
    replacement: &SessionBinding,
) -> bool {
    [
        endpoint.effective_serving.as_ref(),
        endpoint.unresolved_operation.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|operation| operation.canonical_request.binding.admission_session != *replacement)
}

fn next_epoch(epoch: Epoch) -> Result<Epoch> {
    epoch
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or_else(|| ApiError::failed_precondition("Endpoint route epoch is exhausted"))
}

#[cfg(test)]
mod atomic_route_tests {
    use super::*;
    use cats_api::runtime_reconciliation::{
        NodeBootId, RandomId128, Sequence, Sha256Digest, UnixMillis,
    };
    use cats_api::runtime_route::{
        route_terminal_result_digest, RouteCommandResponse, RouteNodeResult, RouteServingResult,
        RouteTerminalResultKind,
    };

    fn id(value: &str) -> Id {
        Id::new(value.to_owned()).unwrap()
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }

    fn random(value: u8) -> RandomId128 {
        RandomId128::new(format!("{value:02x}").repeat(16)).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn session(value: u64) -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("ab".repeat(16)).unwrap(),
            agent_instance_id: random(value as u8),
            agent_session_epoch: epoch(value),
        }
    }

    fn lifecycle(head: &str) -> AtomicRouteLifecycleAuthority {
        AtomicRouteLifecycleAuthority {
            workspace_id: id("workspace_a"),
            cat_id: id("cat_a"),
            lifecycle_head_operation_id: Some(id(head)),
            state: AtomicRouteLifecycleState::Running,
            current_placement: Some(PlacementIdentity {
                node_id: id("node_a"),
                placement_epoch: epoch(3),
            }),
            effective_runtime_ready: Some(EffectiveRuntimeReady {
                source_lifecycle_operation_id: id("start_a"),
                runtime_incarnation: random(4),
                runtime_config_digest: digest(5),
                runtime_ready_receipt_digest: digest(6),
            }),
            unresolved_leaves_running: false,
        }
    }

    fn endpoint(name: &str, route_epoch: u64) -> AtomicEndpointRouteAuthority {
        let endpoint_id = id(name);
        AtomicEndpointRouteAuthority {
            workspace_id: id("workspace_a"),
            cat_id: id("cat_a"),
            endpoint_id: endpoint_id.clone(),
            binding: Some(CurrentEndpointBinding {
                workspace_id: id("workspace_a"),
                cat_id: id("cat_a"),
                endpoint_id,
                hostname: Hostname::new(format!("{}.example.test", name.replace('_', "-")))
                    .unwrap(),
                protocol: HttpProtocol::Http,
                target_port: 8080,
            }),
            route_epoch: epoch(route_epoch),
            route_head: None,
            effective_serving: None,
            unresolved_operation: None,
        }
    }

    fn command_from_action(
        action: AtomicRouteControllerAction,
        operation_id: &str,
    ) -> RouteCommandEnvelope {
        let AtomicRouteControllerAction::Submit(draft) = action else {
            panic!("expected a Route command draft, got {action:?}");
        };
        (*draft).into_envelope(id(operation_id)).unwrap()
    }

    fn unresolved(command: RouteCommandEnvelope) -> AtomicRouteOperation {
        AtomicRouteOperation {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            operation_id: command.operation_id.clone(),
            endpoint_id: command.binding.endpoint_id.clone(),
            command_kind: command.command_kind(),
            request_fingerprint: command.request_fingerprint.clone(),
            canonical_request: Box::new(command),
            state: RouteOperationState::Unresolved,
            created_at_unix_ms: UnixMillis::new(1).unwrap(),
            terminal_at_unix_ms: None,
        }
    }

    fn serving_operation(command: RouteCommandEnvelope) -> AtomicRouteOperation {
        let response = RouteCommandResponse::new(
            &command,
            RouteNodeResult::Serving(RouteServingResult {
                binding: command.binding.clone(),
                admission_cell_receipt_digest: digest(7),
            }),
        )
        .unwrap();
        let terminal_result_digest = route_terminal_result_digest(&response).unwrap();
        AtomicRouteOperation {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            operation_id: command.operation_id.clone(),
            endpoint_id: command.binding.endpoint_id.clone(),
            command_kind: command.command_kind(),
            request_fingerprint: command.request_fingerprint.clone(),
            canonical_request: Box::new(command),
            state: RouteOperationState::Terminal {
                terminal: Box::new(RouteOperationTerminal::NodeResult {
                    response: Box::new(response),
                    terminal_result_digest,
                }),
            },
            created_at_unix_ms: UnixMillis::new(1).unwrap(),
            terminal_at_unix_ms: Some(UnixMillis::new(2).unwrap()),
        }
    }

    #[test]
    fn endpoint_metadata_automatically_derives_exact_enable() {
        let endpoint = endpoint("endpoint_a", 3);
        let lifecycle = lifecycle("start_a");
        let command = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &lifecycle, Some(&session(2))).unwrap(),
            "enable_a",
        );

        assert_eq!(command.command, RouteCommand::Enable);
        assert_eq!(command.binding.route_epoch, epoch(3));
        assert_eq!(
            command
                .binding
                .effective_runtime_ready
                .source_lifecycle_operation_id,
            id("start_a")
        );
        assert_eq!(command.binding.admission_session, session(2));
        assert_eq!(command.predecessor, RouteCommandPredecessor::Genesis);
    }

    #[test]
    fn never_closed_busy_preserves_old_source_serving_and_epoch() {
        let mut endpoint = endpoint("endpoint_a", 3);
        let initial = lifecycle("start_a");
        let command = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &initial, Some(&session(2))).unwrap(),
            "enable_a",
        );
        let serving = serving_operation(command);
        endpoint.route_head = Some(serving.clone());
        endpoint.effective_serving = Some(serving);

        let declined = lifecycle("suspend_declined_a");
        assert_eq!(
            plan_lifecycle_route_invalidation(
                std::slice::from_ref(&endpoint),
                &id("suspend_declined_a"),
                LifecycleAdmissionCloseOutcome::NeverClosed,
            )
            .unwrap(),
            Vec::new()
        );
        assert_eq!(
            plan_atomic_endpoint_route(&endpoint, &declined, Some(&session(2))).unwrap(),
            AtomicRouteControllerAction::Quiescent
        );
        assert_eq!(endpoint.route_epoch, epoch(3));
    }

    #[test]
    fn actual_and_ambiguous_close_burn_only_affected_endpoint_epochs() {
        let lifecycle = lifecycle("start_a");
        let mut active = endpoint("endpoint_a", 3);
        let command = command_from_action(
            plan_atomic_endpoint_route(&active, &lifecycle, Some(&session(2))).unwrap(),
            "enable_a",
        );
        let serving = serving_operation(command);
        active.route_head = Some(serving.clone());
        active.effective_serving = Some(serving);
        let inactive = endpoint("endpoint_b", 8);

        for outcome in [
            LifecycleAdmissionCloseOutcome::Closed,
            LifecycleAdmissionCloseOutcome::Ambiguous,
        ] {
            let plans = plan_lifecycle_route_invalidation(
                &[active.clone(), inactive.clone()],
                &id("stop_a"),
                outcome,
            )
            .unwrap();
            assert_eq!(plans.len(), 1);
            assert_eq!(plans[0].endpoint_id, id("endpoint_a"));
            assert_eq!(plans[0].resulting_route_epoch, epoch(4));
            assert!(plans[0].clear_effective_serving);
        }
    }

    #[test]
    fn session_replacement_invalidates_serving_and_requires_fresh_epoch() {
        let lifecycle = lifecycle("start_a");
        let mut endpoint = endpoint("endpoint_a", 3);
        let command = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &lifecycle, Some(&session(2))).unwrap(),
            "enable_a",
        );
        let serving = serving_operation(command);
        endpoint.route_head = Some(serving.clone());
        endpoint.effective_serving = Some(serving);

        let [plan] =
            plan_agent_session_route_invalidation(std::slice::from_ref(&endpoint), &session(4))
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(plan.resulting_route_epoch, epoch(4));
        assert_eq!(plan.replacement_session, Some(session(4)));
        assert_eq!(
            plan.reason,
            RouteControlInvalidationReason::AgentSessionReplaced
        );
    }

    #[test]
    fn lifecycle_close_wins_race_and_late_serving_has_zero_authority() {
        let lifecycle = lifecycle("start_a");
        let mut endpoint = endpoint("endpoint_a", 3);
        let command = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &lifecycle, Some(&session(2))).unwrap(),
            "enable_a",
        );
        endpoint.unresolved_operation = Some(unresolved(command.clone()));
        let response = RouteCommandResponse::new(
            &command,
            RouteNodeResult::Serving(RouteServingResult {
                binding: command.binding.clone(),
                admission_cell_receipt_digest: digest(7),
            }),
        )
        .unwrap();

        let [close] = plan_lifecycle_route_invalidation(
            std::slice::from_ref(&endpoint),
            &id("stop_a"),
            LifecycleAdmissionCloseOutcome::Closed,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let mut after_close = endpoint;
        after_close.route_epoch = close.resulting_route_epoch;
        after_close.unresolved_operation = None;
        let mut closing_lifecycle = lifecycle;
        closing_lifecycle.unresolved_leaves_running = true;

        assert!(!route_node_result_is_current(
            &after_close,
            &closing_lifecycle,
            &session(2),
            &command,
            &response,
        )
        .unwrap());
    }

    #[test]
    fn enable_first_then_close_also_ends_non_serving_with_burned_epoch() {
        let lifecycle = lifecycle("start_a");
        let mut endpoint = endpoint("endpoint_a", 3);
        let command = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &lifecycle, Some(&session(2))).unwrap(),
            "enable_a",
        );
        endpoint.unresolved_operation = Some(unresolved(command.clone()));
        let response = RouteCommandResponse::new(
            &command,
            RouteNodeResult::Serving(RouteServingResult {
                binding: command.binding.clone(),
                admission_cell_receipt_digest: digest(7),
            }),
        )
        .unwrap();
        assert!(route_node_result_is_current(
            &endpoint,
            &lifecycle,
            &session(2),
            &command,
            &response,
        )
        .unwrap());

        let serving = serving_operation(command);
        endpoint.unresolved_operation = None;
        endpoint.route_head = Some(serving.clone());
        endpoint.effective_serving = Some(serving);
        let [close] = plan_lifecycle_route_invalidation(
            std::slice::from_ref(&endpoint),
            &id("stop_a"),
            LifecycleAdmissionCloseOutcome::Closed,
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert!(close.clear_effective_serving);
        assert_eq!(close.resulting_route_epoch, epoch(4));
    }

    #[test]
    fn endpoint_binding_change_disables_old_head_before_new_enable() {
        let lifecycle = lifecycle("start_a");
        let mut endpoint = endpoint("endpoint_a", 3);
        let enable = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &lifecycle, Some(&session(2))).unwrap(),
            "enable_a",
        );
        let old_binding = enable.binding.clone();
        endpoint.route_head = Some(serving_operation(enable));
        endpoint.route_epoch = epoch(4);
        endpoint.binding.as_mut().unwrap().target_port = 9090;

        let disable = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &lifecycle, Some(&session(2))).unwrap(),
            "disable_old_a",
        );
        assert_eq!(disable.command, RouteCommand::Disable);
        assert_eq!(disable.binding, old_binding);
        assert!(matches!(
            disable.predecessor,
            RouteCommandPredecessor::Exact {
                terminal_result_kind: RouteTerminalResultKind::Serving,
                ..
            }
        ));
    }

    #[test]
    fn epoch_exhaustion_fails_closed() {
        let lifecycle = lifecycle("start_a");
        let mut endpoint = endpoint("endpoint_a", i64::MAX as u64);
        let command = command_from_action(
            plan_atomic_endpoint_route(&endpoint, &lifecycle, Some(&session(2))).unwrap(),
            "enable_a",
        );
        let serving = serving_operation(command);
        endpoint.route_head = Some(serving.clone());
        endpoint.effective_serving = Some(serving);
        assert!(plan_lifecycle_route_invalidation(
            &[endpoint],
            &id("stop_a"),
            LifecycleAdmissionCloseOutcome::Ambiguous,
        )
        .is_err());
    }

    #[test]
    fn command_batches_remain_per_endpoint_not_per_cat() {
        // The route wire is sorted by Endpoint and permits independent
        // commands for two Endpoints of one Cat in the same poll batch.
        assert!(Sequence::new(1).is_some());
        let lifecycle = lifecycle("start_a");
        let a = command_from_action(
            plan_atomic_endpoint_route(&endpoint("endpoint_a", 1), &lifecycle, Some(&session(2)))
                .unwrap(),
            "enable_a",
        );
        let b = command_from_action(
            plan_atomic_endpoint_route(&endpoint("endpoint_b", 1), &lifecycle, Some(&session(2)))
                .unwrap(),
            "enable_b",
        );
        assert_ne!(a.binding.endpoint_id, b.binding.endpoint_id);
        assert_eq!(a.binding.cat_id, b.binding.cat_id);
    }
}

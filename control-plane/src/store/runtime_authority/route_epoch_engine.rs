//! Control-side Endpoint serving lineage and conditional-suspend planning.
//!
//! This module deliberately produces complete successor Desired snapshots; it
//! never writes a Desired row itself.  Callers must submit the returned plan
//! through the A1 covered Desired mutation boundary and its
//! `CoveredCommitState`.

#![allow(
    dead_code,
    reason = "G4 Store planners are composed by the parallel A2/A3 API and singleton slices"
)]

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    spec_digest, AppliedDesiredEvidence, CheckpointEvidence, Condition, DesiredRuntimeSpec,
    EndpointIntent, Epoch, Hostname, HttpProtocol, Id, LifecycleAdmission, Operation,
    OperationFailure, OperationPhase, OperationTerminal, PreconditionFailureReason, RandomId128,
    RequireIdleCheckpoint, Revision, RuntimeTarget, RuntimeTransition, Sha256Digest,
};

use super::placement_planner::{load_current_placement_target_in, PlacementTargetSnapshot};
use super::product::{
    EndpointRecord, EndpointRecordCandidate, RequireIdleAttemptSource, RequireIdleBusySource,
    SystemDesiredMutationCommit, SystemDesiredMutationCommitGuard, SystemDesiredMutationRequest,
};
use super::product_rows::{
    load_desired_unlocked, load_endpoint_by_id_unlocked, load_operation_by_cat_revision_unlocked,
};
use super::runtime_spine::{load_current_cat_runtime_unlocked, CurrentCatRuntime};
use crate::store::{Result, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointBindingWithoutEpoch {
    pub(crate) hostname: Hostname,
    pub(crate) protocol: HttpProtocol,
    pub(crate) target_port: u16,
}

impl EndpointBindingWithoutEpoch {
    pub(crate) fn http(hostname: Hostname, target_port: u16) -> Result<Self> {
        if target_port == 0 {
            return Err(ApiError::invalid("Endpoint target port must be non-zero"));
        }
        Ok(Self {
            hostname,
            protocol: HttpProtocol::Http,
            target_port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EndpointMutation {
    Bind {
        record: EndpointRecordCandidate,
        intent: EndpointBindingWithoutEpoch,
    },
    Unbind {
        endpoint_id: Id,
    },
}

/// Exact accepted Busy fact that permits the sole old-epoch recovery
/// exception: the Node proved that `try_close_all_if_idle` saw guards and
/// therefore left the AdmissionCell open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequireIdleOpenBusyProof {
    pub(crate) node_id: Id,
    pub(crate) agent_session_epoch: Epoch,
    pub(crate) inventory_epoch: Epoch,
    pub(crate) observation_id: RandomId128,
    pub(crate) heartbeat_sequence: cats_api::runtime_reconciliation::Sequence,
    pub(crate) attempt_id: RandomId128,
    pub(crate) source_revision: Revision,
    pub(crate) source_runtime_incarnation: RandomId128,
}

/// Stable G4 domain identity and exact accepted-observation suffix for a
/// one-shot RequireIdle Busy result.  `gate_closed` is deliberately absent:
/// the commit-side validator derives that authority from the accepted
/// checkpoint and matching condition rather than trusting a caller boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequireIdleBusyEvidence {
    pub(crate) node_id: Id,
    pub(crate) agent_session_epoch: Epoch,
    pub(crate) inventory_epoch: Epoch,
    pub(crate) observation_id: RandomId128,
    pub(crate) heartbeat_sequence: cats_api::runtime_reconciliation::Sequence,
    pub(crate) attempt_id: RandomId128,
    pub(crate) source_revision: Revision,
    pub(crate) source_runtime_incarnation: RandomId128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteEpochSystemSource {
    RequireIdleAttempt {
        attempt_id: RandomId128,
        source_revision: Revision,
        source_runtime_incarnation: RandomId128,
    },
    RequireIdleBusy {
        evidence: RequireIdleBusyEvidence,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequireIdleGateOutcome {
    NeverClosed,
    ClosedOrAmbiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteEpochMutationPlan {
    pub(crate) expected_current: DesiredRuntimeSpec,
    pub(crate) desired: DesiredRuntimeSpec,
    pub(crate) endpoint_records: Vec<EndpointRecordCandidate>,
    pub(crate) placement_snapshots: Vec<PlacementTargetSnapshot>,
    pub(crate) active_guest_digest: Sha256Digest,
    pub(crate) require_idle_open_busy_proof: Option<RequireIdleOpenBusyProof>,
    pub(crate) system_source: Option<RouteEpochSystemSource>,
}

impl RouteEpochMutationPlan {
    fn into_system_request(self) -> Result<SystemDesiredMutationRequest> {
        let Self {
            expected_current,
            desired,
            endpoint_records,
            placement_snapshots,
            active_guest_digest,
            require_idle_open_busy_proof,
            system_source,
        } = self;
        match system_source {
            Some(RouteEpochSystemSource::RequireIdleAttempt {
                attempt_id,
                source_revision,
                source_runtime_incarnation,
            }) => Ok(SystemDesiredMutationRequest::require_idle_attempt(
                RequireIdleAttemptSource {
                    attempt_id,
                    source_revision,
                    source_runtime_incarnation,
                },
                expected_current,
                desired,
                placement_snapshots,
                active_guest_digest,
                endpoint_records,
            )),
            Some(RouteEpochSystemSource::RequireIdleBusy { evidence }) => {
                Ok(SystemDesiredMutationRequest::require_idle_busy(
                    RequireIdleBusySource {
                        node_id: evidence.node_id,
                        agent_session_epoch: evidence.agent_session_epoch,
                        inventory_epoch: evidence.inventory_epoch,
                        observation_id: evidence.observation_id,
                        heartbeat_sequence: evidence.heartbeat_sequence,
                        attempt_id: evidence.attempt_id,
                        source_revision: evidence.source_revision,
                        source_runtime_incarnation: evidence.source_runtime_incarnation,
                    },
                    expected_current,
                    desired,
                    placement_snapshots,
                    active_guest_digest,
                    endpoint_records,
                    require_idle_open_busy_proof,
                ))
            }
            None => Err(ApiError::invalid(
                "Endpoint product mutation cannot use the system Desired authority",
            )),
        }
    }
}

impl Store {
    /// Publishes a G4 system plan through A1's shared system-domain suffix.
    /// The caller supplies neither an API replay key nor an Operation ID;
    /// commit ambiguity is resolved by the stable RequireIdle source identity.
    pub(crate) fn commit_route_epoch_system_plan(
        &self,
        plan: RouteEpochMutationPlan,
        guard: &SystemDesiredMutationCommitGuard,
    ) -> Result<SystemDesiredMutationCommit> {
        let request = plan.into_system_request()?;
        self.commit_system_desired_mutation(&request, guard.state())
    }

    /// Plans one Endpoint-only successor from a complete, repeatable-read
    /// snapshot.  The caller supplies product identity/name but never a
    /// revision or serving epoch.
    pub(crate) fn plan_endpoint_route_mutation(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
        mutation: EndpointMutation,
    ) -> Result<RouteEpochMutationPlan> {
        self.authority_read_snapshot(|transaction| {
            plan_endpoint_route_mutation_in(transaction, workspace_id, cat_id, mutation.clone())
        })
    }

    /// Plans the one-shot automatic Running -> Suspended transition.  The
    /// source incarnation comes only from the latest accepted per-Cat runtime
    /// fact; callers cannot supply it.
    pub(crate) fn plan_require_idle_transition(
        &self,
        cat_id: &Id,
        attempt_id: RandomId128,
    ) -> Result<RouteEpochMutationPlan> {
        self.authority_read_snapshot(|transaction| {
            let current = load_desired_unlocked(transaction, cat_id)?
                .ok_or_else(|| ApiError::not_found("Cat"))?;
            let records = load_endpoint_candidates(transaction, &current)?;
            let observed =
                load_current_cat_runtime_unlocked(transaction, &current.placement.node_id, cat_id)?
                    .ok_or_else(|| {
                        ApiError::failed_precondition(
                            "current Running runtime has no accepted fact",
                        )
                    })?;
            plan_require_idle(current, records, observed, attempt_id.clone()).map_err(Into::into)
        })
    }

    /// Plans recovery after the accepted one-shot Busy terminal.  A closed or
    /// ambiguous gate burns every retained Endpoint epoch.  The old epoch is
    /// retained only with the typed accepted proof returned in the plan; A1
    /// revalidates that proof while holding the Node/session/observation
    /// coordination prefix before committing.
    pub(crate) fn plan_require_idle_busy_recovery(
        &self,
        cat_id: &Id,
    ) -> Result<RouteEpochMutationPlan> {
        self.authority_read_snapshot(|transaction| {
            let current = load_desired_unlocked(transaction, cat_id)?
                .ok_or_else(|| ApiError::not_found("Cat"))?;
            let records = load_endpoint_candidates(transaction, &current)?;
            let placement =
                load_current_placement_target_in(transaction, &current)?.ok_or_else(|| {
                    ApiError::failed_precondition(
                        "RequireIdle recovery placement is not currently eligible",
                    )
                })?;
            let observed =
                load_current_cat_runtime_unlocked(transaction, &current.placement.node_id, cat_id)?
                    .ok_or_else(|| {
                        ApiError::failed_precondition("RequireIdle has no accepted terminal fact")
                    })?;
            let operation = load_operation_by_cat_revision_unlocked(
                transaction,
                &current.cat_id,
                current.desired_revision,
            )?
            .ok_or_else(|| corrupt("current RequireIdle Desired has no exact Operation"))?;
            plan_busy_recovery(current, records, observed, operation, vec![placement])
                .map_err(Into::into)
        })
    }
}

pub(super) fn plan_endpoint_route_mutation_in(
    transaction: &mut postgres::Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    mutation: EndpointMutation,
) -> crate::store::transaction::AuthorityTxResult<RouteEpochMutationPlan> {
    let current =
        load_desired_unlocked(transaction, cat_id)?.ok_or_else(|| ApiError::not_found("Cat"))?;
    if current.workspace_id != *workspace_id {
        return Err(ApiError::not_found("Cat").into());
    }
    let records = load_endpoint_candidates(transaction, &current)?;
    plan_endpoint_mutation(current, records, mutation).map_err(Into::into)
}

fn load_endpoint_candidates(
    transaction: &mut postgres::Transaction<'_>,
    desired: &DesiredRuntimeSpec,
) -> crate::store::transaction::AuthorityTxResult<Vec<EndpointRecordCandidate>> {
    let mut records = Vec::with_capacity(desired.endpoints.len());
    for intent in &desired.endpoints {
        let record = load_endpoint_by_id_unlocked(transaction, &intent.endpoint_id)?
            .ok_or_else(|| corrupt("current Desired Endpoint has no product record"))?;
        validate_endpoint_record(desired, intent, &record)?;
        records.push(candidate_from_record(record));
    }
    Ok(records)
}

fn validate_endpoint_record(
    desired: &DesiredRuntimeSpec,
    intent: &EndpointIntent,
    record: &EndpointRecord,
) -> crate::store::transaction::AuthorityTxResult<()> {
    if record.endpoint_id != intent.endpoint_id
        || record.workspace_id != desired.workspace_id
        || record.cat_id != desired.cat_id
    {
        return Err(corrupt("Endpoint product record/Desired binding drift"));
    }
    Ok(())
}

fn candidate_from_record(record: EndpointRecord) -> EndpointRecordCandidate {
    EndpointRecordCandidate {
        endpoint_id: record.endpoint_id,
        workspace_id: record.workspace_id,
        cat_id: record.cat_id,
        name: record.name,
    }
}

fn plan_endpoint_mutation(
    current: DesiredRuntimeSpec,
    mut endpoint_records: Vec<EndpointRecordCandidate>,
    mutation: EndpointMutation,
) -> Result<RouteEpochMutationPlan> {
    let mut desired = successor_shell(&current)?;
    match mutation {
        EndpointMutation::Bind { record, intent } => {
            if record.workspace_id != current.workspace_id || record.cat_id != current.cat_id {
                return Err(ApiError::invalid(
                    "Endpoint product identity belongs to another Cat or Workspace",
                ));
            }
            if current
                .endpoints
                .iter()
                .any(|endpoint| endpoint.endpoint_id == record.endpoint_id)
                || endpoint_records.iter().any(|existing| {
                    existing.endpoint_id == record.endpoint_id || existing.name == record.name
                })
            {
                return Err(ApiError::conflict(
                    "Endpoint identity or Cat-local name already exists",
                ));
            }
            if current
                .endpoints
                .iter()
                .any(|endpoint| endpoint.hostname == intent.hostname)
            {
                return Err(ApiError::conflict("Endpoint hostname already exists"));
            }
            desired.endpoints.push(EndpointIntent {
                endpoint_id: record.endpoint_id.clone(),
                hostname: intent.hostname,
                route_epoch: Epoch::new(1).expect("one is a valid serving epoch"),
                protocol: intent.protocol,
                target_port: intent.target_port,
            });
            endpoint_records.push(record);
        }
        EndpointMutation::Unbind { endpoint_id } => {
            let before = desired.endpoints.len();
            desired
                .endpoints
                .retain(|endpoint| endpoint.endpoint_id != endpoint_id);
            if desired.endpoints.len() == before {
                return Err(ApiError::not_found("Endpoint"));
            }
            endpoint_records.retain(|record| record.endpoint_id != endpoint_id);
        }
    }
    desired
        .endpoints
        .sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
    endpoint_records.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
    finish_plan(current, desired, endpoint_records, Vec::new(), None, None)
}

fn plan_require_idle(
    current: DesiredRuntimeSpec,
    endpoint_records: Vec<EndpointRecordCandidate>,
    observed: CurrentCatRuntime,
    attempt_id: RandomId128,
) -> Result<RouteEpochMutationPlan> {
    if current.target != RuntimeTarget::Running {
        return Err(ApiError::failed_precondition(
            "RequireIdle source Desired is not Running",
        ));
    }
    validate_applied_current(&current, &observed)?;
    let source_runtime_incarnation = observed
        .runtime
        .runtime_incarnation
        .clone()
        .ok_or_else(|| ApiError::failed_precondition("Running runtime has no incarnation"))?;
    if observed.runtime.stable_state != Some(cats_api::runtime_reconciliation::StableState::Running)
        || observed.runtime.lifecycle_admission != LifecycleAdmission::Open
    {
        return Err(ApiError::failed_precondition(
            "RequireIdle source is not observed stable Running with open admission",
        ));
    }
    let mut desired = successor_shell(&current)?;
    desired.target = RuntimeTarget::Suspended;
    desired.transition = RuntimeTransition::RequireIdle {
        attempt_id: attempt_id.clone(),
        source_revision: current.desired_revision,
        source_runtime_incarnation: source_runtime_incarnation.clone(),
    };
    let system_source = RouteEpochSystemSource::RequireIdleAttempt {
        attempt_id,
        source_revision: current.desired_revision,
        source_runtime_incarnation,
    };
    finish_plan(
        current,
        desired,
        endpoint_records,
        Vec::new(),
        None,
        Some(system_source),
    )
}

fn plan_busy_recovery(
    current: DesiredRuntimeSpec,
    endpoint_records: Vec<EndpointRecordCandidate>,
    observed: CurrentCatRuntime,
    operation: Operation,
    placement_snapshots: Vec<PlacementTargetSnapshot>,
) -> Result<RouteEpochMutationPlan> {
    let RuntimeTransition::RequireIdle {
        attempt_id,
        source_revision,
        source_runtime_incarnation,
    } = &current.transition
    else {
        return Err(ApiError::failed_precondition(
            "current Desired is not a RequireIdle transition",
        ));
    };
    if current.target != RuntimeTarget::Suspended {
        return Err(ApiError::failed_precondition(
            "RequireIdle recovery source Desired is not Suspended",
        ));
    }
    validate_applied_current(&current, &observed)?;
    let busy = require_idle_busy_fact(
        &observed,
        attempt_id,
        *source_revision,
        source_runtime_incarnation,
    )?;
    validate_busy_operation_settlement(&current, &observed, &operation)?;
    let mut desired = successor_shell(&current)?;
    desired.target = RuntimeTarget::Running;
    desired.transition = RuntimeTransition::CancelAndDrain;
    let evidence = RequireIdleBusyEvidence {
        node_id: observed.session.node_id.clone(),
        agent_session_epoch: observed.session.agent_session_epoch,
        inventory_epoch: observed.inventory_epoch,
        observation_id: observed.source_observation_id.clone(),
        heartbeat_sequence: observed.heartbeat_sequence,
        attempt_id: attempt_id.clone(),
        source_revision: *source_revision,
        source_runtime_incarnation: source_runtime_incarnation.clone(),
    };
    let proof = if busy.gate_closed {
        for endpoint in &mut desired.endpoints {
            endpoint.route_epoch = next_epoch(endpoint.route_epoch)?;
        }
        None
    } else {
        Some(RequireIdleOpenBusyProof {
            node_id: observed.session.node_id.clone(),
            agent_session_epoch: observed.session.agent_session_epoch,
            inventory_epoch: observed.inventory_epoch,
            observation_id: observed.source_observation_id,
            heartbeat_sequence: observed.heartbeat_sequence,
            attempt_id: attempt_id.clone(),
            source_revision: *source_revision,
            source_runtime_incarnation: source_runtime_incarnation.clone(),
        })
    };
    finish_plan(
        current,
        desired,
        endpoint_records,
        placement_snapshots,
        proof,
        Some(RouteEpochSystemSource::RequireIdleBusy { evidence }),
    )
}

fn validate_busy_operation_settlement(
    current: &DesiredRuntimeSpec,
    observed: &CurrentCatRuntime,
    operation: &Operation,
) -> Result<()> {
    let busy_reason = observed
        .runtime
        .conditions
        .iter()
        .find_map(|condition| match condition {
            Condition::PreconditionFailed { reason }
                if matches!(reason, PreconditionFailureReason::Busy { .. }) =>
            {
                Some(reason)
            }
            _ => None,
        })
        .ok_or_else(|| ApiError::failed_precondition("accepted Busy has no terminal condition"))?;
    let terminal_matches = matches!(
        &operation.terminal,
        Some(OperationTerminal::Failed { error, .. })
            if matches!(error.as_ref(), OperationFailure::PreconditionFailed { reason }
                if reason == busy_reason)
    );
    if operation.workspace_id != current.workspace_id
        || operation.cat_id != current.cat_id
        || operation.desired_revision != current.desired_revision
        || operation.desired_spec_digest != current.spec_digest
        || operation.placement != current.placement
        || operation.target != current.target
        || operation.phase != OperationPhase::Failed
        || !terminal_matches
    {
        return Err(ApiError::failed_precondition(
            "RequireIdle Busy has not settled the exact current Operation",
        ));
    }
    Ok(())
}

struct BusyFact {
    gate_closed: bool,
}

fn require_idle_busy_fact(
    observed: &CurrentCatRuntime,
    attempt_id: &RandomId128,
    source_revision: Revision,
    source_runtime_incarnation: &RandomId128,
) -> Result<BusyFact> {
    let checkpoint_busy = match &observed.runtime.checkpoint {
        CheckpointEvidence::Valid { require_idle, .. } => match require_idle.as_ref() {
            RequireIdleCheckpoint::Busy {
                attempt_id: observed_attempt,
                source_revision: observed_revision,
                source_runtime_incarnation: observed_incarnation,
                gate_closed,
                platform_guards,
                endpoint_guards,
            } if observed_attempt == attempt_id
                && *observed_revision == source_revision
                && observed_incarnation == source_runtime_incarnation =>
            {
                Some((*gate_closed, *platform_guards, endpoint_guards))
            }
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| {
        ApiError::failed_precondition("accepted runtime lacks exact terminal RequireIdle Busy")
    })?;
    let matching = observed
        .runtime
        .conditions
        .iter()
        .filter_map(|condition| match condition {
            Condition::PreconditionFailed {
                reason:
                    PreconditionFailureReason::Busy {
                        attempt_id: observed_attempt,
                        gate_closed,
                        platform_guards,
                        endpoint_guards,
                    },
            } if observed_attempt == attempt_id => {
                Some((*gate_closed, *platform_guards, endpoint_guards))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(gate_closed, platform_guards, endpoint_guards)] = matching.as_slice() else {
        return Err(ApiError::failed_precondition(
            "accepted runtime does not contain one exact Busy condition",
        ));
    };
    if (*gate_closed, *platform_guards, *endpoint_guards) != checkpoint_busy {
        return Err(ApiError::internal(
            "accepted Busy condition/checkpoint projection mismatch",
        ));
    }
    if !gate_closed
        && (observed.runtime.lifecycle_admission != LifecycleAdmission::Open
            || observed.runtime.runtime_incarnation.as_ref() != Some(source_runtime_incarnation))
    {
        return Err(ApiError::failed_precondition(
            "never-closed Busy proof does not retain the source runtime and open cell",
        ));
    }
    Ok(BusyFact {
        gate_closed: *gate_closed,
    })
}

pub(super) fn open_busy_proof_matches(
    expected_current: &DesiredRuntimeSpec,
    observed: &CurrentCatRuntime,
    proof: &RequireIdleOpenBusyProof,
) -> bool {
    let RuntimeTransition::RequireIdle {
        attempt_id,
        source_revision,
        source_runtime_incarnation,
    } = &expected_current.transition
    else {
        return false;
    };
    proof.node_id == expected_current.placement.node_id
        && proof.node_id == observed.session.node_id
        && proof.agent_session_epoch == observed.session.agent_session_epoch
        && proof.inventory_epoch == observed.inventory_epoch
        && proof.observation_id == observed.source_observation_id
        && proof.heartbeat_sequence == observed.heartbeat_sequence
        && proof.attempt_id == *attempt_id
        && proof.source_revision == *source_revision
        && proof.source_runtime_incarnation == *source_runtime_incarnation
        && validate_applied_current(expected_current, observed).is_ok()
        && require_idle_busy_fact(
            observed,
            attempt_id,
            *source_revision,
            source_runtime_incarnation,
        )
        .is_ok_and(|busy| !busy.gate_closed)
}

pub(super) fn busy_evidence_matches(
    expected_current: &DesiredRuntimeSpec,
    observed: &CurrentCatRuntime,
    evidence: &RequireIdleBusyEvidence,
) -> Option<RequireIdleGateOutcome> {
    let RuntimeTransition::RequireIdle {
        attempt_id,
        source_revision,
        source_runtime_incarnation,
    } = &expected_current.transition
    else {
        return None;
    };
    if evidence.node_id != expected_current.placement.node_id
        || evidence.node_id != observed.session.node_id
        || evidence.agent_session_epoch != observed.session.agent_session_epoch
        || evidence.inventory_epoch != observed.inventory_epoch
        || evidence.observation_id != observed.source_observation_id
        || evidence.heartbeat_sequence != observed.heartbeat_sequence
        || evidence.attempt_id != *attempt_id
        || evidence.source_revision != *source_revision
        || evidence.source_runtime_incarnation != *source_runtime_incarnation
        || validate_applied_current(expected_current, observed).is_err()
    {
        return None;
    }
    require_idle_busy_fact(
        observed,
        attempt_id,
        *source_revision,
        source_runtime_incarnation,
    )
    .ok()
    .map(|busy| {
        if busy.gate_closed {
            RequireIdleGateOutcome::ClosedOrAmbiguous
        } else {
            RequireIdleGateOutcome::NeverClosed
        }
    })
}

fn validate_applied_current(
    current: &DesiredRuntimeSpec,
    observed: &CurrentCatRuntime,
) -> Result<()> {
    let expected = AppliedDesiredEvidence {
        desired_revision: current.desired_revision,
        spec_digest: current.spec_digest.clone(),
        placement: current.placement.clone(),
        target: current.target,
    };
    if observed.runtime.cat_id != current.cat_id
        || observed.session.node_id != current.placement.node_id
        || observed.runtime.applied_desired.as_ref() != Some(&expected)
    {
        return Err(ApiError::failed_precondition(
            "accepted runtime does not apply the exact current Desired",
        ));
    }
    Ok(())
}

fn successor_shell(current: &DesiredRuntimeSpec) -> Result<DesiredRuntimeSpec> {
    let mut desired = current.clone();
    desired.desired_revision = current
        .desired_revision
        .get()
        .checked_add(1)
        .and_then(Revision::new)
        .ok_or_else(|| ApiError::failed_precondition("Desired revision is exhausted"))?;
    Ok(desired)
}

fn finish_plan(
    current: DesiredRuntimeSpec,
    mut desired: DesiredRuntimeSpec,
    endpoint_records: Vec<EndpointRecordCandidate>,
    placement_snapshots: Vec<PlacementTargetSnapshot>,
    require_idle_open_busy_proof: Option<RequireIdleOpenBusyProof>,
    system_source: Option<RouteEpochSystemSource>,
) -> Result<RouteEpochMutationPlan> {
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(&desired)
        .map_err(|error| ApiError::internal(format!("cannot digest successor Desired: {error}")))?;
    Ok(RouteEpochMutationPlan {
        active_guest_digest: current.runtime.guest_config_digest.clone(),
        expected_current: current,
        desired,
        endpoint_records,
        placement_snapshots,
        require_idle_open_busy_proof,
        system_source,
    })
}

fn next_epoch(epoch: Epoch) -> Result<Epoch> {
    epoch
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or_else(|| ApiError::failed_precondition("Endpoint route epoch is exhausted"))
}

fn corrupt(message: &'static str) -> crate::store::transaction::AuthorityTransactionError {
    ApiError::internal(message).into()
}

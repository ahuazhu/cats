//! A23 placement planner and deterministic isolated-IPv4 allocator.
//!
//! The planner reads every fact in one repeatable-read, read-only PostgreSQL
//! snapshot. It deliberately persists neither capacity counters nor network
//! leases: current complete Desired rows plus the fresh A20 full inventory are
//! the one authority, and the Cat-create transaction revalidates the selected
//! snapshot under the NodeIdentity coordination lock before writing anything.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use cats_api::runtime_reconciliation::{
    DesiredRuntimeSpec, Epoch, Id, Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig,
    NodePlacementPolicy, NodeResidue, Revision, RuntimeSchedulingState, Sha256Digest,
};
use cats_storage::authority::{AuthorityError, HostFenceEvent};
use postgres::Transaction;
use sha2::{Digest as _, Sha256};

use super::cat_create_service::{
    CatCreatePlacementMutation, CatCreatePlacementOutcome, CatCreatePlacementPlanner,
    CatCreatePlan, CatCreatePlanRequest, ServiceFuture,
};
use super::placement_policy::load_policy_unlocked;
use super::product_rows::{load_assigned_desired_unlocked, load_desired_by_network_id_unlocked};
use super::rows::{database_now, load_active_event_by_node_unlocked};
use super::runtime_spine::{
    load_placement_admission_at_in_checked, lock_placement_admission_for_desired_mutation_checked,
    PlacementAdmissionLoad, PlacementAdmissionRejection, PlacementAdmissionSnapshot,
    MAX_ASSIGNED_SPECS,
};
use crate::store::agent_sessions::{
    load_identity_by_node_for_update, load_identity_by_node_unlocked,
    load_provisioned_node_keys_after, PROVISIONED_NODE_ID_PAGE_SIZE,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{ApiError, Result, Store};

const IPV4_SLOT_COUNT: u32 = 16_383;
const IPV4_SLOT_BYTES: u32 = 4;
#[cfg(test)]
const PLACEMENT_PLANNER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

struct OwnedPlannerExecution<F> {
    live: Arc<AtomicBool>,
    execution: Pin<Box<F>>,
}

impl<F> OwnedPlannerExecution<F> {
    fn new(live: Arc<AtomicBool>, execution: F) -> Self {
        Self {
            live,
            execution: Box::pin(execution),
        }
    }
}

impl<F: Future> Future for OwnedPlannerExecution<F> {
    type Output = F::Output;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.execution.as_mut().poll(context)
    }
}

impl<F> Drop for OwnedPlannerExecution<F> {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
    }
}

/// Complete target facts retained by a placement plan and revalidated by the
/// Desired mutation. An eligible target always has `None` for the fence, but
/// keeping the closed field prevents a later caller from silently dropping
/// that planner input from plan equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlacementTargetSnapshot {
    pub(crate) policy: NodePlacementPolicy,
    pub(crate) admission: PlacementAdmissionSnapshot,
    pub(crate) active_host_fence_event: Option<HostFenceEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlacementCandidateRejection {
    ActiveHostFenceEvent,
    PolicyCordoned,
    PolicyGuestConfigMismatch,
    Admission(PlacementAdmissionRejection),
    NetworkCleanupPending,
    AssignedSetLimit,
    InsufficientVcpus,
    InsufficientMemory,
    NetworkExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CatCreatePlacementLoad {
    Planned(Box<CatCreatePlan>),
    Unavailable {
        first_rejection: Option<(Id, PlacementCandidateRejection)>,
    },
    CandidateIdentityCollision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlacementCommitLoad {
    Accepted,
    Stale,
}

/// Production Cat-create planner adapter. PostgreSQL work stays on the
/// Control Store's bounded blocking executor rather than the async runtime.
pub(crate) struct PostgresCatCreatePlacementPlanner {
    store: Arc<Store>,
}

impl PostgresCatCreatePlacementPlanner {
    #[allow(dead_code, reason = "wired by the A23 Cat-create HTTP composition")]
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl CatCreatePlacementPlanner for PostgresCatCreatePlacementPlanner {
    fn plan<'a>(
        &'a self,
        request: &'a CatCreatePlanRequest,
        deadline: Instant,
    ) -> ServiceFuture<'a, CatCreatePlacementOutcome> {
        let store = Arc::clone(&self.store);
        let request = request.clone();
        Box::pin(async move {
            let live = Arc::new(AtomicBool::new(true));
            let worker_live = Arc::clone(&live);
            let execution = store.execute(move |store| {
                store.plan_cat_create_placement_until(&request, deadline, &worker_live)
            });
            let execution = OwnedPlannerExecution::new(Arc::clone(&live), execution);
            let outcome =
                tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), execution)
                    .await
                    .map_err(|_| ApiError::unavailable("placement planning deadline elapsed"))??;
            match outcome {
                CatCreatePlacementLoad::Planned(plan) => {
                    Ok(CatCreatePlacementOutcome::Planned(*plan))
                }
                CatCreatePlacementLoad::Unavailable { .. } => {
                    Ok(CatCreatePlacementOutcome::Unavailable)
                }
                CatCreatePlacementLoad::CandidateIdentityCollision => {
                    Ok(CatCreatePlacementOutcome::CandidateIdentityCollision)
                }
            }
        })
    }
}

impl Store {
    #[cfg(test)]
    pub(crate) fn plan_cat_create_placement(
        &self,
        request: &CatCreatePlanRequest,
    ) -> Result<CatCreatePlacementLoad> {
        let deadline = Instant::now()
            .checked_add(PLACEMENT_PLANNER_DEADLINE)
            .ok_or_else(|| ApiError::unavailable("placement planner deadline overflow"))?;
        let live = Arc::new(AtomicBool::new(true));
        self.plan_cat_create_placement_until(request, deadline, &live)
    }

    fn plan_cat_create_placement_until(
        &self,
        request: &CatCreatePlanRequest,
        deadline: Instant,
        live: &AtomicBool,
    ) -> Result<CatCreatePlacementLoad> {
        self.authority_read_snapshot(|transaction| {
            plan_cat_create_placement_in(transaction, request, deadline, live)
        })
    }
}

fn plan_cat_create_placement_in(
    transaction: &mut Transaction<'_>,
    request: &CatCreatePlanRequest,
    deadline: Instant,
    live: &AtomicBool,
) -> AuthorityTxResult<CatCreatePlacementLoad> {
    refresh_planner_deadline(transaction, deadline, live)?;
    let now = database_now(transaction)?;
    refresh_planner_deadline(transaction, deadline, live)?;
    if load_desired_by_network_id_unlocked(transaction, &request.network_id)?.is_some() {
        return Ok(CatCreatePlacementLoad::CandidateIdentityCollision);
    }
    let mut after = None;
    let mut first_rejection = None;
    loop {
        refresh_planner_deadline(transaction, deadline, live)?;
        let node_keys = load_provisioned_node_keys_after(transaction, after.as_ref())?;
        let has_more = node_keys.len() == PROVISIONED_NODE_ID_PAGE_SIZE;
        let mut last_node_id = None;
        for node_key in &node_keys {
            refresh_planner_deadline(transaction, deadline, live)?;
            let node_id = Id::new(node_key.clone())
                .ok_or_else(|| corrupt("provisioned NodeIdentity key is malformed"))?;
            refresh_planner_deadline(transaction, deadline, live)?;
            let identity = load_identity_by_node_unlocked(transaction, &node_id)?
                .ok_or_else(|| corrupt("provisioned NodeIdentity page entry disappeared"))?;
            if identity.node_id != node_id
                || identity.state
                    != cats_api::runtime_reconciliation::NodeIdentityState::Provisioned
            {
                return Err(corrupt(
                    "provisioned NodeIdentity page entry changed its identity or state",
                ));
            }
            last_node_id = Some(node_id);
            refresh_planner_deadline(transaction, deadline, live)?;
            let policy = load_policy_unlocked(transaction, &identity.node_id)?
                .ok_or_else(|| corrupt("provisioned NodeIdentity has no placement policy"))?;
            if policy.node_id != identity.node_id {
                return Err(corrupt("placement policy belongs to another Node"));
            }
            // Stored Desired corruption is fatal even when this Node later
            // proves cordoned, expired or otherwise ordinarily ineligible.
            // In particular a hidden 1025th assignment must not be skipped in
            // favor of a later candidate.
            refresh_planner_deadline(transaction, deadline, live)?;
            let current_assigned = load_assigned_desired_unlocked(
                transaction,
                &identity.node_id,
                MAX_ASSIGNED_SPECS.saturating_add(1),
            )?;
            validate_current_assigned(&policy, &current_assigned)?;
            refresh_planner_deadline(transaction, deadline, live)?;
            let active_host_fence_event =
                load_active_event_by_node_unlocked(transaction, &identity.node_id)?;
            refresh_planner_deadline(transaction, deadline, live)?;
            let admission = load_placement_admission_at_in_checked(
                transaction,
                &identity.node_id,
                &request.guest_config_digest,
                now,
                &mut |transaction| refresh_planner_deadline(transaction, deadline, live),
            )?;
            let admission = match admission {
                PlacementAdmissionLoad::Accepted(admission) => *admission,
                PlacementAdmissionLoad::Rejected(rejection) => {
                    remember_rejection(
                        &mut first_rejection,
                        &identity.node_id,
                        PlacementCandidateRejection::Admission(rejection),
                    );
                    continue;
                }
            };
            if admission.node_identity != identity {
                return Err(corrupt(
                    "placement admission identity differs from candidate page identity",
                ));
            }
            let rejection = if active_host_fence_event.is_some() {
                Some(PlacementCandidateRejection::ActiveHostFenceEvent)
            } else if policy.scheduling_state == RuntimeSchedulingState::Cordoned {
                Some(PlacementCandidateRejection::PolicyCordoned)
            } else if policy.capabilities.guest_config_digest != request.guest_config_digest {
                Some(PlacementCandidateRejection::PolicyGuestConfigMismatch)
            } else {
                None
            };
            if let Some(rejection) = rejection {
                remember_rejection(&mut first_rejection, &identity.node_id, rejection);
                continue;
            }
            match evaluate_create_candidate(
                &policy,
                &admission,
                &request.cat_id,
                request.vcpus,
                request.memory_bytes,
                &request.network_id,
            )? {
                CandidateEvaluation::Eligible(network_config) => {
                    return Ok(CatCreatePlacementLoad::Planned(Box::new(CatCreatePlan {
                        target: PlacementTargetSnapshot {
                            policy,
                            admission,
                            active_host_fence_event,
                        },
                        mutation: CatCreatePlacementMutation {
                            cat_id: request.cat_id.clone(),
                            desired_revision: Revision::new(1).expect("one is a valid Revision"),
                            placement_epoch: Epoch::new(1).expect("one is a valid Epoch"),
                            vcpus: request.vcpus,
                            memory_bytes: request.memory_bytes,
                            network_config,
                        },
                    })));
                }
                CandidateEvaluation::Rejected(rejection) => {
                    remember_rejection(&mut first_rejection, &identity.node_id, rejection);
                }
                CandidateEvaluation::CandidateIdentityCollision => {
                    return Ok(CatCreatePlacementLoad::CandidateIdentityCollision);
                }
            }
        }
        if !has_more {
            return Ok(CatCreatePlacementLoad::Unavailable { first_rejection });
        }
        after = last_node_id;
        if after.is_none() {
            return Err(corrupt("provisioned Node page lost its keyset cursor"));
        }
    }
}

fn refresh_planner_deadline(
    transaction: &mut Transaction<'_>,
    deadline: Instant,
    live: &AtomicBool,
) -> AuthorityTxResult<()> {
    if !live.load(Ordering::Acquire) {
        return Err(ApiError::unavailable("placement planning was cancelled").into());
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| ApiError::unavailable("placement planning deadline elapsed"))?;
    let remaining_ms = remaining.as_millis().clamp(1, 5_000);
    transaction.query_one(
        "SELECT set_config('statement_timeout', $1, true)",
        &[&format!("{remaining_ms}ms")],
    )?;
    Ok(())
}

fn remember_rejection(
    first: &mut Option<(Id, PlacementCandidateRejection)>,
    node_id: &Id,
    rejection: PlacementCandidateRejection,
) {
    if first.is_none() {
        *first = Some((node_id.clone(), rejection));
    }
}

enum CandidateEvaluation {
    Eligible(NetworkConfig),
    Rejected(PlacementCandidateRejection),
    CandidateIdentityCollision,
}

struct ValidatedAssignedSet {
    cat_ids: BTreeSet<Id>,
    network_ids: BTreeSet<Id>,
    occupied_slots: BTreeSet<u32>,
    desired_networks: BTreeMap<Id, NetworkConfig>,
    total_vcpus: u128,
    total_memory: u128,
}

fn validate_current_assigned(
    policy: &NodePlacementPolicy,
    assigned: &[cats_api::runtime_reconciliation::DesiredRuntimeSpec],
) -> AuthorityTxResult<ValidatedAssignedSet> {
    if assigned.len() > MAX_ASSIGNED_SPECS {
        return Err(corrupt("current assigned Desired set exceeds its hard cap"));
    }
    let mut validated = ValidatedAssignedSet {
        cat_ids: BTreeSet::new(),
        network_ids: BTreeSet::new(),
        occupied_slots: BTreeSet::new(),
        desired_networks: BTreeMap::new(),
        total_vcpus: 0,
        total_memory: 0,
    };
    for desired in assigned {
        if desired.placement.node_id != policy.node_id
            || !validated.cat_ids.insert(desired.cat_id.clone())
        {
            return Err(corrupt("assigned Desired set is not a unique per-Node map"));
        }
        validated.total_vcpus = validated
            .total_vcpus
            .checked_add(u128::from(desired.runtime.vcpus))
            .ok_or_else(|| corrupt("assigned vCPU sum overflow"))?;
        validated.total_memory = validated
            .total_memory
            .checked_add(u128::from(desired.runtime.memory_bytes))
            .ok_or_else(|| corrupt("assigned memory sum overflow"))?;
        let network = &desired.runtime.network_config;
        let slot = validate_network_config(policy, network)?;
        if !validated.occupied_slots.insert(slot)
            || !validated.network_ids.insert(network.network_id.clone())
            || validated
                .desired_networks
                .insert(desired.cat_id.clone(), network.clone())
                .is_some()
        {
            return Err(corrupt(
                "assigned Desired network slots or identities are duplicated",
            ));
        }
    }
    Ok(validated)
}

fn evaluate_create_candidate(
    policy: &NodePlacementPolicy,
    admission: &PlacementAdmissionSnapshot,
    cat_id: &Id,
    vcpus: u32,
    memory_bytes: u64,
    network_id: &Id,
) -> AuthorityTxResult<CandidateEvaluation> {
    let assigned = &admission.assigned_desired_specs;
    let validated = validate_current_assigned(policy, assigned)?;
    if validated.cat_ids.contains(cat_id) || validated.network_ids.contains(network_id) {
        return Ok(CandidateEvaluation::CandidateIdentityCollision);
    }
    if assigned.len() == MAX_ASSIGNED_SPECS {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::AssignedSetLimit,
        ));
    }
    if !observation_networks_are_clean(admission, &validated.desired_networks) {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::NetworkCleanupPending,
        ));
    }

    let post_vcpus = validated
        .total_vcpus
        .checked_add(u128::from(vcpus))
        .ok_or_else(|| corrupt("post-create vCPU sum overflow"))?;
    if post_vcpus > u128::from(policy.allocatable_vcpus.get()) {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::InsufficientVcpus,
        ));
    }
    let post_memory = validated
        .total_memory
        .checked_add(u128::from(memory_bytes))
        .ok_or_else(|| corrupt("post-create memory sum overflow"))?;
    if post_memory > u128::from(policy.allocatable_memory_bytes.get()) {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::InsufficientMemory,
        ));
    }
    let Some(network) = allocate_network(policy, network_id, &validated.occupied_slots)? else {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::NetworkExhausted,
        ));
    };
    Ok(CandidateEvaluation::Eligible(network))
}

/// Revalidates a Cat-create target after the caller has reserved the API key
/// and proved the name is free, but before any Volume/business row lock. The
/// A20 helper takes the NodeIdentity coordination lock first; policy, fence,
/// capacity and network allocation then observe the serialized current set.
pub(super) fn lock_cat_create_placement_for_desired_mutation(
    transaction: &mut Transaction<'_>,
    planned: &PlacementTargetSnapshot,
    planned_mutation: &CatCreatePlacementMutation,
    active_guest_digest: &Sha256Digest,
    checkpoint: &mut impl FnMut(&mut Transaction<'_>) -> AuthorityTxResult<()>,
) -> AuthorityTxResult<PlacementCommitLoad> {
    if planned.policy.node_id != planned.admission.node_identity.node_id
        || planned.policy.capabilities.guest_config_digest != *active_guest_digest
        || planned.active_host_fence_event.is_some()
    {
        return Ok(PlacementCommitLoad::Stale);
    }

    // The NodeIdentity row is the first and sole assigned-set coordination
    // lock. Strictly load policy, the complete bounded current Desired map and
    // HostFence before interpreting an ordinary session/inventory rejection;
    // stored corruption must never be downgraded to a retryable stale plan.
    checkpoint(transaction)?;
    let Some(identity) =
        load_identity_by_node_for_update(transaction, &planned.admission.node_identity.node_id)?
    else {
        return Ok(PlacementCommitLoad::Stale);
    };
    if identity.state != cats_api::runtime_reconciliation::NodeIdentityState::Provisioned
        || identity != planned.admission.node_identity
    {
        return Ok(PlacementCommitLoad::Stale);
    }
    checkpoint(transaction)?;
    let Some(current_policy) = load_policy_unlocked(transaction, &identity.node_id)? else {
        return Err(corrupt(
            "provisioned NodeIdentity lost its placement policy",
        ));
    };
    if current_policy.node_id != identity.node_id {
        return Err(corrupt("placement policy belongs to another Node"));
    }
    checkpoint(transaction)?;
    let current_assigned = load_assigned_desired_unlocked(
        transaction,
        &identity.node_id,
        MAX_ASSIGNED_SPECS.saturating_add(1),
    )?;
    validate_current_assigned(&current_policy, &current_assigned)?;
    checkpoint(transaction)?;
    let current_event = load_active_event_by_node_unlocked(transaction, &identity.node_id)?;
    checkpoint(transaction)?;
    if current_policy != planned.policy || current_event != planned.active_host_fence_event {
        return Ok(PlacementCommitLoad::Stale);
    }

    let current_admission = match lock_placement_admission_for_desired_mutation_checked(
        transaction,
        &planned.admission,
        active_guest_digest,
        checkpoint,
    )? {
        PlacementAdmissionLoad::Accepted(admission) => *admission,
        PlacementAdmissionLoad::Rejected(_) => return Ok(PlacementCommitLoad::Stale),
    };
    if current_admission.assigned_desired_specs != current_assigned {
        return Err(corrupt(
            "placement admission current Desired set changed under NodeIdentity lock",
        ));
    }
    checkpoint(transaction)?;
    match evaluate_create_candidate(
        &current_policy,
        &current_admission,
        &planned_mutation.cat_id,
        planned_mutation.vcpus,
        planned_mutation.memory_bytes,
        &planned_mutation.network_config.network_id,
    )? {
        CandidateEvaluation::Eligible(recomputed)
            if recomputed == planned_mutation.network_config =>
        {
            Ok(PlacementCommitLoad::Accepted)
        }
        CandidateEvaluation::Eligible(_)
        | CandidateEvaluation::Rejected(_)
        | CandidateEvaluation::CandidateIdentityCollision => Ok(PlacementCommitLoad::Stale),
    }
}

/// Revalidates one complete placement snapshot after the caller has already
/// locked the full old/new NodeIdentity union in canonical Node ID order.
///
/// Keeping identity acquisition outside this helper is intentional: a
/// cross-Node mutation must hold both coordination locks before it reads the
/// policy/session/inventory/assigned-set suffix of either Node. Re-locking the
/// already-held identity inside the A20 helper is harmless and keeps one exact
/// admission comparison shared by create and successor-Desired commits.
pub(super) fn revalidate_desired_mutation_placement_after_identity_locks(
    transaction: &mut Transaction<'_>,
    planned: &PlacementTargetSnapshot,
    active_guest_digest: &Sha256Digest,
) -> AuthorityTxResult<PlacementCommitLoad> {
    if planned.policy.node_id != planned.admission.node_identity.node_id
        || planned.policy.capabilities.guest_config_digest != *active_guest_digest
    {
        return Ok(PlacementCommitLoad::Stale);
    }

    let Some(current_policy) =
        load_policy_unlocked(transaction, &planned.admission.node_identity.node_id)?
    else {
        return Err(corrupt(
            "provisioned NodeIdentity lost its placement policy",
        ));
    };
    if current_policy.node_id != planned.admission.node_identity.node_id {
        return Err(corrupt("placement policy belongs to another Node"));
    }
    let current_assigned = load_assigned_desired_unlocked(
        transaction,
        &planned.admission.node_identity.node_id,
        MAX_ASSIGNED_SPECS.saturating_add(1),
    )?;
    validate_current_assigned(&current_policy, &current_assigned)?;
    let current_event =
        load_active_event_by_node_unlocked(transaction, &planned.admission.node_identity.node_id)?;
    if current_policy != planned.policy || current_event != planned.active_host_fence_event {
        return Ok(PlacementCommitLoad::Stale);
    }

    let mut checkpoint = |_: &mut Transaction<'_>| Ok(());
    let current_admission = match lock_placement_admission_for_desired_mutation_checked(
        transaction,
        &planned.admission,
        active_guest_digest,
        &mut checkpoint,
    )? {
        PlacementAdmissionLoad::Accepted(admission) => *admission,
        PlacementAdmissionLoad::Rejected(_) => return Ok(PlacementCommitLoad::Stale),
    };
    if current_admission.assigned_desired_specs != current_assigned {
        return Err(corrupt(
            "placement admission current Desired set changed under NodeIdentity lock",
        ));
    }
    Ok(PlacementCommitLoad::Accepted)
}

/// Recomputes the bounded post-mutation assigned maps from the exact snapshots
/// that were just revalidated under the complete identity lock union. This is
/// the commit-side capacity and deterministic network probe; callers cannot
/// turn a valid old snapshot into an oversized shape or an arbitrary target
/// network merely by constructing a successor Desired.
pub(super) fn revalidate_desired_mutation_post_assignment(
    planned: &[PlacementTargetSnapshot],
    expected_current: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    active_guest_digest: &Sha256Digest,
) -> AuthorityTxResult<PlacementCommitLoad> {
    if desired.runtime.guest_config_digest != *active_guest_digest {
        return Ok(PlacementCommitLoad::Stale);
    }
    let source_node = &expected_current.placement.node_id;
    let target_node = &desired.placement.node_id;
    let source = planned
        .iter()
        .find(|snapshot| snapshot.policy.node_id == *source_node)
        .ok_or_else(|| corrupt("Desired mutation omitted its source placement snapshot"))?;
    if !source
        .admission
        .assigned_desired_specs
        .iter()
        .any(|assigned| assigned == expected_current)
    {
        return Ok(PlacementCommitLoad::Stale);
    }

    let placement_changed = source_node != target_node;
    let runtime_changed = expected_current.runtime != desired.runtime;
    let target = planned
        .iter()
        .find(|snapshot| snapshot.policy.node_id == *target_node)
        .ok_or_else(|| corrupt("Desired mutation omitted its target placement snapshot"))?;
    if placement_changed {
        // This generic A1 boundary covers planned migration/placement retry.
        // Host takeover requires the later exact event + per-volume
        // authorization request and cannot be inferred from a merely active
        // source fence event.
        if source.active_host_fence_event.is_some() {
            return Ok(PlacementCommitLoad::Stale);
        }
        let current_target =
            validate_current_assigned(&target.policy, &target.admission.assigned_desired_specs)?;
        if target.policy.scheduling_state != RuntimeSchedulingState::Schedulable
            || target.active_host_fence_event.is_some()
            || !observation_networks_are_clean(&target.admission, &current_target.desired_networks)
            || allocate_network(
                &target.policy,
                &desired.runtime.network_config.network_id,
                &current_target.occupied_slots,
            )? != Some(desired.runtime.network_config.clone())
        {
            return Ok(PlacementCommitLoad::Stale);
        }
    } else if runtime_changed
        && (target.policy.scheduling_state != RuntimeSchedulingState::Schedulable
            || target.active_host_fence_event.is_some())
    {
        return Ok(PlacementCommitLoad::Stale);
    }

    for snapshot in planned {
        let node_id = &snapshot.policy.node_id;
        let mut post = snapshot.admission.assigned_desired_specs.clone();
        if node_id == source_node {
            post.retain(|assigned| assigned.cat_id != expected_current.cat_id);
        }
        if node_id == target_node {
            if post
                .iter()
                .any(|assigned| assigned.cat_id == desired.cat_id)
            {
                return Ok(PlacementCommitLoad::Stale);
            }
            post.push(desired.clone());
        }
        let validated = validate_current_assigned(&snapshot.policy, &post)?;
        let capacity_relevant = node_id == target_node && (placement_changed || runtime_changed);
        if post.len() > MAX_ASSIGNED_SPECS
            || (capacity_relevant
                && (validated.total_vcpus > u128::from(snapshot.policy.allocatable_vcpus.get())
                    || validated.total_memory
                        > u128::from(snapshot.policy.allocatable_memory_bytes.get())))
        {
            return Ok(PlacementCommitLoad::Stale);
        }
    }
    Ok(PlacementCommitLoad::Accepted)
}

fn observation_networks_are_clean(
    admission: &PlacementAdmissionSnapshot,
    desired_networks: &BTreeMap<Id, NetworkConfig>,
) -> bool {
    if admission
        .full_inventory_observation
        .residue
        .iter()
        .any(|residue| matches!(residue, NodeResidue::NetworkTap { .. }))
    {
        return false;
    }
    let mut observed_ids = BTreeSet::new();
    for runtime in &admission.full_inventory_observation.runtimes {
        for observed in &runtime.networks {
            let Some(expected) = desired_networks.get(&runtime.cat_id) else {
                return false;
            };
            if !observed_ids.insert(observed.network_id.clone())
                || observed.network_id != expected.network_id
                || observed.kind != expected.kind
                || observed.guest_mac != expected.guest_mac
                || observed.guest_ipv4 != expected.guest_ipv4
                || observed.prefix_length != expected.prefix_length
                || observed.gateway_ipv4 != expected.gateway_ipv4
            {
                return false;
            }
        }
    }
    true
}

fn validate_network_config(
    policy: &NodePlacementPolicy,
    config: &NetworkConfig,
) -> AuthorityTxResult<u32> {
    if config.kind != IsolatedIpv4Kind::IsolatedIpv4 || config.prefix_length != 30 {
        return Err(corrupt(
            "assigned Desired has an unsupported network config",
        ));
    }
    let pool = policy_pool_base(policy)?;
    let guest = ipv4_u32(&config.guest_ipv4)?;
    let gateway = ipv4_u32(&config.gateway_ipv4)?;
    let subnet = guest & !3;
    if subnet <= pool
        || subnet.checked_add(3).is_none()
        || subnet & 0xffff_0000 != pool
        || guest != subnet + 2
        || gateway != subnet + 1
        || config.guest_mac.as_str() != expected_mac(guest)
    {
        return Err(corrupt(
            "assigned Desired network config is outside its policy /16",
        ));
    }
    let slot = (subnet - pool) / IPV4_SLOT_BYTES;
    if !(1..=IPV4_SLOT_COUNT).contains(&slot) {
        return Err(corrupt("assigned Desired uses a reserved network slot"));
    }
    Ok(slot)
}

fn allocate_network(
    policy: &NodePlacementPolicy,
    network_id: &Id,
    occupied: &BTreeSet<u32>,
) -> AuthorityTxResult<Option<NetworkConfig>> {
    let pool = policy_pool_base(policy)?;
    let start = network_start_slot(&policy.node_id, pool, network_id)?;
    for offset in 0..IPV4_SLOT_COUNT {
        let slot = 1 + ((start - 1 + offset) % IPV4_SLOT_COUNT);
        if occupied.contains(&slot) {
            continue;
        }
        let subnet = pool
            .checked_add(
                slot.checked_mul(IPV4_SLOT_BYTES)
                    .ok_or_else(|| corrupt("network slot multiplication overflow"))?,
            )
            .ok_or_else(|| corrupt("network subnet overflow"))?;
        let gateway = subnet
            .checked_add(1)
            .ok_or_else(|| corrupt("network gateway overflow"))?;
        let guest = subnet
            .checked_add(2)
            .ok_or_else(|| corrupt("network guest address overflow"))?;
        let guest_ipv4 = ipv4_from_u32(guest)?;
        return Ok(Some(NetworkConfig {
            kind: IsolatedIpv4Kind::IsolatedIpv4,
            network_id: network_id.clone(),
            guest_mac: MacAddress::new(expected_mac(guest))
                .ok_or_else(|| corrupt("derived guest MAC is invalid"))?,
            guest_ipv4,
            prefix_length: 30,
            gateway_ipv4: ipv4_from_u32(gateway)?,
        }));
    }
    Ok(None)
}

#[cfg(test)]
pub(super) fn allocate_network_for_test(
    policy: &NodePlacementPolicy,
    network_id: &Id,
) -> NetworkConfig {
    match allocate_network(policy, network_id, &BTreeSet::new()) {
        Ok(Some(config)) => config,
        Ok(None) => panic!("an empty /16 has a free slot"),
        Err(_) => panic!("test policy has a valid /16"),
    }
}

fn network_start_slot(node_id: &Id, pool: u32, network_id: &Id) -> AuthorityTxResult<u32> {
    let mut hasher = Sha256::new();
    hasher.update(b"cats.runtime.isolated-ipv4-slot.v1");
    hasher.update([0]);
    update_frame(&mut hasher, node_id.as_str().as_bytes())?;
    update_frame(&mut hasher, &pool.to_be_bytes())?;
    update_frame(&mut hasher, network_id.as_str().as_bytes())?;
    let digest = hasher.finalize();
    let seed = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .map_err(|_| corrupt("SHA-256 seed slice has the wrong size"))?,
    );
    let slot_count = u64::from(IPV4_SLOT_COUNT);
    u32::try_from(1 + seed % slot_count).map_err(corrupt)
}

fn update_frame(hasher: &mut Sha256, bytes: &[u8]) -> AuthorityTxResult<()> {
    let length = u64::try_from(bytes.len()).map_err(corrupt)?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn policy_pool_base(policy: &NodePlacementPolicy) -> AuthorityTxResult<u32> {
    if policy.guest_ipv4_pool.prefix_length != 16 {
        return Err(corrupt("placement policy guest pool is not a /16"));
    }
    let pool = ipv4_u32(&policy.guest_ipv4_pool.network_address)?;
    if pool & 0xffff != 0 {
        return Err(corrupt("placement policy guest /16 is not aligned"));
    }
    Ok(pool)
}

fn ipv4_u32(value: &Ipv4Address) -> AuthorityTxResult<u32> {
    value
        .as_str()
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(corrupt)
}

fn ipv4_from_u32(value: u32) -> AuthorityTxResult<Ipv4Address> {
    Ipv4Address::new(Ipv4Addr::from(value).to_string())
        .ok_or_else(|| corrupt("derived IPv4 address is invalid"))
}

fn expected_mac(guest: u32) -> String {
    let octets = guest.to_be_bytes();
    format!(
        "02:ca:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3]
    )
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_reconciliation::{
        AllocatableMemoryBytes, AllocatableVcpus, AssignedKind, AssignedPlacement, ContractVersion,
        DesiredRuntimeSpec, Epoch, GuestIpv4Pool, GuestIpv4PoolKind, NodeTransportTarget, Revision,
        RuntimeConfig, RuntimePlacementBlockFrontend, RuntimePlacementCapabilities,
        RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport, RuntimePlacementVmm,
        RuntimeTarget, RuntimeTransition,
    };

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn ok<T>(result: AuthorityTxResult<T>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => panic!("test authority operation failed"),
        }
    }

    fn policy() -> NodePlacementPolicy {
        NodePlacementPolicy {
            version: ContractVersion::V1,
            node_id: id("node_a"),
            policy_revision: Epoch::new(1).unwrap(),
            scheduling_state: RuntimeSchedulingState::Schedulable,
            allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
            allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
            capabilities: RuntimePlacementCapabilities {
                vmm: RuntimePlacementVmm::CloudHypervisor,
                block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
                guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
                guest_transport: RuntimePlacementGuestTransport::Vsock,
                guest_agent_protocol_version: ContractVersion::V1,
                guest_config_digest: Sha256Digest::from_bytes([7; 32]),
            },
            guest_ipv4_pool: GuestIpv4Pool {
                kind: GuestIpv4PoolKind::PrivateIpv4_16,
                network_address: Ipv4Address::new("10.240.0.0").unwrap(),
                prefix_length: 16,
            },
            node_transport_target: NodeTransportTarget::new("https://node-a.internal:7301")
                .unwrap(),
        }
    }

    #[test]
    fn fixed_network_vector_uses_canonical_start_slot_and_config() {
        let policy = policy();
        let network_id = id("net_77777777777777777777777777777777");
        let pool = ok(policy_pool_base(&policy));
        let start = ok(network_start_slot(&policy.node_id, pool, &network_id));
        assert_eq!(start, 8_738);
        let config = ok(allocate_network(&policy, &network_id, &BTreeSet::new())).unwrap();
        assert_eq!(config.guest_ipv4.as_str(), "10.240.136.138");
        assert_eq!(config.gateway_ipv4.as_str(), "10.240.136.137");
        assert_eq!(config.guest_mac.as_str(), "02:ca:0a:f0:88:8a");
        assert_eq!(ok(validate_network_config(&policy, &config)), start);
    }

    #[test]
    fn allocator_probes_past_occupied_slot_and_rejects_malformed_config() {
        let policy = policy();
        let network_id = id("net_77777777777777777777777777777777");
        let start = ok(network_start_slot(
            &policy.node_id,
            ok(policy_pool_base(&policy)),
            &network_id,
        ));
        let config = ok(allocate_network(
            &policy,
            &network_id,
            &BTreeSet::from([start]),
        ))
        .unwrap();
        assert_ne!(ok(validate_network_config(&policy, &config)), start);
        let mut malformed = config;
        malformed.guest_mac = MacAddress::new("02:ca:00:00:00:01").unwrap();
        assert!(validate_network_config(&policy, &malformed).is_err());
    }

    #[test]
    fn a_full_1024_assignment_set_is_validated_before_the_ordinary_cap_rejection() {
        let policy = policy();
        let mut occupied = BTreeSet::new();
        let mut assigned = Vec::with_capacity(MAX_ASSIGNED_SPECS);
        for index in 0..MAX_ASSIGNED_SPECS {
            let cat_id = Id::new(format!("cat_{index:032x}")).unwrap();
            let network_id = Id::new(format!("net_{index:032x}")).unwrap();
            let network = ok(allocate_network(&policy, &network_id, &occupied)).unwrap();
            occupied.insert(ok(validate_network_config(&policy, &network)));
            assigned.push(DesiredRuntimeSpec {
                version: ContractVersion::V1,
                workspace_id: id("workspace_a"),
                cat_id,
                desired_revision: Revision::new(1).unwrap(),
                target: RuntimeTarget::Running,
                placement: AssignedPlacement {
                    kind: AssignedKind::Assigned,
                    node_id: policy.node_id.clone(),
                    placement_epoch: Epoch::new(1).unwrap(),
                },
                runtime: RuntimeConfig {
                    vcpus: 1,
                    memory_bytes: 1,
                    boot_image_digest: Sha256Digest::from_bytes([3; 32]),
                    guest_config_digest: policy.capabilities.guest_config_digest.clone(),
                    network_config: network,
                },
                volumes: Vec::new(),
                endpoints: Vec::new(),
                transition: RuntimeTransition::CancelAndDrain,
                spec_digest: Sha256Digest::from_bytes([4; 32]),
            });
        }
        assigned
            .last_mut()
            .unwrap()
            .runtime
            .network_config
            .guest_mac = MacAddress::new("02:ca:00:00:00:01").unwrap();
        assert!(validate_current_assigned(&policy, &assigned).is_err());
    }

    #[test]
    fn expired_or_cancelled_planner_work_stops_inside_its_read_snapshot() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        let live = AtomicBool::new(true);
        let error = store
            .authority_read_snapshot(|transaction| {
                refresh_planner_deadline(transaction, expired, &live)
            })
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);

        let cancelled = AtomicBool::new(false);
        let future = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let error = store
            .authority_read_snapshot(|transaction| {
                refresh_planner_deadline(transaction, future, &cancelled)
            })
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
    }

    #[test]
    fn server_statement_deadline_is_infrastructure_unavailable() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let deadline = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let live = AtomicBool::new(true);
        let started = Instant::now();
        let error = store
            .authority_read_snapshot(|transaction| {
                refresh_planner_deadline(transaction, deadline, &live)?;
                transaction.query_one("SELECT pg_sleep(5)", &[])?;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}

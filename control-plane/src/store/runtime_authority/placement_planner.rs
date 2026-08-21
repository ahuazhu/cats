//! Clean-slate Cat-create placement and deterministic isolated-IPv4 allocation.
//!
//! Placement is admitted from one provisioned Node identity, its current
//! AgentSession, a fresh session-bound full runtime inventory attestation, the
//! current placement policy, and the absence of an active HostFenceEvent.
//! Product runtime configs and current lifecycle operations provide capacity
//! and network reservations; telemetry never becomes assignment authority.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use cats_api::runtime_inventory::{
    encode_runtime_inventory_report, RuntimeInventoryAttestation, RuntimeInventoryBody,
    RuntimeInventoryReport,
};
use cats_api::runtime_lifecycle::{
    validate_immutable_runtime_config, ImmutableRuntimeConfig, LifecycleOperationState,
    LifecycleTerminalResult, NodeResult, PlacementIdentity, RuntimeNetworkConfig,
};
use cats_api::runtime_reconciliation::{
    AgentSession, Epoch, Id, Ipv4Address, MacAddress, NodeIdentity, NodeIdentityState,
    NodePlacementPolicy, RuntimeSchedulingState, SessionBinding, Sha256Digest, UnixMillis,
};
use cats_storage::authority::HostFenceEvent;
use postgres::Transaction;
use sha2::{Digest as _, Sha256};

use super::cat_create_service::{
    CatCreatePlacementMutation, CatCreatePlacementOutcome, CatCreatePlacementPlanner,
    CatCreatePlan, CatCreatePlanRequest, ServiceFuture,
};
use super::lifecycle_commands::{
    load_lifecycle_admission_context_in, LifecycleAdmissionContext, LifecycleStableState,
};
use super::placement_policy::load_policy_unlocked;
use super::rows::{database_now, load_active_event_by_node_unlocked};
use super::runtime_spine::{
    load_runtime_full_inventory_for_update, load_runtime_full_inventory_unlocked,
    runtime_full_inventory_is_fresh_at, RuntimeFullInventoryState, PLACEMENT_INVENTORY_MAX_AGE_MS,
};
use crate::store::agent_sessions::{
    load_current_session_for_update, load_current_session_unlocked,
    load_identity_by_node_for_update, load_identity_by_node_unlocked,
    load_provisioned_node_keys_after, PROVISIONED_NODE_ID_PAGE_SIZE,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{ApiError, Result, Store};

const IPV4_SLOT_COUNT: u32 = 16_383;
const IPV4_SLOT_BYTES: u32 = 4;
const MAX_CURRENT_CATS_PER_NODE: usize = 1_024;
#[cfg(test)]
const PLACEMENT_PLANNER_DEADLINE: Duration = Duration::from_secs(10);

pub(super) struct OwnedPlannerExecution<F> {
    live: Arc<AtomicBool>,
    execution: Pin<Box<F>>,
}

impl<F> OwnedPlannerExecution<F> {
    pub(super) fn new(live: Arc<AtomicBool>, execution: F) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlacementTargetSnapshot {
    pub(crate) policy: NodePlacementPolicy,
    pub(crate) node_identity: NodeIdentity,
    pub(crate) agent_session: AgentSession,
    pub(crate) inventory_attestation: RuntimeInventoryAttestation,
    pub(crate) full_inventory_report: RuntimeInventoryReport,
    pub(crate) active_host_fence_event: Option<HostFenceEvent>,
    pub(crate) evaluated_at_unix_ms: UnixMillis,
}

impl PlacementTargetSnapshot {
    pub(crate) fn node_id(&self) -> &Id {
        &self.node_identity.node_id
    }

    pub(crate) fn session_binding(&self) -> SessionBinding {
        SessionBinding {
            node_id: self.agent_session.node_id.clone(),
            node_boot_id: self.agent_session.node_boot_id.clone(),
            agent_instance_id: self.agent_session.agent_instance_id.clone(),
            agent_session_epoch: self.agent_session.agent_session_epoch,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlacementCandidateRejection {
    ActiveHostFenceEvent,
    PolicyCordoned,
    PolicyGuestConfigMismatch,
    MissingCurrentSession,
    SessionExpired,
    MissingOrStaleFullInventory,
    PhysicalInventoryNotClean,
    AssignedSetLimit,
    InsufficientVcpus,
    InsufficientMemory,
    NetworkExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RuntimeConfigPlacementClaims {
    pub(super) vcpus: i64,
    pub(super) memory_bytes: i64,
    pub(super) network_id: Id,
    pub(super) ipv4_pool_base: i64,
    pub(super) isolated_ipv4_slot: i64,
    pub(super) disk_ids: Vec<String>,
    pub(super) volume_ids: Vec<String>,
}

pub(super) fn runtime_config_placement_claims(
    config: &ImmutableRuntimeConfig,
) -> AuthorityTxResult<RuntimeConfigPlacementClaims> {
    validate_immutable_runtime_config(config)
        .map_err(|_| corrupt("runtime config placement claims are not canonical"))?;
    let (network_id, pool, slot) = project_network_claims(&config.network_config)?;
    if slot == 0 {
        return Err(corrupt("runtime network uses the reserved /16 base slot"));
    }
    Ok(RuntimeConfigPlacementClaims {
        vcpus: i64::from(config.vcpus),
        memory_bytes: i64::try_from(config.memory_bytes)
            .map_err(|_| corrupt("runtime config memory exceeds PostgreSQL BIGINT"))?,
        network_id,
        ipv4_pool_base: i64::from(pool),
        isolated_ipv4_slot: i64::from(slot),
        disk_ids: config
            .volumes
            .iter()
            .map(|volume| volume.disk_id.to_string())
            .collect(),
        volume_ids: config
            .volumes
            .iter()
            .map(|volume| volume.volume_id.to_string())
            .collect(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CatCreatePlacementLoad {
    Planned(Box<CatCreatePlan>),
    Unavailable {
        first_rejection: Option<(Id, PlacementCandidateRejection)>,
    },
    CandidateIdentityCollision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColdStartPlacementRequest {
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) replacement_config_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColdStartPlacementPlan {
    pub(crate) source_operation_id: Id,
    pub(crate) source_terminal_result_digest: Sha256Digest,
    pub(crate) source_runtime_config: ImmutableRuntimeConfig,
    pub(crate) target: PlacementTargetSnapshot,
    pub(crate) target_placement: PlacementIdentity,
    pub(crate) target_runtime_config: ImmutableRuntimeConfig,
}

impl ColdStartPlacementPlan {
    pub(crate) fn advances_runtime_config(&self) -> bool {
        self.target_runtime_config != self.source_runtime_config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ColdStartPlacementLoad {
    /// The exact current terminal predecessor is not Cold. The product
    /// transaction must re-read it and use the ordinary same-Node path.
    NotCold,
    Planned(Box<ColdStartPlacementPlan>),
    Unavailable,
    CandidateIdentityCollision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlacementCommitLoad {
    Accepted,
    Stale,
}

pub(crate) struct PostgresCatCreatePlacementPlanner {
    store: Arc<Store>,
}

impl PostgresCatCreatePlacementPlanner {
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
            Ok(match outcome {
                CatCreatePlacementLoad::Planned(plan) => CatCreatePlacementOutcome::Planned(*plan),
                CatCreatePlacementLoad::Unavailable { .. } => {
                    CatCreatePlacementOutcome::Unavailable
                }
                CatCreatePlacementLoad::CandidateIdentityCollision => {
                    CatCreatePlacementOutcome::CandidateIdentityCollision
                }
            })
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

    pub(crate) fn plan_cold_start_placement_until(
        &self,
        request: &ColdStartPlacementRequest,
        deadline: Instant,
        live: &AtomicBool,
    ) -> Result<ColdStartPlacementLoad> {
        // This planner intentionally takes the Cat/head/config lock before it
        // scans Node candidates. A read-only snapshot cannot use the exact
        // lifecycle context loader, and a weaker unlocked predecessor would
        // let a concurrent command/config successor leak into the request.
        self.authority_transaction(|transaction| {
            plan_cold_start_placement_in(transaction, request, deadline, live)
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
    if runtime_network_id_exists(transaction, &request.network_id)? {
        return Ok(CatCreatePlacementLoad::CandidateIdentityCollision);
    }

    let now = database_now(transaction)?;
    let mut after = None;
    let mut first_rejection = None;
    loop {
        refresh_planner_deadline(transaction, deadline, live)?;
        let node_keys = load_provisioned_node_keys_after(transaction, after.as_ref())?;
        let has_more = node_keys.len() == PROVISIONED_NODE_ID_PAGE_SIZE;
        let mut last_node_id = None;
        for node_key in &node_keys {
            refresh_planner_deadline(transaction, deadline, live)?;
            let node_id =
                Id::new(node_key.clone()).ok_or_else(|| corrupt("invalid provisioned Node key"))?;
            last_node_id = Some(node_id.clone());
            let identity = load_identity_by_node_unlocked(transaction, &node_id)?
                .ok_or_else(|| corrupt("provisioned Node page entry disappeared"))?;
            if identity.node_id != node_id || identity.state != NodeIdentityState::Provisioned {
                return Err(corrupt("provisioned Node page entry is inconsistent"));
            }
            let policy = load_policy_unlocked(transaction, &node_id)?
                .ok_or_else(|| corrupt("provisioned Node has no placement policy"))?;
            if policy.node_id != node_id {
                return Err(corrupt("placement policy belongs to another Node"));
            }
            let active_host_fence_event =
                load_active_event_by_node_unlocked(transaction, &node_id)?;
            let Some(session) = load_current_session_unlocked(transaction, &node_id)? else {
                remember_rejection(
                    &mut first_rejection,
                    &node_id,
                    PlacementCandidateRejection::MissingCurrentSession,
                );
                continue;
            };
            let Some(inventory) = load_runtime_full_inventory_unlocked(transaction, &node_id)?
            else {
                remember_rejection(
                    &mut first_rejection,
                    &node_id,
                    PlacementCandidateRejection::MissingOrStaleFullInventory,
                );
                continue;
            };
            let evaluation = evaluate_candidate(
                transaction,
                request,
                &identity,
                &policy,
                &session,
                &inventory,
                active_host_fence_event.as_ref(),
                now,
                None,
            )?;
            match evaluation {
                CandidateEvaluation::Eligible(network_config) => {
                    return Ok(CatCreatePlacementLoad::Planned(Box::new(CatCreatePlan {
                        target: PlacementTargetSnapshot {
                            policy,
                            node_identity: identity,
                            agent_session: session,
                            inventory_attestation: inventory.attestation,
                            full_inventory_report: inventory.full_report,
                            active_host_fence_event,
                            evaluated_at_unix_ms: now,
                        },
                        mutation: CatCreatePlacementMutation {
                            cat_id: request.cat_id.clone(),
                            placement_epoch: Epoch::new(1).expect("one is a valid Epoch"),
                            vcpus: request.vcpus,
                            memory_bytes: request.memory_bytes,
                            network_config,
                        },
                    })));
                }
                CandidateEvaluation::Rejected(rejection) => {
                    remember_rejection(&mut first_rejection, &node_id, rejection);
                }
            }
        }

        if !has_more {
            return Ok(CatCreatePlacementLoad::Unavailable { first_rejection });
        }
        after = last_node_id;
        if after.is_none() {
            return Err(corrupt("provisioned Node page lost its cursor"));
        }
    }
}

fn plan_cold_start_placement_in(
    transaction: &mut Transaction<'_>,
    request: &ColdStartPlacementRequest,
    deadline: Instant,
    live: &AtomicBool,
) -> AuthorityTxResult<ColdStartPlacementLoad> {
    refresh_planner_deadline(transaction, deadline, live)?;
    let Some(context) =
        load_lifecycle_admission_context_in(transaction, &request.workspace_id, &request.cat_id)?
    else {
        return Ok(ColdStartPlacementLoad::NotCold);
    };
    if context.deleted_at.is_some()
        || context.unresolved_operation.is_some()
        || context.stable_state != Some(LifecycleStableState::Cold)
    {
        return Ok(ColdStartPlacementLoad::NotCold);
    }
    let Some(source_operation) = context.lifecycle_head.as_ref() else {
        return Err(corrupt("Cold Cat has no lifecycle head Operation"));
    };
    let (source_terminal_result_digest, source_cold) = match &source_operation.state {
        LifecycleOperationState::Terminal {
            terminal,
            terminal_result_digest,
        } => match terminal.as_ref() {
            LifecycleTerminalResult::NodeResult { response } => match &response.result {
                NodeResult::Cold(cold) => (terminal_result_digest.clone(), cold),
                _ => {
                    return Err(corrupt(
                        "Cold Cat lifecycle head does not contain a Cold result",
                    ));
                }
            },
            LifecycleTerminalResult::HostLost { .. } => {
                return Err(corrupt("Cold Cat lifecycle head is HostLost"));
            }
        },
        LifecycleOperationState::Unresolved => {
            return Err(corrupt("Cold Cat lifecycle head is unresolved"));
        }
    };
    if source_operation.runtime_config_id
        != source_operation.canonical_request.runtime_config.config_id
        || source_operation.runtime_config_digest
            != source_operation
                .canonical_request
                .runtime_config
                .config_digest
        || source_cold.runtime_config_digest != source_operation.runtime_config_digest
    {
        return Err(corrupt(
            "Cold result does not bind its Operation-frozen runtime config",
        ));
    }

    // Product mutations may append one or more configs while the exact Cold
    // Operation remains the lifecycle head. Start freezes the independently
    // locked latest pointer, never rewrites the historical Cold command.
    let source_config = context.immutable_runtime_config.clone();
    let network_id = runtime_network_id(&source_config.network_config).clone();
    let candidate_request = CatCreatePlanRequest {
        cat_id: request.cat_id.clone(),
        vcpus: source_config.vcpus,
        memory_bytes: source_config.memory_bytes,
        root_size_bytes: 1,
        durability: cats_api::runtime_reconciliation::Durability::Strict,
        boot_image_digest: source_config.boot_image_digest.clone(),
        guest_config_digest: source_config.guest_runtime_profile_digest.clone(),
        network_id,
    };
    let now = database_now(transaction)?;
    let mut after = None;
    loop {
        refresh_planner_deadline(transaction, deadline, live)?;
        let node_keys = load_provisioned_node_keys_after(transaction, after.as_ref())?;
        let has_more = node_keys.len() == PROVISIONED_NODE_ID_PAGE_SIZE;
        let mut last_node_id = None;
        for node_key in &node_keys {
            refresh_planner_deadline(transaction, deadline, live)?;
            let node_id =
                Id::new(node_key.clone()).ok_or_else(|| corrupt("invalid provisioned Node key"))?;
            last_node_id = Some(node_id.clone());
            let identity = load_identity_by_node_unlocked(transaction, &node_id)?
                .ok_or_else(|| corrupt("provisioned Node page entry disappeared"))?;
            if identity.node_id != node_id || identity.state != NodeIdentityState::Provisioned {
                return Err(corrupt("provisioned Node page entry is inconsistent"));
            }
            let policy = load_policy_unlocked(transaction, &node_id)?
                .ok_or_else(|| corrupt("provisioned Node has no placement policy"))?;
            if policy.node_id != node_id {
                return Err(corrupt("placement policy belongs to another Node"));
            }
            let active_host_fence_event =
                load_active_event_by_node_unlocked(transaction, &node_id)?;
            let Some(session) = load_current_session_unlocked(transaction, &node_id)? else {
                continue;
            };
            let Some(inventory) = load_runtime_full_inventory_unlocked(transaction, &node_id)?
            else {
                continue;
            };
            let CandidateEvaluation::Eligible(network_config) = evaluate_candidate(
                transaction,
                &candidate_request,
                &identity,
                &policy,
                &session,
                &inventory,
                active_host_fence_event.as_ref(),
                now,
                Some(&request.cat_id),
            )?
            else {
                continue;
            };
            let target_runtime_config = if network_config == source_config.network_config {
                source_config.clone()
            } else {
                let config = ImmutableRuntimeConfig::new(
                    request.replacement_config_id.clone(),
                    source_config.boot_image_digest.clone(),
                    source_config.vcpus,
                    source_config.memory_bytes,
                    source_config.guest_runtime_profile_digest.clone(),
                    network_config,
                    source_config.volumes.clone(),
                )
                .map_err(|_| corrupt("Cold Start planner constructed an invalid runtime config"))?;
                let collision: bool = transaction
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1 FROM cat_runtime_configs WHERE config_id=$1
                         )",
                        &[&config.config_id.as_str()],
                    )?
                    .try_get(0)?;
                if collision {
                    return Ok(ColdStartPlacementLoad::CandidateIdentityCollision);
                }
                config
            };
            let target_placement = if node_id == source_operation.node_id {
                source_operation.placement_identity.clone()
            } else {
                let next_epoch = source_operation
                    .placement_identity
                    .placement_epoch
                    .get()
                    .checked_add(1)
                    .and_then(Epoch::new)
                    .ok_or_else(|| corrupt("Cold Start placement epoch overflow"))?;
                PlacementIdentity {
                    node_id: node_id.clone(),
                    placement_epoch: next_epoch,
                }
            };
            return Ok(ColdStartPlacementLoad::Planned(Box::new(
                ColdStartPlacementPlan {
                    source_operation_id: source_operation.operation_id.clone(),
                    source_terminal_result_digest,
                    source_runtime_config: source_config,
                    target: PlacementTargetSnapshot {
                        policy,
                        node_identity: identity,
                        agent_session: session,
                        inventory_attestation: inventory.attestation,
                        full_inventory_report: inventory.full_report,
                        active_host_fence_event,
                        evaluated_at_unix_ms: now,
                    },
                    target_placement,
                    target_runtime_config,
                },
            )));
        }
        if !has_more {
            return Ok(ColdStartPlacementLoad::Unavailable);
        }
        after = last_node_id;
        if after.is_none() {
            return Err(corrupt("provisioned Node page lost its cursor"));
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
    Eligible(RuntimeNetworkConfig),
    Rejected(PlacementCandidateRejection),
}

#[derive(Debug)]
struct CurrentNodeAllocation {
    cat_ids: BTreeSet<Id>,
    occupied_slots: BTreeSet<u32>,
    total_vcpus: u128,
    total_memory_bytes: u128,
}

#[allow(clippy::too_many_arguments)]
fn evaluate_candidate(
    transaction: &mut Transaction<'_>,
    request: &CatCreatePlanRequest,
    identity: &NodeIdentity,
    policy: &NodePlacementPolicy,
    session: &AgentSession,
    inventory: &RuntimeFullInventoryState,
    active_host_fence_event: Option<&HostFenceEvent>,
    now: UnixMillis,
    excluded_cat_id: Option<&Id>,
) -> AuthorityTxResult<CandidateEvaluation> {
    if active_host_fence_event.is_some() {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::ActiveHostFenceEvent,
        ));
    }
    if policy.scheduling_state != RuntimeSchedulingState::Schedulable {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::PolicyCordoned,
        ));
    }
    if policy.capabilities.guest_config_digest != request.guest_config_digest
        || session.guest_config_digest != request.guest_config_digest
    {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::PolicyGuestConfigMismatch,
        ));
    }
    if identity.node_id != session.node_id
        || identity.immutable_host_id != session.immutable_host_id
        || now >= session.lease_deadline_unix_ms
    {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::SessionExpired,
        ));
    }
    if !runtime_full_inventory_is_fresh_at(inventory, session, now, PLACEMENT_INVENTORY_MAX_AGE_MS)?
    {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::MissingOrStaleFullInventory,
        ));
    }
    let current =
        load_current_node_allocation(transaction, &identity.node_id, policy, excluded_cat_id)?;
    let assigned_count = current.cat_ids.len()
        - usize::from(excluded_cat_id.is_some_and(|cat_id| current.cat_ids.contains(cat_id)));
    if assigned_count >= MAX_CURRENT_CATS_PER_NODE {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::AssignedSetLimit,
        ));
    }
    if !full_inventory_is_clean_for_allocation(inventory, &current.cat_ids)? {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::PhysicalInventoryNotClean,
        ));
    }
    if current
        .total_vcpus
        .checked_add(u128::from(request.vcpus))
        .is_none_or(|value| value > u128::from(policy.allocatable_vcpus.get()))
    {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::InsufficientVcpus,
        ));
    }
    if current
        .total_memory_bytes
        .checked_add(u128::from(request.memory_bytes))
        .is_none_or(|value| value > u128::from(policy.allocatable_memory_bytes.get()))
    {
        return Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::InsufficientMemory,
        ));
    }
    match allocate_network(policy, &request.network_id, &current.occupied_slots)? {
        Some(network) => Ok(CandidateEvaluation::Eligible(network)),
        None => Ok(CandidateEvaluation::Rejected(
            PlacementCandidateRejection::NetworkExhausted,
        )),
    }
}

fn full_inventory_is_clean_for_allocation(
    inventory: &RuntimeFullInventoryState,
    assigned_cat_ids: &BTreeSet<Id>,
) -> AuthorityTxResult<bool> {
    encode_runtime_inventory_report(&inventory.full_report)
        .map_err(|_| corrupt("stored full inventory cannot be encoded"))?;
    let RuntimeInventoryBody::Full {
        cats,
        unattributed_artifacts,
        ..
    } = &inventory.full_report.inventory
    else {
        return Err(corrupt("full inventory loader returned a Partial report"));
    };
    if !unattributed_artifacts.is_empty() {
        return Ok(false);
    }
    Ok(cats
        .iter()
        .all(|telemetry| assigned_cat_ids.contains(&telemetry.cat_id)))
}

fn load_current_node_allocation(
    transaction: &mut Transaction<'_>,
    node_id: &Id,
    policy: &NodePlacementPolicy,
    excluded_cat_id: Option<&Id>,
) -> AuthorityTxResult<CurrentNodeAllocation> {
    let rows = transaction.query(
        "WITH current_operation AS (
             SELECT cat_id, node_id
               FROM runtime_operations
              WHERE state='unresolved'
             UNION ALL
             SELECT cat.cat_id, head.node_id
               FROM cat_records cat
               JOIN runtime_operations head
                 ON head.cat_id=cat.cat_id
                AND head.operation_id=cat.lifecycle_head_operation_id
              WHERE NOT EXISTS (
                    SELECT 1 FROM runtime_operations pending
                     WHERE pending.cat_id=cat.cat_id
                       AND pending.state='unresolved'
              )
         )
         SELECT cat.cat_id, config.placement_vcpus,
                config.placement_memory_bytes,
                config.placement_ipv4_pool_base,
                config.placement_ipv4_slot
           FROM cat_records cat
           JOIN current_operation operation USING (cat_id)
           JOIN cat_runtime_configs config
             ON config.workspace_id=cat.workspace_id
            AND config.cat_id=cat.cat_id
            AND config.config_id=cat.current_runtime_config_id
            AND config.canonical_config_sha256=cat.current_runtime_config_sha256
          WHERE cat.deleted_at IS NULL
            AND operation.node_id=$1
          ORDER BY cat.cat_id COLLATE \"C\"
          LIMIT $2",
        &[
            &node_id.as_str(),
            &i64::try_from(MAX_CURRENT_CATS_PER_NODE + 1)
                .expect("current Cat bound fits PostgreSQL BIGINT"),
        ],
    )?;
    let mut allocation = CurrentNodeAllocation {
        cat_ids: BTreeSet::new(),
        occupied_slots: BTreeSet::new(),
        total_vcpus: 0,
        total_memory_bytes: 0,
    };
    let expected_pool = i64::from(policy_pool_base(policy)?);
    for row in rows {
        let cat_id = Id::new(row.try_get::<_, String>("cat_id")?)
            .ok_or_else(|| corrupt("stored Cat ID is invalid"))?;
        if !allocation.cat_ids.insert(cat_id.clone()) {
            return Err(corrupt("one Cat has multiple current placement rows"));
        }
        if excluded_cat_id == Some(&cat_id) {
            continue;
        }
        let vcpus: i64 = row.try_get("placement_vcpus")?;
        let memory_bytes: i64 = row.try_get("placement_memory_bytes")?;
        let pool: i64 = row.try_get("placement_ipv4_pool_base")?;
        let slot: i64 = row.try_get("placement_ipv4_slot")?;
        let vcpus = u128::try_from(vcpus)
            .map_err(|_| corrupt("stored placement vCPU claim is negative"))?;
        let memory_bytes = u128::try_from(memory_bytes)
            .map_err(|_| corrupt("stored placement memory claim is negative"))?;
        let slot =
            u32::try_from(slot).map_err(|_| corrupt("stored placement IPv4 slot exceeds u32"))?;
        if vcpus == 0
            || memory_bytes == 0
            || pool != expected_pool
            || slot == 0
            || slot > IPV4_SLOT_COUNT
        {
            return Err(corrupt("stored placement claims are outside their bounds"));
        }
        allocation.total_vcpus = allocation
            .total_vcpus
            .checked_add(vcpus)
            .ok_or_else(|| corrupt("current vCPU allocation overflow"))?;
        allocation.total_memory_bytes = allocation
            .total_memory_bytes
            .checked_add(memory_bytes)
            .ok_or_else(|| corrupt("current memory allocation overflow"))?;
        if !allocation.occupied_slots.insert(slot) {
            return Err(corrupt("current runtime configs reuse an IPv4 slot"));
        }
    }
    Ok(allocation)
}

pub(super) fn runtime_network_id_exists(
    transaction: &mut Transaction<'_>,
    network_id: &Id,
) -> AuthorityTxResult<bool> {
    transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM cat_runtime_configs
                 WHERE placement_network_id=$1
            )",
            &[&network_id.as_str()],
        )?
        .try_get(0)
        .map_err(Into::into)
}

fn runtime_network_id(config: &RuntimeNetworkConfig) -> &Id {
    match config {
        RuntimeNetworkConfig::IsolatedIpv4 { network_id, .. } => network_id,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn revalidate_cat_create_placement(
    transaction: &mut Transaction<'_>,
    planned: &PlacementTargetSnapshot,
    planned_mutation: &CatCreatePlacementMutation,
    active_guest_digest: &Sha256Digest,
    now: UnixMillis,
    checkpoint: &mut impl FnMut(&mut Transaction<'_>) -> AuthorityTxResult<()>,
) -> AuthorityTxResult<PlacementCommitLoad> {
    if planned.policy.node_id != planned.node_identity.node_id
        || planned.node_identity.state != NodeIdentityState::Provisioned
        || planned.policy.capabilities.guest_config_digest != *active_guest_digest
        || planned.agent_session.guest_config_digest != *active_guest_digest
        || planned.active_host_fence_event.is_some()
        || planned.inventory_attestation.session != planned.session_binding()
        || planned.full_inventory_report.session != planned.session_binding()
        || planned_mutation.placement_epoch != Epoch::new(1).expect("one is a valid Epoch")
    {
        return Ok(PlacementCommitLoad::Stale);
    }

    checkpoint(transaction)?;
    let Some(identity) = load_identity_by_node_for_update(transaction, planned.node_id())? else {
        return Ok(PlacementCommitLoad::Stale);
    };
    if identity != planned.node_identity || identity.state != NodeIdentityState::Provisioned {
        return Ok(PlacementCommitLoad::Stale);
    }
    checkpoint(transaction)?;
    let Some(policy) = load_policy_unlocked(transaction, planned.node_id())? else {
        return Err(corrupt("provisioned Node lost its placement policy"));
    };
    checkpoint(transaction)?;
    let Some(session) = load_current_session_for_update(transaction, planned.node_id())? else {
        return Ok(PlacementCommitLoad::Stale);
    };
    checkpoint(transaction)?;
    let Some(inventory) = load_runtime_full_inventory_for_update(transaction, planned.node_id())?
    else {
        return Ok(PlacementCommitLoad::Stale);
    };
    checkpoint(transaction)?;
    let fence = load_active_event_by_node_unlocked(transaction, planned.node_id())?;
    if policy != planned.policy
        || !same_session_with_monotonic_deadline(&planned.agent_session, &session)
        || inventory.attestation != planned.inventory_attestation
        || inventory.full_report != planned.full_inventory_report
        || fence != planned.active_host_fence_event
    {
        return Ok(PlacementCommitLoad::Stale);
    }
    let request = CatCreatePlanRequest {
        cat_id: planned_mutation.cat_id.clone(),
        vcpus: planned_mutation.vcpus,
        memory_bytes: planned_mutation.memory_bytes,
        root_size_bytes: 1,
        durability: cats_api::runtime_reconciliation::Durability::Strict,
        boot_image_digest: Sha256Digest::from_bytes([0; 32]),
        guest_config_digest: active_guest_digest.clone(),
        network_id: runtime_network_id(&planned_mutation.network_config).clone(),
    };
    match evaluate_candidate(
        transaction,
        &request,
        &identity,
        &policy,
        &session,
        &inventory,
        fence.as_ref(),
        now,
        None,
    )? {
        CandidateEvaluation::Eligible(network) if network == planned_mutation.network_config => {
            Ok(PlacementCommitLoad::Accepted)
        }
        CandidateEvaluation::Eligible(_) | CandidateEvaluation::Rejected(_) => {
            Ok(PlacementCommitLoad::Stale)
        }
    }
}

pub(super) fn revalidate_cold_start_placement(
    transaction: &mut Transaction<'_>,
    planned: &ColdStartPlacementPlan,
    context: &LifecycleAdmissionContext,
    now: UnixMillis,
    checkpoint: &mut impl FnMut(&mut Transaction<'_>) -> AuthorityTxResult<()>,
) -> AuthorityTxResult<PlacementCommitLoad> {
    let Some(source) = context.lifecycle_head.as_ref() else {
        return Ok(PlacementCommitLoad::Stale);
    };
    let source_digest_matches = matches!(
        &source.state,
        LifecycleOperationState::Terminal {
            terminal,
            terminal_result_digest,
        } if terminal_result_digest == &planned.source_terminal_result_digest
            && source.runtime_config_id == source.canonical_request.runtime_config.config_id
            && source.runtime_config_digest
                == source.canonical_request.runtime_config.config_digest
            && matches!(
                terminal.as_ref(),
                LifecycleTerminalResult::NodeResult { response }
                    if matches!(
                        &response.result,
                        NodeResult::Cold(cold)
                            if cold.runtime_config_digest == source.runtime_config_digest
                    )
            )
    );
    let placement_matches = if planned.target.node_id() == &source.node_id {
        planned.target_placement == source.placement_identity
    } else {
        source
            .placement_identity
            .placement_epoch
            .get()
            .checked_add(1)
            .and_then(Epoch::new)
            .is_some_and(|epoch| {
                planned.target_placement.node_id == *planned.target.node_id()
                    && planned.target_placement.placement_epoch == epoch
            })
    };
    let config_successor_matches = planned.target_runtime_config.boot_image_digest
        == planned.source_runtime_config.boot_image_digest
        && planned.target_runtime_config.vcpus == planned.source_runtime_config.vcpus
        && planned.target_runtime_config.memory_bytes == planned.source_runtime_config.memory_bytes
        && planned.target_runtime_config.guest_runtime_profile_digest
            == planned.source_runtime_config.guest_runtime_profile_digest
        && planned.target_runtime_config.volumes == planned.source_runtime_config.volumes
        && (planned.target_runtime_config == planned.source_runtime_config
            || planned.target_runtime_config.config_id != planned.source_runtime_config.config_id);
    if context.deleted_at.is_some()
        || context.unresolved_operation.is_some()
        || context.stable_state != Some(LifecycleStableState::Cold)
        || source.operation_id != planned.source_operation_id
        || !source_digest_matches
        || context.immutable_runtime_config != planned.source_runtime_config
        || !placement_matches
        || !config_successor_matches
        || planned.target.policy.node_id != planned.target.node_identity.node_id
        || planned.target.node_identity.state != NodeIdentityState::Provisioned
        || planned.target.policy.capabilities.guest_config_digest
            != planned.target_runtime_config.guest_runtime_profile_digest
        || planned.target.agent_session.guest_config_digest
            != planned.target_runtime_config.guest_runtime_profile_digest
        || planned.target.active_host_fence_event.is_some()
        || planned.target.inventory_attestation.session != planned.target.session_binding()
        || planned.target.full_inventory_report.session != planned.target.session_binding()
    {
        return Ok(PlacementCommitLoad::Stale);
    }

    checkpoint(transaction)?;
    let Some(identity) = load_identity_by_node_for_update(transaction, planned.target.node_id())?
    else {
        return Ok(PlacementCommitLoad::Stale);
    };
    checkpoint(transaction)?;
    let Some(policy) = load_policy_unlocked(transaction, planned.target.node_id())? else {
        return Err(corrupt("provisioned Node lost its placement policy"));
    };
    checkpoint(transaction)?;
    let Some(session) = load_current_session_for_update(transaction, planned.target.node_id())?
    else {
        return Ok(PlacementCommitLoad::Stale);
    };
    checkpoint(transaction)?;
    let Some(inventory) =
        load_runtime_full_inventory_for_update(transaction, planned.target.node_id())?
    else {
        return Ok(PlacementCommitLoad::Stale);
    };
    checkpoint(transaction)?;
    let fence = load_active_event_by_node_unlocked(transaction, planned.target.node_id())?;
    if identity != planned.target.node_identity
        || policy != planned.target.policy
        || !same_session_with_monotonic_deadline(&planned.target.agent_session, &session)
        || inventory.attestation != planned.target.inventory_attestation
        || inventory.full_report != planned.target.full_inventory_report
        || fence != planned.target.active_host_fence_event
    {
        return Ok(PlacementCommitLoad::Stale);
    }
    let request = CatCreatePlanRequest {
        cat_id: source.cat_id.clone(),
        vcpus: planned.target_runtime_config.vcpus,
        memory_bytes: planned.target_runtime_config.memory_bytes,
        root_size_bytes: 1,
        durability: cats_api::runtime_reconciliation::Durability::Strict,
        boot_image_digest: planned.target_runtime_config.boot_image_digest.clone(),
        guest_config_digest: planned
            .target_runtime_config
            .guest_runtime_profile_digest
            .clone(),
        network_id: runtime_network_id(&planned.target_runtime_config.network_config).clone(),
    };
    match evaluate_candidate(
        transaction,
        &request,
        &identity,
        &policy,
        &session,
        &inventory,
        fence.as_ref(),
        now,
        Some(&source.cat_id),
    )? {
        CandidateEvaluation::Eligible(network)
            if network == planned.target_runtime_config.network_config =>
        {
            Ok(PlacementCommitLoad::Accepted)
        }
        CandidateEvaluation::Eligible(_) | CandidateEvaluation::Rejected(_) => {
            Ok(PlacementCommitLoad::Stale)
        }
    }
}

fn same_session_with_monotonic_deadline(planned: &AgentSession, current: &AgentSession) -> bool {
    planned.version == current.version
        && planned.node_id == current.node_id
        && planned.immutable_host_id == current.immutable_host_id
        && planned.node_boot_id == current.node_boot_id
        && planned.agent_instance_id == current.agent_instance_id
        && planned.agent_session_epoch == current.agent_session_epoch
        && planned.registration_attempt_id == current.registration_attempt_id
        && planned.guest_config_digest == current.guest_config_digest
        && current.lease_deadline_unix_ms >= planned.lease_deadline_unix_ms
}

#[cfg(test)]
fn validate_network_config(
    policy: &NodePlacementPolicy,
    config: &RuntimeNetworkConfig,
) -> AuthorityTxResult<u32> {
    let pool = policy_pool_base(policy)?;
    let (_, config_pool, slot) = project_network_claims(config)?;
    if config_pool != pool || slot == 0 {
        return Err(corrupt("runtime network is outside its Node policy /16"));
    }
    Ok(slot)
}

fn project_network_claims(config: &RuntimeNetworkConfig) -> AuthorityTxResult<(Id, u32, u32)> {
    let RuntimeNetworkConfig::IsolatedIpv4 {
        network_id,
        guest_mac,
        guest_ipv4,
        prefix_length,
        gateway_ipv4,
    } = config;
    if *prefix_length != 30 {
        return Err(corrupt("runtime config has an unsupported network prefix"));
    }
    let guest = ipv4_u32(guest_ipv4)?;
    let gateway = ipv4_u32(gateway_ipv4)?;
    let subnet = guest & !3;
    let pool = subnet & 0xffff_0000;
    if subnet.checked_add(3).is_none()
        || guest != subnet + 2
        || gateway != subnet + 1
        || guest_mac.as_str() != expected_mac(guest)
    {
        return Err(corrupt("runtime network projection is invalid"));
    }
    let slot = (subnet - pool) / IPV4_SLOT_BYTES;
    if slot > IPV4_SLOT_COUNT {
        return Err(corrupt("runtime network slot is outside one /16"));
    }
    Ok((network_id.clone(), pool, slot))
}

fn allocate_network(
    policy: &NodePlacementPolicy,
    network_id: &Id,
    occupied: &BTreeSet<u32>,
) -> AuthorityTxResult<Option<RuntimeNetworkConfig>> {
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
        return Ok(Some(RuntimeNetworkConfig::IsolatedIpv4 {
            network_id: network_id.clone(),
            guest_mac: MacAddress::new(expected_mac(guest))
                .ok_or_else(|| corrupt("derived guest MAC is invalid"))?,
            guest_ipv4: ipv4_from_u32(guest)?,
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
) -> RuntimeNetworkConfig {
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

fn corrupt(error: impl std::fmt::Display) -> AuthorityTransactionError {
    ApiError::internal(error.to_string()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_reconciliation::{
        AllocatableMemoryBytes, AllocatableVcpus, ContractVersion, GuestIpv4Pool,
        GuestIpv4PoolKind, NodeTransportTarget, RuntimePlacementBlockFrontend,
        RuntimePlacementCapabilities, RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport,
        RuntimePlacementVmm,
    };

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn policy() -> NodePlacementPolicy {
        NodePlacementPolicy {
            version: ContractVersion::V1,
            node_id: id("node_a"),
            policy_revision: Epoch::new(1).unwrap(),
            scheduling_state: RuntimeSchedulingState::Schedulable,
            allocatable_vcpus: AllocatableVcpus::new(16).unwrap(),
            allocatable_memory_bytes: AllocatableMemoryBytes::new(64 << 30).unwrap(),
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
                network_address: Ipv4Address::new("10.42.0.0").unwrap(),
                prefix_length: 16,
            },
            node_transport_target: NodeTransportTarget::new("https://runtime-node.internal:7301")
                .unwrap(),
        }
    }

    #[test]
    fn deterministic_allocator_returns_a_valid_runtime_network() {
        let policy = policy();
        let network_id = id("net_exact");
        let first = allocate_network_for_test(&policy, &network_id);
        let second = allocate_network_for_test(&policy, &network_id);
        assert_eq!(first, second);
        assert_eq!(runtime_network_id(&first), &network_id);
        assert!(validate_network_config(&policy, &first).is_ok());
    }

    #[test]
    fn allocator_probes_past_an_occupied_slot() {
        let policy = policy();
        let network_id = id("net_probe");
        let first = allocate_network_for_test(&policy, &network_id);
        let occupied = BTreeSet::from([validate_network_config(&policy, &first).unwrap()]);
        let second = allocate_network(&policy, &network_id, &occupied)
            .unwrap()
            .unwrap();
        assert_ne!(first, second);
        assert!(validate_network_config(&policy, &second).is_ok());
    }
}

//! Production integration adapters for the semantic Control/Node protocol.
//!
//! PostgreSQL calls are always submitted through [`Store::execute`], so the
//! synchronous driver never blocks an async request worker. The ingress seam
//! deliberately fails closed: the former Route Operation protocol cannot be
//! presented as the new unique-ingress switch without a real cutover adapter.

use std::sync::Arc;
use std::time::Duration;

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{Id, RandomId128};
use cats_api::semantic_control::{
    CatAction as WireCatAction, CatIngressTarget, CatState as WireCatState, NodeHeartbeatRequest,
    NodeHeartbeatResponse, NodeHeartbeatStatus, NodeName, NodeRegistrationRequest,
    NodeRegistrationResponse, NodeRegistrationStatus, NodeStatus as WireNodeStatus, NodeView,
    NodedCatActionRequest, NodedCatConfig, NodedControlEndpoint, NodedDiskMount, NodedResultStatus,
    PersistentDiskFormat, PersistentMountPath, SemanticErrorCode,
};
use tokio::time::Instant;

use crate::semantic_lifecycle::{
    ActionClaim, Admission, CatAction, CatCreateConfig, CatMount, CatRecord, CatSelector, CatState,
    CreateCatRequest, IngressError, IngressPort, NodeCatStatus, NodeClientError, NodeCommand,
    NodeCommandResult, NodeControlEndpoint, NodedClient, SemanticActionRecoveryStore,
    SemanticFuture, SemanticLifecycleStore, StoreError,
};
use crate::semantic_node::{
    NodeFuture, NodeRecord as ManagedNodeRecord, NodeRepository, StaleNodeCandidate,
};
use crate::semantic_noded_client::{
    SemanticNodedClient, SemanticNodedClientError, DEFAULT_NODED_REQUEST_TIMEOUT,
};
use crate::store::semantic::{
    AdmitCatActionOutcome, AdmitCatCreateOutcome, AtomicCatCreate, CatAction as StoredCatAction,
    CatIngressTargetRecord, CatRecord as StoredCatRecord, CatState as StoredCatState,
    CatWithMounts, FinishCatAction, NewCatMount, NodeHeartbeat, NodeRecord as StoredNodeRecord,
    NodeRegistration, NodeStatus as StoredNodeStatus, PublishCatIngressOutcome,
    RegisterNodeOutcome, SemanticCatSelector, StaleNodeRecord, WithdrawCatIngressOutcome,
};
use crate::store::{new_id, Store};

/// PostgreSQL implementation of semantic lifecycle admission and settlement.
#[derive(Clone)]
pub struct SemanticStoreAdapter {
    store: Arc<Store>,
}

impl SemanticStoreAdapter {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }
}

impl SemanticLifecycleStore for SemanticStoreAdapter {
    fn admit_create<'a>(
        &'a self,
        request: &'a CreateCatRequest,
    ) -> SemanticFuture<'a, Result<Admission, StoreError>> {
        let store = Arc::clone(&self.store);
        let request = request.clone();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let cat_id = new_id("cat_");
                    let owned_mounts = request
                        .config
                        .mounts
                        .iter()
                        .map(|mount| {
                            (
                                new_id("mnt_"),
                                mount.disk_id.clone(),
                                mount.mount_path.clone(),
                            )
                        })
                        .collect::<Vec<_>>();
                    let mounts = owned_mounts
                        .iter()
                        .map(|(binding_id, disk_id, mount_path)| NewCatMount {
                            binding_id,
                            disk_id,
                            mount_path,
                        })
                        .collect::<Vec<_>>();
                    let outcome = store.admit_semantic_cat_create(AtomicCatCreate {
                        cat_id: &cat_id,
                        workspace_id: &request.workspace_id,
                        cat_slug: &request.cat_slug,
                        cpu_count: i64::from(request.config.cpu_count),
                        memory_bytes: i64::try_from(request.config.memory_bytes).map_err(|_| {
                            ApiError::invalid("Cat memory does not fit PostgreSQL BIGINT")
                        })?,
                        boot_image: &request.config.boot_image,
                        mounts: &mounts,
                    })?;
                    map_create_admission(outcome)
                })
                .await
                .map_err(store_error)
        })
    }

    fn admit_action<'a>(
        &'a self,
        selector: &'a CatSelector,
        action: CatAction,
    ) -> SemanticFuture<'a, Result<Admission, StoreError>> {
        let store = Arc::clone(&self.store);
        let selector = selector.clone();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let stored_selector = match &selector {
                        CatSelector::Id(cat_id) => SemanticCatSelector::Id(cat_id),
                        CatSelector::Slug {
                            workspace_id,
                            cat_slug,
                        } => SemanticCatSelector::Slug {
                            workspace_id,
                            cat_slug,
                        },
                    };
                    let outcome = store.admit_semantic_cat_action(
                        stored_selector,
                        core_action_to_stored(action),
                    )?;
                    map_action_admission(outcome, action)
                })
                .await
                .map_err(store_error)
        })
    }

    fn pending_destroy_claims<'a>(
        &'a self,
        minimum_age: Duration,
        limit: usize,
    ) -> SemanticFuture<'a, Result<Vec<ActionClaim>, StoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let minimum_age_ms = i64::try_from(minimum_age.as_millis()).unwrap_or(i64::MAX);
            let limit = i64::try_from(limit).unwrap_or(i64::MAX);
            store
                .execute(move |store| {
                    store
                        .list_pending_semantic_destroy_claims(minimum_age_ms, limit)?
                        .into_iter()
                        .map(|cat| claim_from_aggregate(cat, CatAction::Destroy))
                        .collect()
                })
                .await
                .map_err(store_error)
        })
    }

    fn rotate_pending_destroy<'a>(
        &'a self,
        claim: &'a ActionClaim,
    ) -> SemanticFuture<'a, Result<bool, StoreError>> {
        let store = Arc::clone(&self.store);
        let cat_id = claim.cat.cat_id.clone();
        let node_id = claim.node_id.clone();
        let started_at_unix_ms = claim.started_at_unix_ms;
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.rotate_pending_semantic_destroy_claim(
                        &cat_id,
                        node_id.as_deref(),
                        started_at_unix_ms,
                    )
                })
                .await
                .map_err(store_error)
        })
    }

    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> SemanticFuture<'a, Result<NodeControlEndpoint, StoreError>> {
        let store = Arc::clone(&self.store);
        let node_id = node_id.to_owned();
        Box::pin(async move {
            let node = store
                .execute(move |store| store.find_semantic_node(&node_id))
                .await
                .map_err(store_error)?
                .ok_or_else(|| StoreError::new("selected Node does not exist"))?;
            if node.status == StoredNodeStatus::Deleted {
                return Err(StoreError::new("selected Node is deleted"));
            }
            NodeControlEndpoint::new(node.control_endpoint)
        })
    }

    fn complete_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
        resulting_state: CatState,
    ) -> SemanticFuture<'a, Result<CatRecord, StoreError>> {
        settle_action(self, claim, resulting_state, None, None)
    }

    fn fail_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
        code: &'a str,
        message: &'a str,
    ) -> SemanticFuture<'a, Result<CatRecord, StoreError>> {
        settle_action(
            self,
            claim,
            CatState::Failure,
            Some(code.to_owned()),
            Some(message.to_owned()),
        )
    }
}

fn settle_action<'a>(
    adapter: &'a SemanticStoreAdapter,
    claim: &'a ActionClaim,
    resulting_state: CatState,
    error_code: Option<String>,
    error_message: Option<String>,
) -> SemanticFuture<'a, Result<CatRecord, StoreError>> {
    let store = Arc::clone(&adapter.store);
    let claim = claim.clone();
    Box::pin(async move {
        store
            .execute(move |store| {
                let final_node_id =
                    if matches!(resulting_state, CatState::Cold | CatState::Destroyed) {
                        None
                    } else {
                        claim.node_id.as_deref().or(claim.cat.node_id.as_deref())
                    };
                let row = store.finish_semantic_cat_action(
                    &claim.cat.cat_id,
                    FinishCatAction {
                        expected_action: core_action_to_stored(claim.action),
                        expected_action_started_at: claim.started_at_unix_ms,
                        expected_node_id: claim.node_id.as_deref(),
                        final_state: core_state_to_stored(resulting_state),
                        final_node_id,
                        error_code: error_code.as_deref(),
                        error_message: error_message.as_deref(),
                    },
                )?;
                let row = row.ok_or_else(|| {
                    ApiError::conflict("semantic Cat action claim is no longer current")
                })?;
                let aggregate = store
                    .find_semantic_cat_with_mounts_by_id(&row.cat_id)?
                    .ok_or_else(|| ApiError::internal("settled Cat projection disappeared"))?;
                aggregate_to_core(aggregate)
            })
            .await
            .map_err(store_error)
    })
}

impl SemanticActionRecoveryStore for SemanticStoreAdapter {
    fn stale_actions<'a>(
        &'a self,
        stale_after: Duration,
        limit: usize,
    ) -> SemanticFuture<'a, Result<Vec<ActionClaim>, StoreError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let stale_after_ms = i64::try_from(stale_after.as_millis())
                .map_err(|_| StoreError::new("stale action age exceeds PostgreSQL BIGINT"))?;
            store
                .execute(move |store| {
                    store
                        .list_stale_semantic_cat_actions(stale_after_ms, limit)?
                        .into_iter()
                        .map(|cat| {
                            let action = cat.cat.current_action.ok_or_else(|| {
                                ApiError::internal("stale action scan returned an idle Cat")
                            })?;
                            claim_from_aggregate(cat, stored_action_to_core(action))
                        })
                        .collect()
                })
                .await
                .map_err(store_error)
        })
    }

    fn rotate_stale_action<'a>(
        &'a self,
        claim: &'a ActionClaim,
    ) -> SemanticFuture<'a, Result<bool, StoreError>> {
        let store = Arc::clone(&self.store);
        let cat_id = claim.cat.cat_id.clone();
        let action = core_action_to_stored(claim.action);
        let node_id = claim.node_id.clone();
        let started_at_unix_ms = claim.started_at_unix_ms;
        Box::pin(async move {
            store
                .execute(move |store| {
                    store.rotate_stale_semantic_cat_action(
                        &cat_id,
                        action,
                        node_id.as_deref(),
                        started_at_unix_ms,
                    )
                })
                .await
                .map_err(store_error)
        })
    }
}

fn map_create_admission(outcome: AdmitCatCreateOutcome) -> crate::store::Result<Admission> {
    Ok(match outcome {
        AdmitCatCreateOutcome::Created(cat) => {
            Admission::Claimed(claim_from_aggregate(cat, CatAction::Create)?)
        }
        AdmitCatCreateOutcome::SameAction(cat) => {
            Admission::SameAction(claim_from_aggregate(cat, CatAction::Create)?)
        }
        AdmitCatCreateOutcome::AlreadyExists(cat) => Admission::Already {
            cat: aggregate_to_core(cat)?,
            code: CatAction::Create.already_code(),
        },
        AdmitCatCreateOutcome::Busy(cat) => Admission::Busy(aggregate_to_core(cat)?),
        AdmitCatCreateOutcome::ConfigurationConflict(cat) => Admission::Conflict {
            cat: aggregate_to_core(cat)?,
            code: "cat_configuration_conflict",
        },
        AdmitCatCreateOutcome::NodeNotSchedulable => {
            return Err(ApiError::unavailable("no running Node accepts placement"));
        }
        AdmitCatCreateOutcome::MountRejected { code, message } => {
            return Err(ApiError::failed_precondition(format!("{code}: {message}")));
        }
    })
}

fn map_action_admission(
    outcome: AdmitCatActionOutcome,
    action: CatAction,
) -> crate::store::Result<Admission> {
    Ok(match outcome {
        AdmitCatActionOutcome::Acquired(cat) => {
            Admission::Claimed(claim_from_aggregate(cat, action)?)
        }
        AdmitCatActionOutcome::SameAction(cat) => {
            Admission::SameAction(claim_from_aggregate(cat, action)?)
        }
        AdmitCatActionOutcome::AlreadyDone(cat) => Admission::Already {
            cat: aggregate_to_core(cat)?,
            code: action.already_code(),
        },
        AdmitCatActionOutcome::Busy(cat) => Admission::Busy(aggregate_to_core(cat)?),
        AdmitCatActionOutcome::InvalidState(cat) => {
            Admission::InvalidState(aggregate_to_core(cat)?)
        }
        AdmitCatActionOutcome::NotFound => Admission::NotFound,
        AdmitCatActionOutcome::NodeNotSchedulable(cat) => Admission::Conflict {
            cat: aggregate_to_core(cat)?,
            code: "node_unavailable",
        },
    })
}

fn claim_from_aggregate(
    cat: CatWithMounts,
    action: CatAction,
) -> crate::store::Result<ActionClaim> {
    let node_id = cat.cat.current_action_node_id.clone();
    let started_at_unix_ms = cat
        .cat
        .current_action_started_at
        .ok_or_else(|| ApiError::internal("claimed semantic Cat action omitted its start time"))?;
    Ok(ActionClaim {
        cat: aggregate_to_core(cat)?,
        action,
        started_at_unix_ms,
        node_id,
    })
}

fn aggregate_to_core(cat: CatWithMounts) -> crate::store::Result<CatRecord> {
    let mounts = cat
        .mounts
        .into_iter()
        .map(|mount| CatMount {
            disk_id: mount.disk_id,
            volume_id: mount.volume_id,
            filesystem_uuid: mount.filesystem_uuid,
            disk_format: mount.disk_format,
            mount_path: mount.mount_path,
        })
        .collect();
    stored_cat_to_core(cat.cat, mounts)
}

fn stored_cat_to_core(
    cat: StoredCatRecord,
    mounts: Vec<CatMount>,
) -> crate::store::Result<CatRecord> {
    Ok(CatRecord {
        cat_id: cat.cat_id,
        workspace_id: cat.workspace_id,
        cat_slug: cat.cat_slug,
        state: cat.state.map(stored_state_to_core),
        current_action: cat.current_action.map(stored_action_to_core),
        current_action_node_id: cat.current_action_node_id,
        node_id: cat.node_id,
        config: CatCreateConfig {
            cpu_count: u32::try_from(cat.cpu_count)
                .map_err(|_| ApiError::internal("stored Cat CPU count is invalid"))?,
            memory_bytes: u64::try_from(cat.memory_bytes)
                .map_err(|_| ApiError::internal("stored Cat memory is invalid"))?,
            boot_image: cat.boot_image,
            mounts,
        },
    })
}

fn store_error(error: ApiError) -> StoreError {
    StoreError::new(error.to_string())
}

/// Explicit production placeholder. It never claims that the retired Route
/// Operation protocol performed the new synchronous unique-ingress switch.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableIngressPort;

impl IngressPort for UnavailableIngressPort {
    fn withdraw<'a>(
        &'a self,
        _cat_id: &'a str,
        _old_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>> {
        Box::pin(async {
            Err(IngressError::new(
                "semantic unique-ingress withdraw adapter is not installed",
            ))
        })
    }

    fn publish<'a>(
        &'a self,
        _cat_id: &'a str,
        _new_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>> {
        Box::pin(async {
            Err(IngressError::new(
                "semantic unique-ingress publish adapter is not installed",
            ))
        })
    }
}

/// PostgreSQL-backed current target used by the semantic lifecycle and by a
/// Gateway path resolving each new request. It is independent from the
/// retired Route Operation signer.
#[derive(Clone)]
pub struct SemanticIngressAdapter {
    store: Arc<Store>,
}

impl SemanticIngressAdapter {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Read the one current target for a Cat. `None` means new traffic is
    /// withdrawn; callers must not fall back to lifecycle placement or a
    /// cached retired Route grant.
    pub async fn resolve(&self, cat_id: &str) -> Result<Option<CatIngressTarget>, IngressError> {
        let store = Arc::clone(&self.store);
        let cat_id = cat_id.to_owned();
        let target = store
            .execute(move |store| store.resolve_semantic_cat_ingress(&cat_id))
            .await
            .map_err(|error| IngressError::new(error.to_string()))?;
        target.map(wire_ingress_target).transpose()
    }
}

impl IngressPort for SemanticIngressAdapter {
    fn withdraw<'a>(
        &'a self,
        cat_id: &'a str,
        old_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>> {
        let store = Arc::clone(&self.store);
        let cat_id = cat_id.to_owned();
        let old_node_id = old_node_id.to_owned();
        Box::pin(async move {
            let outcome = store
                .execute(move |store| store.withdraw_semantic_cat_ingress(&cat_id, &old_node_id))
                .await
                .map_err(|error| IngressError::new(error.to_string()))?;
            map_withdraw_ingress_outcome(outcome)
        })
    }

    fn publish<'a>(
        &'a self,
        cat_id: &'a str,
        new_node_id: &'a str,
    ) -> SemanticFuture<'a, Result<(), IngressError>> {
        let store = Arc::clone(&self.store);
        let cat_id = cat_id.to_owned();
        let new_node_id = new_node_id.to_owned();
        Box::pin(async move {
            let outcome = store
                .execute(move |store| store.publish_semantic_cat_ingress(&cat_id, &new_node_id))
                .await
                .map_err(|error| IngressError::new(error.to_string()))?;
            map_publish_ingress_outcome(outcome)
        })
    }
}

fn map_publish_ingress_outcome(outcome: PublishCatIngressOutcome) -> Result<(), IngressError> {
    match outcome {
        PublishCatIngressOutcome::Published(_) | PublishCatIngressOutcome::AlreadyPublished(_) => {
            Ok(())
        }
        PublishCatIngressOutcome::Conflict(current) => Err(IngressError::new(format!(
            "Cat ingress already targets Node {}",
            current.node_id
        ))),
        PublishCatIngressOutcome::CatNotReady => {
            Err(IngressError::new("Cat is not Ready on the requested Node"))
        }
        PublishCatIngressOutcome::NodeNotRunning => {
            Err(IngressError::new("requested Node is not running"))
        }
        PublishCatIngressOutcome::CatNotFound => Err(IngressError::new("Cat does not exist")),
    }
}

fn map_withdraw_ingress_outcome(outcome: WithdrawCatIngressOutcome) -> Result<(), IngressError> {
    match outcome {
        WithdrawCatIngressOutcome::Withdrawn | WithdrawCatIngressOutcome::AlreadyWithdrawn => {
            Ok(())
        }
        WithdrawCatIngressOutcome::Conflict(current) => Err(IngressError::new(format!(
            "Cat ingress now targets Node {}",
            current.node_id
        ))),
        WithdrawCatIngressOutcome::CatNotWithdrawing => {
            Err(IngressError::new("Cat is not withdrawing from this Node"))
        }
        WithdrawCatIngressOutcome::CatNotFound => Err(IngressError::new("Cat does not exist")),
    }
}

fn wire_ingress_target(target: CatIngressTargetRecord) -> Result<CatIngressTarget, IngressError> {
    let target = CatIngressTarget {
        cat_id: Id::new(target.cat_id)
            .ok_or_else(|| IngressError::new("stored Cat ID is invalid"))?,
        node_id: Id::new(target.node_id)
            .ok_or_else(|| IngressError::new("stored Node ID is invalid"))?,
    };
    target
        .validate()
        .map_err(|error| IngressError::new(error.to_string()))?;
    Ok(target)
}

/// PostgreSQL implementation of semantic Node registration and liveness.
#[derive(Clone)]
pub struct SemanticNodeRepositoryAdapter {
    store: Arc<Store>,
}

impl SemanticNodeRepositoryAdapter {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl NodeRepository for SemanticNodeRepositoryAdapter {
    fn register(&self, request: NodeRegistrationRequest) -> NodeFuture<NodeRegistrationResponse> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    let outcome = store.register_semantic_node(NodeRegistration {
                        node_id: request.node_id.as_str(),
                        node_name: request.node_name.as_str(),
                        control_endpoint: request.control_endpoint.as_str(),
                        vendor: &request.vendor,
                        region: &request.region,
                        zone: &request.zone,
                        instance_id: &request.instance_id,
                        machine_type: &request.machine_type,
                        node_version: &request.node_version,
                        reset_completed: request.reset_completed,
                    })?;
                    map_registration_outcome(outcome)
                })
                .await
        })
    }

    fn heartbeat(&self, request: NodeHeartbeatRequest) -> NodeFuture<NodeHeartbeatResponse> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    let (status, _) = store.record_semantic_node_heartbeat(NodeHeartbeat {
                        node_id: request.node_id.as_str(),
                        node_reported_at: Some(
                            i64::try_from(request.node_reported_at_unix_ms).map_err(|_| {
                                ApiError::invalid(
                                    "Node reported timestamp exceeds PostgreSQL BIGINT",
                                )
                            })?,
                        ),
                        reported_status: wire_node_status_to_stored(request.reported_status),
                        total_cpu: i64::from(request.total_cpu),
                        cpu_utilized: request.cpu_utilized,
                        total_memory: i64::try_from(request.total_memory).map_err(|_| {
                            ApiError::invalid("Node total memory exceeds PostgreSQL BIGINT")
                        })?,
                        memory_utilized: i64::try_from(request.memory_utilized).map_err(|_| {
                            ApiError::invalid("Node utilized memory exceeds PostgreSQL BIGINT")
                        })?,
                        running_cat_count: i64::from(request.running_cat_count),
                        suspended_cat_count: i64::from(request.suspended_cat_count),
                        warm_cat_count: i64::from(request.warm_cat_count),
                    })?;
                    Ok(NodeHeartbeatResponse {
                        status: if matches!(
                            status,
                            StoredNodeStatus::Offline
                                | StoredNodeStatus::ResetRequired
                                | StoredNodeStatus::Deleted
                        ) {
                            NodeHeartbeatStatus::ResetRequired
                        } else {
                            NodeHeartbeatStatus::Accepted
                        },
                    })
                })
                .await
        })
    }

    fn begin_drain(&self, node_id: String) -> NodeFuture<ManagedNodeRecord> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    if let Some(node) = store.transition_semantic_node_status(
                        &node_id,
                        &[StoredNodeStatus::Running],
                        StoredNodeStatus::Draining,
                    )? {
                        return stored_node_to_managed(node);
                    }
                    match store.find_semantic_node(&node_id)? {
                        Some(node) if node.status == StoredNodeStatus::Draining => {
                            stored_node_to_managed(node)
                        }
                        Some(_) => Err(ApiError::failed_precondition(
                            "Node state does not allow drain",
                        )),
                        None => Err(ApiError::not_found("Node")),
                    }
                })
                .await
        })
    }

    fn placement_candidates(&self) -> NodeFuture<Vec<ManagedNodeRecord>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(move |store| {
                    store
                        .list_running_semantic_nodes()?
                        .into_iter()
                        .map(stored_node_to_managed)
                        .collect()
                })
                .await
        })
    }

    fn stale_candidates(&self, missed_for: Duration) -> NodeFuture<Vec<StaleNodeCandidate>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let millis = i64::try_from(missed_for.as_millis())
                .map_err(|_| ApiError::invalid("missed heartbeat window is too large"))?;
            store
                .execute(move |store| {
                    Ok(store
                        .list_stale_semantic_nodes(millis)?
                        .into_iter()
                        .map(|candidate| StaleNodeCandidate {
                            node_id: candidate.node_id,
                            control_endpoint: candidate.control_endpoint,
                            last_heartbeat_at: candidate.last_heartbeat_at.to_string(),
                        })
                        .collect())
                })
                .await
        })
    }

    fn mark_offline_if_heartbeat_unchanged(
        &self,
        candidate: StaleNodeCandidate,
    ) -> NodeFuture<bool> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let last_heartbeat_at = candidate.last_heartbeat_at.parse::<i64>().map_err(|_| {
                ApiError::internal("stale Node candidate has an invalid DB timestamp token")
            })?;
            store
                .execute(move |store| {
                    store.mark_semantic_node_offline_if_heartbeat_unchanged(&StaleNodeRecord {
                        node_id: candidate.node_id,
                        control_endpoint: candidate.control_endpoint,
                        last_heartbeat_at,
                    })
                })
                .await
        })
    }

    fn offline_recovery_candidates(&self) -> NodeFuture<Vec<String>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(|store| store.list_semantic_offline_nodes_with_cats())
                .await
        })
    }

    fn planned_drain_candidates(&self) -> NodeFuture<Vec<String>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store
                .execute(|store| store.list_semantic_draining_nodes_with_cats())
                .await
        })
    }
}

fn map_registration_outcome(
    outcome: RegisterNodeOutcome,
) -> crate::store::Result<NodeRegistrationResponse> {
    let (status, node) = match outcome {
        RegisterNodeOutcome::Registered(node) => (NodeRegistrationStatus::Registered, node),
        RegisterNodeOutcome::AlreadyRegistered(node)
        | RegisterNodeOutcome::RegistrationUpdated(node) => {
            (NodeRegistrationStatus::AlreadyRegistered, node)
        }
        RegisterNodeOutcome::ResetRequired(node) => (NodeRegistrationStatus::ResetRequired, node),
        RegisterNodeOutcome::IdentityConflict(_) => {
            return Err(ApiError::conflict(
                "Node identity conflicts with its registration",
            ));
        }
        RegisterNodeOutcome::Deleted(_) => {
            return Err(ApiError::failed_precondition("Node is deleted"));
        }
    };
    Ok(NodeRegistrationResponse {
        status,
        node: stored_node_to_view(node)?,
    })
}

fn stored_node_to_managed(node: StoredNodeRecord) -> crate::store::Result<ManagedNodeRecord> {
    Ok(ManagedNodeRecord {
        node_id: node.node_id,
        node_name: node.node_name,
        vendor: node.vendor,
        region: node.region,
        zone: node.zone,
        instance_id: node.instance_id,
        machine_type: node.machine_type,
        node_version: node.node_version,
        control_endpoint: node.control_endpoint,
        status: stored_node_status_to_wire(node.status),
    })
}

fn stored_node_to_view(node: StoredNodeRecord) -> crate::store::Result<NodeView> {
    let view = NodeView {
        node_id: Id::new(node.node_id)
            .ok_or_else(|| ApiError::internal("stored Node ID is invalid"))?,
        node_name: NodeName::new(node.node_name)
            .ok_or_else(|| ApiError::internal("stored Node name is invalid"))?,
        control_endpoint: NodedControlEndpoint::new(node.control_endpoint)
            .ok_or_else(|| ApiError::internal("stored Node control endpoint is invalid"))?,
        vendor: node.vendor,
        region: node.region,
        zone: node.zone,
        instance_id: node.instance_id,
        machine_type: node.machine_type,
        node_version: node.node_version,
        status: stored_node_status_to_wire(node.status),
        created_at_unix_ms: u64::try_from(node.created_at)
            .map_err(|_| ApiError::internal("stored Node created timestamp is invalid"))?,
        updated_at_unix_ms: u64::try_from(node.updated_at)
            .map_err(|_| ApiError::internal("stored Node updated timestamp is invalid"))?,
    };
    view.validate()
        .map_err(|error| ApiError::internal(format!("stored Node is invalid: {error}")))?;
    Ok(view)
}

/// Maps the lifecycle port onto the bounded authenticated semantic HTTP
/// client. Product failures remain product results; only transport and wire
/// failures become `NodeClientError`.
#[derive(Clone)]
pub struct SemanticNodedLifecycleAdapter {
    client: SemanticNodedClient,
    call_deadline: Duration,
}

impl SemanticNodedLifecycleAdapter {
    pub fn new(client: SemanticNodedClient) -> Self {
        Self {
            client,
            call_deadline: DEFAULT_NODED_REQUEST_TIMEOUT,
        }
    }

    pub fn with_call_deadline(
        client: SemanticNodedClient,
        call_deadline: Duration,
    ) -> Result<Self, ApiError> {
        if call_deadline.is_zero() {
            return Err(ApiError::invalid("noded call deadline must be positive"));
        }
        Ok(Self {
            client,
            call_deadline,
        })
    }
}

impl NodedClient for SemanticNodedLifecycleAdapter {
    fn execute<'a>(
        &'a self,
        endpoint: &'a NodeControlEndpoint,
        command: &'a NodeCommand,
    ) -> SemanticFuture<'a, Result<NodeCommandResult, NodeClientError>> {
        Box::pin(async move {
            let endpoint = wire_endpoint(endpoint)?;
            let cat_id = wire_id(&command.cat_id, "Cat")?;
            let deadline = Instant::now() + self.call_deadline;
            let result = match command.action {
                CatAction::Create => {
                    let config = command.config.as_ref().ok_or_else(|| {
                        NodeClientError::Protocol("Create has no config".to_owned())
                    })?;
                    let request = core_config_to_wire(&command.workspace_id, config)?;
                    self.client
                        .create_cat(&endpoint, &cat_id, &request, deadline)
                        .await
                }
                CatAction::Destroy => self.client.destroy_cat(&endpoint, &cat_id, deadline).await,
                action => {
                    let request = NodedCatActionRequest {
                        config: if action == CatAction::Run {
                            Some(core_config_to_wire(
                                &command.workspace_id,
                                command.config.as_ref().ok_or_else(|| {
                                    NodeClientError::Protocol("Run has no config".to_owned())
                                })?,
                            )?)
                        } else {
                            None
                        },
                    };
                    self.client
                        .cat_action(
                            &endpoint,
                            &cat_id,
                            core_action_to_wire(action),
                            &request,
                            deadline,
                        )
                        .await
                }
            };
            match result {
                Ok(response) => map_noded_response(response.status, response.state),
                Err(error) => map_noded_execute_error(error, command.action),
            }
        })
    }

    fn inspect<'a>(
        &'a self,
        endpoint: &'a NodeControlEndpoint,
        cat_id: &'a str,
    ) -> SemanticFuture<'a, Result<NodeCatStatus, NodeClientError>> {
        Box::pin(async move {
            let endpoint = wire_endpoint(endpoint)?;
            let cat_id = wire_id(cat_id, "Cat")?;
            match self
                .client
                .get_cat(&endpoint, &cat_id, Instant::now() + self.call_deadline)
                .await
            {
                Ok(cat) => Ok(NodeCatStatus::Present {
                    state: cat.state.map(wire_state_to_core),
                    active_action: cat.active_action.map(wire_action_to_core),
                }),
                Err(SemanticNodedClientError::Failed { error, .. })
                    if error.code == SemanticErrorCode::CatNotFound =>
                {
                    Ok(NodeCatStatus::Absent)
                }
                Err(SemanticNodedClientError::Failed { error, .. }) => Ok(NodeCatStatus::Failed {
                    code: semantic_error_code(error.code).to_owned(),
                    message: error.message,
                }),
                Err(error) => Err(map_transport_error(error)),
            }
        })
    }
}

fn map_noded_response(
    status: NodedResultStatus,
    state: WireCatState,
) -> Result<NodeCommandResult, NodeClientError> {
    let state = wire_state_to_core(state);
    match status {
        NodedResultStatus::Ok => Ok(NodeCommandResult::Succeeded(state)),
        NodedResultStatus::AlreadyDone => Ok(NodeCommandResult::AlreadyDone(state)),
        NodedResultStatus::Busy => Ok(NodeCommandResult::Busy),
        NodedResultStatus::Failed => Err(NodeClientError::Protocol(
            "noded returned failed status without its required error response".to_owned(),
        )),
    }
}

fn map_noded_execute_error(
    error: SemanticNodedClientError,
    action: CatAction,
) -> Result<NodeCommandResult, NodeClientError> {
    match error {
        SemanticNodedClientError::Failed { error, .. }
            if error.code == SemanticErrorCode::CatNotFound && action == CatAction::Destroy =>
        {
            Ok(NodeCommandResult::AlreadyDone(CatState::Destroyed))
        }
        SemanticNodedClientError::Failed { error, .. } if error.code == SemanticErrorCode::Busy => {
            Ok(NodeCommandResult::Busy)
        }
        SemanticNodedClientError::Failed { error, .. }
            if matches!(
                error.code,
                SemanticErrorCode::CatConfigurationConflict | SemanticErrorCode::ActionCancelled
            ) =>
        {
            Ok(NodeCommandResult::Conflict {
                code: semantic_error_code(error.code).to_owned(),
                message: error.message,
            })
        }
        SemanticNodedClientError::Failed { error, .. } => Ok(NodeCommandResult::Failed {
            code: semantic_error_code(error.code).to_owned(),
            message: error.message,
        }),
        error => Err(map_transport_error(error)),
    }
}

fn map_transport_error(error: SemanticNodedClientError) -> NodeClientError {
    match error {
        SemanticNodedClientError::Timeout => NodeClientError::Timeout,
        SemanticNodedClientError::Unavailable { message } => NodeClientError::Unavailable(message),
        SemanticNodedClientError::Protocol { message } => NodeClientError::Protocol(message),
        SemanticNodedClientError::Failed { error, .. } => NodeClientError::Protocol(format!(
            "unexpected product error {}: {}",
            semantic_error_code(error.code),
            error.message
        )),
    }
}

fn wire_endpoint(endpoint: &NodeControlEndpoint) -> Result<NodedControlEndpoint, NodeClientError> {
    NodedControlEndpoint::new(endpoint.as_str().to_owned()).ok_or_else(|| {
        NodeClientError::Protocol("stored noded control endpoint is invalid".to_owned())
    })
}

fn wire_id(value: &str, label: &str) -> Result<Id, NodeClientError> {
    Id::new(value.to_owned())
        .ok_or_else(|| NodeClientError::Protocol(format!("stored {label} identity is invalid")))
}

fn core_config_to_wire(
    workspace_id: &str,
    config: &CatCreateConfig,
) -> Result<NodedCatConfig, NodeClientError> {
    let mounts = config
        .mounts
        .iter()
        .map(|mount| {
            Ok(NodedDiskMount {
                disk_id: wire_id(&mount.disk_id, "disk")?,
                volume_id: wire_id(&mount.volume_id, "volume")?,
                filesystem_uuid: RandomId128::new(mount.filesystem_uuid.clone()).ok_or_else(
                    || NodeClientError::Protocol("stored filesystem UUID is invalid".to_owned()),
                )?,
                format: match mount.disk_format.as_str() {
                    "ext4" => PersistentDiskFormat::Ext4,
                    _ => {
                        return Err(NodeClientError::Protocol(
                            "stored PersistentDisk format is invalid".to_owned(),
                        ));
                    }
                },
                mount_path: PersistentMountPath::new(mount.mount_path.clone()).ok_or_else(
                    || NodeClientError::Protocol("stored mount path is invalid".to_owned()),
                )?,
            })
        })
        .collect::<Result<Vec<_>, NodeClientError>>()?;
    Ok(NodedCatConfig {
        workspace_id: wire_id(workspace_id, "Workspace")?,
        cpu: config.cpu_count,
        memory_bytes: config.memory_bytes,
        boot_image: config.boot_image.clone(),
        mounts,
    })
}

fn semantic_error_code(code: SemanticErrorCode) -> &'static str {
    match code {
        SemanticErrorCode::Unauthorized => "unauthorized",
        SemanticErrorCode::InvalidRequest => "invalid_request",
        SemanticErrorCode::CatNotFound => "cat_not_found",
        SemanticErrorCode::CatConfigurationConflict => "cat_configuration_conflict",
        SemanticErrorCode::CatDestroyed => "cat_destroyed",
        SemanticErrorCode::InvalidState => "invalid_state",
        SemanticErrorCode::Busy => "busy",
        SemanticErrorCode::NodeUnavailable => "node_unavailable",
        SemanticErrorCode::NodeResetRequired => "node_reset_required",
        SemanticErrorCode::NodeIdentityConflict => "node_identity_conflict",
        SemanticErrorCode::DiskNotFound => "disk_not_found",
        SemanticErrorCode::DiskSizeConflict => "disk_size_conflict",
        SemanticErrorCode::DiskDeleted => "disk_deleted",
        SemanticErrorCode::DiskInUse => "disk_in_use",
        SemanticErrorCode::DiskAlreadyAttached => "disk_already_attached",
        SemanticErrorCode::DiskBindingConflict => "disk_binding_conflict",
        SemanticErrorCode::MountPathConflict => "mount_path_conflict",
        SemanticErrorCode::CatMustBeCold => "cat_must_be_cold",
        SemanticErrorCode::GuestStartFailed => "guest_start_failed",
        SemanticErrorCode::GuestSuspendFailed => "guest_suspend_failed",
        SemanticErrorCode::GuestWarmFailed => "guest_warm_failed",
        SemanticErrorCode::GuestColdFailed => "guest_cold_failed",
        SemanticErrorCode::DestroyFailed => "destroy_failed",
        SemanticErrorCode::ActionCancelled => "action_cancelled",
        SemanticErrorCode::Timeout => "timeout",
        SemanticErrorCode::InternalError => "internal_error",
    }
}

const fn core_action_to_stored(action: CatAction) -> StoredCatAction {
    match action {
        CatAction::Create => StoredCatAction::Create,
        CatAction::Run => StoredCatAction::Run,
        CatAction::Suspend => StoredCatAction::Suspend,
        CatAction::Warm => StoredCatAction::Warm,
        CatAction::Cold => StoredCatAction::Cold,
        CatAction::Destroy => StoredCatAction::Destroy,
    }
}

const fn stored_action_to_core(action: StoredCatAction) -> CatAction {
    match action {
        StoredCatAction::Create => CatAction::Create,
        StoredCatAction::Run => CatAction::Run,
        StoredCatAction::Suspend => CatAction::Suspend,
        StoredCatAction::Warm => CatAction::Warm,
        StoredCatAction::Cold => CatAction::Cold,
        StoredCatAction::Destroy => CatAction::Destroy,
    }
}

const fn core_state_to_stored(state: CatState) -> StoredCatState {
    match state {
        CatState::Running => StoredCatState::Running,
        CatState::Suspended => StoredCatState::Suspended,
        CatState::Warm => StoredCatState::Warm,
        CatState::Cold => StoredCatState::Cold,
        CatState::Failure => StoredCatState::Failure,
        CatState::Destroyed => StoredCatState::Destroyed,
    }
}

const fn stored_state_to_core(state: StoredCatState) -> CatState {
    match state {
        StoredCatState::Running => CatState::Running,
        StoredCatState::Suspended => CatState::Suspended,
        StoredCatState::Warm => CatState::Warm,
        StoredCatState::Cold => CatState::Cold,
        StoredCatState::Failure => CatState::Failure,
        StoredCatState::Destroyed => CatState::Destroyed,
    }
}

const fn core_action_to_wire(action: CatAction) -> WireCatAction {
    match action {
        CatAction::Create => WireCatAction::Create,
        CatAction::Run => WireCatAction::Run,
        CatAction::Suspend => WireCatAction::Suspend,
        CatAction::Warm => WireCatAction::Warm,
        CatAction::Cold => WireCatAction::Cold,
        CatAction::Destroy => WireCatAction::Destroy,
    }
}

const fn wire_action_to_core(action: WireCatAction) -> CatAction {
    match action {
        WireCatAction::Create => CatAction::Create,
        WireCatAction::Run => CatAction::Run,
        WireCatAction::Suspend => CatAction::Suspend,
        WireCatAction::Warm => CatAction::Warm,
        WireCatAction::Cold => CatAction::Cold,
        WireCatAction::Destroy => CatAction::Destroy,
    }
}

const fn wire_state_to_core(state: WireCatState) -> CatState {
    match state {
        WireCatState::Running => CatState::Running,
        WireCatState::Suspended => CatState::Suspended,
        WireCatState::Warm => CatState::Warm,
        WireCatState::Cold => CatState::Cold,
        WireCatState::Failure => CatState::Failure,
        WireCatState::Destroyed => CatState::Destroyed,
    }
}

const fn wire_node_status_to_stored(status: WireNodeStatus) -> StoredNodeStatus {
    match status {
        WireNodeStatus::Running => StoredNodeStatus::Running,
        WireNodeStatus::Draining => StoredNodeStatus::Draining,
        WireNodeStatus::Offline => StoredNodeStatus::Offline,
        WireNodeStatus::ResetRequired => StoredNodeStatus::ResetRequired,
        WireNodeStatus::Deleted => StoredNodeStatus::Deleted,
    }
}

const fn stored_node_status_to_wire(status: StoredNodeStatus) -> WireNodeStatus {
    match status {
        StoredNodeStatus::Running => WireNodeStatus::Running,
        StoredNodeStatus::Draining => WireNodeStatus::Draining,
        StoredNodeStatus::Offline => WireNodeStatus::Offline,
        StoredNodeStatus::ResetRequired => WireNodeStatus::ResetRequired,
        StoredNodeStatus::Deleted => WireNodeStatus::Deleted,
    }
}

#[cfg(test)]
mod tests {
    use cats_api::semantic_control::SemanticErrorBody;

    use super::*;

    fn stored_cat(state: Option<StoredCatState>, action: Option<StoredCatAction>) -> CatWithMounts {
        CatWithMounts {
            cat: StoredCatRecord {
                cat_id: "cat_01".to_owned(),
                workspace_id: "ws_01".to_owned(),
                cat_slug: "web".to_owned(),
                state,
                current_action: action,
                current_action_started_at: action.map(|_| 1),
                current_action_node_id: action.map(|_| "node_01".to_owned()),
                node_id: state
                    .is_some_and(|state| {
                        matches!(
                            state,
                            StoredCatState::Running
                                | StoredCatState::Suspended
                                | StoredCatState::Warm
                        )
                    })
                    .then(|| "node_01".to_owned()),
                cpu_count: 2,
                memory_bytes: 4096,
                boot_image: "image".to_owned(),
                last_error_code: None,
                last_error_message: None,
                created_at: 1,
                updated_at: 1,
                destroyed_at: None,
            },
            mounts: vec![crate::store::semantic::CatMountRecord {
                disk_id: "disk_01".to_owned(),
                disk_slug: "data".to_owned(),
                volume_id: "vol_01".to_owned(),
                filesystem_uuid: "11111111111111111111111111111111".to_owned(),
                disk_format: "ext4".to_owned(),
                mount_path: "/data".to_owned(),
            }],
        }
    }

    #[test]
    fn store_outcomes_preserve_claim_node_and_resolved_disk_identity() {
        let admission = map_create_admission(AdmitCatCreateOutcome::Created(stored_cat(
            None,
            Some(StoredCatAction::Create),
        )))
        .unwrap();
        let Admission::Claimed(claim) = admission else {
            panic!("expected claimed create")
        };
        assert_eq!(claim.node_id.as_deref(), Some("node_01"));
        assert_eq!(claim.cat.config.mounts[0].disk_id, "disk_01");
        assert_eq!(claim.cat.config.mounts[0].mount_path, "/data");
    }

    #[test]
    fn repeated_and_invalid_actions_map_to_product_admissions() {
        let already = map_action_admission(
            AdmitCatActionOutcome::AlreadyDone(stored_cat(Some(StoredCatState::Running), None)),
            CatAction::Run,
        )
        .unwrap();
        assert!(matches!(
            already,
            Admission::Already {
                code: "already_running",
                ..
            }
        ));

        let invalid = map_action_admission(
            AdmitCatActionOutcome::InvalidState(stored_cat(Some(StoredCatState::Cold), None)),
            CatAction::Suspend,
        )
        .unwrap();
        assert!(matches!(invalid, Admission::InvalidState(_)));
    }

    #[tokio::test]
    async fn production_ingress_placeholder_fails_closed() {
        let ingress = UnavailableIngressPort;
        assert!(ingress.withdraw("cat_01", "node_01").await.is_err());
        assert!(ingress.publish("cat_01", "node_02").await.is_err());
    }

    #[test]
    fn semantic_ingress_adapter_preserves_scenario_outcomes() {
        let target = CatIngressTargetRecord {
            cat_id: "cat_01".to_owned(),
            node_id: "node_01".to_owned(),
            updated_at: 1,
        };
        assert!(
            map_publish_ingress_outcome(PublishCatIngressOutcome::Published(target.clone()))
                .is_ok()
        );
        assert!(
            map_publish_ingress_outcome(PublishCatIngressOutcome::AlreadyPublished(target.clone()))
                .is_ok()
        );
        assert!(
            map_publish_ingress_outcome(PublishCatIngressOutcome::Conflict(target.clone()))
                .is_err()
        );
        assert!(map_withdraw_ingress_outcome(WithdrawCatIngressOutcome::Withdrawn).is_ok());
        assert!(map_withdraw_ingress_outcome(WithdrawCatIngressOutcome::AlreadyWithdrawn).is_ok());
        assert!(
            map_withdraw_ingress_outcome(WithdrawCatIngressOutcome::Conflict(target.clone()))
                .is_err()
        );
        assert!(
            map_withdraw_ingress_outcome(WithdrawCatIngressOutcome::CatNotWithdrawing).is_err()
        );

        let wire = wire_ingress_target(target).unwrap();
        assert_eq!(wire.cat_id.as_str(), "cat_01");
        assert_eq!(wire.node_id.as_str(), "node_01");
    }

    #[test]
    fn noded_product_errors_remain_product_results() {
        let busy = map_noded_execute_error(
            SemanticNodedClientError::Failed {
                http_status: Some(409),
                error: SemanticErrorBody {
                    code: SemanticErrorCode::Busy,
                    message: "working".to_owned(),
                },
            },
            CatAction::Run,
        )
        .unwrap();
        assert_eq!(busy, NodeCommandResult::Busy);

        let absent_destroy = map_noded_execute_error(
            SemanticNodedClientError::Failed {
                http_status: Some(404),
                error: SemanticErrorBody {
                    code: SemanticErrorCode::CatNotFound,
                    message: "gone".to_owned(),
                },
            },
            CatAction::Destroy,
        )
        .unwrap();
        assert_eq!(
            absent_destroy,
            NodeCommandResult::AlreadyDone(CatState::Destroyed)
        );
    }
}

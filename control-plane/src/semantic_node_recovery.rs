//! Cross-Node recovery after the source Node has been marked offline by the
//! exact heartbeat compare-and-set.
//!
//! This deliberately accepts a bounded physical double-run window. Unique
//! ingress is withdrawn before placement changes, while a returning old Node
//! receives `reset_required` through the heartbeat path and removes residue.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use cats_api::error::ApiError;

use crate::semantic_lifecycle::{
    CatAction, CatCreateConfig, CatMount, CatRecord, CatState, IngressPort, NodeCatStatus,
    NodeClientError, NodeCommand, NodeCommandResult, NodeControlEndpoint, NodedClient, StoreError,
};
use crate::store::semantic::{
    CatState as StoredCatState, CatWithMounts, ClaimSemanticCatRecoveryOutcome,
    SemanticCatRecoveryClaim as StoredRecoveryClaim, SemanticCatRecoveryResult,
    SemanticCatRecoverySettlement,
};
use crate::store::Store;

pub type RecoveryFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCandidate {
    pub cat_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryClaim {
    pub cat: CatRecord,
    pub source_node_id: String,
    pub target_node_id: String,
    pub target_state: CatState,
    pub started_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAdmission {
    Claimed(RecoveryClaim),
    AlreadyClaimed(RecoveryClaim),
    ColdNoAction(CatRecord),
    UnsupportedState(CatRecord),
    NoRunningTarget(CatRecord),
    Busy(CatRecord),
    SourceNotOffline,
    SourceNotDraining,
    Stale,
}

pub trait SemanticNodeRecoveryStore: Send + Sync {
    fn list_source_cats<'a>(
        &'a self,
        source_node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<Vec<RecoveryCandidate>, StoreError>>;

    fn list_drain_source_cats<'a>(
        &'a self,
        source_node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<Vec<RecoveryCandidate>, StoreError>> {
        self.list_source_cats(source_node_id)
    }

    fn claim<'a>(
        &'a self,
        source_node_id: &'a str,
        cat_id: &'a str,
    ) -> RecoveryFuture<'a, Result<RecoveryAdmission, StoreError>>;

    fn claim_drain<'a>(
        &'a self,
        source_node_id: &'a str,
        cat_id: &'a str,
    ) -> RecoveryFuture<'a, Result<RecoveryAdmission, StoreError>> {
        self.claim(source_node_id, cat_id)
    }

    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<NodeControlEndpoint, StoreError>>;

    fn draining_node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<NodeControlEndpoint, StoreError>> {
        self.node_control_endpoint(node_id)
    }

    fn finish<'a>(
        &'a self,
        claim: &'a RecoveryClaim,
        result: RecoveryFinish<'a>,
    ) -> RecoveryFuture<'a, Result<Option<CatRecord>, StoreError>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFinish<'a> {
    Recovered,
    RetrySource { code: &'a str, message: &'a str },
    Failed { code: &'a str, message: &'a str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryTimeouts {
    pub node_request: Duration,
    pub retry_count: usize,
    pub retry_interval: Duration,
}

impl Default for RecoveryTimeouts {
    fn default() -> Self {
        Self {
            node_request: Duration::from_secs(30),
            retry_count: 2,
            retry_interval: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatRecoveryStatus {
    Recovered {
        target_node_id: String,
        state: CatState,
    },
    ColdNoAction,
    Stale,
    Failed {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatRecoveryResult {
    pub cat_id: String,
    pub status: CatRecoveryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecoveryReport {
    pub source_node_id: String,
    pub cats: Vec<CatRecoveryResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatDrainStatus {
    Migrated {
        target_node_id: String,
        state: CatState,
    },
    Stale,
    Blocked {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatDrainResult {
    pub cat_id: String,
    pub status: CatDrainStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDrainReport {
    pub source_node_id: String,
    pub cats: Vec<CatDrainResult>,
}

impl NodeDrainReport {
    pub fn is_drained(&self) -> bool {
        self.cats
            .iter()
            .all(|cat| !matches!(cat.status, CatDrainStatus::Blocked { .. }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecoveryError {
    pub message: String,
}

impl From<StoreError> for NodeRecoveryError {
    fn from(error: StoreError) -> Self {
        Self {
            message: error.message,
        }
    }
}

pub struct SemanticNodeRecoveryService<S, N, I> {
    store: S,
    noded: N,
    ingress: I,
    timeouts: RecoveryTimeouts,
}

impl<S, N, I> SemanticNodeRecoveryService<S, N, I>
where
    S: SemanticNodeRecoveryStore,
    N: NodedClient,
    I: IngressPort,
{
    pub fn new(store: S, noded: N, ingress: I, timeouts: RecoveryTimeouts) -> Self {
        Self {
            store,
            noded,
            ingress,
            timeouts,
        }
    }

    pub async fn recover_offline_node(
        &self,
        source_node_id: &str,
    ) -> Result<NodeRecoveryReport, NodeRecoveryError> {
        let candidates = self.store.list_source_cats(source_node_id).await?;
        let mut results = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            results.push(self.recover_cat(source_node_id, candidate).await?);
        }
        Ok(NodeRecoveryReport {
            source_node_id: source_node_id.to_owned(),
            cats: results,
        })
    }

    /// Performs a planned, retryable drain. The Store keeps each Cat's source
    /// placement and original stable state while reserving the target. This
    /// lets a later request resume after a Control restart without a separate
    /// lifecycle Operation or a process-local drain plan.
    pub async fn drain_node(
        &self,
        source_node_id: &str,
    ) -> Result<NodeDrainReport, NodeRecoveryError> {
        let candidates = self.store.list_drain_source_cats(source_node_id).await?;
        let mut results = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            results.push(self.drain_cat(source_node_id, candidate).await?);
        }
        Ok(NodeDrainReport {
            source_node_id: source_node_id.to_owned(),
            cats: results,
        })
    }

    async fn drain_cat(
        &self,
        source_node_id: &str,
        candidate: RecoveryCandidate,
    ) -> Result<CatDrainResult, NodeRecoveryError> {
        let claim = match self
            .store
            .claim_drain(source_node_id, &candidate.cat_id)
            .await?
        {
            RecoveryAdmission::Claimed(claim) | RecoveryAdmission::AlreadyClaimed(claim) => claim,
            RecoveryAdmission::UnsupportedState(_) => {
                return Ok(blocked_drain_cat(
                    &candidate.cat_id,
                    "drain_state_unsupported",
                    "only running, suspended, or warm Cats can be drained".to_owned(),
                ));
            }
            RecoveryAdmission::NoRunningTarget(_) => {
                return Ok(blocked_drain_cat(
                    &candidate.cat_id,
                    "node_unavailable",
                    "no other running Node accepts drain placement".to_owned(),
                ));
            }
            RecoveryAdmission::Busy(_) => {
                return Ok(blocked_drain_cat(
                    &candidate.cat_id,
                    "busy",
                    "Cat has another lifecycle action in progress".to_owned(),
                ));
            }
            RecoveryAdmission::SourceNotDraining => {
                return Ok(blocked_drain_cat(
                    &candidate.cat_id,
                    "source_node_not_draining",
                    "source Node is no longer draining".to_owned(),
                ));
            }
            RecoveryAdmission::Stale | RecoveryAdmission::ColdNoAction(_) => {
                return Ok(CatDrainResult {
                    cat_id: candidate.cat_id,
                    status: CatDrainStatus::Stale,
                });
            }
            RecoveryAdmission::SourceNotOffline => {
                return Ok(blocked_drain_cat(
                    &candidate.cat_id,
                    "source_node_not_draining",
                    "source Node is not draining".to_owned(),
                ));
            }
        };

        // Claim first: the ingress Store permits a planned move only after
        // the exact cross-Node run reservation is durable.
        if let Err(error) = self
            .ingress
            .withdraw(&candidate.cat_id, source_node_id)
            .await
        {
            return Ok(blocked_drain_cat(
                &candidate.cat_id,
                "ingress_withdraw_failed",
                error.message,
            ));
        }

        if let Err(failure) = self.make_source_cold(&claim).await {
            // The source has not crossed the Cold data-safety barrier. Keep
            // its original product state and placement, but release the exact
            // unused target reservation. No target effect starts before this
            // barrier, so a later pass can safely choose a currently running
            // target after the source is repaired. This also prevents the old
            // target's own drain from being pinned by a retryable source.
            let settled = self
                .store
                .finish(
                    &claim,
                    RecoveryFinish::RetrySource {
                        code: &failure.code,
                        message: &failure.message,
                    },
                )
                .await?;
            if settled.is_none() {
                return Err(NodeRecoveryError {
                    message: "blocked source Cold claim is no longer current".to_owned(),
                });
            }
            return Ok(blocked_drain_cat(
                &candidate.cat_id,
                &failure.code,
                failure.message,
            ));
        }

        match self.drive(&claim).await {
            Ok(()) => {
                let settled = self.store.finish(&claim, RecoveryFinish::Recovered).await?;
                if settled.is_none() {
                    return Err(NodeRecoveryError {
                        message: "semantic Cat drain claim is no longer current".to_owned(),
                    });
                }
                Ok(CatDrainResult {
                    cat_id: candidate.cat_id,
                    status: CatDrainStatus::Migrated {
                        target_node_id: claim.target_node_id,
                        state: claim.target_state,
                    },
                })
            }
            Err(failure) => {
                if failure.class == RecoveryFailureClass::Retryable {
                    return Ok(blocked_drain_cat(
                        &candidate.cat_id,
                        &failure.code,
                        failure.message,
                    ));
                }
                let settled = self
                    .store
                    .finish(
                        &claim,
                        RecoveryFinish::Failed {
                            code: &failure.code,
                            message: &failure.message,
                        },
                    )
                    .await?;
                if settled.is_none() {
                    return Err(NodeRecoveryError {
                        message: "failed target drain claim is no longer current".to_owned(),
                    });
                }
                Ok(blocked_drain_cat(
                    &candidate.cat_id,
                    &failure.code,
                    failure.message,
                ))
            }
        }
    }

    async fn recover_cat(
        &self,
        source_node_id: &str,
        candidate: RecoveryCandidate,
    ) -> Result<CatRecoveryResult, NodeRecoveryError> {
        if let Err(error) = self
            .ingress
            .withdraw(&candidate.cat_id, source_node_id)
            .await
        {
            return Ok(failed_cat(
                &candidate.cat_id,
                "ingress_withdraw_failed",
                error.message,
            ));
        }

        let claim = match self.store.claim(source_node_id, &candidate.cat_id).await? {
            RecoveryAdmission::Claimed(claim) | RecoveryAdmission::AlreadyClaimed(claim) => claim,
            RecoveryAdmission::ColdNoAction(_) => {
                return Ok(CatRecoveryResult {
                    cat_id: candidate.cat_id,
                    status: CatRecoveryStatus::ColdNoAction,
                });
            }
            RecoveryAdmission::UnsupportedState(_) => {
                return Ok(failed_cat(
                    &candidate.cat_id,
                    "recovery_state_unsupported",
                    "Cat state has no strict cross-Node recovery transition".to_owned(),
                ));
            }
            RecoveryAdmission::NoRunningTarget(_) => {
                return Ok(failed_cat(
                    &candidate.cat_id,
                    "node_unavailable",
                    "no other running Node accepts recovery placement".to_owned(),
                ));
            }
            RecoveryAdmission::Busy(_) => {
                return Ok(failed_cat(
                    &candidate.cat_id,
                    "busy",
                    "Cat has another lifecycle action in progress".to_owned(),
                ));
            }
            RecoveryAdmission::SourceNotOffline => {
                return Ok(failed_cat(
                    &candidate.cat_id,
                    "source_node_not_offline",
                    "source Node is no longer offline/reset_required".to_owned(),
                ));
            }
            RecoveryAdmission::SourceNotDraining => {
                return Ok(failed_cat(
                    &candidate.cat_id,
                    "source_node_not_draining",
                    "source Node is not draining".to_owned(),
                ));
            }
            RecoveryAdmission::Stale => {
                return Ok(CatRecoveryResult {
                    cat_id: candidate.cat_id,
                    status: CatRecoveryStatus::Stale,
                });
            }
        };

        match self.drive(&claim).await {
            Ok(()) => {
                let settled = self.store.finish(&claim, RecoveryFinish::Recovered).await?;
                if settled.is_none() {
                    return Err(NodeRecoveryError {
                        message: "semantic Cat recovery claim is no longer current".to_owned(),
                    });
                }
                Ok(CatRecoveryResult {
                    cat_id: candidate.cat_id,
                    status: CatRecoveryStatus::Recovered {
                        target_node_id: claim.target_node_id,
                        state: claim.target_state,
                    },
                })
            }
            Err(failure) => {
                let settled = self
                    .store
                    .finish(
                        &claim,
                        RecoveryFinish::Failed {
                            code: &failure.code,
                            message: &failure.message,
                        },
                    )
                    .await?;
                if settled.is_none() {
                    return Err(NodeRecoveryError {
                        message: "failed semantic Cat recovery claim is no longer current"
                            .to_owned(),
                    });
                }
                Ok(failed_cat(
                    &candidate.cat_id,
                    &failure.code,
                    failure.message,
                ))
            }
        }
    }

    async fn make_source_cold(&self, claim: &RecoveryClaim) -> Result<(), RecoveryFailure> {
        let command = NodeCommand {
            cat_id: claim.cat.cat_id.clone(),
            workspace_id: claim.cat.workspace_id.clone(),
            action: CatAction::Cold,
            config: None,
        };
        let mut last_transport = "source noded Cold request timed out".to_owned();
        for attempt in 0..=self.timeouts.retry_count {
            let endpoint = self.draining_endpoint(claim).await?;
            if self
                .inspect_expected(&endpoint, claim, CatState::Cold)
                .await?
            {
                return Ok(());
            }
            let executed = tokio::time::timeout(
                self.timeouts.node_request,
                self.noded.execute(&endpoint, &command),
            )
            .await;
            match executed {
                Ok(Ok(
                    NodeCommandResult::Succeeded(CatState::Cold)
                    | NodeCommandResult::AlreadyDone(CatState::Cold),
                )) => return Ok(()),
                Ok(Ok(NodeCommandResult::Succeeded(_) | NodeCommandResult::AlreadyDone(_))) => {
                    return Err(RecoveryFailure::retryable(
                        "node_protocol_error",
                        "source noded returned success without reaching Cold",
                    ));
                }
                Ok(Ok(
                    NodeCommandResult::Failed { code, message }
                    | NodeCommandResult::Conflict { code, message },
                )) => return Err(RecoveryFailure::definitive(code, message)),
                Ok(Ok(NodeCommandResult::Busy)) => {
                    last_transport = "source noded remained busy during drain".to_owned();
                }
                Ok(Err(NodeClientError::Protocol(message))) => {
                    return Err(RecoveryFailure::retryable("node_protocol_error", message));
                }
                Ok(Err(NodeClientError::Unavailable(message))) => last_transport = message,
                Ok(Err(NodeClientError::Timeout)) | Err(_) => {}
            }
            if self
                .inspect_expected(&endpoint, claim, CatState::Cold)
                .await?
            {
                return Ok(());
            }
            if attempt < self.timeouts.retry_count {
                tokio::time::sleep(self.timeouts.retry_interval).await;
            }
        }
        Err(RecoveryFailure::retryable(
            "drain_source_timeout",
            last_transport,
        ))
    }

    async fn drive(&self, claim: &RecoveryClaim) -> Result<(), RecoveryFailure> {
        // A Control restart after physical completion can settle directly.
        if self.target_is_complete(claim).await? {
            if claim.target_state == CatState::Running {
                self.publish(claim).await?;
            }
            return Ok(());
        }

        self.execute_to_state(
            claim,
            NodeCommand {
                cat_id: claim.cat.cat_id.clone(),
                workspace_id: claim.cat.workspace_id.clone(),
                action: CatAction::Run,
                config: Some(claim.cat.config.clone()),
            },
            CatState::Running,
        )
        .await?;

        match claim.target_state {
            CatState::Running => self.publish(claim).await?,
            CatState::Suspended => {
                self.execute_to_state(
                    claim,
                    NodeCommand {
                        cat_id: claim.cat.cat_id.clone(),
                        workspace_id: claim.cat.workspace_id.clone(),
                        action: CatAction::Suspend,
                        config: None,
                    },
                    CatState::Suspended,
                )
                .await?;
            }
            CatState::Warm => {
                self.execute_to_state(
                    claim,
                    NodeCommand {
                        cat_id: claim.cat.cat_id.clone(),
                        workspace_id: claim.cat.workspace_id.clone(),
                        action: CatAction::Warm,
                        config: None,
                    },
                    CatState::Warm,
                )
                .await?;
            }
            CatState::Cold | CatState::Failure | CatState::Destroyed => {
                return Err(RecoveryFailure::definitive(
                    "recovery_state_unsupported",
                    "recovery claim has an unsupported target state",
                ));
            }
        }
        Ok(())
    }

    async fn publish(&self, claim: &RecoveryClaim) -> Result<(), RecoveryFailure> {
        self.ingress
            .publish(&claim.cat.cat_id, &claim.target_node_id)
            .await
            .map_err(|error| RecoveryFailure::retryable("ingress_publish_failed", error.message))
    }

    async fn target_is_complete(&self, claim: &RecoveryClaim) -> Result<bool, RecoveryFailure> {
        let endpoint = self.endpoint(claim).await?;
        let inspected = tokio::time::timeout(
            self.timeouts.node_request,
            self.noded.inspect(&endpoint, &claim.cat.cat_id),
        )
        .await;
        match inspected {
            Ok(Ok(NodeCatStatus::Present {
                state: Some(state),
                active_action: None,
            })) => Ok(state == claim.target_state),
            Ok(Ok(NodeCatStatus::Failed { code, message })) => {
                Err(RecoveryFailure::definitive(code, message))
            }
            Ok(Err(NodeClientError::Protocol(message))) => {
                Err(RecoveryFailure::retryable("node_protocol_error", message))
            }
            Ok(Ok(NodeCatStatus::Absent | NodeCatStatus::Present { .. }))
            | Ok(Err(NodeClientError::Timeout | NodeClientError::Unavailable(_)))
            | Err(_) => Ok(false),
        }
    }

    async fn execute_to_state(
        &self,
        claim: &RecoveryClaim,
        command: NodeCommand,
        expected: CatState,
    ) -> Result<(), RecoveryFailure> {
        let mut last_transport = "noded recovery request timed out".to_owned();
        for attempt in 0..=self.timeouts.retry_count {
            let endpoint = self.endpoint(claim).await?;
            let executed = tokio::time::timeout(
                self.timeouts.node_request,
                self.noded.execute(&endpoint, &command),
            )
            .await;
            match executed {
                Ok(Ok(
                    NodeCommandResult::Succeeded(state) | NodeCommandResult::AlreadyDone(state),
                )) if state == expected => {
                    return Ok(());
                }
                Ok(Ok(NodeCommandResult::Succeeded(_) | NodeCommandResult::AlreadyDone(_))) => {
                    return Err(RecoveryFailure::retryable(
                        "node_protocol_error",
                        "noded returned success without the requested recovery state",
                    ));
                }
                Ok(Ok(
                    NodeCommandResult::Failed { code, message }
                    | NodeCommandResult::Conflict { code, message },
                )) => return Err(RecoveryFailure::definitive(code, message)),
                Ok(Ok(NodeCommandResult::Busy)) => {
                    last_transport = "noded remained busy during recovery".to_owned();
                }
                Ok(Err(NodeClientError::Protocol(message))) => {
                    return Err(RecoveryFailure::retryable("node_protocol_error", message));
                }
                Ok(Err(NodeClientError::Unavailable(message))) => last_transport = message,
                Ok(Err(NodeClientError::Timeout)) | Err(_) => {}
            }

            if self.inspect_expected(&endpoint, claim, expected).await? {
                return Ok(());
            }
            if attempt < self.timeouts.retry_count {
                tokio::time::sleep(self.timeouts.retry_interval).await;
            }
        }
        Err(RecoveryFailure::retryable(
            "recovery_timeout",
            last_transport,
        ))
    }

    async fn inspect_expected(
        &self,
        endpoint: &NodeControlEndpoint,
        claim: &RecoveryClaim,
        expected: CatState,
    ) -> Result<bool, RecoveryFailure> {
        match tokio::time::timeout(
            self.timeouts.node_request,
            self.noded.inspect(endpoint, &claim.cat.cat_id),
        )
        .await
        {
            Ok(Ok(NodeCatStatus::Present {
                state: Some(state),
                active_action: None,
            })) => Ok(state == expected),
            Ok(Ok(NodeCatStatus::Failed { code, message })) => {
                Err(RecoveryFailure::definitive(code, message))
            }
            Ok(Err(NodeClientError::Protocol(message))) => {
                Err(RecoveryFailure::retryable("node_protocol_error", message))
            }
            Ok(Ok(NodeCatStatus::Absent | NodeCatStatus::Present { .. }))
            | Ok(Err(NodeClientError::Timeout | NodeClientError::Unavailable(_)))
            | Err(_) => Ok(false),
        }
    }

    async fn endpoint(
        &self,
        claim: &RecoveryClaim,
    ) -> Result<NodeControlEndpoint, RecoveryFailure> {
        self.store
            .node_control_endpoint(&claim.target_node_id)
            .await
            .map_err(|error| RecoveryFailure::retryable("node_unavailable", error.message))
    }

    async fn draining_endpoint(
        &self,
        claim: &RecoveryClaim,
    ) -> Result<NodeControlEndpoint, RecoveryFailure> {
        self.store
            .draining_node_control_endpoint(&claim.source_node_id)
            .await
            .map_err(|error| RecoveryFailure::retryable("source_node_not_draining", error.message))
    }
}

fn failed_cat(cat_id: &str, code: &str, message: String) -> CatRecoveryResult {
    CatRecoveryResult {
        cat_id: cat_id.to_owned(),
        status: CatRecoveryStatus::Failed {
            code: code.to_owned(),
            message,
        },
    }
}

fn blocked_drain_cat(cat_id: &str, code: &str, message: String) -> CatDrainResult {
    CatDrainResult {
        cat_id: cat_id.to_owned(),
        status: CatDrainStatus::Blocked {
            code: code.to_owned(),
            message,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveryFailure {
    code: String,
    message: String,
    class: RecoveryFailureClass,
}

impl RecoveryFailure {
    fn definitive(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            class: RecoveryFailureClass::Definitive,
        }
    }

    fn retryable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            class: RecoveryFailureClass::Retryable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryFailureClass {
    Definitive,
    Retryable,
}

/// PostgreSQL adapter for the atomic recovery methods. It deliberately uses
/// the same bounded Store executor as ordinary semantic lifecycle work.
#[derive(Clone)]
pub struct PostgresSemanticNodeRecoveryStore {
    store: Arc<Store>,
}

impl PostgresSemanticNodeRecoveryStore {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    fn finish_owned<'a>(
        &'a self,
        claim: &'a RecoveryClaim,
        owned_result: OwnedRecoveryFinish,
    ) -> RecoveryFuture<'a, Result<Option<CatRecord>, StoreError>> {
        let store = Arc::clone(&self.store);
        let claim = claim.clone();
        Box::pin(async move {
            store
                .execute(move |store| {
                    let result = match &owned_result {
                        OwnedRecoveryFinish::Recovered => SemanticCatRecoveryResult::Recovered,
                        OwnedRecoveryFinish::RetrySource { code, message } => {
                            SemanticCatRecoveryResult::RetrySource { code, message }
                        }
                        OwnedRecoveryFinish::Failed { code, message } => {
                            SemanticCatRecoveryResult::Failed { code, message }
                        }
                    };
                    store
                        .finish_semantic_cat_recovery(
                            SemanticCatRecoverySettlement {
                                cat_id: &claim.cat.cat_id,
                                source_node_id: &claim.source_node_id,
                                target_node_id: &claim.target_node_id,
                                target_state: core_state_to_stored(claim.target_state),
                                expected_action_started_at: claim.started_at_unix_ms,
                            },
                            result,
                        )?
                        .map(stored_cat_to_core)
                        .transpose()
                })
                .await
                .map_err(store_error)
        })
    }
}

impl SemanticNodeRecoveryStore for PostgresSemanticNodeRecoveryStore {
    fn list_source_cats<'a>(
        &'a self,
        source_node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<Vec<RecoveryCandidate>, StoreError>> {
        let store = Arc::clone(&self.store);
        let source_node_id = source_node_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    Ok(store
                        .list_semantic_node_cats(&source_node_id)?
                        .into_iter()
                        .map(|cat| RecoveryCandidate {
                            cat_id: cat.cat.cat_id,
                        })
                        .collect())
                })
                .await
                .map_err(store_error)
        })
    }

    fn list_drain_source_cats<'a>(
        &'a self,
        source_node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<Vec<RecoveryCandidate>, StoreError>> {
        let store = Arc::clone(&self.store);
        let source_node_id = source_node_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    Ok(store
                        .list_semantic_node_drain_cats(&source_node_id)?
                        .into_iter()
                        .map(|cat| RecoveryCandidate {
                            cat_id: cat.cat.cat_id,
                        })
                        .collect())
                })
                .await
                .map_err(store_error)
        })
    }

    fn claim<'a>(
        &'a self,
        source_node_id: &'a str,
        cat_id: &'a str,
    ) -> RecoveryFuture<'a, Result<RecoveryAdmission, StoreError>> {
        let store = Arc::clone(&self.store);
        let source_node_id = source_node_id.to_owned();
        let cat_id = cat_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    map_admission(store.claim_semantic_cat_recovery(&source_node_id, &cat_id)?)
                })
                .await
                .map_err(store_error)
        })
    }

    fn claim_drain<'a>(
        &'a self,
        source_node_id: &'a str,
        cat_id: &'a str,
    ) -> RecoveryFuture<'a, Result<RecoveryAdmission, StoreError>> {
        let store = Arc::clone(&self.store);
        let source_node_id = source_node_id.to_owned();
        let cat_id = cat_id.to_owned();
        Box::pin(async move {
            store
                .execute(move |store| {
                    map_admission(store.claim_semantic_cat_drain(&source_node_id, &cat_id)?)
                })
                .await
                .map_err(store_error)
        })
    }

    fn node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<NodeControlEndpoint, StoreError>> {
        let store = Arc::clone(&self.store);
        let node_id = node_id.to_owned();
        Box::pin(async move {
            let node = store
                .execute(move |store| store.find_semantic_node(&node_id))
                .await
                .map_err(store_error)?
                .ok_or_else(|| StoreError::new("recovery target Node does not exist"))?;
            if !matches!(
                node.status,
                crate::store::semantic::NodeStatus::Running
                    | crate::store::semantic::NodeStatus::Draining
            ) {
                return Err(StoreError::new(
                    "recovery target Node is not running or draining",
                ));
            }
            NodeControlEndpoint::new(node.control_endpoint)
        })
    }

    fn draining_node_control_endpoint<'a>(
        &'a self,
        node_id: &'a str,
    ) -> RecoveryFuture<'a, Result<NodeControlEndpoint, StoreError>> {
        let store = Arc::clone(&self.store);
        let node_id = node_id.to_owned();
        Box::pin(async move {
            let node = store
                .execute(move |store| store.find_semantic_node(&node_id))
                .await
                .map_err(store_error)?
                .ok_or_else(|| StoreError::new("drain source Node does not exist"))?;
            if node.status != crate::store::semantic::NodeStatus::Draining {
                return Err(StoreError::new("drain source Node is not draining"));
            }
            NodeControlEndpoint::new(node.control_endpoint)
        })
    }

    fn finish<'a>(
        &'a self,
        claim: &'a RecoveryClaim,
        result: RecoveryFinish<'a>,
    ) -> RecoveryFuture<'a, Result<Option<CatRecord>, StoreError>> {
        let owned_result = match result {
            RecoveryFinish::Recovered => OwnedRecoveryFinish::Recovered,
            RecoveryFinish::RetrySource { code, message } => OwnedRecoveryFinish::RetrySource {
                code: code.to_owned(),
                message: message.to_owned(),
            },
            RecoveryFinish::Failed { code, message } => OwnedRecoveryFinish::Failed {
                code: code.to_owned(),
                message: message.to_owned(),
            },
        };
        self.finish_owned(claim, owned_result)
    }
}

enum OwnedRecoveryFinish {
    Recovered,
    RetrySource { code: String, message: String },
    Failed { code: String, message: String },
}

fn map_admission(
    outcome: ClaimSemanticCatRecoveryOutcome,
) -> crate::store::Result<RecoveryAdmission> {
    Ok(match outcome {
        ClaimSemanticCatRecoveryOutcome::Claimed(claim) => {
            RecoveryAdmission::Claimed(stored_claim_to_core(claim)?)
        }
        ClaimSemanticCatRecoveryOutcome::AlreadyClaimed(claim) => {
            RecoveryAdmission::AlreadyClaimed(stored_claim_to_core(claim)?)
        }
        ClaimSemanticCatRecoveryOutcome::ColdNoAction(cat) => {
            RecoveryAdmission::ColdNoAction(stored_cat_to_core(cat)?)
        }
        ClaimSemanticCatRecoveryOutcome::UnsupportedState(cat) => {
            RecoveryAdmission::UnsupportedState(stored_cat_to_core(cat)?)
        }
        ClaimSemanticCatRecoveryOutcome::NoRunningTarget(cat) => {
            RecoveryAdmission::NoRunningTarget(stored_cat_to_core(cat)?)
        }
        ClaimSemanticCatRecoveryOutcome::Busy(cat) => {
            RecoveryAdmission::Busy(stored_cat_to_core(cat)?)
        }
        ClaimSemanticCatRecoveryOutcome::SourceNotOffline => RecoveryAdmission::SourceNotOffline,
        ClaimSemanticCatRecoveryOutcome::SourceNotDraining => RecoveryAdmission::SourceNotDraining,
        ClaimSemanticCatRecoveryOutcome::Stale => RecoveryAdmission::Stale,
    })
}

fn stored_claim_to_core(claim: StoredRecoveryClaim) -> crate::store::Result<RecoveryClaim> {
    let started_at_unix_ms =
        claim.cat.cat.current_action_started_at.ok_or_else(|| {
            ApiError::internal("stored recovery claim omitted its action start time")
        })?;
    Ok(RecoveryClaim {
        cat: stored_cat_to_core(claim.cat)?,
        source_node_id: claim.source_node_id,
        target_node_id: claim.target_node_id,
        target_state: stored_state_to_core(claim.target_state),
        started_at_unix_ms,
    })
}

fn stored_cat_to_core(cat: CatWithMounts) -> crate::store::Result<CatRecord> {
    Ok(CatRecord {
        cat_id: cat.cat.cat_id,
        workspace_id: cat.cat.workspace_id,
        cat_slug: cat.cat.cat_slug,
        state: cat.cat.state.map(stored_state_to_core),
        current_action: cat.cat.current_action.map(stored_action_to_core),
        current_action_node_id: cat.cat.current_action_node_id,
        node_id: cat.cat.node_id,
        config: CatCreateConfig {
            cpu_count: u32::try_from(cat.cat.cpu_count)
                .map_err(|_| ApiError::internal("stored recovery Cat CPU is invalid"))?,
            memory_bytes: u64::try_from(cat.cat.memory_bytes)
                .map_err(|_| ApiError::internal("stored recovery Cat memory is invalid"))?,
            boot_image: cat.cat.boot_image,
            mounts: cat
                .mounts
                .into_iter()
                .map(|mount| CatMount {
                    disk_id: mount.disk_id,
                    volume_id: mount.volume_id,
                    filesystem_uuid: mount.filesystem_uuid,
                    disk_format: mount.disk_format,
                    mount_path: mount.mount_path,
                })
                .collect(),
        },
    })
}

fn stored_state_to_core(state: StoredCatState) -> CatState {
    match state {
        StoredCatState::Running => CatState::Running,
        StoredCatState::Suspended => CatState::Suspended,
        StoredCatState::Warm => CatState::Warm,
        StoredCatState::Cold => CatState::Cold,
        StoredCatState::Failure => CatState::Failure,
        StoredCatState::Destroyed => CatState::Destroyed,
    }
}

fn core_state_to_stored(state: CatState) -> StoredCatState {
    match state {
        CatState::Running => StoredCatState::Running,
        CatState::Suspended => StoredCatState::Suspended,
        CatState::Warm => StoredCatState::Warm,
        CatState::Cold => StoredCatState::Cold,
        CatState::Failure => StoredCatState::Failure,
        CatState::Destroyed => StoredCatState::Destroyed,
    }
}

fn stored_action_to_core(action: crate::store::semantic::CatAction) -> CatAction {
    match action {
        crate::store::semantic::CatAction::Create => CatAction::Create,
        crate::store::semantic::CatAction::Run => CatAction::Run,
        crate::store::semantic::CatAction::Suspend => CatAction::Suspend,
        crate::store::semantic::CatAction::Warm => CatAction::Warm,
        crate::store::semantic::CatAction::Cold => CatAction::Cold,
        crate::store::semantic::CatAction::Destroy => CatAction::Destroy,
    }
}

fn store_error(error: ApiError) -> StoreError {
    StoreError::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::semantic_lifecycle::{IngressError, SemanticFuture};

    #[derive(Default)]
    struct Observed {
        events: Vec<String>,
        commands: Vec<NodeCommand>,
        finishes: Vec<OwnedFinish>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum OwnedFinish {
        Recovered,
        RetrySource { code: String, message: String },
        Failed { code: String, message: String },
    }

    #[derive(Clone)]
    struct MockStore {
        observed: Arc<Mutex<Observed>>,
        candidates: Vec<RecoveryCandidate>,
        admissions: Arc<Mutex<VecDeque<RecoveryAdmission>>>,
    }

    impl SemanticNodeRecoveryStore for MockStore {
        fn list_source_cats<'a>(
            &'a self,
            _source_node_id: &'a str,
        ) -> RecoveryFuture<'a, Result<Vec<RecoveryCandidate>, StoreError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push("list_source".to_owned());
                Ok(self.candidates.clone())
            })
        }

        fn list_drain_source_cats<'a>(
            &'a self,
            _source_node_id: &'a str,
        ) -> RecoveryFuture<'a, Result<Vec<RecoveryCandidate>, StoreError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push("list_drain".to_owned());
                Ok(self.candidates.clone())
            })
        }

        fn claim<'a>(
            &'a self,
            _source_node_id: &'a str,
            _cat_id: &'a str,
        ) -> RecoveryFuture<'a, Result<RecoveryAdmission, StoreError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push("claim".to_owned());
                Ok(self
                    .admissions
                    .lock()
                    .expect("admissions")
                    .pop_front()
                    .expect("recovery admission"))
            })
        }

        fn claim_drain<'a>(
            &'a self,
            source_node_id: &'a str,
            cat_id: &'a str,
        ) -> RecoveryFuture<'a, Result<RecoveryAdmission, StoreError>> {
            self.claim(source_node_id, cat_id)
        }

        fn node_control_endpoint<'a>(
            &'a self,
            _node_id: &'a str,
        ) -> RecoveryFuture<'a, Result<NodeControlEndpoint, StoreError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push("endpoint".to_owned());
                NodeControlEndpoint::new("http://target.test:8443")
            })
        }

        fn draining_node_control_endpoint<'a>(
            &'a self,
            _node_id: &'a str,
        ) -> RecoveryFuture<'a, Result<NodeControlEndpoint, StoreError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push("source_endpoint".to_owned());
                NodeControlEndpoint::new("http://source.test:8443")
            })
        }

        fn finish<'a>(
            &'a self,
            _claim: &'a RecoveryClaim,
            result: RecoveryFinish<'a>,
        ) -> RecoveryFuture<'a, Result<Option<CatRecord>, StoreError>> {
            Box::pin(async move {
                let result = match result {
                    RecoveryFinish::Recovered => OwnedFinish::Recovered,
                    RecoveryFinish::RetrySource { code, message } => OwnedFinish::RetrySource {
                        code: code.to_owned(),
                        message: message.to_owned(),
                    },
                    RecoveryFinish::Failed { code, message } => OwnedFinish::Failed {
                        code: code.to_owned(),
                        message: message.to_owned(),
                    },
                };
                let mut observed = self.observed.lock().expect("observed");
                observed.events.push("finish".to_owned());
                observed.finishes.push(result);
                Ok(Some(cat(Some(CatState::Running))))
            })
        }
    }

    #[derive(Clone)]
    struct MockNoded {
        observed: Arc<Mutex<Observed>>,
        execute: Arc<Mutex<VecDeque<Result<NodeCommandResult, NodeClientError>>>>,
        inspect: Arc<Mutex<VecDeque<Result<NodeCatStatus, NodeClientError>>>>,
    }

    impl NodedClient for MockNoded {
        fn execute<'a>(
            &'a self,
            _endpoint: &'a NodeControlEndpoint,
            command: &'a NodeCommand,
        ) -> SemanticFuture<'a, Result<NodeCommandResult, NodeClientError>> {
            Box::pin(async move {
                let mut observed = self.observed.lock().expect("observed");
                observed
                    .events
                    .push(format!("execute:{:?}", command.action));
                observed.commands.push(command.clone());
                drop(observed);
                self.execute
                    .lock()
                    .expect("execute")
                    .pop_front()
                    .expect("execute result")
            })
        }

        fn inspect<'a>(
            &'a self,
            _endpoint: &'a NodeControlEndpoint,
            _cat_id: &'a str,
        ) -> SemanticFuture<'a, Result<NodeCatStatus, NodeClientError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push("inspect".to_owned());
                self.inspect
                    .lock()
                    .expect("inspect")
                    .pop_front()
                    .expect("inspect result")
            })
        }
    }

    #[derive(Clone)]
    struct MockIngress {
        observed: Arc<Mutex<Observed>>,
    }

    impl IngressPort for MockIngress {
        fn withdraw<'a>(
            &'a self,
            _cat_id: &'a str,
            old_node_id: &'a str,
        ) -> SemanticFuture<'a, Result<(), IngressError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push(format!("withdraw:{old_node_id}"));
                Ok(())
            })
        }

        fn publish<'a>(
            &'a self,
            _cat_id: &'a str,
            new_node_id: &'a str,
        ) -> SemanticFuture<'a, Result<(), IngressError>> {
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed")
                    .events
                    .push(format!("publish:{new_node_id}"));
                Ok(())
            })
        }
    }

    fn config() -> CatCreateConfig {
        CatCreateConfig {
            cpu_count: 4,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            boot_image: "sha256:recovery-image".to_owned(),
            mounts: vec![CatMount {
                disk_id: "disk-data".to_owned(),
                volume_id: "vol-data".to_owned(),
                filesystem_uuid: "11111111111111111111111111111111".to_owned(),
                disk_format: "ext4".to_owned(),
                mount_path: "/data".to_owned(),
            }],
        }
    }

    fn cat(state: Option<CatState>) -> CatRecord {
        CatRecord {
            cat_id: "cat-1".to_owned(),
            workspace_id: "workspace-1".to_owned(),
            cat_slug: "web".to_owned(),
            state,
            current_action: Some(CatAction::Run),
            current_action_node_id: Some("node-target".to_owned()),
            node_id: Some("node-source".to_owned()),
            config: config(),
        }
    }

    fn claim(state: CatState) -> RecoveryClaim {
        RecoveryClaim {
            cat: cat(Some(state)),
            source_node_id: "node-source".to_owned(),
            target_node_id: "node-target".to_owned(),
            target_state: state,
            started_at_unix_ms: 1,
        }
    }

    fn service(
        admission: RecoveryAdmission,
        execute: impl IntoIterator<Item = Result<NodeCommandResult, NodeClientError>>,
        inspect: impl IntoIterator<Item = Result<NodeCatStatus, NodeClientError>>,
    ) -> (
        SemanticNodeRecoveryService<MockStore, MockNoded, MockIngress>,
        Arc<Mutex<Observed>>,
    ) {
        let observed = Arc::new(Mutex::new(Observed::default()));
        let store = MockStore {
            observed: Arc::clone(&observed),
            candidates: vec![RecoveryCandidate {
                cat_id: "cat-1".to_owned(),
            }],
            admissions: Arc::new(Mutex::new(VecDeque::from([admission]))),
        };
        let noded = MockNoded {
            observed: Arc::clone(&observed),
            execute: Arc::new(Mutex::new(execute.into_iter().collect())),
            inspect: Arc::new(Mutex::new(inspect.into_iter().collect())),
        };
        let ingress = MockIngress {
            observed: Arc::clone(&observed),
        };
        (
            SemanticNodeRecoveryService::new(
                store,
                noded,
                ingress,
                RecoveryTimeouts {
                    node_request: Duration::from_millis(50),
                    retry_count: 0,
                    retry_interval: Duration::ZERO,
                },
            ),
            observed,
        )
    }

    #[tokio::test]
    async fn running_recovery_withdraws_before_claim_and_publishes_only_after_ready() {
        let recovery_claim = claim(CatState::Running);
        let expected_config = recovery_claim.cat.config.clone();
        let (service, observed) = service(
            RecoveryAdmission::Claimed(recovery_claim),
            [Ok(NodeCommandResult::Succeeded(CatState::Running))],
            [Ok(NodeCatStatus::Absent)],
        );

        let report = service
            .recover_offline_node("node-source")
            .await
            .expect("recover running Cat");

        assert!(matches!(
            report.cats[0].status,
            CatRecoveryStatus::Recovered {
                state: CatState::Running,
                ..
            }
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.events,
            [
                "list_source",
                "withdraw:node-source",
                "claim",
                "endpoint",
                "inspect",
                "endpoint",
                "execute:Run",
                "publish:node-target",
                "finish",
            ]
        );
        assert_eq!(observed.commands.len(), 1);
        assert_eq!(observed.commands[0].action, CatAction::Run);
        assert_eq!(observed.commands[0].config, Some(expected_config));
        assert_eq!(observed.finishes, [OwnedFinish::Recovered]);
    }

    #[tokio::test]
    async fn suspended_recovery_runs_with_full_config_then_suspends_without_publish() {
        let recovery_claim = claim(CatState::Suspended);
        let expected_config = recovery_claim.cat.config.clone();
        let (service, observed) = service(
            RecoveryAdmission::AlreadyClaimed(recovery_claim),
            [
                Ok(NodeCommandResult::Succeeded(CatState::Running)),
                Ok(NodeCommandResult::Succeeded(CatState::Suspended)),
            ],
            [Ok(NodeCatStatus::Absent)],
        );

        service
            .recover_offline_node("node-source")
            .await
            .expect("recover suspended Cat");

        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed
                .commands
                .iter()
                .map(|command| command.action)
                .collect::<Vec<_>>(),
            [CatAction::Run, CatAction::Suspend]
        );
        assert_eq!(observed.commands[0].config, Some(expected_config));
        assert_eq!(observed.commands[1].config, None);
        assert!(!observed
            .events
            .iter()
            .any(|event| event.starts_with("publish:")));
    }

    #[tokio::test]
    async fn warm_recovery_cold_boots_then_recreates_warm_product_state() {
        let (service, observed) = service(
            RecoveryAdmission::Claimed(claim(CatState::Warm)),
            [
                Ok(NodeCommandResult::Succeeded(CatState::Running)),
                Ok(NodeCommandResult::Succeeded(CatState::Warm)),
            ],
            [Ok(NodeCatStatus::Absent)],
        );

        let report = service
            .recover_offline_node("node-source")
            .await
            .expect("recover warm Cat");

        assert!(matches!(
            report.cats[0].status,
            CatRecoveryStatus::Recovered {
                state: CatState::Warm,
                ..
            }
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed
                .commands
                .iter()
                .map(|command| command.action)
                .collect::<Vec<_>>(),
            [CatAction::Run, CatAction::Warm]
        );
        assert!(!observed
            .events
            .iter()
            .any(|event| event.starts_with("publish:")));
    }

    #[tokio::test]
    async fn cold_cat_needs_no_target_node_action() {
        let (service, observed) = service(
            RecoveryAdmission::ColdNoAction(cat(Some(CatState::Cold))),
            [],
            [],
        );

        let report = service
            .recover_offline_node("node-source")
            .await
            .expect("Cold Cat needs no recovery action");

        assert_eq!(report.cats[0].status, CatRecoveryStatus::ColdNoAction);
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.events,
            ["list_source", "withdraw:node-source", "claim"]
        );
        assert!(observed.commands.is_empty());
        assert!(observed.finishes.is_empty());
    }

    #[tokio::test]
    async fn timeout_discovers_ready_target_before_settlement() {
        let (service, observed) = service(
            RecoveryAdmission::Claimed(claim(CatState::Running)),
            [Err(NodeClientError::Timeout)],
            [
                Ok(NodeCatStatus::Absent),
                Ok(NodeCatStatus::Present {
                    state: Some(CatState::Running),
                    active_action: None,
                }),
            ],
        );

        service
            .recover_offline_node("node-source")
            .await
            .expect("recover ambiguous response");

        let observed = observed.lock().expect("observed");
        assert_eq!(observed.commands.len(), 1);
        assert!(observed.events.contains(&"publish:node-target".to_owned()));
        assert_eq!(observed.finishes, [OwnedFinish::Recovered]);
    }

    #[tokio::test]
    async fn unsupported_state_fails_closed_without_touching_target_node() {
        let (service, observed) = service(
            RecoveryAdmission::UnsupportedState(cat(Some(CatState::Failure))),
            [],
            [],
        );

        let report = service
            .recover_offline_node("node-source")
            .await
            .expect("unsupported state is a per-Cat failure");

        assert!(matches!(
            &report.cats[0].status,
            CatRecoveryStatus::Failed { code, .. } if code == "recovery_state_unsupported"
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.events,
            ["list_source", "withdraw:node-source", "claim"]
        );
        assert!(observed.commands.is_empty());
        assert!(observed.finishes.is_empty());
    }

    #[tokio::test]
    async fn planned_running_drain_colds_source_before_running_and_publishing_target() {
        let drain_claim = claim(CatState::Running);
        let expected_config = drain_claim.cat.config.clone();
        let (service, observed) = service(
            RecoveryAdmission::Claimed(drain_claim),
            [
                Ok(NodeCommandResult::Succeeded(CatState::Cold)),
                Ok(NodeCommandResult::Succeeded(CatState::Running)),
            ],
            [Ok(NodeCatStatus::Absent), Ok(NodeCatStatus::Absent)],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("drain running Cat");

        assert!(report.is_drained());
        assert!(matches!(
            report.cats[0].status,
            CatDrainStatus::Migrated {
                state: CatState::Running,
                ..
            }
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.events,
            [
                "list_drain",
                "claim",
                "withdraw:node-source",
                "source_endpoint",
                "inspect",
                "execute:Cold",
                "endpoint",
                "inspect",
                "endpoint",
                "execute:Run",
                "publish:node-target",
                "finish",
            ]
        );
        assert_eq!(observed.commands[0].action, CatAction::Cold);
        assert_eq!(observed.commands[0].config, None);
        assert_eq!(observed.commands[1].action, CatAction::Run);
        assert_eq!(observed.commands[1].config, Some(expected_config));
        assert_eq!(observed.finishes, [OwnedFinish::Recovered]);
    }

    #[tokio::test]
    async fn planned_warm_drain_restores_warm_without_publishing_transient_running() {
        let (service, observed) = service(
            RecoveryAdmission::Claimed(claim(CatState::Warm)),
            [
                Ok(NodeCommandResult::Succeeded(CatState::Cold)),
                Ok(NodeCommandResult::Succeeded(CatState::Running)),
                Ok(NodeCommandResult::Succeeded(CatState::Warm)),
            ],
            [Ok(NodeCatStatus::Absent), Ok(NodeCatStatus::Absent)],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("drain warm Cat");

        assert!(report.is_drained());
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed
                .commands
                .iter()
                .map(|command| command.action)
                .collect::<Vec<_>>(),
            [CatAction::Cold, CatAction::Run, CatAction::Warm]
        );
        assert!(!observed
            .events
            .iter()
            .any(|event| event.starts_with("publish:")));
    }

    #[tokio::test]
    async fn planned_drain_retry_joins_claim_and_discovers_both_completed_sides() {
        let (service, observed) = service(
            RecoveryAdmission::AlreadyClaimed(claim(CatState::Suspended)),
            [],
            [
                Ok(NodeCatStatus::Present {
                    state: Some(CatState::Cold),
                    active_action: None,
                }),
                Ok(NodeCatStatus::Present {
                    state: Some(CatState::Suspended),
                    active_action: None,
                }),
            ],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("resume completed drain");

        assert!(report.is_drained());
        let observed = observed.lock().expect("observed");
        assert!(observed.commands.is_empty());
        assert_eq!(observed.finishes, [OwnedFinish::Recovered]);
    }

    #[tokio::test]
    async fn planned_drain_cold_failure_releases_the_target_but_preserves_source_retry() {
        let (service, observed) = service(
            RecoveryAdmission::Claimed(claim(CatState::Running)),
            [Ok(NodeCommandResult::Failed {
                code: "flush_failed".to_owned(),
                message: "retained volume did not reach R=L".to_owned(),
            })],
            [Ok(NodeCatStatus::Absent)],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("report blocked source Cold");

        assert!(!report.is_drained());
        assert!(matches!(
            &report.cats[0].status,
            CatDrainStatus::Blocked { code, .. } if code == "flush_failed"
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.finishes,
            [OwnedFinish::RetrySource {
                code: "flush_failed".to_owned(),
                message: "retained volume did not reach R=L".to_owned(),
            }]
        );
        assert!(!observed.events.iter().any(|event| event == "endpoint"));
    }

    #[tokio::test]
    async fn planned_drain_ambiguous_source_releases_the_target_but_preserves_source_retry() {
        let (service, observed) = service(
            RecoveryAdmission::Claimed(claim(CatState::Running)),
            [Err(NodeClientError::Timeout)],
            [Ok(NodeCatStatus::Absent), Ok(NodeCatStatus::Absent)],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("report ambiguous source Cold");

        assert!(!report.is_drained());
        assert!(matches!(
            &report.cats[0].status,
            CatDrainStatus::Blocked { code, .. } if code == "drain_source_timeout"
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.finishes,
            [OwnedFinish::RetrySource {
                code: "drain_source_timeout".to_owned(),
                message: "source noded Cold request timed out".to_owned(),
            }]
        );
        assert!(!observed.events.iter().any(|event| event == "endpoint"));
    }

    #[tokio::test]
    async fn planned_drain_target_failure_settles_cleanup_on_target() {
        let (service, observed) = service(
            RecoveryAdmission::Claimed(claim(CatState::Running)),
            [
                Ok(NodeCommandResult::Succeeded(CatState::Cold)),
                Ok(NodeCommandResult::Failed {
                    code: "guest_start_failed".to_owned(),
                    message: "target did not become Ready".to_owned(),
                }),
            ],
            [Ok(NodeCatStatus::Absent), Ok(NodeCatStatus::Absent)],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("report blocked target restore");

        assert!(!report.is_drained());
        assert!(matches!(
            &report.cats[0].status,
            CatDrainStatus::Blocked { code, .. } if code == "guest_start_failed"
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.finishes,
            [OwnedFinish::Failed {
                code: "guest_start_failed".to_owned(),
                message: "target did not become Ready".to_owned(),
            }]
        );
        assert!(!observed
            .events
            .iter()
            .any(|event| event.starts_with("publish:")));
    }

    #[tokio::test]
    async fn planned_drain_ambiguous_target_timeout_retains_the_relocation_claim() {
        let (service, observed) = service(
            RecoveryAdmission::Claimed(claim(CatState::Running)),
            [
                Ok(NodeCommandResult::Succeeded(CatState::Cold)),
                Err(NodeClientError::Timeout),
            ],
            [
                Ok(NodeCatStatus::Absent),
                Ok(NodeCatStatus::Absent),
                Ok(NodeCatStatus::Absent),
            ],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("report ambiguous target Run");

        assert!(!report.is_drained());
        assert!(matches!(
            &report.cats[0].status,
            CatDrainStatus::Blocked { code, .. } if code == "recovery_timeout"
        ));
        let observed = observed.lock().expect("observed");
        assert!(observed.finishes.is_empty());
        assert!(!observed
            .events
            .iter()
            .any(|event| event.starts_with("publish:")));
    }

    #[tokio::test]
    async fn planned_drain_without_target_blocks_before_source_effects() {
        let (service, observed) = service(
            RecoveryAdmission::NoRunningTarget(cat(Some(CatState::Running))),
            [],
            [],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("report missing drain target");

        assert!(!report.is_drained());
        let observed = observed.lock().expect("observed");
        assert_eq!(observed.events, ["list_drain", "claim"]);
        assert!(observed.commands.is_empty());
        assert!(observed.finishes.is_empty());
    }

    #[tokio::test]
    async fn planned_drain_does_not_preempt_an_existing_lifecycle_action() {
        let (service, observed) = service(
            RecoveryAdmission::Busy(cat(Some(CatState::Running))),
            [],
            [],
        );

        let report = service
            .drain_node("node-source")
            .await
            .expect("report busy Cat");

        assert!(!report.is_drained());
        assert!(matches!(
            &report.cats[0].status,
            CatDrainStatus::Blocked { code, .. } if code == "busy"
        ));
        let observed = observed.lock().expect("observed");
        assert_eq!(observed.events, ["list_drain", "claim"]);
        assert!(observed.commands.is_empty());
        assert!(observed.finishes.is_empty());
    }
}

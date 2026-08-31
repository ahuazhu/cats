//! Node registration, heartbeat and placement eligibility for the semantic
//! Control-to-noded protocol.
//!
//! The repository owns database time. Node clocks are stored only as
//! diagnostic payload and never participate in offline decisions.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use cats_protocol::error::ApiError;
use cats_protocol::semantic_control::{
    NodeHeartbeatRequest, NodeHeartbeatResponse, NodeRegistrationRequest, NodeRegistrationResponse,
    NodeStatus, NodedServiceToken, NODED_HEALTH_PATH,
};

use crate::semantic_node_recovery::NodeDrainReport;
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
pub const MISSED_HEARTBEATS_BEFORE_PROBE: u32 = 3;
pub const MISSED_HEARTBEAT_WINDOW: Duration =
    Duration::from_secs(HEARTBEAT_INTERVAL.as_secs() * MISSED_HEARTBEATS_BEFORE_PROBE as u64);

pub type NodeFuture<T> = Pin<Box<dyn Future<Output = Result<T, ApiError>> + Send>>;
pub type OfflineNodeRecovery = Arc<dyn Fn(String) -> NodeFuture<()> + Send + Sync>;
pub type PlannedNodeDrain = Arc<dyn Fn(String) -> NodeFuture<NodeDrainReport> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: String,
    pub node_name: String,
    pub vendor: String,
    pub region: String,
    pub zone: String,
    pub instance_id: String,
    pub machine_type: String,
    pub node_version: String,
    pub control_endpoint: String,
    pub status: NodeStatus,
}

impl NodeRecord {
    pub fn accepts_placement(&self) -> bool {
        self.status.accepts_placement()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleNodeCandidate {
    pub node_id: String,
    pub control_endpoint: String,
    /// Exact database timestamp rendered by PostgreSQL. It is an optimistic
    /// compare token, not a Node timestamp.
    pub last_heartbeat_at: String,
}

pub trait NodeRepository: Send + Sync {
    fn register(&self, request: NodeRegistrationRequest) -> NodeFuture<NodeRegistrationResponse>;

    fn heartbeat(&self, request: NodeHeartbeatRequest) -> NodeFuture<NodeHeartbeatResponse>;

    fn begin_drain(&self, node_id: String) -> NodeFuture<NodeRecord>;

    fn placement_candidates(&self) -> NodeFuture<Vec<NodeRecord>>;

    fn stale_candidates(&self, missed_for: Duration) -> NodeFuture<Vec<StaleNodeCandidate>>;

    fn mark_offline_if_heartbeat_unchanged(
        &self,
        candidate: StaleNodeCandidate,
    ) -> NodeFuture<bool>;

    fn offline_recovery_candidates(&self) -> NodeFuture<Vec<String>>;

    fn planned_drain_candidates(&self) -> NodeFuture<Vec<String>>;
}

pub trait NodeHealthProbe: Send + Sync {
    fn is_healthy(&self, control_endpoint: String) -> NodeFuture<bool>;
}

#[derive(Clone)]
pub struct HttpNodeHealthProbe {
    client: reqwest::Client,
    service_token: NodedServiceToken,
}

impl HttpNodeHealthProbe {
    pub fn new(service_token: NodedServiceToken) -> Result<Self, ApiError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|error| ApiError::internal(format!("build Node health client: {error}")))?;
        Ok(Self {
            client,
            service_token,
        })
    }
}

impl NodeHealthProbe for HttpNodeHealthProbe {
    fn is_healthy(&self, control_endpoint: String) -> NodeFuture<bool> {
        let client = self.client.clone();
        let service_token = self.service_token.clone();
        Box::pin(async move {
            let url = format!(
                "{}{NODED_HEALTH_PATH}",
                control_endpoint.trim_end_matches('/')
            );
            Ok(client
                .get(url)
                .header(
                    cats_protocol::semantic_control::NODED_AUTHORIZATION_HEADER,
                    service_token.authorization_value(),
                )
                .send()
                .await
                .is_ok_and(|response| response.status().is_success()))
        })
    }
}

#[derive(Clone)]
pub struct NodeManagementService {
    repository: Arc<dyn NodeRepository>,
    health_probe: Arc<dyn NodeHealthProbe>,
    missed_heartbeat_window: Duration,
    offline_recovery: Option<OfflineNodeRecovery>,
    planned_drain: Option<PlannedNodeDrain>,
}

impl NodeManagementService {
    pub fn with_default_heartbeat_policy(
        repository: Arc<dyn NodeRepository>,
        health_probe: Arc<dyn NodeHealthProbe>,
    ) -> Self {
        Self {
            repository,
            health_probe,
            missed_heartbeat_window: MISSED_HEARTBEAT_WINDOW,
            offline_recovery: None,
            planned_drain: None,
        }
    }

    pub fn new(
        repository: Arc<dyn NodeRepository>,
        health_probe: Arc<dyn NodeHealthProbe>,
        missed_heartbeat_window: Duration,
    ) -> Result<Self, ApiError> {
        if missed_heartbeat_window.is_zero() {
            return Err(ApiError::invalid(
                "missed heartbeat window must be positive",
            ));
        }
        Ok(Self {
            repository,
            health_probe,
            missed_heartbeat_window,
            offline_recovery: None,
            planned_drain: None,
        })
    }

    pub fn with_offline_recovery(mut self, recovery: OfflineNodeRecovery) -> Self {
        self.offline_recovery = Some(recovery);
        self
    }

    pub fn with_planned_drain(mut self, drain: PlannedNodeDrain) -> Self {
        self.planned_drain = Some(drain);
        self
    }

    pub async fn register(
        &self,
        request: NodeRegistrationRequest,
    ) -> Result<NodeRegistrationResponse, ApiError> {
        request
            .validate()
            .map_err(|error| ApiError::invalid(error.to_string()))?;
        self.repository.register(request).await
    }

    pub async fn heartbeat(
        &self,
        request: NodeHeartbeatRequest,
    ) -> Result<NodeHeartbeatResponse, ApiError> {
        request
            .validate()
            .map_err(|error| ApiError::invalid(error.to_string()))?;
        self.repository.heartbeat(request).await
    }

    pub async fn begin_drain(&self, node_id: String) -> Result<NodeRecord, ApiError> {
        validate_token("node_id", &node_id)?;
        self.repository.begin_drain(node_id).await
    }

    pub async fn drain_node(&self, node_id: String) -> Result<NodeDrainReport, ApiError> {
        validate_token("node_id", &node_id)?;
        let drain = self
            .planned_drain
            .as_ref()
            .ok_or_else(|| ApiError::failed_precondition("planned Node drain is not configured"))?;
        self.repository.begin_drain(node_id.clone()).await?;
        drain(node_id).await
    }

    pub async fn placement_candidates(&self) -> Result<Vec<NodeRecord>, ApiError> {
        let nodes = self.repository.placement_candidates().await?;
        if nodes.iter().any(|node| !node.accepts_placement()) {
            return Err(ApiError::internal(
                "Node repository returned a non-running placement candidate",
            ));
        }
        Ok(nodes)
    }

    /// Runs one level-triggered liveness pass. Three missed 10-second
    /// heartbeats nominate a Node for a final active probe. The exact observed
    /// database timestamp is compared while marking offline, so a heartbeat
    /// racing the probe keeps the Node running.
    pub async fn detect_offline_nodes(&self) -> Result<Vec<String>, ApiError> {
        let candidates = self
            .repository
            .stale_candidates(self.missed_heartbeat_window)
            .await?;
        let mut changed = Vec::new();
        for candidate in candidates {
            if self
                .health_probe
                .is_healthy(candidate.control_endpoint.clone())
                .await?
            {
                continue;
            }
            if self
                .repository
                .mark_offline_if_heartbeat_unchanged(candidate.clone())
                .await?
            {
                changed.push(candidate.node_id);
            }
        }
        Ok(changed)
    }

    async fn continue_node_work(&self) -> Result<(), ApiError> {
        self.recover_offline_nodes().await?;
        self.continue_planned_drains().await
    }

    async fn recover_offline_nodes(&self) -> Result<(), ApiError> {
        let Some(recover) = &self.offline_recovery else {
            return Ok(());
        };
        for node_id in self.repository.offline_recovery_candidates().await? {
            if let Err(error) = recover(node_id.clone()).await {
                tracing::warn!(%node_id, %error, "offline Node Cat recovery failed; retrying after the next liveness pass");
            }
        }
        Ok(())
    }

    async fn continue_planned_drains(&self) -> Result<(), ApiError> {
        let Some(drain) = &self.planned_drain else {
            return Ok(());
        };
        for node_id in self.repository.planned_drain_candidates().await? {
            match drain(node_id.clone()).await {
                Ok(report) if report.is_drained() => {
                    tracing::info!(%node_id, "planned Node drain completed");
                }
                Ok(report) => {
                    tracing::warn!(
                        %node_id,
                        blocked_cats = report
                            .cats
                            .iter()
                            .filter(|cat| matches!(cat.status, crate::semantic_node_recovery::CatDrainStatus::Blocked { .. }))
                            .count(),
                        "planned Node drain remains blocked; retrying after the next liveness pass"
                    );
                }
                Err(error) => {
                    tracing::warn!(%node_id, %error, "planned Node drain pass failed; retrying after the next liveness pass");
                }
            }
        }
        Ok(())
    }

    /// Runs liveness detection and lifecycle recovery on independent loops.
    /// Slow noded lifecycle calls therefore cannot postpone heartbeat probes.
    pub async fn run_liveness_monitor(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        self.run_node_monitors(shutdown, HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL)
            .await;
    }

    async fn run_node_monitors(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
        liveness_interval: Duration,
        recovery_interval: Duration,
    ) {
        tokio::join!(
            self.run_liveness_probe_monitor(shutdown.clone(), liveness_interval),
            self.run_recovery_monitor(shutdown, recovery_interval),
        );
    }

    async fn run_liveness_probe_monitor(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        cadence: Duration,
    ) {
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.detect_offline_nodes().await {
                        Ok(changed) => {
                            for node_id in changed {
                                tracing::warn!(%node_id, "Node marked offline after missed heartbeats and failed active probe");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "Node liveness pass failed; leaving Node status unchanged");
                        }
                    }
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }

    async fn run_recovery_monitor(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        cadence: Duration,
    ) {
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tokio::select! {
                        result = self.continue_node_work() => {
                            if let Err(error) = result {
                                tracing::warn!(%error, "Node recovery pass failed; retrying after the next recovery interval");
                            }
                        }
                        result = shutdown.changed() => {
                            if result.is_err() || *shutdown.borrow() {
                                return;
                            }
                        }
                    }
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }
}

fn validate_token(name: &str, value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
    {
        return Err(ApiError::invalid(format!(
            "{name} must be 1..=128 ASCII token characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use cats_protocol::runtime_reconciliation::Id;
    use cats_protocol::semantic_control::{
        NodeHeartbeatStatus, NodeName, NodeRegistrationStatus, NodedControlEndpoint,
    };

    use super::*;

    fn request() -> NodeRegistrationRequest {
        NodeRegistrationRequest {
            node_id: Id::new("node_a").expect("node id"),
            node_name: NodeName::new("worker-a").expect("node name"),
            vendor: "aws".to_string(),
            region: "us-east-1".to_string(),
            zone: "us-east-1a".to_string(),
            instance_id: "i-123".to_string(),
            machine_type: "m7i.large".to_string(),
            node_version: "1.0.0".to_string(),
            control_endpoint: NodedControlEndpoint::new("http://127.0.0.1:7010").expect("endpoint"),
            reset_completed: false,
        }
    }

    fn record(status: NodeStatus) -> NodeRecord {
        let request = request();
        NodeRecord {
            node_id: request.node_id.to_string(),
            node_name: request.node_name.to_string(),
            vendor: request.vendor,
            region: request.region,
            zone: request.zone,
            instance_id: request.instance_id,
            machine_type: request.machine_type,
            node_version: request.node_version,
            control_endpoint: request.control_endpoint.to_string(),
            status,
        }
    }

    #[derive(Default)]
    struct MockRepository {
        stale: Mutex<Vec<StaleNodeCandidate>>,
        marked: Mutex<Vec<String>>,
        marked_notify: tokio::sync::Notify,
        drained: Mutex<Vec<String>>,
        drain_candidates: Mutex<Vec<String>>,
    }

    impl NodeRepository for MockRepository {
        fn register(
            &self,
            request: NodeRegistrationRequest,
        ) -> NodeFuture<NodeRegistrationResponse> {
            Box::pin(async move {
                Ok(NodeRegistrationResponse {
                    status: NodeRegistrationStatus::Registered,
                    node: cats_protocol::semantic_control::NodeView {
                        node_id: request.node_id,
                        node_name: request.node_name,
                        control_endpoint: request.control_endpoint,
                        vendor: request.vendor,
                        region: request.region,
                        zone: request.zone,
                        instance_id: request.instance_id,
                        machine_type: request.machine_type,
                        node_version: request.node_version,
                        status: NodeStatus::Running,
                        created_at_unix_ms: 1,
                        updated_at_unix_ms: 1,
                    },
                })
            })
        }

        fn heartbeat(&self, _request: NodeHeartbeatRequest) -> NodeFuture<NodeHeartbeatResponse> {
            Box::pin(async {
                Ok(NodeHeartbeatResponse {
                    status: NodeHeartbeatStatus::Accepted,
                })
            })
        }

        fn begin_drain(&self, node_id: String) -> NodeFuture<NodeRecord> {
            self.drained.lock().expect("lock drains").push(node_id);
            Box::pin(async { Ok(record(NodeStatus::Draining)) })
        }

        fn placement_candidates(&self) -> NodeFuture<Vec<NodeRecord>> {
            Box::pin(async { Ok(vec![record(NodeStatus::Running)]) })
        }

        fn stale_candidates(&self, _missed_for: Duration) -> NodeFuture<Vec<StaleNodeCandidate>> {
            let stale = self.stale.lock().expect("lock stale").clone();
            Box::pin(async move { Ok(stale) })
        }

        fn mark_offline_if_heartbeat_unchanged(
            &self,
            candidate: StaleNodeCandidate,
        ) -> NodeFuture<bool> {
            self.marked
                .lock()
                .expect("lock marks")
                .push(candidate.node_id);
            self.marked_notify.notify_one();
            Box::pin(async { Ok(true) })
        }

        fn offline_recovery_candidates(&self) -> NodeFuture<Vec<String>> {
            let nodes = self.marked.lock().expect("lock marks").clone();
            Box::pin(async move { Ok(nodes) })
        }

        fn planned_drain_candidates(&self) -> NodeFuture<Vec<String>> {
            let nodes = self
                .drain_candidates
                .lock()
                .expect("lock drain candidates")
                .clone();
            Box::pin(async move { Ok(nodes) })
        }
    }

    struct MockProbe {
        answers: Mutex<VecDeque<bool>>,
    }

    impl NodeHealthProbe for MockProbe {
        fn is_healthy(&self, _control_endpoint: String) -> NodeFuture<bool> {
            let answer = self.answers.lock().expect("lock probes").pop_front();
            Box::pin(async move { Ok(answer.expect("probe answer")) })
        }
    }

    #[tokio::test]
    async fn active_probe_prevents_false_offline_and_failed_probe_marks_exact_candidate() {
        let repository = Arc::new(MockRepository {
            stale: Mutex::new(vec![
                StaleNodeCandidate {
                    node_id: "node_healthy".to_string(),
                    control_endpoint: "http://healthy:7010".to_string(),
                    last_heartbeat_at: "2026-08-22 00:00:00+00".to_string(),
                },
                StaleNodeCandidate {
                    node_id: "node_failed".to_string(),
                    control_endpoint: "http://failed:7010".to_string(),
                    last_heartbeat_at: "2026-08-22 00:00:00+00".to_string(),
                },
            ]),
            ..MockRepository::default()
        });
        let recovered = Arc::new(Mutex::new(Vec::new()));
        let recovery: OfflineNodeRecovery = {
            let recovered = Arc::clone(&recovered);
            Arc::new(move |node_id| {
                recovered.lock().expect("lock recoveries").push(node_id);
                Box::pin(async { Ok(()) })
            })
        };
        let service = NodeManagementService::new(
            repository.clone(),
            Arc::new(MockProbe {
                answers: Mutex::new(VecDeque::from([true, false])),
            }),
            Duration::from_secs(30),
        )
        .expect("service")
        .with_offline_recovery(recovery);

        assert_eq!(
            service.detect_offline_nodes().await.expect("detect"),
            vec!["node_failed"]
        );
        assert_eq!(
            *repository.marked.lock().expect("lock marks"),
            vec!["node_failed"]
        );
        assert!(recovered.lock().expect("lock recoveries").is_empty());
        service
            .continue_node_work()
            .await
            .expect("recover marked offline Node");
        assert_eq!(
            *recovered.lock().expect("lock recoveries"),
            vec!["node_failed"]
        );

        repository.stale.lock().expect("lock stale").clear();
        assert!(service
            .detect_offline_nodes()
            .await
            .expect("retry offline recovery")
            .is_empty());
        service
            .continue_node_work()
            .await
            .expect("retry offline recovery work");
        assert_eq!(
            *recovered.lock().expect("lock recoveries"),
            vec!["node_failed", "node_failed"]
        );
    }

    #[tokio::test]
    async fn heartbeat_validates_capacity_before_store() {
        let service = NodeManagementService::new(
            Arc::new(MockRepository::default()),
            Arc::new(MockProbe {
                answers: Mutex::new(VecDeque::new()),
            }),
            Duration::from_secs(30),
        )
        .expect("service");
        let error = service
            .heartbeat(NodeHeartbeatRequest {
                node_id: Id::new("node_a").expect("node id"),
                node_reported_at_unix_ms: 1,
                reported_status: NodeStatus::Running,
                total_cpu: 4,
                cpu_utilized: 5.0,
                total_memory: 8,
                memory_utilized: 4,
                running_cat_count: 0,
                suspended_cat_count: 0,
                warm_cat_count: 0,
            })
            .await
            .expect_err("invalid utilization");
        assert_eq!(error.message, "heartbeat resource values are invalid");
    }

    #[tokio::test]
    async fn planned_drain_cordons_before_invoking_relocation() {
        let repository = Arc::new(MockRepository::default());
        let invoked = Arc::new(Mutex::new(Vec::new()));
        let drain: PlannedNodeDrain = {
            let invoked = Arc::clone(&invoked);
            let repository = Arc::clone(&repository);
            Arc::new(move |node_id| {
                assert_eq!(
                    repository.drained.lock().expect("lock drains").as_slice(),
                    std::slice::from_ref(&node_id)
                );
                invoked
                    .lock()
                    .expect("lock invoked drains")
                    .push(node_id.clone());
                Box::pin(async move {
                    Ok(NodeDrainReport {
                        source_node_id: node_id,
                        cats: Vec::new(),
                    })
                })
            })
        };
        let service = NodeManagementService::new(
            repository.clone(),
            Arc::new(MockProbe {
                answers: Mutex::new(VecDeque::new()),
            }),
            Duration::from_secs(30),
        )
        .expect("service")
        .with_planned_drain(drain);

        let report = service
            .drain_node("node_a".to_owned())
            .await
            .expect("drain Node");

        assert!(report.is_drained());
        assert_eq!(*repository.drained.lock().expect("lock drains"), ["node_a"]);
        assert_eq!(*invoked.lock().expect("lock invoked drains"), ["node_a"]);
    }

    #[tokio::test]
    async fn unconfigured_planned_drain_has_no_cordon_side_effect() {
        let repository = Arc::new(MockRepository::default());
        let service = NodeManagementService::new(
            repository.clone(),
            Arc::new(MockProbe {
                answers: Mutex::new(VecDeque::new()),
            }),
            Duration::from_secs(30),
        )
        .expect("service");

        let error = service
            .drain_node("node_a".to_owned())
            .await
            .expect_err("drain callback is required before cordon");

        assert_eq!(error.message, "planned Node drain is not configured");
        assert!(repository.drained.lock().expect("lock drains").is_empty());
    }

    #[tokio::test]
    async fn recovery_pass_resumes_persisted_draining_nodes() {
        let repository = Arc::new(MockRepository {
            drain_candidates: Mutex::new(vec!["node_a".to_owned()]),
            ..MockRepository::default()
        });
        let invoked = Arc::new(Mutex::new(Vec::new()));
        let drain: PlannedNodeDrain = {
            let invoked = Arc::clone(&invoked);
            Arc::new(move |node_id| {
                invoked
                    .lock()
                    .expect("lock invoked drains")
                    .push(node_id.clone());
                Box::pin(async move {
                    Ok(NodeDrainReport {
                        source_node_id: node_id,
                        cats: Vec::new(),
                    })
                })
            })
        };
        let service = NodeManagementService::new(
            repository,
            Arc::new(MockProbe {
                answers: Mutex::new(VecDeque::new()),
            }),
            Duration::from_secs(30),
        )
        .expect("service")
        .with_planned_drain(drain);

        service
            .continue_node_work()
            .await
            .expect("run recovery pass");
        assert_eq!(*invoked.lock().expect("lock invoked drains"), ["node_a"]);
    }

    #[tokio::test]
    async fn stalled_drain_does_not_delay_liveness_detection_or_shutdown() {
        let repository = Arc::new(MockRepository {
            drain_candidates: Mutex::new(vec!["node_drain".to_owned()]),
            ..MockRepository::default()
        });
        let probe = Arc::new(MockProbe {
            answers: Mutex::new(VecDeque::new()),
        });
        let drain_started = Arc::new(tokio::sync::Notify::new());
        let drain: PlannedNodeDrain = {
            let drain_started = Arc::clone(&drain_started);
            Arc::new(move |_node_id| {
                let drain_started = Arc::clone(&drain_started);
                Box::pin(async move {
                    drain_started.notify_one();
                    std::future::pending::<()>().await;
                    unreachable!("pending drain can only be cancelled")
                })
            })
        };
        let service =
            NodeManagementService::new(repository.clone(), probe.clone(), Duration::from_secs(30))
                .expect("service")
                .with_planned_drain(drain);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let monitor = tokio::spawn(async move {
            service
                .run_node_monitors(
                    shutdown_rx,
                    Duration::from_millis(10),
                    Duration::from_millis(10),
                )
                .await;
        });

        tokio::time::timeout(Duration::from_secs(1), drain_started.notified())
            .await
            .expect("drain worker starts");
        repository
            .stale
            .lock()
            .expect("lock stale")
            .push(StaleNodeCandidate {
                node_id: "node_failed".to_owned(),
                control_endpoint: "http://failed:7010".to_owned(),
                last_heartbeat_at: "2026-08-23 00:00:00+00".to_owned(),
            });
        probe.answers.lock().expect("lock probes").push_back(false);

        tokio::time::timeout(Duration::from_secs(1), repository.marked_notify.notified())
            .await
            .expect("liveness detection continues while drain is pending");
        shutdown_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), monitor)
            .await
            .expect("shutdown cancels pending drain")
            .expect("monitor task succeeds");
    }
}

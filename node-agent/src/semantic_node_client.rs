//! noded registration, heartbeat and reset-required convergence.
//!
//! A transport failure never authorizes local cleanup. Only an explicit
//! `reset_required` response closes placement, stops all local Cats and then
//! re-registers with `reset_completed=true`.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use cats_protocol::metering::{
    IngestUsageCheckpointsRequest, IngestUsageCheckpointsResponse, USAGE_CHECKPOINTS_PATH,
};
use cats_protocol::semantic_control::{
    NodeHeartbeatRequest, NodeHeartbeatResponse, NodeHeartbeatStatus, NodeRegistrationRequest,
    NodeRegistrationResponse, NodeRegistrationStatus, NodeStatus, NodedServiceToken,
    NODED_AUTHORIZATION_HEADER,
};

pub const CONTROL_NODE_REGISTER_PATH: &str = "/v1/internal/nodes/register";
pub const CONTROL_NODE_HEARTBEAT_PATH: &str = "/v1/internal/nodes/heartbeat";
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_HEARTBEAT_RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub type NodeClientFuture<T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send>>;

pub trait SemanticNodeTransport: Send + Sync {
    fn register(
        &self,
        request: NodeRegistrationRequest,
    ) -> NodeClientFuture<NodeRegistrationResponse>;

    fn heartbeat(&self, request: NodeHeartbeatRequest) -> NodeClientFuture<NodeHeartbeatResponse>;

    /// Deliver one ordered batch of cumulative usage checkpoints.
    ///
    /// Usage is observation, never authority: a failure here is retried by the
    /// producer and must not affect registration, heartbeat or any runtime
    /// effect.
    fn report_usage(
        &self,
        request: IngestUsageCheckpointsRequest,
    ) -> NodeClientFuture<IngestUsageCheckpointsResponse>;
}

#[derive(Clone)]
pub struct HttpSemanticNodeTransport {
    client: reqwest::Client,
    control_origin: Arc<str>,
    service_token: NodedServiceToken,
}

impl HttpSemanticNodeTransport {
    pub fn new(
        control_origin: impl Into<String>,
        service_token: NodedServiceToken,
    ) -> anyhow::Result<Self> {
        let control_origin = control_origin.into();
        let parsed = reqwest::Url::parse(&control_origin)
            .context("Control origin must be an absolute URL")?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https")
                && parsed.host_str().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none()
                && parsed.path() == "/",
            "Control origin must be a bare absolute http(s) origin"
        );
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .context("build semantic Node Control client")?;
        Ok(Self {
            client,
            control_origin: Arc::from(control_origin.trim_end_matches('/')),
            service_token,
        })
    }

    async fn post<Request, Response>(
        &self,
        path: &str,
        request: &Request,
    ) -> anyhow::Result<Response>
    where
        Request: serde::Serialize + ?Sized,
        Response: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .post(format!("{}{path}", self.control_origin))
            .header(
                NODED_AUTHORIZATION_HEADER,
                self.service_token.authorization_value(),
            )
            .json(request)
            .send()
            .await
            .with_context(|| format!("POST semantic Node endpoint {path}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "semantic Node endpoint {path} returned HTTP {status}"
            ));
        }
        response
            .json()
            .await
            .with_context(|| format!("decode semantic Node response from {path}"))
    }
}

impl SemanticNodeTransport for HttpSemanticNodeTransport {
    fn register(
        &self,
        request: NodeRegistrationRequest,
    ) -> NodeClientFuture<NodeRegistrationResponse> {
        let client = self.clone();
        Box::pin(async move {
            request.validate().context("validate Node registration")?;
            client.post(CONTROL_NODE_REGISTER_PATH, &request).await
        })
    }

    fn report_usage(
        &self,
        request: IngestUsageCheckpointsRequest,
    ) -> NodeClientFuture<IngestUsageCheckpointsResponse> {
        let client = self.clone();
        Box::pin(async move { client.post(USAGE_CHECKPOINTS_PATH, &request).await })
    }

    fn heartbeat(&self, request: NodeHeartbeatRequest) -> NodeClientFuture<NodeHeartbeatResponse> {
        let client = self.clone();
        Box::pin(async move {
            request.validate().context("validate Node heartbeat")?;
            client.post(CONTROL_NODE_HEARTBEAT_PATH, &request).await
        })
    }
}

pub trait NodeResetExecutor: Send + Sync {
    /// Stop accepting Cat work, stop and remove every local Cat artifact, and
    /// retain PersistentDisk product data. The returned future completes only
    /// after the local reset is durable.
    fn reset_all_cats(&self) -> NodeClientFuture<()>;
}

pub trait NodeHeartbeatSource: Send + Sync {
    fn snapshot(&self) -> NodeClientFuture<NodeHeartbeatRequest>;
}

#[derive(Debug, Default)]
pub struct NodePlacementGate(AtomicBool);

impl NodePlacementGate {
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn open(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn close(&self) {
        self.0.store(false, Ordering::Release);
    }
}

pub struct SemanticNodeSupervisor {
    transport: Arc<dyn SemanticNodeTransport>,
    reset: Arc<dyn NodeResetExecutor>,
    placement_gate: Arc<NodePlacementGate>,
    registration: NodeRegistrationRequest,
    heartbeat_interval: Duration,
    retry_interval: Duration,
    reset_completed_waiting: AtomicBool,
}

impl SemanticNodeSupervisor {
    pub fn new(
        transport: Arc<dyn SemanticNodeTransport>,
        reset: Arc<dyn NodeResetExecutor>,
        placement_gate: Arc<NodePlacementGate>,
        registration: NodeRegistrationRequest,
    ) -> anyhow::Result<Self> {
        registration.validate().context("validate registration")?;
        anyhow::ensure!(
            !registration.reset_completed,
            "initial registration must not claim a completed reset"
        );
        Ok(Self {
            transport,
            reset,
            placement_gate,
            registration,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            retry_interval: DEFAULT_HEARTBEAT_RETRY_INTERVAL,
            reset_completed_waiting: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    fn with_intervals(mut self, heartbeat: Duration, retry: Duration) -> Self {
        self.heartbeat_interval = heartbeat;
        self.retry_interval = retry;
        self
    }

    pub fn placement_gate(&self) -> Arc<NodePlacementGate> {
        Arc::clone(&self.placement_gate)
    }

    pub async fn register_until_ready(&self) -> anyhow::Result<()> {
        self.reset_and_reregister().await
    }

    pub async fn heartbeat_once(&self, heartbeat: NodeHeartbeatRequest) -> anyhow::Result<()> {
        anyhow::ensure!(
            heartbeat.node_id == self.registration.node_id,
            "heartbeat node_id does not match registration"
        );
        let response = self
            .transport
            .heartbeat(heartbeat)
            .await
            .context("send Node heartbeat")?;
        match response.status {
            NodeHeartbeatStatus::Accepted => Ok(()),
            NodeHeartbeatStatus::ResetRequired => self.reset_and_reregister().await,
        }
    }

    /// Retries failed heartbeats without closing placement. A transport error
    /// is not a reset command; the gate closes only on `reset_required`.
    pub async fn run(
        &self,
        heartbeat_source: Arc<dyn NodeHeartbeatSource>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        while let Err(error) = self.register_until_ready().await {
            tracing::warn!(%error, "semantic Node registration failed; retrying");
            if wait_or_shutdown(self.retry_interval, &mut shutdown).await {
                return Ok(());
            }
        }
        loop {
            if wait_or_shutdown(self.heartbeat_interval, &mut shutdown).await {
                return Ok(());
            }
            loop {
                let heartbeat = heartbeat_source.snapshot().await?;
                match self.heartbeat_once(heartbeat).await {
                    Ok(()) => break,
                    Err(error) => {
                        tracing::warn!(%error, "semantic Node heartbeat failed; retrying");
                        if wait_or_shutdown(self.retry_interval, &mut shutdown).await {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    async fn reset_and_reregister(&self) -> anyhow::Result<()> {
        self.placement_gate.close();
        if !self.reset_completed_waiting.swap(true, Ordering::AcqRel) {
            if let Err(error) = self.reset.reset_all_cats().await {
                self.reset_completed_waiting.store(false, Ordering::Release);
                return Err(error).context("reset all local Cats");
            }
        }
        let mut completed = self.registration.clone();
        completed.reset_completed = true;
        let response = self
            .transport
            .register(completed)
            .await
            .context("report completed Node reset")?;
        anyhow::ensure!(
            response.node.node_id == self.registration.node_id,
            "completed reset response returned another node_id"
        );
        match response.status {
            NodeRegistrationStatus::Registered | NodeRegistrationStatus::AlreadyRegistered
                if response.node.status == NodeStatus::Running =>
            {
                self.reset_completed_waiting.store(false, Ordering::Release);
                self.placement_gate.open();
                Ok(())
            }
            NodeRegistrationStatus::ResetRequired
                if response.node.status == NodeStatus::ResetRequired =>
            {
                anyhow::bail!(
                    "Control is still recovering Cats from this reset Node; placement remains closed"
                )
            }
            _ => anyhow::bail!("Control returned an invalid completed-reset response"),
        }
    }
}

async fn wait_or_shutdown(
    duration: Duration,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        result = shutdown.changed() => result.is_err() || *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use cats_protocol::runtime_reconciliation::Id;
    use cats_protocol::semantic_control::{NodeName, NodeView, NodedControlEndpoint};

    use super::*;

    fn registration() -> NodeRegistrationRequest {
        NodeRegistrationRequest {
            node_id: Id::new("node_test").expect("node id"),
            node_name: NodeName::new("worker-test").expect("node name"),
            control_endpoint: NodedControlEndpoint::new("http://127.0.0.1:7001")
                .expect("control endpoint"),
            vendor: "aws".to_string(),
            region: "us-east-1".to_string(),
            zone: "us-east-1a".to_string(),
            instance_id: "i-test".to_string(),
            machine_type: "m7i.large".to_string(),
            node_version: "1.0.0".to_string(),
            reset_completed: false,
        }
    }

    fn response(
        status: NodeRegistrationStatus,
        node_status: NodeStatus,
    ) -> NodeRegistrationResponse {
        let request = registration();
        NodeRegistrationResponse {
            status,
            node: NodeView {
                node_id: request.node_id,
                node_name: request.node_name,
                control_endpoint: request.control_endpoint,
                vendor: request.vendor,
                region: request.region,
                zone: request.zone,
                instance_id: request.instance_id,
                machine_type: request.machine_type,
                node_version: request.node_version,
                status: node_status,
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        }
    }

    struct MockTransport {
        registrations: Mutex<VecDeque<NodeRegistrationResponse>>,
        heartbeats: Mutex<VecDeque<NodeHeartbeatResponse>>,
        requests: Mutex<Vec<NodeRegistrationRequest>>,
    }

    impl SemanticNodeTransport for MockTransport {
        fn register(
            &self,
            request: NodeRegistrationRequest,
        ) -> NodeClientFuture<NodeRegistrationResponse> {
            self.requests.lock().expect("lock requests").push(request);
            let response = self
                .registrations
                .lock()
                .expect("lock registrations")
                .pop_front();
            Box::pin(async move { Ok(response.expect("registration response")) })
        }

        fn heartbeat(
            &self,
            _request: NodeHeartbeatRequest,
        ) -> NodeClientFuture<NodeHeartbeatResponse> {
            let response = self.heartbeats.lock().expect("lock heartbeats").pop_front();
            Box::pin(async move { Ok(response.expect("heartbeat response")) })
        }

        fn report_usage(
            &self,
            request: IngestUsageCheckpointsRequest,
        ) -> NodeClientFuture<IngestUsageCheckpointsResponse> {
            let results = request
                .checkpoints
                .iter()
                .map(
                    |checkpoint| cats_protocol::metering::UsageCheckpointIngestResult {
                        event_id: checkpoint.event_id.clone(),
                        outcome: cats_protocol::metering::UsageCheckpointIngestOutcome::Accepted,
                        reason: None,
                    },
                )
                .collect::<Vec<_>>();
            Box::pin(async move {
                Ok(IngestUsageCheckpointsResponse {
                    accepted: results.len() as u64,
                    duplicates: 0,
                    rejected: Vec::new(),
                    results,
                })
            })
        }
    }

    struct MockReset {
        calls: Mutex<u32>,
        gate: Arc<NodePlacementGate>,
        saw_closed_gate: AtomicBool,
    }

    impl NodeResetExecutor for MockReset {
        fn reset_all_cats(&self) -> NodeClientFuture<()> {
            *self.calls.lock().expect("lock reset calls") += 1;
            self.saw_closed_gate
                .store(!self.gate.is_open(), Ordering::Release);
            Box::pin(async { Ok(()) })
        }
    }

    fn heartbeat() -> NodeHeartbeatRequest {
        NodeHeartbeatRequest {
            node_id: Id::new("node_test").expect("node id"),
            node_reported_at_unix_ms: 1,
            reported_status: NodeStatus::Running,
            total_cpu: 8,
            cpu_utilized: 1.0,
            total_memory: 16,
            memory_utilized: 2,
            running_cat_count: 1,
            suspended_cat_count: 0,
            warm_cat_count: 0,
        }
    }

    #[tokio::test]
    async fn reset_required_closes_placement_until_cleanup_and_explicit_completion() {
        let transport = Arc::new(MockTransport {
            registrations: Mutex::new(VecDeque::from([response(
                NodeRegistrationStatus::AlreadyRegistered,
                NodeStatus::Running,
            )])),
            heartbeats: Mutex::new(VecDeque::from([NodeHeartbeatResponse {
                status: NodeHeartbeatStatus::ResetRequired,
            }])),
            requests: Mutex::new(Vec::new()),
        });
        let gate = Arc::new(NodePlacementGate::default());
        gate.open();
        let reset = Arc::new(MockReset {
            calls: Mutex::new(0),
            gate: gate.clone(),
            saw_closed_gate: AtomicBool::new(false),
        });
        let supervisor = SemanticNodeSupervisor::new(
            transport.clone(),
            reset.clone(),
            gate.clone(),
            registration(),
        )
        .expect("supervisor");

        supervisor.heartbeat_once(heartbeat()).await.expect("reset");

        assert!(gate.is_open());
        assert_eq!(*reset.calls.lock().expect("reset calls"), 1);
        assert!(reset.saw_closed_gate.load(Ordering::Acquire));
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].reset_completed);
    }

    #[tokio::test]
    async fn startup_resets_local_state_before_opening_placement() {
        let transport = Arc::new(MockTransport {
            registrations: Mutex::new(VecDeque::from([response(
                NodeRegistrationStatus::Registered,
                NodeStatus::Running,
            )])),
            heartbeats: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
        });
        let gate = Arc::new(NodePlacementGate::default());
        let reset = Arc::new(MockReset {
            calls: Mutex::new(0),
            gate: gate.clone(),
            saw_closed_gate: AtomicBool::new(false),
        });
        let supervisor =
            SemanticNodeSupervisor::new(transport, reset.clone(), gate.clone(), registration())
                .expect("supervisor")
                .with_intervals(Duration::from_millis(1), Duration::from_millis(1));

        supervisor.register_until_ready().await.expect("register");

        assert!(gate.is_open());
        assert_eq!(*reset.calls.lock().expect("reset calls"), 1);
    }
}

//! Production entry point for the signed Runtime spine cutover.
//!
//! The legacy [`crate::server`] remains available to the pre-cutover test
//! suite, but the shipped Node binary starts here. The first production
//! scanner covers the physical clean-slate sources, but MetadataStore remains
//! unavailable until Volume authority persists a pageable owner-Node index;
//! no production full inventory is claimed from point reads. The typed network
//! effect is composed only after an accepted full inventory, and its launch
//! port remains fail-closed until the signed VMM/volume reconciler lands. This
//! path does not construct `NodeRuntime`, adopt a legacy ledger, or run a
//! destructive residue/device sweep.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use cats_storage::authority::VolumeDataAuthority;

use crate::agent_registration::AgentRegistrationConfig;
use crate::ch::{ChConfig, ChNetwork};
use crate::runtime::reconciliation::{
    installed_clean_slate_scanner, InstalledCleanSlateProbeConfig,
};
use crate::runtime_spine::{
    ProductionRuntimeDesiredEffect, RuntimeLaunchPort, RuntimeSpineDeadlinePolicy,
    RuntimeSpineHttpClient, RuntimeSpineRunStep, RuntimeSpineRunner,
};

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Fail-closed endpoint for the next signed reconciliation slice. The
/// production effect plans, checkpoints, and prepares only after a
/// current-process full inventory is accepted. VMM/volume launch remains
/// unavailable until the identity-aware non-empty reconciler is composed.
struct UnavailableRuntimeLaunch;

impl crate::runtime_spine::runtime_launch_port_sealed::Sealed for UnavailableRuntimeLaunch {}

impl RuntimeLaunchPort for UnavailableRuntimeLaunch {
    fn launch(
        &self,
        _desired: &cats_api::runtime_reconciliation::DesiredRuntimeSpec,
        _network: &ChNetwork,
    ) -> anyhow::Result<()> {
        anyhow::bail!("signed Runtime VMM/volume launch port is not composed")
    }
}

pub struct SignedRuntimeCutoverConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub agent_registration: AgentRegistrationConfig,
    pub ch_config: ChConfig,
    pub blockd_binary: std::path::PathBuf,
    pub guest_agent_binary: std::path::PathBuf,
    pub metering_cgroup_root: Option<std::path::PathBuf>,
    /// Retained for the signed acquire/provision effect. It is deliberately
    /// not adapted into a metadata inventory proof: `load_volume` cannot list
    /// authority-only writers or bind them to this Node.
    pub volume_data_authority: Arc<dyn VolumeDataAuthority>,
    pub deadline_policy: RuntimeSpineDeadlinePolicy,
}

pub struct SignedRuntimeCutoverHandle {
    pub addr: std::net::SocketAddr,
    shutdown_runner: Option<tokio::sync::oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    runner_task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl SignedRuntimeCutoverHandle {
    /// Runs until process shutdown or a component failure. Shutdown first
    /// cancels and joins the effect and scanner workers, then joins the journal
    /// worker and drops its flock inside `RuntimeSpineRunner::shutdown`; only
    /// then is the local health listener stopped and the process allowed to
    /// return.
    pub async fn run_until_signal(mut self) -> anyhow::Result<()> {
        enum Stop {
            Signal(anyhow::Result<()>),
            Server(Result<anyhow::Result<()>, tokio::task::JoinError>),
            Runner(Result<anyhow::Result<()>, tokio::task::JoinError>),
        }

        let stop = tokio::select! {
            signal = shutdown_signal() => Stop::Signal(signal),
            result = &mut self.server_task => Stop::Server(result),
            result = &mut self.runner_task => Stop::Runner(result),
        };
        let (outcome, stop_server) = match stop {
            Stop::Signal(signal) => {
                self.request_runner_shutdown();
                let runner = join_result(
                    (&mut self.runner_task).await,
                    "join signed Runtime spine during shutdown",
                );
                (signal.and(runner), true)
            }
            Stop::Server(server) => {
                self.request_runner_shutdown();
                let runner = join_result(
                    (&mut self.runner_task).await,
                    "join signed Runtime spine after listener exit",
                );
                (
                    join_result(server, "signed Runtime health listener task stopped").and(runner),
                    false,
                )
            }
            Stop::Runner(runner) => {
                self.shutdown_runner.take();
                (
                    join_result(runner, "signed Runtime spine task stopped"),
                    true,
                )
            }
        };
        if stop_server {
            self.server_task.abort();
            let _ = (&mut self.server_task).await;
        }
        outcome
    }

    fn request_runner_shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown_runner.take() {
            let _ = shutdown.send(());
        }
    }
}

fn join_result(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    context: &'static str,
) -> anyhow::Result<()> {
    result.context(context)?
}

impl Drop for SignedRuntimeCutoverHandle {
    fn drop(&mut self) {
        self.request_runner_shutdown();
        self.server_task.abort();
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> anyhow::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = terminate.recv() => {}
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[derive(Clone)]
struct Readiness(Arc<AtomicBool>);

impl Readiness {
    fn closed() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

async fn health(State(readiness): State<Readiness>) -> (StatusCode, &'static str) {
    if readiness.is_ready() {
        (StatusCode::OK, "signed Runtime inventory attested")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "signed Runtime inventory is not attested",
        )
    }
}

fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .with_state(readiness)
}

pub async fn spawn_signed_runtime_cutover(
    config: SignedRuntimeCutoverConfig,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    // Reject an unrepresentable operator budget before registration, worker
    // construction, or listener binding can mutate external/local state.
    config
        .deadline_policy
        .deadlines_from(Instant::now())
        .context("validate signed Runtime startup deadlines")?;
    let session = config
        .agent_registration
        .register_until_session(&config.control_plane_url)
        .await
        .context("establish durable Agent session")?;
    #[cfg(not(test))]
    let client = RuntimeSpineHttpClient::for_production(
        &config.control_plane_url,
        &config.agent_registration,
    )?;
    #[cfg(test)]
    let client = if config.agent_registration.uses_loopback_transport_for_test() {
        RuntimeSpineHttpClient::for_loopback_test(
            &config.control_plane_url,
            config.agent_registration.runtime_request_signer(),
        )?
    } else {
        RuntimeSpineHttpClient::for_production(
            &config.control_plane_url,
            &config.agent_registration,
        )?
    };
    let scanner = installed_clean_slate_scanner(InstalledCleanSlateProbeConfig {
        state_directory: config.agent_registration.runtime_state_directory(),
        cloud_hypervisor_binary: config.ch_config.ch_bin.clone(),
        blockd_binary: config.blockd_binary,
        guest_agent_binary: config.guest_agent_binary,
        metering_cgroup_root: config.metering_cgroup_root,
    })
    .context("compose installed clean-slate inventory probes")?;
    let effect =
        ProductionRuntimeDesiredEffect::new(config.ch_config, Arc::new(UnavailableRuntimeLaunch));
    let runner = RuntimeSpineRunner::new_with_desired_effects(
        config.agent_registration.runtime_state_directory(),
        session,
        client,
        scanner,
        Arc::new(effect),
    )?;
    // Bind before spawning either owned task. If binding fails, `runner` drops
    // synchronously and no detached worker can outlive this failed startup.
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind signed Runtime health listener {}", config.listen))?;
    let addr = listener.local_addr()?;

    let readiness = Readiness::closed();
    let runner_readiness = readiness.clone();
    let (shutdown_runner, mut runner_shutdown) = tokio::sync::oneshot::channel();
    // This value owns the Host-global open-file-description lock acquired
    // before registration. Move the opaque authority into the runner task and
    // release it only after effect/scan cancellation and journal/flock join.
    // Keeping it merely in the Handle would release it early when Handle::drop
    // can only request (not await) that shutdown sequence.
    let registration_lease = config.agent_registration;
    let deadline_policy = config.deadline_policy;
    let runner_task = tokio::spawn(async move {
        let mut runner = runner;
        let run_result = tokio::select! {
            result = run_signed_spine(&mut runner, &runner_readiness, deadline_policy) => result,
            _ = &mut runner_shutdown => Ok(()),
        };
        runner_readiness.set(false);
        let shutdown_result = runner.shutdown().await;
        drop(registration_lease);
        match (run_result, shutdown_result) {
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error.into()),
            (Err(error), Err(shutdown)) => {
                Err(error.context(format!("signed Runtime worker shutdown failed: {shutdown}")))
            }
            (Ok(()), Ok(())) => Ok(()),
        }
    });

    let server_task = tokio::spawn(async move {
        axum::serve(listener, health_router(readiness))
            .await
            .context("serve signed Runtime health listener")
    });

    Ok(SignedRuntimeCutoverHandle {
        addr,
        shutdown_runner: Some(shutdown_runner),
        server_task,
        runner_task,
    })
}

async fn run_signed_spine(
    runner: &mut RuntimeSpineRunner,
    readiness: &Readiness,
    deadline_policy: RuntimeSpineDeadlinePolicy,
) -> anyhow::Result<()> {
    loop {
        // Both absolute deadlines start before dispatch into the runner. Time
        // spent waiting on its ordered journal/effect lanes is not refunded at
        // a later blocking boundary.
        let deadlines = deadline_policy.deadlines_from(Instant::now())?;
        let step = runner.run_once_with_deadlines(deadlines).await?;
        match apply_readiness_policy(step, readiness)? {
            RuntimeLoopAction::Continue => {}
            RuntimeLoopAction::RetryAfterDelay => tokio::time::sleep(RETRY_DELAY).await,
            RuntimeLoopAction::WaitForIdentityRepair => {
                // Credential/identity repair is external to the Agent session
                // state machine. Keep the process cordoned and alive so a
                // supervisor restart cannot silently replace the session.
                std::future::pending::<()>().await;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeLoopAction {
    Continue,
    RetryAfterDelay,
    WaitForIdentityRepair,
}

fn apply_readiness_policy(
    step: RuntimeSpineRunStep,
    readiness: &Readiness,
) -> anyhow::Result<RuntimeLoopAction> {
    match step {
        RuntimeSpineRunStep::DesiredAccepted => {
            // A fresh Desired must be reconciled and attested before the
            // process can advertise local readiness again.
            readiness.set(false);
            Ok(RuntimeLoopAction::Continue)
        }
        RuntimeSpineRunStep::ObservationAccepted { service_ready } => {
            readiness.set(service_ready);
            Ok(RuntimeLoopAction::Continue)
        }
        RuntimeSpineRunStep::ObservationReplayed
        | RuntimeSpineRunStep::EffectApplied { .. }
        | RuntimeSpineRunStep::EffectsApplied
        | RuntimeSpineRunStep::EffectRefreshInventory { .. }
        | RuntimeSpineRunStep::EffectReplanDesired { .. }
        | RuntimeSpineRunStep::DesiredInvalidated { .. } => {
            readiness.set(false);
            Ok(RuntimeLoopAction::Continue)
        }
        RuntimeSpineRunStep::RetryExact(_)
        | RuntimeSpineRunStep::ScanUnavailable(_)
        | RuntimeSpineRunStep::ScanIncomplete { .. }
        | RuntimeSpineRunStep::ScanDeadlineExceeded
        | RuntimeSpineRunStep::EffectRetryExact { .. }
        | RuntimeSpineRunStep::EffectUnavailable { .. }
        | RuntimeSpineRunStep::EffectDeadlineExceeded { .. } => {
            readiness.set(false);
            Ok(RuntimeLoopAction::RetryAfterDelay)
        }
        RuntimeSpineRunStep::SessionInvalid { status, error } => {
            readiness.set(false);
            anyhow::bail!("signed Runtime session was rejected with {status}: {error:?}");
        }
        RuntimeSpineRunStep::Rejected { status, error } => {
            readiness.set(false);
            anyhow::bail!("signed Runtime request was rejected with {status}: {error:?}");
        }
        RuntimeSpineRunStep::RouteUnavailable => {
            readiness.set(false);
            anyhow::bail!("signed Runtime routes are not deployed");
        }
        RuntimeSpineRunStep::EffectIdentityRepairRequired { cat_id } => {
            readiness.set(false);
            tracing::error!(%cat_id, "signed Runtime identity repair is required; Agent is cordoned");
            Ok(RuntimeLoopAction::WaitForIdentityRepair)
        }
        RuntimeSpineRunStep::EffectSessionReplacementRequired { cat_id } => {
            readiness.set(false);
            anyhow::bail!("signed Runtime session replacement is required for {cat_id}");
        }
        RuntimeSpineRunStep::EffectStopped { cat_id, reason } => {
            readiness.set(false);
            anyhow::bail!("signed Runtime effect stopped for {cat_id}: {reason:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::response::Response;
    use axum::routing::post;
    use cats_api::agent_registration::{
        Ed25519RequestSigner, JSON_CONTENT_TYPE, REGISTRATION_PATH,
    };
    use cats_api::runtime_reconciliation::{
        decode_agent_registration_attempt, encode_agent_session, AgentSession, AsciiText,
        ContractVersion, CredentialBinding, Epoch, GuestRuntimeProfileReceipt, Id, NodeBootId,
        NodeIdentity, NodeIdentityState, Sha256Digest, UnixMillis, DESIRED_READ_PATH,
    };
    use cats_storage::authority::{
        AuthorityError, RenewLeaseRequest, RenewLeaseResult, VolumeHeadCasRequest,
        VolumeHeadCasResult, VolumeRecord,
    };

    struct TestUnavailableVolumeDataAuthority;

    impl VolumeDataAuthority for TestUnavailableVolumeDataAuthority {
        fn load_volume(&self, _volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
            Err(AuthorityError::BackendUnknown)
        }

        fn renew_lease(
            &self,
            _request: &RenewLeaseRequest,
        ) -> Result<RenewLeaseResult, AuthorityError> {
            Err(AuthorityError::BackendUnknown)
        }

        fn compare_and_swap_head(
            &self,
            _request: &VolumeHeadCasRequest,
        ) -> Result<VolumeHeadCasResult, AuthorityError> {
            Err(AuthorityError::BackendUnknown)
        }
    }

    #[derive(Clone)]
    struct RegistrationStub {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn accept_registration(State(stub): State<RegistrationStub>, body: Bytes) -> Response {
        let attempt = decode_agent_registration_attempt(&body).unwrap();
        stub.calls.fetch_add(1, Ordering::SeqCst);
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: attempt.node_id,
            immutable_host_id: attempt.immutable_host_id,
            node_boot_id: attempt.node_boot_id,
            agent_instance_id: attempt.agent_instance_id,
            agent_session_epoch: Epoch::new(
                attempt
                    .expected_agent_session_epoch
                    .map_or(1, |epoch| epoch.get() + 1),
            )
            .unwrap(),
            registration_attempt_id: attempt.registration_attempt_id,
            guest_config_digest: attempt.guest_config_digest,
            lease_deadline_unix_ms: UnixMillis::new(1_900_000_060_000).unwrap(),
        };
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", JSON_CONTENT_TYPE)
            .body(Body::from(encode_agent_session(&session).unwrap()))
            .unwrap()
    }

    async fn hold_desired_read() -> StatusCode {
        std::future::pending().await
    }

    fn registration_config(
        state_path: std::path::PathBuf,
    ) -> anyhow::Result<AgentRegistrationConfig> {
        let signer = Ed25519RequestSigner::from_pkcs8_pem(
            Id::new("credential_cutover_a").unwrap(),
            include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
        )
        .unwrap();
        AgentRegistrationConfig::for_loopback_test(
            NodeIdentity {
                version: ContractVersion::V1,
                node_id: Id::new("node_cutover_a").unwrap(),
                immutable_host_id: Id::new("host_cutover_a").unwrap(),
                credential_id: signer.credential_id().clone(),
                credential_binding: CredentialBinding::PublicKey {
                    public_key_spki_sha256: signer.public_key_spki_sha256(),
                },
                state_path_id: Id::new("state_cutover_a").unwrap(),
                state: NodeIdentityState::Provisioned,
            },
            signer,
            state_path,
            NodeBootId::new("11111111111111111111111111111111").unwrap(),
            &GuestRuntimeProfileReceipt {
                version: ContractVersion::V1,
                kernel_digest: Sha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
                initramfs_digest: None,
                kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
                guest_agent_protocol_version: ContractVersion::V1,
            },
        )
    }

    fn test_ch_config() -> ChConfig {
        ChConfig {
            block_direct: false,
            ch_bin: "/opt/cats/bin/cloud-hypervisor".into(),
            kernel: "/opt/cats/release/guest/vmlinuz".into(),
            initramfs: None,
            boot_contract: None,
            cmdline: "console=hvc0 root=/dev/vda".into(),
            seed_image: None,
            block_path: crate::ch::BlockPath::KernelNbd,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin: "/usr/sbin/nbd-client".into(),
            nbd_devices: 64,
            ip_bin: "/usr/sbin/ip".into(),
        }
    }

    #[test]
    fn production_composition_uses_the_typed_network_adapter_only() {
        let source = include_str!("runtime_cutover.rs");
        assert!(source.contains("ProductionRuntimeDesiredEffect::new"));
        assert!(source.contains("installed_clean_slate_scanner"));
        assert!(source.contains("UnavailableRuntimeLaunch"));
        let placeholder_effect = ["Unavailable", "Desired", "Effect"].concat();
        let legacy_job = ["Node", "Job"].concat();
        let legacy_runtime = ["Node", "Runtime", "::", "new"].concat();
        assert!(!source.contains(&placeholder_effect));
        assert!(!source.contains(&legacy_job));
        assert!(!source.contains(&legacy_runtime));
    }

    #[tokio::test]
    async fn health_stays_closed_without_an_accepted_full_observation() {
        let readiness = Readiness::closed();
        let response = health(State(readiness.clone())).await;
        assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.1, "signed Runtime inventory is not attested");

        readiness.set(true);
        assert_eq!(health(State(readiness)).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn cutover_listener_exposes_no_legacy_mutation_surface() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, health_router(Readiness::closed()))
                .await
                .unwrap();
        });
        for path in [
            "/v1/jobs",
            "/v1/nodes/heartbeat",
            "/v1/nodes/register",
            "/v1/nodes/work-status",
            "/v1/internal/work/acquire",
            "/v1/internal/work/release",
        ] {
            let response = reqwest::get(format!("http://{address}{path}"))
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        }
        server.abort();
    }

    #[tokio::test]
    async fn runner_owns_host_lock_until_all_runtime_workers_are_joined() {
        let state_root = tempfile::tempdir().unwrap();
        let state_path = state_root.path().join("state");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_address = listener.local_addr().unwrap();
        let stub = RegistrationStub {
            calls: calls.clone(),
        };
        let control = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(REGISTRATION_PATH, post(accept_registration))
                    .route(DESIRED_READ_PATH, post(hold_desired_read))
                    .with_state(stub),
            )
            .await
            .unwrap();
        });
        let origin = format!("http://{control_address}");
        let registration = registration_config(state_path.clone()).unwrap();
        let mut handle = spawn_signed_runtime_cutover(SignedRuntimeCutoverConfig {
            listen: "127.0.0.1:0".into(),
            control_plane_url: origin.clone(),
            agent_registration: registration,
            ch_config: test_ch_config(),
            blockd_binary: "/opt/cats/bin/cats-blockd".into(),
            guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
            metering_cgroup_root: None,
            volume_data_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            deadline_policy: RuntimeSpineDeadlinePolicy::new(
                Duration::from_secs(5),
                Duration::from_secs(30),
            )
            .unwrap(),
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let session_path = state_path.join(crate::agent_registration::SESSION_RELATIVE_PATH);
        let first_session = std::fs::read(&session_path).unwrap();
        let first_epoch = cats_api::runtime_reconciliation::decode_agent_session(&first_session)
            .unwrap()
            .agent_session_epoch;
        assert_eq!(first_epoch.get(), 1);

        // Acquiring the Host lease precedes pending-attempt creation and every
        // network registration write. A competing process cannot replace the
        // active Agent's session and then discover the journal flock too late.
        assert!(registration_config(state_path.clone()).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(&session_path).unwrap(), first_session);

        handle.request_runner_shutdown();
        join_result(
            (&mut handle.runner_task).await,
            "join runner in Host lease regression",
        )
        .unwrap();

        // The task drops its opaque registration lease only after
        // RuntimeSpineRunner::shutdown has joined effect, scan and journal.
        let successor = registration_config(state_path).unwrap();
        let successor_session = successor.register_until_session(&origin).await.unwrap();
        assert_eq!(successor_session.agent_session_epoch.get(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(successor);
        control.abort();
    }

    #[tokio::test]
    async fn deadline_overflow_fails_before_registration_or_listener_binding() {
        let state_root = tempfile::tempdir().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_address = listener.local_addr().unwrap();
        let stub = RegistrationStub {
            calls: calls.clone(),
        };
        let control = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(REGISTRATION_PATH, post(accept_registration))
                    .with_state(stub),
            )
            .await
            .unwrap();
        });
        let result = spawn_signed_runtime_cutover(SignedRuntimeCutoverConfig {
            listen: "not-a-socket-address".into(),
            control_plane_url: format!("http://{control_address}"),
            agent_registration: registration_config(state_root.path().join("state")).unwrap(),
            ch_config: test_ch_config(),
            blockd_binary: "/opt/cats/bin/cats-blockd".into(),
            guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
            metering_cgroup_root: None,
            volume_data_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            deadline_policy: RuntimeSpineDeadlinePolicy::new(Duration::MAX, Duration::from_secs(1))
                .unwrap(),
        })
        .await;
        let Err(error) = result else {
            panic!("overflowing policy must fail before startup")
        };

        assert!(error
            .to_string()
            .contains("validate signed Runtime startup deadlines"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        control.abort();
    }

    #[test]
    fn unavailable_or_residue_scan_can_never_open_readiness() {
        let readiness = Readiness::closed();
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ScanIncomplete {
                    unavailable_sources: vec![
                        cats_api::runtime_reconciliation::InventorySource::MetadataStore,
                    ],
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::RetryAfterDelay
        );
        assert!(!readiness.is_ready());

        readiness.set(true);
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ScanUnavailable(anyhow::anyhow!("physical residue")),
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::RetryAfterDelay
        );
        assert!(!readiness.is_ready());
    }

    #[test]
    fn only_a_nonempty_full_acceptance_opens_readiness() {
        let readiness = Readiness::closed();
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ObservationAccepted {
                    service_ready: false,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(!readiness.is_ready());

        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ObservationAccepted {
                    service_ready: true,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(readiness.is_ready());
    }

    #[test]
    fn identity_repair_cordons_without_requesting_session_replacement() {
        let readiness = Readiness::closed();
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::EffectIdentityRepairRequired {
                    cat_id: Id::new("cat_a").unwrap(),
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::WaitForIdentityRepair
        );
        assert!(!readiness.is_ready());
    }
}

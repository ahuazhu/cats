//! Production entry point for the signed Runtime spine cutover.
//!
//! The legacy [`crate::server`] remains available to the pre-cutover test
//! suite, but the shipped Node binary starts here. The first production
//! scanner covers the physical clean-slate sources, including the bounded
//! owner-Node Volume authority snapshot; no production full inventory is
//! claimed from point reads. The first production effect is exactly one A22
//! signed NormalAcquire after an accepted full inventory. The composed Root
//! prefix now continues through exact target-control handoff and the
//! checkpoint-only `PrepareDevice` transition, old-process retirement, and
//! one-effect start/adoption of the exact serving blockd. Both frontends then
//! converge through independent device, Host-network reservation/TAP, and
//! checkpoint-only StartRuntime CID rounds. Physical VMM launch and Guest
//! handshake remain later fresh-inventory effects.
//! This path does not construct `NodeRuntime`, adopt a legacy ledger, or run a
//! destructive residue/device sweep.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use cats_storage::authority::{RuntimeVolumeInventoryAuthority, VolumeDataAuthority};
use cats_storage::BlobStore;

use crate::agent_registration::AgentRegistrationConfig;
use crate::ch::{BlockPath, ChConfig};
use crate::runtime::reconciliation::{
    installed_clean_slate_scanner, installed_root_process_effect_ports, AdmissionCellRegistry,
    AuthorizedBlockdLaunchConfig, ControlSignedNormalAcquireClient, InstalledCleanSlateProbeConfig,
    KernelNbdClientCleanupOwner, KernelNbdInventoryConfig, RootProvisionSystemdConfig,
    RuntimeVolumeTransitionHttpClient, ServingPrepareFrontend, SignedRunningAcquireEffect,
    SignedRunningEffect, SignedRunningHostConfig, SignedRunningProcessPorts,
    SignedRunningPublicationRecovery, VmmLaunchArtifactPaths,
};
use crate::runtime_spine::{
    RuntimeEffectResourceOwner, RuntimeInventoryScanner, RuntimeSpineDeadlinePolicy,
    RuntimeSpineHttpClient, RuntimeSpineRunStep, RuntimeSpineRunner,
};

const RETRY_DELAY: Duration = Duration::from_secs(1);

pub struct SignedRuntimeCutoverConfig {
    pub listen: String,
    pub control_plane_url: String,
    pub agent_registration: AgentRegistrationConfig,
    pub ch_config: ChConfig,
    pub authorized_blockd_launch: AuthorizedBlockdLaunchConfig,
    pub guest_agent_binary: std::path::PathBuf,
    pub metering_cgroup_root: Option<std::path::PathBuf>,
    /// Retained for the signed acquire/provision effect. It is deliberately
    /// not adapted into a metadata inventory proof: `load_volume` cannot list
    /// authority-only writers or bind them to this Node.
    pub volume_data_authority: Arc<dyn VolumeDataAuthority>,
    /// Enumeration-only authority used by the full inventory scanner. It is
    /// separate from blockd's exact-grant data-plane port.
    pub volume_inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority>,
    /// Read-only image manifest authority used to bind the exact expected
    /// provisioned root before the first lease mutation.
    pub blob_store: Arc<dyn BlobStore>,
    pub volume_lease_duration_ms: u64,
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
    spawn_signed_runtime_cutover_with_scanner(config, None).await
}

async fn spawn_signed_runtime_cutover_with_scanner(
    config: SignedRuntimeCutoverConfig,
    scanner_override: Option<Arc<dyn RuntimeInventoryScanner>>,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    spawn_signed_runtime_cutover_with_overrides(config, scanner_override, None).await
}

async fn spawn_signed_runtime_cutover_with_overrides(
    config: SignedRuntimeCutoverConfig,
    scanner_override: Option<Arc<dyn RuntimeInventoryScanner>>,
    resource_owner_override: Option<Arc<dyn RuntimeEffectResourceOwner>>,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    // Reject an unrepresentable operator budget before registration, worker
    // construction, or listener binding can mutate external/local state.
    config
        .deadline_policy
        .deadlines_from(Instant::now())
        .context("validate signed Runtime startup deadlines")?;
    SignedRunningAcquireEffect::validate_lease_duration(config.volume_lease_duration_ms)
        .context("compose one-step signed Running acquire")?;
    let root_provision_systemd =
        RootProvisionSystemdConfig::new(config.authorized_blockd_launch.clone())
            .context("compose credentialless root-provision systemd process owner")?;
    let effect_root_provision_systemd = root_provision_systemd.clone();
    #[cfg(target_os = "linux")]
    let kernel_nbd_inventory = match config.ch_config.block_path {
        BlockPath::KernelNbd => Some(
            KernelNbdInventoryConfig::installed(
                config.agent_registration.runtime_state_directory(),
                config.ch_config.nbd_client_bin.clone(),
                config.ch_config.nbd_devices,
            )
            .context("compose installed kernel-NBD inventory")?,
        ),
        BlockPath::VhostUser => None,
    };
    #[cfg(not(target_os = "linux"))]
    let kernel_nbd_inventory: Option<KernelNbdInventoryConfig> = None;
    let kernel_nbd_cleanup_owner = Arc::new(KernelNbdClientCleanupOwner::new());
    let effect_vmm_launch_artifacts = VmmLaunchArtifactPaths {
        launcher_executable: config.ch_config.vmm_launcher_bin.clone(),
        vmm_executable: config.ch_config.ch_bin.clone(),
        kernel: config.ch_config.kernel.clone(),
        initramfs: config.ch_config.initramfs.clone(),
        kernel_cmdline: config.ch_config.cmdline.clone(),
    };
    let installed_probe_config = InstalledCleanSlateProbeConfig {
        state_directory: config.agent_registration.runtime_state_directory(),
        cloud_hypervisor_binary: config.ch_config.ch_bin.clone(),
        blockd_binary: config.authorized_blockd_launch.blockd_binary.clone(),
        guest_agent_binary: config.guest_agent_binary.clone(),
        ip_binary: config.ch_config.ip_bin.clone(),
        kernel_nbd_inventory: kernel_nbd_inventory.clone(),
        metering_cgroup_root: config.metering_cgroup_root.clone(),
        volume_inventory_authority: Arc::clone(&config.volume_inventory_authority),
        blob_store: Arc::clone(&config.blob_store),
        root_provision_systemd,
    };
    let effect_root_process_ports =
        installed_root_process_effect_ports(installed_probe_config.clone())
            .context("compose sealed root-process effect inventory")?;
    let effect_prepare_frontend = match config.ch_config.block_path {
        BlockPath::KernelNbd => {
            #[cfg(target_os = "linux")]
            {
                ServingPrepareFrontend::kernel_nbd_from_inventory(
                    kernel_nbd_inventory
                        .clone()
                        .context("kernel-NBD frontend lacks installed inventory config")?,
                    config.ch_config.block_direct,
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                ServingPrepareFrontend::kernel_nbd(
                    config.agent_registration.runtime_state_directory(),
                    config.ch_config.nbd_client_bin.clone(),
                    config.ch_config.nbd_devices,
                    config.ch_config.block_direct,
                )
                .context("compose kernel-NBD PrepareDevice reservation")?
            }
        }
        BlockPath::VhostUser => ServingPrepareFrontend::vhost_user_blk(
            config.ch_config.vhost_user_queues,
            config.ch_config.vhost_user_queue_size,
        )
        .context("compose vhost-user PrepareDevice plan")?,
    };
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
    let scanner = match scanner_override {
        Some(scanner) => scanner,
        None => installed_clean_slate_scanner(installed_probe_config)
            .context("compose installed clean-slate inventory probes")?,
    };
    let effect_registration = config.agent_registration.clone();
    let effect_control_plane_url = config.control_plane_url.clone();
    let effect_volume_authority = Arc::clone(&config.volume_data_authority);
    let effect_blob_store = Arc::clone(&config.blob_store);
    let effect_lease_duration_ms = config.volume_lease_duration_ms;
    let effect_state_directory = config.agent_registration.runtime_state_directory();
    let admission_registry = AdmissionCellRegistry::for_state_directory(&effect_state_directory);
    let effect_network_ip_binary = config.ch_config.ip_bin.clone();
    let effect_kernel_nbd_inventory = kernel_nbd_inventory;
    let effect_kernel_nbd_cleanup_owner = Arc::clone(&kernel_nbd_cleanup_owner);
    let runner_effect_resource_owner = resource_owner_override.unwrap_or_else(|| {
        Arc::clone(&kernel_nbd_cleanup_owner) as Arc<dyn RuntimeEffectResourceOwner>
    });
    let runner = tokio::task::spawn_blocking(move || {
        #[cfg(not(test))]
        let volume_transition_transport = RuntimeVolumeTransitionHttpClient::for_production(
            &effect_control_plane_url,
            &effect_registration,
        )?;
        #[cfg(test)]
        let volume_transition_transport = if effect_registration.uses_loopback_transport_for_test()
        {
            RuntimeVolumeTransitionHttpClient::for_loopback_test(
                &effect_control_plane_url,
                effect_registration.runtime_request_signer(),
            )?
        } else {
            RuntimeVolumeTransitionHttpClient::for_production(
                &effect_control_plane_url,
                &effect_registration,
            )?
        };
        let acquire = SignedRunningAcquireEffect::new(
            Arc::new(ControlSignedNormalAcquireClient::new(
                volume_transition_transport,
            )),
            Arc::clone(&effect_volume_authority),
            Arc::clone(&effect_blob_store),
            effect_lease_duration_ms,
        )
        .context("compose one-step signed Running acquire")?;
        let effect = SignedRunningEffect::platform(
            acquire,
            Arc::clone(&effect_volume_authority),
            effect_blob_store,
            SignedRunningHostConfig::new(
                effect_root_provision_systemd,
                effect_state_directory.clone(),
                effect_network_ip_binary,
                effect_kernel_nbd_inventory,
                Arc::clone(&effect_kernel_nbd_cleanup_owner),
                effect_vmm_launch_artifacts,
            ),
            SignedRunningProcessPorts::new(
                Arc::clone(&effect_root_process_ports.retirement),
                Arc::clone(&effect_root_process_ports.global),
                Arc::clone(&effect_root_process_ports.serving),
                Arc::clone(&effect_root_process_ports.vmm),
                Arc::clone(&effect_root_process_ports.vmm_cid),
            ),
            effect_prepare_frontend,
            admission_registry,
        )
        .context("compose signed Running root provision prefix")?;
        let recovery = SignedRunningPublicationRecovery::new(Arc::clone(&effect_volume_authority));
        RuntimeSpineRunner::new_with_recovery_desired_effects_and_resource_owner(
            effect_state_directory,
            session,
            client,
            scanner,
            Arc::new(recovery),
            Arc::new(effect),
            runner_effect_resource_owner,
        )
        .map_err(anyhow::Error::from)
    })
    .await
    .context("join signed Runtime runner construction")??;
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
        | RuntimeSpineRunStep::PreScanRecovered { .. }
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
        | RuntimeSpineRunStep::PreScanRecoveryUnavailable(_)
        | RuntimeSpineRunStep::PreScanRecoveryDeadlineExceeded
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
        decode_agent_registration_attempt, decode_desired_read_request, decode_node_observation,
        decode_runtime_checkpoint, decode_runtime_volume_transition_request, encode_agent_session,
        encode_desired_read_snapshot, encode_observation_acceptance,
        encode_runtime_volume_transition_success, spec_digest, AcquireOrigin, AgentSession,
        AsciiText, AssignedKind, AssignedPlacement, ContractVersion, CredentialBinding,
        DesiredReadSnapshot, DesiredRuntimeSpec, DiskKind, Durability, Epoch, FenceEpoch,
        Generation, GuestDeviceIdentity, GuestRuntimeProfileReceipt, Id, Ipv4Address,
        IsolatedIpv4Kind, LastVolumeTransition, MacAddress, NetworkConfig, NodeBootId,
        NodeIdentity, NodeIdentityState, NormalAcquireRequest, NormalAcquireResult,
        ObservationAcceptance, ObservationInventoryAcceptance, ReconcileStep, RemoteHead, Revision,
        RuntimeConfig, RuntimeTarget, RuntimeTransition, RuntimeVolumeTransition,
        RuntimeVolumeTransitionOutcome, RuntimeVolumeTransitionRequest,
        RuntimeVolumeTransitionSuccess, SessionBinding, Sha256Digest, UnixMillis, VolumeAccess,
        VolumeAcquire, VolumeAcquireRequest, VolumeAdminState, VolumeDisposition, VolumeIntent,
        VolumeLeaseGrant, DESIRED_READ_PATH, OBSERVATION_PATH, RUNTIME_VOLUME_TRANSITION_PATH,
    };
    use cats_storage::authority::{
        AuthorityError, NodeVolumeInventorySnapshot, RenewLeaseRequest, RenewLeaseResult,
        VolumeHeadCasRequest, VolumeHeadCasResult, VolumeRecord,
    };
    use cats_storage::{
        encode_image_manifest, AdapterConfig, AdapterSelection, BlobError, ImageManifestV1,
        LowerHexSha256,
    };
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;

    use crate::runtime::reconciliation::{
        clean_slate_scanner_with_volume_authority_and_blob_for_test, runtime_checkpoint_path,
        TestCleanSlateProbeConfig,
    };
    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::{
        RetainedManagedVmmLaunchRoot, RetainedManagedVmmSocketRoot, VmmSocketReceiptStore,
        INSTALLED_VMM_SOCKET_ROOT, VMM_LAUNCH_FILE_NAMESPACE,
    };

    struct StubbornEffectChildOwner {
        pending: AtomicBool,
        shutdowns: std::sync::atomic::AtomicUsize,
    }

    impl crate::runtime_spine::effect_resource_owner_sealed::Sealed for StubbornEffectChildOwner {}

    impl RuntimeEffectResourceOwner for StubbornEffectChildOwner {
        fn poll(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn has_pending(&self) -> bool {
            self.pending.load(Ordering::Acquire)
        }

        fn shutdown_until(&self, deadline: Instant) -> anyhow::Result<()> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            while self.pending.load(Ordering::Acquire) {
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "stubborn effect child outlived its shutdown deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        }
    }

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

    impl RuntimeVolumeInventoryAuthority for TestUnavailableVolumeDataAuthority {
        fn load_node_volume_inventory(
            &self,
            _node_id: &Id,
            _candidate_volume_ids: &std::collections::BTreeSet<Id>,
        ) -> Result<NodeVolumeInventorySnapshot, AuthorityError> {
            Err(AuthorityError::BackendUnknown)
        }
    }

    struct TestUnavailableBlobStore;

    impl BlobStore for TestUnavailableBlobStore {
        fn put_immutable(&self, key: &str, _data: &[u8]) -> Result<(), BlobError> {
            Err(test_blob_error(key))
        }

        fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
            Err(test_blob_error(key))
        }

        fn exists(&self, key: &str) -> Result<bool, BlobError> {
            Err(test_blob_error(key))
        }

        fn delete(&self, key: &str) -> Result<(), BlobError> {
            Err(test_blob_error(key))
        }

        fn list(&self, prefix: &str) -> Result<Vec<String>, BlobError> {
            Err(test_blob_error(prefix))
        }
    }

    fn test_blob_error(key: &str) -> BlobError {
        BlobError::Backend {
            key: key.to_owned(),
            message: "test blob store is unavailable".to_owned(),
        }
    }

    fn test_authorized_blockd_launch() -> AuthorizedBlockdLaunchConfig {
        AuthorizedBlockdLaunchConfig {
            blockd_binary: "/opt/cats/bin/cats-blockd".into(),
            metadata_store: AdapterSelection::new(
                "postgres",
                AdapterConfig::from_pairs([("url-file", "/run/cats/postgres.url")]).unwrap(),
            ),
            object_store: AdapterSelection::new(
                "aws-s3",
                AdapterConfig::from_pairs([("bucket", "cats-test")]).unwrap(),
            ),
            max_staged_bytes: cats_api::blockd::DEFAULT_MAX_STAGED_BYTES,
            max_staged_packs: cats_api::blockd::DEFAULT_MAX_STAGED_PACKS,
            max_local_bytes: cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES,
        }
    }

    struct CompositionAuthority {
        record: std::sync::Mutex<VolumeRecord>,
        mutations: std::sync::atomic::AtomicUsize,
    }

    impl CompositionAuthority {
        fn new(desired: &DesiredRuntimeSpec) -> Self {
            let volume = &desired.volumes[0];
            let VolumeAcquire::Normal {
                expected_unowned_epoch,
                ..
            } = volume.acquire
            else {
                unreachable!("composition fixture uses normal acquire")
            };
            Self {
                record: std::sync::Mutex::new(VolumeRecord {
                    volume_id: volume.volume_id.clone(),
                    size_bytes: volume.size_bytes,
                    durability: volume.durability,
                    admin_state: VolumeAdminState::Active,
                    head: blank_head(),
                    lease_owner: None,
                    lease_epoch: expected_unowned_epoch,
                    lease_expires_at: None,
                    last_transition: None,
                }),
                mutations: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn acquire(
            &self,
            request: &RuntimeVolumeTransitionRequest,
        ) -> RuntimeVolumeTransitionSuccess {
            let RuntimeVolumeTransition::Acquire {
                request:
                    VolumeAcquireRequest::Normal {
                        volume_id,
                        transition_id,
                        attachment_id,
                        expected_unowned_epoch,
                        desired_revision,
                        placement_epoch,
                        lease_duration_ms,
                    },
            } = &request.transition
            else {
                panic!("composition A22 supports one normal acquire")
            };
            let resulting_epoch = FenceEpoch::new(expected_unowned_epoch.get() + 1).unwrap();
            let lease_expires_at = UnixMillis::new(1_900_000_090_000).unwrap();
            let normal_request = NormalAcquireRequest {
                volume_id: volume_id.clone(),
                transition_id: transition_id.clone(),
                attachment_id: attachment_id.clone(),
                expected_unowned_epoch: *expected_unowned_epoch,
                desired_revision: *desired_revision,
                placement_epoch: *placement_epoch,
                lease_duration_ms: *lease_duration_ms,
            };
            let result = NormalAcquireResult {
                volume_id: volume_id.clone(),
                transition_id: transition_id.clone(),
                attachment_id: attachment_id.clone(),
                resulting_epoch,
                resulting_head: blank_head(),
                lease_expires_at,
            };
            let mut record = self.record.lock().unwrap();
            if record.last_transition.is_none() {
                self.mutations.fetch_add(1, Ordering::SeqCst);
                record.lease_owner = Some(attachment_id.clone());
                record.lease_epoch = resulting_epoch;
                record.lease_expires_at = Some(lease_expires_at);
                record.last_transition = Some(LastVolumeTransition::NormalAcquire {
                    request: normal_request.clone(),
                    result: result.clone(),
                });
            } else {
                assert_eq!(
                    record.last_transition,
                    Some(LastVolumeTransition::NormalAcquire {
                        request: normal_request.clone(),
                        result: result.clone(),
                    })
                );
            }
            RuntimeVolumeTransitionSuccess {
                version: ContractVersion::V1,
                session: request.session.clone(),
                cat_id: request.cat_id.clone(),
                desired_revision: request.desired_revision,
                spec_digest: request.spec_digest.clone(),
                placement: request.placement.clone(),
                outcome: RuntimeVolumeTransitionOutcome::LeaseGranted {
                    grant: VolumeLeaseGrant {
                        volume_id: volume_id.clone(),
                        attachment_id: attachment_id.clone(),
                        attachment_epoch: resulting_epoch,
                        size_bytes: record.size_bytes,
                        durability: record.durability,
                        head: record.head.clone(),
                        lease_expires_at,
                        acquire_origin: AcquireOrigin::Normal {
                            transition_id: transition_id.clone(),
                        },
                    },
                },
            }
        }
    }

    impl VolumeDataAuthority for CompositionAuthority {
        fn load_volume(&self, volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
            let record = self.record.lock().unwrap().clone();
            if &record.volume_id == volume_id {
                Ok(record)
            } else {
                Err(AuthorityError::NotFound)
            }
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

    struct CompositionBlobStore {
        manifest: Vec<u8>,
    }

    impl CompositionBlobStore {
        fn new(desired: &DesiredRuntimeSpec) -> Self {
            Self {
                manifest: encode_image_manifest(&ImageManifestV1 {
                    version: 1,
                    image_id: LowerHexSha256::from_digest(&desired.runtime.boot_image_digest),
                    size_bytes: desired.volumes[0].size_bytes,
                    chunks: Vec::new(),
                })
                .unwrap(),
            }
        }
    }

    impl BlobStore for CompositionBlobStore {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> Result<(), BlobError> {
            unreachable!("composition only reads the image manifest")
        }

        fn get(&self, _key: &str) -> Result<Vec<u8>, BlobError> {
            Ok(self.manifest.clone())
        }

        fn exists(&self, _key: &str) -> Result<bool, BlobError> {
            Ok(true)
        }

        fn delete(&self, _key: &str) -> Result<(), BlobError> {
            unreachable!("composition only reads the image manifest")
        }

        fn list(&self, _prefix: &str) -> Result<Vec<String>, BlobError> {
            unreachable!("composition only reads the image manifest")
        }
    }

    #[derive(Clone)]
    struct CompositionControl {
        desired: DesiredRuntimeSpec,
        authority: Arc<CompositionAuthority>,
        registrations: Arc<std::sync::atomic::AtomicUsize>,
        desired_reads: Arc<std::sync::atomic::AtomicUsize>,
        observations: Arc<std::sync::atomic::AtomicUsize>,
        a22_calls: Arc<std::sync::atomic::AtomicUsize>,
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

    async fn composition_registration(
        State(control): State<CompositionControl>,
        body: Bytes,
    ) -> Response {
        let attempt = decode_agent_registration_attempt(&body).unwrap();
        control.registrations.fetch_add(1, Ordering::SeqCst);
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
            lease_deadline_unix_ms: UnixMillis::new(1_900_000_120_000).unwrap(),
        };
        json_response(encode_agent_session(&session).unwrap())
    }

    async fn composition_desired(
        State(control): State<CompositionControl>,
        body: Bytes,
    ) -> Response {
        let request = decode_desired_read_request(&body).unwrap();
        control.desired_reads.fetch_add(1, Ordering::SeqCst);
        let snapshot = DesiredReadSnapshot {
            version: ContractVersion::V1,
            session: request.session,
            request_sequence: request.request_sequence,
            read_position: request.request_sequence,
            issued_at_unix_ms: UnixMillis::new(1_900_000_000_000).unwrap(),
            expires_at_unix_ms: UnixMillis::new(1_900_000_110_000).unwrap(),
            desired_specs: vec![control.desired],
        };
        json_response(encode_desired_read_snapshot(&snapshot).unwrap())
    }

    async fn composition_observation(
        State(control): State<CompositionControl>,
        body: Bytes,
    ) -> Response {
        let observation = decode_node_observation(&body).unwrap();
        control.observations.fetch_add(1, Ordering::SeqCst);
        let accepted_at = UnixMillis::new(1_900_000_010_000).unwrap();
        let acceptance = ObservationAcceptance {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: observation.node_id.clone(),
                node_boot_id: observation.node_boot_id.clone(),
                agent_instance_id: observation.agent_instance_id.clone(),
                agent_session_epoch: observation.agent_session_epoch,
            },
            observation_id: observation.observation_id,
            heartbeat_sequence: observation.heartbeat_sequence,
            accepted_at_unix_ms: accepted_at,
            lease_deadline_unix_ms: UnixMillis::new(1_900_000_120_000).unwrap(),
            inventory: ObservationInventoryAcceptance::Full {
                attestation: cats_api::runtime_reconciliation::AdmissionInventoryAttestation {
                    version: ContractVersion::V1,
                    node_id: observation.node_id,
                    agent_session_epoch: observation.agent_session_epoch,
                    inventory_epoch: observation.inventory_epoch,
                    inventory_digest: observation.inventory_digest.unwrap(),
                    inventory_read_position: observation.inventory_read_position.unwrap(),
                    accepted_at_unix_ms: accepted_at,
                },
            },
        };
        json_response(encode_observation_acceptance(&acceptance).unwrap())
    }

    async fn composition_a22(State(control): State<CompositionControl>, body: Bytes) -> Response {
        let request = decode_runtime_volume_transition_request(&body).unwrap();
        control.a22_calls.fetch_add(1, Ordering::SeqCst);
        let success = control.authority.acquire(&request);
        json_response(encode_runtime_volume_transition_success(&success).unwrap())
    }

    fn json_response(body: Vec<u8>) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", JSON_CONTENT_TYPE)
            .header("cache-control", "no-store")
            .body(Body::from(body))
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
        let config = AgentRegistrationConfig::for_loopback_test(
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
            state_path.clone(),
            NodeBootId::new("11111111111111111111111111111111").unwrap(),
            &GuestRuntimeProfileReceipt {
                version: ContractVersion::V1,
                kernel_digest: Sha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
                initramfs_digest: None,
                kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
                guest_agent_protocol_version: ContractVersion::V1,
            },
        )?;
        #[cfg(target_os = "linux")]
        provision_runtime_namespaces_for_test(&state_path)?;
        Ok(config)
    }

    #[cfg(target_os = "linux")]
    fn provision_runtime_namespaces_for_test(state_path: &std::path::Path) -> anyhow::Result<()> {
        let state = crate::state_directory::StateDirectory::unanchored(state_path.to_path_buf());
        let launch = state.path().join(VMM_LAUNCH_FILE_NAMESPACE);
        if !launch.exists() {
            std::fs::create_dir(&launch)?;
            std::fs::set_permissions(&launch, std::fs::Permissions::from_mode(0o700))?;
        }
        RetainedManagedVmmLaunchRoot::open_existing(state.clone())?;
        if VmmSocketReceiptStore::open_existing(state.clone()).is_err() {
            VmmSocketReceiptStore::provision_for_test(state.clone())?;
        }
        let installed = std::path::Path::new(INSTALLED_VMM_SOCKET_ROOT);
        if !installed.exists() {
            std::fs::create_dir_all(installed.parent().unwrap())?;
            RetainedManagedVmmSocketRoot::provision_for_test(installed)?;
        } else {
            RetainedManagedVmmSocketRoot::open_installed()?;
        }
        Ok(())
    }

    fn test_ch_config() -> ChConfig {
        ChConfig {
            block_direct: false,
            vmm_launcher_bin: "/opt/cats/bin/cats-vmm-launcher".into(),
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

    fn composition_desired_spec() -> DesiredRuntimeSpec {
        let volume = VolumeIntent {
            volume_intent_id: Id::new("vint_root").unwrap(),
            disk_id: Id::new("disk_root").unwrap(),
            volume_id: Id::new("vol_root").unwrap(),
            attachment_id: Id::new("att_root").unwrap(),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-root").unwrap(),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: cats_api::runtime_reconciliation::RandomId128::new(
                    "22222222222222222222222222222222",
                )
                .unwrap(),
                expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        };
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: Id::new("ws_01").unwrap(),
            cat_id: Id::new("cat_01").unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: Id::new("node_cutover_a").unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: Id::new("net_01").unwrap(),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: vec![volume],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    fn blank_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn composition_scanner(
        root: &std::path::Path,
        state_path: &std::path::Path,
        authority: Arc<CompositionAuthority>,
        blob: Arc<CompositionBlobStore>,
    ) -> Arc<dyn RuntimeInventoryScanner> {
        let proc_root = root.join("probe-proc");
        let systemd_root = root.join("probe-systemd");
        let block_root = root.join("probe-block");
        let network_root = root.join("probe-network");
        let socket_root = root.join("probe-sockets");
        for directory in [
            &proc_root,
            &systemd_root,
            &block_root,
            &network_root,
            &socket_root,
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let data_authority: Arc<dyn VolumeDataAuthority> = authority;
        let blob_store: Arc<dyn BlobStore> = blob;
        clean_slate_scanner_with_volume_authority_and_blob_for_test(
            TestCleanSlateProbeConfig {
                state_directory: crate::state_directory::StateDirectory::unanchored(
                    std::fs::canonicalize(state_path.parent().unwrap())
                        .unwrap()
                        .join(state_path.file_name().unwrap()),
                ),
                proc_root,
                systemd_cgroup_root: systemd_root,
                block_class_root: block_root,
                network_class_root: network_root,
                legacy_socket_root: socket_root,
                cloud_hypervisor_binary: root.join("bin/cloud-hypervisor"),
                blockd_binary: root.join("bin/cats-blockd"),
                guest_agent_binary: root.join("bin/cats-guest-agent"),
            },
            data_authority,
            blob_store,
        )
        .unwrap()
    }

    fn composition_config(
        state_path: std::path::PathBuf,
        origin: String,
        authority: Arc<CompositionAuthority>,
        blob: Arc<CompositionBlobStore>,
    ) -> SignedRuntimeCutoverConfig {
        let data_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority> =
            Arc::new(TestUnavailableVolumeDataAuthority);
        let blob_store: Arc<dyn BlobStore> = blob;
        SignedRuntimeCutoverConfig {
            listen: "127.0.0.1:0".into(),
            control_plane_url: origin,
            agent_registration: registration_config(state_path).unwrap(),
            ch_config: test_ch_config(),
            authorized_blockd_launch: test_authorized_blockd_launch(),
            guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
            metering_cgroup_root: None,
            volume_data_authority: data_authority,
            volume_inventory_authority: inventory_authority,
            blob_store,
            volume_lease_duration_ms: 60_000,
            deadline_policy: RuntimeSpineDeadlinePolicy::new(
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .unwrap(),
        }
    }

    fn walk_named_files(root: &std::path::Path) -> Vec<String> {
        fn visit(path: &std::path::Path, names: &mut Vec<String>) {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    visit(&entry.path(), names);
                } else {
                    names.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        let mut names = Vec::new();
        visit(root, &mut names);
        names.sort();
        names
    }

    #[test]
    fn production_composition_starts_with_one_checkpointed_signed_acquire() {
        let source = include_str!("runtime_cutover.rs");
        let running_effect = include_str!("runtime/reconciliation/signed_root_provision.rs");
        assert!(source.contains("SignedRunningAcquireEffect::new"));
        assert!(source.contains("RuntimeVolumeTransitionHttpClient::for_production"));
        assert!(source.contains("installed_clean_slate_scanner"));
        assert!(source.contains("VmmLaunchArtifactPaths"));
        assert!(source.contains("vmm_launcher_bin"));
        assert!(running_effect.contains("StartRuntimeReservationEffect::platform"));
        assert!(running_effect.contains("StartRuntimePhysicalEffect::platform"));
        assert!(running_effect.contains("physical_start_runtime.try_apply"));
        let placeholder_effect = ["Unavailable", "Desired", "Effect"].concat();
        let legacy_job = ["Node", "Job"].concat();
        let legacy_runtime = ["Node", "Runtime", "::", "new"].concat();
        let old_network_effect = ["ProductionRuntimeDesiredEffect", "::", "new"].concat();
        let old_unavailable_launch = ["Unavailable", "Runtime", "Launch"].concat();
        assert!(!source.contains(&old_network_effect));
        assert!(!source.contains(&old_unavailable_launch));
        assert!(!source.contains(&placeholder_effect));
        assert!(!source.contains(&legacy_job));
        assert!(!source.contains(&legacy_runtime));
    }

    #[tokio::test]
    async fn loopback_production_composition_restarts_from_a22_files_and_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let state_path = root.path().join("state");
        let desired = composition_desired_spec();
        let authority = Arc::new(CompositionAuthority::new(&desired));
        let blob = Arc::new(CompositionBlobStore::new(&desired));
        let control = CompositionControl {
            desired: desired.clone(),
            authority: Arc::clone(&authority),
            registrations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            desired_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            observations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            a22_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let server_control = control.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(REGISTRATION_PATH, post(composition_registration))
                    .route(DESIRED_READ_PATH, post(composition_desired))
                    .route(OBSERVATION_PATH, post(composition_observation))
                    .route(RUNTIME_VOLUME_TRANSITION_PATH, post(composition_a22))
                    .with_state(server_control),
            )
            .await
            .unwrap();
        });

        let scanner = composition_scanner(
            root.path(),
            &state_path,
            Arc::clone(&authority),
            Arc::clone(&blob),
        );
        let mut first = spawn_signed_runtime_cutover_with_scanner(
            composition_config(
                state_path.clone(),
                origin.clone(),
                Arc::clone(&authority),
                Arc::clone(&blob),
            ),
            Some(scanner),
        )
        .await
        .unwrap();
        let checkpoint_path =
            runtime_checkpoint_path(&state_path.join("checkpoints"), &desired.cat_id);
        let deadline = Instant::now() + Duration::from_secs(8);
        let checkpoint_bytes = loop {
            if let Ok(bytes) = std::fs::read(&checkpoint_path) {
                if matches!(
                    decode_runtime_checkpoint(&bytes).unwrap().step,
                    ReconcileStep::ProvisionRootImage { .. }
                ) {
                    break bytes;
                }
            }
            assert!(
                Instant::now() < deadline,
                "composition did not reach ProvisionRootImage"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(control.a22_calls.load(Ordering::SeqCst), 1);
        assert_eq!(authority.mutations.load(Ordering::SeqCst), 1);
        let data_root = state_path.join("data");
        assert_eq!(
            walk_named_files(&data_root),
            vec![
                "authorized-serving.json".to_owned(),
                "identity.json".to_owned(),
                "launch-checkpoint.json".to_owned(),
            ]
        );

        first.request_runner_shutdown();
        join_result(
            (&mut first.runner_task).await,
            "join first loopback composition",
        )
        .unwrap();
        drop(first);
        let observations_before_restart = control.observations.load(Ordering::SeqCst);

        let restart_scanner = composition_scanner(
            root.path(),
            &state_path,
            Arc::clone(&authority),
            Arc::clone(&blob),
        );
        let mut restart = spawn_signed_runtime_cutover_with_scanner(
            composition_config(state_path.clone(), origin, Arc::clone(&authority), blob),
            Some(restart_scanner),
        )
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while control.observations.load(Ordering::SeqCst) == observations_before_restart {
            assert!(
                Instant::now() < deadline,
                "restart did not publish a fresh full observation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(control.registrations.load(Ordering::SeqCst), 2);
        assert_eq!(control.a22_calls.load(Ordering::SeqCst), 1);
        assert_eq!(authority.mutations.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_bytes);

        restart.request_runner_shutdown();
        join_result(
            (&mut restart.runner_task).await,
            "join restarted loopback composition",
        )
        .unwrap();
        drop(restart);
        server.abort();
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
            authorized_blockd_launch: test_authorized_blockd_launch(),
            guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
            metering_cgroup_root: None,
            volume_data_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            volume_inventory_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            blob_store: Arc::new(TestUnavailableBlobStore),
            volume_lease_duration_ms: 60_000,
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
    async fn stubborn_effect_child_keeps_readiness_and_host_lease_closed_past_timeout() {
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
        let owner = Arc::new(StubbornEffectChildOwner {
            pending: AtomicBool::new(true),
            shutdowns: std::sync::atomic::AtomicUsize::new(0),
        });
        let owner_port: Arc<dyn RuntimeEffectResourceOwner> = owner.clone();
        let mut handle = spawn_signed_runtime_cutover_with_overrides(
            SignedRuntimeCutoverConfig {
                listen: "127.0.0.1:0".into(),
                control_plane_url: origin,
                agent_registration: registration_config(state_path.clone()).unwrap(),
                ch_config: test_ch_config(),
                authorized_blockd_launch: test_authorized_blockd_launch(),
                guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
                metering_cgroup_root: None,
                volume_data_authority: Arc::new(TestUnavailableVolumeDataAuthority),
                volume_inventory_authority: Arc::new(TestUnavailableVolumeDataAuthority),
                blob_store: Arc::new(TestUnavailableBlobStore),
                volume_lease_duration_ms: 60_000,
                deadline_policy: RuntimeSpineDeadlinePolicy::new(
                    Duration::from_secs(5),
                    Duration::from_secs(30),
                )
                .unwrap(),
            },
            None,
            Some(owner_port),
        )
        .await
        .unwrap();

        handle.request_runner_shutdown();
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.shutdowns.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runner did not begin resource-owner shutdown");
        tokio::time::sleep(Duration::from_millis(5_200)).await;
        assert!(
            owner.shutdowns.load(Ordering::SeqCst) >= 2,
            "runner did not retain and retry the timed-out resource owner"
        );
        assert!(!handle.runner_task.is_finished());
        assert!(registration_config(state_path.clone()).is_err());
        let response = reqwest::get(format!("http://{}/healthz", handle.addr))
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

        owner.pending.store(false, Ordering::Release);
        let error = join_result(
            (&mut handle.runner_task).await,
            "join stubborn-child runner shutdown",
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("stubborn effect child outlived"),
            "{error:#}"
        );
        let successor = registration_config(state_path).unwrap();
        drop(successor);
        drop(handle);
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
            authorized_blockd_launch: test_authorized_blockd_launch(),
            guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
            metering_cgroup_root: None,
            volume_data_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            volume_inventory_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            blob_store: Arc::new(TestUnavailableBlobStore),
            volume_lease_duration_ms: 60_000,
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

    #[tokio::test]
    async fn invalid_acquire_lease_fails_before_registration_or_listener_binding() {
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
            authorized_blockd_launch: test_authorized_blockd_launch(),
            guest_agent_binary: "/opt/cats/bin/cats-guest-agent".into(),
            metering_cgroup_root: None,
            volume_data_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            volume_inventory_authority: Arc::new(TestUnavailableVolumeDataAuthority),
            blob_store: Arc::new(TestUnavailableBlobStore),
            volume_lease_duration_ms: 0,
            deadline_policy: RuntimeSpineDeadlinePolicy::new(
                Duration::from_secs(5),
                Duration::from_secs(30),
            )
            .unwrap(),
        })
        .await;
        let Err(error) = result else {
            panic!("zero acquire lease must fail before startup")
        };

        assert!(error
            .to_string()
            .contains("compose one-step signed Running acquire"));
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

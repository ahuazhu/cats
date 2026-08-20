//! Production entry point for the signed Runtime spine cutover.
//!
//! The shipped Node binary starts here. The first production
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

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
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
use crate::object_write_credential::{NodeObjectWriteCredentials, ObjectWriteCredentialPort};
use crate::route_v2_machine::{RouteV2MachineConfig, RouteV2MachineListener};
use crate::runtime::reconciliation::{
    installed_clean_slate_scanner, installed_root_process_effect_ports, AdmissionCellRegistry,
    AuthorizedBlockdLaunchConfig, ControlBlockingSignedVolumeEvidenceClient,
    ControlSignedNormalAcquireClient, InstalledCleanSlateProbeConfig, KernelNbdClientCleanupOwner,
    KernelNbdInventoryConfig, ObjectWriteGatewayLaunch, RootProvisionSystemdConfig,
    RunningAdmissionPreScan, RuntimeVolumeTransitionHttpClient, ServingPrepareFrontend,
    SignedRunningAcquireEffect, SignedRunningEffect, SignedRunningHostConfig,
    SignedRunningProcessPorts, SignedRunningPublicationRecovery, SignedVolumeEvidencePort,
    VmmLaunchArtifactPaths,
};
use crate::runtime_spine::{
    RuntimeEffectResourceOwner, RuntimeInventoryScanner, RuntimeSpineDeadlinePolicy,
    RuntimeSpineHttpClient, RuntimeSpineRunStep, RuntimeSpineRunner,
};
use crate::signed_usage::{
    run_delivery as run_signed_usage_delivery, run_sampler as run_signed_usage_sampler,
    MeteredRuntimeDesiredEffect, SignedUsagePipeline,
};

const RETRY_DELAY: Duration = Duration::from_secs(1);
const FINAL_USAGE_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SignedRuntimeCutoverConfig {
    pub listen: String,
    /// Independent authenticated Gateway-to-Node listener. `noded` can supply
    /// this only from the fixed artifact set; absence keeps Route v2 ingress
    /// closed without affecting the signed Runtime worker.
    pub route_v2_machine: Option<RouteV2MachineConfig>,
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
    /// The ObjectWrite Gateway this Node mints attachment-scoped credentials
    /// against. Production `noded` always supplies it, because a production
    /// worker is denied direct object-store writes by IAM. `None` composes a
    /// Node with no gateway: its grants carry no credential and every
    /// qualified publish path fails closed on that.
    pub object_write_gateway: Option<ObjectWriteGatewayComposition>,
    /// Test-only scheduler barrier after one accepted physical observation
    /// and before the next Desired/effect iteration. It does not replace or
    /// wrap the installed scanner/effect composition.
    #[cfg(test)]
    pub(crate) observation_barrier_for_test: Option<RuntimeObservationBarrierForTest>,
}

/// Node configuration for the ObjectWrite Gateway path.
///
/// The Control-side ObjectWriteAuthority this Host's credentials belong to is
/// deliberately *not* here: it is derived from the Node ID, so it is per Node,
/// while the fleet deployment writes one shared worker environment. The
/// credential port reads it from Control once per Agent session instead.
#[derive(Debug, Clone)]
pub struct ObjectWriteGatewayComposition {
    /// Bare HTTPS origin, from Node configuration rather than a constant.
    pub gateway_url: String,
}

#[cfg(test)]
pub(crate) struct RuntimeObservationBarrierForTest {
    reached: tokio::sync::mpsc::UnboundedSender<()>,
    resume: tokio::sync::mpsc::UnboundedReceiver<()>,
    effect_steps: Option<tokio::sync::mpsc::UnboundedSender<RuntimeEffectStepForTest>>,
    effect_dispatch_count: Option<Arc<AtomicUsize>>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeEffectStepForTest {
    ServingAdopted {
        cat_id: cats_api::runtime_reconciliation::Id,
    },
    RefreshInventory {
        cat_id: cats_api::runtime_reconciliation::Id,
    },
    Stopped {
        cat_id: cats_api::runtime_reconciliation::Id,
        reason: crate::runtime_spine::RuntimeDesiredEffectStopReason,
    },
    SessionReplacementRequired {
        cat_id: cats_api::runtime_reconciliation::Id,
    },
}

#[cfg(test)]
impl RuntimeObservationBarrierForTest {
    pub(crate) fn channel() -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        tokio::sync::mpsc::UnboundedSender<()>,
    ) {
        let (reached, reached_rx) = tokio::sync::mpsc::unbounded_channel();
        let (resume, resume_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                reached,
                resume: resume_rx,
                effect_steps: None,
                effect_dispatch_count: None,
            },
            reached_rx,
            resume,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn channel_with_effect_steps() -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        tokio::sync::mpsc::UnboundedSender<()>,
        tokio::sync::mpsc::UnboundedReceiver<RuntimeEffectStepForTest>,
        Arc<AtomicUsize>,
    ) {
        let (reached, reached_rx) = tokio::sync::mpsc::unbounded_channel();
        let (resume, resume_rx) = tokio::sync::mpsc::unbounded_channel();
        let (effect_steps, effect_steps_rx) = tokio::sync::mpsc::unbounded_channel();
        let effect_dispatch_count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                reached,
                resume: resume_rx,
                effect_steps: Some(effect_steps),
                effect_dispatch_count: Some(Arc::clone(&effect_dispatch_count)),
            },
            reached_rx,
            resume,
            effect_steps_rx,
            effect_dispatch_count,
        )
    }

    fn observe_effect_step(&self, step: &RuntimeSpineRunStep) -> anyhow::Result<()> {
        let event = match step {
            RuntimeSpineRunStep::EffectRefreshInventory { cat_id } => {
                Some(RuntimeEffectStepForTest::RefreshInventory {
                    cat_id: cat_id.clone(),
                })
            }
            RuntimeSpineRunStep::EffectStopped { cat_id, reason } => {
                Some(RuntimeEffectStepForTest::Stopped {
                    cat_id: cat_id.clone(),
                    reason: reason.clone(),
                })
            }
            RuntimeSpineRunStep::EffectSessionReplacementRequired { cat_id } => {
                Some(RuntimeEffectStepForTest::SessionReplacementRequired {
                    cat_id: cat_id.clone(),
                })
            }
            _ => None,
        };
        if let (Some(sender), Some(event)) = (&self.effect_steps, event) {
            sender
                .send(event)
                .map_err(|_| anyhow::anyhow!("test effect-step receiver dropped"))?;
        }
        Ok(())
    }

    async fn wait_after_observation(&mut self) -> anyhow::Result<()> {
        self.reached
            .send(())
            .map_err(|_| anyhow::anyhow!("test observation-barrier receiver dropped"))?;
        self.resume
            .recv()
            .await
            .context("test observation-barrier resume sender dropped")
    }
}

pub struct SignedRuntimeCutoverHandle {
    pub addr: std::net::SocketAddr,
    pub route_v2_addr: Option<std::net::SocketAddr>,
    shutdown_runner: Option<tokio::sync::oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    runner_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    route_v2_machine: Option<RouteV2MachineListener>,
}

impl SignedRuntimeCutoverHandle {
    /// Runs until process shutdown or a component failure. Shutdown first
    /// closes Route v2 admission and joins every tunnel so its guard is
    /// returned, then cancels and joins the effect/scanner/journal workers and
    /// drops the Runtime flock. The health listener is stopped last.
    pub async fn run_until_signal(mut self) -> anyhow::Result<()> {
        enum Stop {
            Signal(anyhow::Result<()>),
            Server(Result<anyhow::Result<()>, tokio::task::JoinError>),
            Runner(Result<anyhow::Result<()>, tokio::task::JoinError>),
            RouteV2(anyhow::Result<()>),
        }

        let stop = tokio::select! {
            signal = shutdown_signal() => Stop::Signal(signal),
            result = &mut self.server_task => Stop::Server(result),
            result = &mut self.runner_task => Stop::Runner(result),
            result = wait_route_v2_machine(&mut self.route_v2_machine) => Stop::RouteV2(result),
        };
        let route_shutdown = self.shutdown_route_v2_machine().await;
        let (outcome, stop_server) = match stop {
            Stop::Signal(signal) => {
                self.request_runner_shutdown();
                let runner = join_result(
                    (&mut self.runner_task).await,
                    "join signed Runtime spine during shutdown",
                );
                (signal.and(route_shutdown).and(runner), true)
            }
            Stop::Server(server) => {
                self.request_runner_shutdown();
                let runner = join_result(
                    (&mut self.runner_task).await,
                    "join signed Runtime spine after listener exit",
                );
                (
                    join_result(server, "signed Runtime health listener task stopped")
                        .and(route_shutdown)
                        .and(runner),
                    false,
                )
            }
            Stop::Runner(runner) => {
                self.shutdown_runner.take();
                (
                    join_result(runner, "signed Runtime spine task stopped").and(route_shutdown),
                    true,
                )
            }
            Stop::RouteV2(route) => {
                self.request_runner_shutdown();
                let runner = join_result(
                    (&mut self.runner_task).await,
                    "join signed Runtime spine after Route v2 listener exit",
                );
                (route.and(route_shutdown).and(runner), true)
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

    async fn shutdown_route_v2_machine(&mut self) -> anyhow::Result<()> {
        match self.route_v2_machine.as_mut() {
            Some(listener) => listener.shutdown().await,
            None => Ok(()),
        }
    }
}

async fn wait_route_v2_machine(
    listener: &mut Option<RouteV2MachineListener>,
) -> anyhow::Result<()> {
    match listener {
        Some(listener) => listener.wait().await,
        None => std::future::pending().await,
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
        if let Some(listener) = &self.route_v2_machine {
            listener.begin_shutdown();
        }
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

/// Two independent local facts, deliberately not one.
///
/// `serving` answers "may this Node admit Route traffic": it additionally
/// requires the Node to actually hold runtimes, so a cordoned empty Node is
/// never serving. `attested` answers "did this process establish a
/// session-bound complete-inventory admission attestation": that is true of a
/// cordoned empty Node, and it is what a worker deployment must prove before
/// it commits a release. Collapsing them made the deployment gate ask the
/// serving question about a Node the cutover requires to be empty, which no
/// first Node could ever satisfy.
#[derive(Clone)]
struct Readiness {
    serving: Arc<AtomicBool>,
    attested: Arc<AtomicBool>,
}

impl Readiness {
    fn closed() -> Self {
        Self {
            serving: Arc::new(AtomicBool::new(false)),
            attested: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set(&self, serving: bool, attested: bool) {
        self.serving.store(serving, Ordering::Release);
        self.attested.store(attested, Ordering::Release);
    }

    fn close(&self) {
        self.set(false, false);
    }

    fn is_serving(&self) -> bool {
        self.serving.load(Ordering::Acquire)
    }

    fn is_attested(&self) -> bool {
        self.attested.load(Ordering::Acquire)
    }
}

async fn health(State(readiness): State<Readiness>) -> (StatusCode, &'static str) {
    if readiness.is_serving() {
        (StatusCode::OK, "signed Runtime inventory attested")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "signed Runtime inventory is not attested",
        )
    }
}

/// A worker deployment proves the candidate Agent established its
/// complete-inventory attestation, not that the Node serves runtimes: it
/// installs a cordoned, empty Node, whose `/healthz` is 503 by design.
async fn attested(State(readiness): State<Readiness>) -> (StatusCode, &'static str) {
    if readiness.is_attested() {
        (StatusCode::OK, "signed Runtime complete inventory attested")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "signed Runtime complete inventory is not attested",
        )
    }
}

fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/attestedz", get(attested))
        .with_state(readiness)
}

pub async fn spawn_signed_runtime_cutover(
    config: SignedRuntimeCutoverConfig,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    #[cfg(not(test))]
    {
        spawn_signed_runtime_cutover_with_scanner(config, None).await
    }
    #[cfg(test)]
    {
        spawn_signed_runtime_cutover_with_scanner(config, None, None).await
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestDesiredEffectComposition {
    AcquireOnly,
}

async fn spawn_signed_runtime_cutover_with_scanner(
    config: SignedRuntimeCutoverConfig,
    scanner_override: Option<Arc<dyn RuntimeInventoryScanner>>,
    #[cfg(test)] desired_effect_override: Option<TestDesiredEffectComposition>,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    #[cfg(not(test))]
    {
        spawn_signed_runtime_cutover_with_overrides(config, scanner_override, None, None).await
    }
    #[cfg(test)]
    {
        spawn_signed_runtime_cutover_with_overrides(
            config,
            scanner_override,
            None,
            None,
            desired_effect_override,
        )
        .await
    }
}

async fn spawn_signed_runtime_cutover_with_overrides(
    config: SignedRuntimeCutoverConfig,
    scanner_override: Option<Arc<dyn RuntimeInventoryScanner>>,
    resource_owner_override: Option<Arc<dyn RuntimeEffectResourceOwner>>,
    recovery_override: Option<SignedRunningPublicationRecovery>,
    #[cfg(test)] desired_effect_override: Option<TestDesiredEffectComposition>,
) -> anyhow::Result<SignedRuntimeCutoverHandle> {
    let route_v2_machine_config = config.route_v2_machine;
    let route_v2_verifier = route_v2_machine_config
        .as_ref()
        .map(RouteV2MachineConfig::verifier);
    // Reject an unrepresentable operator budget before registration, worker
    // construction, or listener binding can mutate external/local state.
    config
        .deadline_policy
        .deadlines_from(Instant::now())
        .context("validate signed Runtime startup deadlines")?;
    SignedRunningAcquireEffect::validate_lease_duration(config.volume_lease_duration_ms)
        .context("compose one-step signed Running acquire")?;
    // Composed before the effect lane starts so a misconfigured gateway origin
    // fails at startup rather than at the first grant.
    let object_write_credentials: Option<Arc<dyn ObjectWriteCredentialPort>> = config
        .object_write_gateway
        .as_ref()
        .map(|gateway| {
            NodeObjectWriteCredentials::for_production(
                config
                    .agent_registration
                    .runtime_state_directory()
                    .path()
                    .to_path_buf(),
                &gateway.gateway_url,
                &config.control_plane_url,
                config.agent_registration.runtime_request_signer(),
            )
            .map(|credentials| Arc::new(credentials) as Arc<dyn ObjectWriteCredentialPort>)
        })
        .transpose()
        .context("compose the Node object-write credential authority")?;
    let mut authorized_blockd_launch = config.authorized_blockd_launch.clone();
    if let Some(credentials) = object_write_credentials.as_ref() {
        authorized_blockd_launch.object_write_gateway = Some(ObjectWriteGatewayLaunch {
            gateway_url: credentials.gateway_origin().to_owned(),
            credential_directory: credentials.credential_directory(),
        });
    }
    let effect_object_write_credentials = object_write_credentials.clone();
    let recovery_object_write_credentials = object_write_credentials;
    let root_provision_systemd = RootProvisionSystemdConfig::new(authorized_blockd_launch)
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
    #[cfg(not(test))]
    let effect_root_process_ports =
        installed_root_process_effect_ports(installed_probe_config.clone())
            .context("compose sealed root-process effect inventory")?;
    #[cfg(test)]
    let effect_root_process_ports = match desired_effect_override {
        Some(TestDesiredEffectComposition::AcquireOnly) => None,
        None => Some(
            installed_root_process_effect_ports(installed_probe_config.clone())
                .context("compose sealed root-process effect inventory")?,
        ),
    };
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
    // The signed Runtime's own inventory proof requires the delegated metering
    // root to exist: an absent root is unprovable, not empty. The V1 server
    // established it at startup; this path never did, so every Node reported an
    // incomplete inventory forever and could not attest.
    if let Some(root) = config.metering_cgroup_root.as_deref() {
        crate::runtime::initialize_metering_cgroup_root(root)
            .context("establish the delegated metering cgroup root")?;
    }
    let usage_pipeline = config
        .metering_cgroup_root
        .as_deref()
        .map(|metering_cgroup_root| {
            SignedUsagePipeline::open(
                &session,
                config.agent_registration.runtime_request_signer(),
                &config.control_plane_url,
                config.agent_registration.runtime_state_directory().path(),
                metering_cgroup_root,
            )
        })
        .transpose()
        .context("compose signed Runtime usage pipeline")?
        .map(Arc::new);
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
    let effect_state_directory = config.agent_registration.runtime_state_directory();
    let admission_registry = AdmissionCellRegistry::for_state_directory(&effect_state_directory);
    let scanner = match scanner_override {
        Some(scanner) => scanner,
        None => installed_clean_slate_scanner(
            installed_probe_config,
            Arc::clone(&admission_registry),
            route_v2_verifier,
        )
        .context("compose installed clean-slate inventory probes")?,
    };
    let effect_registration = config.agent_registration.clone();
    let effect_control_plane_url = config.control_plane_url.clone();
    let effect_volume_authority = Arc::clone(&config.volume_data_authority);
    let effect_blob_store = Arc::clone(&config.blob_store);
    let effect_lease_duration_ms = config.volume_lease_duration_ms;
    let effect_admission_registry = Arc::clone(&admission_registry);
    let effect_network_ip_binary = config.ch_config.ip_bin.clone();
    let effect_kernel_nbd_inventory = kernel_nbd_inventory;
    let effect_kernel_nbd_cleanup_owner = Arc::clone(&kernel_nbd_cleanup_owner);
    let effect_usage_pipeline = usage_pipeline.clone();
    let runner_effect_resource_owner = resource_owner_override.unwrap_or_else(|| {
        Arc::clone(&kernel_nbd_cleanup_owner) as Arc<dyn RuntimeEffectResourceOwner>
    });
    #[cfg(test)]
    let effect_dispatch_count_for_test = config
        .observation_barrier_for_test
        .as_ref()
        .and_then(|barrier| barrier.effect_dispatch_count.clone());
    #[cfg(test)]
    let serving_adoption_steps_for_test = config
        .observation_barrier_for_test
        .as_ref()
        .and_then(|barrier| barrier.effect_steps.clone());
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
        let volume_evidence: Arc<dyn SignedVolumeEvidencePort> = Arc::new(
            ControlBlockingSignedVolumeEvidenceClient::new(volume_transition_transport.clone()),
        );
        #[cfg(feature = "proposed-node-residue-reclamation")]
        let residue_authority = volume_transition_transport.clone();
        let acquire_client = match effect_object_write_credentials.clone() {
            Some(credentials) => ControlSignedNormalAcquireClient::new(volume_transition_transport)
                .with_object_write_credentials(credentials),
            None => ControlSignedNormalAcquireClient::new(volume_transition_transport),
        };
        let acquire = SignedRunningAcquireEffect::new(
            Arc::new(acquire_client),
            Arc::clone(&effect_volume_authority),
            Arc::clone(&effect_blob_store),
            effect_lease_duration_ms,
        )
        .context("compose one-step signed Running acquire")?
        .with_volume_evidence(Arc::clone(&volume_evidence));
        let acquire = match effect_object_write_credentials.clone() {
            Some(credentials) => acquire.with_object_write_credentials(credentials),
            None => acquire,
        };
        macro_rules! compose_platform_effect {
            ($process_ports:expr) => {{
                let process_ports = $process_ports;
                let effect = SignedRunningEffect::platform(
                    acquire,
                    #[cfg(feature = "proposed-node-residue-reclamation")]
                    residue_authority.clone(),
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
                        Arc::clone(&process_ports.retirement),
                        Arc::clone(&process_ports.global),
                        Arc::clone(&process_ports.serving),
                        Arc::clone(&process_ports.vmm),
                        Arc::clone(&process_ports.vmm_cid),
                    ),
                    effect_prepare_frontend,
                    Arc::clone(&effect_admission_registry),
                )
                .context("compose signed Running root provision prefix")?;
                #[cfg(test)]
                let effect = match serving_adoption_steps_for_test.clone() {
                    Some(sender) => {
                        effect.with_serving_adoption_observer_for_test(Arc::new(move |cat_id| {
                            sender
                                .send(RuntimeEffectStepForTest::ServingAdopted {
                                    cat_id: cat_id.clone(),
                                })
                                .map_err(|_| {
                                    anyhow::anyhow!("test serving-adoption observer dropped")
                                })
                        }))
                    }
                    None => effect,
                };
                Ok::<_, anyhow::Error>(effect)
            }};
        }
        #[cfg(not(test))]
        let effect: Arc<dyn crate::runtime_spine::RuntimeDesiredEffect> =
            Arc::new(compose_platform_effect!(&effect_root_process_ports)?);
        #[cfg(test)]
        let effect: Arc<dyn crate::runtime_spine::RuntimeDesiredEffect> =
            match desired_effect_override {
                Some(TestDesiredEffectComposition::AcquireOnly) => Arc::new(acquire),
                None => Arc::new(compose_platform_effect!(effect_root_process_ports
                    .as_ref()
                    .context("test platform composition lacks installed process ports")?)?),
            };
        let effect: Arc<dyn crate::runtime_spine::RuntimeDesiredEffect> =
            match effect_usage_pipeline {
                Some(usage) => Arc::new(MeteredRuntimeDesiredEffect::new(effect, usage)),
                None => effect,
            };
        let recovery = match recovery_override {
            Some(recovery) => recovery,
            None => {
                #[cfg(all(target_os = "linux", not(test)))]
                {
                    SignedRunningPublicationRecovery::with_stale_boot_vmm_recovery(
                        Arc::clone(&effect_volume_authority),
                        effect_root_process_ports.stale_boot_vmm.clone(),
                    )
                }
                #[cfg(all(target_os = "linux", test))]
                {
                    match effect_root_process_ports.as_ref() {
                        Some(ports) => {
                            SignedRunningPublicationRecovery::with_stale_boot_vmm_recovery(
                                Arc::clone(&effect_volume_authority),
                                ports.stale_boot_vmm.clone(),
                            )
                        }
                        None => SignedRunningPublicationRecovery::new(Arc::clone(
                            &effect_volume_authority,
                        )),
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    SignedRunningPublicationRecovery::new(Arc::clone(&effect_volume_authority))
                }
            }
        }
        .with_volume_evidence(volume_evidence);
        let recovery = match recovery_object_write_credentials {
            Some(credentials) => recovery.with_object_write_credentials(credentials),
            None => recovery,
        };
        let runner = RuntimeSpineRunner::new_with_recovery_desired_effects_and_resource_owner(
            effect_state_directory,
            session,
            client,
            scanner,
            Arc::new(RunningAdmissionPreScan::new(effect_admission_registry)),
            Arc::new(recovery),
            effect,
            runner_effect_resource_owner,
        )
        .map_err(anyhow::Error::from)?;
        #[cfg(test)]
        let runner = {
            let mut runner = runner;
            if let Some(dispatch_count) = effect_dispatch_count_for_test {
                runner
                    .set_effect_dispatch_count_for_test(dispatch_count)
                    .map_err(anyhow::Error::from)?;
            }
            runner
        };
        Ok::<_, anyhow::Error>(runner)
    })
    .await
    .context("join signed Runtime runner construction")??;
    // Bind before spawning either owned task. If binding fails, `runner` drops
    // synchronously and no detached worker can outlive this failed startup.
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind signed Runtime health listener {}", config.listen))?;
    let addr = listener.local_addr()?;
    let route_v2_machine = match route_v2_machine_config {
        Some(config) => Some(
            RouteV2MachineListener::spawn(config, admission_registry)
                .await
                .context("start authenticated Node Route v2 listener")?,
        ),
        None => None,
    };
    let route_v2_addr = route_v2_machine.as_ref().map(RouteV2MachineListener::addr);

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
    let runner_usage_pipeline = usage_pipeline;
    #[cfg(test)]
    let observation_barrier_for_test = config.observation_barrier_for_test;
    let runner_task = tokio::spawn(async move {
        let mut runner = runner;
        let (usage_shutdown, usage_shutdown_rx) = tokio::sync::watch::channel(false);
        let mut usage_task = runner_usage_pipeline.clone().map(|pipeline| {
            let sampler = Arc::clone(&pipeline);
            let sampler_shutdown = usage_shutdown_rx.clone();
            tokio::spawn(async move {
                tokio::try_join!(
                    run_signed_usage_sampler(sampler, sampler_shutdown),
                    run_signed_usage_delivery(pipeline, usage_shutdown_rx),
                )?;
                Ok(())
            })
        });
        let (mut run_result, usage_already_joined) = tokio::select! {
            result = run_signed_spine(
                &mut runner,
                &runner_readiness,
                deadline_policy,
                runner_usage_pipeline.clone(),
                #[cfg(test)]
                observation_barrier_for_test,
            ) => (result, false),
            _ = &mut runner_shutdown => (Ok(()), false),
            result = wait_usage_task(&mut usage_task) => (result, true),
        };
        runner_readiness.close();
        let _ = usage_shutdown.send(true);
        if !usage_already_joined {
            if let Some(task) = usage_task.take() {
                let usage_result = match task.await {
                    Ok(result) => result,
                    Err(error) => {
                        Err(anyhow::Error::new(error).context("join signed usage shutdown"))
                    }
                };
                if let Err(error) = usage_result {
                    if run_result.is_ok() {
                        run_result = Err(error);
                    }
                }
            }
        }
        if let Some(pipeline) = runner_usage_pipeline.as_ref() {
            match tokio::time::timeout(
                FINAL_USAGE_DELIVERY_TIMEOUT,
                pipeline.deliver_pending_for_shutdown(),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    error = format!("{error:#}"),
                    "final signed usage delivery failed; durable spool retained"
                ),
                Err(_) => tracing::warn!(
                    timeout_ms = FINAL_USAGE_DELIVERY_TIMEOUT.as_millis(),
                    "final signed usage delivery timed out; durable spool retained"
                ),
            }
        }
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
        route_v2_addr,
        shutdown_runner: Some(shutdown_runner),
        server_task,
        runner_task,
        route_v2_machine,
    })
}

async fn run_signed_spine(
    runner: &mut RuntimeSpineRunner,
    readiness: &Readiness,
    deadline_policy: RuntimeSpineDeadlinePolicy,
    usage_pipeline: Option<Arc<SignedUsagePipeline>>,
    #[cfg(test)] mut observation_barrier_for_test: Option<RuntimeObservationBarrierForTest>,
) -> anyhow::Result<()> {
    loop {
        // Both absolute deadlines start before dispatch into the runner. Time
        // spent waiting on its ordered journal/effect lanes is not refunded at
        // a later blocking boundary.
        let deadlines = deadline_policy.deadlines_from(Instant::now())?;
        let step = runner.run_once_with_deadlines(deadlines).await?;
        // A Node that cannot attest is otherwise completely silent: readiness
        // stays closed, the loop retries, and no operator can tell which step
        // refuses. Name the step every iteration.
        log_spine_step(&step);
        if matches!(&step, RuntimeSpineRunStep::ObservationAccepted { .. }) {
            let observation = runner
                .accepted_full_observation()
                .context("accepted full observation did not retain its usage evidence")?;
            if let Some(pipeline) = usage_pipeline.as_ref() {
                let pipeline = Arc::clone(pipeline);
                tokio::task::spawn_blocking(move || pipeline.update_observation(&observation))
                    .await
                    .context("join signed usage target update")??;
            }
        }
        #[cfg(test)]
        let observation_accepted = matches!(&step, RuntimeSpineRunStep::ObservationAccepted { .. });
        #[cfg(test)]
        if let Some(barrier) = observation_barrier_for_test.as_ref() {
            barrier.observe_effect_step(&step)?;
        }
        match apply_readiness_policy(step, readiness)? {
            RuntimeLoopAction::Continue => {
                #[cfg(test)]
                if observation_accepted {
                    if let Some(barrier) = observation_barrier_for_test.as_mut() {
                        // `run_once_with_deadlines` returned only after the
                        // observation acceptance was durably resolved. Holding
                        // this loop boundary prevents the next Desired/effect
                        // dispatch without replacing either installed port.
                        barrier.wait_after_observation().await?;
                    }
                }
            }
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

async fn wait_usage_task(
    task: &mut Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
) -> anyhow::Result<()> {
    match task {
        Some(task) => task.await.context("join signed usage task")?,
        None => std::future::pending().await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeLoopAction {
    Continue,
    RetryAfterDelay,
    WaitForIdentityRepair,
}

/// Names the step the spine just completed. Steps that keep readiness closed are
/// the ones an operator needs to see, so they are not debug-only.
fn log_spine_step(step: &RuntimeSpineRunStep) {
    match step {
        RuntimeSpineRunStep::ObservationAccepted {
            service_ready,
            inventory_attested,
        } => tracing::info!(
            service_ready,
            inventory_attested,
            "signed Runtime observation accepted"
        ),
        RuntimeSpineRunStep::DesiredAccepted => {
            tracing::info!("signed Runtime Desired accepted");
        }
        RuntimeSpineRunStep::NoEffectsRequired => {
            tracing::debug!("signed Runtime Desired required no effect");
        }
        RuntimeSpineRunStep::PartialObservationAccepted { degraded_runtimes } => {
            tracing::info!(degraded_runtimes, "partial Runtime observation accepted");
        }
        RuntimeSpineRunStep::ScanUnavailable(error) => {
            tracing::warn!(%error, "physical inventory scan is unavailable");
        }
        RuntimeSpineRunStep::ScanIncomplete {
            unavailable_sources,
        } => {
            tracing::warn!(
                ?unavailable_sources,
                "physical inventory scan is incomplete"
            );
        }
        RuntimeSpineRunStep::ScanDeadlineExceeded => {
            tracing::warn!("physical inventory scan exceeded its deadline");
        }
        RuntimeSpineRunStep::PreScanAdmissionUnavailable(error) => {
            tracing::warn!(%error, "pre-scan admission is unavailable");
        }
        RuntimeSpineRunStep::PreScanAdmissionDeadlineExceeded => {
            tracing::warn!("pre-scan admission exceeded its deadline");
        }
        RuntimeSpineRunStep::PreScanRecoveryUnavailable(error) => {
            tracing::warn!(%error, "pre-scan recovery is unavailable");
        }
        RuntimeSpineRunStep::PreScanRecoveryDeadlineExceeded => {
            tracing::warn!("pre-scan recovery exceeded its deadline");
        }
        RuntimeSpineRunStep::RetryExact(retry) => {
            tracing::warn!(?retry, "signed Runtime step must retry the exact request");
        }
        other => tracing::info!(step = ?other, "signed Runtime step"),
    }
}

fn apply_readiness_policy(
    step: RuntimeSpineRunStep,
    readiness: &Readiness,
) -> anyhow::Result<RuntimeLoopAction> {
    match step {
        RuntimeSpineRunStep::DesiredAccepted => {
            // A fresh Desired must be reconciled and attested before the
            // process can advertise local readiness again.
            readiness.close();
            Ok(RuntimeLoopAction::Continue)
        }
        RuntimeSpineRunStep::ObservationAccepted {
            service_ready,
            inventory_attested,
        } => {
            readiness.set(service_ready, inventory_attested);
            Ok(RuntimeLoopAction::Continue)
        }
        RuntimeSpineRunStep::PartialObservationAccepted { .. } => {
            // This result is only produced in the same process after the
            // mandatory pre-scan proved those Running gates safe to retain.
            // It may preserve readiness established by a full attestation,
            // but cannot establish readiness itself: full service admission
            // also depends on there being no unsettled physical effects. A
            // predecessor's durable partial request remains
            // ObservationReplayed and likewise cannot restore readiness.
            Ok(RuntimeLoopAction::Continue)
        }
        // An empty batch applied nothing, so it preserves the attestation the
        // last complete observation established, exactly as a retained partial
        // observation does.
        RuntimeSpineRunStep::NoEffectsRequired => Ok(RuntimeLoopAction::Continue),
        RuntimeSpineRunStep::ObservationReplayed
        | RuntimeSpineRunStep::PreScanRecovered { .. }
        | RuntimeSpineRunStep::EffectApplied { .. }
        | RuntimeSpineRunStep::EffectsApplied
        | RuntimeSpineRunStep::EffectRefreshInventory { .. }
        | RuntimeSpineRunStep::EffectReplanDesired { .. }
        | RuntimeSpineRunStep::DesiredInvalidated { .. } => {
            readiness.close();
            Ok(RuntimeLoopAction::Continue)
        }
        RuntimeSpineRunStep::RetryExact(_)
        | RuntimeSpineRunStep::ScanUnavailable(_)
        | RuntimeSpineRunStep::ScanIncomplete { .. }
        | RuntimeSpineRunStep::ScanDeadlineExceeded
        | RuntimeSpineRunStep::PreScanAdmissionUnavailable(_)
        | RuntimeSpineRunStep::PreScanAdmissionDeadlineExceeded
        | RuntimeSpineRunStep::PreScanRecoveryUnavailable(_)
        | RuntimeSpineRunStep::PreScanRecoveryDeadlineExceeded
        | RuntimeSpineRunStep::EffectRetryExact { .. }
        | RuntimeSpineRunStep::EffectUnavailable { .. }
        | RuntimeSpineRunStep::EffectDeadlineExceeded { .. } => {
            readiness.close();
            Ok(RuntimeLoopAction::RetryAfterDelay)
        }
        RuntimeSpineRunStep::SessionInvalid { status, error } => {
            readiness.close();
            anyhow::bail!("signed Runtime session was rejected with {status}: {error:?}");
        }
        RuntimeSpineRunStep::Rejected { status, error } => {
            readiness.close();
            anyhow::bail!("signed Runtime request was rejected with {status}: {error:?}");
        }
        RuntimeSpineRunStep::RouteUnavailable => {
            readiness.close();
            anyhow::bail!("signed Runtime routes are not deployed");
        }
        RuntimeSpineRunStep::EffectIdentityRepairRequired { cat_id } => {
            readiness.close();
            tracing::error!(%cat_id, "signed Runtime identity repair is required; Agent is cordoned");
            Ok(RuntimeLoopAction::WaitForIdentityRepair)
        }
        RuntimeSpineRunStep::EffectSessionReplacementRequired { cat_id } => {
            readiness.close();
            anyhow::bail!("signed Runtime session replacement is required for {cat_id}");
        }
        RuntimeSpineRunStep::EffectStopped { cat_id, reason } => {
            readiness.close();
            // Stop is an exact Cat reconciliation decision, not a Node-loop
            // terminal condition. Keep the durable Desired item available to
            // a later fresh scan while independent Cat workers continue.
            tracing::warn!(%cat_id, ?reason, "signed Runtime effect stopped for one Cat");
            Ok(RuntimeLoopAction::RetryAfterDelay)
        }
    }
}

#[cfg(test)]
mod cross_component_e2e;

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
    #[cfg(target_os = "linux")]
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, AppliedDesiredEvidence, CheckpointEvidence, Condition,
        GuestTransportEvidence, HostPath, InventorySource, LifecycleAdmission,
        ObservedRuntimeStatus, ProgressingReason, RuntimeLaunch, WarmSnapshotEvidence,
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
        clean_slate_scanner_for_test, clean_slate_scanner_with_volume_authority_and_blob_for_test,
        runtime_checkpoint_path, TestCleanSlateProbeConfig,
    };
    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::{
        current_kernel_node_boot_id, stale_boot_recovery_global_sealed, BlockdSocketIntentStore,
        ExactVmmProcessAbsenceProof, InstalledStaleBootVmmRecoveryPorts, ManagedVmmLaunchFilePaths,
        RetainedManagedBlockdSocketRoot, RetainedManagedVmmLaunchRoot,
        RetainedManagedVmmSocketRoot, RuntimeCheckpointRecoverySet,
        StaleBootVmmProcessGlobalInspection, StaleBootVmmProcessGlobalPort, VmmProcessExpectation,
        VmmSocketOwnershipReceiptV1, VmmSocketReceiptStore, BLOCKD_SOCKET_INTENT_NAMESPACE,
        INSTALLED_VMM_SOCKET_ROOT, VMM_LAUNCH_FILE_NAMESPACE,
    };
    #[cfg(target_os = "linux")]
    use crate::runtime_spine::{
        CompleteRuntimeInventory, InventoryCoverageAggregator, RuntimeInventoryKeyRing,
        RuntimeInventoryScanContext, RuntimeInventoryScanOutcome,
    };

    struct StubbornEffectChildOwner {
        pending: AtomicBool,
        shutdowns: std::sync::atomic::AtomicUsize,
    }

    #[cfg(target_os = "linux")]
    struct CompositionStaleBootGlobal {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl stale_boot_recovery_global_sealed::Sealed for CompositionStaleBootGlobal {}

    #[cfg(target_os = "linux")]
    impl StaleBootVmmProcessGlobalPort for CompositionStaleBootGlobal {
        fn inspect_stale_boot_absence_after_node_global_sweep(
            &self,
            selected: &VmmProcessExpectation,
            checkpoints: &RuntimeCheckpointRecoverySet,
            context: &crate::runtime_spine::RuntimePreScanRecoveryContext,
        ) -> anyhow::Result<StaleBootVmmProcessGlobalInspection> {
            context.check_active()?;
            anyhow::ensure!(
                checkpoints.checkpoint(selected.cat_id()) == Some(selected.checkpoint()),
                "composition recovery did not receive the complete retained checkpoint set"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(StaleBootVmmProcessGlobalInspection::Absent(Box::new(
                ExactVmmProcessAbsenceProof::for_test_expectation(selected.clone()),
            )))
        }
    }

    #[cfg(target_os = "linux")]
    struct ReceiptRetiredCompositionScanner {
        receipts: Arc<VmmSocketReceiptStore>,
        incarnation: cats_api::runtime_reconciliation::RandomId128,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl crate::runtime_spine::inventory_scanner_sealed::Sealed for ReceiptRetiredCompositionScanner {}

    #[cfg(target_os = "linux")]
    impl RuntimeInventoryScanner for ReceiptRetiredCompositionScanner {
        fn scan_complete(
            &self,
            context: RuntimeInventoryScanContext,
        ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
            context.check_active()?;
            anyhow::ensure!(
                self.receipts.load(&self.incarnation)?.is_none(),
                "full scan ran before stale-boot VMM receipt retirement"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut coverage = InventoryCoverageAggregator::new();
            for source in [
                InventorySource::Checkpoint,
                InventorySource::Systemd,
                InventorySource::Process,
                InventorySource::ControlSocket,
                InventorySource::BlockFrontend,
                InventorySource::Network,
                InventorySource::DataDirectory,
                InventorySource::PendingPack,
                InventorySource::WarmSnapshot,
                InventorySource::MetadataStore,
                InventorySource::GuestMount,
            ] {
                coverage.record(source)?;
            }
            let runtimes = context
                .coordinates()
                .desired
                .desired_specs
                .iter()
                .map(|desired| {
                    let step = ReconcileStep::InspectInventory {
                        inventory_epoch: context.coordinates().inventory_epoch,
                    };
                    ObservedRuntimeStatus {
                        cat_id: desired.cat_id.clone(),
                        applied_desired: Some(AppliedDesiredEvidence {
                            desired_revision: desired.desired_revision,
                            spec_digest: desired.spec_digest.clone(),
                            placement: desired.placement.clone(),
                            target: desired.target,
                        }),
                        runtime_incarnation: None,
                        stable_state: None,
                        step: step.clone(),
                        checkpoint: CheckpointEvidence::Missing {
                            checkpoint_path: HostPath::new(format!(
                                "/var/lib/cats/test/{}.json",
                                desired.cat_id
                            ))
                            .unwrap(),
                        },
                        processes: Vec::new(),
                        volumes: Vec::new(),
                        mounts: Vec::new(),
                        networks: Vec::new(),
                        guest_transport: GuestTransportEvidence::Unavailable,
                        warm_snapshot: WarmSnapshotEvidence::Absent,
                        lifecycle_admission: LifecycleAdmission::Closed,
                        routes: Vec::new(),
                        platform_guards: 0,
                        conditions: vec![Condition::Progressing {
                            reason: ProgressingReason::ReconcileStep { step },
                        }],
                    }
                })
                .collect();
            Ok(RuntimeInventoryScanOutcome::Complete(Box::new(
                CompleteRuntimeInventory::from_validated_coverage(
                    coverage.finish()?,
                    UnixMillis::new(1_900_000_006_000).unwrap(),
                    RuntimeInventoryKeyRing::Unavailable,
                    runtimes,
                    Vec::new(),
                    Default::default(),
                ),
            )))
        }
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
            object_write_gateway: None,
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

    /// The composition tests provision the installed `/run/cats` namespaces,
    /// which requires root. The Docker and metal root gates execute the full
    /// bodies; the unprivileged native build-host sandbox cannot create the
    /// installed roots and skips them, matching the runbook contract-test
    /// precedent for root-only fixtures.
    #[cfg(target_os = "linux")]
    fn skip_without_root_installed_namespaces() -> bool {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: installed /run/cats namespaces require the root gates");
            return true;
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    fn skip_without_root_installed_namespaces() -> bool {
        false
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
                provider_scope: cats_api::runtime_reconciliation::ProviderScope {
                    provider: Id::new("test_provider").unwrap(),
                    partition: Id::new("test_partition").unwrap(),
                    account_id: Id::new("test_account").unwrap(),
                    region: Id::new("test_region").unwrap(),
                },
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
        if state
            .path()
            .join(BLOCKD_SOCKET_INTENT_NAMESPACE)
            .try_exists()?
        {
            BlockdSocketIntentStore::open_existing(state.clone())?;
        } else {
            BlockdSocketIntentStore::provision_for_test(state.clone())?;
        }
        let blockd_socket_root =
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed();
        let blockd_installed = std::path::Path::new(blockd_socket_root.path().as_str());
        if !blockd_installed.exists() {
            std::fs::create_dir_all(blockd_installed.parent().unwrap())?;
            RetainedManagedBlockdSocketRoot::provision_for_test(blockd_installed)?;
        } else {
            RetainedManagedBlockdSocketRoot::open_installed()?;
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

    #[cfg(target_os = "linux")]
    fn stale_boot_composition_desired_spec() -> DesiredRuntimeSpec {
        let mut desired = decode_desired_runtime_spec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-desired.json"
        )))
        .unwrap();
        desired.placement.node_id = Id::new("node_cutover_a").unwrap();
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    #[cfg(target_os = "linux")]
    fn stale_boot_composition_fixture(
        root: &std::path::Path,
        state_path: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        global_calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> (
        InstalledStaleBootVmmRecoveryPorts,
        Arc<VmmSocketReceiptStore>,
        cats_api::runtime_reconciliation::RandomId128,
        std::path::PathBuf,
    ) {
        std::fs::create_dir(state_path).unwrap();
        std::fs::set_permissions(state_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = crate::state_directory::StateDirectory::unanchored(state_path.to_path_buf());
        let launch_namespace = state.path().join(VMM_LAUNCH_FILE_NAMESPACE);
        std::fs::create_dir(&launch_namespace).unwrap();
        std::fs::set_permissions(&launch_namespace, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let launch_root =
            Arc::new(RetainedManagedVmmLaunchRoot::open_existing(state.clone()).unwrap());
        let socket_root = Arc::new(
            RetainedManagedVmmSocketRoot::provision_for_test(&root.join("recovery-sockets"))
                .unwrap(),
        );
        let receipts = Arc::new(VmmSocketReceiptStore::provision_for_test(state.clone()).unwrap());
        let mut checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        checkpoint.node_id = desired.placement.node_id.clone();
        checkpoint.desired_revision = desired.desired_revision;
        checkpoint.spec_digest = desired.spec_digest.clone();
        checkpoint.placement_epoch = desired.placement.placement_epoch;
        for lineage in &mut checkpoint.volumes[0].local_lineages {
            lineage.node_id = desired.placement.node_id.clone();
            lineage.placement_epoch = desired.placement.placement_epoch;
        }
        let incarnation = checkpoint.runtime_incarnation.as_ref().unwrap().clone();
        let sockets = socket_root.planner().paths_for(&incarnation).unwrap();
        let files = ManagedVmmLaunchFilePaths::for_incarnation(&state, &incarnation).unwrap();
        let ReconcileStep::StartRuntime {
            api_socket_path,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *api_socket_path = sockets.api_socket_path().clone();
        *vsock_socket_path = sockets.vsock_socket_path().clone();
        *memory_file_path = files.memory_file_path().clone();
        *serial_log_path = files.serial_log_path().clone();
        *vmm_log_path = files.vmm_log_path().clone();
        checkpoint.runtime_launch = RuntimeLaunch::Present(Box::new(
            checkpoint.step.start_runtime_launch_identity().unwrap(),
        ));
        let checkpoint_path =
            runtime_checkpoint_path(&state.path().join("checkpoints"), &checkpoint.cat_id);
        crate::runtime::reconciliation::FileCheckpointStore::open(
            &state.path().join("checkpoints"),
            &checkpoint.cat_id,
        )
        .unwrap()
        .create(&checkpoint)
        .unwrap();
        let mut receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
            &checkpoint,
            &state,
            &socket_root,
            current_kernel_node_boot_id().unwrap(),
            cats_api::runtime_reconciliation::RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap(),
        )
        .unwrap();
        let current_boot = current_kernel_node_boot_id().unwrap();
        let old_boot = ["e".repeat(32), "f".repeat(32)]
            .into_iter()
            .map(|value| NodeBootId::new(value).unwrap())
            .find(|value| value != &current_boot)
            .unwrap();
        receipt.set_node_boot_id_for_test(old_boot);
        receipts.publish(&receipt).unwrap();
        (
            InstalledStaleBootVmmRecoveryPorts {
                global: Arc::new(CompositionStaleBootGlobal {
                    calls: global_calls,
                }),
                socket_root,
                launch_root,
                receipts: Arc::clone(&receipts),
            },
            receipts,
            incarnation,
            checkpoint_path,
        )
    }

    fn blank_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn isolated_probe_config(
        root: &std::path::Path,
        state_path: &std::path::Path,
    ) -> TestCleanSlateProbeConfig {
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
        }
    }

    fn isolated_empty_scanner(
        root: &std::path::Path,
        state_path: &std::path::Path,
    ) -> Arc<dyn RuntimeInventoryScanner> {
        clean_slate_scanner_for_test(isolated_probe_config(root, state_path)).unwrap()
    }

    fn composition_scanner(
        root: &std::path::Path,
        state_path: &std::path::Path,
        authority: Arc<CompositionAuthority>,
        blob: Arc<CompositionBlobStore>,
    ) -> Arc<dyn RuntimeInventoryScanner> {
        let data_authority: Arc<dyn VolumeDataAuthority> = authority;
        let blob_store: Arc<dyn BlobStore> = blob;
        clean_slate_scanner_with_volume_authority_and_blob_for_test(
            isolated_probe_config(root, state_path),
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
            object_write_gateway: None,
            listen: "127.0.0.1:0".into(),
            route_v2_machine: None,
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
            observation_barrier_for_test: None,
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
        #[cfg(target_os = "linux")]
        assert!(source.contains("with_stale_boot_vmm_recovery"));
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn production_composition_retires_stale_boot_receipt_before_fresh_full_scan() {
        if skip_without_root_installed_namespaces() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let state_path = root.path().join("state");
        let desired = stale_boot_composition_desired_spec();
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
        let global_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (ports, receipts, incarnation, checkpoint_path) = stale_boot_composition_fixture(
            root.path(),
            &state_path,
            &desired,
            Arc::clone(&global_calls),
        );
        let scan_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let scanner: Arc<dyn RuntimeInventoryScanner> =
            Arc::new(ReceiptRetiredCompositionScanner {
                receipts: Arc::clone(&receipts),
                incarnation: incarnation.clone(),
                calls: Arc::clone(&scan_calls),
            });
        let recovery_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let recovery = SignedRunningPublicationRecovery::with_stale_boot_vmm_recovery(
            recovery_authority,
            ports,
        );

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

        let mut handle = spawn_signed_runtime_cutover_with_overrides(
            composition_config(state_path.clone(), origin, Arc::clone(&authority), blob),
            Some(scanner),
            None,
            Some(recovery),
            None,
        )
        .await
        .unwrap();
        let deadline = Instant::now() + cats_test_support::poll_bound();
        while control.observations.load(Ordering::SeqCst) == 0 {
            if Instant::now() >= deadline {
                panic!(
                    "production composition did not continue into a fresh full scan: registrations={} desired_reads={} global_calls={} scan_calls={} receipt_present={} runner_finished={}",
                    control.registrations.load(Ordering::SeqCst),
                    control.desired_reads.load(Ordering::SeqCst),
                    global_calls.load(Ordering::SeqCst),
                    scan_calls.load(Ordering::SeqCst),
                    receipts.load(&incarnation).unwrap().is_some(),
                    handle.runner_task.is_finished(),
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(global_calls.load(Ordering::SeqCst), 1);
        assert!(scan_calls.load(Ordering::SeqCst) >= 1);
        assert!(receipts.load(&incarnation).unwrap().is_none());
        assert!(checkpoint_path.is_file());

        handle.request_runner_shutdown();
        join_result(
            (&mut handle.runner_task).await,
            "join stale-boot composition",
        )
        .unwrap();
        drop(handle);
        server.abort();
    }

    #[tokio::test]
    async fn loopback_acquire_runner_composition_restarts_from_a22_files_and_checkpoint() {
        if skip_without_root_installed_namespaces() {
            return;
        }
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
            Some(TestDesiredEffectComposition::AcquireOnly),
        )
        .await
        .unwrap();
        let checkpoint_path =
            runtime_checkpoint_path(&state_path.join("checkpoints"), &desired.cat_id);
        let deadline = Instant::now() + cats_test_support::poll_bound();
        let checkpoint_bytes = loop {
            if let Ok(bytes) = std::fs::read(&checkpoint_path) {
                if matches!(
                    decode_runtime_checkpoint(&bytes).unwrap().step,
                    ReconcileStep::ProvisionRootImage { .. }
                ) {
                    break bytes;
                }
            }
            if Instant::now() >= deadline {
                let checkpoint = std::fs::read(&checkpoint_path)
                    .ok()
                    .and_then(|bytes| decode_runtime_checkpoint(&bytes).ok())
                    .map(|checkpoint| checkpoint.step);
                panic!(
                    "composition did not reach ProvisionRootImage: checkpoint={checkpoint:?}, \
                     desired_reads={}, observations={}, a22_calls={}, authority_mutations={}",
                    control.desired_reads.load(Ordering::SeqCst),
                    control.observations.load(Ordering::SeqCst),
                    control.a22_calls.load(Ordering::SeqCst),
                    authority.mutations.load(Ordering::SeqCst),
                );
            }
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
            Some(TestDesiredEffectComposition::AcquireOnly),
        )
        .await
        .unwrap();
        let deadline = Instant::now() + cats_test_support::poll_bound();
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

        readiness.set(true, true);
        assert_eq!(health(State(readiness)).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn observation_barrier_releases_and_cancels_without_a_detached_waiter() {
        let (mut barrier, mut reached, resume) = RuntimeObservationBarrierForTest::channel();
        let effect_dispatched = Arc::new(AtomicBool::new(false));
        let waiter_effect_dispatched = Arc::clone(&effect_dispatched);
        let waiter = tokio::spawn(async move {
            barrier.wait_after_observation().await?;
            waiter_effect_dispatched.store(true, Ordering::Release);
            anyhow::Ok(())
        });

        tokio::time::timeout(cats_test_support::poll_bound(), reached.recv())
            .await
            .expect("observation barrier was not reached")
            .expect("observation barrier sender dropped before reaching the test");
        assert!(!effect_dispatched.load(Ordering::Acquire));
        assert!(!waiter.is_finished());
        resume.send(()).expect("release observation barrier waiter");
        tokio::time::timeout(cats_test_support::poll_bound(), waiter)
            .await
            .expect("released observation barrier waiter did not join")
            .expect("join released observation barrier waiter")
            .expect("released observation barrier failed");
        assert!(effect_dispatched.load(Ordering::Acquire));

        let (mut barrier, mut reached, resume) = RuntimeObservationBarrierForTest::channel();
        let waiter = tokio::spawn(async move { barrier.wait_after_observation().await });
        tokio::time::timeout(cats_test_support::poll_bound(), reached.recv())
            .await
            .expect("cancellation barrier was not reached")
            .expect("cancellation barrier sender dropped before reaching the test");
        waiter.abort();
        let cancellation = tokio::time::timeout(cats_test_support::poll_bound(), waiter)
            .await
            .expect("cancelled observation barrier waiter did not join")
            .expect_err("cancelled observation barrier waiter unexpectedly succeeded");
        assert!(cancellation.is_cancelled());
        assert!(resume.send(()).is_err());
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
            "/v1/nodes/inventory",
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
        if skip_without_root_installed_namespaces() {
            return;
        }
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
        let scanner = isolated_empty_scanner(state_root.path(), &state_path);
        let mut handle = spawn_signed_runtime_cutover_with_scanner(
            SignedRuntimeCutoverConfig {
                object_write_gateway: None,
                listen: "127.0.0.1:0".into(),
                route_v2_machine: None,
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
                observation_barrier_for_test: None,
            },
            Some(scanner),
            Some(TestDesiredEffectComposition::AcquireOnly),
        )
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
        if skip_without_root_installed_namespaces() {
            return;
        }
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
        let scanner = isolated_empty_scanner(state_root.path(), &state_path);
        let mut handle = spawn_signed_runtime_cutover_with_overrides(
            SignedRuntimeCutoverConfig {
                object_write_gateway: None,
                listen: "127.0.0.1:0".into(),
                route_v2_machine: None,
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
                observation_barrier_for_test: None,
            },
            Some(scanner),
            Some(owner_port),
            None,
            Some(TestDesiredEffectComposition::AcquireOnly),
        )
        .await
        .unwrap();

        handle.request_runner_shutdown();
        tokio::time::timeout(cats_test_support::poll_bound(), async {
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
        if skip_without_root_installed_namespaces() {
            return;
        }
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
            object_write_gateway: None,
            listen: "not-a-socket-address".into(),
            route_v2_machine: None,
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
            observation_barrier_for_test: None,
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
        if skip_without_root_installed_namespaces() {
            return;
        }
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
            object_write_gateway: None,
            listen: "not-a-socket-address".into(),
            route_v2_machine: None,
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
            observation_barrier_for_test: None,
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
        assert!(!readiness.is_serving());

        readiness.set(true, true);
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ScanUnavailable(anyhow::anyhow!("physical residue")),
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::RetryAfterDelay
        );
        assert!(!readiness.is_serving());
    }

    #[test]
    fn full_observation_acceptance_controls_readiness() {
        let readiness = Readiness::closed();
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ObservationAccepted {
                    service_ready: false,
                    inventory_attested: false,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(!readiness.is_serving());

        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ObservationAccepted {
                    service_ready: true,
                    inventory_attested: true,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(readiness.is_serving());
    }

    /// The cutover installs every Node cordoned and empty, and a worker
    /// deployment must prove the candidate Agent came up before it commits the
    /// release. An empty Node never serves, so gating that proof on `/healthz`
    /// could never succeed on a first Node; the attestation is the fact the
    /// deployment actually needs.
    #[test]
    fn an_empty_attested_node_is_not_serving_but_is_attested() {
        let readiness = Readiness::closed();
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ObservationAccepted {
                    service_ready: false,
                    inventory_attested: true,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(
            !readiness.is_serving(),
            "an empty Node must not admit Route traffic"
        );
        assert!(
            readiness.is_attested(),
            "an empty Node still established its complete-inventory attestation"
        );
    }

    /// A Node with no Cats accepts a Desired that requires no effect on every
    /// loop. Reporting that as an applied batch made it withdraw the attestation
    /// its own observation had just established, so it oscillated at loop speed
    /// and never held one long enough for a deployment to read it.
    #[test]
    fn an_empty_effect_batch_preserves_the_established_attestation() {
        let readiness = Readiness::closed();
        readiness.set(false, true);
        assert_eq!(
            apply_readiness_policy(RuntimeSpineRunStep::NoEffectsRequired, &readiness).unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(
            readiness.is_attested(),
            "an empty batch applied nothing and cannot withdraw the attestation"
        );

        // A batch that did apply effects still withdraws it.
        readiness.set(false, true);
        assert_eq!(
            apply_readiness_policy(RuntimeSpineRunStep::EffectsApplied, &readiness).unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(
            !readiness.is_attested(),
            "an applied batch must withdraw the attestation until the next complete observation"
        );
    }

    /// An unsettled physical effect withdraws both facts: a release must not
    /// commit on top of work whose postcondition is unknown.
    #[test]
    fn an_unsettled_effect_withdraws_the_attestation_too() {
        let readiness = Readiness::closed();
        readiness.set(true, true);
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::ObservationAccepted {
                    service_ready: false,
                    inventory_attested: false,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(!readiness.is_serving());
        assert!(!readiness.is_attested());
    }

    #[test]
    fn same_process_retained_partial_acceptance_preserves_readiness() {
        let readiness = Readiness::closed();
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::PartialObservationAccepted {
                    degraded_runtimes: 1,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(!readiness.is_serving());

        readiness.set(true, true);
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::PartialObservationAccepted {
                    degraded_runtimes: 0,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::Continue
        );
        assert!(readiness.is_serving());
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
        assert!(!readiness.is_serving());
    }

    #[test]
    fn one_stopped_cat_does_not_terminate_the_node_loop() {
        let readiness = Readiness::closed();
        assert_eq!(
            apply_readiness_policy(
                RuntimeSpineRunStep::EffectStopped {
                    cat_id: Id::new("cat_stopped").unwrap(),
                    reason: crate::runtime_spine::RuntimeDesiredEffectStopReason::LocalContract,
                },
                &readiness,
            )
            .unwrap(),
            RuntimeLoopAction::RetryAfterDelay
        );
        assert!(!readiness.is_serving());
    }
}

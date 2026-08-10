//! Exact transient-service owner for a root-provision blockd.
//!
//! `systemd-run --scope` is deliberately not used: scope execution is
//! synchronous and keeps `systemd-run` as the payload's parent, which creates
//! a second long-lived process and cannot satisfy Runtime's exact-one process
//! proof. A transient `.service` with `Type=exec` gives an asynchronous start
//! acknowledgement plus one manager-owned `MainPID`. Adoption still requires
//! two stable unit reads around `/proc` and a control-socket handshake whose
//! Linux `SO_PEERCRED` PID is that exact `MainPID`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context as _;
#[cfg(target_os = "linux")]
use cats_api::blockd::BlockdControlResponse;
use cats_api::blockd::DurabilityStatus;
use cats_api::runtime_reconciliation::{Durability, HostPath, Id, RandomId128, WireU64};

use crate::runtime_spine::{RuntimeDesiredEffectContext, RuntimePhysicalReadContext};

use super::authorized_blockd::AuthorizedBlockdLaunchConfig;
#[cfg(test)]
use super::root_provision_process::RootProvisionProcessPhase;
use super::root_provision_process::{
    sealed, CheckpointedRootProvisionProcess, RootProvisionBlockdHandshake,
    RootProvisionProcessConflict, RootProvisionProcessEvidence, RootProvisionProcessExpectation,
    RootProvisionProcessInspection, RootProvisionProcessPort, RootProvisionProcessStart,
};

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SYSTEM_SLICE: &str = "system.slice";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const AUTHORIZED_CONTROL_SPEC: &str = "authorized-serving.json";
const STATUS_MAX_BYTES: usize = 64 * 1024;
const COMMAND_OUTPUT_MAX_BYTES: usize = 32 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const UNSET_CREDENTIAL_ENVIRONMENT: [&str; 6] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "CATS_POSTGRES_URL",
];

/// Credentialless process inputs. PostgreSQL must use its rotating `url-file`
/// source and S3 must use instance-role credentials; this type has no field by
/// which a future caller can place a secret in `systemd-run` argv.
#[derive(Debug, Clone)]
pub(crate) struct RootProvisionSystemdConfig {
    blockd: AuthorizedBlockdLaunchConfig,
}

impl RootProvisionSystemdConfig {
    pub(crate) fn new(blockd: AuthorizedBlockdLaunchConfig) -> anyhow::Result<Self> {
        validate_credentialless_blockd_config(&blockd)?;
        Ok(Self { blockd })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransientServiceLaunch {
    unit_id: Id,
    cgroup_path: HostPath,
    executable: PathBuf,
    arguments: Vec<OsString>,
    process_identity_token: RandomId128,
}

impl TransientServiceLaunch {
    fn expected_command_line(&self) -> Vec<OsString> {
        std::iter::once(self.executable.as_os_str().to_owned())
            .chain(self.arguments.iter().cloned())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemdProcessProof {
    process_id: u32,
    process_start_time_ticks: u64,
    executable_path: PathBuf,
    unit_id: Id,
    cgroup_path: HostPath,
    cgroup_process_ids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SystemdInspection {
    Absent,
    Starting,
    Exact(SystemdProcessProof),
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemdStartSubmission {
    Submitted,
    OutcomeUnknown,
    DefinitelyNotStarted,
}

trait SystemdTransientServicePort: Send + Sync {
    fn inspect(
        &self,
        launch: &TransientServiceLaunch,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<SystemdInspection>;

    fn submit(
        &self,
        launch: &TransientServiceLaunch,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<SystemdStartSubmission>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BlockdHandshakeInspection {
    Verified {
        peer_process_id: u32,
        status: Box<DurabilityStatus>,
    },
    Unavailable,
    Malformed,
}

trait BlockdHandshakePort: Send + Sync {
    fn status(
        &self,
        socket_path: &HostPath,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<BlockdHandshakeInspection>;
}

struct SystemdRootProvisionProcessPort<H, S> {
    config: RootProvisionSystemdConfig,
    systemd: H,
    handshake: S,
}

impl<H, S> SystemdRootProvisionProcessPort<H, S> {
    fn new(config: RootProvisionSystemdConfig, systemd: H, handshake: S) -> Self {
        Self {
            config,
            systemd,
            handshake,
        }
    }

    fn launch(
        &self,
        expected: &RootProvisionProcessExpectation,
    ) -> anyhow::Result<TransientServiceLaunch> {
        build_launch(&self.config, expected)
    }
}

impl<H, S> sealed::Sealed for SystemdRootProvisionProcessPort<H, S>
where
    H: SystemdTransientServicePort,
    S: BlockdHandshakePort,
{
}

impl<H, S> RootProvisionProcessPort for SystemdRootProvisionProcessPort<H, S>
where
    H: SystemdTransientServicePort,
    S: BlockdHandshakePort,
{
    fn inspect(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        let launch = self.launch(expected)?;
        self.inspect_exact(expected, &launch, context)
    }

    fn start_checkpointed(
        &self,
        checkpointed: CheckpointedRootProvisionProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessStart> {
        let expected = checkpointed.expected();
        let launch = self.launch(expected)?;
        match self.systemd.submit(&launch, context)? {
            SystemdStartSubmission::DefinitelyNotStarted => {
                return Ok(RootProvisionProcessStart::Unavailable)
            }
            SystemdStartSubmission::Submitted | SystemdStartSubmission::OutcomeUnknown => {}
        }

        loop {
            context.check_active()?;
            match self.inspect_exact(expected, &launch, context)? {
                RootProvisionProcessInspection::Exact(evidence) => {
                    return Ok(RootProvisionProcessStart::Started(evidence))
                }
                RootProvisionProcessInspection::Conflict(problem) => {
                    return Ok(RootProvisionProcessStart::Conflict(problem))
                }
                RootProvisionProcessInspection::Absent
                | RootProvisionProcessInspection::Unavailable => {
                    let remaining = context.deadline().saturating_duration_since(Instant::now());
                    std::thread::sleep(POLL_INTERVAL.min(remaining));
                }
            }
        }
    }
}

impl<H, S> SystemdRootProvisionProcessPort<H, S>
where
    H: SystemdTransientServicePort,
    S: BlockdHandshakePort,
{
    fn inspect_exact(
        &self,
        expected: &RootProvisionProcessExpectation,
        launch: &TransientServiceLaunch,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        let first = match self.systemd.inspect(launch, context)? {
            SystemdInspection::Absent => return Ok(RootProvisionProcessInspection::Absent),
            SystemdInspection::Starting | SystemdInspection::Unavailable => {
                return Ok(RootProvisionProcessInspection::Unavailable)
            }
            SystemdInspection::Conflict => {
                return Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch,
                ))
            }
            SystemdInspection::Exact(proof) => proof,
        };
        let (peer_process_id, status) = match self
            .handshake
            .status(&expected.control_socket_path, context)?
        {
            BlockdHandshakeInspection::Verified {
                peer_process_id,
                status,
            } => (peer_process_id, status),
            BlockdHandshakeInspection::Unavailable => {
                return Ok(RootProvisionProcessInspection::Unavailable)
            }
            BlockdHandshakeInspection::Malformed => {
                return Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch,
                ))
            }
        };
        // Re-read the unit and `/proc` after the socket round trip. A PID that
        // exited/recycled or moved cgroups while the handshake ran is not the
        // process that produced the first proof.
        let second = match self.systemd.inspect(launch, context)? {
            SystemdInspection::Exact(proof) if proof == first => proof,
            SystemdInspection::Starting | SystemdInspection::Unavailable => {
                return Ok(RootProvisionProcessInspection::Unavailable)
            }
            SystemdInspection::Absent
            | SystemdInspection::Exact(_)
            | SystemdInspection::Conflict => {
                return Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch,
                ))
            }
        };
        let Some(handshake) = (peer_process_id == second.process_id)
            .then(|| exact_handshake(expected, peer_process_id, &status))
            .flatten()
        else {
            return Ok(RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::IdentityMismatch,
            ));
        };
        let start_ticks = WireU64::new(second.process_start_time_ticks)
            .context("systemd root-provision process start ticks exceed the Runtime wire range")?;
        Ok(RootProvisionProcessInspection::Exact(Box::new(
            RootProvisionProcessEvidence {
                process_id: second.process_id,
                unit_main_process_id: second.process_id,
                process_start_time_ticks: start_ticks,
                executable_path: HostPath::new(
                    second.executable_path.to_string_lossy().into_owned(),
                )
                .context("systemd returned a noncanonical executable path")?,
                scope_id: second.unit_id,
                cgroup_path: second.cgroup_path,
                cgroup_process_ids: second.cgroup_process_ids,
                control_socket_path: expected.control_socket_path.clone(),
                data_directory: expected.data_directory.clone(),
                ownership_token: expected.process_identity_token.clone(),
                handshake,
            },
        )))
    }
}

fn exact_handshake(
    expected: &RootProvisionProcessExpectation,
    peer_process_id: u32,
    status: &DurabilityStatus,
) -> Option<RootProvisionBlockdHandshake> {
    let expected_mode = match expected.attachment.durability {
        Durability::Strict => "strict",
        Durability::Relaxed => "relaxed",
    };
    (peer_process_id > 0
        && status.volume_id == expected.volume_id.as_str()
        && status.attachment_id == expected.attachment_id.as_str()
        && status.attachment_epoch == Some(expected.attachment_epoch)
        && status.acquire_origin.as_ref() == Some(&expected.attachment.identity.acquire_origin)
        && status.node_id.as_ref() == Some(&expected.node_id)
        && status.placement_epoch == Some(expected.placement_epoch)
        && status.size_bytes == Some(expected.size_bytes)
        && status.scope_id.as_ref() == Some(&expected.scope_id)
        && status.process_identity_token.as_ref() == Some(&expected.process_identity_token)
        && status.device_ownership_token.is_none()
        && status.control_only == Some(true)
        && status.remote_head.as_ref() == Some(expected.expected_remote_head())
        && status.guest_io_enabled == Some(false)
        && status.mode == expected_mode
        && !status.fenced)
        .then(|| RootProvisionBlockdHandshake {
            peer_process_id,
            identity: expected.attachment.identity.clone(),
            size_bytes: expected.size_bytes,
            durability: expected.attachment.durability,
            remote_head: expected.expected_remote_head().clone(),
            process_identity_token: expected.process_identity_token.clone(),
            control_only: true,
            guest_io_enabled: false,
        })
}

fn build_launch(
    config: &RootProvisionSystemdConfig,
    expected: &RootProvisionProcessExpectation,
) -> anyhow::Result<TransientServiceLaunch> {
    validate_credentialless_blockd_config(&config.blockd)?;
    anyhow::ensure!(
        config.blockd.blockd_binary.is_absolute()
            && config.blockd.blockd_binary == Path::new(expected.executable_path.as_str()),
        "root-provision blockd binary does not match checkpointed executable"
    );
    anyhow::ensure!(
        config.blockd.metadata_store.name == "postgres",
        "root-provision blockd requires the frozen postgres authority adapter"
    );
    anyhow::ensure!(
        config.blockd.max_staged_bytes > 0
            && config.blockd.max_staged_packs > 0
            && config.blockd.max_local_bytes > 0,
        "root-provision blockd resource limits must be positive"
    );
    let data_directory = Path::new(expected.data_directory.as_str());
    let authorized_control_spec = data_directory.join(AUTHORIZED_CONTROL_SPEC);
    let mut arguments = vec![
        OsString::from("--volume-id"),
        OsString::from(expected.volume_id.as_str()),
        OsString::from("--data-dir"),
        data_directory.as_os_str().to_owned(),
        OsString::from("--attachment-id"),
        OsString::from(expected.attachment_id.as_str()),
        OsString::from("--attachment-epoch"),
        OsString::from(expected.attachment_epoch.get().to_string()),
        OsString::from("--control-only"),
        OsString::from("--authorized-control-spec"),
        authorized_control_spec.into_os_string(),
        OsString::from("--runtime-scope-id"),
        OsString::from(expected.scope_id.as_str()),
        OsString::from("--process-identity-token"),
        OsString::from(expected.process_identity_token.as_str()),
        OsString::from("--metadata-store-adapter"),
        OsString::from(&config.blockd.metadata_store.name),
        OsString::from("--object-store-adapter"),
        OsString::from(&config.blockd.object_store.name),
        OsString::from("--lease-ttl-ms"),
        OsString::from(
            expected
                .attachment
                .acquire_request
                .lease_duration_ms
                .to_string(),
        ),
        OsString::from("--max-staged-bytes"),
        OsString::from(config.blockd.max_staged_bytes.to_string()),
        OsString::from("--max-staged-packs"),
        OsString::from(config.blockd.max_staged_packs.to_string()),
        OsString::from("--max-local-bytes"),
        OsString::from(config.blockd.max_local_bytes.to_string()),
        OsString::from("--durability"),
        OsString::from(match expected.attachment.durability {
            Durability::Strict => "strict",
            Durability::Relaxed => "relaxed",
        }),
        OsString::from("--listen-control"),
        OsString::from(expected.control_socket_path.as_str()),
    ];
    for option in config.blockd.metadata_store.config.to_cli() {
        arguments.push(OsString::from("--metadata-store-option"));
        arguments.push(option.into());
    }
    for option in config.blockd.object_store.config.to_cli() {
        arguments.push(OsString::from("--object-store-option"));
        arguments.push(option.into());
    }
    Ok(TransientServiceLaunch {
        unit_id: expected.scope_id.clone(),
        cgroup_path: expected.cgroup_path.clone(),
        executable: config.blockd.blockd_binary.clone(),
        arguments,
        process_identity_token: expected.process_identity_token.clone(),
    })
}

fn validate_credentialless_blockd_config(
    config: &AuthorizedBlockdLaunchConfig,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.metadata_store.name == "postgres",
        "root-provision blockd requires the frozen postgres authority adapter"
    );
    config
        .metadata_store
        .config
        .ensure_only("postgres", &["url-file", "ca-file", "session-setup"])
        .context("root-provision metadata adapter contains an unsafe option")?;
    let url_file = config
        .metadata_store
        .config
        .optional("url-file")
        .context("root-provision postgres authority requires url-file credentials")?;
    anyhow::ensure!(
        Path::new(url_file).is_absolute(),
        "root-provision postgres url-file must be absolute"
    );
    if let Some(ca_file) = config.metadata_store.config.optional("ca-file") {
        anyhow::ensure!(
            Path::new(ca_file).is_absolute(),
            "root-provision postgres ca-file must be absolute"
        );
    }
    anyhow::ensure!(
        config
            .metadata_store
            .config
            .optional("session-setup")
            .is_none_or(|value| matches!(value, "client" | "server-verified")),
        "root-provision postgres session-setup is outside the closed adapter contract"
    );
    anyhow::ensure!(
        config.object_store.name == "aws-s3",
        "root-provision blockd requires the selected Direct-S3 object adapter"
    );
    config
        .object_store
        .config
        .ensure_only("aws-s3", &["endpoint", "bucket", "region", "prefix"])
        .context("root-provision S3 adapter contains an unsafe option")?;
    config
        .object_store
        .config
        .required("aws-s3", "bucket")
        .context("root-provision S3 adapter requires a bucket")?;
    if let Some(endpoint) = config.object_store.config.optional("endpoint") {
        validate_s3_endpoint(endpoint)?;
    }
    Ok(())
}

fn validate_s3_endpoint(endpoint: &str) -> anyhow::Result<()> {
    let endpoint =
        reqwest::Url::parse(endpoint).context("root-provision S3 endpoint is invalid")?;
    anyhow::ensure!(
        matches!(endpoint.scheme(), "http" | "https")
            && endpoint.has_host()
            && endpoint.path() == "/"
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && endpoint.username().is_empty()
            && endpoint.password().is_none(),
        "root-provision S3 endpoint must be an HTTP(S) origin without credentials, path, query, or fragment"
    );
    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
struct PlatformSystemdTransientService;

#[derive(Debug, Default, Clone, Copy)]
struct UnixBlockdHandshake;

pub(crate) struct PlatformSystemdRootProvisionProcessPort {
    inner: SystemdRootProvisionProcessPort<PlatformSystemdTransientService, UnixBlockdHandshake>,
}

impl PlatformSystemdRootProvisionProcessPort {
    pub(crate) fn platform(config: RootProvisionSystemdConfig) -> Self {
        Self {
            inner: SystemdRootProvisionProcessPort::new(
                config,
                PlatformSystemdTransientService,
                UnixBlockdHandshake,
            ),
        }
    }
}

impl sealed::Sealed for PlatformSystemdRootProvisionProcessPort {}

impl RootProvisionProcessPort for PlatformSystemdRootProvisionProcessPort {
    fn inspect(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        self.inner.inspect(expected, context)
    }

    fn start_checkpointed(
        &self,
        checkpointed: CheckpointedRootProvisionProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessStart> {
        self.inner.start_checkpointed(checkpointed, context)
    }
}

impl SystemdTransientServicePort for PlatformSystemdTransientService {
    fn inspect(
        &self,
        launch: &TransientServiceLaunch,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<SystemdInspection> {
        platform_inspect_systemd(launch, context)
    }

    fn submit(
        &self,
        launch: &TransientServiceLaunch,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<SystemdStartSubmission> {
        platform_submit_systemd(launch, context)
    }
}

impl BlockdHandshakePort for UnixBlockdHandshake {
    fn status(
        &self,
        socket_path: &HostPath,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<BlockdHandshakeInspection> {
        platform_blockd_status(socket_path, context)
    }
}

#[cfg(target_os = "linux")]
fn platform_submit_systemd(
    launch: &TransientServiceLaunch,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<SystemdStartSubmission> {
    validate_launch(launch)?;
    let mut command = Command::new(SYSTEMD_RUN);
    sanitized_systemd_command(&mut command);
    command
        .arg("--system")
        .arg("--quiet")
        .arg("--no-ask-password")
        .arg(format!("--unit={}", launch.unit_id))
        .arg("--service-type=exec")
        .arg(format!("--slice={SYSTEM_SLICE}"))
        .arg("--property=KillMode=control-group")
        .arg("--property=Restart=no")
        .arg("--property=TimeoutStopSec=2s")
        .arg("--property=Environment=")
        .arg("--property=EnvironmentFile=")
        .arg("--property=PassEnvironment=")
        .arg(format!(
            "--property=UnsetEnvironment={}",
            UNSET_CREDENTIAL_ENVIRONMENT.join(" ")
        ));
    command
        .arg("--")
        .arg(&launch.executable)
        .args(&launch.arguments);
    match run_bounded(command, context)? {
        BoundedCommandResult::Exited(output) if output.status.success() => {
            Ok(SystemdStartSubmission::Submitted)
        }
        BoundedCommandResult::Exited(_) => Ok(SystemdStartSubmission::OutcomeUnknown),
        BoundedCommandResult::Cancelled => Ok(SystemdStartSubmission::OutcomeUnknown),
    }
}

#[cfg(not(target_os = "linux"))]
fn platform_submit_systemd(
    _launch: &TransientServiceLaunch,
    _context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<SystemdStartSubmission> {
    Ok(SystemdStartSubmission::DefinitelyNotStarted)
}

#[cfg(target_os = "linux")]
fn platform_inspect_systemd(
    launch: &TransientServiceLaunch,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<SystemdInspection> {
    validate_launch(launch)?;
    let Some(first) = systemd_unit_properties(&launch.unit_id, context)? else {
        return Ok(SystemdInspection::Unavailable);
    };
    if first.proves_absent(&launch.unit_id) {
        return Ok(SystemdInspection::Absent);
    }
    if first.is_starting(&launch.unit_id) {
        return Ok(SystemdInspection::Starting);
    }
    if !first.is_running(launch) {
        return Ok(SystemdInspection::Conflict);
    }
    let process_id = first.main_pid;
    let Some(sample_before) = sample_linux_process(process_id) else {
        return Ok(SystemdInspection::Starting);
    };
    if sample_before.executable_path != launch.executable
        || sample_before.command_line != launch.expected_command_line()
        || sample_before.control_group != first.control_group
    {
        return Ok(SystemdInspection::Conflict);
    }
    let physical_cgroup = Path::new(CGROUP_ROOT).join(
        first
            .control_group
            .strip_prefix('/')
            .unwrap_or(first.control_group.as_str()),
    );
    if physical_cgroup != Path::new(launch.cgroup_path.as_str()) {
        return Ok(SystemdInspection::Conflict);
    }
    let Some(cgroup_process_ids) = read_cgroup_processes(&physical_cgroup)? else {
        return Ok(SystemdInspection::Unavailable);
    };
    if cgroup_process_ids != [process_id] {
        return Ok(SystemdInspection::Conflict);
    }
    let Some(sample_after) = sample_linux_process(process_id) else {
        return Ok(SystemdInspection::Starting);
    };
    if sample_after != sample_before {
        return Ok(SystemdInspection::Conflict);
    }
    let Some(second) = systemd_unit_properties(&launch.unit_id, context)? else {
        return Ok(SystemdInspection::Unavailable);
    };
    if second != first {
        return Ok(SystemdInspection::Conflict);
    }
    Ok(SystemdInspection::Exact(SystemdProcessProof {
        process_id,
        process_start_time_ticks: sample_after.start_time_ticks,
        executable_path: sample_after.executable_path,
        unit_id: launch.unit_id.clone(),
        cgroup_path: launch.cgroup_path.clone(),
        cgroup_process_ids,
    }))
}

#[cfg(not(target_os = "linux"))]
fn platform_inspect_systemd(
    _launch: &TransientServiceLaunch,
    _context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<SystemdInspection> {
    Ok(SystemdInspection::Unavailable)
}

fn validate_launch(launch: &TransientServiceLaunch) -> anyhow::Result<()> {
    anyhow::ensure!(
        launch.unit_id.as_str().ends_with(".service")
            && launch.executable.is_absolute()
            && launch.cgroup_path.as_str()
                == format!("{CGROUP_ROOT}/{SYSTEM_SLICE}/{}", launch.unit_id.as_str()),
        "invalid transient root-provision service identity"
    );
    Ok(())
}

fn sanitized_systemd_command(command: &mut Command) {
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
}

#[derive(Debug)]
struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

enum BoundedCommandResult {
    Exited(BoundedOutput),
    Cancelled,
}

fn run_bounded(
    mut command: Command,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<BoundedCommandResult> {
    context.check_active()?;
    let mut child = command.spawn().context("spawn fixed systemd helper")?;
    let stdout = child
        .stdout
        .take()
        .context("capture systemd helper stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("capture systemd helper stderr")?;
    let stdout = std::thread::spawn(move || read_bounded_and_drain(stdout));
    let stderr = std::thread::spawn(move || read_bounded_and_drain(stderr));
    loop {
        if let Some(status) = child.try_wait().context("poll fixed systemd helper")? {
            let stdout = stdout
                .join()
                .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??;
            stderr
                .join()
                .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??;
            return Ok(BoundedCommandResult::Exited(BoundedOutput {
                status,
                stdout,
            }));
        }
        if context.check_active().is_err() {
            // This is only the owned short-lived systemd CLI helper. The
            // transient service outcome remains ambiguous and is resolved by
            // exact unit/process/handshake inspection; no unit-name stop is
            // issued here.
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            return Ok(BoundedCommandResult::Cancelled);
        }
        let remaining = context.deadline().saturating_duration_since(Instant::now());
        std::thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn read_bounded_and_drain(mut reader: impl Read) -> anyhow::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if retained.len() < COMMAND_OUTPUT_MAX_BYTES {
            let keep = read.min(COMMAND_OUTPUT_MAX_BYTES - retained.len());
            retained.extend_from_slice(&buffer[..keep]);
            overflow |= keep != read;
        } else {
            overflow = true;
        }
    }
    anyhow::ensure!(!overflow, "fixed systemd helper output exceeded its bound");
    Ok(retained)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemdUnitProperties {
    id: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    main_pid: u32,
    control_group: String,
    exec_start: String,
    environment: String,
    environment_files: String,
    pass_environment: String,
    unset_environment: String,
}

impl SystemdUnitProperties {
    fn proves_absent(&self, expected: &Id) -> bool {
        self.id == expected.as_str()
            && self.load_state == "not-found"
            && self.active_state == "inactive"
            && self.sub_state == "dead"
            && self.main_pid == 0
            && self.control_group.is_empty()
            && self.exec_start.is_empty()
            && self.environment.is_empty()
            && self.environment_files.is_empty()
            && self.pass_environment.is_empty()
            && self.unset_environment.is_empty()
    }

    fn is_starting(&self, expected: &Id) -> bool {
        self.id == expected.as_str()
            && self.load_state == "loaded"
            && matches!(self.active_state.as_str(), "activating" | "reloading")
    }

    fn is_running(&self, launch: &TransientServiceLaunch) -> bool {
        self.id == launch.unit_id.as_str()
            && self.load_state == "loaded"
            && self.active_state == "active"
            && self.sub_state == "running"
            && self.main_pid > 0
            && self.control_group == format!("/{SYSTEM_SLICE}/{}", launch.unit_id.as_str())
            && self
                .exec_start
                .contains(&launch.executable.to_string_lossy().into_owned())
            && self.exec_start.contains("--process-identity-token")
            && self
                .exec_start
                .contains(launch.process_identity_token.as_str())
            && self.environment.is_empty()
            && self.environment_files.is_empty()
            && self.pass_environment.is_empty()
            && exact_unset_environment(&self.unset_environment)
    }
}

#[cfg(target_os = "linux")]
fn systemd_unit_properties(
    unit_id: &Id,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<Option<SystemdUnitProperties>> {
    let mut command = Command::new(SYSTEMCTL);
    sanitized_systemd_command(&mut command);
    command
        .arg("--system")
        .arg("--no-pager")
        .arg("--plain")
        .arg("show")
        .arg(unit_id.as_str());
    for property in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlGroup",
        "ExecStart",
        "Environment",
        "EnvironmentFiles",
        "PassEnvironment",
        "UnsetEnvironment",
    ] {
        command.arg(format!("--property={property}"));
    }
    let BoundedCommandResult::Exited(output) = run_bounded(command, context)? else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    parse_systemd_properties(&output.stdout).map(Some)
}

fn parse_systemd_properties(bytes: &[u8]) -> anyhow::Result<SystemdUnitProperties> {
    let text = std::str::from_utf8(bytes).context("systemctl show output is not UTF-8")?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .context("systemctl show emitted a malformed property")?;
        anyhow::ensure!(
            values.insert(key, value.to_owned()).is_none(),
            "systemctl show emitted a duplicate property"
        );
    }
    anyhow::ensure!(
        values.len() == 11,
        "systemctl show omitted a fixed property"
    );
    let take = |values: &mut BTreeMap<&str, String>, key| {
        values
            .remove(key)
            .with_context(|| format!("systemctl show omitted {key}"))
    };
    let main_pid = take(&mut values, "MainPID")?
        .parse::<u32>()
        .context("systemctl MainPID is not a u32")?;
    Ok(SystemdUnitProperties {
        id: take(&mut values, "Id")?,
        load_state: take(&mut values, "LoadState")?,
        active_state: take(&mut values, "ActiveState")?,
        sub_state: take(&mut values, "SubState")?,
        main_pid,
        control_group: take(&mut values, "ControlGroup")?,
        exec_start: take(&mut values, "ExecStart")?,
        environment: take(&mut values, "Environment")?,
        environment_files: take(&mut values, "EnvironmentFiles")?,
        pass_environment: take(&mut values, "PassEnvironment")?,
        unset_environment: take(&mut values, "UnsetEnvironment")?,
    })
}

fn exact_unset_environment(value: &str) -> bool {
    let mut actual = value
        .split_ascii_whitespace()
        .map(|entry| entry.trim_matches('"'))
        .collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = UNSET_CREDENTIAL_ENVIRONMENT.to_vec();
    expected.sort_unstable();
    actual == expected
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxProcessSample {
    start_time_ticks: u64,
    executable_path: PathBuf,
    command_line: Vec<OsString>,
    control_group: String,
    environment_keys: Vec<Vec<u8>>,
}

#[cfg(target_os = "linux")]
fn sample_linux_process(process_id: u32) -> Option<LinuxProcessSample> {
    use std::os::unix::ffi::OsStringExt as _;

    let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat")).ok()?;
    let (_, after_comm) = stat.rsplit_once(')')?;
    let start_time_ticks = after_comm.split_whitespace().nth(19)?.parse().ok()?;
    if start_time_ticks == 0 {
        return None;
    }
    let executable_path = std::fs::read_link(format!("/proc/{process_id}/exe")).ok()?;
    let command_line = std::fs::read(format!("/proc/{process_id}/cmdline"))
        .ok()?
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| OsString::from_vec(part.to_vec()))
        .collect::<Vec<_>>();
    let cgroup = std::fs::read_to_string(format!("/proc/{process_id}/cgroup")).ok()?;
    let mut unified = cgroup.lines().filter_map(|line| line.strip_prefix("0::"));
    let control_group = unified.next()?.to_owned();
    if unified.next().is_some() || !control_group.starts_with('/') {
        return None;
    }
    let environment = std::fs::read(format!("/proc/{process_id}/environ")).ok()?;
    let environment_keys = parse_process_environment_keys(&environment)?;
    if !credential_environment_is_absent(&environment_keys) {
        return None;
    }
    Some(LinuxProcessSample {
        start_time_ticks,
        executable_path,
        command_line,
        control_group,
        environment_keys,
    })
}

fn parse_process_environment_keys(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.len() > STATUS_MAX_BYTES || bytes.last().is_some_and(|byte| *byte != 0) {
        return None;
    }
    let mut keys = bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let separator = entry.iter().position(|byte| *byte == b'=')?;
            (separator > 0).then(|| entry[..separator].to_vec())
        })
        .collect::<Option<Vec<_>>>()?;
    keys.sort();
    let before = keys.len();
    keys.dedup();
    (keys.len() == before).then_some(keys)
}

fn credential_environment_is_absent(keys: &[Vec<u8>]) -> bool {
    UNSET_CREDENTIAL_ENVIRONMENT.iter().all(|forbidden| {
        !keys
            .iter()
            .any(|key| key.as_slice() == forbidden.as_bytes())
    })
}

#[cfg(target_os = "linux")]
fn read_cgroup_processes(path: &Path) -> anyhow::Result<Option<Vec<u32>>> {
    let bytes = match std::fs::read(path.join("cgroup.procs")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read exact transient service cgroup.procs"),
    };
    anyhow::ensure!(
        bytes.len() <= STATUS_MAX_BYTES,
        "cgroup.procs exceeds bound"
    );
    let text = std::str::from_utf8(&bytes).context("cgroup.procs is not UTF-8")?;
    let mut processes = text
        .lines()
        .map(|line| line.parse::<u32>().context("cgroup.procs PID is invalid"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    processes.sort_unstable();
    processes.dedup();
    Ok(Some(processes))
}

#[cfg(target_os = "linux")]
fn platform_blockd_status(
    socket_path: &HostPath,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<BlockdHandshakeInspection> {
    use std::mem::size_of;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    context.check_active()?;
    let path = socket_path.as_str().as_bytes();
    if path.len() >= 108 {
        return Ok(BlockdHandshakeInspection::Malformed);
    }
    // SAFETY: socket returns a fresh descriptor and retains no Rust memory.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Ok(BlockdHandshakeInspection::Unavailable);
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(path.iter().copied()) {
        *target = source as libc::c_char;
    }
    let address_length = (size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    // SAFETY: descriptor/address are initialized and connect retains neither.
    let connected = unsafe {
        libc::connect(
            descriptor,
            (&raw const address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if connected != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS)
            || !poll_socket(descriptor, libc::POLLOUT, context)?
            || socket_error(descriptor)? != 0
        {
            // SAFETY: descriptor is still owned here.
            unsafe { libc::close(descriptor) };
            return Ok(BlockdHandshakeInspection::Unavailable);
        }
    }
    // SAFETY: ownership of the connected descriptor moves into UnixStream.
    let mut stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(descriptor) };
    let peer_process_id = peer_process_id(stream.as_raw_fd())?;
    if !write_socket(&mut stream, b"status\n", context)? {
        return Ok(BlockdHandshakeInspection::Unavailable);
    }
    let Some(line) = read_status_line(&mut stream, context)? else {
        return Ok(BlockdHandshakeInspection::Unavailable);
    };
    let Ok(line) = std::str::from_utf8(&line) else {
        return Ok(BlockdHandshakeInspection::Malformed);
    };
    let Ok(BlockdControlResponse::Ok(payload)) = BlockdControlResponse::parse_wire(line) else {
        return Ok(BlockdHandshakeInspection::Malformed);
    };
    let Ok(status) = serde_json::from_str::<DurabilityStatus>(&payload) else {
        return Ok(BlockdHandshakeInspection::Malformed);
    };
    Ok(BlockdHandshakeInspection::Verified {
        peer_process_id,
        status: Box::new(status),
    })
}

#[cfg(not(target_os = "linux"))]
fn platform_blockd_status(
    _socket_path: &HostPath,
    _context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<BlockdHandshakeInspection> {
    Ok(BlockdHandshakeInspection::Unavailable)
}

#[cfg(target_os = "linux")]
fn peer_process_id(descriptor: std::os::fd::RawFd) -> anyhow::Result<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials/length point to writable storage for SO_PEERCRED.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    anyhow::ensure!(
        result == 0 && length as usize == std::mem::size_of::<libc::ucred>(),
        "read Unix control peer credentials"
    );
    u32::try_from(credentials.pid).context("Unix control peer PID is not positive")
}

#[cfg(target_os = "linux")]
fn poll_socket(
    descriptor: std::os::fd::RawFd,
    events: i16,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<bool> {
    loop {
        context.check_active()?;
        let remaining = context.deadline().saturating_duration_since(Instant::now());
        let timeout = i32::try_from(POLL_INTERVAL.min(remaining).as_millis())
            .unwrap_or(1)
            .max(1);
        let mut poll = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        // SAFETY: poll points to one initialized pollfd for this call only.
        let result = unsafe { libc::poll(&raw mut poll, 1, timeout) };
        if result > 0 {
            return Ok(poll.revents & (events | libc::POLLERR | libc::POLLHUP) != 0);
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
    }
}

#[cfg(target_os = "linux")]
fn socket_error(descriptor: std::os::fd::RawFd) -> anyhow::Result<i32> {
    let mut error = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: error/length point to valid writable scalar storage.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut error).cast(),
            &raw mut length,
        )
    };
    anyhow::ensure!(result == 0, "read Unix connect result");
    Ok(error)
}

#[cfg(target_os = "linux")]
fn write_socket(
    stream: &mut std::os::unix::net::UnixStream,
    mut bytes: &[u8],
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<bool> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) => return Ok(false),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if !poll_socket(stream.as_raw_fd(), libc::POLLOUT, context)? {
                    return Ok(false);
                }
            }
            Err(_) => return Ok(false),
        }
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn read_status_line(
    stream: &mut std::os::unix::net::UnixStream,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<Option<Vec<u8>>> {
    use std::os::fd::AsRawFd as _;

    let mut line = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(None),
            Ok(read) => {
                for byte in &buffer[..read] {
                    if *byte == b'\n' {
                        line.push(*byte);
                        return Ok(Some(line));
                    }
                    if line.len() == STATUS_MAX_BYTES {
                        return Ok(None);
                    }
                    line.push(*byte);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if !poll_socket(stream.as_raw_fd(), libc::POLLIN, context)? {
                    return Ok(None);
                }
            }
            Err(_) => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;

    use cats_api::runtime_reconciliation::{
        AcquireOrigin, Epoch, FenceEpoch, Generation, NormalAcquireRequest, NormalAcquireResult,
        RemoteHead, Revision, Sha256Digest, UnixMillis,
    };
    use cats_storage::authority::{AttachmentLineageIdentity, AuthorizedServingAttachment};
    use cats_storage::{AdapterConfig, AdapterSelection};

    use super::*;
    use crate::state_directory::StateDirectory;

    #[derive(Default)]
    struct FakeSystemd {
        inspections: Mutex<VecDeque<SystemdInspection>>,
        submissions: Mutex<Vec<SystemdStartSubmission>>,
        launches: Mutex<Vec<TransientServiceLaunch>>,
    }

    impl SystemdTransientServicePort for Arc<FakeSystemd> {
        fn inspect(
            &self,
            launch: &TransientServiceLaunch,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> anyhow::Result<SystemdInspection> {
            self.launches.lock().unwrap().push(launch.clone());
            Ok(self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(SystemdInspection::Unavailable))
        }

        fn submit(
            &self,
            launch: &TransientServiceLaunch,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<SystemdStartSubmission> {
            self.launches.lock().unwrap().push(launch.clone());
            Ok(self
                .submissions
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(SystemdStartSubmission::DefinitelyNotStarted))
        }
    }

    #[derive(Default)]
    struct FakeHandshake {
        inspections: Mutex<VecDeque<BlockdHandshakeInspection>>,
    }

    impl BlockdHandshakePort for Arc<FakeHandshake> {
        fn status(
            &self,
            _socket_path: &HostPath,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> anyhow::Result<BlockdHandshakeInspection> {
            Ok(self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(BlockdHandshakeInspection::Unavailable))
        }
    }

    #[test]
    fn exact_unit_and_same_peer_handshake_are_adopted_across_two_unit_reads() {
        let expected = expectation();
        let proof = proof();
        let systemd = Arc::new(FakeSystemd::default());
        systemd.inspections.lock().unwrap().extend([
            SystemdInspection::Exact(proof.clone()),
            SystemdInspection::Exact(proof.clone()),
        ]);
        let handshake = Arc::new(FakeHandshake::default());
        handshake
            .inspections
            .lock()
            .unwrap()
            .push_back(verified_handshake(4242));
        let port = SystemdRootProvisionProcessPort::new(config(), systemd, handshake);
        assert_eq!(
            port.inspect(&expected, &context()).unwrap(),
            RootProvisionProcessInspection::Exact(Box::new(evidence()))
        );
    }

    #[test]
    fn authority_confirmed_target_adopts_the_same_unit_pid_and_socket() {
        let target = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([2; 32])),
            root_object_id: Some(
                cats_api::runtime_reconciliation::AsciiText::new("roots/root-1").unwrap(),
            ),
        };
        let expected = expectation().with_provisioned_head_for_test(target.clone());
        let proof = proof();
        let systemd = Arc::new(FakeSystemd::default());
        systemd.inspections.lock().unwrap().extend([
            SystemdInspection::Exact(proof.clone()),
            SystemdInspection::Exact(proof),
        ]);
        let mut target_status = status();
        target_status.remote_head = Some(target.clone());
        let handshake = Arc::new(FakeHandshake::default());
        handshake
            .inspections
            .lock()
            .unwrap()
            .push_back(BlockdHandshakeInspection::Verified {
                peer_process_id: 4242,
                status: Box::new(target_status),
            });
        let port = SystemdRootProvisionProcessPort::new(config(), systemd, handshake);
        let mut target_evidence = evidence();
        target_evidence.handshake.remote_head = target;
        assert_eq!(
            port.inspect(&expected, &context()).unwrap(),
            RootProvisionProcessInspection::Exact(Box::new(target_evidence))
        );
    }

    #[test]
    fn generation_only_or_different_remote_head_is_not_an_exact_handshake() {
        let expected = expectation();
        let proof = proof();
        for remote_head in [
            None,
            Some(RemoteHead {
                generation: Generation::new(1).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([9; 32])),
                root_object_id: Some(
                    cats_api::runtime_reconciliation::AsciiText::new("different.node").unwrap(),
                ),
            }),
        ] {
            let systemd = Arc::new(FakeSystemd::default());
            systemd.inspections.lock().unwrap().extend([
                SystemdInspection::Exact(proof.clone()),
                SystemdInspection::Exact(proof.clone()),
            ]);
            let mut wrong_status = status();
            wrong_status.remote_head = remote_head;
            let handshake = Arc::new(FakeHandshake::default());
            handshake
                .inspections
                .lock()
                .unwrap()
                .push_back(BlockdHandshakeInspection::Verified {
                    peer_process_id: 4242,
                    status: Box::new(wrong_status),
                });
            let port = SystemdRootProvisionProcessPort::new(config(), systemd, handshake);
            assert!(matches!(
                port.inspect(&expected, &context()).unwrap(),
                RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch
                )
            ));
        }
    }

    #[test]
    fn control_only_handshake_rejects_any_device_ownership_token() {
        let expected = expectation();
        assert!(exact_handshake(&expected, 4242, &status()).is_some());

        let mut serving_contaminated = status();
        serving_contaminated.device_ownership_token = Some(random('9'));
        assert!(exact_handshake(&expected, 4242, &serving_contaminated).is_none());

        let proof = proof();
        let systemd = Arc::new(FakeSystemd::default());
        systemd.inspections.lock().unwrap().extend([
            SystemdInspection::Exact(proof.clone()),
            SystemdInspection::Exact(proof),
        ]);
        let handshake = Arc::new(FakeHandshake::default());
        handshake
            .inspections
            .lock()
            .unwrap()
            .push_back(BlockdHandshakeInspection::Verified {
                peer_process_id: 4242,
                status: Box::new(serving_contaminated),
            });
        let port = SystemdRootProvisionProcessPort::new(config(), systemd, handshake);
        assert!(matches!(
            port.inspect(&expected, &context()).unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::IdentityMismatch
            )
        ));
    }

    #[test]
    fn response_loss_polls_exact_identity_without_a_second_submission() {
        let expected = expectation();
        let proof = proof();
        let systemd = Arc::new(FakeSystemd::default());
        systemd
            .submissions
            .lock()
            .unwrap()
            .push(SystemdStartSubmission::OutcomeUnknown);
        systemd.inspections.lock().unwrap().extend([
            SystemdInspection::Starting,
            SystemdInspection::Exact(proof.clone()),
            SystemdInspection::Exact(proof),
        ]);
        let handshake = Arc::new(FakeHandshake::default());
        handshake
            .inspections
            .lock()
            .unwrap()
            .push_back(verified_handshake(4242));
        let port = SystemdRootProvisionProcessPort::new(config(), systemd.clone(), handshake);
        let result = port
            .start_checkpointed(
                CheckpointedRootProvisionProcess::for_test(&expected),
                &context(),
            )
            .unwrap();
        assert_eq!(
            result,
            RootProvisionProcessStart::Started(Box::new(evidence()))
        );
        assert_eq!(systemd.submissions.lock().unwrap().len(), 0);
        assert_eq!(
            systemd
                .launches
                .lock()
                .unwrap()
                .iter()
                .filter(|launch| launch.unit_id == expected.scope_id)
                .count(),
            4
        );
    }

    #[test]
    fn pid_replacement_or_foreign_socket_is_conflict_and_never_submits() {
        for foreign_peer in [false, true] {
            let expected = expectation();
            let systemd = Arc::new(FakeSystemd::default());
            let mut second = proof();
            if !foreign_peer {
                second.process_start_time_ticks += 1;
            }
            systemd.inspections.lock().unwrap().extend([
                SystemdInspection::Exact(proof()),
                SystemdInspection::Exact(second),
            ]);
            let handshake = Arc::new(FakeHandshake::default());
            handshake
                .inspections
                .lock()
                .unwrap()
                .push_back(verified_handshake(if foreign_peer { 5252 } else { 4242 }));
            let port = SystemdRootProvisionProcessPort::new(config(), systemd.clone(), handshake);
            assert_eq!(
                port.inspect(&expected, &context()).unwrap(),
                RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch
                )
            );
            assert!(systemd.submissions.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn command_is_control_only_target_surface_without_secret_environment() {
        let launch = build_launch(&config(), &expectation()).unwrap();
        assert_eq!(launch.unit_id, id("cats-root.service"));
        assert_eq!(launch.executable, Path::new("/usr/bin/cats-blockd"));
        for required in [
            "--control-only",
            "--authorized-control-spec",
            "--runtime-scope-id",
            "--process-identity-token",
            "--listen-control",
        ] {
            assert!(launch.arguments.contains(&OsString::from(required)));
        }
        for forbidden in [
            "--create-volume-size",
            "--seed-image-id",
            "--collect-garbage",
            "--listen-unix",
            "--listen-vhost-user",
            "--listen-tcp",
        ] {
            assert!(!launch.arguments.contains(&OsString::from(forbidden)));
        }
        assert!(launch
            .arguments
            .contains(&OsString::from("url-file=/run/cats/postgres-url")));
        assert!(!launch
            .arguments
            .iter()
            .any(|argument| argument.to_string_lossy().contains("postgres://")));
        assert!(!launch
            .arguments
            .iter()
            .any(|argument| argument.to_string_lossy().contains("url-env=")));
        assert!(!launch.arguments.iter().any(|argument| {
            let argument = argument.to_string_lossy();
            argument.contains("--setenv")
                || argument.contains("secret")
                || argument.contains('@')
                || argument.contains('?')
        }));
        assert_eq!(SYSTEMD_RUN, "/usr/bin/systemd-run");
        assert_eq!(SYSTEMCTL, "/usr/bin/systemctl");
    }

    #[test]
    fn fixed_systemctl_properties_distinguish_absent_and_exact_running_unit() {
        let absent = parse_systemd_properties(
            b"Id=cats-root.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=\nExecStart=\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n",
        )
        .unwrap();
        assert!(absent.proves_absent(&id("cats-root.service")));

        let launch = build_launch(&config(), &expectation()).unwrap();
        let running = parse_systemd_properties(
            b"Id=cats-root.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nControlGroup=/system.slice/cats-root.service\nExecStart={ path=/usr/bin/cats-blockd ; argv[]=/usr/bin/cats-blockd --process-identity-token 44444444444444444444444444444444 ; }\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL\n",
        )
        .unwrap();
        assert!(running.is_running(&launch));

        let wrong_token = parse_systemd_properties(
            b"Id=cats-root.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nControlGroup=/system.slice/cats-root.service\nExecStart={ path=/usr/bin/cats-blockd ; argv[]=/usr/bin/cats-blockd --process-identity-token 55555555555555555555555555555555 ; }\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL\n",
        )
        .unwrap();
        assert!(!wrong_token.is_running(&launch));
    }

    #[test]
    fn running_unit_requires_exactly_empty_explicit_environment_sources() {
        let launch = build_launch(&config(), &expectation()).unwrap();
        for bytes in [
            &b"Id=cats-root.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nControlGroup=/system.slice/cats-root.service\nExecStart=/usr/bin/cats-blockd --process-identity-token 44444444444444444444444444444444\nEnvironment=EXTRA=value\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL\n"[..],
            &b"Id=cats-root.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nControlGroup=/system.slice/cats-root.service\nExecStart=/usr/bin/cats-blockd --process-identity-token 44444444444444444444444444444444\nEnvironment=\nEnvironmentFiles=/run/foreign-environment (ignore_errors=no)\nPassEnvironment=\nUnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL\n"[..],
            &b"Id=cats-root.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nControlGroup=/system.slice/cats-root.service\nExecStart=/usr/bin/cats-blockd --process-identity-token 44444444444444444444444444444444\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=AWS_ACCESS_KEY_ID\nUnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL\n"[..],
            &b"Id=cats-root.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nControlGroup=/system.slice/cats-root.service\nExecStart=/usr/bin/cats-blockd --process-identity-token 44444444444444444444444444444444\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI CATS_POSTGRES_URL\n"[..],
            &b"Id=cats-root.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nControlGroup=/system.slice/cats-root.service\nExecStart=/usr/bin/cats-blockd --process-identity-token 44444444444444444444444444444444\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL EXTRA\n"[..],
        ] {
            assert!(!parse_systemd_properties(bytes).unwrap().is_running(&launch));
        }
    }

    #[test]
    fn malformed_or_incomplete_systemctl_properties_are_not_evidence() {
        for bytes in [
            &b"Id=cats-root.service\n"[..],
            &b"Id=cats-root.service\nId=cats-root.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=\nExecStart=\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n"[..],
            &b"Id=cats-root.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=invalid\nControlGroup=\nExecStart=\nEnvironment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n"[..],
        ] {
            assert!(parse_systemd_properties(bytes).is_err());
        }
    }

    #[test]
    fn process_environment_parser_rejects_credentials_and_ambiguous_samples() {
        let ordinary = parse_process_environment_keys(b"LANG=C\0PATH=/usr/bin\0").unwrap();
        assert_eq!(ordinary, [b"LANG".to_vec(), b"PATH".to_vec()]);
        assert!(credential_environment_is_absent(&ordinary));

        for forbidden in UNSET_CREDENTIAL_ENVIRONMENT {
            let sample = format!("LANG=C\0{forbidden}=secret\0");
            let keys = parse_process_environment_keys(sample.as_bytes()).unwrap();
            assert!(!credential_environment_is_absent(&keys));
        }
        for malformed in [
            &b"LANG=C"[..],
            &b"=value\0"[..],
            &b"LANG\0"[..],
            &b"LANG=C\0LANG=D\0"[..],
        ] {
            assert!(parse_process_environment_keys(malformed).is_none());
        }
    }

    #[test]
    fn config_constructor_rejects_environment_credentials_and_unbounded_adapters() {
        for blockd in [
            blockd_config(
                AdapterSelection::new(
                    "postgres",
                    AdapterConfig::from_pairs([("url-env", "CATS_POSTGRES_URL")]).unwrap(),
                ),
                s3_object_store(),
            ),
            blockd_config(
                AdapterSelection::new(
                    "postgres",
                    AdapterConfig::from_pairs([("url-file", "relative/postgres-url")]).unwrap(),
                ),
                s3_object_store(),
            ),
            blockd_config(
                postgres_file_authority(),
                AdapterSelection::new(
                    "file",
                    AdapterConfig::from_pairs([("root", "/srv/cats/objects")]).unwrap(),
                ),
            ),
            blockd_config(
                postgres_file_authority(),
                AdapterSelection::new(
                    "invented",
                    AdapterConfig::from_pairs([("root", "/srv/cats/objects")]).unwrap(),
                ),
            ),
            blockd_config(
                AdapterSelection::new(
                    "postgres",
                    AdapterConfig::from_pairs([
                        ("url-file", "/run/cats/postgres-url"),
                        ("session-setup", "postgres://secret"),
                    ])
                    .unwrap(),
                ),
                s3_object_store(),
            ),
            blockd_config(
                postgres_file_authority(),
                AdapterSelection::new(
                    "aws-s3",
                    AdapterConfig::from_pairs([
                        ("bucket", "cats-runtime-test"),
                        ("endpoint", "https://access:secret@s3.example.test/"),
                    ])
                    .unwrap(),
                ),
            ),
            blockd_config(
                postgres_file_authority(),
                AdapterSelection::new(
                    "aws-s3",
                    AdapterConfig::from_pairs([
                        ("bucket", "cats-runtime-test"),
                        ("endpoint", "https://s3.example.test/?credential=secret"),
                    ])
                    .unwrap(),
                ),
            ),
        ] {
            assert!(RootProvisionSystemdConfig::new(blockd).is_err());
        }

        for session_setup in ["client", "server-verified"] {
            let metadata = AdapterSelection::new(
                "postgres",
                AdapterConfig::from_pairs([
                    ("url-file", "/run/cats/postgres-url"),
                    ("session-setup", session_setup),
                ])
                .unwrap(),
            );
            assert!(
                RootProvisionSystemdConfig::new(blockd_config(metadata, s3_object_store(),))
                    .is_ok()
            );
        }
    }

    fn config() -> RootProvisionSystemdConfig {
        RootProvisionSystemdConfig::new(blockd_config(postgres_file_authority(), s3_object_store()))
            .unwrap()
    }

    fn blockd_config(
        metadata_store: AdapterSelection,
        object_store: AdapterSelection,
    ) -> AuthorizedBlockdLaunchConfig {
        AuthorizedBlockdLaunchConfig {
            blockd_binary: "/usr/bin/cats-blockd".into(),
            metadata_store,
            object_store,
            max_staged_bytes: 1,
            max_staged_packs: 1,
            max_local_bytes: 4_194_304,
        }
    }

    fn postgres_file_authority() -> AdapterSelection {
        AdapterSelection::new(
            "postgres",
            AdapterConfig::from_pairs([("url-file", "/run/cats/postgres-url")]).unwrap(),
        )
    }

    fn s3_object_store() -> AdapterSelection {
        AdapterSelection::new(
            "aws-s3",
            AdapterConfig::from_pairs([("bucket", "cats-runtime-test")]).unwrap(),
        )
    }

    fn expectation() -> RootProvisionProcessExpectation {
        let attachment = attachment();
        let phase = RootProvisionProcessPhase::AwaitingProvision {
            expected_blank_head: attachment.head.clone(),
        };
        RootProvisionProcessExpectation {
            cat_id: id("cat_01"),
            node_id: id("node_a"),
            placement_epoch: Epoch::new(3).unwrap(),
            desired_revision: Revision::new(5).unwrap(),
            spec_digest: digest('f'),
            provision_transition_id: random('3'),
            volume_id: id("vol_root"),
            attachment_id: id("att_root"),
            attachment_epoch: FenceEpoch::new(7).unwrap(),
            scope_id: id("cats-root.service"),
            cgroup_path: host("/sys/fs/cgroup/system.slice/cats-root.service"),
            control_socket_path: host("/run/cats/cat_01/root-provision.sock"),
            data_directory: host("/var/lib/cats/cat_01/root"),
            process_identity_token: random('4'),
            size_bytes: 4_194_304,
            boot_image_digest: digest('1'),
            attachment,
            phase,
            executable_path: host("/usr/bin/cats-blockd"),
        }
    }

    fn proof() -> SystemdProcessProof {
        SystemdProcessProof {
            process_id: 4242,
            process_start_time_ticks: 700,
            executable_path: "/usr/bin/cats-blockd".into(),
            unit_id: id("cats-root.service"),
            cgroup_path: host("/sys/fs/cgroup/system.slice/cats-root.service"),
            cgroup_process_ids: vec![4242],
        }
    }

    fn evidence() -> RootProvisionProcessEvidence {
        let expected = expectation();
        let handshake = exact_handshake(&expected, 4242, &status()).unwrap();
        RootProvisionProcessEvidence {
            process_id: 4242,
            unit_main_process_id: 4242,
            process_start_time_ticks: WireU64::new(700).unwrap(),
            executable_path: host("/usr/bin/cats-blockd"),
            scope_id: id("cats-root.service"),
            cgroup_path: host("/sys/fs/cgroup/system.slice/cats-root.service"),
            cgroup_process_ids: vec![4242],
            control_socket_path: expected.control_socket_path,
            data_directory: expected.data_directory,
            ownership_token: random('4'),
            handshake,
        }
    }

    fn verified_handshake(peer_process_id: u32) -> BlockdHandshakeInspection {
        BlockdHandshakeInspection::Verified {
            peer_process_id,
            status: Box::new(status()),
        }
    }

    fn status() -> DurabilityStatus {
        let expected = expectation();
        DurabilityStatus {
            volume_id: expected.volume_id.to_string(),
            attachment_id: expected.attachment_id.to_string(),
            attachment_epoch: Some(expected.attachment_epoch),
            acquire_origin: Some(expected.attachment.identity.acquire_origin),
            node_id: Some(expected.node_id),
            placement_epoch: Some(expected.placement_epoch),
            guest_io_enabled: Some(false),
            size_bytes: Some(expected.size_bytes),
            scope_id: Some(expected.scope_id),
            process_identity_token: Some(expected.process_identity_token),
            device_ownership_token: None,
            control_only: Some(true),
            remote_head: Some(expected.attachment.head),
            mode: "strict".into(),
            local_durable_generation: 0,
            remote_durable_generation: 0,
            unpublished_generations: 0,
            unpublished_bytes: 0,
            oldest_unpublished_age_ms: 0,
            max_unpublished_generations: 1,
            max_unpublished_bytes: 1,
            local_allocated_bytes: 0,
            local_accounted_bytes: 0,
            max_local_bytes: 4_194_304,
            evicted_cache_chunks: 0,
            backpressured: false,
            fenced: false,
            last_publish_error: None,
        }
    }

    fn attachment() -> AuthorizedServingAttachment {
        let request = NormalAcquireRequest {
            volume_id: id("vol_root"),
            transition_id: random('6'),
            attachment_id: id("att_root"),
            expected_unowned_epoch: FenceEpoch::new(6).unwrap(),
            desired_revision: Revision::new(5).unwrap(),
            placement_epoch: Epoch::new(3).unwrap(),
            lease_duration_ms: 5_000,
        };
        let head = RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: request.volume_id.clone(),
                attachment_id: request.attachment_id.clone(),
                attachment_epoch: FenceEpoch::new(7).unwrap(),
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: request.transition_id.clone(),
                },
                node_id: id("node_a"),
                placement_epoch: request.placement_epoch,
            },
            size_bytes: 4_194_304,
            durability: Durability::Strict,
            head: head.clone(),
            lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
            acquire_result: NormalAcquireResult {
                volume_id: request.volume_id.clone(),
                transition_id: request.transition_id.clone(),
                attachment_id: request.attachment_id.clone(),
                resulting_epoch: FenceEpoch::new(7).unwrap(),
                resulting_head: head,
                lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
            },
            acquire_request: request,
        }
    }

    fn context() -> RuntimeDesiredEffectContext {
        let root = tempfile::tempdir().unwrap();
        let path = root.keep();
        RuntimeDesiredEffectContext::for_test(
            StateDirectory::unanchored(path),
            Instant::now() + Duration::from_secs(1),
        )
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn host(value: &str) -> HostPath {
        HostPath::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn digest(value: char) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
    }
}

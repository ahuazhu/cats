//! Checkpointed systemd process boundary for one fresh Cloud Hypervisor.
//!
//! The durable `StartRuntime` checkpoint is the only launch request.  The
//! Agent retains that exact checkpoint and every installed artifact
//! descriptor, then asks PID 1 to pass those descriptors to the fixed
//! `cats-vmm-launcher` with `OpenFile=`.  No second JSON request, caller-chosen
//! argv, or pathname-only artifact is accepted at this boundary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::Path;
#[cfg(any(test, target_os = "linux"))]
use std::process::Command;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, ControlHandshakeEvidence, HostPath, Id, ObservedVmShape,
    OwnershipTokenEvidence, PreparedDeviceInput, ProcessEvidence, ProcessRole, ProcessState,
    RandomId128, ReconcileStep, RuntimeCheckpoint, RuntimeLaunchArtifact, RuntimeNetworkIdentity,
    VmmBootProvenance, WireU64,
};

use crate::runtime_spine::RuntimeDesiredEffectContext;
use crate::vmm_launcher::{
    VmmLauncherPlan, RUNTIME_INCARNATION_ENVIRONMENT, VMM_LAUNCHER_CONTRACT_ARGUMENT,
    VMM_PROCESS_TOKEN_ENVIRONMENT,
};

use super::checkpoint::{FileCheckpointStore, RetainedCurrentCheckpoint, StoredCheckpoint};
#[cfg(any(test, target_os = "linux"))]
use super::systemd_root_provision::{
    sanitized_systemd_command, SYSTEMD_RUN, UNSET_PROCESS_ENVIRONMENT,
};
#[cfg(target_os = "linux")]
use super::systemd_root_provision::{submit_fixed_systemd_command, SystemdStartSubmission};
use super::vmm_launch_artifacts::{RetainedVmmLaunchArtifacts, VmmLaunchArtifactDescriptors};

const SYSTEM_SLICE: &str = "system.slice";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const VMM_KILL_MODE: &str = "control-group";
const VMM_RESTART: &str = "no";
const VMM_UMASK: &str = "0077";
const VMM_TIMEOUT_STOP: &str = "2s";

const CHECKPOINT_FD_NAME: &str = "cats-checkpoint-v1";
const VMM_FD_NAME: &str = "cats-vmm-v1";
const KERNEL_FD_NAME: &str = "cats-kernel-v1";
const INITRAMFS_FD_NAME: &str = "cats-initramfs-v1";

mod sealed {
    pub(crate) trait Sealed {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmmProcessStart {
    Submitted,
    OutcomeUnknown,
    DefinitelyNotStarted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VmmProcessConflict {
    IdentityMismatch,
    DuplicateIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VmmProcessInspection {
    Absent,
    Exact(Box<VmmProcessEvidence>),
    Conflict(VmmProcessConflict),
    Unavailable,
}

/// Exact provider-local systemd/process/API inspection.  This is not by
/// itself an absence permit: a start effect must consume the same sealed
/// Node-global admission used by the complete inventory sweep.
pub(crate) trait VmmProcessPort: sealed::Sealed + Send + Sync {
    fn inspect(
        &self,
        expected: &VmmProcessExpectation,
        context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> anyhow::Result<VmmProcessInspection>;

    fn start_checkpointed(
        &self,
        checkpointed: CheckpointedVmmProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<VmmProcessStart>;
}

/// Closed launch identity shared by the physical start adapter and the future
/// full-inventory VMM inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmmProcessExpectation {
    checkpoint: RuntimeCheckpoint,
    unit_id: Id,
    cgroup_path: HostPath,
    launcher_executable: RuntimeLaunchArtifact,
    boot: VmmBootProvenance,
    launcher_command_line: Vec<OsString>,
    vmm_command_line: Vec<OsString>,
    runtime_incarnation: RandomId128,
    process_identity_token: RandomId128,
    /// Present only on an expectation minted by the descriptor-rooted full
    /// scanner.  A naked checkpoint is sufficient to build one start command,
    /// but it cannot authorize adoption because fixed fd 64 must be joined to
    /// the exact current checkpoint pathname.
    checkpoint_path: Option<HostPath>,
}

impl VmmProcessExpectation {
    pub(crate) fn from_checkpoint(checkpoint: RuntimeCheckpoint) -> anyhow::Result<Self> {
        // Direct Rust construction must cross the same F0/cross validator as
        // persisted input before it can become a process expectation.
        encode_runtime_checkpoint(&checkpoint)
            .context("validate VMM process StartRuntime checkpoint")?;
        let plan = VmmLauncherPlan::from_checkpoint(checkpoint.clone())?;
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            scope_id,
            launcher_executable,
            boot,
            process_identity_token,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("VMM process expectation is not StartRuntime")
        };
        let expected_unit = Id::new(format!("cats-vmm-{}.service", runtime_incarnation.as_str()))
            .context("StartRuntime incarnation cannot form a systemd unit")?;
        anyhow::ensure!(
            scope_id == &expected_unit,
            "StartRuntime systemd unit is not the exact incarnation-derived identity"
        );
        let cgroup_path = HostPath::new(format!(
            "{CGROUP_ROOT}/{SYSTEM_SLICE}/{}",
            expected_unit.as_str()
        ))
        .context("StartRuntime cgroup path is not canonical")?;
        let launcher_command_line = vec![
            OsString::from(launcher_executable.path.as_str()),
            OsString::from(VMM_LAUNCHER_CONTRACT_ARGUMENT),
        ];
        let vmm_command_line = std::iter::once(OsString::from(boot.vmm_executable.path.as_str()))
            .chain(plan.cloud_hypervisor_arguments().iter().cloned())
            .collect();
        let launcher_executable = (**launcher_executable).clone();
        let boot = (**boot).clone();
        let runtime_incarnation = runtime_incarnation.clone();
        let process_identity_token = process_identity_token.clone();
        Ok(Self {
            checkpoint,
            unit_id: expected_unit,
            cgroup_path,
            launcher_executable,
            boot,
            launcher_command_line,
            vmm_command_line,
            runtime_incarnation,
            process_identity_token,
            checkpoint_path: None,
        })
    }

    pub(crate) fn with_checkpoint_path(
        mut self,
        checkpoint_path: HostPath,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Path::new(checkpoint_path.as_str()).is_absolute(),
            "VMM process checkpoint path is not absolute"
        );
        self.checkpoint_path = Some(checkpoint_path);
        Ok(self)
    }

    pub(crate) fn cat_id(&self) -> &Id {
        &self.checkpoint.cat_id
    }

    pub(crate) fn checkpoint(&self) -> &RuntimeCheckpoint {
        &self.checkpoint
    }

    pub(crate) fn unit_id(&self) -> &Id {
        &self.unit_id
    }

    pub(crate) fn cgroup_path(&self) -> &HostPath {
        &self.cgroup_path
    }

    pub(crate) fn launcher_command_line(&self) -> &[OsString] {
        &self.launcher_command_line
    }

    pub(crate) fn vmm_command_line(&self) -> &[OsString] {
        &self.vmm_command_line
    }

    pub(crate) fn vmm_executable(&self) -> &RuntimeLaunchArtifact {
        &self.boot.vmm_executable
    }

    pub(crate) fn runtime_incarnation(&self) -> &RandomId128 {
        &self.runtime_incarnation
    }

    pub(crate) fn process_identity_token(&self) -> &RandomId128 {
        &self.process_identity_token
    }

    pub(crate) fn checkpoint_path(&self) -> Option<&HostPath> {
        self.checkpoint_path.as_ref()
    }

    pub(crate) fn api_socket_path(&self) -> &HostPath {
        let ReconcileStep::StartRuntime {
            api_socket_path, ..
        } = &self.checkpoint.step
        else {
            unreachable!("VMM expectation construction checked StartRuntime")
        };
        api_socket_path
    }

    pub(crate) fn vsock_socket_path(&self) -> &HostPath {
        let ReconcileStep::StartRuntime {
            vsock_socket_path, ..
        } = &self.checkpoint.step
        else {
            unreachable!("VMM expectation construction checked StartRuntime")
        };
        vsock_socket_path
    }

    pub(crate) fn memory_file_path(&self) -> &HostPath {
        let ReconcileStep::StartRuntime {
            memory_file_path, ..
        } = &self.checkpoint.step
        else {
            unreachable!("VMM expectation construction checked StartRuntime")
        };
        memory_file_path
    }

    pub(crate) fn serial_log_path(&self) -> &HostPath {
        let ReconcileStep::StartRuntime {
            serial_log_path, ..
        } = &self.checkpoint.step
        else {
            unreachable!("VMM expectation construction checked StartRuntime")
        };
        serial_log_path
    }

    pub(crate) fn vmm_log_path(&self) -> &HostPath {
        let ReconcileStep::StartRuntime { vmm_log_path, .. } = &self.checkpoint.step else {
            unreachable!("VMM expectation construction checked StartRuntime")
        };
        vmm_log_path
    }

    fn exact_environment(&self) -> BTreeMap<OsString, OsString> {
        BTreeMap::from([
            (
                OsString::from(RUNTIME_INCARNATION_ENVIRONMENT),
                OsString::from(self.runtime_incarnation.as_str()),
            ),
            (
                OsString::from(VMM_PROCESS_TOKEN_ENVIRONMENT),
                OsString::from(self.process_identity_token.as_str()),
            ),
        ])
    }

    fn vm_info(&self) -> VmmVmInfoEvidence {
        let ReconcileStep::StartRuntime {
            vcpus,
            memory_bytes,
            boot_image_digest,
            guest_config_digest,
            guest_cid,
            network,
            devices,
            ..
        } = &self.checkpoint.step
        else {
            unreachable!("VMM expectation construction checked StartRuntime")
        };
        VmmVmInfoEvidence {
            vcpus: *vcpus,
            memory_bytes: *memory_bytes,
            boot_image_digest: boot_image_digest.clone(),
            guest_config_digest: guest_config_digest.clone(),
            guest_cid: *guest_cid,
            network: (**network).clone(),
            devices: devices.clone(),
        }
    }

    pub(crate) fn prove_exact_process(
        self,
        evidence: VmmProcessEvidence,
    ) -> anyhow::Result<ExactVmmProcessProof> {
        anyhow::ensure!(
            evidence.exactly_matches(&self),
            "VMM evidence does not exactly match its StartRuntime expectation"
        );
        Ok(ExactVmmProcessProof {
            expectation: self,
            evidence,
        })
    }

    #[cfg(test)]
    pub(crate) fn exact_evidence_for_test(&self, process_id: u32) -> VmmProcessEvidence {
        VmmProcessEvidence {
            process_id,
            unit_main_process_id: process_id,
            process_start_time_ticks: WireU64::new(u64::from(process_id) + 100).unwrap(),
            executable_path: self.vmm_executable().path.clone(),
            unit_id: self.unit_id.clone(),
            cgroup_path: self.cgroup_path.clone(),
            cgroup_process_ids: vec![process_id],
            unit_launcher_command_line: self.launcher_command_line.clone(),
            command_line: self.vmm_command_line.clone(),
            environment: self.exact_environment(),
            api_socket_path: self.api_socket_path().clone(),
            vsock_socket_path: self.vsock_socket_path().clone(),
            process_identity_token: self.process_identity_token.clone(),
            runtime_incarnation: self.runtime_incarnation.clone(),
            api_peer_process_id: process_id,
            fixed_descriptors_exact: true,
            api_socket_exact: true,
            vmm_ping_verified: true,
            vm_info: self.vm_info(),
        }
    }
}

/// Provider-private values returned by the fixed `vm.info` parser.  The
/// digests are not claimed to be returned by Cloud Hypervisor; the inspector
/// joins its exact launch descriptors/argv to the physical shape below before
/// constructing this value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VmmVmInfoEvidence {
    vcpus: u32,
    memory_bytes: u64,
    boot_image_digest: cats_api::runtime_reconciliation::Sha256Digest,
    guest_config_digest: cats_api::runtime_reconciliation::Sha256Digest,
    guest_cid: u32,
    network: RuntimeNetworkIdentity,
    devices: Vec<PreparedDeviceInput>,
}

/// Complete provider-private VMM proof.  Booleans here are deliberately
/// private: only the platform inspector in this module may assert that the
/// fixed descriptor set, API socket and both CH handshakes were physically
/// checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmmProcessEvidence {
    process_id: u32,
    unit_main_process_id: u32,
    process_start_time_ticks: WireU64,
    executable_path: HostPath,
    unit_id: Id,
    cgroup_path: HostPath,
    cgroup_process_ids: Vec<u32>,
    unit_launcher_command_line: Vec<OsString>,
    command_line: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    api_socket_path: HostPath,
    vsock_socket_path: HostPath,
    process_identity_token: RandomId128,
    runtime_incarnation: RandomId128,
    api_peer_process_id: u32,
    fixed_descriptors_exact: bool,
    api_socket_exact: bool,
    vmm_ping_verified: bool,
    vm_info: VmmVmInfoEvidence,
}

impl VmmProcessEvidence {
    fn exactly_matches(&self, expected: &VmmProcessExpectation) -> bool {
        expected.checkpoint_path().is_some()
            && self.process_id > 0
            && self.unit_main_process_id == self.process_id
            && self.process_start_time_ticks.get() > 0
            && self.executable_path == expected.vmm_executable().path
            && self.unit_id == *expected.unit_id()
            && self.cgroup_path == *expected.cgroup_path()
            && self.cgroup_process_ids == [self.process_id]
            && self.unit_launcher_command_line == expected.launcher_command_line()
            && self.command_line == expected.vmm_command_line()
            && self.environment == expected.exact_environment()
            && self.api_socket_path == *expected.api_socket_path()
            && self.vsock_socket_path == *expected.vsock_socket_path()
            && self.process_identity_token == *expected.process_identity_token()
            && self.runtime_incarnation == *expected.runtime_incarnation()
            && self.api_peer_process_id == self.process_id
            && self.fixed_descriptors_exact
            && self.api_socket_exact
            && self.vmm_ping_verified
            && self.vm_info == expected.vm_info()
    }

    pub(crate) fn unit_id(&self) -> &Id {
        &self.unit_id
    }

    pub(crate) fn process_id(&self) -> u32 {
        self.process_id
    }

    pub(crate) fn api_socket_path(&self) -> &HostPath {
        &self.api_socket_path
    }

    pub(crate) fn vsock_socket_path(&self) -> &HostPath {
        &self.vsock_socket_path
    }

    pub(crate) fn into_process_evidence(self) -> ProcessEvidence {
        ProcessEvidence {
            role: ProcessRole::Vmm {
                runtime_incarnation: self.runtime_incarnation,
            },
            process_id: self.process_id,
            process_start_time_ticks: self.process_start_time_ticks,
            executable_path: self.executable_path,
            scope_id: self.unit_id,
            control_socket_path: self.api_socket_path,
            state: ProcessState::Running,
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: self.process_identity_token,
            },
            control_handshake: ControlHandshakeEvidence::Verified,
            observed_vm_shape: Some(ObservedVmShape {
                vcpus: self.vm_info.vcpus,
                memory_bytes: self.vm_info.memory_bytes,
                boot_image_digest: self.vm_info.boot_image_digest,
                guest_config_digest: self.vm_info.guest_config_digest,
            }),
        }
    }
}

/// Unforgeable exact VMM proof retained in the accepted full-inventory
/// admission.  Public `ProcessEvidence` alone cannot reconstruct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactVmmProcessProof {
    expectation: VmmProcessExpectation,
    evidence: VmmProcessEvidence,
}

impl ExactVmmProcessProof {
    pub(crate) fn expectation(&self) -> &VmmProcessExpectation {
        &self.expectation
    }

    pub(crate) fn evidence(&self) -> &VmmProcessEvidence {
        &self.evidence
    }

    pub(crate) fn into_process_evidence(self) -> ProcessEvidence {
        self.evidence.into_process_evidence()
    }
}

/// Descriptor-retained authority held across the one `systemd-run` attempt.
pub(crate) struct CheckpointedVmmProcess<'a> {
    expected: &'a VmmProcessExpectation,
    checkpoint: RetainedCurrentCheckpoint<'a>,
    artifacts: &'a RetainedVmmLaunchArtifacts,
}

impl<'a> CheckpointedVmmProcess<'a> {
    pub(crate) fn prepare(
        expected: &'a VmmProcessExpectation,
        store: &'a FileCheckpointStore,
        stored: &'a StoredCheckpoint,
        artifacts: &'a RetainedVmmLaunchArtifacts,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            stored.checkpoint() == expected.checkpoint(),
            "VMM process expectation is not the retained current checkpoint"
        );
        anyhow::ensure!(
            artifacts.launcher_executable() == &expected.launcher_executable
                && artifacts.boot() == expected.boot,
            "installed VMM artifacts do not match StartRuntime"
        );
        let checkpoint = store
            .retain_current_checkpoint(stored)
            .context("retain current StartRuntime checkpoint descriptor")?;
        let checkpointed = Self {
            expected,
            checkpoint,
            artifacts,
        };
        checkpointed.assert_current()?;
        Ok(checkpointed)
    }

    fn expected(&self) -> &VmmProcessExpectation {
        self.expected
    }

    fn checkpoint_descriptor(&self) -> &File {
        self.checkpoint.descriptor()
    }

    fn artifact_descriptors(&self) -> VmmLaunchArtifactDescriptors<'_> {
        self.artifacts.descriptors()
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.checkpoint.checkpoint() == self.expected.checkpoint(),
            "retained VMM checkpoint value changed"
        );
        self.checkpoint
            .assert_current()
            .context("revalidate current StartRuntime checkpoint")?;
        self.artifacts
            .assert_current()
            .context("revalidate installed VMM launch artifacts")?;
        anyhow::ensure!(
            self.artifacts.launcher_executable() == &self.expected.launcher_executable
                && self.artifacts.boot() == self.expected.boot,
            "installed VMM launch projection changed"
        );
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PlatformSystemdVmmProcessPort;

impl sealed::Sealed for PlatformSystemdVmmProcessPort {}

impl VmmProcessPort for PlatformSystemdVmmProcessPort {
    fn inspect(
        &self,
        _expected: &VmmProcessExpectation,
        _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> anyhow::Result<VmmProcessInspection> {
        // Production inventory wiring is added only together with the full
        // systemd/proc/fd/API bracket.  Until then no caller can turn this
        // provider-local Unavailable result into absence or an adoption proof.
        Ok(VmmProcessInspection::Unavailable)
    }

    fn start_checkpointed(
        &self,
        checkpointed: CheckpointedVmmProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<VmmProcessStart> {
        context.check_active()?;
        checkpointed.assert_current()?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = checkpointed;
            Ok(VmmProcessStart::DefinitelyNotStarted)
        }
        #[cfg(target_os = "linux")]
        {
            let open_files = SystemdVmmOpenFiles::from_checkpointed(&checkpointed);
            let command = systemd_vmm_command(checkpointed.expected(), open_files)?;
            checkpointed.assert_current()?;
            context.check_active()?;
            let submitted = submit_fixed_systemd_command(command, context);
            // After the helper may have contacted PID 1, every local drift or
            // cancellation is an ambiguous external result, never a generic
            // error which a caller could retry in the same admission.
            if checkpointed.assert_current().is_err() || context.check_active().is_err() {
                return Ok(VmmProcessStart::OutcomeUnknown);
            }
            Ok(match submitted {
                SystemdStartSubmission::Submitted => VmmProcessStart::Submitted,
                SystemdStartSubmission::OutcomeUnknown => VmmProcessStart::OutcomeUnknown,
                SystemdStartSubmission::DefinitelyNotStarted => {
                    VmmProcessStart::DefinitelyNotStarted
                }
            })
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SystemdVmmOpenFiles {
    checkpoint: i32,
    vmm: i32,
    kernel: i32,
    initramfs: Option<i32>,
}

impl SystemdVmmOpenFiles {
    #[cfg(target_os = "linux")]
    fn from_checkpointed(checkpointed: &CheckpointedVmmProcess<'_>) -> Self {
        let artifacts = checkpointed.artifact_descriptors();
        Self {
            checkpoint: checkpointed.checkpoint_descriptor().as_raw_fd(),
            vmm: artifacts.vmm_executable().as_raw_fd(),
            kernel: artifacts.kernel().as_raw_fd(),
            initramfs: artifacts.initramfs().map(|file| file.as_raw_fd()),
        }
    }

    fn named(self) -> [Option<(&'static str, i32)>; 4] {
        [
            Some((CHECKPOINT_FD_NAME, self.checkpoint)),
            Some((VMM_FD_NAME, self.vmm)),
            Some((KERNEL_FD_NAME, self.kernel)),
            self.initramfs.map(|fd| (INITRAMFS_FD_NAME, fd)),
        ]
    }
}

#[cfg(any(test, target_os = "linux"))]
fn systemd_vmm_command(
    expected: &VmmProcessExpectation,
    open_files: SystemdVmmOpenFiles,
) -> anyhow::Result<Command> {
    let mut descriptors = open_files.named().into_iter().flatten().collect::<Vec<_>>();
    anyhow::ensure!(
        descriptors.iter().all(|(_, fd)| *fd >= 3),
        "VMM systemd transfer contains a reserved descriptor"
    );
    descriptors.sort_unstable_by_key(|(_, fd)| *fd);
    anyhow::ensure!(
        descriptors.windows(2).all(|pair| pair[0].1 != pair[1].1),
        "VMM systemd transfer reuses one descriptor"
    );

    let mut command = Command::new(SYSTEMD_RUN);
    sanitized_systemd_command(&mut command);
    command
        .arg("--system")
        .arg("--quiet")
        .arg("--no-ask-password")
        .arg("--collect")
        .arg(format!("--unit={}", expected.unit_id()))
        .arg("--service-type=exec")
        .arg(format!("--slice={SYSTEM_SLICE}"))
        .arg(format!("--property=KillMode={VMM_KILL_MODE}"))
        .arg(format!("--property=Restart={VMM_RESTART}"))
        .arg(format!("--property=UMask={VMM_UMASK}"))
        .arg(format!("--property=TimeoutStopSec={VMM_TIMEOUT_STOP}"))
        .arg("--property=EnvironmentFile=")
        .arg("--property=PassEnvironment=")
        .arg(format!(
            "--property=UnsetEnvironment={}",
            UNSET_PROCESS_ENVIRONMENT.join(" ")
        ))
        .arg(format!(
            "--setenv={RUNTIME_INCARNATION_ENVIRONMENT}={}",
            expected.runtime_incarnation()
        ))
        .arg(format!(
            "--setenv={VMM_PROCESS_TOKEN_ENVIRONMENT}={}",
            expected.process_identity_token()
        ));
    let process_id = std::process::id();
    for (name, descriptor) in descriptors {
        command.arg(format!(
            "--property=OpenFile=/proc/{process_id}/fd/{descriptor}:{name}:read-only"
        ));
    }
    let [launcher, argument] = expected.launcher_command_line() else {
        anyhow::bail!("VMM launcher command line is not the exact two arguments")
    };
    anyhow::ensure!(
        Path::new(launcher).is_absolute() && argument == VMM_LAUNCHER_CONTRACT_ARGUMENT,
        "VMM launcher command line is not canonical"
    );
    command.arg("--").arg(launcher).arg(argument);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cats_api::runtime_reconciliation::decode_runtime_checkpoint;

    use super::*;

    fn expectation() -> VmmProcessExpectation {
        let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        VmmProcessExpectation::from_checkpoint(checkpoint).unwrap()
    }

    fn inventory_expectation() -> VmmProcessExpectation {
        expectation()
            .with_checkpoint_path(HostPath::new("/var/lib/cats/checkpoints/cat_01.json").unwrap())
            .unwrap()
    }

    #[test]
    fn start_runtime_freezes_manager_and_live_vmm_identities() {
        let expected = expectation();
        assert_eq!(
            expected.unit_id().as_str(),
            format!(
                "cats-vmm-{}.service",
                expected.runtime_incarnation().as_str()
            )
        );
        assert_eq!(
            expected.cgroup_path().as_str(),
            format!(
                "/sys/fs/cgroup/system.slice/{}",
                expected.unit_id().as_str()
            )
        );
        assert_eq!(
            expected.launcher_command_line(),
            [
                OsString::from("/usr/libexec/cats-vmm-launcher"),
                OsString::from("--contract-version=1")
            ]
        );
        assert_eq!(
            expected.vmm_command_line().first(),
            Some(&OsString::from("/usr/bin/cloud-hypervisor"))
        );
    }

    #[test]
    fn systemd_submission_passes_only_the_exact_named_descriptors_and_identity() {
        let expected = expectation();
        let command = systemd_vmm_command(
            &expected,
            SystemdVmmOpenFiles {
                checkpoint: 41,
                vmm: 42,
                kernel: 43,
                initramfs: Some(44),
            },
        )
        .unwrap();
        let arguments = command
            .get_args()
            .map(|argument| argument.to_str().unwrap())
            .collect::<Vec<_>>();
        let process_id = std::process::id();
        for (name, descriptor) in [
            (CHECKPOINT_FD_NAME, 41),
            (VMM_FD_NAME, 42),
            (KERNEL_FD_NAME, 43),
            (INITRAMFS_FD_NAME, 44),
        ] {
            assert!(arguments.contains(
                &format!("--property=OpenFile=/proc/{process_id}/fd/{descriptor}:{name}:read-only")
                    .as_str()
            ));
        }
        assert!(arguments.contains(
            &format!(
                "--setenv={RUNTIME_INCARNATION_ENVIRONMENT}={}",
                expected.runtime_incarnation()
            )
            .as_str()
        ));
        assert!(arguments.contains(
            &format!(
                "--setenv={VMM_PROCESS_TOKEN_ENVIRONMENT}={}",
                expected.process_identity_token()
            )
            .as_str()
        ));
        assert_eq!(
            &arguments[arguments.len() - 3..],
            [
                "--",
                "/usr/libexec/cats-vmm-launcher",
                "--contract-version=1"
            ]
        );
    }

    #[test]
    fn descriptor_alias_is_rejected_before_systemd_can_be_called() {
        assert!(systemd_vmm_command(
            &expectation(),
            SystemdVmmOpenFiles {
                checkpoint: 41,
                vmm: 41,
                kernel: 43,
                initramfs: None,
            },
        )
        .is_err());
    }

    #[test]
    fn exact_provider_proof_is_the_only_vmm_public_projection() {
        let expected = inventory_expectation();
        let proof = expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(4242))
            .unwrap();
        let projected = proof.into_process_evidence();
        assert_eq!(
            projected.role,
            ProcessRole::Vmm {
                runtime_incarnation: expected.runtime_incarnation().clone(),
            }
        );
        assert_eq!(projected.process_id, 4242);
        assert_eq!(projected.executable_path, expected.vmm_executable().path);
        assert_eq!(projected.scope_id, *expected.unit_id());
        assert_eq!(projected.control_socket_path, *expected.api_socket_path());
        assert_eq!(projected.state, ProcessState::Running);
        assert_eq!(
            projected.ownership_token,
            OwnershipTokenEvidence::Valid {
                ownership_token: expected.process_identity_token().clone(),
            }
        );
        assert_eq!(
            projected.control_handshake,
            ControlHandshakeEvidence::Verified
        );
        assert_eq!(
            projected.observed_vm_shape,
            Some(ObservedVmShape {
                vcpus: 2,
                memory_bytes: 2_147_483_648,
                boot_image_digest: cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                    [0; 32]
                ),
                guest_config_digest: cats_api::runtime_reconciliation::Sha256Digest::new(
                    "sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2",
                )
                .unwrap(),
            })
        );
    }

    #[test]
    fn naked_checkpoint_cannot_mint_an_adoption_proof() {
        let expected = expectation();
        assert!(expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(4242))
            .is_err());
    }

    #[test]
    fn exact_vmm_proof_rejects_descriptor_environment_and_handshake_drift() {
        let expected = inventory_expectation();
        let mut descriptor = expected.exact_evidence_for_test(4242);
        descriptor.fixed_descriptors_exact = false;
        assert!(expected.clone().prove_exact_process(descriptor).is_err());

        let mut environment = expected.exact_evidence_for_test(4242);
        environment
            .environment
            .insert(OsString::from("EXTRA"), OsString::from("value"));
        assert!(expected.clone().prove_exact_process(environment).is_err());

        let mut handshake = expected.exact_evidence_for_test(4242);
        handshake.api_peer_process_id = 4243;
        assert!(expected.prove_exact_process(handshake).is_err());
    }

    #[test]
    fn node_global_admission_retains_absent_or_exact_vmm_authority() {
        let expected = inventory_expectation();
        let cat_id = expected.cat_id().clone();
        let exact = expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(4242))
            .unwrap();
        let scan = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_vmms(
            BTreeMap::from([(cat_id.clone(), expected.clone())]),
            BTreeMap::from([(cat_id.clone(), exact)]),
        )
        .unwrap();
        let projected = scan.process_projections().remove(&cat_id).unwrap();
        let [projected] = projected.as_slice() else {
            panic!("exact VMM must produce one public process")
        };
        assert!(matches!(projected.role, ProcessRole::Vmm { .. }));

        let admission = scan.into_admission_for_test();
        let (retained, inspection) = admission.vmm(&cat_id).unwrap();
        assert_eq!(retained, &expected);
        assert!(inspection.is_some());
        assert!(matches!(
            admission.vmm_state().1.get(&cat_id),
            Some(VmmProcessInspection::Exact(_))
        ));

        let absent = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_vmms(
            BTreeMap::from([(cat_id.clone(), expected)]),
            BTreeMap::new(),
        )
        .unwrap()
        .into_admission_for_test();
        assert!(matches!(
            absent.vmm_state().1.get(&cat_id),
            Some(VmmProcessInspection::Absent)
        ));
    }
}

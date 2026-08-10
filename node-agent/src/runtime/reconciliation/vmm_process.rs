//! Checkpointed systemd process boundary for one fresh Cloud Hypervisor.
//!
//! The durable `StartRuntime` checkpoint is the only launch request.  The
//! Agent retains that exact checkpoint and every installed artifact
//! descriptor, then asks PID 1 to pass those descriptors to the fixed
//! `cats-vmm-launcher` with `OpenFile=`.  No second JSON request, caller-chosen
//! argv, or pathname-only artifact is accepted at this boundary.

use std::ffi::OsString;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
#[cfg(any(test, target_os = "linux"))]
use std::path::Path;
#[cfg(any(test, target_os = "linux"))]
use std::process::Command;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, HostPath, Id, RandomId128, ReconcileStep, RuntimeCheckpoint,
    RuntimeLaunchArtifact, VmmBootProvenance,
};

use crate::runtime_spine::RuntimeDesiredEffectContext;
use crate::vmm_launcher::{VmmLauncherPlan, VMM_LAUNCHER_CONTRACT_ARGUMENT};
#[cfg(any(test, target_os = "linux"))]
use crate::vmm_launcher::{RUNTIME_INCARNATION_ENVIRONMENT, VMM_PROCESS_TOKEN_ENVIRONMENT};

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

pub(crate) trait VmmProcessStartPort: sealed::Sealed + Send + Sync {
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
        })
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

impl VmmProcessStartPort for PlatformSystemdVmmProcessPort {
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
}

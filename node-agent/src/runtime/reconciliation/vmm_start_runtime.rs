//! Checkpoint-only construction of the `PrepareNetwork -> StartRuntime` edge.
//!
//! This module never starts a VMM. The caller must obtain every path and
//! immutable launch projection from retained provider authority, reserve the
//! Guest CID under the Node-global allocator, and publish this successor. A
//! later accepted full inventory owns the physical start/adopt effect.

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, DesiredRuntimeSpec, Id, ObservedNetwork, RandomId128, ReconcileStep,
    RuntimeCheckpoint, RuntimeLaunch, RuntimeLaunchArtifact, RuntimeTarget, UnixMillis,
    VmmBootProvenance,
};

use super::{ManagedVmmLaunchFilePaths, ManagedVmmSocketPaths};

pub(crate) struct StartRuntimeCheckpointAuthority<'a> {
    pub(crate) launcher_executable: RuntimeLaunchArtifact,
    pub(crate) boot: VmmBootProvenance,
    pub(crate) network_projection: ObservedNetwork,
    pub(crate) socket_paths: &'a ManagedVmmSocketPaths,
    pub(crate) launch_file_paths: &'a ManagedVmmLaunchFilePaths,
}

/// Builds the only legal `StartRuntime` successor without performing a
/// physical effect. `encode_runtime_checkpoint` is deliberately the final
/// boundary: it rechecks the complete F0/cross-resource contract after direct
/// Rust construction.
pub(crate) fn build_start_runtime_successor(
    predecessor: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    runtime_incarnation: RandomId128,
    process_identity_token: RandomId128,
    guest_cid: u32,
    authority: StartRuntimeCheckpointAuthority<'_>,
    updated_at_unix_ms: UnixMillis,
) -> Result<RuntimeCheckpoint> {
    anyhow::ensure!(
        desired.target == RuntimeTarget::Running,
        "StartRuntime requires a Running Desired"
    );
    anyhow::ensure!(
        predecessor.cat_id == desired.cat_id
            && predecessor.node_id == desired.placement.node_id
            && predecessor.placement_epoch == desired.placement.placement_epoch
            && predecessor.desired_revision == desired.desired_revision
            && predecessor.spec_digest == desired.spec_digest
            && predecessor.runtime_incarnation.is_none()
            && matches!(&predecessor.runtime_launch, RuntimeLaunch::Absent),
        "StartRuntime predecessor is not current-exact for Desired"
    );
    anyhow::ensure!(
        predecessor.stable_state.is_none() && predecessor.updated_at_unix_ms < updated_at_unix_ms,
        "StartRuntime successor does not advance one prelaunch checkpoint"
    );
    let ReconcileStep::PrepareNetwork { network, devices } = &predecessor.step else {
        anyhow::bail!("StartRuntime predecessor is not PrepareNetwork")
    };
    anyhow::ensure!(
        network.network_config == desired.runtime.network_config,
        "StartRuntime predecessor network differs from Desired"
    );
    let scope_id = Id::new(format!("cats-vmm-{}.service", runtime_incarnation.as_str()))
        .context("StartRuntime incarnation cannot form a systemd unit")?;

    let mut successor = predecessor.clone();
    successor.runtime_incarnation = Some(runtime_incarnation.clone());
    successor.networks = vec![authority.network_projection];
    successor.step = ReconcileStep::StartRuntime {
        runtime_incarnation,
        scope_id,
        launcher_executable: Box::new(authority.launcher_executable),
        boot: Box::new(authority.boot),
        process_identity_token,
        vcpus: desired.runtime.vcpus,
        memory_bytes: desired.runtime.memory_bytes,
        boot_image_digest: desired.runtime.boot_image_digest.clone(),
        guest_config_digest: desired.runtime.guest_config_digest.clone(),
        api_socket_path: authority.socket_paths.api_socket_path().clone(),
        vsock_socket_path: authority.socket_paths.vsock_socket_path().clone(),
        guest_cid,
        memory_file_path: authority.launch_file_paths.memory_file_path().clone(),
        serial_log_path: authority.launch_file_paths.serial_log_path().clone(),
        vmm_log_path: authority.launch_file_paths.vmm_log_path().clone(),
        network: Box::new(network.clone()),
        devices: devices.clone(),
    };
    successor.runtime_launch = RuntimeLaunch::Present(Box::new(
        successor
            .step
            .start_runtime_launch_identity()
            .context("constructed StartRuntime step lost its launch identity")?,
    ));
    successor.updated_at_unix_ms = updated_at_unix_ms;
    encode_runtime_checkpoint(&successor)
        .context("constructed StartRuntime checkpoint is not canonical V1")?;
    Ok(successor)
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, ReconcileStep, RuntimeTarget,
    };

    use crate::state_directory::StateDirectory;

    use super::*;
    use crate::runtime::reconciliation::{ManagedVmmSocketRoot, INSTALLED_VMM_SOCKET_ROOT};

    const PREPARE_NETWORK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-prepare-network-checkpoint.json"
    ));
    const START_RUNTIME: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
    ));
    const DESIRED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-desired.json"
    ));

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn build(
        predecessor: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        process_identity_token: RandomId128,
    ) -> Result<RuntimeCheckpoint> {
        let template = decode_runtime_checkpoint(START_RUNTIME).unwrap();
        let ReconcileStep::StartRuntime {
            launcher_executable,
            boot,
            ..
        } = template.step
        else {
            unreachable!()
        };
        let runtime_incarnation = random('5');
        let sockets = ManagedVmmSocketRoot::installed().paths_for(&runtime_incarnation)?;
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let launch_files =
            ManagedVmmLaunchFilePaths::for_incarnation(&state, &runtime_incarnation)?;
        build_start_runtime_successor(
            predecessor,
            desired,
            runtime_incarnation,
            process_identity_token,
            3,
            StartRuntimeCheckpointAuthority {
                launcher_executable: *launcher_executable,
                boot: *boot,
                network_projection: template.networks.into_iter().next().unwrap(),
                socket_paths: &sockets,
                launch_file_paths: &launch_files,
            },
            UnixMillis::new(predecessor.updated_at_unix_ms.get() + 1).unwrap(),
        )
    }

    #[test]
    fn exact_prepare_network_builds_one_checkpoint_only_start_runtime_successor() {
        let predecessor = decode_runtime_checkpoint(PREPARE_NETWORK).unwrap();
        let desired = decode_desired_runtime_spec(DESIRED).unwrap();
        let successor = build(&predecessor, &desired, random('6')).unwrap();
        assert_eq!(
            successor.runtime_launch,
            RuntimeLaunch::Present(Box::new(
                successor
                    .step
                    .start_runtime_launch_identity()
                    .expect("StartRuntime successor launch identity"),
            )),
        );
        assert_eq!(
            successor.runtime_incarnation.as_ref().unwrap().as_str(),
            "55555555555555555555555555555555"
        );
        let ReconcileStep::StartRuntime {
            scope_id,
            guest_cid,
            api_socket_path,
            memory_file_path,
            network,
            devices,
            ..
        } = &successor.step
        else {
            panic!("successor is not StartRuntime")
        };
        assert_eq!(
            scope_id.as_str(),
            "cats-vmm-55555555555555555555555555555555.service"
        );
        assert_eq!(*guest_cid, 3);
        assert!(api_socket_path
            .as_str()
            .starts_with(INSTALLED_VMM_SOCKET_ROOT));
        assert!(memory_file_path
            .as_str()
            .ends_with("/vmm-launch-v1/p-55555555555555555555555555555555/memory.bin"));
        let ReconcileStep::PrepareNetwork {
            network: predecessor_network,
            devices: predecessor_devices,
        } = &predecessor.step
        else {
            unreachable!()
        };
        assert_eq!(network.as_ref(), predecessor_network);
        assert_eq!(devices, predecessor_devices);
        assert_eq!(successor.networks.len(), 1);
        assert!(predecessor.networks.is_empty());
        assert_eq!(successor.processes, predecessor.processes);
        assert_eq!(successor.volumes, predecessor.volumes);
    }

    #[test]
    fn desired_or_identity_drift_cannot_build_start_runtime() {
        let predecessor = decode_runtime_checkpoint(PREPARE_NETWORK).unwrap();
        let desired = decode_desired_runtime_spec(DESIRED).unwrap();

        let mut cold = desired.clone();
        cold.target = RuntimeTarget::Cold;
        assert!(build(&predecessor, &cold, random('6')).is_err());

        let mut wrong_revision = desired.clone();
        wrong_revision.desired_revision =
            cats_api::runtime_reconciliation::Revision::new(8).unwrap();
        assert!(build(&predecessor, &wrong_revision, random('6')).is_err());

        let mut already_launched = predecessor.clone();
        already_launched.runtime_launch = decode_runtime_checkpoint(START_RUNTIME)
            .unwrap()
            .runtime_launch;
        assert!(build(&already_launched, &desired, random('6')).is_err());

        let ReconcileStep::PrepareNetwork { network, .. } = &predecessor.step else {
            unreachable!()
        };
        assert!(build(&predecessor, &desired, network.ownership_token.clone()).is_err());
    }
}

//! Read-only/operator E3 probe over the installed checkpoint, Guest control
//! transport and blockd status protocol. It is never started by `cats-noded`
//! and introduces no production listener or authority.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse, DurabilityStatus};
use cats_api::guest::{
    RuntimeReadyRequestV1, RuntimeReadyResponseV1, GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
    GUEST_HOST_CONTROL_VSOCK_PORT_V1,
};
use cats_api::runtime_reconciliation::{
    decode_node_identity, decode_runtime_checkpoint, encode_node_identity,
    encode_runtime_checkpoint, FilesystemInitialization, GuestDeviceIdentity,
    GuestTransportEvidence, HostPath, Id, MountAccess, NodeIdentity, NodeIdentityState,
    ObservedDiskKind, ObservedMount, PersistentFilesystemBinding, PrepareDeviceFrontend,
    ProcessRole, RandomId128, ReconcileStep, RemoteHead, RuntimeCheckpoint, RuntimeLaunch,
    StableState, VolumeAuthorityEvidence, RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
};
use cats_node_agent::agent_registration::{NODE_IDENTITY_PATH, NODE_STATE_ROOT};
use cats_node_agent::guest_client::GuestClient;
use clap::{Parser, Subcommand};
use futures_util::{SinkExt as _, StreamExt as _};
use sha2::{Digest as _, Sha256};

const IDENTITY_MAX_BYTES: u64 = 16 * 1024;
const CONTROL_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Exact installed-runtime probe used only by E3 qualification")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write one run-bound marker in the Guest and prove Strict remote FLUSH.
    GuestSync {
        #[arg(long)]
        cat_id: String,
        #[arg(long)]
        run_id: String,
    },
    /// Emit bounded non-secret physical facts before/after Agent restart.
    Snapshot {
        #[arg(long)]
        cat_id: String,
    },
    /// Watch the exact first-format/A22/mount sequence for one PersistentDisk.
    WatchPersistentInitialization {
        #[arg(long)]
        cat_id: String,
        #[arg(long)]
        disk_id: String,
        #[arg(long)]
        volume_id: String,
        #[arg(long)]
        mount_path: String,
        #[arg(long)]
        run_id: String,
        #[arg(long, default_value_t = 240)]
        timeout_seconds: u64,
    },
    /// Emit a fresh RuntimeReady + blockd proof for one mounted PersistentDisk.
    PersistentSnapshot {
        #[arg(long)]
        cat_id: String,
        #[arg(long)]
        disk_id: String,
        #[arg(long)]
        volume_id: String,
        #[arg(long)]
        mount_path: String,
    },
    /// Write on one exact PersistentDisk and prove its Strict head advances.
    PersistentSync {
        #[arg(long)]
        cat_id: String,
        #[arg(long)]
        disk_id: String,
        #[arg(long)]
        volume_id: String,
        #[arg(long)]
        mount_path: String,
        #[arg(long)]
        run_id: String,
    },
    /// Prove a detached PersistentDisk is absent from the exact Cold checkpoint.
    PersistentColdAbsence {
        #[arg(long)]
        cat_id: String,
        #[arg(long)]
        disk_id: String,
        #[arg(long)]
        volume_id: String,
        #[arg(long)]
        mount_path: String,
    },
    /// Copy and start the exact E3 HTTP/WebSocket workload inside the Guest.
    InstallWorkload {
        #[arg(long)]
        cat_id: String,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        workload: PathBuf,
        #[arg(long)]
        workload_sha256: String,
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    /// Stop and remove only the run-bound E3 Guest workload.
    RemoveWorkload {
        #[arg(long)]
        cat_id: String,
        #[arg(long)]
        run_id: String,
    },
    /// Traverse the deployed public Gateway route with HTTP and WebSocket.
    PublicRoute {
        #[arg(long)]
        origin: String,
        #[arg(long)]
        run_id: String,
    },
    /// Prove public TLS ingress is reachable but Route v2 admission is closed.
    PublicRouteClosed {
        #[arg(long)]
        origin: String,
        #[arg(long)]
        run_id: String,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::GuestSync { cat_id, run_id } => guest_sync(&cat_id, &run_id),
        Command::Snapshot { cat_id } => snapshot(&cat_id),
        Command::WatchPersistentInitialization {
            cat_id,
            disk_id,
            volume_id,
            mount_path,
            run_id,
            timeout_seconds,
        } => watch_persistent_initialization(
            &cat_id,
            &disk_id,
            &volume_id,
            &mount_path,
            &run_id,
            timeout_seconds,
        ),
        Command::PersistentSnapshot {
            cat_id,
            disk_id,
            volume_id,
            mount_path,
        } => persistent_snapshot(&cat_id, &disk_id, &volume_id, &mount_path),
        Command::PersistentSync {
            cat_id,
            disk_id,
            volume_id,
            mount_path,
            run_id,
        } => persistent_sync(&cat_id, &disk_id, &volume_id, &mount_path, &run_id),
        Command::PersistentColdAbsence {
            cat_id,
            disk_id,
            volume_id,
            mount_path,
        } => persistent_cold_absence(&cat_id, &disk_id, &volume_id, &mount_path),
        Command::InstallWorkload {
            cat_id,
            run_id,
            workload,
            workload_sha256,
            port,
        } => install_workload(&cat_id, &run_id, &workload, &workload_sha256, port),
        Command::RemoveWorkload { cat_id, run_id } => remove_workload(&cat_id, &run_id),
        Command::PublicRoute { origin, run_id } => public_route(&origin, &run_id),
        Command::PublicRouteClosed { origin, run_id } => public_route_closed(&origin, &run_id),
    }
}

fn installed_identity() -> Result<NodeIdentity> {
    let identity_bytes = bounded_regular_file(Path::new(NODE_IDENTITY_PATH), IDENTITY_MAX_BYTES)?;
    let identity =
        decode_node_identity(&identity_bytes).context("decode installed NodeIdentity")?;
    anyhow::ensure!(
        encode_node_identity(&identity)? == identity_bytes,
        "installed NodeIdentity is not canonical"
    );
    anyhow::ensure!(
        identity.state == NodeIdentityState::Provisioned,
        "installed NodeIdentity is not provisioned"
    );
    Ok(identity)
}

fn installed_state_directory(identity: &NodeIdentity) -> PathBuf {
    Path::new(NODE_STATE_ROOT).join(identity.state_path_id.as_str())
}

fn load_installed_checkpoint(raw_cat_id: &str) -> Result<RuntimeCheckpoint> {
    let cat_id = Id::new(raw_cat_id.to_owned()).context("invalid --cat-id")?;
    let identity = installed_identity()?;
    let path = installed_state_directory(&identity)
        .join("checkpoints")
        .join(format!("cat-{}.checkpoint.json", cat_id.as_str()));
    let bytes = bounded_regular_file(&path, RUNTIME_CHECKPOINT_MAX_WIRE_BYTES as u64)?;
    let checkpoint = decode_runtime_checkpoint(&bytes).context("decode exact RuntimeCheckpoint")?;
    anyhow::ensure!(
        encode_runtime_checkpoint(&checkpoint)? == bytes,
        "RuntimeCheckpoint is not canonical"
    );
    anyhow::ensure!(
        checkpoint.cat_id == cat_id,
        "RuntimeCheckpoint belongs to another Cat"
    );
    anyhow::ensure!(
        checkpoint.node_id == identity.node_id,
        "RuntimeCheckpoint belongs to another Node"
    );
    Ok(checkpoint)
}

fn installed_checkpoint(raw_cat_id: &str) -> Result<RuntimeCheckpoint> {
    let checkpoint = load_installed_checkpoint(raw_cat_id)?;
    anyhow::ensure!(
        checkpoint.stable_state == Some(StableState::Running),
        "Cat is not stable Running"
    );
    Ok(checkpoint)
}

fn bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "{} is not a single-link regular file",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= maximum,
        "{} exceeds its byte bound",
        path.display()
    );
    Ok(bytes)
}

fn guest_client(checkpoint: &RuntimeCheckpoint) -> Result<GuestClient> {
    let RuntimeLaunch::Present(launch) = &checkpoint.runtime_launch else {
        bail!("Running checkpoint has no retained VMM launch")
    };
    let GuestTransportEvidence::VsockReady {
        runtime_incarnation,
        guest_cid,
        guest_port,
        ..
    } = &checkpoint.guest_transport
    else {
        bail!("Running checkpoint has no ready Guest transport")
    };
    anyhow::ensure!(
        Some(runtime_incarnation) == checkpoint.runtime_incarnation.as_ref()
            && runtime_incarnation == &launch.runtime_incarnation
            && *guest_cid == launch.guest_cid,
        "Guest transport does not bind the retained VMM launch"
    );
    GuestClient::connect_hybrid_vsock_bounded(
        Path::new(launch.vsock_socket_path.as_str()),
        u32::from(*guest_port),
        Duration::from_secs(15),
    )
}

struct RootFacts<'a> {
    volume_id: &'a Id,
    attachment_id: &'a Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    head: &'a cats_api::runtime_reconciliation::RemoteHead,
    control_socket: &'a Path,
    block_frontend: &'static str,
}

fn root_facts(checkpoint: &RuntimeCheckpoint) -> Result<RootFacts<'_>> {
    let roots = checkpoint
        .volumes
        .iter()
        .filter(|volume| volume.disk_kind == ObservedDiskKind::Root)
        .collect::<Vec<_>>();
    let [root] = roots.as_slice() else {
        bail!("Running checkpoint does not contain exactly one Root volume")
    };
    anyhow::ensure!(
        root.durability == Some(cats_api::runtime_reconciliation::Durability::Strict),
        "E3 durable-write oracle requires a Strict Root volume"
    );
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &root.authority
    else {
        bail!("Root volume is not exact Owned authority")
    };
    let processes = checkpoint
        .processes
        .iter()
        .filter(|process| {
            matches!(
                &process.role,
                ProcessRole::Blockd { volume_id, attachment_id: observed_id, attachment_epoch: observed_epoch }
                    if volume_id == &root.volume_id
                        && observed_id == attachment_id
                        && observed_epoch == attachment_epoch
            )
        })
        .collect::<Vec<_>>();
    let [process] = processes.as_slice() else {
        bail!("Root volume does not have exactly one matching blockd process")
    };
    let RuntimeLaunch::Present(launch) = &checkpoint.runtime_launch else {
        bail!("Running checkpoint has no retained VMM launch")
    };
    let devices = launch
        .devices
        .iter()
        .filter(|device| {
            device.volume_id == root.volume_id
                && device.attachment_id == *attachment_id
                && device.attachment_epoch == *attachment_epoch
        })
        .collect::<Vec<_>>();
    let [device] = devices.as_slice() else {
        bail!("Root volume does not have exactly one retained launch device")
    };
    let block_frontend = match &device.frontend {
        PrepareDeviceFrontend::KernelNbd { .. } => "kernel-nbd",
        PrepareDeviceFrontend::VhostUserBlk { .. } => "vhost-user",
    };
    Ok(RootFacts {
        volume_id: &root.volume_id,
        attachment_id,
        attachment_epoch: *attachment_epoch,
        head,
        control_socket: Path::new(process.control_socket_path.as_str()),
        block_frontend,
    })
}

fn blockd_status(facts: &RootFacts<'_>) -> Result<DurabilityStatus> {
    exact_blockd_status(
        facts.control_socket,
        facts.volume_id,
        facts.attachment_id,
        facts.attachment_epoch,
    )
}

fn exact_blockd_status(
    control_socket: &Path,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
) -> Result<DurabilityStatus> {
    let mut stream = UnixStream::connect(control_socket)
        .with_context(|| format!("connect blockd control at {}", control_socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(BlockdControlCommand::Status.as_wire().as_bytes())?;
    stream.write_all(b"\n")?;
    let mut line = Vec::new();
    BufReader::new(stream)
        .take((CONTROL_MAX_BYTES + 1) as u64)
        .read_until(b'\n', &mut line)?;
    anyhow::ensure!(
        line.len() <= CONTROL_MAX_BYTES && line.ends_with(b"\n"),
        "blockd status is truncated or oversized"
    );
    let line = std::str::from_utf8(&line).context("blockd status is not UTF-8")?;
    let payload = match BlockdControlResponse::parse_wire(line)? {
        BlockdControlResponse::Ok(payload) => payload,
        BlockdControlResponse::Error(message) => bail!("blockd status failed: {message}"),
    };
    let status: DurabilityStatus =
        serde_json::from_str(&payload).context("decode blockd status")?;
    anyhow::ensure!(
        status.volume_id == volume_id.as_str()
            && status.attachment_id == attachment_id.as_str()
            && status.attachment_epoch == Some(attachment_epoch)
            && status.mode == "strict"
            && status.guest_io_enabled == Some(true)
            && !status.fenced,
        "blockd status does not bind the exact live Strict attachment"
    );
    Ok(status)
}

struct PersistentFacts<'a> {
    volume_intent_id: &'a Id,
    disk_id: &'a Id,
    volume_id: &'a Id,
    attachment_id: &'a Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    head: &'a RemoteHead,
    guest_device: &'a GuestDeviceIdentity,
    mount: &'a ObservedMount,
    control_socket: &'a Path,
    block_frontend: &'static str,
}

fn persistent_facts<'a>(
    checkpoint: &'a RuntimeCheckpoint,
    raw_disk_id: &str,
    raw_volume_id: &str,
    raw_mount_path: &str,
) -> Result<PersistentFacts<'a>> {
    let disk_id = Id::new(raw_disk_id.to_owned()).context("invalid --disk-id")?;
    let volume_id = Id::new(raw_volume_id.to_owned()).context("invalid --volume-id")?;
    let mount_path = HostPath::new(raw_mount_path.to_owned()).context("invalid --mount-path")?;
    anyhow::ensure!(mount_path.as_str() != "/", "Persistent mount path is Root");
    let volumes = checkpoint
        .volumes
        .iter()
        .filter(|volume| {
            volume.disk_kind == ObservedDiskKind::Persistent
                && volume.disk_id.as_ref() == Some(&disk_id)
                && volume.volume_id == volume_id
        })
        .collect::<Vec<_>>();
    let [volume] = volumes.as_slice() else {
        bail!("Running checkpoint lacks one exact PersistentDisk")
    };
    anyhow::ensure!(
        volume.durability == Some(cats_api::runtime_reconciliation::Durability::Strict),
        "PersistentDisk is not Strict"
    );
    let volume_intent_id = volume
        .volume_intent_id
        .as_ref()
        .context("PersistentDisk lacks volume_intent_id")?;
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &volume.authority
    else {
        bail!("PersistentDisk is not exact Owned authority")
    };
    let processes = checkpoint
        .processes
        .iter()
        .filter(|process| {
            matches!(
                &process.role,
                ProcessRole::Blockd { volume_id: observed_volume, attachment_id: observed_attachment, attachment_epoch: observed_epoch }
                    if observed_volume == &volume.volume_id
                        && observed_attachment == attachment_id
                        && observed_epoch == attachment_epoch
            )
        })
        .collect::<Vec<_>>();
    let [process] = processes.as_slice() else {
        bail!("PersistentDisk lacks one exact blockd process")
    };
    let RuntimeLaunch::Present(launch) = &checkpoint.runtime_launch else {
        bail!("Running checkpoint lacks retained launch")
    };
    let prepared = launch
        .devices
        .iter()
        .filter(|device| {
            device.volume_intent_id == *volume_intent_id
                && device.disk_id == disk_id
                && device.volume_id == volume_id
                && device.attachment_id == *attachment_id
                && device.attachment_epoch == *attachment_epoch
        })
        .collect::<Vec<_>>();
    let [prepared] = prepared.as_slice() else {
        bail!("PersistentDisk lacks one exact retained launch device")
    };
    let mounts = checkpoint
        .mounts
        .iter()
        .filter(|mount| mount.volume_id == volume_id)
        .collect::<Vec<_>>();
    let [mount] = mounts.as_slice() else {
        bail!("PersistentDisk lacks one exact mounted-set member")
    };
    anyhow::ensure!(
        mount.guest_device == prepared.guest_device
            && mount.mount_path == mount_path
            && mount.access == MountAccess::ReadWrite
            && mount.instance_count == 1,
        "PersistentDisk mount is not exact read-write readiness"
    );
    let block_frontend = match &prepared.frontend {
        PrepareDeviceFrontend::KernelNbd { .. } => "kernel-nbd",
        PrepareDeviceFrontend::VhostUserBlk { .. } => "vhost-user",
    };
    Ok(PersistentFacts {
        volume_intent_id,
        disk_id: volume.disk_id.as_ref().unwrap(),
        volume_id: &volume.volume_id,
        attachment_id,
        attachment_epoch: *attachment_epoch,
        head,
        guest_device: &prepared.guest_device,
        mount,
        control_socket: Path::new(process.control_socket_path.as_str()),
        block_frontend,
    })
}

fn canonical_head(head: &RemoteHead) -> Result<String> {
    serde_json::to_string(head).context("encode canonical remote head")
}

fn fresh_challenge() -> Result<RandomId128> {
    let mut bytes = [0_u8; 16];
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
        .open("/dev/urandom")
        .context("open kernel entropy source")?
        .read_exact(&mut bytes)
        .context("read fresh RuntimeReady challenge")?;
    anyhow::ensure!(
        bytes.iter().any(|byte| *byte != 0),
        "entropy returned zero ID"
    );
    RandomId128::new(hex::encode(bytes)).context("generated invalid challenge")
}

fn exact_runtime_ready(checkpoint: &RuntimeCheckpoint) -> Result<RuntimeReadyResponseV1> {
    let RuntimeLaunch::Present(launch) = &checkpoint.runtime_launch else {
        bail!("Running checkpoint lacks launch for RuntimeReady")
    };
    let GuestTransportEvidence::VsockReady {
        runtime_incarnation,
        guest_cid,
        guest_port,
        guest_agent_protocol_version,
        guest_boot_id,
    } = &checkpoint.guest_transport
    else {
        bail!("Running checkpoint lacks exact Guest transport")
    };
    anyhow::ensure!(
        runtime_incarnation == &launch.runtime_incarnation
            && *guest_cid == launch.guest_cid
            && u32::from(*guest_port) == GUEST_HOST_CONTROL_VSOCK_PORT_V1
            && *guest_agent_protocol_version
                == cats_api::runtime_reconciliation::ContractVersion::V1,
        "Guest transport does not bind launch and frozen protocol"
    );
    let request = RuntimeReadyRequestV1 {
        version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        challenge: fresh_challenge()?,
        runtime_incarnation: launch.runtime_incarnation.clone(),
        expected_guest_cid: launch.guest_cid,
        expected_guest_port: GUEST_HOST_CONTROL_VSOCK_PORT_V1,
        expected_guest_agent_protocol_version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
    };
    let mut guest = guest_client(checkpoint)?;
    let response = guest.runtime_ready(request)?;
    anyhow::ensure!(
        response.guest_boot_id == *guest_boot_id
            && response.devices.len() == launch.devices.len()
            && response.mounts.len() == checkpoint.mounts.len(),
        "fresh RuntimeReady set differs from exact checkpoint set"
    );
    for prepared in &launch.devices {
        let devices = response
            .devices
            .iter()
            .filter(|device| device.guest_device == prepared.guest_device)
            .collect::<Vec<_>>();
        let [device] = devices.as_slice() else {
            bail!("RuntimeReady lacks one exact retained device")
        };
        anyhow::ensure!(
            device.size_bytes == prepared.size_bytes,
            "RuntimeReady device size differs from launch"
        );
        let checkpoint_mounts = checkpoint
            .mounts
            .iter()
            .filter(|mount| {
                mount.volume_id == prepared.volume_id && mount.guest_device == prepared.guest_device
            })
            .collect::<Vec<_>>();
        let [checkpoint_mount] = checkpoint_mounts.as_slice() else {
            bail!("checkpoint lacks one exact mount for retained device")
        };
        let ready_mounts = response
            .mounts
            .iter()
            .filter(|mount| {
                mount.device_major == device.device_major
                    && mount.device_minor == device.device_minor
                    && mount.source_path == device.device_path
            })
            .collect::<Vec<_>>();
        let [ready_mount] = ready_mounts.as_slice() else {
            bail!("RuntimeReady lacks one exact mount for retained device")
        };
        anyhow::ensure!(
            device.filesystem_uuid == checkpoint_mount.filesystem_uuid
                && ready_mount.filesystem_uuid == checkpoint_mount.filesystem_uuid
                && ready_mount.source_path == checkpoint_mount.source_path
                && ready_mount.mount_root.as_str() == "/"
                && ready_mount.mount_path == checkpoint_mount.mount_path
                && ready_mount.filesystem_type.as_str() == "ext4"
                && ready_mount.access == checkpoint_mount.access
                && checkpoint_mount.instance_count == 1,
            "RuntimeReady mount differs from checkpoint mounted-set"
        );
    }
    Ok(response)
}

fn prove_remote(status: &DurabilityStatus) -> Result<()> {
    let head = status
        .remote_head
        .as_ref()
        .context("blockd status lacks exact remote head")?;
    let head_generation = i64::try_from(head.generation.get())
        .context("remote head generation does not fit blockd status")?;
    anyhow::ensure!(
        status.local_durable_generation == status.remote_durable_generation
            && status.remote_durable_generation == head_generation,
        "Strict FLUSH did not converge L == R == exact remote head"
    );
    Ok(())
}

fn guest_sync(cat_id: &str, run_id: &str) -> Result<()> {
    canonical_run_id(run_id)?;
    let before_checkpoint = installed_checkpoint(cat_id)?;
    let before_facts = root_facts(&before_checkpoint)?;
    let before = blockd_status(&before_facts)?;
    prove_remote(&before)?;
    anyhow::ensure!(
        before.remote_head.as_ref() == Some(before_facts.head),
        "checkpoint and blockd disagree before the write"
    );
    let mut guest = guest_client(&before_checkpoint)?;
    let marker_path = format!("/var/lib/cats-e3/{run_id}.strict-flush");
    let script = "set -eu; umask 077; mkdir -p /var/lib/cats-e3; printf '%s\\n' \"$1\" > \"$2\"; sync -f \"$2\"";
    let (code, stdout, stderr) = guest.exec(vec![
        "sh".into(),
        "-c".into(),
        script.into(),
        "cats-e3".into(),
        run_id.into(),
        marker_path.clone(),
    ])?;
    anyhow::ensure!(
        code == 0,
        "Guest marker write failed: stdout={stdout:?} stderr={stderr:?}"
    );
    guest.syncfs().context("Guest Syncfs control request")?;

    let deadline = Instant::now() + Duration::from_secs(30);
    let after = loop {
        let checkpoint = installed_checkpoint(cat_id)?;
        let facts = root_facts(&checkpoint)?;
        let status = blockd_status(&facts)?;
        if prove_remote(&status).is_ok()
            && status.remote_head.as_ref() == Some(facts.head)
            && status.remote_durable_generation > before.remote_durable_generation
        {
            break status;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "Strict remote head did not become checkpoint-visible"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "cat_id": cat_id,
            "node_id": before_checkpoint.node_id,
            "run_id": run_id,
            "marker_path": marker_path,
            "before_remote_generation": before.remote_durable_generation,
            "after_remote_generation": after.remote_durable_generation,
            "after_remote_head": after.remote_head,
            "strict_flush_remote_durable": true
        })
    );
    Ok(())
}

fn snapshot(cat_id: &str) -> Result<()> {
    let checkpoint = installed_checkpoint(cat_id)?;
    let facts = root_facts(&checkpoint)?;
    let status = blockd_status(&facts)?;
    prove_remote(&status)?;
    let RuntimeLaunch::Present(launch) = &checkpoint.runtime_launch else {
        unreachable!()
    };
    let guest_boot_id = match &checkpoint.guest_transport {
        GuestTransportEvidence::VsockReady { guest_boot_id, .. } => guest_boot_id.as_str(),
        _ => unreachable!(),
    };
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "cat_id": cat_id,
            "node_id": checkpoint.node_id,
            "runtime_incarnation": launch.runtime_incarnation,
            "guest_boot_id": guest_boot_id,
            "vmm_scope_id": launch.scope_id,
            "root_volume_id": facts.volume_id,
            "root_attachment_id": facts.attachment_id,
            "root_attachment_epoch": facts.attachment_epoch,
            "root_remote_head": status.remote_head,
            "root_remote_generation": status.remote_durable_generation,
            "root_block_frontend": facts.block_frontend,
            "lifecycle_admission": checkpoint.lifecycle_admission,
            "route_gate_count": checkpoint.route_gates.len(),
            "active_route_gate_count": checkpoint.route_gates.iter().filter(|gate| matches!(gate.gate, cats_api::runtime_reconciliation::RouteGateState::Active)).count(),
            "strict_remote_durable": true
        })
    );
    Ok(())
}

fn persistent_snapshot_value(
    cat_id: &str,
    disk_id: &str,
    volume_id: &str,
    mount_path: &str,
) -> Result<serde_json::Value> {
    let checkpoint = installed_checkpoint(cat_id)?;
    let facts = persistent_facts(&checkpoint, disk_id, volume_id, mount_path)?;
    let status = exact_blockd_status(
        facts.control_socket,
        facts.volume_id,
        facts.attachment_id,
        facts.attachment_epoch,
    )?;
    prove_remote(&status)?;
    anyhow::ensure!(
        status.remote_head.as_ref() == Some(facts.head),
        "Persistent checkpoint and blockd disagree on current head"
    );
    let ready = exact_runtime_ready(&checkpoint)?;
    let ready_devices = ready
        .devices
        .iter()
        .filter(|device| device.guest_device == *facts.guest_device)
        .collect::<Vec<_>>();
    let [ready_device] = ready_devices.as_slice() else {
        bail!("fresh RuntimeReady lacks exact Persistent device")
    };
    let RuntimeLaunch::Present(launch) = &checkpoint.runtime_launch else {
        unreachable!()
    };
    let guest_boot_id = match &checkpoint.guest_transport {
        GuestTransportEvidence::VsockReady { guest_boot_id, .. } => guest_boot_id,
        _ => unreachable!(),
    };
    Ok(serde_json::json!({
        "version": 1,
        "cat_id": checkpoint.cat_id,
        "node_id": checkpoint.node_id,
        "disk_id": facts.disk_id,
        "volume_id": facts.volume_id,
        "volume_intent_id": facts.volume_intent_id,
        "attachment_id": facts.attachment_id,
        "attachment_epoch": facts.attachment_epoch,
        "guest_device": {
            "serial": facts.guest_device.serial,
            "slot": facts.guest_device.slot.to_string()
        },
        "filesystem_uuid": facts.mount.filesystem_uuid,
        "mount_path": facts.mount.mount_path,
        "runtime_incarnation": launch.runtime_incarnation,
        "guest_boot_id": guest_boot_id,
        "device_path": ready_device.device_path,
        "block_frontend": facts.block_frontend,
        "remote_head": canonical_head(facts.head)?,
        "remote_generation": status.remote_durable_generation,
        "mounted_set_complete": true,
        "strict_remote_durable": true
    }))
}

fn persistent_snapshot(
    cat_id: &str,
    disk_id: &str,
    volume_id: &str,
    mount_path: &str,
) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(&persistent_snapshot_value(
            cat_id, disk_id, volume_id, mount_path,
        )?)?
    );
    Ok(())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationFaultV1 {
    version: u8,
    run_id: String,
    attachment_id: Id,
    initialization_token: RandomId128,
    filesystem_uuid: RandomId128,
    action: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationInvocationV1 {
    version: u8,
    challenge: RandomId128,
    attachment_id: Id,
    initialization_token: RandomId128,
    filesystem_uuid: RandomId128,
    mkfs_invocations: u8,
}

fn arm_format_response_fault(
    checkpoint: &RuntimeCheckpoint,
    filesystem: &PersistentFilesystemBinding,
    run_id: &str,
) -> Result<()> {
    canonical_run_id(run_id)?;
    let FilesystemInitialization::Initialize {
        initialization_token,
        ..
    } = &filesystem.initialization
    else {
        bail!("first-format checkpoint is not Initialize")
    };
    let artifact = QualificationFaultV1 {
        version: 1,
        run_id: run_id.to_owned(),
        attachment_id: filesystem.attachment_id.clone(),
        initialization_token: initialization_token.clone(),
        filesystem_uuid: filesystem.filesystem_uuid.clone(),
        action: "drop_validated_format_response_once".to_owned(),
    };
    let bytes = serde_json::to_vec(&artifact)?;
    let mut guest = guest_client(checkpoint)?;
    let script = r#"set -eu
umask 077
directory=/run/cats/qualification
artifact=$directory/filesystem-fault.v1.json
consumed=$directory/filesystem-fault-consumed.v1.json
mkdir -p -m 0700 "$directory"
test ! -L "$directory"
test "$(stat -c '%u:%g:%a' "$directory")" = '0:0:700'
test ! -e "$artifact" && test ! -L "$artifact"
test ! -e "$consumed" && test ! -L "$consumed"
set -C
cat > "$artifact"
chmod 0600 "$artifact"
test "$(stat -c '%u:%g:%a:%h' "$artifact")" = '0:0:600:1'
sync -f "$artifact"
sync -f "$directory"
printf 'armed\n'"#;
    let (code, stdout, stderr) = guest.exec_with_input(
        vec!["sh".into(), "-c".into(), script.into(), "cats-e3".into()],
        Default::default(),
        bytes,
    )?;
    anyhow::ensure!(
        code == 0 && stdout == "armed\n",
        "arm format-response fault failed: stdout={stdout:?} stderr={stderr:?}"
    );
    Ok(())
}

struct QualificationFaultEvidence {
    artifact_sha256: String,
    mkfs_invocations: u8,
}

fn qualification_fault_evidence(
    checkpoint: &RuntimeCheckpoint,
    filesystem: &PersistentFilesystemBinding,
    run_id: &str,
) -> Result<QualificationFaultEvidence> {
    let FilesystemInitialization::Initialize {
        initialization_token,
        ..
    } = &filesystem.initialization
    else {
        bail!("first-format checkpoint is not Initialize")
    };
    let marker = format!(
        "/run/cats/qualification/filesystem-format-invocation-{}.v1.json",
        filesystem.filesystem_uuid.as_str()
    );
    let mut guest = guest_client(checkpoint)?;
    let script = r#"set -eu
directory=/run/cats/qualification
active=$directory/filesystem-fault.v1.json
consumed=$directory/filesystem-fault-consumed.v1.json
test ! -e "$active"
test ! -L "$consumed" && test -f "$consumed"
test ! -L "$1" && test -f "$1"
test "$(stat -c '%u:%g:%a:%h' "$consumed")" = '0:0:600:1'
test "$(stat -c '%u:%g:%a:%h' "$1")" = '0:0:600:1'
cat "$consumed"
printf '\n'
cat "$1"
printf '\n'
sha256sum "$consumed" | awk '{print $1}'"#;
    let (code, stdout, stderr) = guest.exec(vec![
        "sh".into(),
        "-c".into(),
        script.into(),
        "cats-e3".into(),
        marker,
    ])?;
    anyhow::ensure!(
        code == 0,
        "read format-response fault evidence failed: stdout={stdout:?} stderr={stderr:?}"
    );
    let lines = stdout.lines().collect::<Vec<_>>();
    let [fault_line, invocation_line, digest] = lines.as_slice() else {
        bail!("format-response fault evidence is not exactly three lines")
    };
    let fault: QualificationFaultV1 = serde_json::from_str(fault_line)?;
    let invocation: QualificationInvocationV1 = serde_json::from_str(invocation_line)?;
    anyhow::ensure!(
        serde_json::to_string(&fault)? == *fault_line
            && serde_json::to_string(&invocation)? == *invocation_line
            && fault.version == 1
            && fault.run_id == run_id
            && fault.attachment_id == filesystem.attachment_id
            && fault.initialization_token == *initialization_token
            && fault.filesystem_uuid == filesystem.filesystem_uuid
            && fault.action == "drop_validated_format_response_once"
            && invocation.version == 1
            && invocation.challenge.as_str().len() == 32
            && invocation.attachment_id == filesystem.attachment_id
            && invocation.initialization_token == *initialization_token
            && invocation.filesystem_uuid == filesystem.filesystem_uuid
            && invocation.mkfs_invocations == 1,
        "format-response fault evidence does not bind initialization"
    );
    let calculated = hex::encode(Sha256::digest(fault_line.as_bytes()));
    anyhow::ensure!(
        digest.len() == 64 && *digest == calculated,
        "consumed fault digest differs from exact artifact"
    );
    Ok(QualificationFaultEvidence {
        artifact_sha256: calculated,
        mkfs_invocations: invocation.mkfs_invocations,
    })
}

fn filesystem_step(
    checkpoint: &RuntimeCheckpoint,
) -> Option<(&PersistentFilesystemBinding, Option<&RemoteHead>)> {
    match &checkpoint.step {
        ReconcileStep::FormatFilesystem { filesystem }
        | ReconcileStep::DrainInitialization { filesystem, .. } => Some((filesystem, None)),
        ReconcileStep::CommitInitialized {
            filesystem,
            new_remote_head,
        } => Some((filesystem, Some(new_remote_head))),
        ReconcileStep::MountFilesystem {
            filesystem,
            expected_head,
        } => Some((filesystem, Some(expected_head))),
        _ => None,
    }
}

fn watch_persistent_initialization(
    cat_id: &str,
    disk_id: &str,
    volume_id: &str,
    mount_path: &str,
    run_id: &str,
    timeout_seconds: u64,
) -> Result<()> {
    canonical_run_id(run_id)?;
    let disk_id = Id::new(disk_id.to_owned()).context("invalid --disk-id")?;
    let volume_id = Id::new(volume_id.to_owned()).context("invalid --volume-id")?;
    let mount_path = HostPath::new(mount_path.to_owned()).context("invalid --mount-path")?;
    anyhow::ensure!(mount_path.as_str() != "/", "Persistent mount path is Root");
    anyhow::ensure!(
        (1..=900).contains(&timeout_seconds),
        "--timeout-seconds is outside 1..=900"
    );
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    let mut format: Option<PersistentFilesystemBinding> = None;
    let mut initialized_head: Option<RemoteHead> = None;
    let mut fault_armed = false;
    loop {
        let checkpoint = load_installed_checkpoint(cat_id)?;
        if let Some((filesystem, step_head)) = filesystem_step(&checkpoint) {
            if filesystem.disk_id == disk_id && filesystem.volume_id == volume_id {
                anyhow::ensure!(
                    filesystem.mount_path == mount_path,
                    "filesystem phase uses another mount path"
                );
                if let Some(existing) = &format {
                    anyhow::ensure!(
                        existing == filesystem,
                        "filesystem identity changed between initialization phases"
                    );
                } else {
                    anyhow::ensure!(
                        matches!(checkpoint.step, ReconcileStep::FormatFilesystem { .. }),
                        "initialization watcher missed the first Format checkpoint"
                    );
                    format = Some(filesystem.clone());
                }
                if !fault_armed && matches!(checkpoint.step, ReconcileStep::FormatFilesystem { .. })
                {
                    arm_format_response_fault(&checkpoint, filesystem, run_id)?;
                    fault_armed = true;
                }
                if let Some(head) = step_head {
                    anyhow::ensure!(head.generation.get() > 0, "A22 initialized head is blank");
                    if let Some(existing) = &initialized_head {
                        anyhow::ensure!(
                            existing == head,
                            "A22 initialized head changed between commit and mount"
                        );
                    } else {
                        initialized_head = Some(head.clone());
                    }
                }
            }
        }
        if checkpoint.stable_state == Some(StableState::Running) {
            let filesystem = format
                .as_ref()
                .context("Running became stable without observed first Format checkpoint")?;
            let snapshot = persistent_snapshot_value(
                cat_id,
                disk_id.as_str(),
                volume_id.as_str(),
                mount_path.as_str(),
            )?;
            let stable_head: RemoteHead = serde_json::from_str(
                snapshot
                    .get("remote_head")
                    .and_then(serde_json::Value::as_str)
                    .context("Persistent snapshot lacks remote head")?,
            )?;
            let initialized_head = initialized_head
                .clone()
                .context("Running became stable without observed A22 initialized head")?;
            let FilesystemInitialization::Initialize {
                expected_blank_head,
                ..
            } = &filesystem.initialization
            else {
                bail!("observed first format is not Initialize")
            };
            anyhow::ensure!(
                initialized_head.generation.get() > expected_blank_head.generation.get()
                    && stable_head.generation.get() >= initialized_head.generation.get(),
                "initialized/stable head did not advance from exact blank head"
            );
            let fault = qualification_fault_evidence(&checkpoint, filesystem, run_id)?;
            println!(
                "{}",
                serde_json::json!({
                    "version": 1,
                    "cat_id": cat_id,
                    "disk_id": disk_id,
                    "volume_id": volume_id,
                    "volume_intent_id": filesystem.volume_intent_id,
                    "attachment_id": filesystem.attachment_id,
                    "attachment_epoch": filesystem.attachment_epoch,
                    "guest_device": {
                        "serial": filesystem.guest_device.serial,
                        "slot": filesystem.guest_device.slot.to_string()
                    },
                    "filesystem_uuid": filesystem.filesystem_uuid,
                    "mount_path": filesystem.mount_path,
                    "expected_blank_head": canonical_head(expected_blank_head)?,
                    "initialized_head": canonical_head(&initialized_head)?,
                    "first_format": {
                        "ambiguous_response_discovered": true,
                        "mkfs_invocations": fault.mkfs_invocations,
                        "fault_action": "drop_validated_format_response_once",
                        "consumed": true,
                        "artifact_sha256": fault.artifact_sha256
                    },
                    "ready": snapshot
                })
            );
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "Persistent initialization watcher timed out"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn persistent_sync(
    cat_id: &str,
    disk_id: &str,
    volume_id: &str,
    mount_path: &str,
    run_id: &str,
) -> Result<()> {
    canonical_run_id(run_id)?;
    let before_snapshot = persistent_snapshot_value(cat_id, disk_id, volume_id, mount_path)?;
    let before_generation = before_snapshot
        .get("remote_generation")
        .and_then(serde_json::Value::as_u64)
        .context("Persistent snapshot lacks remote generation")?;
    let before_head = before_snapshot
        .get("remote_head")
        .and_then(serde_json::Value::as_str)
        .context("Persistent snapshot lacks remote head")?
        .to_owned();
    let checkpoint = installed_checkpoint(cat_id)?;
    let mut guest = guest_client(&checkpoint)?;
    let marker_path = format!(
        "{}/.cats-e3-{}.strict-flush",
        mount_path.trim_end_matches('/'),
        run_id
    );
    let script = "set -eu; umask 077; printf '%s\\n' \"$1\" > \"$2\"; sync -f \"$2\"";
    let (code, stdout, stderr) = guest.exec(vec![
        "sh".into(),
        "-c".into(),
        script.into(),
        "cats-e3".into(),
        run_id.into(),
        marker_path.clone(),
    ])?;
    anyhow::ensure!(
        code == 0,
        "Persistent marker write failed: stdout={stdout:?} stderr={stderr:?}"
    );
    guest
        .syncfs()
        .context("Guest Syncfs after Persistent write")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let after_snapshot = loop {
        let snapshot = persistent_snapshot_value(cat_id, disk_id, volume_id, mount_path)?;
        let after_generation = snapshot
            .get("remote_generation")
            .and_then(serde_json::Value::as_u64)
            .context("Persistent snapshot lacks remote generation")?;
        if after_generation > before_generation {
            break snapshot;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "Persistent Strict remote head did not advance"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let after_head = after_snapshot
        .get("remote_head")
        .and_then(serde_json::Value::as_str)
        .context("post-write Persistent snapshot lacks remote head")?;
    for key in [
        "attachment_id",
        "attachment_epoch",
        "filesystem_uuid",
        "mount_path",
        "runtime_incarnation",
        "guest_boot_id",
    ] {
        anyhow::ensure!(
            after_snapshot.get(key) == before_snapshot.get(key),
            "Persistent identity changed while proving Strict head advance: {key}"
        );
    }
    anyhow::ensure!(after_head != before_head, "Persistent head did not change");
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "cat_id": cat_id,
            "disk_id": disk_id,
            "volume_id": volume_id,
            "attachment_id": before_snapshot["attachment_id"],
            "attachment_epoch": before_snapshot["attachment_epoch"],
            "filesystem_uuid": before_snapshot["filesystem_uuid"],
            "mount_path": mount_path,
            "marker_path": marker_path,
            "before_head": before_head,
            "after_head": after_head,
            "before_remote_generation": before_generation,
            "after_remote_generation": after_snapshot["remote_generation"],
            "remote_durable": true
        })
    );
    Ok(())
}

fn persistent_cold_absence(
    cat_id: &str,
    disk_id: &str,
    volume_id: &str,
    mount_path: &str,
) -> Result<()> {
    let disk_id = Id::new(disk_id.to_owned()).context("invalid --disk-id")?;
    let volume_id = Id::new(volume_id.to_owned()).context("invalid --volume-id")?;
    let mount_path = HostPath::new(mount_path.to_owned()).context("invalid --mount-path")?;
    let checkpoint = load_installed_checkpoint(cat_id)?;
    anyhow::ensure!(
        checkpoint.stable_state == Some(StableState::Cold)
            && matches!(checkpoint.runtime_launch, RuntimeLaunch::Absent)
            && checkpoint.runtime_incarnation.is_none()
            && checkpoint.processes.is_empty()
            && checkpoint.mounts.is_empty()
            && checkpoint.volumes.iter().all(|volume| {
                volume.disk_id.as_ref() != Some(&disk_id)
                    && volume.volume_id != volume_id
                    && volume.devices.is_empty()
            })
            && !checkpoint
                .mounts
                .iter()
                .any(|mount| mount.mount_path == mount_path),
        "Cold checkpoint still contains detached Persistent resources"
    );
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "cat_id": checkpoint.cat_id,
            "node_id": checkpoint.node_id,
            "disk_id": disk_id,
            "volume_id": volume_id,
            "mount_path": mount_path,
            "desired_volume_absent": true,
            "device_absent": true,
            "mount_absent": true,
            "stable_cold": true
        })
    );
    Ok(())
}

fn install_workload(
    cat_id: &str,
    run_id: &str,
    workload: &Path,
    expected_sha256: &str,
    port: u16,
) -> Result<()> {
    canonical_run_id(run_id)?;
    anyhow::ensure!(port > 0, "--port must be non-zero");
    anyhow::ensure!(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "--workload-sha256 is not one lowercase SHA-256"
    );
    let bytes = bounded_regular_file(workload, 16 * 1024 * 1024)?;
    let actual_sha256 = hex::encode(Sha256::digest(&bytes));
    anyhow::ensure!(
        actual_sha256 == expected_sha256,
        "Guest workload bytes differ from the E3 manifest"
    );
    let checkpoint = installed_checkpoint(cat_id)?;
    let mut guest = guest_client(&checkpoint)?;
    let unit = format!("cats-e3-{run_id}");
    let path = format!("/run/cats/{unit}");
    let (code, stdout, stderr) = guest.exec(vec![
        "sh".into(),
        "-c".into(),
        "set -eu; umask 077; : > \"$1\"; chmod 0600 \"$1\"".into(),
        "cats-e3".into(),
        path.clone(),
    ])?;
    anyhow::ensure!(
        code == 0,
        "prepare Guest workload failed: stdout={stdout:?} stderr={stderr:?}"
    );
    // Guest Exec uses the existing bounded JSON frame, so transfer the
    // manifest-bound executable in small ordered chunks instead of assuming
    // one encoded Rust binary fits the 16 MiB Guest protocol ceiling.
    for chunk in bytes.chunks(256 * 1024) {
        let (code, stdout, stderr) = guest.exec_with_input(
            vec![
                "sh".into(),
                "-c".into(),
                "set -eu; cat >> \"$1\"".into(),
                "cats-e3".into(),
                path.clone(),
            ],
            Default::default(),
            chunk.to_vec(),
        )?;
        anyhow::ensure!(
            code == 0,
            "copy Guest workload failed: stdout={stdout:?} stderr={stderr:?}"
        );
    }
    let script = r#"set -eu
sync -f "$1"
actual=$(sha256sum "$1")
actual=${actual%% *}
test "$actual" = "$5"
chmod 0700 "$1"
systemd-run --quiet --collect --unit "$2" --property=Restart=no -- "$1" --port "$3" --nonce "$4"
attempt=0
while test "$attempt" -lt 100; do
  attempt=$((attempt + 1))
  main_pid=$(systemctl show --property=MainPID --value "$2.service")
  case "$main_pid" in ''|0|*[!0-9]*) sleep 0.1; continue ;; esac
  main_exe=$(readlink -f "/proc/$main_pid/exe")
  expected_exe=$(readlink -f "$1")
  if test "$main_exe" = "$expected_exe"; then
    printf '%s\n%s\n%s\n' "$actual" "$main_pid" "$main_exe"
    exit 0
  fi
  sleep 0.1
done
exit 1"#;
    let (code, stdout, stderr) = guest.exec(vec![
        "sh".into(),
        "-c".into(),
        script.into(),
        "cats-e3".into(),
        path.clone(),
        unit.clone(),
        port.to_string(),
        run_id.into(),
        expected_sha256.into(),
    ])?;
    anyhow::ensure!(
        code == 0,
        "install Guest workload failed: stdout={stdout:?} stderr={stderr:?}"
    );
    let proof = stdout.lines().collect::<Vec<_>>();
    let [guest_sha256, main_pid, main_executable] = proof.as_slice() else {
        bail!("Guest workload start did not return exact hash and MainPID proof")
    };
    anyhow::ensure!(
        *guest_sha256 == expected_sha256,
        "Guest re-read digest differs from the E3 manifest"
    );
    anyhow::ensure!(
        main_pid.parse::<u32>().is_ok_and(|pid| pid > 0),
        "Guest workload MainPID is invalid"
    );
    anyhow::ensure!(
        *main_executable == path,
        "Guest workload MainPID executes another file"
    );
    println!(
        "{}",
        serde_json::json!({"version":1,"cat_id":cat_id,"node_id":checkpoint.node_id,"run_id":run_id,"unit":unit,"path":path,"port":port,"workload_sha256":actual_sha256,"guest_reread_sha256":guest_sha256,"guest_file_fsynced":true,"unit_main_pid":main_pid,"unit_main_executable":main_executable,"installed":true})
    );
    Ok(())
}

fn remove_workload(cat_id: &str, run_id: &str) -> Result<()> {
    canonical_run_id(run_id)?;
    let checkpoint = installed_checkpoint(cat_id)?;
    let mut guest = guest_client(&checkpoint)?;
    let unit = format!("cats-e3-{run_id}");
    let path = format!("/run/cats/{unit}");
    let script = "set -eu; systemctl stop \"$1.service\" 2>/dev/null || true; rm -f -- \"$2\"";
    let (code, stdout, stderr) = guest.exec(vec![
        "sh".into(),
        "-c".into(),
        script.into(),
        "cats-e3".into(),
        unit,
        path,
    ])?;
    anyhow::ensure!(
        code == 0,
        "remove Guest workload failed: stdout={stdout:?} stderr={stderr:?}"
    );
    println!(
        "{}",
        serde_json::json!({"version":1,"cat_id":cat_id,"node_id":checkpoint.node_id,"run_id":run_id,"removed":true})
    );
    Ok(())
}

fn canonical_run_id(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-')),
        "--run-id is not canonical"
    );
    Ok(())
}

fn public_route(origin: &str, run_id: &str) -> Result<()> {
    canonical_run_id(run_id)?;
    let origin = reqwest::Url::parse(origin).context("parse --origin")?;
    anyhow::ensure!(
        origin.scheme() == "https"
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "--origin must be one canonical HTTPS origin"
    );
    let http_url = origin.join(&format!("e3/{run_id}"))?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = client
        .get(http_url.clone())
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .context("public HTTP response is ambiguous")?;
    anyhow::ensure!(
        response.url() == &http_url,
        "public HTTP request redirected"
    );
    anyhow::ensure!(
        response.status() == reqwest::StatusCode::OK,
        "public HTTP status is not 200"
    );
    let content_types = response
        .headers()
        .get_all(reqwest::header::CONTENT_TYPE)
        .iter()
        .map(reqwest::header::HeaderValue::as_bytes)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        content_types.as_slice() == [b"text/plain"],
        "public HTTP Content-Type is not exact"
    );
    anyhow::ensure!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_none(),
        "public HTTP response is encoded"
    );
    let mut body = Vec::new();
    response.take(4_097).read_to_end(&mut body)?;
    anyhow::ensure!(
        body == format!("cats-e3-http:{run_id}\n").as_bytes(),
        "public HTTP body does not come from the run-bound Guest workload"
    );

    let mut ws_url = origin;
    ws_url
        .set_scheme("wss")
        .map_err(|_| anyhow::anyhow!("replace WebSocket scheme"))?;
    ws_url.set_path(&format!("/e3/{run_id}/ws"));
    let runtime = tokio::runtime::Runtime::new().context("start WebSocket probe runtime")?;
    runtime.block_on(async {
        let (mut socket, response) = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_tungstenite::connect_async(ws_url.as_str()),
        )
        .await
        .context("public WebSocket handshake timed out")??;
        anyhow::ensure!(
            response.status().as_u16() == 101,
            "public WebSocket status is not 101"
        );
        let payload = format!("cats-e3-ws:{run_id}");
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                payload.clone().into(),
            ))
            .await?;
        let echoed = tokio::time::timeout(Duration::from_secs(15), socket.next())
            .await
            .context("public WebSocket echo timed out")?
            .context("public WebSocket closed before echo")??;
        anyhow::ensure!(
            echoed == tokio_tungstenite::tungstenite::Message::Text(payload.into()),
            "public WebSocket frame was not echoed by the Guest"
        );
        socket.close(None).await?;
        Result::<()>::Ok(())
    })?;
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "origin": http_url.origin().ascii_serialization(),
            "run_id": run_id,
            "http_guest_body": true,
            "websocket_guest_echo": true
        })
    );
    Ok(())
}

fn public_route_closed(origin: &str, run_id: &str) -> Result<()> {
    canonical_run_id(run_id)?;
    let origin = reqwest::Url::parse(origin).context("parse --origin")?;
    anyhow::ensure!(
        origin.scheme() == "https"
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "--origin must be one canonical HTTPS origin"
    );
    let http_url = origin.join(&format!("e3/{run_id}"))?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = client
        .get(http_url.clone())
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .context("closed public HTTP response is ambiguous")?;
    anyhow::ensure!(
        response.url() == &http_url,
        "closed public HTTP request redirected"
    );
    anyhow::ensure!(
        response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "closed public HTTP status is not 503"
    );
    let content_types = response
        .headers()
        .get_all(reqwest::header::CONTENT_TYPE)
        .iter()
        .map(reqwest::header::HeaderValue::as_bytes)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        content_types.as_slice() == [b"text/plain"],
        "closed public HTTP Content-Type is not exact"
    );
    let retry_after = response
        .headers()
        .get_all(reqwest::header::RETRY_AFTER)
        .iter()
        .map(reqwest::header::HeaderValue::as_bytes)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        retry_after.as_slice() == [b"1"],
        "closed public HTTP Retry-After is not exact"
    );
    anyhow::ensure!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_none(),
        "closed public HTTP response is encoded"
    );
    let mut body = Vec::new();
    response.take(4_097).read_to_end(&mut body)?;
    anyhow::ensure!(
        body == b"service unavailable\n",
        "closed public HTTP body is not the fixed Gateway rejection"
    );
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "kind": "route_v2_public_admission_closed_v1",
            "origin": http_url.origin().ascii_serialization(),
            "path": http_url.path(),
            "run_id": run_id,
            "tls_reachable": true,
            "http_status": 503,
            "content_type": "text/plain",
            "retry_after_seconds": 1,
            "content_encoding_absent": true,
            "body_sha256": format!("sha256:{}", hex::encode(Sha256::digest(&body))),
            "terminal_marker": "public_ingress_reachable_route_v2_closed"
        })
    );
    Ok(())
}

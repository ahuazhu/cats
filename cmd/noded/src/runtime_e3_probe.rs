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
use cats_api::runtime_reconciliation::{
    decode_node_identity, decode_runtime_checkpoint, encode_node_identity,
    encode_runtime_checkpoint, GuestTransportEvidence, Id, NodeIdentity, NodeIdentityState,
    ObservedDiskKind, PrepareDeviceFrontend, ProcessRole, RuntimeCheckpoint, RuntimeLaunch,
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
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::GuestSync { cat_id, run_id } => guest_sync(&cat_id, &run_id),
        Command::Snapshot { cat_id } => snapshot(&cat_id),
        Command::InstallWorkload {
            cat_id,
            run_id,
            workload,
            workload_sha256,
            port,
        } => install_workload(&cat_id, &run_id, &workload, &workload_sha256, port),
        Command::RemoveWorkload { cat_id, run_id } => remove_workload(&cat_id, &run_id),
        Command::PublicRoute { origin, run_id } => public_route(&origin, &run_id),
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

fn installed_checkpoint(raw_cat_id: &str) -> Result<RuntimeCheckpoint> {
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
    let mut stream = UnixStream::connect(facts.control_socket).with_context(|| {
        format!(
            "connect blockd control at {}",
            facts.control_socket.display()
        )
    })?;
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
        status.volume_id == facts.volume_id.as_str()
            && status.attachment_id == facts.attachment_id.as_str()
            && status.attachment_epoch == Some(facts.attachment_epoch)
            && status.mode == "strict"
            && status.guest_io_enabled == Some(true)
            && !status.fenced,
        "blockd status does not bind the exact live Strict attachment"
    );
    Ok(status)
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
        serde_json::json!({"version":1,"cat_id":cat_id,"run_id":run_id,"unit":unit,"path":path,"port":port,"workload_sha256":actual_sha256,"guest_reread_sha256":guest_sha256,"guest_file_fsynced":true,"unit_main_pid":main_pid,"unit_main_executable":main_executable,"installed":true})
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
        serde_json::json!({"version":1,"cat_id":cat_id,"run_id":run_id,"removed":true})
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
    let mut response = client
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

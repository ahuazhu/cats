use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use cats_guest_agent::{bind_vsock, GuestAgent, GuestMode};
use cats_protocol::guest::{GUEST_HOST_CONTROL_VSOCK_PORT_V1, GUEST_RUNTIME_SOCKET_PATH};

#[derive(Parser, Debug)]
#[command(name = "cats-guest-agent", about = "Cats in-guest control agent")]
struct Args {
    /// fake = FakeVmm host process; vm = real guest (kernel boot_id, vsock).
    #[arg(long, default_value = "fake")]
    mode: String,
    /// Control protocol unix socket (fake mode / debugging).
    #[arg(long)]
    control_socket: Option<PathBuf>,
    /// Control protocol AF_VSOCK port (real guests; requires --mode vm).
    #[arg(long)]
    vsock_port: Option<u32>,
    /// JSON map of attached disks, maintained by the node agent (fake mode).
    #[arg(long)]
    disk_map: Option<PathBuf>,
    /// Tiny demo web service socket (endpoint target in dev).
    #[arg(long)]
    web_socket: Option<PathBuf>,
    /// Guest-local HTTP runtime socket. Real guests default to
    /// /run/cats/runtime.sock; FakeVmm passes an isolated host path.
    #[arg(long)]
    runtime_socket: Option<PathBuf>,
    /// Warm-restore state file; created by SaveState, read at boot (fake).
    #[arg(long)]
    state_file: Option<PathBuf>,
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).context("remove stale Unix socket")
        }
        Ok(_) => anyhow::bail!("refusing to replace non-socket path at {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect Unix socket path"),
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let mode = match args.mode.as_str() {
        "fake" => GuestMode::Fake,
        "vm" => GuestMode::Vm,
        other => anyhow::bail!("unknown mode {other} (expected fake|vm)"),
    };
    let is_vm = mode == GuestMode::Vm;
    let disk_map = args
        .disk_map
        .unwrap_or_else(|| PathBuf::from("/nonexistent-disk-map"));
    let agent = Arc::new(GuestAgent::with_mode(
        mode,
        disk_map,
        args.state_file.as_deref(),
    ));
    tracing::info!(boot_id = agent.boot_id(), mode = %args.mode, "guest agent booting");

    if let Some(web) = &args.web_socket {
        remove_stale_socket(web)?;
        let listener = UnixListener::bind(web).context("bind web socket")?;
        let agent = agent.clone();
        std::thread::spawn(move || agent.serve_web(listener));
    }

    let runtime_socket = args
        .runtime_socket
        .or_else(|| is_vm.then(|| PathBuf::from(GUEST_RUNTIME_SOCKET_PATH)));
    if let Some(runtime) = runtime_socket {
        if let Some(parent) = runtime.parent() {
            std::fs::create_dir_all(parent).context("create Guest runtime socket directory")?;
            if runtime == Path::new(GUEST_RUNTIME_SOCKET_PATH) {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        remove_stale_socket(&runtime)?;
        let listener = UnixListener::bind(&runtime).context("bind Guest runtime socket")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Every user program in the Cat may declare its own work. The
            // socket is Guest-local and carries no platform credentials.
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o666))?;
        }
        tracing::info!(socket = %runtime.display(), "Guest runtime HTTP API listening");
        let agent = agent.clone();
        std::thread::spawn(move || agent.serve_runtime_http(listener));
    }

    match (&args.control_socket, args.vsock_port) {
        (Some(path), None) => {
            remove_stale_socket(path)?;
            let listener = UnixListener::bind(path).context("bind control socket")?;
            println!("READY");
            agent.serve_control(listener);
        }
        (None, Some(port)) => {
            anyhow::ensure!(is_vm, "AF_VSOCK host control requires --mode vm");
            anyhow::ensure!(
                port == GUEST_HOST_CONTROL_VSOCK_PORT_V1,
                "Guest host-control V1 requires fixed AF_VSOCK port {}",
                GUEST_HOST_CONTROL_VSOCK_PORT_V1
            );
            let listener = bind_vsock(port).context("bind vsock control port")?;
            println!("READY");
            agent.serve_vsock_control(listener)?;
        }
        _ => anyhow::bail!("exactly one of --control-socket or --vsock-port must be given"),
    }
    Ok(())
}

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use cats_guest_agent::{bind_vsock, GuestAgent, GuestMode};

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
    /// Warm-restore state file; created by SaveState, read at boot (fake).
    #[arg(long)]
    state_file: Option<PathBuf>,
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
        let _ = std::fs::remove_file(web);
        let listener = UnixListener::bind(web).context("bind web socket")?;
        let agent = agent.clone();
        std::thread::spawn(move || agent.serve_web(listener));
    }

    let listener = match (&args.control_socket, args.vsock_port) {
        (Some(path), None) => {
            let _ = std::fs::remove_file(path);
            UnixListener::bind(path).context("bind control socket")?
        }
        (None, Some(port)) => bind_vsock(port).context("bind vsock control port")?,
        _ => anyhow::bail!("exactly one of --control-socket or --vsock-port must be given"),
    };
    println!("READY");
    agent.serve_control(listener);
    Ok(())
}

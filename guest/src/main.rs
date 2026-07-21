use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use cats_guest_agent::GuestAgent;

#[derive(Parser, Debug)]
#[command(name = "cats-guest-agent", about = "Cats in-guest control agent")]
struct Args {
    /// Control protocol socket (vsock stand-in in dev).
    #[arg(long)]
    control_socket: PathBuf,
    /// JSON map of attached disks, maintained by the node agent.
    #[arg(long)]
    disk_map: PathBuf,
    /// Tiny demo web service socket (endpoint target in dev).
    #[arg(long)]
    web_socket: Option<PathBuf>,
    /// Warm-restore state file; created by SaveState, read at boot.
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

    let agent = Arc::new(GuestAgent::new(
        args.disk_map.clone(),
        args.state_file.as_deref(),
    ));
    tracing::info!(boot_id = agent.boot_id(), "guest agent booting");

    if let Some(web) = &args.web_socket {
        let _ = std::fs::remove_file(web);
        let listener = UnixListener::bind(web).context("bind web socket")?;
        let agent = agent.clone();
        std::thread::spawn(move || agent.serve_web(listener));
    }

    let _ = std::fs::remove_file(&args.control_socket);
    let listener = UnixListener::bind(&args.control_socket).context("bind control socket")?;
    println!("READY");
    agent.serve_control(listener);
    Ok(())
}

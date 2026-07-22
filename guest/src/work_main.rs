use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use cats_api::guest::{
    GuestLocalWorkRequest, GuestLocalWorkRequestBody, GuestLocalWorkResponse,
    GuestLocalWorkResponseBody, GuestWorkLease, DEFAULT_WORK_LEASE_TTL_MS,
};
use cats_guest_agent::{read_frame, write_frame};

#[derive(Parser)]
#[command(name = "cats-guest-work", about = "Declare Guest user work to Cats")]
struct Cli {
    #[arg(
        long,
        env = "CATS_WORK_SOCKET",
        default_value = "/run/cats/work.sock",
        global = true
    )]
    socket: PathBuf,
    #[command(subcommand)]
    command: WorkCommand,
}

#[derive(Subcommand)]
enum WorkCommand {
    Acquire {
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = DEFAULT_WORK_LEASE_TTL_MS)]
        ttl_ms: u64,
    },
    Renew {
        lease_id: String,
        #[arg(long, default_value_t = DEFAULT_WORK_LEASE_TTL_MS)]
        ttl_ms: u64,
    },
    Release {
        lease_id: String,
    },
    List,
    Run {
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = DEFAULT_WORK_LEASE_TTL_MS)]
        ttl_ms: u64,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

fn request(socket: &Path, body: GuestLocalWorkRequestBody) -> Result<GuestLocalWorkResponseBody> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect work socket {}", socket.display()))?;
    write_frame(&mut stream, &GuestLocalWorkRequest { id: 1, body })?;
    let response: GuestLocalWorkResponse = read_frame(&mut stream)?;
    match response.body {
        GuestLocalWorkResponseBody::Error { message } => bail!(message),
        other => Ok(other),
    }
}

fn acquire(socket: &Path, name: String, ttl_ms: u64) -> Result<GuestWorkLease> {
    match request(
        socket,
        GuestLocalWorkRequestBody::Acquire {
            label: name,
            ttl_ms,
        },
    )? {
        GuestLocalWorkResponseBody::Lease { lease } => Ok(lease),
        other => bail!("unexpected work response: {other:?}"),
    }
}

fn release(socket: &Path, lease_id: String) -> Result<()> {
    match request(socket, GuestLocalWorkRequestBody::Release { lease_id })? {
        GuestLocalWorkResponseBody::Ok => Ok(()),
        other => bail!("unexpected work response: {other:?}"),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        WorkCommand::Acquire { name, ttl_ms } => {
            println!("{}", acquire(&cli.socket, name, ttl_ms)?.id);
        }
        WorkCommand::Renew { lease_id, ttl_ms } => match request(
            &cli.socket,
            GuestLocalWorkRequestBody::Renew { lease_id, ttl_ms },
        )? {
            GuestLocalWorkResponseBody::Lease { lease } => println!("{}", lease.id),
            other => bail!("unexpected work response: {other:?}"),
        },
        WorkCommand::Release { lease_id } => release(&cli.socket, lease_id)?,
        WorkCommand::List => match request(&cli.socket, GuestLocalWorkRequestBody::List)? {
            GuestLocalWorkResponseBody::Status { status } => {
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            other => bail!("unexpected work response: {other:?}"),
        },
        WorkCommand::Run {
            name,
            ttl_ms,
            command,
        } => {
            let lease = acquire(&cli.socket, name.clone(), ttl_ms)?;
            let lease_id = Arc::new(Mutex::new(lease.id));
            let (stop_tx, stop_rx) = mpsc::channel();
            let renew_socket = cli.socket.clone();
            let renew_id = lease_id.clone();
            let renew_name = name;
            let renew_every = Duration::from_millis((ttl_ms / 3).max(1));
            let renewer = std::thread::spawn(move || {
                'keepalive: loop {
                    match stop_rx.recv_timeout(renew_every) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let current_id = renew_id.lock().unwrap().clone();
                    if request(
                        &renew_socket,
                        GuestLocalWorkRequestBody::Renew {
                            lease_id: current_id,
                            ttl_ms,
                        },
                    )
                    .is_err()
                    {
                        // Guest Agent restart loses its in-memory lease. Keep
                        // retrying acquire; stale-signal fail-awake protects
                        // the child during the gap. A quiesce-race rejection
                        // changes the Guest sequence and makes Suspend abort.
                        loop {
                            match stop_rx.recv_timeout(Duration::from_millis(100)) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                                    break 'keepalive;
                                }
                                Err(mpsc::RecvTimeoutError::Timeout) => {}
                            }
                            if let Ok(new_lease) =
                                acquire(&renew_socket, renew_name.clone(), ttl_ms)
                            {
                                *renew_id.lock().unwrap() = new_lease.id;
                                break;
                            }
                        }
                    }
                }
            });
            let (program, args) = command
                .split_first()
                .ok_or_else(|| io::Error::other("command is empty"))?;
            let status = Command::new(program).args(args).status();
            let _ = stop_tx.send(());
            renewer
                .join()
                .map_err(|_| io::Error::other("renewer panicked"))?;
            let release_result = release(&cli.socket, lease_id.lock().unwrap().clone());
            let status = status.with_context(|| format!("spawn {program}"))?;
            release_result?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }
    Ok(())
}

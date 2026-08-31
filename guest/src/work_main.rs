use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use serde::de::DeserializeOwned;
use serde::Serialize;

use cats_protocol::guest::{
    AcquireGuestWorkLeaseRequest, GuestRuntimeApiErrorResponse, GuestWorkLease, GuestWorkStatus,
    RenewGuestWorkLeaseRequest, DEFAULT_WORK_LEASE_TTL_MS, GUEST_RUNTIME_SOCKET_PATH,
    GUEST_WORK_LEASES_PATH,
};

#[derive(Parser)]
#[command(name = "cats-guest-work", about = "Declare Guest user work to Cats")]
struct Cli {
    #[arg(
        long,
        env = "CATS_RUNTIME_SOCKET",
        default_value = GUEST_RUNTIME_SOCKET_PATH,
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

fn request(socket: &Path, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect Guest runtime socket {}", socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nhost: cats-runtime\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("Guest runtime returned incomplete HTTP headers")?;
    let head = std::str::from_utf8(&response[..split]).context("HTTP headers are not UTF-8")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("Guest runtime returned an invalid HTTP status line")?
        .parse::<u16>()
        .context("Guest runtime returned a non-numeric HTTP status")?;
    let body = response[split + 4..].to_vec();
    if !(200..300).contains(&status) {
        if let Ok(error) = serde_json::from_slice::<GuestRuntimeApiErrorResponse>(&body) {
            bail!("{}: {}", error.error.code, error.error.message);
        }
        bail!("Guest runtime HTTP request failed with status {status}");
    }
    Ok(body)
}

fn request_json<T: Serialize, R: DeserializeOwned>(
    socket: &Path,
    method: &str,
    path: &str,
    value: &T,
) -> Result<R> {
    let body = serde_json::to_vec(value)?;
    Ok(serde_json::from_slice(&request(
        socket, method, path, &body,
    )?)?)
}

fn lease_path(lease_id: &str) -> Result<String> {
    if lease_id.is_empty()
        || !lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("invalid work lease id");
    }
    Ok(format!("{GUEST_WORK_LEASES_PATH}/{lease_id}"))
}

fn acquire(socket: &Path, name: String, ttl_ms: u64) -> Result<GuestWorkLease> {
    request_json(
        socket,
        "POST",
        GUEST_WORK_LEASES_PATH,
        &AcquireGuestWorkLeaseRequest {
            label: name,
            ttl_ms,
        },
    )
}

fn renew(socket: &Path, lease_id: &str, ttl_ms: u64) -> Result<GuestWorkLease> {
    request_json(
        socket,
        "PUT",
        &lease_path(lease_id)?,
        &RenewGuestWorkLeaseRequest { ttl_ms },
    )
}

fn release(socket: &Path, lease_id: String) -> Result<()> {
    request(socket, "DELETE", &lease_path(&lease_id)?, &[])?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        WorkCommand::Acquire { name, ttl_ms } => {
            println!("{}", acquire(&cli.socket, name, ttl_ms)?.id);
        }
        WorkCommand::Renew { lease_id, ttl_ms } => {
            println!("{}", renew(&cli.socket, &lease_id, ttl_ms)?.id);
        }
        WorkCommand::Release { lease_id } => release(&cli.socket, lease_id)?,
        WorkCommand::List => {
            let status: GuestWorkStatus =
                serde_json::from_slice(&request(&cli.socket, "GET", GUEST_WORK_LEASES_PATH, &[])?)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
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
                    if renew(&renew_socket, &current_id, ttl_ms).is_err() {
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

//! Synchronous client for the guest agent protocol (unix socket dev
//! transport). Called from `spawn_blocking` contexts in the async server.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use cats_api::guest::{
    GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody, GuestWorkStatus,
};
use cats_guest_agent::{read_frame, write_frame};

pub struct GuestClient {
    stream: UnixStream,
    next_id: u64,
}

impl GuestClient {
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connect guest agent at {}", path.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self { stream, next_id: 1 })
    }

    /// Connect through Cloud Hypervisor's hybrid vsock socket: the VMM
    /// exposes a unix socket on the host; the client sends
    /// `CONNECT <port>\n` and the VMM answers `OK <assigned>\n` before the
    /// raw guest byte stream begins (Firecracker-compatible handshake).
    pub fn connect_hybrid_vsock(path: &Path, port: u32) -> Result<Self> {
        use std::io::{BufRead, BufReader, Write};
        let mut stream = UnixStream::connect(path)
            .with_context(|| format!("connect vsock mux at {}", path.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
        // Read the single handshake line without buffering past it.
        let mut reader = BufReader::with_capacity(64, stream.try_clone()?);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("vsock handshake read")?;
        if !line.starts_with("OK") {
            bail!("vsock handshake rejected: {}", line.trim());
        }
        drop(reader); // BufReader consumed exactly the handshake line
        Ok(Self { stream, next_id: 1 })
    }

    pub fn request(&mut self, body: GuestRequestBody) -> Result<GuestResponseBody> {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.stream, &GuestRequest { id, body })?;
        let resp: GuestResponse = read_frame(&mut self.stream)?;
        if resp.id != id {
            bail!("guest response id mismatch");
        }
        if let GuestResponseBody::Error { message } = &resp.body {
            bail!("guest error: {message}");
        }
        Ok(resp.body)
    }

    pub fn health(&mut self) -> Result<(String, Vec<String>)> {
        match self.request(GuestRequestBody::Health)? {
            GuestResponseBody::Health { boot_id, disks, .. } => Ok((boot_id, disks)),
            other => bail!("unexpected health response: {other:?}"),
        }
    }

    pub fn syncfs(&mut self) -> Result<()> {
        self.request(GuestRequestBody::Syncfs).map(|_| ())
    }

    pub fn work_status(
        &mut self,
        after_sequence: Option<u64>,
        wait_timeout_ms: u64,
    ) -> Result<GuestWorkStatus> {
        match self.request(GuestRequestBody::WorkStatus {
            after_sequence,
            wait_timeout_ms,
        })? {
            GuestResponseBody::WorkStatus { status } => Ok(status),
            other => bail!("unexpected work status response: {other:?}"),
        }
    }

    pub fn prepare_suspend(&mut self, expected_lease_sequence: u64) -> Result<(String, u64)> {
        match self.request(GuestRequestBody::PrepareSuspend {
            expected_lease_sequence,
        })? {
            GuestResponseBody::SuspendPrepared {
                source_epoch,
                lease_sequence,
            } => Ok((source_epoch, lease_sequence)),
            other => bail!("unexpected prepare suspend response: {other:?}"),
        }
    }

    pub fn abort_suspend(&mut self) -> Result<()> {
        self.request(GuestRequestBody::AbortSuspend).map(|_| ())
    }

    pub fn flush_disk(&mut self, disk_id: &str) -> Result<()> {
        self.request(GuestRequestBody::FlushDisk {
            disk_id: disk_id.to_string(),
        })
        .map(|_| ())
    }

    pub fn save_state(&mut self, path: &Path) -> Result<()> {
        self.request(GuestRequestBody::SaveState {
            path: path.display().to_string(),
        })
        .map(|_| ())
    }

    pub fn shutdown(&mut self) -> Result<()> {
        // The peer exits without replying; a broken pipe here is success.
        let _ = write_frame(
            &mut self.stream,
            &GuestRequest {
                id: self.next_id,
                body: GuestRequestBody::Shutdown,
            },
        );
        Ok(())
    }

    pub fn exec(&mut self, command: Vec<String>) -> Result<(i32, String, String)> {
        match self.request(GuestRequestBody::Exec {
            command,
            timeout_ms: None,
        })? {
            GuestResponseBody::Exec {
                exit_code,
                stdout,
                stderr,
            } => Ok((exit_code, stdout, stderr)),
            other => bail!("unexpected exec response: {other:?}"),
        }
    }
}

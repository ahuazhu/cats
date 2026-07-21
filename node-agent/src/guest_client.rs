//! Synchronous client for the guest agent protocol (unix socket dev
//! transport). Called from `spawn_blocking` contexts in the async server.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use cats_api::guest::{GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody};
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

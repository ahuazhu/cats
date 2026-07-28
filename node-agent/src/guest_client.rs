//! Synchronous client for the guest agent protocol (unix socket dev
//! transport). Called from `spawn_blocking` contexts in the async server.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use cats_api::guest::{
    GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody, GuestShellFrame,
    GuestWorkStatus,
};
use cats_guest_agent::{read_frame, write_frame};

pub struct GuestClient {
    stream: UnixStream,
    next_id: u64,
}

pub struct GuestShell {
    stream: UnixStream,
}

impl GuestShell {
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
        })
    }

    pub fn send(&mut self, frame: &GuestShellFrame) -> Result<()> {
        write_frame(&mut self.stream, frame).context("write guest shell frame")
    }

    pub fn recv(&mut self) -> Result<GuestShellFrame> {
        read_frame(&mut self.stream).context("read guest shell frame")
    }
}

impl GuestClient {
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connect guest agent at {}", path.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self { stream, next_id: 1 })
    }

    pub fn connect_shell(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connect guest agent at {}", path.display()))?;
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

    /// Connect for a command that may run for a long time without printing.
    ///
    /// The 30 s read timeout the other connects use is right for a health probe
    /// and wrong for `cats exec`: a build, a test run or a large install is
    /// routinely silent for longer than that, and the timeout killed the command
    /// rather than the connection. Measured before the fix, `cats exec -- sleep
    /// 40` failed after 30.7 s with "Resource temporarily unavailable".
    ///
    /// Same trade-off the interactive shell already accepts: a wedged guest agent
    /// holds the connection until the socket dies. The health probes keep their
    /// bound, so a wedged agent is still detected.
    pub fn connect_long_running(path: &Path) -> Result<Self> {
        let client = Self::connect(path)?;
        client
            .stream
            .set_read_timeout(None)
            .context("clear exec read timeout")?;
        Ok(client)
    }

    pub fn connect_hybrid_vsock_long_running(path: &Path, port: u32) -> Result<Self> {
        let client = Self::connect_hybrid_vsock(path, port)?;
        client
            .stream
            .set_read_timeout(None)
            .context("clear exec read timeout")?;
        Ok(client)
    }

    pub fn connect_hybrid_vsock_shell(path: &Path, port: u32) -> Result<Self> {
        let client = Self::connect_hybrid_vsock(path, port)?;
        // Cloud Hypervisor runs on Linux, where an active SO_RCVTIMEO can be
        // cleared after the bounded mux handshake. Keep the handshake bounded
        // but let the subsequent interactive session remain silent forever.
        client
            .stream
            .set_read_timeout(None)
            .context("clear interactive shell read timeout")?;
        Ok(client)
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
        self.exec_with_input(command, Default::default(), Vec::new())
    }

    pub fn exec_with_input(
        &mut self,
        command: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        stdin: Vec<u8>,
    ) -> Result<(i32, String, String)> {
        match self.request(GuestRequestBody::Exec {
            command,
            timeout_ms: None,
            env,
            stdin,
        })? {
            GuestResponseBody::Exec {
                exit_code,
                stdout,
                stderr,
            } => Ok((exit_code, stdout, stderr)),
            other => bail!("unexpected exec response: {other:?}"),
        }
    }

    pub fn start_shell(mut self, rows: u16, cols: u16) -> Result<GuestShell> {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(
            &mut self.stream,
            &GuestRequest {
                id,
                body: GuestRequestBody::Shell { rows, cols },
            },
        )?;
        let response: GuestResponse = read_frame(&mut self.stream)?;
        if response.id != id {
            bail!("guest response id mismatch");
        }
        match response.body {
            GuestResponseBody::ShellReady => Ok(GuestShell {
                stream: self.stream,
            }),
            GuestResponseBody::Error { message } => bail!("guest error: {message}"),
            other => bail!("unexpected shell response: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use cats_api::guest::{GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody};
    use cats_guest_agent::{read_frame, write_frame};

    use super::GuestClient;

    #[test]
    fn interactive_shell_uses_an_unbounded_read_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guest.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            let request: GuestRequest = read_frame(&mut server).unwrap();
            assert!(matches!(
                request.body,
                GuestRequestBody::Shell { rows: 24, cols: 80 }
            ));
            write_frame(
                &mut server,
                &GuestResponse {
                    id: request.id,
                    body: GuestResponseBody::ShellReady,
                },
            )
            .unwrap();
        });

        let shell = GuestClient::connect_shell(&path)
            .unwrap()
            .start_shell(24, 80)
            .unwrap();
        assert_eq!(shell.stream.read_timeout().unwrap(), None);
        peer.join().unwrap();
    }
}

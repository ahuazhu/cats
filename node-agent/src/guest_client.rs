//! Synchronous client for the guest agent protocol (unix socket dev
//! transport). Called from `spawn_blocking` contexts in the async server.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use cats_api::guest::{
    read_frame, read_runtime_ready_response_frame, write_frame, write_runtime_ready_request_frame,
    GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody, GuestShellFrame,
    GuestWorkStatus, RuntimeReadyRequestV1, RuntimeReadyResponseV1,
};
use cats_api::oci::{DeployOciRequest, OciDeployment};

pub struct GuestClient {
    stream: UnixStream,
    next_id: u64,
    hybrid_assigned_port: Option<u32>,
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
        Ok(Self {
            stream,
            next_id: 1,
            hybrid_assigned_port: None,
        })
    }

    pub fn connect_shell(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connect guest agent at {}", path.display()))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self {
            stream,
            next_id: 1,
            hybrid_assigned_port: None,
        })
    }

    /// Connect through Cloud Hypervisor's hybrid vsock socket: the VMM
    /// exposes a unix socket on the host; the client sends
    /// `CONNECT <port>\n` and the VMM answers `OK <assigned>\n` before the
    /// raw guest byte stream begins (Firecracker-compatible handshake).
    pub fn connect_hybrid_vsock(path: &Path, port: u32) -> Result<Self> {
        Self::connect_hybrid_vsock_bounded(path, port, Duration::from_secs(30))
    }

    /// Connect with one caller-supplied bound covering both sides of the mux
    /// handshake. Fresh inventory uses its remaining scan deadline here.
    pub fn connect_hybrid_vsock_bounded(path: &Path, port: u32, timeout: Duration) -> Result<Self> {
        use std::io::Write;

        anyhow::ensure!(
            port > 0 && port < u32::MAX,
            "vsock destination port is outside the canonical range"
        );
        anyhow::ensure!(!timeout.is_zero(), "vsock handshake timeout is zero");
        let mut stream = UnixStream::connect(path)
            .with_context(|| format!("connect vsock mux at {}", path.display()))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
        let hybrid_assigned_port = read_hybrid_vsock_ack(&mut stream)?;
        Ok(Self {
            stream,
            next_id: 1,
            hybrid_assigned_port: Some(hybrid_assigned_port),
        })
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

    /// Issue one RuntimeReady challenge using its independent small request
    /// and response caps. In particular, the response length prefix is
    /// rejected before allocating its body; the generic 16 MiB control cap is
    /// never used on this path.
    pub fn runtime_ready(
        &mut self,
        request: RuntimeReadyRequestV1,
    ) -> Result<RuntimeReadyResponseV1> {
        request
            .validate()
            .context("validate RuntimeReady challenge before send")?;
        let id = self.next_id;
        self.next_id += 1;
        write_runtime_ready_request_frame(
            &mut self.stream,
            &GuestRequest {
                id,
                body: GuestRequestBody::RuntimeReady {
                    ready: request.clone(),
                },
            },
        )
        .context("write bounded RuntimeReady request")?;
        let response: GuestResponse = read_runtime_ready_response_frame(&mut self.stream)
            .context("read bounded RuntimeReady response")?;
        anyhow::ensure!(response.id == id, "guest response id mismatch");
        match response.body {
            GuestResponseBody::RuntimeReady { ready } => {
                ready
                    .validate_against(&request)
                    .context("validate RuntimeReady response")?;
                Ok(ready)
            }
            GuestResponseBody::Error { message } => bail!("guest error: {message}"),
            other => bail!("unexpected RuntimeReady response: {other:?}"),
        }
    }

    pub fn hybrid_assigned_port(&self) -> Option<u32> {
        self.hybrid_assigned_port
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

    pub fn deploy_oci(&mut self, deploy: DeployOciRequest) -> Result<OciDeployment> {
        match self.request(GuestRequestBody::DeployOci { deploy })? {
            GuestResponseBody::OciDeployed { deployment } => Ok(deployment),
            other => bail!("unexpected OCI deploy response: {other:?}"),
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

const MAX_HYBRID_VSOCK_ACK_BYTES: usize = 32;

/// Read exactly through the first LF, one byte at a time. A buffered reader
/// can consume bytes from the following Guest frame and silently lose them
/// when it is dropped after the handshake.
fn read_hybrid_vsock_ack(stream: &mut UnixStream) -> Result<u32> {
    use std::io::Read;

    let mut bytes = Vec::with_capacity(MAX_HYBRID_VSOCK_ACK_BYTES);
    loop {
        anyhow::ensure!(
            bytes.len() < MAX_HYBRID_VSOCK_ACK_BYTES,
            "vsock handshake exceeds its byte bound"
        );
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .context("vsock handshake read")?;
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            return parse_hybrid_vsock_ack(&bytes);
        }
    }
}

fn parse_hybrid_vsock_ack(bytes: &[u8]) -> Result<u32> {
    anyhow::ensure!(
        bytes.len() <= MAX_HYBRID_VSOCK_ACK_BYTES,
        "vsock handshake exceeds its byte bound"
    );
    let line = bytes
        .strip_suffix(b"\n")
        .context("vsock handshake lacks its exact LF terminator")?;
    anyhow::ensure!(
        !line.contains(&b'\n') && !line.contains(&b'\r'),
        "vsock handshake contains multiple lines"
    );
    let assigned = line
        .strip_prefix(b"OK ")
        .context("vsock handshake is not the frozen OK form")?;
    let assigned = std::str::from_utf8(assigned)
        .context("vsock assigned port is not ASCII")?
        .parse::<u32>()
        .ok()
        .filter(|port| *port > 0 && *port < u32::MAX)
        .filter(|port| port.to_string().as_bytes() == assigned)
        .context("vsock assigned port is not a canonical integer")?;
    Ok(assigned)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use cats_api::guest::{
        read_frame, read_guest_request_frame, write_frame, write_runtime_ready_response_frame,
        GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody, RuntimeReadyRequestV1,
        RuntimeReadyResponseV1, RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1,
    };
    use cats_api::runtime_reconciliation::{GuestBootId, RandomId128};

    use super::{parse_hybrid_vsock_ack, GuestClient};

    #[test]
    fn hybrid_vsock_ack_is_one_exact_canonical_line() {
        assert_eq!(
            parse_hybrid_vsock_ack(b"OK 1073741824\n").unwrap(),
            1_073_741_824
        );
        for malformed in [
            &b"OK\n"[..],
            &b"OKAY 7\n"[..],
            &b"OK 7 trailing\n"[..],
            &b"OK 07\n"[..],
            &b"OK 0\n"[..],
            &b"OK 4294967295\n"[..],
            &b"OK 7\r\n"[..],
            &b"OK 7\nOK 8\n"[..],
            &b"OK 7"[..],
        ] {
            assert!(
                parse_hybrid_vsock_ack(malformed).is_err(),
                "accepted {malformed:?}"
            );
        }
    }

    #[test]
    fn hybrid_vsock_reader_does_not_buffer_past_the_ack() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};

            let (mut server, _) = listener.accept().unwrap();
            let mut connect = String::new();
            BufReader::new(server.try_clone().unwrap())
                .read_line(&mut connect)
                .unwrap();
            assert_eq!(connect, "CONNECT 5000\n");
            server.write_all(b"OK 1073741824\n").unwrap();
            write_frame(
                &mut server,
                &GuestResponse {
                    id: 1,
                    body: GuestResponseBody::Health {
                        boot_id: "11111111111111111111111111111111".into(),
                        uptime_ms: 1,
                        disks: Vec::new(),
                    },
                },
            )
            .unwrap();
        });

        let mut client = GuestClient::connect_hybrid_vsock(&path, 5_000).unwrap();
        assert_eq!(client.hybrid_assigned_port(), Some(1_073_741_824));
        assert_eq!(
            client.health().unwrap(),
            ("11111111111111111111111111111111".into(), Vec::new())
        );
        peer.join().unwrap();
    }

    fn ready_request() -> RuntimeReadyRequestV1 {
        RuntimeReadyRequestV1 {
            version: 1,
            challenge: RandomId128::new("11111111111111111111111111111111").unwrap(),
            runtime_incarnation: RandomId128::new("22222222222222222222222222222222").unwrap(),
            expected_guest_cid: 3,
            expected_guest_port: 5_000,
            expected_guest_agent_protocol_version: 1,
        }
    }

    #[test]
    fn runtime_ready_client_uses_its_small_caps_and_exact_echo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guest.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            let request = read_guest_request_frame(&mut server).unwrap();
            let GuestRequestBody::RuntimeReady { ready } = request.body else {
                panic!("unexpected request")
            };
            write_runtime_ready_response_frame(
                &mut server,
                &GuestResponse {
                    id: request.id,
                    body: GuestResponseBody::RuntimeReady {
                        ready: RuntimeReadyResponseV1 {
                            version: 1,
                            challenge: ready.challenge.clone(),
                            runtime_incarnation: ready.runtime_incarnation.clone(),
                            expected_guest_cid: ready.expected_guest_cid,
                            expected_guest_port: ready.expected_guest_port,
                            expected_guest_agent_protocol_version: ready
                                .expected_guest_agent_protocol_version,
                            actual_guest_cid: 3,
                            actual_guest_port: 5_000,
                            actual_guest_agent_protocol_version: 1,
                            guest_boot_id: GuestBootId::new("33333333333333333333333333333333")
                                .unwrap(),
                            devices: Vec::new(),
                            mounts: Vec::new(),
                        },
                    },
                },
            )
            .unwrap();
        });
        let mut client = GuestClient::connect(&path).unwrap();
        assert_eq!(
            client
                .runtime_ready(ready_request())
                .unwrap()
                .actual_guest_cid,
            3
        );
        peer.join().unwrap();

        let path = dir.path().join("oversized.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            use std::io::Write;

            let (mut server, _) = listener.accept().unwrap();
            let _ = read_guest_request_frame(&mut server).unwrap();
            server
                .write_all(&(RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1 + 1).to_be_bytes())
                .unwrap();
        });
        let mut client = GuestClient::connect(&path).unwrap();
        assert!(client
            .runtime_ready(ready_request())
            .unwrap_err()
            .to_string()
            .contains("bounded RuntimeReady response"));
        peer.join().unwrap();
    }

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

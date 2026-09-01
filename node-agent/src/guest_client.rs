//! Synchronous client for the guest agent protocol (unix socket dev
//! transport). Called from `spawn_blocking` contexts in the async server.

use std::io;
use std::net::Shutdown;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use cats_protocol::guest::{
    read_filesystem_control_response_frame, read_frame, read_runtime_ready_response_frame,
    write_filesystem_control_request_frame, write_frame, write_runtime_ready_request_frame,
    FilesystemControlRequestV1, FilesystemControlResponseV1, GuestRequest, GuestRequestBody,
    GuestResponse, GuestResponseBody, GuestShellFrame, GuestWorkStatus, RuntimeReadyRequestV1,
    RuntimeReadyResponseV1,
};
use cats_protocol::oci::{DeployOciRequest, OciDeployment};

pub struct GuestClient {
    stream: UnixStream,
    next_id: u64,
    hybrid_assigned_port: Option<u32>,
    /// One absolute deadline retained by bounded hybrid-vsock connects. Shell
    /// setup consumes the remainder so a trickling ShellReady cannot refresh
    /// a per-syscall socket timeout after the mux handshake.
    hybrid_deadline: Option<Instant>,
}

pub struct GuestShell {
    stream: UnixStream,
}

/// A clone of one Guest control connection used solely to interrupt a
/// blocking exec or shell bridge. `shutdown(Both)` is observable as transport
/// EOF by the Guest, which owns process-group kill and reap semantics.
pub(crate) struct GuestConnectionCancellation {
    stream: UnixStream,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GuestExecError {
    #[error("{message}")]
    Timeout { message: String },
    #[error("{message}")]
    Cancelled { message: String },
    #[error("{message}")]
    RemoteError { message: String },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GuestShellStartError {
    /// Exact Guest Error is terminal: it either rejected before spawn or
    /// completed its own kill/reap path before replying.
    #[error("guest error: {message}")]
    RemoteTerminal { message: String },
    /// Timeout, EOF, malformed frames and identity mismatch are ambiguous.
    #[error(transparent)]
    Ambiguous(#[from] anyhow::Error),
}

impl GuestConnectionCancellation {
    /// Half-close Node -> Guest writes while retaining the response direction.
    /// Exec uses this for graceful lifecycle cancellation: Guest observes EOF,
    /// kills and reaps the process group, then its terminal response proves the
    /// cleanup before the Node access guard can drain.
    pub(crate) fn request_remote_close(&self) {
        let _ = self.stream.shutdown(Shutdown::Write);
    }

    /// Force both directions closed. Destroy/reset and result-unknown Host
    /// deadlines have a physical VMM-stop backstop and may use this stronger
    /// interruption.
    pub(crate) fn cancel(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Drop for GuestConnectionCancellation {
    fn drop(&mut self) {
        // Dropping an HTTP/WebSocket handler is not itself strong lifecycle
        // authority. Preserve the Guest -> Node response direction so remote
        // kill/reap or Shell Exit can still prove cleanup to the retained gate.
        self.request_remote_close();
    }
}

impl GuestShell {
    #[cfg(test)]
    pub(crate) fn from_test_stream(stream: UnixStream) -> Self {
        Self { stream }
    }

    pub(crate) fn cancellation_handle(&self) -> Result<GuestConnectionCancellation> {
        Ok(GuestConnectionCancellation {
            stream: self.stream.try_clone()?,
        })
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
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
    pub(crate) fn cancellation_handle(&self) -> Result<GuestConnectionCancellation> {
        Ok(GuestConnectionCancellation {
            stream: self.stream.try_clone()?,
        })
    }

    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connect guest agent at {}", path.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self {
            stream,
            next_id: 1,
            hybrid_assigned_port: None,
            hybrid_deadline: None,
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
            hybrid_deadline: None,
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
        Self::connect_hybrid_vsock_bounded_inner(path, port, timeout, None)
    }

    /// Connect to the exact installed VMM's hybrid-vsock mux.
    ///
    /// The peer PID is checked both before and after the mux handshake. This
    /// closes path replacement and process-name ambiguity for lifecycle
    /// effects without changing the Guest protocol or treating the transport
    /// check as lifecycle authority.
    pub(crate) fn connect_hybrid_vsock_bounded_exact_peer(
        path: &Path,
        port: u32,
        timeout: Duration,
        expected_vmm_pid: u32,
    ) -> Result<Self> {
        anyhow::ensure!(expected_vmm_pid > 0, "expected VMM PID is zero");
        Self::connect_hybrid_vsock_bounded_inner(path, port, timeout, Some(expected_vmm_pid))
    }

    fn connect_hybrid_vsock_bounded_inner(
        path: &Path,
        port: u32,
        timeout: Duration,
        expected_vmm_pid: Option<u32>,
    ) -> Result<Self> {
        anyhow::ensure!(
            port > 0 && port < u32::MAX,
            "vsock destination port is outside the canonical range"
        );
        anyhow::ensure!(!timeout.is_zero(), "vsock handshake timeout is zero");
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("vsock handshake deadline overflow")?;
        let mut stream = connect_unix_before(path, deadline)
            .with_context(|| format!("connect vsock mux at {}", path.display()))?;
        if let Some(expected_vmm_pid) = expected_vmm_pid {
            ensure_unix_peer_pid(&stream, expected_vmm_pid)
                .context("vsock mux peer is not the exact installed VMM")?;
        }
        write_all_before(
            &mut stream,
            format!("CONNECT {port}\n").as_bytes(),
            deadline,
        )
        .context("vsock handshake write")?;
        let hybrid_assigned_port = read_hybrid_vsock_ack_before(&mut stream, deadline)?;
        if let Some(expected_vmm_pid) = expected_vmm_pid {
            ensure_unix_peer_pid(&stream, expected_vmm_pid)
                .context("vsock mux peer changed during the bounded handshake")?;
        }
        ensure_before(deadline)?;

        // The connect and mux handshake stay nonblocking so one absolute
        // deadline covers every wait. The established Guest stream preserves
        // the blocking and timeout behavior all existing callers rely on.
        stream
            .set_nonblocking(false)
            .context("restore blocking Guest stream")?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Self {
            stream,
            next_id: 1,
            hybrid_assigned_port: Some(hybrid_assigned_port),
            hybrid_deadline: Some(deadline),
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

    pub(crate) fn connect_hybrid_vsock_long_running_exact_peer(
        path: &Path,
        port: u32,
        timeout: Duration,
        expected_vmm_pid: u32,
    ) -> Result<Self> {
        let client =
            Self::connect_hybrid_vsock_bounded_exact_peer(path, port, timeout, expected_vmm_pid)?;
        client
            .stream
            .set_read_timeout(None)
            .context("clear exact-peer exec read timeout")?;
        Ok(client)
    }

    pub fn connect_hybrid_vsock_shell(path: &Path, port: u32) -> Result<Self> {
        Self::connect_hybrid_vsock(path, port)
    }

    pub(crate) fn connect_hybrid_vsock_shell_exact_peer(
        path: &Path,
        port: u32,
        timeout: Duration,
        expected_vmm_pid: u32,
    ) -> Result<Self> {
        Self::connect_hybrid_vsock_bounded_exact_peer(path, port, timeout, expected_vmm_pid)
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

    /// Issue one Guest control request under the caller's absolute deadline.
    ///
    /// `SO_RCVTIMEO` and `SO_SNDTIMEO` are per syscall. Merely setting them
    /// once lets a peer trickle a frame across several successful reads and
    /// extend the lifecycle effect beyond its accepted deadline. The adapter
    /// below refreshes each syscall from the same absolute deadline instead.
    fn request_before(
        &mut self,
        body: GuestRequestBody,
        deadline: Instant,
    ) -> Result<GuestResponseBody> {
        let id = self.next_id;
        self.next_id += 1;
        let mut transport = DeadlineGuestTransport {
            stream: &mut self.stream,
            deadline,
        };
        write_frame(&mut transport, &GuestRequest { id, body })
            .context("write deadline-bounded Guest request")?;
        let resp: GuestResponse =
            read_frame(&mut transport).context("read deadline-bounded Guest response")?;
        if resp.id != id {
            bail!("guest response id mismatch");
        }
        if let GuestResponseBody::Error { message } = &resp.body {
            bail!("guest error: {message}");
        }
        Ok(resp.body)
    }

    pub fn syncfs_before(&mut self, deadline: Instant) -> Result<()> {
        self.request_before(GuestRequestBody::Syncfs, deadline)
            .map(|_| ())
    }

    pub fn work_status_before(
        &mut self,
        after_sequence: Option<u64>,
        wait_timeout_ms: u64,
        deadline: Instant,
    ) -> Result<GuestWorkStatus> {
        match self.request_before(
            GuestRequestBody::WorkStatus {
                after_sequence,
                wait_timeout_ms,
            },
            deadline,
        )? {
            GuestResponseBody::WorkStatus { status } => Ok(status),
            other => bail!("unexpected work status response: {other:?}"),
        }
    }

    pub fn prepare_suspend_before(
        &mut self,
        expected_lease_sequence: u64,
        deadline: Instant,
    ) -> Result<(String, u64)> {
        match self.request_before(
            GuestRequestBody::PrepareSuspend {
                expected_lease_sequence,
            },
            deadline,
        )? {
            GuestResponseBody::SuspendPrepared {
                source_epoch,
                lease_sequence,
            } => Ok((source_epoch, lease_sequence)),
            other => bail!("unexpected prepare suspend response: {other:?}"),
        }
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

    /// Issue one independently tagged, canonical and bounded PersistentDisk
    /// filesystem operation. A response must echo every authority-bearing
    /// request field before its physical observation is returned.
    pub fn filesystem_control(
        &mut self,
        request: FilesystemControlRequestV1,
    ) -> Result<FilesystemControlResponseV1> {
        let timeout = Duration::from_millis(u64::from(request.timeout_ms))
            .checked_add(Duration::from_secs(5))
            .context("filesystem control socket timeout overflow")?;
        self.filesystem_control_bounded(request, timeout)
    }

    /// Apply an outer Host deadline to one filesystem operation. The Guest's
    /// own timeout remains in the canonical request, while this independent
    /// socket bound prevents transport slack from exceeding the reconciler's
    /// accepted-effect deadline.
    pub(crate) fn filesystem_control_bounded(
        &mut self,
        request: FilesystemControlRequestV1,
        transport_timeout: Duration,
    ) -> Result<FilesystemControlResponseV1> {
        request
            .validate()
            .context("validate filesystem control request before send")?;
        anyhow::ensure!(
            !transport_timeout.is_zero(),
            "filesystem control transport timeout is zero"
        );
        let operation_timeout = Duration::from_millis(u64::from(request.timeout_ms))
            .checked_add(Duration::from_secs(5))
            .context("filesystem control socket timeout overflow")?;
        let timeout = transport_timeout.min(operation_timeout);
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        let id = self.next_id;
        self.next_id += 1;
        write_filesystem_control_request_frame(
            &mut self.stream,
            &GuestRequest {
                id,
                body: GuestRequestBody::FilesystemControl {
                    filesystem: request.clone(),
                },
            },
        )
        .context("write bounded filesystem control request")?;
        let response = read_filesystem_control_response_frame(&mut self.stream)
            .context("read bounded filesystem control response")?;
        anyhow::ensure!(response.id == id, "guest response id mismatch");
        match response.body {
            GuestResponseBody::FilesystemControl { filesystem } => {
                filesystem
                    .validate_against(&request)
                    .context("validate filesystem control response")?;
                Ok(filesystem)
            }
            GuestResponseBody::Error { message } => bail!("guest error: {message}"),
            other => bail!("unexpected filesystem control response: {other:?}"),
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
        self.exec_with_options(command, None, env, stdin)
    }

    pub fn exec_with_options(
        &mut self,
        command: Vec<String>,
        timeout_ms: Option<u64>,
        env: std::collections::BTreeMap<String, String>,
        stdin: Vec<u8>,
    ) -> Result<(i32, String, String)> {
        match self.exec_request(GuestRequestBody::Exec {
            command,
            timeout_ms,
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

    fn exec_request(&mut self, body: GuestRequestBody) -> Result<GuestResponseBody> {
        let Some(deadline) = self.hybrid_deadline.take() else {
            return self.request(body);
        };
        let id = self.next_id;
        self.next_id += 1;
        // The exact connect, mux handshake and complete (up to 5 MiB JSON)
        // request write share one admission deadline. Only after this returns
        // does the Guest own its requested execution window.
        let mut transport = DeadlineGuestTransport {
            stream: &mut self.stream,
            deadline,
        };
        write_frame(&mut transport, &GuestRequest { id, body })
            .context("write absolute-deadline Guest Exec request")?;
        let response: GuestResponse = read_frame(&mut self.stream)?;
        if response.id != id {
            bail!("guest response id mismatch");
        }
        if let GuestResponseBody::Error { message } = &response.body {
            bail!("guest error: {message}");
        }
        Ok(response.body)
    }

    pub(crate) fn exec_with_options_classified(
        &mut self,
        command: Vec<String>,
        timeout_ms: Option<u64>,
        env: std::collections::BTreeMap<String, String>,
        stdin: Vec<u8>,
    ) -> std::result::Result<(i32, String, String), GuestExecError> {
        self.exec_with_options(command, timeout_ms, env, stdin)
            .map_err(classify_guest_exec_error)
    }

    pub fn deploy_oci(&mut self, deploy: DeployOciRequest) -> Result<OciDeployment> {
        match self.request(GuestRequestBody::DeployOci { deploy })? {
            GuestResponseBody::OciDeployed { deployment } => Ok(deployment),
            other => bail!("unexpected OCI deploy response: {other:?}"),
        }
    }

    pub(crate) fn start_shell(
        mut self,
        rows: u16,
        cols: u16,
    ) -> std::result::Result<GuestShell, GuestShellStartError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = GuestRequest {
            id,
            body: GuestRequestBody::Shell { rows, cols },
        };
        let response: GuestResponse = if let Some(deadline) = self.hybrid_deadline {
            let mut transport = DeadlineGuestTransport {
                stream: &mut self.stream,
                deadline,
            };
            write_frame(&mut transport, &request)
                .context("write absolute-deadline Guest Shell request")
                .map_err(GuestShellStartError::Ambiguous)?;
            read_frame(&mut transport)
                .context("read absolute-deadline Guest ShellReady")
                .map_err(GuestShellStartError::Ambiguous)?
        } else {
            // Direct development transport retains its existing socket-bound
            // behavior. Production Shell uses the exact hybrid-vsock path.
            write_frame(&mut self.stream, &request)
                .context("write Guest Shell request")
                .map_err(GuestShellStartError::Ambiguous)?;
            read_frame(&mut self.stream)
                .context("read Guest ShellReady")
                .map_err(GuestShellStartError::Ambiguous)?
        };
        if response.id != id {
            return Err(GuestShellStartError::Ambiguous(anyhow::anyhow!(
                "guest response id mismatch"
            )));
        }
        match response.body {
            GuestResponseBody::ShellReady => {
                // Keep the bounded connection timeout through ShellReady. Only
                // the established interactive stream may be silent forever.
                if self
                    .stream
                    .read_timeout()
                    .context("read established shell timeout")
                    .map_err(GuestShellStartError::Ambiguous)?
                    .is_some()
                {
                    self.stream
                        .set_read_timeout(None)
                        .context("clear established shell read timeout")
                        .map_err(GuestShellStartError::Ambiguous)?;
                }
                Ok(GuestShell {
                    stream: self.stream,
                })
            }
            GuestResponseBody::Error { message } => {
                Err(GuestShellStartError::RemoteTerminal { message })
            }
            other => Err(GuestShellStartError::Ambiguous(anyhow::anyhow!(
                "unexpected shell response: {other:?}"
            ))),
        }
    }
}

fn classify_guest_exec_error(error: anyhow::Error) -> GuestExecError {
    const TIMEOUT_PREFIX: &str = "guest error: exec timed out after ";
    const SUFFIX: &str = " ms";
    const CANCELLED: &str = "guest error: exec caller disconnected";
    let message = error.to_string();
    let is_canonical_timeout = message
        .strip_prefix(TIMEOUT_PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
        .is_some_and(|millis| millis.parse::<u64>().is_ok());
    if is_canonical_timeout {
        GuestExecError::Timeout { message }
    } else if message == CANCELLED {
        GuestExecError::Cancelled { message }
    } else if message.starts_with("guest error: ") {
        GuestExecError::RemoteError { message }
    } else {
        GuestExecError::Other(error)
    }
}

struct DeadlineGuestTransport<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl DeadlineGuestTransport<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Guest control deadline elapsed",
            ));
        }
        Ok(remaining)
    }
}

impl io::Read for DeadlineGuestTransport<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        io::Read::read(self.stream, buffer)
    }
}

impl io::Write for DeadlineGuestTransport<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        io::Write::write(self.stream, buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        io::Write::flush(self.stream)
    }
}

const MAX_HYBRID_VSOCK_ACK_BYTES: usize = 32;

#[cfg(target_os = "linux")]
fn ensure_unix_peer_pid(stream: &UnixStream, expected_pid: u32) -> Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .context("vsock mux peer credential length overflow")?;
    // SAFETY: both output pointers name initialized writable objects and the
    // stream retains its live descriptor for the complete getsockopt call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    anyhow::ensure!(
        result == 0
            && usize::try_from(length).ok() == Some(std::mem::size_of::<libc::ucred>())
            && credentials.pid > 0
            && u32::try_from(credentials.pid).ok() == Some(expected_pid),
        "vsock mux Unix peer PID differs from the installed VMM"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_unix_peer_pid(_stream: &UnixStream, _expected_pid: u32) -> Result<()> {
    bail!("exact vsock mux peer credentials require Linux")
}

fn connect_unix_before(path: &Path, deadline: Instant) -> Result<UnixStream> {
    use std::mem::offset_of;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    ensure_before(deadline)?;
    let path_bytes = path.as_os_str().as_bytes();
    // SAFETY: all-zero is a valid initial sockaddr_un. The family, optional
    // BSD length and complete pathname are initialized before connect reads it.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    anyhow::ensure!(
        !path_bytes.is_empty()
            && path_bytes.len() < address.sun_path.len()
            && !path_bytes.contains(&0),
        "vsock mux path is outside the Unix socket address range"
    );
    let address_length = offset_of!(libc::sockaddr_un, sun_path)
        .checked_add(path_bytes.len())
        .and_then(|length| length.checked_add(1))
        .context("vsock mux address length overflow")?;
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sun_len =
            u8::try_from(address_length).context("vsock mux address exceeds BSD range")?;
    }
    for (target, source) in address.sun_path.iter_mut().zip(path_bytes.iter().copied()) {
        *target = source as libc::c_char;
    }
    let address_length = libc::socklen_t::try_from(address_length)
        .context("vsock mux address exceeds socket range")?;

    let socket_type = libc::SOCK_STREAM;
    #[cfg(target_os = "linux")]
    let socket_type = socket_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    // SAFETY: socket returns a fresh descriptor and retains no Rust memory.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).context("create nonblocking vsock mux socket");
    }
    #[cfg(not(target_os = "linux"))]
    if let Err(error) = set_descriptor_nonblocking_and_cloexec(descriptor) {
        // SAFETY: ownership of the fresh descriptor has not moved.
        unsafe { libc::close(descriptor) };
        return Err(error).context("configure nonblocking vsock mux socket");
    }
    // SAFETY: ownership of the fresh descriptor moves into UnixStream once.
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };

    loop {
        ensure_before(deadline)?;
        // SAFETY: stream owns a live AF_UNIX descriptor; address is fully
        // initialized and neither pointer is retained after this call.
        let result = unsafe {
            libc::connect(
                stream.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                address_length,
            )
        };
        if result == 0 {
            return Ok(stream);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EISCONN) => return Ok(stream),
            Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                // Linux AF_UNIX reports a full listener backlog as EAGAIN
                // without arming an asynchronous connect. Retry at a bounded
                // cadence rather than spinning on an always-writable socket.
                wait_before_retry(deadline)?;
            }
            Some(libc::EINPROGRESS) | Some(libc::EALREADY) => {
                poll_before(&stream, libc::POLLOUT, deadline)?;
                match socket_error_before(&stream, deadline)? {
                    0 => return Ok(stream),
                    libc::EINTR | libc::EINPROGRESS | libc::EALREADY => {}
                    code if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                        wait_before_retry(deadline)?;
                    }
                    code => {
                        return Err(std::io::Error::from_raw_os_error(code))
                            .context("complete nonblocking vsock mux connect")
                    }
                }
            }
            _ => return Err(error).context("start nonblocking vsock mux connect"),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_descriptor_nonblocking_and_cloexec(descriptor: libc::c_int) -> std::io::Result<()> {
    // SAFETY: descriptor is live and these fcntl operations only read or
    // replace its integer status/descriptor flags.
    let status = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: descriptor remains live and F_SETFL consumes only the status
    // flags read immediately above.
    let set_status = unsafe { libc::fcntl(descriptor, libc::F_SETFL, status | libc::O_NONBLOCK) };
    if set_status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same live descriptor; preserve any existing descriptor flags.
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: descriptor remains live and F_SETFD consumes only the descriptor
    // flags read immediately above.
    let set_descriptor = unsafe {
        libc::fcntl(
            descriptor,
            libc::F_SETFD,
            descriptor_flags | libc::FD_CLOEXEC,
        )
    };
    if set_descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn socket_error_before(stream: &UnixStream, deadline: Instant) -> Result<libc::c_int> {
    use std::mem::size_of;
    use std::os::fd::AsRawFd as _;

    loop {
        ensure_before(deadline)?;
        let mut error = 0_i32;
        let mut length = size_of::<i32>() as libc::socklen_t;
        // SAFETY: error and length are valid writable scalar storage and the
        // stream retains ownership of its live descriptor.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut error).cast(),
                &raw mut length,
            )
        };
        if result == 0 {
            anyhow::ensure!(
                length as usize == size_of::<i32>(),
                "vsock mux SO_ERROR returned a malformed length"
            );
            return Ok(error);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("read nonblocking vsock mux connect result");
        }
    }
}

fn write_all_before(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    use std::io::Write as _;

    while !bytes.is_empty() {
        ensure_before(deadline)?;
        match stream.write(bytes) {
            Ok(0) => bail!("vsock handshake closed during write"),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_before(stream, libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error).context("write nonblocking vsock handshake"),
        }
    }
    Ok(())
}

/// Read exactly through the first LF, one byte at a time. A buffered reader
/// can consume bytes from the following Guest frame and silently lose them
/// when it is dropped after the handshake.
fn read_hybrid_vsock_ack_before(stream: &mut UnixStream, deadline: Instant) -> Result<u32> {
    use std::io::Read as _;

    let mut bytes = Vec::with_capacity(MAX_HYBRID_VSOCK_ACK_BYTES);
    loop {
        ensure_before(deadline)?;
        anyhow::ensure!(
            bytes.len() < MAX_HYBRID_VSOCK_ACK_BYTES,
            "vsock handshake exceeds its byte bound"
        );
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => bail!("vsock handshake closed before its ACK"),
            Ok(_) => {
                bytes.push(byte[0]);
                if byte[0] == b'\n' {
                    ensure_before(deadline)?;
                    return parse_hybrid_vsock_ack(&bytes);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_before(stream, libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(error).context("read nonblocking vsock handshake"),
        }
    }
}

fn poll_before(stream: &UnixStream, events: libc::c_short, deadline: Instant) -> Result<()> {
    use std::os::fd::AsRawFd as _;

    loop {
        let timeout = poll_timeout_before(deadline)?;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for this call.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result > 0 {
            anyhow::ensure!(
                descriptor.revents & libc::POLLNVAL == 0,
                "vsock mux descriptor became invalid"
            );
            return Ok(());
        }
        if result == 0 {
            ensure_before(deadline)?;
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("poll nonblocking vsock mux socket");
        }
    }
}

fn wait_before_retry(deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("vsock handshake deadline expired")?;
        let timeout = duration_to_poll_timeout(remaining.min(Duration::from_millis(5)));
        // SAFETY: a null descriptor array with zero entries is the portable
        // poll form of a signal-interruptible bounded wait.
        let result = unsafe { libc::poll(std::ptr::null_mut(), 0, timeout) };
        if result == 0 {
            return ensure_before(deadline);
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            ensure_before(deadline)?;
            continue;
        }
        anyhow::bail!("poll retry wait returned an invalid result");
    }
}

fn poll_timeout_before(deadline: Instant) -> Result<libc::c_int> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("vsock handshake deadline expired")?;
    Ok(duration_to_poll_timeout(remaining))
}

fn duration_to_poll_timeout(duration: Duration) -> libc::c_int {
    let milliseconds = duration.as_millis();
    let rounded = milliseconds.saturating_add(u128::from(
        !duration.subsec_nanos().is_multiple_of(1_000_000),
    ));
    i32::try_from(rounded.min(i32::MAX as u128)).unwrap_or(i32::MAX)
}

fn ensure_before(deadline: Instant) -> Result<()> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "vsock handshake deadline expired"
    );
    Ok(())
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
    use std::os::fd::AsRawFd as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;
    use std::time::{Duration, Instant};

    use cats_protocol::guest::{
        read_frame, read_guest_request_frame, write_frame, write_runtime_ready_response_frame,
        GuestRequest, GuestRequestBody, GuestResponse, GuestResponseBody, GuestWorkStatus,
        RuntimeReadyRequestV1, RuntimeReadyResponseV1, RUNTIME_READY_RESPONSE_MAX_FRAME_BYTES_V1,
    };
    use cats_protocol::runtime_reconciliation::{GuestBootId, RandomId128};

    #[cfg(target_os = "linux")]
    use super::connect_unix_before;
    use super::{
        classify_guest_exec_error, parse_hybrid_vsock_ack, GuestClient, GuestExecError,
        GuestShellStartError,
    };

    #[test]
    fn only_the_canonical_guest_exec_timeout_is_classified_as_timeout() {
        assert!(matches!(
            classify_guest_exec_error(anyhow::anyhow!(
                "guest error: exec timed out after 120000 ms"
            )),
            GuestExecError::Timeout { .. }
        ));
        assert!(matches!(
            classify_guest_exec_error(anyhow::anyhow!("guest error: exec caller disconnected")),
            GuestExecError::Cancelled { .. }
        ));
        for remote in [
            "guest error: exec timed out",
            "guest error: exec timed out after nope ms",
        ] {
            assert!(matches!(
                classify_guest_exec_error(anyhow::anyhow!(remote)),
                GuestExecError::RemoteError { .. }
            ));
        }
        assert!(matches!(
            classify_guest_exec_error(anyhow::anyhow!("exec timed out after 120000 ms")),
            GuestExecError::Other(_)
        ));
    }

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
            let request: GuestRequest = read_frame(&mut server).unwrap();
            assert_eq!(request.id, 1);
            assert!(matches!(request.body, GuestRequestBody::Health));
        });

        let timeout = Duration::from_secs(2);
        let mut client = GuestClient::connect_hybrid_vsock_bounded(&path, 5_000, timeout).unwrap();
        assert_eq!(client.hybrid_assigned_port(), Some(1_073_741_824));
        // SAFETY: the client owns a live descriptor and F_GETFL only reads its
        // integer status flags.
        let status = unsafe { libc::fcntl(client.stream.as_raw_fd(), libc::F_GETFL) };
        assert!(status >= 0);
        assert_eq!(status & libc::O_NONBLOCK, 0);
        assert_eq!(client.stream.read_timeout().unwrap(), Some(timeout));
        assert_eq!(client.stream.write_timeout().unwrap(), Some(timeout));
        assert_eq!(
            client.health().unwrap(),
            ("11111111111111111111111111111111".into(), Vec::new())
        );
        peer.join().unwrap();
    }

    #[test]
    fn exact_hybrid_shell_keeps_its_read_deadline_until_shell_ready() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shell-vsock.sock");
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
            let request: GuestRequest = read_frame(&mut server).unwrap();
            assert!(matches!(
                request.body,
                GuestRequestBody::Shell { rows: 24, cols: 80 }
            ));
            // ACK is not ShellReady. Retain the socket past the client's bound
            // to prove it cannot turn into an unbounded interactive wait early.
            thread::sleep(Duration::from_millis(200));
        });

        let timeout = Duration::from_millis(50);
        let started = Instant::now();
        #[cfg(target_os = "linux")]
        let client = GuestClient::connect_hybrid_vsock_shell_exact_peer(
            &path,
            5_000,
            timeout,
            std::process::id(),
        )
        .unwrap();
        #[cfg(not(target_os = "linux"))]
        let client = GuestClient::connect_hybrid_vsock_bounded(&path, 5_000, timeout).unwrap();
        let error = match client.start_shell(24, 80) {
            Ok(_) => panic!("ShellReady wait unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(started.elapsed() < Duration::from_millis(180));
        let error = format!("{error:#}");
        assert!(error.contains("timed out") || error.contains("temporarily unavailable"));
        peer.join().unwrap();
    }

    #[test]
    fn exact_hybrid_shell_uses_one_absolute_deadline_across_trickled_shell_ready() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trickled-shell-ready-vsock.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            use std::io::{BufRead, BufReader};

            let (mut server, _) = listener.accept().unwrap();
            let mut connect = String::new();
            BufReader::new(server.try_clone().unwrap())
                .read_line(&mut connect)
                .unwrap();
            assert_eq!(connect, "CONNECT 5000\n");
            thread::sleep(Duration::from_millis(20));
            server.write_all(b"OK 1073741824\n").unwrap();
            let request: GuestRequest = read_frame(&mut server).unwrap();
            assert!(matches!(request.body, GuestRequestBody::Shell { .. }));
            let response = GuestResponse {
                id: request.id,
                body: GuestResponseBody::ShellReady,
            };
            let mut frame = Vec::new();
            write_frame(&mut frame, &response).unwrap();
            for byte in frame {
                if server.write_all(&[byte]).is_err() {
                    break;
                }
                // Every syscall stays comfortably inside the original socket
                // timeout; only an absolute deadline rejects this peer.
                thread::sleep(Duration::from_millis(15));
            }
        });

        let timeout = Duration::from_millis(90);
        let started = Instant::now();
        #[cfg(target_os = "linux")]
        let client = GuestClient::connect_hybrid_vsock_shell_exact_peer(
            &path,
            5_000,
            timeout,
            std::process::id(),
        )
        .unwrap();
        #[cfg(not(target_os = "linux"))]
        let client = GuestClient::connect_hybrid_vsock_bounded(&path, 5_000, timeout).unwrap();
        assert!(client.start_shell(24, 80).is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
        peer.join().unwrap();
    }

    #[test]
    fn lifecycle_guest_request_uses_one_absolute_deadline_across_trickled_reads() {
        use std::io::Write as _;

        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let mut client = GuestClient {
            stream: client_stream,
            next_id: 1,
            hybrid_assigned_port: Some(1_073_741_824),
            hybrid_deadline: None,
        };
        let peer = thread::spawn(move || {
            let request: GuestRequest = read_frame(&mut server_stream).unwrap();
            assert!(matches!(request.body, GuestRequestBody::WorkStatus { .. }));
            let response = GuestResponse {
                id: request.id,
                body: GuestResponseBody::WorkStatus {
                    status: GuestWorkStatus {
                        source_epoch: "11111111111111111111111111111111".into(),
                        lease_sequence: 0,
                        quiescing: true,
                        leases: Vec::new(),
                    },
                },
            };
            let mut frame = Vec::new();
            write_frame(&mut frame, &response).unwrap();
            for byte in frame {
                thread::sleep(Duration::from_millis(20));
                if server_stream.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });

        let bound = Duration::from_millis(75);
        let started = Instant::now();
        let error = client
            .work_status_before(None, 0, started + bound)
            .expect_err("a trickled response must not extend the lifecycle deadline");
        let elapsed = started.elapsed();
        assert!(
            format!("{error:#}").contains("deadline-bounded Guest response"),
            "{error:#}"
        );
        assert!(
            elapsed >= Duration::from_millis(40) && elapsed < Duration::from_secs(1),
            "absolute Guest deadline returned after {elapsed:?}"
        );
        drop(client);
        peer.join().unwrap();
    }

    #[test]
    fn exact_exec_request_write_consumes_the_connect_admission_deadline() {
        let (client_stream, _blocked_peer) = UnixStream::pair().unwrap();
        let mut client = GuestClient {
            stream: client_stream,
            next_id: 1,
            hybrid_assigned_port: Some(1_073_741_824),
            hybrid_deadline: Some(Instant::now() + Duration::from_millis(50)),
        };
        let started = Instant::now();
        let error = client
            .exec_with_options(
                vec!["true".to_owned()],
                Some(100),
                Default::default(),
                vec![0x5a; cats_protocol::sessions::MAX_EXEC_STDIN_BYTES],
            )
            .expect_err("blocked request write must not refresh its deadline");
        assert!(started.elapsed() < Duration::from_millis(500));
        let error = format!("{error:#}");
        assert!(error.contains("deadline") || error.contains("timed out"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_hybrid_vsock_connect_rejects_another_unix_peer_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong-vmm-peer.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        let actual = std::process::id();
        let wrong = actual.checked_add(1).filter(|pid| *pid > 0).unwrap_or(1);
        assert_ne!(wrong, actual);
        let error = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            &path,
            5_000,
            Duration::from_secs(2),
            wrong,
        )
        .err()
        .expect("another Unix peer PID must be rejected");
        assert!(
            format!("{error:#}").contains("not the exact installed VMM"),
            "{error:#}"
        );
        peer.join().unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn exact_hybrid_vsock_connect_fails_closed_without_peer_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsupported-peer-credentials.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        let error = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            &path,
            5_000,
            Duration::from_secs(2),
            1,
        )
        .err()
        .expect("unsupported exact peer proof must fail closed");
        assert!(
            format!("{error:#}").contains("exact vsock mux peer credentials require Linux"),
            "{error:#}"
        );
        peer.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_hybrid_connect_expires_while_listener_backlog_is_saturated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // Linux permits updating the backlog of an existing listener. Keep it
        // tiny so saturation does not depend on the host's `somaxconn`.
        // SAFETY: listener owns a live AF_UNIX listening descriptor.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let peer = thread::spawn(move || {
            let accepted = listener.accept().unwrap().0;
            accepted_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(accepted);
            drop(listener);
        });

        let first =
            connect_unix_before(&path, Instant::now() + cats_test_support::poll_bound()).unwrap();
        accepted_rx.recv().unwrap();
        let mut fillers = vec![first];
        let mut saturated = false;
        // Never accepting eventually fills the platform listener queue. Every
        // filler uses the same bounded nonblocking primitive, so the first
        // deadline is a positive proof that the queue is saturated without a
        // setup thread that can itself hang.
        for _ in 0..16 {
            let deadline = Instant::now() + Duration::from_millis(100);
            match connect_unix_before(&path, deadline) {
                Ok(stream) => fillers.push(stream),
                Err(error) if format!("{error:#}").contains("vsock handshake deadline expired") => {
                    saturated = true;
                    break;
                }
                Err(error) => panic!("unexpected backlog filler error: {error:#}"),
            }
        }
        assert!(saturated, "listener backlog did not saturate");
        assert!(!fillers.is_empty());

        let timeout = Duration::from_millis(50);
        let started = Instant::now();
        let error = match GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            &path,
            5_000,
            timeout,
            std::process::id(),
        ) {
            Ok(_) => panic!("a full listener backlog must not connect"),
            Err(error) => error,
        };
        let elapsed = started.elapsed();
        let error = format!("{error:#}");
        assert!(error.contains("connect vsock mux"), "{error}");
        assert!(
            error.contains("vsock handshake deadline expired"),
            "{error}"
        );
        assert!(
            elapsed >= timeout && elapsed < Duration::from_secs(1),
            "bounded connect returned after {elapsed:?}"
        );

        drop(fillers);
        release_tx.send(()).unwrap();
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

    #[test]
    fn exact_guest_shell_error_is_a_terminal_start_result() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guest-shell-error.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            let request: GuestRequest = read_frame(&mut server).unwrap();
            write_frame(
                &mut server,
                &GuestResponse {
                    id: request.id,
                    body: GuestResponseBody::Error {
                        message: "shell is unavailable".to_owned(),
                    },
                },
            )
            .unwrap();
        });
        let client = GuestClient::connect_shell(&path).unwrap();
        let error = match client.start_shell(24, 80) {
            Ok(_) => panic!("Guest Error unexpectedly started a shell"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            GuestShellStartError::RemoteTerminal { message }
                if message == "shell is unavailable"
        ));
        peer.join().unwrap();
    }
}

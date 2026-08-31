use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use cats_api::guest::GuestResponseBody;
use cats_api::sessions::{ExecRequest, MAX_EXEC_OUTPUT_BYTES};

const IO_CHUNK_BYTES: usize = 16 * 1024;
const IO_CHANNEL_DEPTH: usize = 8;
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const EXIT_OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(1);
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

enum OutputEvent {
    Data(OutputStream, Vec<u8>),
    Closed(OutputStream),
    Error(OutputStream, std::io::Error),
}

#[derive(Clone, Copy)]
enum OutputStream {
    Stdout,
    Stderr,
}

/// Owns a spawned Exec process until every success postcondition is proven.
/// Any ordinary error or panic unwind before `disarm` kills the complete
/// process group and reaps the direct child before an exact Guest Error can be
/// written to Node.
struct ExecChildGuard {
    child: Child,
    process_group: u32,
    group_termination_attempted: bool,
    child_reaped: bool,
    disarmed: bool,
}

impl ExecChildGuard {
    fn new(child: Child) -> Self {
        let process_group = child.id();
        Self {
            child,
            process_group,
            group_termination_attempted: false,
            child_reaped: false,
            disarmed: false,
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.child_reaped = true;
        }
        Ok(status)
    }

    fn terminate_process_group_once(&mut self) {
        if self.group_termination_attempted {
            return;
        }
        // Record the attempt before the raw signal so even an unexpected
        // unwind can never target this numeric PGID a second time after it may
        // have been recycled.
        self.group_termination_attempted = true;
        kill_process_group(self.process_group, &mut self.child);
    }

    fn terminate_and_reap(&mut self) -> std::io::Result<ExitStatus> {
        self.terminate_process_group_once();
        let status = self.child.wait()?;
        self.child_reaped = true;
        // Cleanup is already complete. In particular, do not let Drop signal
        // the old numeric PGID again while workers are drained and joined.
        self.disarmed = true;
        Ok(status)
    }

    fn disarm(&mut self) {
        debug_assert!(self.child_reaped);
        self.disarmed = true;
    }
}

impl Deref for ExecChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl DerefMut for ExecChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for ExecChildGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let retry_direct_child_kill = self.group_termination_attempted;
        self.terminate_process_group_once();
        if !self.child_reaped {
            // If an earlier wait failed, retry only the owned direct Child.
            // Re-sending to the old raw PGID would risk killing an unrelated
            // task after PGID reuse.
            if retry_direct_child_kill {
                let _ = self.child.kill();
            }
            if self.child.wait().is_ok() {
                self.child_reaped = true;
            }
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static POST_SPAWN_ERROR_DELAY_MS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static PROCESS_GROUP_TERMINATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn inject_post_spawn_error_once(delay: Duration) {
    POST_SPAWN_ERROR_DELAY_MS.with(|slot| {
        slot.set(Some(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)));
    });
}

#[cfg(test)]
fn maybe_inject_post_spawn_error() -> Result<()> {
    if let Some(delay_ms) = POST_SPAWN_ERROR_DELAY_MS.with(std::cell::Cell::take) {
        thread::sleep(Duration::from_millis(delay_ms));
        anyhow::bail!("injected post-spawn Exec failure");
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn reset_process_group_termination_count() {
    PROCESS_GROUP_TERMINATION_COUNT.set(0);
}

#[cfg(test)]
pub(super) fn process_group_termination_count() -> usize {
    PROCESS_GROUP_TERMINATION_COUNT.get()
}

pub(super) fn execute(request: ExecRequest, peer_fd: Option<RawFd>) -> Result<GuestResponseBody> {
    request.validate().context("validate exec request")?;
    let timeout_ms = request.effective_timeout_ms();
    let timeout = Duration::from_millis(timeout_ms);
    let (argv0, rest) = request
        .command
        .split_first()
        .context("validated exec command unexpectedly had no argv[0]")?;

    let mut command = Command::new(argv0);
    command
        .args(rest)
        .envs(&request.env)
        .stdin(if request.stdin.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A separate process group lets every timeout, disconnect, and
        // output-bound failure stop descendants before the Guest reports a
        // terminal result.
        .process_group(0);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GuestResponseBody::Exec {
                exit_code: 127,
                stdout: String::new(),
                stderr: format!("{argv0}: command not found\n"),
            });
        }
        Err(error) => return Err(error).with_context(|| format!("spawn {argv0}")),
    };
    let mut child = ExecChildGuard::new(child);
    #[cfg(test)]
    maybe_inject_post_spawn_error()?;

    // Take every configured pipe before starting workers so an impossible
    // local invariant error still unwinds through the child cleanup guard
    // without leaving detached I/O threads.
    let stdin = child.stdin.take();
    let stdout_pipe = child.stdout.take().context("child stdout was not piped")?;
    let stderr_pipe = child.stderr.take().context("child stderr was not piped")?;
    if let Some(stdin) = stdin.as_ref() {
        set_nonblocking(stdin.as_raw_fd()).context("make child stdin nonblocking")?;
    }

    let stdin_cancel = Arc::new(AtomicBool::new(false));
    let stdin_thread = if let Some(stdin) = stdin {
        let input = request.stdin;
        let cancel = Arc::clone(&stdin_cancel);
        Some(thread::spawn(move || {
            write_stdin_cancellable(stdin, &input, &cancel)
        }))
    } else {
        None
    };
    let (output_tx, output_rx) = mpsc::sync_channel(IO_CHANNEL_DEPTH);
    let stdout_thread = spawn_reader(stdout_pipe, OutputStream::Stdout, output_tx.clone());
    let stderr_thread = spawn_reader(stderr_pipe, OutputStream::Stderr, output_tx);
    let deadline = Instant::now() + timeout;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut status = None;
    let mut failure = None;
    let mut post_exit_deadline = None;
    let mut termination_attempted = false;

    while stdout_open || stderr_open || (status.is_none() && !termination_attempted) {
        if failure.is_none() {
            if peer_fd.is_some_and(transport_disconnected) {
                failure = Some("exec caller disconnected".to_string());
            } else if Instant::now() >= deadline {
                failure = Some(format!("exec timed out after {timeout_ms} ms"));
            }
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(child_status) => {
                    status = child_status;
                    if status.is_some() {
                        post_exit_deadline = Some(Instant::now() + EXIT_OUTPUT_DRAIN_GRACE);
                    }
                }
                Err(error) => {
                    failure.get_or_insert_with(|| format!("wait for {argv0}: {error}"));
                }
            }
        }
        if failure.is_none()
            && post_exit_deadline.is_some_and(|drain_deadline| Instant::now() >= drain_deadline)
            && (stdout_open || stderr_open)
        {
            failure =
                Some("exec descendants kept output pipes open after command exit".to_string());
        }

        if failure.is_some() && !termination_attempted {
            termination_attempted = true;
            match child.terminate_and_reap() {
                Ok(child_status) => status = Some(child_status),
                Err(error) => {
                    let original = failure.take().unwrap_or_default();
                    failure = Some(format!("{original}; reap {argv0}: {error}"));
                }
            }
        }

        match output_rx.recv_timeout(WAIT_POLL_INTERVAL) {
            Ok(OutputEvent::Data(stream, data)) => {
                if failure.is_none()
                    && stdout
                        .len()
                        .saturating_add(stderr.len())
                        .saturating_add(data.len())
                        > MAX_EXEC_OUTPUT_BYTES
                {
                    failure = Some(format!(
                        "exec stdout and stderr exceed the combined {} byte limit",
                        MAX_EXEC_OUTPUT_BYTES
                    ));
                } else if failure.is_none() {
                    match stream {
                        OutputStream::Stdout => stdout.extend_from_slice(&data),
                        OutputStream::Stderr => stderr.extend_from_slice(&data),
                    }
                }
            }
            Ok(OutputEvent::Closed(OutputStream::Stdout)) => stdout_open = false,
            Ok(OutputEvent::Closed(OutputStream::Stderr)) => stderr_open = false,
            Ok(OutputEvent::Error(stream, error)) => {
                failure.get_or_insert_with(|| format!("read child {}: {error}", stream.name()));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stdout_open = false;
                stderr_open = false;
            }
        }
    }

    stdin_cancel.store(true, Ordering::Release);
    drop(output_rx);
    // Attempt every join before interpreting any result so one failed worker
    // cannot skip cancellation/join of its siblings.
    let stdin_result = stdin_thread.map(|thread| join_worker(thread, "stdin writer"));
    let stdout_result = join_worker(stdout_thread, "stdout reader");
    let stderr_result = join_worker(stderr_thread, "stderr reader");
    if let Some(stdin_result) = stdin_result {
        match stdin_result? {
            Ok(()) => {}
            // A command may validly close stdin without consuming every byte.
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => return Err(error).with_context(|| format!("write stdin for {argv0}")),
        }
    }
    stdout_result?;
    stderr_result?;
    if let Some(message) = failure {
        anyhow::bail!(message);
    }

    let status = status.context("exec exited without a wait status")?;
    let response = cats_api::sessions::ExecResponse {
        exit_code: exit_code(status),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    };
    response.validate().context("validate exec response")?;
    let response = GuestResponseBody::Exec {
        exit_code: response.exit_code,
        stdout: response.stdout,
        stderr: response.stderr,
    };
    child.disarm();
    Ok(response)
}

fn write_stdin_cancellable(
    mut stdin: impl Write,
    input: &[u8],
    cancel: &AtomicBool,
) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < input.len() {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        match stdin.write(&input[written..]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(WAIT_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn spawn_reader(
    mut reader: impl Read + Send + 'static,
    stream: OutputStream,
    sender: SyncSender<OutputEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0u8; IO_CHUNK_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(OutputEvent::Closed(stream));
                    return;
                }
                Ok(count) => {
                    if sender
                        .send(OutputEvent::Data(stream, buffer[..count].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let _ = sender.send(OutputEvent::Error(stream, error));
                    return;
                }
            }
        }
    })
}

impl OutputStream {
    fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `fd` is a live descriptor owned by the caller. F_GETFL and
    // F_SETFL neither retain the descriptor nor access Rust memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same live descriptor; the existing flags are preserved and only
    // O_NONBLOCK is added.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn join_worker<T>(handle: thread::JoinHandle<T>, label: &str) -> Result<T> {
    let deadline = Instant::now() + WORKER_JOIN_TIMEOUT;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            anyhow::bail!("{label} did not stop within one second");
        }
        thread::sleep(WAIT_POLL_INTERVAL);
    }
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("{label} thread panicked"))
}

fn kill_process_group(process_group: u32, child: &mut Child) {
    #[cfg(test)]
    PROCESS_GROUP_TERMINATION_COUNT.set(PROCESS_GROUP_TERMINATION_COUNT.get().saturating_add(1));
    if let Ok(process_group) = i32::try_from(process_group) {
        // SAFETY: negative PID addresses the process group created explicitly
        // for this exec. SIGKILL has no borrowed memory or Rust aliasing rules.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

fn transport_disconnected(fd: RawFd) -> bool {
    let mut poll_fd = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    // SAFETY: `poll_fd` is one initialized element and remains live and
    // writable for this non-blocking poll call. HUP/ERR/NVAL are reported even
    // when not requested, including when unread pipelined bytes precede EOF.
    let poll_result = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    if poll_result > 0 && poll_fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return true;
    }

    let mut byte = 0u8;
    // SAFETY: `fd` is the live accepted control socket for the duration of
    // request handling, and `byte` provides one writable byte. Exec is a
    // strictly sequential exchange, so readable protocol data before its
    // response is either an invalid pipeline or precedes EOF. MSG_PEEK detects
    // it without consuming bytes; either case cancels the live command.
    let result = unsafe {
        libc::recv(
            fd,
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result == 0 {
        return true;
    }
    if result > 0 {
        return true;
    }
    !matches!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

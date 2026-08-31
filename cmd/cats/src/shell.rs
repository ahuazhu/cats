//! Interactive PTY client for `cats shell`.

use std::io::{IsTerminal, Read};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use cats_api::sessions::{ShellClientControl, ShellServerControl, MAX_SHELL_MESSAGE_BYTES};

/// Restores the caller's terminal on every normal and error return after raw
/// mode has been enabled. The interactive loop catches the Unix terminating
/// signals it can handle and returns through this guard; SIGKILL cannot be
/// caught by any process and therefore cannot run cleanup.
struct RawModeGuard {
    enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellExit {
    Remote(i32),
    Interrupted {
        signal: &'static str,
        process_exit_code: i32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminationSignal {
    Hangup,
    Interrupt,
    Quit,
    Terminate,
}

impl TerminationSignal {
    fn name(self) -> &'static str {
        match self {
            Self::Hangup => "SIGHUP",
            Self::Interrupt => "SIGINT",
            Self::Quit => "SIGQUIT",
            Self::Terminate => "SIGTERM",
        }
    }

    fn process_exit_code(self) -> i32 {
        match self {
            Self::Hangup => 129,
            Self::Interrupt => 130,
            Self::Quit => 131,
            Self::Terminate => 143,
        }
    }
}

enum StdinEvent {
    Data(Vec<u8>),
    Eof,
    Error(std::io::Error),
}

#[cfg(any(test, not(unix)))]
fn spawn_stdin_reader<R>(mut reader: R) -> tokio::sync::mpsc::Receiver<StdinEvent>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = tokio::sync::mpsc::channel(32);
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let event = match reader.read(&mut buffer) {
                Ok(0) => StdinEvent::Eof,
                Ok(count) => StdinEvent::Data(buffer[..count].to_vec()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => StdinEvent::Error(error),
            };
            let terminal = matches!(event, StdinEvent::Eof | StdinEvent::Error(_));
            if sender.blocking_send(event).is_err() || terminal {
                return;
            }
        }
    });
    receiver
}

struct TerminalStdin {
    receiver: tokio::sync::mpsc::Receiver<StdinEvent>,
    #[cfg(unix)]
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(unix)]
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TerminalStdin {
    async fn recv(&mut self) -> Option<StdinEvent> {
        self.receiver.recv().await
    }
}

#[cfg(unix)]
fn spawn_terminal_stdin_reader() -> TerminalStdin {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let (sender, receiver) = tokio::sync::mpsc::channel(32);
    let cancelled = Arc::new(AtomicBool::new(false));
    let thread_cancelled = Arc::clone(&cancelled);
    let thread = std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buffer = vec![0u8; 16 * 1024];
        while !thread_cancelled.load(Ordering::Acquire) {
            let mut descriptor = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // A short poll makes the otherwise blocking terminal reader
            // cancellable when the remote exits or a Unix signal is handled.
            // SAFETY: descriptor points to one initialized pollfd for the
            // duration of the call; the timeout is finite.
            let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = sender.blocking_send(StdinEvent::Error(error));
                return;
            }
            if thread_cancelled.load(Ordering::Acquire) {
                return;
            }
            let event = match stdin.read(&mut buffer) {
                Ok(0) => StdinEvent::Eof,
                Ok(count) => StdinEvent::Data(buffer[..count].to_vec()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => StdinEvent::Error(error),
            };
            let terminal = matches!(event, StdinEvent::Eof | StdinEvent::Error(_));
            if sender.blocking_send(event).is_err() || terminal {
                return;
            }
        }
    });
    TerminalStdin {
        receiver,
        cancelled,
        thread: Some(thread),
    }
}

#[cfg(not(unix))]
fn spawn_terminal_stdin_reader() -> TerminalStdin {
    TerminalStdin {
        receiver: spawn_stdin_reader(std::io::stdin()),
    }
}

impl Drop for TerminalStdin {
    fn drop(&mut self) {
        // Wake a producer blocked on the bounded channel before joining it.
        // Otherwise a piped input that filled all 32 slots could deadlock
        // cleanup after the remote exit arrived first.
        self.receiver.close();
        #[cfg(unix)]
        {
            use std::sync::atomic::Ordering;

            self.cancelled.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

impl RawModeGuard {
    fn enable_if_terminal() -> Result<Self> {
        let enabled = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        if enabled {
            enable_raw_mode().context("enable terminal raw mode")?;
        }
        Ok(Self { enabled })
    }

    fn restore(&mut self) -> Result<()> {
        if self.enabled {
            disable_raw_mode().context("restore terminal mode")?;
            self.enabled = false;
        }
        Ok(())
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.enabled {
            let _ = disable_raw_mode();
        }
    }
}

fn terminal_size() -> (u16, u16) {
    size()
        .map(|(cols, rows)| (rows.clamp(1, 1_000), cols.clamp(1, 1_000)))
        .unwrap_or((24, 80))
}

fn websocket_config() -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_SHELL_MESSAGE_BYTES);
    config.max_frame_size = Some(MAX_SHELL_MESSAGE_BYTES);
    config
}

const WEBSOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(5);

enum SignalRace<T> {
    Completed(T),
    Signal(TerminationSignal),
}

async fn race_with_signal<S, F, T>(mut signal: std::pin::Pin<&mut S>, operation: F) -> SignalRace<T>
where
    S: std::future::Future<Output = TerminationSignal> + ?Sized,
    F: std::future::Future<Output = T>,
{
    tokio::select! {
        signal = signal.as_mut() => SignalRace::Signal(signal),
        completed = operation => SignalRace::Completed(completed),
    }
}

async fn send_websocket_with_signal<S, W>(
    signal: std::pin::Pin<&mut S>,
    sender: &mut W,
    message: Message,
) -> Result<Option<TerminationSignal>>
where
    S: std::future::Future<Output = TerminationSignal> + ?Sized,
    W: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    match race_with_signal(
        signal,
        tokio::time::timeout(WEBSOCKET_SEND_TIMEOUT, sender.send(message)),
    )
    .await
    {
        SignalRace::Signal(signal) => Ok(Some(signal)),
        SignalRace::Completed(Ok(result)) => {
            result.context("write shell WebSocket")?;
            Ok(None)
        }
        SignalRace::Completed(Err(_)) => {
            bail!(
                "shell WebSocket send timed out after {}s",
                WEBSOCKET_SEND_TIMEOUT.as_secs()
            )
        }
    }
}

async fn output_io_with_signal<S, F>(
    signal: std::pin::Pin<&mut S>,
    operation: F,
    action: &'static str,
) -> Result<Option<TerminationSignal>>
where
    S: std::future::Future<Output = TerminationSignal> + ?Sized,
    F: std::future::Future<Output = std::io::Result<()>>,
{
    match race_with_signal(signal, operation).await {
        SignalRace::Signal(signal) => Ok(Some(signal)),
        SignalRace::Completed(result) => {
            result.context(action)?;
            Ok(None)
        }
    }
}

enum SessionEnd {
    Remote(i32),
    Signal(TerminationSignal),
}

#[cfg(unix)]
fn termination_signal() -> std::io::Result<impl std::future::Future<Output = TerminationSignal>> {
    use tokio::signal::unix::{signal, SignalKind};

    // Construct every listener before raw mode is enabled. The returned future
    // is then pinned once and kept across every loop iteration, so polling the
    // select cannot repeatedly register or lose a signal handler.
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut quit = signal(SignalKind::quit())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = hangup.recv() => TerminationSignal::Hangup,
            _ = interrupt.recv() => TerminationSignal::Interrupt,
            _ = quit.recv() => TerminationSignal::Quit,
            _ = terminate.recv() => TerminationSignal::Terminate,
        }
    })
}

#[cfg(not(unix))]
fn termination_signal() -> std::io::Result<impl std::future::Future<Output = TerminationSignal>> {
    Ok(std::future::pending())
}

pub(crate) fn run(base: &str, workspace_id: &str, token: &str, cat: &str) -> Result<ShellExit> {
    let runtime = tokio::runtime::Runtime::new().context("start shell runtime")?;
    runtime.block_on(run_async(base, workspace_id, token, cat))
}

async fn run_async(base: &str, workspace_id: &str, token: &str, cat: &str) -> Result<ShellExit> {
    let (rows, cols) = terminal_size();
    let mut url = reqwest::Url::parse(base).context("invalid control plane URL")?;
    url.set_scheme(match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => bail!("unsupported control plane URL scheme {other}"),
    })
    .map_err(|_| anyhow::anyhow!("invalid WebSocket URL"))?;
    url.set_path(&format!("/v1/workspaces/{workspace_id}/cats/{cat}/shell"));
    url.set_query(Some(&format!("rows={rows}&cols={cols}")));
    let mut request = url
        .as_str()
        .into_client_request()
        .context("build shell WebSocket request")?;
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid authorization header")?,
    );

    // Tungstenite's error display omits a rejected upgrade's response body.
    // That body carries the actionable admission reason, so preserve it.
    let (socket, _) = match tokio_tungstenite::connect_async_with_config(
        request,
        Some(websocket_config()),
        false,
    )
    .await
    {
        Ok(connected) => connected,
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            let status = response.status();
            let body = response
                .into_body()
                .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
                .unwrap_or_default();
            if body.is_empty() {
                bail!("connect interactive shell: HTTP {status}");
            }
            bail!("connect interactive shell: HTTP {status}: {body}");
        }
        Err(error) => return Err(error).context("connect interactive shell"),
    };

    let termination_signal = termination_signal().context("install terminal signal handlers")?;
    tokio::pin!(termination_signal);
    let mut raw_mode = RawModeGuard::enable_if_terminal()?;
    let (mut sender, mut receiver) = socket.split();
    // Tokio stdin is backed by an uncancellable blocking read. Unix uses a
    // short-poll OS thread that Drop can cancel and join; non-Unix keeps the
    // historical detached-reader fallback.
    let mut stdin = spawn_terminal_stdin_reader();
    let mut stdout = tokio::io::stdout();
    let mut stdin_open = true;
    let mut known_size = (rows, cols);
    let mut resize_poll = tokio::time::interval(Duration::from_millis(250));
    resize_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keepalive = tokio::time::interval(Duration::from_secs(20));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    resize_poll.tick().await;
    keepalive.tick().await;

    let end = 'session: loop {
        tokio::select! {
            signal = &mut termination_signal => {
                break 'session SessionEnd::Signal(signal);
            }
            read = stdin.recv(), if stdin_open => {
                match read.unwrap_or(StdinEvent::Eof) {
                    StdinEvent::Data(data) => {
                        if let Some(signal) = send_websocket_with_signal(
                            termination_signal.as_mut(),
                            &mut sender,
                            Message::Binary(data.into()),
                        ).await? {
                            break 'session SessionEnd::Signal(signal);
                        }
                    }
                    StdinEvent::Eof => {
                        // A pipe has no terminal driver to turn EOF into ^D.
                        // Deliver it to the PTY without closing the WebSocket,
                        // then drain output through the exact exit frame.
                        if let Some(signal) = send_websocket_with_signal(
                            termination_signal.as_mut(),
                            &mut sender,
                            Message::Binary(vec![0x04].into()),
                        ).await? {
                            break 'session SessionEnd::Signal(signal);
                        }
                        stdin_open = false;
                    }
                    StdinEvent::Error(error) => {
                        return Err(error).context("read terminal input");
                    }
                }
            }
            incoming = receiver.next() => {
                let Some(message) = incoming else {
                    bail!("interactive shell disconnected before reporting an exit status");
                };
                match message.context("read shell WebSocket")? {
                    Message::Binary(data) => {
                        if let Some(signal) = output_io_with_signal(
                            termination_signal.as_mut(),
                            stdout.write_all(&data),
                            "write shell output",
                        ).await? {
                            break 'session SessionEnd::Signal(signal);
                        }
                        if let Some(signal) = output_io_with_signal(
                            termination_signal.as_mut(),
                            stdout.flush(),
                            "flush shell output",
                        ).await? {
                            break 'session SessionEnd::Signal(signal);
                        }
                    }
                    Message::Text(text) => {
                        match serde_json::from_str::<ShellServerControl>(text.as_str())
                            .context("invalid shell control response")?
                        {
                            ShellServerControl::Exit { exit_code } => {
                                if let Some(signal) = output_io_with_signal(
                                    termination_signal.as_mut(),
                                    stdout.flush(),
                                    "flush shell output",
                                ).await? {
                                    break 'session SessionEnd::Signal(signal);
                                }
                                break 'session SessionEnd::Remote(exit_code);
                            }
                            ShellServerControl::Error { message } => bail!("{message}"),
                        }
                    }
                    Message::Ping(data) => {
                        if let Some(signal) = send_websocket_with_signal(
                            termination_signal.as_mut(),
                            &mut sender,
                            Message::Pong(data),
                        ).await? {
                            break 'session SessionEnd::Signal(signal);
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => {
                        bail!("interactive shell closed before reporting an exit status")
                    }
                    Message::Frame(_) => {}
                }
            }
            _ = resize_poll.tick() => {
                let next = terminal_size();
                if next != known_size {
                    known_size = next;
                    let control = ShellClientControl::Resize {
                        rows: next.0,
                        cols: next.1,
                    };
                    if let Some(signal) = send_websocket_with_signal(
                        termination_signal.as_mut(),
                        &mut sender,
                        Message::Text(serde_json::to_string(&control)?.into()),
                    ).await? {
                        break 'session SessionEnd::Signal(signal);
                    }
                }
            }
            _ = keepalive.tick() => {
                if let Some(signal) = send_websocket_with_signal(
                    termination_signal.as_mut(),
                    &mut sender,
                    Message::Ping(Vec::new().into()),
                ).await? {
                    break 'session SessionEnd::Signal(signal);
                }
            }
        }
    };

    match end {
        SessionEnd::Remote(exit_code) => Ok(ShellExit::Remote(exit_code)),
        SessionEnd::Signal(signal) => {
            // Restore explicitly instead of relying only on Drop so a
            // restoration failure is reported while the process is alive.
            raw_mode
                .restore()
                .with_context(|| format!("restore terminal after {}", signal.name()))?;
            Ok(ShellExit::Interrupted {
                signal: signal.name(),
                process_exit_code: signal.process_exit_code(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::task::{Context as TaskContext, Poll};
    use std::time::{Duration, Instant};

    use futures_util::{Sink, SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message;

    use super::{
        run_async, send_websocket_with_signal, spawn_stdin_reader, websocket_config, StdinEvent,
        TerminationSignal,
    };
    use cats_api::sessions::MAX_SHELL_MESSAGE_BYTES;

    #[tokio::test]
    async fn detached_stdin_reader_reports_data_then_eof() {
        let mut events = spawn_stdin_reader(Cursor::new(b"exit\n".to_vec()));
        match events.recv().await.unwrap() {
            StdinEvent::Data(data) => assert_eq!(data, b"exit\n"),
            _ => panic!("expected stdin data"),
        }
        assert!(matches!(events.recv().await.unwrap(), StdinEvent::Eof));
    }

    #[tokio::test]
    async fn rejected_upgrade_surfaces_the_control_body() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(cats_test_support::poll_bound()))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                assert_eq!(stream.read(&mut byte).unwrap(), 1);
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("GET /v1/workspaces/ws_01/cats/dev/shell?rows="),
                "unexpected shell path: {request}"
            );
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("authorization: Bearer token-a")),
                "workspace authorization was absent: {request}"
            );
            let body = b"cat is not running";
            write!(
                stream,
                "HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
            stream.flush().unwrap();
        });

        let error = run_async(&format!("http://{address}"), "ws_01", "token-a", "dev")
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("HTTP 409 Conflict: cat is not running"),
            "upgrade reason was lost: {error:#}"
        );
        server.join().unwrap();
    }

    async fn receive_sized_shell_message(
        message_bytes: usize,
    ) -> Result<Message, tokio_tungstenite::tungstenite::Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket
                .send(Message::Binary(vec![0_u8; message_bytes].into()))
                .await
                .unwrap();
        });
        let (mut client, _) = tokio_tungstenite::connect_async_with_config(
            format!("ws://{address}"),
            Some(websocket_config()),
            false,
        )
        .await
        .unwrap();
        let received = client
            .next()
            .await
            .expect("server closed before its test frame");
        server.await.unwrap();
        received
    }

    #[tokio::test]
    async fn shell_receive_accepts_exactly_the_64k_contract_bound() {
        let message = receive_sized_shell_message(MAX_SHELL_MESSAGE_BYTES)
            .await
            .unwrap();
        assert!(matches!(
            message,
            Message::Binary(bytes) if bytes.len() == MAX_SHELL_MESSAGE_BYTES
        ));
    }

    #[tokio::test]
    async fn shell_receive_rejects_one_byte_over_the_64k_contract_bound() {
        let error = receive_sized_shell_message(MAX_SHELL_MESSAGE_BYTES + 1)
            .await
            .unwrap_err();
        assert!(
            matches!(error, tokio_tungstenite::tungstenite::Error::Capacity(_)),
            "oversized shell frame failed for the wrong reason: {error}"
        );
    }

    struct StalledWebSocketSink;

    impl Sink<Message> for StalledWebSocketSink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            unreachable!("a permanently stalled sink never becomes ready")
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn persistent_signal_preempts_a_stalled_websocket_send() {
        let (signal_sender, signal_receiver) = tokio::sync::oneshot::channel();
        let signal = async move {
            signal_receiver.await.unwrap();
            TerminationSignal::Terminate
        };
        tokio::pin!(signal);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            signal_sender.send(()).unwrap();
        });
        let before = Instant::now();
        let interrupted = send_websocket_with_signal(
            signal.as_mut(),
            &mut StalledWebSocketSink,
            Message::Ping(Vec::new().into()),
        )
        .await
        .unwrap();
        assert_eq!(interrupted, Some(TerminationSignal::Terminate));
        assert!(
            before.elapsed() < Duration::from_secs(1),
            "signal waited for the 5s WebSocket timeout"
        );
    }

    #[test]
    fn handled_unix_signals_use_conventional_process_exit_codes() {
        for (signal, name, code) in [
            (TerminationSignal::Hangup, "SIGHUP", 129),
            (TerminationSignal::Interrupt, "SIGINT", 130),
            (TerminationSignal::Quit, "SIGQUIT", 131),
            (TerminationSignal::Terminate, "SIGTERM", 143),
        ] {
            assert_eq!(signal.name(), name);
            assert_eq!(signal.process_exit_code(), code);
        }
    }

    struct BlockingReader {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    impl Read for BlockingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            let _ = self.started.send(());
            let _ = self.release.recv();
            Ok(0)
        }
    }

    #[test]
    fn pending_terminal_read_does_not_block_runtime_drop() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let input = spawn_stdin_reader(BlockingReader {
            started: started_tx,
            release: release_rx,
        });
        started_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap();
        drop(input);

        let before = Instant::now();
        drop(runtime);
        assert!(before.elapsed() < Duration::from_secs(1));
        drop(release_tx);
    }

    #[cfg(unix)]
    #[test]
    fn terminal_stdin_drop_unblocks_a_full_input_channel() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let (blocked_tx, blocked_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            sender.blocking_send(StdinEvent::Data(vec![1])).unwrap();
            blocked_tx.send(()).unwrap();
            // This send remains blocked until TerminalStdin::drop closes its
            // receiver, which is the cleanup race under a large pipe.
            let _ = sender.blocking_send(StdinEvent::Data(vec![2]));
        });
        blocked_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap();
        let input = super::TerminalStdin {
            receiver,
            cancelled: Arc::new(AtomicBool::new(false)),
            thread: Some(thread),
        };
        let before = Instant::now();
        drop(input);
        assert!(before.elapsed() < Duration::from_secs(1));
    }
}

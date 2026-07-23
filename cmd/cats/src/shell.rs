//! Interactive PTY client for `cats shell`.

use std::io::{IsTerminal, Read};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header, HeaderValue};
use tokio_tungstenite::tungstenite::Message;

use cats_api::requests::{ShellClientControl, ShellServerControl};

struct RawModeGuard {
    enabled: bool,
}

enum StdinEvent {
    Data(Vec<u8>),
    Eof,
    Error(std::io::Error),
}

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

impl RawModeGuard {
    fn enable_if_terminal() -> Result<Self> {
        let enabled = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        if enabled {
            enable_raw_mode().context("enable terminal raw mode")?;
        }
        Ok(Self { enabled })
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

pub fn run(base: &str, project: &str, token: &str, cat: &str) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("start shell runtime")?;
    let exit_code = runtime.block_on(run_async(base, project, token, cat))?;
    if exit_code != 0 {
        bail!("remote shell exited with {exit_code}");
    }
    Ok(())
}

async fn run_async(base: &str, project: &str, token: &str, cat: &str) -> Result<i32> {
    let (rows, cols) = terminal_size();
    let mut url = reqwest::Url::parse(base).context("invalid control plane URL")?;
    url.set_scheme(match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => bail!("unsupported control plane URL scheme {other}"),
    })
    .map_err(|_| anyhow::anyhow!("invalid WebSocket URL"))?;
    url.set_path(&format!("/v1/projects/{project}/cats/{cat}/shell"));
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
    let (socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .context("connect interactive shell")?;
    let _raw_mode = RawModeGuard::enable_if_terminal()?;
    let (mut sender, mut receiver) = socket.split();
    // Tokio's stdin uses a blocking-pool read that cannot be cancelled. In an
    // interactive terminal it keeps Runtime::drop waiting after the remote
    // shell has already exited. A detached OS thread lets the WebSocket exit
    // frame end the process immediately; process teardown closes the pending
    // terminal read.
    let mut stdin = spawn_stdin_reader(std::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut stdin_open = true;
    let mut known_size = (rows, cols);
    let mut resize_poll = tokio::time::interval(Duration::from_millis(250));
    resize_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keepalive = tokio::time::interval(Duration::from_secs(20));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    resize_poll.tick().await;
    keepalive.tick().await;

    loop {
        tokio::select! {
            read = stdin.recv(), if stdin_open => {
                match read.unwrap_or(StdinEvent::Eof) {
                    StdinEvent::Data(data) => {
                        sender.send(Message::Binary(data.into())).await?;
                    }
                    StdinEvent::Eof => {
                    // Deliver terminal EOF instead of closing the transport so
                    // a piped `printf '...\nexit\n' | cats shell` drains output.
                        sender.send(Message::Binary(vec![0x04].into())).await?;
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
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Message::Text(text) => {
                        match serde_json::from_str::<ShellServerControl>(text.as_str())
                            .context("invalid shell control response")?
                        {
                            ShellServerControl::Exit { exit_code } => {
                                stdout.flush().await?;
                                return Ok(exit_code);
                            }
                            ShellServerControl::Error { message } => bail!("{message}"),
                        }
                    }
                    Message::Ping(data) => sender.send(Message::Pong(data)).await?,
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
                    sender.send(Message::Text(serde_json::to_string(&control)?.into())).await?;
                }
            }
            _ = keepalive.tick() => {
                sender.send(Message::Ping(Vec::new().into())).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::{spawn_stdin_reader, StdinEvent};

    #[tokio::test]
    async fn detached_stdin_reader_reports_data_then_eof() {
        let mut events = spawn_stdin_reader(Cursor::new(b"exit\n".to_vec()));
        match events.recv().await.unwrap() {
            StdinEvent::Data(data) => assert_eq!(data, b"exit\n"),
            _ => panic!("expected stdin data"),
        }
        assert!(matches!(events.recv().await.unwrap(), StdinEvent::Eof));
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
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(input);

        let before = Instant::now();
        drop(runtime);
        assert!(before.elapsed() < Duration::from_secs(1));
        drop(release_tx);
    }
}

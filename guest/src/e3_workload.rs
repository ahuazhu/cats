//! Small qualification-only workload copied into a real Guest by the E3
//! operator probe. It deliberately has no Cats credential or platform API.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clap::Parser;

const REQUEST_HEAD_MAX: usize = 16 * 1024;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    port: u16,
    #[arg(long)]
    nonce: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    anyhow::ensure!(args.port > 0, "--port must be non-zero");
    anyhow::ensure!(
        !args.nonce.is_empty()
            && args.nonce.len() <= 64
            && args.nonce.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            }),
        "--nonce is not canonical"
    );
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.port))
        .context("bind E3 Guest workload")?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let _ = serve(stream, &args.nonce);
    }
    Ok(())
}

fn serve(mut stream: TcpStream, nonce: &str) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut peek = vec![0_u8; REQUEST_HEAD_MAX + 1];
    let deadline = Instant::now() + Duration::from_secs(5);
    let (count, head_end) = loop {
        let count = stream.peek(&mut peek)?;
        anyhow::ensure!(count <= REQUEST_HEAD_MAX, "request head is oversized");
        if let Some(offset) = peek[..count]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break (count, offset);
        }
        anyhow::ensure!(Instant::now() < deadline, "request head is incomplete");
        std::thread::sleep(Duration::from_millis(10));
    };
    let head = std::str::from_utf8(&peek[..count]).context("request head is not UTF-8")?;
    let bounded_head = &head[..head_end + 4];
    let expected_http_path = format!("/e3/{nonce}");
    let expected_ws_path = format!("/e3/{nonce}/ws");
    let request_line = bounded_head
        .lines()
        .next()
        .context("request line is absent")?
        .trim_end_matches('\r');
    anyhow::ensure!(
        !bounded_head.lines().skip(1).any(|line| {
            let line = line.trim_end_matches('\r');
            line.to_ascii_lowercase().starts_with("content-length:")
                || line.eq_ignore_ascii_case("transfer-encoding: chunked")
        }),
        "qualification GET request must not carry a body"
    );
    let websocket = bounded_head.lines().any(|line| {
        line.trim_end_matches('\r')
            .eq_ignore_ascii_case("upgrade: websocket")
    });
    if websocket {
        anyhow::ensure!(
            request_line == format!("GET {expected_ws_path} HTTP/1.1"),
            "unexpected WebSocket target"
        );
        stream.set_read_timeout(None)?;
        let mut websocket = tungstenite::accept(stream).context("accept WebSocket upgrade")?;
        while let Ok(message) = websocket.read() {
            if message.is_close() {
                let _ = websocket.close(None);
                break;
            }
            if message.is_text() || message.is_binary() {
                websocket.send(message)?;
            }
        }
        return Ok(());
    }
    anyhow::ensure!(
        request_line == format!("GET {expected_http_path} HTTP/1.1"),
        "unexpected HTTP target"
    );
    let mut consumed = vec![0_u8; head_end + 4];
    stream.read_exact(&mut consumed)?;
    let body = format!("cats-e3-http:{nonce}\n");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()?;
    Ok(())
}

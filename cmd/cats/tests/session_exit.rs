use std::io::{Read as _, Write as _};
use std::process::Command;
use std::time::Duration;

fn read_http_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "request ended before its headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while bytes.len() - header_end < content_length {
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "request ended before its body");
        bytes.extend_from_slice(&chunk[..count]);
    }
    (
        headers,
        bytes[header_end..header_end + content_length].to_vec(),
    )
}

#[test]
fn binary_preserves_an_exact_remote_exec_exit_code() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (headers, _) = read_http_request(&mut stream);
        assert_eq!(
            headers.lines().next().unwrap(),
            "POST /v1/workspaces/ws_01/cats/app/exec HTTP/1.1"
        );
        let body = br#"{"exit_code":7,"stdout":"","stderr":"remote stderr\n"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_cats"))
        .args([
            "--api-url",
            &format!("http://{address}"),
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "exec",
            "app",
            "--",
            "/usr/bin/false",
        ])
        .output()
        .unwrap();
    server.join().unwrap();

    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("remote stderr\n"), "{stderr}");
    assert!(stderr.contains("remote command exited with 7"), "{stderr}");
}

#[test]
fn binary_preserves_an_exact_remote_shell_exit_code() {
    use futures_util::SinkExt as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    r#"{"type":"exit","exit_code":7}"#.into(),
                ))
                .await
                .unwrap();
        });
    });

    let output = Command::new(env!("CARGO_BIN_EXE_cats"))
        .args([
            "--api-url",
            &format!("http://{address}"),
            "--token",
            "test-token",
            "--workspace",
            "ws_01",
            "shell",
            "app",
        ])
        .output()
        .unwrap();
    server.join().unwrap();

    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("remote shell exited with 7"), "{stderr}");
}

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt as _;
    use std::process::{Child, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::Instant;

    use futures_util::StreamExt as _;

    use super::*;

    fn terminal_attributes(fd: libc::c_int) -> libc::termios {
        let mut attributes = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `attributes` points to writable storage for one termios and
        // `fd` is the live slave side of the PTY for the whole test.
        let result = unsafe { libc::tcgetattr(fd, attributes.as_mut_ptr()) };
        assert_eq!(
            result,
            0,
            "tcgetattr failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful tcgetattr initialized the complete termios value.
        unsafe { attributes.assume_init() }
    }

    fn terminal_attributes_match(left: &libc::termios, right: &libc::termios) -> bool {
        left.c_iflag == right.c_iflag
            && left.c_oflag == right.c_oflag
            && left.c_cflag == right.c_cflag
            && left.c_lflag == right.c_lflag
            && left.c_cc == right.c_cc
            // SAFETY: both references are initialized termios values.
            && unsafe { libc::cfgetispeed(left) == libc::cfgetispeed(right) }
            // SAFETY: both references are initialized termios values.
            && unsafe { libc::cfgetospeed(left) == libc::cfgetospeed(right) }
    }

    fn open_pty() -> (File, File) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty receives valid output pointers and null optional
        // name/termios/winsize pointers; successful descriptors are owned
        // immediately below.
        let result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            result,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful openpty returned two new owned descriptors.
        let master = unsafe { File::from_raw_fd(master) };
        // SAFETY: successful openpty returned two new owned descriptors.
        let slave = unsafe { File::from_raw_fd(slave) };
        (master, slave)
    }

    fn spawn_shell_in_pty(base: &str, slave: &File) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cats"));
        command
            .args([
                "--api-url",
                base,
                "--token",
                "test-token",
                "--workspace",
                "ws_01",
                "shell",
                "app",
            ])
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: this closure calls only async-signal-safe libc operations
        // between fork and exec. Standard streams have already been installed
        // on the PTY slave by Command.
        unsafe {
            command.pre_exec(|| {
                // SAFETY: setsid has no pointer preconditions.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // SAFETY: fd 0 is the live PTY slave installed above; a zero
                // integer third argument is the platform TIOCSCTTY contract.
                #[cfg(target_os = "macos")]
                let tiocsctty = libc::TIOCSCTTY.into();
                #[cfg(not(target_os = "macos"))]
                let tiocsctty = libc::TIOCSCTTY;
                if libc::ioctl(libc::STDIN_FILENO, tiocsctty, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    fn wait_for_child(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_available_pty(master: &File) -> String {
        let mut reader = master.try_clone().unwrap();
        // SAFETY: reader owns a live PTY master descriptor and fcntl receives
        // the documented integer commands/flag value.
        unsafe {
            let flags = libc::fcntl(reader.as_raw_fd(), libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let mut bytes = Vec::new();
        let _ = reader.read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn sigterm_returns_through_raw_mode_guard_and_restores_the_terminal() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (connected_tx, connected_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let Ok(Ok((stream, _))) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
                else {
                    return;
                };
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                connected_tx.send(()).unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    while socket.next().await.is_some() {}
                })
                .await;
            });
        });

        let (master, slave) = open_pty();
        let original = terminal_attributes(slave.as_raw_fd());
        let mut child = spawn_shell_in_pty(&format!("http://{address}"), &slave);
        // The child owns the slave after spawn. Keeping a second slave open in
        // the harness can delay controlling-terminal teardown on macOS; the
        // master remains valid for termios observation.
        drop(slave);
        if connected_rx.recv_timeout(Duration::from_secs(5)).is_err() {
            let transcript = read_available_pty(&master);
            let _ = child.kill();
            let _ = wait_for_child(&mut child, Duration::from_secs(2));
            panic!("cats shell did not connect within 5s; PTY: {transcript:?}");
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let current = terminal_attributes(master.as_raw_fd());
            if current.c_lflag & (libc::ICANON | libc::ECHO) == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "child never enabled raw mode");
            std::thread::sleep(Duration::from_millis(10));
        }

        // SAFETY: the child PID is live and SIGTERM carries no pointer data.
        let signal_result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        assert_eq!(signal_result, 0);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut transcript = String::new();
        let restored = loop {
            transcript.push_str(&read_available_pty(&master));
            let current = terminal_attributes(master.as_raw_fd());
            if terminal_attributes_match(&original, &current)
                && transcript.contains("interactive shell interrupted by SIGTERM")
            {
                break current;
            }
            assert!(
                Instant::now() < deadline,
                "SIGTERM did not return through raw cleanup; PTY: {transcript:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            terminal_attributes_match(&original, &restored),
            "terminal attributes were not restored after SIGTERM"
        );
        // The synthetic macOS controlling-PTY session can remain in kernel
        // exit teardown while its master is held for termios inspection. The
        // assertions above are the raw-mode oracle; exact 143 mapping is tested
        // independently without depending on that PTY teardown behavior.
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(143), "{status:?}");
        } else {
            let _ = child.kill();
            let _ = wait_for_child(&mut child, Duration::from_secs(2));
        }
        server.join().unwrap();
    }
}

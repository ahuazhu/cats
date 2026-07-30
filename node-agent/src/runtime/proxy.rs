use super::*;

#[derive(Debug, thiserror::Error)]
#[error("activity changed while preparing to suspend")]
pub(super) struct ActivityChanged;

pub(crate) fn is_activity_changed(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ActivityChanged>().is_some()
        || format!("{error:#}").contains("activity_changed")
}

#[derive(Default)]
struct RuntimeActivityInner {
    sequence: u64,
    active: u32,
    quiescing: bool,
}

#[derive(Default)]
pub(super) struct RuntimeActivity {
    inner: Mutex<RuntimeActivityInner>,
}

impl RuntimeActivity {
    pub(super) fn acquire(self: &Arc<Self>) -> Result<RuntimeActivityGuard> {
        let mut inner = self.inner.lock().unwrap();
        if inner.quiescing {
            inner.sequence = inner.sequence.saturating_add(1);
            return Err(ActivityChanged.into());
        }
        inner.active = inner.active.saturating_add(1);
        inner.sequence = inner.sequence.saturating_add(1);
        Ok(RuntimeActivityGuard {
            activity: self.clone(),
        })
    }

    pub(super) fn prepare(&self) -> Result<u64> {
        let mut inner = self.inner.lock().unwrap();
        if inner.quiescing || inner.active != 0 {
            return Err(ActivityChanged.into());
        }
        inner.quiescing = true;
        Ok(inner.sequence)
    }

    pub(super) fn unchanged_since(&self, sequence: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.quiescing && inner.active == 0 && inner.sequence == sequence
    }

    pub(super) fn open(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.quiescing = false;
        inner.sequence = inner.sequence.saturating_add(1);
    }
}

pub(crate) struct RuntimeActivityGuard {
    activity: Arc<RuntimeActivity>,
}

/// Network target for a streaming endpoint connection. FakeVmm exposes the
/// guest workload on a Unix socket; real Cats use the guest tap address.
pub(crate) enum ProxyTarget {
    Unix(PathBuf),
    Tcp(std::net::SocketAddr),
}

impl Drop for RuntimeActivityGuard {
    fn drop(&mut self) {
        let mut inner = self.activity.inner.lock().unwrap();
        inner.active = inner.active.saturating_sub(1);
        inner.sequence = inner.sequence.saturating_add(1);
    }
}

impl NodeRuntime {
    pub fn exec(&self, cat_id: &str, command: Vec<String>) -> Result<(i32, String, String)> {
        self.exec_with_input(cat_id, command, Default::default(), Vec::new())
    }

    pub fn exec_with_input(
        &self,
        cat_id: &str,
        command: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        stdin: Vec<u8>,
    ) -> Result<(i32, String, String)> {
        let (conn, activity) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if rt.state != ObservedState::Running {
                bail!("cat is not running (state {:?})", rt.state);
            }
            (rt.conn(), rt.activity.clone())
        };
        let _guard = activity.acquire()?;
        let mut client = conn.connect_long_running()?;
        client.exec_with_input(command, env, stdin)
    }

    pub(crate) fn open_shell(
        &self,
        cat_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<(GuestShell, RuntimeActivityGuard)> {
        let (conn, activity) = {
            let cats = self.cats.lock().unwrap();
            let runtime = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if runtime.state != ObservedState::Running {
                bail!("cat is not running (state {:?})", runtime.state);
            }
            (runtime.conn(), runtime.activity.clone())
        };
        let guard = activity.acquire()?;
        let shell = conn.connect_shell()?.start_shell(rows, cols)?;
        Ok((shell, guard))
    }

    /// Forward an HTTP request to the guest service. In Cloud Hypervisor mode
    /// this is a direct host-tap -> guest-IP connection; FakeVmm uses its
    /// Unix test workload. Errors with "not active" when the Cat is not
    /// running here, which the gateway treats as a stale route.
    pub fn proxy_http(
        &self,
        cat_id: &str,
        request: &ProxyHttpRequest,
    ) -> Result<ProxyHttpResponse> {
        use std::io::{Read, Write};
        anyhow::ensure!(
            request.target_port > 0,
            "endpoint target port must be non-zero"
        );
        let (target, activity) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats.get(cat_id).context("cat is not active on this node")?;
            if rt.state != ObservedState::Running {
                bail!("cat is not active on this node (state {:?})", rt.state);
            }
            let target = match rt.ch.as_ref() {
                Some(chrt) => {
                    let network = chrt.network.as_ref().context("cat has no guest network")?;
                    let ip = network
                        .guest_ip
                        .split('/')
                        .next()
                        .context("invalid guest address")?
                        .parse::<std::net::IpAddr>()
                        .context("invalid guest IP")?;
                    ProxyTarget::Tcp(std::net::SocketAddr::new(ip, request.target_port))
                }
                None => ProxyTarget::Unix(rt.web_socket()),
            };
            (target, rt.activity.clone())
        };
        let _guard = activity.acquire()?;
        let raw_request = build_guest_http_request(request)?;
        let mut buf = Vec::new();
        match target {
            ProxyTarget::Unix(path) => {
                let mut stream = std::os::unix::net::UnixStream::connect(&path)?;
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                stream.write_all(&raw_request)?;
                stream
                    .take((MAX_PROXY_RESPONSE_BYTES + 1) as u64)
                    .read_to_end(&mut buf)?;
            }
            ProxyTarget::Tcp(address) => {
                let mut stream =
                    std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
                        .with_context(|| format!("connect guest service {address}"))?;
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                stream.write_all(&raw_request)?;
                stream
                    .take((MAX_PROXY_RESPONSE_BYTES + 1) as u64)
                    .read_to_end(&mut buf)?;
            }
        }
        anyhow::ensure!(
            buf.len() <= MAX_PROXY_RESPONSE_BYTES,
            "guest response exceeds {MAX_PROXY_RESPONSE_BYTES} bytes"
        );
        parse_guest_http_response(&buf)
    }

    /// Resolve a streaming endpoint and hold the runtime activity fence for
    /// the entire connection. Callers must keep the returned guard alive.
    pub(crate) fn open_proxy_target(
        &self,
        cat_id: &str,
        target_port: u16,
    ) -> Result<(ProxyTarget, RuntimeActivityGuard)> {
        anyhow::ensure!(target_port > 0, "endpoint target port must be non-zero");
        let (target, activity) = {
            let cats = self.cats.lock().unwrap();
            let runtime = cats.get(cat_id).context("cat is not active on this node")?;
            if runtime.state != ObservedState::Running {
                bail!("cat is not active on this node (state {:?})", runtime.state);
            }
            let target = match runtime.ch.as_ref() {
                Some(ch_runtime) => {
                    let network = ch_runtime
                        .network
                        .as_ref()
                        .context("cat has no guest network")?;
                    let ip = network
                        .guest_ip
                        .split('/')
                        .next()
                        .context("invalid guest address")?
                        .parse::<std::net::IpAddr>()
                        .context("invalid guest IP")?;
                    ProxyTarget::Tcp(std::net::SocketAddr::new(ip, target_port))
                }
                None => ProxyTarget::Unix(runtime.web_socket()),
            };
            (target, runtime.activity.clone())
        };
        let guard = activity.acquire()?;
        Ok((target, guard))
    }
}

const MAX_PROXY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub(super) fn build_guest_http_request(request: &ProxyHttpRequest) -> Result<Vec<u8>> {
    use std::io::Write as _;

    anyhow::ensure!(is_http_token(&request.method), "invalid HTTP method");
    anyhow::ensure!(
        request.path.starts_with('/')
            && !request.path.contains('\r')
            && !request.path.contains('\n'),
        "invalid HTTP request path"
    );
    let guest_host = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-host"))
        .map(|(_, value)| value.as_str())
        .unwrap_or("guest");
    anyhow::ensure!(
        !guest_host.contains('\r') && !guest_host.contains('\n'),
        "invalid forwarded host"
    );
    let mut raw = format!(
        "{} {} HTTP/1.1\r\nhost: {guest_host}\r\n",
        request.method, request.path
    )
    .into_bytes();
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || hop_by_hop_header(name)
        {
            continue;
        }
        anyhow::ensure!(
            is_http_token(name) && !value.contains('\r') && !value.contains('\n'),
            "invalid HTTP header"
        );
        write!(&mut raw, "{name}: {value}\r\n")?;
    }
    write!(
        &mut raw,
        "x-cats-route-epoch: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        request.route_epoch,
        request.body.len()
    )?;
    raw.extend_from_slice(&request.body);
    Ok(raw)
}

pub(super) fn parse_guest_http_response(raw: &[u8]) -> Result<ProxyHttpResponse> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("guest returned malformed HTTP response")?;
    let head = std::str::from_utf8(&raw[..head_end]).context("guest returned non-UTF8 headers")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("guest response is missing status")?
        .parse::<u16>()
        .context("invalid guest response status")?;
    anyhow::ensure!((100..=599).contains(&status), "invalid guest HTTP status");

    let mut headers = Vec::new();
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("malformed guest response header")?;
        let name = name.trim();
        let value = value.trim();
        anyhow::ensure!(
            is_http_token(name) && !value.contains('\r') && !value.contains('\n'),
            "invalid guest response header"
        );
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .context("invalid guest Content-Length")?,
            );
        }
        if !hop_by_hop_header(name) && !name.eq_ignore_ascii_case("content-length") {
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let encoded_body = &raw[head_end + 4..];
    let body = if chunked {
        decode_chunked_body(encoded_body)?
    } else if let Some(length) = content_length {
        anyhow::ensure!(
            encoded_body.len() >= length,
            "truncated guest HTTP response body"
        );
        encoded_body[..length].to_vec()
    } else {
        encoded_body.to_vec()
    };
    Ok(ProxyHttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked_body(mut encoded: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .context("malformed chunked response")?;
        let size_line =
            std::str::from_utf8(&encoded[..line_end]).context("invalid chunk size line")?;
        let size =
            usize::from_str_radix(size_line.split(';').next().unwrap_or_default().trim(), 16)
                .context("invalid chunk size")?;
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        anyhow::ensure!(
            encoded.len() >= size + 2 && &encoded[size..size + 2] == b"\r\n",
            "truncated chunked response"
        );
        decoded.extend_from_slice(&encoded[..size]);
        anyhow::ensure!(
            decoded.len() <= MAX_PROXY_RESPONSE_BYTES,
            "guest response exceeds {MAX_PROXY_RESPONSE_BYTES} bytes"
        );
        encoded = &encoded[size + 2..];
    }
}

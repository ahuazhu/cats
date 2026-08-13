//! Public HTTP/1.1 ingress composition for Route Grant v2.
//!
//! Each HTTP request gets exactly one authenticated Node tunnel attempt. The
//! Gateway parses only the head and request-body boundary needed to select a
//! canonical hostname and prevent another pipelined Host from crossing the
//! admitted tunnel. A successful WebSocket upgrade keeps that one tunnel for
//! all subsequent raw bytes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use cats_api::route_grant_v2::RouteAdmissionV2Reason;
use cats_api::runtime_reconciliation::Hostname;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::{
    CacheLookup, GatewayNodeRouteV2Error, NegativeRoute, RefreshableRejection, RequestKind,
    ResolvedRoute, RouteCache,
};

const DEFAULT_MAX_PUBLIC_REQUEST_HEAD_BYTES: usize = 32 * 1024;
const DEFAULT_MAX_PUBLIC_CONNECTIONS: usize = 4_096;
const DEFAULT_PUBLIC_HEAD_DEADLINE: Duration = Duration::from_secs(5);
const DEFAULT_SHUTDOWN_DRAIN_DEADLINE: Duration = Duration::from_secs(10);
const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;

pub trait GatewayTunnel: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> GatewayTunnel for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedGatewayTunnel = Box<dyn GatewayTunnel>;
pub type TunnelFuture = Pin<
    Box<dyn Future<Output = Result<BoxedGatewayTunnel, GatewayNodeRouteV2Error>> + Send + 'static>,
>;
/// Provider-neutral port for the one authenticated Node tunnel attempt.
///
/// Production supplies [`super::GatewayNodeRouteV2Client`]. Tests can supply
/// an in-memory duplex stream without weakening the shipped composition.
pub type TunnelConnector = Arc<dyn Fn(Arc<ResolvedRoute>) -> TunnelFuture + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayIngressConfig {
    pub max_public_connections: usize,
    pub max_public_request_head_bytes: usize,
    pub public_request_head_deadline: Duration,
    pub shutdown_drain_deadline: Duration,
}

impl Default for GatewayIngressConfig {
    fn default() -> Self {
        Self {
            max_public_connections: DEFAULT_MAX_PUBLIC_CONNECTIONS,
            max_public_request_head_bytes: DEFAULT_MAX_PUBLIC_REQUEST_HEAD_BYTES,
            public_request_head_deadline: DEFAULT_PUBLIC_HEAD_DEADLINE,
            shutdown_drain_deadline: DEFAULT_SHUTDOWN_DRAIN_DEADLINE,
        }
    }
}

impl GatewayIngressConfig {
    fn validate(self) -> Result<Self, GatewayIngressError> {
        if self.max_public_connections == 0 || self.max_public_connections > Semaphore::MAX_PERMITS
        {
            return Err(GatewayIngressError::InvalidConfig(
                "max_public_connections is outside the semaphore range",
            ));
        }
        if self.max_public_request_head_bytes == 0
            || self.public_request_head_deadline.is_zero()
            || self.shutdown_drain_deadline.is_zero()
        {
            return Err(GatewayIngressError::InvalidConfig(
                "public header and shutdown bounds must be positive",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayIngressError {
    #[error("invalid public Gateway configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("public Gateway listener failed")]
    Listener,
    #[error("public Gateway connection task failed")]
    ConnectionTask,
}

pub struct GatewayIngress {
    config: GatewayIngressConfig,
    cache: RouteCache,
    connector: TunnelConnector,
}

impl std::fmt::Debug for GatewayIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayIngress")
            .field("config", &self.config)
            .field("cache", &"[bounded local cache]")
            .field("connector", &"[authenticated machine connector]")
            .finish()
    }
}

impl GatewayIngress {
    pub fn new(
        config: GatewayIngressConfig,
        cache: RouteCache,
        connector: TunnelConnector,
    ) -> Result<Self, GatewayIngressError> {
        Ok(Self {
            config: config.validate()?,
            cache,
            connector,
        })
    }

    /// Serve until `shutdown` resolves, then stop cache/resolve admission and
    /// drain active public connections for the configured bounded interval.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) -> Result<(), GatewayIngressError> {
        let connection_slots = Arc::new(Semaphore::new(self.config.max_public_connections));
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);

        'accept: loop {
            while let Some(result) = connections.try_join_next() {
                if result.is_err() {
                    self.cache.shutdown();
                    connections.abort_all();
                    return Err(GatewayIngressError::ConnectionTask);
                }
            }

            let permit = tokio::select! {
                _ = &mut shutdown => break 'accept,
                result = Arc::clone(&connection_slots).acquire_owned() => {
                    result.map_err(|_| GatewayIngressError::Listener)?
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    if result.is_some_and(|result| result.is_err()) {
                        self.cache.shutdown();
                        connections.abort_all();
                        return Err(GatewayIngressError::ConnectionTask);
                    }
                    continue 'accept;
                }
            };
            let accepted = tokio::select! {
                _ = &mut shutdown => {
                    drop(permit);
                    break 'accept;
                }
                accepted = listener.accept() => accepted,
            };
            let (stream, _) = accepted.map_err(|_| GatewayIngressError::Listener)?;
            let cache = self.cache.clone();
            let connector = Arc::clone(&self.connector);
            let config = self.config;
            connections.spawn(async move {
                let _permit = permit;
                handle_connection(stream, cache, connector, config).await;
            });
        }

        self.cache.shutdown();
        let drain = async {
            while let Some(result) = connections.join_next().await {
                if result.is_err() {
                    return Err(GatewayIngressError::ConnectionTask);
                }
            }
            Ok(())
        };
        match tokio::time::timeout(self.config.shutdown_drain_deadline, drain).await {
            Ok(result) => result,
            Err(_) => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                Ok(())
            }
        }
    }
}

async fn handle_connection(
    mut public: TcpStream,
    cache: RouteCache,
    connector: TunnelConnector,
    config: GatewayIngressConfig,
) {
    let mut pending = Vec::new();
    let mut served_request = false;
    loop {
        let header_end = match read_request_head(&mut public, &mut pending, config).await {
            Ok(header_end) => header_end,
            Err(ReadRequestHeadError::CleanClose) if served_request => return,
            Err(_) => {
                write_public_error(&mut public, PublicError::BadRequest).await;
                return;
            }
        };
        let parsed = match parse_request_head(&pending[..header_end], header_end) {
            Some(parsed) => parsed,
            None => {
                write_public_error(&mut public, PublicError::BadRequest).await;
                return;
            }
        };
        match parsed.local_health {
            LocalHealthDisposition::RespondOk => {
                write_local_health(&mut public).await;
                return;
            }
            LocalHealthDisposition::Reject => {
                write_public_error(&mut public, PublicError::BadRequest).await;
                return;
            }
            LocalHealthDisposition::NotHealth => {}
        }
        let route = match cache.lookup(parsed.hostname.as_str()).await {
            Ok(CacheLookup::Positive(route)) => route,
            Ok(CacheLookup::Negative(NegativeRoute::NotFound)) => {
                write_public_error(&mut public, PublicError::NotFound).await;
                return;
            }
            Ok(CacheLookup::Negative(NegativeRoute::Gone)) => {
                write_public_error(&mut public, PublicError::Gone).await;
                return;
            }
            Err(_) => {
                write_public_error(&mut public, PublicError::Unavailable).await;
                return;
            }
        };

        let mut tunnel = match connector(Arc::clone(&route)).await {
            Ok(tunnel) => tunnel,
            Err(GatewayNodeRouteV2Error::Admission(failure)) => {
                if !failure.guard_acquired {
                    if let Some(rejection) = refreshable_rejection(failure.reason) {
                        let _ = cache
                            .refresh_for_later(
                                parsed.request_kind,
                                parsed.hostname.as_str(),
                                route.grant_digest(),
                                rejection,
                            )
                            .await;
                    }
                }
                let response = if failure.guard_acquired
                    && failure.reason == RouteAdmissionV2Reason::UpstreamUnavailable
                {
                    PublicError::BadGateway
                } else {
                    PublicError::Unavailable
                };
                write_public_error(&mut public, response).await;
                return;
            }
            Err(_) => {
                write_public_error(&mut public, PublicError::BadGateway).await;
                return;
            }
        };

        if parsed.request_kind == RequestKind::WebSocketUpgrade {
            if tunnel.write_all(&pending).await.is_err() {
                return;
            }
            pending.clear();
            let _ = tokio::io::copy_bidirectional(&mut public, &mut tunnel).await;
            return;
        }

        if tunnel.write_all(&pending[..header_end]).await.is_err() {
            return;
        }
        pending.drain(..header_end);
        match parsed.body_framing {
            BodyFraming::Fixed(content_length) => {
                if forward_fixed_body(&mut public, &mut tunnel, &mut pending, content_length)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            BodyFraming::Chunked => {
                if forward_chunked_body(&mut public, &mut tunnel, &mut pending, config)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        if tunnel.shutdown().await.is_err() {
            return;
        }
        if tokio::io::copy(&mut tunnel, &mut public).await.is_err() {
            return;
        }
        served_request = true;
        if parsed.connection_close {
            let _ = public.shutdown().await;
            return;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadRequestHeadError {
    CleanClose,
    Invalid,
}

async fn read_request_head(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    config: GatewayIngressConfig,
) -> Result<usize, ReadRequestHeadError> {
    tokio::time::timeout(config.public_request_head_deadline, async {
        if let Some(header_end) = find_header_end(pending) {
            return (header_end <= config.max_public_request_head_bytes)
                .then_some(header_end)
                .ok_or(ReadRequestHeadError::Invalid);
        }
        let mut chunk = [0_u8; 4 * 1024];
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|_| ReadRequestHeadError::Invalid)?;
            if read == 0 {
                return Err(if pending.is_empty() {
                    ReadRequestHeadError::CleanClose
                } else {
                    ReadRequestHeadError::Invalid
                });
            }
            let next = pending
                .len()
                .checked_add(read)
                .ok_or(ReadRequestHeadError::Invalid)?;
            pending.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = find_header_end(pending) {
                return (header_end <= config.max_public_request_head_bytes)
                    .then_some(header_end)
                    .ok_or(ReadRequestHeadError::Invalid);
            }
            if next >= config.max_public_request_head_bytes {
                return Err(ReadRequestHeadError::Invalid);
            }
        }
    })
    .await
    .map_err(|_| {
        if pending.is_empty() {
            ReadRequestHeadError::CleanClose
        } else {
            ReadRequestHeadError::Invalid
        }
    })?
}

struct ParsedInitialRequest {
    hostname: Hostname,
    request_kind: RequestKind,
    body_framing: BodyFraming,
    connection_close: bool,
    local_health: LocalHealthDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    Fixed(usize),
    Chunked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalHealthDisposition {
    NotHealth,
    RespondOk,
    Reject,
}

fn parse_request_head(bytes: &[u8], header_end: usize) -> Option<ParsedInitialRequest> {
    if bytes.len() != header_end || find_header_end(bytes)? != header_end {
        return None;
    }
    let head = bytes.get(..header_end.checked_sub(4)?)?;
    let text = std::str::from_utf8(head).ok()?;
    if !text.is_ascii() || text.bytes().any(|byte| byte == 0 || byte == 0x7f) {
        return None;
    }
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next()?;
    let request_target = request_parts.next()?;
    let version = request_parts.next()?;
    if request_parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(is_token_byte)
        || !(request_target.starts_with('/') || request_target == "*")
        || request_target
            .bytes()
            .any(|byte| byte <= 0x20 || byte == 0x7f)
        || version != "HTTP/1.1"
    {
        return None;
    }

    let mut host = None;
    let mut connection_upgrade = false;
    let mut connection_close = false;
    let mut websocket_upgrade = false;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return None;
        }
        if name.eq_ignore_ascii_case("host") {
            if host.replace(parse_public_host(value)?).is_some() {
                return None;
            }
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= value
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("upgrade"));
            connection_close |= value
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("close"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            websocket_upgrade |= value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length
                .replace(parse_content_length(value)?)
                .is_some()
            {
                return None;
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return None;
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("expect") {
            // 100-continue would require consuming an upstream interim
            // response before the one-request body boundary is known.
            return None;
        }
    }
    if connection_upgrade != websocket_upgrade {
        return None;
    }
    let request_kind = if connection_upgrade {
        RequestKind::WebSocketUpgrade
    } else {
        RequestKind::Http
    };
    if chunked && content_length.is_some() {
        return None;
    }
    let body_framing = if chunked {
        BodyFraming::Chunked
    } else {
        BodyFraming::Fixed(content_length.unwrap_or(0))
    };
    if request_kind == RequestKind::WebSocketUpgrade && body_framing != BodyFraming::Fixed(0) {
        return None;
    }
    let local_health = if method == "GET" && request_target == "/healthz" {
        if request_kind == RequestKind::Http && body_framing == BodyFraming::Fixed(0) {
            LocalHealthDisposition::RespondOk
        } else {
            LocalHealthDisposition::Reject
        }
    } else {
        LocalHealthDisposition::NotHealth
    };
    Some(ParsedInitialRequest {
        hostname: host?,
        request_kind,
        body_framing,
        connection_close,
        local_health,
    })
}

async fn forward_fixed_body(
    public: &mut TcpStream,
    tunnel: &mut BoxedGatewayTunnel,
    pending: &mut Vec<u8>,
    content_length: usize,
) -> Result<(), ()> {
    let buffered = pending.len().min(content_length);
    tunnel
        .write_all(&pending[..buffered])
        .await
        .map_err(|_| ())?;
    pending.drain(..buffered);
    let remaining = content_length - buffered;
    if remaining != 0 {
        let mut body = public.take(remaining as u64);
        let copied = tokio::io::copy(&mut body, tunnel).await.map_err(|_| ())?;
        if copied != remaining as u64 {
            return Err(());
        }
    }
    Ok(())
}

async fn forward_chunked_body(
    public: &mut TcpStream,
    tunnel: &mut BoxedGatewayTunnel,
    pending: &mut Vec<u8>,
    config: GatewayIngressConfig,
) -> Result<(), ()> {
    loop {
        let line = take_crlf_line(
            public,
            pending,
            MAX_CHUNK_LINE_BYTES.min(config.max_public_request_head_bytes),
        )
        .await?;
        let chunk_size = parse_chunk_size(&line).ok_or(())?;
        tunnel.write_all(&line).await.map_err(|_| ())?;
        if chunk_size == 0 {
            let mut trailer_bytes = 0_usize;
            loop {
                let trailer =
                    take_crlf_line(public, pending, config.max_public_request_head_bytes).await?;
                trailer_bytes = trailer_bytes.checked_add(trailer.len()).ok_or(())?;
                if trailer_bytes > config.max_public_request_head_bytes {
                    return Err(());
                }
                if trailer != b"\r\n" && !valid_trailer_line(&trailer) {
                    return Err(());
                }
                tunnel.write_all(&trailer).await.map_err(|_| ())?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        forward_exact_bytes(public, tunnel, pending, chunk_size).await?;
        ensure_pending(public, pending, 2).await?;
        if pending.get(..2) != Some(b"\r\n") {
            return Err(());
        }
        tunnel.write_all(&pending[..2]).await.map_err(|_| ())?;
        pending.drain(..2);
    }
}

async fn forward_exact_bytes(
    public: &mut TcpStream,
    tunnel: &mut BoxedGatewayTunnel,
    pending: &mut Vec<u8>,
    length: u64,
) -> Result<(), ()> {
    let buffered = u64::try_from(pending.len())
        .ok()
        .map_or(length, |available| available.min(length));
    let buffered = usize::try_from(buffered).map_err(|_| ())?;
    tunnel
        .write_all(&pending[..buffered])
        .await
        .map_err(|_| ())?;
    pending.drain(..buffered);
    let remaining = length - buffered as u64;
    if remaining != 0 {
        let mut body = public.take(remaining);
        let copied = tokio::io::copy(&mut body, tunnel).await.map_err(|_| ())?;
        if copied != remaining {
            return Err(());
        }
    }
    Ok(())
}

async fn take_crlf_line(
    public: &mut TcpStream,
    pending: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<Vec<u8>, ()> {
    loop {
        if let Some(position) = pending.windows(2).position(|window| window == b"\r\n") {
            let end = position.checked_add(2).ok_or(())?;
            if end > max_bytes {
                return Err(());
            }
            return Ok(pending.drain(..end).collect());
        }
        if pending.len() >= max_bytes {
            return Err(());
        }
        read_more(public, pending).await?;
    }
}

async fn ensure_pending(
    public: &mut TcpStream,
    pending: &mut Vec<u8>,
    required: usize,
) -> Result<(), ()> {
    while pending.len() < required {
        read_more(public, pending).await?;
    }
    Ok(())
}

async fn read_more(public: &mut TcpStream, pending: &mut Vec<u8>) -> Result<(), ()> {
    let mut chunk = [0_u8; 4 * 1024];
    let read = public.read(&mut chunk).await.map_err(|_| ())?;
    if read == 0 {
        return Err(());
    }
    pending.extend_from_slice(&chunk[..read]);
    Ok(())
}

fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    // Extensions are deliberately excluded from the production v1 proxy. A
    // single hexadecimal size keeps the local boundary proof closed.
    let size = line.strip_suffix(b"\r\n")?;
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    size.iter().try_fold(0_u64, |parsed, byte| {
        parsed
            .checked_mul(16)?
            .checked_add(u64::from((*byte as char).to_digit(16)?))
    })
}

fn valid_trailer_line(line: &[u8]) -> bool {
    let Some(line) = line.strip_suffix(b"\r\n") else {
        return false;
    };
    let Some(separator) = line.iter().position(|byte| *byte == b':') else {
        return false;
    };
    let name = &line[..separator];
    separator != 0
        && name.iter().copied().all(is_token_byte)
        && !forbidden_trailer_name(name)
        && line[separator + 1..]
            .iter()
            .all(|byte| (*byte >= 0x20 || *byte == b'\t') && *byte != 0x7f)
}

fn forbidden_trailer_name(name: &[u8]) -> bool {
    [
        b"host".as_slice(),
        b"content-length",
        b"transfer-encoding",
        b"connection",
        b"trailer",
        b"te",
        b"upgrade",
        b"expect",
    ]
    .iter()
    .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

fn parse_content_length(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let parsed = value.parse::<usize>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn parse_public_host(value: &str) -> Option<Hostname> {
    if value.is_empty() || !value.is_ascii() || value.starts_with('[') {
        return None;
    }
    let hostname = match value.rsplit_once(':') {
        Some((hostname, port)) => {
            let parsed = port.parse::<u16>().ok().filter(|port| *port != 0)?;
            if parsed.to_string() != port {
                return None;
            }
            hostname
        }
        None => value,
    };
    Hostname::new(hostname.to_ascii_lowercase())
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .and_then(|position| position.checked_add(4))
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn refreshable_rejection(reason: RouteAdmissionV2Reason) -> Option<RefreshableRejection> {
    match reason {
        RouteAdmissionV2Reason::Expired => Some(RefreshableRejection::Expired),
        RouteAdmissionV2Reason::BindingMismatch => Some(RefreshableRejection::BindingMismatch),
        RouteAdmissionV2Reason::GateClosed => Some(RefreshableRejection::GateClosed),
        RouteAdmissionV2Reason::RuntimeNotReady => Some(RefreshableRejection::RuntimeNotReady),
        RouteAdmissionV2Reason::NotYetValid
        | RouteAdmissionV2Reason::UnknownKey
        | RouteAdmissionV2Reason::InvalidSignature
        | RouteAdmissionV2Reason::InvalidClaims
        | RouteAdmissionV2Reason::UpstreamUnavailable => None,
    }
}

#[derive(Clone, Copy)]
enum PublicError {
    BadRequest,
    NotFound,
    Gone,
    BadGateway,
    Unavailable,
}

async fn write_public_error(stream: &mut TcpStream, error: PublicError) {
    let response: &[u8] = match error {
        PublicError::BadRequest => {
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nbad request\n"
        }
        PublicError::NotFound => {
            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot found\n"
        }
        PublicError::Gone => {
            b"HTTP/1.1 410 Gone\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\ngone\n"
        }
        PublicError::BadGateway => {
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nbad gateway\n"
        }
        PublicError::Unavailable => {
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\nRetry-After: 1\r\n\r\nservice unavailable\n"
        }
    };
    let _ = stream.write_all(response).await;
    let _ = stream.shutdown().await;
}

async fn write_local_health(stream: &mut TcpStream) {
    let _ = stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
        )
        .await;
    let _ = stream.shutdown().await;
}

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use cats_api::route_grant_v2::{RouteAdmissionV2Failure, RouteAdmissionV2Reason};
use cats_api::runtime_reconciliation::{Hostname, Id, NodeTransportTarget};
use cats_network::route_v2::{
    AuthenticatedResolveEnvelope, BoxedGatewayTunnel, GatewayIngress, GatewayIngressConfig,
    GatewayNodeRouteV2Error, GrantDigest, ResolveFuture, RouteCache, RouteCacheConfig,
    RouteResolution, RouteResolver, TunnelConnector, TunnelFuture,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::Instant;

fn route(hostname: Hostname, grant: &[u8]) -> cats_network::route_v2::ResolvedRoute {
    let now_unix_seconds = 1_786_156_800;
    AuthenticatedResolveEnvelope::from_authenticated_transport(
        Id::new("cat_01").unwrap(),
        Id::new("ep_01").unwrap(),
        NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
        now_unix_seconds + 120,
        grant.to_vec(),
        GrantDigest::from_bytes(Sha256::digest(grant).into()),
        grant.len() + 256,
    )
    .validate_for_hostname(&hostname, now_unix_seconds, Instant::now())
    .unwrap()
}

fn cache_config() -> RouteCacheConfig {
    RouteCacheConfig {
        max_entries: 16,
        max_bytes: 16 * 1024,
        max_entry_bytes: 8 * 1024,
        max_resolve_response_bytes: 8 * 1024,
        max_waiters_per_hostname: 8,
        max_concurrent_resolves: 2,
        resolve_timeout: Duration::from_secs(1),
        negative_ttl: Duration::from_millis(50),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(100),
    }
}

async fn spawn_gateway(
    cache: RouteCache,
    connector: TunnelConnector,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), cats_network::route_v2::GatewayIngressError>>,
) {
    spawn_gateway_with_config(cache, connector, GatewayIngressConfig::default()).await
}

async fn spawn_gateway_with_config(
    cache: RouteCache,
    connector: TunnelConnector,
    config: GatewayIngressConfig,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), cats_network::route_v2::GatewayIngressError>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let gateway = GatewayIngress::new(config, cache, connector).unwrap();
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        gateway
            .serve(listener, async move {
                let _ = shutdown_receiver.await;
            })
            .await
    });
    (address, shutdown_sender, task)
}

struct SilentTunnel {
    dropped: Option<oneshot::Sender<()>>,
}

struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockStage {
    HeadWrite,
    BodyWrite,
    Shutdown,
}

struct BlockingStageTunnel {
    stage: BlockStage,
    written: Arc<Mutex<Vec<u8>>>,
    blocked: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}

#[derive(Clone, Copy, Debug)]
enum PublicEgressStage {
    HttpHead,
    HttpBody,
    WebSocketRaw,
}

struct FloodingResponseTunnel {
    response: Vec<u8>,
    offset: usize,
    notify_after: usize,
    egress_started: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}

impl Drop for FloodingResponseTunnel {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl AsyncRead for FloodingResponseTunnel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset == self.response.len() {
            return Poll::Pending;
        }
        let read = buffer.remaining().min(self.response.len() - self.offset);
        let end = self.offset + read;
        buffer.put_slice(&self.response[self.offset..end]);
        self.offset = end;
        if self.offset >= self.notify_after {
            if let Some(started) = self.egress_started.take() {
                let _ = started.send(());
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FloodingResponseTunnel {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn flooding_response(stage: PublicEgressStage) -> (Vec<u8>, usize, &'static [u8], usize) {
    const FLOOD_BYTES: usize = 16 * 1024 * 1024;
    match stage {
        PublicEgressStage::HttpHead => {
            let mut response = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
            response.resize(2 * 1024 * 1024, b'a');
            response.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
            let notify_after = response.len();
            (
                response,
                notify_after,
                b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
                3 * 1024 * 1024,
            )
        }
        PublicEgressStage::HttpBody => {
            let mut response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {FLOOD_BYTES}\r\n\r\n").into_bytes();
            let notify_after = response.len() + 1;
            response.resize(response.len() + FLOOD_BYTES, b'b');
            (
                response,
                notify_after,
                b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
                32 * 1024,
            )
        }
        PublicEgressStage::WebSocketRaw => {
            let mut response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_vec();
            let notify_after = response.len() + 1;
            response.resize(response.len() + FLOOD_BYTES, b'w');
            (
                response,
                notify_after,
                b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                32 * 1024,
            )
        }
    }
}

impl Drop for BlockingStageTunnel {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl AsyncRead for BlockingStageTunnel {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for BlockingStageTunnel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let block = self.stage == BlockStage::HeadWrite
            || (self.stage == BlockStage::BodyWrite && !self.written.lock().unwrap().is_empty());
        if block {
            if let Some(blocked) = self.blocked.take() {
                let _ = blocked.send(());
            }
            return Poll::Pending;
        }
        self.written.lock().unwrap().extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.stage == BlockStage::Shutdown {
            if let Some(blocked) = self.blocked.take() {
                let _ = blocked.send(());
            }
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl Drop for SilentTunnel {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl AsyncRead for SilentTunnel {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for SilentTunnel {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

async fn exact_local_health_is_the_only_request_that_bypasses_route_authority_case() {
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_call = Arc::clone(&resolve_calls);
    let resolver: RouteResolver = Arc::new(move |hostname| {
        resolve_calls_call.fetch_add(1, Ordering::SeqCst);
        let route = route(hostname, b"ordinary-route-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let tunnel_attempts = Arc::new(AtomicUsize::new(0));
    let tunnel_attempts_call = Arc::clone(&tunnel_attempts);
    let connector: TunnelConnector = Arc::new(move |_| {
        tunnel_attempts_call.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(GatewayNodeRouteV2Error::Protocol) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: alb.internal\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"
    );
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 0);

    for request in [
        b"GET /healthz/ HTTP/1.1\r\nHost: app.cats.run\r\n\r\n".as_slice(),
        b"GET /healthz?probe HTTP/1.1\r\nHost: app.cats.run\r\n\r\n".as_slice(),
        b"POST /healthz HTTP/1.1\r\nHost: app.cats.run\r\nContent-Length: 0\r\n\r\n".as_slice(),
    ] {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    }
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 3);

    for request in [
        b"GET /healthz HTTP/1.1\r\n\r\n".as_slice(),
        b"GET /healthz HTTP/1.1\r\nHost: alb.internal\r\nContent-Length: 4\r\n\r\ndataGET /smuggled HTTP/1.1\r\nHost: app.cats.run\r\n\r\n".as_slice(),
        b"GET /healthz HTTP/1.1\r\nHost: alb.internal\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: app.cats.run\r\n\r\n".as_slice(),
    ] {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 3);

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn public_http_bytes_cross_one_route_lookup_and_one_node_tunnel_case() {
    let resolved_hostname = Arc::new(Mutex::new(None));
    let resolved_hostname_call = Arc::clone(&resolved_hostname);
    let resolver: RouteResolver = Arc::new(move |hostname| {
        *resolved_hostname_call.lock().unwrap() = Some(hostname.clone());
        let route = route(hostname, b"opaque-route-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();

    let expected =
        b"POST /mutate HTTP/1.1\r\nHost: App.Cats.Run:443\r\nContent-Length: 7\r\n\r\npayload";
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_call = Arc::clone(&attempts);
    let connector: TunnelConnector = Arc::new(move |_| {
        attempts_call.fetch_add(1, Ordering::SeqCst);
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut request = vec![0_u8; expected.len()];
            node_side.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            node_side
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            node_side.shutdown().await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(expected).await.unwrap();
    let expected_response = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";
    let mut response = vec![0_u8; expected_response.len()];
    client.read_exact(&mut response).await.unwrap();

    assert_eq!(response, expected_response);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        resolved_hostname.lock().unwrap().as_ref().unwrap().as_str(),
        "app.cats.run"
    );
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn keep_alive_requests_with_different_hosts_get_distinct_tunnels_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"per-request-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let admitted_hosts = Arc::new(Mutex::new(Vec::new()));
    let admitted_hosts_call = Arc::clone(&admitted_hosts);
    let connector: TunnelConnector = Arc::new(move |route| {
        let hostname = route.hostname().as_str().to_owned();
        admitted_hosts_call.lock().unwrap().push(hostname.clone());
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let expected = format!("GET / HTTP/1.1\r\nHost: {hostname}\r\n\r\n");
            let mut request = vec![0_u8; expected.len()];
            node_side.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected.as_bytes());
            assert_eq!(
                node_side.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
            node_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1")
                .await
                .unwrap();
            node_side.shutdown().await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    let expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1";
    for hostname in ["one.cats.run", "two.cats.run"] {
        client
            .write_all(format!("GET / HTTP/1.1\r\nHost: {hostname}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = vec![0_u8; expected_response.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected_response);
    }

    assert_eq!(
        *admitted_hosts.lock().unwrap(),
        ["one.cats.run".to_owned(), "two.cats.run".to_owned()]
    );
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn chunked_http_body_and_trailer_stay_on_one_request_tunnel_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"chunked-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let expected = b"POST /stream HTTP/1.1\r\nHost: app.cats.run\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n4\r\ndata\r\n0\r\nX-End: yes\r\n\r\n";
    let connector: TunnelConnector = Arc::new(move |_| {
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut request = vec![0_u8; expected.len()];
            node_side.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            assert_eq!(
                node_side.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
            node_side
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            node_side.shutdown().await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(expected).await.unwrap();
    let expected_response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    let mut response = vec![0_u8; expected_response.len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, expected_response);

    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn split_chunked_body_retains_pipelined_next_host_for_a_distinct_tunnel_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"split-chunked-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let admitted_hosts = Arc::new(Mutex::new(Vec::new()));
    let admitted_hosts_call = Arc::clone(&admitted_hosts);
    let connector: TunnelConnector = Arc::new(move |route| {
        let hostname = route.hostname().as_str().to_owned();
        admitted_hosts_call.lock().unwrap().push(hostname.clone());
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let expected = if hostname == "one.cats.run" {
                b"POST /stream HTTP/1.1\r\nHost: one.cats.run\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n4\r\ndata\r\n0\r\nX-End: yes\r\n\r\n".as_slice()
            } else {
                b"GET /next HTTP/1.1\r\nHost: two.cats.run\r\n\r\n".as_slice()
            };
            let mut request = vec![0_u8; expected.len()];
            node_side.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            assert_eq!(
                node_side.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
            node_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1")
                .await
                .unwrap();
            node_side.shutdown().await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(
            b"POST /stream HTTP/1.1\r\nHost: one.cats.run\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n",
        )
        .await
        .unwrap();
    for boundary in [
        b"4".as_slice(),
        b"\r".as_slice(),
        b"\nda".as_slice(),
        b"ta\r".as_slice(),
        b"\n0\r\nX-End: yes\r\n\r\nGET /next HTTP/1.1\r\nHost: two.cats.run\r\n\r\n".as_slice(),
    ] {
        client.write_all(boundary).await.unwrap();
        tokio::task::yield_now().await;
    }
    let expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1";
    for _ in 0..2 {
        let mut response = vec![0_u8; expected_response.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected_response);
    }

    assert_eq!(
        *admitted_hosts.lock().unwrap(),
        ["one.cats.run".to_owned(), "two.cats.run".to_owned()]
    );
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn ambiguous_transfer_framing_is_rejected_before_route_authority_case() {
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_call = Arc::clone(&resolve_calls);
    let resolver: RouteResolver = Arc::new(move |_| {
        resolve_calls_call.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(cats_network::route_v2::ResolveFailure::InvalidAuthority) })
            as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let tunnel_attempts = Arc::new(AtomicUsize::new(0));
    let tunnel_attempts_call = Arc::clone(&tunnel_attempts);
    let connector: TunnelConnector = Arc::new(move |_| {
        tunnel_attempts_call.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(GatewayNodeRouteV2Error::Protocol) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    for request in [
        b"POST / HTTP/1.1\r\nHost: app.cats.run\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: app.cats.run\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: app.cats.run\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n".as_slice(),
    ] {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }

    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn malformed_chunk_framing_never_forwards_smuggled_request_bytes_case() {
    const REQUEST_HEAD: &[u8] =
        b"POST / HTTP/1.1\r\nHost: app.cats.run\r\nTransfer-Encoding: chunked\r\n\r\n";
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"malformed-chunk-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let (captured_sender, mut captured_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (head_forwarded_sender, mut head_forwarded_receiver) =
        tokio::sync::mpsc::unbounded_channel();
    let tunnel_attempts = Arc::new(AtomicUsize::new(0));
    let tunnel_attempts_call = Arc::clone(&tunnel_attempts);
    let connector: TunnelConnector = Arc::new(move |_| {
        tunnel_attempts_call.fetch_add(1, Ordering::SeqCst);
        let captured_sender = captured_sender.clone();
        let head_forwarded_sender = head_forwarded_sender.clone();
        let (gateway_side, mut node_side) = tokio::io::duplex(128 * 1024);
        tokio::spawn(async move {
            let mut request = vec![0_u8; REQUEST_HEAD.len()];
            if node_side.read_exact(&mut request).await.is_err() {
                captured_sender.send(Vec::new()).unwrap();
                return;
            }
            head_forwarded_sender.send(()).unwrap();
            node_side.read_to_end(&mut request).await.unwrap();
            captured_sender.send(request).unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let oversized_trailer = format!(
        "0\r\nX-Large: {}\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n",
        "x".repeat(33 * 1024)
    );
    for (case_index, (malformed, head_is_forwarded)) in [
        (
            b"4;extension=yes\r\ndata\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
            true,
        ),
        (
            b"10000000000000000\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
            true,
        ),
        (
            b"1\r\naXGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
            true,
        ),
        (b"0\r\n".to_vec(), true),
        (
            b"0\r\nHost: other.cats.run\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
            true,
        ),
        // The bounded public watcher sees this overflow before the request
        // head write wins. Cancellation must leave the Guest with zero bytes.
        (oversized_trailer.into_bytes(), false),
    ]
    .into_iter()
    .enumerate()
    {
        let attempts_before = tunnel_attempts.load(Ordering::SeqCst);
        let truncated = malformed == b"0\r\n";
        let mut request = REQUEST_HEAD.to_vec();
        request.extend_from_slice(&malformed);
        let mut client = await_production_gateway_stage(
            format!("malformed-chunk[{case_index}]/connect"),
            TcpStream::connect(address),
        )
        .await
        .unwrap();
        await_production_gateway_stage(
            format!("malformed-chunk[{case_index}]/request-write"),
            client.write_all(&request),
        )
        .await
        .unwrap();
        if head_is_forwarded {
            await_production_gateway_stage(
                format!("malformed-chunk[{case_index}]/head-forwarded-channel"),
                head_forwarded_receiver.recv(),
            )
            .await
            .unwrap();
        }
        if truncated {
            await_production_gateway_stage(
                format!("malformed-chunk[{case_index}]/client-shutdown"),
                client.shutdown(),
            )
            .await
            .unwrap();
        }
        let mut response = Vec::new();
        if let Err(error) = await_production_gateway_stage(
            format!("malformed-chunk[{case_index}]/response-read"),
            client.read_to_end(&mut response),
        )
        .await
        {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
        assert!(response.is_empty());

        let connector_was_called = tunnel_attempts.load(Ordering::SeqCst) != attempts_before;
        let captured = if connector_was_called {
            await_production_gateway_stage(
                format!("malformed-chunk[{case_index}]/captured-channel"),
                captured_receiver.recv(),
            )
            .await
            .unwrap()
        } else {
            Vec::new()
        };
        if head_is_forwarded {
            assert!(captured.starts_with(REQUEST_HEAD));
        } else {
            assert!(captured.is_empty());
        }
        assert!(!captured
            .windows(b"GET /smuggled".len())
            .any(|window| window == b"GET /smuggled"));
    }

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn authenticated_stale_rejection_refreshes_only_for_a_later_request_case() {
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_call = Arc::clone(&resolve_calls);
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let generation = resolve_calls_call.fetch_add(1, Ordering::SeqCst);
        let grant = if generation == 0 {
            b"stale-grant".as_slice()
        } else {
            b"fresh-grant".as_slice()
        };
        let route = route(hostname, grant);
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let tunnel_attempts = Arc::new(AtomicUsize::new(0));
    let tunnel_attempts_call = Arc::clone(&tunnel_attempts);
    let connector: TunnelConnector = Arc::new(move |_| {
        tunnel_attempts_call.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(GatewayNodeRouteV2Error::Admission(
                RouteAdmissionV2Failure::pre_admission(RouteAdmissionV2Reason::Expired).unwrap(),
            ))
        }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: app.cats.run\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 2);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn websocket_upgrade_and_frames_remain_raw_on_the_one_admitted_tunnel_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"websocket-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let connector: TunnelConnector = Arc::new(move |_| {
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let expected = b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n";
            let mut request = vec![0_u8; expected.len()];
            node_side.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            let mut early = [0_u8; 1];
            assert!(tokio::time::timeout(
                Duration::from_millis(25),
                node_side.read_exact(&mut early)
            )
            .await
            .is_err());
            node_side
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();
            let mut frame = [0_u8; 6];
            node_side.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, b"frame1");
            node_side.write_all(b"frame2").await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\nframe1")
        .await
        .unwrap();
    let mut response = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        client.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
    let mut frame = [0_u8; 6];
    client.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, b"frame2");
    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn rejected_websocket_discards_buffered_bytes_before_the_guest_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"rejected-websocket-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let (captured_sender, captured_receiver) = oneshot::channel();
    let captured_sender = Arc::new(Mutex::new(Some(captured_sender)));
    let connector: TunnelConnector = Arc::new(move |_| {
        let captured_sender = Arc::clone(&captured_sender);
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let expected = b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
            let mut head = vec![0_u8; expected.len()];
            node_side.read_exact(&mut head).await.unwrap();
            assert_eq!(head, expected);
            node_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .ok();
            node_side.shutdown().await.ok();
            let mut leaked = Vec::new();
            node_side.read_to_end(&mut leaked).await.unwrap();
            captured_sender
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(leaked)
                .unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(250),
        client.read_to_end(&mut response),
    )
    .await
    .expect("rejected WebSocket did not close the public connection")
    .unwrap();

    assert!(response.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(250), captured_receiver)
            .await
            .expect("rejected WebSocket did not close the Node tunnel")
            .unwrap()
            .is_empty()
    );
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn malformed_websocket_101_never_commits_raw_mode_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"malformed-websocket-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let (captured_sender, captured_receiver) = oneshot::channel();
    let captured_sender = Arc::new(Mutex::new(Some(captured_sender)));
    let connector: TunnelConnector = Arc::new(move |_| {
        let captured_sender = Arc::clone(&captured_sender);
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let expected = b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
            let mut head = vec![0_u8; expected.len()];
            node_side.read_exact(&mut head).await.unwrap();
            assert_eq!(head, expected);
            // Missing `Connection: Upgrade` must not authorize raw mode.
            node_side
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                .await
                .ok();
            node_side.shutdown().await.ok();
            let mut leaked = Vec::new();
            node_side.read_to_end(&mut leaked).await.unwrap();
            captured_sender
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(leaked)
                .unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nframe1")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(250),
        client.read_to_end(&mut response),
    )
    .await
    .expect("malformed 101 did not close the public connection")
    .unwrap();

    assert!(response.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(250), captured_receiver)
            .await
            .expect("malformed 101 did not close the Node tunnel")
            .unwrap()
            .is_empty()
    );
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn content_length_response_never_forwards_a_second_response_frame_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"response-boundary-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_call = Arc::clone(&attempts);
    let connector: TunnelConnector = Arc::new(move |_| {
        let attempt = attempts_call.fetch_add(1, Ordering::SeqCst);
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            node_side.read_to_end(&mut request).await.unwrap();
            if attempt == 0 {
                node_side
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil")
                    .await
                    .unwrap();
            } else {
                node_side
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n2")
                    .await
                    .unwrap();
            }
            node_side.shutdown().await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /one HTTP/1.1\r\nHost: one.cats.run\r\n\r\nGET /two HTTP/1.1\r\nHost: two.cats.run\r\n\r\n")
        .await
        .unwrap();
    let expected = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let mut response = vec![0_u8; expected.len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, expected);
    let mut extra = Vec::new();
    client.read_to_end(&mut extra).await.unwrap();
    assert!(extra.is_empty());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn chunked_response_is_self_delimited_before_the_next_host_request_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"chunked-response-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let admitted_hosts = Arc::new(Mutex::new(Vec::new()));
    let admitted_hosts_call = Arc::clone(&admitted_hosts);
    let connector: TunnelConnector = Arc::new(move |route| {
        let hostname = route.hostname().as_str().to_owned();
        admitted_hosts_call.lock().unwrap().push(hostname);
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            node_side.read_to_end(&mut request).await.unwrap();
            for fragment in [
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n4\r"
                    .as_slice(),
                b"\ndata\r\n0\r\nX-End: yes\r".as_slice(),
                b"\n\r\n".as_slice(),
            ] {
                node_side.write_all(fragment).await.unwrap();
                tokio::task::yield_now().await;
            }
            node_side.shutdown().await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /one HTTP/1.1\r\nHost: one.cats.run\r\n\r\nGET /two HTTP/1.1\r\nHost: two.cats.run\r\n\r\n")
        .await
        .unwrap();
    let expected = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n4\r\ndata\r\n0\r\nX-End: yes\r\n\r\n";
    for _ in 0..2 {
        let mut response = vec![0_u8; expected.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected);
    }
    assert_eq!(
        *admitted_hosts.lock().unwrap(),
        ["one.cats.run".to_owned(), "two.cats.run".to_owned()]
    );

    drop(client);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn close_delimited_and_connection_close_responses_close_public_connection_case() {
    for response in [
        b"HTTP/1.1 200 OK\r\n\r\nbody".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody".as_slice(),
    ] {
        let resolver: RouteResolver = Arc::new(move |hostname| {
            let route = route(hostname, b"closing-response-grant");
            Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
        });
        let cache = RouteCache::new(cache_config(), resolver).unwrap();
        let connector: TunnelConnector = Arc::new(move |_| {
            let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
            tokio::spawn(async move {
                let mut request = Vec::new();
                node_side.read_to_end(&mut request).await.unwrap();
                node_side.write_all(response).await.unwrap();
                node_side.shutdown().await.unwrap();
            });
            Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) })
                as TunnelFuture
        });
        let (address, shutdown, server) = spawn_gateway(cache, connector).await;

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.cats.run\r\n\r\n")
            .await
            .unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(
            Duration::from_millis(250),
            client.read_to_end(&mut received),
        )
        .await
        .expect("Gateway did not close a non-reusable response")
        .unwrap();
        assert_eq!(received, response);

        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}

async fn public_disconnect_drops_silent_tunnel_and_releases_connection_slot_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"disconnect-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_call = Arc::clone(&attempts);
    let (first_dropped_sender, first_dropped_receiver) = oneshot::channel();
    let first_dropped_sender = Arc::new(Mutex::new(Some(first_dropped_sender)));
    let connector: TunnelConnector = Arc::new(move |_| {
        let attempt = attempts_call.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            let dropped = first_dropped_sender.lock().unwrap().take().unwrap();
            return Box::pin(async move {
                Ok(Box::new(SilentTunnel {
                    dropped: Some(dropped),
                }) as BoxedGatewayTunnel)
            }) as TunnelFuture;
        }
        let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            node_side.read_to_end(&mut request).await.unwrap();
            node_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            node_side.shutdown().await.unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let config = GatewayIngressConfig {
        max_public_connections: 1,
        shutdown_drain_deadline: Duration::from_millis(250),
        ..GatewayIngressConfig::default()
    };
    let (address, shutdown, server) = spawn_gateway_with_config(cache, connector, config).await;

    let mut abandoned = TcpStream::connect(address).await.unwrap();
    abandoned
        .write_all(b"GET /silent HTTP/1.1\r\nHost: one.cats.run\r\n\r\n")
        .await
        .unwrap();
    while attempts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    drop(abandoned);
    tokio::time::timeout(Duration::from_millis(250), first_dropped_receiver)
        .await
        .expect("public disconnect did not drop the Node tunnel")
        .unwrap();

    let mut next = TcpStream::connect(address).await.unwrap();
    next.write_all(b"GET / HTTP/1.1\r\nHost: two.cats.run\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_millis(250), next.read_to_end(&mut response))
        .await
        .expect("released connection slot did not admit the next client")
        .unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    );

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn public_disconnect_cancels_a_blocked_cache_waiter_before_tunnel_authority_case() {
    let (started_sender, started_receiver) = oneshot::channel();
    let started_sender = Arc::new(Mutex::new(Some(started_sender)));
    let resolver: RouteResolver = Arc::new(move |_| {
        let started = started_sender.lock().unwrap().take().unwrap();
        Box::pin(async move {
            let _ = started.send(());
            std::future::pending().await
        }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let connector_calls = Arc::new(AtomicUsize::new(0));
    let connector_calls_for_closure = Arc::clone(&connector_calls);
    let connector: TunnelConnector = Arc::new(move |_| {
        connector_calls_for_closure.fetch_add(1, Ordering::SeqCst);
        let (gateway_side, _) = tokio::io::duplex(64);
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let config = GatewayIngressConfig {
        max_public_connections: 1,
        shutdown_drain_deadline: Duration::from_millis(250),
        ..GatewayIngressConfig::default()
    };
    let (address, shutdown, server) = spawn_gateway_with_config(cache, connector, config).await;

    let mut abandoned = TcpStream::connect(address).await.unwrap();
    abandoned
        .write_all(b"POST /mutate HTTP/1.1\r\nHost: one.cats.run\r\nContent-Length: 4\r\n\r\ndata")
        .await
        .unwrap();
    started_receiver.await.unwrap();
    drop(abandoned);
    assert_health_gets_released_permit(address).await;
    assert_eq!(connector_calls.load(Ordering::SeqCst), 0);

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn public_disconnect_cancels_a_blocked_connector_before_tunnel_authority_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"blocked-connector-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let (started_sender, started_receiver) = oneshot::channel();
    let started_sender = Arc::new(Mutex::new(Some(started_sender)));
    let (dropped_sender, dropped_receiver) = oneshot::channel();
    let dropped_sender = Arc::new(Mutex::new(Some(dropped_sender)));
    let connector: TunnelConnector = Arc::new(move |_| {
        let _ = started_sender.lock().unwrap().take().unwrap().send(());
        let dropped = dropped_sender.lock().unwrap().take().unwrap();
        Box::pin(async move {
            let _drop_signal = DropSignal(Some(dropped));
            std::future::pending::<Result<BoxedGatewayTunnel, GatewayNodeRouteV2Error>>().await
        }) as TunnelFuture
    });
    let config = GatewayIngressConfig {
        max_public_connections: 1,
        shutdown_drain_deadline: Duration::from_millis(250),
        ..GatewayIngressConfig::default()
    };
    let (address, shutdown, server) = spawn_gateway_with_config(cache, connector, config).await;

    let mut abandoned = TcpStream::connect(address).await.unwrap();
    abandoned
        .write_all(b"POST /mutate HTTP/1.1\r\nHost: one.cats.run\r\nContent-Length: 4\r\n\r\ndata")
        .await
        .unwrap();
    started_receiver.await.unwrap();
    drop(abandoned);
    tokio::time::timeout(Duration::from_millis(250), dropped_receiver)
        .await
        .expect("public disconnect did not cancel the connector future")
        .unwrap();
    assert_health_gets_released_permit(address).await;

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn public_pipeline_overflow_cancels_a_blocked_connector_and_releases_its_slot_case() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"overflow-connector-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let (started_sender, started_receiver) = oneshot::channel();
    let started_sender = Arc::new(Mutex::new(Some(started_sender)));
    let (dropped_sender, dropped_receiver) = oneshot::channel();
    let dropped_sender = Arc::new(Mutex::new(Some(dropped_sender)));
    let connector: TunnelConnector = Arc::new(move |_| {
        let _ = started_sender.lock().unwrap().take().unwrap().send(());
        let dropped = dropped_sender.lock().unwrap().take().unwrap();
        Box::pin(async move {
            let _drop_signal = DropSignal(Some(dropped));
            std::future::pending::<Result<BoxedGatewayTunnel, GatewayNodeRouteV2Error>>().await
        }) as TunnelFuture
    });
    let config = GatewayIngressConfig {
        max_public_connections: 1,
        max_public_request_head_bytes: 128,
        shutdown_drain_deadline: Duration::from_millis(250),
        ..GatewayIngressConfig::default()
    };
    let (address, shutdown, server) = spawn_gateway_with_config(cache, connector, config).await;

    let mut attacker = TcpStream::connect(address).await.unwrap();
    attacker
        .write_all(b"POST /mutate HTTP/1.1\r\nHost: one.cats.run\r\nContent-Length: 129\r\n\r\n")
        .await
        .unwrap();
    started_receiver.await.unwrap();
    attacker.write_all(&[b'x'; 129]).await.unwrap();
    tokio::time::timeout(Duration::from_millis(250), dropped_receiver)
        .await
        .expect("bounded public overflow did not cancel the connector future")
        .unwrap();
    assert_health_gets_released_permit(address).await;

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn public_disconnect_cancels_each_blocked_tunnel_write_stage_case() {
    const REQUEST_HEAD: &[u8] =
        b"POST /mutate HTTP/1.1\r\nHost: one.cats.run\r\nContent-Length: 4\r\n\r\n";
    for stage in [
        BlockStage::HeadWrite,
        BlockStage::BodyWrite,
        BlockStage::Shutdown,
    ] {
        let resolver: RouteResolver = Arc::new(move |hostname| {
            let route = route(hostname, b"blocked-write-grant");
            Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
        });
        let cache = RouteCache::new(cache_config(), resolver).unwrap();
        let written = Arc::new(Mutex::new(Vec::new()));
        let written_call = Arc::clone(&written);
        let (blocked_sender, blocked_receiver) = oneshot::channel();
        let blocked_sender = Arc::new(Mutex::new(Some(blocked_sender)));
        let (dropped_sender, dropped_receiver) = oneshot::channel();
        let dropped_sender = Arc::new(Mutex::new(Some(dropped_sender)));
        let connector: TunnelConnector = Arc::new(move |_| {
            let tunnel = BlockingStageTunnel {
                stage,
                written: Arc::clone(&written_call),
                blocked: blocked_sender.lock().unwrap().take(),
                dropped: dropped_sender.lock().unwrap().take(),
            };
            Box::pin(async move { Ok(Box::new(tunnel) as BoxedGatewayTunnel) }) as TunnelFuture
        });
        let config = GatewayIngressConfig {
            max_public_connections: 1,
            shutdown_drain_deadline: Duration::from_millis(250),
            ..GatewayIngressConfig::default()
        };
        let (address, shutdown, server) = spawn_gateway_with_config(cache, connector, config).await;

        let mut abandoned = TcpStream::connect(address).await.unwrap();
        let mut request = REQUEST_HEAD.to_vec();
        request.extend_from_slice(b"data");
        abandoned.write_all(&request).await.unwrap();
        tokio::time::timeout(Duration::from_millis(250), blocked_receiver)
            .await
            .expect("Gateway did not reach the selected blocked tunnel stage")
            .unwrap();
        drop(abandoned);
        tokio::time::timeout(Duration::from_millis(250), dropped_receiver)
            .await
            .expect("public disconnect did not drop the blocked tunnel")
            .unwrap();

        let expected: &[u8] = match stage {
            BlockStage::HeadWrite => b"",
            BlockStage::BodyWrite => REQUEST_HEAD,
            BlockStage::Shutdown => &request,
        };
        assert_eq!(*written.lock().unwrap(), expected);
        assert_health_gets_released_permit(address).await;

        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}

async fn run_blocked_public_egress_case(stage: PublicEgressStage, disconnect: bool) {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"blocked-public-egress-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let (response, notify_after, request, max_head_bytes) = flooding_response(stage);
    let (started_sender, started_receiver) = oneshot::channel();
    let started_sender = Arc::new(Mutex::new(Some(started_sender)));
    let (dropped_sender, dropped_receiver) = oneshot::channel();
    let dropped_sender = Arc::new(Mutex::new(Some(dropped_sender)));
    let response = Arc::new(response);
    let connector: TunnelConnector = Arc::new(move |_| {
        let tunnel = FloodingResponseTunnel {
            response: response.as_ref().clone(),
            offset: 0,
            notify_after,
            egress_started: started_sender.lock().unwrap().take(),
            dropped: dropped_sender.lock().unwrap().take(),
        };
        Box::pin(async move { Ok(Box::new(tunnel) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let config = GatewayIngressConfig {
        max_public_connections: 1,
        max_public_request_head_bytes: max_head_bytes,
        public_egress_deadline: Duration::from_millis(100),
        shutdown_drain_deadline: Duration::from_millis(250),
        ..GatewayIngressConfig::default()
    };
    let (address, shutdown, server) = spawn_gateway_with_config(cache, connector, config).await;

    let mut abandoned = Some(TcpStream::connect(address).await.unwrap());
    abandoned
        .as_mut()
        .unwrap()
        .write_all(request)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), started_receiver)
        .await
        .unwrap_or_else(|_| panic!("{stage:?}: Gateway never began the selected public egress"))
        .unwrap();
    if disconnect {
        drop(abandoned.take());
    }
    tokio::time::timeout(Duration::from_secs(1), dropped_receiver)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{stage:?}: {} did not drop the Node tunnel",
                if disconnect {
                    "public EOF"
                } else {
                    "absolute public-egress deadline"
                }
            )
        })
        .unwrap();
    if !disconnect {
        drop(abandoned.take());
    }
    assert_health_gets_released_permit(address).await;

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn public_eof_cancels_blocked_http_and_websocket_egress_case() {
    for stage in [
        PublicEgressStage::HttpHead,
        PublicEgressStage::HttpBody,
        PublicEgressStage::WebSocketRaw,
    ] {
        run_blocked_public_egress_case(stage, true).await;
    }
}

async fn absolute_egress_deadline_cancels_nonreading_http_and_websocket_peers_case() {
    for stage in [
        PublicEgressStage::HttpHead,
        PublicEgressStage::HttpBody,
        PublicEgressStage::WebSocketRaw,
    ] {
        run_blocked_public_egress_case(stage, false).await;
    }
}

async fn assert_health_gets_released_permit(address: std::net::SocketAddr) {
    let mut next = TcpStream::connect(address).await.unwrap();
    next.write_all(b"GET /healthz HTTP/1.1\r\nHost: alb.internal\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_millis(250), next.read_to_end(&mut response))
        .await
        .expect("released connection slot did not admit health probe")
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

async fn response_socket_matrix_keeps_no_body_and_ambiguous_frames_closed_case() {
    struct Case {
        request: &'static [u8],
        upstream: &'static [u8],
        expected: &'static [u8],
    }
    for case in [
        Case {
            request: b"HEAD / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
            upstream: b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n",
            expected: b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n",
        },
        Case {
            request: b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
            upstream: b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n",
            expected: b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n",
        },
        Case {
            request: b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
            upstream: b"HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n",
            expected: b"HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n",
        },
        Case {
            request: b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
            upstream: b"HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            expected: b"",
        },
        Case {
            request: b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
            upstream: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            expected: b"",
        },
        Case {
            request: b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
            upstream: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            expected: b"",
        },
        Case {
            request: b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nConnection: close\r\n\r\n",
            upstream: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            expected: b"",
        },
    ] {
        let request_bytes = case.request;
        let upstream_bytes = case.upstream;
        let expected_bytes = case.expected;
        let resolver: RouteResolver = Arc::new(move |hostname| {
            let route = route(hostname, b"response-matrix-grant");
            Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
        });
        let cache = RouteCache::new(cache_config(), resolver).unwrap();
        let connector: TunnelConnector = Arc::new(move |_| {
            let (gateway_side, mut node_side) = tokio::io::duplex(16 * 1024);
            tokio::spawn(async move {
                let mut request = Vec::new();
                node_side.read_to_end(&mut request).await.unwrap();
                node_side.write_all(upstream_bytes).await.ok();
                node_side.shutdown().await.ok();
            });
            Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
        });
        let (address, shutdown, server) = spawn_gateway(cache, connector).await;

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request_bytes).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_millis(250), client.read_to_end(&mut response))
            .await
            .expect("response matrix connection did not close")
            .unwrap();
        assert_eq!(response, expected_bytes);

        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}

async fn guard_acquired_failure_never_refreshes_the_route_case() {
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_call = Arc::clone(&resolve_calls);
    let resolver: RouteResolver = Arc::new(move |hostname| {
        resolve_calls_call.fetch_add(1, Ordering::SeqCst);
        let route = route(hostname, b"current-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let connector: TunnelConnector = Arc::new(move |_| {
        Box::pin(async {
            Err(GatewayNodeRouteV2Error::Admission(
                RouteAdmissionV2Failure::upstream_unavailable(),
            ))
        }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"POST /mutate HTTP/1.1\r\nHost: app.cats.run\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn duplicate_host_is_rejected_before_cache_or_tunnel_authority_case() {
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_call = Arc::clone(&resolve_calls);
    let resolver: RouteResolver = Arc::new(move |_| {
        resolve_calls_call.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(cats_network::route_v2::ResolveFailure::InvalidAuthority) })
            as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let connector: TunnelConnector =
        Arc::new(|_| Box::pin(async { Err(GatewayNodeRouteV2Error::Protocol) }) as TunnelFuture);
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: app.cats.run\r\nHost: other.cats.run\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

async fn zero_public_egress_deadline_is_rejected_at_startup_case() {
    let resolver: RouteResolver = Arc::new(|_| {
        Box::pin(async { Err(cats_network::route_v2::ResolveFailure::InvalidAuthority) })
            as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let connector: TunnelConnector =
        Arc::new(|_| Box::pin(async { Err(GatewayNodeRouteV2Error::Protocol) }) as TunnelFuture);
    let config = GatewayIngressConfig {
        public_egress_deadline: Duration::ZERO,
        ..GatewayIngressConfig::default()
    };

    assert!(GatewayIngress::new(config, cache, connector).is_err());
}

const PRODUCTION_GATEWAY_CASE_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Clone, Copy)]
struct ProductionGatewayCaseContext {
    case: &'static str,
    deadline: Instant,
}

tokio::task_local! {
    static PRODUCTION_GATEWAY_CASE: ProductionGatewayCaseContext;
}

async fn await_production_gateway_stage<T>(
    stage: impl std::fmt::Display,
    future: impl std::future::Future<Output = T>,
) -> T {
    let context = PRODUCTION_GATEWAY_CASE.with(|context| *context);
    tokio::time::timeout_at(context.deadline, future)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "production_gateway case={} stage={} exceeded its absolute total deadline",
                context.case, stage
            )
        })
}

async fn run_production_gateway_case(
    case: &'static str,
    future: impl std::future::Future<Output = ()>,
) {
    let deadline = Instant::now()
        .checked_add(PRODUCTION_GATEWAY_CASE_DEADLINE)
        .expect("fixed production Gateway test deadline fits");
    let context = ProductionGatewayCaseContext { case, deadline };
    tokio::time::timeout_at(deadline, PRODUCTION_GATEWAY_CASE.scope(context, future))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "production_gateway case={case} stage=total-e2e exceeded absolute {}s deadline",
                PRODUCTION_GATEWAY_CASE_DEADLINE.as_secs()
            )
        });
}

macro_rules! bounded_production_gateway_tests {
    ($( $test:ident => $case:ident ),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $test() {
                run_production_gateway_case(stringify!($test), $case()).await;
            }
        )+
    };
}

bounded_production_gateway_tests!(
    exact_local_health_is_the_only_request_that_bypasses_route_authority =>
        exact_local_health_is_the_only_request_that_bypasses_route_authority_case,
    public_http_bytes_cross_one_route_lookup_and_one_node_tunnel =>
        public_http_bytes_cross_one_route_lookup_and_one_node_tunnel_case,
    keep_alive_requests_with_different_hosts_get_distinct_tunnels =>
        keep_alive_requests_with_different_hosts_get_distinct_tunnels_case,
    chunked_http_body_and_trailer_stay_on_one_request_tunnel =>
        chunked_http_body_and_trailer_stay_on_one_request_tunnel_case,
    split_chunked_body_retains_pipelined_next_host_for_a_distinct_tunnel =>
        split_chunked_body_retains_pipelined_next_host_for_a_distinct_tunnel_case,
    ambiguous_transfer_framing_is_rejected_before_route_authority =>
        ambiguous_transfer_framing_is_rejected_before_route_authority_case,
    malformed_chunk_framing_never_forwards_smuggled_request_bytes =>
        malformed_chunk_framing_never_forwards_smuggled_request_bytes_case,
    authenticated_stale_rejection_refreshes_only_for_a_later_request =>
        authenticated_stale_rejection_refreshes_only_for_a_later_request_case,
    websocket_upgrade_and_frames_remain_raw_on_the_one_admitted_tunnel =>
        websocket_upgrade_and_frames_remain_raw_on_the_one_admitted_tunnel_case,
    rejected_websocket_discards_buffered_bytes_before_the_guest =>
        rejected_websocket_discards_buffered_bytes_before_the_guest_case,
    malformed_websocket_101_never_commits_raw_mode =>
        malformed_websocket_101_never_commits_raw_mode_case,
    content_length_response_never_forwards_a_second_response_frame =>
        content_length_response_never_forwards_a_second_response_frame_case,
    chunked_response_is_self_delimited_before_the_next_host_request =>
        chunked_response_is_self_delimited_before_the_next_host_request_case,
    close_delimited_and_connection_close_responses_close_public_connection =>
        close_delimited_and_connection_close_responses_close_public_connection_case,
    public_disconnect_drops_silent_tunnel_and_releases_connection_slot =>
        public_disconnect_drops_silent_tunnel_and_releases_connection_slot_case,
    public_disconnect_cancels_a_blocked_cache_waiter_before_tunnel_authority =>
        public_disconnect_cancels_a_blocked_cache_waiter_before_tunnel_authority_case,
    public_disconnect_cancels_a_blocked_connector_before_tunnel_authority =>
        public_disconnect_cancels_a_blocked_connector_before_tunnel_authority_case,
    public_pipeline_overflow_cancels_a_blocked_connector_and_releases_its_slot =>
        public_pipeline_overflow_cancels_a_blocked_connector_and_releases_its_slot_case,
    public_disconnect_cancels_each_blocked_tunnel_write_stage =>
        public_disconnect_cancels_each_blocked_tunnel_write_stage_case,
    public_eof_cancels_blocked_http_and_websocket_egress =>
        public_eof_cancels_blocked_http_and_websocket_egress_case,
    absolute_egress_deadline_cancels_nonreading_http_and_websocket_peers =>
        absolute_egress_deadline_cancels_nonreading_http_and_websocket_peers_case,
    response_socket_matrix_keeps_no_body_and_ambiguous_frames_closed =>
        response_socket_matrix_keeps_no_body_and_ambiguous_frames_closed_case,
    guard_acquired_failure_never_refreshes_the_route =>
        guard_acquired_failure_never_refreshes_the_route_case,
    duplicate_host_is_rejected_before_cache_or_tunnel_authority =>
        duplicate_host_is_rejected_before_cache_or_tunnel_authority_case,
    zero_public_egress_deadline_is_rejected_at_startup =>
        zero_public_egress_deadline_is_rejected_at_startup_case,
);

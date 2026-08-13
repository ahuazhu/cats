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

#[tokio::test]
async fn exact_local_health_is_the_only_request_that_bypasses_route_authority() {
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
        client.shutdown().await.unwrap();
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
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 3);

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn public_http_bytes_cross_one_route_lookup_and_one_node_tunnel() {
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

#[tokio::test]
async fn keep_alive_requests_with_different_hosts_get_distinct_tunnels() {
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

#[tokio::test]
async fn chunked_http_body_and_trailer_stay_on_one_request_tunnel() {
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

#[tokio::test]
async fn split_chunked_body_retains_pipelined_next_host_for_a_distinct_tunnel() {
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

#[tokio::test]
async fn ambiguous_transfer_framing_is_rejected_before_route_authority() {
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
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }

    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn malformed_chunk_framing_never_forwards_smuggled_request_bytes() {
    let resolver: RouteResolver = Arc::new(move |hostname| {
        let route = route(hostname, b"malformed-chunk-grant");
        Box::pin(async move { Ok(RouteResolution::Positive(route)) }) as ResolveFuture
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let (captured_sender, mut captured_receiver) = tokio::sync::mpsc::unbounded_channel();
    let connector: TunnelConnector = Arc::new(move |_| {
        let captured_sender = captured_sender.clone();
        let (gateway_side, mut node_side) = tokio::io::duplex(128 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            node_side.read_to_end(&mut request).await.unwrap();
            captured_sender.send(request).unwrap();
        });
        Box::pin(async move { Ok(Box::new(gateway_side) as BoxedGatewayTunnel) }) as TunnelFuture
    });
    let (address, shutdown, server) = spawn_gateway(cache, connector).await;

    let common = b"POST / HTTP/1.1\r\nHost: app.cats.run\r\nTransfer-Encoding: chunked\r\n\r\n";
    let oversized_trailer = format!(
        "0\r\nX-Large: {}\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n",
        "x".repeat(33 * 1024)
    );
    for malformed in [
        b"4;extension=yes\r\ndata\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
        b"10000000000000000\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
        b"1\r\naXGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
        b"0\r\n".to_vec(),
        b"0\r\nHost: other.cats.run\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.cats.run\r\n\r\n".to_vec(),
        oversized_trailer.into_bytes(),
    ] {
        let mut request = common.to_vec();
        request.extend_from_slice(&malformed);
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());

        let captured = captured_receiver.recv().await.unwrap();
        assert!(captured.starts_with(common));
        assert!(!captured
            .windows(b"GET /smuggled".len())
            .any(|window| window == b"GET /smuggled"));
    }

    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn authenticated_stale_rejection_refreshes_only_for_a_later_request() {
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
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert_eq!(tunnel_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 2);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn websocket_upgrade_and_frames_remain_raw_on_the_one_admitted_tunnel() {
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

#[tokio::test]
async fn rejected_websocket_discards_buffered_bytes_before_the_guest() {
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
    client.shutdown().await.unwrap();
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

#[tokio::test]
async fn malformed_websocket_101_never_commits_raw_mode() {
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
    client.shutdown().await.unwrap();
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

#[tokio::test]
async fn content_length_response_never_forwards_a_second_response_frame() {
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

#[tokio::test]
async fn chunked_response_is_self_delimited_before_the_next_host_request() {
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

#[tokio::test]
async fn close_delimited_and_connection_close_responses_close_public_connection() {
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

#[tokio::test]
async fn public_disconnect_drops_silent_tunnel_and_releases_connection_slot() {
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

#[tokio::test]
async fn guard_acquired_failure_never_refreshes_the_route() {
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
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn duplicate_host_is_rejected_before_cache_or_tunnel_authority() {
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
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

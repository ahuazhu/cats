use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cats_api::route_grant_v2::{RouteAdmissionV2Failure, RouteAdmissionV2Reason};
use cats_api::runtime_reconciliation::{Hostname, Id, NodeTransportTarget};
use cats_network::route_v2::{
    AuthenticatedResolveEnvelope, BoxedGatewayTunnel, GatewayIngress, GatewayIngressConfig,
    GatewayNodeRouteV2Error, GrantDigest, ResolveFuture, RouteCache, RouteCacheConfig,
    RouteResolution, RouteResolver, TunnelConnector, TunnelFuture,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let gateway = GatewayIngress::new(GatewayIngressConfig::default(), cache, connector).unwrap();
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
        .write_all(b"GET /socket HTTP/1.1\r\nHost: app.cats.run\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n")
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
    client.write_all(b"frame1").await.unwrap();
    let mut frame = [0_u8; 6];
    client.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, b"frame2");
    drop(client);
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

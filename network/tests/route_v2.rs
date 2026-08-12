use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cats_api::route_grant_v2::MAX_ROUTE_GRANT_V2_COMPACT_BYTES;
use cats_api::runtime_reconciliation::{Hostname, Id, NodeTransportTarget};
use cats_network::route_v2::{
    read_bounded_response_body, AuthenticatedResolveEnvelope, CacheLookup, CacheRefreshStatus,
    CurrentRequestDisposition, GrantDigest, NegativeRoute, RefreshableRejection, RequestKind,
    ResolveEnvelopeError, ResolveFailure, ResolveFuture, ResolvedRoute, ResponseBodyBounds,
    ResponseReadError, RouteCache, RouteCacheConfig, RouteCacheError, RouteResolution,
    RouteResolver,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;

fn hostname() -> Hostname {
    Hostname::new("app.cats.run").unwrap()
}

fn grant_digest(grant: &[u8]) -> GrantDigest {
    GrantDigest::from_bytes(Sha256::digest(grant).into())
}

fn envelope(opaque_grant: Vec<u8>, expires_at_unix_seconds: u64) -> AuthenticatedResolveEnvelope {
    let response_bytes = opaque_grant.len() + 256;
    let digest = grant_digest(&opaque_grant);
    AuthenticatedResolveEnvelope::from_authenticated_transport(
        Id::new("cat_01").unwrap(),
        Id::new("ep_01").unwrap(),
        NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
        expires_at_unix_seconds,
        opaque_grant,
        digest,
        response_bytes,
    )
}

fn resolved_route(opaque_grant: &[u8], now_unix_seconds: u64) -> ResolvedRoute {
    envelope(opaque_grant.to_vec(), now_unix_seconds + 120)
        .validate_for_hostname(&hostname(), now_unix_seconds, Instant::now())
        .unwrap()
}

#[test]
fn authenticated_envelope_validates_metadata_without_parsing_the_opaque_grant() {
    let now = 1_786_156_800;
    let deliberately_non_jws_bytes =
        vec![0xff, 0x00, b'.', b'n', b'o', b't', b'-', b'j', b'w', b's'];
    let route = envelope(deliberately_non_jws_bytes.clone(), now + 120)
        .validate_for_hostname(&hostname(), now, Instant::now())
        .unwrap();
    assert_eq!(route.opaque_grant(), deliberately_non_jws_bytes);
    assert_eq!(route.endpoint_id().as_str(), "ep_01");
    assert_eq!(
        route.node_transport_target().as_str(),
        "https://node-a.internal:7301"
    );
    assert_eq!(route.expires_at_unix_seconds(), now + 120);

    assert_eq!(
        envelope(b"opaque".to_vec(), now)
            .validate_for_hostname(&hostname(), now, Instant::now())
            .unwrap_err(),
        ResolveEnvelopeError::Expired
    );
    assert_eq!(
        envelope(b"opaque".to_vec(), now + 306)
            .validate_for_hostname(&hostname(), now, Instant::now())
            .unwrap_err(),
        ResolveEnvelopeError::ExpiryTooFar
    );
    let wrong_digest = AuthenticatedResolveEnvelope::from_authenticated_transport(
        Id::new("cat_01").unwrap(),
        Id::new("ep_01").unwrap(),
        NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
        now + 120,
        b"opaque".to_vec(),
        GrantDigest::from_bytes([0x55; 32]),
        512,
    );
    assert_eq!(
        wrong_digest
            .validate_for_hostname(&hostname(), now, Instant::now())
            .unwrap_err(),
        ResolveEnvelopeError::GrantDigestMismatch
    );
    assert_eq!(
        envelope(Vec::new(), now + 120)
            .validate_for_hostname(&hostname(), now, Instant::now())
            .unwrap_err(),
        ResolveEnvelopeError::EmptyOpaqueGrant
    );
    let invalid_size = AuthenticatedResolveEnvelope::from_authenticated_transport(
        Id::new("cat_01").unwrap(),
        Id::new("ep_01").unwrap(),
        NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
        now + 120,
        b"opaque".to_vec(),
        grant_digest(b"opaque"),
        b"opaque".len() - 1,
    );
    assert_eq!(
        invalid_size
            .validate_for_hostname(&hostname(), now, Instant::now())
            .unwrap_err(),
        ResolveEnvelopeError::InvalidResponseSize
    );
    let oversized = vec![b'x'; MAX_ROUTE_GRANT_V2_COMPACT_BYTES + 1];
    assert_eq!(
        envelope(oversized, now + 120)
            .validate_for_hostname(&hostname(), now, Instant::now())
            .unwrap_err(),
        ResolveEnvelopeError::OpaqueGrantTooLarge
    );
    assert!(NodeTransportTarget::new("https://127.0.0.1:7301").is_none());
    assert!(NodeTransportTarget::new("https://node-a.internal:7301/path").is_none());
}

fn cache_config() -> RouteCacheConfig {
    RouteCacheConfig {
        max_entries: 16,
        max_bytes: 16 * 1024,
        max_entry_bytes: 8 * 1024,
        max_resolve_response_bytes: 7 * 1024,
        max_waiters_per_hostname: 16,
        max_concurrent_resolves: 4,
        resolve_timeout: Duration::from_secs(1),
        negative_ttl: Duration::from_millis(30),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(100),
    }
}

#[test]
fn cache_constructor_accepts_semaphore_max_and_rejects_max_plus_one() {
    let resolver: RouteResolver =
        Arc::new(|_| Box::pin(async { Err(ResolveFailure::Unavailable) }) as ResolveFuture);
    let mut at_limit = cache_config();
    at_limit.max_concurrent_resolves = tokio::sync::Semaphore::MAX_PERMITS;
    let cache = RouteCache::new(at_limit, resolver.clone()).unwrap();
    assert_eq!(
        cache.stats().available_resolve_slots,
        tokio::sync::Semaphore::MAX_PERMITS
    );

    let mut above_limit = cache_config();
    above_limit.max_concurrent_resolves = tokio::sync::Semaphore::MAX_PERMITS
        .checked_add(1)
        .expect("Tokio semaphore maximum leaves room for the invalid boundary");
    let error = match RouteCache::new(above_limit, resolver) {
        Ok(_) => panic!("constructor accepted more than Semaphore::MAX_PERMITS"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        RouteCacheError::InvalidConfig(
            "max_concurrent_resolves exceeds the resolve semaphore capacity"
        )
    );
}

#[tokio::test]
async fn cancelled_lookup_leader_does_not_cancel_the_singleflight() {
    let now = 1_786_156_800;
    let route = resolved_route(b"opaque-grant", now);
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let resolver: RouteResolver = {
        let calls = calls.clone();
        let started = started.clone();
        let release = release.clone();
        Arc::new(move |_| {
            let calls = calls.clone();
            let started = started.clone();
            let release = release.clone();
            let route = route.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                started.notify_waiters();
                release.notified().await;
                Ok(RouteResolution::Positive(route))
            })
        })
    };
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let leader_cache = cache.clone();
    let leader = tokio::spawn(async move { leader_cache.lookup("app.cats.run").await });
    while calls.load(Ordering::SeqCst) == 0 {
        started.notified().await;
    }
    let follower_cache = cache.clone();
    let follower = tokio::spawn(async move { follower_cache.lookup("app.cats.run").await });
    leader.abort();
    release.notify_one();
    assert!(matches!(
        follower.await.unwrap().unwrap(),
        CacheLookup::Positive(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.stats().in_flight_keys, 0);
}

#[tokio::test]
async fn shutdown_cancels_resolver_and_fails_all_waiters_closed() {
    struct CancelOnDrop(Option<oneshot::Sender<()>>);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            if let Some(cancelled) = self.0.take() {
                let _ = cancelled.send(());
            }
        }
    }

    let started = Arc::new(Notify::new());
    let (cancelled_tx, cancelled_rx) = oneshot::channel();
    let cancelled_tx = Arc::new(std::sync::Mutex::new(Some(cancelled_tx)));
    let resolver: RouteResolver = {
        let started = started.clone();
        Arc::new(move |_| {
            let started = started.clone();
            let cancelled = cancelled_tx.lock().unwrap().take();
            Box::pin(async move {
                let _cancel = CancelOnDrop(cancelled);
                started.notify_waiters();
                std::future::pending::<Result<RouteResolution, ResolveFailure>>().await
            })
        })
    };
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let lookup_cache = cache.clone();
    let lookup = tokio::spawn(async move { lookup_cache.lookup("app.cats.run").await });
    while cache.stats().available_resolve_slots == cache_config().max_concurrent_resolves {
        started.notified().await;
    }
    cache.shutdown();
    assert_eq!(
        lookup.await.unwrap().unwrap_err(),
        RouteCacheError::Shutdown
    );
    tokio::time::timeout(Duration::from_secs(1), cancelled_rx)
        .await
        .expect("resolver future was cancelled")
        .unwrap();
    assert_eq!(
        cache.lookup("app.cats.run").await.unwrap_err(),
        RouteCacheError::Shutdown
    );
    assert_eq!(cache.stats().entries, 0);
}

#[tokio::test]
async fn authoritative_negative_is_cached_without_shared_state() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver: RouteResolver = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(RouteResolution::Negative(NegativeRoute::NotFound)) })
                as ResolveFuture
        })
    };
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    for _ in 0..8 {
        assert_eq!(
            cache.lookup("missing.cats.run").await.unwrap(),
            CacheLookup::Negative(NegativeRoute::NotFound)
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn resolver_cannot_install_a_resolved_route_under_a_different_hostname() {
    let now = 1_786_156_800;
    let route = resolved_route(b"opaque-grant", now);
    let resolver: RouteResolver = Arc::new(move |_| {
        let route = route.clone();
        Box::pin(async move { Ok(RouteResolution::Positive(route)) })
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    assert_eq!(
        cache.lookup("other.cats.run").await.unwrap_err(),
        RouteCacheError::InvalidResponse
    );
    assert_eq!(cache.stats().entries, 0);
}

#[tokio::test]
async fn cache_entry_waiter_and_response_limits_apply_before_more_work_is_admitted() {
    let resolver: RouteResolver = Arc::new(move |_| {
        Box::pin(async { std::future::pending::<Result<RouteResolution, ResolveFailure>>().await })
    });
    let mut bounded_config = cache_config();
    bounded_config.max_entries = 1;
    bounded_config.max_waiters_per_hostname = 1;
    let cache = RouteCache::new(bounded_config, resolver).unwrap();
    let leader_cache = cache.clone();
    let leader = tokio::spawn(async move { leader_cache.lookup("app.cats.run").await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while cache.stats().in_flight_keys == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("leader did not install the in-flight entry");
    let follower_cache = cache.clone();
    let follower = tokio::spawn(async move { follower_cache.lookup("app.cats.run").await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while cache.stats().waiters == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("follower did not register as a bounded waiter");
    assert_eq!(
        cache.lookup("app.cats.run").await.unwrap_err(),
        RouteCacheError::WaiterLimit
    );
    assert_eq!(
        cache.lookup("other.cats.run").await.unwrap_err(),
        RouteCacheError::CapacityExhausted
    );
    cache.shutdown();
    assert_eq!(
        leader.await.unwrap().unwrap_err(),
        RouteCacheError::Shutdown
    );
    assert_eq!(
        follower.await.unwrap().unwrap_err(),
        RouteCacheError::Shutdown
    );

    let now = 1_786_156_800;
    let route = resolved_route(b"opaque-grant", now);
    let resolver: RouteResolver = Arc::new(move |_| {
        let route = route.clone();
        Box::pin(async move { Ok(RouteResolution::Positive(route)) })
    });
    let mut response_bounded_config = cache_config();
    response_bounded_config.max_resolve_response_bytes = 1;
    let response_bounded = RouteCache::new(response_bounded_config, resolver).unwrap();
    assert_eq!(
        response_bounded.lookup("app.cats.run").await.unwrap_err(),
        RouteCacheError::ResponseTooLarge
    );
    assert_eq!(response_bounded.stats().entries, 0);
}

#[tokio::test]
async fn response_loss_fails_closed_and_only_transient_failure_backs_off() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver: RouteResolver = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(ResolveFailure::Unavailable) }) as ResolveFuture
        })
    };
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    assert_eq!(
        cache.lookup("app.cats.run").await.unwrap_err(),
        RouteCacheError::ResolveUnavailable
    );
    assert!(matches!(
        cache.lookup("app.cats.run").await.unwrap_err(),
        RouteCacheError::Backoff { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let invalid_calls = Arc::new(AtomicUsize::new(0));
    let invalid_resolver: RouteResolver = {
        let invalid_calls = invalid_calls.clone();
        Arc::new(move |_| {
            invalid_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(ResolveFailure::InvalidAuthority) }) as ResolveFuture
        })
    };
    let invalid_cache = RouteCache::new(cache_config(), invalid_resolver).unwrap();
    for _ in 0..2 {
        assert_eq!(
            invalid_cache.lookup("app.cats.run").await.unwrap_err(),
            RouteCacheError::ResolveInvalidAuthority
        );
    }
    assert_eq!(invalid_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn resolver_panic_wakes_waiters_and_removes_the_in_flight_entry() {
    let resolver: RouteResolver = Arc::new(|_| -> ResolveFuture {
        panic!("simulated resolver panic before returning its future")
    });
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), cache.lookup("app.cats.run"))
        .await
        .expect("panic must not strand the cache waiter");
    assert_eq!(result.unwrap_err(), RouteCacheError::InFlightLost);
    assert_eq!(cache.stats().in_flight_keys, 0);
}

#[tokio::test]
async fn signer_switch_to_node_acked_kid_needs_no_gateway_ring_update() {
    let now = 1_786_156_800;
    // These are exact opaque bytes from authenticated Control responses. The
    // new signer kid is already ACKed by Node; Gateway has no key-ring update.
    let old_grant = b"protected-kid-old.payload.signature";
    let new_grant = b"protected-kid-new.payload.signature";
    let old_route = resolved_route(old_grant, now);
    let new_route = resolved_route(new_grant, now);
    let old_digest = old_route.grant_digest();
    let new_digest = new_route.grant_digest();
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver: RouteResolver = {
        let calls = calls.clone();
        Arc::new(move |_| {
            let route = if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                old_route.clone()
            } else {
                new_route.clone()
            };
            Box::pin(async move { Ok(RouteResolution::Positive(route)) })
        })
    };
    let cache = RouteCache::new(cache_config(), resolver).unwrap();
    let CacheLookup::Positive(cached_old) = cache.lookup("app.cats.run").await.unwrap() else {
        panic!("expected old positive route")
    };
    assert_eq!(cached_old.opaque_grant(), old_grant);

    let refreshed = cache
        .refresh_for_later(
            RequestKind::Http,
            "app.cats.run",
            old_digest,
            RefreshableRejection::Expired,
        )
        .await;
    assert_eq!(
        refreshed.current_request,
        CurrentRequestDisposition::RejectWithoutReplay
    );
    assert_eq!(refreshed.cache, CacheRefreshStatus::RefreshedPositive);
    assert_eq!(cache.cached_digest("app.cats.run"), Some(new_digest));
    let CacheLookup::Positive(cached_new) = cache.lookup("app.cats.run").await.unwrap() else {
        panic!("expected new positive route")
    };
    assert_eq!(cached_new.opaque_grant(), new_grant);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let delayed_old_rejection = cache
        .refresh_for_later(
            RequestKind::WebSocketUpgrade,
            "app.cats.run",
            old_digest,
            RefreshableRejection::BindingMismatch,
        )
        .await;
    assert_eq!(
        delayed_old_rejection.current_request,
        CurrentRequestDisposition::RejectWithoutReplay
    );
    assert_eq!(
        delayed_old_rejection.cache,
        CacheRefreshStatus::DigestDidNotMatch
    );
    assert_eq!(cache.cached_digest("app.cats.run"), Some(new_digest));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

async fn response_from_parts(
    parts: Vec<Vec<u8>>,
    delay: Duration,
) -> (reqwest::Response, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await;
        for part in parts {
            stream.write_all(&part).await.unwrap();
            tokio::time::sleep(delay).await;
        }
        let _ = stream.shutdown().await;
    });
    let response = reqwest::Client::new()
        .get(format!("http://{address}/resolve"))
        .send()
        .await
        .unwrap();
    (response, task)
}

#[tokio::test]
async fn loopback_chunked_body_is_counted_while_streaming() {
    let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let exact_parts = vec![
        headers.clone(),
        b"4\r\nabcd\r\n".to_vec(),
        b"4\r\nefgh\r\n".to_vec(),
        b"0\r\n\r\n".to_vec(),
    ];
    let (response, server) = response_from_parts(exact_parts, Duration::from_millis(2)).await;
    let body = read_bounded_response_body(
        response,
        ResponseBodyBounds {
            max_body_bytes: 8,
            ..ResponseBodyBounds::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(body, b"abcdefgh");
    server.await.unwrap();

    let oversized_parts = vec![
        headers,
        b"8\r\nabcdefgh\r\n".to_vec(),
        b"1\r\ni\r\n".to_vec(),
        b"0\r\n\r\n".to_vec(),
    ];
    let (response, server) = response_from_parts(oversized_parts, Duration::from_millis(2)).await;
    assert_eq!(
        read_bounded_response_body(
            response,
            ResponseBodyBounds {
                max_body_bytes: 8,
                ..ResponseBodyBounds::default()
            }
        )
        .await
        .unwrap_err(),
        ResponseReadError::BodyTooLarge
    );
    server.abort();
}

#[tokio::test]
async fn loopback_response_headers_and_stream_deadline_are_bounded() {
    let (response, server) = response_from_parts(
        vec![b"HTTP/1.1 200 OK\r\nX-One: 1\r\nX-Two: 2\r\nContent-Length: 0\r\n\r\n".to_vec()],
        Duration::from_millis(1),
    )
    .await;
    assert_eq!(
        read_bounded_response_body(
            response,
            ResponseBodyBounds {
                max_headers: 1,
                ..ResponseBodyBounds::default()
            }
        )
        .await
        .unwrap_err(),
        ResponseReadError::TooManyHeaders
    );
    server.await.unwrap();

    let (response, server) = response_from_parts(
        vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            b"1\r\na\r\n0\r\n\r\n".to_vec(),
        ],
        Duration::from_millis(50),
    )
    .await;
    assert_eq!(
        read_bounded_response_body(
            response,
            ResponseBodyBounds {
                body_deadline: Duration::from_millis(5),
                ..ResponseBodyBounds::default()
            }
        )
        .await
        .unwrap_err(),
        ResponseReadError::BodyDeadline
    );
    server.abort();
}

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cats_api::route_grant_v2::{
    RouteGrantV2Claims, RouteGrantV2ProtectedHeader, RouteGrantV2PublicKey,
    RouteGrantV2SigningInput, ROUTE_GRANT_V2_AUDIENCE, ROUTE_GRANT_V2_ISSUER,
    ROUTE_GRANT_V2_VERSION,
};
use cats_api::runtime_reconciliation::{Epoch, Hostname, HttpProtocol, Id, RandomId128};
use cats_network::route_v2::{
    read_bounded_response_body, AuthenticatedResolveEnvelope, CacheLookup, CacheRefreshStatus,
    CurrentRequestDisposition, NegativeRoute, RefreshableRejection, RequestKind, ResolveFailure,
    ResolveFuture, ResponseBodyBounds, ResponseReadError, RouteCache, RouteCacheConfig,
    RouteCacheError, RouteGrantKeyRing, RouteGrantVerificationError, RouteResolution,
    RouteResolver, VerifiedRoute,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

struct SigningKey {
    pair: Ed25519KeyPair,
    public: RouteGrantV2PublicKey,
}

fn signing_key() -> SigningKey {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(pair.public_key().as_ref());
    let public = RouteGrantV2PublicKey::from_spki_der(&spki).unwrap();
    SigningKey { pair, public }
}

fn claims(now: u64, route_epoch: u64) -> RouteGrantV2Claims {
    RouteGrantV2Claims {
        version: ROUTE_GRANT_V2_VERSION,
        iss: ROUTE_GRANT_V2_ISSUER.to_owned(),
        aud: ROUTE_GRANT_V2_AUDIENCE.to_owned(),
        workspace_id: Id::new("ws_01").unwrap(),
        endpoint_id: Id::new("ep_01").unwrap(),
        hostname: Hostname::new("app.cats.run").unwrap(),
        cat_id: Id::new("cat_01").unwrap(),
        node_id: Id::new("node_a").unwrap(),
        runtime_incarnation: RandomId128::new("11111111111111111111111111111111").unwrap(),
        route_epoch: Epoch::new(route_epoch).unwrap(),
        protocol: HttpProtocol::Http,
        target_port: 8080,
        iat: now,
        nbf: now,
        exp: now + 120,
    }
}

fn sign(key: &SigningKey, claims: &RouteGrantV2Claims) -> String {
    let input = RouteGrantV2SigningInput::new(
        &RouteGrantV2ProtectedHeader::new(key.public.kid().clone()),
        claims,
    )
    .unwrap();
    let signature: [u8; 64] = key.pair.sign(input.as_bytes()).as_ref().try_into().unwrap();
    input.finish(&signature).unwrap()
}

fn envelope(token: String, claims: &RouteGrantV2Claims) -> AuthenticatedResolveEnvelope {
    let response_bytes = token.len() + 256;
    AuthenticatedResolveEnvelope::from_authenticated_transport(
        claims.endpoint_id.as_str(),
        claims.node_id.as_str(),
        "https://node-a.internal:7301",
        token,
        claims.exp,
        response_bytes,
    )
}

fn verify_route(key: &SigningKey, claims: &RouteGrantV2Claims, now: u64) -> VerifiedRoute {
    let ring =
        RouteGrantKeyRing::from_public_keys(Epoch::new(1).unwrap(), [key.public.clone()]).unwrap();
    ring.verify(
        &claims.hostname,
        envelope(sign(key, claims), claims),
        now,
        Instant::now(),
    )
    .unwrap()
}

#[test]
fn verifier_first_rotation_accepts_overlap_then_retires_the_old_key() {
    let now = 1_786_156_800;
    let old = signing_key();
    let new = signing_key();
    let old_claims = claims(now, 7);
    let new_claims = claims(now, 8);
    let old_envelope = envelope(sign(&old, &old_claims), &old_claims);
    let new_envelope = envelope(sign(&new, &new_claims), &new_claims);

    let old_only =
        RouteGrantKeyRing::from_public_keys(Epoch::new(1).unwrap(), [old.public.clone()]).unwrap();
    assert!(old_only
        .verify(
            &old_claims.hostname,
            old_envelope.clone(),
            now,
            Instant::now()
        )
        .is_ok());

    let overlap = RouteGrantKeyRing::from_public_keys(
        Epoch::new(2).unwrap(),
        [old.public.clone(), new.public.clone()],
    )
    .unwrap();
    assert!(overlap
        .verify(
            &old_claims.hostname,
            old_envelope.clone(),
            now,
            Instant::now()
        )
        .is_ok());
    assert!(overlap
        .verify(
            &new_claims.hostname,
            new_envelope.clone(),
            now,
            Instant::now()
        )
        .is_ok());

    let new_only =
        RouteGrantKeyRing::from_public_keys(Epoch::new(3).unwrap(), [new.public.clone()]).unwrap();
    assert_eq!(
        new_only
            .verify(&old_claims.hostname, old_envelope, now, Instant::now())
            .unwrap_err(),
        RouteGrantVerificationError::UnknownKey
    );
    assert!(new_only
        .verify(&new_claims.hostname, new_envelope, now, Instant::now())
        .is_ok());
}

#[test]
fn expired_grant_invalid_https_target_and_wrong_placement_fail_before_caching() {
    let now = 1_786_156_800;
    let key = signing_key();
    let ring =
        RouteGrantKeyRing::from_public_keys(Epoch::new(1).unwrap(), [key.public.clone()]).unwrap();

    let mut expired = claims(now - 121, 7);
    expired.exp = now - 1;
    assert_eq!(
        ring.verify(
            &expired.hostname,
            envelope(sign(&key, &expired), &expired),
            now,
            Instant::now()
        )
        .unwrap_err(),
        RouteGrantVerificationError::Expired
    );

    let valid = claims(now, 7);
    let wrong_target = AuthenticatedResolveEnvelope::from_authenticated_transport(
        valid.endpoint_id.as_str(),
        valid.node_id.as_str(),
        "https://127.0.0.1:7301",
        sign(&key, &valid),
        valid.exp,
        1024,
    );
    assert_eq!(
        ring.verify(&valid.hostname, wrong_target, now, Instant::now())
            .unwrap_err(),
        RouteGrantVerificationError::InvalidNodeTransportTarget
    );

    let token = sign(&key, &valid);
    let wrong_placement = AuthenticatedResolveEnvelope::from_authenticated_transport(
        valid.endpoint_id.as_str(),
        "node_b",
        "https://node-b.internal:7301",
        token.clone(),
        valid.exp,
        token.len() + 256,
    );
    assert_eq!(
        ring.verify(&valid.hostname, wrong_placement, now, Instant::now())
            .unwrap_err(),
        RouteGrantVerificationError::BindingMismatch
    );
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

#[tokio::test]
async fn cancelled_lookup_leader_does_not_cancel_the_singleflight() {
    let now = 1_786_156_800;
    let key = signing_key();
    let route = verify_route(&key, &claims(now, 7), now);
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
async fn resolver_cannot_install_a_verified_route_under_a_different_hostname() {
    let now = 1_786_156_800;
    let key = signing_key();
    let route = verify_route(&key, &claims(now, 7), now);
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
    let key = signing_key();
    let route = verify_route(&key, &claims(now, 7), now);
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
async fn refresh_updates_only_later_requests_and_old_rejection_cannot_delete_new_grant() {
    let now = 1_786_156_800;
    let key = signing_key();
    let old_route = verify_route(&key, &claims(now, 7), now);
    let new_route = verify_route(&key, &claims(now, 8), now);
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
    assert!(matches!(
        cache.lookup("app.cats.run").await.unwrap(),
        CacheLookup::Positive(_)
    ));

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

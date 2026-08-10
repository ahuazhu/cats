use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use cats_api::runtime_reconciliation::Hostname;
use tokio::sync::{watch, Semaphore};
use tokio::time::Instant;

use super::{GrantDigest, ResolvedRoute};

const RECORD_OVERHEAD_BYTES: usize = 96;

/// Future returned by the provider-neutral trusted Control resolve port.
pub type ResolveFuture =
    Pin<Box<dyn Future<Output = Result<RouteResolution, ResolveFailure>> + Send + 'static>>;
/// Provider-neutral trusted Control resolve port.
///
/// A production adapter must machine-authenticate Control, bound the response,
/// construct [`super::AuthenticatedResolveEnvelope`], and validate it into a
/// positive [`ResolvedRoute`] before returning from this port. Its HTTP wire is
/// intentionally not declared here.
pub type RouteResolver = Arc<dyn Fn(Hostname) -> ResolveFuture + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteCacheConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_entry_bytes: usize,
    pub max_resolve_response_bytes: usize,
    pub max_waiters_per_hostname: usize,
    pub max_concurrent_resolves: usize,
    pub resolve_timeout: Duration,
    pub negative_ttl: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RouteCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1_024,
            max_bytes: 8 * 1024 * 1024,
            max_entry_bytes: 8 * 1024,
            max_resolve_response_bytes: 8 * 1024,
            max_waiters_per_hostname: 64,
            max_concurrent_resolves: 32,
            resolve_timeout: Duration::from_secs(2),
            negative_ttl: Duration::from_secs(2),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl RouteCacheConfig {
    fn validate(self) -> Result<Self, RouteCacheError> {
        if self.max_entries == 0 {
            return Err(RouteCacheError::InvalidConfig(
                "max_entries must be positive",
            ));
        }
        if self.max_bytes == 0 {
            return Err(RouteCacheError::InvalidConfig("max_bytes must be positive"));
        }
        if self.max_entry_bytes == 0 || self.max_entry_bytes > self.max_bytes {
            return Err(RouteCacheError::InvalidConfig(
                "max_entry_bytes must be positive and no larger than max_bytes",
            ));
        }
        if self.max_resolve_response_bytes == 0
            || self.max_resolve_response_bytes > self.max_entry_bytes
        {
            return Err(RouteCacheError::InvalidConfig(
                "max_resolve_response_bytes must fit one cache entry",
            ));
        }
        if self.max_waiters_per_hostname == 0 {
            return Err(RouteCacheError::InvalidConfig(
                "max_waiters_per_hostname must be positive",
            ));
        }
        if self.max_concurrent_resolves == 0 {
            return Err(RouteCacheError::InvalidConfig(
                "max_concurrent_resolves must be positive",
            ));
        }
        if self.max_concurrent_resolves > Semaphore::MAX_PERMITS {
            return Err(RouteCacheError::InvalidConfig(
                "max_concurrent_resolves exceeds the resolve semaphore capacity",
            ));
        }
        if self.resolve_timeout.is_zero()
            || self.negative_ttl.is_zero()
            || self.initial_backoff.is_zero()
            || self.initial_backoff > self.max_backoff
        {
            return Err(RouteCacheError::InvalidConfig(
                "deadlines, negative TTL and backoff must be positive and ordered",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCacheError {
    InvalidConfig(&'static str),
    InvalidHostname,
    CapacityExhausted,
    WaiterLimit,
    ResponseTooLarge,
    InvalidResponse,
    ResolveTimeout,
    ResolveUnavailable,
    ResolveInvalidAuthority,
    Backoff { retry_after: Duration },
    DeadlineOverflow,
    CounterExhausted,
    InFlightLost,
    Shutdown,
}

impl std::fmt::Display for RouteCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid Route cache configuration: {message}")
            }
            Self::InvalidHostname => formatter.write_str("hostname is not canonical"),
            Self::CapacityExhausted => {
                formatter.write_str("Route cache entry or byte capacity is exhausted")
            }
            Self::WaiterLimit => {
                formatter.write_str("per-hostname Route resolve waiter limit is exhausted")
            }
            Self::ResponseTooLarge => {
                formatter.write_str("Route resolve response exceeds its byte limit")
            }
            Self::InvalidResponse => {
                formatter.write_str("Route resolver returned an invalid positive entry")
            }
            Self::ResolveTimeout => formatter.write_str("Route resolve timed out"),
            Self::ResolveUnavailable => formatter.write_str("Route resolver is unavailable"),
            Self::ResolveInvalidAuthority => {
                formatter.write_str("Route resolver returned invalid authority")
            }
            Self::Backoff { retry_after } => {
                write!(
                    formatter,
                    "Route resolve is backing off for another {retry_after:?}"
                )
            }
            Self::DeadlineOverflow => formatter.write_str("Route cache deadline overflow"),
            Self::CounterExhausted => formatter.write_str("Route cache counter exhausted"),
            Self::InFlightLost => formatter.write_str("Route singleflight ended without a result"),
            Self::Shutdown => formatter.write_str("Route cache is shut down"),
        }
    }
}

impl std::error::Error for RouteCacheError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegativeRoute {
    NotFound,
    Gone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteResolution {
    /// Authenticated Control metadata plus an opaque, unverified Grant.
    Positive(ResolvedRoute),
    Negative(NegativeRoute),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveFailure {
    Unavailable,
    InvalidAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    Positive(Arc<ResolvedRoute>),
    Negative(NegativeRoute),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Http,
    WebSocketUpgrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshableRejection {
    Expired,
    BindingMismatch,
    GateClosed,
    RuntimeNotReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentRequestDisposition {
    RejectWithoutReplay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheRefreshStatus {
    DigestDidNotMatch,
    RefreshedPositive,
    RefreshedNegative(NegativeRoute),
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshForLaterOutcome {
    pub current_request: CurrentRequestDisposition,
    pub cache: CacheRefreshStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteCacheStats {
    pub entries: usize,
    pub bytes: usize,
    pub in_flight_keys: usize,
    pub waiters: usize,
    pub available_resolve_slots: usize,
    pub shutdown: bool,
}

type LookupResult = Result<CacheLookup, RouteCacheError>;

#[derive(Debug)]
struct InFlight {
    generation: u64,
    waiters: usize,
    prior_backoff_attempts: u32,
    completed: watch::Sender<Option<Arc<LookupResult>>>,
}

#[derive(Debug)]
enum CacheValue {
    Positive(Arc<ResolvedRoute>),
    Negative {
        reason: NegativeRoute,
        expires_at: Instant,
    },
    Backoff {
        retry_at: Instant,
        attempts: u32,
    },
    InFlight(InFlight),
}

#[derive(Debug)]
struct CacheRecord {
    lru: u64,
    bytes: usize,
    value: CacheValue,
}

#[derive(Debug, Default)]
struct State {
    records: HashMap<String, CacheRecord>,
    total_bytes: usize,
    lru_clock: u64,
    next_generation: u64,
    shutdown: bool,
}

impl State {
    fn next_lru(&mut self) -> Result<u64, RouteCacheError> {
        self.lru_clock = self
            .lru_clock
            .checked_add(1)
            .ok_or(RouteCacheError::CounterExhausted)?;
        Ok(self.lru_clock)
    }

    fn next_generation(&mut self) -> Result<u64, RouteCacheError> {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(RouteCacheError::CounterExhausted)?;
        Ok(self.next_generation)
    }

    fn remove(&mut self, hostname: &str) -> Option<CacheRecord> {
        let removed = self.records.remove(hostname)?;
        self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
        Some(removed)
    }

    fn fail_closed(&mut self, error: RouteCacheError) {
        let failure = Arc::new(Err(error));
        for record in self.records.values() {
            if let CacheValue::InFlight(in_flight) = &record.value {
                in_flight.completed.send_replace(Some(failure.clone()));
            }
        }
        self.records.clear();
        self.total_bytes = 0;
    }
}

struct Inner {
    config: RouteCacheConfig,
    resolver: RouteResolver,
    resolve_slots: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
    state: Mutex<State>,
}

#[derive(Clone)]
pub struct RouteCache {
    inner: Arc<Inner>,
}

impl RouteCache {
    pub fn new(config: RouteCacheConfig, resolver: RouteResolver) -> Result<Self, RouteCacheError> {
        let config = config.validate()?;
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            inner: Arc::new(Inner {
                resolve_slots: Arc::new(Semaphore::new(config.max_concurrent_resolves)),
                config,
                resolver,
                shutdown,
                state: Mutex::new(State::default()),
            }),
        })
    }

    /// Return a cache hit or join/start one bounded per-hostname resolve.
    pub async fn lookup(&self, hostname: &str) -> LookupResult {
        let hostname_value = parse_hostname(hostname)?;
        let action = {
            let now = Instant::now();
            let mut state = lock_state(&self.inner);
            if state.shutdown {
                return Err(RouteCacheError::Shutdown);
            }
            let lru = state.next_lru()?;
            let existing = state.records.get_mut(hostname).map(|record| {
                record.lru = lru;
                match &mut record.value {
                    CacheValue::Positive(route) if route.expires_at() > now => {
                        Existing::Return(Ok(CacheLookup::Positive(route.clone())))
                    }
                    CacheValue::Positive(_) => Existing::Expired,
                    CacheValue::Negative { reason, expires_at } if *expires_at > now => {
                        Existing::Return(Ok(CacheLookup::Negative(*reason)))
                    }
                    CacheValue::Negative { .. } => Existing::Expired,
                    CacheValue::Backoff { retry_at, .. } if *retry_at > now => {
                        Existing::Return(Err(RouteCacheError::Backoff {
                            retry_after: retry_at.duration_since(now),
                        }))
                    }
                    CacheValue::Backoff { attempts, .. } => Existing::ExpiredBackoff(*attempts),
                    CacheValue::InFlight(in_flight) => {
                        if in_flight.waiters >= self.inner.config.max_waiters_per_hostname {
                            Existing::Return(Err(RouteCacheError::WaiterLimit))
                        } else {
                            in_flight.waiters += 1;
                            Existing::Wait(in_flight.generation, in_flight.completed.subscribe())
                        }
                    }
                }
            });

            match existing {
                Some(Existing::Return(result)) => Action::Return(result),
                Some(Existing::Wait(generation, completed)) => Action::Wait(WaitRegistration {
                    inner: self.inner.clone(),
                    hostname: hostname.to_owned(),
                    generation,
                    counted_waiter: true,
                    completed,
                }),
                Some(Existing::ExpiredBackoff(attempts)) => {
                    state.remove(hostname);
                    self.insert_in_flight(&mut state, hostname, hostname_value, attempts)?
                }
                Some(Existing::Expired) => {
                    state.remove(hostname);
                    self.insert_in_flight(&mut state, hostname, hostname_value, 0)?
                }
                None => self.insert_in_flight(&mut state, hostname, hostname_value, 0)?,
            }
        };

        match action {
            Action::Return(result) => result,
            Action::Wait(waiter) => waiter.wait().await,
            Action::Start(waiter, hostname, generation) => {
                self.start_resolve(hostname, generation);
                waiter.wait().await
            }
        }
    }

    fn insert_in_flight(
        &self,
        state: &mut State,
        hostname_wire: &str,
        hostname: Hostname,
        prior_backoff_attempts: u32,
    ) -> Result<Action, RouteCacheError> {
        let bytes = hostname_wire
            .len()
            .checked_add(RECORD_OVERHEAD_BYTES)
            .ok_or(RouteCacheError::CapacityExhausted)?;
        ensure_capacity(&self.inner.config, state, bytes)?;
        let generation = state.next_generation()?;
        let lru = state.next_lru()?;
        let (completed, receiver) = watch::channel(None);
        state.total_bytes = state
            .total_bytes
            .checked_add(bytes)
            .ok_or(RouteCacheError::CapacityExhausted)?;
        state.records.insert(
            hostname_wire.to_owned(),
            CacheRecord {
                lru,
                bytes,
                value: CacheValue::InFlight(InFlight {
                    generation,
                    waiters: 0,
                    prior_backoff_attempts,
                    completed,
                }),
            },
        );
        Ok(Action::Start(
            WaitRegistration {
                inner: self.inner.clone(),
                hostname: hostname_wire.to_owned(),
                generation,
                counted_waiter: false,
                completed: receiver,
            },
            hostname,
            generation,
        ))
    }

    fn start_resolve(&self, hostname: Hostname, generation: u64) {
        let cache = self.clone();
        tokio::spawn(async move {
            let mut shutdown = cache.inner.shutdown.subscribe();
            let resolve_inner = cache.inner.clone();
            let resolve_hostname = hostname.clone();
            let mut resolve_task = tokio::spawn(async move {
                let permit = resolve_inner
                    .resolve_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| ResolveCompletionFailure::Shutdown)?;
                let result = (resolve_inner.resolver)(resolve_hostname).await;
                drop(permit);
                result.map_err(|failure| match failure {
                    ResolveFailure::Unavailable => ResolveCompletionFailure::Unavailable,
                    ResolveFailure::InvalidAuthority => ResolveCompletionFailure::InvalidAuthority,
                })
            });
            let deadline = tokio::time::sleep(cache.inner.config.resolve_timeout);
            tokio::pin!(deadline);
            let result = tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut shutdown) => {
                    resolve_task.abort();
                    let _ = resolve_task.await;
                    Err(ResolveCompletionFailure::Shutdown)
                }
                _ = &mut deadline => {
                    resolve_task.abort();
                    let _ = resolve_task.await;
                    Err(ResolveCompletionFailure::Timeout)
                }
                result = &mut resolve_task => result
                    .unwrap_or(Err(ResolveCompletionFailure::InFlightLost)),
            };
            cache.complete_resolve(hostname.as_str(), generation, result);
        });
    }

    fn complete_resolve(
        &self,
        hostname: &str,
        generation: u64,
        resolved: Result<RouteResolution, ResolveCompletionFailure>,
    ) {
        let now = Instant::now();
        let mut state = lock_state(&self.inner);
        if state.shutdown {
            return;
        }
        let Some(record) = state.records.get(hostname) else {
            return;
        };
        let CacheValue::InFlight(in_flight) = &record.value else {
            return;
        };
        if in_flight.generation != generation {
            return;
        }
        let completed = in_flight.completed.clone();
        let prior_backoff_attempts = in_flight.prior_backoff_attempts;
        state.remove(hostname);

        let result = match resolved {
            Ok(RouteResolution::Positive(route)) => {
                self.complete_positive(&mut state, hostname, route, now)
            }
            Ok(RouteResolution::Negative(reason)) => {
                self.complete_negative(&mut state, hostname, reason, now)
            }
            Err(ResolveCompletionFailure::Shutdown) => Err(RouteCacheError::Shutdown),
            Err(failure) => {
                self.complete_failure(&mut state, hostname, failure, prior_backoff_attempts, now)
            }
        };
        completed.send_replace(Some(Arc::new(result)));
    }

    fn complete_positive(
        &self,
        state: &mut State,
        hostname: &str,
        route: ResolvedRoute,
        now: Instant,
    ) -> LookupResult {
        if route.hostname().as_str() != hostname || route.expires_at() <= now {
            return Err(RouteCacheError::InvalidResponse);
        }
        let response_bytes = route.response_bytes();
        let bytes = hostname
            .len()
            .checked_add(response_bytes)
            .and_then(|value| value.checked_add(RECORD_OVERHEAD_BYTES))
            .ok_or(RouteCacheError::ResponseTooLarge)?;
        if response_bytes > self.inner.config.max_resolve_response_bytes
            || bytes > self.inner.config.max_entry_bytes
        {
            return Err(RouteCacheError::ResponseTooLarge);
        }
        ensure_capacity(&self.inner.config, state, bytes)?;
        let route = Arc::new(route);
        insert_record(state, hostname, bytes, CacheValue::Positive(route.clone()))?;
        Ok(CacheLookup::Positive(route))
    }

    fn complete_negative(
        &self,
        state: &mut State,
        hostname: &str,
        reason: NegativeRoute,
        now: Instant,
    ) -> LookupResult {
        let bytes = hostname
            .len()
            .checked_add(RECORD_OVERHEAD_BYTES)
            .ok_or(RouteCacheError::CapacityExhausted)?;
        let expires_at = now
            .checked_add(self.inner.config.negative_ttl)
            .ok_or(RouteCacheError::DeadlineOverflow)?;
        ensure_capacity(&self.inner.config, state, bytes)?;
        insert_record(
            state,
            hostname,
            bytes,
            CacheValue::Negative { reason, expires_at },
        )?;
        Ok(CacheLookup::Negative(reason))
    }

    fn complete_failure(
        &self,
        state: &mut State,
        hostname: &str,
        failure: ResolveCompletionFailure,
        prior_backoff_attempts: u32,
        now: Instant,
    ) -> LookupResult {
        if matches!(
            failure,
            ResolveCompletionFailure::Timeout | ResolveCompletionFailure::Unavailable
        ) {
            let attempts = prior_backoff_attempts.saturating_add(1);
            let delay = backoff_delay(&self.inner.config, hostname, attempts);
            let retry_at = now
                .checked_add(delay)
                .ok_or(RouteCacheError::DeadlineOverflow)?;
            let bytes = hostname
                .len()
                .checked_add(RECORD_OVERHEAD_BYTES)
                .ok_or(RouteCacheError::CapacityExhausted)?;
            if ensure_capacity(&self.inner.config, state, bytes).is_ok() {
                let _ = insert_record(
                    state,
                    hostname,
                    bytes,
                    CacheValue::Backoff { retry_at, attempts },
                );
            }
        }
        match failure {
            ResolveCompletionFailure::Timeout => Err(RouteCacheError::ResolveTimeout),
            ResolveCompletionFailure::Unavailable => Err(RouteCacheError::ResolveUnavailable),
            ResolveCompletionFailure::InvalidAuthority => {
                Err(RouteCacheError::ResolveInvalidAuthority)
            }
            ResolveCompletionFailure::InFlightLost => Err(RouteCacheError::InFlightLost),
            ResolveCompletionFailure::Shutdown => Err(RouteCacheError::Shutdown),
        }
    }

    /// Delete only the positive entry whose opaque-grant digest still matches.
    pub fn compare_and_delete(
        &self,
        hostname: &str,
        expected_digest: GrantDigest,
    ) -> Result<bool, RouteCacheError> {
        let _ = parse_hostname(hostname)?;
        let mut state = lock_state(&self.inner);
        if state.shutdown {
            return Err(RouteCacheError::Shutdown);
        }
        let matches = state.records.get(hostname).is_some_and(|record| {
            matches!(
                &record.value,
                CacheValue::Positive(route) if route.grant_digest() == expected_digest
            )
        });
        if matches {
            state.remove(hostname);
        }
        Ok(matches)
    }

    /// Refresh a digest-matched stale grant only for subsequent requests.
    ///
    /// The return type intentionally carries no resolved route and always says
    /// to reject the current HTTP request or WebSocket upgrade without replay.
    pub async fn refresh_for_later(
        &self,
        _request_kind: RequestKind,
        hostname: &str,
        rejected_digest: GrantDigest,
        _rejection: RefreshableRejection,
    ) -> RefreshForLaterOutcome {
        let cache = match self.compare_and_delete(hostname, rejected_digest) {
            Ok(false) => CacheRefreshStatus::DigestDidNotMatch,
            Err(_) => CacheRefreshStatus::Failed,
            Ok(true) => match self.lookup(hostname).await {
                Ok(CacheLookup::Positive(_)) => CacheRefreshStatus::RefreshedPositive,
                Ok(CacheLookup::Negative(reason)) => CacheRefreshStatus::RefreshedNegative(reason),
                Err(_) => CacheRefreshStatus::Failed,
            },
        };
        RefreshForLaterOutcome {
            current_request: CurrentRequestDisposition::RejectWithoutReplay,
            cache,
        }
    }

    /// Stop new resolves, cancel in-flight resolver futures, wake all waiters
    /// with a closed result, and discard every cached capability.
    pub fn shutdown(&self) {
        let mut state = lock_state(&self.inner);
        if state.shutdown {
            return;
        }
        state.shutdown = true;
        state.fail_closed(RouteCacheError::Shutdown);
        drop(state);
        self.inner.resolve_slots.close();
        self.inner.shutdown.send_replace(true);
    }

    pub fn stats(&self) -> RouteCacheStats {
        let state = lock_state(&self.inner);
        let mut in_flight_keys = 0;
        let mut waiters = 0;
        for record in state.records.values() {
            if let CacheValue::InFlight(in_flight) = &record.value {
                in_flight_keys += 1;
                waiters += in_flight.waiters;
            }
        }
        RouteCacheStats {
            entries: state.records.len(),
            bytes: state.total_bytes,
            in_flight_keys,
            waiters,
            available_resolve_slots: self.inner.resolve_slots.available_permits(),
            shutdown: state.shutdown,
        }
    }

    pub fn cached_digest(&self, hostname: &str) -> Option<GrantDigest> {
        let state = lock_state(&self.inner);
        state
            .records
            .get(hostname)
            .and_then(|record| match &record.value {
                CacheValue::Positive(route) if route.expires_at() > Instant::now() => {
                    Some(route.grant_digest())
                }
                _ => None,
            })
    }
}

enum Existing {
    Return(LookupResult),
    Wait(u64, watch::Receiver<Option<Arc<LookupResult>>>),
    Expired,
    ExpiredBackoff(u32),
}

enum Action {
    Return(LookupResult),
    Wait(WaitRegistration),
    Start(WaitRegistration, Hostname, u64),
}

#[derive(Debug, Clone, Copy)]
enum ResolveCompletionFailure {
    Timeout,
    Unavailable,
    InvalidAuthority,
    InFlightLost,
    Shutdown,
}

struct WaitRegistration {
    inner: Arc<Inner>,
    hostname: String,
    generation: u64,
    counted_waiter: bool,
    completed: watch::Receiver<Option<Arc<LookupResult>>>,
}

impl WaitRegistration {
    async fn wait(mut self) -> LookupResult {
        loop {
            if let Some(result) = self.completed.borrow().as_ref() {
                return (**result).clone();
            }
            if self.completed.changed().await.is_err() {
                return Err(RouteCacheError::InFlightLost);
            }
        }
    }
}

impl Drop for WaitRegistration {
    fn drop(&mut self) {
        if !self.counted_waiter {
            return;
        }
        let mut state = lock_state(&self.inner);
        let Some(record) = state.records.get_mut(&self.hostname) else {
            return;
        };
        let CacheValue::InFlight(in_flight) = &mut record.value else {
            return;
        };
        if in_flight.generation == self.generation {
            in_flight.waiters = in_flight.waiters.saturating_sub(1);
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn parse_hostname(hostname: &str) -> Result<Hostname, RouteCacheError> {
    if !(1..=253).contains(&hostname.len()) {
        return Err(RouteCacheError::InvalidHostname);
    }
    Hostname::new(hostname.to_owned()).ok_or(RouteCacheError::InvalidHostname)
}

fn ensure_capacity(
    config: &RouteCacheConfig,
    state: &mut State,
    new_bytes: usize,
) -> Result<(), RouteCacheError> {
    if new_bytes > config.max_entry_bytes || new_bytes > config.max_bytes {
        return Err(RouteCacheError::CapacityExhausted);
    }
    while state.records.len() >= config.max_entries
        || state
            .total_bytes
            .checked_add(new_bytes)
            .is_none_or(|bytes| bytes > config.max_bytes)
    {
        let evict = state
            .records
            .iter()
            .filter(|(_, record)| !matches!(record.value, CacheValue::InFlight(_)))
            .min_by_key(|(_, record)| record.lru)
            .map(|(hostname, _)| hostname.clone());
        let Some(evict) = evict else {
            return Err(RouteCacheError::CapacityExhausted);
        };
        state.remove(&evict);
    }
    Ok(())
}

fn insert_record(
    state: &mut State,
    hostname: &str,
    bytes: usize,
    value: CacheValue,
) -> Result<(), RouteCacheError> {
    let lru = state.next_lru()?;
    state.total_bytes = state
        .total_bytes
        .checked_add(bytes)
        .ok_or(RouteCacheError::CapacityExhausted)?;
    state
        .records
        .insert(hostname.to_owned(), CacheRecord { lru, bytes, value });
    Ok(())
}

fn backoff_delay(config: &RouteCacheConfig, hostname: &str, attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(31);
    let multiplier = 1_u32 << exponent;
    let base = config
        .initial_backoff
        .checked_mul(multiplier)
        .unwrap_or(config.max_backoff)
        .min(config.max_backoff);
    if base >= config.max_backoff {
        return config.max_backoff;
    }

    let mut seed = 0xcbf2_9ce4_8422_2325_u64;
    for byte in hostname.bytes().chain(attempts.to_be_bytes()) {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let jitter_bound = (base.as_nanos() / 4).min(u64::MAX as u128) as u64;
    let jitter_nanos = if jitter_bound == u64::MAX {
        seed
    } else {
        seed % (jitter_bound + 1)
    };
    base.saturating_add(Duration::from_nanos(jitter_nanos))
        .min(config.max_backoff)
}

fn lock_state(inner: &Inner) -> MutexGuard<'_, State> {
    match inner.state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            inner.shutdown.send_replace(true);
            inner.resolve_slots.close();
            state.shutdown = true;
            state.fail_closed(RouteCacheError::InFlightLost);
            inner.state.clear_poison();
            state
        }
    }
}

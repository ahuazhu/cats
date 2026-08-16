//! Bounded waiting primitives for tests that poll for a condition.
//!
//! Design principle: a pure polling upper bound is not a performance
//! assertion. A passing test exits the moment its condition holds, so a
//! healthy run pays nothing for a generous bound; the bound only decides
//! how long a genuinely broken run takes to fail. It must therefore be
//! absurdly wide by default instead of being calibrated against an idle
//! development machine. Hand-written `Instant::now() + Duration::from_secs(N)`
//! deadlines with small `N` are exactly the pattern that turns host
//! saturation into probabilistic test failures; use [`poll_bound`],
//! [`wait_until`], [`wait_until_async`], or [`bounded`] instead.
//!
//! This module is only for waits whose success is expected. Deliberate
//! negative assertions about timeout behavior, and protocol deadlines
//! inside production code, keep their own explicit durations.

use std::future::Future;
use std::time::{Duration, Instant};

/// Environment variable overriding the default polling bound, in whole
/// seconds. Parse failure panics: a typo must not silently reintroduce an
/// implicit calibration.
pub const POLL_BOUND_ENV: &str = "CATS_TEST_POLL_BOUND_SECS";

const DEFAULT_POLL_BOUND: Duration = Duration::from_secs(180);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Upper bound for a test wait whose success is expected.
///
/// Defaults to 180 seconds; `CATS_TEST_POLL_BOUND_SECS` overrides it for
/// hosts that need an even wider (or, for local flake reproduction, a
/// deliberately narrow) bound.
pub fn poll_bound() -> Duration {
    match std::env::var(POLL_BOUND_ENV) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => panic!("{POLL_BOUND_ENV} must be a positive whole number of seconds, got {raw:?}"),
        },
        Err(std::env::VarError::NotPresent) => DEFAULT_POLL_BOUND,
        Err(err) => panic!("{POLL_BOUND_ENV} is not readable: {err}"),
    }
}

/// Polls `check` every 10ms until it returns true, panicking with `purpose`
/// once [`poll_bound`] elapses. Blocking; do not call on an async executor
/// thread — use [`wait_until_async`] there.
pub fn wait_until(purpose: &str, mut check: impl FnMut() -> bool) {
    let bound = poll_bound();
    let deadline = Instant::now() + bound;
    loop {
        if check() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {}s waiting for: {purpose}",
                bound.as_secs()
            );
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Async [`wait_until`]: polls the future produced by `check` every 10ms
/// until it resolves to true, panicking with `purpose` once [`poll_bound`]
/// elapses.
pub async fn wait_until_async<F, Fut>(purpose: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let bound = poll_bound();
    let deadline = Instant::now() + bound;
    loop {
        if check().await {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {}s waiting for: {purpose}",
                bound.as_secs()
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Awaits `operation`, panicking with `purpose` if it has not completed
/// within [`poll_bound`]. This replaces ad-hoc
/// `tokio::time::timeout(Duration::from_secs(N), op)` wrappers around
/// operations whose completion is expected.
pub async fn bounded<F: Future>(purpose: &str, operation: F) -> F::Output {
    let bound = poll_bound();
    match tokio::time::timeout(bound, operation).await {
        Ok(output) => output,
        Err(_) => panic!("timed out after {}s awaiting: {purpose}", bound.as_secs()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bound_is_wide() {
        // Serialize around the env var via a lock-free convention: this
        // test only reads when the variable is absent in the test env.
        if std::env::var(POLL_BOUND_ENV).is_err() {
            assert_eq!(poll_bound(), Duration::from_secs(180));
        }
    }

    #[test]
    fn wait_until_returns_once_condition_holds() {
        let mut remaining = 3u32;
        wait_until("countdown reaches zero", || {
            remaining = remaining.saturating_sub(1);
            remaining == 0
        });
    }

    #[tokio::test]
    async fn wait_until_async_returns_once_condition_holds() {
        let mut remaining = 3u32;
        wait_until_async("countdown reaches zero", || {
            remaining = remaining.saturating_sub(1);
            async move { remaining == 0 }
        })
        .await;
    }

    #[tokio::test]
    async fn bounded_passes_through_output() {
        assert_eq!(bounded("trivial future", async { 7 }).await, 7);
    }
}

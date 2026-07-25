//! Concurrent-wake admission control (ADR-0002 §8 and its open item
//! "Warm/Suspended wake storm 的准入与限流").
//!
//! # Why bytes and not a plain count
//!
//! The 2026-07-21 concurrency experiment measured ten simultaneous 512 MiB
//! Warm restores and found the first-health P50 collapsing from 0.53 s on
//! local NVMe to 19.05 s on EBS, while the Cloud Hypervisor `vm.restore` API
//! call itself stayed at 25–26 ms in both runs. The bottleneck is therefore
//! **Guest memory page read-back**, not the VMM. Admission is consequently
//! accounted in *resume commitment bytes* — the memory a wake must fault back
//! in — with a wake count ceiling only as defence in depth so that many tiny
//! Cats cannot bypass the byte budget.
//!
//! # Why it queues instead of rejecting
//!
//! A node-side rejection is not usable here: the control plane converges any
//! failed resume/restore to a clean Cold fallback (ADR-0002 §7). Rejecting a
//! wake merely because the node is momentarily saturated would destroy the
//! local Suspended memory backing or Warm snapshot and turn every rejected
//! wake into a full Cold boot — making a wake storm strictly worse. Rejection
//! also cannot make page read-back faster.
//!
//! So a wake **waits** for budget up to a deadline. Bounded concurrency makes
//! total wake time degrade linearly (two batches of ten ≈ 2× one batch)
//! instead of collapsing (10× concurrency on EBS cost 36× the latency).
//! Only two conditions are genuine failures, and both are unsatisfiable by
//! waiting:
//!
//! - the commitment of a single Cat exceeds the whole node budget, and
//! - the deadline elapses.
//!
//! # Defaults
//!
//! Defaults are pinned to the *validated* operating point — ten concurrent
//! wakes and 5 GiB of concurrent commitment (10 × 512 MiB) — not to a proven
//! optimum. Beyond that point there is no measurement, and per ADRs a
//! prototype measurement must never become a production SLA. Operators on
//! faster or slower storage should re-measure before raising these.

use std::fmt;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Concurrent wake footprint validated by the 2026-07-21 experiment:
/// ten simultaneous 512 MiB restores.
pub const DEFAULT_WAKE_COMMITMENT_BUDGET_BYTES: u64 = 10 * 512 * 1024 * 1024;
/// Concurrency validated by the same run.
pub const DEFAULT_MAX_CONCURRENT_WAKES: usize = 10;
/// How long a wake may wait for budget before the node admits it cannot
/// serve the wake. Chosen above the slowest measured concurrent restore
/// (EBS first-health P50 19.05 s) so that a legitimately slow medium queues
/// rather than falls back to Cold.
pub const DEFAULT_WAKE_QUEUE_TIMEOUT: Duration = Duration::from_secs(60);

/// Node-level ceiling on concurrent wakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeBudget {
    /// Total resume-commitment bytes admitted at once.
    pub commitment_bytes: u64,
    /// Hard ceiling on concurrently admitted wakes.
    pub max_wakes: usize,
    /// Bounded wait before a wake is treated as unservable.
    pub queue_timeout: Duration,
}

impl Default for WakeBudget {
    fn default() -> Self {
        Self {
            commitment_bytes: DEFAULT_WAKE_COMMITMENT_BUDGET_BYTES,
            max_wakes: DEFAULT_MAX_CONCURRENT_WAKES,
            queue_timeout: DEFAULT_WAKE_QUEUE_TIMEOUT,
        }
    }
}

/// Why a wake could not be admitted. Both variants are unsatisfiable by
/// waiting, so both are genuine failures that converge to Cold (ADR-0002 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// One Cat needs more than the entire node budget. Waiting can never
    /// help, so this must not be reported as a transient condition.
    ExceedsNodeBudget { requested: u64, budget: u64 },
    /// The bounded wait elapsed while other wakes held the budget.
    QueueTimeout { requested: u64, waited: Duration },
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsNodeBudget { requested, budget } => write!(
                f,
                "resume commitment {requested} B exceeds the node wake budget {budget} B; \
                 this Cat can never be woken on this node"
            ),
            Self::QueueTimeout { requested, waited } => write!(
                f,
                "waited {:.1}s for {requested} B of wake budget",
                waited.as_secs_f64()
            ),
        }
    }
}

impl std::error::Error for AdmissionError {}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    commitment_bytes: u64,
    wakes: usize,
}

/// Snapshot of current saturation, for telemetry and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WakeLoad {
    pub wakes: usize,
    pub commitment_bytes: u64,
    pub peak_wakes: usize,
    pub peak_commitment_bytes: u64,
}

#[derive(Debug, Default)]
struct State {
    in_flight: InFlight,
    peak: InFlight,
}

/// Admits concurrent wakes against a node budget.
#[derive(Debug)]
pub struct WakeAdmission {
    budget: WakeBudget,
    state: Mutex<State>,
    released: Condvar,
}

impl WakeAdmission {
    pub fn new(budget: WakeBudget) -> Self {
        Self {
            budget,
            state: Mutex::new(State::default()),
            released: Condvar::new(),
        }
    }

    pub fn budget(&self) -> WakeBudget {
        self.budget
    }

    pub fn load(&self) -> WakeLoad {
        let state = self.state.lock().expect("wake admission mutex");
        WakeLoad {
            wakes: state.in_flight.wakes,
            commitment_bytes: state.in_flight.commitment_bytes,
            peak_wakes: state.peak.wakes,
            peak_commitment_bytes: state.peak.commitment_bytes,
        }
    }

    /// Reserve budget for one wake, waiting up to the configured timeout.
    ///
    /// The returned permit releases the reservation on drop, so a wake that
    /// fails or panics never leaks commitment and wedges the node.
    pub fn acquire(&self, commitment_bytes: u64) -> Result<WakePermit<'_>, AdmissionError> {
        self.acquire_until(commitment_bytes, self.budget.queue_timeout)
    }

    /// `acquire` with an explicit bound, so tests need not wait a minute.
    pub fn acquire_until(
        &self,
        commitment_bytes: u64,
        timeout: Duration,
    ) -> Result<WakePermit<'_>, AdmissionError> {
        // Unsatisfiable by waiting: fail before joining the queue. A zero
        // budget would otherwise stall every wake until the deadline.
        if commitment_bytes > self.budget.commitment_bytes || self.budget.max_wakes == 0 {
            return Err(AdmissionError::ExceedsNodeBudget {
                requested: commitment_bytes,
                budget: self.budget.commitment_bytes,
            });
        }

        let started = Instant::now();
        let mut state = self.state.lock().expect("wake admission mutex");
        loop {
            if self.fits(&state.in_flight, commitment_bytes) {
                state.in_flight.wakes += 1;
                // Checked at the call boundary above, so this cannot overflow.
                state.in_flight.commitment_bytes += commitment_bytes;
                state.peak.wakes = state.peak.wakes.max(state.in_flight.wakes);
                state.peak.commitment_bytes = state
                    .peak
                    .commitment_bytes
                    .max(state.in_flight.commitment_bytes);
                return Ok(WakePermit {
                    admission: self,
                    commitment_bytes,
                });
            }
            let elapsed = started.elapsed();
            let Some(remaining) = timeout.checked_sub(elapsed) else {
                return Err(AdmissionError::QueueTimeout {
                    requested: commitment_bytes,
                    waited: elapsed,
                });
            };
            // Condvar waits may wake spuriously; the loop re-checks the fit.
            let (next, _) = self
                .released
                .wait_timeout(state, remaining)
                .expect("wake admission mutex");
            state = next;
        }
    }

    fn fits(&self, in_flight: &InFlight, commitment_bytes: u64) -> bool {
        if in_flight.wakes >= self.budget.max_wakes {
            return false;
        }
        // A zero-commitment wake still consumes a slot, checked above, so an
        // accounting bug cannot admit an unbounded number of them.
        in_flight
            .commitment_bytes
            .checked_add(commitment_bytes)
            .is_some_and(|total| total <= self.budget.commitment_bytes)
    }

    fn release(&self, commitment_bytes: u64) {
        let mut state = self.state.lock().expect("wake admission mutex");
        state.in_flight.wakes = state.in_flight.wakes.saturating_sub(1);
        state.in_flight.commitment_bytes = state
            .in_flight
            .commitment_bytes
            .saturating_sub(commitment_bytes);
        drop(state);
        // Several waiters may now fit: a small wake can proceed where a large
        // one still cannot, so wake all of them and let each re-check.
        self.released.notify_all();
    }
}

/// Holds one wake's reservation. Releasing is unconditional on drop.
#[derive(Debug)]
pub struct WakePermit<'a> {
    admission: &'a WakeAdmission,
    commitment_bytes: u64,
}

impl WakePermit<'_> {
    pub fn commitment_bytes(&self) -> u64 {
        self.commitment_bytes
    }
}

impl Drop for WakePermit<'_> {
    fn drop(&mut self) {
        self.admission.release(self.commitment_bytes);
    }
}

/// Resume commitment for a Cat with `memory_mib` of Guest RAM.
///
/// Both wake paths are charged the Guest RAM size: Suspended must refault it
/// from the file-backed memory zone and Warm must read it back out of the
/// snapshot. ADR-0002 §8 names this the "resume commitment" for both states.
pub fn resume_commitment_bytes(memory_mib: u64) -> u64 {
    memory_mib.saturating_mul(1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const MIB: u64 = 1024 * 1024;

    fn budget(commitment_bytes: u64, max_wakes: usize) -> WakeBudget {
        WakeBudget {
            commitment_bytes,
            max_wakes,
            queue_timeout: Duration::from_millis(50),
        }
    }

    #[test]
    fn defaults_match_the_validated_operating_point() {
        let budget = WakeBudget::default();
        // Ten simultaneous 512 MiB restores (2026-07-21 concurrency run).
        assert_eq!(budget.max_wakes, 10);
        assert_eq!(budget.commitment_bytes, 10 * 512 * MIB);
    }

    #[test]
    fn commitment_is_guest_ram_and_cannot_overflow() {
        assert_eq!(resume_commitment_bytes(512), 512 * MIB);
        assert_eq!(resume_commitment_bytes(0), 0);
        assert_eq!(resume_commitment_bytes(u64::MAX), u64::MAX);
    }

    #[test]
    fn admits_up_to_the_byte_budget_then_queues() {
        let admission = WakeAdmission::new(budget(1024 * MIB, 100));
        let first = admission.acquire(512 * MIB).expect("first fits");
        let _second = admission.acquire(512 * MIB).expect("second fits");
        assert_eq!(admission.load().commitment_bytes, 1024 * MIB);

        let error = admission
            .acquire_until(512 * MIB, Duration::from_millis(20))
            .expect_err("budget is exhausted");
        assert!(matches!(error, AdmissionError::QueueTimeout { .. }));

        drop(first);
        admission
            .acquire_until(512 * MIB, Duration::from_millis(20))
            .expect("released budget is reusable");
    }

    #[test]
    fn wake_count_ceiling_bounds_many_tiny_cats() {
        // Byte budget alone would admit thousands of 1 MiB Cats.
        let admission = WakeAdmission::new(budget(1024 * MIB, 2));
        let _a = admission.acquire(MIB).expect("first");
        let _b = admission.acquire(MIB).expect("second");
        let error = admission
            .acquire_until(MIB, Duration::from_millis(20))
            .expect_err("count ceiling holds");
        assert!(matches!(error, AdmissionError::QueueTimeout { .. }));
        assert_eq!(admission.load().wakes, 2);
    }

    #[test]
    fn zero_commitment_still_consumes_a_slot() {
        let admission = WakeAdmission::new(budget(1024 * MIB, 1));
        let _only = admission.acquire(0).expect("zero-byte wake is admitted");
        let error = admission
            .acquire_until(0, Duration::from_millis(20))
            .expect_err("a zero-byte wake must not be unbounded");
        assert!(matches!(error, AdmissionError::QueueTimeout { .. }));
    }

    #[test]
    fn oversized_cat_fails_immediately_rather_than_waiting() {
        let admission = WakeAdmission::new(budget(256 * MIB, 10));
        let started = Instant::now();
        let error = admission
            .acquire_until(512 * MIB, Duration::from_secs(30))
            .expect_err("cannot ever fit");
        // Waiting can never satisfy it, so it must not burn the deadline.
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            error,
            AdmissionError::ExceedsNodeBudget {
                requested,
                budget: 268_435_456,
            } if requested == 512 * MIB
        ));
    }

    #[test]
    fn zero_max_wakes_is_reported_as_unsatisfiable_not_a_timeout() {
        let admission = WakeAdmission::new(budget(1024 * MIB, 0));
        let error = admission
            .acquire_until(MIB, Duration::from_secs(30))
            .expect_err("a disabled node admits nothing");
        assert!(matches!(error, AdmissionError::ExceedsNodeBudget { .. }));
    }

    /// Stands in for a wake that is admitted and then fails mid-flight.
    fn failing_wake(admission: &WakeAdmission) -> Result<(), &'static str> {
        let _permit = admission.acquire(512 * MIB).expect("admitted");
        Err("resume lost the boot id")
    }

    #[test]
    fn permit_release_is_unconditional_on_drop() {
        let admission = WakeAdmission::new(budget(512 * MIB, 1));
        // A wake that fails mid-flight must not leak its commitment.
        assert!(failing_wake(&admission).is_err());
        assert_eq!(admission.load().commitment_bytes, 0);
        assert_eq!(admission.load().wakes, 0);
        admission.acquire(512 * MIB).expect("budget was returned");
    }

    #[test]
    fn permit_release_survives_a_panicking_wake() {
        let admission = Arc::new(WakeAdmission::new(budget(512 * MIB, 1)));
        let panicked = {
            let admission = Arc::clone(&admission);
            std::thread::spawn(move || {
                let _permit = admission.acquire(512 * MIB).expect("admitted");
                panic!("wake blew up");
            })
            .join()
        };
        assert!(panicked.is_err());
        // Drop still ran during unwind, so the node is not wedged.
        assert_eq!(admission.load().wakes, 0);
        admission.acquire(512 * MIB).expect("budget was returned");
    }

    #[test]
    fn a_wake_storm_is_serialized_and_never_exceeds_the_ceiling() {
        // 24 wakes of 512 MiB against the validated 10 × 512 MiB budget.
        let admission = Arc::new(WakeAdmission::new(WakeBudget {
            commitment_bytes: 10 * 512 * MIB,
            max_wakes: 10,
            queue_timeout: Duration::from_secs(30),
        }));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..24 {
            let admission = Arc::clone(&admission);
            let completed = Arc::clone(&completed);
            handles.push(std::thread::spawn(move || {
                let permit = admission.acquire(512 * MIB).expect("eventually admitted");
                // Observe the ceiling from inside the critical section.
                let load = admission.load();
                assert!(load.wakes <= 10, "admitted {} wakes", load.wakes);
                assert!(load.commitment_bytes <= 10 * 512 * MIB);
                std::thread::sleep(Duration::from_millis(5));
                drop(permit);
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        for handle in handles {
            handle.join().expect("wake thread");
        }
        // Every wake is served; the storm is spread, not dropped.
        assert_eq!(completed.load(Ordering::SeqCst), 24);
        let load = admission.load();
        assert_eq!(load.wakes, 0);
        assert_eq!(load.commitment_bytes, 0);
        assert!(load.peak_wakes <= 10, "peak {} wakes", load.peak_wakes);
        assert!(load.peak_commitment_bytes <= 10 * 512 * MIB);
    }

    #[test]
    fn a_large_wake_is_not_starved_by_a_stream_of_small_ones() {
        // notify_all + re-check means the big waiter competes on each release
        // instead of being permanently skipped.
        let admission = Arc::new(WakeAdmission::new(WakeBudget {
            commitment_bytes: 512 * MIB,
            max_wakes: 8,
            queue_timeout: Duration::from_secs(30),
        }));
        let hold = admission.acquire(512 * MIB).expect("fill the budget");
        let big = {
            let admission = Arc::clone(&admission);
            std::thread::spawn(move || {
                admission
                    .acquire_until(512 * MIB, Duration::from_secs(10))
                    .map(|permit| permit.commitment_bytes())
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        drop(hold);
        assert_eq!(big.join().expect("big wake thread"), Ok(512 * MIB));
    }
}

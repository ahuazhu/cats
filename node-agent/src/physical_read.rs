//! Observation-only deadline and cancellation boundary for Host reads.
//!
//! Lifecycle inventory and exact physical verifiers may share parsers and
//! descriptor-retained inspection without importing the retired Desired
//! reconcile spine. Implementations authorize reads only; they cannot mint a
//! physical-effect permit.

use std::time::Instant;

pub(crate) trait PhysicalReadContext {
    fn deadline(&self) -> Instant;
    fn check_active(&self) -> anyhow::Result<()>;
}

/// A caller-owned cancellation/deadline boundary for one already-authorized
/// physical mutation.
///
/// Implementing this marker does not itself grant lifecycle authority. The
/// atomic lifecycle executor must first retain and validate the command
/// journal; this context only lets leaf adapters stop at bounded cancellation
/// boundaries without depending on the retired Desired reconcile spine.
pub(crate) trait PhysicalEffectContext: PhysicalReadContext {}

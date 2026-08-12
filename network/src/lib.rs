//! Endpoint Gateway protocol components.
//!
//! The production Route Grant v2 pieces live in [`route_v2`]. The historical
//! V1 process harness is compiled only for explicitly opted-in compatibility
//! tests and is never part of the shipped binary.

mod production_blocker;
pub mod route_v2;

#[cfg(feature = "legacy-test-harness")]
#[path = "legacy.rs"]
mod legacy;

#[cfg(feature = "legacy-test-harness")]
pub use legacy::*;

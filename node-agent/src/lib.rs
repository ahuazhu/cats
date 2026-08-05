//! Cats node agent: executes control-plane jobs by supervising the fake VMM
//! (guest-agent process) and one cats-blockd per attachment. See
//! `runtime.rs` for the FakeVmm / Cloud Hypervisor seam.

pub mod admission;
pub mod ch;
pub mod guest_client;
pub(crate) mod proc;
pub mod runtime;
pub mod server;
pub mod usage_spool;

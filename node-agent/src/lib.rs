//! Cats node agent: executes control-plane jobs by supervising the fake VMM
//! (guest-agent process) and one cats-blockd per attachment. See
//! `runtime.rs` for the FakeVmm / Cloud Hypervisor seam.

pub mod admission;
pub mod agent_registration;
pub mod ch;
pub mod guest_client;
pub(crate) mod proc;
pub mod route_grant;
pub mod route_grant_v2;
pub mod runtime;
pub mod runtime_cutover;
pub mod runtime_spine;
pub mod server;
pub mod state_directory;
pub mod usage_spool;

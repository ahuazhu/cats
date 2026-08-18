//! Cats node agent: executes control-plane jobs by supervising the fake VMM
//! (guest-agent process) and one cats-blockd per attachment. See
//! `runtime.rs` for the FakeVmm / Cloud Hypervisor seam.

pub mod admission;
pub mod agent_registration;
pub mod ch;
pub mod guest_client;
pub mod object_write_credential;
/// End-to-end acceptance for the Node -> ObjectWrite Gateway -> object-store
/// publish chain. This crate is the only one that can see all of it.
#[cfg(test)]
mod object_write_end_to_end;
pub(crate) mod proc;
pub mod route_grant;
pub mod route_grant_v2;
pub mod route_signing_rotation;
pub mod route_v2_machine;
pub mod runtime;
pub mod runtime_cutover;
pub mod runtime_spine;
pub mod server;
pub(crate) mod signed_usage;
pub mod state_directory;
pub(crate) mod usage_delivery;
pub mod usage_spool;
pub mod vmm_launcher;

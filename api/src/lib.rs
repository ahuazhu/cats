//! Public HTTP API types for Cats clients and the Control Plane.
//!
//! Cross-component wire contracts live in `cats-protocol`; installed Host
//! artifact readers live in `cats-artifacts`. Compatibility features re-export
//! their former `cats_api` paths for existing library consumers. Workspace
//! components depend on the owning crates directly.
//!
//! This crate stays dependency-light and contains no wire codec, cryptography,
//! or Host filesystem I/O.

pub mod auth;
pub mod billing;
pub mod ids;
pub mod list;

#[cfg(feature = "protocol-compat")]
pub use cats_protocol::{
    blockd, chunk, error, guest, metering, node_identity, oci, production_mutation_admission,
    runtime_node_authority, runtime_reconciliation, semantic_control, sessions,
};

#[cfg(feature = "artifacts-compat")]
pub use cats_artifacts as runtime_artifacts;

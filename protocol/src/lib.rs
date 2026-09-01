//! Shared wire contracts and strict codecs for Cats components.
//!
//! This crate is the single source of truth for:
//! - closed product, identity, and operation wire contracts;
//! - semantic runtime control and provider-neutral storage protocols;
//! - Guest Agent protocol frames;
//! - blockd host-control protocol and observability DTOs;
//! - ChunkStore protocol constants;
//! - stable error codes shared across HTTP surfaces.
//!
//! It is dependency-light and contains no installed Host filesystem I/O.
//! Encoding and hashing live here only when they are part of a shared wire
//! contract.

pub mod blockd;
pub mod chunk;
pub mod error;
pub mod guest;
pub mod metering;
pub mod node_identity;
pub mod oci;
pub mod production_mutation_admission;
pub mod runtime_node_authority;
pub mod runtime_reconciliation;
pub mod semantic_control;
pub mod sessions;

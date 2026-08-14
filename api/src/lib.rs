//! Shared API and protocol types for all Cats components.
//!
//! This crate is the single source of truth for:
//! - resource wire types served by the control plane (`resources`, `requests`)
//! - lifecycle states per ADR-0002 (`resources::CatState` and friends)
//! - control-plane -> node-agent job protocol (`nodejob`)
//! - target runtime reconciliation protocol (`runtime_reconciliation`)
//! - guest agent protocol frames (`guest`)
//! - blockd host-control protocol and observability DTOs (`blockd`)
//! - ChunkStore protocol constants per ADR-0003 (`chunk`)
//! - error codes shared across HTTP surfaces (`error`)
//!
//! It must stay dependency-light. Encoding and hashing live here only when
//! they are themselves part of a shared wire contract.

pub mod agent_registration;
pub mod auth;
pub mod billing;
pub mod blockd;
pub mod cat_create;
pub mod chunk;
pub mod error;
pub mod fleet_verification;
pub mod gateway_workload_identity;
pub mod guest;
pub mod ids;
pub mod metering;
pub mod nodejob;
pub mod object_write_gateway;
pub mod oci;
pub mod persistent_disk;
pub mod requests;
pub mod resources;
pub mod route_grant;
pub mod route_grant_v2;
pub mod runtime_artifacts;
pub mod runtime_host_loss_recovery;
pub mod runtime_node_authority;
pub mod runtime_product_reads;
pub mod runtime_reconciliation;

//! Shared API and protocol types for all Cats components.
//!
//! This crate is the single source of truth for:
//! - closed product, identity and operation wire contracts
//! - atomic runtime lifecycle and observation-only inventory protocols
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
pub mod chunk;
pub mod error;
pub mod gateway_workload_identity;
pub mod guest;
pub mod ids;
pub mod list;
pub mod metering;
pub mod object_write_gateway;
pub mod oci;
pub mod production_mutation_admission;
pub mod route_grant_v2;
pub mod route_signing_operator;
pub mod runtime_artifacts;
pub mod runtime_lifecycle_volume;
pub mod runtime_node_authority;
pub mod runtime_reconciliation;
pub mod semantic_control;
pub mod sessions;

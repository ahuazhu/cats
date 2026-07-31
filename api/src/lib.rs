//! Shared API and protocol types for all Cats components.
//!
//! This crate is the single source of truth for:
//! - resource wire types served by the control plane (`resources`, `requests`)
//! - lifecycle states per ADR-0002 (`resources::CatState` and friends)
//! - control-plane -> node-agent job protocol (`nodejob`)
//! - guest agent protocol frames (`guest`)
//! - blockd host-control protocol and observability DTOs (`blockd`)
//! - ChunkStore protocol constants per ADR-0003 (`chunk`)
//! - error codes shared across HTTP surfaces (`error`)
//!
//! It must stay dependency-light; encoding/hashing implementations live in
//! `cats-blockd`.

pub mod auth;
pub mod billing;
pub mod blockd;
pub mod chunk;
pub mod error;
pub mod guest;
pub mod ids;
pub mod metering;
pub mod nodejob;
pub mod requests;
pub mod resources;

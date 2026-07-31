//! Lightweight host-side clients for Cats block frontends.
//!
//! This crate deliberately contains no block engine, storage adapter, or
//! Linux vhost-user implementation. FakeVmm, readiness probes, recovery tools,
//! and protocol oracles can speak NBD without linking the `cats-blockd`
//! service implementation.

pub mod nbd;

pub use nbd::{NbdClient, NbdError, NbdResult, ReadWriteSend, EINVAL, EIO, EPERM};

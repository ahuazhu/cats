//! Shared semantic contracts, fixtures, and test doubles.
//!
//! This crate is deliberately test-only: workspace crates may reference it
//! through `dev-dependencies`, never through production dependencies.

pub mod blob_doubles;
pub mod node_builder;
pub mod storage_contract;

pub use node_builder::{workspace_bin, NodeConfigBuilder, NodeConfigParts, TempDirFixture};
pub use storage_contract::{blob_store_contract, metadata_store_contract};

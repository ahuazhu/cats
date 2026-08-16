//! Shared semantic contracts, fixtures, and test doubles.
//!
//! This crate is deliberately test-only: workspace crates may reference it
//! through `dev-dependencies`, never through production dependencies.

pub mod blob_doubles;
pub mod node_builder;
pub mod sqlite_volume_authority;
pub mod storage_contract;

pub use node_builder::{
    sqlite_node_runtime_blockd_fixture, workspace_bin, workspace_example, NodeConfigBuilder,
    NodeConfigParts, TempDirFixture,
};
pub use sqlite_volume_authority::{
    install_sqlite_grant, prepare_sqlite_authorized_serving, SqliteTestVolumeAuthority,
    SqliteTestVolumeGrant,
};
pub use storage_contract::{blob_store_contract, metadata_store_contract};

//! Provider-neutral storage contracts used by the Cats control and data planes.
//!
//! This crate intentionally contains no cloud SDK, wire protocol, bucket,
//! database driver, or provider-specific configuration. Implementations live
//! in adapter crates and are selected only by process composition roots.

pub mod adapter;
pub mod authority;
pub mod blob;
pub mod metadata;

pub use adapter::{
    open_blob_store, open_metadata_store, AdapterConfig, AdapterError, AdapterSelection,
    BlobStoreFactory, MetadataStoreFactory,
};
pub use blob::{validate_key, BlobError, BlobStore};
pub use metadata::{MetaError, MetadataStore, SnapshotRow, VolumeHead};

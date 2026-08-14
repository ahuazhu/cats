//! Provider-neutral storage contracts used by the Cats control and data planes.
//!
//! This crate intentionally contains no cloud SDK, wire protocol, bucket,
//! database driver, or provider-specific configuration. Implementations live
//! in adapter crates and are selected only by process composition roots.

pub mod adapter;
pub mod authority;
pub mod blob;
pub mod delete;
pub mod host_fence;
pub mod image_manifest;
pub mod metadata;
pub mod object_write_authority;
pub mod trusted_host_fence;
pub mod trusted_host_recovery;

pub use adapter::{
    open_blob_store, open_metadata_store, AdapterConfig, AdapterError, AdapterSelection,
    BlobStoreFactory, MetadataStoreFactory,
};
pub use blob::{
    validate_key, BlobError, BlobListPage, BlobStore, QualifiedDeleteListPage,
    BLOB_LIST_PAGE_MAX_KEYS,
};
pub use delete::{delete_volume_objects_page, volume_object_prefix, DeletePrefixPage};
pub use image_manifest::{
    decode_image_manifest, encode_image_manifest, image_manifest_key, read_image_manifest,
    read_image_manifest_until, ImageManifestChunkV1, ImageManifestProblem, ImageManifestReadError,
    ImageManifestV1, LowerHexSha256, IMAGE_MANIFEST_MAX_BYTES,
};
pub use metadata::{MetaError, MetadataStore, SnapshotRow, VolumeHead};

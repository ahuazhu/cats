//! cats-blockd: Direct-OS ChunkStore block engine (Direct-S3 implementation).
//!
//! Layering (spec: docs/specs/blockd-protocol.md):
//!
//! ```text
//! frontend (NBD today, vhost-user-blk on Linux later)
//!        └── engine::ChunkEngine        read/write/flush/trim, dirty tracking,
//!                                       pending commit packs, crash recovery
//!             ├── blobstore::BlobStore  immutable objects (File / S3)
//!             └── meta::MetadataStore   volume root CAS + lease/fencing
//! ```
//!
//! The engine is deliberately synchronous: every entry point is `&self` and
//! thread-safe, correctness comes from a small number of coarse locks. This
//! is the V1 correctness baseline the spec freezes; multi-queue performance
//! work must not change the commit protocol.

pub mod blobstore;
pub mod crashpoint;
pub mod engine;
pub mod format;
pub mod meta;
pub mod nbd;
pub mod s3;

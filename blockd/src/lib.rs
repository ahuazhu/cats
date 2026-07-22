//! Provider-neutral Direct-OS ChunkStore block engine.
//!
//! Layering (spec: docs/specs/blockd-protocol.md):
//!
//! ```text
//! frontend (NBD today, vhost-user-blk on Linux later)
//!        └── engine::ChunkEngine        read/write/flush/trim, dirty tracking,
//!                                       pending commit packs, crash recovery
//!             ├── cats_storage::BlobStore      immutable object port
//!             └── cats_storage::MetadataStore  root CAS + fencing port
//! ```
//!
//! The engine is deliberately synchronous: every entry point is `&self` and
//! thread-safe, correctness comes from a small number of coarse locks. This
//! is the V1 correctness baseline the spec freezes; multi-queue performance
//! work must not change the commit protocol.

pub mod crashpoint;
pub mod engine;
pub mod format;
pub mod nbd;

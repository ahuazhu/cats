//! Provider-neutral Direct-OS ChunkStore block engine.
//!
//! Layering (spec: docs/specs/blockd-protocol.md):
//!
//! ```text
//! frontend  ├── nbd            portable: dev/test/recovery/oracle (§7)
//!           └── vhost_user     Linux: production Guest path (§7.1)
//!        └── engine::ChunkEngine        read/write/flush/trim, dirty tracking,
//!                                       pending commit packs, crash recovery
//!             ├── cats_storage::BlobStore      immutable object port
//!             └── cats_storage::MetadataStore  root CAS + fencing port
//! ```
//!
//! Both frontends are protocol adapters over the same engine calls, so they
//! share one commit protocol and one set of correctness tests; only the
//! transport differs.
//!
//! The engine is deliberately synchronous: every entry point is `&self` and
//! thread-safe, correctness comes from a small number of coarse locks. This
//! is the V1 correctness baseline the spec freezes; multi-queue performance
//! work must not change the commit protocol.

pub mod crashpoint;
pub mod engine;
pub mod format;
pub mod image;
pub mod nbd;
#[cfg(target_os = "linux")]
pub mod vhost_user;

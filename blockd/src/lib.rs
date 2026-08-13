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
pub mod frontend_contract;
pub mod image;
pub mod nbd;
pub mod runtime_socket_namespace;
pub mod serving_handoff;
pub mod target_control;
#[cfg(target_os = "linux")]
pub mod vhost_user;

// Keep the rust-vmm frontend implementation owned by cats-blockd, where its
// vm-memory and vmm-sys-util dependencies are real production dependencies.
// Cross-crate Linux qualification gets only the three synchronous operations
// needed to prove the installed vhost-user data path.
#[cfg(all(target_os = "linux", feature = "test-vhost-user-frontend"))]
#[path = "../tests/vhu_frontend/mod.rs"]
mod vhu_frontend_driver;

#[cfg(all(target_os = "linux", feature = "test-vhost-user-frontend"))]
#[doc(hidden)]
pub mod test_vhost_user_frontend {
    use std::io;
    use std::path::Path;

    pub const STATUS_OK: u8 = super::vhu_frontend_driver::VIRTIO_BLK_S_OK;

    pub struct Frontend(super::vhu_frontend_driver::BlkFrontend);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Completion {
        pub status: u8,
        pub data: Vec<u8>,
    }

    impl Frontend {
        pub fn connect(
            socket: &Path,
            num_queues: usize,
            queue_size: u16,
            slots: u16,
            event_idx: bool,
        ) -> io::Result<Self> {
            super::vhu_frontend_driver::BlkFrontend::connect(
                socket, num_queues, queue_size, slots, event_idx,
            )
            .map(Self)
        }

        pub fn write_at(&mut self, sector: u64, data: &[u8]) -> io::Result<Completion> {
            self.0.queue(0).write_at(sector, data).map(Completion::from)
        }

        pub fn flush(&mut self) -> io::Result<Completion> {
            self.0.queue(0).flush().map(Completion::from)
        }

        pub fn read_at(&mut self, sector: u64, len: usize) -> io::Result<Completion> {
            self.0.queue(0).read_at(sector, len).map(Completion::from)
        }
    }

    impl From<super::vhu_frontend_driver::Completion> for Completion {
        fn from(completion: super::vhu_frontend_driver::Completion) -> Self {
            Self {
                status: completion.status,
                data: completion.data,
            }
        }
    }
}

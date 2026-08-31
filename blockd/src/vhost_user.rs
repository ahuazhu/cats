//! vhost-user-blk frontend (production Guest data path, spec §7.1).
//!
//! ```text
//! Guest virtio-blk driver
//!   └── Cloud Hypervisor vhost-user-blk client (queues live in shared Guest RAM)
//!        └── this module: virtqueue -> virtio-blk request decode
//!             └── engine::ChunkEngine  (identical commit protocol as NBD)
//! ```
//!
//! The frontend is a protocol adapter only: every request is translated into the
//! same `ChunkEngine` calls the NBD frontend makes (spec §7), so the FLUSH
//! commit protocol, dirty tracking, fencing and crash recovery are unchanged and
//! stay covered by the existing oracle tests. What changes is the transport: the
//! Guest kicks a virtqueue in shared memory instead of crossing the host kernel's
//! NBD client and a Unix socket per request.
//!
//! Linux only: vhost-user needs eventfd, shared file-backed Guest memory and
//! `SCM_RIGHTS` fd passing. The NBD frontend remains the portable path.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{Error as VhostUserError, Listener};
use vhost_user_backend::{
    Error as DaemonError, VhostUserBackend, VhostUserDaemon, VringRwLock, VringT,
};
use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_MQ,
    VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_WRITE_ZEROES, VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_IOERR,
    VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_T_DISCARD, VIRTIO_BLK_T_FLUSH,
    VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, VIRTIO_BLK_T_WRITE_ZEROES,
};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC};
use virtio_queue::{DescriptorChain, QueueOwnedT, Reader, Writer};
use vm_memory::{
    ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::event::{
    new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier,
};

use cats_protocol::runtime_reconciliation::{Id, GUEST_DEVICE_SERIAL_MAX_BYTES_V1};

use crate::engine::{ChunkEngine, EngineError};

/// virtio-blk works in 512-byte sectors regardless of the advertised block size.
pub const SECTOR_SHIFT: u32 = 9;
pub const SECTOR_SIZE: u64 = 1 << SECTOR_SHIFT;

/// Logical block size advertised to the Guest. 512 keeps the Guest-visible
/// geometry identical to the Phase A kernel-NBD path (`nbd-client -b 512`), so
/// an already-seeded golden root image stays byte-compatible when a Cat moves
/// from the NBD path to this one.
pub const BLK_SIZE: u32 = 512;

/// Largest data transfer accepted in one request. Mirrors the NBD frontend's
/// `MAX_PAYLOAD`: a malicious or broken driver must not be able to make the
/// backend allocate without bound.
pub const MAX_IO_BYTES: usize = 32 * 1024 * 1024;

/// Default virtqueue depth. Cloud Hypervisor's default for a block device.
pub const DEFAULT_QUEUE_SIZE: u16 = 256;

/// virtio-blk request header: device-readable, first descriptor of every chain.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct RequestHeader {
    request_type: u32,
    _ioprio: u32,
    sector: u64,
}

// SAFETY: `RequestHeader` is `repr(C)`, contains only integer fields with no
// padding and no invalid bit patterns, so any byte pattern is a valid value.
unsafe impl ByteValued for RequestHeader {}

/// Payload of DISCARD / WRITE_ZEROES requests (one per segment).
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct DiscardWriteZeroes {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}

// SAFETY: `repr(C)` integer-only POD without padding; every byte pattern is
// a valid value.
unsafe impl ByteValued for DiscardWriteZeroes {}

type GuestMem = GuestMemoryMmap<()>;
type MemGuard = GuestMemoryLoadGuard<GuestMem>;

/// One worker thread per queue, and the queue-to-thread map is a 64-bit mask.
pub const MAX_QUEUES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum VhostUserBlkError {
    #[error("vhost-user needs between 1 and {MAX_QUEUES} queues, got {0}")]
    BadQueueCount(usize),
    #[error("vhost-user queue size must be a power of two in 1..=32768, got {0}")]
    BadQueueSize(u16),
    #[error("vhost-user Guest device serial must be a canonical Id of 1..=20 UTF-8 bytes")]
    BadGuestDeviceSerial,
    #[error("bind vhost-user socket {path}: {message}")]
    Bind { path: String, message: String },
    #[error("vhost-user daemon: {0}")]
    Daemon(String),
}

/// Exact Cloud Hypervisor V53 virtio-blk serial returned by GET_ID. The
/// zero-padded 20-byte transport representation is derived once from the
/// shared GuestDeviceIdentity value; it is never reconstructed from volume id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhostUserDeviceId([u8; VIRTIO_BLK_ID_BYTES as usize]);

impl VhostUserDeviceId {
    pub fn from_guest_device_serial(serial: &Id) -> Result<Self, VhostUserBlkError> {
        let bytes = serial.as_str().as_bytes();
        if bytes.is_empty() || bytes.len() > GUEST_DEVICE_SERIAL_MAX_BYTES_V1 {
            return Err(VhostUserBlkError::BadGuestDeviceSerial);
        }
        let mut padded = [0; VIRTIO_BLK_ID_BYTES as usize];
        padded[..bytes.len()].copy_from_slice(bytes);
        Ok(Self(padded))
    }

    fn test_default() -> Self {
        let mut padded = [0; VIRTIO_BLK_ID_BYTES as usize];
        let value = b"cats-vhost-test";
        padded[..value.len()].copy_from_slice(value);
        Self(padded)
    }

    fn padded_bytes(self) -> [u8; VIRTIO_BLK_ID_BYTES as usize] {
        self.0
    }
}

/// Frontend tunables. Multi-queue is the reason this frontend exists, but the
/// commit protocol is queue-count independent: every queue calls the same
/// engine, and FLUSH remains a whole-volume barrier.
#[derive(Debug, Clone, Copy)]
pub struct VhostUserOptions {
    pub num_queues: usize,
    pub queue_size: u16,
    pub guest_device_serial: VhostUserDeviceId,
}

impl Default for VhostUserOptions {
    fn default() -> Self {
        Self {
            num_queues: 1,
            queue_size: DEFAULT_QUEUE_SIZE,
            guest_device_serial: VhostUserDeviceId::test_default(),
        }
    }
}

impl VhostUserOptions {
    fn validate(&self) -> Result<(), VhostUserBlkError> {
        if self.num_queues == 0 || self.num_queues > MAX_QUEUES {
            return Err(VhostUserBlkError::BadQueueCount(self.num_queues));
        }
        // Upper bound is the virtio maximum ring size (spec 2.7).
        if self.queue_size == 0 || !self.queue_size.is_power_of_two() {
            return Err(VhostUserBlkError::BadQueueSize(self.queue_size));
        }
        Ok(())
    }
}

/// Serve one volume as a vhost-user-blk device on `socket` until the VMM
/// disconnects. The backend listens; Cloud Hypervisor connects.
pub fn serve_unix(
    socket: &Path,
    engine: Arc<ChunkEngine>,
    options: VhostUserOptions,
) -> Result<(), VhostUserBlkError> {
    let mut listener = bind(socket, options)?;
    serve_listener(&mut listener, engine, options)
}

/// Bind the vhost-user socket without accepting yet. Callers that must publish
/// readiness before a VMM starts (the node agent) bind first, then serve.
pub fn bind(socket: &Path, options: VhostUserOptions) -> Result<Listener, VhostUserBlkError> {
    bind_with_replacement(socket, options, true)
}

/// Bind only if the exact socket name is absent. Signed Runtime reconciliation
/// uses this after a full inventory proved absence; it must never unlink an
/// unverified process merely because the path collides.
pub fn bind_new(socket: &Path, options: VhostUserOptions) -> Result<Listener, VhostUserBlkError> {
    bind_with_replacement(socket, options, false)
}

fn bind_with_replacement(
    socket: &Path,
    options: VhostUserOptions,
    replace_existing: bool,
) -> Result<Listener, VhostUserBlkError> {
    options.validate()?;
    Listener::new(socket, replace_existing).map_err(|e| VhostUserBlkError::Bind {
        path: socket.display().to_string(),
        message: e.to_string(),
    })
}

/// Accept one VMM connection on an already bound listener and serve it until the
/// VMM disconnects.
pub fn serve_listener(
    listener: &mut Listener,
    engine: Arc<ChunkEngine>,
    options: VhostUserOptions,
) -> Result<(), VhostUserBlkError> {
    options.validate()?;
    let backend = BlkBackend::new(engine, options);
    // Empty until the VMM sends SET_MEM_TABLE with its shared Guest RAM.
    let mem = GuestMemoryAtomic::new(GuestMemoryMmap::new());
    let mut daemon = VhostUserDaemon::new("cats-blockd-vhu".to_string(), backend, mem)
        .map_err(|e| VhostUserBlkError::Daemon(e.to_string()))?;
    daemon
        .start(listener)
        .map_err(|e| VhostUserBlkError::Daemon(e.to_string()))?;
    match daemon.wait() {
        // A VMM that shuts the device down closes the control socket. That is
        // the normal end of service, not a failure.
        Ok(())
        | Err(DaemonError::HandleRequest(
            VhostUserError::Disconnected | VhostUserError::SocketBroken(_),
        )) => Ok(()),
        Err(error) => Err(VhostUserBlkError::Daemon(error.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

struct Inner {
    engine: Arc<ChunkEngine>,
    options: VhostUserOptions,
    mem: RwLock<Option<GuestMemoryAtomic<GuestMem>>>,
    event_idx: AtomicBool,
    /// Reported by VIRTIO_BLK_T_GET_ID; `blkid`-style tools show it as the
    /// device serial. This is the exact sealed GuestDeviceIdentity serial.
    device_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
}

/// vhost-user-blk device backed by one [`ChunkEngine`].
#[derive(Clone)]
pub struct BlkBackend {
    inner: Arc<Inner>,
}

impl BlkBackend {
    pub fn new(engine: Arc<ChunkEngine>, options: VhostUserOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                engine,
                options,
                mem: RwLock::new(None),
                event_idx: AtomicBool::new(false),
                device_id: options.guest_device_serial.padded_bytes(),
            }),
        }
    }

    /// virtio-blk config space (spec 5.2.4), little-endian, built explicitly so
    /// the wire layout does not depend on struct padding.
    fn config_space(&self) -> Vec<u8> {
        let engine = &self.inner.engine;
        let mut out = Vec::with_capacity(60);
        // capacity is in 512-byte sectors.
        out.extend_from_slice(&(engine.size() / SECTOR_SIZE).to_le_bytes());
        // size_max: largest single segment; seg_max: segments per request. Two
        // descriptors of every chain carry the header and the status byte.
        out.extend_from_slice(&(MAX_IO_BYTES as u32).to_le_bytes());
        out.extend_from_slice(&(u32::from(self.inner.options.queue_size) - 2).to_le_bytes());
        // geometry (cylinders/heads/sectors): unused by Linux, reported zero.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.push(0);
        out.push(0);
        out.extend_from_slice(&BLK_SIZE.to_le_bytes());
        // topology (not advertised): physical_block_exp, alignment_offset,
        // min_io_size, opt_io_size.
        out.push(0);
        out.push(0);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        // writeback cache: the engine acknowledges writes from the local NVMe
        // cache and only becomes durable on FLUSH (§6), which is exactly what
        // writeback=1 promises the Guest.
        out.push(1);
        out.push(0); // unused
        out.extend_from_slice(&(self.inner.options.num_queues as u16).to_le_bytes());
        // DISCARD limits: one segment per request, 512-byte alignment.
        let max_zero_sectors = (MAX_IO_BYTES as u32) >> SECTOR_SHIFT;
        out.extend_from_slice(&max_zero_sectors.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        // WRITE_ZEROES limits.
        out.extend_from_slice(&max_zero_sectors.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        // write_zeroes_may_unmap: a chunk covered end to end really is unmapped —
        // its map entry becomes a Hole and its objects are freed (spec §7.2) —
        // and a Hole reads as zeros, which is exactly what this bit promises.
        out.push(1);
        out.extend_from_slice(&[0u8; 3]);
        out
    }

    fn process_queue(&self, vring: &VringRwLock) -> io::Result<()> {
        let binding = self
            .inner
            .mem
            .read()
            .expect("guest memory lock poisoned")
            .clone()
            .ok_or_else(|| io::Error::other("vhost-user kick before SET_MEM_TABLE"))?;
        let guard = binding.memory();
        let mem: &GuestMem = &guard;

        // Collect first: the avail ring must be released before `add_used`.
        let chains: Vec<DescriptorChain<MemGuard>> = {
            let mut state = vring.get_mut();
            state
                .get_queue_mut()
                .iter(guard.clone())
                .map_err(|e| io::Error::other(format!("virtqueue iteration: {e}")))?
                .collect()
        };

        let mut any = false;
        for chain in chains {
            let head = chain.head_index();
            let written = self.execute(mem, chain);
            vring
                .add_used(head, written)
                .map_err(|e| io::Error::other(format!("add used descriptor: {e}")))?;
            any = true;
        }
        if any
            && vring
                .needs_notification()
                .map_err(|e| io::Error::other(format!("needs notification: {e}")))?
        {
            vring.signal_used_queue()?;
        }
        Ok(())
    }

    /// Execute one virtio-blk request; returns the number of bytes written into
    /// the device-writable part of the chain (payload plus the status byte).
    ///
    /// A malformed chain (no writable status byte, truncated header) is the one
    /// case with nowhere to report an error: it is logged and completed with a
    /// zero-length used entry, matching how Cloud Hypervisor's own block devices
    /// handle a broken driver.
    fn execute(&self, mem: &GuestMem, chain: DescriptorChain<MemGuard>) -> u32 {
        let mut reader = match Reader::new(mem, chain.clone()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("vhost-user-blk: unreadable descriptor chain: {e}");
                return 0;
            }
        };
        let mut writer = match Writer::new(mem, chain) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!("vhost-user-blk: unwritable descriptor chain: {e}");
                return 0;
            }
        };
        if writer.available_bytes() == 0 {
            tracing::warn!("vhost-user-blk: request chain without a status byte");
            return 0;
        }
        // The status byte is always the last device-writable byte.
        let data_capacity = writer.available_bytes() - 1;
        let mut status_writer = match writer.split_at(data_capacity) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!("vhost-user-blk: cannot split status byte: {e}");
                return 0;
            }
        };
        let header: RequestHeader = match reader.read_obj() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("vhost-user-blk: truncated request header: {e}");
                let _ = status_writer.write_obj(VIRTIO_BLK_S_IOERR as u8);
                return 1;
            }
        };

        let (status, written) = self.dispatch(&header, &mut reader, &mut writer, data_capacity);
        if status_writer.write_obj(status).is_err() {
            tracing::warn!("vhost-user-blk: cannot write request status");
            return written;
        }
        written + 1
    }

    fn dispatch(
        &self,
        header: &RequestHeader,
        reader: &mut Reader<'_>,
        writer: &mut Writer<'_>,
        data_capacity: usize,
    ) -> (u8, u32) {
        let engine = &self.inner.engine;
        let sector = u64::from_le(header.sector);
        let offset = match sector.checked_mul(SECTOR_SIZE) {
            Some(o) => o,
            None => return (VIRTIO_BLK_S_IOERR as u8, 0),
        };

        match u32::from_le(header.request_type) {
            VIRTIO_BLK_T_IN => {
                if data_capacity > MAX_IO_BYTES {
                    return (VIRTIO_BLK_S_IOERR as u8, 0);
                }
                let mut buf = vec![0u8; data_capacity];
                match engine.read(offset, &mut buf) {
                    Ok(()) => match writer.write_all(&buf) {
                        Ok(()) => (VIRTIO_BLK_S_OK as u8, data_capacity as u32),
                        Err(e) => {
                            tracing::warn!("vhost-user-blk: read payload write-back failed: {e}");
                            (VIRTIO_BLK_S_IOERR as u8, 0)
                        }
                    },
                    Err(e) => (status_for(&e), 0),
                }
            }
            VIRTIO_BLK_T_OUT => {
                let len = reader.available_bytes();
                if len > MAX_IO_BYTES {
                    return (VIRTIO_BLK_S_IOERR as u8, 0);
                }
                let mut buf = vec![0u8; len];
                if let Err(e) = reader.read_exact(&mut buf) {
                    tracing::warn!("vhost-user-blk: truncated write payload: {e}");
                    return (VIRTIO_BLK_S_IOERR as u8, 0);
                }
                match engine.write(offset, &buf) {
                    Ok(()) => (VIRTIO_BLK_S_OK as u8, 0),
                    Err(e) => (status_for(&e), 0),
                }
            }
            VIRTIO_BLK_T_FLUSH => match engine.flush() {
                Ok(_) => (VIRTIO_BLK_S_OK as u8, 0),
                Err(e) => (status_for(&e), 0),
            },
            request_type @ (VIRTIO_BLK_T_DISCARD | VIRTIO_BLK_T_WRITE_ZEROES) => {
                // The sector field of the header is unused here; each segment
                // carries its own range.
                let segments = reader.available_bytes() / size_of::<DiscardWriteZeroes>();
                if segments == 0 {
                    return (VIRTIO_BLK_S_IOERR as u8, 0);
                }
                for _ in 0..segments {
                    let segment: DiscardWriteZeroes = match reader.read_obj() {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("vhost-user-blk: truncated discard segment: {e}");
                            return (VIRTIO_BLK_S_IOERR as u8, 0);
                        }
                    };
                    // The only defined flag is UNMAP (bit 0) on WRITE_ZEROES;
                    // we always write real zeroes, which satisfies both.
                    let flags = u32::from_le(segment.flags);
                    let unmap_allowed = request_type == VIRTIO_BLK_T_WRITE_ZEROES && flags & 1 != 0;
                    if flags & !1 != 0 || (flags & 1 != 0 && !unmap_allowed) {
                        return (VIRTIO_BLK_S_UNSUPP as u8, 0);
                    }
                    let start = match u64::from_le(segment.sector).checked_mul(SECTOR_SIZE) {
                        Some(s) => s,
                        None => return (VIRTIO_BLK_S_IOERR as u8, 0),
                    };
                    let len = u64::from(u32::from_le(segment.num_sectors)) * SECTOR_SIZE;
                    if let Err(e) = engine.write_zeroes(start, len) {
                        return (status_for(&e), 0);
                    }
                }
                (VIRTIO_BLK_S_OK as u8, 0)
            }
            VIRTIO_BLK_T_GET_ID => {
                let len = data_capacity.min(self.inner.device_id.len());
                match writer.write_all(&self.inner.device_id[..len]) {
                    Ok(()) => (VIRTIO_BLK_S_OK as u8, len as u32),
                    Err(e) => {
                        tracing::warn!("vhost-user-blk: cannot report device id: {e}");
                        (VIRTIO_BLK_S_IOERR as u8, 0)
                    }
                }
            }
            other => {
                tracing::debug!("vhost-user-blk: unsupported request type {other}");
                (VIRTIO_BLK_S_UNSUPP as u8, 0)
            }
        }
    }
}

/// Engine errors the Guest can see. A fenced attachment must fail closed: the
/// Guest gets EIO rather than a silently dropped write.
fn status_for(error: &EngineError) -> u8 {
    match error {
        EngineError::Fenced => tracing::warn!("vhost-user-blk: request on a fenced attachment"),
        EngineError::OutOfBounds { .. } => {}
        other => tracing::warn!("vhost-user-blk: request failed: {other}"),
    }
    VIRTIO_BLK_S_IOERR as u8
}

impl VhostUserBackend for BlkBackend {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        self.inner.options.num_queues
    }

    fn max_queue_size(&self) -> usize {
        self.inner.options.queue_size as usize
    }

    fn features(&self) -> u64 {
        let mut features = 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_DISCARD
            | 1 << VIRTIO_BLK_F_WRITE_ZEROES
            | 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        if self.inner.options.num_queues > 1 {
            features |= 1 << VIRTIO_BLK_F_MQ;
        }
        features
    }

    /// Logged rather than stored: a Guest that refuses a feature we depend on
    /// (FLUSH above all) is the first thing to check when a device misbehaves.
    fn acked_features(&self, features: u64) {
        tracing::debug!(
            volume = self.inner.engine.volume_id(),
            features = format!("{features:#x}"),
            "vhost-user-blk features negotiated"
        );
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&self, enabled: bool) {
        self.inner.event_idx.store(enabled, Ordering::Release);
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let space = self.config_space();
        let mut out = vec![0u8; size as usize];
        let offset = offset as usize;
        if offset < space.len() {
            let available = space.len() - offset;
            let copy = available.min(out.len());
            out[..copy].copy_from_slice(&space[offset..offset + copy]);
        }
        out
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMem>) -> io::Result<()> {
        *self.inner.mem.write().expect("guest memory lock poisoned") = Some(mem);
        Ok(())
    }

    /// One worker thread per queue: the whole point of the frontend is that a
    /// multi-queue Guest can have several requests in the engine at once.
    fn queues_per_thread(&self) -> Vec<u64> {
        (0..self.inner.options.num_queues)
            .map(|queue| 1u64 << queue)
            .collect()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        new_event_consumer_and_notifier(EventFlag::NONBLOCK).ok()
    }

    fn handle_event(
        &self,
        device_event: u16,
        _evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> io::Result<()> {
        let vring = vrings.get(device_event as usize).ok_or_else(|| {
            io::Error::other(format!("event {device_event} on thread {thread_id}"))
        })?;

        if self.inner.event_idx.load(Ordering::Acquire) {
            // With EVENT_IDX the Guest suppresses kicks while we are draining,
            // so re-check the ring until it stays empty after re-enabling
            // notifications; otherwise a request can sit unnoticed.
            loop {
                vring
                    .disable_notification()
                    .map_err(|e| io::Error::other(format!("disable notification: {e}")))?;
                self.process_queue(vring)?;
                if !vring
                    .enable_notification()
                    .map_err(|e| io::Error::other(format!("enable notification: {e}")))?
                {
                    break;
                }
            }
        } else {
            self.process_queue(vring)?;
        }
        Ok(())
    }
}

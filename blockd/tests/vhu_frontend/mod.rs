//! A userspace vhost-user **frontend**: the VMM/driver half of the protocol.
//!
//! The backend under test (`cats_blockd::vhost_user`) is built on the rust-vmm
//! `vhost-user-backend` crate, so validating it with that crate's own helpers
//! would prove little. This harness instead implements the driver side straight
//! from the virtio 1.2 and vhost-user specifications: it allocates "Guest RAM"
//! as a memfd, hands it over with `VHOST_USER_SET_MEM_TABLE`, builds split
//! virtqueues by hand, kicks eventfds and reads the used ring. That is exactly
//! what Cloud Hypervisor's vhost-user-blk client does, minus the VM.
//!
//! Assumes a little-endian host (x86_64 / aarch64): descriptor fields use the
//! explicit `Le*` types, but ring indices are written as native `u16`.

#![allow(dead_code)] // Each test target uses a subset of the driver API.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{Frontend, VhostUserFrontend};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{
    Bytes, FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, Le16, Le32, Le64,
};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const SECTOR_SIZE: u64 = 512;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_RING_F_EVENT_IDX: u64 = 1 << 29;

/// Per-queue ring area: descriptor table, avail ring and used ring each get one
/// page-aligned 4 KiB slot, which covers queue sizes up to 256.
const RING_STRIDE: u64 = 3 * 4096;
const MAX_QUEUE_SIZE: u16 = 256;

/// Largest single transfer the harness can stage in one slot.
pub const MAX_XFER: usize = 1024 * 1024;
/// Scratch bytes per in-flight request: header/status page, then the outgoing
/// and incoming payload areas.
const SLOT_SIZE: u64 = 4096 + 2 * MAX_XFER as u64;
const SLOT_HEADER: u64 = 0;
const SLOT_STATUS: u64 = 32;
const SLOT_OUT: u64 = 4096;
const SLOT_IN: u64 = 4096 + MAX_XFER as u64;

/// Descriptors reserved per in-flight request, so a slot index maps to a fixed
/// descriptor head and the harness needs no free list. Eight covers the longest
/// chain it builds: header, up to five payload chunks, incoming data, status.
const DESCS_PER_SLOT: u16 = 8;

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Anonymous shared memory standing in for Guest RAM. memfd (tmpfs) rather than
/// a temp file so benchmark numbers are not polluted by page-cache writeback.
fn memfd(size: u64) -> io::Result<File> {
    // SAFETY: the name is a valid NUL-terminated C string and MFD_CLOEXEC is a
    // valid flag; the returned fd is owned by this process.
    let fd = unsafe { libc::memfd_create(c"cats-vhu-harness".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, valid, owned file descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_len(size)?;
    Ok(file)
}

#[derive(Debug, Clone, Copy)]
struct RingLayout {
    desc: u64,
    avail: u64,
    used: u64,
    size: u16,
}

impl RingLayout {
    fn new(base: u64, size: u16) -> Self {
        Self {
            desc: base,
            avail: base + 4096,
            used: base + 8192,
            size,
        }
    }
}

/// Connected vhost-user frontend. Dropping it closes the control socket, which
/// is how a VMM tells the backend the device is gone.
pub struct BlkFrontend {
    frontend: Frontend,
    mem: Arc<GuestMemoryMmap<()>>,
    _memfd: File,
    queues: Vec<Option<BlkQueue>>,
    acked_features: u64,
    num_queues: usize,
}

impl BlkFrontend {
    /// Connect to `socket`, negotiate, and set up `num_queues` ready virtqueues.
    pub fn connect(
        socket: &Path,
        num_queues: usize,
        queue_size: u16,
        slots: u16,
        event_idx: bool,
    ) -> io::Result<Self> {
        assert!(num_queues > 0, "at least one queue");
        assert!(
            queue_size <= MAX_QUEUE_SIZE && queue_size.is_power_of_two(),
            "queue size must be a power of two up to {MAX_QUEUE_SIZE}"
        );
        let slots = slots.min(queue_size / DESCS_PER_SLOT).max(1);

        let ring_area = RING_STRIDE * num_queues as u64;
        let slot_area_base = ring_area.next_multiple_of(1024 * 1024);
        let per_queue_slots = SLOT_SIZE * u64::from(slots);
        let size = slot_area_base + per_queue_slots * num_queues as u64;

        let file = memfd(size)?;
        let mem = GuestMemoryMmap::<()>::from_ranges_with_files([(
            GuestAddress(0),
            size as usize,
            Some(FileOffset::new(file.try_clone()?, 0)),
        )])
        .map_err(|e| other(format!("map guest memory: {e}")))?;
        let region = mem
            .find_region(GuestAddress(0))
            .ok_or_else(|| other("guest memory region vanished"))?;
        let region_info = VhostUserMemoryRegionInfo::from_guest_region(region)
            .map_err(|e| other(format!("describe guest memory region: {e}")))?;
        // vhost-user passes vring addresses in the *frontend's* address space
        // (the backend translates them through the memory table), while
        // descriptor addresses are guest-physical. Guest physical base is 0
        // here, so a GPA is also the offset into the region.
        let vmm_base = region_info.userspace_addr;
        let mem = Arc::new(mem);

        let stream = UnixStream::connect(socket)?;
        let mut frontend = Frontend::from_stream(stream, num_queues as u64);
        frontend
            .set_owner()
            .map_err(|e| other(format!("SET_OWNER: {e}")))?;
        let backend_features = frontend
            .get_features()
            .map_err(|e| other(format!("GET_FEATURES: {e}")))?;
        if backend_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return Err(other("backend does not offer VHOST_USER_F_PROTOCOL_FEATURES"));
        }
        if backend_features & VIRTIO_F_VERSION_1 == 0 {
            return Err(other("backend does not offer VIRTIO_F_VERSION_1"));
        }
        let protocol = frontend
            .get_protocol_features()
            .map_err(|e| other(format!("GET_PROTOCOL_FEATURES: {e}")))?;
        frontend
            .set_protocol_features(
                protocol & (VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG),
            )
            .map_err(|e| other(format!("SET_PROTOCOL_FEATURES: {e}")))?;

        // A driver may decline any feature; declining EVENT_IDX exercises the
        // backend's plain notification path.
        let mut acked = backend_features;
        if !event_idx {
            acked &= !VIRTIO_RING_F_EVENT_IDX;
        }
        frontend
            .set_features(acked)
            .map_err(|e| other(format!("SET_FEATURES: {e}")))?;
        frontend
            .set_mem_table(std::slice::from_ref(&region_info))
            .map_err(|e| other(format!("SET_MEM_TABLE: {e}")))?;

        let event_idx = event_idx && acked & VIRTIO_RING_F_EVENT_IDX != 0;
        let mut queues = Vec::with_capacity(num_queues);
        for index in 0..num_queues {
            let ring = RingLayout::new(RING_STRIDE * index as u64, queue_size);
            // Rings start zeroed: memfd pages are zero-filled, and the harness
            // never reuses a frontend.
            let kick = EventFd::new(EFD_NONBLOCK)?;
            let call = EventFd::new(EFD_NONBLOCK)?;
            frontend
                .set_vring_num(index, queue_size)
                .map_err(|e| other(format!("SET_VRING_NUM: {e}")))?;
            frontend
                .set_vring_addr(
                    index,
                    &VringConfigData {
                        queue_max_size: queue_size,
                        queue_size,
                        flags: 0,
                        desc_table_addr: vmm_base + ring.desc,
                        used_ring_addr: vmm_base + ring.used,
                        avail_ring_addr: vmm_base + ring.avail,
                        log_addr: None,
                    },
                )
                .map_err(|e| other(format!("SET_VRING_ADDR: {e}")))?;
            frontend
                .set_vring_base(index, 0)
                .map_err(|e| other(format!("SET_VRING_BASE: {e}")))?;
            frontend
                .set_vring_kick(index, &kick)
                .map_err(|e| other(format!("SET_VRING_KICK: {e}")))?;
            frontend
                .set_vring_call(index, &call)
                .map_err(|e| other(format!("SET_VRING_CALL: {e}")))?;
            frontend
                .set_vring_enable(index, true)
                .map_err(|e| other(format!("SET_VRING_ENABLE: {e}")))?;
            queues.push(Some(BlkQueue {
                mem: mem.clone(),
                ring,
                slot_base: slot_area_base + per_queue_slots * index as u64,
                slots,
                kick,
                call,
                avail_idx: 0,
                last_used: 0,
                in_flight: 0,
                next_slot: 0,
                event_idx,
                timeout: Duration::from_secs(20),
                spin_iterations: 0,
            }));
        }

        Ok(Self {
            frontend,
            mem,
            _memfd: file,
            queues,
            acked_features: acked,
            num_queues,
        })
    }

    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }

    /// Read the virtio-blk configuration space over `VHOST_USER_GET_CONFIG`.
    pub fn config(&mut self, size: u32) -> io::Result<Vec<u8>> {
        let request = vec![0u8; size as usize];
        let (_, payload) = self
            .frontend
            .get_config(0, size, VhostUserConfigFlags::empty(), &request)
            .map_err(|e| other(format!("GET_CONFIG: {e}")))?;
        Ok(payload)
    }

    /// Borrow one queue's driver. Panics if it was taken with [`Self::take`].
    pub fn queue(&mut self, index: usize) -> &mut BlkQueue {
        self.queues[index]
            .as_mut()
            .expect("queue was moved out of the frontend")
    }

    /// Move a queue driver out so it can be run from its own thread. The
    /// frontend must stay alive: dropping it disconnects the backend.
    pub fn take(&mut self, index: usize) -> BlkQueue {
        self.queues[index]
            .take()
            .expect("queue already taken from the frontend")
    }

    pub fn num_queues(&self) -> usize {
        self.num_queues
    }

    pub fn memory(&self) -> &Arc<GuestMemoryMmap<()>> {
        &self.mem
    }
}

/// One virtqueue driven from the driver side.
pub struct BlkQueue {
    mem: Arc<GuestMemoryMmap<()>>,
    ring: RingLayout,
    slot_base: u64,
    slots: u16,
    kick: EventFd,
    call: EventFd,
    avail_idx: u16,
    last_used: u16,
    in_flight: u16,
    next_slot: u16,
    event_idx: bool,
    timeout: Duration,
    spin_iterations: u32,
}

/// A submitted, not yet completed request.
#[derive(Debug, Clone, Copy)]
pub struct Pending {
    pub head: u16,
    slot: u16,
    in_len: usize,
}

/// A completed request as the driver sees it.
#[derive(Debug, Clone)]
pub struct Completion {
    pub status: u8,
    pub data: Vec<u8>,
    /// `len` field of the used-ring element: bytes the device says it wrote.
    pub used_len: u32,
}

impl BlkQueue {
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Poll the used ring this many times before blocking on the call eventfd.
    ///
    /// Zero (the default) means "block immediately", which costs a `poll(2)` and
    /// a wakeup per completion. Real drivers pay neither: in a VM the completion
    /// arrives as an injected interrupt. Benchmarks use this to separate the
    /// backend's cost from the harness's notification cost.
    pub fn set_spin_iterations(&mut self, iterations: u32) {
        self.spin_iterations = iterations;
    }

    pub fn slots(&self) -> u16 {
        self.slots
    }

    fn slot_addr(&self, slot: u16) -> u64 {
        self.slot_base + SLOT_SIZE * u64::from(slot)
    }

    fn write_desc(&self, index: u16, addr: u64, len: u32, flags: u16, next: u16) -> io::Result<()> {
        let at = self.ring.desc + u64::from(index) * 16;
        self.mem
            .write_obj(Le64::from(addr), GuestAddress(at))
            .map_err(|e| other(format!("write descriptor addr: {e}")))?;
        self.mem
            .write_obj(Le32::from(len), GuestAddress(at + 8))
            .map_err(|e| other(format!("write descriptor len: {e}")))?;
        self.mem
            .write_obj(Le16::from(flags), GuestAddress(at + 12))
            .map_err(|e| other(format!("write descriptor flags: {e}")))?;
        self.mem
            .write_obj(Le16::from(next), GuestAddress(at + 14))
            .map_err(|e| other(format!("write descriptor next: {e}")))
    }

    /// Stage a request and publish it in the avail ring, without kicking.
    ///
    /// `out` is the device-readable payload after the 16-byte header, `in_len`
    /// the device-writable payload size (excluding the status byte), and
    /// `out_chunks` how many descriptors the outgoing payload is split across
    /// (a real driver splits at page boundaries).
    pub fn submit(
        &mut self,
        request_type: u32,
        sector: u64,
        out: &[u8],
        in_len: usize,
        out_chunks: usize,
    ) -> io::Result<Pending> {
        self.submit_inner(request_type, sector, Some(out), out.len(), in_len, out_chunks)
    }

    fn submit_inner(
        &mut self,
        request_type: u32,
        sector: u64,
        out: Option<&[u8]>,
        out_len: usize,
        in_len: usize,
        out_chunks: usize,
    ) -> io::Result<Pending> {
        assert!(out_len <= MAX_XFER, "outgoing payload too large");
        assert!(in_len <= MAX_XFER, "incoming payload too large");
        if self.in_flight >= self.slots {
            return Err(other("no free request slot; reap a completion first"));
        }
        let out_chunks = out_chunks.max(1);
        assert!(
            out_chunks == 1 || out_len.is_multiple_of(out_chunks),
            "split payload must divide evenly"
        );

        let slot = self.next_slot;
        self.next_slot = (self.next_slot + 1) % self.slots;
        let base = self.slot_addr(slot);

        // virtio-blk request header: type, ioprio, sector.
        self.mem
            .write_obj(Le32::from(request_type), GuestAddress(base + SLOT_HEADER))
            .map_err(|e| other(format!("write request type: {e}")))?;
        self.mem
            .write_obj(Le32::from(0u32), GuestAddress(base + SLOT_HEADER + 4))
            .map_err(|e| other(format!("write ioprio: {e}")))?;
        self.mem
            .write_obj(Le64::from(sector), GuestAddress(base + SLOT_HEADER + 8))
            .map_err(|e| other(format!("write sector: {e}")))?;
        if let Some(out) = out.filter(|o| !o.is_empty()) {
            self.mem
                .write_slice(out, GuestAddress(base + SLOT_OUT))
                .map_err(|e| other(format!("stage outgoing payload: {e}")))?;
        }
        // Poison the status byte so a device that never writes it is detected.
        self.mem
            .write_obj(0xffu8, GuestAddress(base + SLOT_STATUS))
            .map_err(|e| other(format!("poison status byte: {e}")))?;

        // Descriptor chain: header, outgoing chunks, incoming payload, status.
        let head = slot * DESCS_PER_SLOT;
        let mut chain: Vec<(u64, u32, bool)> = vec![(base + SLOT_HEADER, 16, false)];
        if out_len > 0 {
            let chunk = out_len / out_chunks;
            for index in 0..out_chunks {
                chain.push((
                    base + SLOT_OUT + (chunk * index) as u64,
                    chunk as u32,
                    false,
                ));
            }
        }
        if in_len > 0 {
            chain.push((base + SLOT_IN, in_len as u32, true));
        }
        chain.push((base + SLOT_STATUS, 1, true));
        assert!(
            chain.len() <= DESCS_PER_SLOT as usize,
            "chain of {} descriptors exceeds the {DESCS_PER_SLOT} reserved per slot",
            chain.len()
        );

        let ring_size = self.ring.size;
        for (position, (addr, len, writable)) in chain.iter().enumerate() {
            let index = (head + position as u16) % ring_size;
            let last = position + 1 == chain.len();
            let mut flags = 0u16;
            if *writable {
                flags |= VRING_DESC_F_WRITE;
            }
            let next = if last {
                0
            } else {
                (head + position as u16 + 1) % ring_size
            };
            if !last {
                flags |= VRING_DESC_F_NEXT;
            }
            self.write_desc(index, *addr, *len, flags, next)?;
        }

        // Publish: ring slot first, then the index with release ordering.
        let ring_slot = self.ring.avail + 4 + u64::from(self.avail_idx % ring_size) * 2;
        self.mem
            .write_obj(Le16::from(head % ring_size), GuestAddress(ring_slot))
            .map_err(|e| other(format!("publish avail entry: {e}")))?;
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.mem
            .store(self.avail_idx, GuestAddress(self.ring.avail + 2), Ordering::Release)
            .map_err(|e| other(format!("publish avail index: {e}")))?;
        if self.event_idx {
            // Ask to be notified as soon as the next used entry lands.
            self.mem
                .store(
                    self.last_used,
                    GuestAddress(self.ring.avail + 4 + u64::from(ring_size) * 2),
                    Ordering::Release,
                )
                .map_err(|e| other(format!("publish used_event: {e}")))?;
        }
        self.in_flight += 1;
        Ok(Pending {
            head: head % ring_size,
            slot,
            in_len,
        })
    }

    /// Pre-fill every slot's outgoing payload area.
    ///
    /// A real driver hands the device memory the Guest already holds; it does
    /// not copy the payload into a staging buffer per request. Benchmarks call
    /// this once and then use [`Self::submit_staged`] so the measurement does
    /// not include a copy that no real driver performs.
    pub fn prestage_out(&mut self, data: &[u8]) -> io::Result<()> {
        assert!(data.len() <= MAX_XFER, "outgoing payload too large");
        for slot in 0..self.slots {
            let base = self.slot_addr(slot);
            self.mem
                .write_slice(data, GuestAddress(base + SLOT_OUT))
                .map_err(|e| other(format!("prestage payload: {e}")))?;
        }
        Ok(())
    }

    /// Like [`Self::submit`], but the outgoing payload is whatever
    /// [`Self::prestage_out`] already placed in the slot.
    pub fn submit_staged(
        &mut self,
        request_type: u32,
        sector: u64,
        out_len: usize,
        in_len: usize,
    ) -> io::Result<Pending> {
        self.submit_inner(request_type, sector, None, out_len, in_len, 1)
    }

    /// Notify the device. Always kicking is spec-legal and keeps the harness
    /// independent of the device's suppression state.
    pub fn kick(&self) -> io::Result<()> {
        self.kick.write(1)
    }

    fn used_idx(&self) -> io::Result<u16> {
        self.mem
            .load(GuestAddress(self.ring.used + 2), Ordering::Acquire)
            .map_err(|e| other(format!("read used index: {e}")))
    }

    /// Wait for one used-ring element.
    pub fn reap(&mut self) -> io::Result<(u16, u32)> {
        let deadline = Instant::now() + self.timeout;
        for _ in 0..self.spin_iterations {
            if self.used_idx()? != self.last_used {
                break;
            }
            std::hint::spin_loop();
        }
        loop {
            if self.used_idx()? != self.last_used {
                break;
            }
            if Instant::now() >= deadline {
                return Err(other("timed out waiting for a used descriptor"));
            }
            // The call eventfd is the device's completion signal; poll it so an
            // idle wait does not burn a core, then re-check the ring.
            self.wait_call(Duration::from_millis(50))?;
        }
        let slot = u64::from(self.last_used % self.ring.size);
        let element = self.ring.used + 4 + slot * 8;
        let id: u32 = self
            .mem
            .read_obj::<Le32>(GuestAddress(element))
            .map_err(|e| other(format!("read used id: {e}")))?
            .into();
        let len: u32 = self
            .mem
            .read_obj::<Le32>(GuestAddress(element + 4))
            .map_err(|e| other(format!("read used len: {e}")))?
            .into();
        self.last_used = self.last_used.wrapping_add(1);
        self.in_flight -= 1;
        Ok((id as u16, len))
    }

    fn wait_call(&self, timeout: Duration) -> io::Result<()> {
        let mut fds = [libc::pollfd {
            fd: self.call.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: `fds` is a valid, correctly sized array of pollfd for the
        // duration of the call.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout.as_millis() as libc::c_int) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if ready > 0 {
            // Drain the counter; a completion may cover several requests.
            let _ = self.call.read();
        }
        Ok(())
    }

    /// Read back only the status byte, leaving the incoming payload in place
    /// (a real driver does not copy it out either).
    pub fn collect_status(&self, pending: Pending) -> io::Result<u8> {
        let base = self.slot_addr(pending.slot);
        self.mem
            .read_obj(GuestAddress(base + SLOT_STATUS))
            .map_err(|e| other(format!("read status byte: {e}")))
    }

    /// Read back a completion's status byte and incoming payload.
    pub fn collect(&self, pending: Pending, used_len: u32) -> io::Result<Completion> {
        let base = self.slot_addr(pending.slot);
        let status: u8 = self
            .mem
            .read_obj(GuestAddress(base + SLOT_STATUS))
            .map_err(|e| other(format!("read status byte: {e}")))?;
        let mut data = vec![0u8; pending.in_len];
        if pending.in_len > 0 {
            self.mem
                .read_slice(&mut data, GuestAddress(base + SLOT_IN))
                .map_err(|e| other(format!("read incoming payload: {e}")))?;
        }
        Ok(Completion {
            status,
            data,
            used_len,
        })
    }

    /// Submit one request and wait for it (the common case in tests).
    pub fn request(
        &mut self,
        request_type: u32,
        sector: u64,
        out: &[u8],
        in_len: usize,
    ) -> io::Result<Completion> {
        self.request_split(request_type, sector, out, in_len, 1)
    }

    pub fn request_split(
        &mut self,
        request_type: u32,
        sector: u64,
        out: &[u8],
        in_len: usize,
        out_chunks: usize,
    ) -> io::Result<Completion> {
        let pending = self.submit(request_type, sector, out, in_len, out_chunks)?;
        self.kick()?;
        let (id, used_len) = self.reap()?;
        if id != pending.head {
            return Err(other(format!(
                "used descriptor {id} does not match submitted head {}",
                pending.head
            )));
        }
        self.collect(pending, used_len)
    }

    pub fn read_at(&mut self, sector: u64, len: usize) -> io::Result<Completion> {
        self.request(VIRTIO_BLK_T_IN, sector, &[], len)
    }

    pub fn write_at(&mut self, sector: u64, data: &[u8]) -> io::Result<Completion> {
        self.request(VIRTIO_BLK_T_OUT, sector, data, 0)
    }

    pub fn flush(&mut self) -> io::Result<Completion> {
        self.request(VIRTIO_BLK_T_FLUSH, 0, &[], 0)
    }

    pub fn get_id(&mut self) -> io::Result<Completion> {
        self.request(VIRTIO_BLK_T_GET_ID, 0, &[], 20)
    }

    /// DISCARD / WRITE_ZEROES take their ranges as a payload, one 16-byte
    /// segment per range.
    pub fn zero_range(
        &mut self,
        request_type: u32,
        segments: &[(u64, u32, u32)],
    ) -> io::Result<Completion> {
        let mut payload = Vec::with_capacity(segments.len() * 16);
        for (sector, num_sectors, flags) in segments {
            payload.extend_from_slice(&sector.to_le_bytes());
            payload.extend_from_slice(&num_sectors.to_le_bytes());
            payload.extend_from_slice(&flags.to_le_bytes());
        }
        self.request(request_type, 0, &payload, 0)
    }
}

//! vhost-user-blk frontend acceptance tests (spec §7.1).
//!
//! Every test drives the backend through [`vhu_frontend`], an independent
//! driver-side implementation of virtio-blk over vhost-user, and cross-checks
//! the result through the NBD frontend attached to the *same* engine. NBD is the
//! spec's correctness oracle (§7), so "the Guest path and the oracle path see
//! the same bytes" is the property under test.
#![cfg(target_os = "linux")]

mod vhu_frontend;

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use cats_api::runtime_reconciliation::Id;
use cats_block_client::NbdClient;
use cats_blockd::engine::{ChunkEngine, EngineConfig, EngineError};
use cats_blockd::nbd;
use cats_blockd::vhost_user::{self, VhostUserDeviceId, VhostUserOptions};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_storage::MetadataStore;
use vhu_frontend::{
    BlkFrontend, SECTOR_SIZE, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP,
    VIRTIO_BLK_T_DISCARD, VIRTIO_BLK_T_WRITE_ZEROES,
};

const VOLUME_ID: &str = "vol_vhu_test";
const VOLUME_SIZE: u64 = 16 * 1024 * 1024;

/// One engine served by both frontends, mirroring how the node agent runs
/// `cats-blockd`: vhost-user for the Guest, NBD for seeding and recovery.
struct Harness {
    _dir: tempfile::TempDir,
    engine: Arc<ChunkEngine>,
    meta: Arc<SqliteMetadataStore>,
    vhost_user_socket: PathBuf,
    nbd_socket: PathBuf,
    server: Option<JoinHandle<Result<(), vhost_user::VhostUserBlkError>>>,
    options: VhostUserOptions,
}

impl Harness {
    fn start(options: VhostUserOptions) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).expect("blob store"));
        let meta =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).expect("meta store"));
        meta.create_volume(VOLUME_ID, VOLUME_SIZE).expect("volume");
        meta.install_grant_for_tests(VOLUME_ID, "att-vhu", 1)
            .expect("external grant");
        let engine = ChunkEngine::attach_granted(
            EngineConfig::new(VOLUME_ID, dir.path().join("data"), "att-vhu"),
            blob,
            meta.clone(),
        )
        .expect("attach engine");

        // Bind before spawning so a connect() right after `start` cannot race
        // the listener; this is also why the daemon exposes `bind` separately.
        let vhost_user_socket = dir.path().join("vhu.sock");
        let mut listener = vhost_user::bind(&vhost_user_socket, options).expect("bind vhost-user");
        let served = engine.clone();
        let server =
            std::thread::spawn(move || vhost_user::serve_listener(&mut listener, served, options));

        let nbd_socket = dir.path().join("nbd.sock");
        let nbd_listener = UnixListener::bind(&nbd_socket).expect("bind nbd");
        let nbd_engine = engine.clone();
        std::thread::spawn(move || nbd::serve_unix(nbd_listener, nbd_engine));

        Self {
            _dir: dir,
            engine,
            meta,
            vhost_user_socket,
            nbd_socket,
            server: Some(server),
            options,
        }
    }

    fn single_queue() -> Self {
        Self::start(VhostUserOptions::default())
    }

    fn connect(&self) -> BlkFrontend {
        self.connect_with(self.options.num_queues, true)
    }

    fn connect_with(&self, queues: usize, event_idx: bool) -> BlkFrontend {
        // A backend that died during startup unlinks its socket on the way out,
        // which would otherwise surface as a bare ENOENT from connect().
        if self.server.as_ref().is_some_and(|s| s.is_finished()) {
            panic!("vhost-user backend exited before the frontend connected");
        }
        BlkFrontend::connect(
            &self.vhost_user_socket,
            queues,
            self.options.queue_size,
            8,
            event_idx,
        )
        .expect("connect vhost-user frontend")
    }

    /// Read through the oracle frontend.
    fn oracle_read(&self, offset: u64, len: u32) -> Vec<u8> {
        let mut client = NbdClient::connect_unix(Path::new(&self.nbd_socket)).expect("nbd connect");
        let data = client.read(offset, len).expect("nbd read");
        client.disconnect().expect("nbd disconnect");
        data
    }

    fn oracle_write(&self, offset: u64, data: &[u8]) {
        let mut client = NbdClient::connect_unix(Path::new(&self.nbd_socket)).expect("nbd connect");
        client.write(offset, data).expect("nbd write");
        client.disconnect().expect("nbd disconnect");
    }

    /// Drop the frontend and confirm the backend treats the disconnect as a
    /// clean device teardown rather than an error.
    fn shutdown(mut self, frontend: BlkFrontend) {
        self.shutdown_with_fencing(frontend, false);
    }

    fn shutdown_fenced(mut self, frontend: BlkFrontend) {
        self.shutdown_with_fencing(frontend, true);
    }

    fn shutdown_with_fencing(&mut self, frontend: BlkFrontend, expect_fenced: bool) {
        drop(frontend);
        let server = self.server.take().expect("server handle");
        let result = server.join().expect("vhost-user server panicked");
        result.expect("vhost-user server ended with an error");
        let detach = self.engine.detach();
        if expect_fenced {
            assert!(matches!(detach, Err(EngineError::Fenced)));
        } else {
            detach.unwrap();
        }
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn config_space_reports_the_engine_geometry() {
    let options = VhostUserOptions {
        num_queues: 2,
        queue_size: 128,
        ..VhostUserOptions::default()
    };
    let harness = Harness::start(options);
    let mut frontend = harness.connect();
    let config = frontend.config(60).expect("get config");
    assert_eq!(config.len(), 60);

    let capacity = u64::from_le_bytes(config[0..8].try_into().unwrap());
    assert_eq!(capacity, VOLUME_SIZE / SECTOR_SIZE, "capacity in sectors");
    let seg_max = u32::from_le_bytes(config[12..16].try_into().unwrap());
    assert_eq!(seg_max, 126, "queue_size minus header and status");
    let blk_size = u32::from_le_bytes(config[20..24].try_into().unwrap());
    assert_eq!(blk_size, 512, "same logical block size as the NBD path");
    assert_eq!(
        config[32], 1,
        "writeback cache: durability comes from FLUSH"
    );
    let num_queues = u16::from_le_bytes(config[34..36].try_into().unwrap());
    assert_eq!(num_queues, 2);
    let max_discard_sectors = u32::from_le_bytes(config[36..40].try_into().unwrap());
    assert!(max_discard_sectors > 0, "DISCARD needs a non-zero limit");
    let write_zeroes_may_unmap = config[56];
    assert_eq!(
        write_zeroes_may_unmap, 1,
        "a fully covered chunk really is unmapped (spec §7.2) and reads as zeros"
    );

    // A short read of the config space must still be answered.
    let short = frontend.config(8).expect("short get config");
    assert_eq!(short, config[..8]);

    harness.shutdown(frontend);
}

#[test]
fn write_read_flush_matches_the_nbd_oracle() {
    let harness = Harness::single_queue();
    let mut frontend = harness.connect();
    let generation_before = harness.engine.generation();

    let data = pattern(8 * 1024, 7);
    let queue = frontend.queue(0);
    let completion = queue.write_at(8, &data).expect("write");
    assert_eq!(completion.status, VIRTIO_BLK_S_OK);

    // Same bytes through the Guest path...
    let read_back = queue.read_at(8, data.len()).expect("read");
    assert_eq!(read_back.status, VIRTIO_BLK_S_OK);
    assert_eq!(read_back.data, data);
    assert_eq!(read_back.used_len, data.len() as u32 + 1);
    // ... and through the oracle, which reads the engine independently.
    assert_eq!(
        harness.oracle_read(8 * SECTOR_SIZE, data.len() as u32),
        data
    );

    // A hole still reads as zeroes and a FLUSH commits one generation.
    let hole = queue.read_at(1024, 4096).expect("read hole");
    assert!(hole.data.iter().all(|&b| b == 0));
    assert_eq!(queue.flush().expect("flush").status, VIRTIO_BLK_S_OK);
    assert_eq!(harness.engine.generation(), generation_before + 1);

    // An empty FLUSH is a no-op that must still succeed (§6).
    assert_eq!(queue.flush().expect("flush again").status, VIRTIO_BLK_S_OK);
    assert_eq!(harness.engine.generation(), generation_before + 1);

    // Writes made through the oracle are visible to the Guest path: one engine.
    let oracle_data = pattern(512, 99);
    harness.oracle_write(64 * SECTOR_SIZE, &oracle_data);
    let seen = frontend
        .queue(0)
        .read_at(64, 512)
        .expect("read oracle write");
    assert_eq!(seen.data, oracle_data);

    harness.shutdown(frontend);
}

#[test]
fn payload_split_across_descriptors_is_reassembled() {
    let harness = Harness::single_queue();
    let mut frontend = harness.connect();
    let queue = frontend.queue(0);

    // A real driver splits a request at page boundaries; the backend must treat
    // the chain as one contiguous payload.
    let data = pattern(12 * 1024, 3);
    let completion = queue
        .request_split(vhu_frontend::VIRTIO_BLK_T_OUT, 32, &data, 0, 3)
        .expect("split write");
    assert_eq!(completion.status, VIRTIO_BLK_S_OK);
    assert_eq!(
        harness.oracle_read(32 * SECTOR_SIZE, data.len() as u32),
        data
    );

    harness.shutdown(frontend);
}

#[test]
fn discard_and_write_zeroes_zero_the_range() {
    let harness = Harness::single_queue();
    let mut frontend = harness.connect();
    let queue = frontend.queue(0);

    let data = pattern(4096, 11);
    queue.write_at(128, &data).expect("write");
    queue.write_at(256, &data).expect("write");

    // DISCARD: one segment of 4 KiB.
    let discard = queue
        .zero_range(VIRTIO_BLK_T_DISCARD, &[(128, 8, 0)])
        .expect("discard");
    assert_eq!(discard.status, VIRTIO_BLK_S_OK);
    assert!(harness
        .oracle_read(128 * SECTOR_SIZE, 4096)
        .iter()
        .all(|&b| b == 0));

    // WRITE_ZEROES with the UNMAP hint set: still zeroes, never a hole.
    let zeroes = queue
        .zero_range(VIRTIO_BLK_T_WRITE_ZEROES, &[(256, 8, 1)])
        .expect("write zeroes");
    assert_eq!(zeroes.status, VIRTIO_BLK_S_OK);
    assert!(harness
        .oracle_read(256 * SECTOR_SIZE, 4096)
        .iter()
        .all(|&b| b == 0));

    // Multi-segment requests are accepted even though seg_max is 1.
    queue.write_at(512, &data).expect("write");
    queue.write_at(1024, &data).expect("write");
    let multi = queue
        .zero_range(VIRTIO_BLK_T_WRITE_ZEROES, &[(512, 8, 0), (1024, 8, 0)])
        .expect("multi-segment write zeroes");
    assert_eq!(multi.status, VIRTIO_BLK_S_OK);
    assert!(harness
        .oracle_read(512 * SECTOR_SIZE, 4096)
        .iter()
        .all(|&b| b == 0));
    assert!(harness
        .oracle_read(1024 * SECTOR_SIZE, 4096)
        .iter()
        .all(|&b| b == 0));

    // An undefined flag must be rejected rather than silently ignored.
    let bad = queue
        .zero_range(VIRTIO_BLK_T_WRITE_ZEROES, &[(512, 8, 0x8000_0000)])
        .expect("bad flags request completes");
    assert_eq!(bad.status, VIRTIO_BLK_S_UNSUPP);
    // DISCARD has no defined flags at all.
    let bad_discard = queue
        .zero_range(VIRTIO_BLK_T_DISCARD, &[(512, 8, 1)])
        .expect("bad discard flags request completes");
    assert_eq!(bad_discard.status, VIRTIO_BLK_S_UNSUPP);

    harness.shutdown(frontend);
}

#[test]
fn get_id_reports_the_exact_guest_serial_not_the_volume_id() {
    let guest_serial = Id::new("guest-root-serial").unwrap();
    let harness = Harness::start(VhostUserOptions {
        guest_device_serial: VhostUserDeviceId::from_guest_device_serial(&guest_serial).unwrap(),
        ..VhostUserOptions::default()
    });
    let mut frontend = harness.connect();
    let completion = frontend.queue(0).get_id().expect("get id");
    assert_eq!(completion.status, VIRTIO_BLK_S_OK);
    let id = String::from_utf8_lossy(&completion.data)
        .trim_end_matches('\0')
        .to_string();
    assert_ne!(id, VOLUME_ID);
    assert_eq!(id, guest_serial.as_str());
    harness.shutdown(frontend);
}

#[test]
fn guest_serial_accepts_twenty_bytes_and_rejects_twenty_one() {
    assert!(
        VhostUserDeviceId::from_guest_device_serial(&Id::new("12345678901234567890").unwrap())
            .is_ok()
    );
    assert!(VhostUserDeviceId::from_guest_device_serial(
        &Id::new("123456789012345678901").unwrap()
    )
    .is_err());
}

#[test]
fn out_of_range_and_unknown_requests_fail_the_request_only() {
    let harness = Harness::single_queue();
    let mut frontend = harness.connect();
    let queue = frontend.queue(0);

    // One sector past the end of the volume.
    let past_end = VOLUME_SIZE / SECTOR_SIZE;
    let read = queue.read_at(past_end, 512).expect("out of range read");
    assert_eq!(read.status, VIRTIO_BLK_S_IOERR);
    let write = queue
        .write_at(past_end, &pattern(512, 1))
        .expect("out of range write");
    assert_eq!(write.status, VIRTIO_BLK_S_IOERR);

    // An unknown request type is answered with UNSUPP, not a dead queue.
    let unknown = queue.request(0x4242, 0, &[], 0).expect("unknown request");
    assert_eq!(unknown.status, VIRTIO_BLK_S_UNSUPP);

    // The queue keeps working after all three failures.
    let data = pattern(512, 5);
    assert_eq!(
        queue.write_at(0, &data).expect("write").status,
        VIRTIO_BLK_S_OK
    );
    assert_eq!(queue.read_at(0, 512).expect("read").data, data);

    harness.shutdown(frontend);
}

#[test]
fn fenced_attachment_fails_closed_for_the_guest() {
    let harness = Harness::single_queue();
    let mut frontend = harness.connect();
    let queue = frontend.queue(0);
    queue.write_at(0, &pattern(4096, 2)).expect("write");

    // The authority closes the exact grant. The engine discovers this on its
    // next commit and fences itself.
    let head = harness.meta.load_head(VOLUME_ID).expect("load grant");
    harness
        .meta
        .release_lease(
            VOLUME_ID,
            head.lease_owner.as_deref().expect("owned test volume"),
            head.lease_epoch,
        )
        .expect("close grant");
    let flush = queue.flush().expect("flush completes");
    assert_eq!(flush.status, VIRTIO_BLK_S_IOERR, "revoked lease must fail");
    assert!(harness.engine.is_fenced());

    // Every later write must fail closed rather than acknowledge data that can
    // never be committed.
    let write = queue
        .write_at(8, &pattern(512, 3))
        .expect("write completes");
    assert_eq!(write.status, VIRTIO_BLK_S_IOERR);
    let flush_again = queue.flush().expect("flush completes");
    assert_eq!(flush_again.status, VIRTIO_BLK_S_IOERR);

    harness.shutdown_fenced(frontend);
}

#[test]
fn multi_queue_requests_run_in_parallel() {
    let options = VhostUserOptions {
        num_queues: 4,
        queue_size: 256,
        ..VhostUserOptions::default()
    };
    let harness = Harness::start(options);
    let mut frontend = harness.connect();

    // Each queue owns a disjoint 1 MiB region; a wrong queue-to-thread mapping
    // or shared mutable state in the backend shows up as crossed data.
    let per_queue = 1024 * 1024u64;
    let mut workers = Vec::new();
    for index in 0..options.num_queues {
        let mut queue = frontend.take(index);
        workers.push(std::thread::spawn(move || {
            let data = pattern(64 * 1024, index as u8 + 1);
            let base = per_queue * index as u64 / SECTOR_SIZE;
            for round in 0..8u64 {
                let sector = base + round * (data.len() as u64 / SECTOR_SIZE);
                assert_eq!(
                    queue.write_at(sector, &data).expect("write").status,
                    VIRTIO_BLK_S_OK
                );
                let read = queue.read_at(sector, data.len()).expect("read");
                assert_eq!(read.status, VIRTIO_BLK_S_OK);
                assert_eq!(read.data, data, "queue {index} round {round}");
            }
            queue.flush().expect("flush");
        }));
    }
    for worker in workers {
        worker.join().expect("queue worker panicked");
    }

    // Verify every region through the oracle.
    for index in 0..options.num_queues {
        let data = pattern(64 * 1024, index as u8 + 1);
        for round in 0..8u64 {
            let offset = per_queue * index as u64 + round * data.len() as u64;
            assert_eq!(
                harness.oracle_read(offset, data.len() as u32),
                data,
                "oracle disagrees for queue {index} round {round}"
            );
        }
    }

    harness.shutdown(frontend);
}

#[test]
fn works_without_event_idx() {
    let harness = Harness::single_queue();
    // A driver that declines VIRTIO_RING_F_EVENT_IDX takes the backend's plain
    // notification path.
    let mut frontend = harness.connect_with(1, false);
    let queue = frontend.queue(0);
    queue.set_timeout(Duration::from_secs(20));
    let data = pattern(4096, 21);
    assert_eq!(
        queue.write_at(16, &data).expect("write").status,
        VIRTIO_BLK_S_OK
    );
    let read = queue.read_at(16, data.len()).expect("read");
    assert_eq!(read.data, data);
    assert_eq!(queue.flush().expect("flush").status, VIRTIO_BLK_S_OK);
    harness.shutdown(frontend);
}

#[test]
fn pipelined_requests_complete_out_of_order_safely() {
    let harness = Harness::single_queue();
    let mut frontend = harness.connect();
    let queue = frontend.queue(0);

    // Keep several requests in flight on one queue: the backend drains the whole
    // avail ring per kick, so completions may batch.
    let depth = queue.slots().min(8);
    let mut pending = Vec::new();
    for slot in 0..depth {
        let data = pattern(4096, slot as u8 + 40);
        pending.push((
            slot,
            queue
                .submit(
                    vhu_frontend::VIRTIO_BLK_T_OUT,
                    u64::from(slot) * 8,
                    &data,
                    0,
                    1,
                )
                .expect("submit"),
        ));
    }
    queue.kick().expect("kick");
    for _ in 0..depth {
        let (_, _) = queue.reap().expect("reap");
    }
    for (slot, request) in pending {
        let completion = queue.collect(request, 1).expect("collect");
        assert_eq!(completion.status, VIRTIO_BLK_S_OK, "slot {slot}");
    }
    for slot in 0..depth {
        let data = pattern(4096, slot as u8 + 40);
        assert_eq!(
            harness.oracle_read(u64::from(slot) * 8 * SECTOR_SIZE, data.len() as u32),
            data
        );
    }

    harness.shutdown(frontend);
}

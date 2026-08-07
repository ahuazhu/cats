//! Crash-safe, versioned record of what this node last started (legacy-ledger characterization CH-01/CH-02).
//!
//! `NodeRuntime.cats` is process-local, so an agent restart loses every fact
//! needed to re-adopt the Cloud Hypervisor and `cats-blockd` processes that are
//! still running on the host: generation, observed state, PIDs, grants, the
//! Warm snapshot location, the kernel-NBD device map and the metering epoch.
//! This module persists those facts under `<state_dir>/runtime-ledger/`, one
//! JSON record per Cat.
//!
//! The ledger is *local fact only* (ADR-0040 §1 local-authority boundary). It answers "what did this
//! node last start"; it never grants, extends or revives a storage write right,
//! and it carries no object-store or metadata-store credentials. Regaining
//! write access still goes through the MetadataStore lease/epoch CAS.
//!
//! Every record carries [`LEDGER_VERSION`]. A reader must accept only the
//! version it understands: guessing the meaning of an unknown layout is exactly
//! the failure mode that would let a stale identity be mistaken for a live one.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use cats_api::nodejob::VolumeGrant;
use cats_api::resources::ObservedState;

use crate::ch::ChNetwork;
use crate::proc::{host_boot_id, ProcIdentity};

use super::{volume_data_dir, CatRuntime, NodeRuntime};

/// Persisted format version. A record written by any other version is not
/// interpreted; see the module docs.
pub(super) const LEDGER_VERSION: u32 = 1;

/// Everything needed to rebuild one `CatRuntime` after an agent restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CatLedgerRecord {
    pub ledger_version: u32,
    pub node_id: String,
    /// Host boot identity at write time. A mismatch on read means the host
    /// rebooted, so no recorded PID can be trusted.
    pub host_boot_id: Option<String>,
    pub updated_at_ms: i64,

    pub cat_id: String,
    pub generation: i64,
    pub state: ObservedState,
    pub cpus: u32,
    pub memory_mib: u64,

    /// Per-Cat runtime directory under `<state_dir>/cats/`.
    pub dir: PathBuf,
    /// Short hashed bind paths; recomputable, but recorded so a reader never
    /// has to reproduce the hash to know which socket it is looking at.
    pub ctl_sock: PathBuf,
    pub web_sock: PathBuf,
    pub runtime_sock: PathBuf,

    /// The Guest process (FakeVmm child or Cloud Hypervisor), when one is
    /// resident. Absent while Warm.
    pub guest: Option<ProcIdentity>,
    /// Guest-reported boot id, checked against `health()` before re-adoption.
    pub boot_id: Option<String>,

    pub blockds: Vec<BlockdRecord>,
    /// Grants remembered for Warm restore.
    pub volumes: Vec<VolumeGrant>,

    /// Present only in Cloud Hypervisor mode.
    pub ch: Option<ChRecord>,
    pub metering: Option<MeteringRecord>,
}

/// One `cats-blockd` process and the volume it serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockdRecord {
    pub grant: VolumeGrant,
    pub proc: ProcIdentity,
    /// NBD socket, present on both block paths.
    pub socket: PathBuf,
    /// vhost-user socket the VMM consumes, when the Cat runs on that path.
    pub vhost_user_socket: Option<PathBuf>,
    /// Control socket for `drain`/`status` (ADR-0022).
    pub control_socket: PathBuf,
    /// Local journal and cache directory. In relaxed mode with `R < L` this is
    /// the only authoritative copy of the unpublished writes (ADR-0021).
    pub data_dir: PathBuf,
}

/// Mirrors `ChRuntime`, which is not itself serializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ChRecord {
    pub api_sock: PathBuf,
    pub vsock_sock: PathBuf,
    pub memory_file: PathBuf,
    /// disk_id -> `/dev/nbdN`. Ordered so the serialized bytes are
    /// deterministic; restore order comes from the disk list, not this map.
    pub nbd: BTreeMap<String, String>,
    pub snapshot_dir: Option<PathBuf>,
    pub network: Option<ChNetwork>,
}

/// The billing attribution epoch (ADR-0011), so a re-adopted Cat keeps
/// counting against the same cgroup rather than inventing a new interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MeteringRecord {
    pub cgroup_path: PathBuf,
    pub source_epoch: String,
}

/// Handle over `<state_dir>/runtime-ledger/`.
pub(super) struct Ledger {
    dir: PathBuf,
}

impl Ledger {
    pub(super) fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create runtime ledger directory {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Publish one record durably.
    ///
    /// Temp file, `fsync`, `rename`, directory `fsync`. All four steps matter:
    /// without the first `fsync` the rename can publish a torn or empty file,
    /// and without the directory `fsync` the rename itself is not durable, so a
    /// host that loses power right after a successful `put` could come back
    /// with the previous record — or with none at all.
    pub(super) fn put(&self, record: &CatLedgerRecord) -> Result<()> {
        let (path, tmp) = self.record_paths(&record.cat_id)?;
        let bytes =
            serde_json::to_vec_pretty(record).context("serialize node runtime ledger record")?;
        {
            let mut file =
                File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            file.write_all(&bytes)
                .with_context(|| format!("write {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("sync {}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("publish runtime ledger record {}", path.display()))?;
        sync_dir(&self.dir)
    }

    /// Forget a Cat. Idempotent: a record that is already gone is success, so a
    /// retried Stop or Destroy does not fail on the second attempt.
    pub(super) fn remove(&self, cat_id: &str) -> Result<()> {
        let (path, tmp) = self.record_paths(cat_id)?;
        let _ = std::fs::remove_file(&tmp);
        match std::fs::remove_file(&path) {
            Ok(()) => sync_dir(&self.dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("remove runtime ledger record {}", path.display())),
        }
    }

    /// Every readable, current-version record, sorted by `cat_id`.
    ///
    /// A record that is unreadable, malformed, or written by another format
    /// version is skipped with a warning rather than failing the scan: one
    /// corrupt record must not stop the node from re-adopting the rest.
    pub(super) fn load_all(&self) -> Result<Vec<CatLedgerRecord>> {
        let entries = std::fs::read_dir(&self.dir)
            .with_context(|| format!("read runtime ledger directory {}", self.dir.display()))?;
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry
                .with_context(|| format!("list runtime ledger directory {}", self.dir.display()))?;
            let path = entry.path();
            // Leftovers from an interrupted `put` are named `*.json.tmp` and
            // were never published.
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if let Some(record) = load_record(&path) {
                records.push(record);
            }
        }
        records.sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
        Ok(records)
    }

    fn record_paths(&self, cat_id: &str) -> Result<(PathBuf, PathBuf)> {
        let name = ledger_file_stem(cat_id)?;
        Ok((
            self.dir.join(format!("{name}.json")),
            self.dir.join(format!("{name}.json.tmp")),
        ))
    }
}

fn load_record(path: &Path) -> Option<CatLedgerRecord> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(
                record = %path.display(),
                "skipping unreadable runtime ledger record: {error}"
            );
            return None;
        }
    };
    // Read the version before the body: a future layout may not deserialize
    // into today's struct at all, and "unknown version" is the accurate reason
    // to report for it.
    let version = match serde_json::from_str::<VersionProbe>(&text) {
        Ok(probe) => probe.ledger_version,
        Err(error) => {
            tracing::warn!(
                record = %path.display(),
                "skipping runtime ledger record with no readable version: {error}"
            );
            return None;
        }
    };
    if version != LEDGER_VERSION {
        tracing::warn!(
            record = %path.display(),
            version,
            expected = LEDGER_VERSION,
            "skipping runtime ledger record written by another format version"
        );
        return None;
    }
    match serde_json::from_str::<CatLedgerRecord>(&text) {
        Ok(record) => Some(record),
        Err(error) => {
            tracing::warn!(
                record = %path.display(),
                "skipping malformed runtime ledger record: {error}"
            );
            None
        }
    }
}

#[derive(Deserialize)]
struct VersionProbe {
    ledger_version: u32,
}

/// A rename is a directory-entry change and is not durable until the directory
/// itself is synced.
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .with_context(|| format!("open runtime ledger directory {}", dir.display()))?
        .sync_all()
        .with_context(|| format!("sync runtime ledger directory {}", dir.display()))
}

/// Refuse any Cat id that would not stay inside the ledger directory as a
/// single file name. The id reaches the node from the control plane, so it is
/// untrusted input on a path-building boundary.
fn ledger_file_stem(cat_id: &str) -> Result<&str> {
    if cat_id.is_empty() {
        bail!("runtime ledger record needs a cat id");
    }
    if cat_id.contains('/') || cat_id.contains('\\') || cat_id.contains("..") {
        bail!("refusing to use cat id {cat_id:?} as a runtime ledger file name");
    }
    Ok(cat_id)
}

/// Wall-clock milliseconds for `updated_at_ms`.
///
/// Diagnostic only: none of the identity checks in the ADR-0040 §6 adoption
/// proof depend on it, so an
/// unreadable clock is recorded as 0 rather than failing an otherwise good
/// write.
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl NodeRuntime {
    /// Record what this node is now running for `cat_id`.
    ///
    /// Called once per job from `execute_locked`, after the final state has
    /// settled. Intermediate states (the Running -> Suspended -> Running bounce
    /// inside `suspend_cat`, for instance) are deliberately never written.
    pub(super) fn persist_cat(&self, cat_id: &str) {
        // Snapshot under `cats`, then drop the guard before writing. `put`
        // fsyncs the record and then the directory; holding the map across those
        // two syncs would queue every other job on this node behind disk
        // latency.
        let record = {
            let cats = self.cats.lock().unwrap();
            let Some(runtime) = cats.get(cat_id) else {
                return;
            };
            self.ledger_record(cat_id, runtime)
        };
        if let Err(error) = self.ledger.put(&record) {
            // A failed write must not fail the job. The ledger is a local
            // recovery aid and explicitly not a source of authority
            // (ADR-0040 §1 local-authority boundary), so tearing down a healthy running Cat because a
            // JSON file could not be written would be strictly worse than
            // losing the ability to re-adopt it later.
            tracing::error!(cat = %cat_id, "writing the node runtime ledger record failed: {error:#}");
        }
    }

    /// Drop `cat_id` from the inventory once it no longer runs here.
    pub(super) fn forget_cat(&self, cat_id: &str) {
        if let Err(error) = self.ledger.remove(cat_id) {
            // Same policy as `persist_cat`: a stale record is a re-adoption
            // problem for the next stage to reject, not a reason to fail a job
            // whose real work already succeeded.
            tracing::error!(cat = %cat_id, "removing the node runtime ledger record failed: {error:#}");
        }
    }

    fn ledger_record(&self, cat_id: &str, runtime: &CatRuntime) -> CatLedgerRecord {
        let mut blockds: Vec<BlockdRecord> = runtime
            .blockds
            .values()
            .map(|blockd| BlockdRecord {
                grant: blockd.grant.clone(),
                proc: ProcIdentity::sample(blockd.child.id()),
                socket: blockd.socket.clone(),
                vhost_user_socket: blockd.vhost_user_socket.clone(),
                control_socket: blockd.control_socket.clone(),
                // The same path `spawn_blockd` passes as `--data-dir`.
                data_dir: volume_data_dir(&runtime.dir, &blockd.grant.disk_id),
            })
            .collect();
        // `blockds` is a HashMap, so fix an order: the serialized record should
        // not churn between two writes that describe the same runtime.
        blockds.sort_by(|left, right| left.grant.disk_id.cmp(&right.grant.disk_id));
        CatLedgerRecord {
            ledger_version: LEDGER_VERSION,
            node_id: self.cfg.node_id.clone(),
            host_boot_id: host_boot_id(),
            updated_at_ms: now_unix_ms(),
            cat_id: cat_id.to_string(),
            generation: runtime.generation,
            state: runtime.state,
            cpus: runtime.cpus,
            memory_mib: runtime.memory_mib,
            dir: runtime.dir.clone(),
            ctl_sock: runtime.ctl_sock.clone(),
            web_sock: runtime.web_sock.clone(),
            runtime_sock: runtime.runtime_sock.clone(),
            guest: runtime
                .guest
                .as_ref()
                .map(|guest| ProcIdentity::sample(guest.id())),
            boot_id: runtime.boot_id.clone(),
            blockds,
            volumes: runtime.volumes.clone(),
            ch: runtime.ch.as_ref().map(|ch| ChRecord {
                api_sock: ch.api_sock.clone(),
                vsock_sock: ch.vsock_sock.clone(),
                memory_file: ch.memory_file.clone(),
                nbd: ch
                    .nbd
                    .iter()
                    .map(|(disk_id, device)| (disk_id.clone(), device.clone()))
                    .collect(),
                snapshot_dir: ch.snapshot_dir.clone(),
                network: ch.network.clone(),
            }),
            metering: runtime.metering.as_ref().map(|metering| MeteringRecord {
                cgroup_path: metering.cgroup_path.clone(),
                source_epoch: metering.source_epoch.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::resources::DiskDurability;

    fn grant(disk_id: &str, mount_path: &str, durability: DiskDurability) -> VolumeGrant {
        VolumeGrant {
            disk_id: disk_id.to_string(),
            volume_id: format!("vol_{disk_id}"),
            attachment_id: format!("att_{disk_id}"),
            epoch: 7,
            size_bytes: 4 * 1024 * 1024 * 1024,
            mount_path: mount_path.to_string(),
            durability,
        }
    }

    fn populated_record(cat_id: &str) -> CatLedgerRecord {
        CatLedgerRecord {
            ledger_version: LEDGER_VERSION,
            node_id: "node_1".into(),
            host_boot_id: Some("4f0a2e0c-0000-4000-8000-000000000001".into()),
            updated_at_ms: 1_754_179_200_000,
            cat_id: cat_id.to_string(),
            generation: 3,
            state: ObservedState::Running,
            cpus: 2,
            memory_mib: 2048,
            dir: PathBuf::from("/var/lib/cats/cats").join(cat_id),
            ctl_sock: PathBuf::from("/tmp/cats-sock/aaaa.sock"),
            web_sock: PathBuf::from("/tmp/cats-sock/bbbb.sock"),
            runtime_sock: PathBuf::from("/tmp/cats-sock/cccc.sock"),
            guest: Some(ProcIdentity {
                pid: 4242,
                start_ticks: Some(918_273),
                exe: Some(PathBuf::from("/usr/local/bin/cloud-hypervisor")),
            }),
            boot_id: Some("guest-boot-9".into()),
            blockds: vec![
                BlockdRecord {
                    grant: grant("dsk_root", "/", DiskDurability::Relaxed),
                    proc: ProcIdentity {
                        pid: 4243,
                        start_ticks: Some(918_275),
                        exe: Some(PathBuf::from("/usr/local/bin/cats-blockd")),
                    },
                    socket: PathBuf::from("/tmp/cats-sock/dddd.sock"),
                    vhost_user_socket: Some(PathBuf::from("/tmp/cats-sock/eeee.sock")),
                    control_socket: PathBuf::from("/tmp/cats-sock/ffff.sock"),
                    data_dir: PathBuf::from("/var/lib/cats/cats")
                        .join(cat_id)
                        .join("vol-dsk_root"),
                },
                BlockdRecord {
                    grant: grant("dsk_data", "/data", DiskDurability::Strict),
                    proc: ProcIdentity {
                        pid: 4244,
                        start_ticks: None,
                        exe: None,
                    },
                    socket: PathBuf::from("/tmp/cats-sock/1111.sock"),
                    vhost_user_socket: None,
                    control_socket: PathBuf::from("/tmp/cats-sock/2222.sock"),
                    data_dir: PathBuf::from("/var/lib/cats/cats")
                        .join(cat_id)
                        .join("vol-dsk_data"),
                },
            ],
            volumes: vec![
                grant("dsk_root", "/", DiskDurability::Relaxed),
                grant("dsk_data", "/data", DiskDurability::Strict),
            ],
            ch: Some(ChRecord {
                api_sock: PathBuf::from("/tmp/cats-sock/3333.sock"),
                vsock_sock: PathBuf::from("/tmp/cats-sock/4444.sock"),
                memory_file: PathBuf::from("/var/lib/cats/cats")
                    .join(cat_id)
                    .join("guest-memory.bin"),
                nbd: BTreeMap::from([
                    ("dsk_data".to_string(), "/dev/nbd1".to_string()),
                    ("dsk_root".to_string(), "/dev/nbd0".to_string()),
                ]),
                snapshot_dir: Some(
                    PathBuf::from("/var/lib/cats/cats")
                        .join(cat_id)
                        .join("snapshot"),
                ),
                network: Some(ChNetwork {
                    tap: "cat00000000abc".into(),
                    mac: "02:ca:0a:f0:00:06".into(),
                    host_ip: "10.240.0.5/30".into(),
                    guest_ip: "10.240.0.6/30".into(),
                }),
            }),
            metering: Some(MeteringRecord {
                cgroup_path: PathBuf::from("/sys/fs/cgroup/cats/node_1").join(cat_id),
                source_epoch: "8d0a2b8f9c1e4a6f".into(),
            }),
        }
    }

    fn ledger() -> (tempfile::TempDir, Ledger) {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger = Ledger::open(&dir.path().join("runtime-ledger")).expect("open ledger");
        (dir, ledger)
    }

    #[test]
    fn open_creates_the_directory_and_starts_empty() {
        let (dir, ledger) = ledger();
        assert!(dir.path().join("runtime-ledger").is_dir());
        assert!(ledger.load_all().expect("load").is_empty());
    }

    #[test]
    fn a_fully_populated_record_round_trips() {
        let (_dir, ledger) = ledger();
        let record = populated_record("cat_round_trip");
        ledger.put(&record).expect("put");

        let loaded = ledger.load_all().expect("load");
        assert_eq!(loaded.len(), 1);
        let loaded = &loaded[0];
        assert_eq!(loaded.cat_id, "cat_round_trip");
        assert_eq!(loaded.state, ObservedState::Running);
        assert_eq!(loaded.blockds.len(), 2);
        assert_eq!(loaded.blockds[0].grant.attachment_id, "att_dsk_root");
        assert_eq!(loaded.blockds[0].proc.start_ticks, Some(918_275));
        assert_eq!(loaded.blockds[1].vhost_user_socket, None);
        let ch = loaded.ch.as_ref().expect("ch section");
        assert_eq!(
            ch.nbd.get("dsk_root").map(String::as_str),
            Some("/dev/nbd0")
        );
        assert_eq!(
            ch.network.as_ref().map(|network| network.tap.as_str()),
            Some("cat00000000abc")
        );
        let metering = loaded.metering.as_ref().expect("metering section");
        assert_eq!(metering.source_epoch, "8d0a2b8f9c1e4a6f");

        // VolumeGrant has no PartialEq, so compare the serialized forms; that
        // also asserts the encoding is stable across a write/read cycle.
        assert_eq!(
            serde_json::to_string(&record).expect("encode"),
            serde_json::to_string(loaded).expect("re-encode")
        );
    }

    #[test]
    fn one_unreadable_record_does_not_hide_the_others() {
        let (dir, ledger) = ledger();
        let ledger_dir = dir.path().join("runtime-ledger");
        ledger.put(&populated_record("cat_good_a")).expect("put a");
        ledger.put(&populated_record("cat_good_b")).expect("put b");

        // A record from a format version this agent does not understand.
        let mut future = serde_json::to_value(populated_record("cat_future")).expect("encode");
        future["ledger_version"] = serde_json::json!(LEDGER_VERSION + 1);
        // ... whose body this agent could not interpret even if it tried.
        future["state"] = serde_json::json!("hibernating");
        std::fs::write(
            ledger_dir.join("cat_future.json"),
            serde_json::to_vec(&future).expect("encode future"),
        )
        .expect("write future record");

        // A truncated write from an older, non-atomic writer.
        std::fs::write(ledger_dir.join("cat_truncated.json"), b"{\"ledger_ver")
            .expect("write truncated record");

        // Right version, unusable body.
        std::fs::write(
            ledger_dir.join("cat_bad_body.json"),
            format!("{{\"ledger_version\":{LEDGER_VERSION},\"cat_id\":42}}"),
        )
        .expect("write malformed record");

        let loaded = ledger.load_all().expect("load");
        let ids: Vec<&str> = loaded.iter().map(|r| r.cat_id.as_str()).collect();
        assert_eq!(ids, ["cat_good_a", "cat_good_b"]);
    }

    #[test]
    fn a_leftover_temp_file_is_never_loaded() {
        let (dir, ledger) = ledger();
        let ledger_dir = dir.path().join("runtime-ledger");
        ledger.put(&populated_record("cat_kept")).expect("put");
        // An interrupted put leaves a complete-looking record under `.tmp`.
        std::fs::write(
            ledger_dir.join("cat_partial.json.tmp"),
            serde_json::to_vec(&populated_record("cat_partial")).expect("encode"),
        )
        .expect("write temp record");

        let loaded = ledger.load_all().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cat_id, "cat_kept");
    }

    #[test]
    fn put_replaces_the_record_in_place() {
        let (dir, ledger) = ledger();
        let ledger_dir = dir.path().join("runtime-ledger");
        let mut record = populated_record("cat_updated");
        ledger.put(&record).expect("first put");

        record.generation = 4;
        record.state = ObservedState::Warm;
        record.guest = None;
        record.updated_at_ms += 1_000;
        ledger.put(&record).expect("second put");

        let files: Vec<String> = std::fs::read_dir(&ledger_dir)
            .expect("read dir")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().into())
            .collect();
        assert_eq!(files, ["cat_updated.json"]);

        let loaded = ledger.load_all().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].generation, 4);
        assert_eq!(loaded[0].state, ObservedState::Warm);
        assert!(loaded[0].guest.is_none());
    }

    #[test]
    fn remove_is_idempotent() {
        let (_dir, ledger) = ledger();
        ledger.put(&populated_record("cat_gone")).expect("put");
        ledger.remove("cat_gone").expect("first remove");
        ledger.remove("cat_gone").expect("second remove");
        ledger.remove("cat_never_written").expect("unknown remove");
        assert!(ledger.load_all().expect("load").is_empty());
    }

    #[test]
    fn a_cat_id_that_escapes_the_directory_is_rejected() {
        let (dir, ledger) = ledger();
        for cat_id in ["", "..", "../escape", "a/b", "a\\b", "cat/../../etc/passwd"] {
            let mut record = populated_record("cat_placeholder");
            record.cat_id = cat_id.to_string();
            assert!(
                ledger.put(&record).is_err(),
                "put accepted cat id {cat_id:?}"
            );
            assert!(
                ledger.remove(cat_id).is_err(),
                "remove accepted cat id {cat_id:?}"
            );
        }
        // Nothing was created anywhere, inside the ledger or above it.
        assert!(ledger.load_all().expect("load").is_empty());
        let stray: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(stray, ["runtime-ledger"]);
    }
}

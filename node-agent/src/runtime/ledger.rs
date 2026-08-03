//! Crash-safe, versioned record of what this node last started (ADR-0028 §1).
//!
//! `NodeRuntime.cats` is process-local, so an agent restart loses every fact
//! needed to re-adopt the Cloud Hypervisor and `cats-blockd` processes that are
//! still running on the host: generation, observed state, PIDs, grants, the
//! Warm snapshot location, the kernel-NBD device map and the metering epoch.
//! This module persists those facts under `<state_dir>/runtime-ledger/`, one
//! JSON record per Cat.
//!
//! The ledger is *local fact only* (ADR-0028 §2). It answers "what did this
//! node last start"; it never grants, extends or revives a storage write right,
//! and it carries no object-store or metadata-store credentials. Regaining
//! write access still goes through the MetadataStore lease/epoch CAS.
//!
//! Every record carries [`LEDGER_VERSION`]. A reader must accept only the
//! version it understands: guessing the meaning of an unknown layout is exactly
//! the failure mode that would let a stale identity be mistaken for a live one.

// ADR-0028 lands in stages, and this is stage 1: the format and the write path
// only, deliberately with no caller. The reader (startup scan and identity
// proof) is stage 2, and wiring `put`/`remove` into the lifecycle paths belongs
// with it, so that a half-written inventory can never be treated as authority.
// The allow is scoped to this module and comes off as soon as stage 2 lands.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use cats_api::nodejob::VolumeGrant;
use cats_api::resources::ObservedState;

use crate::ch::ChNetwork;

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

/// Enough of a process's identity to tell it apart from a recycled PID.
///
/// A bare PID proves nothing: the kernel reuses PIDs, and after a restart the
/// agent has no parent/child relationship left to lean on. `start_ticks` plus
/// the executable path make the check specific to the process this node
/// actually spawned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ProcIdentity {
    pub pid: u32,
    pub start_ticks: Option<u64>,
    pub exe: Option<PathBuf>,
}

impl ProcIdentity {
    /// Sample a live process. A process that exits mid-sample yields absent
    /// fields rather than an error: a weaker identity is a reason to refuse
    /// re-adoption later, not a reason to fail the write now.
    pub(super) fn sample(pid: u32) -> Self {
        Self {
            pid,
            start_ticks: sample_start_ticks(pid),
            exe: sample_exe(pid),
        }
    }
}

#[cfg(target_os = "linux")]
fn sample_start_ticks(pid: u32) -> Option<u64> {
    parse_start_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Dev and macOS hosts have no `/proc`, so process identity is weaker there.
/// ADR-0028 §6 accepts that: those paths never carry production workload.
#[cfg(not(target_os = "linux"))]
fn sample_start_ticks(_pid: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn sample_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(target_os = "linux"))]
fn sample_exe(_pid: u32) -> Option<PathBuf> {
    None
}

/// `starttime` — field 22 of `/proc/<pid>/stat`, in clock ticks since boot.
///
/// Field 2 (`comm`) is wrapped in parentheses and may itself contain spaces and
/// parentheses (it is the first 15 bytes of the executable's basename, which
/// the kernel does not sanitize), so the fields cannot be taken by splitting the
/// line on whitespace. Splitting after the *last* `)` is the documented way to
/// parse this file. Getting it wrong yields a plausible but wrong start time,
/// which would later let a recycled PID pass for a surviving process.
#[cfg(any(target_os = "linux", test))]
fn parse_start_ticks(stat: &str) -> Option<u64> {
    // Everything after the comm field starts at field 3 (`state`), so field 22
    // is at index 19.
    let (_, after_comm) = stat.rsplit_once(')')?;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Identity of the current host boot. Used to reject every recorded PID at once
/// after a host reboot (ADR-0028 §3 step 1).
pub(super) fn host_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
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

    #[test]
    fn start_ticks_come_from_the_field_after_the_last_paren() {
        // Real shape of /proc/<pid>/stat, truncated after starttime.
        let stat =
            "4242 (cats-blockd) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 918273 ";
        assert_eq!(parse_start_ticks(stat), Some(918_273));

        // comm is the unsanitized executable basename, so it can contain
        // spaces and parentheses. Splitting on whitespace, or on the first
        // `)`, silently returns a different field's value here.
        let tricky =
            "4242 (odd ) name (x) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 918273 ";
        assert_eq!(parse_start_ticks(tricky), Some(918_273));

        let trailing_paren =
            "4242 (weird)) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 4242424 0 0";
        assert_eq!(parse_start_ticks(trailing_paren), Some(4_242_424));
    }

    #[test]
    fn a_malformed_stat_line_yields_no_start_ticks() {
        assert_eq!(parse_start_ticks(""), None);
        assert_eq!(parse_start_ticks("4242 (cats-blockd S 1 2 3"), None);
        // Truncated before field 22.
        assert_eq!(parse_start_ticks("4242 (cats-blockd) S 1 4242"), None);
        // Field 22 present but not a number.
        assert_eq!(
            parse_start_ticks(
                "4242 (cats-blockd) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 x"
            ),
            None
        );
    }

    #[test]
    fn sampling_a_process_that_is_not_there_does_not_fail() {
        // PID 0 is never a live process, so every /proc lookup misses.
        let identity = ProcIdentity::sample(0);
        assert_eq!(identity.pid, 0);
        assert_eq!(identity.start_ticks, None);
        assert_eq!(identity.exe, None);
    }

    #[test]
    fn host_boot_id_is_stable_within_one_boot() {
        // None off Linux by design; on Linux the value must not vary between
        // reads, or step 1 of the re-adoption check would reject everything.
        assert_eq!(host_boot_id(), host_boot_id());
        #[cfg(target_os = "linux")]
        assert!(host_boot_id().is_some_and(|id| !id.trim().is_empty()));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(host_boot_id(), None);
    }
}

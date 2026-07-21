//! Authoritative volume metadata: root pointer CAS + lease/fencing (spec §4).
//!
//! The SQLite implementation is the dev/test stand-in for the production
//! PostgreSQL store; both must keep the exact SQL shape of the spec: the
//! CAS is a single conditional UPDATE whose affected-row count decides
//! whether a FLUSH may be acknowledged.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone)]
pub struct VolumeHead {
    pub volume_id: String,
    pub size_bytes: u64,
    pub generation: i64,
    pub root_hash: Option<[u8; 32]>,
    pub root_object_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnapshotRow {
    pub snapshot_id: String,
    pub volume_id: String,
    pub generation: i64,
    pub root_hash: Option<[u8; 32]>,
    pub root_object_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("volume not found: {0}")]
    NotFound(String),
    #[error("volume already exists: {0}")]
    AlreadyExists(String),
    #[error("lease is held by another attachment")]
    LeaseHeld,
    #[error("lease epoch is stale or expired (fenced)")]
    Fenced,
    #[error("root CAS conflict: expected generation {expected}")]
    CasConflict { expected: i64 },
    #[error("metadata backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, MetaError>;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis() as i64
}

/// Authoritative metadata operations. All implementations must be safe for
/// concurrent use from multiple processes (the SQLite impl relies on the
/// database file's own locking).
pub trait MetadataStore: Send + Sync {
    fn create_volume(&self, volume_id: &str, size_bytes: u64) -> Result<()>;
    fn load_head(&self, volume_id: &str) -> Result<VolumeHead>;
    fn delete_volume(&self, volume_id: &str) -> Result<()>;

    /// Acquire the single-writer lease. Succeeds only when no unexpired lease
    /// is held by a different attachment; always bumps the fencing epoch.
    /// Re-acquiring with the same attachment id is allowed (crash restart)
    /// and also bumps the epoch.
    fn acquire_lease(&self, volume_id: &str, attachment_id: &str, ttl_ms: i64) -> Result<i64>;
    fn renew_lease(
        &self,
        volume_id: &str,
        attachment_id: &str,
        epoch: i64,
        ttl_ms: i64,
    ) -> Result<()>;
    fn release_lease(&self, volume_id: &str, attachment_id: &str, epoch: i64) -> Result<()>;
    /// Control-plane fencing: expire the current lease immediately so the old
    /// holder's next renew fails and a new attachment can acquire.
    fn revoke_lease(&self, volume_id: &str) -> Result<()>;

    /// Spec §4 root CAS. Returns the new generation.
    fn cas_head(
        &self,
        volume_id: &str,
        expected_generation: i64,
        new_root_hash: [u8; 32],
        new_root_object_id: &str,
        attachment_id: &str,
        epoch: i64,
    ) -> Result<i64>;

    fn create_snapshot(&self, snapshot_id: &str, volume_id: &str) -> Result<SnapshotRow>;
    fn list_snapshots(&self, volume_id: &str) -> Result<Vec<SnapshotRow>>;
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

pub struct SqliteMeta {
    conn: Mutex<Connection>,
}

impl SqliteMeta {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(sql_err)?;
        conn.busy_timeout(std::time::Duration::from_secs(10)).map_err(sql_err)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(sql_err)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(sql_err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS volumes (
                volume_id TEXT PRIMARY KEY,
                size_bytes INTEGER NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                root_hash BLOB,
                root_object_id TEXT,
                lease_owner TEXT,
                lease_epoch INTEGER NOT NULL DEFAULT 0,
                lease_expires_at_ms INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                volume_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                root_hash BLOB,
                root_object_id TEXT,
                created_at_ms INTEGER NOT NULL
            );",
        )
        .map_err(sql_err)?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

fn sql_err(e: rusqlite::Error) -> MetaError {
    MetaError::Backend(e.to_string())
}

fn row_to_head(row: &rusqlite::Row<'_>) -> rusqlite::Result<VolumeHead> {
    let hash: Option<Vec<u8>> = row.get(3)?;
    Ok(VolumeHead {
        volume_id: row.get(0)?,
        size_bytes: row.get::<_, i64>(1)? as u64,
        generation: row.get(2)?,
        root_hash: hash.map(|h| h.try_into().expect("stored hash is 32 bytes")),
        root_object_id: row.get(4)?,
    })
}

impl MetadataStore for SqliteMeta {
    fn create_volume(&self, volume_id: &str, size_bytes: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "INSERT OR IGNORE INTO volumes (volume_id, size_bytes) VALUES (?1, ?2)",
                params![volume_id, size_bytes as i64],
            )
            .map_err(sql_err)?;
        if n == 0 {
            return Err(MetaError::AlreadyExists(volume_id.to_string()));
        }
        Ok(())
    }

    fn load_head(&self, volume_id: &str) -> Result<VolumeHead> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT volume_id, size_bytes, generation, root_hash, root_object_id
               FROM volumes WHERE volume_id = ?1",
            params![volume_id],
            row_to_head,
        )
        .optional()
        .map_err(sql_err)?
        .ok_or_else(|| MetaError::NotFound(volume_id.to_string()))
    }

    fn delete_volume(&self, volume_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM volumes WHERE volume_id = ?1", params![volume_id])
            .map_err(sql_err)?;
        conn.execute("DELETE FROM snapshots WHERE volume_id = ?1", params![volume_id])
            .map_err(sql_err)?;
        Ok(())
    }

    fn acquire_lease(&self, volume_id: &str, attachment_id: &str, ttl_ms: i64) -> Result<i64> {
        let now = now_ms();
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "UPDATE volumes
                    SET lease_owner = ?2,
                        lease_epoch = lease_epoch + 1,
                        lease_expires_at_ms = ?3
                  WHERE volume_id = ?1
                    AND (lease_owner IS NULL
                         OR lease_expires_at_ms <= ?4
                         OR lease_owner = ?2)",
                params![volume_id, attachment_id, now + ttl_ms, now],
            )
            .map_err(sql_err)?;
        if n == 0 {
            // Distinguish missing volume from a held lease.
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM volumes WHERE volume_id = ?1",
                    params![volume_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            return match exists {
                None => Err(MetaError::NotFound(volume_id.to_string())),
                Some(_) => Err(MetaError::LeaseHeld),
            };
        }
        conn.query_row(
            "SELECT lease_epoch FROM volumes WHERE volume_id = ?1",
            params![volume_id],
            |r| r.get(0),
        )
        .map_err(sql_err)
    }

    fn renew_lease(
        &self,
        volume_id: &str,
        attachment_id: &str,
        epoch: i64,
        ttl_ms: i64,
    ) -> Result<()> {
        let now = now_ms();
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "UPDATE volumes SET lease_expires_at_ms = ?4
                  WHERE volume_id = ?1 AND lease_owner = ?2 AND lease_epoch = ?3
                    AND lease_expires_at_ms > ?5",
                params![volume_id, attachment_id, epoch, now + ttl_ms, now],
            )
            .map_err(sql_err)?;
        if n == 0 {
            return Err(MetaError::Fenced);
        }
        Ok(())
    }

    fn release_lease(&self, volume_id: &str, attachment_id: &str, epoch: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE volumes SET lease_owner = NULL, lease_expires_at_ms = 0
              WHERE volume_id = ?1 AND lease_owner = ?2 AND lease_epoch = ?3",
            params![volume_id, attachment_id, epoch],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    fn revoke_lease(&self, volume_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE volumes SET lease_expires_at_ms = 0 WHERE volume_id = ?1",
            params![volume_id],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    fn cas_head(
        &self,
        volume_id: &str,
        expected_generation: i64,
        new_root_hash: [u8; 32],
        new_root_object_id: &str,
        attachment_id: &str,
        epoch: i64,
    ) -> Result<i64> {
        let now = now_ms();
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "UPDATE volumes
                    SET root_hash = ?3, root_object_id = ?4, generation = generation + 1
                  WHERE volume_id = ?1
                    AND generation = ?2
                    AND lease_owner = ?5
                    AND lease_epoch = ?6
                    AND lease_expires_at_ms > ?7",
                params![
                    volume_id,
                    expected_generation,
                    new_root_hash.as_slice(),
                    new_root_object_id,
                    attachment_id,
                    epoch,
                    now
                ],
            )
            .map_err(sql_err)?;
        if n != 1 {
            return Err(MetaError::CasConflict { expected: expected_generation });
        }
        Ok(expected_generation + 1)
    }

    fn create_snapshot(&self, snapshot_id: &str, volume_id: &str) -> Result<SnapshotRow> {
        let conn = self.conn.lock().unwrap();
        let head = conn
            .query_row(
                "SELECT volume_id, size_bytes, generation, root_hash, root_object_id
                   FROM volumes WHERE volume_id = ?1",
                params![volume_id],
                row_to_head,
            )
            .optional()
            .map_err(sql_err)?
            .ok_or_else(|| MetaError::NotFound(volume_id.to_string()))?;
        conn.execute(
            "INSERT INTO snapshots (snapshot_id, volume_id, generation, root_hash, root_object_id, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                snapshot_id,
                volume_id,
                head.generation,
                head.root_hash.as_ref().map(|h| h.as_slice()),
                head.root_object_id,
                now_ms()
            ],
        )
        .map_err(sql_err)?;
        Ok(SnapshotRow {
            snapshot_id: snapshot_id.to_string(),
            volume_id: volume_id.to_string(),
            generation: head.generation,
            root_hash: head.root_hash,
            root_object_id: head.root_object_id,
        })
    }

    fn list_snapshots(&self, volume_id: &str) -> Result<Vec<SnapshotRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT snapshot_id, volume_id, generation, root_hash, root_object_id
                   FROM snapshots WHERE volume_id = ?1 ORDER BY created_at_ms",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![volume_id], |row| {
                let hash: Option<Vec<u8>> = row.get(3)?;
                Ok(SnapshotRow {
                    snapshot_id: row.get(0)?,
                    volume_id: row.get(1)?,
                    generation: row.get(2)?,
                    root_hash: hash.map(|h| h.try_into().expect("32 bytes")),
                    root_object_id: row.get(4)?,
                })
            })
            .map_err(sql_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(sql_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, SqliteMeta) {
        let dir = tempfile::tempdir().unwrap();
        let meta = SqliteMeta::open(&dir.path().join("meta.db")).unwrap();
        (dir, meta)
    }

    #[test]
    fn volume_lifecycle_and_head() {
        let (_d, m) = store();
        m.create_volume("v1", 1 << 22).unwrap();
        assert!(matches!(m.create_volume("v1", 1), Err(MetaError::AlreadyExists(_))));
        let head = m.load_head("v1").unwrap();
        assert_eq!(head.generation, 0);
        assert!(head.root_hash.is_none());
        assert!(matches!(m.load_head("nope"), Err(MetaError::NotFound(_))));
    }

    #[test]
    fn lease_acquire_renew_fence() {
        let (_d, m) = store();
        m.create_volume("v1", 1 << 22).unwrap();
        let e1 = m.acquire_lease("v1", "attA", 60_000).unwrap();
        assert_eq!(e1, 1);
        // Another attachment cannot steal an unexpired lease.
        assert!(matches!(m.acquire_lease("v1", "attB", 60_000), Err(MetaError::LeaseHeld)));
        m.renew_lease("v1", "attA", e1, 60_000).unwrap();
        // Revoke fences the current holder.
        m.revoke_lease("v1").unwrap();
        assert!(matches!(m.renew_lease("v1", "attA", e1, 60_000), Err(MetaError::Fenced)));
        let e2 = m.acquire_lease("v1", "attB", 60_000).unwrap();
        assert_eq!(e2, 2);
        // Old epoch renew still fails even though owner column changed.
        assert!(matches!(m.renew_lease("v1", "attA", e1, 60_000), Err(MetaError::Fenced)));
    }

    #[test]
    fn cas_requires_generation_owner_epoch_and_live_lease() {
        let (_d, m) = store();
        m.create_volume("v1", 1 << 22).unwrap();
        let epoch = m.acquire_lease("v1", "attA", 60_000).unwrap();
        let g1 = m.cas_head("v1", 0, [1; 32], "obj1", "attA", epoch).unwrap();
        assert_eq!(g1, 1);
        // Wrong expected generation.
        assert!(m.cas_head("v1", 0, [2; 32], "obj2", "attA", epoch).is_err());
        // Wrong epoch.
        assert!(m.cas_head("v1", 1, [2; 32], "obj2", "attA", epoch + 1).is_err());
        // Fenced holder cannot CAS.
        m.revoke_lease("v1").unwrap();
        assert!(m.cas_head("v1", 1, [2; 32], "obj2", "attA", epoch).is_err());
        // New holder continues from the committed generation.
        let e2 = m.acquire_lease("v1", "attB", 60_000).unwrap();
        let g2 = m.cas_head("v1", 1, [3; 32], "obj3", "attB", e2).unwrap();
        assert_eq!(g2, 2);
        let head = m.load_head("v1").unwrap();
        assert_eq!(head.root_hash, Some([3; 32]));
        assert_eq!(head.root_object_id.as_deref(), Some("obj3"));
    }

    #[test]
    fn expired_lease_can_be_taken_and_old_epoch_is_dead() {
        let (_d, m) = store();
        m.create_volume("v1", 1 << 22).unwrap();
        let e1 = m.acquire_lease("v1", "attA", 1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let e2 = m.acquire_lease("v1", "attB", 60_000).unwrap();
        assert!(e2 > e1);
        assert!(m.cas_head("v1", 0, [1; 32], "obj", "attA", e1).is_err());
        assert!(m.cas_head("v1", 0, [1; 32], "obj", "attB", e2).is_ok());
    }

    #[test]
    fn snapshots_capture_current_root() {
        let (_d, m) = store();
        m.create_volume("v1", 1 << 22).unwrap();
        let epoch = m.acquire_lease("v1", "attA", 60_000).unwrap();
        m.cas_head("v1", 0, [7; 32], "obj7", "attA", epoch).unwrap();
        let snap = m.create_snapshot("snap_1", "v1").unwrap();
        assert_eq!(snap.generation, 1);
        assert_eq!(snap.root_hash, Some([7; 32]));
        assert_eq!(m.list_snapshots("v1").unwrap().len(), 1);
    }
}

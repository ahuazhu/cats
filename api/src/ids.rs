//! Resource identifier helpers.
//!
//! Ids are prefixed strings (`cat_…`, `disk_…`) so they stay self-describing
//! in logs and API payloads. The random part is produced by the caller
//! (control plane uses UUIDv4 simple form) to keep this crate free of RNG
//! dependencies.

pub const CAT_PREFIX: &str = "cat_";
pub const DISK_PREFIX: &str = "disk_";
pub const VOLUME_PREFIX: &str = "vol_";
pub const ATTACHMENT_PREFIX: &str = "att_";
pub const MOUNT_PREFIX: &str = "mnt_";
pub const OPERATION_PREFIX: &str = "op_";
pub const NODE_PREFIX: &str = "node_";
pub const ENDPOINT_PREFIX: &str = "ep_";
pub const SNAPSHOT_PREFIX: &str = "snap_";
pub const JOB_PREFIX: &str = "job_";
pub const SESSION_PREFIX: &str = "sess_";

/// Build a prefixed id from a prefix constant and a random suffix.
pub fn make_id(prefix: &str, random_suffix: &str) -> String {
    format!("{prefix}{random_suffix}")
}

/// Validate the shape of a prefixed id.
pub fn has_prefix(id: &str, prefix: &str) -> bool {
    id.starts_with(prefix) && id.len() > prefix.len()
}

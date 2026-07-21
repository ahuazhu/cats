//! Control-plane -> node-agent job protocol.
//!
//! Jobs are idempotent: `job_id` is derived by the caller from
//! `resource/generation/action`; the node agent journals results and replays
//! them for duplicate submissions instead of re-executing (arch doc §17.4).

use serde::{Deserialize, Serialize};

use crate::resources::ObservedState;

/// Authorization envelope for storage access carried by a job.
///
/// The fencing epoch is the only credential the node needs in the local
/// dev/test blobstore; the S3 backend adds scoped remote credentials here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeGrant {
    pub disk_id: String,
    pub volume_id: String,
    pub attachment_id: String,
    pub epoch: i64,
    pub size_bytes: u64,
    /// Mount path inside the guest ("/" for the root disk).
    pub mount_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NodeJobAction {
    /// Start the block backend + VMM + guest for a cat.
    StartCat {
        cat_id: String,
        image: String,
        cpus: u32,
        memory_mib: u64,
        volumes: Vec<VolumeGrant>,
    },
    /// Flush disks, stop guest/VMM/backends, release runtime state.
    StopCat { cat_id: String },
    /// Pause + page-out (Suspended, ADR-0002).
    SuspendCat { cat_id: String },
    /// Resume a suspended cat.
    ResumeCat { cat_id: String },
    /// Snapshot + VMM/backend exit (Warm, ADR-0002).
    WarmCat { cat_id: String },
    /// Restore a warm cat on the same node.
    RestoreCat { cat_id: String },
    /// Hot-attach an additional disk to a running cat.
    AttachDisk { cat_id: String, volume: VolumeGrant },
    /// Flush + detach a disk from a running cat.
    DetachDisk { cat_id: String, disk_id: String },
    /// Remove any local residue for a cat (idempotent; used after failures).
    CleanupCat { cat_id: String },
}

impl NodeJobAction {
    pub fn kind(&self) -> &'static str {
        match self {
            NodeJobAction::StartCat { .. } => "start_cat",
            NodeJobAction::StopCat { .. } => "stop_cat",
            NodeJobAction::SuspendCat { .. } => "suspend_cat",
            NodeJobAction::ResumeCat { .. } => "resume_cat",
            NodeJobAction::WarmCat { .. } => "warm_cat",
            NodeJobAction::RestoreCat { .. } => "restore_cat",
            NodeJobAction::AttachDisk { .. } => "attach_disk",
            NodeJobAction::DetachDisk { .. } => "detach_disk",
            NodeJobAction::CleanupCat { .. } => "cleanup_cat",
        }
    }

    pub fn cat_id(&self) -> &str {
        match self {
            NodeJobAction::StartCat { cat_id, .. }
            | NodeJobAction::StopCat { cat_id }
            | NodeJobAction::SuspendCat { cat_id }
            | NodeJobAction::ResumeCat { cat_id }
            | NodeJobAction::WarmCat { cat_id }
            | NodeJobAction::RestoreCat { cat_id }
            | NodeJobAction::AttachDisk { cat_id, .. }
            | NodeJobAction::DetachDisk { cat_id, .. }
            | NodeJobAction::CleanupCat { cat_id } => cat_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeJob {
    /// `job_<cat>_<generation>_<action>`; duplicates replay journaled results.
    pub job_id: String,
    pub cat_generation: i64,
    #[serde(flatten)]
    pub action: NodeJobAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeJobResult {
    pub job_id: String,
    pub phase: JobPhase,
    pub observed_state: ObservedState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub retryable: bool,
}

impl NodeJobResult {
    pub fn ok(job_id: impl Into<String>, observed: ObservedState) -> Self {
        Self {
            job_id: job_id.into(),
            phase: JobPhase::Succeeded,
            observed_state: observed,
            error: None,
            retryable: false,
        }
    }

    pub fn fail(
        job_id: impl Into<String>,
        observed: ObservedState,
        error: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            phase: JobPhase::Failed,
            observed_state: observed,
            error: Some(error.into()),
            retryable,
        }
    }
}

/// Derive the idempotent job id.
pub fn job_id(cat_id: &str, generation: i64, action_kind: &str) -> String {
    format!(
        "{}{}_{}_{}",
        crate::ids::JOB_PREFIX,
        cat_id,
        generation,
        action_kind
    )
}

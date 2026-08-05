//! Control-plane -> node-agent job protocol.
//!
//! Jobs are idempotent: `job_id` is derived by the caller from
//! `resource/generation/action`; the node agent journals results and replays
//! them for duplicate submissions instead of re-executing (arch doc §17.4).

use serde::{Deserialize, Serialize};

use crate::resources::ObservedState;

/// Storage attachment grant carried by a job.
///
/// Provider credentials never cross this API boundary. The node obtains
/// adapter credentials from its own workload identity or secret source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeGrant {
    pub disk_id: String,
    pub volume_id: String,
    pub attachment_id: String,
    pub epoch: i64,
    pub size_bytes: u64,
    /// Mount path inside the guest ("/" for the root disk).
    pub mount_path: String,
    /// Passed to blockd as the engine's durability mode (ADR-0021).
    #[serde(default)]
    pub durability: crate::resources::DiskDurability,
}

/// Exact writer authority acquired by one node lifecycle action.
///
/// Start/Restore can acquire a new fencing epoch after the control plane has
/// persisted its dispatch marker. Returning the action's exact identities is
/// what lets a superseding Stop revoke only that writer, never a replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeLeaseAuthority {
    pub volume_id: String,
    pub attachment_id: String,
    pub epoch: i64,
}

/// Why a Cat runtime is being stopped.
///
/// A normal Cold transition preserves every disk and therefore drains every
/// local durability journal. Destroy removes the Cat-owned RootDisk, so the
/// node may discard only that disk's local state; independently-owned
/// PersistentDisks still cross the mandatory remote-drain boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum StopCatDisposition {
    #[default]
    Cold,
    Destroy {
        /// Cat-owned RootDisks whose local journal/cache may be discarded.
        disposable_root_disk_ids: Vec<String>,
        /// Independently-owned disks that must still complete final drain.
        retained_persistent_disk_ids: Vec<String>,
    },
}

impl StopCatDisposition {
    fn is_cold(&self) -> bool {
        matches!(self, Self::Cold)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendWorkFence {
    pub control_work_version: i64,
    pub guest_lease_sequence: u64,
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
    StopCat {
        cat_id: String,
        /// Omitted by older controllers and for ordinary Cold stops. The safe
        /// compatibility default is to preserve and drain every disk.
        #[serde(default, skip_serializing_if = "StopCatDisposition::is_cold")]
        disposition: StopCatDisposition,
    },
    /// Pause + page-out (Suspended, ADR-0002).
    SuspendCat {
        cat_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        work_fence: Option<SuspendWorkFence>,
    },
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
    /// Force every attached disk to a durable point: guest page cache down to
    /// the engines, staged packs published (ADR-0021). The escape hatch that
    /// lets a relaxed workload buy one strict moment on demand.
    SyncCat { cat_id: String },
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
            NodeJobAction::SyncCat { .. } => "sync_cat",
            NodeJobAction::CleanupCat { .. } => "cleanup_cat",
        }
    }

    pub fn cat_id(&self) -> &str {
        match self {
            NodeJobAction::StartCat { cat_id, .. }
            | NodeJobAction::StopCat { cat_id, .. }
            | NodeJobAction::SuspendCat { cat_id, .. }
            | NodeJobAction::ResumeCat { cat_id }
            | NodeJobAction::WarmCat { cat_id }
            | NodeJobAction::RestoreCat { cat_id }
            | NodeJobAction::AttachDisk { cat_id, .. }
            | NodeJobAction::DetachDisk { cat_id, .. }
            | NodeJobAction::SyncCat { cat_id }
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
pub enum TopologyBarrierMode {
    Fence,
    Release,
}

/// Agent-side queue fence used while repairing pre-provenance disk topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyBarrierRequest {
    pub epoch: i64,
    pub mode: TopologyBarrierMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyBarrierResponse {
    pub epoch: i64,
    pub drained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Succeeded,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeJobErrorCode {
    ActivityChanged,
    /// The requested disk is absent from a Cloud Hypervisor runtime, whose
    /// current production configuration cannot hot-plug it. The control plane
    /// may rebuild that Cat from its complete authoritative binding set.
    HotAttachUnsupported,
    LifecycleFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeJobResult {
    pub job_id: String,
    pub phase: JobPhase,
    pub observed_state: ObservedState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<NodeJobErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub retryable: bool,
    /// Writer epochs acquired inside this successful action. Older agents omit
    /// the field; controllers must then retain their pre-action authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_leases: Vec<VolumeLeaseAuthority>,
}

impl NodeJobResult {
    pub fn ok(job_id: impl Into<String>, observed: ObservedState) -> Self {
        Self {
            job_id: job_id.into(),
            phase: JobPhase::Succeeded,
            observed_state: observed,
            error_code: None,
            error: None,
            retryable: false,
            volume_leases: Vec::new(),
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
            error_code: Some(NodeJobErrorCode::LifecycleFailed),
            error: Some(error.into()),
            retryable,
            volume_leases: Vec::new(),
        }
    }

    pub fn rejected(
        job_id: impl Into<String>,
        observed: ObservedState,
        error: impl Into<String>,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            phase: JobPhase::Rejected,
            observed_state: observed,
            error_code: Some(NodeJobErrorCode::ActivityChanged),
            error: Some(error.into()),
            retryable: true,
            volume_leases: Vec::new(),
        }
    }

    pub fn fail_with_code(
        job_id: impl Into<String>,
        observed: ObservedState,
        code: NodeJobErrorCode,
        error: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            phase: JobPhase::Failed,
            observed_state: observed,
            error_code: Some(code),
            error: Some(error.into()),
            retryable,
            volume_leases: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_stop_payload_defaults_to_cold() {
        let job: NodeJob = serde_json::from_str(
            r#"{"job_id":"job_cat-a_1_stop_cat","cat_generation":1,"action":"stop_cat","cat_id":"cat-a"}"#,
        )
        .unwrap();
        assert!(matches!(
            job.action,
            NodeJobAction::StopCat {
                disposition: StopCatDisposition::Cold,
                ..
            }
        ));

        let encoded = serde_json::to_value(job).unwrap();
        assert_eq!(encoded.get("action").unwrap(), "stop_cat");
        assert!(
            encoded.get("disposition").is_none(),
            "ordinary Cold stops keep the legacy wire shape"
        );
    }

    #[test]
    fn destroy_disk_disposition_is_explicit_on_the_wire() {
        let job = NodeJob {
            job_id: "job_cat-a_2_stop_cat".to_string(),
            cat_generation: 2,
            action: NodeJobAction::StopCat {
                cat_id: "cat-a".to_string(),
                disposition: StopCatDisposition::Destroy {
                    disposable_root_disk_ids: vec!["root".to_string()],
                    retained_persistent_disk_ids: vec!["data".to_string()],
                },
            },
        };
        let encoded = serde_json::to_value(job).unwrap();
        assert_eq!(encoded["disposition"]["mode"], "destroy");
        assert_eq!(
            encoded["disposition"]["disposable_root_disk_ids"][0],
            "root"
        );
        assert_eq!(
            encoded["disposition"]["retained_persistent_disk_ids"][0],
            "data"
        );
    }

    #[test]
    fn legacy_job_result_defaults_to_no_action_acquired_writer_authority() {
        let result: NodeJobResult = serde_json::from_str(
            r#"{"job_id":"job_cat-a_1_start_cat","phase":"succeeded","observed_state":"running","retryable":false}"#,
        )
        .unwrap();
        assert!(result.volume_leases.is_empty());

        let mut current = NodeJobResult::ok("job_cat-a_1_start_cat", ObservedState::Running);
        current.volume_leases.push(VolumeLeaseAuthority {
            volume_id: "vol-a".into(),
            attachment_id: "att-a".into(),
            epoch: 7,
        });
        let round_trip: NodeJobResult =
            serde_json::from_value(serde_json::to_value(&current).unwrap()).unwrap();
        assert_eq!(round_trip.volume_leases, current.volume_leases);
    }
}

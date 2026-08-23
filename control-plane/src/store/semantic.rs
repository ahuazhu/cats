//! PostgreSQL store for the synchronous, semantic Control/Node protocol.
//!
//! This module deliberately does not mirror writes into `cat_records`,
//! `disk_records`, runtime Operations, Node inventory or Agent sessions.  The
//! cutover is an empty-data protocol replacement; callers use only these
//! product rows.

use postgres::Row;

use self::placement::{LeastAllocatedPlacement, SemanticPlacementStrategy};
use super::{Result, Store};

mod placement;

const DB_NOW_MS: &str = "CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS BIGINT)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatState {
    Running,
    Suspended,
    Warm,
    Cold,
    Failure,
    Destroyed,
}

impl CatState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Failure => "failure",
            Self::Destroyed => "destroyed",
        }
    }

    fn from_db(value: &str) -> Self {
        match value {
            "running" => Self::Running,
            "suspended" => Self::Suspended,
            "warm" => Self::Warm,
            "cold" => Self::Cold,
            "failure" => Self::Failure,
            "destroyed" => Self::Destroyed,
            _ => unreachable!("cats.state is protected by a closed CHECK constraint"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatAction {
    Create,
    Run,
    Suspend,
    Warm,
    Cold,
    Destroy,
}

impl CatAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Run => "run",
            Self::Suspend => "suspend",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Destroy => "destroy",
        }
    }

    fn from_db(value: &str) -> Self {
        match value {
            "create" => Self::Create,
            "run" => Self::Run,
            "suspend" => Self::Suspend,
            "warm" => Self::Warm,
            "cold" => Self::Cold,
            "destroy" => Self::Destroy,
            _ => unreachable!("cats.current_action is protected by a closed CHECK constraint"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Running,
    Draining,
    Offline,
    ResetRequired,
    Deleted,
}

impl NodeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Offline => "offline",
            Self::ResetRequired => "reset_required",
            Self::Deleted => "deleted",
        }
    }

    fn from_db(value: &str) -> Self {
        match value {
            "running" => Self::Running,
            "draining" => Self::Draining,
            "offline" => Self::Offline,
            "reset_required" => Self::ResetRequired,
            "deleted" => Self::Deleted,
            _ => unreachable!("nodes.status is protected by a closed CHECK constraint"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CatRecord {
    pub cat_id: String,
    pub workspace_id: String,
    pub cat_slug: String,
    pub state: Option<CatState>,
    pub current_action: Option<CatAction>,
    pub current_action_started_at: Option<i64>,
    pub current_action_node_id: Option<String>,
    pub node_id: Option<String>,
    pub cpu_count: i64,
    pub memory_bytes: i64,
    pub boot_image: String,
    pub last_error_code: Option<String>,
    pub last_error_message: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub destroyed_at: Option<i64>,
}

impl CatRecord {
    fn has_internal_relocation_claim(&self) -> bool {
        self.current_action == Some(CatAction::Run)
            && self
                .node_id
                .as_deref()
                .zip(self.current_action_node_id.as_deref())
                .is_some_and(|(source, target)| source != target)
    }
}

/// The only Node selected for new traffic to a Cat. No row means that new
/// traffic is withdrawn. This projection deliberately carries no lifecycle
/// Operation, request identity or heartbeat state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatIngressTargetRecord {
    pub cat_id: String,
    pub node_id: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishCatIngressOutcome {
    Published(CatIngressTargetRecord),
    AlreadyPublished(CatIngressTargetRecord),
    Conflict(CatIngressTargetRecord),
    CatNotReady,
    NodeNotRunning,
    CatNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WithdrawCatIngressOutcome {
    Withdrawn,
    AlreadyWithdrawn,
    Conflict(CatIngressTargetRecord),
    CatNotWithdrawing,
    CatNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCat<'a> {
    pub cat_id: &'a str,
    pub workspace_id: &'a str,
    pub cat_slug: &'a str,
    pub node_id: &'a str,
    pub cpu_count: i64,
    pub memory_bytes: i64,
    pub boot_image: &'a str,
}

/// One mount requested as part of an atomic Cat create. The public create
/// protocol resolves a current workspace-scoped slug before admission. The
/// Store only accepts and locks the resulting immutable disk ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCatMount<'a> {
    pub binding_id: &'a str,
    pub disk_id: &'a str,
    pub mount_path: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatMountRecord {
    pub disk_id: String,
    pub disk_slug: String,
    pub volume_id: String,
    pub filesystem_uuid: String,
    pub disk_format: String,
    pub mount_path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CatWithMounts {
    pub cat: CatRecord,
    pub mounts: Vec<CatMountRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicCatCreate<'a> {
    pub cat_id: &'a str,
    pub workspace_id: &'a str,
    pub cat_slug: &'a str,
    pub cpu_count: i64,
    pub memory_bytes: i64,
    pub boot_image: &'a str,
    pub mounts: &'a [NewCatMount<'a>],
}

#[derive(Debug, Clone, PartialEq)]
pub enum AdmitCatCreateOutcome {
    Created(CatWithMounts),
    SameAction(CatWithMounts),
    AlreadyExists(CatWithMounts),
    Busy(CatWithMounts),
    ConfigurationConflict(CatWithMounts),
    NodeNotSchedulable,
    MountRejected { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticCatSelector<'a> {
    Id(&'a str),
    Slug {
        workspace_id: &'a str,
        cat_slug: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum AdmitCatActionOutcome {
    Acquired(CatWithMounts),
    SameAction(CatWithMounts),
    AlreadyDone(CatWithMounts),
    Busy(CatWithMounts),
    InvalidState(CatWithMounts),
    NotFound,
    NodeNotSchedulable(CatWithMounts),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateCatOutcome {
    Created(CatRecord),
    Existing(CatRecord),
    NodeNotSchedulable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BeginCatActionOutcome {
    Acquired(CatRecord),
    SameActionInProgress(CatRecord),
    Busy(CatRecord),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishCatAction<'a> {
    pub expected_action: CatAction,
    pub expected_action_started_at: i64,
    pub expected_node_id: Option<&'a str>,
    pub final_state: CatState,
    pub final_node_id: Option<&'a str>,
    pub error_code: Option<&'a str>,
    pub error_message: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: String,
    pub node_name: String,
    pub control_endpoint: String,
    pub vendor: String,
    pub region: String,
    pub zone: String,
    pub instance_id: String,
    pub machine_type: String,
    pub node_version: String,
    pub status: NodeStatus,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A DB-time heartbeat observation used as the exact optimistic token for an
/// offline transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleNodeRecord {
    pub node_id: String,
    pub control_endpoint: String,
    pub last_heartbeat_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRegistration<'a> {
    pub node_id: &'a str,
    pub node_name: &'a str,
    pub control_endpoint: &'a str,
    pub vendor: &'a str,
    pub region: &'a str,
    pub zone: &'a str,
    pub instance_id: &'a str,
    pub machine_type: &'a str,
    pub node_version: &'a str,
    pub reset_completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterNodeOutcome {
    Registered(NodeRecord),
    AlreadyRegistered(NodeRecord),
    RegistrationUpdated(NodeRecord),
    ResetRequired(NodeRecord),
    IdentityConflict(NodeRecord),
    Deleted(NodeRecord),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeHeartbeat<'a> {
    pub node_id: &'a str,
    pub node_reported_at: Option<i64>,
    pub reported_status: NodeStatus,
    pub total_cpu: i64,
    pub cpu_utilized: f64,
    pub total_memory: i64,
    pub memory_utilized: i64,
    pub running_cat_count: i64,
    pub suspended_cat_count: i64,
    pub warm_cat_count: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeHeartbeatRecord {
    pub node_id: String,
    pub last_heartbeat_at: i64,
    pub node_reported_at: Option<i64>,
    pub reported_status: NodeStatus,
    pub total_cpu: i64,
    pub cpu_utilized: f64,
    pub total_memory: i64,
    pub memory_utilized: i64,
    pub running_cat_count: i64,
    pub suspended_cat_count: i64,
    pub warm_cat_count: i64,
}

/// One Cat recovery claim after its source Node was marked offline. The Cat's
/// stable product state and source placement remain unchanged until the new
/// Node has reached `target_state`; `current_action_node_id` is the committed
/// target placement and fences late settlement from the old Node.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticCatRecoveryClaim {
    pub cat: CatWithMounts,
    pub source_node_id: String,
    pub target_node_id: String,
    pub target_state: CatState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClaimSemanticCatRecoveryOutcome {
    Claimed(SemanticCatRecoveryClaim),
    AlreadyClaimed(SemanticCatRecoveryClaim),
    ColdNoAction(CatWithMounts),
    UnsupportedState(CatWithMounts),
    NoRunningTarget(CatWithMounts),
    Busy(CatWithMounts),
    SourceNotOffline,
    SourceNotDraining,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticCatRecoveryResult<'a> {
    Recovered,
    RetrySource { code: &'a str, message: &'a str },
    Failed { code: &'a str, message: &'a str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCatRecoverySettlement<'a> {
    pub cat_id: &'a str,
    pub source_node_id: &'a str,
    pub target_node_id: &'a str,
    pub target_state: CatState,
    pub expected_action_started_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticRelocationSource {
    Offline,
    Draining,
}

impl SemanticRelocationSource {
    fn accepts(self, status: &str) -> bool {
        match self {
            Self::Offline => matches!(status, "offline" | "reset_required"),
            Self::Draining => status == "draining",
        }
    }

    fn mismatch(self) -> ClaimSemanticCatRecoveryOutcome {
        match self {
            Self::Offline => ClaimSemanticCatRecoveryOutcome::SourceNotOffline,
            Self::Draining => ClaimSemanticCatRecoveryOutcome::SourceNotDraining,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentDiskRecord {
    pub disk_id: String,
    pub workspace_id: String,
    pub disk_slug: String,
    pub size_bytes: i64,
    pub volume_id: String,
    pub filesystem_uuid: String,
    pub disk_format: String,
    pub status: String,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPersistentDisk<'a> {
    pub disk_id: &'a str,
    pub workspace_id: &'a str,
    pub disk_slug: &'a str,
    pub size_bytes: i64,
    pub volume_id: &'a str,
    pub filesystem_uuid: &'a str,
    pub disk_format: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatePersistentDiskOutcome {
    Created(PersistentDiskRecord),
    Existing(PersistentDiskRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletePersistentDiskOutcome {
    Deleting(PersistentDiskRecord),
    AlreadyDeleted(PersistentDiskRecord),
    Attached,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskBindingRecord {
    pub binding_id: String,
    pub workspace_id: String,
    pub disk_id: String,
    pub cat_id: String,
    pub mount_path: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskBindingWithCat {
    pub binding: DiskBindingRecord,
    pub cat_slug: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachDiskOutcome {
    Attached(DiskBindingRecord),
    AlreadyAttached(DiskBindingRecord),
    MountPathConflict(DiskBindingRecord),
    DiskAlreadyAttached(DiskBindingRecord),
    CatMustBeCold,
    DiskDeleted,
    WorkspaceMismatch,
    CatNotFound,
    DiskNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetachDiskOutcome {
    Detached,
    AlreadyDetached,
    DiskBindingConflict(DiskBindingRecord),
    CatMustBeCold,
    CatNotFound,
}

impl Store {
    /// Publish one current Node for new traffic after noded has reported the
    /// Cat Ready. The lifecycle claim is the scenario condition proving that
    /// this Node is the current create/run target; a stable Running Cat may
    /// replay the same publication after Control has settled the action.
    ///
    /// Publication never switches directly from one Node to another. The old
    /// target must first be withdrawn with its exact Node identity.
    pub fn publish_semantic_cat_ingress(
        &self,
        cat_id: &str,
        node_id: &str,
    ) -> Result<PublishCatIngressOutcome> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let Some(cat) = transaction.query_opt(
                "SELECT state,current_action,current_action_node_id,node_id
                   FROM cats WHERE cat_id=$1 FOR UPDATE",
                &[&cat_id],
            )?
            else {
                transaction.rollback()?;
                return Ok(PublishCatIngressOutcome::CatNotFound);
            };

            if let Some(row) = transaction.query_opt(
                &format!(
                    "SELECT {INGRESS_TARGET_COLUMNS} FROM cat_ingress_targets
                      WHERE cat_id=$1 FOR UPDATE"
                ),
                &[&cat_id],
            )? {
                let current = row_to_ingress_target(&row);
                transaction.commit()?;
                return Ok(if current.node_id == node_id {
                    PublishCatIngressOutcome::AlreadyPublished(current)
                } else {
                    PublishCatIngressOutcome::Conflict(current)
                });
            }

            let state: Option<&str> = cat.get(0);
            let current_action: Option<&str> = cat.get(1);
            let current_action_node_id: Option<&str> = cat.get(2);
            let placed_node_id: Option<&str> = cat.get(3);
            let ready_target = matches!(current_action, Some("create" | "run"))
                && current_action_node_id == Some(node_id);
            let settled_target = current_action.is_none()
                && state == Some("running")
                && placed_node_id == Some(node_id);
            if !ready_target && !settled_target {
                transaction.rollback()?;
                return Ok(PublishCatIngressOutcome::CatNotReady);
            }

            if transaction
                .query_opt(
                    "SELECT node_id FROM nodes WHERE node_id=$1 AND status='running' FOR SHARE",
                    &[&node_id],
                )?
                .is_none()
            {
                transaction.rollback()?;
                return Ok(PublishCatIngressOutcome::NodeNotRunning);
            }

            let row = transaction.query_one(
                &format!(
                    "INSERT INTO cat_ingress_targets (cat_id,node_id,updated_at)
                     VALUES ($1,$2,{DB_NOW_MS})
                     RETURNING {INGRESS_TARGET_COLUMNS}"
                ),
                &[&cat_id, &node_id],
            )?;
            let target = row_to_ingress_target(&row);
            transaction.commit()?;
            Ok(PublishCatIngressOutcome::Published(target))
        })
    }

    /// Withdraw new traffic only when the caller still names the published
    /// Node. A delayed withdrawal for an older Node cannot clear a newer
    /// target. Repeating an exact successful withdrawal is already done.
    pub fn withdraw_semantic_cat_ingress(
        &self,
        cat_id: &str,
        old_node_id: &str,
    ) -> Result<WithdrawCatIngressOutcome> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let Some(cat) = transaction.query_opt(
                "SELECT state,current_action,current_action_node_id,node_id
                   FROM cats WHERE cat_id=$1 FOR UPDATE",
                &[&cat_id],
            )?
            else {
                transaction.rollback()?;
                return Ok(WithdrawCatIngressOutcome::CatNotFound);
            };
            let Some(row) = transaction.query_opt(
                &format!(
                    "SELECT {INGRESS_TARGET_COLUMNS} FROM cat_ingress_targets
                      WHERE cat_id=$1 FOR UPDATE"
                ),
                &[&cat_id],
            )?
            else {
                transaction.commit()?;
                return Ok(WithdrawCatIngressOutcome::AlreadyWithdrawn);
            };
            let target = row_to_ingress_target(&row);
            if target.node_id != old_node_id {
                transaction.commit()?;
                return Ok(WithdrawCatIngressOutcome::Conflict(target));
            }

            let state: Option<&str> = cat.get(0);
            let current_action: Option<&str> = cat.get(1);
            let current_action_node_id: Option<&str> = cat.get(2);
            let placed_node_id: Option<&str> = cat.get(3);
            let leaves_running = state == Some("running")
                && matches!(
                    current_action,
                    Some("suspend" | "warm" | "cold" | "destroy")
                )
                && current_action_node_id == Some(old_node_id)
                && placed_node_id == Some(old_node_id);
            let moves_running = state == Some("running")
                && current_action == Some("run")
                && placed_node_id == Some(old_node_id)
                && current_action_node_id.is_some_and(|node_id| node_id != old_node_id);
            let old_node_is_offline = placed_node_id == Some(old_node_id)
                && transaction
                    .query_opt(
                        "SELECT node_id FROM nodes
                          WHERE node_id=$1 AND status IN ('offline','reset_required','deleted')
                          FOR SHARE",
                        &[&old_node_id],
                    )?
                    .is_some();
            if !leaves_running && !moves_running && !old_node_is_offline {
                transaction.commit()?;
                return Ok(WithdrawCatIngressOutcome::CatNotWithdrawing);
            }
            transaction.execute(
                "DELETE FROM cat_ingress_targets WHERE cat_id=$1",
                &[&cat_id],
            )?;
            transaction.commit()?;
            Ok(WithdrawCatIngressOutcome::Withdrawn)
        })
    }

    /// Resolve the current target for one new ingress request. The projection
    /// row is the complete answer; lifecycle state and heartbeat do not become
    /// a second serving authority here.
    pub fn resolve_semantic_cat_ingress(
        &self,
        cat_id: &str,
    ) -> Result<Option<CatIngressTargetRecord>> {
        self.with(|client| {
            client
                .query_opt(
                    &format!(
                        "SELECT {INGRESS_TARGET_COLUMNS} FROM cat_ingress_targets WHERE cat_id=$1"
                    ),
                    &[&cat_id],
                )
                .map(|row| row.map(|row| row_to_ingress_target(&row)))
        })
    }

    /// Atomically decides a semantic create and, for a new Cat, records the
    /// complete immutable configuration and all initial disk bindings.
    ///
    /// Placement is selected and reserved in this transaction. An
    /// already-existing slug is still classified from its full configuration;
    /// only a genuinely new create returns `NodeNotSchedulable`.
    pub fn admit_semantic_cat_create(
        &self,
        request: AtomicCatCreate<'_>,
    ) -> Result<AdmitCatCreateOutcome> {
        let mut disk_ids = std::collections::BTreeSet::new();
        let mut mount_paths = std::collections::BTreeSet::new();
        for mount in request.mounts {
            if !disk_ids.insert(mount.disk_id) {
                return Ok(AdmitCatCreateOutcome::MountRejected {
                    code: "duplicate_disk_mount".to_owned(),
                    message: format!("disk {} is mounted more than once", mount.disk_id),
                });
            }
            if !mount_paths.insert(mount.mount_path) {
                return Ok(AdmitCatCreateOutcome::MountRejected {
                    code: "duplicate_mount_path".to_owned(),
                    message: format!("mount path {} is used more than once", mount.mount_path),
                });
            }
        }

        self.with(|client| {
            let mut transaction = client.transaction()?;
            if let Some(row) = transaction.query_opt(
                &format!(
                    "SELECT {CAT_COLUMNS} FROM cats
                      WHERE workspace_id=$1 AND cat_slug=$2 AND destroyed_at IS NULL
                      FOR UPDATE"
                ),
                &[&request.workspace_id, &request.cat_slug],
            )? {
                let cat = row_to_cat(&row);
                let aggregate = cat_with_mounts(&mut transaction, cat)?;
                let configuration_matches = cat_create_configuration_matches(&aggregate, &request);
                let outcome = if !configuration_matches {
                    AdmitCatCreateOutcome::ConfigurationConflict(aggregate)
                } else {
                    match aggregate.cat.current_action {
                        Some(CatAction::Create) => AdmitCatCreateOutcome::SameAction(
                            refresh_current_action_activity(&mut transaction, aggregate)?,
                        ),
                        Some(_) => AdmitCatCreateOutcome::Busy(aggregate),
                        None => AdmitCatCreateOutcome::AlreadyExists(aggregate),
                    }
                };
                transaction.commit()?;
                return Ok(outcome);
            }

            let Some(node_id) =
                ACTIVE_PLACEMENT_STRATEGY.select_running_node(&mut transaction, None)?
            else {
                transaction.rollback()?;
                return Ok(AdmitCatCreateOutcome::NodeNotSchedulable);
            };

            let inserted = transaction.query_opt(
                &format!(
                    "INSERT INTO cats (
                        cat_id,workspace_id,cat_slug,state,current_action,
                        current_action_started_at,current_action_node_id,node_id,
                        cpu_count,memory_bytes,boot_image,created_at,updated_at
                     ) VALUES ($1,$2,$3,NULL,'create',{DB_NOW_MS},$4,NULL,$5,$6,$7,
                               {DB_NOW_MS},{DB_NOW_MS})
                     ON CONFLICT (workspace_id,cat_slug) WHERE destroyed_at IS NULL
                     DO NOTHING
                     RETURNING {CAT_COLUMNS}"
                ),
                &[
                    &request.cat_id,
                    &request.workspace_id,
                    &request.cat_slug,
                    &node_id,
                    &request.cpu_count,
                    &request.memory_bytes,
                    &request.boot_image,
                ],
            )?;
            let Some(row) = inserted else {
                // A concurrent creator won the partial unique index after the
                // first lookup. Classify its committed full configuration in
                // this same transaction.
                let row = transaction.query_one(
                    &format!(
                        "SELECT {CAT_COLUMNS} FROM cats
                          WHERE workspace_id=$1 AND cat_slug=$2 AND destroyed_at IS NULL
                          FOR UPDATE"
                    ),
                    &[&request.workspace_id, &request.cat_slug],
                )?;
                let aggregate = cat_with_mounts(&mut transaction, row_to_cat(&row))?;
                let configuration_matches = cat_create_configuration_matches(&aggregate, &request);
                let outcome = if !configuration_matches {
                    AdmitCatCreateOutcome::ConfigurationConflict(aggregate)
                } else {
                    match aggregate.cat.current_action {
                        Some(CatAction::Create) => AdmitCatCreateOutcome::SameAction(
                            refresh_current_action_activity(&mut transaction, aggregate)?,
                        ),
                        Some(_) => AdmitCatCreateOutcome::Busy(aggregate),
                        None => AdmitCatCreateOutcome::AlreadyExists(aggregate),
                    }
                };
                transaction.commit()?;
                return Ok(outcome);
            };
            let cat = row_to_cat(&row);

            // Lock disks in immutable-ID order so two multi-disk creates cannot
            // deadlock merely because clients supplied mounts in a different
            // order.
            let mut mounts = request.mounts.iter().collect::<Vec<_>>();
            mounts.sort_unstable_by_key(|mount| mount.disk_id);
            for mount in mounts {
                let disk = transaction.query_opt(
                    "SELECT workspace_id,status FROM persistent_disks
                      WHERE disk_id=$1 FOR UPDATE",
                    &[&mount.disk_id],
                )?;
                let Some(disk) = disk else {
                    transaction.rollback()?;
                    return Ok(AdmitCatCreateOutcome::MountRejected {
                        code: "disk_not_found".to_owned(),
                        message: format!("disk {} was not found", mount.disk_id),
                    });
                };
                let disk_workspace: &str = disk.get(0);
                let status: &str = disk.get(1);
                if disk_workspace != request.workspace_id {
                    transaction.rollback()?;
                    return Ok(AdmitCatCreateOutcome::MountRejected {
                        code: "disk_not_found".to_owned(),
                        message: format!("disk {} was not found", mount.disk_id),
                    });
                }
                if status != "normal" {
                    transaction.rollback()?;
                    return Ok(AdmitCatCreateOutcome::MountRejected {
                        code: "disk_deleted".to_owned(),
                        message: format!("disk {} is deleted", mount.disk_id),
                    });
                }
                if transaction
                    .query_opt(
                        "SELECT binding_id FROM disk_bindings WHERE disk_id=$1 FOR UPDATE",
                        &[&mount.disk_id],
                    )?
                    .is_some()
                {
                    transaction.rollback()?;
                    return Ok(AdmitCatCreateOutcome::MountRejected {
                        code: "disk_already_attached".to_owned(),
                        message: format!("disk {} is already attached", mount.disk_id),
                    });
                }
                transaction.execute(
                    &format!(
                        "INSERT INTO disk_bindings (
                            binding_id,workspace_id,disk_id,cat_id,mount_path,created_at
                         ) VALUES ($1,$2,$3,$4,$5,{DB_NOW_MS})"
                    ),
                    &[
                        &mount.binding_id,
                        &request.workspace_id,
                        &mount.disk_id,
                        &request.cat_id,
                        &mount.mount_path,
                    ],
                )?;
            }
            let aggregate = cat_with_mounts(&mut transaction, cat)?;
            transaction.commit()?;
            Ok(AdmitCatCreateOutcome::Created(aggregate))
        })
    }

    /// Atomically classifies and claims one action while returning the exact
    /// mount set that is immutable for the duration of the action.
    pub fn admit_semantic_cat_action(
        &self,
        selector: SemanticCatSelector<'_>,
        action: CatAction,
    ) -> Result<AdmitCatActionOutcome> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let row = match selector {
                SemanticCatSelector::Id(cat_id) => transaction.query_opt(
                    &format!("SELECT {CAT_COLUMNS} FROM cats WHERE cat_id=$1 FOR UPDATE"),
                    &[&cat_id],
                )?,
                SemanticCatSelector::Slug {
                    workspace_id,
                    cat_slug,
                } => transaction.query_opt(
                    &format!(
                        "SELECT {CAT_COLUMNS} FROM cats
                          WHERE workspace_id=$1 AND cat_slug=$2 AND destroyed_at IS NULL
                          FOR UPDATE"
                    ),
                    &[&workspace_id, &cat_slug],
                )?,
            };
            let Some(row) = row else {
                transaction.rollback()?;
                return Ok(AdmitCatActionOutcome::NotFound);
            };
            let cat = row_to_cat(&row);
            let aggregate = cat_with_mounts(&mut transaction, cat)?;
            if aggregate.cat.has_internal_relocation_claim() {
                transaction.commit()?;
                return Ok(AdmitCatActionOutcome::Busy(aggregate));
            }
            if aggregate.cat.state == Some(action_target(action)) {
                transaction.commit()?;
                return Ok(AdmitCatActionOutcome::AlreadyDone(aggregate));
            }
            match aggregate.cat.current_action {
                Some(current) if current == action => {
                    let aggregate = refresh_current_action_activity(&mut transaction, aggregate)?;
                    transaction.commit()?;
                    return Ok(AdmitCatActionOutcome::SameAction(aggregate));
                }
                Some(_) if action != CatAction::Destroy => {
                    transaction.commit()?;
                    return Ok(AdmitCatActionOutcome::Busy(aggregate));
                }
                // Destroy replaces an unresolved action in this locked row.
                // Its noded target remains the replaced action's selected
                // Node, where the physical work must be cancelled and joined.
                Some(_) => {}
                None => {}
            }
            if !semantic_action_allowed(action, aggregate.cat.state) {
                transaction.commit()?;
                return Ok(AdmitCatActionOutcome::InvalidState(aggregate));
            }

            let selected_node_id = match (action, aggregate.cat.state) {
                (CatAction::Run, Some(CatState::Cold)) => {
                    ACTIVE_PLACEMENT_STRATEGY.select_running_node(&mut transaction, None)?
                }
                (CatAction::Destroy, _) => aggregate
                    .cat
                    .current_action_node_id
                    .clone()
                    .or_else(|| aggregate.cat.node_id.clone()),
                _ => aggregate.cat.node_id.clone(),
            };
            let action_node_id = selected_node_id.as_deref();
            if action == CatAction::Run {
                let Some(node_id) = action_node_id else {
                    transaction.commit()?;
                    return Ok(AdmitCatActionOutcome::NodeNotSchedulable(aggregate));
                };
                if transaction
                    .query_opt(
                        "SELECT node_id FROM nodes
                          WHERE node_id=$1 AND status='running' FOR SHARE",
                        &[&node_id],
                    )?
                    .is_none()
                {
                    transaction.commit()?;
                    return Ok(AdmitCatActionOutcome::NodeNotSchedulable(aggregate));
                }
            }
            let row = transaction.query_one(
                &format!(
                    "UPDATE cats
                        SET state=CASE
                                WHEN $2='destroy' AND state IS NULL THEN 'failure'
                                ELSE state
                            END,
                            current_action=$2,
                            current_action_started_at=GREATEST({DB_NOW_MS}, updated_at + 1),
                            current_action_node_id=$3,updated_at={DB_NOW_MS},
                            last_error_code=NULL,last_error_message=NULL
                      WHERE cat_id=$1
                      RETURNING {CAT_COLUMNS}"
                ),
                &[&aggregate.cat.cat_id, &action.as_str(), &action_node_id],
            )?;
            let acquired = CatWithMounts {
                cat: row_to_cat(&row),
                mounts: aggregate.mounts,
            };
            transaction.commit()?;
            Ok(AdmitCatActionOutcome::Acquired(acquired))
        })
    }

    pub fn create_semantic_cat(&self, request: NewCat<'_>) -> Result<CreateCatOutcome> {
        let row = self.with(|client| {
            let mut transaction = client.transaction()?;
            if let Some(existing) = transaction.query_opt(
                &format!(
                    "SELECT {CAT_COLUMNS} FROM cats
                      WHERE workspace_id=$1 AND cat_slug=$2 AND destroyed_at IS NULL"
                ),
                &[&request.workspace_id, &request.cat_slug],
            )? {
                let existing = row_to_cat(&existing);
                transaction.rollback()?;
                return Ok(Some((false, existing)));
            }
            let schedulable = transaction.query_opt(
                "SELECT node_id FROM nodes WHERE node_id=$1 AND status='running' FOR UPDATE",
                &[&request.node_id],
            )?;
            if schedulable.is_none() {
                transaction.rollback()?;
                return Ok(None);
            }
            let inserted = transaction.query_opt(
                &format!(
                    "INSERT INTO cats (
                        cat_id, workspace_id, cat_slug, state, current_action,
                        current_action_started_at, current_action_node_id, node_id,
                        cpu_count, memory_bytes, boot_image, created_at, updated_at
                     ) VALUES ($1,$2,$3,NULL,'create',{DB_NOW_MS},$4,NULL,$5,$6,$7,
                               {DB_NOW_MS},{DB_NOW_MS})
                     ON CONFLICT (workspace_id, cat_slug) WHERE destroyed_at IS NULL
                     DO NOTHING
                     RETURNING {}",
                    CAT_COLUMNS
                ),
                &[
                    &request.cat_id,
                    &request.workspace_id,
                    &request.cat_slug,
                    &request.node_id,
                    &request.cpu_count,
                    &request.memory_bytes,
                    &request.boot_image,
                ],
            )?;
            let outcome = match inserted {
                Some(row) => (true, row_to_cat(&row)),
                None => {
                    let row = transaction.query_one(
                        &format!(
                            "SELECT {CAT_COLUMNS} FROM cats
                              WHERE workspace_id=$1 AND cat_slug=$2 AND destroyed_at IS NULL"
                        ),
                        &[&request.workspace_id, &request.cat_slug],
                    )?;
                    (false, row_to_cat(&row))
                }
            };
            transaction.commit()?;
            Ok(Some(outcome))
        })?;
        Ok(match row {
            None => CreateCatOutcome::NodeNotSchedulable,
            Some((true, row)) => CreateCatOutcome::Created(row),
            Some((false, row)) => CreateCatOutcome::Existing(row),
        })
    }

    pub fn find_current_semantic_cat(
        &self,
        workspace_id: &str,
        cat_slug: &str,
    ) -> Result<Option<CatRecord>> {
        self.with(|client| {
            client
                .query_opt(
                    &format!(
                        "SELECT {CAT_COLUMNS} FROM cats
                          WHERE workspace_id=$1 AND cat_slug=$2 AND destroyed_at IS NULL"
                    ),
                    &[&workspace_id, &cat_slug],
                )
                .map(|row| row.map(|row| row_to_cat(&row)))
        })
    }

    pub fn list_current_semantic_cat_ids(&self, workspace_id: &str) -> Result<Vec<String>> {
        self.with(|client| {
            client
                .query(
                    "SELECT cat_id FROM cats
                      WHERE workspace_id=$1 AND destroyed_at IS NULL
                      ORDER BY cat_slug,cat_id",
                    &[&workspace_id],
                )
                .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    pub fn find_semantic_cat_by_id(&self, cat_id: &str) -> Result<Option<CatRecord>> {
        self.with(|client| {
            client
                .query_opt(
                    &format!("SELECT {CAT_COLUMNS} FROM cats WHERE cat_id=$1"),
                    &[&cat_id],
                )
                .map(|row| row.map(|row| row_to_cat(&row)))
        })
    }

    pub fn find_semantic_cat_with_mounts_by_id(
        &self,
        cat_id: &str,
    ) -> Result<Option<CatWithMounts>> {
        self.with(|client| {
            let Some(row) = client.query_opt(
                &format!("SELECT {CAT_COLUMNS} FROM cats WHERE cat_id=$1"),
                &[&cat_id],
            )?
            else {
                return Ok(None);
            };
            cat_with_mounts(client, row_to_cat(&row)).map(Some)
        })
    }

    /// Returns one DB-time ordered page of ordinary non-Destroy lifecycle
    /// actions with no foreground activity for `stale_after_ms`. Same-action
    /// admission refreshes `updated_at` without changing the action occurrence
    /// identity. Cross-Node offline recovery owns a distinct multi-step state
    /// machine while reusing a `run` lane, so those rows remain exclusively
    /// with that recovery loop.
    pub fn list_stale_semantic_cat_actions(
        &self,
        stale_after_ms: i64,
        limit: usize,
    ) -> Result<Vec<CatWithMounts>> {
        if stale_after_ms <= 0 || !(1..=1024).contains(&limit) {
            return Err(cats_api::error::ApiError::invalid(
                "stale semantic action scan bounds are invalid",
            ));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| cats_api::error::ApiError::invalid("scan limit exceeds BIGINT"))?;
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let rows = transaction.query(
                &format!(
                    "SELECT {CAT_COLUMNS}
                       FROM cats
                      WHERE current_action IS NOT NULL
                        AND current_action<>'destroy'
                        AND updated_at <= {DB_NOW_MS} - $1
                        AND NOT (
                            current_action='run'
                            AND node_id IS NOT NULL
                            AND current_action_node_id IS DISTINCT FROM node_id
                        )
                      ORDER BY updated_at, cat_id COLLATE \"C\"
                      LIMIT $2
                      FOR SHARE SKIP LOCKED"
                ),
                &[&stale_after_ms, &limit],
            )?;
            let mut cats = Vec::with_capacity(rows.len());
            for row in rows {
                cats.push(cat_with_mounts(&mut transaction, row_to_cat(&row))?);
            }
            transaction.commit()?;
            Ok(cats)
        })
    }

    /// Durably rotates one unresolved ordinary recovery attempt behind older
    /// untried claims. The exact occurrence predicate makes a stale attempt a
    /// successful no-op.
    pub fn rotate_stale_semantic_cat_action(
        &self,
        cat_id: &str,
        expected_action: CatAction,
        expected_node_id: Option<&str>,
        expected_action_started_at: i64,
    ) -> Result<bool> {
        self.with(|client| {
            client
                .execute(
                    &format!(
                        "UPDATE cats
                            SET updated_at={DB_NOW_MS}
                          WHERE cat_id=$1
                            AND current_action=$2
                            AND current_action<>'destroy'
                            AND current_action_node_id IS NOT DISTINCT FROM $3
                            AND current_action_started_at=$4"
                    ),
                    &[
                        &cat_id,
                        &expected_action.as_str(),
                        &expected_node_id,
                        &expected_action_started_at,
                    ],
                )
                .map(|changed| changed == 1)
        })
    }

    pub fn try_begin_semantic_cat_action(
        &self,
        cat_id: &str,
        action: CatAction,
        node_id: Option<&str>,
    ) -> Result<BeginCatActionOutcome> {
        let updated = self.with(|client| {
            client.query_opt(
                &format!(
                    "UPDATE cats
                        SET current_action=$2,
                            current_action_started_at=GREATEST({DB_NOW_MS}, updated_at + 1),
                            current_action_node_id=$3,
                            updated_at={DB_NOW_MS},
                            last_error_code=NULL,
                            last_error_message=NULL
                      WHERE cat_id=$1 AND destroyed_at IS NULL AND current_action IS NULL
                      RETURNING {CAT_COLUMNS}"
                ),
                &[&cat_id, &action.as_str(), &node_id],
            )
        })?;
        if let Some(row) = updated {
            return Ok(BeginCatActionOutcome::Acquired(row_to_cat(&row)));
        }
        let Some(row) = self.find_semantic_cat_by_id(cat_id)? else {
            return Ok(BeginCatActionOutcome::NotFound);
        };
        if row.current_action == Some(action) {
            Ok(BeginCatActionOutcome::SameActionInProgress(row))
        } else {
            Ok(BeginCatActionOutcome::Busy(row))
        }
    }

    /// Settle only the action occurrence and Node that still own the Cat row.
    /// A late completion cannot clear another action acquired afterward,
    /// including a later occurrence of the same action/Node tuple.
    pub fn finish_semantic_cat_action(
        &self,
        cat_id: &str,
        finish: FinishCatAction<'_>,
    ) -> Result<Option<CatRecord>> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let row = transaction.query_opt(
                &format!(
                    "UPDATE cats
                        SET state=$5,
                            node_id=$6,
                            current_action=NULL,
                            current_action_started_at=NULL,
                            current_action_node_id=NULL,
                            last_error_code=$7,
                            last_error_message=$8,
                            destroyed_at=CASE WHEN $5='destroyed' THEN {DB_NOW_MS} ELSE NULL END,
                            updated_at={DB_NOW_MS}
                      WHERE cat_id=$1
                        AND current_action=$2
                        AND current_action_node_id IS NOT DISTINCT FROM $3
                        AND current_action_started_at=$4
                      RETURNING {CAT_COLUMNS}"
                ),
                &[
                    &cat_id,
                    &finish.expected_action.as_str(),
                    &finish.expected_node_id,
                    &finish.expected_action_started_at,
                    &finish.final_state.as_str(),
                    &finish.final_node_id,
                    &finish.error_code,
                    &finish.error_message,
                ],
            )?;
            if row.is_some() && finish.final_state == CatState::Destroyed {
                transaction.execute("DELETE FROM disk_bindings WHERE cat_id=$1", &[&cat_id])?;
            }
            transaction.commit()?;
            Ok(row.map(|row| row_to_cat(&row)))
        })
    }

    pub fn register_semantic_node(
        &self,
        request: NodeRegistration<'_>,
    ) -> Result<RegisterNodeOutcome> {
        let outcome = self.with(|client| register_node_transaction(client, request))?;
        Ok(outcome)
    }

    pub fn find_semantic_node(&self, node_id: &str) -> Result<Option<NodeRecord>> {
        self.with(|client| {
            client
                .query_opt(
                    &format!("SELECT {NODE_COLUMNS} FROM nodes WHERE node_id=$1"),
                    &[&node_id],
                )
                .map(|row| row.map(|row| row_to_node(&row)))
        })
    }

    /// Deterministic snapshot for Node management and diagnostics. Lifecycle
    /// placement is selected and reserved inside its mutation transaction.
    pub fn list_running_semantic_nodes(&self) -> Result<Vec<NodeRecord>> {
        self.with(|client| {
            client
                .query(
                    &format!(
                        "SELECT {NODE_COLUMNS} FROM nodes
                          WHERE status='running' ORDER BY node_id"
                    ),
                    &[],
                )
                .map(|rows| rows.iter().map(row_to_node).collect())
        })
    }

    /// Return Nodes whose DB-receipt heartbeat is older than the requested
    /// window. Every registered Node has an initial heartbeat row, so a Node
    /// that never sends its first heartbeat is still discovered here.
    pub fn list_stale_semantic_nodes(&self, missed_for_ms: i64) -> Result<Vec<StaleNodeRecord>> {
        if missed_for_ms <= 0 {
            return Err(cats_api::error::ApiError::invalid(
                "missed heartbeat window must be positive",
            ));
        }
        self.with(|client| {
            client
                .query(
                    &format!(
                        "SELECT n.node_id,n.control_endpoint,h.last_heartbeat_at
                           FROM nodes n
                           JOIN node_heartbeats h ON h.node_id=n.node_id
                          WHERE n.status IN ('running','draining')
                            AND h.last_heartbeat_at <= {DB_NOW_MS} - $1
                          ORDER BY n.node_id"
                    ),
                    &[&missed_for_ms],
                )
                .map(|rows| {
                    rows.into_iter()
                        .map(|row| StaleNodeRecord {
                            node_id: row.get(0),
                            control_endpoint: row.get(1),
                            last_heartbeat_at: row.get(2),
                        })
                        .collect()
                })
        })
    }

    /// Level-triggered recovery discovery. An offline Node remains here while
    /// any current Cat still names it, so transient Control/noded failures are
    /// retried after restart and on every liveness pass without a job table.
    pub fn list_semantic_offline_nodes_with_cats(&self) -> Result<Vec<String>> {
        self.with(|client| {
            client
                .query(
                    "SELECT n.node_id FROM nodes n
                      WHERE n.status IN ('offline','reset_required')
                        AND EXISTS (
                            SELECT 1 FROM cats c
                             WHERE c.node_id=n.node_id AND c.destroyed_at IS NULL
                        )
                      ORDER BY n.node_id",
                    &[],
                )
                .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    /// Level-triggered planned-drain discovery. A draining Node remains here
    /// until no current Cat retains its source placement, so another Control
    /// replica can resume after request cancellation or process restart.
    pub fn list_semantic_draining_nodes_with_cats(&self) -> Result<Vec<String>> {
        self.with(|client| {
            client
                .query(
                    "SELECT n.node_id FROM nodes n
                      WHERE n.status='draining'
                        AND EXISTS (
                            SELECT 1 FROM cats c
                             WHERE (c.node_id=n.node_id OR c.current_action_node_id=n.node_id)
                               AND c.destroyed_at IS NULL
                        )
                      ORDER BY n.node_id",
                    &[],
                )
                .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    /// Mark a stale Node offline only if its heartbeat DB timestamp is still
    /// exactly the one observed before the active health probe.
    pub fn mark_semantic_node_offline_if_heartbeat_unchanged(
        &self,
        candidate: &StaleNodeRecord,
    ) -> Result<bool> {
        self.with(|client| {
            client
                .execute(
                    &format!(
                        "UPDATE nodes n
                            SET status='offline',updated_at={DB_NOW_MS}
                           FROM node_heartbeats h
                          WHERE n.node_id=$1
                            AND n.status IN ('running','draining')
                            AND h.node_id=n.node_id
                            AND h.last_heartbeat_at=$2"
                    ),
                    &[&candidate.node_id, &candidate.last_heartbeat_at],
                )
                .map(|changed| changed == 1)
        })
    }

    /// Snapshot the current non-destroyed Cats whose stable placement still
    /// names this Node. Every Cat is rechecked under row lock by
    /// `claim_semantic_cat_recovery`; this list is discovery, not authority.
    pub fn list_semantic_node_cats(&self, node_id: &str) -> Result<Vec<CatWithMounts>> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let rows = transaction.query(
                &format!(
                    "SELECT {CAT_COLUMNS} FROM cats
                      WHERE node_id=$1 AND destroyed_at IS NULL
                      ORDER BY cat_id FOR SHARE"
                ),
                &[&node_id],
            )?;
            let mut cats = Vec::with_capacity(rows.len());
            for row in rows {
                cats.push(cat_with_mounts(&mut transaction, row_to_cat(&row))?);
            }
            transaction.commit()?;
            Ok(cats)
        })
    }

    /// Discovers a bounded snapshot of unresolved Destroy claims with no
    /// foreground activity for the supplied grace period. Discovery is not
    /// authority: callers must settle through the exact action occurrence and
    /// Node predicate after noded discovery.
    pub fn list_pending_semantic_destroy_claims(
        &self,
        minimum_age_ms: i64,
        limit: i64,
    ) -> Result<Vec<CatWithMounts>> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let rows = transaction.query(
                &format!(
                    "SELECT {CAT_COLUMNS} FROM cats
                      WHERE current_action='destroy'
                        AND updated_at <= {DB_NOW_MS} - $1
                        AND destroyed_at IS NULL
                      ORDER BY updated_at,cat_id
                      LIMIT $2
                      FOR SHARE SKIP LOCKED"
                ),
                &[&minimum_age_ms, &limit],
            )?;
            let mut cats = Vec::with_capacity(rows.len());
            for row in rows {
                cats.push(cat_with_mounts(&mut transaction, row_to_cat(&row))?);
            }
            transaction.commit()?;
            Ok(cats)
        })
    }

    /// Durably rotates one failed recovery attempt behind older untried
    /// Destroy claims. The exact occurrence predicate prevents a stale
    /// scanner from touching a different action or Node lane.
    pub fn rotate_pending_semantic_destroy_claim(
        &self,
        cat_id: &str,
        expected_node_id: Option<&str>,
        expected_action_started_at: i64,
    ) -> Result<bool> {
        self.with(|client| {
            client
                .execute(
                    &format!(
                        "UPDATE cats
                            SET updated_at={DB_NOW_MS}
                          WHERE cat_id=$1
                            AND current_action='destroy'
                            AND current_action_node_id IS NOT DISTINCT FROM $2
                            AND current_action_started_at=$3"
                    ),
                    &[&cat_id, &expected_node_id, &expected_action_started_at],
                )
                .map(|changed| changed == 1)
        })
    }

    /// Planned drain must also observe a placement transaction that reserved
    /// this Node before the cordon committed but has not published stable
    /// `node_id` yet. The exact claim recheck reports that action as busy.
    pub fn list_semantic_node_drain_cats(&self, node_id: &str) -> Result<Vec<CatWithMounts>> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let rows = transaction.query(
                &format!(
                    "SELECT {CAT_COLUMNS} FROM cats
                      WHERE (node_id=$1 OR current_action_node_id=$1)
                        AND destroyed_at IS NULL
                      ORDER BY cat_id FOR SHARE"
                ),
                &[&node_id],
            )?;
            let mut cats = Vec::with_capacity(rows.len());
            for row in rows {
                cats.push(cat_with_mounts(&mut transaction, row_to_cat(&row))?);
            }
            transaction.commit()?;
            Ok(cats)
        })
    }

    /// Atomically replaces any old-Node action lane with one recovery `run`
    /// claim and selects another currently running Node. The source placement
    /// stays on the Cat until terminal recovery, so a Control restart can
    /// rediscover and resume this exact scenario without an Operation row.
    pub fn claim_semantic_cat_recovery(
        &self,
        source_node_id: &str,
        cat_id: &str,
    ) -> Result<ClaimSemanticCatRecoveryOutcome> {
        self.claim_semantic_cat_relocation(
            source_node_id,
            cat_id,
            SemanticRelocationSource::Offline,
        )
    }

    /// Planned drain uses the same durable relocation claim as offline
    /// recovery, but it admits only an exact `draining` source. The stable
    /// state and source placement remain unchanged while Control first makes
    /// the source Cold and then restores the Cat on the reserved target.
    pub fn claim_semantic_cat_drain(
        &self,
        source_node_id: &str,
        cat_id: &str,
    ) -> Result<ClaimSemanticCatRecoveryOutcome> {
        self.claim_semantic_cat_relocation(
            source_node_id,
            cat_id,
            SemanticRelocationSource::Draining,
        )
    }

    fn claim_semantic_cat_relocation(
        &self,
        source_node_id: &str,
        cat_id: &str,
        required_source: SemanticRelocationSource,
    ) -> Result<ClaimSemanticCatRecoveryOutcome> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let source = transaction.query_opt(
                "SELECT status FROM nodes WHERE node_id=$1 FOR SHARE",
                &[&source_node_id],
            )?;
            let Some(source) = source else {
                transaction.rollback()?;
                return Ok(required_source.mismatch());
            };
            if !required_source.accepts(source.get(0)) {
                transaction.rollback()?;
                return Ok(required_source.mismatch());
            }

            let row = transaction.query_opt(
                &format!("SELECT {CAT_COLUMNS} FROM cats WHERE cat_id=$1 FOR UPDATE"),
                &[&cat_id],
            )?;
            let Some(row) = row else {
                transaction.rollback()?;
                return Ok(ClaimSemanticCatRecoveryOutcome::Stale);
            };
            let cat = row_to_cat(&row);
            if cat.destroyed_at.is_some() {
                transaction.rollback()?;
                return Ok(ClaimSemanticCatRecoveryOutcome::Stale);
            }
            let aggregate = cat_with_mounts(&mut transaction, cat)?;
            if aggregate.cat.node_id.as_deref() != Some(source_node_id) {
                if required_source == SemanticRelocationSource::Draining
                    && aggregate.cat.current_action.is_some()
                    && aggregate.cat.current_action_node_id.as_deref() == Some(source_node_id)
                {
                    transaction.commit()?;
                    return Ok(ClaimSemanticCatRecoveryOutcome::Busy(aggregate));
                }
                transaction.commit()?;
                return Ok(ClaimSemanticCatRecoveryOutcome::Stale);
            }
            let Some(target_state) = aggregate.cat.state else {
                transaction.commit()?;
                return Ok(ClaimSemanticCatRecoveryOutcome::UnsupportedState(aggregate));
            };
            match target_state {
                CatState::Cold => {
                    transaction.commit()?;
                    return Ok(ClaimSemanticCatRecoveryOutcome::ColdNoAction(aggregate));
                }
                CatState::Failure | CatState::Destroyed => {
                    transaction.commit()?;
                    return Ok(ClaimSemanticCatRecoveryOutcome::UnsupportedState(aggregate));
                }
                CatState::Running | CatState::Suspended | CatState::Warm => {}
            }

            // A previous relocation claim is recognizable without another
            // resource: the stable placement is still the source while the
            // run lane names a distinct target admitted while running. A
            // later cordon does not invalidate that already-owned placement.
            let mut unavailable_drain_target = None;
            if aggregate.cat.current_action == Some(CatAction::Run) {
                if let Some(target_node_id) = aggregate.cat.current_action_node_id.clone() {
                    if target_node_id != source_node_id {
                        let target_is_available = transaction
                            .query_opt(
                                "SELECT node_id FROM nodes
                                  WHERE node_id=$1 AND status IN ('running','draining') FOR SHARE",
                                &[&target_node_id],
                            )?
                            .is_some();
                        if target_is_available {
                            let claim = SemanticCatRecoveryClaim {
                                cat: aggregate,
                                source_node_id: source_node_id.to_owned(),
                                target_node_id,
                                target_state,
                            };
                            transaction.commit()?;
                            return Ok(ClaimSemanticCatRecoveryOutcome::AlreadyClaimed(claim));
                        }
                        // A planned drain may replace only its recognizable
                        // cross-Node Run reservation after that exact target
                        // stops accepting placement. The Cat row lock and the
                        // target-bound settlement predicate prevent a late
                        // result for the old target from winning.
                        if required_source == SemanticRelocationSource::Draining {
                            unavailable_drain_target = Some(target_node_id);
                        }
                    }
                }
            }

            if required_source == SemanticRelocationSource::Draining
                && aggregate.cat.current_action.is_some()
                && unavailable_drain_target.is_none()
            {
                transaction.commit()?;
                return Ok(ClaimSemanticCatRecoveryOutcome::Busy(aggregate));
            }

            let Some(target_node_id) = ACTIVE_PLACEMENT_STRATEGY
                .select_running_node(&mut transaction, Some(source_node_id))?
            else {
                transaction.commit()?;
                return Ok(ClaimSemanticCatRecoveryOutcome::NoRunningTarget(aggregate));
            };
            if let Some(old_target_node_id) = unavailable_drain_target {
                // Running drain publishes ingress before settling placement.
                // Close an exact old-target publication in the same Cat-row
                // transaction that replaces the reservation. A concurrent or
                // late publish for the old target observes the new claim and
                // fails CatNotReady.
                transaction.execute(
                    "DELETE FROM cat_ingress_targets WHERE cat_id=$1 AND node_id=$2",
                    &[&cat_id, &old_target_node_id],
                )?;
            }
            let row = transaction.query_one(
                &format!(
                    "UPDATE cats
                        SET current_action='run',
                            current_action_started_at=GREATEST({DB_NOW_MS}, updated_at + 1),
                            current_action_node_id=$3,
                            last_error_code=NULL,last_error_message=NULL,
                            updated_at={DB_NOW_MS}
                      WHERE cat_id=$1 AND node_id=$2 AND destroyed_at IS NULL
                      RETURNING {CAT_COLUMNS}"
                ),
                &[&cat_id, &source_node_id, &target_node_id],
            )?;
            let claimed = cat_with_mounts(&mut transaction, row_to_cat(&row))?;
            let claim = SemanticCatRecoveryClaim {
                cat: claimed,
                source_node_id: source_node_id.to_owned(),
                target_node_id,
                target_state,
            };
            transaction.commit()?;
            Ok(ClaimSemanticCatRecoveryOutcome::Claimed(claim))
        })
    }

    /// Settle only the exact relocation occurrence, lane and source placement.
    /// Success
    /// publishes the new placement while retaining the pre-relocation product
    /// state. A source Cold failure releases only the unused target
    /// reservation while preserving retryable source state and placement; a
    /// target start/restore failure remains attached to that target for cleanup.
    pub fn finish_semantic_cat_recovery(
        &self,
        settlement: SemanticCatRecoverySettlement<'_>,
        result: SemanticCatRecoveryResult<'_>,
    ) -> Result<Option<CatWithMounts>> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let source_is_draining: bool = transaction
                .query_one(
                    "SELECT EXISTS (
                        SELECT 1 FROM nodes WHERE node_id=$1 AND status='draining'
                    )",
                    &[&settlement.source_node_id],
                )?
                .get(0);
            let (state, final_node_id, error_code, error_message) = match result {
                SemanticCatRecoveryResult::Recovered => (
                    settlement.target_state.as_str(),
                    settlement.target_node_id,
                    None,
                    None,
                ),
                SemanticCatRecoveryResult::RetrySource { code, message } => (
                    settlement.target_state.as_str(),
                    settlement.source_node_id,
                    Some(code),
                    Some(message),
                ),
                SemanticCatRecoveryResult::Failed { code, message } => (
                    CatState::Failure.as_str(),
                    settlement.target_node_id,
                    Some(code),
                    Some(message),
                ),
            };
            let row = transaction.query_opt(
                &format!(
                    "UPDATE cats
                        SET state=$6,node_id=$9,
                            current_action=NULL,current_action_started_at=NULL,
                            current_action_node_id=NULL,
                            last_error_code=$7,last_error_message=$8,
                            updated_at={DB_NOW_MS}
                      WHERE cat_id=$1
                        AND node_id=$2
                        AND current_action='run'
                        AND current_action_node_id=$3
                        AND state=$4
                        AND current_action_started_at=$5
                        AND destroyed_at IS NULL
                      RETURNING {CAT_COLUMNS}"
                ),
                &[
                    &settlement.cat_id,
                    &settlement.source_node_id,
                    &settlement.target_node_id,
                    &settlement.target_state.as_str(),
                    &settlement.expected_action_started_at,
                    &state,
                    &error_code,
                    &error_message,
                    &final_node_id,
                ],
            )?;
            let aggregate = match row {
                Some(row) => Some(cat_with_mounts(&mut transaction, row_to_cat(&row))?),
                None if source_is_draining => {
                    let current = transaction.query_opt(
                        &format!("SELECT {CAT_COLUMNS} FROM cats WHERE cat_id=$1 FOR SHARE"),
                        &[&settlement.cat_id],
                    )?;
                    match current.map(|row| row_to_cat(&row)) {
                        Some(current)
                            if current.state == Some(CatState::from_db(state))
                                && current.node_id.as_deref() == Some(final_node_id)
                                && current.current_action.is_none()
                                && current.last_error_code.as_deref() == error_code
                                && current.last_error_message.as_deref() == error_message =>
                        {
                            Some(cat_with_mounts(&mut transaction, current)?)
                        }
                        _ => None,
                    }
                }
                None => None,
            };
            transaction.commit()?;
            Ok(aggregate)
        })
    }

    pub fn transition_semantic_node_status(
        &self,
        node_id: &str,
        expected: &[NodeStatus],
        next: NodeStatus,
    ) -> Result<Option<NodeRecord>> {
        let expected: Vec<&str> = expected.iter().map(|status| status.as_str()).collect();
        self.with(|client| {
            client
                .query_opt(
                    &format!(
                        "UPDATE nodes SET status=$3, updated_at={DB_NOW_MS}
                          WHERE node_id=$1 AND status=ANY($2::TEXT[]) AND status<>'deleted'
                          RETURNING {NODE_COLUMNS}"
                    ),
                    &[&node_id, &expected, &next.as_str()],
                )
                .map(|row| row.map(|row| row_to_node(&row)))
        })
    }

    /// Heartbeat receipt time comes exclusively from PostgreSQL.  This query
    /// never writes Node identity or its explicit control endpoint.
    pub fn record_semantic_node_heartbeat(
        &self,
        heartbeat: NodeHeartbeat<'_>,
    ) -> Result<(NodeStatus, NodeHeartbeatRecord)> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let node_row = transaction.query_one(
                "SELECT status FROM nodes WHERE node_id=$1 FOR SHARE",
                &[&heartbeat.node_id],
            )?;
            let node_status: &str = node_row.get(0);
            let row = transaction.query_one(
                &format!(
                    "INSERT INTO node_heartbeats (
                        node_id,last_heartbeat_at,node_reported_at,reported_status,
                        total_cpu,cpu_utilized,total_memory,memory_utilized,
                        running_cat_count,suspended_cat_count,warm_cat_count
                     ) VALUES ($1,{DB_NOW_MS},$2,$3,$4,$5,$6,$7,$8,$9,$10)
                     ON CONFLICT (node_id) DO UPDATE SET
                        last_heartbeat_at={DB_NOW_MS},
                        node_reported_at=EXCLUDED.node_reported_at,
                        reported_status=EXCLUDED.reported_status,
                        total_cpu=EXCLUDED.total_cpu,
                        cpu_utilized=EXCLUDED.cpu_utilized,
                        total_memory=EXCLUDED.total_memory,
                        memory_utilized=EXCLUDED.memory_utilized,
                        running_cat_count=EXCLUDED.running_cat_count,
                        suspended_cat_count=EXCLUDED.suspended_cat_count,
                        warm_cat_count=EXCLUDED.warm_cat_count
                     RETURNING {HEARTBEAT_COLUMNS}"
                ),
                &[
                    &heartbeat.node_id,
                    &heartbeat.node_reported_at,
                    &heartbeat.reported_status.as_str(),
                    &heartbeat.total_cpu,
                    &heartbeat.cpu_utilized,
                    &heartbeat.total_memory,
                    &heartbeat.memory_utilized,
                    &heartbeat.running_cat_count,
                    &heartbeat.suspended_cat_count,
                    &heartbeat.warm_cat_count,
                ],
            )?;
            let node_status = NodeStatus::from_db(node_status);
            let heartbeat = row_to_heartbeat(&row);
            transaction.commit()?;
            Ok((node_status, heartbeat))
        })
    }

    pub fn create_semantic_persistent_disk(
        &self,
        request: NewPersistentDisk<'_>,
    ) -> Result<CreatePersistentDiskOutcome> {
        self.with(|client| {
            let inserted = client.query_opt(
                &format!(
                    "INSERT INTO persistent_disks (
                        disk_id,workspace_id,disk_slug,size_bytes,volume_id,
                        filesystem_uuid,disk_format,status,created_at,deleted_at
                     ) VALUES ($1,$2,$3,$4,$5,$6,$7,'provisioning',{DB_NOW_MS},NULL)
                     ON CONFLICT (workspace_id,disk_slug) WHERE deleted_at IS NULL
                     DO NOTHING
                     RETURNING {DISK_COLUMNS}"
                ),
                &[
                    &request.disk_id,
                    &request.workspace_id,
                    &request.disk_slug,
                    &request.size_bytes,
                    &request.volume_id,
                    &request.filesystem_uuid,
                    &request.disk_format,
                ],
            )?;
            if let Some(row) = inserted {
                return Ok(CreatePersistentDiskOutcome::Created(row_to_disk(&row)));
            }
            let row = client.query_one(
                &format!(
                    "SELECT {DISK_COLUMNS} FROM persistent_disks
                      WHERE workspace_id=$1 AND disk_slug=$2 AND deleted_at IS NULL"
                ),
                &[&request.workspace_id, &request.disk_slug],
            )?;
            Ok(CreatePersistentDiskOutcome::Existing(row_to_disk(&row)))
        })
    }

    /// Publishes `normal` only after the strict backend confirms the exact
    /// immutable Volume identity and capacity. Repeating the same completion
    /// after a response loss returns the stored row.
    pub fn complete_semantic_persistent_disk_create(
        &self,
        disk_id: &str,
        volume_id: &str,
        filesystem_uuid: &str,
        size_bytes: i64,
    ) -> Result<Option<PersistentDiskRecord>> {
        self.with(|client| {
            let row = client.query_opt(
                &format!(
                    "UPDATE persistent_disks
                        SET status='normal'
                      WHERE disk_id=$1 AND volume_id=$2 AND filesystem_uuid=$3
                        AND size_bytes=$4 AND status IN ('provisioning','normal')
                      RETURNING {DISK_COLUMNS}"
                ),
                &[&disk_id, &volume_id, &filesystem_uuid, &size_bytes],
            )?;
            Ok(row.map(|row| row_to_disk(&row)))
        })
    }

    pub fn find_current_semantic_disk(
        &self,
        workspace_id: &str,
        disk_slug: &str,
    ) -> Result<Option<PersistentDiskRecord>> {
        self.with(|client| {
            client
                .query_opt(
                    &format!(
                        "SELECT {DISK_COLUMNS} FROM persistent_disks
                          WHERE workspace_id=$1 AND disk_slug=$2 AND deleted_at IS NULL"
                    ),
                    &[&workspace_id, &disk_slug],
                )
                .map(|row| row.map(|row| row_to_disk(&row)))
        })
    }

    pub fn list_current_semantic_disk_ids(&self, workspace_id: &str) -> Result<Vec<String>> {
        self.with(|client| {
            client
                .query(
                    "SELECT disk_id FROM persistent_disks
                      WHERE workspace_id=$1 AND deleted_at IS NULL
                      ORDER BY disk_slug,disk_id",
                    &[&workspace_id],
                )
                .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
        })
    }

    pub fn find_semantic_disk_by_id(&self, disk_id: &str) -> Result<Option<PersistentDiskRecord>> {
        self.with(|client| {
            client
                .query_opt(
                    &format!("SELECT {DISK_COLUMNS} FROM persistent_disks WHERE disk_id=$1"),
                    &[&disk_id],
                )
                .map(|row| row.map(|row| row_to_disk(&row)))
        })
    }

    pub fn find_semantic_disk_binding(&self, disk_id: &str) -> Result<Option<DiskBindingWithCat>> {
        self.with(|client| {
            client
                .query_opt(
                    "SELECT b.binding_id,b.workspace_id,b.disk_id,b.cat_id,
                            b.mount_path,b.created_at,c.cat_slug
                           FROM disk_bindings b
                           JOIN cats c ON c.cat_id=b.cat_id
                          WHERE b.disk_id=$1",
                    &[&disk_id],
                )
                .map(|row| {
                    row.map(|row| DiskBindingWithCat {
                        binding: row_to_binding(&row),
                        cat_slug: row.get(6),
                    })
                })
        })
    }

    pub fn delete_semantic_persistent_disk(
        &self,
        disk_id: &str,
    ) -> Result<DeletePersistentDiskOutcome> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            let Some(row) = transaction.query_opt(
                &format!("SELECT {DISK_COLUMNS} FROM persistent_disks WHERE disk_id=$1 FOR UPDATE"),
                &[&disk_id],
            )?
            else {
                transaction.rollback()?;
                return Ok(DeletePersistentDiskOutcome::NotFound);
            };
            let disk = row_to_disk(&row);
            if disk.status == "deleted" {
                transaction.rollback()?;
                return Ok(DeletePersistentDiskOutcome::AlreadyDeleted(disk));
            }
            if transaction
                .query_opt(
                    "SELECT binding_id FROM disk_bindings WHERE disk_id=$1",
                    &[&disk_id],
                )?
                .is_some()
            {
                transaction.rollback()?;
                return Ok(DeletePersistentDiskOutcome::Attached);
            }
            let row = transaction.query_one(
                &format!(
                    "UPDATE persistent_disks
                        SET status='deleting'
                      WHERE disk_id=$1
                      RETURNING {DISK_COLUMNS}"
                ),
                &[&disk_id],
            )?;
            transaction.commit()?;
            Ok(DeletePersistentDiskOutcome::Deleting(row_to_disk(&row)))
        })
    }

    /// Marks the product row deleted only after the strict backend confirms
    /// that the exact immutable Volume is absent.
    pub fn complete_semantic_persistent_disk_delete(
        &self,
        disk_id: &str,
        volume_id: &str,
    ) -> Result<Option<PersistentDiskRecord>> {
        self.with(|client| {
            let row = client.query_opt(
                &format!(
                    "UPDATE persistent_disks
                        SET status='deleted', deleted_at=COALESCE(deleted_at,{DB_NOW_MS})
                      WHERE disk_id=$1 AND volume_id=$2
                        AND status IN ('deleting','deleted')
                      RETURNING {DISK_COLUMNS}"
                ),
                &[&disk_id, &volume_id],
            )?;
            Ok(row.map(|row| row_to_disk(&row)))
        })
    }

    pub fn attach_semantic_disk(
        &self,
        binding_id: &str,
        cat_id: &str,
        disk_id: &str,
        mount_path: &str,
    ) -> Result<AttachDiskOutcome> {
        self.with(|client| attach_disk_transaction(client, binding_id, cat_id, disk_id, mount_path))
    }

    pub fn detach_semantic_disk(&self, cat_id: &str, disk_id: &str) -> Result<DetachDiskOutcome> {
        self.with(|client| detach_disk_transaction(client, cat_id, disk_id))
    }

    pub fn list_semantic_disk_bindings(&self, cat_id: &str) -> Result<Vec<DiskBindingRecord>> {
        self.with(|client| {
            client
                .query(
                    &format!(
                        "SELECT {BINDING_COLUMNS} FROM disk_bindings
                          WHERE cat_id=$1 ORDER BY disk_id"
                    ),
                    &[&cat_id],
                )
                .map(|rows| rows.iter().map(row_to_binding).collect())
        })
    }
}

fn register_node_transaction(
    client: &mut postgres::Client,
    request: NodeRegistration<'_>,
) -> std::result::Result<RegisterNodeOutcome, postgres::Error> {
    let mut transaction = client.transaction()?;
    let existing = transaction.query_opt(
        &format!(
            "SELECT {NODE_COLUMNS} FROM nodes
              WHERE node_id=$1 OR (vendor=$2 AND instance_id=$3)
              ORDER BY (node_id=$1) DESC LIMIT 1 FOR UPDATE"
        ),
        &[&request.node_id, &request.vendor, &request.instance_id],
    )?;
    let Some(row) = existing else {
        let row = transaction.query_one(
            &format!(
                "INSERT INTO nodes (
                    node_id,node_name,control_endpoint,vendor,region,zone,instance_id,
                    machine_type,node_version,status,created_at,updated_at
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'running',{DB_NOW_MS},{DB_NOW_MS})
                 RETURNING {NODE_COLUMNS}"
            ),
            &[
                &request.node_id,
                &request.node_name,
                &request.control_endpoint,
                &request.vendor,
                &request.region,
                &request.zone,
                &request.instance_id,
                &request.machine_type,
                &request.node_version,
            ],
        )?;
        let record = row_to_node(&row);
        transaction.execute(
            &format!(
                "INSERT INTO node_heartbeats (
                    node_id,last_heartbeat_at,node_reported_at,reported_status,
                    total_cpu,cpu_utilized,total_memory,memory_utilized,
                    running_cat_count,suspended_cat_count,warm_cat_count
                 ) VALUES ($1,{DB_NOW_MS},NULL,'running',0,0,0,0,0,0,0)"
            ),
            &[&request.node_id],
        )?;
        transaction.commit()?;
        return Ok(RegisterNodeOutcome::Registered(record));
    };
    let record = row_to_node(&row);
    let same_identity = record.node_id == request.node_id
        && record.node_name == request.node_name
        && record.vendor == request.vendor
        && record.region == request.region
        && record.zone == request.zone
        && record.instance_id == request.instance_id
        && record.machine_type == request.machine_type;
    if !same_identity {
        transaction.rollback()?;
        return Ok(RegisterNodeOutcome::IdentityConflict(record));
    }
    if record.status == NodeStatus::Deleted {
        transaction.rollback()?;
        return Ok(RegisterNodeOutcome::Deleted(record));
    }
    // A failed Cat has no runnable physical state to recover.  Keeping its
    // placement on the reset Node lets the user issue the only useful next
    // action (`destroy`) after that Node has reopened.  Treating it as a
    // recovery blocker deadlocks registration because Failure deliberately
    // has no cross-Node Run transition.
    let has_recovery_blocking_cats: bool = transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM cats
                 WHERE node_id=$1 AND destroyed_at IS NULL
                   AND state IS DISTINCT FROM 'failure'
            )",
            &[&request.node_id],
        )?
        .get(0);
    if request.reset_completed && has_recovery_blocking_cats {
        let row = transaction.query_one(
            &format!(
                "UPDATE nodes
                    SET control_endpoint=$2,node_version=$3,
                        status='reset_required',updated_at={DB_NOW_MS}
                  WHERE node_id=$1
                  RETURNING {NODE_COLUMNS}"
            ),
            &[
                &request.node_id,
                &request.control_endpoint,
                &request.node_version,
            ],
        )?;
        let reset_required = row_to_node(&row);
        transaction.commit()?;
        return Ok(RegisterNodeOutcome::ResetRequired(reset_required));
    }
    if matches!(
        record.status,
        NodeStatus::Offline | NodeStatus::ResetRequired
    ) && !request.reset_completed
    {
        transaction.rollback()?;
        return Ok(RegisterNodeOutcome::ResetRequired(record));
    }
    let endpoint_changed = record.control_endpoint != request.control_endpoint;
    let version_changed = record.node_version != request.node_version;
    let reset_completed = request.reset_completed;
    if endpoint_changed || version_changed || reset_completed {
        let next_status = if reset_completed {
            NodeStatus::Running
        } else {
            record.status
        };
        let row = transaction.query_one(
            &format!(
                "UPDATE nodes
                    SET control_endpoint=$2,node_version=$3,status=$4,updated_at={DB_NOW_MS}
                  WHERE node_id=$1
                  RETURNING {NODE_COLUMNS}"
            ),
            &[
                &request.node_id,
                &request.control_endpoint,
                &request.node_version,
                &next_status.as_str(),
            ],
        )?;
        let updated = row_to_node(&row);
        transaction.commit()?;
        return Ok(RegisterNodeOutcome::RegistrationUpdated(updated));
    }
    transaction.rollback()?;
    Ok(RegisterNodeOutcome::AlreadyRegistered(record))
}

fn attach_disk_transaction(
    client: &mut postgres::Client,
    binding_id: &str,
    cat_id: &str,
    disk_id: &str,
    mount_path: &str,
) -> std::result::Result<AttachDiskOutcome, postgres::Error> {
    let mut transaction = client.transaction()?;
    let Some(disk) = transaction.query_opt(
        "SELECT workspace_id,status FROM persistent_disks WHERE disk_id=$1 FOR UPDATE",
        &[&disk_id],
    )?
    else {
        transaction.rollback()?;
        return Ok(AttachDiskOutcome::DiskNotFound);
    };
    let disk_workspace: &str = disk.get(0);
    let disk_status: &str = disk.get(1);
    if disk_status != "normal" {
        transaction.rollback()?;
        return Ok(AttachDiskOutcome::DiskDeleted);
    }
    if let Some(row) = transaction.query_opt(
        &format!("SELECT {BINDING_COLUMNS} FROM disk_bindings WHERE disk_id=$1"),
        &[&disk_id],
    )? {
        let binding = row_to_binding(&row);
        transaction.rollback()?;
        return Ok(
            if binding.cat_id == cat_id && binding.mount_path == mount_path {
                AttachDiskOutcome::AlreadyAttached(binding)
            } else if binding.cat_id == cat_id {
                AttachDiskOutcome::MountPathConflict(binding)
            } else {
                AttachDiskOutcome::DiskAlreadyAttached(binding)
            },
        );
    }
    let Some(cat) = transaction.query_opt(
        "SELECT workspace_id,state,current_action FROM cats WHERE cat_id=$1 FOR UPDATE",
        &[&cat_id],
    )?
    else {
        transaction.rollback()?;
        return Ok(AttachDiskOutcome::CatNotFound);
    };
    let cat_workspace: &str = cat.get(0);
    let cat_state: Option<&str> = cat.get(1);
    let current_action: Option<&str> = cat.get(2);
    if cat_workspace != disk_workspace {
        transaction.rollback()?;
        return Ok(AttachDiskOutcome::WorkspaceMismatch);
    }
    let mutable_cold = cat_state == Some("cold") && current_action.is_none();
    let initial_create = cat_state.is_none() && current_action == Some("create");
    if !mutable_cold && !initial_create {
        transaction.rollback()?;
        return Ok(AttachDiskOutcome::CatMustBeCold);
    }
    if let Some(row) = transaction.query_opt(
        &format!("SELECT {BINDING_COLUMNS} FROM disk_bindings WHERE cat_id=$1 AND mount_path=$2"),
        &[&cat_id, &mount_path],
    )? {
        let binding = row_to_binding(&row);
        transaction.rollback()?;
        return Ok(AttachDiskOutcome::MountPathConflict(binding));
    }
    let row = transaction.query_one(
        &format!(
            "INSERT INTO disk_bindings (
                binding_id,workspace_id,disk_id,cat_id,mount_path,created_at
             ) VALUES ($1,$2,$3,$4,$5,{DB_NOW_MS})
             RETURNING {BINDING_COLUMNS}"
        ),
        &[&binding_id, &cat_workspace, &disk_id, &cat_id, &mount_path],
    )?;
    let binding = row_to_binding(&row);
    transaction.commit()?;
    Ok(AttachDiskOutcome::Attached(binding))
}

fn detach_disk_transaction(
    client: &mut postgres::Client,
    cat_id: &str,
    disk_id: &str,
) -> std::result::Result<DetachDiskOutcome, postgres::Error> {
    let mut transaction = client.transaction()?;
    let Some(cat) = transaction.query_opt(
        "SELECT state,current_action FROM cats WHERE cat_id=$1 FOR UPDATE",
        &[&cat_id],
    )?
    else {
        transaction.rollback()?;
        return Ok(DetachDiskOutcome::CatNotFound);
    };
    if cat.get::<_, Option<&str>>(0) != Some("cold") || cat.get::<_, Option<&str>>(1).is_some() {
        transaction.rollback()?;
        return Ok(DetachDiskOutcome::CatMustBeCold);
    }
    let Some(row) = transaction.query_opt(
        &format!("SELECT {BINDING_COLUMNS} FROM disk_bindings WHERE disk_id=$1 FOR UPDATE"),
        &[&disk_id],
    )?
    else {
        transaction.rollback()?;
        return Ok(DetachDiskOutcome::AlreadyDetached);
    };
    let binding = row_to_binding(&row);
    if binding.cat_id != cat_id {
        transaction.rollback()?;
        return Ok(DetachDiskOutcome::DiskBindingConflict(binding));
    }
    transaction.execute("DELETE FROM disk_bindings WHERE disk_id=$1", &[&disk_id])?;
    transaction.commit()?;
    Ok(DetachDiskOutcome::Detached)
}

fn cat_with_mounts(
    client: &mut impl postgres::GenericClient,
    cat: CatRecord,
) -> std::result::Result<CatWithMounts, postgres::Error> {
    let rows = client.query(
        "SELECT b.disk_id,d.disk_slug,d.volume_id,d.filesystem_uuid,d.disk_format,b.mount_path
           FROM disk_bindings b
           JOIN persistent_disks d ON d.disk_id=b.disk_id
          WHERE b.cat_id=$1
          ORDER BY d.disk_slug,b.mount_path",
        &[&cat.cat_id],
    )?;
    Ok(CatWithMounts {
        cat,
        mounts: rows
            .into_iter()
            .map(|row| CatMountRecord {
                disk_id: row.get(0),
                disk_slug: row.get(1),
                volume_id: row.get(2),
                filesystem_uuid: row.get(3),
                disk_format: row.get(4),
                mount_path: row.get(5),
            })
            .collect(),
    })
}

/// Records that a foreground request is actively resuming the same action
/// occurrence. The action start time remains unchanged because it is the
/// settlement identity; only the scanner's DB-time activity clock advances.
fn refresh_current_action_activity(
    client: &mut impl postgres::GenericClient,
    mut aggregate: CatWithMounts,
) -> std::result::Result<CatWithMounts, postgres::Error> {
    // Each caller holds this Cat row FOR UPDATE and has already classified it
    // as the same active action occurrence, so Cat identity is sufficient for
    // this activity-only update.
    let row = client.query_one(
        &format!(
            "UPDATE cats
                SET updated_at={DB_NOW_MS}
              WHERE cat_id=$1
              RETURNING {CAT_COLUMNS}"
        ),
        &[&aggregate.cat.cat_id],
    )?;
    aggregate.cat = row_to_cat(&row);
    Ok(aggregate)
}

fn cat_create_configuration_matches(
    existing: &CatWithMounts,
    request: &AtomicCatCreate<'_>,
) -> bool {
    if existing.cat.cpu_count != request.cpu_count
        || existing.cat.memory_bytes != request.memory_bytes
        || existing.cat.boot_image != request.boot_image
    {
        return false;
    }
    let mut existing_mounts = existing
        .mounts
        .iter()
        .map(|mount| (mount.disk_id.as_str(), mount.mount_path.as_str()))
        .collect::<Vec<_>>();
    existing_mounts.sort_unstable();
    let mut requested_mounts = request
        .mounts
        .iter()
        .map(|mount| (mount.disk_id, mount.mount_path))
        .collect::<Vec<_>>();
    requested_mounts.sort_unstable();
    existing_mounts == requested_mounts
}

const ACTIVE_PLACEMENT_STRATEGY: LeastAllocatedPlacement = LeastAllocatedPlacement;

const fn action_target(action: CatAction) -> CatState {
    match action {
        CatAction::Create | CatAction::Run => CatState::Running,
        CatAction::Suspend => CatState::Suspended,
        CatAction::Warm => CatState::Warm,
        CatAction::Cold => CatState::Cold,
        CatAction::Destroy => CatState::Destroyed,
    }
}

const fn semantic_action_allowed(action: CatAction, state: Option<CatState>) -> bool {
    match (action, state) {
        (CatAction::Run, Some(CatState::Suspended | CatState::Warm | CatState::Cold)) => true,
        (CatAction::Suspend, Some(CatState::Running)) => true,
        (CatAction::Warm, Some(CatState::Running | CatState::Suspended)) => true,
        (CatAction::Cold, Some(CatState::Running | CatState::Suspended | CatState::Warm)) => true,
        (CatAction::Destroy, state) => !matches!(state, Some(CatState::Destroyed)),
        _ => false,
    }
}

const CAT_COLUMNS: &str = "cat_id,workspace_id,cat_slug,state,current_action,
    current_action_started_at,current_action_node_id,node_id,cpu_count,memory_bytes,
    boot_image,last_error_code,last_error_message,created_at,updated_at,destroyed_at";
const NODE_COLUMNS: &str = "node_id,node_name,control_endpoint,vendor,region,zone,instance_id,
    machine_type,node_version,status,created_at,updated_at";
const HEARTBEAT_COLUMNS: &str = "node_id,last_heartbeat_at,node_reported_at,reported_status,
    total_cpu,cpu_utilized,total_memory,memory_utilized,running_cat_count,
    suspended_cat_count,warm_cat_count";
const DISK_COLUMNS: &str = "disk_id,workspace_id,disk_slug,size_bytes,volume_id,filesystem_uuid,disk_format,status,created_at,deleted_at";
const BINDING_COLUMNS: &str = "binding_id,workspace_id,disk_id,cat_id,mount_path,created_at";
const INGRESS_TARGET_COLUMNS: &str = "cat_id,node_id,updated_at";

fn row_to_cat(row: &Row) -> CatRecord {
    CatRecord {
        cat_id: row.get(0),
        workspace_id: row.get(1),
        cat_slug: row.get(2),
        state: row.get::<_, Option<&str>>(3).map(CatState::from_db),
        current_action: row.get::<_, Option<&str>>(4).map(CatAction::from_db),
        current_action_started_at: row.get(5),
        current_action_node_id: row.get(6),
        node_id: row.get(7),
        cpu_count: row.get(8),
        memory_bytes: row.get(9),
        boot_image: row.get(10),
        last_error_code: row.get(11),
        last_error_message: row.get(12),
        created_at: row.get(13),
        updated_at: row.get(14),
        destroyed_at: row.get(15),
    }
}

fn row_to_node(row: &Row) -> NodeRecord {
    NodeRecord {
        node_id: row.get(0),
        node_name: row.get(1),
        control_endpoint: row.get(2),
        vendor: row.get(3),
        region: row.get(4),
        zone: row.get(5),
        instance_id: row.get(6),
        machine_type: row.get(7),
        node_version: row.get(8),
        status: NodeStatus::from_db(row.get(9)),
        created_at: row.get(10),
        updated_at: row.get(11),
    }
}

fn row_to_heartbeat(row: &Row) -> NodeHeartbeatRecord {
    NodeHeartbeatRecord {
        node_id: row.get(0),
        last_heartbeat_at: row.get(1),
        node_reported_at: row.get(2),
        reported_status: NodeStatus::from_db(row.get(3)),
        total_cpu: row.get(4),
        cpu_utilized: row.get(5),
        total_memory: row.get(6),
        memory_utilized: row.get(7),
        running_cat_count: row.get(8),
        suspended_cat_count: row.get(9),
        warm_cat_count: row.get(10),
    }
}

fn row_to_disk(row: &Row) -> PersistentDiskRecord {
    PersistentDiskRecord {
        disk_id: row.get(0),
        workspace_id: row.get(1),
        disk_slug: row.get(2),
        size_bytes: row.get(3),
        volume_id: row.get(4),
        filesystem_uuid: row.get(5),
        disk_format: row.get(6),
        status: row.get(7),
        created_at: row.get(8),
        deleted_at: row.get(9),
    }
}

fn row_to_binding(row: &Row) -> DiskBindingRecord {
    DiskBindingRecord {
        binding_id: row.get(0),
        workspace_id: row.get(1),
        disk_id: row.get(2),
        cat_id: row.get(3),
        mount_path: row.get(4),
        created_at: row.get(5),
    }
}

fn row_to_ingress_target(row: &Row) -> CatIngressTargetRecord {
    CatIngressTargetRecord {
        cat_id: row.get(0),
        node_id: row.get(1),
        updated_at: row.get(2),
    }
}

#[cfg(test)]
mod tests;

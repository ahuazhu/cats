//! PostgreSQL store for the synchronous, semantic Control/Node protocol.
//!
//! This module deliberately does not mirror writes into `cat_records`,
//! `disk_records`, runtime Operations, Node inventory or Agent sessions.  The
//! cutover is an empty-data protocol replacement; callers use only these
//! product rows.

use postgres::Row;

use super::{Result, Store};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentDiskRecord {
    pub disk_id: String,
    pub workspace_id: String,
    pub disk_slug: String,
    pub size_bytes: i64,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreatePersistentDiskOutcome {
    Created(PersistentDiskRecord),
    Existing(PersistentDiskRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletePersistentDiskOutcome {
    Deleted(PersistentDiskRecord),
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
                            current_action_started_at={DB_NOW_MS},
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

    /// Settle only the action and Node that still own the Cat row.  A late
    /// completion cannot clear another action acquired afterward.
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
                        SET state=$4,
                            node_id=$5,
                            current_action=NULL,
                            current_action_started_at=NULL,
                            current_action_node_id=NULL,
                            last_error_code=$6,
                            last_error_message=$7,
                            destroyed_at=CASE WHEN $4='destroyed' THEN {DB_NOW_MS} ELSE NULL END,
                            updated_at={DB_NOW_MS}
                      WHERE cat_id=$1
                        AND current_action=$2
                        AND current_action_node_id IS NOT DISTINCT FROM $3
                      RETURNING {CAT_COLUMNS}"
                ),
                &[
                    &cat_id,
                    &finish.expected_action.as_str(),
                    &finish.expected_node_id,
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
                        disk_id,workspace_id,disk_slug,size_bytes,status,created_at,deleted_at
                     ) VALUES ($1,$2,$3,$4,'normal',{DB_NOW_MS},NULL)
                     ON CONFLICT (workspace_id,disk_slug) WHERE deleted_at IS NULL
                     DO NOTHING
                     RETURNING {DISK_COLUMNS}"
                ),
                &[
                    &request.disk_id,
                    &request.workspace_id,
                    &request.disk_slug,
                    &request.size_bytes,
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
                        SET status='deleted', deleted_at={DB_NOW_MS}
                      WHERE disk_id=$1
                      RETURNING {DISK_COLUMNS}"
                ),
                &[&disk_id],
            )?;
            transaction.commit()?;
            Ok(DeletePersistentDiskOutcome::Deleted(row_to_disk(&row)))
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
    let reset_completed = request.reset_completed
        && matches!(
            record.status,
            NodeStatus::Offline | NodeStatus::ResetRequired
        );
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
    if disk_status == "deleted" {
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
    if cat_state != Some("cold") && !(cat_state.is_none() && current_action == Some("create")) {
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
        "SELECT state FROM cats WHERE cat_id=$1 FOR UPDATE",
        &[&cat_id],
    )?
    else {
        transaction.rollback()?;
        return Ok(DetachDiskOutcome::CatNotFound);
    };
    if cat.get::<_, Option<&str>>(0) != Some("cold") {
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

const CAT_COLUMNS: &str = "cat_id,workspace_id,cat_slug,state,current_action,
    current_action_started_at,current_action_node_id,node_id,cpu_count,memory_bytes,
    boot_image,last_error_code,last_error_message,created_at,updated_at,destroyed_at";
const NODE_COLUMNS: &str = "node_id,node_name,control_endpoint,vendor,region,zone,instance_id,
    machine_type,node_version,status,created_at,updated_at";
const HEARTBEAT_COLUMNS: &str = "node_id,last_heartbeat_at,node_reported_at,reported_status,
    total_cpu,cpu_utilized,total_memory,memory_utilized,running_cat_count,
    suspended_cat_count,warm_cat_count";
const DISK_COLUMNS: &str = "disk_id,workspace_id,disk_slug,size_bytes,status,created_at,deleted_at";
const BINDING_COLUMNS: &str = "binding_id,workspace_id,disk_id,cat_id,mount_path,created_at";

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
        status: row.get(4),
        created_at: row.get(5),
        deleted_at: row.get(6),
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

#[cfg(test)]
mod tests;

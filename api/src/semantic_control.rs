//! Shared contracts for the semantic Control Plane -> noded protocol.
//!
//! Idempotency in this protocol comes from the current resource identity,
//! complete parameters and requested target state. There is deliberately no
//! request ID, idempotency key or Operation resource in any DTO in this
//! module.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::runtime_reconciliation::{Id, RandomId128};

pub const NODED_AUTHORIZATION_HEADER: &str = "authorization";
pub const NODED_BEARER_SCHEME: &str = "Bearer";
pub const NODED_HEALTH_PATH: &str = "/v1/health";
pub const NODED_CATS_PATH: &str = "/v1/cats";
pub const CONTROL_NODE_DRAIN_PATH: &str = "/v1/admin/nodes/{node_id}/actions/drain";

const MAX_BOOT_IMAGE_BYTES: usize = 512;
const MAX_NODE_TEXT_BYTES: usize = 255;
const MAX_NODE_NAME_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_SERVICE_TOKEN_BYTES: usize = 4096;

macro_rules! validated_string_newtype {
    ($name:ident, $validator:ident, $message:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Option<Self> {
                let value = value.into();
                $validator(&value).then_some(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).ok_or_else(|| serde::de::Error::custom($message))
            }
        }
    };
}

fn valid_slug(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_node_name(value: &str) -> bool {
    (1..=MAX_NODE_NAME_BYTES).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && value.trim() == value
}

fn valid_mount_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || !value.starts_with('/')
        || value.bytes().any(|byte| byte <= 0x1f || byte == 0x7f)
    {
        return false;
    }
    if value == "/" {
        return false;
    }
    !value.ends_with('/')
        && value[1..]
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
        && !matches!(value, "/boot" | "/proc" | "/sys" | "/dev" | "/run")
}

fn valid_control_endpoint(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_ENDPOINT_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return false;
    }
    let authority = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"));
    authority.is_some_and(|authority| {
        !authority.is_empty()
            && !authority.contains(['/', '?', '#', '@'])
            && authority != ":"
            && !authority.starts_with(':')
    })
}

validated_string_newtype!(
    ResourceSlug,
    valid_slug,
    "slug must be 1..=63 lowercase ASCII letters, digits or interior hyphens"
);
validated_string_newtype!(
    NodeName,
    valid_node_name,
    "node_name must be 1..=128 printable ASCII bytes without outer whitespace"
);
validated_string_newtype!(
    PersistentMountPath,
    valid_mount_path,
    "mount_path must be an allowed normalized absolute Guest path"
);
validated_string_newtype!(
    NodedControlEndpoint,
    valid_control_endpoint,
    "control_endpoint must be an absolute http/https origin URL"
);

/// A shared Control -> noded service credential.
///
/// The token never enters a JSON body and its `Debug` implementation is
/// intentionally redacted. HTTP adapters put [`Self::authorization_value`]
/// in [`NODED_AUTHORIZATION_HEADER`].
#[derive(Clone, PartialEq, Eq)]
pub struct NodedServiceToken(String);

impl NodedServiceToken {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        ((32..=MAX_SERVICE_TOKEN_BYTES).contains(&value.len())
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            }))
        .then_some(Self(value))
    }

    pub fn parse_authorization(value: &str) -> Option<Self> {
        let token = value.strip_prefix("Bearer ")?;
        Self::new(token)
    }

    pub fn authorization_value(&self) -> String {
        format!("{NODED_BEARER_SCHEME} {}", self.0)
    }
}

impl fmt::Debug for NodedServiceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NodedServiceToken([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatState {
    Running,
    Suspended,
    Warm,
    Cold,
    Failure,
    Destroyed,
}

impl CatState {
    pub const fn retains_node(self) -> bool {
        matches!(self, Self::Running | Self::Suspended | Self::Warm)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatAction {
    Create,
    Run,
    Suspend,
    Warm,
    Cold,
    Destroy,
}

impl CatAction {
    pub const fn target_state(self) -> CatState {
        match self {
            Self::Create | Self::Run => CatState::Running,
            Self::Suspend => CatState::Suspended,
            Self::Warm => CatState::Warm,
            Self::Cold => CatState::Cold,
            Self::Destroy => CatState::Destroyed,
        }
    }

    pub const fn allowed_from(self, state: Option<CatState>) -> bool {
        match (self, state) {
            (Self::Create, None) => true,
            (Self::Run, Some(CatState::Suspended | CatState::Warm | CatState::Cold)) => true,
            (Self::Suspend, Some(CatState::Running)) => true,
            (Self::Warm, Some(CatState::Running | CatState::Suspended)) => true,
            (Self::Cold, Some(CatState::Running | CatState::Suspended | CatState::Warm)) => true,
            (Self::Destroy, Some(state)) => !matches!(state, CatState::Destroyed),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskStatus {
    Normal,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskSnapshotStatus {
    Normal,
    Deleted,
}

/// Filesystem authority fixed when a PersistentDisk identity is allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistentDiskFormat {
    Ext4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Running,
    Draining,
    Offline,
    ResetRequired,
    Deleted,
}

impl NodeStatus {
    pub const fn accepts_placement(self) -> bool {
        matches!(self, Self::Running)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticStatus {
    Ok,
    AlreadyDone,
    AlreadyExists,
    Busy,
    Conflict,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSuccessCode {
    CatCreated,
    CatRunning,
    CatSuspended,
    CatWarm,
    CatCold,
    CatDestroyed,
    DiskCreated,
    DiskAttached,
    DiskDetached,
    DiskDeleted,
    SnapshotCreated,
    SnapshotDestroyed,
    SnapshotRestored,
    NodeRegistered,
    NodeReset,
    AlreadyExists,
    AlreadyRunning,
    AlreadySuspended,
    AlreadyWarm,
    AlreadyCold,
    AlreadyDestroyed,
    AlreadyAttached,
    AlreadyDetached,
    AlreadyDeleted,
    AlreadyRestored,
    AlreadyRegistered,
    ResetRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticErrorCode {
    Unauthorized,
    InvalidRequest,
    CatNotFound,
    CatConfigurationConflict,
    CatDestroyed,
    InvalidState,
    Busy,
    NodeUnavailable,
    NodeResetRequired,
    NodeIdentityConflict,
    DiskNotFound,
    SnapshotNotFound,
    DiskSizeConflict,
    DiskDeleted,
    DiskInUse,
    DiskAlreadyAttached,
    DiskBindingConflict,
    SnapshotConfigurationConflict,
    SnapshotInUse,
    DiskOwned,
    HeadConflict,
    SnapshotCorrupt,
    StorageUnavailable,
    MountPathConflict,
    CatMustBeCold,
    GuestStartFailed,
    GuestSuspendFailed,
    GuestWarmFailed,
    GuestColdFailed,
    DestroyFailed,
    ActionCancelled,
    Timeout,
    InternalError,
}

impl SemanticErrorCode {
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::InvalidRequest => 400,
            Self::CatNotFound | Self::DiskNotFound | Self::SnapshotNotFound => 404,
            Self::CatConfigurationConflict
            | Self::Busy
            | Self::NodeIdentityConflict
            | Self::DiskSizeConflict
            | Self::DiskInUse
            | Self::DiskAlreadyAttached
            | Self::DiskBindingConflict
            | Self::MountPathConflict
            | Self::SnapshotConfigurationConflict
            | Self::SnapshotInUse
            | Self::DiskOwned
            | Self::HeadConflict
            | Self::ActionCancelled => 409,
            Self::CatDestroyed
            | Self::InvalidState
            | Self::NodeResetRequired
            | Self::DiskDeleted
            | Self::CatMustBeCold => 422,
            Self::NodeUnavailable | Self::StorageUnavailable => 503,
            Self::Timeout => 504,
            Self::GuestStartFailed
            | Self::GuestSuspendFailed
            | Self::GuestWarmFailed
            | Self::GuestColdFailed
            | Self::DestroyFailed
            | Self::SnapshotCorrupt
            | Self::InternalError => 500,
        }
    }
}

/// Error body for the semantic protocol. It intentionally has no request ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticErrorBody {
    pub code: SemanticErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatMountRequest {
    pub disk_slug: ResourceSlug,
    pub mount_path: PersistentMountPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCatRequest {
    pub cat_slug: ResourceSlug,
    pub cpu: u32,
    pub memory_bytes: u64,
    #[serde(default)]
    pub mounts: Vec<CatMountRequest>,
}

impl CreateCatRequest {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        if self.cpu == 0 {
            return Err(SemanticValidationError::Cpu);
        }
        if self.memory_bytes == 0 || self.memory_bytes > i64::MAX as u64 {
            return Err(SemanticValidationError::Memory);
        }
        validate_mounts_by_slug(&self.mounts)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatActionRequest {
    pub action: CatAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDiskRequest {
    pub disk_slug: ResourceSlug,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDiskSnapshotRequest {
    pub snapshot_slug: ResourceSlug,
    pub disk_slug: ResourceSlug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreDiskSnapshotRequest {
    pub expected_generation: u64,
}

impl RestoreDiskSnapshotRequest {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        if self.expected_generation > i64::MAX as u64 {
            return Err(SemanticValidationError::Generation);
        }
        Ok(())
    }
}

impl CreateDiskRequest {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        if self.size_bytes == 0 || self.size_bytes > i64::MAX as u64 {
            return Err(SemanticValidationError::DiskSize);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachDiskRequest {
    pub cat_slug: ResourceSlug,
    pub mount_path: PersistentMountPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachDiskRequest {
    pub cat_slug: ResourceSlug,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskBindingView {
    pub cat_id: Id,
    pub cat_slug: ResourceSlug,
    pub mount_path: PersistentMountPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatMountView {
    pub disk_id: Id,
    pub disk_slug: ResourceSlug,
    pub mount_path: PersistentMountPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatView {
    pub cat_id: Id,
    pub workspace_id: Id,
    pub cat_slug: ResourceSlug,
    pub state: Option<CatState>,
    pub current_action: Option<CatAction>,
    pub node_id: Option<Id>,
    /// Human-readable placement name. Internal calls still use `node_id`.
    pub node_name: Option<NodeName>,
    pub cpu: u32,
    pub memory_bytes: u64,
    pub boot_image: String,
    pub mounts: Vec<CatMountView>,
    pub last_error: Option<SemanticErrorBody>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub destroyed_at_unix_ms: Option<u64>,
    /// When the in-flight action started, present exactly while
    /// `current_action` is.
    ///
    /// This is the action's own clock, not `updated_at`: the retry rotations
    /// and the foreground activity refresh advance `updated_at` while the same
    /// action occurrence continues, deliberately leaving the start alone
    /// because it is the settlement identity. A reader that wants "how long has
    /// this been stuck" must read this field.
    pub current_action_started_at_unix_ms: Option<u64>,
    /// Newest time this Cat was recorded settled in Running, or `None` if it
    /// has never run.
    ///
    /// For a Cat running now this is when the current run began. For any other
    /// state it is when it stopped running, and it survives later transitions,
    /// so a Cat that went running -> suspended -> warm still reports when it
    /// last actually ran.
    pub last_running_at_unix_ms: Option<u64>,
}

impl CatView {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.cat_id, "cat_")?;
        validate_prefixed_id(&self.workspace_id, "ws_")?;
        if self.node_id.is_some() != self.node_name.is_some() {
            return Err(SemanticValidationError::Placement);
        }
        if let Some(node_id) = &self.node_id {
            validate_prefixed_id(node_id, "node_")?;
        }
        if self.cpu == 0 || self.memory_bytes == 0 {
            return Err(SemanticValidationError::Resources);
        }
        if self.updated_at_unix_ms < self.created_at_unix_ms {
            return Err(SemanticValidationError::Timestamp);
        }
        // Only the ordering of these two observations is checked, never their
        // presence.
        //
        // `cats_current_action_shape_check` and `cats_running_records_its_run_check`
        // already make a Control that has this schema unable to omit either one,
        // so a presence rule here would guard nothing on a correct server. What
        // it would do is turn a Control that predates the fields into a total
        // read failure: absent optionals deserialize to `None`, and a client
        // built from a newer commit than the deployed Control would fail every
        // Cat that is Running or mid-action instead of degrading to the reading
        // it can still make. Absence is a fact about the peer, not a corrupt
        // Cat; a value before `created_at` is corruption.
        if self
            .current_action_started_at_unix_ms
            .is_some_and(|started| started < self.created_at_unix_ms)
            || self
                .last_running_at_unix_ms
                .is_some_and(|ran| ran < self.created_at_unix_ms)
        {
            return Err(SemanticValidationError::Timestamp);
        }
        match self.state {
            None if self.current_action == Some(CatAction::Create) => {}
            None => return Err(SemanticValidationError::CatShape),
            Some(CatState::Destroyed) => {
                if self.destroyed_at_unix_ms.is_none()
                    || self.node_id.is_some()
                    || self.current_action.is_some()
                {
                    return Err(SemanticValidationError::CatShape);
                }
            }
            Some(state) => {
                if self.destroyed_at_unix_ms.is_some()
                    || (state.retains_node() && self.node_id.is_none())
                {
                    return Err(SemanticValidationError::CatShape);
                }
                if state == CatState::Cold && self.node_id.is_some() {
                    return Err(SemanticValidationError::CatShape);
                }
            }
        }
        validate_mount_views(&self.mounts)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskView {
    pub disk_id: Id,
    pub workspace_id: Id,
    pub disk_slug: ResourceSlug,
    pub size_bytes: u64,
    /// Current remotely authoritative disk generation. Snapshot restore uses
    /// a fresh read of this value as its optimistic occurrence precondition.
    /// It is absent before initialization and after deletion.
    #[serde(default)]
    pub head_generation: Option<u64>,
    pub status: DiskStatus,
    pub binding: Option<DiskBindingView>,
    pub created_at_unix_ms: u64,
    pub deleted_at_unix_ms: Option<u64>,
}

impl DiskView {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.disk_id, "disk_")?;
        validate_prefixed_id(&self.workspace_id, "ws_")?;
        if self.size_bytes == 0 {
            return Err(SemanticValidationError::DiskSize);
        }
        if self
            .head_generation
            .is_some_and(|generation| generation > i64::MAX as u64)
        {
            return Err(SemanticValidationError::Generation);
        }
        match self.status {
            DiskStatus::Normal if self.deleted_at_unix_ms.is_none() => {}
            DiskStatus::Deleted
                if self.deleted_at_unix_ms.is_some()
                    && self.binding.is_none()
                    && self.head_generation.is_none() => {}
            _ => return Err(SemanticValidationError::DiskShape),
        }
        if let Some(binding) = &self.binding {
            validate_prefixed_id(&binding.cat_id, "cat_")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskSnapshotView {
    pub snapshot_id: Id,
    pub workspace_id: Id,
    pub snapshot_slug: ResourceSlug,
    pub disk_id: Id,
    pub disk_slug: ResourceSlug,
    pub size_bytes: u64,
    pub status: DiskSnapshotStatus,
    pub captured_generation: u64,
    pub created_at_unix_ms: u64,
    pub deleted_at_unix_ms: Option<u64>,
}

impl DiskSnapshotView {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.snapshot_id, "snapshot_")?;
        validate_prefixed_id(&self.workspace_id, "ws_")?;
        validate_prefixed_id(&self.disk_id, "disk_")?;
        if self.size_bytes == 0
            || self.size_bytes > i64::MAX as u64
            || self.captured_generation > i64::MAX as u64
        {
            return Err(SemanticValidationError::DiskSize);
        }
        match self.status {
            DiskSnapshotStatus::Normal if self.deleted_at_unix_ms.is_none() => Ok(()),
            DiskSnapshotStatus::Deleted
                if self
                    .deleted_at_unix_ms
                    .is_some_and(|deleted| deleted >= self.created_at_unix_ms) =>
            {
                Ok(())
            }
            _ => Err(SemanticValidationError::SnapshotShape),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeView {
    pub node_id: Id,
    pub node_name: NodeName,
    /// Absolute base URL used by Control to call this noded instance.
    pub control_endpoint: NodedControlEndpoint,
    pub vendor: String,
    pub region: String,
    pub zone: String,
    pub instance_id: String,
    pub machine_type: String,
    pub node_version: String,
    pub status: NodeStatus,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

impl NodeView {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.node_id, "node_")?;
        for value in [
            &self.vendor,
            &self.region,
            &self.zone,
            &self.instance_id,
            &self.machine_type,
            &self.node_version,
        ] {
            validate_node_text(value)?;
        }
        if self.updated_at_unix_ms < self.created_at_unix_ms {
            return Err(SemanticValidationError::Timestamp);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatResponse {
    pub status: SemanticStatus,
    pub code: SemanticSuccessCode,
    pub cat: CatView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskResponse {
    pub status: SemanticStatus,
    pub code: SemanticSuccessCode,
    pub disk: DiskView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskSnapshotResponse {
    pub status: SemanticStatus,
    pub code: SemanticSuccessCode,
    pub snapshot: DiskSnapshotView,
    pub disk_head_generation: u64,
}

impl DiskSnapshotResponse {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        self.snapshot.validate()?;
        if self.disk_head_generation > i64::MAX as u64 {
            return Err(SemanticValidationError::Generation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeResponse {
    pub status: SemanticStatus,
    pub code: SemanticSuccessCode,
    pub node: NodeView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeDrainStatus {
    Drained,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeDrainCatResult {
    Migrated {
        cat_id: Id,
        target_node_id: Id,
        state: CatState,
    },
    Stale {
        cat_id: Id,
    },
    Blocked {
        cat_id: Id,
        code: String,
        message: String,
    },
}

impl NodeDrainCatResult {
    fn cat_id(&self) -> &Id {
        match self {
            Self::Migrated { cat_id, .. }
            | Self::Stale { cat_id }
            | Self::Blocked { cat_id, .. } => cat_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDrainResponse {
    pub status: NodeDrainStatus,
    pub source_node_id: Id,
    pub cats: Vec<NodeDrainCatResult>,
}

impl NodeDrainResponse {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.source_node_id, "node_")?;
        let mut cat_ids = HashSet::with_capacity(self.cats.len());
        let mut blocked = false;
        for result in &self.cats {
            validate_prefixed_id(result.cat_id(), "cat_")?;
            if !cat_ids.insert(result.cat_id().as_str()) {
                return Err(SemanticValidationError::DuplicateCat);
            }
            match result {
                NodeDrainCatResult::Migrated {
                    target_node_id,
                    state,
                    ..
                } => {
                    validate_prefixed_id(target_node_id, "node_")?;
                    if !matches!(
                        state,
                        CatState::Running | CatState::Suspended | CatState::Warm
                    ) {
                        return Err(SemanticValidationError::ResponseShape);
                    }
                }
                NodeDrainCatResult::Blocked { code, message, .. } => {
                    blocked = true;
                    if code.is_empty()
                        || code.len() > 128
                        || message.is_empty()
                        || message.len() > 4096
                    {
                        return Err(SemanticValidationError::ResponseShape);
                    }
                }
                NodeDrainCatResult::Stale { .. } => {}
            }
        }
        if (self.status == NodeDrainStatus::Blocked) != blocked {
            return Err(SemanticValidationError::ResponseShape);
        }
        Ok(())
    }
}

/// The current Node selected for new traffic to one Cat. Absence of this DTO
/// from a resolve result means that traffic has been withdrawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatIngressTarget {
    pub cat_id: Id,
    pub node_id: Id,
}

impl CatIngressTarget {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.cat_id, "cat_")?;
        validate_prefixed_id(&self.node_id, "node_")
    }
}

/// Complete, immutable Cat configuration sent to noded on create and run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodedCatConfig {
    pub workspace_id: Id,
    pub cpu: u32,
    pub memory_bytes: u64,
    pub boot_image: String,
    #[serde(default)]
    pub mounts: Vec<NodedDiskMount>,
}

impl NodedCatConfig {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.workspace_id, "ws_")?;
        if self.cpu == 0 {
            return Err(SemanticValidationError::Cpu);
        }
        if self.memory_bytes == 0 || self.memory_bytes > i64::MAX as u64 {
            return Err(SemanticValidationError::Memory);
        }
        if self.boot_image.is_empty()
            || self.boot_image.len() > MAX_BOOT_IMAGE_BYTES
            || self.boot_image.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(SemanticValidationError::BootImage);
        }
        validate_noded_mounts(&self.mounts)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodedDiskMount {
    pub disk_id: Id,
    pub volume_id: Id,
    pub filesystem_uuid: RandomId128,
    pub format: PersistentDiskFormat,
    pub mount_path: PersistentMountPath,
}

/// Body for `PUT /v1/cats/{cat_id}`. The path is the only Cat identity, so
/// the body is exactly the complete configuration and cannot disagree with
/// it.
pub type NodedCreateCatRequest = NodedCatConfig;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodedCatActionRequest {
    /// Run carries the complete current configuration; all other actions omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<NodedCatConfig>,
}

impl NodedCatActionRequest {
    /// Validates this body against the action selected by the HTTP path. The
    /// action is intentionally not repeated in JSON.
    pub fn validate_for(&self, action: CatAction) -> Result<(), SemanticValidationError> {
        match (action, &self.config) {
            (CatAction::Run, Some(config)) => config.validate(),
            (CatAction::Run, None) => Err(SemanticValidationError::ActionConfig),
            (CatAction::Create, _) => Err(SemanticValidationError::ActionConfig),
            (_, None) => Ok(()),
            (_, Some(_)) => Err(SemanticValidationError::ActionConfig),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodedCatView {
    pub cat_id: Id,
    /// `None` exists only while the first create is executing.
    pub state: Option<CatState>,
    pub active_action: Option<CatAction>,
    pub config: NodedCatConfig,
}

impl NodedCatView {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.cat_id, "cat_")?;
        match (self.state, self.active_action) {
            (None, Some(CatAction::Create)) => {}
            (None, _) | (Some(_), Some(CatAction::Create)) => {
                return Err(SemanticValidationError::CatShape)
            }
            (Some(_), _) => {}
        }
        self.config.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodedCatListResponse {
    pub cats: Vec<NodedCatView>,
}

impl NodedCatListResponse {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        let mut cat_ids = HashSet::with_capacity(self.cats.len());
        for cat in &self.cats {
            cat.validate()?;
            if !cat_ids.insert(cat.cat_id.as_str()) {
                return Err(SemanticValidationError::DuplicateCat);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodedResultStatus {
    Ok,
    AlreadyDone,
    Busy,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodedCatResponse {
    pub status: NodedResultStatus,
    pub cat_id: Id,
    pub state: CatState,
    pub error: Option<SemanticErrorBody>,
}

impl NodedCatResponse {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.cat_id, "cat_")?;
        if (self.status == NodedResultStatus::Failed) != self.error.is_some() {
            return Err(SemanticValidationError::ResponseShape);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRegistrationRequest {
    pub node_id: Id,
    pub node_name: NodeName,
    pub control_endpoint: NodedControlEndpoint,
    pub vendor: String,
    pub region: String,
    pub zone: String,
    pub instance_id: String,
    pub machine_type: String,
    pub node_version: String,
    #[serde(default)]
    pub reset_completed: bool,
}

impl NodeRegistrationRequest {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.node_id, "node_")?;
        for value in [
            &self.vendor,
            &self.region,
            &self.zone,
            &self.instance_id,
            &self.machine_type,
            &self.node_version,
        ] {
            validate_node_text(value)?;
        }
        Ok(())
    }

    /// Immutable identity fields which must remain equal when the same
    /// `node_id` registers again. `control_endpoint` and `node_version` are
    /// mutable registration metadata and are deliberately excluded.
    pub fn same_identity_as(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.node_name == other.node_name
            && self.vendor == other.vendor
            && self.region == other.region
            && self.zone == other.zone
            && self.instance_id == other.instance_id
            && self.machine_type == other.machine_type
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRegistrationStatus {
    Registered,
    AlreadyRegistered,
    ResetRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRegistrationResponse {
    pub status: NodeRegistrationStatus,
    pub node: NodeView,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHeartbeatRequest {
    pub node_id: Id,
    pub node_reported_at_unix_ms: u64,
    pub reported_status: NodeStatus,
    pub total_cpu: u32,
    pub cpu_utilized: f64,
    pub total_memory: u64,
    pub memory_utilized: u64,
    pub running_cat_count: u32,
    pub suspended_cat_count: u32,
    pub warm_cat_count: u32,
}

impl NodeHeartbeatRequest {
    pub fn validate(&self) -> Result<(), SemanticValidationError> {
        validate_prefixed_id(&self.node_id, "node_")?;
        if self.total_cpu == 0
            || !self.cpu_utilized.is_finite()
            || self.cpu_utilized < 0.0
            || self.cpu_utilized > f64::from(self.total_cpu)
            || self.total_memory == 0
            || self.memory_utilized > self.total_memory
        {
            return Err(SemanticValidationError::HeartbeatResources);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeHeartbeatStatus {
    Accepted,
    ResetRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHeartbeatResponse {
    pub status: NodeHeartbeatStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHeartbeatView {
    pub node_id: Id,
    /// Control database receive time; this is the liveness clock.
    pub last_heartbeat_at_unix_ms: u64,
    /// Node-provided diagnostic time; it never decides liveness.
    pub node_reported_at_unix_ms: u64,
    pub reported_status: NodeStatus,
    pub total_cpu: u32,
    pub cpu_utilized: f64,
    pub total_memory: u64,
    pub memory_utilized: u64,
    pub running_cat_count: u32,
    pub suspended_cat_count: u32,
    pub warm_cat_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SemanticValidationError {
    #[error("resource ID has the wrong prefix")]
    IdPrefix,
    #[error("cpu must be positive")]
    Cpu,
    #[error("memory_bytes must be positive and fit PostgreSQL BIGINT")]
    Memory,
    #[error("boot_image must be non-empty bounded text")]
    BootImage,
    #[error("size_bytes must be positive and fit PostgreSQL BIGINT")]
    DiskSize,
    #[error("generation must fit PostgreSQL BIGINT")]
    Generation,
    #[error("a disk occurs more than once in the mount set")]
    DuplicateDisk,
    #[error("a mount_path occurs more than once in the mount set")]
    DuplicateMountPath,
    #[error("a Cat occurs more than once in a complete noded list")]
    DuplicateCat,
    #[error("Cat placement must carry node_id and node_name together")]
    Placement,
    #[error("resource cpu or memory is invalid")]
    Resources,
    #[error("resource timestamps are invalid")]
    Timestamp,
    #[error("Cat projection fields do not match its state")]
    CatShape,
    #[error("Disk projection fields do not match its status")]
    DiskShape,
    #[error("DiskSnapshot projection fields do not match its status")]
    SnapshotShape,
    #[error("Node identity text is empty, too long or contains control bytes")]
    NodeText,
    #[error("noded action config does not match the action")]
    ActionConfig,
    #[error("noded response error does not match its status")]
    ResponseShape,
    #[error("heartbeat resource values are invalid")]
    HeartbeatResources,
}

pub fn noded_cat_path(cat_id: &Id) -> Result<String, SemanticValidationError> {
    validate_prefixed_id(cat_id, "cat_")?;
    Ok(format!("{NODED_CATS_PATH}/{cat_id}"))
}

pub fn noded_cat_action_path(
    cat_id: &Id,
    action: CatAction,
) -> Result<String, SemanticValidationError> {
    validate_prefixed_id(cat_id, "cat_")?;
    let action = match action {
        CatAction::Run => "run",
        CatAction::Suspend => "suspend",
        CatAction::Warm => "warm",
        CatAction::Cold => "cold",
        CatAction::Create | CatAction::Destroy => {
            return Err(SemanticValidationError::ActionConfig)
        }
    };
    Ok(format!("{NODED_CATS_PATH}/{cat_id}/actions/{action}"))
}

fn validate_prefixed_id(id: &Id, prefix: &str) -> Result<(), SemanticValidationError> {
    if id.as_str().starts_with(prefix) && id.as_str().len() > prefix.len() {
        Ok(())
    } else {
        Err(SemanticValidationError::IdPrefix)
    }
}

fn validate_node_text(value: &str) -> Result<(), SemanticValidationError> {
    if value.is_empty()
        || value.len() > MAX_NODE_TEXT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(SemanticValidationError::NodeText)
    } else {
        Ok(())
    }
}

fn validate_mounts_by_slug(mounts: &[CatMountRequest]) -> Result<(), SemanticValidationError> {
    let mut disks = HashSet::with_capacity(mounts.len());
    let mut paths = HashSet::with_capacity(mounts.len());
    for mount in mounts {
        if !disks.insert(mount.disk_slug.as_str()) {
            return Err(SemanticValidationError::DuplicateDisk);
        }
        if !paths.insert(mount.mount_path.as_str()) {
            return Err(SemanticValidationError::DuplicateMountPath);
        }
    }
    Ok(())
}

fn validate_noded_mounts(mounts: &[NodedDiskMount]) -> Result<(), SemanticValidationError> {
    let mut disks = HashSet::with_capacity(mounts.len());
    let mut volumes = HashSet::with_capacity(mounts.len());
    let mut filesystem_uuids = HashSet::with_capacity(mounts.len());
    let mut paths = HashSet::with_capacity(mounts.len());
    for mount in mounts {
        validate_prefixed_id(&mount.disk_id, "disk_")?;
        validate_prefixed_id(&mount.volume_id, "vol_")?;
        if !disks.insert(mount.disk_id.as_str()) {
            return Err(SemanticValidationError::DuplicateDisk);
        }
        if !volumes.insert(mount.volume_id.as_str())
            || !filesystem_uuids.insert(mount.filesystem_uuid.as_str())
        {
            return Err(SemanticValidationError::DuplicateDisk);
        }
        if !paths.insert(mount.mount_path.as_str()) {
            return Err(SemanticValidationError::DuplicateMountPath);
        }
    }
    Ok(())
}

fn validate_mount_views(mounts: &[CatMountView]) -> Result<(), SemanticValidationError> {
    let mut disks = HashSet::with_capacity(mounts.len());
    let mut paths = HashSet::with_capacity(mounts.len());
    for mount in mounts {
        validate_prefixed_id(&mount.disk_id, "disk_")?;
        if !disks.insert(mount.disk_id.as_str()) {
            return Err(SemanticValidationError::DuplicateDisk);
        }
        if !paths.insert(mount.mount_path.as_str()) {
            return Err(SemanticValidationError::DuplicateMountPath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    #[test]
    fn slug_is_strict_and_reusable_identity_is_not_encoded_in_it() {
        for valid in ["a", "web-01", "data-disk"] {
            assert_eq!(ResourceSlug::new(valid).unwrap().as_str(), valid);
        }
        for invalid in ["", "DATA_DISK", "-web", "web-", "web_name", &"a".repeat(64)] {
            assert!(ResourceSlug::new(invalid).is_none(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn create_cat_wire_has_semantic_identity_and_no_operation_tokens() {
        let body = br#"{
            "cat_slug":"web",
            "cpu":2,
            "memory_bytes":4294967296,
            "mounts":[{"disk_slug":"data-disk","mount_path":"/data"}]
        }"#;
        let request: CreateCatRequest = serde_json::from_slice(body).unwrap();
        request.validate().unwrap();
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("request_id"));
        assert!(!encoded.contains("operation"));
        assert!(serde_json::from_slice::<CreateCatRequest>(
            br#"{"cat_slug":"web","cpu":2,"memory_bytes":4,"request_id":"req_1"}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<CreateCatRequest>(
            br#"{"cat_slug":"web","cpu":2,"memory_bytes":4,"boot_image":"image"}"#
        )
        .is_err());
    }

    #[test]
    fn create_cat_rejects_duplicate_disks_and_mount_paths() {
        let duplicate_disk: CreateCatRequest = serde_json::from_slice(
            br#"{"cat_slug":"web","cpu":1,"memory_bytes":1,"mounts":[{"disk_slug":"data","mount_path":"/data"},{"disk_slug":"data","mount_path":"/other"}]}"#,
        )
        .unwrap();
        assert_eq!(
            duplicate_disk.validate(),
            Err(SemanticValidationError::DuplicateDisk)
        );

        let duplicate_path: CreateCatRequest = serde_json::from_slice(
            br#"{"cat_slug":"web","cpu":1,"memory_bytes":1,"mounts":[{"disk_slug":"data","mount_path":"/data"},{"disk_slug":"logs","mount_path":"/data"}]}"#,
        )
        .unwrap();
        assert_eq!(
            duplicate_path.validate(),
            Err(SemanticValidationError::DuplicateMountPath)
        );
    }

    #[test]
    fn snapshot_wire_uses_user_slugs_and_generation_not_internal_roots() {
        let create: CreateDiskSnapshotRequest =
            serde_json::from_slice(br#"{"snapshot_slug":"before-upgrade","disk_slug":"data"}"#)
                .unwrap();
        assert_eq!(create.snapshot_slug.as_str(), "before-upgrade");
        assert_eq!(create.disk_slug.as_str(), "data");
        assert!(serde_json::from_slice::<CreateDiskSnapshotRequest>(
            br#"{"snapshot_slug":"before-upgrade","disk_slug":"data","root_hash":"secret"}"#
        )
        .is_err());

        let restore: RestoreDiskSnapshotRequest =
            serde_json::from_slice(br#"{"expected_generation":0}"#).unwrap();
        restore.validate().unwrap();
        assert_eq!(
            RestoreDiskSnapshotRequest {
                expected_generation: i64::MAX as u64 + 1,
            }
            .validate(),
            Err(SemanticValidationError::Generation)
        );
    }

    #[test]
    fn snapshot_projection_binds_immutable_ids_and_tombstone_shape() {
        let mut snapshot = DiskSnapshotView {
            snapshot_id: id("snapshot_01"),
            workspace_id: id("ws_01"),
            snapshot_slug: ResourceSlug::new("before-upgrade").unwrap(),
            disk_id: id("disk_01"),
            disk_slug: ResourceSlug::new("data").unwrap(),
            size_bytes: 1 << 30,
            status: DiskSnapshotStatus::Normal,
            captured_generation: 42,
            created_at_unix_ms: 10,
            deleted_at_unix_ms: None,
        };
        snapshot.validate().unwrap();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("root_hash"));
        assert!(!encoded.contains("root_object_id"));

        snapshot.status = DiskSnapshotStatus::Deleted;
        assert_eq!(
            snapshot.validate(),
            Err(SemanticValidationError::SnapshotShape)
        );
        snapshot.deleted_at_unix_ms = Some(11);
        snapshot.validate().unwrap();
        snapshot.snapshot_id = id("disk_01");
        assert_eq!(snapshot.validate(), Err(SemanticValidationError::IdPrefix));
    }

    #[test]
    fn persistent_mount_path_rejects_unsafe_or_ambiguous_paths() {
        for valid in ["/data", "/srv/app-data"] {
            assert!(PersistentMountPath::new(valid).is_some());
        }
        for invalid in [
            "/",
            "relative",
            "/data/",
            "/data//logs",
            "/data/../logs",
            "/proc",
        ] {
            assert!(
                PersistentMountPath::new(invalid).is_none(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn action_transition_table_matches_the_product_state_machine() {
        assert!(CatAction::Create.allowed_from(None));
        assert!(CatAction::Run.allowed_from(Some(CatState::Cold)));
        assert!(CatAction::Warm.allowed_from(Some(CatState::Suspended)));
        assert!(CatAction::Destroy.allowed_from(Some(CatState::Failure)));
        assert!(!CatAction::Run.allowed_from(Some(CatState::Failure)));
        assert!(!CatAction::Suspend.allowed_from(Some(CatState::Warm)));
        assert!(!CatAction::Destroy.allowed_from(Some(CatState::Destroyed)));
    }

    #[test]
    fn a_cat_read_from_a_control_without_the_run_clocks_still_validates() {
        // A client built from a newer commit than the deployed Control gets
        // these optionals as absent. That is a fact about the peer, so the read
        // must survive and let the renderer degrade -- not fail every Running
        // or mid-action Cat and take the whole list with it.
        let running: CatView = serde_json::from_slice(
            br#"{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"web",
                 "state":"running","current_action":null,"node_id":"node_01",
                 "node_name":"worker-a","cpu":2,"memory_bytes":1024,
                 "boot_image":"sha256:abc","mounts":[],"last_error":null,
                 "created_at_unix_ms":100,"updated_at_unix_ms":101,
                 "destroyed_at_unix_ms":null}"#,
        )
        .expect("an older Control's body still deserializes");
        assert_eq!(running.last_running_at_unix_ms, None);
        running
            .validate()
            .expect("absent observations are not a corrupt Cat");

        let in_flight: CatView = serde_json::from_slice(
            br#"{"cat_id":"cat_01","workspace_id":"ws_01","cat_slug":"web",
                 "state":"cold","current_action":"run","node_id":null,
                 "node_name":null,"cpu":2,"memory_bytes":1024,
                 "boot_image":"sha256:abc","mounts":[],"last_error":null,
                 "created_at_unix_ms":100,"updated_at_unix_ms":101,
                 "destroyed_at_unix_ms":null}"#,
        )
        .expect("an in-flight body without the action clock deserializes");
        assert_eq!(in_flight.current_action_started_at_unix_ms, None);
        in_flight.validate().expect("and validates");

        // A stamp before the Cat existed is corruption, and still rejected.
        let mut corrupt = running;
        corrupt.last_running_at_unix_ms = Some(99);
        assert_eq!(
            corrupt.validate(),
            Err(SemanticValidationError::Timestamp),
            "a run recorded before the Cat was created is not a skew case"
        );
    }

    #[test]
    fn cat_display_carries_node_name_with_node_id() {
        let cat = CatView {
            cat_id: id("cat_01"),
            workspace_id: id("ws_01"),
            cat_slug: ResourceSlug::new("web").unwrap(),
            state: Some(CatState::Running),
            current_action: None,
            node_id: Some(id("node_01")),
            node_name: Some(NodeName::new("worker-us-east-1a-01").unwrap()),
            cpu: 2,
            memory_bytes: 4_294_967_296,
            boot_image: "ubuntu-24.04".to_owned(),
            mounts: Vec::new(),
            last_error: None,
            created_at_unix_ms: 100,
            updated_at_unix_ms: 101,
            destroyed_at_unix_ms: None,
            current_action_started_at_unix_ms: None,
            last_running_at_unix_ms: Some(101),
        };
        cat.validate().unwrap();
        let body = serde_json::to_string(&cat).unwrap();
        assert!(body.contains(r#""node_id":"node_01""#));
        assert!(body.contains(r#""node_name":"worker-us-east-1a-01""#));

        let mut missing_name = cat;
        missing_name.node_name = None;
        assert_eq!(
            missing_name.validate(),
            Err(SemanticValidationError::Placement)
        );
    }

    #[test]
    fn node_registration_requires_but_can_update_control_endpoint() {
        let body = br#"{
            "node_id":"node_01",
            "node_name":"worker-us-east-1a-01",
            "control_endpoint":"https://10.0.0.12:8443",
            "vendor":"aws",
            "region":"us-east-1",
            "zone":"us-east-1a",
            "instance_id":"i-123",
            "machine_type":"m7i.4xlarge",
            "node_version":"1.0.0"
        }"#;
        let original: NodeRegistrationRequest = serde_json::from_slice(body).unwrap();
        original.validate().unwrap();
        let mut changed = original.clone();
        changed.control_endpoint = NodedControlEndpoint::new("https://10.0.0.13:8443").unwrap();
        assert!(original.same_identity_as(&changed));
        changed.instance_id = "i-456".to_owned();
        assert!(!original.same_identity_as(&changed));
        assert!(serde_json::from_slice::<NodeRegistrationRequest>(
            br#"{"node_id":"node_01","node_name":"worker","control_endpoint":"10.0.0.12:8443","vendor":"aws","region":"r","zone":"z","instance_id":"i","machine_type":"m","node_version":"1"}"#
        )
        .is_err());
    }

    #[test]
    fn ingress_target_is_only_the_current_cat_and_node() {
        let target: CatIngressTarget =
            serde_json::from_slice(br#"{"cat_id":"cat_01","node_id":"node_01"}"#).unwrap();
        target.validate().unwrap();
        assert_eq!(
            serde_json::to_string(&target).unwrap(),
            r#"{"cat_id":"cat_01","node_id":"node_01"}"#
        );
        for retired in [
            br#"{"cat_id":"cat_01","node_id":"node_01","request_id":"req_01"}"#.as_slice(),
            br#"{"cat_id":"cat_01","node_id":"node_01","operation_id":"op_01"}"#.as_slice(),
            br#"{"cat_id":"cat_01","node_id":"node_01","generation":2}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<CatIngressTarget>(retired).is_err());
        }
    }

    #[test]
    fn node_drain_response_is_closed_and_status_matches_blocked_cats() {
        let response = NodeDrainResponse {
            status: NodeDrainStatus::Blocked,
            source_node_id: id("node_source"),
            cats: vec![
                NodeDrainCatResult::Migrated {
                    cat_id: id("cat_ok"),
                    target_node_id: id("node_target"),
                    state: CatState::Warm,
                },
                NodeDrainCatResult::Blocked {
                    cat_id: id("cat_blocked"),
                    code: "flush_failed".to_owned(),
                    message: "retained volume did not reach R=L".to_owned(),
                },
            ],
        };
        response.validate().unwrap();
        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: NodeDrainResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, response);

        let mut invalid = response;
        invalid.status = NodeDrainStatus::Drained;
        assert_eq!(
            invalid.validate(),
            Err(SemanticValidationError::ResponseShape)
        );
        assert!(serde_json::from_str::<NodeDrainResponse>(
            r#"{"status":"drained","source_node_id":"node_source","cats":[],"operation_id":"op_1"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<NodeDrainResponse>(
            r#"{"status":"drained","source_node_id":"node_source","cats":[{"status":"stale","cat_id":"cat_gone","operation_id":"op_1"}]}"#
        )
        .is_err());
    }

    #[test]
    fn bearer_service_token_is_header_only_and_debug_is_redacted() {
        let token = NodedServiceToken::new("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            token.authorization_value(),
            "Bearer 0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            NodedServiceToken::parse_authorization(&token.authorization_value()),
            Some(token.clone())
        );
        assert_eq!(format!("{token:?}"), "NodedServiceToken([REDACTED])");
        assert!(NodedServiceToken::parse_authorization("Basic abc").is_none());
        assert!(NodedServiceToken::new("too-short").is_none());
    }

    #[test]
    fn noded_contract_is_closed_and_status_error_shape_is_exact() {
        let body = br#"{
            "workspace_id":"ws_01",
            "cpu":2,
            "memory_bytes":4294967296,
            "boot_image":"ubuntu-24.04",
            "mounts":[{"disk_id":"disk_01","volume_id":"vol_01","filesystem_uuid":"11111111111111111111111111111111","format":"ext4","mount_path":"/data"}]
        }"#;
        let request: NodedCreateCatRequest = serde_json::from_slice(body).unwrap();
        request.validate().unwrap();
        assert!(serde_json::from_slice::<NodedCreateCatRequest>(
            br#"{"workspace_id":"ws_01","cpu":2,"memory_bytes":4,"boot_image":"image","mounts":[],"request_id":"req_01"}"#
        )
        .is_err());

        let run = NodedCatActionRequest {
            config: Some(request),
        };
        run.validate_for(CatAction::Run).unwrap();
        assert_eq!(
            NodedCatActionRequest { config: None }.validate_for(CatAction::Run),
            Err(SemanticValidationError::ActionConfig)
        );
        assert_eq!(
            serde_json::to_string(&NodedCatActionRequest { config: None }).unwrap(),
            "{}"
        );

        let failed = NodedCatResponse {
            status: NodedResultStatus::Failed,
            cat_id: id("cat_01"),
            state: CatState::Failure,
            error: Some(SemanticErrorBody {
                code: SemanticErrorCode::GuestStartFailed,
                message: "guest did not become ready".to_owned(),
            }),
        };
        failed.validate().unwrap();
        let mut invalid = failed;
        invalid.error = None;
        assert_eq!(
            invalid.validate(),
            Err(SemanticValidationError::ResponseShape)
        );

        let creating = NodedCatView {
            cat_id: id("cat_01"),
            state: None,
            active_action: Some(CatAction::Create),
            config: NodedCatConfig {
                workspace_id: id("ws_01"),
                cpu: 1,
                memory_bytes: 1,
                boot_image: "image".to_owned(),
                mounts: Vec::new(),
            },
        };
        creating.validate().unwrap();
        let mut invalid_creating = creating;
        invalid_creating.active_action = Some(CatAction::Run);
        assert_eq!(
            invalid_creating.validate(),
            Err(SemanticValidationError::CatShape)
        );
    }

    #[test]
    fn noded_paths_are_derived_only_from_cat_identity_and_action() {
        let cat_id = id("cat_01");
        assert_eq!(noded_cat_path(&cat_id).unwrap(), "/v1/cats/cat_01");
        assert_eq!(
            noded_cat_action_path(&cat_id, CatAction::Warm).unwrap(),
            "/v1/cats/cat_01/actions/warm"
        );
        assert_eq!(
            noded_cat_action_path(&cat_id, CatAction::Destroy),
            Err(SemanticValidationError::ActionConfig)
        );
    }

    #[test]
    fn stable_error_codes_have_documented_wire_and_http_mapping() {
        let body = SemanticErrorBody {
            code: SemanticErrorCode::CatMustBeCold,
            message: "Cat must be Cold before attach".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"code":"cat_must_be_cold","message":"Cat must be Cold before attach"}"#
        );
        assert_eq!(body.code.http_status(), 422);
        assert_eq!(SemanticErrorCode::Unauthorized.http_status(), 401);
        assert_eq!(SemanticErrorCode::InvalidRequest.http_status(), 400);
        assert_eq!(SemanticErrorCode::ActionCancelled.http_status(), 409);
        assert_eq!(SemanticErrorCode::NodeUnavailable.http_status(), 503);
        assert_eq!(SemanticErrorCode::Timeout.http_status(), 504);
    }

    #[test]
    fn heartbeat_uses_separate_control_receive_and_node_reported_times() {
        let heartbeat = NodeHeartbeatRequest {
            node_id: id("node_01"),
            node_reported_at_unix_ms: 123,
            reported_status: NodeStatus::Running,
            total_cpu: 8,
            cpu_utilized: 2.5,
            total_memory: 16_000,
            memory_utilized: 4_000,
            running_cat_count: 2,
            suspended_cat_count: 1,
            warm_cat_count: 0,
        };
        heartbeat.validate().unwrap();
        let view = NodeHeartbeatView {
            node_id: heartbeat.node_id.clone(),
            last_heartbeat_at_unix_ms: 130,
            node_reported_at_unix_ms: heartbeat.node_reported_at_unix_ms,
            reported_status: heartbeat.reported_status,
            total_cpu: heartbeat.total_cpu,
            cpu_utilized: heartbeat.cpu_utilized,
            total_memory: heartbeat.total_memory,
            memory_utilized: heartbeat.memory_utilized,
            running_cat_count: heartbeat.running_cat_count,
            suspended_cat_count: heartbeat.suspended_cat_count,
            warm_cat_count: heartbeat.warm_cat_count,
        };
        let body = serde_json::to_string(&view).unwrap();
        assert!(body.contains("last_heartbeat_at_unix_ms"));
        assert!(body.contains("node_reported_at_unix_ms"));
    }
}

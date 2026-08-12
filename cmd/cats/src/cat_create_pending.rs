//! Durable, descriptor-relative recovery state for covered public create
//! requests. One unresolved request is bound to one API origin, immutable
//! Workspace ID, resource name, exact path, exact body, and Idempotency-Key.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cats_api::cat_create::CatCreateV2Request;
use cats_api::persistent_disk::PersistentDiskCreateV1Request;
use cats_api::runtime_reconciliation::Id;
use fs2::FileExt as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::stable_unix_fs::{
    c_os_name, effective_uid, identity_at, open_directory_nofollow, open_file_at,
    open_or_create_directory_at, sync_directory, validate_owned_directory, FileIdentity,
    StableDirectory,
};

const STATE_VERSION: u32 = 1;
const METHOD: &str = "POST";
const CONTENT_TYPE: &str = "application/json";
const PENDING_MAX_BYTES: usize = 16 * 1024;
const BODY_MAX_BYTES: usize = 4 * 1024;
const CAT_STATE_DIRECTORY: &str = "cat-create-v2-authority-v1";
const PERSISTENT_DISK_STATE_DIRECTORY: &str = "persistent-disk-create-v1-authority-v1";

#[derive(Clone, Copy)]
struct PendingNamespace {
    description: &'static str,
    lock_scope: &'static str,
    file_prefix: &'static str,
}

const CAT_NAMESPACE: PendingNamespace = PendingNamespace {
    description: "Cat-create",
    lock_scope: "cat-create-v2",
    file_prefix: "cat",
};

const PERSISTENT_DISK_NAMESPACE: PendingNamespace = PendingNamespace {
    description: "PersistentDisk-create",
    lock_scope: "persistent-disk-create-v1",
    file_prefix: "disk",
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    version: u32,
    origin: String,
    authenticated_workspace_id: String,
    method: String,
    target: String,
    content_type: String,
    idempotency_key: String,
    request_sha256: String,
    body_base64: String,
}

impl PendingRecord {
    fn new(origin: &str, workspace_id: &str, body: &[u8]) -> Result<Self> {
        let origin = canonical_api_origin(origin)?;
        let workspace_id = canonical_workspace_id(workspace_id)?;
        let request = canonical_request(body)?;
        let target = cat_create_target(&workspace_id);
        let record = Self {
            version: STATE_VERSION,
            origin,
            authenticated_workspace_id: workspace_id,
            method: METHOD.to_owned(),
            target,
            content_type: CONTENT_TYPE.to_owned(),
            idempotency_key: format!("cli-{}", uuid::Uuid::new_v4().simple()),
            request_sha256: sha256_digest(body),
            body_base64: URL_SAFE_NO_PAD.encode(body),
        };
        let recovered = record.validate()?;
        anyhow::ensure!(
            recovered == request,
            "new pending Cat-create state changed the exact request body"
        );
        Ok(record)
    }

    fn validate(&self) -> Result<CatCreateV2Request> {
        anyhow::ensure!(
            self.version == STATE_VERSION,
            "pending Cat-create state has an unsupported version"
        );
        anyhow::ensure!(
            canonical_api_origin(&self.origin)? == self.origin,
            "pending Cat-create state contains a non-canonical API origin"
        );
        let workspace_id = canonical_workspace_id(&self.authenticated_workspace_id)?;
        anyhow::ensure!(
            self.method == METHOD
                && self.content_type == CONTENT_TYPE
                && self.target == cat_create_target(&workspace_id),
            "pending Cat-create state changed its exact HTTP request binding"
        );
        anyhow::ensure!(
            (1..=512).contains(&self.idempotency_key.len())
                && self
                    .idempotency_key
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte)),
            "pending Cat-create state contains an invalid Idempotency-Key"
        );
        let body = URL_SAFE_NO_PAD
            .decode(&self.body_base64)
            .context("pending Cat-create state contains invalid body base64")?;
        anyhow::ensure!(
            URL_SAFE_NO_PAD.encode(&body) == self.body_base64,
            "pending Cat-create body base64 is not canonical"
        );
        anyhow::ensure!(
            body.len() <= BODY_MAX_BYTES,
            "pending Cat-create body exceeds its closed byte limit"
        );
        anyhow::ensure!(
            sha256_digest(&body) == self.request_sha256,
            "pending Cat-create body digest does not match"
        );
        canonical_request(&body)
    }

    fn body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        URL_SAFE_NO_PAD
            .decode(&self.body_base64)
            .context("pending Cat-create state contains invalid body base64")
    }

    fn binds(&self, desired: &Self) -> Result<bool> {
        self.validate()?;
        desired.validate()?;
        Ok(self.origin == desired.origin
            && self.authenticated_workspace_id == desired.authenticated_workspace_id
            && self.method == desired.method
            && self.target == desired.target
            && self.content_type == desired.content_type
            && self.request_sha256 == desired.request_sha256
            && self.body_base64 == desired.body_base64)
    }
}

/// A held cross-process authority lock plus the exact persisted request. The
/// lock is intentionally non-blocking: a concurrent invocation fails locally
/// instead of waiting and accidentally issuing a second request after the
/// first invocation has already cleared its state.
pub(crate) struct PreparedCatCreate {
    state: PendingState,
    record: PendingRecord,
}

impl PreparedCatCreate {
    pub(crate) fn prepare(origin: &str, workspace_id: &str, body: &[u8]) -> Result<Self> {
        Self::prepare_in(&state_root()?, origin, workspace_id, body)
    }

    fn prepare_in(root: &Path, origin: &str, workspace_id: &str, body: &[u8]) -> Result<Self> {
        let desired = PendingRecord::new(origin, workspace_id, body)?;
        let request = desired.validate()?;
        let slot = request_slot(&desired.authenticated_workspace_id, request.name.as_str());
        let state = PendingState::acquire(
            root,
            &desired.authenticated_workspace_id,
            &request.name,
            CAT_NAMESPACE,
            slot,
        )?;
        let record: PendingRecord = match state.load_pending::<PendingRecord>()? {
            Some(existing) => {
                anyhow::ensure!(
                    existing.binds(&desired)?,
                    "an unresolved Cat-create request for this Workspace and Cat name is bound to a different origin, path, or body; no HTTP request was sent (pending {})",
                    state.pending_path().display()
                );
                existing
            }
            None => {
                desired.validate_for_slot(&state.slot)?;
                state.publish_pending(&desired)?;
                desired
            }
        };
        record.validate_for_slot(&state.slot)?;
        Ok(Self { state, record })
    }

    pub(crate) fn origin(&self) -> &str {
        &self.record.origin
    }

    pub(crate) fn target(&self) -> &str {
        &self.record.target
    }

    pub(crate) fn content_type(&self) -> &str {
        &self.record.content_type
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        &self.record.idempotency_key
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>> {
        self.record.body()
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        self.state.assert_current_authority()
    }

    pub(crate) fn pending_path(&self) -> PathBuf {
        self.state.pending_path()
    }

    pub(crate) fn clear(&self) -> Result<()> {
        self.state.delete_pending()
    }
}

impl PendingRecord {
    fn validate_for_slot(&self, slot: &str) -> Result<()> {
        let request = self.validate()?;
        anyhow::ensure!(
            request_slot(&self.authenticated_workspace_id, request.name.as_str(),) == slot,
            "pending Cat-create state does not bind its storage slot"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentDiskPendingRecord {
    version: u32,
    origin: String,
    authenticated_workspace_id: String,
    method: String,
    target: String,
    content_type: String,
    idempotency_key: String,
    request_sha256: String,
    body_base64: String,
}

impl PersistentDiskPendingRecord {
    fn new(origin: &str, workspace_id: &str, body: &[u8]) -> Result<Self> {
        let origin = canonical_api_origin(origin)?;
        let workspace_id = canonical_workspace_id(workspace_id)?;
        let request = canonical_persistent_disk_request(body)?;
        let record = Self {
            version: STATE_VERSION,
            origin,
            target: persistent_disk_create_target(&workspace_id),
            authenticated_workspace_id: workspace_id,
            method: METHOD.to_owned(),
            content_type: CONTENT_TYPE.to_owned(),
            idempotency_key: format!("cli-{}", uuid::Uuid::new_v4().simple()),
            request_sha256: sha256_digest(body),
            body_base64: URL_SAFE_NO_PAD.encode(body),
        };
        anyhow::ensure!(
            record.validate()? == request,
            "new pending PersistentDisk-create state changed the exact request body"
        );
        Ok(record)
    }

    fn validate(&self) -> Result<PersistentDiskCreateV1Request> {
        anyhow::ensure!(
            self.version == STATE_VERSION,
            "pending PersistentDisk-create state has an unsupported version"
        );
        anyhow::ensure!(
            canonical_api_origin(&self.origin)? == self.origin,
            "pending PersistentDisk-create state contains a non-canonical API origin"
        );
        let workspace_id = canonical_workspace_id(&self.authenticated_workspace_id)?;
        anyhow::ensure!(
            self.method == METHOD
                && self.content_type == CONTENT_TYPE
                && self.target == persistent_disk_create_target(&workspace_id),
            "pending PersistentDisk-create state changed its exact HTTP request binding"
        );
        validate_idempotency_key(&self.idempotency_key, "PersistentDisk-create")?;
        let body = canonical_pending_body(
            &self.body_base64,
            &self.request_sha256,
            "PersistentDisk-create",
        )?;
        canonical_persistent_disk_request(&body)
    }

    fn validate_for_slot(&self, slot: &str) -> Result<()> {
        let request = self.validate()?;
        anyhow::ensure!(
            persistent_disk_request_slot(&self.authenticated_workspace_id, request.name.as_str(),)
                == slot,
            "pending PersistentDisk-create state does not bind its storage slot"
        );
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>> {
        self.validate()?;
        URL_SAFE_NO_PAD
            .decode(&self.body_base64)
            .context("pending PersistentDisk-create state contains invalid body base64")
    }

    fn binds(&self, desired: &Self) -> Result<bool> {
        self.validate()?;
        desired.validate()?;
        Ok(self.origin == desired.origin
            && self.authenticated_workspace_id == desired.authenticated_workspace_id
            && self.method == desired.method
            && self.target == desired.target
            && self.content_type == desired.content_type
            && self.request_sha256 == desired.request_sha256
            && self.body_base64 == desired.body_base64)
    }
}

/// A held cross-process authority lock plus the exact persisted
/// PersistentDisk-create request.
pub(crate) struct PreparedPersistentDiskCreate {
    state: PendingState,
    record: PersistentDiskPendingRecord,
}

impl PreparedPersistentDiskCreate {
    pub(crate) fn prepare(origin: &str, workspace_id: &str, body: &[u8]) -> Result<Self> {
        Self::prepare_in(&persistent_disk_state_root()?, origin, workspace_id, body)
    }

    fn prepare_in(root: &Path, origin: &str, workspace_id: &str, body: &[u8]) -> Result<Self> {
        let desired = PersistentDiskPendingRecord::new(origin, workspace_id, body)?;
        let request = desired.validate()?;
        let slot = persistent_disk_request_slot(
            &desired.authenticated_workspace_id,
            request.name.as_str(),
        );
        let state = PendingState::acquire(
            root,
            &desired.authenticated_workspace_id,
            &request.name,
            PERSISTENT_DISK_NAMESPACE,
            slot,
        )?;
        let record: PersistentDiskPendingRecord = match state
            .load_pending::<PersistentDiskPendingRecord>()?
        {
            Some(existing) => {
                anyhow::ensure!(
                    existing.binds(&desired)?,
                    "an unresolved PersistentDisk-create request for this Workspace and Disk name is bound to a different origin, path, or body; no HTTP request was sent (pending {})",
                    state.pending_path().display()
                );
                existing
            }
            None => {
                desired.validate_for_slot(&state.slot)?;
                state.publish_pending(&desired)?;
                desired
            }
        };
        record.validate_for_slot(&state.slot)?;
        Ok(Self { state, record })
    }

    pub(crate) fn origin(&self) -> &str {
        &self.record.origin
    }

    pub(crate) fn target(&self) -> &str {
        &self.record.target
    }

    pub(crate) fn content_type(&self) -> &str {
        &self.record.content_type
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        &self.record.idempotency_key
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.record.authenticated_workspace_id
    }

    pub(crate) fn request(&self) -> Result<PersistentDiskCreateV1Request> {
        self.record.validate()
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>> {
        self.record.body()
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        self.state.assert_current_authority()
    }

    pub(crate) fn pending_path(&self) -> PathBuf {
        self.state.pending_path()
    }

    pub(crate) fn clear(&self) -> Result<()> {
        self.state.delete_pending()
    }
}

pub(crate) fn canonical_api_origin(value: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(value).context("invalid Cats API origin")?;
    let has_userinfo = value.split_once("://").is_some_and(|(_, remainder)| {
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        remainder[..authority_end].contains('@')
    });
    anyhow::ensure!(
        value.trim() == value
            && matches!(parsed.scheme(), "http" | "https")
            && parsed.has_host()
            && !has_userinfo
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "Cats API URL must be one exact HTTP(S) origin without path, query, credentials, or fragment"
    );
    Ok(parsed.origin().ascii_serialization())
}

fn canonical_workspace_id(value: &str) -> Result<String> {
    Id::new(value.to_owned())
        .map(|workspace| workspace.as_str().to_owned())
        .context("invalid immutable Workspace ID")
}

fn cat_create_target(workspace_id: &str) -> String {
    format!("/v1/workspaces/{workspace_id}/cats")
}

fn persistent_disk_create_target(workspace_id: &str) -> String {
    format!("/v1/workspaces/{workspace_id}/disks")
}

fn canonical_request(bytes: &[u8]) -> Result<CatCreateV2Request> {
    anyhow::ensure!(
        bytes.len() <= BODY_MAX_BYTES,
        "Cat-create request exceeds its closed byte limit"
    );
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let request =
        CatCreateV2Request::deserialize(&mut decoder).context("parse exact Cat-create request")?;
    decoder
        .end()
        .context("Cat-create request has a trailing JSON value")?;
    request.validate().context("invalid Cat-create request")?;
    anyhow::ensure!(
        serde_json::to_vec(&request)? == bytes,
        "Cat-create request is not the canonical frozen DTO encoding"
    );
    Ok(request)
}

fn canonical_persistent_disk_request(bytes: &[u8]) -> Result<PersistentDiskCreateV1Request> {
    anyhow::ensure!(
        bytes.len() <= BODY_MAX_BYTES,
        "PersistentDisk-create request exceeds its closed byte limit"
    );
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let request = PersistentDiskCreateV1Request::deserialize(&mut decoder)
        .context("parse exact PersistentDisk-create request")?;
    decoder
        .end()
        .context("PersistentDisk-create request has a trailing JSON value")?;
    request
        .validate()
        .context("invalid PersistentDisk-create request")?;
    anyhow::ensure!(
        serde_json::to_vec(&request)? == bytes,
        "PersistentDisk-create request is not the canonical frozen DTO encoding"
    );
    Ok(request)
}

fn validate_idempotency_key(value: &str, description: &str) -> Result<()> {
    anyhow::ensure!(
        (1..=512).contains(&value.len()) && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "pending {description} state contains an invalid Idempotency-Key"
    );
    Ok(())
}

fn canonical_pending_body(
    body_base64: &str,
    request_sha256: &str,
    description: &str,
) -> Result<Vec<u8>> {
    let body = URL_SAFE_NO_PAD
        .decode(body_base64)
        .with_context(|| format!("pending {description} state contains invalid body base64"))?;
    anyhow::ensure!(
        URL_SAFE_NO_PAD.encode(&body) == body_base64,
        "pending {description} body base64 is not canonical"
    );
    anyhow::ensure!(
        body.len() <= BODY_MAX_BYTES,
        "pending {description} body exceeds its closed byte limit"
    );
    anyhow::ensure!(
        sha256_digest(&body) == request_sha256,
        "pending {description} body digest does not match"
    );
    Ok(body)
}

fn state_root() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(root) = TEST_STATE_ROOT.with(|slot| slot.borrow().clone()) {
        return Ok(root);
    }
    #[cfg(test)]
    if let Some(root) = std::env::var_os("CATS_TEST_CAT_CREATE_STATE_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let config = crate::config::config_path();
    let parent = config.parent().context("Cats config path has no parent")?;
    Ok(parent.join(CAT_STATE_DIRECTORY))
}

fn persistent_disk_state_root() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(root) = TEST_PERSISTENT_DISK_STATE_ROOT.with(|slot| slot.borrow().clone()) {
        return Ok(root);
    }
    #[cfg(test)]
    if let Some(root) = std::env::var_os("CATS_TEST_PERSISTENT_DISK_CREATE_STATE_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let config = crate::config::config_path();
    let parent = config.parent().context("Cats config path has no parent")?;
    Ok(parent.join(PERSISTENT_DISK_STATE_DIRECTORY))
}

#[cfg(test)]
thread_local! {
    static TEST_STATE_ROOT: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    static TEST_PERSISTENT_DISK_STATE_ROOT: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
pub(crate) struct TestStateRootGuard;

#[cfg(test)]
impl TestStateRootGuard {
    pub(crate) fn set(root: PathBuf) -> Self {
        TEST_STATE_ROOT.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "Cat-create test state root is already set"
            );
            *slot.borrow_mut() = Some(root);
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestStateRootGuard {
    fn drop(&mut self) {
        TEST_STATE_ROOT.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) struct TestPersistentDiskStateRootGuard;

#[cfg(test)]
impl TestPersistentDiskStateRootGuard {
    pub(crate) fn set(root: PathBuf) -> Self {
        TEST_PERSISTENT_DISK_STATE_ROOT.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "PersistentDisk-create test state root is already set"
            );
            *slot.borrow_mut() = Some(root);
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestPersistentDiskStateRootGuard {
    fn drop(&mut self) {
        TEST_PERSISTENT_DISK_STATE_ROOT.with(|slot| *slot.borrow_mut() = None);
    }
}

struct PendingState {
    display_root: PathBuf,
    state_root: StateRoot,
    _lock: File,
    lock_directory: File,
    lock_name: CString,
    lock_identity: FileIdentity,
    slot: String,
    namespace: PendingNamespace,
}

impl PendingState {
    fn acquire(
        root: &Path,
        workspace_id: &str,
        name: &Id,
        namespace: PendingNamespace,
        slot: String,
    ) -> Result<Self> {
        let state_root = StateRoot::open_or_create(root, namespace.description)?;
        let lock_directory = open_global_lock_directory()?;
        let root_digest = sha256_digest(root.as_os_str().as_bytes());
        let lock_name = c_name(&format!(
            ".cats-{}-{}-{root_digest}-{slot}.lock",
            namespace.lock_scope,
            effective_uid(),
        ))?;
        let (lock, created) = open_state_lock(&lock_directory, &lock_name)?;
        lock.try_lock_exclusive().with_context(|| {
            format!(
                "another {} invocation for Workspace {workspace_id} and resource {name} is in progress; no HTTP request was sent",
                namespace.description
            )
        })?;
        validate_private_regular_file(&lock, lock_name.to_string_lossy().as_ref())?;
        if created {
            sync_directory(&lock_directory, "sync global Cat-create lock directory")?;
        }
        let state = Self {
            display_root: root.to_owned(),
            lock_identity: FileIdentity::of(&lock)?,
            lock_name,
            lock_directory,
            _lock: lock,
            state_root,
            slot,
            namespace,
        };
        state.assert_current_authority()?;
        Ok(state)
    }

    fn pending_name(&self) -> Result<CString> {
        c_name(&format!(
            "{}-{}.pending.json",
            self.namespace.file_prefix, self.slot
        ))
    }

    fn pending_path(&self) -> PathBuf {
        self.display_root.join(format!(
            "{}-{}.pending.json",
            self.namespace.file_prefix, self.slot
        ))
    }

    fn assert_current_authority(&self) -> Result<()> {
        self.state_root.assert_current()?;
        let current_lock = identity_at(
            &self.lock_directory,
            &self.lock_name,
            libc::AT_SYMLINK_NOFOLLOW,
        )?;
        anyhow::ensure!(
            current_lock == self.lock_identity,
            "{} authority lock identity changed",
            self.namespace.description
        );
        validate_private_regular_file(&self._lock, self.lock_name.to_string_lossy().as_ref())
    }

    fn load_pending<T>(&self) -> Result<Option<T>>
    where
        T: DeserializeOwned + Serialize,
    {
        self.assert_current_authority()?;
        let name = self.pending_name()?;
        cleanup_publish_temp(&self.state_root.directory, &name)?;
        let Some(bytes) =
            read_optional_state_file(&self.state_root.directory, &name, PENDING_MAX_BYTES)?
        else {
            return Ok(None);
        };
        let pending: T = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse pending {} state", self.namespace.description))?;
        anyhow::ensure!(
            serde_json::to_vec(&pending)? == bytes,
            "pending {} state is not canonical",
            self.namespace.description
        );
        Ok(Some(pending))
    }

    fn publish_pending<T: Serialize>(&self, pending: &T) -> Result<()> {
        self.assert_current_authority()?;
        let bytes = serde_json::to_vec(pending)?;
        anyhow::ensure!(
            bytes.len() <= PENDING_MAX_BYTES,
            "pending {} state exceeds its closed byte limit",
            self.namespace.description
        );
        publish_new(&self.state_root.directory, &self.pending_name()?, &bytes)?;
        self.assert_current_authority()
    }

    fn delete_pending(&self) -> Result<()> {
        self.assert_current_authority()?;
        let name = self.pending_name()?;
        match unlink_at(&self.state_root.directory, &name) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("remove pending {} state", self.namespace.description)
                })
            }
        }
        sync_directory(
            &self.state_root.directory,
            "sync pending covered-create deletion",
        )?;
        self.assert_current_authority()
    }
}

struct StateRoot {
    parent: StableDirectory,
    directory: File,
    entry_name: CString,
    identity: FileIdentity,
    description: &'static str,
}

impl StateRoot {
    fn open_or_create(path: &Path, description: &'static str) -> Result<Self> {
        anyhow::ensure!(
            path.is_absolute(),
            "durable {description} state requires an absolute config directory"
        );
        let parent_path = path
            .parent()
            .with_context(|| format!("{description} state root has no parent"))?;
        let entry_name = c_os_name(
            path.file_name()
                .with_context(|| format!("{description} state root has no basename"))?,
        )?;
        let parent = StableDirectory::open_or_create(parent_path)?;
        parent.assert_current()?;
        let (directory, created) = open_or_create_directory_at(&parent.directory, &entry_name)?;
        validate_owned_directory(&directory, true)?;
        sync_directory(
            &parent.directory,
            "sync selected Cat-create state-root parent",
        )?;
        if created {
            sync_directory(&directory, "sync new Cat-create state root")?;
        }
        let identity = FileIdentity::of(&directory)?;
        let root = Self {
            parent,
            directory,
            entry_name,
            identity,
            description,
        };
        root.assert_current()?;
        Ok(root)
    }

    fn assert_current(&self) -> Result<()> {
        self.parent.assert_current()?;
        anyhow::ensure!(
            FileIdentity::of(&self.directory)? == self.identity,
            "{} state-root descriptor changed identity",
            self.description
        );
        anyhow::ensure!(
            identity_at(
                &self.parent.directory,
                &self.entry_name,
                libc::AT_SYMLINK_NOFOLLOW,
            )? == self.identity,
            "{} state root was renamed or replaced",
            self.description
        );
        validate_owned_directory(&self.directory, true)
    }
}

fn read_optional_state_file(
    directory: &File,
    name: &CStr,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let mut file = match open_file_at(directory, name, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open pending Cat-create state"),
    };
    validate_private_regular_file(&file, name.to_string_lossy().as_ref())?;
    let before = file.metadata()?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "pending Cat-create state exceeds its closed byte limit"
    );
    let after = file.metadata()?;
    anyhow::ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "pending Cat-create state changed while being read"
    );
    Ok(Some(bytes))
}

fn validate_private_regular_file(file: &File, display: &str) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == effective_uid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600,
        "{display} is not a private, owned, single-link regular file with mode 0600"
    );
    Ok(())
}

fn open_state_lock(parent: &File, name: &CStr) -> Result<(File, bool)> {
    match open_file_at(
        parent,
        name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Ok((open_file_at(parent, name, libc::O_RDWR, 0)?, false))
        }
        Err(error) => Err(error).context("open Cat-create authority lock"),
    }
}

fn open_global_lock_directory() -> Result<File> {
    #[cfg(target_os = "macos")]
    const COMPONENTS: &[&str] = &["private", "tmp"];
    #[cfg(not(target_os = "macos"))]
    const COMPONENTS: &[&str] = &["tmp"];

    let mut directory = open_directory_nofollow(Path::new("/"))?;
    for component in COMPONENTS {
        let name = c_name(component)?;
        directory = open_file_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .context("open global Cat-create lock directory")?;
    }
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && metadata.uid() == 0 && metadata.mode() & 0o1777 == 0o1777,
        "global Cat-create lock directory is not root-owned sticky 01777"
    );
    Ok(directory)
}

fn publish_new(directory: &File, target: &CStr, bytes: &[u8]) -> Result<()> {
    cleanup_publish_temp(directory, target)?;
    let temporary = publish_temp_name(target)?;
    let mut file = open_file_at(
        directory,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .context("create temporary pending Cat-create state")?;
    validate_private_regular_file(&file, temporary.to_string_lossy().as_ref())?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Err(error) = rename_relative(directory, &temporary, target, true) {
        let _ = unlink_at(directory, &temporary);
        let _ = directory.sync_all();
        return Err(error).context("publish immutable pending Cat-create state");
    }
    sync_directory(directory, "sync published pending Cat-create state")
}

fn cleanup_publish_temp(directory: &File, target: &CStr) -> Result<()> {
    let temporary = publish_temp_name(target)?;
    match unlink_at(directory, &temporary) {
        Ok(()) => sync_directory(directory, "sync Cat-create state temp cleanup"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove stale pending Cat-create state temp"),
    }
}

fn publish_temp_name(target: &CStr) -> Result<CString> {
    c_name(&format!(".{}.tmp", target.to_string_lossy()))
}

#[cfg(target_os = "linux")]
fn rename_relative(
    directory: &File,
    source: &CStr,
    target: &CStr,
    no_replace: bool,
) -> io::Result<()> {
    let flags = if no_replace {
        libc::RENAME_NOREPLACE
    } else {
        0
    };
    // SAFETY: both names are live NUL-terminated single components and both
    // are resolved beneath the held state-directory descriptor.
    let result = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_relative(
    directory: &File,
    source: &CStr,
    target: &CStr,
    no_replace: bool,
) -> io::Result<()> {
    let flags = if no_replace { libc::RENAME_EXCL } else { 0 };
    // SAFETY: both names are live NUL-terminated single components and both
    // are resolved beneath the held state-directory descriptor.
    let result = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_relative(
    directory: &File,
    source: &CStr,
    target: &CStr,
    no_replace: bool,
) -> io::Result<()> {
    let result = if no_replace {
        // SAFETY: names are valid and resolved beneath the same held directory.
        unsafe {
            libc::linkat(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
                0,
            )
        }
    } else {
        // SAFETY: names are valid and resolved beneath the same held directory.
        unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if no_replace {
        unlink_at(directory, source)?;
    }
    Ok(())
}

fn unlink_at(directory: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: `name` is a live NUL-terminated component resolved beneath the
    // held directory descriptor; flags zero refuses directory removal.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn c_name(value: &str) -> Result<CString> {
    anyhow::ensure!(
        !value.is_empty() && !value.as_bytes().contains(&b'/'),
        "state entry is not one path component"
    );
    CString::new(value).context("state entry contains NUL")
}

fn request_slot(workspace_id: &str, name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cats.cat-create-v2.pending-slot.v1\0");
    hasher.update(workspace_id.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    lowercase_hex(&hasher.finalize())
}

fn persistent_disk_request_slot(workspace_id: &str, name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cats.persistent-disk-create-v1.pending-slot.v1\0");
    hasher.update(workspace_id.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    lowercase_hex(&hasher.finalize())
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", lowercase_hex(&hasher.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn body(vcpus: u32) -> Vec<u8> {
        serde_json::to_vec(
            &CatCreateV2Request::new(
                "app",
                DIGEST,
                vcpus,
                2 << 30,
                4 << 30,
                cats_api::runtime_reconciliation::Durability::Strict,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn persistent_disk_body(size_bytes: u64) -> Vec<u8> {
        serde_json::to_vec(&PersistentDiskCreateV1Request {
            durability: cats_api::resources::DiskDurability::Strict,
            name: Id::new("data").unwrap(),
            size_bytes,
        })
        .unwrap()
    }

    #[test]
    fn restart_recovers_exact_path_body_and_key_and_clear_removes_pending() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("state");
        let first =
            PreparedCatCreate::prepare_in(&root, "https://CONTROL.example:443", "ws_01", &body(2))
                .unwrap();
        let key = first.idempotency_key().to_owned();
        let target = first.target().to_owned();
        let exact_body = first.body().unwrap();
        let pending_path = first.pending_path();
        assert!(pending_path.exists());
        let metadata = std::fs::metadata(&pending_path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        drop(first);

        let recovered =
            PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(2))
                .unwrap();
        assert_eq!(recovered.origin(), "https://control.example");
        assert_eq!(recovered.idempotency_key(), key);
        assert_eq!(recovered.target(), target);
        assert_eq!(recovered.body().unwrap(), exact_body);
        recovered.clear().unwrap();
        assert!(!pending_path.exists());
    }

    #[test]
    fn incompatible_pending_body_fails_closed_and_preserves_original() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("state");
        let first =
            PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(2))
                .unwrap();
        let key = first.idempotency_key().to_owned();
        drop(first);
        let error =
            PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(3))
                .err()
                .unwrap();
        assert!(error
            .to_string()
            .contains("different origin, path, or body"));
        let recovered =
            PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(2))
                .unwrap();
        assert_eq!(recovered.idempotency_key(), key);
    }

    #[test]
    fn persistent_disk_restart_recovers_exact_path_body_and_key() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("disk-state");
        let first = PreparedPersistentDiskCreate::prepare_in(
            &root,
            "https://CONTROL.example:443",
            "ws_01",
            &persistent_disk_body(1 << 30),
        )
        .unwrap();
        let key = first.idempotency_key().to_owned();
        let exact_body = first.body().unwrap();
        let pending_path = first.pending_path();
        assert!(pending_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("disk-"));
        drop(first);

        let recovered = PreparedPersistentDiskCreate::prepare_in(
            &root,
            "https://control.example",
            "ws_01",
            &persistent_disk_body(1 << 30),
        )
        .unwrap();
        assert_eq!(recovered.idempotency_key(), key);
        assert_eq!(recovered.body().unwrap(), exact_body);
        assert_eq!(recovered.target(), "/v1/workspaces/ws_01/disks");
        recovered.clear().unwrap();
        assert!(!pending_path.exists());
    }

    #[test]
    fn persistent_disk_incompatible_pending_body_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("disk-state");
        let first = PreparedPersistentDiskCreate::prepare_in(
            &root,
            "https://control.example",
            "ws_01",
            &persistent_disk_body(1 << 30),
        )
        .unwrap();
        let key = first.idempotency_key().to_owned();
        drop(first);
        let error = PreparedPersistentDiskCreate::prepare_in(
            &root,
            "https://control.example",
            "ws_01",
            &persistent_disk_body(2 << 30),
        )
        .err()
        .unwrap();
        assert!(error
            .to_string()
            .contains("different origin, path, or body"));
        let recovered = PreparedPersistentDiskCreate::prepare_in(
            &root,
            "https://control.example",
            "ws_01",
            &persistent_disk_body(1 << 30),
        )
        .unwrap();
        assert_eq!(recovered.idempotency_key(), key);
    }

    #[test]
    fn pending_symlink_is_rejected_without_following_or_replacing_it() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("state");
        let first =
            PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(2))
                .unwrap();
        let pending_path = first.pending_path();
        drop(first);
        std::fs::remove_file(&pending_path).unwrap();
        let target = directory.path().join("attacker-controlled");
        std::fs::write(&target, b"do not read or replace").unwrap();
        symlink(&target, &pending_path).unwrap();

        let error =
            PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(2))
                .err()
                .unwrap();
        assert!(error.to_string().contains("open pending Cat-create state"));
        assert_eq!(std::fs::read(&target).unwrap(), b"do not read or replace");
        assert!(std::fs::symlink_metadata(&pending_path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn concurrent_process_authority_fails_closed_instead_of_waiting_then_resending() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("state");
        let first =
            PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(2))
                .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let thread_root = root.clone();
        let thread_barrier = Arc::clone(&barrier);
        let handle = std::thread::spawn(move || {
            thread_barrier.wait();
            PreparedCatCreate::prepare_in(
                &thread_root,
                "https://control.example",
                "ws_01",
                &body(2),
            )
            .err()
            .unwrap()
            .to_string()
        });
        barrier.wait();
        let error = handle.join().unwrap();
        assert!(error.contains("another Cat-create invocation"));
        drop(first);
    }

    #[test]
    fn every_pre_send_directory_barrier_failure_fails_closed() {
        use crate::stable_unix_fs::DirectorySyncProbeGuard;

        let successful_directory = tempfile::tempdir().unwrap();
        let successful_root = successful_directory
            .path()
            .canonicalize()
            .unwrap()
            .join("state");
        let successful_probe = DirectorySyncProbeGuard::start(None);
        let prepared = PreparedCatCreate::prepare_in(
            &successful_root,
            "https://control.example",
            "ws_01",
            &body(2),
        )
        .unwrap();
        let barrier_count = successful_probe.count();
        assert!(barrier_count > 0);
        drop(prepared);
        drop(successful_probe);

        for fail_at in 0..barrier_count {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap().join("state");
            let probe = DirectorySyncProbeGuard::start(Some(fail_at));
            assert!(
                PreparedCatCreate::prepare_in(&root, "https://control.example", "ws_01", &body(2),)
                    .is_err(),
                "directory barrier {fail_at} did not stop request preparation"
            );
            drop(probe);
        }
    }
}

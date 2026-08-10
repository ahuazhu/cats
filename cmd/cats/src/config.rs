use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(unix)]
use crate::stable_unix_fs::{
    effective_uid, identity_at, open_file_at, FileIdentity, StableDirectory,
};
use cats_api::auth::{UserProfile, Workspace};

pub(crate) const DEFAULT_API_URL: &str = "https://cats.run";
const CONFIG_VERSION: u32 = 2;
const KEYRING_SERVICE: &str = "cats.run CLI";
const ADMIN_KEYRING_PREFIX: &str = "fleet-admin:";
const ADMIN_LOCK_DOMAIN: &[u8] = b"cats.fleet-admin-credential-lock.v1\0";
const ADMIN_LOCK_DIRECTORY: &str = "fleet-admin-credential-locks-v1";

/// Return the only identity used for fleet-administrator credentials, locks,
/// and network requests. Equivalent host case and default-port spellings
/// therefore cannot split one rotating refresh-token authority.
pub(crate) fn canonical_https_origin(value: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(value).context("invalid Cats API origin")?;
    let has_userinfo = value.split_once("://").is_some_and(|(_, remainder)| {
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        remainder[..authority_end].contains('@')
    });
    anyhow::ensure!(
        value.trim() == value
            && parsed.scheme() == "https"
            && parsed.has_host()
            && !has_userinfo
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "Cats administration requires an exact HTTPS origin without path, query, credentials, or fragment"
    );
    Ok(parsed.origin().ascii_serialization())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredConfig {
    pub version: u32,
    pub api_url: String,
    pub workos_client_id: String,
    pub workos_api_base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_workspace: Option<String>,
    #[serde(default)]
    pub workspaces: Vec<Workspace>,
}

impl StoredConfig {
    pub(crate) fn new(
        api_url: String,
        workos_client_id: String,
        workos_api_base_url: String,
    ) -> Self {
        Self {
            version: CONFIG_VERSION,
            api_url,
            workos_client_id,
            workos_api_base_url,
            user: None,
            current_workspace: None,
            workspaces: Vec::new(),
        }
    }

    pub(crate) fn load() -> Result<Option<Self>> {
        Self::load_from(&config_path())
    }

    fn load_from(path: &Path) -> Result<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .context("Cats CLI config has no numeric version")?;
        let config = match version {
            1 => {
                let legacy: LegacyStoredConfig = serde_json::from_value(value)
                    .with_context(|| format!("parse legacy {}", path.display()))?;
                Self {
                    version: CONFIG_VERSION,
                    api_url: legacy.api_url,
                    workos_client_id: legacy.workos_client_id,
                    workos_api_base_url: legacy.workos_api_base_url,
                    user: None,
                    current_workspace: None,
                    workspaces: Vec::new(),
                }
            }
            version if version == u64::from(CONFIG_VERSION) => serde_json::from_value(value)
                .with_context(|| format!("parse {}", path.display()))?,
            unsupported => anyhow::bail!(
                "unsupported Cats CLI config version {unsupported}; expected {CONFIG_VERSION}"
            ),
        };
        Ok(Some(config))
    }

    pub(crate) fn save(&self) -> Result<()> {
        self.save_to(&config_path())
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("Cats config path has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("create config directory {}", parent.display()))?;
        let temporary = path.with_extension("json.tmp");
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("write {}", temporary.display()))?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    }

    pub(crate) fn clear_identity(&mut self) {
        self.user = None;
        self.current_workspace = None;
        self.workspaces.clear();
    }
}

/// V1 cached workspaces did not contain immutable Account/Workspace identity.
/// They cannot be upgraded locally without trusting mutable slugs, so only the
/// public AuthKit endpoint configuration is retained. The next login fetches
/// authoritative workspace records from the control plane.
#[derive(Deserialize)]
struct LegacyStoredConfig {
    api_url: String,
    workos_client_id: String,
    workos_api_base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_organization_id: Option<String>,
}

/// Fleet-administrator credentials are deliberately disjoint from the
/// Workspace login. In particular, an administrator does not need a Cats
/// Account or Workspace mapping to acquire or refresh this session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FleetAdminCredentials {
    pub access_token: String,
    pub refresh_token: String,
    pub organization_id: String,
    pub subject: String,
    pub email: String,
}

impl FleetAdminCredentials {
    fn account(api_url: &str) -> String {
        format!("{ADMIN_KEYRING_PREFIX}{api_url}")
    }

    fn decode(encoded: &str) -> Result<Self> {
        serde_json::from_str(encoded)
            .context("parse Cats fleet-administrator login from credential store")
    }

    fn encode(&self) -> Result<String> {
        serde_json::to_string(self).context("encode Cats fleet-administrator login")
    }

    #[cfg(test)]
    pub(crate) fn test_store_path(root: &Path, api_url: &str) -> PathBuf {
        crate::credential_store::test_path(root, KEYRING_SERVICE, &Self::account(api_url))
    }
}

impl Credentials {
    pub(crate) fn load(api_url: &str) -> Result<Option<Self>> {
        let encoded = match crate::credential_store::get(KEYRING_SERVICE, api_url)? {
            Some(value) => value,
            None => return Ok(None),
        };
        Ok(Some(
            serde_json::from_str(&encoded).context("parse Cats login from credential store")?,
        ))
    }

    pub(crate) fn save(&self, api_url: &str) -> Result<()> {
        crate::credential_store::set(KEYRING_SERVICE, api_url, &serde_json::to_string(self)?)
    }

    pub(crate) fn delete(api_url: &str) -> Result<()> {
        crate::credential_store::delete(KEYRING_SERVICE, api_url)
    }
}

pub(crate) struct CliStateLock {
    file: std::fs::File,
}

impl CliStateLock {
    pub(crate) fn acquire() -> Result<Self> {
        let path = config_path().with_file_name("credentials.lock");
        let parent = path
            .parent()
            .context("Cats credential lock has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("create config directory {}", parent.display()))?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", path.display()))?;
        Ok(Self { file })
    }
}

pub(crate) struct FleetAdminStateLock {
    file: std::fs::File,
    canonical_origin: String,
    #[cfg(unix)]
    root: StableDirectory,
    #[cfg(unix)]
    lock_name: std::ffi::CString,
    #[cfg(unix)]
    lock_identity: FileIdentity,
    #[cfg(not(unix))]
    lock_path: PathBuf,
}

impl FleetAdminStateLock {
    /// Serialize every consumer of one rotating administrator credential.
    ///
    /// The keyring account, lock name, and network authority all use the same
    /// canonical HTTPS origin. On Unix, every ancestor/root descriptor and the
    /// linked lock dev+ino remain part of the authority until the operation is
    /// complete. This matches the repository's descriptor-identity contract;
    /// it does not claim to defeat a same-UID actor racing after the final
    /// pre-effect check at nanosecond granularity.
    pub(crate) fn acquire(api_url: &str) -> Result<Self> {
        let canonical_origin = canonical_https_origin(api_url)?;
        let state = open_fleet_admin_lock(&canonical_origin)?;
        FileExt::lock_exclusive(&state.file)
            .with_context(|| format!("lock fleet-administrator state for {canonical_origin}"))?;
        state.finish_acquire()
    }

    #[cfg(test)]
    pub(crate) fn try_acquire(api_url: &str) -> Result<Option<Self>> {
        let canonical_origin = canonical_https_origin(api_url)?;
        let state = open_fleet_admin_lock(&canonical_origin)?;
        match FileExt::try_lock_exclusive(&state.file) {
            Ok(()) => state.finish_acquire().map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error).with_context(|| {
                format!("try lock fleet-administrator state for {canonical_origin}")
            }),
        }
    }

    fn finish_acquire(self) -> Result<Self> {
        validate_fleet_admin_lock_file(&self.file, &self.canonical_origin)?;
        self.assert_current()?;
        #[cfg(test)]
        fleet_admin_after_lock_test_barrier()?;
        self.assert_current()?;
        Ok(self)
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        #[cfg(unix)]
        {
            self.root
                .assert_current()
                .context("fleet-administrator lock ancestor identity changed")?;
            validate_fleet_admin_lock_directory(&self.root.directory)?;
            anyhow::ensure!(
                FileIdentity::of(&self.file)? == self.lock_identity,
                "fleet-administrator lock descriptor changed identity"
            );
            let linked = identity_at(
                &self.root.directory,
                &self.lock_name,
                libc::AT_SYMLINK_NOFOLLOW,
            )
            .context("resolve current fleet-administrator lock identity")?;
            anyhow::ensure!(
                linked == self.lock_identity,
                "fleet-administrator lock path was unlinked or replaced"
            );
        }
        #[cfg(not(unix))]
        {
            let metadata = fs::symlink_metadata(&self.lock_path)
                .with_context(|| format!("inspect lock {}", self.lock_path.display()))?;
            anyhow::ensure!(
                metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
                "fleet-administrator lock {} was replaced",
                self.lock_path.display()
            );
        }
        validate_fleet_admin_lock_file(&self.file, &self.canonical_origin)
    }

    pub(crate) fn load_credentials(
        &self,
        raw_api_url: &str,
    ) -> Result<Option<FleetAdminCredentials>> {
        self.ensure_origin(raw_api_url)?;
        let canonical_account = FleetAdminCredentials::account(&self.canonical_origin);
        let canonical = self.checked_get_account(&canonical_account)?;
        if raw_api_url == self.canonical_origin {
            return canonical
                .map(|encoded| FleetAdminCredentials::decode(&encoded))
                .transpose();
        }

        let legacy_account = FleetAdminCredentials::account(raw_api_url);
        let legacy = self.checked_get_account(&legacy_account)?;
        let canonical = match (canonical, legacy) {
            (Some(canonical), Some(legacy)) => {
                anyhow::ensure!(
                    canonical == legacy,
                    "canonical and legacy fleet-administrator credentials disagree; refusing to choose one rotating refresh token"
                );
                self.checked_delete_account(&legacy_account)?;
                anyhow::ensure!(
                    self.checked_get_account(&legacy_account)?.is_none(),
                    "legacy fleet-administrator credential remained after deletion"
                );
                Some(canonical)
            }
            (Some(canonical), None) => Some(canonical),
            (None, Some(legacy)) => {
                self.checked_set_account(&canonical_account, &legacy)?;
                anyhow::ensure!(
                    self.checked_get_account(&canonical_account)?.as_deref()
                        == Some(legacy.as_str()),
                    "canonical fleet-administrator credential did not persist exact legacy bytes"
                );
                self.checked_delete_account(&legacy_account)?;
                anyhow::ensure!(
                    self.checked_get_account(&legacy_account)?.is_none(),
                    "legacy fleet-administrator credential remained after migration"
                );
                Some(legacy)
            }
            (None, None) => None,
        };
        canonical
            .map(|encoded| FleetAdminCredentials::decode(&encoded))
            .transpose()
    }

    pub(crate) fn save_credentials(&self, credentials: &FleetAdminCredentials) -> Result<()> {
        let account = FleetAdminCredentials::account(&self.canonical_origin);
        let encoded = credentials.encode()?;
        self.checked_set_account(&account, &encoded)?;
        anyhow::ensure!(
            self.checked_get_account(&account)?.as_deref() == Some(encoded.as_str()),
            "fleet-administrator credential store did not retain exact replacement bytes"
        );
        Ok(())
    }

    pub(crate) fn delete_credentials(&self) -> Result<()> {
        let account = FleetAdminCredentials::account(&self.canonical_origin);
        self.checked_delete_account(&account)?;
        anyhow::ensure!(
            self.checked_get_account(&account)?.is_none(),
            "fleet-administrator credential remained after deletion"
        );
        Ok(())
    }

    fn ensure_origin(&self, raw_api_url: &str) -> Result<()> {
        anyhow::ensure!(
            canonical_https_origin(raw_api_url)? == self.canonical_origin,
            "fleet-administrator credential operation used a different API origin"
        );
        Ok(())
    }

    fn checked_get_account(&self, account: &str) -> Result<Option<String>> {
        self.assert_current()?;
        let result = crate::credential_store::get(KEYRING_SERVICE, account);
        self.assert_current()?;
        result
    }

    fn checked_set_account(&self, account: &str, encoded: &str) -> Result<()> {
        self.assert_current()?;
        let result = crate::credential_store::set(KEYRING_SERVICE, account, encoded);
        self.assert_current()?;
        result
    }

    fn checked_delete_account(&self, account: &str) -> Result<()> {
        self.assert_current()?;
        let result = crate::credential_store::delete(KEYRING_SERVICE, account);
        self.assert_current()?;
        result
    }
}

fn open_fleet_admin_lock(canonical_origin: &str) -> Result<FleetAdminStateLock> {
    let root_path = fleet_admin_lock_root()?;
    open_fleet_admin_lock_in(&root_path, canonical_origin)
}

fn open_fleet_admin_lock_in(
    root_path: &Path,
    canonical_origin: &str,
) -> Result<FleetAdminStateLock> {
    anyhow::ensure!(
        canonical_https_origin(canonical_origin)? == canonical_origin,
        "fleet-administrator lock input is not canonical"
    );

    #[cfg(unix)]
    {
        let root = StableDirectory::open_or_create(root_path)
            .context("open stable fleet-administrator lock directory")?;
        validate_fleet_admin_lock_directory(&root.directory).with_context(|| {
            format!(
                "validate fleet-administrator lock directory {}",
                root_path.display()
            )
        })?;
        let lock_name =
            std::ffi::CString::new(fleet_admin_lock_filename_canonical(canonical_origin))
                .context("fleet-administrator lock name contains NUL")?;
        let (file, created) = match open_file_at(
            &root.directory,
            &lock_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                open_file_at(&root.directory, &lock_name, libc::O_RDWR, 0)
                    .context("open existing fleet-administrator lock")?,
                false,
            ),
            Err(error) => return Err(error).context("create fleet-administrator lock"),
        };
        validate_fleet_admin_lock_file(&file, canonical_origin)?;
        if created {
            root.directory
                .sync_all()
                .context("sync fleet-administrator lock directory")?;
        }
        let lock_identity = FileIdentity::of(&file)?;
        Ok(FleetAdminStateLock {
            file,
            canonical_origin: canonical_origin.to_owned(),
            root,
            lock_name,
            lock_identity,
        })
    }

    #[cfg(not(unix))]
    {
        ensure_fleet_admin_lock_directory(root_path)?;
        let lock_path = root_path.join(fleet_admin_lock_filename_canonical(canonical_origin));
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) => anyhow::ensure!(
                metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
                "fleet-administrator lock {} must be a non-symlink regular file",
                lock_path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect lock file {}", lock_path.display()));
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open {}", lock_path.display()))?;
        validate_fleet_admin_lock_file(&file, canonical_origin)?;
        Ok(FleetAdminStateLock {
            file,
            canonical_origin: canonical_origin.to_owned(),
            lock_path,
        })
    }
}

fn fleet_admin_lock_root() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("CATS_TEST_FLEET_ADMIN_LOCK_ROOT") {
        let path = PathBuf::from(path);
        anyhow::ensure!(
            path.is_absolute(),
            "test fleet-administrator lock root must be absolute"
        );
        return Ok(path);
    }

    let project = ProjectDirs::from("run", "Cats", "cats")
        .context("cannot locate a stable per-user directory for fleet-administrator locks")?;
    let path = project.data_local_dir().join(ADMIN_LOCK_DIRECTORY);
    anyhow::ensure!(
        path.is_absolute(),
        "fleet-administrator lock directory is not absolute"
    );
    Ok(path)
}

fn fleet_admin_lock_filename_canonical(canonical_origin: &str) -> String {
    let account = FleetAdminCredentials::account(canonical_origin);
    let mut hasher = Sha256::new();
    hasher.update(ADMIN_LOCK_DOMAIN);
    hasher.update(account.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    format!("sha256-{hex}.lock")
}

#[cfg(test)]
pub(crate) fn fleet_admin_lock_filename(api_url: &str) -> Result<String> {
    Ok(fleet_admin_lock_filename_canonical(
        &canonical_https_origin(api_url)?,
    ))
}

#[cfg(not(unix))]
fn ensure_fleet_admin_lock_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("fleet-administrator lock directory has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create lock parent directory {}", parent.display()))?;

    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create lock directory {}", path.display()));
        }
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect lock directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "fleet-administrator lock directory {} must be a non-symlink directory",
        path.display()
    );
    Ok(())
}

fn validate_fleet_admin_lock_file(file: &std::fs::File, display: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect fleet-administrator lock for {display}"))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "fleet-administrator lock for {display} is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        anyhow::ensure!(
            metadata.uid() == effective_uid()
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == 0o600,
            "fleet-administrator lock for {display} must be an owned, single-link 0600 file"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_fleet_admin_lock_directory(directory: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = directory
        .metadata()
        .context("inspect fleet-administrator lock directory")?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == effective_uid()
            && metadata.mode() & 0o7777 == 0o700,
        "fleet-administrator lock directory must be an owned exact 0700 directory"
    );
    Ok(())
}

#[cfg(test)]
fn fleet_admin_after_lock_test_barrier() -> Result<()> {
    let Some(marker) = std::env::var_os("CATS_TEST_FLEET_ADMIN_AFTER_LOCK_MARKER") else {
        return Ok(());
    };
    let release = std::env::var_os("CATS_TEST_FLEET_ADMIN_AFTER_LOCK_RELEASE")
        .context("test fleet-administrator lock marker has no release path")?;
    fs::write(PathBuf::from(marker), b"locked")?;
    let release = PathBuf::from(release);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !release.exists() {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for fleet-administrator lock test release"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}

impl Drop for FleetAdminStateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

impl Drop for CliStateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub(crate) fn config_path() -> PathBuf {
    if let Some(directory) = std::env::var_os("CATS_CONFIG_DIR") {
        return PathBuf::from(directory).join("config.json");
    }
    ProjectDirs::from("run", "Cats", "cats")
        .map(|dirs| dirs.config_dir().join("config.json"))
        .unwrap_or_else(|| PathBuf::from(".cats-config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip_does_not_contain_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut config = StoredConfig::new(
            "https://cats.run".into(),
            "client_test".into(),
            "https://api.workos.com".into(),
        );
        config.user = Some(UserProfile {
            id: "user_123".into(),
            email: "cat@example.com".into(),
            name: Some("Cat".into()),
        });
        config.save_to(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("access_token"));
        assert!(!text.contains("refresh_token"));
        assert_eq!(
            StoredConfig::load_from(&path)
                .unwrap()
                .unwrap()
                .user
                .unwrap()
                .id,
            "user_123"
        );
    }

    #[test]
    fn legacy_workspace_cache_is_discarded_instead_of_inventing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(
            &path,
            br#"{
                "version": 1,
                "api_url": "https://cats.example",
                "workos_client_id": "client_test",
                "workos_api_base_url": "https://api.workos.com",
                "user": {"id": "user_old", "email": "old@example.com"},
                "current_workspace": "mutable-slug",
                "workspaces": [{
                    "slug": "mutable-slug",
                    "display_name": "Old",
                    "kind": "organization",
                    "organization_id": "org_old"
                }]
            }"#,
        )
        .unwrap();

        let config = StoredConfig::load_from(&path).unwrap().unwrap();
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.api_url, "https://cats.example");
        assert!(config.user.is_none());
        assert!(config.current_workspace.is_none());
        assert!(config.workspaces.is_empty());
    }

    #[test]
    fn fleet_admin_lock_namespace_is_origin_scoped_without_raw_url_paths() {
        let first = fleet_admin_lock_filename("https://control-a.example").unwrap();
        let second = fleet_admin_lock_filename("https://control-b.example").unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with("sha256-"));
        assert!(first.ends_with(".lock"));
        assert_eq!(first.len(), "sha256-".len() + 64 + ".lock".len());
        assert!(!first.contains("control-a"));
        assert!(!first.contains(['/', '\\', ':']));
    }

    #[test]
    fn fleet_admin_origin_canonicalization_unifies_equivalent_authorities() {
        assert_eq!(
            canonical_https_origin("https://CONTROL.example").unwrap(),
            "https://control.example"
        );
        assert_eq!(
            canonical_https_origin("https://control.example:443/").unwrap(),
            "https://control.example"
        );
        assert_eq!(
            fleet_admin_lock_filename("https://CONTROL.example").unwrap(),
            fleet_admin_lock_filename("https://control.example:443/").unwrap()
        );
        assert_ne!(
            fleet_admin_lock_filename("https://control.example").unwrap(),
            fleet_admin_lock_filename("https://control.example:8443/").unwrap()
        );
        for invalid in [
            "http://control.example",
            " https://control.example",
            "https://@control.example",
            "https://user@control.example",
            "https://control.example/path",
            "https://control.example/?query",
            "https://control.example/#fragment",
        ] {
            assert!(canonical_https_origin(invalid).is_err(), "{invalid}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn equivalent_origins_contend_while_distinct_origins_are_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap().join("locks");
        let first_origin = canonical_https_origin("https://CONTROL.example").unwrap();
        let equivalent_origin = canonical_https_origin("https://control.example:443/").unwrap();
        let distinct_origin = canonical_https_origin("https://control.example:8443/").unwrap();

        let first = open_fleet_admin_lock_in(&root, &first_origin).unwrap();
        FileExt::lock_exclusive(&first.file).unwrap();
        let equivalent = open_fleet_admin_lock_in(&root, &equivalent_origin).unwrap();
        assert_eq!(
            FileExt::try_lock_exclusive(&equivalent.file)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        let distinct = open_fleet_admin_lock_in(&root, &distinct_origin).unwrap();
        FileExt::try_lock_exclusive(&distinct.file).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fleet_admin_lock_rejects_symlink_and_hardlink_namespace_aliases() {
        use std::os::unix::fs::{symlink, OpenOptionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap().join("locks");
        drop(StableDirectory::open_or_create(&root).unwrap());
        let outside = directory.path().join("outside");
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true).mode(0o600);
        options.open(&outside).unwrap();

        let symlink_path = root.join(fleet_admin_lock_filename("https://symlink.example").unwrap());
        symlink(&outside, &symlink_path).unwrap();
        let error = open_fleet_admin_lock_in(&root, "https://symlink.example")
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("open existing fleet-administrator lock"),
            "{error}"
        );
        fs::remove_file(&symlink_path).unwrap();

        let hardlink_path =
            root.join(fleet_admin_lock_filename("https://hardlink.example").unwrap());
        fs::hard_link(&outside, &hardlink_path).unwrap();
        let error = open_fleet_admin_lock_in(&root, "https://hardlink.example")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("single-link 0600 file"), "{error}");
    }
}

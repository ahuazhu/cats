use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use cats_api::auth::{UserProfile, Workspace};

pub(crate) const DEFAULT_API_URL: &str = "https://cats.run";
const CONFIG_VERSION: u32 = 2;
const KEYRING_SERVICE: &str = "cats.run CLI";
const ADMIN_KEYRING_PREFIX: &str = "fleet-admin:";
const ADMIN_LOCK_DOMAIN: &[u8] = b"cats.fleet-admin-credential-lock.v1\0";
const ADMIN_LOCK_DIRECTORY: &str = "fleet-admin-credential-locks-v1";

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
#[derive(Clone, Serialize, Deserialize)]
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

    pub(crate) fn load(api_url: &str) -> Result<Option<Self>> {
        let encoded = match crate::credential_store::get(KEYRING_SERVICE, &Self::account(api_url))?
        {
            Some(value) => value,
            None => return Ok(None),
        };
        Ok(Some(serde_json::from_str(&encoded).context(
            "parse Cats fleet-administrator login from credential store",
        )?))
    }

    pub(crate) fn save(&self, api_url: &str) -> Result<()> {
        crate::credential_store::set(
            KEYRING_SERVICE,
            &Self::account(api_url),
            &serde_json::to_string(self)?,
        )
    }

    pub(crate) fn delete(api_url: &str) -> Result<()> {
        crate::credential_store::delete(KEYRING_SERVICE, &Self::account(api_url))
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
}

impl FleetAdminStateLock {
    /// Serialize every consumer of one rotating administrator credential.
    ///
    /// The credential-store account is global to the operating-system user,
    /// so its lock must not live below `CATS_CONFIG_DIR`. The lock filename is
    /// a domain-separated digest of that exact account string: arbitrary URL
    /// bytes cannot select a path, and different origins do not share a local
    /// namespace except under a SHA-256 collision.
    pub(crate) fn acquire(api_url: &str) -> Result<Self> {
        let (file, path) = open_fleet_admin_lock_file(api_url)?;
        FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", path.display()))?;
        Ok(Self { file })
    }

    #[cfg(test)]
    pub(crate) fn try_acquire(api_url: &str) -> Result<Option<Self>> {
        let (file, path) = open_fleet_admin_lock_file(api_url)?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(Self { file })),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error).with_context(|| format!("try lock {}", path.display())),
        }
    }
}

fn open_fleet_admin_lock_file(api_url: &str) -> Result<(std::fs::File, PathBuf)> {
    let root = fleet_admin_lock_root()?;
    open_fleet_admin_lock_file_in(&root, api_url)
}

fn open_fleet_admin_lock_file_in(root: &Path, api_url: &str) -> Result<(std::fs::File, PathBuf)> {
    ensure_fleet_admin_lock_directory(root)?;
    let path = root.join(fleet_admin_lock_filename(api_url));
    match fs::symlink_metadata(&path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "fleet-administrator lock {} must be a non-symlink regular file",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect lock file {}", path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    validate_fleet_admin_lock_file(&file, &path)?;
    Ok((file, path))
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

fn fleet_admin_lock_filename(api_url: &str) -> String {
    let account = FleetAdminCredentials::account(api_url);
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

fn ensure_fleet_admin_lock_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("fleet-administrator lock directory has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create lock parent directory {}", parent.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create lock directory {}", path.display()));
            }
        }
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect lock directory {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == current_effective_user_id()
                && metadata.mode() & 0o777 == 0o700,
            "fleet-administrator lock directory {} must be an owned, non-symlink 0700 directory",
            path.display()
        );
    }

    #[cfg(not(unix))]
    {
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create lock directory {}", path.display()));
            }
        }
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect lock directory {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "fleet-administrator lock directory {} must be a non-symlink directory",
            path.display()
        );
    }
    Ok(())
}

fn validate_fleet_admin_lock_file(file: &std::fs::File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect lock file {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "fleet-administrator lock {} is not a regular file",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        anyhow::ensure!(
            metadata.uid() == current_effective_user_id()
                && metadata.nlink() == 1
                && metadata.mode() & 0o777 == 0o600,
            "fleet-administrator lock {} must be an owned, single-link 0600 file",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn current_effective_user_id() -> u32 {
    // SAFETY: `geteuid` has no preconditions and only returns process state.
    unsafe { libc::geteuid() }
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
        let first = fleet_admin_lock_filename("https://control-a.example");
        let second = fleet_admin_lock_filename("https://control-b.example");
        assert_ne!(first, second);
        assert!(first.starts_with("sha256-"));
        assert!(first.ends_with(".lock"));
        assert_eq!(first.len(), "sha256-".len() + 64 + ".lock".len());
        assert!(!first.contains("control-a"));
        assert!(!first.contains(['/', '\\', ':']));
    }

    #[cfg(unix)]
    #[test]
    fn fleet_admin_lock_rejects_symlink_and_hardlink_namespace_aliases() {
        use std::os::unix::fs::{symlink, OpenOptionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("locks");
        ensure_fleet_admin_lock_directory(&root).unwrap();
        let outside = directory.path().join("outside");
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true).mode(0o600);
        options.open(&outside).unwrap();

        let symlink_path = root.join(fleet_admin_lock_filename("https://symlink.example"));
        symlink(&outside, &symlink_path).unwrap();
        let error = open_fleet_admin_lock_file_in(&root, "https://symlink.example")
            .unwrap_err()
            .to_string();
        assert!(error.contains("non-symlink regular file"), "{error}");
        fs::remove_file(&symlink_path).unwrap();

        let hardlink_path = root.join(fleet_admin_lock_filename("https://hardlink.example"));
        fs::hard_link(&outside, &hardlink_path).unwrap();
        let error = open_fleet_admin_lock_file_in(&root, "https://hardlink.example")
            .unwrap_err()
            .to_string();
        assert!(error.contains("single-link 0600 file"), "{error}");
    }
}

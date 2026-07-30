use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use cats_api::auth::{UserProfile, Workspace};

pub(crate) const DEFAULT_API_URL: &str = "https://cats.run";
const CONFIG_VERSION: u32 = 2;
const KEYRING_SERVICE: &str = "cats.run CLI";

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
}

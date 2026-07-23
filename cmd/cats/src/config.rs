use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use cats_api::auth::{UserProfile, Workspace};

pub const DEFAULT_API_URL: &str = "https://cats.run";
const CONFIG_VERSION: u32 = 1;
const KEYRING_SERVICE: &str = "cats.run CLI";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConfig {
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
    pub fn new(api_url: String, workos_client_id: String, workos_api_base_url: String) -> Self {
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

    pub fn load() -> Result<Option<Self>> {
        Self::load_from(&config_path())
    }

    fn load_from(path: &Path) -> Result<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let config: Self =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        anyhow::ensure!(
            config.version == CONFIG_VERSION,
            "unsupported Cats CLI config version {}",
            config.version
        );
        Ok(Some(config))
    }

    pub fn save(&self) -> Result<()> {
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

    pub fn clear_identity(&mut self) {
        self.user = None;
        self.current_workspace = None;
        self.workspaces.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_organization_id: Option<String>,
}

impl Credentials {
    pub fn load(api_url: &str) -> Result<Option<Self>> {
        let encoded = match crate::credential_store::get(KEYRING_SERVICE, api_url)? {
            Some(value) => value,
            None => return Ok(None),
        };
        Ok(Some(
            serde_json::from_str(&encoded).context("parse Cats login from credential store")?,
        ))
    }

    pub fn save(&self, api_url: &str) -> Result<()> {
        crate::credential_store::set(KEYRING_SERVICE, api_url, &serde_json::to_string(self)?)
    }

    pub fn delete(api_url: &str) -> Result<()> {
        crate::credential_store::delete(KEYRING_SERVICE, api_url)
    }
}

pub fn config_path() -> PathBuf {
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
}

//! OCI application deployment contracts.
//!
//! Cats accepts only digest-pinned image references. Registry credentials are
//! transient pull credentials: the control plane forwards them to the running
//! Guest Agent and never persists them in a resource, operation, or log.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Basic credentials used for one registry pull.
///
/// `password` may be a short-lived registry token. This type intentionally
/// avoids `Debug` so an enclosing request cannot accidentally log the secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct OciRegistryAuth {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for OciRegistryAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OciRegistryAuth")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Install or replace one named OCI application in a Cat.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeployOciRequest {
    /// Stable application name and systemd unit suffix.
    pub app: String,
    /// OCI/Docker registry reference pinned by `@sha256:<64 hex>`.
    pub image: String,
    /// Replaces the OCI image's Entrypoint + Cmd when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Values override duplicate environment names from the OCI config.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Optional one-pull registry credential. Never persisted by Cats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_auth: Option<OciRegistryAuth>,
}

impl fmt::Debug for DeployOciRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeployOciRequest")
            .field("app", &self.app)
            .field("image", &self.image)
            .field("command", &self.command)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("registry_auth", &self.registry_auth)
            .finish()
    }
}

/// The immutable identity and service state produced by a deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciDeployment {
    pub app: String,
    /// The digest from the caller's reference. This may identify an OCI index.
    pub image_digest: String,
    /// The platform-specific image manifest selected for this Guest.
    pub manifest_digest: String,
    pub service: String,
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_debug_output_redacts_credentials_and_environment_values() {
        let request = DeployOciRequest {
            app: "server".into(),
            image: "ghcr.io/acme/server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            command: Vec::new(),
            env: BTreeMap::from([("DATABASE_URL".into(), "secret-db-url".into())]),
            registry_auth: Some(OciRegistryAuth {
                username: "ci".into(),
                password: "secret-registry-token".into(),
            }),
        };
        let output = format!("{request:?}");
        assert!(output.contains("DATABASE_URL"));
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("secret-db-url"));
        assert!(!output.contains("secret-registry-token"));
    }
}

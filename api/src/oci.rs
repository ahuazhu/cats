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

/// The digest a caller pinned in `image`, without the `@`.
///
/// Cats accepts only digest-pinned references, which makes the digest part of
/// the request's identity: `(cat, app, digest)` names one deployment, so the
/// control plane can recognise a retry of the same deploy without reaching a
/// registry. Returns `None` for anything that is not a well-formed
/// `…@sha256:<64 lowercase hex>` suffix; the Guest performs the full reference
/// parse and reports the specific defect.
pub fn pinned_digest(image: &str) -> Option<&str> {
    let (_, digest) = image.rsplit_once('@')?;
    let hex = digest.strip_prefix("sha256:")?;
    let well_formed = hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || b"abcdef".contains(&b));
    well_formed.then_some(digest)
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

    const HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn pinned_digest_accepts_a_digest_reference_and_keeps_the_algorithm_prefix() {
        assert_eq!(
            pinned_digest(&format!("ghcr.io/acme/server@sha256:{HEX}")),
            Some(format!("sha256:{HEX}").as_str())
        );
        // A port in the registry host must not be mistaken for the digest.
        assert_eq!(
            pinned_digest(&format!("registry.local:5000/acme/server@sha256:{HEX}")),
            Some(format!("sha256:{HEX}").as_str())
        );
    }

    #[test]
    fn pinned_digest_rejects_references_that_do_not_name_one_immutable_image() {
        // A tag is not an identity: the same tag can resolve to new bytes.
        assert_eq!(pinned_digest("ghcr.io/acme/server:latest"), None);
        assert_eq!(pinned_digest("ghcr.io/acme/server"), None);
        // Malformed digests must not become idempotency keys.
        assert_eq!(pinned_digest("ghcr.io/acme/server@sha256:"), None);
        assert_eq!(pinned_digest("ghcr.io/acme/server@sha512:{HEX}"), None);
        assert_eq!(
            pinned_digest(&format!("ghcr.io/acme/server@sha256:{}", &HEX[..63])),
            None,
            "a 63-hex digest is short by one and must be rejected"
        );
        assert_eq!(
            pinned_digest(&format!("ghcr.io/acme/server@sha256:{HEX}a")),
            None,
            "a 65-hex digest is long by one and must be rejected"
        );
        assert_eq!(
            pinned_digest(&format!(
                "ghcr.io/acme/server@sha256:{}",
                HEX.to_uppercase()
            )),
            None,
            "uppercase hex would key two spellings of one digest apart"
        );
        assert_eq!(
            pinned_digest(&format!("ghcr.io/acme/server@sha256:{}g", &HEX[..63])),
            None,
            "non-hex characters must be rejected"
        );
    }
}

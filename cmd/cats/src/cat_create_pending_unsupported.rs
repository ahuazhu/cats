//! Non-Unix compile boundary for durable covered-mutation recovery.
//!
//! The shipped implementation requires descriptor-relative `openat`, nofollow,
//! durable directory barriers, and a process-wide file lock. Fail before any
//! mutation rather than silently weakening that recovery contract.

use std::path::PathBuf;

use anyhow::{bail, Result};

pub(crate) enum PreparedCatCreate {}

pub(crate) enum PreparedCatLifecycle {}

pub(crate) enum PreparedPersistentDiskCreate {}

pub(crate) enum PreparedPersistentDiskBinding {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistentDiskBindingAction {
    Attach,
    Detach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatLifecycleAction {
    Run,
    Suspend,
    Warm,
    Cold,
    Destroy,
}

impl CatLifecycleAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Suspend => "suspend",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Destroy => "destroy",
        }
    }
}

impl PersistentDiskBindingAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Detach => "detach",
        }
    }
}

impl PreparedCatCreate {
    pub(crate) fn prepare(_origin: &str, _workspace_id: &str, _body: &[u8]) -> Result<Self> {
        bail!(
            "durable Cat-create recovery is unavailable on this platform; no HTTP request was sent"
        )
    }

    pub(crate) fn prepare_existing(
        _origin: &str,
        _workspace_id: &str,
        _body: &[u8],
    ) -> Result<Option<Self>> {
        bail!(
            "durable Cat-create recovery is unavailable on this platform; no HTTP request was sent"
        )
    }

    pub(crate) fn origin(&self) -> &str {
        match *self {}
    }

    pub(crate) fn target(&self) -> &str {
        match *self {}
    }

    pub(crate) fn content_type(&self) -> &str {
        match *self {}
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        match *self {}
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>> {
        match *self {}
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        match *self {}
    }

    pub(crate) fn pending_path(&self) -> PathBuf {
        match *self {}
    }

    pub(crate) fn clear(&self) -> Result<()> {
        match *self {}
    }
}

impl PreparedCatLifecycle {
    pub(crate) fn prepare(
        _origin: &str,
        _workspace_id: &str,
        _cat_id: &str,
        _action: CatLifecycleAction,
    ) -> Result<Self> {
        bail!(
            "durable Cat-lifecycle recovery is unavailable on this platform; no HTTP request was sent"
        )
    }

    pub(crate) fn origin(&self) -> &str {
        match *self {}
    }

    pub(crate) fn target(&self) -> &str {
        match *self {}
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        match *self {}
    }

    pub(crate) fn workspace_id(&self) -> &str {
        match *self {}
    }

    pub(crate) fn cat_id(&self) -> &cats_api::runtime_reconciliation::Id {
        match *self {}
    }

    pub(crate) fn action(&self) -> CatLifecycleAction {
        match *self {}
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        match *self {}
    }

    pub(crate) fn pending_path(&self) -> PathBuf {
        match *self {}
    }

    pub(crate) fn clear(&self) -> Result<()> {
        match *self {}
    }
}

impl PreparedPersistentDiskCreate {
    pub(crate) fn prepare(_origin: &str, _workspace_id: &str, _body: &[u8]) -> Result<Self> {
        bail!(
            "durable PersistentDisk-create recovery is unavailable on this platform; no HTTP request was sent"
        )
    }

    pub(crate) fn origin(&self) -> &str {
        match *self {}
    }

    pub(crate) fn target(&self) -> &str {
        match *self {}
    }

    pub(crate) fn content_type(&self) -> &str {
        match *self {}
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        match *self {}
    }

    pub(crate) fn workspace_id(&self) -> &str {
        match *self {}
    }

    pub(crate) fn request(
        &self,
    ) -> Result<cats_api::persistent_disk::PersistentDiskCreateV1Request> {
        match *self {}
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>> {
        match *self {}
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        match *self {}
    }

    pub(crate) fn pending_path(&self) -> PathBuf {
        match *self {}
    }

    pub(crate) fn clear(&self) -> Result<()> {
        match *self {}
    }
}

impl PreparedPersistentDiskBinding {
    pub(crate) fn prepare(
        _origin: &str,
        _workspace_id: &str,
        _disk_id: &str,
        _action: PersistentDiskBindingAction,
        _body: &[u8],
    ) -> Result<Self> {
        bail!(
            "durable PersistentDisk-binding recovery is unavailable on this platform; no HTTP request was sent"
        )
    }

    pub(crate) fn origin(&self) -> &str {
        match *self {}
    }

    pub(crate) fn target(&self) -> &str {
        match *self {}
    }

    pub(crate) fn content_type(&self) -> &str {
        match *self {}
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        match *self {}
    }

    pub(crate) fn workspace_id(&self) -> &str {
        match *self {}
    }

    pub(crate) fn disk_id(&self) -> &cats_api::runtime_reconciliation::Id {
        match *self {}
    }

    pub(crate) fn action(&self) -> PersistentDiskBindingAction {
        match *self {}
    }

    pub(crate) fn request(
        &self,
    ) -> Result<cats_api::persistent_disk::PersistentDiskBindingV2Request> {
        match *self {}
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>> {
        match *self {}
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        match *self {}
    }

    pub(crate) fn pending_path(&self) -> PathBuf {
        match *self {}
    }

    pub(crate) fn clear(&self) -> Result<()> {
        match *self {}
    }
}

pub(crate) fn canonical_api_origin(value: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(value).map_err(anyhow::Error::from)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_fails_before_request_materialization() {
        let error = PreparedCatCreate::prepare("https://cats.run", "ws_01", b"{}")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("no HTTP request was sent"));

        let error = PreparedPersistentDiskCreate::prepare("https://cats.run", "ws_01", b"{}")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("no HTTP request was sent"));

        let error = PreparedPersistentDiskBinding::prepare(
            "https://cats.run",
            "ws_01",
            "disk_01",
            PersistentDiskBindingAction::Attach,
            b"{}",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("no HTTP request was sent"));

        let error = PreparedCatLifecycle::prepare(
            "https://cats.run",
            "ws_01",
            "cat_01",
            CatLifecycleAction::Run,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("no HTTP request was sent"));
    }
}

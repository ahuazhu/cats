//! Strict public PersistentDisk create contract.
//!
//! The synchronous create mutation is one PostgreSQL transaction: it creates
//! the product Disk row, its exact blank Volume authority row, and the stored
//! HTTP result together.  Formatting and mounting are later runtime effects
//! and are deliberately absent from this request.

use serde::{Deserialize, Serialize};

use crate::chunk::MAX_VOLUME_BYTES;
use crate::runtime_reconciliation::{AsciiText, HostPath, Id, Sha256Digest, UnixMillis};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    Root,
    Persistent,
}

/// What a guest fsync acknowledgment promises for this disk (ADR-0021).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskDurability {
    /// fsync returns only once the data is durable in the object store; an
    /// acknowledged write survives losing the host outright.
    #[default]
    Strict,
    /// fsync returns after a local commit; data reaches the object store
    /// asynchronously and an unclean host loss may lose recent writes.
    Relaxed,
}

impl DiskDurability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Relaxed => "relaxed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "strict" => Some(Self::Strict),
            "relaxed" => Some(Self::Relaxed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskState {
    Creating,
    Available,
    Bound,
    Deleting,
    Deleted,
}

/// Public PersistentDisk product projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disk {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub kind: DiskKind,
    pub size_bytes: u64,
    pub state: DiskState,
    #[serde(default)]
    pub durability: DiskDurability,
    pub volume_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_cat_id: Option<String>,
    pub created_at_unix: i64,
}

pub const PERSISTENT_DISK_NAME_CONFLICT_BODY: &[u8] =
    br#"{"code":"already_exists","message":"disk name already exists"}"#;
pub const PERSISTENT_DISK_BINDING_CONFLICT_BODY: &[u8] =
    br#"{"code":"conflict","message":"disk binding does not match the requested Cat and mount path"}"#;
pub const PERSISTENT_DISK_BINDING_PRECONDITION_BODY: &[u8] =
    br#"{"code":"failed_precondition","message":"disk binding requires an exact settled Cold Cat and unowned PersistentDisk"}"#;
pub const PERSISTENT_DISK_BINDING_NOT_FOUND_BODY: &[u8] =
    br#"{"code":"not_found","message":"Cat or PersistentDisk not found"}"#;

/// Exact logical binding named by both clean-slate PersistentDisk actions.
///
/// Attach and detach intentionally use the same closed body.  Detach therefore
/// cannot remove a disk merely because the disk is currently bound somewhere:
/// it compares both the Cat and Guest mount path selected by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentDiskBindingV2Request {
    pub cat_id: Id,
    pub mount_path: HostPath,
}

impl PersistentDiskBindingV2Request {
    pub fn validate(&self) -> Result<(), PersistentDiskBindingV2Error> {
        if !self.cat_id.as_str().starts_with("cat_") {
            return Err(PersistentDiskBindingV2Error::CatId);
        }
        if self.mount_path.as_str() == "/" {
            return Err(PersistentDiskBindingV2Error::GuestRoot);
        }
        if AsciiText::new(self.mount_path.as_str().to_owned()).is_none() {
            return Err(PersistentDiskBindingV2Error::MountPath);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PersistentDiskBindingV2Error {
    #[error("cat_id must be an immutable Cat ID")]
    CatId,
    #[error("PersistentDisk mount_path cannot replace the Guest root filesystem")]
    GuestRoot,
    #[error("PersistentDisk mount_path must be 1..=512 printable ASCII bytes")]
    MountPath,
}

/// Exact committed current-config identity returned by both binding actions.
///
/// Binding is a synchronous product transaction while the Cat is terminal
/// Cold. It does not create a lifecycle Operation and is not mount-readiness
/// evidence; a later Start freezes this exact immutable config in its command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentDiskBindingV2CommittedResponse {
    pub cat_id: Id,
    pub disk_id: Id,
    pub runtime_config_id: Id,
    pub runtime_config_digest: Sha256Digest,
}

pub fn encode_persistent_disk_binding_v2_committed_response(
    response: &PersistentDiskBindingV2CommittedResponse,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(response)
}

pub fn decode_persistent_disk_binding_v2_committed_response(
    body: &[u8],
) -> Result<PersistentDiskBindingV2CommittedResponse, serde_json::Error> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let response = PersistentDiskBindingV2CommittedResponse::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(response)
}

/// Closed body for `POST /v1/workspaces/{workspace}/disks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentDiskCreateV1Request {
    pub durability: DiskDurability,
    pub name: Id,
    pub size_bytes: u64,
}

impl PersistentDiskCreateV1Request {
    pub fn validate(&self) -> Result<(), PersistentDiskCreateV1Error> {
        if !(1..=MAX_VOLUME_BYTES).contains(&self.size_bytes) {
            return Err(PersistentDiskCreateV1Error::SizeBytes);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PersistentDiskCreateV1Error {
    #[error("PersistentDisk size_bytes is outside the V1 range")]
    SizeBytes,
}

/// Build the established public [`Disk`] projection from the new authority
/// rows.  The initialization token and filesystem UUID remain internal
/// authority and never enter this product response.
pub fn persistent_disk_create_response(
    disk_id: &Id,
    workspace_id: &Id,
    name: &Id,
    volume_id: &Id,
    size_bytes: u64,
    durability: DiskDurability,
    created_at: UnixMillis,
) -> Disk {
    Disk {
        id: disk_id.to_string(),
        workspace_id: workspace_id.to_string(),
        name: name.to_string(),
        kind: DiskKind::Persistent,
        size_bytes,
        state: DiskState::Available,
        durability,
        volume_id: volume_id.to_string(),
        bound_cat_id: None,
        // UnixMillis is at most i64::MAX; dividing before the cast keeps this
        // conversion within i64 without a fallible response path.
        created_at_unix: (created_at.get() / 1_000) as i64,
    }
}

pub fn encode_persistent_disk_create_response(disk: &Disk) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(disk)
}

pub fn encode_persistent_disk_name_conflict_response() -> Vec<u8> {
    PERSISTENT_DISK_NAME_CONFLICT_BODY.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    #[test]
    fn request_is_closed_and_enforces_the_size_boundary() {
        let valid = br#"{"durability":"strict","name":"data","size_bytes":1073741824}"#;
        let request: PersistentDiskCreateV1Request = serde_json::from_slice(valid).unwrap();
        request.validate().unwrap();

        for invalid in [
            br#"{"durability":"strict","name":"data","size_bytes":0}"#.as_slice(),
            br#"{"durability":"strict","name":"data","size_bytes":1099511627777}"#,
        ] {
            let request: PersistentDiskCreateV1Request = serde_json::from_slice(invalid).unwrap();
            assert_eq!(
                request.validate(),
                Err(PersistentDiskCreateV1Error::SizeBytes)
            );
        }
        assert!(serde_json::from_slice::<PersistentDiskCreateV1Request>(
            br#"{"durability":"strict","name":"data","size_bytes":1,"unknown":true}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<PersistentDiskCreateV1Request>(
            br#"{"name":"data","size_bytes":1}"#
        )
        .is_err());
    }

    #[test]
    fn response_reuses_the_established_disk_shape_without_authority_secrets() {
        let response = persistent_disk_create_response(
            &id("disk_11111111111111111111111111111111"),
            &id("ws_01"),
            &id("data"),
            &id("vol_22222222222222222222222222222222"),
            1_073_741_824,
            DiskDurability::Strict,
            UnixMillis::new(1_720_000_000_123).unwrap(),
        );
        let encoded = encode_persistent_disk_create_response(&response).unwrap();
        assert_eq!(
            encoded,
            br#"{"id":"disk_11111111111111111111111111111111","workspace_id":"ws_01","name":"data","kind":"persistent","size_bytes":1073741824,"state":"available","durability":"strict","volume_id":"vol_22222222222222222222222222222222","created_at_unix":1720000000}"#
        );
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(!text.contains("initialization"));
        assert!(!text.contains("filesystem_uuid"));
    }

    #[test]
    fn binding_request_is_closed_and_uses_the_runtime_host_path_contract() {
        let request: PersistentDiskBindingV2Request =
            serde_json::from_slice(br#"{"cat_id":"cat_01","mount_path":"/srv/data"}"#).unwrap();
        request.validate().unwrap();
        assert_eq!(request.cat_id, id("cat_01"));
        assert_eq!(request.mount_path.as_str(), "/srv/data");

        for invalid in [
            br#"{"cat_id":"dev","mount_path":"/srv/data"}"#.as_slice(),
            br#"{"cat_id":"cat_01","mount_path":"relative"}"#.as_slice(),
            br#"{"cat_id":"cat_01","mount_path":"/srv/data","extra":true}"#.as_slice(),
            br#"{"cat_id":"cat_01"}"#.as_slice(),
        ] {
            if let Ok(request) = serde_json::from_slice::<PersistentDiskBindingV2Request>(invalid) {
                assert!(request.validate().is_err());
            }
        }
        let root: PersistentDiskBindingV2Request =
            serde_json::from_slice(br#"{"cat_id":"cat_01","mount_path":"/"}"#).unwrap();
        assert_eq!(
            root.validate(),
            Err(PersistentDiskBindingV2Error::GuestRoot)
        );

        let non_ascii: PersistentDiskBindingV2Request =
            serde_json::from_slice(br#"{"cat_id":"cat_01","mount_path":"/srv/\u6570\u636e"}"#)
                .unwrap();
        assert_eq!(
            non_ascii.validate(),
            Err(PersistentDiskBindingV2Error::MountPath)
        );
    }

    #[test]
    fn binding_committed_response_is_flat_strict_and_byte_stable() {
        let wire = br#"{"cat_id":"cat_01","disk_id":"disk_01","runtime_config_id":"cfg_02","runtime_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#;
        let committed = decode_persistent_disk_binding_v2_committed_response(wire).unwrap();
        assert_eq!(committed.cat_id, id("cat_01"));
        assert_eq!(committed.disk_id, id("disk_01"));
        assert_eq!(committed.runtime_config_id, id("cfg_02"));
        assert_eq!(
            encode_persistent_disk_binding_v2_committed_response(&committed).unwrap(),
            wire
        );
        assert!(decode_persistent_disk_binding_v2_committed_response(
            br#"{"cat_id":"cat_01","disk_id":"disk_01","runtime_config_id":"cfg_02","runtime_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","settled":true}"#,
        )
        .is_err());
        assert!(decode_persistent_disk_binding_v2_committed_response(
            br#"{"cat_id":"cat_01","disk_id":"disk_01","runtime_config_id":"cfg_02"}"#,
        )
        .is_err());
    }
}

//! Strict public PersistentDisk create contract.
//!
//! The synchronous create mutation is one PostgreSQL transaction: it creates
//! the product Disk row, its exact blank Volume authority row, and the stored
//! HTTP result together.  Formatting and mounting are later runtime effects
//! and are deliberately absent from this request.

use serde::{Deserialize, Serialize};

use crate::chunk::MAX_VOLUME_BYTES;
use crate::resources::{Disk, DiskDurability, DiskKind, DiskState};
use crate::runtime_reconciliation::{HostPath, Id, Revision, UnixMillis};

pub const PERSISTENT_DISK_NAME_CONFLICT_BODY: &[u8] =
    br#"{"code":"already_exists","message":"disk name already exists"}"#;
pub const PERSISTENT_DISK_BINDING_CONFLICT_BODY: &[u8] =
    br#"{"code":"conflict","message":"disk binding does not match the requested Cat and mount path"}"#;
pub const PERSISTENT_DISK_BINDING_PRECONDITION_BODY: &[u8] =
    br#"{"code":"failed_precondition","message":"disk binding requires an exact settled Cold Cat and unowned PersistentDisk"}"#;

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
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PersistentDiskBindingV2Error {
    #[error("cat_id must be an immutable Cat ID")]
    CatId,
    #[error("PersistentDisk mount_path cannot replace the Guest root filesystem")]
    GuestRoot,
}

/// Exact terminal acceptance returned by both PersistentDisk binding actions.
/// The Operation settles only after the successor complete Desired membership
/// is observed as stable Cold; acceptance is not mount-readiness evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentDiskBindingV2AcceptedResponse {
    pub desired_revision: Revision,
    pub operation_id: Id,
}

pub fn decode_persistent_disk_binding_v2_accepted_response(
    body: &[u8],
) -> Result<PersistentDiskBindingV2AcceptedResponse, serde_json::Error> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let response = PersistentDiskBindingV2AcceptedResponse::deserialize(&mut decoder)?;
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
    }

    #[test]
    fn binding_accepted_response_is_flat_strict_and_canonical() {
        let wire = br#"{"desired_revision":7,"operation_id":"op_01"}"#;
        let accepted = decode_persistent_disk_binding_v2_accepted_response(wire).unwrap();
        assert_eq!(accepted.desired_revision.get(), 7);
        assert_eq!(accepted.operation_id, id("op_01"));
        assert_eq!(serde_json::to_vec(&accepted).unwrap(), wire);
        assert!(decode_persistent_disk_binding_v2_accepted_response(
            br#"{"desired_revision":7,"operation_id":"op_01","settled":true}"#,
        )
        .is_err());
        assert!(decode_persistent_disk_binding_v2_accepted_response(
            br#"{"desired_revision":0,"operation_id":"op_01"}"#,
        )
        .is_err());
    }
}

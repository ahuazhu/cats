//! Closed root-provision handoff shared by the Node and serving blockd.
//!
//! A target-control authorization remains control-only.  This record binds
//! that immutable artifact to the exact provision checkpoint and exact old
//! control-process handshake which reached the generation-one target.  A
//! serving process must validate both files and the record's physical identity
//! before it may pass the embedded attachment to the data-plane engine.

use std::path::{Path, PathBuf};

use cats_api::runtime_reconciliation::{
    AcquireOrigin, ContractVersion, Durability, Epoch, FenceEpoch, HostPath, Id, RandomId128,
    RemoteHead, Revision, Sha256Digest, WireU64,
};
use cats_storage::authority::AttachmentLineageIdentity;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::target_control::{
    encode_target_control_authorization, target_control_authorization_file_name,
    validate_target_control_authorization, TargetControlAuthorizationArtifact,
    TargetControlAuthorizationCodecError,
};

const ARTIFACT: &str = "record";

pub const SERVING_HANDOFF_RECORD_FILE: &str = "serving-handoff.json";
pub const SERVING_HANDOFF_RECORD_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServingHandoffCodecError {
    #[error("serving handoff {artifact} exceeds {maximum} bytes")]
    WireBytesLimitExceeded {
        artifact: &'static str,
        maximum: usize,
    },
    #[error("serving handoff {artifact} is malformed")]
    Malformed { artifact: &'static str },
    #[error("serving handoff {artifact} is not in canonical JSON form")]
    NonCanonical { artifact: &'static str },
    #[error("serving handoff {artifact} violates its closed contract: {reason}")]
    Invalid {
        artifact: &'static str,
        reason: &'static str,
    },
}

impl From<TargetControlAuthorizationCodecError> for ServingHandoffCodecError {
    fn from(error: TargetControlAuthorizationCodecError) -> Self {
        match error {
            TargetControlAuthorizationCodecError::WireBytesLimitExceeded { artifact, maximum } => {
                Self::WireBytesLimitExceeded { artifact, maximum }
            }
            TargetControlAuthorizationCodecError::Malformed { artifact } => {
                Self::Malformed { artifact }
            }
            TargetControlAuthorizationCodecError::NonCanonical { artifact } => {
                Self::NonCanonical { artifact }
            }
            TargetControlAuthorizationCodecError::Invalid { artifact, reason } => {
                Self::Invalid { artifact, reason }
            }
        }
    }
}

/// Durable identity of the no-replace target-control authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetControlAuthorizationIdentity {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
    pub artifact: TargetControlAuthorizationArtifact,
}

impl TargetControlAuthorizationIdentity {
    pub fn path(&self) -> &HostPath {
        &self.path
    }

    pub fn device(&self) -> WireU64 {
        self.device
    }

    pub fn inode(&self) -> WireU64 {
        self.inode
    }

    pub fn length(&self) -> WireU64 {
        self.length
    }

    pub fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }
}

/// The exact target reload observed on the old control-only process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingControlReloadHandshake {
    pub peer_process_id: WireU64,
    pub identity: AttachmentLineageIdentity,
    pub size_bytes: u64,
    pub durability: Durability,
    pub remote_head: RemoteHead,
    pub process_identity_token: RandomId128,
    pub control_only: bool,
    pub guest_io_enabled: bool,
}

/// Complete physical identity of the old control process proven at handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingControlProcessIdentity {
    pub process_id: WireU64,
    pub unit_main_process_id: WireU64,
    pub process_start_time_ticks: WireU64,
    pub executable_path: HostPath,
    pub scope_id: Id,
    pub cgroup_path: HostPath,
    pub cgroup_process_ids: Vec<WireU64>,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub ownership_token: RandomId128,
    pub handshake: ServingControlReloadHandshake,
}

/// Immutable proof linking one target-control attempt to PrepareDevice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingHandoffRecord {
    pub version: ContractVersion,
    pub checkpoint_content_digest: Sha256Digest,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub provision_transition_id: RandomId128,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    pub node_id: Id,
    pub placement_epoch: Epoch,
    pub expected_provisioned_head: RemoteHead,
    pub expected_control_executable_path: HostPath,
    pub target_control_authorization: TargetControlAuthorizationIdentity,
    pub old_control_process: ServingControlProcessIdentity,
}

/// Content-addressed physical identity of the durable handoff record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingHandoffRecordIdentity {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
}

impl ServingHandoffRecordIdentity {
    pub fn path(&self) -> &HostPath {
        &self.path
    }

    pub fn device(&self) -> WireU64 {
        self.device
    }

    pub fn inode(&self) -> WireU64 {
        self.inode
    }

    pub fn length(&self) -> WireU64 {
        self.length
    }

    pub fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }
}

pub fn encode_serving_handoff_record(
    record: &ServingHandoffRecord,
) -> Result<Vec<u8>, ServingHandoffCodecError> {
    validate_serving_handoff_record(record)?;
    canonical_encode(record)
}

pub fn decode_serving_handoff_record(
    bytes: &[u8],
) -> Result<ServingHandoffRecord, ServingHandoffCodecError> {
    canonical_decode(bytes, validate_serving_handoff_record)
}

pub fn validate_serving_handoff_record(
    record: &ServingHandoffRecord,
) -> Result<(), ServingHandoffCodecError> {
    let target_artifact = &record.target_control_authorization.artifact;
    validate_target_control_authorization(target_artifact)?;
    let attachment = &target_artifact.attachment;
    let target_bytes = encode_target_control_authorization(target_artifact)?;
    let target_digest = Sha256Digest::from_bytes(Sha256::digest(&target_bytes).into());
    let identity = &attachment.identity;
    let Some((acquire_request, _)) = attachment.normal_acquire() else {
        return Err(ServingHandoffCodecError::Invalid {
            artifact: ARTIFACT,
            reason: "root serving handoff requires one normal acquire",
        });
    };
    let process = &record.old_control_process;
    let handshake = &process.handshake;
    let expected_cgroup = format!("/sys/fs/cgroup/system.slice/{}", process.scope_id.as_str());
    let artifact_path = Path::new(record.target_control_authorization.path.as_str());
    let process_directory = Path::new(process.data_directory.as_str());
    let expected_directory_suffix = PathBuf::from("data")
        .join(format!("cat-{}", record.cat_id.as_str()))
        .join(format!("volume-{}", record.volume_id.as_str()))
        .join(format!("attachment-{}", record.attachment_id.as_str()))
        .join(format!("epoch-{}", record.attachment_epoch.get()));
    let expected_control_socket = process_directory.join("root-provision.sock");
    let expected_artifact_name =
        target_control_authorization_file_name(&record.provision_transition_id);
    if record.version != ContractVersion::V1
        || target_artifact.version != record.version
        || target_artifact.provision_transition_id != record.provision_transition_id
        || record.volume_id != identity.volume_id
        || record.attachment_id != identity.attachment_id
        || record.attachment_epoch != identity.attachment_epoch
        || record.acquire_origin != identity.acquire_origin
        || record.node_id != identity.node_id
        || record.placement_epoch != identity.placement_epoch
        || record.desired_revision != acquire_request.desired_revision
        || record.placement_epoch != acquire_request.placement_epoch
        || record.expected_provisioned_head != attachment.head
        || record.expected_control_executable_path != process.executable_path
        || target_artifact.runtime_scope_id != process.scope_id
        || target_artifact.control_socket_path != process.control_socket_path
        || record.target_control_authorization.device
            != target_artifact.local_state.attachment_directory.device
        || record.target_control_authorization.inode.get() == 0
        || record.target_control_authorization.length.get() != target_bytes.len() as u64
        || record.target_control_authorization.content_sha256 != target_digest
        || process.process_id.get() == 0
        || process.unit_main_process_id != process.process_id
        || process.process_start_time_ticks.get() == 0
        || process.cgroup_process_ids != [process.process_id]
        || process.cgroup_path.as_str() != expected_cgroup
        || !process_directory.ends_with(&expected_directory_suffix)
        || Path::new(process.control_socket_path.as_str()) != expected_control_socket
        || process.ownership_token != handshake.process_identity_token
        || process.process_id != handshake.peer_process_id
        || handshake.identity != *identity
        || handshake.size_bytes != attachment.size_bytes
        || handshake.durability != attachment.durability
        || handshake.remote_head != attachment.head
        || !handshake.control_only
        || handshake.guest_io_enabled
        || artifact_path.file_name().and_then(|name| name.to_str())
            != Some(expected_artifact_name.as_str())
        || artifact_path.parent() != Some(process_directory)
        || process_directory
            != Path::new(
                target_artifact
                    .local_state
                    .attachment_directory
                    .path
                    .as_str(),
            )
    {
        return Err(ServingHandoffCodecError::Invalid {
            artifact: ARTIFACT,
            reason: "record fields do not form one exact serving handoff",
        });
    }
    Ok(())
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ServingHandoffCodecError> {
    let value = serde_json::to_value(value)
        .map_err(|_| ServingHandoffCodecError::Malformed { artifact: ARTIFACT })?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)
        .map_err(|_| ServingHandoffCodecError::Malformed { artifact: ARTIFACT })?;
    if bytes.len() > SERVING_HANDOFF_RECORD_MAX_BYTES {
        return Err(ServingHandoffCodecError::WireBytesLimitExceeded {
            artifact: ARTIFACT,
            maximum: SERVING_HANDOFF_RECORD_MAX_BYTES,
        });
    }
    Ok(bytes)
}

fn canonical_decode<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ServingHandoffCodecError>,
) -> Result<T, ServingHandoffCodecError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > SERVING_HANDOFF_RECORD_MAX_BYTES {
        return Err(ServingHandoffCodecError::WireBytesLimitExceeded {
            artifact: ARTIFACT,
            maximum: SERVING_HANDOFF_RECORD_MAX_BYTES,
        });
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| ServingHandoffCodecError::Malformed { artifact: ARTIFACT })?;
    validate(&value)?;
    if canonical_encode(&value)? != bytes {
        return Err(ServingHandoffCodecError::NonCanonical { artifact: ARTIFACT });
    }
    Ok(value)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> serde_json::Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => serde_json::to_writer(output, string)?,
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(members) => {
            output.push(b'{');
            let mut keys = members.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_json(&members[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_SERVING_HANDOFF_RECORD_FILE: &[u8] =
        include_bytes!("../tests/fixtures/serving-handoff-v1.json");

    fn fixed_serving_handoff_record() -> &'static [u8] {
        FIXED_SERVING_HANDOFF_RECORD_FILE
            .strip_suffix(b"\n")
            .expect("fixture file has its source newline")
    }

    #[test]
    fn fixed_serving_handoff_record_bytes_are_stable() {
        let fixed = fixed_serving_handoff_record();
        let decoded =
            decode_serving_handoff_record(fixed).expect("fixed serving handoff record decodes");
        assert_eq!(decoded.version, ContractVersion::V1);
        assert_eq!(decoded.cat_id.as_str(), "cat_01");
        assert_eq!(decoded.volume_id.as_str(), "vol_root");
        assert_eq!(decoded.attachment_id.as_str(), "att_root");
        assert_eq!(decoded.attachment_epoch.get(), 7);
        assert_eq!(
            decoded.checkpoint_content_digest.as_str(),
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(encode_serving_handoff_record(&decoded).unwrap(), fixed);
    }

    #[test]
    fn serving_handoff_decoder_is_bounded_canonical_and_closed() {
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(fixed_serving_handoff_record());
        assert!(matches!(
            decode_serving_handoff_record(&noncanonical),
            Err(ServingHandoffCodecError::NonCanonical { .. })
        ));
        assert!(matches!(
            decode_serving_handoff_record(&vec![b' '; SERVING_HANDOFF_RECORD_MAX_BYTES + 1]),
            Err(ServingHandoffCodecError::WireBytesLimitExceeded { .. })
        ));

        let mut unknown = serde_json::from_slice::<Value>(fixed_serving_handoff_record()).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        let mut unknown_bytes = Vec::new();
        write_canonical_json(&unknown, &mut unknown_bytes).unwrap();
        assert!(matches!(
            decode_serving_handoff_record(&unknown_bytes),
            Err(ServingHandoffCodecError::Malformed { .. })
        ));

        let mut wrong_target_digest =
            decode_serving_handoff_record(fixed_serving_handoff_record()).unwrap();
        wrong_target_digest
            .target_control_authorization
            .content_sha256 = Sha256Digest::from_bytes([0; 32]);
        assert!(matches!(
            encode_serving_handoff_record(&wrong_target_digest),
            Err(ServingHandoffCodecError::Invalid { .. })
        ));
    }
}

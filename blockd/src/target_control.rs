//! Closed target-head control authorization shared by the Node and blockd.
//!
//! This artifact may restart or adopt only a `control_only` blockd after an
//! exact root-provision transition reached its generation-one target.  It is
//! not a serving grant and does not authorize a Guest frontend.

use std::path::{Component, Path};

use cats_api::runtime_reconciliation::{
    ContractVersion, HostPath, RandomId128, Sha256Digest, WireU64,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, AuthorizedServingAttachment,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const ARTIFACT: &str = "target authorization";
const ATTACHMENT_IDENTITY_FILE: &str = "identity.json";
const ACQUIRE_AUTHORIZATION_FILE: &str = "authorized-serving.json";
const LAUNCH_CHECKPOINT_FILE: &str = "launch-checkpoint.json";
const MAX_LAUNCH_CHECKPOINT_BYTES: u64 = 512 * 1024;

pub const TARGET_CONTROL_AUTHORIZATION_MAX_BYTES: usize = 32 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TargetControlAuthorizationCodecError {
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

/// Canonical bytes consumed only by a target-head `control_only` blockd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetControlAuthorizationArtifact {
    pub version: ContractVersion,
    pub provision_transition_id: RandomId128,
    pub checkpoint_content_digest: Sha256Digest,
    pub local_state: TargetControlLocalStateIdentity,
    pub attachment: AuthorizedServingAttachment,
}

/// Stable local identities retained by the Node when it sealed the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetControlLocalStateIdentity {
    pub state_directory: StableDirectoryIdentity,
    pub attachment_directory: StableDirectoryIdentity,
    pub attachment_identity_file: StableFileIdentity,
    pub acquire_authorization_file: StableFileIdentity,
    pub launch_checkpoint_file: StableFileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableDirectoryIdentity {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableFileIdentity {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
}

pub fn target_control_authorization_file_name(provision_transition_id: &RandomId128) -> String {
    format!(
        "authorized-target-control-{}.json",
        provision_transition_id.as_str()
    )
}

pub fn encode_target_control_authorization(
    artifact: &TargetControlAuthorizationArtifact,
) -> Result<Vec<u8>, TargetControlAuthorizationCodecError> {
    validate_target_control_authorization(artifact)?;
    canonical_encode(artifact)
}

pub fn decode_target_control_authorization(
    bytes: &[u8],
) -> Result<TargetControlAuthorizationArtifact, TargetControlAuthorizationCodecError> {
    canonical_decode(bytes, validate_target_control_authorization)
}

pub fn validate_target_control_authorization(
    artifact: &TargetControlAuthorizationArtifact,
) -> Result<(), TargetControlAuthorizationCodecError> {
    validate_target_control_attachment(&artifact.attachment)?;
    validate_local_state_identity(&artifact.local_state, &artifact.attachment)?;
    if artifact.version != ContractVersion::V1 {
        return Err(invalid("version is not the exact supported contract"));
    }
    Ok(())
}

pub fn validate_target_control_attachment(
    attachment: &AuthorizedServingAttachment,
) -> Result<(), TargetControlAuthorizationCodecError> {
    validate_authorized_serving_attachment(attachment)
        .map_err(|_| invalid("authorized serving attachment is not internally closed"))?;
    if attachment.head.generation.get() != 1
        || attachment.head.root_hash.is_none()
        || attachment.head.root_object_id.is_none()
    {
        return Err(invalid("head is not exact generation one"));
    }
    Ok(())
}

fn validate_local_state_identity(
    local: &TargetControlLocalStateIdentity,
    attachment: &AuthorizedServingAttachment,
) -> Result<(), TargetControlAuthorizationCodecError> {
    let state_path = Path::new(local.state_directory.path.as_str());
    let attachment_path = Path::new(local.attachment_directory.path.as_str());
    let strict_descendant = attachment_path
        .strip_prefix(state_path)
        .is_ok_and(|relative| {
            relative.components().next().is_some()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
        });
    let expected_identity_path = attachment_path.join(ATTACHMENT_IDENTITY_FILE);
    let expected_blank_path = attachment_path.join(ACQUIRE_AUTHORIZATION_FILE);
    let expected_launch_path = attachment_path.join(LAUNCH_CHECKPOINT_FILE);
    let identity_bytes = serde_json::to_vec(&attachment.identity).map_err(|_| malformed())?;
    let mut blank_attachment = attachment.clone();
    blank_attachment.head = attachment.acquire_result.resulting_head.clone();
    let blank_bytes = serde_json::to_vec(&blank_attachment).map_err(|_| malformed())?;
    let identity_digest = Sha256Digest::from_bytes(Sha256::digest(&identity_bytes).into());
    let blank_digest = Sha256Digest::from_bytes(Sha256::digest(&blank_bytes).into());
    if !strict_descendant
        || local.state_directory.inode.get() == 0
        || local.attachment_directory.inode.get() == 0
        || Path::new(local.attachment_identity_file.path.as_str()) != expected_identity_path
        || Path::new(local.acquire_authorization_file.path.as_str()) != expected_blank_path
        || Path::new(local.launch_checkpoint_file.path.as_str()) != expected_launch_path
        || local.attachment_identity_file.inode.get() == 0
        || local.acquire_authorization_file.inode.get() == 0
        || local.launch_checkpoint_file.inode.get() == 0
        || local.attachment_identity_file.device != local.attachment_directory.device
        || local.acquire_authorization_file.device != local.attachment_directory.device
        || local.launch_checkpoint_file.device != local.attachment_directory.device
        || local.attachment_identity_file.length.get() != identity_bytes.len() as u64
        || local.acquire_authorization_file.length.get() != blank_bytes.len() as u64
        || local.launch_checkpoint_file.length.get() == 0
        || local.launch_checkpoint_file.length.get() > MAX_LAUNCH_CHECKPOINT_BYTES
        || local.attachment_identity_file.content_sha256 != identity_digest
        || local.acquire_authorization_file.content_sha256 != blank_digest
        || !exact_blank_head(&blank_attachment)
    {
        return Err(invalid(
            "retained local state identities are not one closed attachment",
        ));
    }
    Ok(())
}

fn exact_blank_head(attachment: &AuthorizedServingAttachment) -> bool {
    let head = &attachment.head;
    head.generation.get() == 0 && head.root_hash.is_none() && head.root_object_id.is_none()
}

fn canonical_encode<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, TargetControlAuthorizationCodecError> {
    let value = serde_json::to_value(value).map_err(|_| malformed())?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes).map_err(|_| malformed())?;
    if bytes.len() > TARGET_CONTROL_AUTHORIZATION_MAX_BYTES {
        return Err(
            TargetControlAuthorizationCodecError::WireBytesLimitExceeded {
                artifact: ARTIFACT,
                maximum: TARGET_CONTROL_AUTHORIZATION_MAX_BYTES,
            },
        );
    }
    Ok(bytes)
}

fn canonical_decode<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), TargetControlAuthorizationCodecError>,
) -> Result<T, TargetControlAuthorizationCodecError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > TARGET_CONTROL_AUTHORIZATION_MAX_BYTES {
        return Err(
            TargetControlAuthorizationCodecError::WireBytesLimitExceeded {
                artifact: ARTIFACT,
                maximum: TARGET_CONTROL_AUTHORIZATION_MAX_BYTES,
            },
        );
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| malformed())?;
    validate(&value)?;
    if canonical_encode(&value)? != bytes {
        return Err(TargetControlAuthorizationCodecError::NonCanonical { artifact: ARTIFACT });
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

fn malformed() -> TargetControlAuthorizationCodecError {
    TargetControlAuthorizationCodecError::Malformed { artifact: ARTIFACT }
}

fn invalid(reason: &'static str) -> TargetControlAuthorizationCodecError {
    TargetControlAuthorizationCodecError::Invalid {
        artifact: ARTIFACT,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_TARGET_CONTROL_AUTHORIZATION: &[u8] = br#"{"attachment":{"acquire_request":{"attachment_id":"att_root","desired_revision":11,"expected_unowned_epoch":6,"lease_duration_ms":60000,"placement_epoch":3,"transition_id":"11111111111111111111111111111111","volume_id":"vol_root"},"acquire_result":{"attachment_id":"att_root","lease_expires_at":1720000060000,"resulting_epoch":7,"resulting_head":{"generation":0,"root_hash":null,"root_object_id":null},"transition_id":"11111111111111111111111111111111","volume_id":"vol_root"},"durability":"strict","head":{"generation":1,"root_hash":"sha256:0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d","root_object_id":"roots/generation-1.node"},"identity":{"acquire_origin":{"kind":"normal","transition_id":"11111111111111111111111111111111"},"attachment_epoch":7,"attachment_id":"att_root","node_id":"node_a","placement_epoch":3,"volume_id":"vol_root"},"lease_expires_at":1720000060000,"size_bytes":4194304},"checkpoint_content_digest":"sha256:0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","local_state":{"acquire_authorization_file":{"content_sha256":"sha256:7f8916bf692fad3e61120f4033f131c621fe15a8eda5e39927df5f3368616380","device":41,"inode":45,"length":811,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/authorized-serving.json"},"attachment_directory":{"device":41,"inode":43,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7"},"attachment_identity_file":{"content_sha256":"sha256:3e32061ef92bb54f78dd7191aa9271ac07a6f4012ec5d333e04402eef00e0d9d","device":41,"inode":44,"length":197,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/identity.json"},"launch_checkpoint_file":{"content_sha256":"sha256:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","device":41,"inode":46,"length":1024,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/launch-checkpoint.json"},"state_directory":{"device":41,"inode":42,"path":"/var/lib/cats/node/state_path_a"}},"provision_transition_id":"33333333333333333333333333333333","version":1}"#;

    #[test]
    fn fixed_target_control_authorization_bytes_are_stable() {
        let decoded = decode_target_control_authorization(FIXED_TARGET_CONTROL_AUTHORIZATION)
            .expect("fixed target-control authorization decodes");
        assert_eq!(decoded.version, ContractVersion::V1);
        assert_eq!(
            decoded.provision_transition_id.as_str(),
            "33333333333333333333333333333333"
        );
        assert_eq!(decoded.attachment.head.generation.get(), 1);
        assert_eq!(
            encode_target_control_authorization(&decoded).unwrap(),
            FIXED_TARGET_CONTROL_AUTHORIZATION
        );
    }
}

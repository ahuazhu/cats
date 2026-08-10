//! Closed target-head control authorization shared by the Node and blockd.
//!
//! This artifact may restart or adopt only a `control_only` blockd after an
//! exact root-provision transition reached its generation-one target.  It is
//! not a serving grant and does not authorize a Guest frontend.

use std::path::{Component, Path};

use cats_api::runtime_reconciliation::{
    CheckpointRouteGate, ContractVersion, Epoch, FenceEpoch, GuestTransportEvidence, HostPath, Id,
    LifecycleAdmission, ObservedMount, ObservedNetwork, ObservedVolume, ProcessEvidence,
    ProvisionRootImageRequest, RandomId128, ReconcileStep, RemoteHead, RequireIdleCheckpoint,
    Revision, RuntimeCheckpoint, Sha256Digest, StableState, WarmSnapshotEvidence, WireU64,
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
const PROVISION_ROOT_AUTHORIZATION_CONTEXT_DOMAIN: &[u8] =
    b"cats.runtime.provision-root-authorization-context.v1";

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
    pub request: ProvisionRootImageRequest,
    pub provision_context_digest: ProvisionRootAuthorizationContextDigest,
    pub runtime_scope_id: Id,
    pub control_socket_path: HostPath,
    pub local_state: TargetControlLocalStateIdentity,
    pub attachment: AuthorizedServingAttachment,
}

/// Stable authorization context for a root-provision retry.
///
/// This digest deliberately excludes the checkpoint timestamp and process
/// identity token. Runtime Reconciliation v1 permits a retry after exact
/// process absence to rotate only that token while preserving every other
/// checkpoint field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProvisionRootAuthorizationContextDigest(Sha256Digest);

impl ProvisionRootAuthorizationContextDigest {
    pub fn new(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub fn as_sha256_digest(&self) -> &Sha256Digest {
        &self.0
    }
}

/// Computes the stable RuntimeCheckpoint authorization context.
pub fn provision_root_authorization_context_digest(
    checkpoint: &RuntimeCheckpoint,
) -> Result<ProvisionRootAuthorizationContextDigest, TargetControlAuthorizationCodecError> {
    let RuntimeCheckpoint {
        version,
        cat_id,
        node_id,
        placement_epoch,
        desired_revision,
        spec_digest,
        runtime_incarnation,
        stable_state,
        step,
        processes,
        volumes,
        mounts,
        networks,
        guest_transport,
        warm_snapshot,
        lifecycle_admission,
        route_gates,
        require_idle,
        updated_at_unix_ms: _,
    } = checkpoint;
    let ReconcileStep::ProvisionRootImage {
        provision_transition_id,
        volume_id,
        attachment_id,
        attachment_epoch,
        scope_id,
        control_socket_path,
        data_directory,
        process_identity_token: _,
        size_bytes,
        boot_image_digest,
        expected_blank_head,
        expected_provisioned_head,
    } = step
    else {
        return Err(invalid(
            "provision authorization context requires provision_root_image",
        ));
    };
    if runtime_incarnation.is_some() || stable_state.is_some() {
        return Err(invalid(
            "provision authorization context requires an unstable runtime",
        ));
    }
    let value = serde_json::to_value(ProvisionRootAuthorizationContext {
        version: *version,
        cat_id,
        node_id,
        placement_epoch: *placement_epoch,
        desired_revision: *desired_revision,
        spec_digest,
        runtime_incarnation,
        stable_state,
        step: ProvisionRootAuthorizationStep {
            kind: "provision_root_image",
            provision_transition_id,
            volume_id,
            attachment_id,
            attachment_epoch: *attachment_epoch,
            scope_id,
            control_socket_path,
            data_directory,
            size_bytes: *size_bytes,
            boot_image_digest,
            expected_blank_head,
            expected_provisioned_head,
        },
        processes,
        volumes,
        mounts,
        networks,
        guest_transport,
        warm_snapshot,
        lifecycle_admission: *lifecycle_admission,
        route_gates,
        require_idle,
    })
    .map_err(|_| malformed())?;
    let canonical = canonical_json_bytes(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(PROVISION_ROOT_AUTHORIZATION_CONTEXT_DOMAIN);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(ProvisionRootAuthorizationContextDigest(
        Sha256Digest::from_bytes(hasher.finalize().into()),
    ))
}

/// Projects the complete typed blockd request from one ProvisionRootImage
/// checkpoint without carrying retryable process-attempt fields.
pub fn provision_root_image_request(
    checkpoint: &RuntimeCheckpoint,
) -> Result<ProvisionRootImageRequest, TargetControlAuthorizationCodecError> {
    let ReconcileStep::ProvisionRootImage {
        provision_transition_id,
        volume_id,
        attachment_id,
        attachment_epoch,
        scope_id: _,
        control_socket_path: _,
        data_directory: _,
        process_identity_token: _,
        size_bytes,
        boot_image_digest,
        expected_blank_head,
        expected_provisioned_head,
    } = &checkpoint.step
    else {
        return Err(invalid("provision request requires provision_root_image"));
    };
    Ok(ProvisionRootImageRequest {
        provision_transition_id: provision_transition_id.clone(),
        volume_id: volume_id.clone(),
        attachment_id: attachment_id.clone(),
        attachment_epoch: *attachment_epoch,
        size_bytes: *size_bytes,
        boot_image_digest: boot_image_digest.clone(),
        expected_blank_head: expected_blank_head.clone(),
        expected_provisioned_head: expected_provisioned_head.clone(),
    })
}

#[derive(Serialize)]
struct ProvisionRootAuthorizationContext<'a> {
    version: ContractVersion,
    cat_id: &'a Id,
    node_id: &'a Id,
    placement_epoch: Epoch,
    desired_revision: Revision,
    spec_digest: &'a Sha256Digest,
    runtime_incarnation: &'a Option<RandomId128>,
    stable_state: &'a Option<StableState>,
    step: ProvisionRootAuthorizationStep<'a>,
    processes: &'a [ProcessEvidence],
    volumes: &'a [ObservedVolume],
    mounts: &'a [ObservedMount],
    networks: &'a [ObservedNetwork],
    guest_transport: &'a GuestTransportEvidence,
    warm_snapshot: &'a WarmSnapshotEvidence,
    lifecycle_admission: LifecycleAdmission,
    route_gates: &'a [CheckpointRouteGate],
    require_idle: &'a RequireIdleCheckpoint,
}

#[derive(Serialize)]
struct ProvisionRootAuthorizationStep<'a> {
    kind: &'static str,
    provision_transition_id: &'a RandomId128,
    volume_id: &'a Id,
    attachment_id: &'a Id,
    attachment_epoch: FenceEpoch,
    scope_id: &'a Id,
    control_socket_path: &'a HostPath,
    data_directory: &'a HostPath,
    size_bytes: u64,
    boot_image_digest: &'a Sha256Digest,
    expected_blank_head: &'a RemoteHead,
    expected_provisioned_head: &'a RemoteHead,
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
    let expected_control_socket =
        Path::new(artifact.local_state.attachment_directory.path.as_str())
            .join("root-provision.sock");
    let request = &artifact.request;
    let attachment = &artifact.attachment;
    if artifact.version != ContractVersion::V1
        || artifact.provision_transition_id != request.provision_transition_id
        || request.volume_id != attachment.identity.volume_id
        || request.attachment_id != attachment.identity.attachment_id
        || request.attachment_epoch != attachment.identity.attachment_epoch
        || request.size_bytes != attachment.size_bytes
        || request.expected_blank_head != attachment.acquire_result.resulting_head
        || request.expected_provisioned_head != attachment.head
        || Path::new(artifact.control_socket_path.as_str()) != expected_control_socket
    {
        return Err(invalid(
            "version or control-process binding is not the exact supported contract",
        ));
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

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, TargetControlAuthorizationCodecError> {
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes).map_err(|_| malformed())?;
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

    const FIXED_PROVISION_CHECKPOINT: &[u8] = br#"{"cat_id":"cat_01","desired_revision":11,"guest_transport":{"kind":"unavailable"},"lifecycle_admission":"closed","mounts":[],"networks":[],"node_id":"node_a","placement_epoch":3,"processes":[],"require_idle":{"kind":"not_applicable"},"route_gates":[],"runtime_incarnation":null,"spec_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","stable_state":null,"step":{"attachment_epoch":7,"attachment_id":"att_root","boot_image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","control_socket_path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/root-provision.sock","data_directory":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7","expected_blank_head":{"generation":0,"root_hash":null,"root_object_id":null},"expected_provisioned_head":{"generation":1,"root_hash":"sha256:0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d","root_object_id":"roots/generation-1.node"},"kind":"provision_root_image","process_identity_token":"44444444444444444444444444444444","provision_transition_id":"33333333333333333333333333333333","scope_id":"cats-root-44444444444444444444444444444444.service","size_bytes":4194304,"volume_id":"vol_root"},"updated_at_unix_ms":1720000000000,"version":1,"volumes":[],"warm_snapshot":{"kind":"absent"}}"#;

    const FIXED_TARGET_CONTROL_AUTHORIZATION: &[u8] = br#"{"attachment":{"acquire_request":{"attachment_id":"att_root","desired_revision":11,"expected_unowned_epoch":6,"lease_duration_ms":60000,"placement_epoch":3,"transition_id":"11111111111111111111111111111111","volume_id":"vol_root"},"acquire_result":{"attachment_id":"att_root","lease_expires_at":1720000060000,"resulting_epoch":7,"resulting_head":{"generation":0,"root_hash":null,"root_object_id":null},"transition_id":"11111111111111111111111111111111","volume_id":"vol_root"},"durability":"strict","head":{"generation":1,"root_hash":"sha256:0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d","root_object_id":"roots/generation-1.node"},"identity":{"acquire_origin":{"kind":"normal","transition_id":"11111111111111111111111111111111"},"attachment_epoch":7,"attachment_id":"att_root","node_id":"node_a","placement_epoch":3,"volume_id":"vol_root"},"lease_expires_at":1720000060000,"size_bytes":4194304},"control_socket_path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/root-provision.sock","local_state":{"acquire_authorization_file":{"content_sha256":"sha256:7f8916bf692fad3e61120f4033f131c621fe15a8eda5e39927df5f3368616380","device":41,"inode":45,"length":811,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/authorized-serving.json"},"attachment_directory":{"device":41,"inode":43,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7"},"attachment_identity_file":{"content_sha256":"sha256:3e32061ef92bb54f78dd7191aa9271ac07a6f4012ec5d333e04402eef00e0d9d","device":41,"inode":44,"length":197,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/identity.json"},"launch_checkpoint_file":{"content_sha256":"sha256:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","device":41,"inode":46,"length":1024,"path":"/var/lib/cats/node/state_path_a/data/cat-cat_01/volume-vol_root/attachment-att_root/epoch-7/launch-checkpoint.json"},"state_directory":{"device":41,"inode":42,"path":"/var/lib/cats/node/state_path_a"}},"provision_context_digest":"sha256:59dd3c80e16df23f3c4f647178368ebdaf7e5f465c3c165030bf1349a139bdb3","provision_transition_id":"33333333333333333333333333333333","request":{"attachment_epoch":7,"attachment_id":"att_root","boot_image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_blank_head":{"generation":0,"root_hash":null,"root_object_id":null},"expected_provisioned_head":{"generation":1,"root_hash":"sha256:0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d","root_object_id":"roots/generation-1.node"},"provision_transition_id":"33333333333333333333333333333333","size_bytes":4194304,"volume_id":"vol_root"},"runtime_scope_id":"cats-root-44444444444444444444444444444444.service","version":1}"#;

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
        let checkpoint =
            cats_api::runtime_reconciliation::decode_runtime_checkpoint(FIXED_PROVISION_CHECKPOINT)
                .unwrap();
        assert_eq!(
            decoded.provision_context_digest,
            provision_root_authorization_context_digest(&checkpoint).unwrap()
        );
        assert_eq!(
            decoded.request,
            provision_root_image_request(&checkpoint).unwrap()
        );
        assert_eq!(
            encode_target_control_authorization(&decoded).unwrap(),
            FIXED_TARGET_CONTROL_AUTHORIZATION
        );
    }

    #[test]
    fn fixed_provision_checkpoint_has_one_stable_context_digest() {
        let checkpoint =
            cats_api::runtime_reconciliation::decode_runtime_checkpoint(FIXED_PROVISION_CHECKPOINT)
                .expect("literal provision checkpoint decodes");
        let digest = provision_root_authorization_context_digest(&checkpoint).unwrap();
        assert_eq!(
            digest.as_sha256_digest().as_str(),
            "sha256:59dd3c80e16df23f3c4f647178368ebdaf7e5f465c3c165030bf1349a139bdb3"
        );

        let mut timestamp_only = checkpoint.clone();
        timestamp_only.updated_at_unix_ms =
            cats_api::runtime_reconciliation::UnixMillis::new(1_720_000_000_001).unwrap();
        assert_eq!(
            provision_root_authorization_context_digest(&timestamp_only).unwrap(),
            digest
        );

        let mut token_only = checkpoint.clone();
        let ReconcileStep::ProvisionRootImage {
            process_identity_token,
            ..
        } = &mut token_only.step
        else {
            unreachable!()
        };
        *process_identity_token = RandomId128::new("55555555555555555555555555555555").unwrap();
        assert_eq!(
            provision_root_authorization_context_digest(&token_only).unwrap(),
            digest
        );

        let mut changed_step = checkpoint.clone();
        let ReconcileStep::ProvisionRootImage {
            boot_image_digest, ..
        } = &mut changed_step.step
        else {
            unreachable!()
        };
        *boot_image_digest = Sha256Digest::from_bytes([0xbb; 32]);
        assert_ne!(
            provision_root_authorization_context_digest(&changed_step).unwrap(),
            digest
        );

        let mut changed_checkpoint = checkpoint;
        changed_checkpoint.lifecycle_admission = LifecycleAdmission::Open;
        assert_ne!(
            provision_root_authorization_context_digest(&changed_checkpoint).unwrap(),
            digest
        );
    }
}

//! Qualification-only, physical postcondition fault for first-format recovery.
//!
//! The ordinary production path never creates the fixed root-only artifact.
//! When an exact metal qualification run does create it, the Guest consumes it
//! only after a real mkfs, device sync, second stable observation and response
//! validation have all succeeded. The transport then closes that one request
//! without writing its valid response, exercising the Node's discovery path.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context as _, Result};
use cats_api::guest::{
    FilesystemControlOperationV1, FilesystemControlOutcomeV1, FilesystemControlResponseV1,
};
use cats_api::runtime_reconciliation::{FilesystemInitialization, Id, RandomId128};
use serde::{Deserialize, Serialize};

const DIRECTORY: &str = "/run/cats/qualification";
const ACTIVE: &str = "filesystem-fault.v1.json";
const CONSUMED: &str = "filesystem-fault-consumed.v1.json";
const ACTION: &str = "drop_validated_format_response_once";
const MAX_BYTES: u64 = 4 * 1024;

static FORMAT_INVOCATIONS: OnceLock<Mutex<BTreeMap<String, FormatInvocationV1>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemFaultV1 {
    version: u8,
    run_id: String,
    attachment_id: Id,
    initialization_token: RandomId128,
    filesystem_uuid: RandomId128,
    action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatInvocationV1 {
    version: u8,
    challenge: RandomId128,
    attachment_id: Id,
    initialization_token: RandomId128,
    filesystem_uuid: RandomId128,
    mkfs_invocations: u8,
}

fn invocation_name(filesystem_uuid: &RandomId128) -> String {
    format!(
        "filesystem-format-invocation-{}.v1.json",
        filesystem_uuid.as_str()
    )
}

fn increment_invocations(
    request: &cats_api::guest::FilesystemControlRequestV1,
    initialization_token: &RandomId128,
) -> Result<FormatInvocationV1> {
    let mut counts = FORMAT_INVOCATIONS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| anyhow::anyhow!("qualification invocation counter is poisoned"))?;
    let invocation = counts
        .entry(request.filesystem.filesystem_uuid.as_str().to_owned())
        .or_insert_with(|| FormatInvocationV1 {
            version: 1,
            challenge: request.challenge.clone(),
            attachment_id: request.filesystem.attachment_id.clone(),
            initialization_token: initialization_token.clone(),
            filesystem_uuid: request.filesystem.filesystem_uuid.clone(),
            mkfs_invocations: 0,
        });
    invocation.mkfs_invocations = invocation.mkfs_invocations.saturating_add(1);
    Ok(invocation.clone())
}

fn invocation(filesystem_uuid: &RandomId128) -> Result<Option<FormatInvocationV1>> {
    let counts = FORMAT_INVOCATIONS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| anyhow::anyhow!("qualification invocation counter is poisoned"))?;
    Ok(counts.get(filesystem_uuid.as_str()).cloned())
}

fn qualification_directory() -> &'static Path {
    Path::new(DIRECTORY)
}

fn canonical_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn initialize_binding(
    response: &FilesystemControlResponseV1,
) -> Option<(&Id, &RandomId128, &RandomId128)> {
    let FilesystemInitialization::Initialize {
        initialization_token,
        ..
    } = &response.request.filesystem.initialization
    else {
        return None;
    };
    Some((
        &response.request.filesystem.attachment_id,
        initialization_token,
        &response.request.filesystem.filesystem_uuid,
    ))
}

fn exact_fault_binding(
    response: &FilesystemControlResponseV1,
    fault: &FilesystemFaultV1,
    invocation: &FormatInvocationV1,
) -> bool {
    let Some((attachment_id, initialization_token, filesystem_uuid)) = initialize_binding(response)
    else {
        return false;
    };
    response.request.operation == FilesystemControlOperationV1::FormatExt4
        && response.outcome == FilesystemControlOutcomeV1::Exact
        && fault.version == 1
        && canonical_run_id(&fault.run_id)
        && fault.action == ACTION
        && fault.attachment_id == *attachment_id
        && fault.initialization_token == *initialization_token
        && fault.filesystem_uuid == *filesystem_uuid
        && invocation.version == 1
        && invocation.challenge == response.request.challenge
        && invocation.attachment_id == *attachment_id
        && invocation.initialization_token == *initialization_token
        && invocation.filesystem_uuid == *filesystem_uuid
        && invocation.mkfs_invocations == 1
}

fn ensure_root_only_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect qualification directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "qualification directory is not root:root mode 0700"
    );
    Ok(())
}

fn read_canonical<T>(path: &Path) -> Result<(T, Vec<u8>, File, std::fs::Metadata)>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("open qualification artifact {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.len() <= MAX_BYTES,
        "qualification artifact is not one bounded root:root mode 0600 file"
    );
    let mut bytes = Vec::new();
    (&file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "qualification artifact is oversized"
    );
    let value: T = serde_json::from_slice(&bytes).context("decode qualification artifact")?;
    anyhow::ensure!(
        serde_json::to_vec(&value)? == bytes,
        "qualification artifact is not canonical JSON"
    );
    Ok((value, bytes, file, metadata))
}

fn write_new_canonical<T>(directory: &Path, path: &Path, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "qualification receipt is oversized"
    );
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("create qualification receipt {}", path.display()))?;
    file.write_all(&bytes)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.len() == bytes.len() as u64,
        "new qualification receipt is not one exact root-only file"
    );
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

/// Record the one actual mkfs invocation. Failure to record never blocks a
/// production format; it merely makes a qualification fault ineligible.
pub(super) fn record_format_invocation(
    response_request: &cats_api::guest::FilesystemControlRequestV1,
) -> Result<()> {
    let FilesystemInitialization::Initialize {
        initialization_token,
        ..
    } = &response_request.filesystem.initialization
    else {
        anyhow::bail!("format invocation is not an Initialize request")
    };
    // Keep the ordinary production path free of qualification filesystem
    // effects. The marker is materialized only if an exact active artifact is
    // later accepted at the validated response transport boundary.
    increment_invocations(response_request, initialization_token)?;
    Ok(())
}

/// Atomically consume the exact one-shot artifact after the response has
/// already passed its normal protocol validation. `true` tells the transport
/// to close this request socket without writing the response.
pub(super) fn consume_validated_format_response_once(
    response: &FilesystemControlResponseV1,
) -> Result<bool> {
    if response.request.operation != FilesystemControlOperationV1::FormatExt4
        || response.outcome != FilesystemControlOutcomeV1::Exact
    {
        return Ok(false);
    }
    response
        .validate()
        .context("revalidate format response at qualification transport boundary")?;
    let Some((_, _, filesystem_uuid)) = initialize_binding(response) else {
        return Ok(false);
    };
    let directory = qualification_directory();
    let active = directory.join(ACTIVE);
    if !active.exists() {
        return Ok(false);
    }
    ensure_root_only_directory(directory)?;
    let (fault, _bytes, active_file, active_metadata) =
        read_canonical::<FilesystemFaultV1>(&active)?;
    let Some(invocation) = invocation(filesystem_uuid)? else {
        return Ok(false);
    };
    if !exact_fault_binding(response, &fault, &invocation) {
        return Ok(false);
    }
    let invocation_path = directory.join(invocation_name(filesystem_uuid));
    write_new_canonical(directory, &invocation_path, &invocation)
        .context("record exact qualification mkfs invocation")?;

    let consumed = directory.join(CONSUMED);
    match std::fs::hard_link(&active, &consumed) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error).context("no-replace consume qualification artifact"),
    }
    let consumed_metadata = std::fs::symlink_metadata(&consumed)?;
    anyhow::ensure!(
        consumed_metadata.dev() == active_metadata.dev()
            && consumed_metadata.ino() == active_metadata.ino()
            && consumed_metadata.nlink() == 2,
        "consumed qualification artifact is not the validated inode"
    );
    active_file.sync_all()?;
    std::fs::remove_file(&active).context("unlink consumed active qualification artifact")?;
    File::open(directory)?.sync_all()?;
    let final_metadata = std::fs::symlink_metadata(&consumed)?;
    anyhow::ensure!(
        final_metadata.nlink() == 1
            && final_metadata.uid() == 0
            && final_metadata.gid() == 0
            && final_metadata.permissions().mode() & 0o7777 == 0o600,
        "consumed qualification receipt did not settle to one root-only inode"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use cats_api::guest::{
        FilesystemControlRequestV1, FilesystemIdentityV1, PersistentFilesystemObservationV1,
        GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
    };
    use cats_api::runtime_reconciliation::{
        FenceEpoch, Generation, GuestDeviceIdentity, HostPath, PersistentFilesystemBinding,
        RemoteHead,
    };

    use super::*;

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn response() -> FilesystemControlResponseV1 {
        let filesystem_uuid = random('c');
        let binding = PersistentFilesystemBinding {
            runtime_incarnation: random('b'),
            volume_intent_id: Id::new("intent-data").unwrap(),
            disk_id: Id::new("disk-data").unwrap(),
            volume_id: Id::new("volume-data").unwrap(),
            attachment_id: Id::new("attachment-data").unwrap(),
            attachment_epoch: FenceEpoch::new(4).unwrap(),
            size_bytes: 4_294_967_296,
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-data").unwrap(),
                slot: 1,
            },
            filesystem_uuid: filesystem_uuid.clone(),
            mount_path: HostPath::new("/data").unwrap(),
            initialization: FilesystemInitialization::Initialize {
                initialization_token: random('d'),
                expected_blank_head: RemoteHead {
                    generation: Generation::new(0).unwrap(),
                    root_hash: None,
                    root_object_id: None,
                },
            },
        };
        FilesystemControlResponseV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            request: Box::new(FilesystemControlRequestV1 {
                version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
                challenge: random('a'),
                timeout_ms: 30_000,
                operation: FilesystemControlOperationV1::FormatExt4,
                expected_head: match &binding.initialization {
                    FilesystemInitialization::Initialize {
                        expected_blank_head,
                        ..
                    } => expected_blank_head.clone(),
                    FilesystemInitialization::Existing => unreachable!(),
                },
                filesystem: Box::new(binding.clone()),
            }),
            outcome: FilesystemControlOutcomeV1::Exact,
            observation: PersistentFilesystemObservationV1 {
                guest_device: binding.guest_device,
                device_path: HostPath::new("/dev/vdb").unwrap(),
                device_major: 252,
                device_minor: 16,
                size_bytes: binding.size_bytes,
                filesystem: FilesystemIdentityV1::Ext4 { filesystem_uuid },
                mounts: Vec::new(),
            },
        }
    }

    fn fault_and_invocation(
        response: &FilesystemControlResponseV1,
    ) -> (FilesystemFaultV1, FormatInvocationV1) {
        let FilesystemInitialization::Initialize {
            initialization_token,
            ..
        } = &response.request.filesystem.initialization
        else {
            unreachable!()
        };
        let fault = FilesystemFaultV1 {
            version: 1,
            run_id: "qualification-run-1".to_owned(),
            attachment_id: response.request.filesystem.attachment_id.clone(),
            initialization_token: initialization_token.clone(),
            filesystem_uuid: response.request.filesystem.filesystem_uuid.clone(),
            action: ACTION.to_owned(),
        };
        let invocation = FormatInvocationV1 {
            version: 1,
            challenge: response.request.challenge.clone(),
            attachment_id: fault.attachment_id.clone(),
            initialization_token: fault.initialization_token.clone(),
            filesystem_uuid: fault.filesystem_uuid.clone(),
            mkfs_invocations: 1,
        };
        (fault, invocation)
    }

    #[test]
    fn exact_fault_requires_one_actual_request_bound_mkfs() {
        let response = response();
        response.validate().unwrap();
        let (fault, invocation) = fault_and_invocation(&response);
        assert!(exact_fault_binding(&response, &fault, &invocation));

        let mut duplicate = invocation.clone();
        duplicate.mkfs_invocations = 2;
        assert!(!exact_fault_binding(&response, &fault, &duplicate));

        let mut stale = invocation;
        stale.challenge = random('e');
        assert!(!exact_fault_binding(&response, &fault, &stale));
    }

    #[test]
    fn wrong_or_conflicting_fault_never_drops_a_response() {
        let mut response = response();
        let (mut fault, invocation) = fault_and_invocation(&response);
        fault.attachment_id = Id::new("attachment-other").unwrap();
        assert!(!exact_fault_binding(&response, &fault, &invocation));

        let (fault, invocation) = fault_and_invocation(&response);
        response.outcome = FilesystemControlOutcomeV1::Conflict;
        assert!(!exact_fault_binding(&response, &fault, &invocation));
    }

    #[test]
    fn unsafe_run_ids_are_not_qualification_authority() {
        for run_id in ["", "../escape", "UPPER", "space separated"] {
            assert!(!canonical_run_id(run_id));
        }
        assert!(canonical_run_id("run-2026_08.14"));
    }
}

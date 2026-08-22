//! Guest mount-readiness gate for the semantic Control -> Node protocol.

use std::collections::BTreeSet;

use cats_api::guest::{RuntimeReadyContractError, RuntimeReadyRequestV1, RuntimeReadyResponseV1};
use cats_api::runtime_reconciliation::{GuestDeviceIdentity, Id, MountAccess, RandomId128};
use cats_api::semantic_control::NodedDiskMount;

/// Node-enriched identity for one element of the complete mount set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPersistentMount {
    /// Exact element received in the complete Control -> Node mount set.
    pub requested: NodedDiskMount,
    /// Identity reported by the installed strict-volume/device path.
    pub volume_id: Id,
    pub filesystem_uuid: RandomId128,
    pub size_bytes: u64,
    pub guest_device: GuestDeviceIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPersistentMountSet {
    /// Strictly sorted by immutable disk ID.
    pub mounts: Vec<ExpectedPersistentMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedPersistentMountSet {
    pub disk_ids: Vec<Id>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MountReadinessError {
    #[error("Guest RuntimeReady contract failed: {0}")]
    GuestContract(#[from] RuntimeReadyContractError),
    #[error("expected PersistentDisk mount set is not canonical")]
    InvalidExpectedSet,
    #[error("Guest did not report the exact expected PersistentDisk device")]
    DeviceMismatch,
    #[error("Guest did not report the exact expected PersistentDisk ext4 mount")]
    MountMismatch,
    #[error("Guest reported a PersistentDisk mount absent from the complete expected set")]
    UnexpectedMount,
}

/// Return success only after the Guest has confirmed the whole mount set.
///
/// The Guest observation is not storage authority.  It is the final readiness
/// postcondition joined to the Node's already-installed virtio device identity.
pub fn confirm_complete_mount_set(
    request: &RuntimeReadyRequestV1,
    response: &RuntimeReadyResponseV1,
    expected: &ExpectedPersistentMountSet,
) -> Result<ConfirmedPersistentMountSet, MountReadinessError> {
    validate_expected(expected)?;
    response.validate_against(request)?;

    for expected_mount in &expected.mounts {
        let devices = response
            .devices
            .iter()
            .filter(|device| device.guest_device == expected_mount.guest_device)
            .collect::<Vec<_>>();
        if devices.len() != 1
            || devices[0].size_bytes != expected_mount.size_bytes
            || devices[0].filesystem_uuid != expected_mount.requested.filesystem_uuid
        {
            return Err(MountReadinessError::DeviceMismatch);
        }
        let device = devices[0];
        let exact_mounts = response
            .mounts
            .iter()
            .filter(|mount| {
                mount.device_major == device.device_major
                    && mount.device_minor == device.device_minor
                    && mount.source_path == device.device_path
                    && mount.filesystem_uuid == expected_mount.requested.filesystem_uuid
                    && mount.mount_root.as_str() == "/"
                    && mount.mount_path.as_str() == expected_mount.requested.mount_path.as_str()
                    && mount.filesystem_type.as_str() == "ext4"
                    && mount.access == MountAccess::ReadWrite
            })
            .count();
        if exact_mounts != 1 {
            return Err(MountReadinessError::MountMismatch);
        }
    }

    let expected_paths = expected
        .mounts
        .iter()
        .map(|mount| mount.requested.mount_path.as_str())
        .collect::<BTreeSet<_>>();
    if response
        .mounts
        .iter()
        .filter(|mount| mount.mount_path.as_str() != "/")
        .any(|mount| !expected_paths.contains(mount.mount_path.as_str()))
    {
        return Err(MountReadinessError::UnexpectedMount);
    }

    Ok(ConfirmedPersistentMountSet {
        disk_ids: expected
            .mounts
            .iter()
            .map(|mount| mount.requested.disk_id.clone())
            .collect(),
    })
}

fn validate_expected(expected: &ExpectedPersistentMountSet) -> Result<(), MountReadinessError> {
    let mut previous_disk: Option<&Id> = None;
    let mut volume_ids = BTreeSet::new();
    let mut filesystem_uuids = BTreeSet::new();
    let mut mount_paths = BTreeSet::new();
    let mut device_slots = BTreeSet::new();
    let mut device_serials = BTreeSet::new();
    for mount in &expected.mounts {
        if previous_disk.is_some_and(|previous| previous >= &mount.requested.disk_id)
            || mount.size_bytes == 0
            || mount.requested.volume_id != mount.volume_id
            || mount.requested.filesystem_uuid != mount.filesystem_uuid
            || !volume_ids.insert(mount.volume_id.as_str())
            || !filesystem_uuids.insert(mount.filesystem_uuid.as_str())
            || !mount_paths.insert(mount.requested.mount_path.as_str())
            || !device_slots.insert(mount.guest_device.slot)
            || !device_serials.insert(mount.guest_device.serial.as_str())
        {
            return Err(MountReadinessError::InvalidExpectedSet);
        }
        previous_disk = Some(&mount.requested.disk_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::guest::{
        RuntimeReadyDeviceV1, RuntimeReadyMountV1, GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        GUEST_HOST_CONTROL_VSOCK_PORT_V1,
    };
    use cats_api::runtime_reconciliation::{GuestBootId, HostPath};
    use cats_api::semantic_control::{PersistentDiskFormat, PersistentMountPath};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(value.to_string().repeat(32)).unwrap()
    }

    fn path(value: &str) -> HostPath {
        HostPath::new(value).unwrap()
    }

    fn device(serial: &str, slot: u16) -> GuestDeviceIdentity {
        GuestDeviceIdentity {
            serial: id(serial),
            slot,
        }
    }

    fn request() -> RuntimeReadyRequestV1 {
        RuntimeReadyRequestV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            challenge: random('1'),
            runtime_incarnation: random('2'),
            expected_guest_cid: 3,
            expected_guest_port: GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            expected_guest_agent_protocol_version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        }
    }

    fn expected() -> ExpectedPersistentMountSet {
        ExpectedPersistentMountSet {
            mounts: vec![
                ExpectedPersistentMount {
                    requested: NodedDiskMount {
                        disk_id: id("disk_1"),
                        volume_id: id("vol_1"),
                        filesystem_uuid: random('4'),
                        format: PersistentDiskFormat::Ext4,
                        mount_path: PersistentMountPath::new("/data").unwrap(),
                    },
                    volume_id: id("vol_1"),
                    filesystem_uuid: random('4'),
                    size_bytes: 100,
                    guest_device: device("persist1", 1),
                },
                ExpectedPersistentMount {
                    requested: NodedDiskMount {
                        disk_id: id("disk_2"),
                        volume_id: id("vol_2"),
                        filesystem_uuid: random('5'),
                        format: PersistentDiskFormat::Ext4,
                        mount_path: PersistentMountPath::new("/logs").unwrap(),
                    },
                    volume_id: id("vol_2"),
                    filesystem_uuid: random('5'),
                    size_bytes: 200,
                    guest_device: device("persist2", 2),
                },
            ],
        }
    }

    fn response(request: &RuntimeReadyRequestV1) -> RuntimeReadyResponseV1 {
        let devices = vec![
            RuntimeReadyDeviceV1 {
                guest_device: device("root", 0),
                device_path: path("/dev/vda"),
                device_major: 254,
                device_minor: 0,
                size_bytes: 1_000,
                filesystem_uuid: random('3'),
            },
            RuntimeReadyDeviceV1 {
                guest_device: device("persist1", 1),
                device_path: path("/dev/vdb"),
                device_major: 254,
                device_minor: 16,
                size_bytes: 100,
                filesystem_uuid: random('4'),
            },
            RuntimeReadyDeviceV1 {
                guest_device: device("persist2", 2),
                device_path: path("/dev/vdc"),
                device_major: 254,
                device_minor: 32,
                size_bytes: 200,
                filesystem_uuid: random('5'),
            },
        ];
        let mounts = vec![
            mount(&devices[0], "/"),
            mount(&devices[1], "/data"),
            mount(&devices[2], "/logs"),
        ];
        RuntimeReadyResponseV1 {
            version: request.version,
            challenge: request.challenge.clone(),
            runtime_incarnation: request.runtime_incarnation.clone(),
            expected_guest_cid: request.expected_guest_cid,
            expected_guest_port: request.expected_guest_port,
            expected_guest_agent_protocol_version: request.expected_guest_agent_protocol_version,
            actual_guest_cid: request.expected_guest_cid,
            actual_guest_port: request.expected_guest_port,
            actual_guest_agent_protocol_version: request.expected_guest_agent_protocol_version,
            guest_boot_id: GuestBootId::new("66666666666666666666666666666666").unwrap(),
            devices,
            mounts,
        }
    }

    fn mount(device: &RuntimeReadyDeviceV1, mount_path: &str) -> RuntimeReadyMountV1 {
        RuntimeReadyMountV1 {
            device_major: device.device_major,
            device_minor: device.device_minor,
            source_path: device.device_path.clone(),
            filesystem_uuid: device.filesystem_uuid.clone(),
            mount_root: path("/"),
            mount_path: path(mount_path),
            filesystem_type: id("ext4"),
            access: MountAccess::ReadWrite,
        }
    }

    #[test]
    fn succeeds_only_for_the_complete_exact_guest_mount_set() {
        let request = request();
        let response = response(&request);
        let confirmed = confirm_complete_mount_set(&request, &response, &expected()).unwrap();
        assert_eq!(confirmed.disk_ids, vec![id("disk_1"), id("disk_2")]);
    }

    #[test]
    fn missing_wrong_or_extra_mount_fails_readiness() {
        let request = request();

        let mut missing = response(&request);
        missing.mounts.remove(1);
        assert_eq!(
            confirm_complete_mount_set(&request, &missing, &expected()),
            Err(MountReadinessError::MountMismatch)
        );

        let mut wrong_uuid = response(&request);
        wrong_uuid.devices[1].filesystem_uuid = random('7');
        wrong_uuid.mounts[1].filesystem_uuid = random('7');
        assert_eq!(
            confirm_complete_mount_set(&request, &wrong_uuid, &expected()),
            Err(MountReadinessError::DeviceMismatch)
        );

        let mut extra = response(&request);
        let extra_device = RuntimeReadyDeviceV1 {
            guest_device: device("persist3", 3),
            device_path: path("/dev/vdd"),
            device_major: 254,
            device_minor: 48,
            size_bytes: 300,
            filesystem_uuid: random('8'),
        };
        extra.mounts.push(mount(&extra_device, "/extra"));
        extra.devices.push(extra_device);
        extra.mounts.sort_by(|left, right| {
            (left.mount_path.as_str(), left.source_path.as_str())
                .cmp(&(right.mount_path.as_str(), right.source_path.as_str()))
        });
        assert_eq!(
            confirm_complete_mount_set(&request, &extra, &expected()),
            Err(MountReadinessError::UnexpectedMount)
        );
    }

    #[test]
    fn expected_mount_set_must_be_sorted_and_unique() {
        let request = request();
        let response = response(&request);
        let mut unsorted = expected();
        unsorted.mounts.swap(0, 1);
        assert_eq!(
            confirm_complete_mount_set(&request, &response, &unsorted),
            Err(MountReadinessError::InvalidExpectedSet)
        );

        let mut wrong_volume = expected();
        wrong_volume.mounts[0].requested.volume_id = id("vol_other");
        assert_eq!(
            confirm_complete_mount_set(&request, &response, &wrong_volume),
            Err(MountReadinessError::InvalidExpectedSet)
        );

        let mut wrong_filesystem = expected();
        wrong_filesystem.mounts[0].requested.filesystem_uuid = random('9');
        assert_eq!(
            confirm_complete_mount_set(&request, &response, &wrong_filesystem),
            Err(MountReadinessError::InvalidExpectedSet)
        );
    }

    #[test]
    fn runtime_ready_challenge_still_fences_the_guest_observation() {
        let request = request();
        let mut response = response(&request);
        response.challenge = random('9');
        assert_eq!(
            confirm_complete_mount_set(&request, &response, &expected()),
            Err(MountReadinessError::GuestContract(
                RuntimeReadyContractError::ChallengeEcho
            ))
        );
    }
}

//! Read-only Guest-side RuntimeReady V1 physical projection.
//!
//! This module never formats or mounts a filesystem.  It reads the kernel's
//! virtio-blk sysfs facts, the ext4 superblock UUID and this process's
//! mountinfo, then emits one bounded canonical response.  The Host must still
//! join that projection to its retained VMM and storage authority.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cats_api::guest::{
    RuntimeReadyDeviceV1, RuntimeReadyMountV1, RuntimeReadyRequestV1, RuntimeReadyResponseV1,
    GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1, RUNTIME_READY_MAX_DEVICES_V1,
    RUNTIME_READY_MAX_MOUNTS_V1,
};
use cats_api::runtime_reconciliation::{
    GuestBootId, GuestDeviceIdentity, HostPath, Id, MountAccess, RandomId128,
};

use crate::VsockLocalEndpoint;

const SECTOR_BYTES: u64 = 512;
const EXT4_SUPERBLOCK_OFFSET: u64 = 1_024;
const EXT4_SUPERBLOCK_BYTES: usize = 1_024;
const EXT4_MAGIC_OFFSET: usize = 56;
const EXT4_UUID_OFFSET: usize = 104;
const EXT4_UUID_BYTES: usize = 16;
const MAX_MOUNTINFO_BYTES: u64 = 256 * 1024;

pub(super) struct RuntimeReadyCollector {
    sys_block_root: PathBuf,
    dev_root: PathBuf,
    reported_dev_root: PathBuf,
    mountinfo_path: PathBuf,
}

impl RuntimeReadyCollector {
    pub(super) fn system() -> Self {
        Self {
            sys_block_root: PathBuf::from("/sys/block"),
            dev_root: PathBuf::from("/dev"),
            reported_dev_root: PathBuf::from("/dev"),
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
        }
    }

    #[cfg(test)]
    fn for_test(sys_block_root: PathBuf, dev_root: PathBuf, mountinfo_path: PathBuf) -> Self {
        Self {
            sys_block_root,
            dev_root,
            reported_dev_root: PathBuf::from("/dev"),
            mountinfo_path,
        }
    }

    pub(super) fn collect(
        &self,
        request: RuntimeReadyRequestV1,
        endpoint: VsockLocalEndpoint,
        boot_id: &str,
    ) -> Result<RuntimeReadyResponseV1> {
        request
            .validate()
            .context("validate RuntimeReady V1 challenge")?;
        let guest_boot_id = GuestBootId::new(boot_id.to_owned())
            .context("Guest kernel boot ID is not canonical")?;
        let devices = self.devices()?;
        let mounts = self.mounts(&devices)?;
        let response = RuntimeReadyResponseV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            challenge: request.challenge.clone(),
            runtime_incarnation: request.runtime_incarnation.clone(),
            expected_guest_cid: request.expected_guest_cid,
            expected_guest_port: request.expected_guest_port,
            expected_guest_agent_protocol_version: request.expected_guest_agent_protocol_version,
            actual_guest_cid: endpoint.cid,
            actual_guest_port: endpoint.port,
            actual_guest_agent_protocol_version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            guest_boot_id,
            devices,
            mounts,
        };
        response
            .validate_against(&request)
            .context("validate collected RuntimeReady V1 response")?;
        Ok(response)
    }

    fn devices(&self) -> Result<Vec<RuntimeReadyDeviceV1>> {
        let entries = std::fs::read_dir(&self.sys_block_root)
            .with_context(|| format!("read {}", self.sys_block_root.display()))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.context("read one sysfs block entry")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("sysfs block device name is not UTF-8"))?;
            if name.starts_with("vd") {
                let slot = virtio_block_slot(&name)
                    .with_context(|| format!("decode virtio block slot for {name}"))?;
                names.push((slot, name));
                anyhow::ensure!(
                    names.len() <= RUNTIME_READY_MAX_DEVICES_V1,
                    "RuntimeReady virtio device count exceeds {}",
                    RUNTIME_READY_MAX_DEVICES_V1
                );
            }
        }
        names.sort();
        anyhow::ensure!(
            names.windows(2).all(|pair| pair[0].0 != pair[1].0),
            "two virtio block names map to one Guest slot"
        );

        names
            .into_iter()
            .map(|(slot, name)| self.device(slot, &name))
            .collect()
    }

    fn device(&self, slot: u16, name: &str) -> Result<RuntimeReadyDeviceV1> {
        let sysfs = self.sys_block_root.join(name);
        let serial = read_trimmed(&sysfs.join("serial"))?;
        let serial = Id::new(serial).context("virtio block serial is not a canonical Id")?;
        let sectors = parse_canonical_u64(&read_trimmed(&sysfs.join("size"))?)
            .context("virtio block sector count is not canonical")?;
        let size_bytes = sectors
            .checked_mul(SECTOR_BYTES)
            .filter(|size| *size > 0)
            .context("virtio block size is zero or overflows bytes")?;
        let (device_major, device_minor) = parse_device_number(&read_trimmed(&sysfs.join("dev"))?)
            .context("virtio block device number is not canonical")?;
        let physical_device_path = self.dev_root.join(name);
        let filesystem_uuid = read_ext4_uuid(&physical_device_path)
            .with_context(|| format!("read ext4 UUID from {}", physical_device_path.display()))?;
        let device_path = HostPath::new(
            self.reported_dev_root
                .join(name)
                .to_string_lossy()
                .into_owned(),
        )
        .context("virtio block path is not canonical")?;
        Ok(RuntimeReadyDeviceV1 {
            guest_device: GuestDeviceIdentity { serial, slot },
            device_path,
            device_major,
            device_minor,
            size_bytes,
            filesystem_uuid,
        })
    }

    fn mounts(&self, devices: &[RuntimeReadyDeviceV1]) -> Result<Vec<RuntimeReadyMountV1>> {
        let bytes = read_bounded(&self.mountinfo_path, MAX_MOUNTINFO_BYTES)
            .with_context(|| format!("read {}", self.mountinfo_path.display()))?;
        let text = std::str::from_utf8(&bytes).context("mountinfo is not UTF-8")?;
        let by_number: BTreeMap<(u32, u32), &RuntimeReadyDeviceV1> = devices
            .iter()
            .map(|device| ((device.device_major, device.device_minor), device))
            .collect();
        anyhow::ensure!(
            by_number.len() == devices.len(),
            "RuntimeReady devices duplicate a kernel device number"
        );

        let mut mounts = Vec::new();
        for line in text.lines() {
            let (left, right) = line
                .split_once(" - ")
                .context("mountinfo line lacks its field separator")?;
            anyhow::ensure!(
                !right.contains(" - "),
                "mountinfo line contains two field separators"
            );
            let left: Vec<&str> = left.split_ascii_whitespace().collect();
            let right: Vec<&str> = right.split_ascii_whitespace().collect();
            anyhow::ensure!(
                left.len() >= 6 && right.len() >= 3,
                "mountinfo line lacks required fields"
            );
            let number = parse_device_number(left[2]).context("mountinfo device is malformed")?;
            let Some(device) = by_number.get(&number) else {
                continue;
            };
            anyhow::ensure!(
                mounts.len() < RUNTIME_READY_MAX_MOUNTS_V1,
                "RuntimeReady mount count exceeds {}",
                RUNTIME_READY_MAX_MOUNTS_V1
            );
            let mount_root = HostPath::new(unescape_mountinfo(left[3])?)
                .context("mountinfo root is not canonical")?;
            let mount_path = HostPath::new(unescape_mountinfo(left[4])?)
                .context("mountinfo mount point is not canonical")?;
            let source_path = HostPath::new(unescape_mountinfo(right[1])?)
                .context("mountinfo source is not canonical")?;
            anyhow::ensure!(
                source_path == device.device_path,
                "mountinfo source path disagrees with its kernel device number"
            );
            let filesystem_type = Id::new(right[0].to_owned())
                .context("mountinfo filesystem type is not canonical")?;
            let options: Vec<&str> = left[5].split(',').collect();
            let read_write = options.iter().filter(|option| **option == "rw").count();
            let read_only = options.iter().filter(|option| **option == "ro").count();
            let access = match (read_write, read_only) {
                (1, 0) => MountAccess::ReadWrite,
                (0, 1) => MountAccess::ReadOnly,
                _ => anyhow::bail!("mountinfo access is missing or ambiguous"),
            };
            mounts.push(RuntimeReadyMountV1 {
                device_major: number.0,
                device_minor: number.1,
                source_path,
                filesystem_uuid: device.filesystem_uuid.clone(),
                mount_root,
                mount_path,
                filesystem_type,
                access,
            });
        }
        mounts.sort_by(|left, right| {
            (left.mount_path.as_str(), left.source_path.as_str())
                .cmp(&(right.mount_path.as_str(), right.source_path.as_str()))
        });
        anyhow::ensure!(
            mounts
                .windows(2)
                .all(|pair| pair[0].mount_path != pair[1].mount_path),
            "RuntimeReady mountinfo contains duplicate mount points"
        );
        Ok(mounts)
    }
}

fn read_trimmed(path: &Path) -> Result<String> {
    let value =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let trimmed = value.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(
        !trimmed.is_empty()
            && trimmed.len() <= 128
            && !trimmed.bytes().any(|byte| byte.is_ascii_whitespace()),
        "{} contains an empty, oversized or whitespace-bearing value",
        path.display()
    );
    Ok(trimmed.to_owned())
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
}

fn parse_device_number(value: &str) -> Option<(u32, u32)> {
    let (major, minor) = value.split_once(':')?;
    let major = major
        .parse::<u32>()
        .ok()
        .filter(|parsed| parsed.to_string() == major)?;
    let minor = minor
        .parse::<u32>()
        .ok()
        .filter(|parsed| parsed.to_string() == minor)?;
    Some((major, minor))
}

fn virtio_block_slot(name: &str) -> Result<u16> {
    let suffix = name
        .strip_prefix("vd")
        .filter(|suffix| !suffix.is_empty())
        .context("virtio block name lacks a letter suffix")?;
    let mut ordinal = 0_u32;
    for byte in suffix.bytes() {
        anyhow::ensure!(
            byte.is_ascii_lowercase(),
            "virtio block suffix is not lowercase ASCII"
        );
        ordinal = ordinal
            .checked_mul(26)
            .and_then(|value| value.checked_add(u32::from(byte - b'a') + 1))
            .context("virtio block slot overflows")?;
    }
    let slot = ordinal
        .checked_sub(1)
        .context("virtio block slot underflows")?;
    u16::try_from(slot).context("virtio block slot exceeds V1")
}

fn read_ext4_uuid(path: &Path) -> Result<RandomId128> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))?;
    let mut superblock = [0_u8; EXT4_SUPERBLOCK_BYTES];
    file.read_exact(&mut superblock)?;
    anyhow::ensure!(
        superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2] == [0x53, 0xef],
        "block device does not contain an ext4 superblock"
    );
    let uuid = hex::encode(&superblock[EXT4_UUID_OFFSET..EXT4_UUID_OFFSET + EXT4_UUID_BYTES]);
    RandomId128::new(uuid).context("ext4 UUID is zero or noncanonical")
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        u64::try_from(bytes.len())
            .ok()
            .is_some_and(|len| len <= maximum),
        "file exceeds its {} byte bound",
        maximum
    );
    Ok(bytes)
}

fn unescape_mountinfo(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let escape = bytes
            .get(index + 1..index + 4)
            .context("mountinfo path ends in a partial escape")?;
        let byte = match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => anyhow::bail!("mountinfo path contains a noncanonical escape"),
        };
        decoded.push(byte);
        index += 4;
    }
    String::from_utf8(decoded).context("mountinfo path is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_device(root: &Path, name: &str, serial: &str, number: &str, uuid: [u8; 16]) {
        let sysfs = root.join("sys/block").join(name);
        std::fs::create_dir_all(&sysfs).unwrap();
        std::fs::write(sysfs.join("serial"), format!("{serial}\n")).unwrap();
        std::fs::write(sysfs.join("size"), "8388608\n").unwrap();
        std::fs::write(sysfs.join("dev"), format!("{number}\n")).unwrap();
        let mut image = vec![0_u8; 2_048];
        let superblock = &mut image[1_024..];
        superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2].copy_from_slice(&[0x53, 0xef]);
        superblock[EXT4_UUID_OFFSET..EXT4_UUID_OFFSET + 16].copy_from_slice(&uuid);
        std::fs::write(root.join("dev").join(name), image).unwrap();
    }

    fn request() -> RuntimeReadyRequestV1 {
        RuntimeReadyRequestV1 {
            version: 1,
            challenge: RandomId128::new("11111111111111111111111111111111").unwrap(),
            runtime_incarnation: RandomId128::new("22222222222222222222222222222222").unwrap(),
            expected_guest_cid: 3,
            expected_guest_port: 5_000,
            expected_guest_agent_protocol_version: 1,
        }
    }

    fn virtio_block_name(slot: usize) -> String {
        let mut ordinal = slot + 1;
        let mut suffix = Vec::new();
        while ordinal > 0 {
            ordinal -= 1;
            suffix.push(char::from(b'a' + u8::try_from(ordinal % 26).unwrap()));
            ordinal /= 26;
        }
        suffix.reverse();
        format!("vd{}", suffix.into_iter().collect::<String>())
    }

    #[test]
    fn collector_reports_sorted_exact_device_and_mountinfo_facts() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("dev")).unwrap();
        write_device(root.path(), "vdb", "cats-data", "252:16", [0xbb; 16]);
        write_device(root.path(), "vda", "cats-root", "252:0", [0xaa; 16]);
        let mountinfo = root.path().join("mountinfo");
        std::fs::write(
            &mountinfo,
            "20 1 0:20 / /proc rw,nosuid - proc proc rw\n31 1 252:16 / /data ro,relatime - ext4 /dev/vdb ro\n30 1 252:0 / / rw,relatime - ext4 /dev/vda rw\n",
        )
        .unwrap();
        let collector = RuntimeReadyCollector::for_test(
            root.path().join("sys/block"),
            root.path().join("dev"),
            mountinfo,
        );
        let ready = collector
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 3,
                    port: 5_000,
                },
                "33333333333333333333333333333333",
            )
            .unwrap();
        assert_eq!(ready.devices.len(), 2);
        assert_eq!(ready.devices[0].guest_device.serial.as_str(), "cats-root");
        assert_eq!(ready.devices[0].guest_device.slot, 0);
        assert_eq!(ready.devices[0].size_bytes, 4_294_967_296);
        assert_eq!(ready.devices[1].guest_device.slot, 1);
        assert_eq!(ready.mounts.len(), 2);
        assert_eq!(ready.mounts[0].mount_path.as_str(), "/");
        assert_eq!(ready.mounts[0].access, MountAccess::ReadWrite);
        assert_eq!(ready.mounts[1].mount_path.as_str(), "/data");
        assert_eq!(ready.mounts[1].access, MountAccess::ReadOnly);
    }

    #[test]
    fn collector_fails_closed_on_uuid_source_and_mount_drift() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("dev")).unwrap();
        write_device(root.path(), "vda", "cats-root", "252:0", [0xaa; 16]);
        let mountinfo = root.path().join("mountinfo");
        let collector = RuntimeReadyCollector::for_test(
            root.path().join("sys/block"),
            root.path().join("dev"),
            mountinfo.clone(),
        );

        std::fs::write(&mountinfo, "30 1 252:0 / / rw - ext4 /dev/vdb rw\n").unwrap();
        assert!(collector
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 3,
                    port: 5_000
                },
                "33333333333333333333333333333333",
            )
            .unwrap_err()
            .to_string()
            .contains("source path"));

        let image = root.path().join("dev/vda");
        let mut bytes = std::fs::read(&image).unwrap();
        bytes[1_024 + EXT4_UUID_OFFSET..1_024 + EXT4_UUID_OFFSET + 16].fill(0);
        std::fs::write(image, bytes).unwrap();
        std::fs::write(&mountinfo, "30 1 252:0 / / rw - ext4 /dev/vda rw\n").unwrap();
        assert!(collector
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 3,
                    port: 5_000
                },
                "33333333333333333333333333333333",
            )
            .is_err());
    }

    #[test]
    fn collector_rejects_duplicate_mounts_and_oversized_inventory() {
        assert_eq!(RUNTIME_READY_MAX_DEVICES_V1, 64);
        assert_eq!(RUNTIME_READY_MAX_MOUNTS_V1, 64);
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("dev")).unwrap();
        write_device(root.path(), "vda", "cats-root", "252:0", [0xaa; 16]);
        let mountinfo = root.path().join("mountinfo");
        std::fs::write(
            &mountinfo,
            "30 1 252:0 / / rw - ext4 /dev/vda rw\n31 1 252:0 / / rw - ext4 /dev/vda rw\n",
        )
        .unwrap();
        let collector = RuntimeReadyCollector::for_test(
            root.path().join("sys/block"),
            root.path().join("dev"),
            mountinfo,
        );
        assert!(collector
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 3,
                    port: 5_000
                },
                "33333333333333333333333333333333",
            )
            .unwrap_err()
            .to_string()
            .contains("duplicate mount"));

        for slot in 1..=RUNTIME_READY_MAX_DEVICES_V1 {
            std::fs::create_dir_all(root.path().join("sys/block").join(virtio_block_name(slot)))
                .unwrap();
        }
        assert!(collector
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 3,
                    port: 5_000,
                },
                "33333333333333333333333333333333",
            )
            .unwrap_err()
            .to_string()
            .contains("device count"));
    }

    #[test]
    fn virtio_slot_and_mountinfo_escape_decoders_are_canonical() {
        assert_eq!(virtio_block_slot("vda").unwrap(), 0);
        assert_eq!(virtio_block_slot("vdz").unwrap(), 25);
        assert_eq!(virtio_block_slot("vdaa").unwrap(), 26);
        assert!(virtio_block_slot("vdA").is_err());
        assert_eq!(unescape_mountinfo("/data\\040set").unwrap(), "/data set");
        assert!(unescape_mountinfo("/data\\000set").is_err());
    }
}

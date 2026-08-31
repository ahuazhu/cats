//! Read-only Guest-side RuntimeReady V1 physical projection.
//!
//! This module never formats or mounts a filesystem.  It reads the kernel's
//! virtio-blk sysfs facts, the ext4 superblock UUID and this process's
//! mountinfo, then emits one bounded canonical response.  The Host must still
//! join that projection to its retained VMM and storage authority.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cats_protocol::guest::{
    RuntimeReadyDeviceV1, RuntimeReadyMountV1, RuntimeReadyRequestV1, RuntimeReadyResponseV1,
    GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1, RUNTIME_READY_MAX_DEVICES_V1,
    RUNTIME_READY_MAX_MOUNTS_V1,
};
use cats_protocol::runtime_reconciliation::{
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceSnapshot {
    guest_device: GuestDeviceIdentity,
    name: String,
    physical_device_path: PathBuf,
    device_path: HostPath,
    device_major: u32,
    device_minor: u32,
    size_bytes: u64,
}

trait RetainedBlockDevice {
    fn verify_identity(&self, expected_major: u32, expected_minor: u32) -> Result<()>;
    fn ext4_uuid(&self) -> Result<RandomId128>;
}

trait RuntimeReadyPhysicalProvider {
    fn sample_devices(&self) -> Result<Vec<DeviceSnapshot>>;
    fn retain_device(&self, device: &DeviceSnapshot) -> Result<Box<dyn RetainedBlockDevice>>;
    fn sample_mountinfo(&self) -> Result<Vec<u8>>;
}

struct SystemPhysicalProvider {
    sys_block_root: PathBuf,
    dev_root: PathBuf,
    reported_dev_root: PathBuf,
    mountinfo_path: PathBuf,
}

pub(super) struct RuntimeReadyCollector {
    provider: Box<dyn RuntimeReadyPhysicalProvider>,
}

impl RuntimeReadyCollector {
    pub(super) fn system() -> Self {
        Self {
            provider: Box::new(SystemPhysicalProvider {
                sys_block_root: PathBuf::from("/sys/block"),
                dev_root: PathBuf::from("/dev"),
                reported_dev_root: PathBuf::from("/dev"),
                mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
            }),
        }
    }

    #[cfg(test)]
    fn for_test(provider: impl RuntimeReadyPhysicalProvider + 'static) -> Self {
        Self {
            provider: Box::new(provider),
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
        anyhow::ensure!(
            endpoint.cid == request.expected_guest_cid
                && endpoint.port == request.expected_guest_port
                && request.expected_guest_agent_protocol_version
                    == GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            "accepted AF_VSOCK local endpoint does not match the RuntimeReady challenge"
        );
        let guest_boot_id = GuestBootId::new(boot_id.to_owned())
            .context("Guest kernel boot ID is not canonical")?;
        let devices_first = self
            .provider
            .sample_devices()
            .context("sample initial virtio block inventory")?;
        validate_device_inventory(&devices_first)?;

        let mut retained = Vec::with_capacity(devices_first.len());
        for device in &devices_first {
            let handle = self
                .provider
                .retain_device(device)
                .with_context(|| format!("retain {}", device.physical_device_path.display()))?;
            handle
                .verify_identity(device.device_major, device.device_minor)
                .with_context(|| format!("verify retained {}", device.name))?;
            retained.push(handle);
        }
        let uuids_first = retained
            .iter()
            .zip(&devices_first)
            .map(|(handle, device)| {
                handle
                    .ext4_uuid()
                    .with_context(|| format!("read ext4 UUID from retained {}", device.name))
            })
            .collect::<Result<Vec<_>>>()?;
        let mountinfo_first = self
            .provider
            .sample_mountinfo()
            .context("sample initial mountinfo")?;

        let mountinfo_second = self
            .provider
            .sample_mountinfo()
            .context("sample final mountinfo")?;
        anyhow::ensure!(
            mountinfo_first == mountinfo_second,
            "mountinfo changed during RuntimeReady collection"
        );
        let uuids_second = retained
            .iter()
            .zip(&devices_first)
            .map(|(handle, device)| {
                handle
                    .ext4_uuid()
                    .with_context(|| format!("re-read ext4 UUID from retained {}", device.name))
            })
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(
            uuids_first == uuids_second,
            "filesystem UUID changed during RuntimeReady collection"
        );
        for (handle, device) in retained.iter().zip(&devices_first) {
            handle
                .verify_identity(device.device_major, device.device_minor)
                .with_context(|| format!("re-verify retained {}", device.name))?;
        }
        let devices_second = self
            .provider
            .sample_devices()
            .context("sample final virtio block inventory")?;
        validate_device_inventory(&devices_second)?;
        anyhow::ensure!(
            devices_first == devices_second,
            "virtio block inventory changed during RuntimeReady collection"
        );

        let devices = project_devices(&devices_first, uuids_first);
        let mounts = mounts_from_bytes(&mountinfo_first, &devices)?;
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
}

fn validate_device_inventory(devices: &[DeviceSnapshot]) -> Result<()> {
    anyhow::ensure!(
        devices.len() <= RUNTIME_READY_MAX_DEVICES_V1,
        "RuntimeReady virtio device count exceeds {}",
        RUNTIME_READY_MAX_DEVICES_V1
    );
    anyhow::ensure!(
        devices.windows(2).all(|pair| {
            (
                pair[0].guest_device.slot,
                pair[0].guest_device.serial.as_str(),
            ) < (
                pair[1].guest_device.slot,
                pair[1].guest_device.serial.as_str(),
            )
        }),
        "RuntimeReady virtio device inventory is not strictly sorted"
    );
    let by_number: BTreeMap<(u32, u32), &DeviceSnapshot> = devices
        .iter()
        .map(|device| ((device.device_major, device.device_minor), device))
        .collect();
    anyhow::ensure!(
        by_number.len() == devices.len(),
        "RuntimeReady devices duplicate a kernel device number"
    );
    Ok(())
}

fn project_devices(
    snapshots: &[DeviceSnapshot],
    uuids: Vec<RandomId128>,
) -> Vec<RuntimeReadyDeviceV1> {
    snapshots
        .iter()
        .zip(uuids)
        .map(|(device, filesystem_uuid)| RuntimeReadyDeviceV1 {
            guest_device: device.guest_device.clone(),
            device_path: device.device_path.clone(),
            device_major: device.device_major,
            device_minor: device.device_minor,
            size_bytes: device.size_bytes,
            filesystem_uuid,
        })
        .collect()
}

impl RuntimeReadyPhysicalProvider for SystemPhysicalProvider {
    fn sample_devices(&self) -> Result<Vec<DeviceSnapshot>> {
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
            .map(|(slot, name)| self.device_snapshot(slot, name))
            .collect()
    }

    fn retain_device(&self, device: &DeviceSnapshot) -> Result<Box<dyn RetainedBlockDevice>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&device.physical_device_path)
            .with_context(|| {
                format!(
                    "open {} with O_NOFOLLOW",
                    device.physical_device_path.display()
                )
            })?;
        let retained = SystemRetainedBlockDevice {
            file,
            path: device.physical_device_path.clone(),
        };
        retained.verify_identity(device.device_major, device.device_minor)?;
        Ok(Box::new(retained))
    }

    fn sample_mountinfo(&self) -> Result<Vec<u8>> {
        read_bounded(&self.mountinfo_path, MAX_MOUNTINFO_BYTES)
            .with_context(|| format!("read {}", self.mountinfo_path.display()))
    }
}

impl SystemPhysicalProvider {
    fn device_snapshot(&self, slot: u16, name: String) -> Result<DeviceSnapshot> {
        let sysfs = self.sys_block_root.join(&name);
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
        let physical_device_path = self.dev_root.join(&name);
        let device_path = HostPath::new(
            self.reported_dev_root
                .join(&name)
                .to_string_lossy()
                .into_owned(),
        )
        .context("virtio block path is not canonical")?;
        Ok(DeviceSnapshot {
            guest_device: GuestDeviceIdentity { serial, slot },
            name,
            physical_device_path,
            device_path,
            device_major,
            device_minor,
            size_bytes,
        })
    }
}

struct SystemRetainedBlockDevice {
    file: File,
    path: PathBuf,
}

impl RetainedBlockDevice for SystemRetainedBlockDevice {
    fn verify_identity(&self, expected_major: u32, expected_minor: u32) -> Result<()> {
        let metadata = self
            .file
            .metadata()
            .context("fstat retained block device")?;
        anyhow::ensure!(
            metadata.file_type().is_block_device(),
            "retained device is not a block device"
        );
        let path_metadata = std::fs::symlink_metadata(&self.path)
            .with_context(|| format!("lstat retained device path {}", self.path.display()))?;
        anyhow::ensure!(
            path_metadata.file_type().is_block_device()
                && path_metadata.dev() == metadata.dev()
                && path_metadata.ino() == metadata.ino()
                && path_metadata.rdev() == metadata.rdev(),
            "retained block device path was replaced"
        );
        #[cfg(target_os = "linux")]
        {
            let actual_major = libc::major(metadata.rdev());
            let actual_minor = libc::minor(metadata.rdev());
            anyhow::ensure!(
                actual_major == expected_major && actual_minor == expected_minor,
                "retained block device number disagrees with sysfs"
            );
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected_major, expected_minor, metadata.rdev());
            anyhow::bail!("RuntimeReady block identity proof is Linux-only")
        }
    }

    fn ext4_uuid(&self) -> Result<RandomId128> {
        read_ext4_uuid(&self.file)
    }
}

fn mounts_from_bytes(
    bytes: &[u8],
    devices: &[RuntimeReadyDeviceV1],
) -> Result<Vec<RuntimeReadyMountV1>> {
    let text = std::str::from_utf8(bytes).context("mountinfo is not UTF-8")?;
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
        let _source_alias = HostPath::new(unescape_mountinfo(right[1])?)
            .context("mountinfo source is not canonical")?;
        // mount(2) accepts the retained `/proc/self/fd/N` used by filesystem
        // control, and mountinfo is allowed to preserve that source spelling.
        // Major/minor plus the retained sysfs/fstat identity is the authority;
        // normalize the observation to the proven canonical `/dev/vdX` path.
        let source_path = device.device_path.clone();
        let filesystem_type =
            Id::new(right[0].to_owned()).context("mountinfo filesystem type is not canonical")?;
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

fn read_ext4_uuid(file: &File) -> Result<RandomId128> {
    let mut superblock = [0_u8; EXT4_SUPERBLOCK_BYTES];
    file.read_exact_at(&mut superblock, EXT4_SUPERBLOCK_OFFSET)?;
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
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    struct FakePhysicalProvider {
        state: Arc<Mutex<FakeProviderState>>,
    }

    struct FakeProviderState {
        device_samples: VecDeque<Vec<DeviceSnapshot>>,
        mountinfo_samples: VecDeque<Vec<u8>>,
        retained: BTreeMap<String, FakeRetainedBlockDevice>,
        device_sample_count: usize,
        mountinfo_sample_count: usize,
        retain_count: BTreeMap<String, usize>,
    }

    #[derive(Clone)]
    struct FakeRetainedBlockDevice {
        state: Arc<Mutex<FakeRetainedState>>,
    }

    struct FakeRetainedState {
        identities: VecDeque<FakeIdentity>,
        uuids: VecDeque<FakeUuid>,
    }

    #[derive(Debug, Clone)]
    enum FakeIdentity {
        Exact(u32, u32),
        Error(&'static str),
    }

    #[derive(Debug, Clone)]
    enum FakeUuid {
        Value(RandomId128),
        Error(&'static str),
    }

    fn next_scripted<T: Clone>(values: &mut VecDeque<T>, fact: &str) -> Result<T> {
        anyhow::ensure!(!values.is_empty(), "fake {fact} script is empty");
        if values.len() == 1 {
            Ok(values.front().expect("checked nonempty").clone())
        } else {
            Ok(values.pop_front().expect("checked nonempty"))
        }
    }

    impl RuntimeReadyPhysicalProvider for FakePhysicalProvider {
        fn sample_devices(&self) -> Result<Vec<DeviceSnapshot>> {
            let mut state = self.state.lock().unwrap();
            state.device_sample_count += 1;
            next_scripted(&mut state.device_samples, "device")
        }

        fn retain_device(&self, device: &DeviceSnapshot) -> Result<Box<dyn RetainedBlockDevice>> {
            let mut state = self.state.lock().unwrap();
            *state.retain_count.entry(device.name.clone()).or_default() += 1;
            Ok(Box::new(
                state
                    .retained
                    .get(&device.name)
                    .with_context(|| format!("no fake retained device for {}", device.name))?
                    .clone(),
            ))
        }

        fn sample_mountinfo(&self) -> Result<Vec<u8>> {
            let mut state = self.state.lock().unwrap();
            state.mountinfo_sample_count += 1;
            next_scripted(&mut state.mountinfo_samples, "mountinfo")
        }
    }

    impl RetainedBlockDevice for FakeRetainedBlockDevice {
        fn verify_identity(&self, expected_major: u32, expected_minor: u32) -> Result<()> {
            match next_scripted(&mut self.state.lock().unwrap().identities, "identity")? {
                FakeIdentity::Exact(major, minor) => {
                    anyhow::ensure!(
                        (major, minor) == (expected_major, expected_minor),
                        "fake retained device number disagrees with sysfs"
                    );
                    Ok(())
                }
                FakeIdentity::Error(message) => anyhow::bail!("{message}"),
            }
        }

        fn ext4_uuid(&self) -> Result<RandomId128> {
            match next_scripted(&mut self.state.lock().unwrap().uuids, "UUID")? {
                FakeUuid::Value(uuid) => Ok(uuid),
                FakeUuid::Error(message) => anyhow::bail!("{message}"),
            }
        }
    }

    fn snapshot(slot: u16, serial: &str, number: (u32, u32)) -> DeviceSnapshot {
        let name = virtio_block_name(usize::from(slot));
        DeviceSnapshot {
            guest_device: GuestDeviceIdentity {
                serial: Id::new(serial).unwrap(),
                slot,
            },
            physical_device_path: PathBuf::from("/dev").join(&name),
            device_path: HostPath::new(format!("/dev/{name}")).unwrap(),
            name,
            device_major: number.0,
            device_minor: number.1,
            size_bytes: 4_294_967_296,
        }
    }

    fn uuid(byte: u8) -> RandomId128 {
        RandomId128::new(hex::encode([byte; 16])).unwrap()
    }

    fn fake_provider(
        device_samples: Vec<Vec<DeviceSnapshot>>,
        mountinfo_samples: Vec<&str>,
        retained: Vec<(&str, Vec<FakeIdentity>, Vec<FakeUuid>)>,
    ) -> FakePhysicalProvider {
        FakePhysicalProvider {
            state: Arc::new(Mutex::new(FakeProviderState {
                device_samples: device_samples.into(),
                mountinfo_samples: mountinfo_samples
                    .into_iter()
                    .map(|sample| sample.as_bytes().to_vec())
                    .collect(),
                retained: retained
                    .into_iter()
                    .map(|(name, identities, uuids)| {
                        (
                            name.to_owned(),
                            FakeRetainedBlockDevice {
                                state: Arc::new(Mutex::new(FakeRetainedState {
                                    identities: identities.into(),
                                    uuids: uuids.into(),
                                })),
                            },
                        )
                    })
                    .collect(),
                device_sample_count: 0,
                mountinfo_sample_count: 0,
                retain_count: BTreeMap::new(),
            })),
        }
    }

    fn stable_provider(
        devices: Vec<DeviceSnapshot>,
        mountinfo: &str,
        uuids: &[(&str, RandomId128)],
    ) -> FakePhysicalProvider {
        let by_name: BTreeMap<&str, RandomId128> = uuids.iter().cloned().collect();
        let retained = devices
            .iter()
            .map(|device| {
                (
                    device.name.as_str(),
                    vec![FakeIdentity::Exact(
                        device.device_major,
                        device.device_minor,
                    )],
                    vec![FakeUuid::Value(
                        by_name
                            .get(device.name.as_str())
                            .expect("UUID supplied for fake device")
                            .clone(),
                    )],
                )
            })
            .collect();
        fake_provider(vec![devices.clone()], vec![mountinfo], retained)
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
        let devices = vec![
            snapshot(0, "cats-root", (252, 0)),
            snapshot(1, "cats-data", (252, 16)),
        ];
        let provider = stable_provider(
            devices,
            "20 1 0:20 / /proc rw,nosuid - proc proc rw\n31 1 252:16 / /data ro,relatime - ext4 /dev/vdb ro\n30 1 252:0 / / rw,relatime - ext4 /dev/vda rw\n",
            &[("vda", uuid(0xaa)), ("vdb", uuid(0xbb))],
        );
        let provider_state = provider.state.clone();
        let collector = RuntimeReadyCollector::for_test(provider);
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
        let state = provider_state.lock().unwrap();
        assert_eq!(state.device_sample_count, 2);
        assert_eq!(state.mountinfo_sample_count, 2);
        assert_eq!(state.retain_count.get("vda"), Some(&1));
        assert_eq!(state.retain_count.get("vdb"), Some(&1));
    }

    #[test]
    fn collector_normalizes_source_alias_and_fails_closed_on_uuid_and_mount_drift() {
        let device = snapshot(0, "cats-root", (252, 0));
        let provider = stable_provider(
            vec![device.clone()],
            "30 1 252:0 / / rw - ext4 /proc/self/fd/19 rw\n",
            &[("vda", uuid(0xaa))],
        );
        let collector = RuntimeReadyCollector::for_test(provider);
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
        assert_eq!(ready.mounts[0].source_path.as_str(), "/dev/vda");

        let provider = fake_provider(
            vec![vec![device.clone()]],
            vec![
                "30 1 252:0 / / rw - ext4 /dev/vda rw\n",
                "30 1 252:0 / / ro - ext4 /dev/vda ro\n",
            ],
            vec![(
                "vda",
                vec![FakeIdentity::Exact(252, 0)],
                vec![FakeUuid::Value(uuid(0xaa))],
            )],
        );
        let collector = RuntimeReadyCollector::for_test(provider);
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
            .contains("mountinfo changed"));

        let provider = fake_provider(
            vec![vec![device]],
            vec!["30 1 252:0 / / rw - ext4 /dev/vda rw\n"],
            vec![(
                "vda",
                vec![FakeIdentity::Exact(252, 0)],
                vec![FakeUuid::Value(uuid(0xaa)), FakeUuid::Value(uuid(0xbb))],
            )],
        );
        let collector = RuntimeReadyCollector::for_test(provider);
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
            .contains("UUID changed"));
    }

    #[test]
    fn collector_rejects_duplicate_mounts_and_oversized_inventory() {
        assert_eq!(RUNTIME_READY_MAX_DEVICES_V1, 64);
        assert_eq!(RUNTIME_READY_MAX_MOUNTS_V1, 64);
        let collector = RuntimeReadyCollector::for_test(stable_provider(
            vec![snapshot(0, "cats-root", (252, 0))],
            "30 1 252:0 / / rw - ext4 /dev/vda rw\n31 1 252:0 / / rw - ext4 /dev/vda rw\n",
            &[("vda", uuid(0xaa))],
        ));
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

        let devices = (0..=RUNTIME_READY_MAX_DEVICES_V1)
            .map(|slot| {
                snapshot(
                    u16::try_from(slot).unwrap(),
                    &format!("serial{slot}"),
                    (252, u32::try_from(slot).unwrap()),
                )
            })
            .collect();
        let collector =
            RuntimeReadyCollector::for_test(fake_provider(vec![devices], vec![""], Vec::new()));
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
    fn collector_rejects_every_mid_sample_device_mutation() {
        let first = snapshot(0, "cats-root", (252, 0));
        let mut mutations = Vec::new();
        let mut serial = first.clone();
        serial.guest_device.serial = Id::new("cats-other").unwrap();
        mutations.push(serial);
        let mut size = first.clone();
        size.size_bytes += SECTOR_BYTES;
        mutations.push(size);
        let mut number = first.clone();
        number.device_minor = 1;
        mutations.push(number);

        for second in mutations {
            let provider = fake_provider(
                vec![vec![first.clone()], vec![second]],
                vec!["30 1 252:0 / / rw - ext4 /dev/vda rw\n"],
                vec![(
                    "vda",
                    vec![FakeIdentity::Exact(252, 0)],
                    vec![FakeUuid::Value(uuid(0xaa))],
                )],
            );
            let error = RuntimeReadyCollector::for_test(provider)
                .collect(
                    request(),
                    VsockLocalEndpoint {
                        cid: 3,
                        port: 5_000,
                    },
                    "33333333333333333333333333333333",
                )
                .unwrap_err();
            assert!(error.to_string().contains("inventory changed"), "{error:#}");
        }
    }

    #[test]
    fn collector_rejects_retained_path_replacement_and_unformatted_uuid() {
        let device = snapshot(0, "cats-root", (252, 0));
        let provider = fake_provider(
            vec![vec![device.clone()]],
            vec!["30 1 252:0 / / rw - ext4 /dev/vda rw\n"],
            vec![(
                "vda",
                vec![
                    FakeIdentity::Exact(252, 0),
                    FakeIdentity::Error("retained block device path was replaced"),
                ],
                vec![FakeUuid::Value(uuid(0xaa))],
            )],
        );
        let error = RuntimeReadyCollector::for_test(provider)
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 3,
                    port: 5_000,
                },
                "33333333333333333333333333333333",
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("path was replaced"));

        let provider = fake_provider(
            vec![vec![device]],
            vec!["30 1 252:0 / / rw - ext4 /dev/vda rw\n"],
            vec![(
                "vda",
                vec![FakeIdentity::Exact(252, 0)],
                vec![FakeUuid::Error("block device is not formatted as ext4")],
            )],
        );
        let error = RuntimeReadyCollector::for_test(provider)
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 3,
                    port: 5_000,
                },
                "33333333333333333333333333333333",
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("not formatted as ext4"));
    }

    #[test]
    fn system_provider_rejects_regular_and_symlink_device_paths() {
        let root = tempfile::tempdir().unwrap();
        let regular = root.path().join("vda");
        std::fs::write(&regular, [0_u8; 2_048]).unwrap();
        let provider = SystemPhysicalProvider {
            sys_block_root: root.path().join("sys"),
            dev_root: root.path().to_path_buf(),
            reported_dev_root: PathBuf::from("/dev"),
            mountinfo_path: root.path().join("mountinfo"),
        };
        let mut device = snapshot(0, "cats-root", (252, 0));
        device.physical_device_path = regular;
        let error = match provider.retain_device(&device) {
            Ok(_) => panic!("regular file was accepted as a block device"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("not a block device"));

        let symlink = root.path().join("vdb");
        std::os::unix::fs::symlink(root.path().join("vda"), &symlink).unwrap();
        device.physical_device_path = symlink;
        let error = match provider.retain_device(&device) {
            Ok(_) => panic!("symlink was accepted as a block device"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("O_NOFOLLOW"));
    }

    #[test]
    fn accepted_vsock_endpoint_must_match_challenged_cid_before_physical_reads() {
        let provider = stable_provider(Vec::new(), "", &[]);
        let state = provider.state.clone();
        let error = RuntimeReadyCollector::for_test(provider)
            .collect(
                request(),
                VsockLocalEndpoint {
                    cid: 4,
                    port: 5_000,
                },
                "33333333333333333333333333333333",
            )
            .unwrap_err();
        assert!(error.to_string().contains("accepted AF_VSOCK"));
        let state = state.lock().unwrap();
        assert_eq!(state.device_sample_count, 0);
        assert_eq!(state.mountinfo_sample_count, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "SSM-scoped: requires a real ext4 virtio-blk Guest device"]
    fn real_linux_virtio_block_uses_retained_fd_and_exact_sysfs_identity() {
        let device_path = PathBuf::from(
            std::env::var_os("CATS_RUNTIME_READY_TEST_BLOCK_DEVICE")
                .expect("set CATS_RUNTIME_READY_TEST_BLOCK_DEVICE to a direct /dev/vd* node"),
        );
        let name = device_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("test block device basename is UTF-8")
            .to_owned();
        assert!(name.starts_with("vd"), "test device must be virtio-blk");
        let provider = SystemPhysicalProvider {
            sys_block_root: PathBuf::from("/sys/block"),
            dev_root: device_path
                .parent()
                .expect("test block device has a parent")
                .to_path_buf(),
            reported_dev_root: PathBuf::from("/dev"),
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
        };
        let devices_first = provider.sample_devices().unwrap();
        let device = devices_first
            .iter()
            .find(|device| device.name == name)
            .expect("test device appears in /sys/block");
        let retained = provider.retain_device(device).unwrap();
        retained
            .verify_identity(device.device_major, device.device_minor)
            .unwrap();
        let first_uuid = retained.ext4_uuid().unwrap();
        let second_uuid = retained.ext4_uuid().unwrap();
        assert_eq!(first_uuid, second_uuid);
        retained
            .verify_identity(device.device_major, device.device_minor)
            .unwrap();
        assert_eq!(devices_first, provider.sample_devices().unwrap());
        assert_eq!(
            provider.sample_mountinfo().unwrap(),
            provider.sample_mountinfo().unwrap()
        );
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

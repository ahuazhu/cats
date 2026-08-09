//! Shared fail-closed readers for the one installed runtime release.

use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_reconciliation::{
    decode_guest_runtime_profile_receipt, ContractVersion, GuestRuntimeProfileReceipt,
    Sha256Digest, WireU64, GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES,
};

pub const GUEST_RUNTIME_PROFILE_RECEIPT_PATH: &str =
    "/opt/cats/release/guest-runtime-profile.v1.json";
pub const GUEST_RUNTIME_RELEASE_MANIFEST_PATH: &str =
    "/opt/cats/release/guest-runtime-release-manifest.v1.json";
pub const GUEST_KERNEL_PATH: &str = "/opt/cats/guest/vmlinuz";
pub const GUEST_INITRAMFS_PATH: &str = "/opt/cats/guest/initramfs.img";
pub const GUEST_RUNTIME_PROFILE_RECEIPT_ENV: &str = "CATS_GUEST_RUNTIME_PROFILE_RECEIPT_FILE";
pub const GUEST_RUNTIME_RELEASE_MANIFEST_MAX_BYTES: usize = 4_096;
pub const GUEST_BOOT_MEMBER_MAX_BYTES: usize = 536_870_912;

const RELEASE_ID_DOMAIN: &[u8] = b"cats.release.guest-runtime-manifest.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRuntimeReleaseManifest {
    pub version: ContractVersion,
    pub guest_runtime_profile: GuestRuntimeReleaseMember,
    pub kernel: GuestRuntimeReleaseMember,
    pub initramfs: Option<GuestRuntimeReleaseMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRuntimeReleaseMember {
    pub path: String,
    pub sha256: Sha256Digest,
    pub size_bytes: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledGuestRuntimeProfileReceipt {
    receipt: GuestRuntimeProfileReceipt,
    exact_bytes: Vec<u8>,
    manifest: GuestRuntimeReleaseManifest,
    exact_manifest_bytes: Vec<u8>,
    release_id: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRuntimeBootContract {
    kernel: GuestRuntimeReleaseMember,
    initramfs: Option<GuestRuntimeReleaseMember>,
}

impl GuestRuntimeBootContract {
    pub fn kernel(&self) -> &GuestRuntimeReleaseMember {
        &self.kernel
    }

    pub fn initramfs(&self) -> Option<&GuestRuntimeReleaseMember> {
        self.initramfs.as_ref()
    }
}

/// Open descriptors whose exact bytes were revalidated immediately before a
/// VMM launch. Passing `/proc/self/fd/<n>` for these descriptors closes the
/// validate/path-replacement race.
#[derive(Debug)]
pub struct VerifiedGuestRuntimeLaunch {
    kernel: File,
    initramfs: Option<File>,
}

impl VerifiedGuestRuntimeLaunch {
    pub fn kernel(&self) -> &File {
        &self.kernel
    }

    pub fn initramfs(&self) -> Option<&File> {
        self.initramfs.as_ref()
    }
}

impl InstalledGuestRuntimeProfileReceipt {
    pub fn receipt(&self) -> &GuestRuntimeProfileReceipt {
        &self.receipt
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub fn manifest(&self) -> &GuestRuntimeReleaseManifest {
        &self.manifest
    }

    pub fn exact_manifest_bytes(&self) -> &[u8] {
        &self.exact_manifest_bytes
    }

    pub fn release_id(&self) -> &Sha256Digest {
        &self.release_id
    }

    pub fn boot_contract(&self) -> GuestRuntimeBootContract {
        GuestRuntimeBootContract {
            kernel: self.manifest.kernel.clone(),
            initramfs: self.manifest.initramfs.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeArtifactError {
    #[error("Guest runtime profile receipt path must be the canonical installed path")]
    WrongReceiptPath,
    #[error("Guest runtime release is not supported on this platform")]
    UnsupportedPlatform,
    #[error("Guest runtime release filesystem contract failed at {path}")]
    Filesystem { path: PathBuf },
    #[error("Guest runtime release exceeds its wire or member limit")]
    LimitExceeded,
    #[error("Guest runtime release contract is invalid")]
    InvalidReceipt,
}

pub fn load_installed_guest_runtime_profile_receipt(
    selected_path: &Path,
) -> Result<InstalledGuestRuntimeProfileReceipt, RuntimeArtifactError> {
    if selected_path != Path::new(GUEST_RUNTIME_PROFILE_RECEIPT_PATH) {
        return Err(RuntimeArtifactError::WrongReceiptPath);
    }
    load_installed_guest_runtime_profile_receipt_platform(selected_path)
}

#[cfg(unix)]
fn load_installed_guest_runtime_profile_receipt_platform(
    receipt_path: &Path,
) -> Result<InstalledGuestRuntimeProfileReceipt, RuntimeArtifactError> {
    validate_directory_chain(
        &["/", "/opt", "/opt/cats"],
        Some((Path::new("/opt/cats/release"), 0o755)),
    )?;
    let manifest_path = Path::new(GUEST_RUNTIME_RELEASE_MANIFEST_PATH);
    let exact_manifest_bytes =
        read_exact_installed_file(manifest_path, GUEST_RUNTIME_RELEASE_MANIFEST_MAX_BYTES)?;
    let manifest = decode_release_manifest(&exact_manifest_bytes)?;
    let exact_bytes =
        read_exact_installed_file(receipt_path, GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES)?;
    validate_member_bytes(
        &manifest.guest_runtime_profile,
        "guest-runtime-profile.v1.json",
        &exact_bytes,
        GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES,
    )?;
    let receipt = decode_guest_runtime_profile_receipt(&exact_bytes)
        .map_err(|_| RuntimeArtifactError::InvalidReceipt)?;
    if manifest.kernel.sha256 != receipt.kernel_digest
        || manifest.initramfs.as_ref().map(|member| &member.sha256)
            != receipt.initramfs_digest.as_ref()
    {
        return Err(RuntimeArtifactError::InvalidReceipt);
    }
    let release_id = release_id(&exact_manifest_bytes);
    Ok(InstalledGuestRuntimeProfileReceipt {
        receipt,
        exact_bytes,
        manifest,
        exact_manifest_bytes,
        release_id,
    })
}

#[cfg(not(unix))]
fn load_installed_guest_runtime_profile_receipt_platform(
    _path: &Path,
) -> Result<InstalledGuestRuntimeProfileReceipt, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

/// Node-only validation of the exact boot bytes named by the shared receipt.
#[cfg(unix)]
pub fn validate_installed_node_guest_runtime(
    installed: &InstalledGuestRuntimeProfileReceipt,
) -> Result<(), RuntimeArtifactError> {
    validate_directory_chain(
        &["/", "/opt", "/opt/cats"],
        Some((Path::new("/opt/cats/guest"), 0o755)),
    )?;
    let kernel =
        read_exact_installed_file(Path::new(GUEST_KERNEL_PATH), GUEST_BOOT_MEMBER_MAX_BYTES)?;
    validate_member_bytes(
        &installed.manifest.kernel,
        "guest/vmlinuz",
        &kernel,
        GUEST_BOOT_MEMBER_MAX_BYTES,
    )?;
    match &installed.manifest.initramfs {
        Some(member) => {
            let initramfs = read_exact_installed_file(
                Path::new(GUEST_INITRAMFS_PATH),
                GUEST_BOOT_MEMBER_MAX_BYTES,
            )?;
            validate_member_bytes(
                member,
                "guest/initramfs.img",
                &initramfs,
                GUEST_BOOT_MEMBER_MAX_BYTES,
            )?;
        }
        None => match std::fs::symlink_metadata(GUEST_INITRAMFS_PATH) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(filesystem_error(Path::new(GUEST_INITRAMFS_PATH))),
        },
    }
    Ok(())
}

#[cfg(unix)]
pub fn open_verified_guest_runtime_launch(
    contract: &GuestRuntimeBootContract,
    kernel_path: &Path,
    initramfs_path: Option<&Path>,
) -> Result<VerifiedGuestRuntimeLaunch, RuntimeArtifactError> {
    if kernel_path != Path::new(GUEST_KERNEL_PATH)
        || initramfs_path
            != contract
                .initramfs
                .as_ref()
                .map(|_| Path::new(GUEST_INITRAMFS_PATH))
    {
        return Err(RuntimeArtifactError::InvalidReceipt);
    }
    let kernel = open_verified_installed_member(
        kernel_path,
        &contract.kernel,
        "guest/vmlinuz",
        GUEST_BOOT_MEMBER_MAX_BYTES,
    )?;
    let initramfs = match (&contract.initramfs, initramfs_path) {
        (Some(member), Some(path)) => Some(open_verified_installed_member(
            path,
            member,
            "guest/initramfs.img",
            GUEST_BOOT_MEMBER_MAX_BYTES,
        )?),
        (None, None) => None,
        _ => return Err(RuntimeArtifactError::InvalidReceipt),
    };
    Ok(VerifiedGuestRuntimeLaunch { kernel, initramfs })
}

#[cfg(not(unix))]
pub fn open_verified_guest_runtime_launch(
    _contract: &GuestRuntimeBootContract,
    _kernel_path: &Path,
    _initramfs_path: Option<&Path>,
) -> Result<VerifiedGuestRuntimeLaunch, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

#[cfg(not(unix))]
pub fn validate_installed_node_guest_runtime(
    _installed: &InstalledGuestRuntimeProfileReceipt,
) -> Result<(), RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

fn decode_release_manifest(
    bytes: &[u8],
) -> Result<GuestRuntimeReleaseManifest, RuntimeArtifactError> {
    if bytes.len() > GUEST_RUNTIME_RELEASE_MANIFEST_MAX_BYTES {
        return Err(RuntimeArtifactError::LimitExceeded);
    }
    let manifest: GuestRuntimeReleaseManifest =
        serde_json::from_slice(bytes).map_err(|_| RuntimeArtifactError::InvalidReceipt)?;
    let canonical = crate::runtime_reconciliation::canonical_json_value_bytes(
        &serde_json::to_value(&manifest).map_err(|_| RuntimeArtifactError::InvalidReceipt)?,
    );
    if canonical != bytes
        || manifest.version != ContractVersion::V1
        || manifest.guest_runtime_profile.path != "guest-runtime-profile.v1.json"
        || manifest.kernel.path != "guest/vmlinuz"
        || manifest
            .initramfs
            .as_ref()
            .is_some_and(|member| member.path != "guest/initramfs.img")
        || manifest.guest_runtime_profile.size_bytes.get() == 0
        || manifest.kernel.size_bytes.get() == 0
        || manifest
            .initramfs
            .as_ref()
            .is_some_and(|member| member.size_bytes.get() == 0)
        || manifest.guest_runtime_profile.size_bytes.get()
            > GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES as u64
        || manifest.kernel.size_bytes.get() > GUEST_BOOT_MEMBER_MAX_BYTES as u64
        || manifest
            .initramfs
            .as_ref()
            .is_some_and(|member| member.size_bytes.get() > GUEST_BOOT_MEMBER_MAX_BYTES as u64)
    {
        return Err(RuntimeArtifactError::InvalidReceipt);
    }
    Ok(manifest)
}

fn validate_member_bytes(
    member: &GuestRuntimeReleaseMember,
    expected_path: &str,
    bytes: &[u8],
    cap: usize,
) -> Result<(), RuntimeArtifactError> {
    if member.path != expected_path
        || bytes.is_empty()
        || bytes.len() > cap
        || member.size_bytes.get() != bytes.len() as u64
        || member.sha256 != Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    {
        return Err(RuntimeArtifactError::InvalidReceipt);
    }
    Ok(())
}

fn release_id(exact_manifest: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(RELEASE_ID_DOMAIN);
    digest.update([0]);
    digest.update(exact_manifest);
    Sha256Digest::from_bytes(digest.finalize().into())
}

#[cfg(unix)]
fn validate_directory_chain(
    ancestors: &[&str],
    exact: Option<(&Path, u32)>,
) -> Result<(), RuntimeArtifactError> {
    use std::os::unix::fs::MetadataExt as _;

    for path in ancestors.iter().map(Path::new) {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| filesystem_error(path))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(filesystem_error(path));
        }
    }
    if let Some((path, mode)) = exact {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| filesystem_error(path))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != mode
        {
            return Err(filesystem_error(path));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_installed_file(path: &Path, cap: usize) -> Result<Vec<u8>, RuntimeArtifactError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| filesystem_error(path))?;
    let before = StableFileMetadata::new(&file.metadata().map_err(|_| filesystem_error(path))?);
    if !before.is_exact_installed_file() {
        return Err(filesystem_error(path));
    }
    if before.len > cap as u64 {
        return Err(RuntimeArtifactError::LimitExceeded);
    }
    let mut bytes = Vec::with_capacity(before.len as usize);
    file.by_ref()
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| filesystem_error(path))?;
    if bytes.len() > cap {
        return Err(RuntimeArtifactError::LimitExceeded);
    }
    let after = StableFileMetadata::new(&file.metadata().map_err(|_| filesystem_error(path))?);
    if before != after || bytes.len() as u64 != after.len {
        return Err(filesystem_error(path));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_verified_installed_member(
    path: &Path,
    member: &GuestRuntimeReleaseMember,
    expected_path: &str,
    cap: usize,
) -> Result<File, RuntimeArtifactError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| filesystem_error(path))?;
    let before = StableFileMetadata::new(&file.metadata().map_err(|_| filesystem_error(path))?);
    if !before.is_exact_installed_file()
        || before.len == 0
        || before.len > cap as u64
        || member.path != expected_path
        || member.size_bytes.get() != before.len
    {
        return Err(filesystem_error(path));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut observed = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| filesystem_error(path))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or(RuntimeArtifactError::LimitExceeded)?;
        if observed > cap as u64 {
            return Err(RuntimeArtifactError::LimitExceeded);
        }
        digest.update(&buffer[..count]);
    }
    let after = StableFileMetadata::new(&file.metadata().map_err(|_| filesystem_error(path))?);
    if before != after
        || observed != after.len
        || member.sha256 != Sha256Digest::from_bytes(digest.finalize().into())
    {
        return Err(filesystem_error(path));
    }
    file.rewind().map_err(|_| filesystem_error(path))?;
    Ok(file)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableFileMetadata {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[cfg(unix)]
impl StableFileMetadata {
    fn new(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }

    fn is_exact_installed_file(self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
            && self.mode & 0o777 == 0o644
            && self.uid == 0
            && self.gid == 0
            && self.nlink == 1
    }
}

fn filesystem_error(path: &Path) -> RuntimeArtifactError {
    RuntimeArtifactError::Filesystem {
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECEIPT: &[u8] = br#"{"guest_agent_protocol_version":1,"initramfs_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","kernel_cmdline":"console=ttyS0 root=/dev/vda rw clocksource=kvm-clock","kernel_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","version":1}"#;
    const MANIFEST: &[u8] = br#"{"guest_runtime_profile":{"path":"guest-runtime-profile.v1.json","sha256":"sha256:dae6f9b08706e17d03cbeece8141fef960185fe0758f80f999f9f2218d43e10a","size_bytes":301},"initramfs":{"path":"guest/initramfs.img","sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size_bytes":8388608},"kernel":{"path":"guest/vmlinuz","sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size_bytes":16777216},"version":1}"#;

    #[test]
    fn fixed_manifest_vector_and_release_id_are_exact() {
        assert_eq!(RECEIPT.len(), 301);
        let manifest = decode_release_manifest(MANIFEST).unwrap();
        validate_member_bytes(
            &manifest.guest_runtime_profile,
            "guest-runtime-profile.v1.json",
            RECEIPT,
            GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES,
        )
        .unwrap();
        assert_eq!(
            release_id(MANIFEST).as_str(),
            "sha256:dfe2076171c35378fc247191c43a27a3ea9f819cc99c5cdf107157ce50918e5e"
        );
        let mut changed = MANIFEST.to_vec();
        changed.insert(1, b' ');
        assert!(decode_release_manifest(&changed).is_err());
    }

    #[test]
    fn receipt_path_selection_rejects_every_alternate_before_filesystem_access() {
        assert!(matches!(
            load_installed_guest_runtime_profile_receipt(Path::new("relative.json")),
            Err(RuntimeArtifactError::WrongReceiptPath)
        ));
    }

    #[test]
    fn launch_revalidation_rejects_noncanonical_paths_before_filesystem_access() {
        let manifest = decode_release_manifest(MANIFEST).unwrap();
        let contract = GuestRuntimeBootContract {
            kernel: manifest.kernel,
            initramfs: manifest.initramfs,
        };
        assert!(matches!(
            open_verified_guest_runtime_launch(
                &contract,
                Path::new("/tmp/vmlinuz"),
                Some(Path::new(GUEST_INITRAMFS_PATH)),
            ),
            Err(RuntimeArtifactError::InvalidReceipt)
        ));
    }
}

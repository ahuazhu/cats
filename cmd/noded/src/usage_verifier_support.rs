//! Shared protected-file and durable-receipt boundary for Usage host verifiers.

#[cfg(not(target_os = "linux"))]
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_VERIFICATION_RECEIPT_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    modified_nanoseconds: i128,
    changed_nanoseconds: i128,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            size: metadata.size(),
            modified_nanoseconds: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            changed_nanoseconds: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        }
    }
}

pub(crate) struct ProtectedFile {
    file: File,
    identity: FileIdentity,
}

impl ProtectedFile {
    pub(crate) fn read_bounded(mut self, maximum: u64, description: &str) -> Result<Vec<u8>> {
        let capacity = usize::try_from(self.identity.size)
            .context("protected input size does not fit this host")?;
        let mut bytes = Vec::with_capacity(capacity);
        Read::by_ref(&mut self.file)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {description}"))?;
        let after = FileIdentity::from_metadata(
            &self
                .file
                .metadata()
                .with_context(|| format!("reinspect {description}"))?,
        );
        if after != self.identity || bytes.len() as u64 != self.identity.size {
            bail!("{description} changed while it was read");
        }
        Ok(bytes)
    }

    // Shared verifier-support surface: the schema verifier consumes this on
    // Linux while the terminal-receipt verifier compiles the same module
    // without needing it, so its per-binary dead-code analysis is expected.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub(crate) fn proc_fd_path(&self) -> String {
        use std::os::fd::AsRawFd;
        format!("/proc/self/fd/{}", self.file.as_raw_fd())
    }
}

pub(crate) fn effective_uid() -> u32 {
    // SAFETY: `geteuid` accepts no pointers and only reads the process's
    // effective credential, so it cannot violate Rust memory invariants.
    unsafe { libc::geteuid() }
}

pub(crate) fn effective_gid() -> u32 {
    // SAFETY: `getegid` has the same no-pointer credential-read contract as
    // `geteuid` above.
    unsafe { libc::getegid() }
}

fn validate_root_directory_chain(path: &Path, private_leaf: bool) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("protected path must be absolute");
    }
    let ancestor_count = path.ancestors().count();
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for (index, directory) in ancestors.into_iter().enumerate() {
        let metadata = fs::symlink_metadata(directory)
            .with_context(|| format!("inspect protected directory {}", directory.display()))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            bail!("protected path has an unsafe directory component");
        }
        if private_leaf && index + 1 == ancestor_count && metadata.mode() & 0o077 != 0 {
            bail!("receipt directory must be root-only");
        }
    }
    Ok(())
}

pub(crate) fn open_protected_input(
    path: &Path,
    maximum: u64,
    allowed_modes: &[u32],
    description: &str,
) -> Result<ProtectedFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("protected input has no parent")?;
    validate_root_directory_chain(parent, false)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("securely open {description}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {description}"))?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || !allowed_modes.contains(&mode)
        || metadata.size() == 0
        || metadata.size() > maximum
    {
        bail!("{description} violates its root-owned closed file contract");
    }
    Ok(ProtectedFile {
        identity: FileIdentity::from_metadata(&metadata),
        file,
    })
}

pub(crate) fn hash_running_executable() -> Result<String> {
    #[cfg(target_os = "linux")]
    let executable = Path::new("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let executable_path = env::current_exe().context("resolve running executable")?;
    #[cfg(not(target_os = "linux"))]
    let executable = executable_path.as_path();

    // `/proc/self/exe` is a kernel-held reference to the running image. It is
    // intentionally opened without O_NOFOLLOW on Linux; ordinary operator
    // paths are never granted this exception.
    let mut file = File::open(executable).context("open running executable image")?;
    let before = FileIdentity::from_metadata(
        &file
            .metadata()
            .context("inspect running executable image")?,
    );
    if before.uid != 0
        || before.gid != 0
        || before.links != 1
        || before.mode & 0o777 != 0o755
        || before.size == 0
        || before.size > MAX_EXECUTABLE_BYTES
    {
        bail!("running executable violates the installed release contract");
    }
    let mut hasher = Sha256::new();
    let copied = io::copy(
        &mut Read::by_ref(&mut file).take(MAX_EXECUTABLE_BYTES + 1),
        &mut hasher,
    )
    .context("hash running executable image")?;
    let after = FileIdentity::from_metadata(
        &file
            .metadata()
            .context("reinspect running executable image")?,
    );
    if before != after || copied != before.size {
        bail!("running executable changed while it was hashed");
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub(crate) fn validate_lower_hex(value: &str, length: usize, description: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{description} is not canonical lowercase hexadecimal");
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, description: &str) -> Result<()> {
    let hex = value
        .strip_prefix("sha256:")
        .context("digest lacks sha256 prefix")?;
    validate_lower_hex(hex, 64, description)
}

fn open_receipt_directory(parent: &Path) -> Result<File> {
    validate_root_directory_chain(parent, true)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(parent).context("open receipt directory")
}

fn read_existing_receipt(path: &Path, expected: &[u8]) -> Result<Option<FileIdentity>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("securely open existing verification receipt"),
    };
    let before = FileIdentity::from_metadata(
        &file
            .metadata()
            .context("inspect existing verification receipt")?,
    );
    if before.uid != 0
        || before.gid != 0
        || !(before.links == 1 || before.links == 2)
        || before.mode & 0o777 != 0o600
        || before.size == 0
        || before.size > MAX_VERIFICATION_RECEIPT_BYTES
    {
        bail!("existing verification receipt violates its closed file contract");
    }
    let mut bytes = Vec::with_capacity(before.size as usize);
    Read::by_ref(&mut file)
        .take(MAX_VERIFICATION_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read existing verification receipt")?;
    let after = FileIdentity::from_metadata(
        &file
            .metadata()
            .context("reinspect existing verification receipt")?,
    );
    if before != after || bytes.len() as u64 != before.size || bytes != expected {
        bail!("existing verification receipt conflicts with this exact verification");
    }
    Ok(Some(before))
}

pub(crate) fn publish_receipt(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_VERIFICATION_RECEIPT_BYTES {
        bail!("verification receipt exceeds its closed byte limit");
    }
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("receipt output must be an absolute file path");
    }
    let parent = path.parent().context("receipt output has no parent")?;
    let directory = open_receipt_directory(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("receipt output name is not UTF-8")?;
    let pending = parent.join(format!(".{file_name}.pending"));

    if let Some(receipt) = read_existing_receipt(path, bytes)? {
        if let Some(pending_identity) = read_existing_receipt(&pending, bytes)? {
            if receipt.device != pending_identity.device || receipt.inode != pending_identity.inode
            {
                bail!("verification receipt has a conflicting pending publication");
            }
            match fs::remove_file(&pending) {
                Ok(()) => directory
                    .sync_all()
                    .context("sync recovered receipt directory")?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("remove recovered receipt pending link"),
            }
        }
        return Ok(());
    }

    if read_existing_receipt(&pending, bytes)?.is_none() {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&pending)
            .context("create verification receipt pending file")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("protect verification receipt pending file")?;
        file.write_all(bytes)
            .context("write verification receipt pending file")?;
        file.sync_all()
            .context("sync verification receipt pending file")?;
        directory
            .sync_all()
            .context("sync verification receipt pending creation")?;
    }

    match fs::hard_link(&pending, path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let receipt = read_existing_receipt(path, bytes)?
                .context("receipt appeared without exact readable bytes")?;
            let pending_identity = read_existing_receipt(&pending, bytes)?
                .context("receipt pending file disappeared during publication")?;
            if receipt.device != pending_identity.device || receipt.inode != pending_identity.inode
            {
                bail!("a different receipt won no-replace publication");
            }
        }
        Err(error) => {
            return Err(error).context("publish verification receipt without replacement")
        }
    }
    directory
        .sync_all()
        .context("sync published verification receipt")?;
    match fs::remove_file(&pending) {
        Ok(()) => directory
            .sync_all()
            .context("sync verification receipt pending cleanup")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove verification receipt pending link"),
    }
    let final_identity =
        read_existing_receipt(path, bytes)?.context("published verification receipt is absent")?;
    if final_identity.links != 1 {
        bail!("published verification receipt retained an unexpected link");
    }
    Ok(())
}

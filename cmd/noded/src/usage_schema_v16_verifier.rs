//! Release-bound, read-only verifier for the exact Usage PostgreSQL v16 schema.
//!
//! The DSN is accepted only through a protected file and is never emitted in
//! argv, the environment, logs, stdout or the deterministic receipt. The
//! caller verifies this executable against the approved release manifest and
//! installation receipt before invoking it; the receipt records the digest of
//! the executable image that actually performed the verification.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use cats_usage_store_postgres::{
    PostgresUsageStore, USAGE_SCHEMA_V16_CATALOG_SHA256, USAGE_SCHEMA_VERSION,
};
use clap::Parser;
use serde_json::Value;
use sha2::{Digest, Sha256};

const RECEIPT_KIND: &str = "cats.usage-schema-v16-verification.v1";
const RECEIPT_VERSION: u64 = 1;
const MAX_DSN_BYTES: u64 = 16 * 1024;
const MAX_CA_BYTES: u64 = 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 4096;

#[derive(Parser, Debug)]
#[command(
    name = "cats-usage-schema-v16-verifier",
    about = "Verify an existing exact Usage PostgreSQL v16 schema without mutation"
)]
struct Args {
    /// Root-owned mode-0600 file containing exactly one PostgreSQL URL.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    dsn_file: PathBuf,

    /// Root-owned PostgreSQL CA bundle. Production verification never falls
    /// back to an absent CA input.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    ca_file: PathBuf,

    /// Exact dedicated Usage schema selected by the reset plan.
    #[arg(long)]
    schema: String,

    /// Exact release commit already accepted by the reset actor.
    #[arg(long)]
    release_commit: String,

    /// Approved worker bundle digest bound by the installation receipt.
    #[arg(long)]
    worker_bundle_sha256: String,

    /// Reset-private deterministic receipt destination.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    receipt_out: PathBuf,
}

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

struct ProtectedFile {
    file: File,
    identity: FileIdentity,
}

impl ProtectedFile {
    fn read_bounded(mut self, maximum: u64, description: &str) -> Result<Vec<u8>> {
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
}

#[derive(Debug)]
struct Receipt<'a> {
    binary_sha256: &'a str,
    release_commit: &'a str,
    schema: &'a str,
    worker_bundle_sha256: &'a str,
}

impl Receipt<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut value = BTreeMap::<&str, Value>::new();
        value.insert("binary_sha256", self.binary_sha256.into());
        value.insert("catalog_sha256", USAGE_SCHEMA_V16_CATALOG_SHA256.into());
        value.insert("kind", RECEIPT_KIND.into());
        value.insert("release_commit", self.release_commit.into());
        value.insert("schema", self.schema.into());
        value.insert("schema_version", i64::from(USAGE_SCHEMA_VERSION).into());
        value.insert("verified", true.into());
        value.insert("version", RECEIPT_VERSION.into());
        value.insert("worker_bundle_sha256", self.worker_bundle_sha256.into());
        let mut bytes = serde_json::to_vec(&value).context("encode verification receipt")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            bail!("verification receipt exceeds its closed byte limit");
        }
        Ok(bytes)
    }
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` accepts no pointers and only reads the process's
    // effective credential, so it cannot violate Rust memory invariants.
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
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
        if private_leaf && index + 1 == path.ancestors().count() && metadata.mode() & 0o077 != 0 {
            bail!("receipt directory must be root-only");
        }
    }
    Ok(())
}

fn open_protected_input(
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

fn decode_dsn(bytes: Vec<u8>) -> Result<String> {
    let mut value = String::from_utf8(bytes).context("PostgreSQL DSN file is not UTF-8")?;
    if value.ends_with('\n') {
        value.pop();
    }
    if value.is_empty()
        || value.ends_with('\r')
        || value.contains(['\r', '\n'])
        || value.trim() != value
    {
        bail!("PostgreSQL DSN file must contain exactly one non-empty canonical line");
    }
    Ok(value)
}

fn hash_running_executable() -> Result<String> {
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

fn validate_lower_hex(value: &str, length: usize, description: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{description} is not canonical lowercase hexadecimal");
    }
    Ok(())
}

fn validate_sha256(value: &str, description: &str) -> Result<()> {
    let hex = value
        .strip_prefix("sha256:")
        .context("digest lacks sha256 prefix")?;
    validate_lower_hex(hex, 64, description)
}

fn clear_postgres_environment() {
    let names: Vec<_> = env::vars_os()
        .filter_map(|(name, _value)| {
            let name_bytes = name.as_encoded_bytes();
            (name_bytes == b"DATABASE_URL" || name_bytes.starts_with(b"PG")).then_some(name)
        })
        .collect();
    for name in names {
        env::remove_var(name);
    }
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
        || before.size > MAX_RECEIPT_BYTES
    {
        bail!("existing verification receipt violates its closed file contract");
    }
    let mut bytes = Vec::with_capacity(before.size as usize);
    Read::by_ref(&mut file)
        .take(MAX_RECEIPT_BYTES + 1)
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

fn publish_receipt(path: &Path, bytes: &[u8]) -> Result<()> {
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

fn run(args: Args) -> Result<()> {
    if effective_uid() != 0 || effective_gid() != 0 {
        bail!("verification must run with root credentials");
    }
    validate_lower_hex(&args.release_commit, 40, "release commit")?;
    validate_sha256(&args.worker_bundle_sha256, "worker bundle digest")?;

    let dsn = decode_dsn(
        open_protected_input(
            &args.dsn_file,
            MAX_DSN_BYTES,
            &[0o600],
            "PostgreSQL DSN file",
        )?
        .read_bounded(MAX_DSN_BYTES, "PostgreSQL DSN file")?,
    )?;
    let ca_input = open_protected_input(
        &args.ca_file,
        MAX_CA_BYTES,
        &[0o600, 0o644],
        "PostgreSQL CA file",
    )?;

    let binary_sha256 = hash_running_executable()?;
    validate_sha256(&binary_sha256, "running executable digest")?;
    clear_postgres_environment();

    #[cfg(target_os = "linux")]
    let ca_path = format!("/proc/self/fd/{}", ca_input.file.as_raw_fd());
    #[cfg(not(target_os = "linux"))]
    let ca_path = args
        .ca_file
        .to_str()
        .context("PostgreSQL CA path is not UTF-8")?
        .to_string();

    // Keep `ca_input` alive while the adapter re-opens its pinned procfs
    // descriptor. On non-Linux development hosts it still pins and validates
    // the original file around the adapter call.
    let _keep_ca_open = &ca_input;
    PostgresUsageStore::verify_existing_schema_v16(&dsn, Some(&ca_path), &args.schema)
        .map_err(|_error| anyhow::anyhow!("Usage schema verification failed closed"))?;

    let bytes = Receipt {
        binary_sha256: &binary_sha256,
        release_commit: &args.release_commit,
        schema: &args.schema,
        worker_bundle_sha256: &args.worker_bundle_sha256,
    }
    .canonical_bytes()?;
    publish_receipt(&args.receipt_out, &bytes)
}

fn main() {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(_error) => {
            eprintln!("Usage schema v16 verification failed closed");
            std::process::exit(1);
        }
    };
    match run(args) {
        Ok(()) => println!("Usage schema v16 verified"),
        Err(_error) => {
            eprintln!("Usage schema v16 verification failed closed");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn receipt_shape_and_bytes_are_frozen() {
        let bytes = Receipt {
            binary_sha256: SHA,
            release_commit: "0123456789abcdef0123456789abcdef01234567",
            schema: "cats_usage_fresh",
            worker_bundle_sha256: SHA,
        }
        .canonical_bytes()
        .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                "{\"binary_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
                "\"catalog_sha256\":\"sha256:ec10b4afe112dba411466e9b2d67d1cef5d8d232da4ec52c11ced993d771f157\",",
                "\"kind\":\"cats.usage-schema-v16-verification.v1\",",
                "\"release_commit\":\"0123456789abcdef0123456789abcdef01234567\",",
                "\"schema\":\"cats_usage_fresh\",\"schema_version\":16,\"verified\":true,\"version\":1,",
                "\"worker_bundle_sha256\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}\n"
            )
        );
    }

    #[test]
    fn dsn_decoder_accepts_one_optional_lf_and_rejects_ambiguous_lines() {
        assert_eq!(
            decode_dsn(b"postgresql://cats:secret@example/cats?sslmode=verify-full\n".to_vec())
                .unwrap(),
            "postgresql://cats:secret@example/cats?sslmode=verify-full"
        );
        for invalid in [
            b"".as_slice(),
            b"\n".as_slice(),
            b" postgresql://example/cats".as_slice(),
            b"postgresql://example/cats\nsecond".as_slice(),
            b"postgresql://example/cats\r\n".as_slice(),
        ] {
            assert!(decode_dsn(invalid.to_vec()).is_err());
        }
    }

    #[test]
    fn release_identifiers_are_canonical_lowercase_only() {
        assert!(
            validate_lower_hex("0123456789abcdef0123456789abcdef01234567", 40, "commit").is_ok()
        );
        assert!(
            validate_lower_hex("0123456789ABCDEF0123456789abcdef01234567", 40, "commit").is_err()
        );
        assert!(validate_sha256(SHA, "digest").is_ok());
        assert!(validate_sha256(&SHA[7..], "digest").is_err());
    }
}

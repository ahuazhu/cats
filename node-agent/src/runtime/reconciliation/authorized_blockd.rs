//! Descriptor-relative, checkpoint-first inputs for one authorized blockd.
//!
//! This module deliberately stops before process creation. The signed Runtime
//! may persist these exact inputs only after a Normal acquire. They authorize
//! the later control-only root-provision process as well as the eventual
//! serving process, but do not prove either one exists. A later process-owner
//! port must create the systemd service and prove the blockd handshake before
//! any observation calls the lineage serving; writing these files alone is
//! not serving evidence.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::DesiredRuntimeSpec;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, ContractVersion, DiskKind, Durability, Id, RandomId128,
    RuntimeTarget, VolumeAccess, VolumeAcquire, VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, AttachmentLineageIdentity, AuthorizedServingAttachment,
};
use cats_storage::AdapterSelection;
use serde::{Deserialize, Serialize};

use crate::state_directory::StateDirectory;

const DATA_DIRECTORY: &str = "data";
pub(crate) const IDENTITY_FILE: &str = "identity.json";
pub(crate) const IDENTITY_TEMP: &str = ".identity.json.tmp";
pub(crate) const AUTHORIZED_SERVING_FILE: &str = "authorized-serving.json";
pub(crate) const AUTHORIZED_SERVING_TEMP: &str = ".authorized-serving.json.tmp";
pub(crate) const LAUNCH_CHECKPOINT_FILE: &str = "launch-checkpoint.json";
pub(crate) const LAUNCH_CHECKPOINT_TEMP: &str = ".launch-checkpoint.json.tmp";
pub(crate) const MAX_IDENTITY_BYTES: usize = 4 * 1024;
pub(crate) const MAX_AUTHORIZED_SERVING_BYTES: usize = 32 * 1024;
pub(crate) const MAX_LAUNCH_CHECKPOINT_BYTES: usize = 512 * 1024;

/// Exact signed inputs persisted before starting an authorized blockd.
///
/// Keeping the complete Desired (rather than selected fields) gives the
/// inventory scanner a closed binding for runtime config, network config and
/// the one supported root volume. `volume` is repeated intentionally so a
/// consumer cannot silently select a different member of a future multi-disk
/// Desired; validation requires it to equal the sole member exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedBlockdCheckpoint {
    pub version: ContractVersion,
    pub desired: DesiredRuntimeSpec,
    pub volume: VolumeIntent,
    pub attachment: AuthorizedServingAttachment,
}

/// Descriptor-relative store rooted in the identity-selected Node state fd.
#[derive(Clone)]
pub struct AuthorizedBlockdStore {
    state_directory: StateDirectory,
}

impl AuthorizedBlockdStore {
    pub fn new(state_directory: StateDirectory) -> Self {
        Self { state_directory }
    }

    /// Validate and durably publish the exact attachment files in their only
    /// allowed order. Exact replays recover response loss; conflicting bytes,
    /// unsafe entries and residue before the checkpoint fail closed.
    pub fn prepare(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
    ) -> Result<PreparedAuthorizedBlockd> {
        validate_checkpoint_inputs(desired, volume, attachment)?;
        self.prepare_validated(desired, volume, attachment, false)
    }

    /// Persist or reopen an attachment whose exact NormalAcquire receipt was
    /// issued to an older revision of the same-Node Desired. This never
    /// rewrites an existing launch checkpoint: a compatible old checkpoint is
    /// retained as provenance, while an absent directory receives the current
    /// Desired plus the immutable old receipt. The caller must already have a
    /// current Runtime checkpoint authorizing this adoption.
    pub(crate) fn prepare_adopted(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
    ) -> Result<PreparedAuthorizedBlockd> {
        validate_adopted_checkpoint_inputs(desired, volume, attachment)?;
        self.prepare_validated(desired, volume, attachment, true)
    }

    /// Reopen the scanner-attributed attachment and close the scan/effect ABA
    /// window by feeding the decoded candidate back through the locked,
    /// descriptor-relative exact-file verifier in `prepare_adopted`.
    pub(crate) fn reopen_adopted(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        identity: &AttachmentLineageIdentity,
    ) -> Result<PreparedAuthorizedBlockd> {
        let directory =
            authorized_blockd_data_directory(self.state_directory.path(), desired, identity);
        let path = directory.join(AUTHORIZED_SERVING_FILE);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect adopted attachment {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= MAX_AUTHORIZED_SERVING_BYTES as u64,
            "adopted authorized-serving candidate has unsafe metadata"
        );
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read adopted attachment {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() <= MAX_AUTHORIZED_SERVING_BYTES,
            "adopted authorized-serving candidate exceeds its bound"
        );
        let attachment: AuthorizedServingAttachment = serde_json::from_slice(&bytes)
            .context("decode adopted authorized-serving attachment")?;
        anyhow::ensure!(
            serde_json::to_vec(&attachment).context("re-encode adopted attachment")? == bytes
                && attachment.identity == *identity,
            "adopted authorized-serving candidate conflicts with scanned identity"
        );
        self.prepare_adopted(desired, volume, &attachment)
    }

    fn prepare_validated(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
        permit_compatible_superseded_launch: bool,
    ) -> Result<PreparedAuthorizedBlockd> {
        let checkpoint = AuthorizedBlockdCheckpoint {
            version: ContractVersion::V1,
            desired: desired.clone(),
            volume: volume.clone(),
            attachment: attachment.clone(),
        };
        let identity_bytes = bounded_json(
            &attachment.identity,
            MAX_IDENTITY_BYTES,
            "attachment identity",
        )?;
        let attachment_bytes = bounded_json(
            attachment,
            MAX_AUTHORIZED_SERVING_BYTES,
            "authorized serving spec",
        )?;
        let checkpoint_bytes = bounded_json(
            &checkpoint,
            MAX_LAUNCH_CHECKPOINT_BYTES,
            "authorized blockd launch checkpoint",
        )?;

        let root = self
            .state_directory
            .try_clone_directory()
            .context("clone retained Node state directory")?;
        let mut relative = PathBuf::new();
        let mut directory = root;
        for component in directory_components(desired, &attachment.identity) {
            relative.push(&component);
            directory = ensure_directory_at(&directory, &component, &relative)?;
        }
        lock_directory(&directory).with_context(|| {
            format!(
                "lock authorized blockd directory {}",
                self.state_directory.path().join(&relative).display()
            )
        })?;

        persist_ordered_file(
            &directory,
            &relative,
            IDENTITY_FILE,
            IDENTITY_TEMP,
            &identity_bytes,
            &[],
            MAX_IDENTITY_BYTES,
        )?;
        persist_ordered_file(
            &directory,
            &relative,
            AUTHORIZED_SERVING_FILE,
            AUTHORIZED_SERVING_TEMP,
            &attachment_bytes,
            &[IDENTITY_FILE],
            MAX_AUTHORIZED_SERVING_BYTES,
        )?;
        let checkpoint = if permit_compatible_superseded_launch {
            persist_adopted_launch_file(&directory, &relative, &checkpoint, &checkpoint_bytes)?
        } else {
            persist_ordered_file(
                &directory,
                &relative,
                LAUNCH_CHECKPOINT_FILE,
                LAUNCH_CHECKPOINT_TEMP,
                &checkpoint_bytes,
                &[IDENTITY_FILE, AUTHORIZED_SERVING_FILE],
                MAX_LAUNCH_CHECKPOINT_BYTES,
            )?;
            checkpoint
        };

        let data_directory = self.state_directory.path().join(&relative);
        Ok(PreparedAuthorizedBlockd {
            state_directory: self.state_directory.path().to_path_buf(),
            identity_path: data_directory.join(IDENTITY_FILE),
            authorized_serving_path: data_directory.join(AUTHORIZED_SERVING_FILE),
            launch_checkpoint_path: data_directory.join(LAUNCH_CHECKPOINT_FILE),
            data_directory,
            checkpoint,
            // Retain the exclusive cooperative lock through command
            // construction and process handoff.
            _directory_lock: directory,
        })
    }
}

/// Prepared exact files plus the held attachment-directory lock.
#[derive(Debug)]
pub struct PreparedAuthorizedBlockd {
    state_directory: PathBuf,
    data_directory: PathBuf,
    identity_path: PathBuf,
    authorized_serving_path: PathBuf,
    launch_checkpoint_path: PathBuf,
    checkpoint: AuthorizedBlockdCheckpoint,
    _directory_lock: File,
}

impl PreparedAuthorizedBlockd {
    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub fn identity_path(&self) -> &Path {
        &self.identity_path
    }

    pub fn authorized_serving_path(&self) -> &Path {
        &self.authorized_serving_path
    }

    pub fn launch_checkpoint_path(&self) -> &Path {
        &self.launch_checkpoint_path
    }

    pub fn checkpoint(&self) -> &AuthorizedBlockdCheckpoint {
        &self.checkpoint
    }
}

/// Process composition values that are not part of Desired or Volume
/// Authority. Adapter options remain opaque and provider-neutral here.
#[derive(Debug, Clone)]
pub struct AuthorizedBlockdLaunchConfig {
    pub blockd_binary: PathBuf,
    pub metadata_store: AdapterSelection,
    pub object_store: AdapterSelection,
    pub max_staged_bytes: u64,
    pub max_staged_packs: usize,
    pub max_local_bytes: u64,
}

/// Exactly one Guest block frontend for the first Running slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedBlockFrontend {
    NbdUnix {
        socket: PathBuf,
    },
    VhostUser {
        socket: PathBuf,
        queues: usize,
        queue_size: u16,
    },
}

/// Build only the closed authorized-serving CLI. This does not start a child,
/// create a scope or claim that the frontend is ready.
pub fn authorized_blockd_command(
    config: &AuthorizedBlockdLaunchConfig,
    prepared: &PreparedAuthorizedBlockd,
    scope_id: &Id,
    process_identity_token: &RandomId128,
    control_socket: &Path,
    frontend: &AuthorizedBlockFrontend,
) -> Result<Command> {
    anyhow::ensure!(
        config.blockd_binary.is_absolute(),
        "authorized blockd binary must be absolute"
    );
    anyhow::ensure!(
        config.metadata_store.name == "postgres",
        "authorized serving currently requires the frozen postgres authority adapter"
    );
    anyhow::ensure!(
        config.max_staged_bytes > 0 && config.max_staged_packs > 0 && config.max_local_bytes > 0,
        "authorized blockd resource limits must be positive"
    );
    validate_descendant(&prepared.state_directory, control_socket, "control socket")?;
    let frontend_socket = match frontend {
        AuthorizedBlockFrontend::NbdUnix { socket }
        | AuthorizedBlockFrontend::VhostUser { socket, .. } => socket,
    };
    validate_descendant(
        &prepared.state_directory,
        frontend_socket,
        "block frontend socket",
    )?;
    anyhow::ensure!(
        control_socket != frontend_socket,
        "authorized blockd control and frontend sockets must differ"
    );
    if let AuthorizedBlockFrontend::VhostUser {
        queues, queue_size, ..
    } = frontend
    {
        anyhow::ensure!(*queues > 0, "vhost-user queue count must be positive");
        anyhow::ensure!(
            queue_size.is_power_of_two() && *queue_size >= 2,
            "vhost-user queue size must be a power of two of at least 2"
        );
    }

    let checkpoint = prepared.checkpoint();
    let attachment = &checkpoint.attachment;
    let mut command = Command::new(&config.blockd_binary);
    command
        .arg("--volume-id")
        .arg(attachment.identity.volume_id.as_str())
        .arg("--data-dir")
        .arg(prepared.data_directory())
        .arg("--attachment-id")
        .arg(attachment.identity.attachment_id.as_str())
        .arg("--authorized-serving-spec")
        .arg(prepared.authorized_serving_path())
        .arg("--runtime-scope-id")
        .arg(scope_id.as_str())
        .arg("--process-identity-token")
        .arg(process_identity_token.as_str())
        .arg("--metadata-store-adapter")
        .arg(&config.metadata_store.name)
        .arg("--object-store-adapter")
        .arg(&config.object_store.name)
        .arg("--lease-ttl-ms")
        .arg(attachment.acquire_request.lease_duration_ms.to_string())
        .arg("--max-staged-bytes")
        .arg(config.max_staged_bytes.to_string())
        .arg("--max-staged-packs")
        .arg(config.max_staged_packs.to_string())
        .arg("--max-local-bytes")
        .arg(config.max_local_bytes.to_string())
        .arg("--durability")
        .arg(match attachment.durability {
            Durability::Strict => "strict",
            Durability::Relaxed => "relaxed",
        })
        .arg("--listen-control")
        .arg(control_socket);
    match frontend {
        AuthorizedBlockFrontend::NbdUnix { socket } => {
            command.arg("--listen-unix").arg(socket);
        }
        AuthorizedBlockFrontend::VhostUser {
            socket,
            queues,
            queue_size,
        } => {
            command
                .arg("--listen-vhost-user")
                .arg(socket)
                .arg("--vhost-user-queues")
                .arg(queues.to_string())
                .arg("--vhost-user-queue-size")
                .arg(queue_size.to_string());
        }
    }
    for option in config.metadata_store.config.to_cli() {
        command.arg("--metadata-store-option").arg(option);
    }
    for option in config.object_store.config.to_cli() {
        command.arg("--object-store-option").arg(option);
    }
    // Crash injection belongs only to explicit blockd tests. A production
    // Node never forwards an ambient value across this signed seam.
    command.env_remove("CATS_CRASH_POINT");
    Ok(command)
}

fn validate_checkpoint_inputs(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    attachment: &AuthorizedServingAttachment,
) -> Result<()> {
    encode_desired_runtime_spec(desired).context("validate complete DesiredRuntimeSpec")?;
    validate_authorized_serving_attachment(attachment)
        .map_err(|error| anyhow::anyhow!("invalid authorized serving attachment: {error}"))?;
    anyhow::ensure!(
        desired.version == ContractVersion::V1 && desired.target == RuntimeTarget::Running,
        "authorized blockd supports only Runtime Reconciliation v1 Running"
    );
    anyhow::ensure!(
        desired.volumes.len() == 1 && desired.volumes.first() == Some(volume),
        "authorized blockd requires exactly the supplied root volume"
    );
    anyhow::ensure!(
        volume.disk_kind == DiskKind::Root
            && volume.access == VolumeAccess::ReadWriteOnce
            && volume.mount.is_none()
            && matches!(volume.disposition, VolumeDisposition::Retain),
        "authorized blockd first slice supports only an unmounted retained RWO root"
    );
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &volume.acquire
    else {
        anyhow::bail!("authorized blockd first slice requires a Normal acquire");
    };
    let identity = &attachment.identity;
    let request = &attachment.acquire_request;
    anyhow::ensure!(
        volume.volume_id == identity.volume_id
            && volume.attachment_id == identity.attachment_id
            && volume.size_bytes == attachment.size_bytes
            && volume.durability == attachment.durability
            && desired.placement.node_id == identity.node_id
            && desired.placement.placement_epoch == identity.placement_epoch
            && request.transition_id == *transition_id
            && request.expected_unowned_epoch == *expected_unowned_epoch
            && request.desired_revision == desired.desired_revision
            && request.placement_epoch == desired.placement.placement_epoch,
        "Desired, root VolumeIntent and authorized grant do not form one exact lineage"
    );
    Ok(())
}

fn validate_adopted_checkpoint_inputs(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    attachment: &AuthorizedServingAttachment,
) -> Result<()> {
    encode_desired_runtime_spec(desired).context("validate complete DesiredRuntimeSpec")?;
    validate_authorized_serving_attachment(attachment)
        .map_err(|error| anyhow::anyhow!("invalid authorized serving attachment: {error}"))?;
    anyhow::ensure!(
        desired.version == ContractVersion::V1
            && desired.target == RuntimeTarget::Running
            && desired.volumes.len() == 1
            && desired.volumes.first() == Some(volume)
            && volume.disk_kind == DiskKind::Root
            && volume.access == VolumeAccess::ReadWriteOnce
            && volume.mount.is_none()
            && matches!(volume.disposition, VolumeDisposition::Retain),
        "authorized blockd adoption requires one retained RWO Running root"
    );
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &volume.acquire
    else {
        anyhow::bail!("authorized blockd adoption requires a Normal acquire")
    };
    let identity = &attachment.identity;
    let request = &attachment.acquire_request;
    anyhow::ensure!(
        volume.volume_id == identity.volume_id
            && volume.attachment_id == identity.attachment_id
            && volume.size_bytes == attachment.size_bytes
            && volume.durability == attachment.durability
            && desired.placement.node_id == identity.node_id
            && desired.placement.placement_epoch == identity.placement_epoch
            && request.transition_id == *transition_id
            && request.expected_unowned_epoch == *expected_unowned_epoch
            && request.volume_id == volume.volume_id
            && request.attachment_id == volume.attachment_id
            && request.desired_revision <= desired.desired_revision
            && request.placement_epoch == desired.placement.placement_epoch,
        "current Desired and superseded authorized grant are not one adoptable lineage"
    );
    Ok(())
}

pub(crate) fn validate_authorized_blockd_checkpoint(
    checkpoint: &AuthorizedBlockdCheckpoint,
) -> Result<()> {
    anyhow::ensure!(
        checkpoint.version == ContractVersion::V1,
        "authorized blockd checkpoint has an unsupported version"
    );
    validate_checkpoint_inputs(
        &checkpoint.desired,
        &checkpoint.volume,
        &checkpoint.attachment,
    )
    .or_else(|_| {
        validate_adopted_checkpoint_inputs(
            &checkpoint.desired,
            &checkpoint.volume,
            &checkpoint.attachment,
        )
    })
}

fn directory_components(
    desired: &DesiredRuntimeSpec,
    identity: &AttachmentLineageIdentity,
) -> [String; 5] {
    [
        DATA_DIRECTORY.to_owned(),
        format!("cat-{}", desired.cat_id),
        format!("volume-{}", identity.volume_id),
        format!("attachment-{}", identity.attachment_id),
        format!("epoch-{}", identity.attachment_epoch.get()),
    ]
}

/// Deterministic physical path selected by the complete attachment lineage.
/// Inventory admission uses this same function when deciding whether a
/// durable directory left by an interrupted prepare is the exact effect it is
/// allowed to adopt.
pub(crate) fn authorized_blockd_data_directory(
    state_directory: &Path,
    desired: &DesiredRuntimeSpec,
    identity: &AttachmentLineageIdentity,
) -> PathBuf {
    directory_components(desired, identity)
        .into_iter()
        .fold(state_directory.to_path_buf(), |path, component| {
            path.join(component)
        })
}

fn bounded_json<T: Serialize>(value: &T, maximum: usize, label: &str) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).with_context(|| format!("encode {label}"))?;
    anyhow::ensure!(bytes.len() <= maximum, "{label} exceeds {maximum} bytes");
    Ok(bytes)
}

fn ensure_directory_at(parent: &File, name: &str, relative: &Path) -> Result<File> {
    let name_c = c_string(name, relative)?;
    // SAFETY: `parent` is a live directory descriptor and `name_c` remains
    // NUL-terminated for this call. mkdirat retains neither.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } == 0;
    if !created {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(source).with_context(|| format!("create {}", relative.display()));
        }
    } else {
        parent
            .sync_all()
            .with_context(|| format!("sync parent after creating {}", relative.display()))?;
    }
    let directory = open_at(
        parent,
        &name_c,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .with_context(|| format!("open {}", relative.display()))?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect {}", relative.display()))?;
    // SAFETY: geteuid takes no pointers and cannot fail.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o777 == 0o700,
        "authorized blockd directory {} has unsafe metadata",
        relative.display()
    );
    Ok(directory)
}

fn lock_directory(directory: &File) -> io::Result<()> {
    // SAFETY: the descriptor is live and flock retains no Rust memory. The
    // lock remains held by the returned Prepared object.
    let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn persist_ordered_file(
    directory: &File,
    relative_directory: &Path,
    target_name: &str,
    temporary_name: &str,
    expected: &[u8],
    predecessors: &[&str],
    maximum: usize,
) -> Result<()> {
    let target_path = relative_directory.join(target_name);
    let temporary_path = relative_directory.join(temporary_name);
    let target_c = c_string(target_name, &target_path)?;
    let temporary_c = c_string(temporary_name, &temporary_path)?;

    if let Some(bytes) = read_optional_bounded(directory, &target_c, &target_path, maximum)? {
        anyhow::ensure!(
            bytes == expected,
            "{} conflicts with the exact authorized blockd input",
            target_path.display()
        );
        if let Some(temporary) =
            read_optional_bounded(directory, &temporary_c, &temporary_path, maximum)?
        {
            anyhow::ensure!(
                temporary == expected,
                "{} conflicts with the published authorized blockd input",
                temporary_path.display()
            );
            unlink_at(directory, &temporary_c)
                .with_context(|| format!("remove recovered {}", temporary_path.display()))?;
            directory
                .sync_all()
                .with_context(|| format!("sync {}", relative_directory.display()))?;
        }
        return Ok(());
    }

    let mut allowed = predecessors
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    allowed.push(temporary_name.to_owned());
    let entries = directory_entries(directory)
        .with_context(|| format!("enumerate {}", relative_directory.display()))?;
    let unexpected = entries
        .iter()
        .filter(|entry| !allowed.contains(entry))
        .cloned()
        .collect::<Vec<_>>();
    anyhow::ensure!(
        unexpected.is_empty(),
        "authorized blockd input {} is missing beside residue {:?}",
        target_path.display(),
        unexpected
    );
    for predecessor in predecessors {
        let predecessor_path = relative_directory.join(predecessor);
        let predecessor_c = c_string(predecessor, &predecessor_path)?;
        anyhow::ensure!(
            read_optional_bounded(
                directory,
                &predecessor_c,
                &predecessor_path,
                MAX_LAUNCH_CHECKPOINT_BYTES,
            )?
            .is_some(),
            "authorized blockd predecessor {} is missing",
            predecessor_path.display()
        );
    }

    if let Some(bytes) = read_optional_bounded(directory, &temporary_c, &temporary_path, maximum)? {
        anyhow::ensure!(
            bytes == expected,
            "{} conflicts with the exact authorized blockd input",
            temporary_path.display()
        );
    } else {
        let mut file = open_at(
            directory,
            &temporary_c,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .with_context(|| format!("create {}", temporary_path.display()))?;
        verify_regular_file(&file, &temporary_path, Some(0))?;
        file.write_all(expected)
            .with_context(|| format!("write {}", temporary_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary_path.display()))?;
        verify_regular_file(&file, &temporary_path, Some(expected.len() as u64))?;
    }
    #[cfg(test)]
    pause_authorized_publication_for_process_kill(target_name, "temp");

    anyhow::ensure!(
        read_optional_bounded(directory, &target_c, &target_path, maximum)?.is_none(),
        "authorized blockd input {} appeared before publish",
        target_path.display()
    );
    rename_at(directory, &temporary_c, directory, &target_c)
        .with_context(|| format!("publish {}", target_path.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("sync {}", relative_directory.display()))?;
    #[cfg(test)]
    pause_authorized_publication_for_process_kill(target_name, "target");
    let published = read_optional_bounded(directory, &target_c, &target_path, maximum)?
        .context("published authorized blockd input disappeared")?;
    anyhow::ensure!(
        published == expected,
        "published authorized blockd input changed"
    );
    Ok(())
}

#[cfg(test)]
fn pause_authorized_publication_for_process_kill(target_name: &str, phase: &str) {
    let Ok(requested) = std::env::var("CATS_AUTHORIZED_BLOCKD_KILL_POINT") else {
        return;
    };
    if requested != format!("{target_name}:{phase}") {
        return;
    }
    let marker = std::env::var("CATS_AUTHORIZED_BLOCKD_KILL_MARKER")
        .expect("authorized blockd kill probe marker path");
    std::fs::write(marker, requested.as_bytes()).expect("write authorized blockd kill marker");
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(60));
    }
}

fn persist_adopted_launch_file(
    directory: &File,
    relative_directory: &Path,
    current: &AuthorizedBlockdCheckpoint,
    current_bytes: &[u8],
) -> Result<AuthorizedBlockdCheckpoint> {
    let target_path = relative_directory.join(LAUNCH_CHECKPOINT_FILE);
    let temporary_path = relative_directory.join(LAUNCH_CHECKPOINT_TEMP);
    let target_c = c_string(LAUNCH_CHECKPOINT_FILE, &target_path)?;
    let temporary_c = c_string(LAUNCH_CHECKPOINT_TEMP, &temporary_path)?;
    let Some(existing_bytes) = read_optional_bounded(
        directory,
        &target_c,
        &target_path,
        MAX_LAUNCH_CHECKPOINT_BYTES,
    )?
    else {
        persist_ordered_file(
            directory,
            relative_directory,
            LAUNCH_CHECKPOINT_FILE,
            LAUNCH_CHECKPOINT_TEMP,
            current_bytes,
            &[IDENTITY_FILE, AUTHORIZED_SERVING_FILE],
            MAX_LAUNCH_CHECKPOINT_BYTES,
        )?;
        return Ok(current.clone());
    };

    let existing: AuthorizedBlockdCheckpoint = serde_json::from_slice(&existing_bytes)
        .context("decode existing authorized blockd launch checkpoint for adoption")?;
    anyhow::ensure!(
        serde_json::to_vec(&existing).context("re-encode adopted blockd checkpoint")?
            == existing_bytes,
        "existing authorized blockd launch checkpoint is not canonical"
    );
    validate_authorized_blockd_checkpoint(&existing)?;
    anyhow::ensure!(
        existing.attachment == current.attachment
            && existing.volume == current.volume
            && existing.desired.cat_id == current.desired.cat_id
            && existing.desired.placement.node_id == current.desired.placement.node_id
            && existing.desired.placement.placement_epoch
                == current.desired.placement.placement_epoch
            && existing.desired.desired_revision <= current.desired.desired_revision,
        "existing authorized blockd launch checkpoint is not compatible with adoption"
    );
    if let Some(temporary) = read_optional_bounded(
        directory,
        &temporary_c,
        &temporary_path,
        MAX_LAUNCH_CHECKPOINT_BYTES,
    )? {
        anyhow::ensure!(
            temporary == existing_bytes || temporary == current_bytes,
            "{} conflicts with adopted blockd provenance",
            temporary_path.display()
        );
        unlink_at(directory, &temporary_c)
            .with_context(|| format!("remove recovered {}", temporary_path.display()))?;
        directory
            .sync_all()
            .with_context(|| format!("sync {}", relative_directory.display()))?;
    }
    Ok(existing)
}

fn read_optional_bounded(
    directory: &File,
    name: &CStr,
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let mut file = match open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    verify_regular_file(&file, path, None)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(
        metadata.len() <= maximum as u64,
        "{} exceeds its bounded size",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "{} exceeds its bounded size",
        path.display()
    );
    Ok(Some(bytes))
}

fn verify_regular_file(file: &File, path: &Path, expected_len: Option<u64>) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    // SAFETY: geteuid takes no pointers and cannot fail.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o777 == 0o600
            && expected_len.is_none_or(|len| metadata.len() == len),
        "authorized blockd file {} has unsafe metadata",
        path.display()
    );
    Ok(())
}

fn directory_entries(directory: &File) -> io::Result<Vec<String>> {
    let mut stream = DirectoryStream::open(directory)?;
    let mut entries = Vec::new();
    while let Some(bytes) = stream.next()? {
        let name = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 directory entry"))?;
        entries.push(name.to_owned());
    }
    entries.sort();
    Ok(entries)
}

struct DirectoryStream(*mut libc::DIR);

impl DirectoryStream {
    fn open(directory: &File) -> io::Result<Self> {
        // SAFETY: fcntl duplicates the live descriptor and retains no Rust
        // memory. fdopendir consumes the duplicate on success.
        let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: duplicate is a fresh owned directory descriptor.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let source = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not consume duplicate.
            unsafe { libc::close(duplicate) };
            return Err(source);
        }
        Ok(Self(stream))
    }

    fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            set_errno(0);
            // SAFETY: the DIR pointer is exclusively owned by this value.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = errno();
                return if error == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::from_raw_os_error(error))
                };
            }
            // SAFETY: readdir returned a live dirent and the name is copied
            // before the next call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            return Ok(Some(name.to_vec()));
        }
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this value owns the non-null DIR pointer exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(target_os = "linux")]
fn set_errno(value: libc::c_int) {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
fn errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn set_errno(value: libc::c_int) {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() }
}

fn c_string(value: &str, path: &Path) -> Result<CString> {
    CString::new(value).with_context(|| format!("{} contains NUL", path.display()))
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: directory and name remain live for this call. A successful
        // descriptor is transferred exactly once into File.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: openat returned one new owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both directory descriptors and names remain live for the
        // call; renameat retains none of them.
        let result = unsafe {
            libc::renameat(
                old_directory.as_raw_fd(),
                old_name.as_ptr(),
                new_directory.as_raw_fd(),
                new_name.as_ptr(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn unlink_at(directory: &File, name: &CStr) -> io::Result<()> {
    loop {
        // SAFETY: directory and name remain live; unlinkat retains neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn validate_descendant(root: &Path, candidate: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(candidate.is_absolute(), "{label} must be absolute");
    let relative = candidate
        .strip_prefix(root)
        .with_context(|| format!("{label} must be under the retained Node state directory"))?;
    anyhow::ensure!(
        relative.components().next().is_some()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "{label} must be a strict descriptor-derived descendant"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

    use cats_api::runtime_reconciliation::{
        spec_digest, AcquireOrigin, AsciiText, AssignedKind, AssignedPlacement, Epoch, FenceEpoch,
        Generation, GuestDeviceIdentity, Id, Ipv4Address, IsolatedIpv4Kind, MacAddress,
        NetworkConfig, NormalAcquireRequest, NormalAcquireResult, RandomId128, RemoteHead,
        Revision, RuntimeConfig, RuntimeTransition, Sha256Digest, UnixMillis,
    };
    use cats_storage::authority::AttachmentLineageIdentity;
    use cats_storage::AdapterConfig;

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).unwrap()
    }

    fn empty_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn provisioned_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([9; 32])),
            root_object_id: Some(AsciiText::new("roots/root-1").unwrap()),
        }
    }

    fn fixture() -> (
        DesiredRuntimeSpec,
        VolumeIntent,
        AuthorizedServingAttachment,
    ) {
        let transition_id = random(1);
        let desired_revision = Revision::new(11).unwrap();
        let placement_epoch = Epoch::new(3).unwrap();
        let expected_unowned_epoch = FenceEpoch::new(7).unwrap();
        let resulting_epoch = FenceEpoch::new(8).unwrap();
        let volume = VolumeIntent {
            volume_intent_id: id("root-intent"),
            disk_id: id("root-disk"),
            volume_id: id("volume-1"),
            attachment_id: id("attachment-1"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-root-1"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: transition_id.clone(),
                expected_unowned_epoch,
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        };
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("workspace-1"),
            cat_id: id("cat-1"),
            desired_revision,
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: id("node-1"),
                placement_epoch,
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("network-1"),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: vec![volume.clone()],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let acquire_request = NormalAcquireRequest {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            expected_unowned_epoch,
            desired_revision,
            placement_epoch,
            lease_duration_ms: 5_000,
        };
        let acquire_result = NormalAcquireResult {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            resulting_epoch,
            resulting_head: empty_head(),
            lease_expires_at: UnixMillis::new(20_000).unwrap(),
        };
        let attachment = AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: resulting_epoch,
                acquire_origin: AcquireOrigin::Normal { transition_id },
                node_id: desired.placement.node_id.clone(),
                placement_epoch,
            },
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            // Root provision may have advanced the head after acquire.
            head: provisioned_head(),
            lease_expires_at: acquire_result.lease_expires_at,
            acquire_request,
            acquire_result,
        };
        (desired, volume, attachment)
    }

    fn final_directory(root: &Path) -> PathBuf {
        root.join("data")
            .join("cat-cat-1")
            .join("volume-volume-1")
            .join("attachment-attachment-1")
            .join("epoch-8")
    }

    fn create_final_directory(root: &Path) -> PathBuf {
        let path = final_directory(root);
        std::fs::create_dir_all(&path).unwrap();
        let mut current = root.to_path_buf();
        for component in [
            "data",
            "cat-cat-1",
            "volume-volume-1",
            "attachment-attachment-1",
            "epoch-8",
        ] {
            current.push(component);
            std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn launch_config() -> AuthorizedBlockdLaunchConfig {
        AuthorizedBlockdLaunchConfig {
            blockd_binary: "/opt/cats/bin/cats-blockd".into(),
            metadata_store: AdapterSelection::new(
                "postgres",
                AdapterConfig::from_pairs([
                    ("url-env", "CATS_TEST_POSTGRES_URL"),
                    ("connect-timeout-ms", "500"),
                ])
                .unwrap(),
            ),
            object_store: AdapterSelection::new(
                "file",
                AdapterConfig::from_pairs([("root", "/srv/cats/objects")]).unwrap(),
            ),
            max_staged_bytes: 101,
            max_staged_packs: 102,
            max_local_bytes: 103,
        }
    }

    fn argv(command: &Command) -> Vec<OsString> {
        command.get_args().map(ToOwned::to_owned).collect()
    }

    #[test]
    fn complete_desired_grant_and_network_are_checkpointed_before_closed_cli_is_built() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()))
                .prepare(&desired, &volume, &attachment)
                .unwrap();

        assert_eq!(prepared.data_directory(), final_directory(temp.path()));
        assert_eq!(
            serde_json::from_slice::<AttachmentLineageIdentity>(
                &std::fs::read(prepared.identity_path()).unwrap()
            )
            .unwrap(),
            attachment.identity
        );
        assert_eq!(
            serde_json::from_slice::<AuthorizedServingAttachment>(
                &std::fs::read(prepared.authorized_serving_path()).unwrap()
            )
            .unwrap(),
            attachment
        );
        let stored: AuthorizedBlockdCheckpoint =
            serde_json::from_slice(&std::fs::read(prepared.launch_checkpoint_path()).unwrap())
                .unwrap();
        assert_eq!(
            stored.desired.runtime.network_config,
            desired.runtime.network_config
        );
        assert_eq!(stored, *prepared.checkpoint());

        let control = temp.path().join("control-sockets/cat-1-blockd.sock");
        let frontend = temp.path().join("vhost-user/cat-1-root.sock");
        let command = authorized_blockd_command(
            &launch_config(),
            &prepared,
            &id("cats-cat-1-root.scope"),
            &random(2),
            &control,
            &AuthorizedBlockFrontend::VhostUser {
                socket: frontend.clone(),
                queues: 2,
                queue_size: 256,
            },
        )
        .unwrap();
        assert_eq!(command.get_program(), "/opt/cats/bin/cats-blockd");
        let arguments = argv(&command);
        for required in [
            OsString::from("--authorized-serving-spec"),
            prepared.authorized_serving_path().as_os_str().to_owned(),
            OsString::from("--listen-control"),
            control.into_os_string(),
            OsString::from("--runtime-scope-id"),
            OsString::from("cats-cat-1-root.scope"),
            OsString::from("--process-identity-token"),
            OsString::from("00000000000000000000000000000002"),
            OsString::from("--listen-vhost-user"),
            frontend.into_os_string(),
            OsString::from("--lease-ttl-ms"),
            OsString::from("5000"),
            OsString::from("--durability"),
            OsString::from("strict"),
        ] {
            assert!(arguments.contains(&required), "missing argv {required:?}");
        }
        for forbidden in [
            "--create-volume-size",
            "--seed-image-id",
            "--collect-garbage",
            "--attachment-epoch",
            "--control-only",
            "--listen-tcp",
        ] {
            assert!(!arguments.contains(&OsString::from(forbidden)));
        }
        assert!(command
            .get_envs()
            .any(|(name, value)| name == "CATS_CRASH_POINT" && value.is_none()));
    }

    #[test]
    fn exact_replay_keeps_inodes_but_a_changed_grant_cannot_replace_any_file() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let store =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()));
        let prepared = store.prepare(&desired, &volume, &attachment).unwrap();
        let paths = [
            prepared.identity_path().to_path_buf(),
            prepared.authorized_serving_path().to_path_buf(),
            prepared.launch_checkpoint_path().to_path_buf(),
        ];
        let before = paths
            .iter()
            .map(|path| {
                (
                    std::fs::metadata(path).unwrap().ino(),
                    std::fs::read(path).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        drop(prepared);

        drop(store.prepare(&desired, &volume, &attachment).unwrap());
        for (path, expected) in paths.iter().zip(&before) {
            assert_eq!(std::fs::metadata(path).unwrap().ino(), expected.0);
            assert_eq!(std::fs::read(path).unwrap(), expected.1);
        }

        let mut changed_volume = volume.clone();
        changed_volume.size_bytes += 4 * 1024 * 1024;
        let mut changed_desired = desired.clone();
        changed_desired.volumes = vec![changed_volume.clone()];
        changed_desired.spec_digest = spec_digest(&changed_desired).unwrap();
        let mut changed_attachment = attachment.clone();
        changed_attachment.size_bytes = changed_volume.size_bytes;
        let error = store
            .prepare(&changed_desired, &changed_volume, &changed_attachment)
            .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
        for (path, expected) in paths.iter().zip(&before) {
            assert_eq!(std::fs::metadata(path).unwrap().ino(), expected.0);
            assert_eq!(std::fs::read(path).unwrap(), expected.1);
        }
    }

    #[test]
    fn identity_temp_is_recovered_exactly_after_response_loss() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let directory = create_final_directory(temp.path());
        let temporary = directory.join(IDENTITY_TEMP);
        std::fs::write(
            &temporary,
            serde_json::to_vec(&attachment.identity).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();

        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()))
                .prepare(&desired, &volume, &attachment)
                .unwrap();
        assert!(!temporary.exists());
        assert!(prepared.identity_path().exists());
        assert!(prepared.authorized_serving_path().exists());
        assert!(prepared.launch_checkpoint_path().exists());
    }

    #[test]
    fn unknown_residue_or_symlink_before_identity_is_never_adopted() {
        let (desired, volume, attachment) = fixture();

        let residue_root = tempfile::tempdir().unwrap();
        let residue_directory = create_final_directory(residue_root.path());
        std::fs::write(residue_directory.join("cache.bin"), b"unknown").unwrap();
        let residue_store = AuthorizedBlockdStore::new(StateDirectory::unanchored(
            residue_root.path().to_path_buf(),
        ));
        let error = residue_store
            .prepare(&desired, &volume, &attachment)
            .unwrap_err();
        assert!(error.to_string().contains("residue"));
        assert!(!residue_directory.join(IDENTITY_FILE).exists());

        let symlink_root = tempfile::tempdir().unwrap();
        let symlink_directory = create_final_directory(symlink_root.path());
        let external = symlink_root.path().join("external");
        std::fs::write(&external, serde_json::to_vec(&attachment.identity).unwrap()).unwrap();
        symlink(&external, symlink_directory.join(IDENTITY_FILE)).unwrap();
        let symlink_store = AuthorizedBlockdStore::new(StateDirectory::unanchored(
            symlink_root.path().to_path_buf(),
        ));
        assert!(symlink_store
            .prepare(&desired, &volume, &attachment)
            .is_err());
        assert_eq!(
            std::fs::read(external).unwrap(),
            serde_json::to_vec(&attachment.identity).unwrap()
        );
        assert!(
            std::fs::symlink_metadata(symlink_directory.join(IDENTITY_FILE))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn unsupported_lifecycle_or_non_state_socket_fails_before_process_construction() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let mut cold = desired.clone();
        cold.target = RuntimeTarget::Cold;
        cold.spec_digest = spec_digest(&cold).unwrap();
        let store =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()));
        assert!(store.prepare(&cold, &volume, &attachment).is_err());
        assert!(!temp.path().join(DATA_DIRECTORY).exists());

        let prepared = store.prepare(&desired, &volume, &attachment).unwrap();
        let result = authorized_blockd_command(
            &launch_config(),
            &prepared,
            &id("cats-cat-1-root.scope"),
            &random(2),
            Path::new("/tmp/not-state-derived-control.sock"),
            &AuthorizedBlockFrontend::NbdUnix {
                socket: temp.path().join("frontends/root.sock"),
            },
        );
        assert!(result.is_err());
    }
}

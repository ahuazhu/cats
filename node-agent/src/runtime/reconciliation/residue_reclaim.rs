//! Descriptor-retained exact reclamation of one released blockd data directory.
//!
//! The full scanner is the only constructor of the private admission below.
//! It retains every directory in the public Cat/Volume/attachment/epoch chain,
//! so the effect never resolves a qualified `HostPath` back through the
//! filesystem. Control's proof closes Volume authority; the retained
//! descriptors and accepted full observation close local identity/owner
//! absence. The current `CleanupRelease::Volume` RuntimeCheckpoint is the
//! durable pre-effect record.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::sync::Arc;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    residue_reclaim_proof_is_closed, CleanupTarget, ContractVersion, DesiredRuntimeSpec, HostPath,
    Id, NodeObservation, NodeResidue, ReconcileStep, ResidueLineageEvidence,
    RuntimeResidueAuthorityOutcome, RuntimeResidueAuthorityRequest, SessionBinding,
};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};

use super::{
    authorized_blockd::LAUNCH_CHECKPOINT_FILE, FileCheckpointStore, RuntimeResidueAuthorityAttempt,
    RuntimeVolumeTransitionHttpClient, StoredCheckpoint,
};

const MAX_RECLAIM_ENTRIES: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    size: u64,
    blocks: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl EntryIdentity {
    fn from_stat(stat: &libc::stat) -> anyhow::Result<Self> {
        Ok(Self {
            device: u64::try_from(stat.st_dev).context("entry device is negative")?,
            inode: stat.st_ino,
            uid: stat.st_uid,
            mode: stat.st_mode.into(),
            links: stat.st_nlink.into(),
            size: u64::try_from(stat.st_size).context("entry size is negative")?,
            blocks: u64::try_from(stat.st_blocks).context("entry block count is negative")?,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn file_type(self) -> u32 {
        self.mode & u32::from(libc::S_IFMT)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RetainedTreeEntry {
    File(EntryIdentity),
    Directory {
        identity: EntryIdentity,
        entries: BTreeMap<OsString, RetainedTreeEntry>,
    },
}

impl RetainedTreeEntry {
    fn identity(&self) -> EntryIdentity {
        match self {
            Self::File(identity) | Self::Directory { identity, .. } => *identity,
        }
    }
}

impl DirectoryIdentity {
    fn from_file(file: &File) -> anyhow::Result<Self> {
        let metadata = file
            .metadata()
            .context("inspect retained reclaim directory")?;
        anyhow::ensure!(
            metadata.is_dir(),
            "retained reclaim object is not a directory"
        );
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        })
    }

    fn matches_file(self, file: &File) -> bool {
        file.metadata().is_ok_and(|metadata| {
            metadata.is_dir()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.uid() == self.uid
                && metadata.mode() == self.mode
        })
    }
}

/// Scanner-owned descriptor chain for one exact data-directory lineage.
///
/// The parent/name pairs are retained as well as the epoch directory because
/// removing empty ancestors through a reconstructed pathname would reopen an
/// ABA window after the qualified leaf was deleted.
#[derive(Debug)]
pub(crate) struct RetainedDataDirectory {
    data_root: Arc<File>,
    data_root_identity: DirectoryIdentity,
    cat_name: OsString,
    cat: Arc<File>,
    cat_identity: DirectoryIdentity,
    volume_name: OsString,
    volume: Arc<File>,
    volume_identity: DirectoryIdentity,
    attachment_name: OsString,
    attachment: Arc<File>,
    attachment_identity: DirectoryIdentity,
    epoch_name: OsString,
    epoch: Arc<File>,
    epoch_identity: DirectoryIdentity,
    entries: BTreeMap<OsString, RetainedTreeEntry>,
    data_directory: HostPath,
}

impl PartialEq for RetainedDataDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.data_root_identity == other.data_root_identity
            && self.cat_name == other.cat_name
            && self.cat_identity == other.cat_identity
            && self.volume_name == other.volume_name
            && self.volume_identity == other.volume_identity
            && self.attachment_name == other.attachment_name
            && self.attachment_identity == other.attachment_identity
            && self.epoch_name == other.epoch_name
            && self.epoch_identity == other.epoch_identity
            && self.entries == other.entries
            && self.data_directory == other.data_directory
    }
}

impl Eq for RetainedDataDirectory {}

impl RetainedDataDirectory {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_scanner<'a>(
        data_root: &File,
        cat_name: &OsStr,
        cat: &File,
        volume_name: &OsStr,
        volume: &File,
        attachment_name: &OsStr,
        attachment: &File,
        epoch_name: &OsStr,
        epoch: &File,
        data_directory: HostPath,
        enumerated_epoch_entries: impl IntoIterator<Item = (&'a OsStr, &'a libc::stat)>,
        context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> anyhow::Result<Self> {
        let root_uid = data_root.metadata()?.uid();
        let mut budget = MAX_RECLAIM_ENTRIES;
        let entries = snapshot_tree(epoch, root_uid, &mut budget, context)?;
        let enumerated = enumerated_epoch_entries
            .into_iter()
            .map(|(name, stat)| Ok((name.to_owned(), EntryIdentity::from_stat(stat)?)))
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        anyhow::ensure!(
            entries.len() == enumerated.len()
                && entries.iter().all(|(name, retained)| {
                    enumerated
                        .get(name)
                        .is_some_and(|identity| retained.identity() == *identity)
                }),
            "retained data-directory child set changed after scanner validation"
        );
        anyhow::ensure!(
            entries.contains_key(OsStr::new(LAUNCH_CHECKPOINT_FILE)),
            "retained data-directory lacks its durable launch checkpoint restart anchor"
        );
        Ok(Self {
            data_root: Arc::new(data_root.try_clone()?),
            data_root_identity: DirectoryIdentity::from_file(data_root)?,
            cat_name: cat_name.to_owned(),
            cat: Arc::new(cat.try_clone()?),
            cat_identity: DirectoryIdentity::from_file(cat)?,
            volume_name: volume_name.to_owned(),
            volume: Arc::new(volume.try_clone()?),
            volume_identity: DirectoryIdentity::from_file(volume)?,
            attachment_name: attachment_name.to_owned(),
            attachment: Arc::new(attachment.try_clone()?),
            attachment_identity: DirectoryIdentity::from_file(attachment)?,
            epoch_name: epoch_name.to_owned(),
            epoch: Arc::new(epoch.try_clone()?),
            epoch_identity: DirectoryIdentity::from_file(epoch)?,
            entries,
            data_directory,
        })
    }

    fn revalidate_chain(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.data_root_identity.matches_file(&self.data_root)
                && self.cat_identity.matches_file(&self.cat)
                && self.volume_identity.matches_file(&self.volume)
                && self.attachment_identity.matches_file(&self.attachment)
                && self.epoch_identity.matches_file(&self.epoch)
                && entry_names_directory(&self.data_root, &self.cat_name, self.cat_identity,)?
                && entry_names_directory(&self.cat, &self.volume_name, self.volume_identity)?
                && entry_names_directory(
                    &self.volume,
                    &self.attachment_name,
                    self.attachment_identity,
                )?
                && entry_names_directory(&self.attachment, &self.epoch_name, self.epoch_identity,)?,
            "retained data-directory descriptor chain changed identity"
        );
        Ok(())
    }

    fn reclaim(&self, context: &RuntimeDesiredEffectContext) -> anyhow::Result<()> {
        self.revalidate_chain()?;
        let mut budget = MAX_RECLAIM_ENTRIES;
        anyhow::ensure!(
            snapshot_tree(&self.epoch, self.epoch_identity.uid, &mut budget, context,)?
                == self.entries,
            "retained data-directory complete child set changed before reclaim"
        );
        let mut budget = MAX_RECLAIM_ENTRIES;
        remove_retained_tree(
            &self.epoch,
            self.epoch_identity.uid,
            &self.entries,
            &mut budget,
            context,
            Some(OsStr::new(LAUNCH_CHECKPOINT_FILE)),
        )
        .context("unlink exact retained data-directory contents")?;
        if let Some(anchor) = self.entries.get(OsStr::new(LAUNCH_CHECKPOINT_FILE)) {
            let remaining = directory_entries(&self.epoch)?;
            anyhow::ensure!(
                remaining.len() == 1 && remaining[0] == LAUNCH_CHECKPOINT_FILE,
                "data-directory restart anchor is not the sole remaining entry"
            );
            remove_retained_entry(
                &self.epoch,
                self.epoch_identity.uid,
                OsStr::new(LAUNCH_CHECKPOINT_FILE),
                anchor,
                &mut budget,
                context,
            )?;
        }
        sync_directory(&self.epoch).context("sync reclaimed data-directory contents")?;
        unlink_empty_directory(&self.attachment, &self.epoch_name)
            .context("remove exact retained epoch directory")?;
        sync_directory(&self.attachment).context("sync epoch directory removal")?;
        remove_empty_ancestor(
            &self.volume,
            &self.attachment_name,
            &self.attachment,
            context,
        )?;
        remove_empty_ancestor(&self.cat, &self.volume_name, &self.volume, context)?;
        remove_empty_ancestor(&self.data_root, &self.cat_name, &self.cat, context)?;
        Ok(())
    }
}

#[derive(Debug)]
struct RetainedDirectoryLink {
    parent: Arc<File>,
    parent_identity: DirectoryIdentity,
    name: OsString,
    child: Arc<File>,
    child_identity: DirectoryIdentity,
}

/// One descriptor-retained empty suffix left if the Agent crashes after the
/// launch checkpoint (the final restart anchor) is unlinked. The ordinary
/// Release successor and current RuntimeCheckpoint are revalidated by the
/// pre-scan recovery lane before this value may remove even an empty inode.
#[derive(Debug)]
pub(crate) struct RetainedEmptyDataDirectoryPrefix {
    links: Vec<RetainedDirectoryLink>,
}

impl RetainedEmptyDataDirectoryPrefix {
    pub(super) fn from_scanner(
        links: &[(&File, &OsStr, &File)],
        context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !links.is_empty(),
            "empty reclaim prefix lacks a directory link"
        );
        let retained = links
            .iter()
            .map(|(parent, name, child)| {
                Ok(RetainedDirectoryLink {
                    parent: Arc::new(parent.try_clone()?),
                    parent_identity: DirectoryIdentity::from_file(parent)?,
                    name: (*name).to_owned(),
                    child: Arc::new(child.try_clone()?),
                    child_identity: DirectoryIdentity::from_file(child)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let candidate = Self { links: retained };
        candidate.revalidate(context)?;
        anyhow::ensure!(
            directory_entries(
                candidate
                    .links
                    .last()
                    .expect("nonempty prefix was checked")
                    .child
                    .as_ref(),
            )?
            .is_empty(),
            "reclaim prefix leaf is not empty"
        );
        Ok(candidate)
    }

    fn revalidate(
        &self,
        context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> anyhow::Result<()> {
        for (index, link) in self.links.iter().enumerate() {
            context.check_active()?;
            anyhow::ensure!(
                link.parent_identity.matches_file(&link.parent)
                    && link.child_identity.matches_file(&link.child)
                    && entry_names_directory(&link.parent, &link.name, link.child_identity)?,
                "empty reclaim prefix changed directory identity"
            );
            if let Some(previous) = index.checked_sub(1).and_then(|value| self.links.get(value)) {
                anyhow::ensure!(
                    previous.child_identity == link.parent_identity,
                    "empty reclaim prefix is not one contiguous directory chain"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn reclaim_after_exact_release(
        &self,
        context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> anyhow::Result<()> {
        self.revalidate(context)?;
        for link in self.links.iter().rev() {
            context.check_active()?;
            if !directory_entries(&link.child)?.is_empty() {
                break;
            }
            anyhow::ensure!(
                entry_names_directory(&link.parent, &link.name, link.child_identity)?,
                "empty reclaim prefix changed at unlink boundary"
            );
            unlink_empty_directory(&link.parent, &link.name)?;
            sync_directory(&link.parent)?;
        }
        Ok(())
    }
}

/// Unbound private scan result. The runner binds it to the exact public full
/// observation only after the observation digest has been built.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DataDirectoryReclaimScanAdmission {
    entries: BTreeMap<(Id, Id), (NodeResidue, Arc<RetainedDataDirectory>)>,
}

impl DataDirectoryReclaimScanAdmission {
    pub(crate) fn insert(
        &mut self,
        cat_id: Id,
        volume_id: Id,
        residue: NodeResidue,
        retained: Arc<RetainedDataDirectory>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.entries
                .insert((cat_id, volume_id), (residue, retained))
                .is_none(),
            "data-directory reclaim scan duplicated one Cat/Volume"
        );
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn bind(
        self,
        observation: &NodeObservation,
    ) -> anyhow::Result<DataDirectoryReclaimAdmission> {
        for (residue, retained) in self.entries.values() {
            anyhow::ensure!(
                observation
                    .residue
                    .iter()
                    .filter(|item| *item == residue)
                    .count()
                    == 1,
                "retained data-directory admission lacks one exact public residue"
            );
            let NodeResidue::DataDirectory { data_directory, .. } = residue else {
                anyhow::bail!("retained data-directory admission contains another residue kind")
            };
            anyhow::ensure!(
                data_directory == &retained.data_directory,
                "retained data-directory admission and public path disagree"
            );
        }
        Ok(DataDirectoryReclaimAdmission {
            observation_id: observation.observation_id.clone(),
            inventory_digest: observation
                .inventory_digest
                .clone()
                .context("data-directory admission requires an inventory digest")?,
            entries: self.entries,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataDirectoryReclaimAdmission {
    observation_id: cats_api::runtime_reconciliation::RandomId128,
    inventory_digest: cats_api::runtime_reconciliation::Sha256Digest,
    entries: BTreeMap<(Id, Id), (NodeResidue, Arc<RetainedDataDirectory>)>,
}

impl DataDirectoryReclaimAdmission {
    pub(crate) fn matches_observation(&self, observation: &NodeObservation) -> bool {
        observation.complete_inventory
            && observation.observation_id == self.observation_id
            && observation.inventory_digest.as_ref() == Some(&self.inventory_digest)
    }

    fn exact(
        &self,
        observation: &NodeObservation,
        cat_id: &Id,
        volume_id: &Id,
    ) -> Option<&(NodeResidue, Arc<RetainedDataDirectory>)> {
        self.matches_observation(observation)
            .then(|| self.entries.get(&(cat_id.clone(), volume_id.clone())))
            .flatten()
    }
}

pub(crate) struct DataDirectoryReclaimEffect {
    authority: Arc<dyn ResidueAuthorityPort>,
}

pub(super) trait ResidueAuthorityPort: Send + Sync + 'static {
    fn request(
        &self,
        request: &RuntimeResidueAuthorityRequest,
        deadline: std::time::Instant,
    ) -> Result<RuntimeResidueAuthorityAttempt, cats_api::runtime_reconciliation::ContractError>;
}

impl ResidueAuthorityPort for RuntimeVolumeTransitionHttpClient {
    fn request(
        &self,
        request: &RuntimeResidueAuthorityRequest,
        deadline: std::time::Instant,
    ) -> Result<RuntimeResidueAuthorityAttempt, cats_api::runtime_reconciliation::ContractError>
    {
        self.request_residue_authority(request, deadline)
    }
}

impl DataDirectoryReclaimEffect {
    pub(crate) fn new(authority: RuntimeVolumeTransitionHttpClient) -> Self {
        Self {
            authority: Arc::new(authority),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(authority: Arc<dyn ResidueAuthorityPort>) -> Self {
        Self { authority }
    }

    pub(super) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        current: &super::checkpoint::CurrentCheckpointGuard<'_>,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let ReconcileStep::CleanupRelease { cleanup } = &stored.checkpoint().step else {
            return Ok(None);
        };
        let CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        } = &cleanup.target
        else {
            return Ok(None);
        };
        let accepted = context.accepted_full()?;
        let Some(admission) = context.optional_data_directory_reclaim() else {
            return Ok(None);
        };
        let Some((residue, retained)) =
            admission.exact(accepted.observation(), &desired.cat_id, volume_id)
        else {
            return Ok(None);
        };
        let processes = context.node_global_process()?;
        let networks = context.node_global_network()?;
        if !processes.matches_observation(accepted.observation())
            || processes.exact_process_count(&desired.cat_id) != 0
            || processes.stop_receipt_socket(&desired.cat_id).is_some()
            || !networks.matches_observation(accepted.observation())
            || context.optional_kernel_nbd_pool().is_some_and(|pool| {
                !pool.matches_observation(accepted.observation())
                    || pool.device_count(&desired.cat_id) != 0
            })
            || accepted
                .observation()
                .residue
                .iter()
                .any(|item| !matches!(item, NodeResidue::DataDirectory { .. }))
        {
            return Ok(Some(stop_local()));
        }
        let Some(request) = authority_request(accepted.session(), residue) else {
            return Ok(Some(stop_local()));
        };
        if request.lineage.cat_id != desired.cat_id
            || request.lineage.volume_id != *volume_id
            || request.lineage.attachment_id != *attachment_id
            || request.lineage.attachment_epoch != *attachment_epoch
            || request.lineage.desired_revision != desired.desired_revision
            || request.lineage.spec_digest != desired.spec_digest
            || request.lineage.placement != desired.placement
        {
            return Ok(Some(stop_local()));
        }
        context.check_active()?;
        let qualified = match self.authority.request(&request, context.deadline())? {
            RuntimeResidueAuthorityAttempt::Qualified(success) => success,
            RuntimeResidueAuthorityAttempt::ReauthenticationRequired => {
                return Ok(Some(RuntimeDesiredEffectOutcome::IdentityRepairRequired))
            }
            RuntimeResidueAuthorityAttempt::IdentityReplacementRequired => {
                return Ok(Some(
                    RuntimeDesiredEffectOutcome::SessionReplacementRequired,
                ))
            }
            RuntimeResidueAuthorityAttempt::Retain => {
                return Ok(Some(RuntimeDesiredEffectOutcome::RetryExact))
            }
        };
        let RuntimeResidueAuthorityOutcome::Reclaimable { proof } = &qualified.outcome else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RetryExact));
        };
        if qualified.version != ContractVersion::V1
            || qualified.session != request.session
            || qualified.lineage != request.lineage
            || !residue_reclaim_proof_is_closed(&request.lineage, proof)
        {
            return Ok(Some(stop_local()));
        }

        // RuntimeCheckpoint is already durable and retained by the lifecycle
        // store guard before this adapter is called. Serialize Host-global
        // mutation, then revalidate both the accepted private descriptor and
        // cancellation immediately before the first unlink.
        let _node_global = context.lock_node_global_effect()?;
        context.check_active()?;
        store
            .revalidate_current(stored, current)
            .context("revalidate exact cleanup checkpoint before DataDirectory unlink")?;
        retained.revalidate_chain()?;
        retained.reclaim(context)?;
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }
}

fn authority_request(
    session: &cats_api::runtime_reconciliation::AgentSession,
    residue: &NodeResidue,
) -> Option<RuntimeResidueAuthorityRequest> {
    let NodeResidue::DataDirectory {
        cat_id_hint,
        disk_id_hint,
        volume_id_hint,
        lineage: ResidueLineageEvidence::Readable { lineage },
        ..
    } = residue
    else {
        return None;
    };
    if cat_id_hint
        .as_ref()
        .is_some_and(|value| value != &lineage.cat_id)
        || disk_id_hint
            .as_ref()
            .is_some_and(|value| value != &lineage.disk_id)
        || volume_id_hint
            .as_ref()
            .is_some_and(|value| value != &lineage.volume_id)
    {
        return None;
    }
    Some(RuntimeResidueAuthorityRequest {
        version: ContractVersion::V1,
        session: SessionBinding {
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
        },
        lineage: lineage.as_ref().clone(),
    })
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

fn entry_names_directory(
    parent: &File,
    name: &OsStr,
    expected: DirectoryIdentity,
) -> anyhow::Result<bool> {
    let name = CString::new(name.as_bytes()).context("retained directory name contains NUL")?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent and name are live; fstatat initializes `stat` on success.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Ok(false);
    }
    // SAFETY: successful fstatat initialized the value.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
        && u64::try_from(stat.st_dev).ok() == Some(expected.device)
        && stat.st_ino == expected.inode
        && stat.st_uid == expected.uid
        && u32::from(stat.st_mode) == expected.mode)
}

fn snapshot_tree(
    directory: &File,
    expected_uid: u32,
    budget: &mut usize,
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> anyhow::Result<BTreeMap<OsString, RetainedTreeEntry>> {
    let mut retained = BTreeMap::new();
    for entry in directory_entries(directory)? {
        context.check_active()?;
        *budget = budget
            .checked_sub(1)
            .context("data-directory reclaim exceeds entry cap")?;
        let name = CString::new(entry.as_bytes()).context("reclaim entry contains NUL")?;
        let stat = stat_at(directory, &name)?;
        let identity = EntryIdentity::from_stat(&stat)?;
        anyhow::ensure!(
            stat.st_uid == expected_uid,
            "data-directory reclaim found a foreign owner"
        );
        let retained_entry = match identity.file_type() {
            kind if kind == u32::from(libc::S_IFREG) => {
                anyhow::ensure!(stat.st_nlink == 1, "reclaim file is multiply linked");
                RetainedTreeEntry::File(identity)
            }
            kind if kind == u32::from(libc::S_IFDIR) => {
                let child = open_child_directory(directory, &name, &stat, expected_uid)?;
                RetainedTreeEntry::Directory {
                    identity,
                    entries: snapshot_tree(&child, expected_uid, budget, context)?,
                }
            }
            _ => anyhow::bail!("data-directory reclaim found an unsupported entry type"),
        };
        anyhow::ensure!(
            retained.insert(entry, retained_entry).is_none(),
            "data-directory reclaim enumerated a duplicate name"
        );
    }
    Ok(retained)
}

fn remove_retained_tree(
    directory: &File,
    expected_uid: u32,
    expected: &BTreeMap<OsString, RetainedTreeEntry>,
    budget: &mut usize,
    context: &RuntimeDesiredEffectContext,
    preserve_top_level: Option<&OsStr>,
) -> anyhow::Result<()> {
    let mut snapshot_budget = *budget;
    anyhow::ensure!(
        snapshot_tree(directory, expected_uid, &mut snapshot_budget, context)? == *expected,
        "data-directory child set changed at delete boundary"
    );
    for (entry, retained) in expected {
        if preserve_top_level == Some(entry.as_os_str()) {
            continue;
        }
        remove_retained_entry(directory, expected_uid, entry, retained, budget, context)?;
    }
    Ok(())
}

fn remove_retained_entry(
    directory: &File,
    expected_uid: u32,
    entry: &OsStr,
    retained: &RetainedTreeEntry,
    budget: &mut usize,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<()> {
    context.check_active()?;
    *budget = budget
        .checked_sub(1)
        .context("data-directory reclaim exceeds entry cap")?;
    let name = CString::new(entry.as_bytes()).context("reclaim entry contains NUL")?;
    let stat = stat_at(directory, &name)?;
    anyhow::ensure!(
        EntryIdentity::from_stat(&stat)? == retained.identity(),
        "data-directory reclaim entry changed identity before unlink"
    );
    match retained {
        RetainedTreeEntry::File(_) => unlink_at(directory, &name, 0)?,
        RetainedTreeEntry::Directory { entries, .. } => {
            let child = open_child_directory(directory, &name, &stat, expected_uid)?;
            remove_retained_tree(&child, expected_uid, entries, budget, context, None)?;
            sync_directory(&child)?;
            let current = stat_at(directory, &name)?;
            anyhow::ensure!(
                same_directory_stat(&stat, &current),
                "reclaim child changed identity before directory unlink"
            );
            unlink_at(directory, &name, libc::AT_REMOVEDIR)?;
        }
    }
    sync_directory(directory)?;
    Ok(())
}

fn remove_empty_ancestor(
    parent: &File,
    name: &OsStr,
    retained: &File,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<()> {
    context.check_active()?;
    if !directory_entries(retained)?.is_empty() {
        return Ok(());
    }
    let name_c = CString::new(name.as_bytes()).context("ancestor directory name contains NUL")?;
    let current = stat_at(parent, &name_c)?;
    let retained_identity = DirectoryIdentity::from_file(retained)?;
    anyhow::ensure!(
        u64::try_from(current.st_dev).ok() == Some(retained_identity.device)
            && current.st_ino == retained_identity.inode,
        "empty reclaim ancestor changed identity"
    );
    unlink_at(parent, &name_c, libc::AT_REMOVEDIR)?;
    sync_directory(parent)?;
    Ok(())
}

fn unlink_empty_directory(parent: &File, name: &OsStr) -> anyhow::Result<()> {
    let name = CString::new(name.as_bytes()).context("epoch directory name contains NUL")?;
    unlink_at(parent, &name, libc::AT_REMOVEDIR).map_err(anyhow::Error::from)
}

fn stat_at(directory: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor and name are live; successful fstatat initializes stat.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: success initialized stat.
        Ok(unsafe { stat.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn open_child_directory(
    parent: &File,
    name: &CStr,
    enumerated: &libc::stat,
    expected_uid: u32,
) -> anyhow::Result<File> {
    // SAFETY: parent/name are live; success returns a new owned descriptor.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open reclaim child directory");
    }
    // SAFETY: openat returned this newly owned descriptor.
    let child = unsafe { File::from_raw_fd(fd) };
    let metadata = child.metadata()?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == expected_uid
            && u64::try_from(enumerated.st_dev).ok() == Some(metadata.dev())
            && enumerated.st_ino == metadata.ino(),
        "reclaim child changed identity after enumeration"
    );
    Ok(child)
}

fn same_directory_stat(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_mode == right.st_mode
}

fn unlink_at(directory: &File, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: directory/name remain live; unlinkat retains neither.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn sync_directory(directory: &File) -> io::Result<()> {
    directory.sync_all()
}

fn directory_entries(directory: &File) -> io::Result<Vec<OsString>> {
    let dot = CString::new(".").expect("static directory name contains no NUL");
    // SAFETY: directory/dot live; success returns a new owned descriptor for fdopendir.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly owned; fdopendir consumes it on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not consume the owned fd.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    let mut entries = Vec::new();
    loop {
        set_errno_zero();
        // SAFETY: stream is live and uniquely used by this function.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: stream is live and closed exactly once.
            unsafe { libc::closedir(stream) };
            return if error.raw_os_error() == Some(0) {
                Ok(entries)
            } else {
                Err(error)
            };
        }
        // SAFETY: readdir returned a live dirent until the next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            entries.push(OsString::from_vec(name.to_vec()));
        }
    }
}

#[cfg(target_os = "macos")]
fn set_errno_zero() {
    // SAFETY: libc returns this thread's errno location.
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn set_errno_zero() {
    // SAFETY: libc returns this thread's errno location.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::HostPath;

    use crate::runtime_spine::RuntimeDesiredEffectContext;
    use crate::state_directory::StateDirectory;

    use super::*;

    struct RetainedFixture {
        _temp: tempfile::TempDir,
        data_root_path: PathBuf,
        leaf_path: PathBuf,
        retained: RetainedDataDirectory,
        context: RuntimeDesiredEffectContext,
    }

    fn retained_fixture() -> RetainedFixture {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let data_root_path = state.join("runtime-blockd-data-v1");
        let cat_path = data_root_path.join("cat-cat_a");
        let volume_path = cat_path.join("volume-vol_a");
        let attachment_path = volume_path.join("attachment-att_a");
        let epoch_path = attachment_path.join("epoch-7");
        let nested = epoch_path.join("pending");
        std::fs::create_dir_all(&nested).unwrap();
        for path in [
            &state,
            &data_root_path,
            &cat_path,
            &volume_path,
            &attachment_path,
            &epoch_path,
            &nested,
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let leaf_path = epoch_path.join("identity.json");
        std::fs::write(&leaf_path, b"old exact bytes").unwrap();
        std::fs::set_permissions(&leaf_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let launch_checkpoint = epoch_path.join(LAUNCH_CHECKPOINT_FILE);
        std::fs::write(&launch_checkpoint, b"durable restart anchor").unwrap();
        std::fs::set_permissions(&launch_checkpoint, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let nested_leaf = nested.join("pack.bin");
        std::fs::write(&nested_leaf, b"pack").unwrap();
        std::fs::set_permissions(&nested_leaf, std::fs::Permissions::from_mode(0o600)).unwrap();

        let data_root = File::open(&data_root_path).unwrap();
        let cat = File::open(&cat_path).unwrap();
        let volume = File::open(&volume_path).unwrap();
        let attachment = File::open(&attachment_path).unwrap();
        let epoch = File::open(&epoch_path).unwrap();
        let context = RuntimeDesiredEffectContext::for_test(
            StateDirectory::unanchored(state),
            Instant::now() + Duration::from_secs(5),
        );
        let entries = top_entry_stats(&epoch_path);
        let retained = RetainedDataDirectory::from_scanner(
            &data_root,
            OsStr::new("cat-cat_a"),
            &cat,
            OsStr::new("volume-vol_a"),
            &volume,
            OsStr::new("attachment-att_a"),
            &attachment,
            OsStr::new("epoch-7"),
            &epoch,
            HostPath::new(epoch_path.to_string_lossy().into_owned()).unwrap(),
            entries.iter().map(|(name, stat)| (name.as_os_str(), stat)),
            &context,
        )
        .unwrap();
        RetainedFixture {
            _temp: temp,
            data_root_path,
            leaf_path,
            retained,
            context,
        }
    }

    fn top_entry_stats(path: &Path) -> Vec<(OsString, libc::stat)> {
        let directory = File::open(path).unwrap();
        directory_entries(&directory)
            .unwrap()
            .into_iter()
            .map(|name| {
                let name_c = CString::new(name.as_bytes()).unwrap();
                let stat = stat_at(&directory, &name_c).unwrap();
                (name, stat)
            })
            .collect()
    }

    #[test]
    fn exact_retained_tree_is_unlinked_descriptor_relative_and_parents_are_synced() {
        let fixture = retained_fixture();

        fixture.retained.reclaim(&fixture.context).unwrap();

        assert!(fixture.data_root_path.exists());
        assert!(!fixture.data_root_path.join("cat-cat_a").exists());
    }

    #[test]
    fn same_name_leaf_replacement_after_scan_is_preserved() {
        let fixture = retained_fixture();
        std::fs::remove_file(&fixture.leaf_path).unwrap();
        std::fs::write(&fixture.leaf_path, b"replacement bytes").unwrap();
        std::fs::set_permissions(&fixture.leaf_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();

        let error = fixture.retained.reclaim(&fixture.context).unwrap_err();

        assert!(error
            .to_string()
            .contains("complete child set changed before reclaim"));
        assert_eq!(
            std::fs::read(&fixture.leaf_path).unwrap(),
            b"replacement bytes"
        );
    }
}

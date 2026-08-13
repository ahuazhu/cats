//! Durable ownership for the installation-managed blockd socket namespace.
//!
//! A Runtime checkpoint remains the semantic authority for a Root or Serving
//! blockd. Before a process may bind either checkpointed Unix-socket path, the
//! Node writes this provider-private intent receipt durably. Only then may it
//! create a staging directory, fsync the exact receipt bytes as its owner
//! marker, and publish the whole directory without replacement.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Context as _;
use cats_api::guest::RUNTIME_READY_MAX_DEVICES_V1;
use cats_api::runtime_reconciliation::{
    HostPath, NodeBootId, PreparedDeviceInput, RandomId128, Sha256Digest,
};
use cats_blockd::runtime_socket_namespace::{
    ManagedBlockdSocketRoot, BLOCKD_CONTROL_SOCKET_BASENAME, BLOCKD_IO_SOCKET_BASENAME,
    BLOCKD_SOCKET_OWNER_MARKER_BASENAME,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::runtime_spine::RuntimeNodeGlobalEffectPermit;
use crate::state_directory::StateDirectory;

use super::clean_slate_probes::RUNTIME_V1_MAX_ASSIGNED_CATS;

pub(crate) const BLOCKD_SOCKET_INTENT_NAMESPACE: &str = "blockd-socket-intents-v1";

const BLOCKD_SOCKET_INTENT_VERSION: u32 = 1;
const BLOCKD_SOCKET_INTENT_MAX_BYTES: usize = 8 * 1024;
const BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT: usize =
    RUNTIME_V1_MAX_ASSIGNED_CATS * (RUNTIME_READY_MAX_DEVICES_V1 + 1);
// Enumerate one entry beyond the maximum legal owner set so that the first
// foreign name is classified as residue rather than mistaken for truncation.
// Further entries still fail closed at the same descriptor-relative boundary.
const BLOCKD_SOCKET_WHOLE_ROOT_SCAN_ENTRY_LIMIT: usize = BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT + 1;
const SERVING_OWNER_AUTHORITY_DOMAIN: &[u8] = b"cats.blockd.socket-serving-owner.v1";

fn validate_whole_root_expected_owner_count(owner_count: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        owner_count <= BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT,
        "managed blockd whole-root expectation exceeds the assigned owner contract"
    );
    Ok(())
}

/// Sealed sample of the running kernel boot. Raw observation/session values
/// are not namespace deletion authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentBlockdSocketBoot {
    node_boot_id: NodeBootId,
}

impl CurrentBlockdSocketBoot {
    pub(crate) fn read() -> anyhow::Result<Self> {
        Ok(Self {
            node_boot_id: super::vmm_socket_namespace::current_kernel_node_boot_id()?,
        })
    }

    pub(crate) fn node_boot_id(&self) -> &NodeBootId {
        &self.node_boot_id
    }

    #[cfg(test)]
    pub(crate) fn for_test(node_boot_id: NodeBootId) -> Self {
        Self { node_boot_id }
    }
}

/// Canonical digest of the stable PreparedDevice generation. Successor
/// checkpoints preserve this value byte-for-byte, while any owner, frontend,
/// attachment, process or handoff change burns a new namespace authority.
pub(crate) fn serving_socket_owner_authority_digest(
    prepared: &PreparedDeviceInput,
) -> anyhow::Result<Sha256Digest> {
    let value = serde_json::to_value(prepared).context("encode Serving socket owner authority")?;
    let bytes = canonical_json_bytes(&value);
    let decoded: PreparedDeviceInput =
        serde_json::from_value(value.clone()).context("decode Serving socket owner authority")?;
    anyhow::ensure!(
        decoded == *prepared
            && canonical_json_bytes(
                &serde_json::to_value(&decoded)
                    .context("re-encode Serving socket owner authority")?
            ) == bytes,
        "Serving socket owner authority is not canonical"
    );
    let mut hasher = Sha256::new();
    hasher.update(SERVING_OWNER_AUTHORITY_DOMAIN);
    hasher.update([0]);
    hasher.update(bytes);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut Vec<u8>) {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(true) => output.extend_from_slice(b"true"),
            Value::Bool(false) => output.extend_from_slice(b"false"),
            Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
            Value::String(string) => {
                output.extend_from_slice(
                    serde_json::to_string(string)
                        .expect("a Rust string always has a JSON encoding")
                        .as_bytes(),
                );
            }
            Value::Array(items) => {
                output.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(item, output);
                }
                output.push(b']');
            }
            Value::Object(object) => {
                let mut members = object.iter().collect::<Vec<_>>();
                members.sort_unstable_by_key(|(key, _)| *key);
                output.push(b'{');
                for (index, (key, member)) in members.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(
                        serde_json::to_string(key)
                            .expect("a Rust string always has a JSON encoding")
                            .as_bytes(),
                    );
                    output.push(b':');
                    write(member, output);
                }
                output.push(b'}');
            }
        }
    }

    let mut output = Vec::new();
    write(value, &mut output);
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            user: metadata.uid(),
            group: metadata.gid(),
        }
    }
}

#[derive(Debug)]
struct RetainedPathDirectory {
    name: OsString,
    descriptor: File,
    identity: DirectoryIdentity,
}

/// Descriptor-retained authority over the one installation-owned blockd
/// socket root. Production never creates this root while handling a Cat.
#[derive(Debug)]
pub(crate) struct RetainedManagedBlockdSocketRoot {
    planner: ManagedBlockdSocketRoot,
    directories: Vec<RetainedPathDirectory>,
    descriptor: File,
    identity: DirectoryIdentity,
}

impl RetainedManagedBlockdSocketRoot {
    pub(crate) fn open_installed() -> anyhow::Result<Self> {
        Self::open(ManagedBlockdSocketRoot::installed(), 0, 0)
    }

    fn open(
        planner: ManagedBlockdSocketRoot,
        expected_user: u32,
        expected_group: u32,
    ) -> anyhow::Result<Self> {
        let mut directories = open_directory_chain(Path::new(planner.path().as_str()))
            .context("open installed managed blockd socket root")?;
        let descriptor = directories
            .last()
            .context("managed blockd socket root chain is empty")?
            .descriptor
            .try_clone()?;
        let metadata = descriptor.metadata()?;
        ensure_owned_directory(&metadata, expected_user, expected_group, 0o700)?;
        let retained = Self {
            planner,
            directories: std::mem::take(&mut directories),
            descriptor,
            identity: DirectoryIdentity::from_metadata(&metadata),
        };
        retained.assert_current()?;
        Ok(retained)
    }

    pub(crate) fn planner(&self) -> &ManagedBlockdSocketRoot {
        &self.planner
    }

    pub(crate) fn owner(&self) -> (u32, u32) {
        (self.identity.user, self.identity.group)
    }

    pub(crate) fn identity_coordinate(&self) -> (u64, u64, u32, u32, u32) {
        (
            self.identity.device,
            self.identity.inode,
            self.identity.mode,
            self.identity.user,
            self.identity.group,
        )
    }

    /// Clones the retained root descriptor only after a fresh no-follow
    /// traversal proves the installed pathname still names this capability.
    /// Callers may traverse children relative to the clone, but cannot forge
    /// or replace the root authority itself.
    pub(crate) fn try_clone_descriptor(&self) -> anyhow::Result<File> {
        self.assert_current()?;
        self.descriptor
            .try_clone()
            .context("clone retained managed blockd socket root")
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        let retained = self.descriptor.metadata()?;
        ensure_owned_directory(&retained, self.identity.user, self.identity.group, 0o700)?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&retained) == self.identity,
            "retained managed blockd socket root changed identity"
        );
        for directory in &self.directories {
            let metadata = directory.descriptor.metadata()?;
            anyhow::ensure!(
                metadata.file_type().is_dir()
                    && metadata.nlink() > 0
                    && DirectoryIdentity::from_metadata(&metadata) == directory.identity,
                "retained managed blockd socket ancestor changed identity"
            );
        }
        let reopened = open_directory_chain(Path::new(self.planner.path().as_str()))?;
        anyhow::ensure!(
            reopened.len() == self.directories.len()
                && reopened.iter().zip(&self.directories).all(|(left, right)| {
                    left.name == right.name && left.identity == right.identity
                }),
            "managed blockd socket root ancestor chain changed identity"
        );
        Ok(())
    }

    /// Recover or create the exact public owner directory. The durable intent
    /// must already exist byte-for-byte; this method never manufactures it.
    pub(crate) fn prepare_existing_intent<'a>(
        &'a self,
        intents: &'a BlockdSocketIntentStore,
        expected: &BlockdSocketOwnershipIntentV1,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<PreparedManagedBlockdSocketOwner<'a>> {
        let namespace_lock = intents.lock_exclusive()?;
        self.prepare_existing_intent_locked(intents, expected, current_boot, namespace_lock)
    }

    /// Atomically settles an exact old-boot receipt, publishes the current
    /// boot's durable intent, and installs its boot-local owner directory.
    /// No caller can interleave a current receipt between stale retirement
    /// and reissue because all three phases share one retained namespace lock.
    pub(crate) fn prepare_for_start<'a>(
        &'a self,
        intents: &'a BlockdSocketIntentStore,
        expected: &BlockdSocketOwnershipIntentV1,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<PreparedManagedBlockdSocketOwner<'a>> {
        let namespace_lock = intents.lock_exclusive()?;
        self.assert_current()?;
        intents.assert_current()?;
        expected.validate_against(self, current_boot.node_boot_id())?;
        if let Some(existing) = intents.load_unlocked(expected.owner())? {
            if existing != *expected {
                anyhow::ensure!(
                    existing.owner() == expected.owner()
                        && existing.owner_authority_digest() == expected.owner_authority_digest()
                        && existing.node_boot_id() != current_boot.node_boot_id(),
                    "existing blockd socket intent is not the exact stable owner generation"
                );
                intents.retire_stale_boot_intent_unlocked(&existing, self, current_boot)?;
            }
        }
        intents.publish_unlocked(expected, self, current_boot)?;
        self.prepare_existing_intent_locked(intents, expected, current_boot, namespace_lock)
    }

    /// Consume the Node-global absence proof for exactly one owner. A fresh
    /// namespace can only be created. A same-boot captured directory is first
    /// moved as a whole to quarantine, then its exact captured leaves are
    /// removed descriptor-relative while the owner inode remains flocked.
    pub(crate) fn prepare_absent_owner_for_start<'a>(
        &'a self,
        intents: &'a BlockdSocketIntentStore,
        expected: &BlockdSocketOwnershipIntentV1,
        current_boot: &CurrentBlockdSocketBoot,
        absence: ExactManagedBlockdSocketOwnerStartAbsence,
    ) -> anyhow::Result<PreparedManagedBlockdSocketOwner<'a>> {
        anyhow::ensure!(
            absence.intent() == expected,
            "blockd start-absence proof names another owner generation"
        );
        absence.assert_current(current_boot)?;
        match absence.capture {
            ManagedBlockdSocketOwnerStartCapture::Fresh(fresh) => {
                if let Some(captured) = fresh.receipt {
                    intents.settle_captured_intent_for_start(
                        &captured,
                        self,
                        current_boot,
                        expected,
                    )?;
                }
            }
            ManagedBlockdSocketOwnerStartCapture::ExistingSameBoot(captured) => {
                captured.settle_for_start_after_absence(current_boot)?;
            }
        }
        self.prepare_for_start(intents, expected, current_boot)
    }

    /// Consume the same accepted-full/global-absence proof in the opposite
    /// direction: first settle the exact captured owner directory as a whole,
    /// then claim and remove its exact durable intent. No pathname-local
    /// inspection can reach this deletion edge.
    pub(crate) fn retire_absent_owner(
        &self,
        intents: &BlockdSocketIntentStore,
        expected: &BlockdSocketOwnershipIntentV1,
        current_boot: &CurrentBlockdSocketBoot,
        absence: ExactManagedBlockdSocketOwnerStartAbsence,
    ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
        anyhow::ensure!(
            absence.intent() == expected,
            "blockd retirement absence proof names another owner generation"
        );
        absence.assert_current(current_boot)?;
        let captured_intent = match absence.capture {
            ManagedBlockdSocketOwnerStartCapture::Fresh(fresh) => fresh.receipt,
            ManagedBlockdSocketOwnerStartCapture::ExistingSameBoot(captured) => {
                let intent_capture = captured.intent_capture.clone();
                captured.settle_for_retirement_after_absence(current_boot)?;
                Some(intent_capture)
            }
        };
        let retired = intents.retire_owner_intent_after_absence(
            captured_intent.as_ref(),
            self,
            current_boot,
            expected,
        )?;
        let paths = expected.derived_paths(self)?;
        assert_all_owner_names_absent(self, &paths)?;
        anyhow::ensure!(
            capture_intent_receipt_unlocked_with_lock(intents, expected.owner())?.is_none(),
            "retired blockd owner intent reappeared"
        );
        Ok(retired)
    }

    /// Retains the exact current receipt/marker/directory without creating or
    /// publishing anything. A live process may be adopted only from
    /// `Current`; every absent variant is a read-only fact for the higher
    /// Node-global scanner/effect admission to consume. `RecoverableAbsent`
    /// covers the exact joint crash phases (intent staging/quarantine, owner
    /// staging/quarantine, or current intent with no owner directory). It must
    /// never be treated as local authority to create or delete paths.
    pub(crate) fn retain_existing_intent<'a>(
        &'a self,
        intents: &'a BlockdSocketIntentStore,
        expected: &BlockdSocketOwnershipIntentV1,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<ManagedBlockdSocketOwnerInspection<'a>> {
        let namespace_lock = intents.lock_exclusive()?;
        self.assert_current()?;
        intents.assert_current()?;
        expected.validate_against(self, current_boot.node_boot_id())?;
        let paths = expected.derived_paths(self)?;
        let Some(captured) = capture_intent_receipt_unlocked(intents, expected.owner())? else {
            assert_all_owner_names_absent(self, &paths)?;
            return Ok(ManagedBlockdSocketOwnerInspection::Absent);
        };
        let durable = captured.intent;
        if durable.node_boot_id() != current_boot.node_boot_id() {
            durable.validate_stale_mapping(self)?;
            anyhow::ensure!(
                durable.owner() == expected.owner()
                    && durable.owner_authority_digest() == expected.owner_authority_digest(),
                "old-boot blockd socket intent is another stable owner generation"
            );
            assert_all_owner_names_absent(self, &paths)?;
            return Ok(ManagedBlockdSocketOwnerInspection::StaleBootAbsent);
        }
        anyhow::ensure!(
            durable == *expected,
            "current-boot blockd socket ownership intent differs from expectation"
        );
        if captured.phase != CapturedBlockdSocketIntentPhase::Public {
            assert_all_owner_names_absent(self, &paths)?;
            return Ok(ManagedBlockdSocketOwnerInspection::RecoverableAbsent);
        }
        let candidates = [
            (CapturedOwnerDirectoryPhase::Public, &paths.public_name),
            (CapturedOwnerDirectoryPhase::Staging, &paths.staging_name),
            (
                CapturedOwnerDirectoryPhase::Quarantine,
                &paths.quarantine_name,
            ),
        ]
        .into_iter()
        .map(|(phase, name)| {
            open_owned_directory(
                &self.descriptor,
                name,
                self.identity.user,
                self.identity.group,
            )
            .map(|directory| directory.map(|directory| (phase, directory)))
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let [(phase, directory)] = candidates.as_slice() else {
            anyhow::ensure!(
                candidates.is_empty(),
                "current blockd intent retains multiple public/recovery aliases"
            );
            return Ok(ManagedBlockdSocketOwnerInspection::RecoverableAbsent);
        };
        assert_other_owner_names_absent(self, &paths, *phase)?;
        if *phase != CapturedOwnerDirectoryPhase::Public {
            verify_owner_directory(directory, expected, phase.snapshot_phase())?;
            return Ok(ManagedBlockdSocketOwnerInspection::RecoverableAbsent);
        }
        let public = directory.try_clone()?;
        verify_owner_directory(&public, expected, DirectoryPhase::Public)?;
        drop(namespace_lock);
        let owner_lock = OwnerDirectoryLock::acquire(&public)?;
        let namespace_lock = intents.lock_exclusive()?;
        let retained = PreparedManagedBlockdSocketOwner {
            root: self,
            intents,
            receipt: durable,
            public_identity: DirectoryIdentity::from_metadata(&public.metadata()?),
            snapshot: owner_directory_snapshot(&public, expected, DirectoryPhase::Public)?,
            public_directory: public,
            _owner_lock: owner_lock,
        };
        retained.assert_current_unlocked(current_boot)?;
        drop(namespace_lock);
        Ok(ManagedBlockdSocketOwnerInspection::Current(Box::new(
            retained,
        )))
    }

    /// Capture one exact owner namespace before the Node-global process sweep.
    /// This is strictly read-only: missing/stale receipts remain `Fresh`, and
    /// an existing current directory is descriptor-retained without repair.
    pub(crate) fn capture_start_absence(
        self: &Arc<Self>,
        intents: &Arc<BlockdSocketIntentStore>,
        expected: &BlockdSocketOwnershipIntentV1,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<ManagedBlockdSocketOwnerStartCapture> {
        let _namespace_lock = intents.lock_exclusive()?;
        self.assert_current()?;
        intents.assert_current()?;
        expected.validate_against(self, current_boot.node_boot_id())?;
        let paths = expected.derived_paths(self)?;
        let receipt = capture_intent_receipt_unlocked(intents, expected.owner())?;
        match receipt {
            None => {
                assert_all_owner_names_absent(self, &paths)?;
                Ok(ManagedBlockdSocketOwnerStartCapture::fresh(
                    Arc::clone(self),
                    Arc::clone(intents),
                    expected.clone(),
                    None,
                ))
            }
            Some(captured) if captured.intent.node_boot_id() != current_boot.node_boot_id() => {
                captured.intent.validate_stale_mapping(self)?;
                anyhow::ensure!(
                    captured.intent.owner() == expected.owner()
                        && captured.intent.owner_authority_digest()
                            == expected.owner_authority_digest(),
                    "old-boot blockd socket intent is another stable owner generation"
                );
                assert_all_owner_names_absent(self, &paths)?;
                Ok(ManagedBlockdSocketOwnerStartCapture::fresh(
                    Arc::clone(self),
                    Arc::clone(intents),
                    expected.clone(),
                    Some(captured),
                ))
            }
            Some(captured) => {
                anyhow::ensure!(
                    captured.intent == *expected,
                    "current-boot blockd socket ownership intent differs from expectation"
                );
                if captured.phase != CapturedBlockdSocketIntentPhase::Public {
                    assert_all_owner_names_absent(self, &paths)?;
                    return Ok(ManagedBlockdSocketOwnerStartCapture::fresh(
                        Arc::clone(self),
                        Arc::clone(intents),
                        expected.clone(),
                        Some(captured),
                    ));
                }
                let candidates = [
                    (
                        CapturedOwnerDirectoryPhase::Public,
                        paths.public_name.as_str(),
                    ),
                    (
                        CapturedOwnerDirectoryPhase::Staging,
                        paths.staging_name.as_str(),
                    ),
                    (
                        CapturedOwnerDirectoryPhase::Quarantine,
                        paths.quarantine_name.as_str(),
                    ),
                ]
                .into_iter()
                .map(|(phase, name)| {
                    open_owned_directory(
                        &self.descriptor,
                        name,
                        self.identity.user,
                        self.identity.group,
                    )
                    .map(|directory| directory.map(|directory| (phase, directory)))
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
                if candidates.is_empty() {
                    return Ok(ManagedBlockdSocketOwnerStartCapture::fresh(
                        Arc::clone(self),
                        Arc::clone(intents),
                        expected.clone(),
                        Some(captured),
                    ));
                }
                let [(phase, directory)] = candidates.as_slice() else {
                    anyhow::bail!(
                        "current blockd intent must retain exactly one public or recovery directory"
                    )
                };
                let identity = DirectoryIdentity::from_metadata(&directory.metadata()?);
                let snapshot =
                    owner_directory_snapshot(directory, expected, phase.snapshot_phase())?;
                Ok(ManagedBlockdSocketOwnerStartCapture::ExistingSameBoot(
                    Box::new(ManagedBlockdSocketOwnerCleanupCapture {
                        root: Arc::clone(self),
                        intents: Arc::clone(intents),
                        receipt: captured.intent.clone(),
                        intent_capture: captured,
                        phase: *phase,
                        directory: directory.try_clone()?,
                        directory_identity: identity,
                        snapshot,
                    }),
                ))
            }
        }
    }

    pub(crate) fn capture_closed_whole_root(
        self: &Arc<Self>,
        intents: &Arc<BlockdSocketIntentStore>,
        expected: &[BlockdSocketOwnershipIntentV1],
    ) -> anyhow::Result<ManagedBlockdSocketWholeRootSnapshot> {
        let _namespace_lock = intents.lock_exclusive()?;
        self.capture_closed_whole_root_unlocked(intents, expected)
    }

    fn capture_closed_whole_root_unlocked(
        self: &Arc<Self>,
        intents: &Arc<BlockdSocketIntentStore>,
        expected: &[BlockdSocketOwnershipIntentV1],
    ) -> anyhow::Result<ManagedBlockdSocketWholeRootSnapshot> {
        self.assert_current()?;
        intents.assert_current()?;
        validate_whole_root_expected_owner_count(expected.len())?;
        let mut allowed_directories = BTreeSet::new();
        let mut allowed_receipts = BTreeSet::new();
        let mut owner_snapshots = BTreeMap::new();
        for intent in expected {
            let paths = derive_paths(self.planner(), intent.owner())?;
            for name in [
                paths.public_name.as_str(),
                paths.staging_name.as_str(),
                paths.quarantine_name.as_str(),
            ] {
                anyhow::ensure!(
                    allowed_directories.insert(name.to_owned()),
                    "managed blockd whole-root expectation repeats an owner directory"
                );
            }
            for name in [
                intent_file_name(intent.owner())?,
                intent_staging_file_name(intent.owner())?,
                intent_quarantine_file_name(intent.owner())?,
            ] {
                anyhow::ensure!(
                    allowed_receipts.insert(name.to_string_lossy().into_owned()),
                    "managed blockd whole-root expectation repeats an intent receipt"
                );
            }

            let receipt = capture_intent_receipt_unlocked(intents, intent.owner())?;
            let (directory_phase, directory) = match receipt.as_ref() {
                None => {
                    assert_all_owner_names_absent(self, &paths)?;
                    (None, None)
                }
                Some(captured) => {
                    anyhow::ensure!(
                        captured.intent.owner() == intent.owner()
                            && captured.intent.owner_authority_digest()
                                == intent.owner_authority_digest(),
                        "managed blockd whole-root receipt names another owner generation"
                    );
                    if captured.intent.node_boot_id() != intent.node_boot_id() {
                        captured.intent.validate_stale_mapping(self)?;
                        assert_all_owner_names_absent(self, &paths)?;
                        (None, None)
                    } else if captured.phase != CapturedBlockdSocketIntentPhase::Public {
                        anyhow::ensure!(
                            captured.intent == *intent,
                            "managed blockd recovery receipt differs from expectation"
                        );
                        assert_all_owner_names_absent(self, &paths)?;
                        (None, None)
                    } else {
                        anyhow::ensure!(
                            captured.intent == *intent,
                            "managed blockd whole-root current receipt differs from expectation"
                        );
                        let candidates = [
                            (CapturedOwnerDirectoryPhase::Public, &paths.public_name),
                            (CapturedOwnerDirectoryPhase::Staging, &paths.staging_name),
                            (
                                CapturedOwnerDirectoryPhase::Quarantine,
                                &paths.quarantine_name,
                            ),
                        ]
                        .into_iter()
                        .map(|(phase, name)| {
                            open_owned_directory(
                                &self.descriptor,
                                name,
                                self.identity.user,
                                self.identity.group,
                            )
                            .map(|directory| directory.map(|directory| (phase, directory)))
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>();
                        match candidates.as_slice() {
                            [] => (None, None),
                            [(phase, directory)] => {
                                let first = owner_directory_snapshot(
                                    directory,
                                    intent,
                                    phase.snapshot_phase(),
                                )?;
                                let second = owner_directory_snapshot(
                                    directory,
                                    intent,
                                    phase.snapshot_phase(),
                                )?;
                                anyhow::ensure!(
                                    first == second,
                                    "managed blockd sibling owner changed during whole-root snapshot"
                                );
                                (Some(*phase), Some(first))
                            }
                            _ => anyhow::bail!(
                                "managed blockd owner retains multiple public/recovery aliases"
                            ),
                        }
                    }
                }
            };
            anyhow::ensure!(
                owner_snapshots
                    .insert(
                        paths.public_name,
                        ManagedBlockdSocketWholeOwnerSnapshot {
                            intent: intent.clone(),
                            receipt,
                            directory_phase,
                            directory,
                        },
                    )
                    .is_none(),
                "managed blockd whole-root expectation repeats an owner"
            );
        }
        let directory_names = strict_directory_names_bounded(
            &self.descriptor,
            BLOCKD_SOCKET_WHOLE_ROOT_SCAN_ENTRY_LIMIT,
        )?;
        anyhow::ensure!(
            directory_names.is_subset(&allowed_directories),
            "managed blockd socket root contains an unknown owner or recovery alias"
        );
        let receipt_names = strict_directory_names_bounded(
            &intents.directory,
            BLOCKD_SOCKET_WHOLE_ROOT_SCAN_ENTRY_LIMIT,
        )?;
        anyhow::ensure!(
            receipt_names.is_subset(&allowed_receipts),
            "managed blockd intent root contains an unknown or quarantined receipt"
        );
        Ok(ManagedBlockdSocketWholeRootSnapshot {
            root: Arc::clone(self),
            intents: Arc::clone(intents),
            expected: expected.to_vec(),
            directory_names,
            receipt_names,
            owner_snapshots,
        })
    }

    fn prepare_existing_intent_locked<'a>(
        &'a self,
        intents: &'a BlockdSocketIntentStore,
        expected: &BlockdSocketOwnershipIntentV1,
        current_boot: &CurrentBlockdSocketBoot,
        namespace_lock: BlockdSocketNamespaceLock<'a>,
    ) -> anyhow::Result<PreparedManagedBlockdSocketOwner<'a>> {
        self.assert_current()?;
        intents.assert_current()?;
        expected.validate_against(self, current_boot.node_boot_id())?;
        let durable = intents
            .load_unlocked(expected.owner())?
            .context("blockd socket ownership intent is not durable")?;
        anyhow::ensure!(
            durable == *expected,
            "durable blockd socket ownership intent differs from this attempt"
        );

        let paths = expected.derived_paths(self)?;
        let (expected_user, expected_group) = self.owner();
        let mut public = open_owned_directory(
            &self.descriptor,
            &paths.public_name,
            expected_user,
            expected_group,
        )?;
        let staging = open_owned_directory(
            &self.descriptor,
            &paths.staging_name,
            expected_user,
            expected_group,
        )?;
        let quarantine = open_owned_directory(
            &self.descriptor,
            &paths.quarantine_name,
            expected_user,
            expected_group,
        )?;
        let present = usize::from(public.is_some())
            + usize::from(staging.is_some())
            + usize::from(quarantine.is_some());
        anyhow::ensure!(
            present <= 1,
            "multiple blockd socket owner names are a preserved ABA conflict"
        );
        anyhow::ensure!(
            quarantine.is_none(),
            "blockd socket owner is stranded in cleanup quarantine"
        );

        if public.is_none() {
            let staging = match staging {
                Some(staging) => {
                    ensure_staging_marker(&staging, expected)?;
                    verify_owner_directory(&staging, expected, DirectoryPhase::Staging)?;
                    staging
                }
                None => {
                    let name = CString::new(paths.staging_name.as_bytes())?;
                    mkdir_at(&self.descriptor, &name, 0o700)
                        .context("create blockd staging socket directory")?;
                    self.descriptor
                        .sync_all()
                        .context("fsync blockd socket root after staging create")?;
                    let staging = open_directory_at(&self.descriptor, &name)?;
                    ensure_owned_directory(
                        &staging.metadata()?,
                        expected_user,
                        expected_group,
                        0o700,
                    )?;
                    ensure_staging_marker(&staging, expected)?;
                    staging
                }
            };
            let before = DirectoryIdentity::from_metadata(&staging.metadata()?);
            rename_no_replace(
                &self.descriptor,
                &CString::new(paths.staging_name.as_bytes())?,
                &self.descriptor,
                &CString::new(paths.public_name.as_bytes())?,
            )
            .context("publish blockd socket owner directory")?;
            self.descriptor
                .sync_all()
                .context("fsync published blockd socket owner directory")?;
            let published = open_directory_at(
                &self.descriptor,
                &CString::new(paths.public_name.as_bytes())?,
            )?;
            anyhow::ensure!(
                DirectoryIdentity::from_metadata(&published.metadata()?) == before,
                "published blockd socket owner directory changed identity"
            );
            public = Some(published);
        }

        let public = public.context("blockd socket owner directory was not published")?;
        verify_owner_directory(&public, expected, DirectoryPhase::Public)?;
        // Do not hold the Node-global namespace lock while waiting for or
        // submitting systemd. Retain the exact public inode, release global,
        // then serialize only this owner generation by inode flock.
        drop(namespace_lock);
        let owner_lock = OwnerDirectoryLock::acquire(&public)?;
        let namespace_lock = intents.lock_exclusive()?;
        let prepared = PreparedManagedBlockdSocketOwner {
            root: self,
            intents,
            receipt: expected.clone(),
            public_identity: DirectoryIdentity::from_metadata(&public.metadata()?),
            snapshot: owner_directory_snapshot(&public, expected, DirectoryPhase::Public)?,
            public_directory: public,
            _owner_lock: owner_lock,
        };
        prepared.assert_current_unlocked(current_boot)?;
        drop(namespace_lock);
        Ok(prepared)
    }

    #[cfg(test)]
    pub(crate) fn provision_for_test(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir(path).context("create test managed blockd socket root")?;
        std::fs::set_permissions(
            path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )?;
        let metadata = std::fs::metadata(path)?;
        let host_path = HostPath::new(
            path.to_str()
                .context("test managed blockd socket root is not UTF-8")?,
        )
        .context("test managed blockd socket root is not canonical")?;
        let planner = ManagedBlockdSocketRoot::from_canonical_path(host_path)?;
        Self::open(planner, metadata.uid(), metadata.gid())
    }
}

/// Which stable checkpoint identity owns one complete blockd socket
/// directory. Root process-token rotation deliberately is not part of the
/// key; Serving device-token rotation deliberately is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BlockdSocketOwnerV1 {
    Root {
        provision_transition_id: RandomId128,
    },
    Serving {
        device_ownership_token: RandomId128,
    },
}

impl BlockdSocketOwnerV1 {
    fn token(&self) -> &RandomId128 {
        match self {
            Self::Root {
                provision_transition_id,
            } => provision_transition_id,
            Self::Serving {
                device_ownership_token,
            } => device_ownership_token,
        }
    }

    fn role_prefix(&self) -> &'static str {
        match self {
            Self::Root { .. } => "r",
            Self::Serving { .. } => "d",
        }
    }
}

/// Minimal provider-private WAL for one checkpoint-owned blockd socket
/// namespace. The marker is exactly the canonical JSON encoding of this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BlockdSocketOwnershipIntentV1 {
    version: u32,
    node_boot_id: NodeBootId,
    owner_authority_digest: Sha256Digest,
    owner: BlockdSocketOwnerV1,
    managed_root_path: HostPath,
    managed_root_identity: DirectoryIdentity,
    public_directory: HostPath,
    staging_directory: HostPath,
    quarantine_directory: HostPath,
    owner_marker_path: HostPath,
    control_socket_path: HostPath,
    io_socket_path: Option<HostPath>,
}

impl BlockdSocketOwnershipIntentV1 {
    pub(crate) fn root(
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
        provision_transition_id: RandomId128,
        owner_authority_digest: Sha256Digest,
    ) -> anyhow::Result<Self> {
        let owner = BlockdSocketOwnerV1::Root {
            provision_transition_id,
        };
        Self::new(
            root,
            current_boot.node_boot_id().clone(),
            owner,
            owner_authority_digest,
        )
    }

    pub(crate) fn serving(
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
        device_ownership_token: RandomId128,
        owner_authority_digest: Sha256Digest,
    ) -> anyhow::Result<Self> {
        let owner = BlockdSocketOwnerV1::Serving {
            device_ownership_token,
        };
        Self::new(
            root,
            current_boot.node_boot_id().clone(),
            owner,
            owner_authority_digest,
        )
    }

    fn new(
        root: &RetainedManagedBlockdSocketRoot,
        node_boot_id: NodeBootId,
        owner: BlockdSocketOwnerV1,
        owner_authority_digest: Sha256Digest,
    ) -> anyhow::Result<Self> {
        root.assert_current()?;
        let paths = derive_paths(root.planner(), &owner)?;
        let receipt = Self {
            version: BLOCKD_SOCKET_INTENT_VERSION,
            node_boot_id,
            owner_authority_digest,
            owner,
            managed_root_path: root.planner().path().clone(),
            managed_root_identity: root.identity,
            public_directory: paths.public_directory,
            staging_directory: paths.staging_directory,
            quarantine_directory: paths.quarantine_directory,
            owner_marker_path: paths.owner_marker_path,
            control_socket_path: paths.control_socket_path,
            io_socket_path: paths.io_socket_path,
        };
        receipt.validate_mapping(root)?;
        Ok(receipt)
    }

    pub(crate) fn owner(&self) -> &BlockdSocketOwnerV1 {
        &self.owner
    }

    pub(crate) fn node_boot_id(&self) -> &NodeBootId {
        &self.node_boot_id
    }

    pub(crate) fn owner_authority_digest(&self) -> &Sha256Digest {
        &self.owner_authority_digest
    }

    pub(crate) fn control_socket_path(&self) -> &HostPath {
        &self.control_socket_path
    }

    pub(crate) fn io_socket_path(&self) -> Option<&HostPath> {
        self.io_socket_path.as_ref()
    }

    fn validate_against(
        &self,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot_id: &NodeBootId,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            &self.node_boot_id == current_boot_id,
            "blockd socket ownership intent belongs to another Node boot"
        );
        self.validate_mapping(root)
    }

    fn validate_mapping(&self, root: &RetainedManagedBlockdSocketRoot) -> anyhow::Result<()> {
        root.assert_current()?;
        anyhow::ensure!(
            self.version == BLOCKD_SOCKET_INTENT_VERSION,
            "unsupported blockd socket ownership intent version"
        );
        let expected = derive_paths(root.planner(), &self.owner)?;
        anyhow::ensure!(
            self.managed_root_path == *root.planner().path()
                && self.managed_root_identity == root.identity
                && self.public_directory == expected.public_directory
                && self.staging_directory == expected.staging_directory
                && self.quarantine_directory == expected.quarantine_directory
                && self.owner_marker_path == expected.owner_marker_path
                && self.control_socket_path == expected.control_socket_path
                && self.io_socket_path == expected.io_socket_path,
            "blockd socket ownership intent is outside its exact managed mapping"
        );
        Ok(())
    }

    /// Validate a durable receipt from a previous boot against the fresh
    /// installation path. The `/run` root inode is expected to change across
    /// reboot and is therefore explicitly excluded; every lexical owner path
    /// and stable owner-generation field remains exact.
    fn validate_stale_mapping(&self, root: &RetainedManagedBlockdSocketRoot) -> anyhow::Result<()> {
        root.assert_current()?;
        anyhow::ensure!(
            self.version == BLOCKD_SOCKET_INTENT_VERSION,
            "unsupported blockd socket ownership intent version"
        );
        let expected = derive_paths(root.planner(), &self.owner)?;
        anyhow::ensure!(
            self.managed_root_path == *root.planner().path()
                && self.public_directory == expected.public_directory
                && self.staging_directory == expected.staging_directory
                && self.quarantine_directory == expected.quarantine_directory
                && self.owner_marker_path == expected.owner_marker_path
                && self.control_socket_path == expected.control_socket_path
                && self.io_socket_path == expected.io_socket_path,
            "stale blockd socket intent is outside its exact installed mapping"
        );
        Ok(())
    }

    fn derived_paths(
        &self,
        root: &RetainedManagedBlockdSocketRoot,
    ) -> anyhow::Result<DerivedSocketPaths> {
        self.validate_mapping(root)?;
        derive_paths(root.planner(), &self.owner)
    }

    fn encoded_bytes(&self) -> anyhow::Result<Vec<u8>> {
        encode_intent(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivedSocketPaths {
    public_name: String,
    staging_name: String,
    quarantine_name: String,
    public_directory: HostPath,
    staging_directory: HostPath,
    quarantine_directory: HostPath,
    owner_marker_path: HostPath,
    control_socket_path: HostPath,
    io_socket_path: Option<HostPath>,
}

fn derive_paths(
    root: &ManagedBlockdSocketRoot,
    owner: &BlockdSocketOwnerV1,
) -> anyhow::Result<DerivedSocketPaths> {
    let prefix = owner.role_prefix();
    let token = owner.token();
    let public_name = format!("{prefix}-{}", token.as_str());
    let staging_name = format!(".s-{prefix}-{}", token.as_str());
    let quarantine_name = format!(".q-{prefix}-{}", token.as_str());
    match owner {
        BlockdSocketOwnerV1::Root { .. } => {
            let paths = root.root_paths(token)?;
            Ok(DerivedSocketPaths {
                public_name,
                staging_name,
                quarantine_name,
                public_directory: paths.public_directory().clone(),
                staging_directory: paths.staging_directory().clone(),
                quarantine_directory: paths.quarantine_directory().clone(),
                owner_marker_path: paths.owner_marker().clone(),
                control_socket_path: paths.control_socket().clone(),
                io_socket_path: None,
            })
        }
        BlockdSocketOwnerV1::Serving { .. } => {
            let paths = root.serving_paths(token)?;
            Ok(DerivedSocketPaths {
                public_name,
                staging_name,
                quarantine_name,
                public_directory: paths.public_directory().clone(),
                staging_directory: paths.staging_directory().clone(),
                quarantine_directory: paths.quarantine_directory().clone(),
                owner_marker_path: paths.owner_marker().clone(),
                control_socket_path: paths.control_socket().clone(),
                io_socket_path: Some(paths.io_socket().clone()),
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockdSocketIntentPublication {
    Published,
    ExactReplay,
}

/// Durable intent store under the identity-selected Node state directory.
/// The directory is provisioned before reconciliation; opening it is read-only
/// with respect to namespace structure.
#[derive(Debug)]
pub(crate) struct BlockdSocketIntentStore {
    state_directory: StateDirectory,
    directory: File,
    identity: DirectoryIdentity,
    namespace_lock: Mutex<()>,
}

impl BlockdSocketIntentStore {
    pub(crate) fn open_existing(state_directory: StateDirectory) -> anyhow::Result<Self> {
        let root = state_directory
            .try_clone_directory()
            .context("retain Node state directory for blockd socket intents")?;
        let root_metadata = root.metadata()?;
        let directory = open_directory_at(&root, &fixed_c_string(BLOCKD_SOCKET_INTENT_NAMESPACE))
            .context("open provisioned blockd socket intent namespace")?;
        let metadata = directory.metadata()?;
        ensure_owned_directory(&metadata, root_metadata.uid(), root_metadata.gid(), 0o700)?;
        let store = Self {
            state_directory,
            directory,
            identity: DirectoryIdentity::from_metadata(&metadata),
            namespace_lock: Mutex::new(()),
        };
        store.assert_current()?;
        Ok(store)
    }

    pub(crate) fn state_directory(&self) -> &StateDirectory {
        &self.state_directory
    }

    pub(crate) fn identity_coordinate(&self) -> (u64, u64, u32, u32, u32) {
        (
            self.identity.device,
            self.identity.inode,
            self.identity.mode,
            self.identity.user,
            self.identity.group,
        )
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        let root = self
            .state_directory
            .try_reopen_directory()
            .context("reopen Node state directory for blockd socket intent")?;
        let current = open_directory_at(&root, &fixed_c_string(BLOCKD_SOCKET_INTENT_NAMESPACE))?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&self.directory.metadata()?) == self.identity
                && DirectoryIdentity::from_metadata(&current.metadata()?) == self.identity,
            "blockd socket intent namespace changed identity"
        );
        Ok(())
    }

    pub(crate) fn load(
        &self,
        owner: &BlockdSocketOwnerV1,
    ) -> anyhow::Result<Option<BlockdSocketOwnershipIntentV1>> {
        let _namespace_lock = self.lock_exclusive()?;
        self.load_unlocked(owner)
    }

    fn load_unlocked(
        &self,
        owner: &BlockdSocketOwnerV1,
    ) -> anyhow::Result<Option<BlockdSocketOwnershipIntentV1>> {
        self.assert_current()?;
        let bytes = read_optional_bounded_file(&self.directory, &intent_file_name(owner)?)?;
        self.assert_current()?;
        bytes.map(|bytes| decode_intent(&bytes)).transpose()
    }

    pub(crate) fn publish(
        &self,
        intent: &BlockdSocketOwnershipIntentV1,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<BlockdSocketIntentPublication> {
        let _namespace_lock = self.lock_exclusive()?;
        self.publish_unlocked(intent, root, current_boot)
    }

    fn publish_unlocked(
        &self,
        intent: &BlockdSocketOwnershipIntentV1,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<BlockdSocketIntentPublication> {
        self.assert_current()?;
        intent.validate_against(root, current_boot.node_boot_id())?;
        let bytes = intent.encoded_bytes()?;
        let final_name = intent_file_name(intent.owner())?;
        #[cfg(not(target_os = "linux"))]
        let staging_name = intent_staging_file_name(intent.owner())?;

        if let Some(existing) = read_optional_bounded_file(&self.directory, &final_name)? {
            anyhow::ensure!(
                existing == bytes && decode_intent(&existing)? == *intent,
                "existing blockd socket ownership intent differs from this attempt"
            );
            #[cfg(not(target_os = "linux"))]
            settle_matching_intent_staging(&self.directory, &staging_name, &bytes)?;
            self.directory
                .sync_all()
                .context("settle replayed blockd socket intent directory")?;
            self.assert_current()?;
            return Ok(BlockdSocketIntentPublication::ExactReplay);
        }

        #[cfg(not(target_os = "linux"))]
        match read_optional_bounded_file(&self.directory, &staging_name)? {
            Some(existing) => anyhow::ensure!(
                existing == bytes && decode_intent(&existing)? == *intent,
                "staged blockd socket ownership intent differs from this attempt"
            ),
            None => {
                let mut staging = open_at(
                    &self.directory,
                    &staging_name,
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
                .context("create staged blockd socket ownership intent")?;
                staging
                    .write_all(&bytes)
                    .context("write staged blockd socket ownership intent")?;
                staging
                    .sync_all()
                    .context("fsync staged blockd socket ownership intent")?;
            }
        }

        #[cfg(not(target_os = "linux"))]
        match rename_no_replace(&self.directory, &staging_name, &self.directory, &final_name) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let existing = read_optional_bounded_file(&self.directory, &final_name)?
                    .context("racing blockd socket ownership intent is unreadable")?;
                anyhow::ensure!(
                    existing == bytes && decode_intent(&existing)? == *intent,
                    "racing blockd socket ownership intent differs from this attempt"
                );
                settle_matching_intent_staging(&self.directory, &staging_name, &bytes)?;
            }
            Err(source) => return Err(source).context("publish blockd socket ownership intent"),
        }
        #[cfg(target_os = "linux")]
        {
            let mut anonymous = open_anonymous_intent(&self.directory)
                .context("create anonymous blockd socket ownership intent")?;
            anonymous
                .write_all(&bytes)
                .context("write anonymous blockd socket ownership intent")?;
            anonymous
                .sync_all()
                .context("fsync anonymous blockd socket ownership intent")?;
            match link_anonymous_no_replace(&anonymous, &self.directory, &final_name) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    let existing = read_optional_bounded_file(&self.directory, &final_name)?
                        .context("racing blockd socket ownership intent is unreadable")?;
                    anyhow::ensure!(
                        existing == bytes && decode_intent(&existing)? == *intent,
                        "racing blockd socket ownership intent differs from this attempt"
                    );
                }
                Err(source) => {
                    return Err(source).context("publish anonymous blockd socket ownership intent")
                }
            }
        }
        self.directory
            .sync_all()
            .context("fsync blockd socket ownership intent directory")?;
        let published = read_optional_bounded_file(&self.directory, &final_name)?
            .context("published blockd socket ownership intent disappeared")?;
        anyhow::ensure!(
            published == bytes && decode_intent(&published)? == *intent,
            "published blockd socket ownership intent changed"
        );
        self.assert_current()?;
        Ok(BlockdSocketIntentPublication::Published)
    }

    fn settle_captured_intent_for_start(
        &self,
        captured: &CapturedBlockdSocketIntent,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
        expected: &BlockdSocketOwnershipIntentV1,
    ) -> anyhow::Result<()> {
        let _namespace_lock = self.lock_exclusive()?;
        let current = capture_intent_receipt_unlocked(self, expected.owner())?
            .context("captured blockd socket intent disappeared before recovery")?;
        anyhow::ensure!(
            current == *captured
                && captured.intent.owner() == expected.owner()
                && captured.intent.owner_authority_digest() == expected.owner_authority_digest(),
            "captured blockd socket intent changed before recovery"
        );
        match captured.phase {
            CapturedBlockdSocketIntentPhase::Public
                if captured.intent.node_boot_id() == current_boot.node_boot_id() =>
            {
                anyhow::ensure!(
                    captured.intent == *expected,
                    "current blockd intent changed stable owner generation"
                );
                Ok(())
            }
            CapturedBlockdSocketIntentPhase::Public => {
                self.retire_stale_boot_intent_unlocked(&captured.intent, root, current_boot)?;
                Ok(())
            }
            CapturedBlockdSocketIntentPhase::Staging
                if captured.intent.node_boot_id() == current_boot.node_boot_id() =>
            {
                anyhow::ensure!(
                    captured.intent == *expected,
                    "staged current blockd intent changed stable owner generation"
                );
                Ok(())
            }
            CapturedBlockdSocketIntentPhase::Staging => {
                let retired = self.retire_owner_intent_after_absence_unlocked(
                    Some(captured),
                    root,
                    current_boot,
                    expected,
                )?;
                anyhow::ensure!(
                    retired == ManagedBlockdSocketOwnerRetirement::Retired,
                    "captured old-boot staged blockd intent was not retired"
                );
                Ok(())
            }
            CapturedBlockdSocketIntentPhase::Quarantine => {
                self.finish_captured_intent_quarantine(captured, root, current_boot, expected)
            }
        }
    }

    fn retire_owner_intent_after_absence(
        &self,
        captured: Option<&CapturedBlockdSocketIntent>,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
        expected: &BlockdSocketOwnershipIntentV1,
    ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
        let _namespace_lock = self.lock_exclusive()?;
        self.retire_owner_intent_after_absence_unlocked(captured, root, current_boot, expected)
    }

    fn retire_owner_intent_after_absence_unlocked(
        &self,
        captured: Option<&CapturedBlockdSocketIntent>,
        root: &RetainedManagedBlockdSocketRoot,
        _current_boot: &CurrentBlockdSocketBoot,
        expected: &BlockdSocketOwnershipIntentV1,
    ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
        root.assert_current()?;
        self.assert_current()?;
        assert_all_owner_names_absent(root, &expected.derived_paths(root)?)?;
        let current = capture_intent_receipt_unlocked(self, expected.owner())?;
        anyhow::ensure!(
            current.as_ref() == captured,
            "blockd owner intent changed after its accepted absence proof"
        );
        let Some(captured) = current else {
            return Ok(ManagedBlockdSocketOwnerRetirement::AlreadyAbsent);
        };
        anyhow::ensure!(
            captured.intent.owner() == expected.owner()
                && captured.intent.owner_authority_digest() == expected.owner_authority_digest(),
            "blockd owner retirement receipt names another stable generation"
        );
        let quarantine_name = intent_quarantine_file_name(expected.owner())?;
        let claimed_identity = match captured.phase {
            CapturedBlockdSocketIntentPhase::Quarantine => captured.identity,
            CapturedBlockdSocketIntentPhase::Public | CapturedBlockdSocketIntentPhase::Staging => {
                let source_name = match captured.phase {
                    CapturedBlockdSocketIntentPhase::Public => intent_file_name(expected.owner())?,
                    CapturedBlockdSocketIntentPhase::Staging => {
                        intent_staging_file_name(expected.owner())?
                    }
                    CapturedBlockdSocketIntentPhase::Quarantine => unreachable!(),
                };
                rename_no_replace(
                    &self.directory,
                    &source_name,
                    &self.directory,
                    &quarantine_name,
                )
                .context("claim exact blockd owner intent for retirement")?;
                self.directory
                    .sync_all()
                    .context("fsync blockd owner intent retirement claim")?;
                captured.identity
            }
        };
        let (claimed_bytes, claimed_current_identity) =
            read_optional_bounded_file_with_identity(&self.directory, &quarantine_name)?
                .context("claimed blockd owner intent disappeared")?;
        anyhow::ensure!(
            claimed_bytes == captured.bytes
                && same_file_after_rename(claimed_identity, claimed_current_identity)
                && decode_intent(&claimed_bytes)? == captured.intent,
            "claimed blockd owner intent changed identity or bytes"
        );
        assert_all_owner_names_absent(root, &expected.derived_paths(root)?)?;
        unlink_at(&self.directory, &quarantine_name)
            .context("remove exact retired blockd owner intent")?;
        self.directory
            .sync_all()
            .context("fsync retired blockd owner intent")?;
        anyhow::ensure!(
            capture_intent_receipt_unlocked(self, expected.owner())?.is_none(),
            "retired blockd owner intent reappeared"
        );
        Ok(ManagedBlockdSocketOwnerRetirement::Retired)
    }

    fn finish_captured_intent_quarantine(
        &self,
        captured: &CapturedBlockdSocketIntent,
        root: &RetainedManagedBlockdSocketRoot,
        _current_boot: &CurrentBlockdSocketBoot,
        expected: &BlockdSocketOwnershipIntentV1,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            captured.phase == CapturedBlockdSocketIntentPhase::Quarantine
                && captured.intent.owner() == expected.owner()
                && captured.intent.owner_authority_digest() == expected.owner_authority_digest(),
            "blockd intent quarantine belongs to another owner generation"
        );
        let paths = derive_paths(root.planner(), captured.intent.owner())?;
        assert_all_owner_names_absent(root, &paths)?;
        let quarantine_name = intent_quarantine_file_name(captured.intent.owner())?;
        let (bytes, identity) =
            read_optional_bounded_file_with_identity(&self.directory, &quarantine_name)?
                .context("captured blockd intent quarantine disappeared")?;
        anyhow::ensure!(
            bytes == captured.bytes
                && identity == captured.identity
                && decode_intent(&bytes)? == captured.intent,
            "captured blockd intent quarantine changed"
        );
        unlink_at(&self.directory, &quarantine_name)
            .context("remove exact recovered blockd intent quarantine")?;
        self.directory
            .sync_all()
            .context("fsync recovered blockd intent quarantine removal")?;
        anyhow::ensure!(
            capture_intent_receipt_unlocked(self, expected.owner())?.is_none(),
            "blockd intent receipt reappeared during quarantine recovery"
        );
        Ok(())
    }

    /// Retire exactly one receipt from an older kernel boot after the caller
    /// has opened the fresh, installation-owned `/run` root and proven that
    /// all three names for this owner are absent. A current-boot receipt is
    /// never rewritten, even when the caller presents the same owner.
    pub(crate) fn retire_stale_boot_intent(
        &self,
        stale: &BlockdSocketOwnershipIntentV1,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<BlockdSocketStaleIntentRetirement> {
        let _namespace_lock = self.lock_exclusive()?;
        self.retire_stale_boot_intent_unlocked(stale, root, current_boot)
    }

    fn retire_stale_boot_intent_unlocked(
        &self,
        stale: &BlockdSocketOwnershipIntentV1,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<BlockdSocketStaleIntentRetirement> {
        self.assert_current()?;
        root.assert_current()?;
        stale.validate_stale_mapping(root)?;
        anyhow::ensure!(
            stale.node_boot_id() != current_boot.node_boot_id(),
            "current-boot blockd socket intent is not stale"
        );
        let paths = derive_paths(root.planner(), stale.owner())?;
        for name in [
            paths.public_name.as_str(),
            paths.staging_name.as_str(),
            paths.quarantine_name.as_str(),
        ] {
            anyhow::ensure!(
                open_owned_directory(
                    &root.descriptor,
                    name,
                    root.identity.user,
                    root.identity.group,
                )?
                .is_none(),
                "old-boot blockd intent still has a boot-local namespace entry"
            );
        }
        root.assert_current()?;
        let final_name = intent_file_name(stale.owner())?;
        let staging_name = intent_staging_file_name(stale.owner())?;
        let quarantine_name = intent_quarantine_file_name(stale.owner())?;
        let expected = stale.encoded_bytes()?;
        let public = read_optional_bounded_file_with_identity(&self.directory, &final_name)?;
        let quarantine =
            read_optional_bounded_file_with_identity(&self.directory, &quarantine_name)?;
        anyhow::ensure!(
            public.is_none() || quarantine.is_none(),
            "stale blockd intent retains both public and quarantine names"
        );
        let Some((current, public_identity)) = public else {
            if let Some((quarantined, quarantine_identity)) = quarantine {
                anyhow::ensure!(
                    quarantined == expected && decode_intent(&quarantined)? == *stale,
                    "quarantined stale blockd socket intent changed"
                );
                return self.finish_stale_intent_retirement(
                    stale,
                    root,
                    current_boot,
                    quarantine_identity,
                );
            }
            anyhow::ensure!(
                read_optional_bounded_file(&self.directory, &staging_name)?.is_none(),
                "absent stale blockd intent retained an ambiguous staging receipt"
            );
            self.directory
                .sync_all()
                .context("settle already-absent stale blockd intent")?;
            return Ok(BlockdSocketStaleIntentRetirement::AlreadyAbsent);
        };
        anyhow::ensure!(
            current == expected && decode_intent(&current)? == *stale,
            "stale blockd socket intent changed before retirement"
        );
        let staged = read_optional_bounded_file(&self.directory, &staging_name)?;
        anyhow::ensure!(
            staged.is_none(),
            "stale blockd intent staging receipt requires serialized recovery before retirement"
        );
        rename_no_replace(
            &self.directory,
            &final_name,
            &self.directory,
            &quarantine_name,
        )
        .context("claim exact stale blockd socket intent")?;
        self.directory
            .sync_all()
            .context("fsync stale blockd socket intent claim")?;
        self.finish_stale_intent_retirement(stale, root, current_boot, public_identity)
    }

    fn finish_stale_intent_retirement(
        &self,
        stale: &BlockdSocketOwnershipIntentV1,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
        claimed_identity: StableFileIdentity,
    ) -> anyhow::Result<BlockdSocketStaleIntentRetirement> {
        anyhow::ensure!(
            stale.node_boot_id() != current_boot.node_boot_id(),
            "stale blockd intent became current during retirement"
        );
        let paths = derive_paths(root.planner(), stale.owner())?;
        let quarantine_name = intent_quarantine_file_name(stale.owner())?;
        let expected = stale.encoded_bytes()?;
        root.assert_current()?;
        for name in [
            paths.public_name.as_str(),
            paths.staging_name.as_str(),
            paths.quarantine_name.as_str(),
        ] {
            anyhow::ensure!(
                open_owned_directory(
                    &root.descriptor,
                    name,
                    root.identity.user,
                    root.identity.group,
                )?
                .is_none(),
                "old-boot blockd namespace reappeared during intent retirement"
            );
        }
        let (claimed, current_identity) =
            read_optional_bounded_file_with_identity(&self.directory, &quarantine_name)?
                .context("claimed stale blockd socket intent disappeared")?;
        anyhow::ensure!(
            claimed == expected
                && same_file_after_rename(claimed_identity, current_identity)
                && decode_intent(&claimed)? == *stale,
            "claimed stale blockd socket intent changed identity or bytes"
        );
        unlink_at(&self.directory, &quarantine_name)
            .context("remove claimed stale blockd socket intent")?;
        self.directory
            .sync_all()
            .context("fsync stale blockd socket intent retirement")?;
        anyhow::ensure!(
            read_optional_bounded_file(&self.directory, &quarantine_name)?.is_none(),
            "stale blockd socket intent quarantine reappeared"
        );
        root.assert_current()?;
        self.assert_current()?;
        Ok(BlockdSocketStaleIntentRetirement::Retired)
    }

    #[cfg(test)]
    pub(crate) fn provision_for_test(state_directory: StateDirectory) -> anyhow::Result<Self> {
        let root = state_directory.try_clone_directory()?;
        let root_metadata = root.metadata()?;
        let name = fixed_c_string(BLOCKD_SOCKET_INTENT_NAMESPACE);
        mkdir_at(&root, &name, 0o700)?;
        root.sync_all()?;
        let directory = open_directory_at(&root, &name)?;
        let metadata = directory.metadata()?;
        anyhow::ensure!(
            metadata.uid() == root_metadata.uid() && metadata.gid() == root_metadata.gid(),
            "test blockd socket intent namespace owner changed"
        );
        Self::open_existing(state_directory)
    }

    fn lock_exclusive(&self) -> anyhow::Result<BlockdSocketNamespaceLock<'_>> {
        let local = self
            .namespace_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("blockd socket namespace lock poisoned"))?;
        let root = self
            .state_directory
            .try_reopen_directory()
            .context("reopen Node state directory for blockd namespace lock")?;
        let descriptor = open_directory_at(&root, &fixed_c_string(BLOCKD_SOCKET_INTENT_NAMESPACE))?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&descriptor.metadata()?) == self.identity,
            "blockd socket namespace lock directory changed identity"
        );
        flock_exclusive(&descriptor).context("lock blockd socket namespace")?;
        self.assert_current()?;
        Ok(BlockdSocketNamespaceLock {
            _local: local,
            descriptor,
        })
    }
}

#[derive(Debug)]
struct BlockdSocketNamespaceLock<'a> {
    _local: MutexGuard<'a, ()>,
    descriptor: File,
}

#[derive(Debug)]
struct OwnerDirectoryLock {
    descriptor: File,
    identity: DirectoryIdentity,
}

impl OwnerDirectoryLock {
    fn acquire(directory: &File) -> anyhow::Result<Self> {
        let descriptor = directory.try_clone()?;
        let identity = DirectoryIdentity::from_metadata(&descriptor.metadata()?);
        flock_exclusive(&descriptor).context("lock managed blockd owner directory")?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&descriptor.metadata()?) == identity,
            "managed blockd owner directory changed while locking"
        );
        Ok(Self {
            descriptor,
            identity,
        })
    }

    fn assert_current(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&self.descriptor.metadata()?) == self.identity,
            "managed blockd owner directory lock changed identity"
        );
        Ok(())
    }
}

impl Drop for OwnerDirectoryLock {
    fn drop(&mut self) {
        // SAFETY: this descriptor owns the per-owner flock.
        unsafe { libc::flock(self.descriptor.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl Drop for BlockdSocketNamespaceLock<'_> {
    fn drop(&mut self) {
        // SAFETY: this retained descriptor owns one flock acquisition. Unlock
        // is best-effort in Drop; closing the descriptor also releases it.
        unsafe { libc::flock(self.descriptor.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockdSocketStaleIntentRetirement {
    Retired,
    AlreadyAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedBlockdSocketOwnerRetirement {
    Retired,
    AlreadyAbsent,
}

#[derive(Debug)]
pub(crate) enum ManagedBlockdSocketOwnerInspection<'a> {
    Absent,
    StaleBootAbsent,
    RecoverableAbsent,
    Current(Box<PreparedManagedBlockdSocketOwner<'a>>),
}

/// Namespace state retained before a sealed Node-global process sweep.
/// `Fresh` can authorize creation but never deletion. `ExistingSameBoot`
/// retains the exact public directory, marker and socket-leaf snapshot which
/// a later absence proof may consume for descriptor-relative cleanup.
#[derive(Debug)]
pub(crate) enum ManagedBlockdSocketOwnerStartCapture {
    Fresh(Box<ManagedBlockdSocketFreshCapture>),
    ExistingSameBoot(Box<ManagedBlockdSocketOwnerCleanupCapture>),
}

#[derive(Debug)]
pub(crate) struct ManagedBlockdSocketFreshCapture {
    root: Arc<RetainedManagedBlockdSocketRoot>,
    intents: Arc<BlockdSocketIntentStore>,
    intent: BlockdSocketOwnershipIntentV1,
    receipt: Option<CapturedBlockdSocketIntent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturedBlockdSocketIntentPhase {
    Public,
    Staging,
    Quarantine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapturedBlockdSocketIntent {
    phase: CapturedBlockdSocketIntentPhase,
    intent: BlockdSocketOwnershipIntentV1,
    bytes: Vec<u8>,
    identity: StableFileIdentity,
}

#[derive(Debug)]
pub(crate) struct ManagedBlockdSocketWholeRootSnapshot {
    root: Arc<RetainedManagedBlockdSocketRoot>,
    intents: Arc<BlockdSocketIntentStore>,
    expected: Vec<BlockdSocketOwnershipIntentV1>,
    directory_names: BTreeSet<String>,
    receipt_names: BTreeSet<String>,
    owner_snapshots: BTreeMap<String, ManagedBlockdSocketWholeOwnerSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedBlockdSocketWholeOwnerSnapshot {
    intent: BlockdSocketOwnershipIntentV1,
    receipt: Option<CapturedBlockdSocketIntent>,
    directory_phase: Option<CapturedOwnerDirectoryPhase>,
    directory: Option<OwnerDirectorySnapshot>,
}

impl ManagedBlockdSocketWholeRootSnapshot {
    pub(crate) fn socket_paths(&self) -> BTreeSet<HostPath> {
        self.owner_snapshots
            .values()
            .flat_map(|owner| {
                let mut paths = Vec::with_capacity(2);
                if owner
                    .directory
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.control_socket.is_some())
                {
                    paths.push(owner.intent.control_socket_path().clone());
                }
                if owner
                    .directory
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.io_socket.is_some())
                {
                    paths.extend(owner.intent.io_socket_path().cloned());
                }
                paths
            })
            .collect()
    }

    /// Join a durable Root stop journal to the exact managed-owner snapshot
    /// captured by the full scanner. The journal may outlive the boot-local
    /// public directory; when a current public/quarantine directory remains,
    /// every retained inode must still be the receipted object.
    pub(crate) fn bind_root_stop_owner(
        &self,
        evidence: &ManagedBlockdRootStopOwnerEvidence,
    ) -> anyhow::Result<BTreeSet<HostPath>> {
        let expected = self
            .expected
            .iter()
            .find(|expected| expected.owner() == evidence.intent.owner())
            .context("managed Root stop owner is outside the whole-root expectation")?;
        anyhow::ensure!(
            expected.owner_authority_digest() == evidence.intent.owner_authority_digest(),
            "managed Root stop owner names another stable authority"
        );
        if expected.node_boot_id() == evidence.intent.node_boot_id() {
            evidence.intent.validate_mapping(&self.root)?;
        } else {
            evidence.intent.validate_stale_mapping(&self.root)?;
        }
        let paths = derive_paths(self.root.planner(), expected.owner())?;
        let owner = self
            .owner_snapshots
            .get(&paths.public_name)
            .context("managed Root stop owner is outside the whole-root expectation")?;
        anyhow::ensure!(
            owner.intent.owner() == evidence.intent.owner()
                && owner.intent.owner_authority_digest()
                    == evidence.intent.owner_authority_digest(),
            "managed Root stop owner names another stable generation"
        );
        let Some(captured_receipt) = owner.receipt.as_ref() else {
            anyhow::ensure!(
                owner.directory.is_none(),
                "retired managed Root stop owner retained a directory without its intent"
            );
            return Ok(BTreeSet::new());
        };
        anyhow::ensure!(
            captured_receipt.intent == evidence.intent,
            "managed Root stop owner intent changed from its journal"
        );
        let Some(directory) = owner.directory.as_ref() else {
            return Ok(BTreeSet::new());
        };
        anyhow::ensure!(
            directory.directory == evidence.public_directory && directory.io_socket.is_none(),
            "managed Root stop owner directory changed from its journal"
        );
        if let Some(marker) = directory.marker_identity {
            anyhow::ensure!(
                marker == evidence.marker,
                "managed Root stop owner marker changed from its journal"
            );
        }
        let mut physical = BTreeSet::new();
        if let Some(control) = directory.control_socket {
            anyhow::ensure!(
                control == evidence.control_socket,
                "managed Root stop control socket changed from its journal"
            );
            // A bound pathname remains the original public path after the
            // whole owner directory is renamed into quarantine.
            physical.insert(evidence.intent.control_socket_path().clone());
        }
        Ok(physical)
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        let _namespace_lock = self.intents.lock_exclusive()?;
        let current = self
            .root
            .capture_closed_whole_root_unlocked(&self.intents, &self.expected)?;
        anyhow::ensure!(
            self.same_coordinates(&current),
            "managed blockd whole-root snapshot changed"
        );
        Ok(())
    }

    pub(crate) fn same_coordinates(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root, &other.root)
            && Arc::ptr_eq(&self.intents, &other.intents)
            && self.expected == other.expected
            && self.directory_names == other.directory_names
            && self.receipt_names == other.receipt_names
            && self.owner_snapshots == other.owner_snapshots
    }
}

#[derive(Debug)]
pub(crate) struct ManagedBlockdSocketOwnerCleanupCapture {
    root: Arc<RetainedManagedBlockdSocketRoot>,
    intents: Arc<BlockdSocketIntentStore>,
    receipt: BlockdSocketOwnershipIntentV1,
    intent_capture: CapturedBlockdSocketIntent,
    phase: CapturedOwnerDirectoryPhase,
    directory: File,
    directory_identity: DirectoryIdentity,
    snapshot: OwnerDirectorySnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapturedOwnerDirectoryPhase {
    Public,
    Staging,
    Quarantine,
}

impl CapturedOwnerDirectoryPhase {
    fn name(self, paths: &DerivedSocketPaths) -> &str {
        match self {
            Self::Public => &paths.public_name,
            Self::Staging => &paths.staging_name,
            Self::Quarantine => &paths.quarantine_name,
        }
    }

    fn snapshot_phase(self) -> DirectoryPhase {
        match self {
            Self::Staging => DirectoryPhase::Staging,
            Self::Public => DirectoryPhase::Public,
            Self::Quarantine => DirectoryPhase::Quarantine,
        }
    }
}

impl ManagedBlockdSocketOwnerStartCapture {
    fn fresh(
        root: Arc<RetainedManagedBlockdSocketRoot>,
        intents: Arc<BlockdSocketIntentStore>,
        intent: BlockdSocketOwnershipIntentV1,
        receipt: Option<CapturedBlockdSocketIntent>,
    ) -> Self {
        Self::Fresh(Box::new(ManagedBlockdSocketFreshCapture {
            root,
            intents,
            intent,
            receipt,
        }))
    }

    pub(crate) fn intent(&self) -> &BlockdSocketOwnershipIntentV1 {
        match self {
            Self::Fresh(fresh) => &fresh.intent,
            Self::ExistingSameBoot(retained) => &retained.receipt,
        }
    }

    pub(crate) fn socket_paths(&self) -> BTreeSet<HostPath> {
        match self {
            Self::Fresh(_) => BTreeSet::new(),
            Self::ExistingSameBoot(retained) => {
                let mut paths = BTreeSet::new();
                if retained.snapshot.control_socket.is_some() {
                    paths.insert(retained.receipt.control_socket_path().clone());
                }
                if retained.snapshot.io_socket.is_some() {
                    paths.extend(retained.receipt.io_socket_path().cloned());
                }
                paths
            }
        }
    }

    pub(crate) fn assert_current(
        &self,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<()> {
        match self {
            Self::Fresh(fresh) => {
                let ManagedBlockdSocketFreshCapture {
                    root,
                    intents,
                    intent,
                    receipt,
                } = fresh.as_ref();
                root.assert_current()?;
                intents.assert_current()?;
                assert_all_owner_names_absent(root, &intent.derived_paths(root)?)?;
                let _namespace_lock = intents.lock_exclusive()?;
                let current = capture_intent_receipt_unlocked(intents, intent.owner())?;
                anyhow::ensure!(
                    &current == receipt,
                    "fresh blockd owner receipt or recovery alias changed"
                );
                if let Some(existing) = current {
                    anyhow::ensure!(
                        existing.intent == *intent
                            || existing.intent.owner() == intent.owner()
                                && existing.intent.owner_authority_digest()
                                    == intent.owner_authority_digest()
                                && existing.intent.node_boot_id() != current_boot.node_boot_id(),
                        "fresh blockd owner capture changed durable owner generation"
                    );
                }
                Ok(())
            }
            Self::ExistingSameBoot(retained) => retained.assert_current(current_boot),
        }
    }
}

impl ManagedBlockdSocketOwnerCleanupCapture {
    fn assert_current(&self, current_boot: &CurrentBlockdSocketBoot) -> anyhow::Result<()> {
        let _namespace_lock = self.intents.lock_exclusive()?;
        self.root.assert_current()?;
        self.intents.assert_current()?;
        self.receipt
            .validate_against(&self.root, current_boot.node_boot_id())?;
        anyhow::ensure!(
            self.intents.load_unlocked(self.receipt.owner())? == Some(self.receipt.clone()),
            "captured blockd socket intent changed"
        );
        let paths = self.receipt.derived_paths(&self.root)?;
        assert_other_owner_names_absent(&self.root, &paths, self.phase)?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&self.directory.metadata()?)
                == self.directory_identity,
            "captured blockd owner directory changed identity"
        );
        let reopened = open_directory_at(
            &self.root.descriptor,
            &CString::new(self.phase.name(&paths).as_bytes())?,
        )?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&reopened.metadata()?) == self.directory_identity
                && owner_directory_snapshot(
                    &self.directory,
                    &self.receipt,
                    self.phase.snapshot_phase(),
                )? == self.snapshot,
            "captured blockd owner pathname or leaves changed"
        );
        Ok(())
    }

    fn settle_for_start_after_absence(
        self,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<()> {
        if self.phase == CapturedOwnerDirectoryPhase::Staging {
            return self.assert_current(current_boot);
        }
        self.settle_for_retirement_after_absence(current_boot)
    }

    fn settle_for_retirement_after_absence(
        self,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<()> {
        let owner_lock = OwnerDirectoryLock::acquire(&self.directory)?;
        let _namespace_lock = self.intents.lock_exclusive()?;
        owner_lock.assert_current()?;
        self.root.assert_current()?;
        self.intents.assert_current()?;
        self.receipt
            .validate_against(&self.root, current_boot.node_boot_id())?;
        anyhow::ensure!(
            self.intents.load_unlocked(self.receipt.owner())? == Some(self.receipt.clone()),
            "cleanup capture lost its exact durable intent"
        );
        let paths = self.receipt.derived_paths(&self.root)?;
        assert_other_owner_names_absent(&self.root, &paths, self.phase)?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&self.directory.metadata()?)
                == self.directory_identity
                && owner_directory_snapshot(
                    &self.directory,
                    &self.receipt,
                    self.phase.snapshot_phase(),
                )? == self.snapshot,
            "cleanup capture changed after Node-global absence proof"
        );
        if matches!(
            self.phase,
            CapturedOwnerDirectoryPhase::Public | CapturedOwnerDirectoryPhase::Staging
        ) {
            let source_name = self.phase.name(&paths);
            rename_no_replace(
                &self.root.descriptor,
                &CString::new(source_name.as_bytes())?,
                &self.root.descriptor,
                &CString::new(paths.quarantine_name.as_bytes())?,
            )
            .context("quarantine exact absent blockd owner directory")?;
            self.root
                .descriptor
                .sync_all()
                .context("fsync blockd owner quarantine claim")?;
        }
        let quarantined = open_directory_at(
            &self.root.descriptor,
            &CString::new(paths.quarantine_name.as_bytes())?,
        )?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&quarantined.metadata()?) == self.directory_identity
                && owner_directory_snapshot(
                    &quarantined,
                    &self.receipt,
                    DirectoryPhase::Quarantine,
                )? == self.snapshot,
            "quarantined blockd owner changed identity or leaves"
        );
        remove_captured_socket_leaf(
            &quarantined,
            BLOCKD_CONTROL_SOCKET_BASENAME,
            self.snapshot.control_socket,
        )?;
        remove_captured_socket_leaf(
            &quarantined,
            BLOCKD_IO_SOCKET_BASENAME,
            self.snapshot.io_socket,
        )?;
        let marker_name = fixed_c_string(BLOCKD_SOCKET_OWNER_MARKER_BASENAME);
        match (
            self.snapshot.marker_bytes.as_ref(),
            self.snapshot.marker_identity,
        ) {
            (Some(expected_bytes), Some(expected_identity)) => {
                let (marker_bytes, marker_identity) =
                    read_optional_bounded_file_with_identity(&quarantined, &marker_name)?
                        .context("quarantined blockd owner marker disappeared")?;
                anyhow::ensure!(
                    &marker_bytes == expected_bytes && marker_identity == expected_identity,
                    "quarantined blockd owner marker changed before removal"
                );
                unlink_at(&quarantined, &marker_name)
                    .context("remove quarantined blockd owner marker")?;
            }
            (None, None) => anyhow::ensure!(
                read_optional_bounded_file(&quarantined, &marker_name)?.is_none(),
                "quarantined blockd marker appeared after its absence proof"
            ),
            _ => anyhow::bail!("quarantined blockd marker snapshot is inconsistent"),
        }
        quarantined
            .sync_all()
            .context("fsync emptied blockd owner quarantine")?;
        anyhow::ensure!(
            strict_directory_names(&quarantined)?.is_empty(),
            "quarantined blockd owner retained an unexpected leaf"
        );
        remove_directory_at(
            &self.root.descriptor,
            &CString::new(paths.quarantine_name.as_bytes())?,
        )
        .context("remove empty blockd owner quarantine")?;
        self.root
            .descriptor
            .sync_all()
            .context("fsync retired blockd owner quarantine")?;
        assert_all_owner_names_absent(&self.root, &paths)?;
        Ok(())
    }
}

/// Opaque join between one pre-sweep namespace capture and the accepted
/// Node-global process/cgroup/socket absence sweep. The effect permit is held
/// inside this value; provider-local start code cannot synthesize it from a
/// path or a local `systemctl` result.
pub(crate) struct ExactManagedBlockdSocketOwnerStartAbsence {
    capture: ManagedBlockdSocketOwnerStartCapture,
    whole_root: ManagedBlockdSocketWholeRootSnapshot,
    _node_global_effect: RuntimeNodeGlobalEffectPermit,
}

impl ExactManagedBlockdSocketOwnerStartAbsence {
    pub(crate) fn seal_after_node_global_sweep(
        capture: ManagedBlockdSocketOwnerStartCapture,
        before: ManagedBlockdSocketWholeRootSnapshot,
        after: ManagedBlockdSocketWholeRootSnapshot,
        current_boot: &CurrentBlockdSocketBoot,
        node_global_effect: RuntimeNodeGlobalEffectPermit,
    ) -> anyhow::Result<Self> {
        capture.assert_current(current_boot)?;
        before.assert_current()?;
        anyhow::ensure!(
            before.same_coordinates(&after),
            "managed blockd whole-root changed across Node-global absence sweep"
        );
        Ok(Self {
            capture,
            whole_root: after,
            _node_global_effect: node_global_effect,
        })
    }

    pub(crate) fn intent(&self) -> &BlockdSocketOwnershipIntentV1 {
        self.capture.intent()
    }

    fn assert_current(&self, current_boot: &CurrentBlockdSocketBoot) -> anyhow::Result<()> {
        self.capture.assert_current(current_boot)?;
        self.whole_root.assert_current()
    }
}

/// Descriptor-retained proof that the exact receipt-owned directory is public
/// and closed to all entries except the marker and role-specific sockets.
#[derive(Debug)]
pub(crate) struct PreparedManagedBlockdSocketOwner<'a> {
    root: &'a RetainedManagedBlockdSocketRoot,
    intents: &'a BlockdSocketIntentStore,
    receipt: BlockdSocketOwnershipIntentV1,
    public_directory: File,
    public_identity: DirectoryIdentity,
    snapshot: OwnerDirectorySnapshot,
    _owner_lock: OwnerDirectoryLock,
}

impl PreparedManagedBlockdSocketOwner<'_> {
    pub(crate) fn receipt(&self) -> &BlockdSocketOwnershipIntentV1 {
        &self.receipt
    }

    pub(crate) fn public_directory(&self) -> &HostPath {
        &self.receipt.public_directory
    }

    pub(crate) fn control_socket_path(&self) -> &HostPath {
        self.receipt.control_socket_path()
    }

    pub(crate) fn io_socket_path(&self) -> Option<&HostPath> {
        self.receipt.io_socket_path()
    }

    pub(crate) fn public_identity_coordinate(&self) -> (u64, u64, u32, u32, u32) {
        (
            self.public_identity.device,
            self.public_identity.inode,
            self.public_identity.mode,
            self.public_identity.user,
            self.public_identity.group,
        )
    }

    pub(crate) fn assert_current(
        &self,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<()> {
        let _namespace_lock = self.intents.lock_exclusive()?;
        self.assert_current_unlocked(current_boot)
    }

    /// Revalidate the retained owner after a process submission. The exact
    /// pre-bind snapshot must contain no socket leaves. A submission may add
    /// only the role-specific ctl/io socket leaves; the receipt, marker,
    /// public directory inode and recovery-alias absence stay exact.
    pub(crate) fn assert_post_submit_owner_current(
        &self,
        current_boot: &CurrentBlockdSocketBoot,
        outcome: BlockdSocketPostSubmitOutcome,
    ) -> anyhow::Result<()> {
        if outcome == BlockdSocketPostSubmitOutcome::DefinitelyNotStarted {
            return self.assert_current(current_boot);
        }
        anyhow::ensure!(
            self.snapshot.control_socket.is_none() && self.snapshot.io_socket.is_none(),
            "prepared blockd owner was not socket-free before submission"
        );
        let _namespace_lock = self.intents.lock_exclusive()?;
        let after = self.current_closed_snapshot_unlocked(current_boot)?;
        anyhow::ensure!(
            after.directory == self.snapshot.directory
                && after.marker_identity == self.snapshot.marker_identity
                && after.marker_bytes == self.snapshot.marker_bytes,
            "blockd owner directory or marker changed across process submission"
        );
        if outcome == BlockdSocketPostSubmitOutcome::HandshakeVerified {
            anyhow::ensure!(
                after.control_socket.is_some(),
                "handshake-verified blockd process lacks its managed control socket"
            );
        }
        Ok(())
    }

    pub(crate) fn retain_root_stop_owner_evidence(
        &self,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<ManagedBlockdRootStopOwnerEvidence> {
        let _namespace_lock = self.intents.lock_exclusive()?;
        let snapshot = self.current_closed_snapshot_unlocked(current_boot)?;
        anyhow::ensure!(
            matches!(self.receipt.owner(), BlockdSocketOwnerV1::Root { .. })
                && snapshot.io_socket.is_none(),
            "Root stop evidence requires one Root-only managed owner"
        );
        Ok(ManagedBlockdRootStopOwnerEvidence {
            intent: self.receipt.clone(),
            public_directory: self.public_identity,
            marker: snapshot
                .marker_identity
                .context("Root stop owner marker disappeared")?,
            control_socket: snapshot
                .control_socket
                .context("Root stop owner lacks its managed control socket")?,
        })
    }

    fn assert_current_unlocked(
        &self,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<()> {
        let current = self.current_closed_snapshot_unlocked(current_boot)?;
        anyhow::ensure!(
            current == self.snapshot,
            "retained blockd owner leaf snapshot changed"
        );
        Ok(())
    }

    fn current_closed_snapshot_unlocked(
        &self,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<OwnerDirectorySnapshot> {
        self._owner_lock.assert_current()?;
        self.root.assert_current()?;
        self.intents.assert_current()?;
        self.receipt
            .validate_against(self.root, current_boot.node_boot_id())?;
        let durable = self
            .intents
            .load_unlocked(self.receipt.owner())?
            .context("prepared blockd socket ownership intent disappeared")?;
        anyhow::ensure!(
            durable == self.receipt,
            "prepared blockd socket ownership intent changed"
        );
        let metadata = self.public_directory.metadata()?;
        ensure_owned_directory(
            &metadata,
            self.public_identity.user,
            self.public_identity.group,
            0o700,
        )?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&metadata) == self.public_identity,
            "retained blockd public socket directory changed identity"
        );
        let paths = self.receipt.derived_paths(self.root)?;
        assert_recovery_aliases_absent(self.root, &paths)?;
        let reopened = open_directory_at(
            &self.root.descriptor,
            &CString::new(paths.public_name.as_bytes())?,
        )?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&reopened.metadata()?) == self.public_identity,
            "blockd public socket directory pathname changed identity"
        );
        let first = owner_directory_snapshot(
            &self.public_directory,
            &self.receipt,
            DirectoryPhase::Public,
        )?;
        self.root.assert_current()?;
        assert_recovery_aliases_absent(self.root, &paths)?;
        let reopened = open_directory_at(
            &self.root.descriptor,
            &CString::new(paths.public_name.as_bytes())?,
        )?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&reopened.metadata()?) == self.public_identity,
            "blockd public socket directory changed during validation"
        );
        let second = owner_directory_snapshot(
            &self.public_directory,
            &self.receipt,
            DirectoryPhase::Public,
        )?;
        anyhow::ensure!(
            first == second,
            "blockd owner leaves changed during post-submission validation"
        );
        Ok(second)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockdSocketPostSubmitOutcome {
    DefinitelyNotStarted,
    MayHaveStarted,
    HandshakeVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryPhase {
    Staging,
    Public,
    Quarantine,
}

fn ensure_staging_marker(
    directory: &File,
    intent: &BlockdSocketOwnershipIntentV1,
) -> anyhow::Result<()> {
    let marker_name = fixed_c_string(BLOCKD_SOCKET_OWNER_MARKER_BASENAME);
    if let Some(existing) = read_optional_bounded_file(directory, &marker_name)? {
        anyhow::ensure!(
            existing == intent.encoded_bytes()?,
            "blockd socket owner marker differs from its durable intent"
        );
        return Ok(());
    }
    anyhow::ensure!(
        strict_directory_names(directory)?.is_empty(),
        "unmarked blockd staging directory is not empty"
    );
    let bytes = intent.encoded_bytes()?;
    let mut marker = open_at(
        directory,
        &marker_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .context("create blockd socket owner marker")?;
    marker
        .write_all(&bytes)
        .context("write blockd socket owner marker")?;
    marker
        .sync_all()
        .context("fsync blockd socket owner marker")?;
    directory
        .sync_all()
        .context("fsync blockd staging socket directory")?;
    verify_owner_marker(directory, intent)
}

fn verify_owner_marker(
    directory: &File,
    intent: &BlockdSocketOwnershipIntentV1,
) -> anyhow::Result<()> {
    let existing = read_optional_bounded_file(
        directory,
        &fixed_c_string(BLOCKD_SOCKET_OWNER_MARKER_BASENAME),
    )?
    .context("blockd socket owner marker is missing")?;
    anyhow::ensure!(
        existing == intent.encoded_bytes()?,
        "blockd socket owner marker differs from its durable intent"
    );
    Ok(())
}

fn verify_owner_directory(
    directory: &File,
    intent: &BlockdSocketOwnershipIntentV1,
    phase: DirectoryPhase,
) -> anyhow::Result<()> {
    let before = owner_directory_snapshot(directory, intent, phase)?;
    let after = owner_directory_snapshot(directory, intent, phase)?;
    anyhow::ensure!(
        before == after,
        "blockd socket owner directory changed during closed validation: {before:?} != {after:?}"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerDirectorySnapshot {
    directory: DirectoryIdentity,
    names: BTreeSet<String>,
    marker_identity: Option<StableFileIdentity>,
    marker_bytes: Option<Vec<u8>>,
    control_socket: Option<SocketLeafIdentity>,
    io_socket: Option<SocketLeafIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SocketLeafIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    user: u32,
    group: u32,
}

/// Durable physical binding stored in the semantic Root stop journal. It is
/// minted only from a descriptor-retained current managed owner after the
/// accepted Node-global process sweep; no data-directory pathname can
/// manufacture this evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedBlockdRootStopOwnerEvidence {
    intent: BlockdSocketOwnershipIntentV1,
    public_directory: DirectoryIdentity,
    marker: StableFileIdentity,
    control_socket: SocketLeafIdentity,
}

impl ManagedBlockdRootStopOwnerEvidence {
    #[cfg(test)]
    pub(crate) fn for_test(
        expectation: &super::root_provision_process::RootProvisionProcessExpectation,
        node_boot_id: NodeBootId,
    ) -> anyhow::Result<Self> {
        let planner = ManagedBlockdSocketRoot::installed();
        let paths = planner.root_paths(&expectation.provision_transition_id)?;
        anyhow::ensure!(
            paths.control_socket() == &expectation.control_socket_path,
            "test stop owner expectation changed its installed socket mapping"
        );
        let intent = BlockdSocketOwnershipIntentV1 {
            version: BLOCKD_SOCKET_INTENT_VERSION,
            node_boot_id,
            owner_authority_digest: expectation.socket_owner_authority_digest.clone(),
            owner: BlockdSocketOwnerV1::Root {
                provision_transition_id: expectation.provision_transition_id.clone(),
            },
            managed_root_path: planner.path().clone(),
            managed_root_identity: DirectoryIdentity {
                device: 41,
                inode: 42,
                mode: stat_mode_bits(libc::S_IFDIR) | 0o700,
                user: 0,
                group: 0,
            },
            public_directory: paths.public_directory().clone(),
            staging_directory: paths.staging_directory().clone(),
            quarantine_directory: paths.quarantine_directory().clone(),
            owner_marker_path: paths.owner_marker().clone(),
            control_socket_path: paths.control_socket().clone(),
            io_socket_path: None,
        };
        Ok(Self {
            intent,
            public_directory: DirectoryIdentity {
                device: 41,
                inode: 43,
                mode: stat_mode_bits(libc::S_IFDIR) | 0o700,
                user: 0,
                group: 0,
            },
            marker: StableFileIdentity {
                device: 41,
                inode: 44,
                length: 512,
                modified_seconds: 1_900_000_000,
                modified_nanoseconds: 0,
                changed_seconds: 1_900_000_000,
                changed_nanoseconds: 0,
            },
            control_socket: SocketLeafIdentity {
                device: 41,
                inode: 45,
                mode: stat_mode_bits(libc::S_IFSOCK) | 0o700,
                links: 1,
                user: 0,
                group: 0,
            },
        })
    }

    pub(crate) fn intent(&self) -> &BlockdSocketOwnershipIntentV1 {
        &self.intent
    }

    pub(crate) fn control_socket_path(&self) -> &HostPath {
        self.intent.control_socket_path()
    }

    pub(crate) fn matches_expectation(
        &self,
        expectation: &super::root_provision_process::RootProvisionProcessExpectation,
    ) -> bool {
        matches!(self.intent.owner(), BlockdSocketOwnerV1::Root { provision_transition_id }
            if provision_transition_id == &expectation.provision_transition_id)
            && self.intent.owner_authority_digest() == &expectation.socket_owner_authority_digest
            && self.control_socket_path() == &expectation.control_socket_path
    }

    pub(crate) fn matches_process(
        &self,
        process: &super::root_provision_process::RootProvisionProcessEvidence,
    ) -> bool {
        matches!(self.intent.owner(), BlockdSocketOwnerV1::Root { .. })
            && self.control_socket_path() == &process.control_socket_path
    }
}

fn owner_directory_snapshot(
    directory: &File,
    intent: &BlockdSocketOwnershipIntentV1,
    phase: DirectoryPhase,
) -> anyhow::Result<OwnerDirectorySnapshot> {
    let directory_before = DirectoryIdentity::from_metadata(&directory.metadata()?);
    let names = strict_directory_names(directory)?;
    let mut allowed = BTreeSet::from([BLOCKD_SOCKET_OWNER_MARKER_BASENAME.to_owned()]);
    if matches!(phase, DirectoryPhase::Public | DirectoryPhase::Quarantine) {
        allowed.insert(BLOCKD_CONTROL_SOCKET_BASENAME.to_owned());
        if matches!(intent.owner, BlockdSocketOwnerV1::Serving { .. }) {
            allowed.insert(BLOCKD_IO_SOCKET_BASENAME.to_owned());
        }
    }
    anyhow::ensure!(
        names.is_subset(&allowed),
        "blockd socket owner directory contains a foreign entry"
    );
    let marker_name = fixed_c_string(BLOCKD_SOCKET_OWNER_MARKER_BASENAME);
    let marker = read_optional_bounded_file_with_identity(directory, &marker_name)?;
    anyhow::ensure!(
        marker.is_some() || matches!(phase, DirectoryPhase::Staging | DirectoryPhase::Quarantine),
        "blockd socket owner marker is missing"
    );
    if let Some((marker_bytes, _)) = marker.as_ref() {
        anyhow::ensure!(
            marker_bytes == &intent.encoded_bytes()?,
            "blockd socket owner marker differs from its durable intent"
        );
    }
    let control_socket = names
        .contains(BLOCKD_CONTROL_SOCKET_BASENAME)
        .then(|| {
            owned_socket_leaf_identity(
                directory,
                BLOCKD_CONTROL_SOCKET_BASENAME,
                directory_before.user,
                directory_before.group,
            )
        })
        .transpose()?;
    let io_socket = names
        .contains(BLOCKD_IO_SOCKET_BASENAME)
        .then(|| {
            owned_socket_leaf_identity(
                directory,
                BLOCKD_IO_SOCKET_BASENAME,
                directory_before.user,
                directory_before.group,
            )
        })
        .transpose()?;
    let directory_after = DirectoryIdentity::from_metadata(&directory.metadata()?);
    anyhow::ensure!(
        directory_after == directory_before,
        "blockd socket owner directory identity changed during snapshot"
    );
    Ok(OwnerDirectorySnapshot {
        directory: directory_after,
        names,
        marker_identity: marker.as_ref().map(|(_, identity)| *identity),
        marker_bytes: marker.map(|(bytes, _)| bytes),
        control_socket,
        io_socket,
    })
}

fn assert_recovery_aliases_absent(
    root: &RetainedManagedBlockdSocketRoot,
    paths: &DerivedSocketPaths,
) -> anyhow::Result<()> {
    for name in [&paths.staging_name, &paths.quarantine_name] {
        anyhow::ensure!(
            open_owned_directory(
                &root.descriptor,
                name,
                root.identity.user,
                root.identity.group,
            )?
            .is_none(),
            "blockd socket owner retains a recovery alias"
        );
    }
    Ok(())
}

fn assert_other_owner_names_absent(
    root: &RetainedManagedBlockdSocketRoot,
    paths: &DerivedSocketPaths,
    present: CapturedOwnerDirectoryPhase,
) -> anyhow::Result<()> {
    for (phase, name) in [
        (CapturedOwnerDirectoryPhase::Public, &paths.public_name),
        (CapturedOwnerDirectoryPhase::Staging, &paths.staging_name),
        (
            CapturedOwnerDirectoryPhase::Quarantine,
            &paths.quarantine_name,
        ),
    ] {
        if phase == present {
            continue;
        }
        anyhow::ensure!(
            open_owned_directory(
                &root.descriptor,
                name,
                root.identity.user,
                root.identity.group,
            )?
            .is_none(),
            "blockd socket owner retains multiple public/recovery aliases"
        );
    }
    Ok(())
}

fn assert_all_owner_names_absent(
    root: &RetainedManagedBlockdSocketRoot,
    paths: &DerivedSocketPaths,
) -> anyhow::Result<()> {
    for name in [
        &paths.public_name,
        &paths.staging_name,
        &paths.quarantine_name,
    ] {
        anyhow::ensure!(
            open_owned_directory(
                &root.descriptor,
                name,
                root.identity.user,
                root.identity.group,
            )?
            .is_none(),
            "blockd socket owner retains a boot-local namespace entry"
        );
    }
    root.assert_current()
}

fn open_owned_directory(
    root: &File,
    name: &str,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<Option<File>> {
    let name = CString::new(name)?;
    match open_directory_at(root, &name) {
        Ok(directory) => {
            ensure_owned_directory(&directory.metadata()?, expected_user, expected_group, 0o700)?;
            Ok(Some(directory))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(source).context("open managed blockd socket owner directory"),
    }
}

fn settle_matching_intent_staging(
    directory: &File,
    staging_name: &CStr,
    expected_bytes: &[u8],
) -> anyhow::Result<()> {
    let Some(staged) = read_optional_bounded_file(directory, staging_name)? else {
        return Ok(());
    };
    anyhow::ensure!(
        staged == expected_bytes && decode_intent(&staged)?.encoded_bytes()? == expected_bytes,
        "staged blockd socket ownership intent differs from the published receipt"
    );
    unlink_at(directory, staging_name).context("remove settled blockd socket intent staging")?;
    Ok(())
}

fn intent_file_name(owner: &BlockdSocketOwnerV1) -> anyhow::Result<CString> {
    CString::new(format!(
        "{}-{}.intent.v1.json",
        owner.role_prefix(),
        owner.token().as_str()
    ))
    .context("blockd socket intent filename contains NUL")
}

fn intent_staging_file_name(owner: &BlockdSocketOwnerV1) -> anyhow::Result<CString> {
    CString::new(format!(
        ".{}-{}.intent.v1.json.staging",
        owner.role_prefix(),
        owner.token().as_str()
    ))
    .context("blockd socket intent staging filename contains NUL")
}

fn intent_quarantine_file_name(owner: &BlockdSocketOwnerV1) -> anyhow::Result<CString> {
    CString::new(format!(
        ".q-{}-{}.intent.v1.json",
        owner.role_prefix(),
        owner.token().as_str()
    ))
    .context("blockd socket intent quarantine filename contains NUL")
}

fn capture_intent_receipt_unlocked(
    store: &BlockdSocketIntentStore,
    owner: &BlockdSocketOwnerV1,
) -> anyhow::Result<Option<CapturedBlockdSocketIntent>> {
    store.assert_current()?;
    let candidates = [
        (
            CapturedBlockdSocketIntentPhase::Public,
            intent_file_name(owner)?,
        ),
        (
            CapturedBlockdSocketIntentPhase::Staging,
            intent_staging_file_name(owner)?,
        ),
        (
            CapturedBlockdSocketIntentPhase::Quarantine,
            intent_quarantine_file_name(owner)?,
        ),
    ]
    .into_iter()
    .map(|(phase, name)| {
        read_optional_bounded_file_with_identity(&store.directory, &name)
            .map(|value| value.map(|(bytes, identity)| (phase, bytes, identity)))
    })
    .collect::<anyhow::Result<Vec<_>>>()?
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let captured = match candidates.as_slice() {
        [] => None,
        [(phase, bytes, identity)] => Some(CapturedBlockdSocketIntent {
            phase: *phase,
            intent: decode_intent(bytes)?,
            bytes: bytes.clone(),
            identity: *identity,
        }),
        _ => anyhow::bail!("blockd socket intent retains multiple public/recovery aliases"),
    };
    store.assert_current()?;
    Ok(captured)
}

fn capture_intent_receipt_unlocked_with_lock(
    store: &BlockdSocketIntentStore,
    owner: &BlockdSocketOwnerV1,
) -> anyhow::Result<Option<CapturedBlockdSocketIntent>> {
    let _namespace_lock = store.lock_exclusive()?;
    capture_intent_receipt_unlocked(store, owner)
}

fn encode_intent(intent: &BlockdSocketOwnershipIntentV1) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        intent.version == BLOCKD_SOCKET_INTENT_VERSION,
        "unsupported blockd socket ownership intent version"
    );
    let bytes = serde_json::to_vec(intent).context("encode blockd socket ownership intent")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= BLOCKD_SOCKET_INTENT_MAX_BYTES,
        "blockd socket ownership intent exceeds its wire bound"
    );
    Ok(bytes)
}

fn decode_intent(bytes: &[u8]) -> anyhow::Result<BlockdSocketOwnershipIntentV1> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= BLOCKD_SOCKET_INTENT_MAX_BYTES,
        "blockd socket ownership intent exceeds its wire bound"
    );
    let intent: BlockdSocketOwnershipIntentV1 =
        serde_json::from_slice(bytes).context("decode blockd socket ownership intent")?;
    anyhow::ensure!(
        intent.version == BLOCKD_SOCKET_INTENT_VERSION,
        "unsupported blockd socket ownership intent version"
    );
    anyhow::ensure!(
        encode_intent(&intent)? == bytes,
        "blockd socket ownership intent is not canonically encoded"
    );
    Ok(intent)
}

fn read_optional_bounded_file(directory: &File, name: &CStr) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(read_optional_bounded_file_with_identity(directory, name)?.map(|(bytes, _)| bytes))
}

fn read_optional_bounded_file_with_identity(
    directory: &File,
    name: &CStr,
) -> anyhow::Result<Option<(Vec<u8>, StableFileIdentity)>> {
    let mut file = match open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context("open blockd socket ownership file"),
    };
    let before = file.metadata()?;
    ensure_owned_regular_file(
        &before,
        directory.metadata()?.uid(),
        directory.metadata()?.gid(),
        0o600,
    )?;
    anyhow::ensure!(
        before.len() <= BLOCKD_SOCKET_INTENT_MAX_BYTES as u64,
        "blockd socket ownership file exceeds its wire bound"
    );
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(BLOCKD_SOCKET_INTENT_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= BLOCKD_SOCKET_INTENT_MAX_BYTES,
        "blockd socket ownership file grew beyond its wire bound"
    );
    let after = file.metadata()?;
    anyhow::ensure!(
        stable_file_identity(&before) == stable_file_identity(&after),
        "blockd socket ownership file changed while read"
    );
    Ok(Some((bytes, stable_file_identity(&after))))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StableFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn same_file_after_rename(before: StableFileIdentity, after: StableFileIdentity) -> bool {
    before.device == after.device
        && before.inode == after.inode
        && before.length == after.length
        && before.modified_seconds == after.modified_seconds
        && before.modified_nanoseconds == after.modified_nanoseconds
}

fn stable_file_identity(metadata: &std::fs::Metadata) -> StableFileIdentity {
    StableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn strict_directory_names(directory: &File) -> anyhow::Result<BTreeSet<String>> {
    strict_directory_names_bounded(directory, 3)
}

fn strict_directory_names_bounded(
    directory: &File,
    maximum_entries: usize,
) -> anyhow::Result<BTreeSet<String>> {
    let mut stream =
        DirectoryStream::open(directory).context("open blockd socket directory enumeration")?;
    let mut names = BTreeSet::new();
    while let Some(name) = stream
        .next()
        .context("read blockd socket directory enumeration")?
    {
        let name = String::from_utf8(name)
            .map_err(|_| anyhow::anyhow!("blockd socket directory entry is not UTF-8"))?;
        anyhow::ensure!(
            names.insert(name),
            "blockd socket directory contains a duplicate entry"
        );
        anyhow::ensure!(
            names.len() <= maximum_entries,
            "blockd socket directory exceeds its closed entry bound"
        );
    }
    Ok(names)
}

/// Closed descriptor-relative iterator. `readdir(NULL)` is EOF only when
/// errno remains zero; an injected or kernel I/O error can therefore never be
/// misclassified as an empty/complete owner directory.
struct DirectoryStream(*mut libc::DIR);

impl DirectoryStream {
    fn open(directory: &File) -> io::Result<Self> {
        // A dup shares the directory stream offset with the retained
        // descriptor, so a second closed snapshot would spuriously start at
        // EOF. Open `.` descriptor-relative to obtain an independent open
        // file description for every enumeration.
        let duplicate = open_directory_at(directory, &fixed_c_string("."))?.into_raw_fd();
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
            // SAFETY: this value exclusively owns the live DIR pointer.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = errno();
                return if error == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::from_raw_os_error(error))
                };
            }
            // SAFETY: readdir returned one live dirent; copy before the next
            // readdir call invalidates its storage.
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

fn ensure_owned_socket_leaf(
    directory: &File,
    basename: &str,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<()> {
    owned_socket_leaf_identity(directory, basename, expected_user, expected_group).map(drop)
}

fn owned_socket_leaf_identity(
    directory: &File,
    basename: &str,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<SocketLeafIdentity> {
    let name = CString::new(basename)?;
    // SAFETY: zeroed stat is valid output storage for fstatat.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: directory/name and metadata stay live; AT_SYMLINK_NOFOLLOW
    // ensures a same-name symlink can never be accepted as the socket leaf.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &raw mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("inspect blockd socket leaf");
    }
    anyhow::ensure!(
        metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && metadata.st_nlink == 1
            && metadata.st_uid == expected_user
            && metadata.st_gid == expected_group,
        "blockd socket leaf has unsafe type, links or owner"
    );
    Ok(SocketLeafIdentity {
        device: stat_device_number(metadata.st_dev)?,
        inode: metadata.st_ino,
        mode: stat_mode_bits(metadata.st_mode),
        links: stat_link_count(metadata.st_nlink),
        user: metadata.st_uid,
        group: metadata.st_gid,
    })
}

#[cfg(target_os = "linux")]
fn stat_device_number(device: libc::dev_t) -> anyhow::Result<u64> {
    Ok(device)
}

#[cfg(not(target_os = "linux"))]
fn stat_device_number(device: libc::dev_t) -> anyhow::Result<u64> {
    u64::try_from(device).context("socket device number is negative")
}

// libc exposes `nlink_t` at different unsigned widths on supported targets.
// The generic bound keeps the conversion lossless without making an identity
// conversion visible to Clippy on targets where the alias is already `u64`.
fn stat_link_count<T>(links: T) -> u64
where
    u64: From<T>,
{
    u64::from(links)
}

#[cfg(target_os = "linux")]
fn stat_mode_bits(mode: libc::mode_t) -> u32 {
    mode
}

#[cfg(not(target_os = "linux"))]
fn stat_mode_bits(mode: libc::mode_t) -> u32 {
    u32::from(mode)
}

fn remove_captured_socket_leaf(
    directory: &File,
    basename: &str,
    captured: Option<SocketLeafIdentity>,
) -> anyhow::Result<()> {
    let name = CString::new(basename)?;
    match captured {
        Some(expected) => {
            let metadata = directory.metadata()?;
            anyhow::ensure!(
                owned_socket_leaf_identity(directory, basename, metadata.uid(), metadata.gid(),)?
                    == expected,
                "captured blockd socket leaf changed before quarantine cleanup"
            );
            unlink_at(directory, &name).context("remove exact quarantined blockd socket leaf")?;
            directory
                .sync_all()
                .context("fsync quarantined blockd socket leaf removal")?;
        }
        None => anyhow::ensure!(
            !strict_directory_names(directory)?.contains(basename),
            "uncaptured blockd socket leaf appeared in quarantine"
        ),
    }
    Ok(())
}

fn remove_directory_at(parent: &File, name: &CStr) -> io::Result<()> {
    loop {
        // SAFETY: parent/name are live and AT_REMOVEDIR prevents removal of a
        // non-directory leaf or traversal through a symlink.
        let result =
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn open_directory_chain(path: &Path) -> anyhow::Result<Vec<RetainedPathDirectory>> {
    ensure_canonical_root(path)?;
    let root_name = fixed_c_string("/");
    let root = loop {
        // SAFETY: the fixed root name remains live. A successful descriptor is
        // transferred exactly once to File.
        let descriptor = unsafe {
            libc::open(
                root_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor >= 0 {
            // SAFETY: open returned one fresh owned descriptor.
            break unsafe { File::from_raw_fd(descriptor) };
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source).context("open filesystem root");
        }
    };
    let root_metadata = root.metadata()?;
    anyhow::ensure!(
        root_metadata.file_type().is_dir() && root_metadata.nlink() > 0,
        "filesystem root is not one live directory"
    );
    let mut directories = vec![RetainedPathDirectory {
        name: OsString::from("/"),
        descriptor: root,
        identity: DirectoryIdentity::from_metadata(&root_metadata),
    }];
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name_c =
            CString::new(name.as_bytes()).context("managed root component contains NUL")?;
        let descriptor = open_directory_at(
            &directories
                .last()
                .expect("filesystem root starts the directory chain")
                .descriptor,
            &name_c,
        )?;
        let metadata = descriptor.metadata()?;
        anyhow::ensure!(
            metadata.file_type().is_dir() && metadata.nlink() > 0,
            "managed blockd socket ancestor is not one live directory"
        );
        directories.push(RetainedPathDirectory {
            name: name.to_owned(),
            descriptor,
            identity: DirectoryIdentity::from_metadata(&metadata),
        });
    }
    Ok(directories)
}

fn open_directory_at(parent: &File, name: &CStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

fn open_at(parent: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: parent/name remain live. A successful descriptor is
        // transferred exactly once to File.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: openat returned one fresh owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn mkdir_at(parent: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    loop {
        // SAFETY: parent/name remain live and mkdirat retains neither.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn unlink_at(parent: &File, name: &CStr) -> io::Result<()> {
    loop {
        // SAFETY: parent/name remain live and unlinkat retains neither.
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn flock_exclusive(file: &File) -> io::Result<()> {
    loop {
        // SAFETY: flock retains no pointer; the descriptor remains live for
        // the returned guard's lifetime.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

#[cfg(target_os = "linux")]
fn open_anonymous_intent(directory: &File) -> io::Result<File> {
    open_at(
        directory,
        &fixed_c_string("."),
        libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
        0o600,
    )
}

#[cfg(target_os = "linux")]
fn link_anonymous_no_replace(file: &File, directory: &File, name: &CStr) -> io::Result<()> {
    let empty = fixed_c_string("");
    loop {
        // SAFETY: descriptors and C strings remain live; AT_EMPTY_PATH links
        // the already-fsynced anonymous inode without a source pathname.
        let result = unsafe {
            libc::linkat(
                file.as_raw_fd(),
                empty.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::AT_EMPTY_PATH,
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

#[cfg(target_os = "linux")]
fn rename_no_replace(
    old_parent: &File,
    old_name: &CStr,
    new_parent: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both descriptors and names remain live; renameat2 retains no
        // pointers and RENAME_NOREPLACE forbids overwrite.
        let result = unsafe {
            libc::renameat2(
                old_parent.as_raw_fd(),
                old_name.as_ptr(),
                new_parent.as_raw_fd(),
                new_name.as_ptr(),
                libc::RENAME_NOREPLACE,
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

#[cfg(target_os = "macos")]
fn rename_no_replace(
    old_parent: &File,
    old_name: &CStr,
    new_parent: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both descriptors and names remain live; renameatx_np retains
        // no pointers and RENAME_EXCL forbids overwrite.
        let result = unsafe {
            libc::renameatx_np(
                old_parent.as_raw_fd(),
                old_name.as_ptr(),
                new_parent.as_raw_fd(),
                new_name.as_ptr(),
                libc::RENAME_EXCL,
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_no_replace(
    _old_parent: &File,
    _old_name: &CStr,
    _new_parent: &File,
    _new_name: &CStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace blockd namespace publication is unsupported",
    ))
}

fn ensure_owned_directory(
    metadata: &std::fs::Metadata,
    expected_user: u32,
    expected_group: u32,
    expected_mode: u32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == expected_user
            && metadata.gid() == expected_group
            && metadata.nlink() > 0
            && metadata.mode() & 0o7777 == expected_mode,
        "managed blockd directory has unsafe type, owner, links or mode"
    );
    Ok(())
}

fn ensure_owned_regular_file(
    metadata: &std::fs::Metadata,
    expected_user: u32,
    expected_group: u32,
    expected_mode: u32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == expected_user
            && metadata.gid() == expected_group
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == expected_mode,
        "blockd socket ownership file has unsafe type, owner, links or mode"
    );
    Ok(())
}

fn ensure_canonical_root(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "managed blockd socket root is not absolute"
    );
    let mut normal = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => normal += 1,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("managed blockd socket root is not canonical")
            }
        }
    }
    anyhow::ensure!(
        normal > 0,
        "managed blockd socket root names filesystem root"
    );
    anyhow::ensure!(
        !path.as_os_str().as_bytes().contains(&0),
        "managed blockd socket root contains NUL"
    );
    Ok(())
}

fn fixed_c_string(value: &str) -> CString {
    CString::new(value).expect("fixed blockd socket namespace name contains no NUL")
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::runtime_spine::RuntimeDesiredEffectContext;

    struct Fixture {
        _temporary: tempfile::TempDir,
        socket_path: std::path::PathBuf,
        root: Arc<RetainedManagedBlockdSocketRoot>,
        intents: Arc<BlockdSocketIntentStore>,
        boot_id: NodeBootId,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::Builder::new()
                .prefix("bns")
                .tempdir_in("/private/tmp")
                .or_else(|_| tempfile::Builder::new().prefix("bns").tempdir_in("/tmp"))
                .unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let socket_path = temporary.path().join("s");
            let root = RetainedManagedBlockdSocketRoot::provision_for_test(&socket_path).unwrap();
            let state_path = temporary.path().join("state");
            std::fs::create_dir(&state_path).unwrap();
            std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let intents =
                BlockdSocketIntentStore::provision_for_test(StateDirectory::unanchored(state_path))
                    .unwrap();
            Self {
                _temporary: temporary,
                socket_path,
                root: Arc::new(root),
                intents: Arc::new(intents),
                boot_id: node_boot_id('a'),
            }
        }

        fn current_boot(&self) -> CurrentBlockdSocketBoot {
            CurrentBlockdSocketBoot::for_test(self.boot_id.clone())
        }

        fn root_intent(&self, owner: char) -> BlockdSocketOwnershipIntentV1 {
            BlockdSocketOwnershipIntentV1::root(
                &self.root,
                &CurrentBlockdSocketBoot::for_test(self.boot_id.clone()),
                random_id(owner),
                digest('b'),
            )
            .unwrap()
        }

        fn serving_intent(&self, owner: char) -> BlockdSocketOwnershipIntentV1 {
            BlockdSocketOwnershipIntentV1::serving(
                &self.root,
                &CurrentBlockdSocketBoot::for_test(self.boot_id.clone()),
                random_id(owner),
                digest('c'),
            )
            .unwrap()
        }

        fn indexed_root_intent(&self, owner: usize) -> BlockdSocketOwnershipIntentV1 {
            BlockdSocketOwnershipIntentV1::root(
                &self.root,
                &self.current_boot(),
                RandomId128::new(format!("{owner:032x}")).unwrap(),
                digest('b'),
            )
            .unwrap()
        }

        /// Install canonical current bytes without one fsync per owner. The
        /// capacity regression exercises closed enumeration, decoding and
        /// owner snapshots rather than publication crash durability, which is
        /// covered by the ordinary prepare/replay tests above.
        fn install_current_owner_for_capacity_test(&self, intent: &BlockdSocketOwnershipIntentV1) {
            let mut receipt = open_at(
                &self.intents.directory,
                &intent_file_name(intent.owner()).unwrap(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
            .unwrap();
            let bytes = intent.encoded_bytes().unwrap();
            receipt.write_all(&bytes).unwrap();

            let public = Path::new(intent.public_directory.as_str());
            std::fs::create_dir(public).unwrap();
            std::fs::set_permissions(public, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = Path::new(intent.owner_marker_path.as_str());
            std::fs::write(marker, bytes).unwrap();
            std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn create_owner_staging_without_marker(&self, intent: &BlockdSocketOwnershipIntentV1) {
            let path = Path::new(intent.staging_directory.as_str());
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn install_intent_receipt(
            &self,
            intent: &BlockdSocketOwnershipIntentV1,
            phase: CapturedBlockdSocketIntentPhase,
        ) {
            let name = match phase {
                CapturedBlockdSocketIntentPhase::Public => intent_file_name(intent.owner()),
                CapturedBlockdSocketIntentPhase::Staging => {
                    intent_staging_file_name(intent.owner())
                }
                CapturedBlockdSocketIntentPhase::Quarantine => {
                    intent_quarantine_file_name(intent.owner())
                }
            }
            .unwrap();
            let mut receipt = open_at(
                &self.intents.directory,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
            .unwrap();
            receipt.write_all(&intent.encoded_bytes().unwrap()).unwrap();
            receipt.sync_all().unwrap();
            self.intents.directory.sync_all().unwrap();
        }

        fn exact_start_absence(
            &self,
            intent: &BlockdSocketOwnershipIntentV1,
        ) -> ExactManagedBlockdSocketOwnerStartAbsence {
            let context = RuntimeDesiredEffectContext::for_test(
                self.intents.state_directory().clone(),
                Instant::now() + Duration::from_secs(5),
            );
            let node_global_effect = context.lock_node_global_effect().unwrap();
            let current_boot = self.current_boot();
            let capture = self
                .root
                .capture_start_absence(&self.intents, intent, &current_boot)
                .unwrap();
            let expected = [intent.clone()];
            let before = self
                .root
                .capture_closed_whole_root(&self.intents, &expected)
                .unwrap();
            let after = self
                .root
                .capture_closed_whole_root(&self.intents, &expected)
                .unwrap();
            ExactManagedBlockdSocketOwnerStartAbsence::seal_after_node_global_sweep(
                capture,
                before,
                after,
                &current_boot,
                node_global_effect,
            )
            .unwrap()
        }

        fn assert_owner_and_intent_absent(&self, intent: &BlockdSocketOwnershipIntentV1) {
            assert_all_owner_names_absent(&self.root, &intent.derived_paths(&self.root).unwrap())
                .unwrap();
            assert!(
                capture_intent_receipt_unlocked_with_lock(&self.intents, intent.owner())
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn first_prepare_publishes_exact_marker_after_durable_intent() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('1');
        assert_eq!(
            fixture
                .intents
                .publish(
                    &intent,
                    &fixture.root,
                    &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
                )
                .unwrap(),
            BlockdSocketIntentPublication::Published
        );
        let prepared = fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        prepared
            .assert_current(&CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()))
            .unwrap();
        assert!(Path::new(prepared.public_directory().as_str()).is_dir());
        assert!(!Path::new(prepared.control_socket_path().as_str()).exists());
        assert_eq!(prepared.io_socket_path(), None);
        assert_eq!(
            std::fs::read(Path::new(intent.owner_marker_path.as_str())).unwrap(),
            intent.encoded_bytes().unwrap()
        );
    }

    #[test]
    fn exact_receipt_and_public_directory_replay_are_idempotent() {
        let fixture = Fixture::new();
        let intent = fixture.serving_intent('2');
        fixture
            .intents
            .publish(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        let first = fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        let identity = first.public_identity_coordinate();
        drop(first);
        assert_eq!(
            fixture
                .intents
                .publish(
                    &intent,
                    &fixture.root,
                    &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
                )
                .unwrap(),
            BlockdSocketIntentPublication::ExactReplay
        );
        let replay = fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        assert_eq!(replay.public_identity_coordinate(), identity);
        assert!(replay.io_socket_path().is_some());
    }

    #[test]
    fn receipt_must_precede_every_namespace_mutation_and_closes_crash_window() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('3');
        assert!(fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());
        assert!(std::fs::read_dir(&fixture.socket_path)
            .unwrap()
            .next()
            .is_none());

        fixture
            .intents
            .publish(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        // Simulate a crash immediately after the durable receipt and before
        // the first namespace mutation.
        assert!(std::fs::read_dir(&fixture.socket_path)
            .unwrap()
            .next()
            .is_none());
        fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        assert!(Path::new(intent.public_directory.as_str()).is_dir());
    }

    #[test]
    fn public_directory_without_marker_fails_closed() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('4');
        fixture
            .intents
            .publish(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        std::fs::create_dir(Path::new(intent.public_directory.as_str())).unwrap();
        std::fs::set_permissions(
            Path::new(intent.public_directory.as_str()),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());
        assert!(Path::new(intent.public_directory.as_str()).is_dir());
    }

    #[test]
    fn foreign_marker_and_directory_entry_fail_closed() {
        let fixture = Fixture::new();
        let intent = fixture.serving_intent('5');
        fixture
            .intents
            .publish(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        let prepared = fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        drop(prepared);
        std::fs::write(Path::new(intent.owner_marker_path.as_str()), b"{}").unwrap();
        assert!(fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());

        std::fs::write(
            Path::new(intent.owner_marker_path.as_str()),
            intent.encoded_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(
            Path::new(intent.public_directory.as_str()).join("foreign"),
            b"x",
        )
        .unwrap();
        assert!(fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());
    }

    #[test]
    fn symlink_owner_name_is_never_followed() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('6');
        fixture
            .intents
            .publish(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        let foreign = fixture.socket_path.join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        symlink(&foreign, Path::new(intent.public_directory.as_str())).unwrap();
        assert!(fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());
        assert!(foreign.is_dir());
    }

    #[test]
    fn stable_root_and_rotating_serving_owners_never_alias() {
        let fixture = Fixture::new();
        let root = fixture.root_intent('7');
        let serving_a = fixture.serving_intent('7');
        let serving_b = fixture.serving_intent('8');
        assert_ne!(root.public_directory, serving_a.public_directory);
        assert_ne!(root.control_socket_path, serving_a.control_socket_path);
        assert_ne!(serving_a.public_directory, serving_b.public_directory);
        assert_ne!(serving_a.io_socket_path, serving_b.io_socket_path);

        fixture
            .intents
            .publish(
                &root,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        let mut conflicting = root.clone();
        conflicting.owner_authority_digest = digest('d');
        assert!(fixture
            .intents
            .publish(
                &conflicting,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());
    }

    #[test]
    fn stable_owner_authority_reopens_across_process_and_checkpoint_successors() {
        let fixture = Fixture::new();
        let root = fixture.root_intent('a');
        fixture
            .intents
            .publish(
                &root,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        // A Root process-token-only checkpoint replacement retains the same
        // transition authority digest and must not rewrite the marker.
        assert_eq!(
            fixture
                .intents
                .publish(
                    &root,
                    &fixture.root,
                    &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
                )
                .unwrap(),
            BlockdSocketIntentPublication::ExactReplay
        );

        let serving = fixture.serving_intent('b');
        fixture
            .intents
            .publish(
                &serving,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        // PrepareNetwork and later checkpoints carry the same exact
        // PreparedDeviceInput authority.
        assert_eq!(
            fixture
                .intents
                .publish(
                    &serving,
                    &fixture.root,
                    &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
                )
                .unwrap(),
            BlockdSocketIntentPublication::ExactReplay
        );

        let mut changed_generation = serving.clone();
        changed_generation.owner_authority_digest = digest('e');
        assert!(fixture
            .intents
            .publish(
                &changed_generation,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());
    }

    #[test]
    fn stale_boot_root_and_serving_intents_can_reissue_after_empty_run_root() {
        stale_boot_reissue(false);
        stale_boot_reissue(true);
    }

    fn stale_boot_reissue(serving: bool) {
        let fixture = Fixture::new();
        let stale = if serving {
            fixture.serving_intent('c')
        } else {
            fixture.root_intent('c')
        };
        fixture
            .intents
            .publish(
                &stale,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        let new_boot = node_boot_id('f');
        let current = match stale.owner() {
            BlockdSocketOwnerV1::Root {
                provision_transition_id,
            } => BlockdSocketOwnershipIntentV1::root(
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(new_boot.clone()),
                provision_transition_id.clone(),
                stale.owner_authority_digest().clone(),
            )
            .unwrap(),
            BlockdSocketOwnerV1::Serving {
                device_ownership_token,
            } => BlockdSocketOwnershipIntentV1::serving(
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(new_boot.clone()),
                device_ownership_token.clone(),
                stale.owner_authority_digest().clone(),
            )
            .unwrap(),
        };
        assert!(fixture
            .intents
            .publish(
                &current,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(new_boot.clone())
            )
            .is_err());
        assert_eq!(
            fixture
                .intents
                .retire_stale_boot_intent(
                    &stale,
                    &fixture.root,
                    &CurrentBlockdSocketBoot::for_test(new_boot.clone())
                )
                .unwrap(),
            BlockdSocketStaleIntentRetirement::Retired
        );
        fixture
            .intents
            .publish(
                &current,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(new_boot.clone()),
            )
            .unwrap();
        fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &current,
                &CurrentBlockdSocketBoot::for_test(new_boot.clone()),
            )
            .unwrap();
    }

    #[test]
    fn stale_boot_retirement_rejects_current_boot_and_nonempty_run_root() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('d');
        fixture
            .intents
            .publish(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        assert!(fixture
            .intents
            .retire_stale_boot_intent(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone())
            )
            .is_err());

        std::fs::create_dir(Path::new(intent.public_directory.as_str())).unwrap();
        std::fs::set_permissions(
            Path::new(intent.public_directory.as_str()),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(fixture
            .intents
            .retire_stale_boot_intent(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(node_boot_id('f'))
            )
            .is_err());
    }

    #[test]
    fn empty_receipt_owned_staging_recovers_but_public_marker_never_does() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('9');
        fixture
            .intents
            .publish(
                &intent,
                &fixture.root,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        std::fs::create_dir(Path::new(intent.staging_directory.as_str())).unwrap();
        std::fs::set_permissions(
            Path::new(intent.staging_directory.as_str()),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fixture
            .root
            .prepare_existing_intent(
                &fixture.intents,
                &intent,
                &CurrentBlockdSocketBoot::for_test(fixture.boot_id.clone()),
            )
            .unwrap();
        assert!(Path::new(intent.owner_marker_path.as_str()).is_file());
    }

    #[test]
    fn markerless_owner_staging_can_be_started_or_retired_after_exact_absence() {
        for (owner, start) in [('1', true), ('2', false)] {
            let fixture = Fixture::new();
            let intent = fixture.root_intent(owner);
            fixture
                .intents
                .publish(&intent, &fixture.root, &fixture.current_boot())
                .unwrap();
            fixture.create_owner_staging_without_marker(&intent);

            let absence = fixture.exact_start_absence(&intent);
            if start {
                let prepared = fixture
                    .root
                    .prepare_absent_owner_for_start(
                        &fixture.intents,
                        &intent,
                        &fixture.current_boot(),
                        absence,
                    )
                    .unwrap();
                assert!(Path::new(intent.public_directory.as_str()).is_dir());
                assert!(!Path::new(intent.staging_directory.as_str()).exists());
                assert_eq!(
                    std::fs::read(Path::new(intent.owner_marker_path.as_str())).unwrap(),
                    intent.encoded_bytes().unwrap()
                );
                prepared.assert_current(&fixture.current_boot()).unwrap();
            } else {
                assert_eq!(
                    fixture
                        .root
                        .retire_absent_owner(
                            &fixture.intents,
                            &intent,
                            &fixture.current_boot(),
                            absence,
                        )
                        .unwrap(),
                    ManagedBlockdSocketOwnerRetirement::Retired
                );
                fixture.assert_owner_and_intent_absent(&intent);
            }
        }
    }

    #[test]
    fn current_intent_without_an_owner_directory_is_read_only_absent_and_retirable() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('e');
        fixture
            .intents
            .publish(&intent, &fixture.root, &fixture.current_boot())
            .unwrap();

        assert!(matches!(
            fixture
                .root
                .retain_existing_intent(&fixture.intents, &intent, &fixture.current_boot())
                .unwrap(),
            ManagedBlockdSocketOwnerInspection::RecoverableAbsent
        ));

        let absence = fixture.exact_start_absence(&intent);
        assert_eq!(
            fixture
                .root
                .retire_absent_owner(&fixture.intents, &intent, &fixture.current_boot(), absence,)
                .unwrap(),
            ManagedBlockdSocketOwnerRetirement::Retired
        );
        fixture.assert_owner_and_intent_absent(&intent);
    }

    #[test]
    fn root_and_serving_recovery_directories_are_read_only_absent() {
        for (serving, quarantine, owner) in [
            (false, false, '1'),
            (true, false, '2'),
            (false, true, '3'),
            (true, true, '4'),
        ] {
            let fixture = Fixture::new();
            let intent = if serving {
                fixture.serving_intent(owner)
            } else {
                fixture.root_intent(owner)
            };
            if quarantine {
                let prepared = fixture
                    .root
                    .prepare_for_start(&fixture.intents, &intent, &fixture.current_boot())
                    .unwrap();
                let control =
                    UnixListener::bind(Path::new(intent.control_socket_path.as_str())).unwrap();
                let io = intent
                    .io_socket_path
                    .as_ref()
                    .map(|path| UnixListener::bind(Path::new(path.as_str())).unwrap());
                drop((control, io, prepared));
                std::fs::rename(
                    Path::new(intent.public_directory.as_str()),
                    Path::new(intent.quarantine_directory.as_str()),
                )
                .unwrap();
            } else {
                fixture
                    .intents
                    .publish(&intent, &fixture.root, &fixture.current_boot())
                    .unwrap();
                fixture.create_owner_staging_without_marker(&intent);
            }

            assert!(matches!(
                fixture
                    .root
                    .retain_existing_intent(&fixture.intents, &intent, &fixture.current_boot())
                    .unwrap(),
                ManagedBlockdSocketOwnerInspection::RecoverableAbsent
            ));
            let absence = fixture.exact_start_absence(&intent);
            assert_eq!(
                fixture
                    .root
                    .retire_absent_owner(
                        &fixture.intents,
                        &intent,
                        &fixture.current_boot(),
                        absence,
                    )
                    .unwrap(),
                ManagedBlockdSocketOwnerRetirement::Retired
            );
            fixture.assert_owner_and_intent_absent(&intent);
        }
    }

    #[test]
    fn public_and_owner_quarantine_cleanup_resume_remove_exact_serving_leaves() {
        for quarantine_before_capture in [false, true] {
            let fixture = Fixture::new();
            let intent = fixture.serving_intent(if quarantine_before_capture { '4' } else { '3' });
            let prepared = fixture
                .root
                .prepare_for_start(&fixture.intents, &intent, &fixture.current_boot())
                .unwrap();
            let control =
                UnixListener::bind(Path::new(intent.control_socket_path.as_str())).unwrap();
            let io =
                UnixListener::bind(Path::new(intent.io_socket_path.as_ref().unwrap().as_str()))
                    .unwrap();
            drop((control, io, prepared));
            if quarantine_before_capture {
                std::fs::rename(
                    Path::new(intent.public_directory.as_str()),
                    Path::new(intent.quarantine_directory.as_str()),
                )
                .unwrap();
            }

            let absence = fixture.exact_start_absence(&intent);
            assert_eq!(
                fixture
                    .root
                    .retire_absent_owner(
                        &fixture.intents,
                        &intent,
                        &fixture.current_boot(),
                        absence,
                    )
                    .unwrap(),
                ManagedBlockdSocketOwnerRetirement::Retired
            );
            fixture.assert_owner_and_intent_absent(&intent);
        }
    }

    #[test]
    fn sealed_absence_rejects_public_owner_pathname_aba_and_preserves_both_inodes() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('a');
        let prepared = fixture
            .root
            .prepare_for_start(&fixture.intents, &intent, &fixture.current_boot())
            .unwrap();
        let listener = UnixListener::bind(Path::new(intent.control_socket_path.as_str())).unwrap();
        drop((listener, prepared));
        let absence = fixture.exact_start_absence(&intent);

        let moved = fixture.socket_path.join("moved-old-owner");
        std::fs::rename(Path::new(intent.public_directory.as_str()), &moved).unwrap();
        std::fs::create_dir(Path::new(intent.public_directory.as_str())).unwrap();
        std::fs::set_permissions(
            Path::new(intent.public_directory.as_str()),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(
            Path::new(intent.owner_marker_path.as_str()),
            intent.encoded_bytes().unwrap(),
        )
        .unwrap();

        assert!(fixture
            .root
            .retire_absent_owner(&fixture.intents, &intent, &fixture.current_boot(), absence)
            .is_err());
        assert!(Path::new(intent.public_directory.as_str()).is_dir());
        assert!(moved.join(BLOCKD_CONTROL_SOCKET_BASENAME).exists());
        assert_eq!(fixture.intents.load(intent.owner()).unwrap(), Some(intent));
    }

    #[test]
    fn owner_quarantine_plus_late_public_replacement_is_conflict_and_zero_mutation() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('b');
        let prepared = fixture
            .root
            .prepare_for_start(&fixture.intents, &intent, &fixture.current_boot())
            .unwrap();
        let listener = UnixListener::bind(Path::new(intent.control_socket_path.as_str())).unwrap();
        drop((listener, prepared));
        std::fs::rename(
            Path::new(intent.public_directory.as_str()),
            Path::new(intent.quarantine_directory.as_str()),
        )
        .unwrap();
        std::fs::create_dir(Path::new(intent.public_directory.as_str())).unwrap();
        std::fs::set_permissions(
            Path::new(intent.public_directory.as_str()),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        assert!(fixture
            .root
            .retain_existing_intent(&fixture.intents, &intent, &fixture.current_boot())
            .is_err());
        assert!(fixture
            .root
            .capture_start_absence(&fixture.intents, &intent, &fixture.current_boot())
            .is_err());
        assert!(Path::new(intent.public_directory.as_str()).is_dir());
        assert!(Path::new(intent.quarantine_directory.as_str())
            .join(BLOCKD_CONTROL_SOCKET_BASENAME)
            .exists());
        assert_eq!(fixture.intents.load(intent.owner()).unwrap(), Some(intent));
    }

    #[test]
    fn partial_owner_quarantine_crash_states_replay_to_exact_absence() {
        for (serving, keep_control, keep_io, keep_marker, owner) in [
            (false, true, false, true, '1'),
            (false, false, false, true, '2'),
            (false, false, false, false, '3'),
            (true, true, true, true, '4'),
            (true, false, true, true, '5'),
            (true, false, false, true, '6'),
            (true, false, false, false, '7'),
        ] {
            let fixture = Fixture::new();
            let intent = if serving {
                fixture.serving_intent(owner)
            } else {
                fixture.root_intent(owner)
            };
            let prepared = fixture
                .root
                .prepare_for_start(&fixture.intents, &intent, &fixture.current_boot())
                .unwrap();
            let control =
                UnixListener::bind(Path::new(intent.control_socket_path.as_str())).unwrap();
            let io = intent
                .io_socket_path
                .as_ref()
                .map(|path| UnixListener::bind(Path::new(path.as_str())).unwrap());
            let stop_owner = (!serving).then(|| {
                prepared
                    .retain_root_stop_owner_evidence(&fixture.current_boot())
                    .unwrap()
            });
            drop((control, io, prepared));
            std::fs::rename(
                Path::new(intent.public_directory.as_str()),
                Path::new(intent.quarantine_directory.as_str()),
            )
            .unwrap();
            let quarantine = Path::new(intent.quarantine_directory.as_str());
            if !keep_control {
                std::fs::remove_file(quarantine.join(BLOCKD_CONTROL_SOCKET_BASENAME)).unwrap();
            }
            if !keep_io {
                if let Some(io) = &intent.io_socket_path {
                    let io = quarantine.join(Path::new(io.as_str()).file_name().unwrap());
                    if io.exists() {
                        std::fs::remove_file(io).unwrap();
                    }
                }
            }
            if !keep_marker {
                std::fs::remove_file(quarantine.join(BLOCKD_SOCKET_OWNER_MARKER_BASENAME)).unwrap();
            }

            let snapshot = fixture
                .root
                .capture_closed_whole_root(&fixture.intents, std::slice::from_ref(&intent))
                .unwrap();
            if let Some(stop_owner) = stop_owner {
                let physical = snapshot.bind_root_stop_owner(&stop_owner).unwrap();
                let expected = keep_control
                    .then(|| intent.control_socket_path().clone())
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                assert_eq!(physical, expected);
            }
            let absence = fixture.exact_start_absence(&intent);
            assert_eq!(
                fixture
                    .root
                    .retire_absent_owner(
                        &fixture.intents,
                        &intent,
                        &fixture.current_boot(),
                        absence,
                    )
                    .unwrap(),
                ManagedBlockdSocketOwnerRetirement::Retired
            );
            fixture.assert_owner_and_intent_absent(&intent);
        }
    }

    #[test]
    fn old_boot_staged_intent_is_retired_before_current_start_reissue() {
        let fixture = Fixture::new();
        let current = fixture.root_intent('5');
        let mut stale = current.clone();
        stale.node_boot_id = node_boot_id('f');
        fixture.install_intent_receipt(&stale, CapturedBlockdSocketIntentPhase::Staging);

        let absence = fixture.exact_start_absence(&current);
        let prepared = fixture
            .root
            .prepare_absent_owner_for_start(
                &fixture.intents,
                &current,
                &fixture.current_boot(),
                absence,
            )
            .unwrap();
        assert_eq!(prepared.receipt(), &current);
        assert_eq!(
            fixture.intents.load(current.owner()).unwrap(),
            Some(current)
        );
    }

    #[test]
    fn quarantined_intent_is_finished_before_exact_start_replay() {
        let fixture = Fixture::new();
        let intent = fixture.root_intent('6');
        fixture.install_intent_receipt(&intent, CapturedBlockdSocketIntentPhase::Quarantine);

        let absence = fixture.exact_start_absence(&intent);
        let prepared = fixture
            .root
            .prepare_absent_owner_for_start(
                &fixture.intents,
                &intent,
                &fixture.current_boot(),
                absence,
            )
            .unwrap();
        prepared.assert_current(&fixture.current_boot()).unwrap();
        assert_eq!(fixture.intents.load(intent.owner()).unwrap(), Some(intent));
    }

    #[test]
    fn post_submit_accepts_only_the_role_specific_socket_leaves() {
        let root_fixture = Fixture::new();
        let root_intent = root_fixture.root_intent('7');
        let prepared_root = root_fixture
            .root
            .prepare_for_start(
                &root_fixture.intents,
                &root_intent,
                &root_fixture.current_boot(),
            )
            .unwrap();
        prepared_root
            .assert_current(&root_fixture.current_boot())
            .unwrap();
        let root_control =
            UnixListener::bind(Path::new(root_intent.control_socket_path.as_str())).unwrap();
        assert!(prepared_root
            .assert_current(&root_fixture.current_boot())
            .is_err());
        prepared_root
            .assert_post_submit_owner_current(
                &root_fixture.current_boot(),
                BlockdSocketPostSubmitOutcome::HandshakeVerified,
            )
            .unwrap();
        drop((root_control, prepared_root));

        let serving_fixture = Fixture::new();
        let serving_intent = serving_fixture.serving_intent('8');
        let prepared_serving = serving_fixture
            .root
            .prepare_for_start(
                &serving_fixture.intents,
                &serving_intent,
                &serving_fixture.current_boot(),
            )
            .unwrap();
        prepared_serving
            .assert_current(&serving_fixture.current_boot())
            .unwrap();
        let serving_control =
            UnixListener::bind(Path::new(serving_intent.control_socket_path.as_str())).unwrap();
        let serving_io = UnixListener::bind(Path::new(
            serving_intent.io_socket_path.as_ref().unwrap().as_str(),
        ))
        .unwrap();
        assert!(prepared_serving
            .assert_current(&serving_fixture.current_boot())
            .is_err());
        prepared_serving
            .assert_post_submit_owner_current(
                &serving_fixture.current_boot(),
                BlockdSocketPostSubmitOutcome::HandshakeVerified,
            )
            .unwrap();
        drop((serving_control, serving_io, prepared_serving));
    }

    #[test]
    fn post_submit_rejects_a_foreign_leaf_and_exact_bytes_marker_aba() {
        let foreign_fixture = Fixture::new();
        let foreign_intent = foreign_fixture.root_intent('9');
        let prepared_foreign = foreign_fixture
            .root
            .prepare_for_start(
                &foreign_fixture.intents,
                &foreign_intent,
                &foreign_fixture.current_boot(),
            )
            .unwrap();
        let foreign_control =
            UnixListener::bind(Path::new(foreign_intent.control_socket_path.as_str())).unwrap();
        std::fs::write(
            Path::new(foreign_intent.public_directory.as_str()).join("foreign"),
            b"not provider owned",
        )
        .unwrap();
        assert!(prepared_foreign
            .assert_post_submit_owner_current(
                &foreign_fixture.current_boot(),
                BlockdSocketPostSubmitOutcome::MayHaveStarted,
            )
            .is_err());
        drop((foreign_control, prepared_foreign));

        let marker_fixture = Fixture::new();
        let marker_intent = marker_fixture.root_intent('a');
        let prepared_marker = marker_fixture
            .root
            .prepare_for_start(
                &marker_fixture.intents,
                &marker_intent,
                &marker_fixture.current_boot(),
            )
            .unwrap();
        let marker_control =
            UnixListener::bind(Path::new(marker_intent.control_socket_path.as_str())).unwrap();
        let marker_path = Path::new(marker_intent.owner_marker_path.as_str());
        let displaced_marker = marker_fixture
            ._temporary
            .path()
            .join("displaced-owner-marker");
        std::fs::rename(marker_path, &displaced_marker).unwrap();
        std::fs::write(marker_path, marker_intent.encoded_bytes().unwrap()).unwrap();
        std::fs::set_permissions(marker_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(prepared_marker
            .assert_post_submit_owner_current(
                &marker_fixture.current_boot(),
                BlockdSocketPostSubmitOutcome::MayHaveStarted,
            )
            .is_err());
        drop((marker_control, prepared_marker));
    }

    #[test]
    fn whole_root_capacity_covers_more_than_legacy_bound_and_rejects_first_foreign_owner() {
        const LEGACY_BROKEN_ENTRY_BOUND: usize = 8_192;
        const OWNER_COUNT: usize = LEGACY_BROKEN_ENTRY_BOUND + 1;

        assert_eq!(
            BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT,
            RUNTIME_V1_MAX_ASSIGNED_CATS * (RUNTIME_READY_MAX_DEVICES_V1 + 1)
        );
        assert_eq!(
            BLOCKD_SOCKET_WHOLE_ROOT_SCAN_ENTRY_LIMIT,
            BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT + 1
        );
        const { assert!(OWNER_COUNT < BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT) };
        validate_whole_root_expected_owner_count(BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT).unwrap();
        assert!(
            validate_whole_root_expected_owner_count(BLOCKD_SOCKET_EXPECTED_OWNER_LIMIT + 1)
                .is_err()
        );

        let fixture = Fixture::new();
        let expected = (1..=OWNER_COUNT)
            .map(|owner| fixture.indexed_root_intent(owner))
            .collect::<Vec<_>>();
        for intent in &expected {
            fixture.install_current_owner_for_capacity_test(intent);
        }
        fixture.intents.directory.sync_all().unwrap();
        fixture.root.descriptor.sync_all().unwrap();

        let snapshot = fixture
            .root
            .capture_closed_whole_root(&fixture.intents, &expected)
            .unwrap();
        assert_eq!(snapshot.directory_names.len(), OWNER_COUNT);
        assert_eq!(snapshot.receipt_names.len(), OWNER_COUNT);
        assert_eq!(snapshot.owner_snapshots.len(), OWNER_COUNT);

        let foreign = fixture.socket_path.join("foreign-owner");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = fixture
            .root
            .capture_closed_whole_root(&fixture.intents, &expected)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("contains an unknown owner or recovery alias"));
        assert!(
            foreign.is_dir(),
            "failed scan must not clean foreign residue"
        );
    }

    fn random_id(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn node_boot_id(value: char) -> NodeBootId {
        NodeBootId::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn digest(value: char) -> Sha256Digest {
        Sha256Digest::new(format!(
            "sha256:{}",
            std::iter::repeat_n(value, 64).collect::<String>()
        ))
        .unwrap()
    }
}

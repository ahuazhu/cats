//! The one production Desired-to-Cloud-Hypervisor network effect adapter.
//!
//! Network planning is deliberately split from Host mutation: an exact
//! `(network_id, tap_name, ownership_token, config)` tuple is written through
//! the retained Node state-directory descriptor and made durable before `ip`
//! or the typed launch port can observe it. A retry or process restart always
//! re-reads that record and cannot manufacture a second Host identity.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, ContractVersion, DesiredRuntimeSpec, Id, NetworkConfig,
    NodeResidue, ObservedNetwork, OwnershipTokenEvidence, RandomId128, RuntimeTarget,
};
use serde::{Deserialize, Serialize};

use crate::ch::{
    plan_network, prepare_network_with_tap_port, validate_network_plan, ChConfig, ChNetwork,
    PlatformTapCreatePort, TapCreatePort,
};
use crate::state_directory::StateDirectory;

use super::{RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome};

const DIRECTORY_NAME: &str = "runtime-effects";
const CHECKPOINT_MAX_BYTES: usize = 4_096;

/// The narrow handoff to the future signed VMM/volume reconciler.
///
/// The port is crate-sealed so production cannot substitute the legacy job
/// callback. Its inputs are the complete signed Desired value and the exact
/// tuple that this adapter has just re-read from durable storage.
pub(crate) trait RuntimeLaunchPort:
    super::runtime_launch_port_sealed::Sealed + Send + Sync + 'static
{
    fn launch(&self, desired: &DesiredRuntimeSpec, network: &ChNetwork) -> anyhow::Result<()>;
}

trait RuntimeNetworkPort: Send + Sync + 'static {
    fn plan(&self, desired: &NetworkConfig) -> anyhow::Result<ChNetwork>;
    fn prepare(
        &self,
        context: &RuntimeDesiredEffectContext,
        network: &ChNetwork,
    ) -> anyhow::Result<()>;
}

struct CloudHypervisorNetworkPort {
    config: ChConfig,
    tap_create: Arc<dyn TapCreatePort>,
}

impl RuntimeNetworkPort for CloudHypervisorNetworkPort {
    fn plan(&self, desired: &NetworkConfig) -> anyhow::Result<ChNetwork> {
        plan_network(desired)
    }

    fn prepare(
        &self,
        context: &RuntimeDesiredEffectContext,
        network: &ChNetwork,
    ) -> anyhow::Result<()> {
        prepare_network_with_tap_port(&self.config, network, context, self.tap_create.as_ref())
    }
}

/// Production implementation of the signed Runtime Desired effect seam.
pub(crate) struct ProductionRuntimeDesiredEffect {
    network: Arc<dyn RuntimeNetworkPort>,
    launch: Arc<dyn RuntimeLaunchPort>,
    #[cfg(test)]
    after_checkpoint: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ProductionRuntimeDesiredEffect {
    pub(crate) fn new(config: ChConfig, launch: Arc<dyn RuntimeLaunchPort>) -> Self {
        Self {
            network: Arc::new(CloudHypervisorNetworkPort {
                config,
                tap_create: Arc::new(PlatformTapCreatePort),
            }),
            launch,
            #[cfg(test)]
            after_checkpoint: None,
        }
    }

    #[cfg(test)]
    fn with_network_port(
        network: Arc<dyn RuntimeNetworkPort>,
        launch: Arc<dyn RuntimeLaunchPort>,
    ) -> Self {
        Self {
            network,
            launch,
            after_checkpoint: None,
        }
    }

    #[cfg(test)]
    fn with_tap_create_port(
        config: ChConfig,
        tap_create: Arc<dyn TapCreatePort>,
        launch: Arc<dyn RuntimeLaunchPort>,
    ) -> Self {
        Self {
            network: Arc::new(CloudHypervisorNetworkPort { config, tap_create }),
            launch,
            after_checkpoint: None,
        }
    }

    #[cfg(test)]
    fn with_after_checkpoint(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.after_checkpoint = Some(hook);
        self
    }
}

impl RuntimeDesiredEffect for ProductionRuntimeDesiredEffect {
    fn apply(
        &self,
        context: RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        // This is intentionally the first operation. A queued unit whose
        // current-process admission has already expired must touch nothing.
        context.check_active()?;
        anyhow::ensure!(
            desired.target == RuntimeTarget::Running,
            "signed Runtime target {:?} has no composed effect adapter",
            desired.target
        );
        encode_desired_runtime_spec(desired)
            .context("validate signed Desired before planning a Host effect")?;

        // Establish the current-process accepted full-inventory binding before
        // opening or creating any effect state. The durable network tuple is
        // a crash-recovery aid; it can never manufacture admission on its own.
        let accepted_runtime = accepted_full_runtime(&context, desired)?;

        let store = NetworkCheckpointStore::open(context.state_directory(), &context)?;
        let (network, publish) = match store.load(desired)? {
            Some(network) => (network, false),
            None => {
                let planned = self
                    .network
                    .plan(&desired.runtime.network_config)
                    .context("plan exact Desired Host network")?;
                validate_planned_network(desired, &planned)?;
                // Planning is zero-effect, so cancellation here may safely
                // leave no record. No physical mutation can have occurred.
                context.check_active()?;
                (planned, true)
            }
        };
        let network_is_ready =
            accepted_full_proves_exact_network(&context, desired, accepted_runtime, &network)?;
        if publish {
            store.publish(desired, &network)?;
            let persisted = store
                .load(desired)?
                .context("durable Host network checkpoint disappeared after publish")?;
            anyhow::ensure!(
                persisted == network,
                "durable Host network checkpoint changed during publish"
            );
        }

        // Hold the effect-directory lock and the exact checkpoint lineage
        // through this one physical planner step. A fresh accepted full scan,
        // not the checkpoint alone, decides whether Host network preparation
        // or runtime launch is next.
        #[cfg(test)]
        if let Some(after_checkpoint) = &self.after_checkpoint {
            after_checkpoint();
        }
        context.check_active()?;
        if network_is_ready {
            self.launch
                .launch(desired, &network)
                .context("launch exact checkpointed Desired runtime")?;
        } else {
            self.network
                .prepare(&context, &network)
                .context("prepare exact checkpointed Host network")?;
        }
        // If cancellation or the deadline crossed the physical call, retain
        // the checkpoint but publish no success from the stale admission.
        // The runner discards the batch and a fresh full scan observes the
        // exact late result before any successor step can be chosen.
        context.check_active()?;
        // Every successful invocation performed at most one physical step.
        // The runner must discard this admission and establish another full
        // physical inventory before it can choose the successor step.
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
    }
}

fn accepted_full_runtime<'a>(
    context: &'a RuntimeDesiredEffectContext,
    desired: &DesiredRuntimeSpec,
) -> anyhow::Result<&'a cats_api::runtime_reconciliation::ObservedRuntimeStatus> {
    let accepted = context.accepted_full()?;
    let observation = accepted.observation();
    let attestation = accepted.attestation();
    let session = accepted.session();
    anyhow::ensure!(
        observation.complete_inventory
            && observation.node_id == desired.placement.node_id
            && session.node_id == desired.placement.node_id
            && observation.node_id == session.node_id
            && observation.node_boot_id == session.node_boot_id
            && observation.agent_instance_id == session.agent_instance_id
            && observation.agent_session_epoch == session.agent_session_epoch
            && attestation.node_id == observation.node_id
            && attestation.agent_session_epoch == observation.agent_session_epoch
            && attestation.inventory_epoch == observation.inventory_epoch
            && observation.inventory_digest.as_ref() == Some(&attestation.inventory_digest)
            && observation.inventory_read_position == Some(attestation.inventory_read_position),
        "Host network step lacks an exact accepted full-inventory admission"
    );

    let mut matching_runtimes = observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let runtime = matching_runtimes
        .next()
        .context("accepted full inventory omitted the exact Desired Cat")?;
    anyhow::ensure!(
        matching_runtimes.next().is_none(),
        "accepted full inventory contains duplicate Runtime entries for the Desired Cat"
    );
    anyhow::ensure!(
        runtime.applied_desired.as_ref().is_some_and(|applied| {
            applied.desired_revision == desired.desired_revision
                && applied.spec_digest == desired.spec_digest
                && applied.placement == desired.placement
                && applied.target == desired.target
        }),
        "accepted full inventory does not bind the exact Desired revision"
    );
    Ok(runtime)
}

fn accepted_full_proves_exact_network(
    context: &RuntimeDesiredEffectContext,
    desired: &DesiredRuntimeSpec,
    runtime: &cats_api::runtime_reconciliation::ObservedRuntimeStatus,
    expected: &ChNetwork,
) -> anyhow::Result<bool> {
    let accepted = context.accepted_full()?;
    let observation = accepted.observation();

    for foreign in observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.cat_id != desired.cat_id)
        .flat_map(|runtime| &runtime.networks)
    {
        anyhow::ensure!(
            !observed_network_identity_overlaps(foreign, expected),
            "accepted full inventory contains a foreign Runtime using the checkpointed network identity"
        );
    }
    for residue in &observation.residue {
        if let NodeResidue::NetworkTap {
            network_id_hint,
            tap_name,
            ownership_token,
        } = residue
        {
            let token_matches = matches!(
                ownership_token,
                OwnershipTokenEvidence::Valid { ownership_token }
                    if ownership_token == &expected.ownership_token
            );
            anyhow::ensure!(
                network_id_hint.as_ref() != Some(&expected.config.network_id)
                    && tap_name.as_str() != expected.tap
                    && !token_matches,
                "accepted full inventory contains residue using the checkpointed network identity"
            );
        }
    }

    match runtime.networks.as_slice() {
        [] => Ok(false),
        [observed] => {
            anyhow::ensure!(
                observed_network_exactly_matches(observed, expected),
                "accepted full inventory contains a non-matching network for the Desired Cat"
            );
            Ok(true)
        }
        _ => {
            anyhow::bail!("accepted full inventory contains duplicate networks for the Desired Cat")
        }
    }
}

fn observed_network_identity_overlaps(observed: &ObservedNetwork, expected: &ChNetwork) -> bool {
    observed.network_id == expected.config.network_id
        || observed.tap_name.as_str() == expected.tap
        || matches!(
            &observed.ownership_token,
            OwnershipTokenEvidence::Valid { ownership_token }
                if ownership_token == &expected.ownership_token
        )
}

fn observed_network_exactly_matches(observed: &ObservedNetwork, expected: &ChNetwork) -> bool {
    observed.kind == expected.config.kind
        && observed.network_id == expected.config.network_id
        && observed.guest_mac == expected.config.guest_mac
        && observed.guest_ipv4 == expected.config.guest_ipv4
        && observed.prefix_length == expected.config.prefix_length
        && observed.gateway_ipv4 == expected.config.gateway_ipv4
        && observed.tap_name.as_str() == expected.tap
        && matches!(
            &observed.ownership_token,
            OwnershipTokenEvidence::Valid { ownership_token }
                if ownership_token == &expected.ownership_token
        )
}

fn validate_planned_network(
    desired: &DesiredRuntimeSpec,
    network: &ChNetwork,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        network.config == desired.runtime.network_config,
        "Host network tuple does not match exact Desired network config"
    );
    validate_network_plan(network)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableNetworkCheckpoint {
    version: ContractVersion,
    workspace_id: Id,
    cat_id: Id,
    network_id: Id,
    tap_name: String,
    ownership_token: RandomId128,
    config: NetworkConfig,
}

impl DurableNetworkCheckpoint {
    fn from_network(desired: &DesiredRuntimeSpec, network: &ChNetwork) -> Self {
        Self {
            version: ContractVersion::V1,
            workspace_id: desired.workspace_id.clone(),
            cat_id: desired.cat_id.clone(),
            network_id: network.config.network_id.clone(),
            tap_name: network.tap.clone(),
            ownership_token: network.ownership_token.clone(),
            config: network.config.clone(),
        }
    }

    fn into_network(self, desired: &DesiredRuntimeSpec) -> anyhow::Result<ChNetwork> {
        anyhow::ensure!(
            self.version == ContractVersion::V1,
            "Host network checkpoint has an unsupported version"
        );
        anyhow::ensure!(
            self.workspace_id == desired.workspace_id && self.cat_id == desired.cat_id,
            "Host network checkpoint belongs to a different Cat"
        );
        anyhow::ensure!(
            self.network_id == self.config.network_id,
            "Host network checkpoint has inconsistent network identity"
        );
        anyhow::ensure!(
            self.config == desired.runtime.network_config,
            "Host network checkpoint does not match exact Desired network config"
        );
        let network = ChNetwork {
            tap: self.tap_name,
            ownership_token: self.ownership_token,
            config: self.config,
        };
        validate_planned_network(desired, &network)?;
        Ok(network)
    }
}

struct NetworkCheckpointStore {
    directory: File,
    path: PathBuf,
}

impl NetworkCheckpointStore {
    fn open(
        state_directory: &StateDirectory,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<Self> {
        let parent = state_directory
            .try_clone_directory()
            .context("clone retained Node state directory")?;
        let path = state_directory.path().join(DIRECTORY_NAME);
        let directory = ensure_directory(&parent, &path)?;
        lock_directory(&directory, context)
            .with_context(|| format!("lock signed Runtime effect directory {}", path.display()))?;
        Ok(Self { directory, path })
    }

    fn load(&self, desired: &DesiredRuntimeSpec) -> anyhow::Result<Option<ChNetwork>> {
        let name = checkpoint_name(&desired.cat_id);
        let target = self.path.join(&name);
        let name = c_string(&name)?;
        let mut file = match open_at(
            &self.directory,
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(source)
                    .with_context(|| format!("open Host network checkpoint {}", target.display()))
            }
        };
        verify_file(&file)
            .with_context(|| format!("verify Host network checkpoint {}", target.display()))?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(CHECKPOINT_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read Host network checkpoint {}", target.display()))?;
        anyhow::ensure!(
            bytes.len() <= CHECKPOINT_MAX_BYTES,
            "Host network checkpoint exceeds its bounded size"
        );
        let checkpoint: DurableNetworkCheckpoint =
            serde_json::from_slice(&bytes).context("Host network checkpoint JSON is malformed")?;
        let canonical = encode_checkpoint(&checkpoint)?;
        anyhow::ensure!(
            canonical == bytes,
            "Host network checkpoint JSON is not canonical"
        );
        checkpoint.into_network(desired).map(Some)
    }

    fn publish(&self, desired: &DesiredRuntimeSpec, network: &ChNetwork) -> anyhow::Result<()> {
        validate_planned_network(desired, network)?;
        let checkpoint = DurableNetworkCheckpoint::from_network(desired, network);
        let bytes = encode_checkpoint(&checkpoint)?;
        let name = checkpoint_name(&desired.cat_id);
        let target = self.path.join(&name);
        let temporary_name = format!(".{name}.tmp");
        let temporary = self.path.join(&temporary_name);
        let name = c_string(&name)?;
        let temporary_name = c_string(&temporary_name)?;

        unlink_if_exists(&self.directory, &temporary_name)
            .with_context(|| format!("remove stale Host network temp {}", temporary.display()))?;
        // The directory lock makes this a single-writer transition. Never
        // replace a readable checkpoint: an existing tuple is authority and
        // must have been returned by `load` instead of reaching publication.
        anyhow::ensure!(
            open_at(
                &self.directory,
                &name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
            "Host network checkpoint appeared before publish"
        );

        let mut file = open_at(
            &self.directory,
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .with_context(|| format!("create Host network temp {}", temporary.display()))?;
        verify_file(&file)
            .with_context(|| format!("verify Host network temp {}", temporary.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("write Host network temp {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync Host network temp {}", temporary.display()))?;
        rename_at(&self.directory, &temporary_name, &self.directory, &name)
            .with_context(|| format!("publish Host network checkpoint {}", target.display()))?;
        self.directory.sync_all().with_context(|| {
            format!(
                "sync Host network checkpoint directory {}",
                self.path.display()
            )
        })
    }
}

fn checkpoint_name(cat_id: &Id) -> String {
    format!("{}.network.json", cat_id.as_str())
}

fn encode_checkpoint(checkpoint: &DurableNetworkCheckpoint) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(checkpoint).context("encode Host network checkpoint")?;
    anyhow::ensure!(
        bytes.len() <= CHECKPOINT_MAX_BYTES,
        "Host network checkpoint exceeds its bounded size"
    );
    Ok(bytes)
}

fn ensure_directory(parent: &File, path: &Path) -> anyhow::Result<File> {
    let name = c_string(DIRECTORY_NAME)?;
    // SAFETY: `parent` owns a live directory descriptor and `name` remains a
    // valid NUL-terminated string for this call.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        parent.sync_all().with_context(|| {
            format!(
                "sync Node state directory after creating {}",
                path.display()
            )
        })?;
    } else {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(source)
                .with_context(|| format!("create Runtime effect directory {}", path.display()));
        }
    }
    let directory = open_at(
        parent,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .with_context(|| format!("open Runtime effect directory {}", path.display()))?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect Runtime effect directory {}", path.display()))?;
    // SAFETY: `geteuid` has no pointer arguments or failure mode.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o777 == 0o700,
        "Runtime effect directory has unsafe metadata"
    );
    Ok(directory)
}

fn lock_directory(directory: &File, context: &RuntimeDesiredEffectContext) -> anyhow::Result<()> {
    loop {
        context.check_active()?;
        // SAFETY: `directory` owns a live descriptor and `flock` retains no
        // Rust memory. The lock is released with the store after launch
        // handoff.
        let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(error.into());
        }
        let remaining = context.deadline().saturating_duration_since(Instant::now());
        std::thread::sleep(Duration::from_millis(5).min(remaining));
    }
}

fn verify_file(file: &File) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    // SAFETY: `geteuid` has no pointer arguments or failure mode.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o777 == 0o600,
        "Host network checkpoint file has unsafe metadata"
    );
    Ok(())
}

fn c_string(value: &str) -> anyhow::Result<CString> {
    CString::new(value).context("Host network checkpoint name contains NUL")
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: the directory descriptor is live, `name` is stable for the
    // call, and a successful descriptor is transferred once into `File`.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a fresh descriptor owned by this call.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    // SAFETY: both descriptors are live and both names remain valid for the
    // duration of the call.
    let result = unsafe {
        libc::renameat(
            old_directory.as_raw_fd(),
            old_name.as_ptr(),
            new_directory.as_raw_fd(),
            new_name.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_if_exists(directory: &File, name: &CStr) -> io::Result<bool> {
    // SAFETY: the directory descriptor is live and `name` remains valid for
    // the call.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(true)
    } else {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(source)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        spec_digest, AdmissionInventoryAttestation, AgentSession, AppliedDesiredEvidence,
        AssignedKind, AssignedPlacement, CheckpointEvidence, Epoch, GuestTransportEvidence,
        HostPath, Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission, MacAddress, NodeBootId,
        NodeObservation, ObservedRuntimeStatus, ReconcileStep, Revision, RuntimeConfig,
        RuntimeTransition, Sequence, Sha256Digest, UnixMillis, WarmSnapshotEvidence,
    };

    use crate::ch::PendingTap;
    use crate::runtime_spine::RuntimeDesiredEffectAdmission;

    use super::*;

    #[derive(Default)]
    struct NetworkCalls {
        plans: usize,
        prepares: Vec<ChNetwork>,
    }

    struct FakeNetworkPort {
        planned: ChNetwork,
        calls: Arc<Mutex<NetworkCalls>>,
        fail_plan: bool,
        fail_prepare: bool,
        on_plan: Option<Arc<dyn Fn() + Send + Sync>>,
        on_prepare: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    #[derive(Default)]
    struct TapCalls {
        created: Vec<String>,
        published: Vec<String>,
    }

    #[derive(Default)]
    struct FakeTapCreatePort {
        calls: Arc<Mutex<TapCalls>>,
    }

    struct FakePendingTap {
        tap_name: String,
        calls: Arc<Mutex<TapCalls>>,
    }

    impl PendingTap for FakePendingTap {
        fn configure(
            &mut self,
            _ip_bin: &Path,
            _network: &ChNetwork,
            effect_context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<()> {
            effect_context.check_active()
        }

        fn publish(self: Box<Self>) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .published
                .push(self.tap_name.clone());
            Ok(())
        }
    }

    impl TapCreatePort for FakeTapCreatePort {
        fn create_nonpersistent(&self, tap_name: &str) -> anyhow::Result<Box<dyn PendingTap>> {
            self.calls.lock().unwrap().created.push(tap_name.to_owned());
            Ok(Box::new(FakePendingTap {
                tap_name: tap_name.to_owned(),
                calls: Arc::clone(&self.calls),
            }))
        }
    }

    impl FakeNetworkPort {
        fn new(planned: ChNetwork) -> (Self, Arc<Mutex<NetworkCalls>>) {
            let calls = Arc::new(Mutex::new(NetworkCalls::default()));
            (
                Self {
                    planned,
                    calls: Arc::clone(&calls),
                    fail_plan: false,
                    fail_prepare: false,
                    on_plan: None,
                    on_prepare: None,
                },
                calls,
            )
        }
    }

    impl RuntimeNetworkPort for FakeNetworkPort {
        fn plan(&self, desired: &NetworkConfig) -> anyhow::Result<ChNetwork> {
            self.calls.lock().unwrap().plans += 1;
            assert_eq!(desired, &self.planned.config);
            if let Some(on_plan) = &self.on_plan {
                on_plan();
            }
            anyhow::ensure!(!self.fail_plan, "injected plan failure");
            Ok(self.planned.clone())
        }

        fn prepare(
            &self,
            _context: &RuntimeDesiredEffectContext,
            network: &ChNetwork,
        ) -> anyhow::Result<()> {
            self.calls.lock().unwrap().prepares.push(network.clone());
            if let Some(on_prepare) = &self.on_prepare {
                on_prepare();
            }
            anyhow::ensure!(!self.fail_prepare, "injected prepare failure");
            Ok(())
        }
    }

    struct RecordingLaunch {
        calls: LaunchCalls,
        fail: bool,
    }

    type LaunchCalls = Arc<Mutex<Vec<(DesiredRuntimeSpec, ChNetwork)>>>;

    impl RecordingLaunch {
        fn new(fail: bool) -> (Self, LaunchCalls) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    calls: Arc::clone(&calls),
                    fail,
                },
                calls,
            )
        }
    }

    impl super::super::runtime_launch_port_sealed::Sealed for RecordingLaunch {}

    impl RuntimeLaunchPort for RecordingLaunch {
        fn launch(&self, desired: &DesiredRuntimeSpec, network: &ChNetwork) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((desired.clone(), network.clone()));
            anyhow::ensure!(!self.fail, "injected launch response loss");
            Ok(())
        }
    }

    fn desired_network() -> NetworkConfig {
        NetworkConfig {
            kind: IsolatedIpv4Kind::IsolatedIpv4,
            network_id: Id::new("net_01").unwrap(),
            guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
            guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
            prefix_length: 30,
            gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
        }
    }

    fn desired() -> DesiredRuntimeSpec {
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: Id::new("ws_01").unwrap(),
            cat_id: Id::new("cat_01").unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: Id::new("node_01").unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2_147_483_648,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: desired_network(),
            },
            volumes: Vec::new(),
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    fn planned_network(desired: &DesiredRuntimeSpec) -> ChNetwork {
        ChNetwork {
            tap: "catphysical01".to_owned(),
            ownership_token: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            config: desired.runtime.network_config.clone(),
        }
    }

    fn observed_network(network: &ChNetwork) -> ObservedNetwork {
        ObservedNetwork {
            kind: network.config.kind,
            network_id: network.config.network_id.clone(),
            guest_mac: network.config.guest_mac.clone(),
            guest_ipv4: network.config.guest_ipv4.clone(),
            prefix_length: network.config.prefix_length,
            gateway_ipv4: network.config.gateway_ipv4.clone(),
            tap_name: Id::new(network.tap.clone()).unwrap(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: network.ownership_token.clone(),
            },
        }
    }

    fn observed_runtime(
        root: &Path,
        desired: &DesiredRuntimeSpec,
        networks: Vec<ObservedNetwork>,
    ) -> ObservedRuntimeStatus {
        ObservedRuntimeStatus {
            cat_id: desired.cat_id.clone(),
            applied_desired: Some(AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: desired.target,
            }),
            runtime_incarnation: None,
            stable_state: None,
            step: ReconcileStep::InspectInventory {
                inventory_epoch: Epoch::new(4).unwrap(),
            },
            checkpoint: CheckpointEvidence::Missing {
                checkpoint_path: HostPath::new(
                    root.join(format!("{}.runtime.json", desired.cat_id))
                        .display()
                        .to_string(),
                )
                .unwrap(),
            },
            processes: Vec::new(),
            volumes: Vec::new(),
            mounts: Vec::new(),
            networks,
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            routes: Vec::new(),
            platform_guards: 0,
            conditions: Vec::new(),
        }
    }

    fn effect_context_with_runtimes(
        root: &Path,
        desired: &DesiredRuntimeSpec,
        runtimes: Vec<ObservedRuntimeStatus>,
        residue: Vec<NodeResidue>,
    ) -> RuntimeDesiredEffectContext {
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: desired.placement.node_id.clone(),
            immutable_host_id: Id::new("host_01").unwrap(),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: Epoch::new(2).unwrap(),
            registration_attempt_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: UnixMillis::new(1_900_000_120_000).unwrap(),
        };
        let inventory_digest = Sha256Digest::from_bytes([7; 32]);
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: Epoch::new(4).unwrap(),
            inventory_digest: inventory_digest.clone(),
            inventory_read_position: Sequence::new(12).unwrap(),
            accepted_at_unix_ms: UnixMillis::new(1_900_000_000_000).unwrap(),
        };
        let observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("44444444444444444444444444444444").unwrap(),
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(9).unwrap(),
            observed_at_unix_ms: UnixMillis::new(1_899_999_999_000).unwrap(),
            complete_inventory: true,
            inventory_epoch: attestation.inventory_epoch,
            inventory_digest: Some(inventory_digest),
            inventory_read_position: Some(attestation.inventory_read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes,
            residue,
        };
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(root.to_path_buf()),
            Instant::now() + Duration::from_secs(10),
            RuntimeDesiredEffectAdmission::for_test(session, observation, attestation),
        )
    }

    fn effect_context(root: &Path, desired: &DesiredRuntimeSpec) -> RuntimeDesiredEffectContext {
        effect_context_with_runtimes(
            root,
            desired,
            vec![observed_runtime(root, desired, Vec::new())],
            Vec::new(),
        )
    }

    fn launch_context(
        root: &Path,
        desired: &DesiredRuntimeSpec,
        network: &ChNetwork,
    ) -> RuntimeDesiredEffectContext {
        effect_context_with_runtimes(
            root,
            desired,
            vec![observed_runtime(
                root,
                desired,
                vec![observed_network(network)],
            )],
            Vec::new(),
        )
    }

    fn mutate_effect_context(
        root: &Path,
        desired: &DesiredRuntimeSpec,
        mutate: impl FnOnce(&mut AgentSession, &mut NodeObservation, &mut AdmissionInventoryAttestation),
    ) -> RuntimeDesiredEffectContext {
        let base = effect_context(root, desired);
        let accepted = base.accepted_full().unwrap();
        let mut session = accepted.session().clone();
        let mut observation = accepted.observation().clone();
        let mut attestation = accepted.attestation().clone();
        mutate(&mut session, &mut observation, &mut attestation);
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(root.to_path_buf()),
            Instant::now() + Duration::from_secs(10),
            RuntimeDesiredEffectAdmission::for_test(session, observation, attestation),
        )
    }

    fn checkpoint_path(root: &Path, desired: &DesiredRuntimeSpec) -> PathBuf {
        root.join(DIRECTORY_NAME)
            .join(checkpoint_name(&desired.cat_id))
    }

    fn checkpoint(root: &Path, desired: &DesiredRuntimeSpec) -> DurableNetworkCheckpoint {
        serde_json::from_slice(&std::fs::read(checkpoint_path(root, desired)).unwrap()).unwrap()
    }

    fn adapter(
        network: FakeNetworkPort,
        launch: RecordingLaunch,
    ) -> ProductionRuntimeDesiredEffect {
        ProductionRuntimeDesiredEffect::with_network_port(Arc::new(network), Arc::new(launch))
    }

    fn ch_config(ip_bin: PathBuf) -> ChConfig {
        ChConfig {
            block_direct: false,
            vmm_launcher_bin: "unused-vmm-launcher".into(),
            ch_bin: "unused-ch".into(),
            kernel: "unused-kernel".into(),
            initramfs: None,
            boot_contract: None,
            cmdline: String::new(),
            seed_image: None,
            block_path: crate::ch::BlockPath::KernelNbd,
            vhost_user_queues: 1,
            vhost_user_queue_size: 256,
            nbd_client_bin: "unused-nbd-client".into(),
            nbd_devices: 8,
            ip_bin,
        }
    }

    #[test]
    fn prepare_and_launch_are_separate_steps_bridged_only_by_exact_full_inventory() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let (mut network, network_calls) = FakeNetworkPort::new(planned.clone());
        let durable_path = checkpoint_path(root.path(), &desired);
        let expected = DurableNetworkCheckpoint::from_network(&desired, &planned);
        network.on_prepare = Some(Arc::new(move || {
            let bytes = std::fs::read(&durable_path)
                .expect("checkpoint must be visible before Host preparation");
            let stored: DurableNetworkCheckpoint = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(stored, expected);
            assert_eq!(encode_checkpoint(&stored).unwrap(), bytes);
        }));
        let (launch, launch_calls) = RecordingLaunch::new(false);
        let effect = adapter(network, launch);
        let outcome = effect
            .apply(effect_context(root.path(), &desired), &desired)
            .unwrap();
        assert_eq!(outcome, RuntimeDesiredEffectOutcome::RefreshInventory);
        assert_eq!(network_calls.lock().unwrap().plans, 1);
        assert_eq!(
            network_calls.lock().unwrap().prepares,
            vec![planned.clone()]
        );
        assert!(
            launch_calls.lock().unwrap().is_empty(),
            "the prepare admission must not also reach launch"
        );

        let outcome = effect
            .apply(launch_context(root.path(), &desired, &planned), &desired)
            .unwrap();
        assert_eq!(outcome, RuntimeDesiredEffectOutcome::RefreshInventory);
        assert_eq!(network_calls.lock().unwrap().plans, 1);
        assert_eq!(
            network_calls.lock().unwrap().prepares,
            vec![planned.clone()],
            "the launch admission must not repeat prepare"
        );
        assert_eq!(
            launch_calls.lock().unwrap().as_slice(),
            &[(desired.clone(), planned.clone())]
        );
        let stored = checkpoint(root.path(), &desired);
        assert_eq!(stored.network_id, desired.runtime.network_config.network_id);
        assert_eq!(stored.tap_name, planned.tap);
        assert_eq!(stored.ownership_token, planned.ownership_token);
        assert_eq!(stored.config, desired.runtime.network_config);
        assert_eq!(
            std::fs::metadata(checkpoint_path(root.path(), &desired))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn current_process_full_admission_is_required_before_any_effect_state_or_plan() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let context = RuntimeDesiredEffectContext::for_test(
            StateDirectory::unanchored(root.path().to_path_buf()),
            Instant::now() + Duration::from_secs(10),
        );
        let (network, network_calls) = FakeNetworkPort::new(planned);
        let (launch, launch_calls) = RecordingLaunch::new(false);

        let error = adapter(network, launch)
            .apply(context, &desired)
            .unwrap_err();

        assert!(format!("{error:#}").contains("current-process full admission"));
        let network_calls = network_calls.lock().unwrap();
        assert_eq!(network_calls.plans, 0);
        assert!(network_calls.prepares.is_empty());
        assert!(launch_calls.lock().unwrap().is_empty());
        assert!(!root.path().join(DIRECTORY_NAME).exists());
    }

    #[test]
    fn stale_duplicate_or_colliding_full_evidence_has_zero_physical_effect() {
        #[derive(Clone, Copy)]
        enum Case {
            StaleRevision,
            DuplicateRuntime,
            NonMatchingOwnNetwork,
            ForeignNetworkIdentity,
            ResidueNetworkIdentity,
        }

        for case in [
            Case::StaleRevision,
            Case::DuplicateRuntime,
            Case::NonMatchingOwnNetwork,
            Case::ForeignNetworkIdentity,
            Case::ResidueNetworkIdentity,
        ] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let planned = planned_network(&desired);
            let context =
                mutate_effect_context(root.path(), &desired, |_, observation, _| match case {
                    Case::StaleRevision => {
                        observation.runtimes[0]
                            .applied_desired
                            .as_mut()
                            .unwrap()
                            .desired_revision = Revision::new(2).unwrap();
                    }
                    Case::DuplicateRuntime => {
                        observation.runtimes.push(observation.runtimes[0].clone());
                    }
                    Case::NonMatchingOwnNetwork => {
                        let mut observed = observed_network(&planned);
                        observed.tap_name = Id::new("foreign_tap").unwrap();
                        observation.runtimes[0].networks.push(observed);
                    }
                    Case::ForeignNetworkIdentity => {
                        let mut foreign = observed_runtime(
                            root.path(),
                            &desired,
                            vec![observed_network(&planned)],
                        );
                        foreign.cat_id = Id::new("cat_02").unwrap();
                        observation.runtimes.push(foreign);
                    }
                    Case::ResidueNetworkIdentity => {
                        observation.residue.push(NodeResidue::NetworkTap {
                            network_id_hint: Some(planned.config.network_id.clone()),
                            tap_name: Id::new("foreign_tap").unwrap(),
                            ownership_token: OwnershipTokenEvidence::Missing,
                        });
                    }
                });
            let (network, network_calls) = FakeNetworkPort::new(planned);
            let (launch, launch_calls) = RecordingLaunch::new(false);

            assert!(adapter(network, launch).apply(context, &desired).is_err());

            let network_calls = network_calls.lock().unwrap();
            assert!(network_calls.prepares.is_empty());
            assert!(launch_calls.lock().unwrap().is_empty());
            assert!(!checkpoint_path(root.path(), &desired).exists());
        }
    }

    #[test]
    fn prepare_failure_restart_reuses_checkpoint_and_never_replans() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let (mut first_network, first_calls) = FakeNetworkPort::new(planned.clone());
        first_network.fail_prepare = true;
        let (first_launch, first_launch_calls) = RecordingLaunch::new(false);
        let error = adapter(first_network, first_launch)
            .apply(effect_context(root.path(), &desired), &desired)
            .unwrap_err();
        assert!(error.to_string().contains("prepare exact checkpointed"));
        assert_eq!(first_calls.lock().unwrap().plans, 1);
        assert!(first_launch_calls.lock().unwrap().is_empty());
        let durable_bytes = std::fs::read(checkpoint_path(root.path(), &desired)).unwrap();

        let (mut restarted_network, restarted_calls) = FakeNetworkPort::new(planned.clone());
        restarted_network.fail_plan = true;
        let (restarted_launch, restarted_launch_calls) = RecordingLaunch::new(false);
        adapter(restarted_network, restarted_launch)
            .apply(effect_context(root.path(), &desired), &desired)
            .unwrap();
        let restarted_calls = restarted_calls.lock().unwrap();
        assert_eq!(restarted_calls.plans, 0);
        assert_eq!(restarted_calls.prepares, vec![planned.clone()]);
        assert!(restarted_launch_calls.lock().unwrap().is_empty());
        assert_eq!(
            std::fs::read(checkpoint_path(root.path(), &desired)).unwrap(),
            durable_bytes
        );
    }

    #[test]
    fn launch_response_loss_restart_reuses_checkpoint_and_exact_tuple() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let setup_context = effect_context(root.path(), &desired);
        NetworkCheckpointStore::open(setup_context.state_directory(), &setup_context)
            .unwrap()
            .publish(&desired, &planned)
            .unwrap();

        let (mut first_network, first_calls) = FakeNetworkPort::new(planned.clone());
        first_network.fail_plan = true;
        first_network.fail_prepare = true;
        let (first_launch, first_launch_calls) = RecordingLaunch::new(true);
        let error = adapter(first_network, first_launch)
            .apply(launch_context(root.path(), &desired, &planned), &desired)
            .unwrap_err();
        assert!(error.to_string().contains("launch exact checkpointed"));
        assert_eq!(first_calls.lock().unwrap().plans, 0);
        assert!(first_calls.lock().unwrap().prepares.is_empty());
        assert_eq!(
            first_launch_calls.lock().unwrap().as_slice(),
            &[(desired.clone(), planned.clone())]
        );

        let (mut restarted_network, restarted_calls) = FakeNetworkPort::new(planned.clone());
        restarted_network.fail_plan = true;
        restarted_network.fail_prepare = true;
        let (restarted_launch, restarted_launch_calls) = RecordingLaunch::new(false);
        adapter(restarted_network, restarted_launch)
            .apply(launch_context(root.path(), &desired, &planned), &desired)
            .unwrap();
        assert_eq!(restarted_calls.lock().unwrap().plans, 0);
        assert!(restarted_calls.lock().unwrap().prepares.is_empty());
        assert_eq!(
            restarted_launch_calls.lock().unwrap().as_slice(),
            &[(desired, planned)]
        );
    }

    #[test]
    fn cancellation_after_zero_effect_plan_writes_no_checkpoint_or_host_effect() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let context = effect_context(root.path(), &desired);
        let canceller = context.clone();
        let (mut network, calls) = FakeNetworkPort::new(planned);
        network.on_plan = Some(Arc::new(move || canceller.cancel_for_test()));
        let (launch, launch_calls) = RecordingLaunch::new(false);
        let error = adapter(network, launch)
            .apply(context, &desired)
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.plans, 1);
        assert!(calls.prepares.is_empty());
        assert!(launch_calls.lock().unwrap().is_empty());
        assert!(!checkpoint_path(root.path(), &desired).exists());
    }

    #[test]
    fn cancellation_after_durable_checkpoint_prevents_prepare_and_restart_reuses_tuple() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let context = effect_context(root.path(), &desired);
        let canceller = context.clone();
        let (network, calls) = FakeNetworkPort::new(planned.clone());
        let (launch, launch_calls) = RecordingLaunch::new(false);
        let effect = adapter(network, launch)
            .with_after_checkpoint(Arc::new(move || canceller.cancel_for_test()));
        let error = effect.apply(context, &desired).unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.plans, 1);
        assert!(calls.prepares.is_empty());
        assert!(launch_calls.lock().unwrap().is_empty());
        assert_eq!(
            checkpoint(root.path(), &desired),
            DurableNetworkCheckpoint::from_network(&desired, &planned)
        );
        drop(calls);

        let (mut restarted_network, restarted_calls) = FakeNetworkPort::new(planned.clone());
        restarted_network.fail_plan = true;
        let (restarted_launch, restarted_launch_calls) = RecordingLaunch::new(false);
        adapter(restarted_network, restarted_launch)
            .apply(effect_context(root.path(), &desired), &desired)
            .unwrap();
        let restarted_calls = restarted_calls.lock().unwrap();
        assert_eq!(restarted_calls.plans, 0);
        assert_eq!(restarted_calls.prepares, vec![planned.clone()]);
        assert!(restarted_launch_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn cancellation_during_prepare_retains_tuple_but_never_launches() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let context = effect_context(root.path(), &desired);
        let canceller = context.clone();
        let (mut network, calls) = FakeNetworkPort::new(planned.clone());
        network.on_prepare = Some(Arc::new(move || canceller.cancel_for_test()));
        let (launch, launch_calls) = RecordingLaunch::new(false);
        let error = adapter(network, launch)
            .apply(context, &desired)
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert_eq!(calls.lock().unwrap().prepares, vec![planned.clone()]);
        assert!(launch_calls.lock().unwrap().is_empty());
        assert_eq!(
            checkpoint(root.path(), &desired),
            DurableNetworkCheckpoint::from_network(&desired, &planned)
        );
    }

    #[test]
    fn restart_after_pre_publish_crash_discards_only_stale_temp() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let planned = planned_network(&desired);
        let directory = root.path().join(DIRECTORY_NAME);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let temporary = directory.join(format!(".{}.tmp", checkpoint_name(&desired.cat_id)));
        std::fs::write(&temporary, b"torn pre-publish bytes").unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();

        let (network, calls) = FakeNetworkPort::new(planned.clone());
        let (launch, _) = RecordingLaunch::new(false);
        adapter(network, launch)
            .apply(effect_context(root.path(), &desired), &desired)
            .unwrap();
        assert_eq!(calls.lock().unwrap().plans, 1);
        assert!(!temporary.exists());
        assert_eq!(
            checkpoint(root.path(), &desired),
            DurableNetworkCheckpoint::from_network(&desired, &planned)
        );
    }

    #[test]
    fn malformed_or_wrong_config_checkpoint_fails_closed_without_replanning() {
        for wrong_config in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let planned = planned_network(&desired);
            let directory = root.path().join(DIRECTORY_NAME);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let target = checkpoint_path(root.path(), &desired);
            if wrong_config {
                let mut checkpoint = DurableNetworkCheckpoint::from_network(&desired, &planned);
                checkpoint.config = NetworkConfig {
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:0a").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.10").unwrap(),
                    gateway_ipv4: Ipv4Address::new("10.240.0.9").unwrap(),
                    ..checkpoint.config
                };
                std::fs::write(&target, encode_checkpoint(&checkpoint).unwrap()).unwrap();
            } else {
                std::fs::write(&target, b"{\"version\":1").unwrap();
            }
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

            let (mut network, calls) = FakeNetworkPort::new(planned);
            network.fail_plan = true;
            let (launch, launch_calls) = RecordingLaunch::new(false);
            assert!(adapter(network, launch)
                .apply(effect_context(root.path(), &desired), &desired)
                .is_err());
            let calls = calls.lock().unwrap();
            assert_eq!(calls.plans, 0);
            assert!(calls.prepares.is_empty());
            assert!(launch_calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn non_running_targets_fail_before_any_checkpoint_or_effect() {
        for target in [
            RuntimeTarget::Suspended,
            RuntimeTarget::Warm,
            RuntimeTarget::Cold,
            RuntimeTarget::Deleted,
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut desired = desired();
            desired.target = target;
            desired.spec_digest = spec_digest(&desired).unwrap();
            let (network, calls) = FakeNetworkPort::new(planned_network(&desired));
            let (launch, launch_calls) = RecordingLaunch::new(false);
            let error = adapter(network, launch)
                .apply(effect_context(root.path(), &desired), &desired)
                .unwrap_err();
            assert!(error.to_string().contains("no composed effect adapter"));
            let calls = calls.lock().unwrap();
            assert_eq!(calls.plans, 0);
            assert!(calls.prepares.is_empty());
            assert!(launch_calls.lock().unwrap().is_empty());
            assert!(!root.path().join(DIRECTORY_NAME).exists());
        }
    }

    #[test]
    fn production_adapter_uses_real_plan_prepare_and_exact_desired_config() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let ip_log = root.path().join("ip.log");
        let fake_ip = root.path().join("ip");
        std::fs::write(
            &fake_ip,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = '-d' ]; then exit 1; fi\nexit 0\n",
                ip_log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (launch, launch_calls) = RecordingLaunch::new(false);
        let tap_create = Arc::new(FakeTapCreatePort::default());
        let tap_calls = Arc::clone(&tap_create.calls);
        let effect = ProductionRuntimeDesiredEffect::with_tap_create_port(
            ch_config(fake_ip),
            tap_create,
            Arc::new(launch),
        );
        let outcome = effect
            .apply(effect_context(root.path(), &desired), &desired)
            .unwrap();
        assert_eq!(outcome, RuntimeDesiredEffectOutcome::RefreshInventory);

        assert!(launch_calls.lock().unwrap().is_empty());
        let network = checkpoint(root.path(), &desired)
            .into_network(&desired)
            .unwrap();
        assert_eq!(network.config, desired.runtime.network_config);
        assert_eq!(
            checkpoint(root.path(), &desired),
            DurableNetworkCheckpoint::from_network(&desired, &network)
        );
        let tap_calls = tap_calls.lock().unwrap();
        assert_eq!(tap_calls.created, vec![network.tap.clone()]);
        assert_eq!(tap_calls.published, vec![network.tap.clone()]);
        drop(tap_calls);
        let ip_calls = std::fs::read_to_string(ip_log).unwrap();
        assert!(
            !ip_calls.contains("tuntap"),
            "production adapter fell back to command-line TAP creation"
        );
        assert!(ip_calls.contains(&format!(
            "addr add {}/{} dev {}",
            network.config.gateway_ipv4.as_str(),
            network.config.prefix_length,
            network.tap
        )));

        let outcome = effect
            .apply(launch_context(root.path(), &desired, &network), &desired)
            .unwrap();
        assert_eq!(outcome, RuntimeDesiredEffectOutcome::RefreshInventory);
        assert_eq!(
            launch_calls.lock().unwrap().as_slice(),
            &[(desired, network)]
        );
    }

    #[test]
    fn production_adapter_rejects_wrong_host_token_or_address_without_mutation_or_launch() {
        for wrong_token in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let planned = planned_network(&desired);
            let directory = root.path().join(DIRECTORY_NAME);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let target = checkpoint_path(root.path(), &desired);
            std::fs::write(
                &target,
                encode_checkpoint(&DurableNetworkCheckpoint::from_network(&desired, &planned))
                    .unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

            let alias = root.path().join("alias");
            let address = root.path().join("address");
            let mutation = root.path().join("mutation");
            let fake_ip = root.path().join("ip");
            let expected_alias = format!(
                "cats-network:{}:{}",
                planned.config.network_id, planned.ownership_token
            );
            std::fs::write(
                &alias,
                if wrong_token {
                    format!(
                        "cats-network:{}:{}",
                        planned.config.network_id,
                        RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap()
                    )
                } else {
                    expected_alias
                },
            )
            .unwrap();
            std::fs::write(
                &address,
                if wrong_token {
                    "10.240.0.5/30"
                } else {
                    "10.240.0.9/30"
                },
            )
            .unwrap();
            std::fs::write(
                &fake_ip,
                format!(
                    "#!/bin/sh\n\
if [ \"$1\" = '-d' ]; then printf '1: tap0 alias %s\\n' \"$(cat '{}')\"; exit 0; fi\n\
if [ \"$1\" = '-o' ] && [ \"$5\" = 'dev' ]; then printf '1: tap0 inet %s scope global\\n' \"$(cat '{}')\"; exit 0; fi\n\
if [ \"$1\" = '-o' ]; then exit 0; fi\n\
: > '{}'\nexit 0\n",
                    alias.display(),
                    address.display(),
                    mutation.display(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();

            let (launch, launch_calls) = RecordingLaunch::new(false);
            let error = ProductionRuntimeDesiredEffect::new(ch_config(fake_ip), Arc::new(launch))
                .apply(effect_context(root.path(), &desired), &desired)
                .unwrap_err();
            let error = format!("{error:#}");
            if wrong_token {
                assert!(error.contains("ownership token"));
            } else {
                assert!(error.contains("address other than exact"));
            }
            assert!(!mutation.exists());
            assert!(launch_calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn production_adapter_rejects_overlapping_malformed_or_duplicate_host_addresses() {
        for (name, inventory, expected_error) in [
            (
                "same /30 slot",
                "2: foreign0 inet 10.240.0.6/30 scope global\n",
                "address collision",
            ),
            (
                "covering prefix",
                "2: foreign0 inet 10.240.0.1/24 scope global\n",
                "address collision",
            ),
            (
                "malformed inventory",
                "this is not ip -o output\n",
                "interface index",
            ),
            (
                "duplicate address",
                "2: foreign0 inet 10.240.0.9/30 scope global\n\
3: foreign1 inet 10.240.0.9/32 scope global\n",
                "repeats IPv4 address",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let mutation = root.path().join("mutation");
            let fake_ip = root.path().join("ip");
            std::fs::write(
                &fake_ip,
                format!(
                    "#!/bin/sh\n\
if [ \"$1\" = '-d' ]; then exit 1; fi\n\
if [ \"$1\" = '-o' ]; then printf '%s' '{inventory}'; exit 0; fi\n\
: > '{mutation}'\n\
exit 0\n",
                    mutation = mutation.display(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();

            let (launch, launch_calls) = RecordingLaunch::new(false);
            let error = ProductionRuntimeDesiredEffect::new(ch_config(fake_ip), Arc::new(launch))
                .apply(effect_context(root.path(), &desired), &desired)
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected_error),
                "{name} returned unexpected error: {error:#}"
            );
            assert!(
                !mutation.exists(),
                "{name} reached a tuntap/address/link mutation"
            );
            assert!(
                launch_calls.lock().unwrap().is_empty(),
                "{name} reached the launch seam"
            );
        }
    }

    #[test]
    fn production_adapter_kills_and_reaps_ip_after_started_child_is_cancelled() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let pid_file = root.path().join("ip.pid");
        let started_fifo_path = root.path().join("ip.started");
        let started_fifo_c =
            CString::new(started_fifo_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path is a live NUL-terminated string and mode contains
        // only permission bits. The test owns the previously absent path.
        assert_eq!(unsafe { libc::mkfifo(started_fifo_c.as_ptr(), 0o600) }, 0);
        // O_RDWR prevents either endpoint's open from becoming a second
        // timing condition; the single byte remains the exact child-started
        // barrier.
        let mut started_fifo = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&started_fifo_path)
            .unwrap();
        let fake_ip = root.path().join("ip");
        std::fs::write(
            &fake_ip,
            format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{pid}'\nprintf x > '{started}'\nexec /bin/sleep 60\n",
                pid = pid_file.display(),
                started = started_fifo_path.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_ip, std::fs::Permissions::from_mode(0o755)).unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let network = planned_network(&desired);
        let setup_context = RuntimeDesiredEffectContext::for_test(
            state.clone(),
            Instant::now() + Duration::from_secs(10),
        );
        NetworkCheckpointStore::open(&state, &setup_context)
            .unwrap()
            .publish(&desired, &network)
            .unwrap();
        let context = effect_context(root.path(), &desired);
        let cancellation = context.clone();
        let (launch, launch_calls) = RecordingLaunch::new(false);
        let worker = std::thread::spawn(move || {
            ProductionRuntimeDesiredEffect::new(ch_config(fake_ip), Arc::new(launch))
                .apply(context, &desired)
                .unwrap_err()
        });
        let mut started = [0_u8; 1];
        started_fifo.read_exact(&mut started).unwrap();
        assert_eq!(started, [b'x']);
        let cancel_started = Instant::now();
        cancellation.cancel_for_test();
        let error = worker.join().unwrap();
        assert!(format!("{error:#}").contains("cancelled"));
        assert!(
            cancel_started.elapsed() < Duration::from_secs(2),
            "hung ip outlived explicit effect cancellation"
        );
        assert!(launch_calls.lock().unwrap().is_empty());

        let pid: libc::pid_t = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let mut status = 0;
        // SAFETY: pid was written by the exact child spawned above and the
        // status pointer is valid for this nonblocking waitpid probe.
        let wait = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(wait, -1, "Host ip remained waitable after adapter return");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "Host ip was not reaped by the deadline path"
        );
    }
}

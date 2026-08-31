//! Installed Cloud Hypervisor, blockd and Guest effects for the direct
//! Control -> Node protocol.
//!
//! Product idempotency remains the Cat/action state machine. This module
//! derives every Host and storage coordinate from the current Cat, Node and
//! volume rows; it does not recreate an Operation, request ID, command poll or
//! old lifecycle journal.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse, DurabilityStatus};
use cats_api::guest::{
    FilesystemControlOperationV1, FilesystemControlOutcomeV1, FilesystemControlRequestV1,
    FilesystemIdentityV1, RuntimeReadyRequestV1, GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
    GUEST_HOST_CONTROL_VSOCK_PORT_V1,
};
use cats_api::runtime_reconciliation::{
    AsciiText, FilesystemInitialization, Generation, GuestDeviceIdentity, HostPath, Id,
    PersistentFilesystemBinding, ProvisionRootImageRequest, RandomId128, RemoteHead, Sha256Digest,
};
use cats_api::semantic_control::{CatAction, CatState, NodedCatConfig, NodedDiskMount};
use cats_blockd::engine::{ChunkEngine, DurabilityMode, EngineConfig};
use cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot;
use cats_storage::authority::{
    AttachedVolume, CatVolume, CatVolumeRole, CatVolumeStore, PersistentInitialization,
    PersistentInitializationCommit, RootDeleteState, RootVolumeSpec, VolumeAttachRequest,
    VolumeDataAuthority,
};
use cats_storage::{
    delete_volume_objects_page, read_image_manifest, AdapterSelection, BlobStore, DeletePrefixPage,
};
use sha2::{Digest as _, Sha256};

use crate::ch::{self, BlockPath, ChConfig, ChSpawn, GUEST_MEMORY_FILE};
use crate::guest_client::GuestClient;
use crate::semantic_lifecycle::{
    RuntimeAccessTarget, SemanticActionCancellation, SemanticCatEffects, SemanticEffectError,
    SemanticEffectFuture, SemanticEffectRequest,
};
use crate::semantic_mounts::{
    confirm_complete_mount_set, ExpectedPersistentMount, ExpectedPersistentMountSet,
};
use crate::semantic_usage::CatUsageMeters;

const ROOT_DEVICE_SERIAL: &str = "cats-root";
const ROOT_DISK_SCOPE: &[u8] = b"cats.direct.root-disk.v1\0";
const ROOT_VOLUME_SCOPE: &[u8] = b"cats.direct.root-volume.v1\0";
const ROOT_PROVISION_SCOPE: &[u8] = b"cats.direct.root-provision.v1\0";
const DEVICE_SERIAL_SCOPE: &[u8] = b"cats.direct.device-serial.v1\0";
const DELETE_PAGE_SIZE: usize = 1_000;
const DEFAULT_MAX_STAGED_BYTES: u64 = 8 << 30;
const DEFAULT_MAX_STAGED_PACKS: usize = 4_096;
const DEFAULT_MAX_LOCAL_BYTES: u64 = 16 << 30;

/// Fixed installed coordinates supplied by the noded composition root.
#[derive(Debug, Clone)]
pub struct InstalledCatConfig {
    pub node_id: Id,
    pub state_directory: PathBuf,
    pub runtime_directory: PathBuf,
    pub host_lock: PathBuf,
    pub blockd_binary: PathBuf,
    pub blockd_socket_root: ManagedBlockdSocketRoot,
    pub golden_root_cache_image: PathBuf,
    pub metadata_store: AdapterSelection,
    pub object_store: AdapterSelection,
    pub ch: ChConfig,
    pub root_size_bytes: u64,
    pub lease_duration_ms: u64,
    pub effect_timeout: Duration,
    pub guest_ready_timeout: Duration,
}

impl InstalledCatConfig {
    pub fn validate(&self) -> Result<()> {
        for (label, path) in [
            ("state directory", self.state_directory.as_path()),
            ("runtime directory", self.runtime_directory.as_path()),
            ("Host lock", self.host_lock.as_path()),
            ("blockd binary", self.blockd_binary.as_path()),
            (
                "Golden Root cache image",
                self.golden_root_cache_image.as_path(),
            ),
            ("Cloud Hypervisor binary", self.ch.ch_bin.as_path()),
            ("Guest kernel", self.ch.kernel.as_path()),
        ] {
            anyhow::ensure!(path.is_absolute(), "installed {label} is not absolute");
        }
        anyhow::ensure!(
            self.root_size_bytes > 0
                && self.lease_duration_ms > 0
                && !self.effect_timeout.is_zero()
                && !self.guest_ready_timeout.is_zero(),
            "installed Cat size, lease and timeouts must be positive"
        );
        anyhow::ensure!(
            self.metadata_store.name == "postgres",
            "installed Cat volume authority must be postgres"
        );
        anyhow::ensure!(
            !self.object_store.name.is_empty(),
            "installed Cat object-store adapter is empty"
        );
        Ok(())
    }
}

struct PhysicalCatLane {
    cat: Mutex<Option<ManagedCat>>,
}

impl PhysicalCatLane {
    fn new() -> Self {
        Self {
            cat: Mutex::new(None),
        }
    }

    fn cat(&self) -> MutexGuard<'_, Option<ManagedCat>> {
        self.cat
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct InstalledInner {
    config: InstalledCatConfig,
    _host_lock: File,
    volumes: Arc<dyn CatVolumeStore>,
    volume_data: Arc<dyn VolumeDataAuthority>,
    blob: Arc<dyn BlobStore>,
    /// Billing observation only. A metering failure is logged and skipped; it
    /// never fails a lifecycle effect.
    meters: Arc<CatUsageMeters>,
    cats: Mutex<BTreeMap<String, Arc<PhysicalCatLane>>>,
}

impl InstalledInner {
    fn cats(&self) -> MutexGuard<'_, BTreeMap<String, Arc<PhysicalCatLane>>> {
        self.cats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lane(&self, cat_id: &str) -> Arc<PhysicalCatLane> {
        self.cats()
            .entry(cat_id.to_owned())
            .or_insert_with(|| Arc::new(PhysicalCatLane::new()))
            .clone()
    }

    fn apply(
        &self,
        request: SemanticEffectRequest,
        cancellation: SemanticActionCancellation,
    ) -> Result<()> {
        self.config.validate()?;
        let cat_id = Id::new(request.cat_id.clone()).context("invalid Cat ID")?;
        let lane = self.lane(cat_id.as_str());
        let mut managed = lane.cat();
        check_cancellation(&cancellation, request.action)?;
        match request.action {
            CatAction::Create => {
                anyhow::ensure!(
                    managed.is_none(),
                    "Cat already has installed physical state"
                );
                *managed = Some(self.start_fresh(&cat_id, &request.config, &cancellation)?);
            }
            CatAction::Run => match managed.as_mut() {
                Some(cat) if cat.state == CatState::Suspended => {
                    ch::resume(&cat.api_socket).context("resume suspended Cloud Hypervisor")?;
                    cat.state = CatState::Running;
                    self.confirm_guest_ready(cat)?;
                }
                Some(cat) if cat.state == CatState::Warm => {
                    self.restore_warm(cat, &cancellation)?;
                }
                Some(cat) => bail!("installed Run cannot start from {:?}", cat.state),
                None => {
                    *managed = Some(self.start_fresh(&cat_id, &request.config, &cancellation)?);
                }
            },
            CatAction::Suspend => {
                let cat = managed.as_mut().context("installed Cat is absent")?;
                anyhow::ensure!(cat.state == CatState::Running, "Cat is not Running");
                self.quiesce(cat)?;
                ch::pause(&cat.api_socket).context("pause Cloud Hypervisor")?;
                let vmm = cat.vmm.as_ref().context("Running Cat has no VMM")?;
                ch::page_out_memory(vmm.id(), &cat.memory_file)
                    .context("page out suspended Guest memory")?;
                cat.state = CatState::Suspended;
            }
            CatAction::Warm => {
                let cat = managed.as_mut().context("installed Cat is absent")?;
                self.make_warm(cat, &cancellation)?;
            }
            CatAction::Cold => {
                let cat = managed.as_mut().context("installed Cat is absent")?;
                self.stop_cat(cat, true, &cancellation)
                    .context("stop installed Cat for Cold")?;
                managed.take();
            }
            CatAction::Destroy => {
                if let Some(cat) = managed.as_mut() {
                    self.stop_cat_for_destroy(cat, &cancellation)?;
                    managed.take();
                }
                self.destroy_root(&cat_id, &request.config)
                    .context("destroy RootDisk")?;
            }
        }
        Ok(())
    }

    fn reset_all(&self) -> Result<()> {
        let lanes = self.cats().values().cloned().collect::<Vec<_>>();
        for lane in lanes {
            if let Some(mut cat) = lane.cat().take() {
                self.stop_cat_without_release(&mut cat);
            }
        }
        if self.config.ch.block_path == BlockPath::KernelNbd {
            ch::reclaim_leaked_nbd_devices(&self.config.ch)
                .context("reclaim leaked NBD devices during Node reset")?;
        }
        self.volumes
            .detach_node_volumes(&self.config.node_id)
            .context("detach Node volumes during reset")?;
        clear_managed_directory(&self.config.runtime_directory)?;
        clear_managed_directory(&self.config.state_directory)?;
        clear_managed_directory(Path::new(self.config.blockd_socket_root.path().as_str()))?;
        self.cats().clear();
        Ok(())
    }
}

/// Real installed effects selected by `cats-noded --vmm ch`.
#[derive(Clone)]
pub struct InstalledSemanticCatEffects {
    inner: Arc<InstalledInner>,
}

impl InstalledSemanticCatEffects {
    pub fn new(
        config: InstalledCatConfig,
        volumes: Arc<dyn CatVolumeStore>,
        volume_data: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        meters: Arc<CatUsageMeters>,
    ) -> Result<Self> {
        config.validate()?;
        let host_lock = open_host_lock(&config.host_lock)?;
        create_private_directory(&config.state_directory)?;
        create_private_directory(&config.runtime_directory)?;
        create_private_directory(Path::new(config.blockd_socket_root.path().as_str()))?;
        create_private_directory(
            config
                .golden_root_cache_image
                .parent()
                .context("Golden Root cache image has no parent directory")?,
        )?;
        Ok(Self {
            inner: Arc::new(InstalledInner {
                config,
                _host_lock: host_lock,
                volumes,
                volume_data,
                blob,
                meters,
                cats: Mutex::new(BTreeMap::new()),
            }),
        })
    }
}

impl SemanticCatEffects for InstalledSemanticCatEffects {
    fn execute(
        &self,
        request: SemanticEffectRequest,
        cancellation: SemanticActionCancellation,
    ) -> SemanticEffectFuture {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || inner.apply(request, cancellation))
                .await
                .map_err(|error| installed_error(format!("join installed effect: {error}")))?
                .map_err(format_installed_error)
        })
    }

    fn reset_all(&self) -> SemanticEffectFuture {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || inner.reset_all())
                .await
                .map_err(|error| installed_error(format!("join installed reset: {error}")))?
                .map_err(format_installed_error)
        })
    }

    fn running_access_target(
        &self,
        cat_id: &str,
    ) -> Result<Option<RuntimeAccessTarget>, SemanticEffectError> {
        let lane = self
            .inner
            .cats()
            .get(cat_id)
            .cloned()
            .ok_or_else(|| installed_error("installed Cat is absent"))?;
        let managed = lane.cat();
        let cat = managed
            .as_ref()
            .ok_or_else(|| installed_error("installed Cat is absent"))?;
        if cat.state != CatState::Running {
            return Err(SemanticEffectError::new(
                cats_api::semantic_control::SemanticErrorCode::InvalidState,
                "installed Cat is not Running",
            ));
        }
        let vmm = cat
            .vmm
            .as_ref()
            .ok_or_else(|| installed_error("Running Cat has no VMM"))?;
        Ok(Some(RuntimeAccessTarget {
            runtime_incarnation: cat.runtime_incarnation.clone(),
            vsock_socket: cat.vsock_socket.clone(),
            guest_port: ch::GUEST_VSOCK_PORT,
            vmm_pid: vmm.id(),
        }))
    }
}

struct ManagedCat {
    cat_id: Id,
    config: NodedCatConfig,
    state: CatState,
    runtime_incarnation: RandomId128,
    runtime_directory: PathBuf,
    api_socket: PathBuf,
    vsock_socket: PathBuf,
    serial_log: PathBuf,
    memory_file: PathBuf,
    snapshot_directory: PathBuf,
    volumes: Vec<LocalVolume>,
    vmm: Option<Child>,
    boot_descriptors: Option<cats_api::runtime_artifacts::VerifiedGuestRuntimeLaunch>,
}

struct LocalVolume {
    requested: Option<NodedDiskMount>,
    attached: AttachedVolume,
    data_directory: PathBuf,
    authorization_file: PathBuf,
    process_identity_token: RandomId128,
    device_ownership_token: RandomId128,
    guest_device: GuestDeviceIdentity,
    control_socket: PathBuf,
    io_socket: PathBuf,
    blockd: Option<Child>,
    nbd_device: Option<String>,
}

#[derive(Default)]
struct FreshStartTimings {
    root_setup_ms: u64,
    root_provision_ms: u64,
    persistent_attach_ms: u64,
    block_frontends_ms: u64,
    memory_backing_ms: u64,
    vmm_spawn_ms: u64,
    guest_agent_health_ms: u64,
    persistent_prepare_ms: u64,
    runtime_ready_ms: u64,
}

impl InstalledInner {
    fn start_fresh(
        &self,
        cat_id: &Id,
        config: &NodedCatConfig,
        cancellation: &SemanticActionCancellation,
    ) -> Result<ManagedCat> {
        let create_started = Instant::now();
        let mut timings = FreshStartTimings::default();
        let mut root_provisioned = false;
        config.validate().context("validate installed Cat config")?;
        let runtime_directory = self.config.runtime_directory.join(cat_id.as_str());
        create_private_directory(&runtime_directory)?;
        let mut cat = ManagedCat {
            cat_id: cat_id.clone(),
            config: config.clone(),
            state: CatState::Cold,
            runtime_incarnation: fresh_random()?,
            api_socket: runtime_directory.join("vmm-api.sock"),
            vsock_socket: runtime_directory.join("vmm-vsock.sock"),
            serial_log: runtime_directory.join("guest-serial.log"),
            memory_file: runtime_directory.join(GUEST_MEMORY_FILE),
            snapshot_directory: runtime_directory.join("warm-snapshot"),
            runtime_directory,
            volumes: Vec::with_capacity(config.mounts.len() + 1),
            vmm: None,
            boot_descriptors: None,
        };

        let result = (|| {
            check_cancellation(cancellation, CatAction::Run)?;
            let stage_started = Instant::now();
            let root = self.ensure_root(cat_id, config)?;
            let root = self.attach(root)?;
            let root = self.local_volume(&cat, None, root, 0)?;
            cat.volumes.push(root);
            timings.root_setup_ms = elapsed_millis(stage_started);
            if cat.volumes[0].attached.volume.head.generation.get() == 0 {
                let stage_started = Instant::now();
                self.provision_root(config, &mut cat.volumes[0])?;
                timings.root_provision_ms = elapsed_millis(stage_started);
                root_provisioned = true;
            }

            let stage_started = Instant::now();
            for (index, requested) in config.mounts.iter().enumerate() {
                check_cancellation(cancellation, CatAction::Run)?;
                let mount_path = HostPath::new(requested.mount_path.as_str().to_owned())
                    .context("PersistentDisk mount path is outside HostPath")?;
                let persistent = self
                    .volumes
                    .load_persistent_volume(
                        &config.workspace_id,
                        cat_id,
                        &requested.disk_id,
                        &requested.volume_id,
                        &requested.filesystem_uuid,
                        &mount_path,
                    )
                    .context("load exact PersistentDisk binding")?;
                let attached = self.attach(persistent)?;
                cat.volumes.push(self.local_volume(
                    &cat,
                    Some(requested.clone()),
                    attached,
                    u16::try_from(index + 1).context("too many PersistentDisk devices")?,
                )?);
            }
            timings.persistent_attach_ms = elapsed_millis(stage_started);

            check_cancellation(cancellation, CatAction::Run)?;
            let stage_started = Instant::now();
            let disks = self.start_block_frontends(&mut cat, false)?;
            timings.block_frontends_ms = elapsed_millis(stage_started);
            let stage_started = Instant::now();
            ch::prepare_memory_backing(&cat.memory_file, bytes_to_mib(cat.config.memory_bytes)?)
                .context("prepare Guest memory backing")?;
            timings.memory_backing_ms = elapsed_millis(stage_started);
            let stage_started = Instant::now();
            self.open_meter(&cat);
            let spawned = ch::spawn_vmm_retaining_boot(&ChSpawn {
                cfg: &self.config.ch,
                api_sock: &cat.api_socket,
                vsock_sock: &cat.vsock_socket,
                serial_log: &cat.serial_log,
                cpus: cat.config.cpu,
                memory_mib: bytes_to_mib(cat.config.memory_bytes)?,
                memory_file: Some(&cat.memory_file),
                disks: &disks,
                restore_from: None,
                network: None,
            })
            .context("spawn Cloud Hypervisor")?;
            cat.vmm = Some(spawned.child);
            cat.boot_descriptors = spawned.boot_descriptors;
            self.meter_vmm(&cat);
            timings.vmm_spawn_ms = elapsed_millis(stage_started);
            let stage_started = Instant::now();
            self.wait_for_guest(&mut cat)?;
            timings.guest_agent_health_ms = elapsed_millis(stage_started);
            let stage_started = Instant::now();
            self.prepare_persistent_volumes(&mut cat)?;
            timings.persistent_prepare_ms = elapsed_millis(stage_started);
            let stage_started = Instant::now();
            self.confirm_guest_ready(&mut cat)?;
            timings.runtime_ready_ms = elapsed_millis(stage_started);
            cat.state = CatState::Running;
            check_cancellation(cancellation, CatAction::Run)?;
            Ok(())
        })();

        let total_ms = elapsed_millis(create_started);
        match &result {
            Ok(()) => tracing::info!(
                cat_id = cat_id.as_str(),
                root_provisioned,
                root_setup_ms = timings.root_setup_ms,
                root_provision_ms = timings.root_provision_ms,
                persistent_attach_ms = timings.persistent_attach_ms,
                block_frontends_ms = timings.block_frontends_ms,
                memory_backing_ms = timings.memory_backing_ms,
                vmm_spawn_ms = timings.vmm_spawn_ms,
                guest_agent_health_ms = timings.guest_agent_health_ms,
                persistent_prepare_ms = timings.persistent_prepare_ms,
                runtime_ready_ms = timings.runtime_ready_ms,
                total_ms,
                "installed Cat fresh start completed"
            ),
            Err(error) => tracing::warn!(
                cat_id = cat_id.as_str(),
                root_provisioned,
                root_setup_ms = timings.root_setup_ms,
                root_provision_ms = timings.root_provision_ms,
                persistent_attach_ms = timings.persistent_attach_ms,
                block_frontends_ms = timings.block_frontends_ms,
                memory_backing_ms = timings.memory_backing_ms,
                vmm_spawn_ms = timings.vmm_spawn_ms,
                guest_agent_health_ms = timings.guest_agent_health_ms,
                persistent_prepare_ms = timings.persistent_prepare_ms,
                runtime_ready_ms = timings.runtime_ready_ms,
                total_ms,
                %error,
                "installed Cat fresh start failed"
            ),
        }

        if let Err(error) = result {
            self.stop_cat_without_release(&mut cat);
            for volume in &cat.volumes {
                let _ = self.volumes.detach_volume(&volume.attached);
            }
            return Err(error);
        }
        Ok(cat)
    }

    fn ensure_root(&self, cat_id: &Id, config: &NodedCatConfig) -> Result<CatVolume> {
        self.volumes
            .ensure_root_volume(&RootVolumeSpec {
                workspace_id: config.workspace_id.clone(),
                cat_id: cat_id.clone(),
                disk_id: derived_id("disk_", ROOT_DISK_SCOPE, cat_id.as_str())?,
                volume_id: derived_id("vol_", ROOT_VOLUME_SCOPE, cat_id.as_str())?,
                size_bytes: self.config.root_size_bytes,
            })
            .context("ensure RootDisk authority")
    }

    fn root_descriptor(&self, cat_id: &Id, config: &NodedCatConfig) -> Result<CatVolume> {
        Ok(CatVolume {
            workspace_id: config.workspace_id.clone(),
            disk_id: derived_id("disk_", ROOT_DISK_SCOPE, cat_id.as_str())?,
            volume_id: derived_id("vol_", ROOT_VOLUME_SCOPE, cat_id.as_str())?,
            size_bytes: self.config.root_size_bytes,
            durability: cats_api::runtime_reconciliation::VolumeDurability::Strict,
            head: blank_head(),
            role: CatVolumeRole::Root {
                cat_id: cat_id.clone(),
            },
        })
    }

    fn attach(&self, volume: CatVolume) -> Result<AttachedVolume> {
        self.volumes
            .attach_volume(&VolumeAttachRequest {
                node_id: self.config.node_id.clone(),
                volume,
                lease_duration_ms: self.config.lease_duration_ms,
            })
            .context("attach volume to installed Node")
    }

    fn local_volume(
        &self,
        cat: &ManagedCat,
        requested: Option<NodedDiskMount>,
        attached: AttachedVolume,
        slot: u16,
    ) -> Result<LocalVolume> {
        let process_identity_token = fresh_random()?;
        let device_ownership_token = fresh_random()?;
        let serial = match &requested {
            Some(requested) => persistent_device_serial(&requested.disk_id)?,
            None => Id::new(ROOT_DEVICE_SERIAL).context("invalid Root device serial")?,
        };
        let guest_device = GuestDeviceIdentity { serial, slot };
        let data_directory = self
            .config
            .state_directory
            .join("data")
            .join(cat.cat_id.as_str())
            .join(attached.volume.volume_id.as_str())
            .join(attached.serving.identity.attachment_id.as_str())
            .join(attached.serving.identity.attachment_epoch.get().to_string());
        create_private_directory(&data_directory)?;
        write_exact_file(
            &data_directory.join("identity.json"),
            &serde_json::to_vec(&attached.serving.identity)
                .context("encode attachment identity")?,
        )?;
        let authorization_file = cat.runtime_directory.join(format!(
            "authorized-{}-{}.json",
            attached.volume.volume_id, process_identity_token
        ));
        write_exact_file(
            &authorization_file,
            &serde_json::to_vec(&attached.serving).context("encode serving authorization")?,
        )?;
        let sockets = self
            .config
            .blockd_socket_root
            .serving_paths(&device_ownership_token)
            .context("derive serving blockd sockets")?;
        let socket_directory = Path::new(sockets.public_directory().as_str());
        create_private_directory(socket_directory)?;
        Ok(LocalVolume {
            requested,
            attached,
            data_directory,
            authorization_file,
            process_identity_token,
            device_ownership_token,
            guest_device,
            control_socket: PathBuf::from(sockets.control_socket().as_str()),
            io_socket: PathBuf::from(sockets.io_socket().as_str()),
            blockd: None,
            nbd_device: None,
        })
    }

    fn provision_root(&self, config: &NodedCatConfig, root: &mut LocalVolume) -> Result<()> {
        let digest = Sha256Digest::new(config.boot_image.clone())
            .context("boot_image must be an exact sha256 digest in installed mode")?;
        let manifest = read_image_manifest(self.blob.as_ref(), &digest)
            .map_err(|error| anyhow::anyhow!(error))
            .context("read immutable Root image manifest")?;
        anyhow::ensure!(
            manifest.size_bytes <= root.attached.volume.size_bytes,
            "Root image exceeds RootDisk capacity"
        );
        let identity =
            cats_blockd::format::image_root_identity(&manifest, root.attached.volume.size_bytes)
                .context("derive generation-one Root image")?;
        let expected = RemoteHead {
            generation: Generation::new(1).context("generation one is invalid")?,
            root_hash: Some(Sha256Digest::from_bytes(identity.root_hash)),
            root_object_id: Some(
                AsciiText::new(identity.root_object_id)
                    .context("Root object identity is invalid")?,
            ),
        };
        let provision_transition_id = derived_random(
            ROOT_PROVISION_SCOPE,
            &[root.attached.volume.volume_id.as_str(), digest.as_str()],
        )?;
        let engine = ChunkEngine::attach_authorized_control_only(
            engine_config(&root.attached, &root.data_directory)?,
            root.attached.serving.clone(),
            Arc::clone(&self.blob),
            Arc::clone(&self.volume_data),
        )
        .context("open Root control-only engine")?;
        let request = ProvisionRootImageRequest {
            provision_transition_id,
            volume_id: root.attached.volume.volume_id.clone(),
            attachment_id: root.attached.serving.identity.attachment_id.clone(),
            attachment_epoch: root.attached.serving.identity.attachment_epoch,
            size_bytes: root.attached.volume.size_bytes,
            boot_image_digest: digest,
            expected_blank_head: root.attached.volume.head.clone(),
            expected_provisioned_head: expected.clone(),
        };
        let provision_started = Instant::now();
        let validation_preference = "node_shared_cache";
        let result = engine
            .provision_root_image_with_local_cache(&request, &self.config.golden_root_cache_image)
            .map_err(|error| anyhow::anyhow!(error))
            .context("provision Root image")?;
        tracing::info!(
            volume_id = root.attached.volume.volume_id.as_str(),
            boot_image_digest = request.boot_image_digest.as_str(),
            validation_preference,
            elapsed_ms = elapsed_millis(provision_started),
            "installed Root image provision completed"
        );
        anyhow::ensure!(
            result.resulting_head == expected,
            "Root provision head changed"
        );
        engine
            .stop_authorized_serving()
            .context("stop Root provision engine")?;
        root.attached = self.attach(root.attached.volume.clone())?;
        Ok(())
    }

    fn start_block_frontends(
        &self,
        cat: &mut ManagedCat,
        reuse_devices: bool,
    ) -> Result<Vec<String>> {
        let mut disks = Vec::with_capacity(cat.volumes.len());
        for volume in &mut cat.volumes {
            self.spawn_blockd(cat.config.cpu, volume)?;
            let disk = match self.config.ch.block_path {
                BlockPath::KernelNbd => {
                    let wanted = reuse_devices
                        .then_some(volume.nbd_device.as_deref())
                        .flatten();
                    let device = ch::nbd_attach(&self.config.ch, &volume.io_socket, wanted)
                        .context("attach kernel NBD frontend")?;
                    volume.nbd_device = Some(device.clone());
                    ch::file_disk_arg_with_serial(
                        &device,
                        self.config.ch.block_direct,
                        volume.guest_device.serial.as_str(),
                    )?
                }
                BlockPath::VhostUser => ch::vhost_user_disk_arg_with_serial(
                    &volume.io_socket,
                    ch::vhost_user_queues_for(&self.config.ch, cat.config.cpu),
                    self.config.ch.vhost_user_queue_size,
                    volume.guest_device.serial.as_str(),
                )?,
            };
            disks.push(disk);
        }
        Ok(disks)
    }

    fn spawn_blockd(&self, cpus: u32, volume: &mut LocalVolume) -> Result<()> {
        anyhow::ensure!(volume.blockd.is_none(), "blockd is already running");
        let _ = fs::remove_file(&volume.control_socket);
        let _ = fs::remove_file(&volume.io_socket);
        let scope_id = format!("cats-blockd-{}", volume.process_identity_token);
        let mut command = Command::new(&self.config.blockd_binary);
        command
            .arg("--volume-id")
            .arg(volume.attached.volume.volume_id.as_str())
            .arg("--data-dir")
            .arg(&volume.data_directory)
            .arg("--attachment-id")
            .arg(volume.attached.serving.identity.attachment_id.as_str())
            .arg("--authorized-serving-spec")
            .arg(&volume.authorization_file)
            .arg("--runtime-scope-id")
            .arg(scope_id)
            .arg("--process-identity-token")
            .arg(volume.process_identity_token.as_str())
            .arg("--device-ownership-token")
            .arg(volume.device_ownership_token.as_str())
            .arg("--guest-device-serial")
            .arg(volume.guest_device.serial.as_str())
            .arg("--metadata-store-adapter")
            .arg(&self.config.metadata_store.name)
            .arg("--object-store-adapter")
            .arg(&self.config.object_store.name)
            .arg("--lease-ttl-ms")
            .arg(self.config.lease_duration_ms.to_string())
            .arg("--durability")
            .arg("strict")
            .arg("--listen-control")
            .arg(&volume.control_socket);
        for option in self.config.metadata_store.config.to_cli() {
            command.arg("--metadata-store-option").arg(option);
        }
        for option in self.config.object_store.config.to_cli() {
            command.arg("--object-store-option").arg(option);
        }
        match self.config.ch.block_path {
            BlockPath::KernelNbd => {
                command.arg("--listen-unix").arg(&volume.io_socket);
            }
            BlockPath::VhostUser => {
                command
                    .arg("--listen-vhost-user")
                    .arg(&volume.io_socket)
                    .arg("--vhost-user-queues")
                    .arg(ch::vhost_user_queues_for(&self.config.ch, cpus).to_string())
                    .arg("--vhost-user-queue-size")
                    .arg(self.config.ch.vhost_user_queue_size.to_string());
            }
        }
        if self.config.blockd_socket_root != ManagedBlockdSocketRoot::installed() {
            command.env(
                "CATS_BLOCKD_TEST_SOCKET_ROOT",
                self.config.blockd_socket_root.path().as_str(),
            );
        }
        command.stdout(Stdio::null()).stderr(Stdio::inherit());
        let mut child = command.spawn().context("spawn cats-blockd")?;
        let deadline = deadline_after(self.config.effect_timeout)?;
        loop {
            if let Some(status) = child.try_wait().context("poll cats-blockd")? {
                bail!("cats-blockd exited before readiness: {status}");
            }
            if let Ok(status) = blockd_status(&volume.control_socket, Duration::from_millis(100)) {
                validate_blockd_status(volume, &status)?;
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("cats-blockd readiness timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        volume.blockd = Some(child);
        Ok(())
    }

    fn wait_for_guest(&self, cat: &mut ManagedCat) -> Result<()> {
        let deadline = deadline_after(self.config.guest_ready_timeout)?;
        loop {
            if cat
                .vmm
                .as_mut()
                .context("Cat has no VMM")?
                .try_wait()
                .context("poll Cloud Hypervisor")?
                .is_some()
            {
                bail!("Cloud Hypervisor exited before Guest readiness");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                if let Ok(mut guest) = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
                    &cat.vsock_socket,
                    GUEST_HOST_CONTROL_VSOCK_PORT_V1,
                    remaining.min(Duration::from_millis(250)),
                    cat.vmm.as_ref().context("Cat has no VMM")?.id(),
                ) {
                    if guest.health().is_ok() {
                        return Ok(());
                    }
                }
            }
            if Instant::now() >= deadline {
                bail!("Guest Agent readiness timed out");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn prepare_persistent_volumes(&self, cat: &mut ManagedCat) -> Result<()> {
        for index in 1..cat.volumes.len() {
            let initialization = match &cat.volumes[index].attached.volume.role {
                CatVolumeRole::Persistent { initialization, .. } => initialization.clone(),
                CatVolumeRole::Root { .. } => bail!("non-root device has RootDisk role"),
            };
            match initialization {
                PersistentInitialization::Uninitialized {
                    initialization_token,
                    expected_blank_head,
                } => {
                    let binding = persistent_binding(
                        cat,
                        &cat.volumes[index],
                        FilesystemInitialization::Initialize {
                            initialization_token,
                            expected_blank_head: expected_blank_head.clone(),
                        },
                    )?;
                    let probe = self.guest_filesystem(
                        cat,
                        filesystem_request(
                            binding.clone(),
                            FilesystemControlOperationV1::Probe,
                            expected_blank_head.clone(),
                            self.guest_timeout_ms()?,
                        )?,
                    )?;
                    anyhow::ensure!(
                        probe.outcome == FilesystemControlOutcomeV1::Exact,
                        "Guest PersistentDisk probe conflicted"
                    );
                    match &probe.observation.filesystem {
                        FilesystemIdentityV1::Blank => {
                            let formatted = self.guest_filesystem(
                                cat,
                                filesystem_request(
                                    binding.clone(),
                                    FilesystemControlOperationV1::FormatExt4,
                                    expected_blank_head.clone(),
                                    self.guest_timeout_ms()?,
                                )?,
                            )?;
                            anyhow::ensure!(
                                formatted.outcome == FilesystemControlOutcomeV1::Exact,
                                "Guest PersistentDisk format conflicted"
                            );
                        }
                        FilesystemIdentityV1::Ext4 { filesystem_uuid }
                            if filesystem_uuid
                                == &cat.volumes[index]
                                    .requested
                                    .as_ref()
                                    .context("PersistentDisk request is absent")?
                                    .filesystem_uuid => {}
                        FilesystemIdentityV1::Ext4 { .. } | FilesystemIdentityV1::Foreign => {
                            bail!("PersistentDisk contains a different filesystem")
                        }
                    }
                    let post_probe = self.guest_filesystem(
                        cat,
                        filesystem_request(
                            binding.clone(),
                            FilesystemControlOperationV1::Probe,
                            expected_blank_head.clone(),
                            self.guest_timeout_ms()?,
                        )?,
                    )?;
                    anyhow::ensure!(
                        post_probe.outcome == FilesystemControlOutcomeV1::Exact
                            && matches!(
                                &post_probe.observation.filesystem,
                                FilesystemIdentityV1::Ext4 { filesystem_uuid }
                                    if filesystem_uuid
                                        == &cat.volumes[index]
                                            .requested
                                            .as_ref()
                                            .expect("PersistentDisk request was checked")
                                            .filesystem_uuid
                            ),
                        "Guest did not prove the exact initialized ext4 filesystem"
                    );
                    let flush = self.guest_filesystem(
                        cat,
                        filesystem_request(
                            binding,
                            FilesystemControlOperationV1::FlushDevice,
                            expected_blank_head,
                            self.guest_timeout_ms()?,
                        )?,
                    )?;
                    anyhow::ensure!(
                        flush.outcome == FilesystemControlOutcomeV1::Exact,
                        "Guest PersistentDisk flush did not complete exactly"
                    );
                    self.drain_volume(&cat.volumes[index])?;
                    let initialized_head = self.current_volume_head(&cat.volumes[index])?;
                    anyhow::ensure!(
                        initialized_head.generation.get() > 0,
                        "PersistentDisk initialization did not publish a remote head"
                    );
                    let evidence = serde_json::to_vec(&(post_probe, flush))
                        .context("encode Guest initialization evidence")?;
                    let commit = PersistentInitializationCommit {
                        attached: cat.volumes[index].attached.clone(),
                        initialized_head: initialized_head.clone(),
                        guest_evidence: evidence,
                    };
                    let mut committed = None;
                    let mut last_error = None;
                    for _ in 0..3 {
                        match self.volumes.commit_persistent_initialization(&commit) {
                            Ok(volume) => {
                                committed = Some(volume);
                                break;
                            }
                            Err(error) => last_error = Some(error),
                        }
                    }
                    cat.volumes[index].attached.volume = committed.ok_or_else(|| {
                        anyhow::anyhow!(
                            "commit PersistentDisk initialization: {}",
                            last_error
                                .map(|error| error.to_string())
                                .unwrap_or_else(|| "unknown failure".to_owned())
                        )
                    })?;
                }
                PersistentInitialization::Initialized { .. } => {}
            }
            self.mount_persistent(cat, index)?;
        }
        Ok(())
    }

    fn mount_persistent(&self, cat: &ManagedCat, index: usize) -> Result<()> {
        let volume = cat
            .volumes
            .get(index)
            .context("PersistentDisk index is absent")?;
        let binding = persistent_binding(cat, volume, FilesystemInitialization::Existing)?;
        let head = self.current_volume_head(volume)?;
        let probe = self.guest_filesystem(
            cat,
            filesystem_request(
                binding.clone(),
                FilesystemControlOperationV1::Probe,
                head.clone(),
                self.guest_timeout_ms()?,
            )?,
        )?;
        anyhow::ensure!(
            probe.outcome == FilesystemControlOutcomeV1::Exact,
            "Guest PersistentDisk mount probe conflicted"
        );
        if probe.observation.mounts.is_empty() {
            let mounted = self.guest_filesystem(
                cat,
                filesystem_request(
                    binding,
                    FilesystemControlOperationV1::MountExt4,
                    head,
                    self.guest_timeout_ms()?,
                )?,
            )?;
            anyhow::ensure!(
                mounted.outcome == FilesystemControlOutcomeV1::Exact,
                "Guest PersistentDisk mount did not complete exactly"
            );
        }
        Ok(())
    }

    fn guest_filesystem(
        &self,
        cat: &ManagedCat,
        request: FilesystemControlRequestV1,
    ) -> Result<cats_api::guest::FilesystemControlResponseV1> {
        let vmm_pid = cat.vmm.as_ref().context("Cat has no VMM")?.id();
        let mut guest = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            &cat.vsock_socket,
            GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            self.config.effect_timeout,
            vmm_pid,
        )
        .context("connect Guest filesystem control")?;
        guest
            .filesystem_control(request)
            .context("execute Guest filesystem control")
    }

    fn guest_timeout_ms(&self) -> Result<u32> {
        let millis = self.config.effect_timeout.as_millis().clamp(
            1,
            u128::from(cats_api::guest::FILESYSTEM_CONTROL_MAX_TIMEOUT_MS_V1),
        );
        u32::try_from(millis).context("Guest filesystem timeout is outside u32")
    }

    fn current_volume_head(&self, volume: &LocalVolume) -> Result<RemoteHead> {
        let current = self
            .volume_data
            .load_volume(&volume.attached.volume.volume_id)
            .context("read current volume head")?;
        anyhow::ensure!(
            current.lease_owner.as_ref() == Some(&volume.attached.serving.identity.attachment_id)
                && current.lease_epoch == volume.attached.serving.identity.attachment_epoch,
            "volume owner changed while installed"
        );
        Ok(current.head)
    }

    fn confirm_guest_ready(&self, cat: &mut ManagedCat) -> Result<()> {
        let request = RuntimeReadyRequestV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            challenge: fresh_random()?,
            runtime_incarnation: cat.runtime_incarnation.clone(),
            expected_guest_cid: 3,
            expected_guest_port: GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            expected_guest_agent_protocol_version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        };
        let vmm_pid = cat.vmm.as_ref().context("Cat has no VMM")?.id();
        let mut guest = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            &cat.vsock_socket,
            GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            self.config.guest_ready_timeout,
            vmm_pid,
        )
        .context("connect Guest RuntimeReady")?;
        let response = guest
            .runtime_ready(request.clone())
            .context("execute Guest RuntimeReady")?;
        let mut mounts = cat
            .volumes
            .iter()
            .filter_map(|volume| {
                volume
                    .requested
                    .as_ref()
                    .map(|requested| ExpectedPersistentMount {
                        requested: requested.clone(),
                        volume_id: volume.attached.volume.volume_id.clone(),
                        filesystem_uuid: requested.filesystem_uuid.clone(),
                        size_bytes: volume.attached.volume.size_bytes,
                        guest_device: volume.guest_device.clone(),
                    })
            })
            .collect::<Vec<_>>();
        mounts.sort_by(|left, right| left.requested.disk_id.cmp(&right.requested.disk_id));
        confirm_complete_mount_set(&request, &response, &ExpectedPersistentMountSet { mounts })
            .context("confirm complete PersistentDisk mount set")?;
        Ok(())
    }

    fn quiesce(&self, cat: &ManagedCat) -> Result<()> {
        let vmm_pid = cat.vmm.as_ref().context("Running Cat has no VMM")?.id();
        let mut guest = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            &cat.vsock_socket,
            GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            self.config.effect_timeout,
            vmm_pid,
        )
        .context("connect Guest for syncfs")?;
        guest.syncfs().context("sync Guest filesystems")?;
        for volume in &cat.volumes {
            self.drain_volume(volume)?;
        }
        Ok(())
    }

    fn drain_volume(&self, volume: &LocalVolume) -> Result<()> {
        if let Some(blockd) = &volume.blockd {
            let payload = blockd_control(
                &volume.control_socket,
                BlockdControlCommand::Drain,
                self.config.effect_timeout,
            )?;
            let generation = payload
                .parse::<i64>()
                .context("blockd drain generation is invalid")?;
            anyhow::ensure!(generation >= 0, "blockd drain generation is negative");
            let status = blockd_status(&volume.control_socket, self.config.effect_timeout)?;
            validate_blockd_status(volume, &status)?;
            anyhow::ensure!(
                status.unpublished_generations == 0
                    && status.local_durable_generation == status.remote_durable_generation,
                "blockd did not converge to remote durability"
            );
            anyhow::ensure!(blockd.id() > 0, "blockd process identity is invalid");
        }
        Ok(())
    }

    fn make_warm(
        &self,
        cat: &mut ManagedCat,
        cancellation: &SemanticActionCancellation,
    ) -> Result<()> {
        match cat.state {
            CatState::Running => {
                self.quiesce(cat)?;
                ch::pause(&cat.api_socket).context("pause Cloud Hypervisor for Warm")?;
            }
            CatState::Suspended => {}
            other => bail!("installed Warm cannot start from {other:?}"),
        }
        check_cancellation(cancellation, CatAction::Warm)?;
        if cat.snapshot_directory.exists() {
            remove_managed_tree(&cat.snapshot_directory)?;
        }
        ch::snapshot(&cat.api_socket, &cat.snapshot_directory)
            .context("snapshot Cloud Hypervisor")?;
        ch::sync_memory_backing(&cat.memory_file).context("sync Warm memory backing")?;
        cat.state = CatState::Warm;
        self.stop_vmm(cat);
        self.stop_frontends(cat, true)?;
        Ok(())
    }

    fn restore_warm(
        &self,
        cat: &mut ManagedCat,
        cancellation: &SemanticActionCancellation,
    ) -> Result<()> {
        anyhow::ensure!(
            cat.snapshot_directory.is_dir(),
            "Warm snapshot directory is absent"
        );
        check_cancellation(cancellation, CatAction::Run)?;
        anyhow::ensure!(
            self.config.ch.boot_contract.is_none() || cat.boot_descriptors.is_some(),
            "Warm restore lost its verified Guest boot descriptors"
        );
        let disks = self.start_block_frontends(cat, true)?;
        cat.vmm = Some(
            ch::spawn_vmm(&ChSpawn {
                cfg: &self.config.ch,
                api_sock: &cat.api_socket,
                vsock_sock: &cat.vsock_socket,
                serial_log: &cat.serial_log,
                cpus: cat.config.cpu,
                memory_mib: bytes_to_mib(cat.config.memory_bytes)?,
                memory_file: None,
                disks: &disks,
                restore_from: Some(&cat.snapshot_directory),
                network: None,
            })
            .context("restore Cloud Hypervisor from Warm snapshot")?,
        );
        self.meter_vmm(cat);
        let deadline = deadline_after(self.config.effect_timeout)?;
        loop {
            if let Some(status) = cat
                .vmm
                .as_mut()
                .context("Warm restore has no VMM")?
                .try_wait()
                .context("poll Warm Cloud Hypervisor")?
            {
                bail!("Warm Cloud Hypervisor exited before resume: {status}");
            }
            if ch::resume(&cat.api_socket).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                bail!("Warm Cloud Hypervisor resume timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.wait_for_guest(cat)?;
        self.confirm_guest_ready(cat)?;
        remove_managed_tree(&cat.snapshot_directory)?;
        cat.state = CatState::Running;
        Ok(())
    }

    fn stop_cat(
        &self,
        cat: &mut ManagedCat,
        release_volumes: bool,
        cancellation: &SemanticActionCancellation,
    ) -> Result<()> {
        match cat.state {
            CatState::Suspended => {
                ch::resume(&cat.api_socket).context("resume Cat before stop")?;
                cat.state = CatState::Running;
                self.wait_for_guest(cat)?;
                self.quiesce(cat)?;
            }
            CatState::Running => self.quiesce(cat)?,
            CatState::Warm | CatState::Cold => {}
            other => bail!("installed stop cannot start from {other:?}"),
        }
        check_cancellation(cancellation, CatAction::Destroy)?;
        if cat.vmm.is_some() {
            if let Ok(mut guest) = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
                &cat.vsock_socket,
                GUEST_HOST_CONTROL_VSOCK_PORT_V1,
                self.config.effect_timeout,
                cat.vmm.as_ref().expect("VMM was checked").id(),
            ) {
                let _ = guest.shutdown();
            }
            self.stop_vmm(cat);
        }
        self.stop_frontends(cat, true)?;
        self.meters.close(cat.cat_id.as_str());
        cat.state = CatState::Cold;
        if release_volumes {
            for volume in &cat.volumes {
                self.volumes
                    .detach_volume(&volume.attached)
                    .context("detach stopped Cat volume")?;
            }
            for volume in &cat.volumes {
                remove_managed_tree(&volume.data_directory)?;
            }
        }
        remove_managed_tree(&cat.runtime_directory)?;
        Ok(())
    }

    fn stop_cat_for_destroy(
        &self,
        cat: &mut ManagedCat,
        cancellation: &SemanticActionCancellation,
    ) -> Result<()> {
        let result = self
            .stop_cat(cat, true, cancellation)
            .context("stop installed Cat for destroy");
        if let Err(graceful_error) = &result {
            // Destroy is strong stop authority for this exact installed Cat.
            // A failed Guest resume/readiness/quiesce cannot leave its VMM
            // or dedicated frontends running, but the failed graceful stop
            // must not continue into volume release or RootDisk deletion.
            self.stop_vmm(cat);
            if let Err(cleanup_error) = self.stop_frontends(cat, false) {
                tracing::error!(
                    cat_id = cat.cat_id.as_str(),
                    graceful_error = %format!("{graceful_error:#}"),
                    cleanup_error = %format!("{cleanup_error:#}"),
                    "Destroy strong-stop frontend cleanup failed"
                );
            }
            self.meters.close(cat.cat_id.as_str());
        }
        result
    }

    fn stop_cat_without_release(&self, cat: &mut ManagedCat) {
        if cat.state == CatState::Suspended {
            let _ = ch::resume(&cat.api_socket);
        }
        self.stop_vmm(cat);
        let _ = self.stop_frontends(cat, false);
        self.meters.close(cat.cat_id.as_str());
    }

    fn stop_vmm(&self, cat: &mut ManagedCat) {
        if let Some(mut child) = cat.vmm.take() {
            stop_child(&mut child, Duration::from_secs(2));
        }
    }

    /// Open the billing meter for this Cat runtime. The runtime incarnation is
    /// the usage source epoch: a replaced runtime bills from its own baseline
    /// and can never continue an older epoch's counters.
    fn open_meter(&self, cat: &ManagedCat) {
        if let Err(error) = self.meters.open(&cat.cat_id, &cat.runtime_incarnation) {
            tracing::error!(
                cat_id = cat.cat_id.as_str(),
                error = %format!("{error:#}"),
                "could not open the Cat usage meter; this runtime will not be billed"
            );
        }
    }

    /// Charge the live VMM to the Cat's meter. Called for the fresh launch and
    /// again for every Warm restore into the same runtime epoch.
    fn meter_vmm(&self, cat: &ManagedCat) {
        let Some(vmm) = cat.vmm.as_ref() else {
            return;
        };
        if let Err(error) = self.meters.place(cat.cat_id.as_str(), vmm.id()) {
            tracing::error!(
                cat_id = cat.cat_id.as_str(),
                error = %format!("{error:#}"),
                "could not charge the Guest VMM to the Cat usage meter"
            );
        }
    }

    fn stop_frontends(&self, cat: &mut ManagedCat, require_drain: bool) -> Result<()> {
        if require_drain {
            // Drain every live frontend before stopping any of them.  If one
            // drain is ambiguous, leaving all processes and attachments in
            // place is the only retryable, fail-closed outcome.
            for volume in &mut cat.volumes {
                if volume.blockd.is_none() {
                    continue;
                }
                if let Err(error) = blockd_control(
                    &volume.control_socket,
                    BlockdControlCommand::Drain,
                    self.config.effect_timeout,
                ) {
                    let clean_exit = volume
                        .blockd
                        .as_mut()
                        .and_then(|child| child.try_wait().ok())
                        .flatten()
                        .is_some_and(|status| status.success());
                    if !clean_exit {
                        return Err(error).context("drain blockd before frontend stop");
                    }
                }
            }
        }

        for volume in &mut cat.volumes {
            if let Some(device) = volume.nbd_device.as_deref() {
                ch::nbd_detach(&self.config.ch, device);
            }
            if let Some(mut child) = volume.blockd.take() {
                stop_child(&mut child, Duration::from_secs(2));
            }
            let _ = fs::remove_file(&volume.control_socket);
            let _ = fs::remove_file(&volume.io_socket);
        }
        Ok(())
    }

    fn destroy_root(&self, cat_id: &Id, config: &NodedCatConfig) -> Result<()> {
        let root = self.root_descriptor(cat_id, config)?;
        match self
            .volumes
            .begin_root_delete(&root)
            .context("begin RootDisk delete")?
        {
            RootDeleteState::Absent => return Ok(()),
            RootDeleteState::Deleting => {}
        }
        let deadline = deadline_after(self.config.effect_timeout)?;
        loop {
            match delete_volume_objects_page(
                self.blob.as_ref(),
                &root.volume_id,
                DELETE_PAGE_SIZE,
                deadline,
            )
            .map_err(|error| anyhow::anyhow!(error))
            .context("delete RootDisk objects")?
            {
                DeletePrefixPage::Empty
                | DeletePrefixPage::Progress {
                    now_empty: true, ..
                } => break,
                DeletePrefixPage::Progress {
                    now_empty: false, ..
                } => {}
            }
        }
        self.volumes
            .complete_root_delete(&root)
            .context("complete RootDisk delete")
    }
}

fn persistent_binding(
    cat: &ManagedCat,
    volume: &LocalVolume,
    initialization: FilesystemInitialization,
) -> Result<PersistentFilesystemBinding> {
    let requested = volume
        .requested
        .as_ref()
        .context("PersistentDisk request is absent")?;
    let CatVolumeRole::Persistent {
        cat_id,
        filesystem_uuid,
        mount_path,
        ..
    } = &volume.attached.volume.role
    else {
        bail!("PersistentDisk device has RootDisk role")
    };
    anyhow::ensure!(
        cat_id == &cat.cat_id
            && filesystem_uuid == &requested.filesystem_uuid
            && mount_path.as_str() == requested.mount_path.as_str(),
        "PersistentDisk product and storage binding changed"
    );
    Ok(PersistentFilesystemBinding {
        runtime_incarnation: cat.runtime_incarnation.clone(),
        volume_intent_id: volume.attached.volume.volume_id.clone(),
        disk_id: volume.attached.volume.disk_id.clone(),
        volume_id: volume.attached.volume.volume_id.clone(),
        attachment_id: volume.attached.serving.identity.attachment_id.clone(),
        attachment_epoch: volume.attached.serving.identity.attachment_epoch,
        size_bytes: volume.attached.volume.size_bytes,
        guest_device: volume.guest_device.clone(),
        filesystem_uuid: filesystem_uuid.clone(),
        mount_path: mount_path.clone(),
        initialization,
    })
}

fn filesystem_request(
    binding: PersistentFilesystemBinding,
    operation: FilesystemControlOperationV1,
    expected_head: RemoteHead,
    timeout_ms: u32,
) -> Result<FilesystemControlRequestV1> {
    let request = FilesystemControlRequestV1 {
        version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        challenge: fresh_random()?,
        timeout_ms,
        operation,
        filesystem: Box::new(binding),
        expected_head,
    };
    request
        .validate()
        .context("construct Guest filesystem request")?;
    Ok(request)
}

fn engine_config(attached: &AttachedVolume, data_directory: &Path) -> Result<EngineConfig> {
    Ok(EngineConfig {
        volume_id: attached.volume.volume_id.to_string(),
        data_dir: data_directory.to_path_buf(),
        attachment_id: attached.serving.identity.attachment_id.to_string(),
        lease_ttl_ms: i64::try_from(attached.serving.lease_duration_ms())
            .context("volume lease duration exceeds i64")?,
        durability: DurabilityMode::Strict,
        max_staged_bytes: DEFAULT_MAX_STAGED_BYTES,
        max_staged_packs: DEFAULT_MAX_STAGED_PACKS,
        max_local_bytes: DEFAULT_MAX_LOCAL_BYTES,
    })
}

fn blockd_status(socket: &Path, timeout: Duration) -> Result<DurabilityStatus> {
    let payload = blockd_control(socket, BlockdControlCommand::Status, timeout)?;
    serde_json::from_str(&payload).context("decode blockd status")
}

fn blockd_control(
    socket: &Path,
    command: BlockdControlCommand,
    timeout: Duration,
) -> Result<String> {
    const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
    anyhow::ensure!(!timeout.is_zero(), "blockd control timeout is zero");
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect blockd control socket {}", socket.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(command.as_wire().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut bytes = Vec::new();
    BufReader::new(stream)
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_RESPONSE_BYTES,
        "blockd control response exceeds its byte limit"
    );
    let response = std::str::from_utf8(&bytes).context("blockd response is not UTF-8")?;
    match BlockdControlResponse::parse_wire(response)? {
        BlockdControlResponse::Ok(payload) => Ok(payload),
        BlockdControlResponse::Error(message) => bail!("blockd rejected {command}: {message}"),
    }
}

fn validate_blockd_status(volume: &LocalVolume, status: &DurabilityStatus) -> Result<()> {
    let scope_id = Id::new(format!("cats-blockd-{}", volume.process_identity_token))
        .context("blockd scope ID is invalid")?;
    anyhow::ensure!(
        status.volume_id == volume.attached.volume.volume_id.as_str()
            && status.attachment_id == volume.attached.serving.identity.attachment_id.as_str()
            && status.attachment_epoch == Some(volume.attached.serving.identity.attachment_epoch)
            && status.node_id.as_ref() == Some(&volume.attached.serving.identity.node_id)
            && status.placement_epoch == Some(volume.attached.serving.identity.placement_epoch)
            && status.size_bytes == Some(volume.attached.volume.size_bytes)
            && status.scope_id.as_ref() == Some(&scope_id)
            && status.process_identity_token.as_ref() == Some(&volume.process_identity_token)
            && status.device_ownership_token.as_ref() == Some(&volume.device_ownership_token)
            && status.guest_device_serial.as_ref() == Some(&volume.guest_device.serial)
            && status.control_only == Some(false)
            && status.guest_io_enabled == Some(true)
            && status.mode == "strict"
            && !status.fenced,
        "blockd readiness identity does not match the installed volume"
    );
    Ok(())
}

fn fresh_random() -> Result<RandomId128> {
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .context("generated random identity is invalid")
}

fn derived_random(domain: &[u8], fields: &[&str]) -> Result<RandomId128> {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_le_bytes());
        digest.update(field.as_bytes());
    }
    let encoded = hex::encode(digest.finalize());
    RandomId128::new(encoded[..32].to_owned()).context("derived random identity is invalid")
}

fn derived_id(prefix: &str, domain: &[u8], field: &str) -> Result<Id> {
    Id::new(format!("{prefix}{}", derived_random(domain, &[field])?))
        .context("derived resource ID is invalid")
}

fn persistent_device_serial(disk_id: &Id) -> Result<Id> {
    let digest = derived_random(DEVICE_SERIAL_SCOPE, &[disk_id.as_str()])?;
    Id::new(format!("cats-{}", &digest.as_str()[..15]))
        .context("derived PersistentDisk serial is invalid")
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).expect("zero generation is valid"),
        root_hash: None,
        root_object_id: None,
    }
}

fn bytes_to_mib(bytes: u64) -> Result<u64> {
    bytes
        .checked_add((1 << 20) - 1)
        .map(|rounded| rounded >> 20)
        .filter(|mib| *mib > 0)
        .context("Guest memory size overflow")
}

fn deadline_after(duration: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(duration)
        .context("installed effect deadline overflow")
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn open_host_lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open provisioned Host lock {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect provisioned Host lock {}", path.display()))?;
    // SAFETY: geteuid has no pointer arguments and cannot outlive this call.
    let effective_uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == effective_uid
            && metadata.permissions().mode() & 0o777 == 0o600,
        "provisioned Host lock is not an owner-only single-link file"
    );
    // SAFETY: `file` owns this descriptor for the lifetime of InstalledInner;
    // flock retains neither the descriptor pointer nor any Rust reference.
    let result = unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    anyhow::ensure!(result == 0, "another noded already owns the Host lock");
    Ok(file)
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("create private directory {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "private directory is not one real directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("protect private directory {}", path.display()))
}

fn write_exact_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("open exact file {}", path.display()))?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.file_type().is_file()
                && metadata.nlink() == 1
                && metadata.len() == bytes.len() as u64,
            "existing exact file has unsafe metadata"
        );
        let mut observed = Vec::with_capacity(bytes.len());
        file.read_to_end(&mut observed)?;
        anyhow::ensure!(observed == bytes, "existing exact file content changed");
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("create exact file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if let Some(parent) = path.parent() {
        OpenOptions::new().read(true).open(parent)?.sync_all()?;
    }
    Ok(())
}

fn clear_managed_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect managed directory {}", path.display()))?;
    anyhow::ensure!(
        path.is_absolute()
            && path.components().count() > 2
            && metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink(),
        "managed cleanup root is not one narrow real directory"
    );
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() && !file_type.is_symlink() {
            remove_managed_tree(&entry_path)?;
        } else {
            fs::remove_file(&entry_path)
                .with_context(|| format!("remove managed file {}", entry_path.display()))?;
        }
    }
    Ok(())
}

fn remove_managed_tree(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect managed tree {}", path.display()))?;
    anyhow::ensure!(
        path.is_absolute()
            && path.components().count() > 3
            && metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink(),
        "managed tree is not one narrow real directory"
    );
    fs::remove_dir_all(path).with_context(|| format!("remove managed tree {}", path.display()))
}

fn stop_child(child: &mut Child, grace: Duration) {
    let deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

fn installed_error(message: impl Into<String>) -> SemanticEffectError {
    SemanticEffectError::new(
        cats_api::semantic_control::SemanticErrorCode::InternalError,
        message,
    )
}

fn format_installed_error(error: anyhow::Error) -> SemanticEffectError {
    installed_error(format!("{error:#}"))
}

fn check_cancellation(cancellation: &SemanticActionCancellation, action: CatAction) -> Result<()> {
    if action != CatAction::Destroy && cancellation.is_cancelled() {
        bail!("installed action was cancelled by destroy");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use cats_api::runtime_reconciliation::{
        Epoch, FenceEpoch, NormalAcquireRequest, NormalAcquireResult, UnixMillis, VolumeDurability,
        VolumeRecord,
    };
    use cats_storage::authority::{
        authorized_serving_attachment_from_direct_acquire, AuthorityError,
        DirectAcquireServingInput, RenewLeaseRequest, RenewLeaseResult, VolumeHeadCasRequest,
        VolumeHeadCasResult,
    };

    use super::*;

    #[test]
    fn installed_effect_error_preserves_the_physical_cause_chain() {
        let error = anyhow::anyhow!("inner device failure").context("outer Guest operation");
        let mapped = format_installed_error(error);

        assert_eq!(
            mapped.message,
            "outer Guest operation: inner device failure"
        );
    }

    struct RecordingRootStore {
        root: CatVolume,
        attached: AttachedVolume,
        detach_calls: AtomicUsize,
        begin_delete_calls: AtomicUsize,
    }

    impl CatVolumeStore for RecordingRootStore {
        fn ensure_root_volume(
            &self,
            _spec: &RootVolumeSpec,
        ) -> cats_storage::authority::Result<CatVolume> {
            Ok(self.root.clone())
        }

        fn load_persistent_volume(
            &self,
            _workspace_id: &Id,
            _cat_id: &Id,
            _disk_id: &Id,
            _volume_id: &Id,
            _filesystem_uuid: &RandomId128,
            _mount_path: &HostPath,
        ) -> cats_storage::authority::Result<CatVolume> {
            Err(AuthorityError::NotFound)
        }

        fn attach_volume(
            &self,
            request: &VolumeAttachRequest,
        ) -> cats_storage::authority::Result<AttachedVolume> {
            assert_eq!(request.volume, self.root);
            Ok(self.attached.clone())
        }

        fn detach_volume(&self, attached: &AttachedVolume) -> cats_storage::authority::Result<()> {
            assert_eq!(attached, &self.attached);
            self.detach_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn detach_node_volumes(&self, _node_id: &Id) -> cats_storage::authority::Result<usize> {
            Ok(0)
        }

        fn commit_persistent_initialization(
            &self,
            _commit: &PersistentInitializationCommit,
        ) -> cats_storage::authority::Result<CatVolume> {
            Err(AuthorityError::BackendUnknown)
        }

        fn begin_root_delete(
            &self,
            _volume: &CatVolume,
        ) -> cats_storage::authority::Result<RootDeleteState> {
            self.begin_delete_calls.fetch_add(1, Ordering::SeqCst);
            Err(AuthorityError::BackendUnknown)
        }

        fn complete_root_delete(&self, _volume: &CatVolume) -> cats_storage::authority::Result<()> {
            Err(AuthorityError::BackendUnknown)
        }
    }

    struct UnusedVolumeData;

    impl VolumeDataAuthority for UnusedVolumeData {
        fn load_volume(&self, _volume_id: &Id) -> cats_storage::authority::Result<VolumeRecord> {
            Err(AuthorityError::BackendUnknown)
        }

        fn renew_lease(
            &self,
            _request: &RenewLeaseRequest,
        ) -> cats_storage::authority::Result<RenewLeaseResult> {
            Err(AuthorityError::BackendUnknown)
        }

        fn compare_and_swap_head(
            &self,
            _request: &VolumeHeadCasRequest,
        ) -> cats_storage::authority::Result<VolumeHeadCasResult> {
            Err(AuthorityError::BackendUnknown)
        }
    }

    struct MissingBlob;

    impl BlobStore for MissingBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
            Err(cats_storage::BlobError::Backend {
                key: "unused".to_owned(),
                message: "unexpected write".to_owned(),
            })
        }

        fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            Err(cats_storage::BlobError::NotFound(key.to_owned()))
        }

        fn exists(&self, _key: &str) -> cats_storage::blob::Result<bool> {
            Ok(false)
        }

        fn delete(&self, _key: &str) -> cats_storage::blob::Result<()> {
            Ok(())
        }

        fn list(&self, _prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    fn root_store() -> Arc<RecordingRootStore> {
        let workspace_id = Id::new("ws_cleanup").expect("workspace ID");
        let cat_id = Id::new("cat_cleanup").expect("Cat ID");
        let volume_id = Id::new("vol_cleanup").expect("volume ID");
        let head = blank_head();
        let root = CatVolume {
            workspace_id,
            disk_id: Id::new("disk_cleanup").expect("disk ID"),
            volume_id: volume_id.clone(),
            size_bytes: 4 << 20,
            durability: VolumeDurability::Strict,
            head: head.clone(),
            role: CatVolumeRole::Root { cat_id },
        };
        let transition_id =
            RandomId128::new("11111111111111111111111111111111").expect("transition ID");
        let request = NormalAcquireRequest {
            volume_id: volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: Id::new("attach_cleanup").expect("attachment ID"),
            expected_unowned_epoch: FenceEpoch::new(0).expect("zero epoch"),
            placement_epoch: Epoch::new(1).expect("placement epoch"),
            lease_duration_ms: 5_000,
        };
        let result = NormalAcquireResult {
            volume_id,
            transition_id,
            attachment_id: request.attachment_id.clone(),
            resulting_epoch: FenceEpoch::new(1).expect("attachment epoch"),
            resulting_head: head.clone(),
            lease_expires_at: UnixMillis::new(6_000).expect("lease expiry"),
        };
        let serving =
            authorized_serving_attachment_from_direct_acquire(DirectAcquireServingInput {
                node_id: Id::new("node_cleanup").expect("Node ID"),
                size_bytes: root.size_bytes,
                durability: root.durability,
                request,
                result,
                current_head: head,
                current_lease_expires_at: UnixMillis::new(6_000).expect("lease expiry"),
            })
            .expect("direct attachment");
        Arc::new(RecordingRootStore {
            root: root.clone(),
            attached: AttachedVolume {
                volume: root,
                serving,
            },
            detach_calls: AtomicUsize::new(0),
            begin_delete_calls: AtomicUsize::new(0),
        })
    }

    #[test]
    fn destroy_stops_fake_vmm_when_guest_is_unavailable_and_preserves_root() {
        let directory = tempfile::tempdir_in("/tmp").expect("temporary installed directory");
        let socket_root = directory.path().join("sockets");
        let host_lock = directory.path().join("host.lock");
        drop(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&host_lock)
                .expect("provision Host lock"),
        );
        let config = InstalledCatConfig {
            node_id: Id::new("node_cleanup").expect("Node ID"),
            state_directory: directory.path().join("state"),
            runtime_directory: directory.path().join("runtime"),
            host_lock,
            blockd_binary: PathBuf::from("/unused/cats-blockd"),
            blockd_socket_root: ManagedBlockdSocketRoot::from_canonical_path(
                HostPath::new(socket_root.to_string_lossy().into_owned()).expect("socket root"),
            )
            .expect("managed socket root"),
            golden_root_cache_image: directory.path().join("golden-root-cache/rootfs.ext4"),
            metadata_store: AdapterSelection::new(
                "postgres",
                cats_storage::AdapterConfig::from_cli(Vec::<String>::new())
                    .expect("empty metadata config"),
            ),
            object_store: AdapterSelection::new(
                "file",
                cats_storage::AdapterConfig::from_cli(Vec::<String>::new())
                    .expect("empty object config"),
            ),
            ch: ChConfig {
                block_direct: false,
                ch_bin: PathBuf::from("/unused/cloud-hypervisor"),
                kernel: PathBuf::from("/unused/vmlinuz"),
                initramfs: None,
                boot_contract: None,
                cmdline: String::new(),
                seed_image: None,
                block_path: BlockPath::VhostUser,
                vhost_user_queues: 1,
                vhost_user_queue_size: 256,
                nbd_client_bin: PathBuf::from("/unused/nbd-client"),
                nbd_devices: 1,
                ip_bin: PathBuf::from("/unused/ip"),
            },
            root_size_bytes: 4 << 20,
            lease_duration_ms: 5_000,
            effect_timeout: Duration::from_millis(50),
            guest_ready_timeout: Duration::from_millis(50),
        };
        let volumes = root_store();
        let effects = InstalledSemanticCatEffects::new(
            config,
            Arc::clone(&volumes) as Arc<dyn CatVolumeStore>,
            Arc::new(UnusedVolumeData),
            Arc::new(MissingBlob),
            Arc::new(
                CatUsageMeters::new(Id::new("node_test").expect("node id"), None)
                    .expect("unmetered test Node"),
            ),
        )
        .expect("installed effects");
        let request_config = NodedCatConfig {
            workspace_id: Id::new("ws_cleanup").expect("workspace ID"),
            cpu: 1,
            memory_bytes: 1 << 30,
            boot_image: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            mounts: Vec::new(),
        };
        let runtime_directory = effects.inner.config.runtime_directory.join("cat_cleanup");
        create_private_directory(&runtime_directory).expect("create Cat runtime directory");
        let volume_data_directory = effects
            .inner
            .config
            .state_directory
            .join("data/cat_cleanup/vol_cleanup");
        create_private_directory(&volume_data_directory).expect("create volume data directory");
        let fake_vmm = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn fake VMM");
        let fake_vmm_pid = fake_vmm.id();
        let fake_frontend = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn fake block frontend");
        let fake_frontend_pid = fake_frontend.id();
        let lane = effects.inner.lane("cat_cleanup");
        *lane.cat() = Some(ManagedCat {
            cat_id: Id::new("cat_cleanup").expect("Cat ID"),
            config: request_config.clone(),
            state: CatState::Running,
            runtime_incarnation: RandomId128::new("22222222222222222222222222222222")
                .expect("runtime incarnation"),
            api_socket: runtime_directory.join("vmm-api.sock"),
            // No listener exists: the fake VMM models an unavailable Guest.
            vsock_socket: runtime_directory.join("missing-vmm-vsock.sock"),
            serial_log: runtime_directory.join("guest-serial.log"),
            memory_file: runtime_directory.join(GUEST_MEMORY_FILE),
            snapshot_directory: runtime_directory.join("warm-snapshot"),
            runtime_directory,
            volumes: vec![LocalVolume {
                requested: None,
                attached: volumes.attached.clone(),
                data_directory: volume_data_directory.clone(),
                authorization_file: directory.path().join("unused-authorization.json"),
                process_identity_token: RandomId128::new("33333333333333333333333333333333")
                    .expect("process identity"),
                device_ownership_token: RandomId128::new("44444444444444444444444444444444")
                    .expect("device ownership"),
                guest_device: GuestDeviceIdentity {
                    serial: Id::new(ROOT_DEVICE_SERIAL).expect("Root device serial"),
                    slot: 0,
                },
                control_socket: directory.path().join("unused-control.sock"),
                io_socket: directory.path().join("unused-io.sock"),
                blockd: Some(fake_frontend),
                nbd_device: None,
            }],
            vmm: Some(fake_vmm),
            boot_descriptors: None,
        });

        let error = effects
            .inner
            .apply(
                SemanticEffectRequest {
                    cat_id: "cat_cleanup".to_owned(),
                    action: CatAction::Destroy,
                    config: request_config,
                },
                SemanticActionCancellation::new(),
            )
            .expect_err("unavailable Guest must fail graceful destroy");

        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("stop installed Cat for destroy"));
        assert!(error_chain.contains("connect Guest for syncfs"));
        let mut managed = lane.cat();
        let cat = managed.as_mut().expect("failed destroy retains Cat state");
        let vmm_was_stopped = cat.vmm.is_none();
        let frontend_was_stopped = cat.volumes[0].blockd.is_none();
        if let Some(mut leaked_vmm) = cat.vmm.take() {
            let _ = leaked_vmm.kill();
            let _ = leaked_vmm.wait();
        }
        if let Some(mut leaked_frontend) = cat.volumes[0].blockd.take() {
            let _ = leaked_frontend.kill();
            let _ = leaked_frontend.wait();
        }
        assert!(vmm_was_stopped, "Destroy must stop the exact retained VMM");
        assert!(
            frontend_was_stopped,
            "Destroy must stop the retained Cat's dedicated frontends"
        );
        // SAFETY: kill with signal zero only probes the checked positive PID;
        // stop_vmm has already waited for that exact child.
        let probe = unsafe {
            libc::kill(
                i32::try_from(fake_vmm_pid).expect("fake VMM PID fits pid_t"),
                0,
            )
        };
        assert_eq!(probe, -1, "fake VMM must no longer exist");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        // SAFETY: as above, this only probes the checked positive PID of the
        // exact frontend child retained by this Cat.
        let frontend_probe = unsafe {
            libc::kill(
                i32::try_from(fake_frontend_pid).expect("fake frontend PID fits pid_t"),
                0,
            )
        };
        assert_eq!(frontend_probe, -1, "fake frontend must no longer exist");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(cat.volumes.len(), 1);
        assert!(volume_data_directory.is_dir());
        assert_eq!(volumes.detach_calls.load(Ordering::SeqCst), 0);
        assert_eq!(volumes.begin_delete_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_root_manifest_releases_the_new_attachment() {
        let directory = tempfile::tempdir_in("/tmp").expect("temporary installed directory");
        let socket_root = directory.path().join("sockets");
        let golden_root_cache_directory = directory.path().join("golden-root-cache");
        let host_lock = directory.path().join("host.lock");
        drop(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&host_lock)
                .expect("provision Host lock"),
        );
        let config = InstalledCatConfig {
            node_id: Id::new("node_cleanup").expect("Node ID"),
            state_directory: directory.path().join("state"),
            runtime_directory: directory.path().join("runtime"),
            host_lock,
            blockd_binary: PathBuf::from("/unused/cats-blockd"),
            blockd_socket_root: ManagedBlockdSocketRoot::from_canonical_path(
                HostPath::new(socket_root.to_string_lossy().into_owned()).expect("socket root"),
            )
            .expect("managed socket root"),
            golden_root_cache_image: golden_root_cache_directory.join("rootfs.ext4"),
            metadata_store: AdapterSelection::new(
                "postgres",
                cats_storage::AdapterConfig::from_cli(Vec::<String>::new())
                    .expect("empty metadata config"),
            ),
            object_store: AdapterSelection::new(
                "file",
                cats_storage::AdapterConfig::from_cli(Vec::<String>::new())
                    .expect("empty object config"),
            ),
            ch: ChConfig {
                block_direct: false,
                ch_bin: PathBuf::from("/unused/cloud-hypervisor"),
                kernel: PathBuf::from("/unused/vmlinuz"),
                initramfs: None,
                boot_contract: None,
                cmdline: String::new(),
                seed_image: None,
                block_path: BlockPath::VhostUser,
                vhost_user_queues: 1,
                vhost_user_queue_size: 256,
                nbd_client_bin: PathBuf::from("/unused/nbd-client"),
                nbd_devices: 1,
                ip_bin: PathBuf::from("/unused/ip"),
            },
            root_size_bytes: 4 << 20,
            lease_duration_ms: 5_000,
            effect_timeout: Duration::from_secs(1),
            guest_ready_timeout: Duration::from_secs(1),
        };
        let volumes = root_store();
        let effects = InstalledSemanticCatEffects::new(
            config,
            Arc::clone(&volumes) as Arc<dyn CatVolumeStore>,
            Arc::new(UnusedVolumeData),
            Arc::new(MissingBlob),
            Arc::new(
                CatUsageMeters::new(Id::new("node_test").expect("node id"), None)
                    .expect("unmetered test Node"),
            ),
        )
        .expect("installed effects");
        assert!(golden_root_cache_directory.is_dir());
        let request = NodedCatConfig {
            workspace_id: Id::new("ws_cleanup").expect("workspace ID"),
            cpu: 1,
            memory_bytes: 1 << 30,
            boot_image: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            mounts: Vec::new(),
        };

        let error = match effects.inner.start_fresh(
            &Id::new("cat_cleanup").expect("Cat ID"),
            &request,
            &SemanticActionCancellation::new(),
        ) {
            Ok(_) => panic!("missing manifest must fail create"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("read immutable Root image manifest"));
        assert_eq!(volumes.detach_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn host_lock_excludes_a_second_installed_agent() {
        let directory = tempfile::tempdir().expect("temporary Host-lock directory");
        let path = directory.path().join("host.lock");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create Host lock fixture");
        drop(file);
        let first = open_host_lock(&path).expect("first Agent owns Host lock");
        let second = open_host_lock(&path).expect_err("second Agent must be excluded");
        assert!(second.to_string().contains("already owns"));
        drop(first);
        open_host_lock(&path).expect("Host lock is released with the Agent");
    }
}

//! Provider-private Guest RuntimeReady proof for the Running tail.
//!
//! The Guest response is never authority by itself. A caller must bracket one
//! fresh challenge with the exact VMM proof from the same complete inventory
//! pass. This module then joins every Guest device and mount to the retained
//! launch identity and Desired volume set. The public transport/mount values
//! are only projections of the resulting opaque evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

use anyhow::Context as _;
use cats_api::guest::{
    RuntimeReadyRequestV1, RuntimeReadyResponseV1, GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
    GUEST_HOST_CONTROL_VSOCK_PORT_V1,
};
use cats_api::runtime_reconciliation::{
    ContractVersion, DesiredRuntimeSpec, DiskKind, GuestTransportEvidence, MountAccess,
    ObservedMount, PreparedDeviceInput, RandomId128, RuntimeCheckpoint, RuntimeLaunchIdentity,
};

use crate::guest_client::GuestClient;
use crate::runtime_spine::RuntimePhysicalReadContext;

use super::vmm_process::ExactVmmProcessProof;

/// Provider-private proof of the exact mounted Root + Persistent device set.
///
/// Device major/minor values remain provider-private. They make a later fresh
/// challenge compare the complete Guest physical view rather than only the
/// smaller public `ObservedMount` projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactGuestMountedSetProof {
    response: RuntimeReadyResponseV1,
    guest_transport: GuestTransportEvidence,
    mounts: Vec<ObservedMount>,
}

impl ExactGuestMountedSetProof {
    pub(crate) fn guest_transport(&self) -> &GuestTransportEvidence {
        &self.guest_transport
    }

    pub(crate) fn mounts(&self) -> &[ObservedMount] {
        &self.mounts
    }

    fn same_physical_facts(&self, other: &Self) -> bool {
        self.guest_transport == other.guest_transport
            && self.mounts == other.mounts
            && self.response.guest_boot_id == other.response.guest_boot_id
            && self.response.devices == other.response.devices
            && self.response.mounts == other.response.mounts
    }

    fn ensure_same_physical_facts(&self, other: &Self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.same_physical_facts(other),
            "exact Guest mounted set changed before admission"
        );
        Ok(())
    }

    /// Repeat the complete challenge while the retained VMM stays exact and
    /// require the private device/mount set to be byte-for-byte unchanged.
    /// This is shared by the scanner-minted proof and the final gate barrier;
    /// public `ObservedMount` values are never accepted as authority here.
    pub(crate) fn revalidate(
        &self,
        port: &dyn GuestReadyTransportPort,
        context: &dyn RuntimePhysicalReadContext,
        desired: &DesiredRuntimeSpec,
        checkpoint: &RuntimeCheckpoint,
        vmm: &ExactVmmProcessProof,
    ) -> anyhow::Result<()> {
        let fresh = probe_exact_guest_mounted_set(port, context, desired, checkpoint, vmm)?;
        self.ensure_same_physical_facts(&fresh)
    }

    fn from_response(
        desired: &DesiredRuntimeSpec,
        launch: &RuntimeLaunchIdentity,
        request: &RuntimeReadyRequestV1,
        response: RuntimeReadyResponseV1,
    ) -> anyhow::Result<Self> {
        response
            .validate_against(request)
            .context("validate RuntimeReady response envelope")?;
        anyhow::ensure!(
            request.runtime_incarnation == launch.runtime_incarnation
                && request.expected_guest_cid == launch.guest_cid
                && request.expected_guest_port == GUEST_HOST_CONTROL_VSOCK_PORT_V1
                && request.expected_guest_agent_protocol_version
                    == GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            "RuntimeReady challenge does not bind the retained launch"
        );

        let desired_by_intent = desired
            .volumes
            .iter()
            .map(|volume| (volume.volume_intent_id.clone(), volume))
            .collect::<BTreeMap<_, _>>();
        anyhow::ensure!(
            desired_by_intent.len() == desired.volumes.len()
                && launch.devices.len() == desired.volumes.len()
                && response.devices.len() == desired.volumes.len()
                && response.mounts.len() == desired.volumes.len(),
            "RuntimeReady volume, launch, device and mount sets are not exact"
        );

        let mut seen_intents = BTreeSet::new();
        let mut seen_mounts = BTreeSet::new();
        let mut root_count = 0usize;
        let mut mounts = Vec::with_capacity(launch.devices.len());
        for prepared in &launch.devices {
            let intent = desired_by_intent
                .get(&prepared.volume_intent_id)
                .context("retained launch device is absent from Desired")?;
            ensure_prepared_joins_desired(prepared, intent)?;
            anyhow::ensure!(
                seen_intents.insert(prepared.volume_intent_id.clone()),
                "retained launch repeats one Desired volume"
            );

            let device = response
                .devices
                .iter()
                .find(|device| device.guest_device == prepared.guest_device)
                .context("RuntimeReady lacks one retained Guest device")?;
            anyhow::ensure!(
                device.size_bytes == prepared.size_bytes,
                "RuntimeReady device size differs from retained authority"
            );
            let matching_mounts = response
                .mounts
                .iter()
                .filter(|mount| {
                    mount.device_major == device.device_major
                        && mount.device_minor == device.device_minor
                        && mount.source_path == device.device_path
                        && mount.filesystem_uuid == device.filesystem_uuid
                })
                .collect::<Vec<_>>();
            let [mount] = matching_mounts.as_slice() else {
                anyhow::bail!("RuntimeReady device does not have one exact mount")
            };
            anyhow::ensure!(
                seen_mounts.insert((mount.mount_path.clone(), mount.source_path.clone())),
                "RuntimeReady repeats one mount identity"
            );
            anyhow::ensure!(
                mount.filesystem_type.as_str() == "ext4"
                    && mount.mount_root.as_str() == "/"
                    && mount.access == MountAccess::ReadWrite,
                "RuntimeReady mount is not the exact V1 ext4 read-write shape"
            );

            match intent.disk_kind {
                DiskKind::Root => {
                    root_count += 1;
                    anyhow::ensure!(
                        intent.mount.is_none() && mount.mount_path.as_str() == "/",
                        "RuntimeReady Root is not mounted at the Guest root"
                    );
                }
                DiskKind::Persistent => {
                    let expected = intent
                        .mount
                        .as_ref()
                        .context("Persistent Desired volume lacks its mount authority")?;
                    anyhow::ensure!(
                        mount.mount_path == expected.mount_path
                            && mount.filesystem_uuid == expected.filesystem_uuid,
                        "RuntimeReady Persistent mount differs from Desired"
                    );
                }
            }

            mounts.push(ObservedMount {
                volume_id: prepared.volume_id.clone(),
                guest_device: prepared.guest_device.clone(),
                source_path: mount.source_path.clone(),
                filesystem_uuid: mount.filesystem_uuid.clone(),
                mount_path: mount.mount_path.clone(),
                access: mount.access,
                instance_count: 1,
            });
        }
        anyhow::ensure!(
            seen_intents.len() == desired.volumes.len()
                && seen_mounts.len() == response.mounts.len()
                && root_count == 1,
            "RuntimeReady does not cover the exact Desired volume set"
        );
        mounts.sort_by(|left, right| {
            (
                left.volume_id.as_str(),
                left.mount_path.as_str(),
                left.source_path.as_str(),
                left.guest_device.serial.as_str(),
                left.guest_device.slot,
                left.access,
            )
                .cmp(&(
                    right.volume_id.as_str(),
                    right.mount_path.as_str(),
                    right.source_path.as_str(),
                    right.guest_device.serial.as_str(),
                    right.guest_device.slot,
                    right.access,
                ))
        });

        let guest_port = u16::try_from(response.actual_guest_port)
            .context("RuntimeReady Guest port does not fit the public projection")?;
        let guest_transport = GuestTransportEvidence::VsockReady {
            runtime_incarnation: launch.runtime_incarnation.clone(),
            guest_cid: response.actual_guest_cid,
            guest_port,
            guest_agent_protocol_version: ContractVersion::new(u64::from(
                response.actual_guest_agent_protocol_version,
            ))
            .context("RuntimeReady protocol version exceeds the wire range")?,
            guest_boot_id: response.guest_boot_id.clone(),
        };
        Ok(Self {
            response,
            guest_transport,
            mounts,
        })
    }
}

fn ensure_prepared_joins_desired(
    prepared: &PreparedDeviceInput,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        prepared.volume_intent_id == intent.volume_intent_id
            && prepared.disk_id == intent.disk_id
            && prepared.volume_id == intent.volume_id
            && prepared.disk_kind == intent.disk_kind
            && prepared.attachment_id == intent.attachment_id
            && prepared.size_bytes == intent.size_bytes
            && prepared.durability == intent.durability
            && prepared.guest_device == intent.guest_device,
        "retained PreparedDeviceInput differs from Desired"
    );
    Ok(())
}

/// Narrow transport seam shared by the full scanner and the immediate
/// pre-linearization Running-tail revalidation.
pub(crate) trait GuestReadyTransportPort: Send + Sync {
    fn challenge(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        launch: &RuntimeLaunchIdentity,
        request: RuntimeReadyRequestV1,
    ) -> anyhow::Result<RuntimeReadyResponseV1>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PlatformGuestReadyTransportPort;

impl GuestReadyTransportPort for PlatformGuestReadyTransportPort {
    fn challenge(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        launch: &RuntimeLaunchIdentity,
        request: RuntimeReadyRequestV1,
    ) -> anyhow::Result<RuntimeReadyResponseV1> {
        context.check_active()?;
        let timeout = context
            .deadline()
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("RuntimeReady challenge deadline expired")?;
        let mut client = GuestClient::connect_hybrid_vsock_bounded(
            Path::new(launch.vsock_socket_path.as_str()),
            GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            timeout,
        )?;
        context.check_active()?;
        let response = client.runtime_ready(request)?;
        context.check_active()?;
        Ok(response)
    }
}

/// Mint one opaque Guest proof while the exact live VMM remains unchanged.
pub(crate) fn probe_exact_guest_mounted_set(
    port: &dyn GuestReadyTransportPort,
    context: &dyn RuntimePhysicalReadContext,
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    vmm: &ExactVmmProcessProof,
) -> anyhow::Result<ExactGuestMountedSetProof> {
    let launch = checkpoint
        .runtime_launch
        .identity()
        .context("RuntimeReady checkpoint lacks retained launch authority")?;
    anyhow::ensure!(
        vmm.expectation().checkpoint() == checkpoint
            && vmm.expectation().launch_identity() == launch,
        "RuntimeReady VMM proof does not bind the current retained launch"
    );
    context.check_active()?;
    vmm.assert_current(context)?;
    let request = RuntimeReadyRequestV1 {
        version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        challenge: RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .context("generated RuntimeReady challenge is invalid")?,
        runtime_incarnation: launch.runtime_incarnation.clone(),
        expected_guest_cid: launch.guest_cid,
        expected_guest_port: GUEST_HOST_CONTROL_VSOCK_PORT_V1,
        expected_guest_agent_protocol_version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
    };
    let response = port.challenge(context, launch, request.clone())?;
    let evidence = ExactGuestMountedSetProof::from_response(desired, launch, &request, response)?;
    context.check_active()?;
    vmm.assert_current(context)?;
    context.check_active()?;
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use cats_api::guest::{RuntimeReadyDeviceV1, RuntimeReadyMountV1};
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, DiskKind, Ext4MountIntent,
        FilesystemInitialization, GuestBootId, GuestDeviceIdentity, HostPath, Id, MountAccess,
        RuntimeLaunch,
    };

    use super::*;

    const DESIRED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-desired.json"
    ));
    const START_RUNTIME: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
    ));

    fn random(value: char) -> RandomId128 {
        RandomId128::new(value.to_string().repeat(32)).expect("RandomId128")
    }

    fn fixture() -> (
        DesiredRuntimeSpec,
        RuntimeLaunchIdentity,
        RuntimeReadyRequestV1,
        RuntimeReadyResponseV1,
    ) {
        let desired = decode_desired_runtime_spec(DESIRED).expect("Desired");
        let checkpoint = decode_runtime_checkpoint(START_RUNTIME).expect("StartRuntime");
        let RuntimeLaunch::Present(launch) = checkpoint.runtime_launch else {
            panic!("fixture retains launch")
        };
        let request = RuntimeReadyRequestV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            challenge: random('a'),
            runtime_incarnation: launch.runtime_incarnation.clone(),
            expected_guest_cid: launch.guest_cid,
            expected_guest_port: GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            expected_guest_agent_protocol_version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        };
        let root_uuid = random('b');
        let response = RuntimeReadyResponseV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            challenge: request.challenge.clone(),
            runtime_incarnation: request.runtime_incarnation.clone(),
            expected_guest_cid: request.expected_guest_cid,
            expected_guest_port: request.expected_guest_port,
            expected_guest_agent_protocol_version: request.expected_guest_agent_protocol_version,
            actual_guest_cid: request.expected_guest_cid,
            actual_guest_port: request.expected_guest_port,
            actual_guest_agent_protocol_version: request.expected_guest_agent_protocol_version,
            guest_boot_id: GuestBootId::new("11111111222233334444555555555555").expect("boot ID"),
            devices: vec![RuntimeReadyDeviceV1 {
                guest_device: launch.devices[0].guest_device.clone(),
                device_path: HostPath::new("/dev/vda").expect("device path"),
                device_major: 252,
                device_minor: 0,
                size_bytes: launch.devices[0].size_bytes,
                filesystem_uuid: root_uuid.clone(),
            }],
            mounts: vec![RuntimeReadyMountV1 {
                device_major: 252,
                device_minor: 0,
                source_path: HostPath::new("/dev/vda").expect("source"),
                filesystem_uuid: root_uuid,
                mount_root: HostPath::new("/").expect("root"),
                mount_path: HostPath::new("/").expect("mount"),
                filesystem_type: Id::new("ext4").expect("filesystem type"),
                access: MountAccess::ReadWrite,
            }],
        };
        (desired, *launch, request, response)
    }

    fn add_persistent(
        desired: &mut DesiredRuntimeSpec,
        launch: &mut RuntimeLaunchIdentity,
        response: &mut RuntimeReadyResponseV1,
    ) {
        let mut intent = desired.volumes[0].clone();
        intent.volume_intent_id = Id::new("vint_data").unwrap();
        intent.disk_id = Id::new("disk_data").unwrap();
        intent.volume_id = Id::new("vol_data").unwrap();
        intent.attachment_id = Id::new("att_data").unwrap();
        intent.disk_kind = DiskKind::Persistent;
        intent.guest_device = GuestDeviceIdentity {
            serial: Id::new("cats-data").unwrap(),
            slot: 1,
        };
        intent.mount = Some(Ext4MountIntent {
            filesystem_uuid: random('c'),
            mount_path: HostPath::new("/data").unwrap(),
            initialization: FilesystemInitialization::Existing,
        });
        desired.volumes.push(intent.clone());

        let mut prepared = launch.devices[0].clone();
        prepared.volume_intent_id = intent.volume_intent_id.clone();
        prepared.disk_id = intent.disk_id.clone();
        prepared.volume_id = intent.volume_id.clone();
        prepared.attachment_id = intent.attachment_id.clone();
        prepared.disk_kind = DiskKind::Persistent;
        prepared.guest_device = intent.guest_device.clone();
        launch.devices.push(prepared);

        response.devices.push(RuntimeReadyDeviceV1 {
            guest_device: intent.guest_device,
            device_path: HostPath::new("/dev/vdb").unwrap(),
            device_major: 252,
            device_minor: 16,
            size_bytes: intent.size_bytes,
            filesystem_uuid: random('c'),
        });
        response.mounts.push(RuntimeReadyMountV1 {
            device_major: 252,
            device_minor: 16,
            source_path: HostPath::new("/dev/vdb").unwrap(),
            filesystem_uuid: random('c'),
            mount_root: HostPath::new("/").unwrap(),
            mount_path: HostPath::new("/data").unwrap(),
            filesystem_type: Id::new("ext4").unwrap(),
            access: MountAccess::ReadWrite,
        });
    }

    #[test]
    fn root_and_persistent_devices_project_exact_guest_mounts() {
        let (mut desired, mut launch, request, mut response) = fixture();
        add_persistent(&mut desired, &mut launch, &mut response);
        let evidence =
            ExactGuestMountedSetProof::from_response(&desired, &launch, &request, response)
                .unwrap();
        assert_eq!(evidence.mounts().len(), 2);
        assert_eq!(evidence.mounts()[0].volume_id.as_str(), "vol_data");
        assert_eq!(evidence.mounts()[0].mount_path.as_str(), "/data");
        assert_eq!(evidence.mounts()[1].volume_id.as_str(), "vol_root");
        assert_eq!(evidence.mounts()[1].mount_path.as_str(), "/");
        assert!(matches!(
            evidence.guest_transport(),
            GuestTransportEvidence::VsockReady { guest_cid, .. }
                if *guest_cid == request.expected_guest_cid
        ));
    }

    #[test]
    fn wrong_device_or_mount_fact_cannot_mint_guest_ready() {
        let (mut desired, mut launch, request, mut response) = fixture();
        add_persistent(&mut desired, &mut launch, &mut response);

        let mut cases = Vec::new();
        let mut wrong_serial = response.clone();
        wrong_serial.devices[1].guest_device.serial = Id::new("foreign").unwrap();
        cases.push(wrong_serial);
        let mut wrong_size = response.clone();
        wrong_size.devices[1].size_bytes += 1;
        cases.push(wrong_size);
        let mut wrong_uuid = response.clone();
        wrong_uuid.mounts[1].filesystem_uuid = random('d');
        cases.push(wrong_uuid);
        let mut wrong_path = response.clone();
        wrong_path.mounts[1].mount_path = HostPath::new("/foreign").unwrap();
        cases.push(wrong_path);
        let mut read_only = response.clone();
        read_only.mounts[1].access = MountAccess::ReadOnly;
        cases.push(read_only);
        let mut wrong_type = response.clone();
        wrong_type.mounts[1].filesystem_type = Id::new("xfs").unwrap();
        cases.push(wrong_type);
        let mut missing = response.clone();
        missing.mounts.pop();
        cases.push(missing);
        let mut extra = response.clone();
        extra.mounts.push(extra.mounts[0].clone());
        cases.push(extra);

        for changed in cases {
            assert!(
                ExactGuestMountedSetProof::from_response(&desired, &launch, &request, changed)
                    .is_err()
            );
        }
    }

    #[test]
    fn a_fresh_challenge_may_revalidate_the_same_physical_facts() {
        let (mut desired, mut launch, request, mut response) = fixture();
        add_persistent(&mut desired, &mut launch, &mut response);
        let first =
            ExactGuestMountedSetProof::from_response(&desired, &launch, &request, response.clone())
                .unwrap();
        let mut second_request = request;
        second_request.challenge = random('f');
        let mut second_response = response;
        second_response.challenge = second_request.challenge.clone();
        let second = ExactGuestMountedSetProof::from_response(
            &desired,
            &launch,
            &second_request,
            second_response,
        )
        .unwrap();
        assert!(first.same_physical_facts(&second));
        let mut changed = second.response.clone();
        changed.devices[1].device_major = 253;
        changed.devices[1].device_minor = 7;
        changed.mounts[1].device_major = 253;
        changed.mounts[1].device_minor = 7;
        let changed =
            ExactGuestMountedSetProof::from_response(&desired, &launch, &second_request, changed)
                .unwrap();
        assert_eq!(first.mounts(), changed.mounts());
        let error = first
            .ensure_same_physical_facts(&changed)
            .expect_err("changed private major/minor mapping reached admission");
        assert!(error.to_string().contains("mounted set changed"));
    }
}

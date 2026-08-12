//! Characterization of the installed blockd Unix-socket namespace.
//!
//! These tests intentionally describe the production pathname and ownership
//! contract, not a tempfile-only approximation. They stay red while blockd
//! sockets are derived beneath the complete durable attachment lineage.

use std::path::{Path, PathBuf};

use cats_api::runtime_reconciliation::{
    AcquireOrigin, AssignedKind, AssignedPlacement, ContractVersion, DesiredRuntimeSpec, DiskKind,
    Durability, Epoch, FenceEpoch, GuestDeviceIdentity, Id, Ipv4Address, IsolatedIpv4Kind,
    MacAddress, NetworkConfig, RandomId128, Revision, RuntimeConfig, RuntimeTarget, Sha256Digest,
    VolumeAccess, VolumeAcquire, VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::AttachmentLineageIdentity;

use super::authorized_blockd::authorized_blockd_data_directory;
use super::serving_handoff_effect::{SERVING_NBD_SOCKET_BASENAME, SERVING_VHOST_SOCKET_BASENAME};

const INSTALLED_STATE_ROOT: &str = "/var/lib/cats/node";
const ROOT_CONTROL_SOCKET_BASENAME: &str = "root-provision.sock";
const SERVING_CONTROL_SOCKET_BASENAME: &str = "serving-control.sock";

// Linux sockaddr_un::sun_path has 108 bytes. A filesystem pathname needs one
// trailing NUL, so 107 pathname bytes is the exact inclusive ceiling.
const LINUX_UNIX_PATHNAME_MAX_BYTES: usize = 107;

#[derive(Clone)]
struct InstalledLineageCase {
    state_directory: PathBuf,
    desired: DesiredRuntimeSpec,
    identity: AttachmentLineageIdentity,
}

#[derive(Clone, Copy)]
enum BlockdSocketKind {
    RootControl,
    ServingControl,
    KernelNbd,
    VhostUserBlk,
}

impl BlockdSocketKind {
    const ALL: [Self; 4] = [
        Self::RootControl,
        Self::ServingControl,
        Self::KernelNbd,
        Self::VhostUserBlk,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::RootControl => "root control",
            Self::ServingControl => "serving control",
            Self::KernelNbd => "kernel-NBD listener",
            Self::VhostUserBlk => "vhost-user-blk",
        }
    }

    fn basename(self) -> &'static str {
        match self {
            Self::RootControl => ROOT_CONTROL_SOCKET_BASENAME,
            Self::ServingControl => SERVING_CONTROL_SOCKET_BASENAME,
            Self::KernelNbd => SERVING_NBD_SOCKET_BASENAME,
            Self::VhostUserBlk => SERVING_VHOST_SOCKET_BASENAME,
        }
    }
}

impl InstalledLineageCase {
    fn product_ids() -> Self {
        Self::new(
            "state_path_a",
            &format!("cat_{}", "c".repeat(32)),
            &format!("vol_{}", "v".repeat(32)),
            &format!("att_{}", "a".repeat(32)),
        )
    }

    fn maximum_ids() -> Self {
        Self::new(
            &"s".repeat(128),
            &"c".repeat(128),
            &"v".repeat(128),
            &"a".repeat(128),
        )
    }

    fn new(state_path_id: &str, cat_id: &str, volume_id: &str, attachment_id: &str) -> Self {
        let volume_id = id(volume_id);
        let attachment_id = id(attachment_id);
        let acquire_transition = random('1');
        let desired = desired(cat_id, &volume_id, &attachment_id, &acquire_transition);
        let identity = AttachmentLineageIdentity {
            volume_id,
            attachment_id,
            attachment_epoch: FenceEpoch::new(1).unwrap(),
            acquire_origin: AcquireOrigin::Normal {
                transition_id: acquire_transition,
            },
            node_id: desired.placement.node_id.clone(),
            placement_epoch: desired.placement.placement_epoch,
        };
        Self {
            state_directory: Path::new(INSTALLED_STATE_ROOT).join(state_path_id),
            desired,
            identity,
        }
    }

    fn data_directory(&self) -> PathBuf {
        authorized_blockd_data_directory(&self.state_directory, &self.desired, &self.identity)
    }

    fn current_socket_path(&self, kind: BlockdSocketKind) -> PathBuf {
        self.data_directory().join(kind.basename())
    }

    fn all_current_socket_paths(&self) -> Vec<(BlockdSocketKind, PathBuf)> {
        BlockdSocketKind::ALL
            .into_iter()
            .map(|kind| (kind, self.current_socket_path(kind)))
            .collect()
    }

    // Current production root-control naming is rooted only in the durable
    // lineage. Supplying both identities here makes the missing ownership
    // dimension explicit and deterministic in the characterization.
    fn current_root_control_path(
        &self,
        _provision_transition_id: &RandomId128,
        _process_identity_token: &RandomId128,
    ) -> PathBuf {
        self.current_socket_path(BlockdSocketKind::RootControl)
    }

    // Current serving naming likewise ignores the device ownership token.
    fn current_serving_path(
        &self,
        kind: BlockdSocketKind,
        _ownership_token: &RandomId128,
    ) -> PathBuf {
        self.current_socket_path(kind)
    }
}

#[test]
fn installed_product_lineage_blockd_sockets_fit_linux_sun_path() {
    let case = InstalledLineageCase::product_ids();
    let oversized = case
        .all_current_socket_paths()
        .into_iter()
        .filter_map(|(kind, path)| {
            let bytes = path.as_os_str().as_encoded_bytes().len();
            (bytes > LINUX_UNIX_PATHNAME_MAX_BYTES)
                .then(|| format!("{}={bytes}:{}", kind.label(), path.display()))
        })
        .collect::<Vec<_>>();
    assert!(
        oversized.is_empty(),
        "standard installed state plus real 36-byte product IDs exceeds Linux sun_path: {}",
        oversized.join(", ")
    );
}

#[test]
fn maximum_legal_ids_preserve_the_blockd_socket_path_contract() {
    let case = InstalledLineageCase::maximum_ids();
    for value in [
        case.desired.cat_id.as_str(),
        case.identity.volume_id.as_str(),
        case.identity.attachment_id.as_str(),
    ] {
        assert_eq!(value.len(), 128, "fixture stopped exercising Id::MAX");
    }
    assert_eq!(
        case.state_directory
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .len(),
        128,
        "fixture stopped exercising state_path_id: Id::MAX"
    );

    let oversized = case
        .all_current_socket_paths()
        .into_iter()
        .filter_map(|(kind, path)| {
            let bytes = path.as_os_str().as_encoded_bytes().len();
            (bytes > LINUX_UNIX_PATHNAME_MAX_BYTES).then(|| format!("{}={bytes}", kind.label()))
        })
        .collect::<Vec<_>>();
    assert!(
        oversized.is_empty(),
        "maximum legal identity tuple has unbindable blockd sockets: {}",
        oversized.join(", ")
    );
}

#[test]
fn root_socket_owner_is_transition_stable_across_process_token_rotation() {
    let case = InstalledLineageCase::product_ids();
    let transition_a = random('2');
    let transition_b = random('3');
    let process_a = random('4');
    let process_b = random('5');

    let original = case.current_root_control_path(&transition_a, &process_a);
    assert_eq!(
        original,
        case.current_root_control_path(&transition_a, &process_b),
        "root process-attempt token rotation changed the stable socket owner"
    );
    assert_ne!(
        original,
        case.current_root_control_path(&transition_b, &process_a),
        "a distinct root provision transition reused the prior socket owner"
    );
}

#[test]
fn serving_socket_owner_changes_with_the_device_ownership_token() {
    let case = InstalledLineageCase::product_ids();
    let owner_a = random('6');
    let owner_b = random('7');
    for kind in [
        BlockdSocketKind::ServingControl,
        BlockdSocketKind::KernelNbd,
        BlockdSocketKind::VhostUserBlk,
    ] {
        assert_ne!(
            case.current_serving_path(kind, &owner_a),
            case.current_serving_path(kind, &owner_b),
            "{} socket owner ignored a changed device ownership token",
            kind.label()
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_unix_listener_enforces_the_exact_sun_path_boundary() {
    use std::os::unix::net::UnixListener;

    let root = tempfile::Builder::new()
        .prefix("csp")
        .tempdir_in("/tmp")
        .unwrap();
    let exact = pathname_with_length(root.path(), LINUX_UNIX_PATHNAME_MAX_BYTES);
    assert_eq!(
        exact.as_os_str().as_encoded_bytes().len(),
        LINUX_UNIX_PATHNAME_MAX_BYTES
    );
    let listener = UnixListener::bind(&exact).expect("107-byte Linux Unix pathname must bind");
    drop(listener);
    std::fs::remove_file(&exact).unwrap();

    let oversized = pathname_with_length(root.path(), LINUX_UNIX_PATHNAME_MAX_BYTES + 1);
    assert_eq!(
        oversized.as_os_str().as_encoded_bytes().len(),
        LINUX_UNIX_PATHNAME_MAX_BYTES + 1
    );
    UnixListener::bind(&oversized).expect_err("108-byte Linux Unix pathname must be rejected");
}

#[cfg(target_os = "linux")]
fn pathname_with_length(root: &Path, length: usize) -> PathBuf {
    let prefix = root.as_os_str().as_encoded_bytes().len() + 1;
    assert!(prefix < length);
    root.join("x".repeat(length - prefix))
}

fn desired(
    cat_id: &str,
    volume_id: &Id,
    attachment_id: &Id,
    transition_id: &RandomId128,
) -> DesiredRuntimeSpec {
    DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: id("ws_01"),
        cat_id: id(cat_id),
        desired_revision: Revision::new(1).unwrap(),
        target: RuntimeTarget::Running,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: id("node_a"),
            placement_epoch: Epoch::new(1).unwrap(),
        },
        runtime: RuntimeConfig {
            vcpus: 1,
            memory_bytes: 512 * 1024 * 1024,
            boot_image_digest: Sha256Digest::from_bytes([1; 32]),
            guest_config_digest: Sha256Digest::from_bytes([2; 32]),
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: id("net_01"),
                guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
            },
        },
        volumes: vec![VolumeIntent {
            volume_intent_id: id("vint_01"),
            disk_id: id("disk_01"),
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-root"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: transition_id.clone(),
                expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        }],
        endpoints: Vec::new(),
        transition: cats_api::runtime_reconciliation::RuntimeTransition::CancelAndDrain,
        spec_digest: Sha256Digest::from_bytes([3; 32]),
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random(value: char) -> RandomId128 {
    RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
}

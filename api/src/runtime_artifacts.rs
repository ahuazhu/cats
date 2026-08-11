//! Shared fail-closed readers for the one installed runtime release.

use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{ffi::CString, os::fd::AsRawFd as _, os::fd::FromRawFd as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::gateway_workload_identity::{
    decode_gateway_workload_identity_authority, GatewayWorkloadIdentityAuthority,
    CONTROL_MACHINE_SERVER_CERTIFICATE_MAX_WIRE_BYTES, CONTROL_MACHINE_SERVER_CERTIFICATE_PATH,
    CONTROL_MACHINE_SERVER_PRIVATE_KEY_MAX_WIRE_BYTES, CONTROL_MACHINE_SERVER_PRIVATE_KEY_PATH,
    GATEWAY_CLIENT_CA_BUNDLE_MAX_WIRE_BYTES, GATEWAY_CLIENT_CA_BUNDLE_PATH,
    GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_MAX_WIRE_BYTES, GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_PATH,
};
use crate::route_grant_v2::{
    decode_route_grant_v2_public_key_ring, decode_route_grant_v2_signer_reference,
    RouteGrantV2PublicKeyRingArtifact, RouteGrantV2SignerReference, RouteGrantV2SignerSelection,
    GATEWAY_ROUTE_V2_CLIENT_CERTIFICATE_PATH, GATEWAY_ROUTE_V2_CLIENT_PRIVATE_KEY_PATH,
    NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH, NODE_ROUTE_V2_SERVER_CERTIFICATE_PATH,
    NODE_ROUTE_V2_SERVER_PRIVATE_KEY_PATH, ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
    ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH, ROUTE_GRANT_V2_SIGNER_PRIVATE_KEY_PATH,
    ROUTE_GRANT_V2_SIGNER_REFERENCE_PATH, ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES,
    ROUTE_V2_PRIVATE_KEY_MAX_WIRE_BYTES,
};
use crate::runtime_reconciliation::{
    decode_guest_runtime_profile_receipt, decode_runtime_provisioner_trust_bundle, ContractVersion,
    GuestRuntimeProfileReceipt, RuntimeProvisionerTrustBundle, Sha256Digest, WireU64,
    GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES, RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES,
};

pub const GUEST_RUNTIME_PROFILE_RECEIPT_PATH: &str =
    "/opt/cats/release/guest-runtime-profile.v1.json";
pub const GUEST_RUNTIME_RELEASE_MANIFEST_PATH: &str =
    "/opt/cats/release/guest-runtime-release-manifest.v1.json";
pub const GUEST_KERNEL_PATH: &str = "/opt/cats/guest/vmlinuz";
pub const GUEST_INITRAMFS_PATH: &str = "/opt/cats/guest/initramfs.img";
pub const GUEST_RUNTIME_PROFILE_RECEIPT_ENV: &str = "CATS_GUEST_RUNTIME_PROFILE_RECEIPT_FILE";
pub const RUNTIME_PROVISIONER_TRUST_PATH: &str =
    "/etc/cats/identity/runtime-provisioner-trust.v1.json";
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
pub struct InstalledRuntimeProvisionerTrustBundle {
    bundle: RuntimeProvisionerTrustBundle,
    exact_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRouteGrantV2PublicKeyRing {
    ring: RouteGrantV2PublicKeyRingArtifact,
    exact_bytes: Vec<u8>,
}

/// Read-only state of the one fixed Node public-ring artifact.
///
/// An absent fixed path is an ordinary unavailable observation. Once any
/// member of the installed path exists, however, ownership, mode, link,
/// canonical-wire or stable-read failures remain errors and cannot be
/// translated back into absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledRouteGrantV2PublicKeyRingState {
    Unavailable,
    Loaded(InstalledRouteGrantV2PublicKeyRing),
}

impl InstalledRouteGrantV2PublicKeyRing {
    pub fn ring(&self) -> &RouteGrantV2PublicKeyRingArtifact {
        &self.ring
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub fn into_ring(self) -> RouteGrantV2PublicKeyRingArtifact {
        self.ring
    }
}

/// Startup-pinned Control artifacts. Debug output deliberately contains only
/// non-secret lineage; private PEM bytes never implement `Debug` or `Display`.
pub struct InstalledRouteGrantV2Signer {
    reference: RouteGrantV2SignerReference,
    exact_reference_bytes: Vec<u8>,
    ring: InstalledRouteGrantV2PublicKeyRing,
    private_key_pem: Option<Vec<u8>>,
}

/// Startup-pinned Gateway authentication and machine-listener TLS artifacts.
///
/// All four files come from one retained fixed directory and are revalidated
/// together against the canonical lexical path before this value is returned.
/// Debug output deliberately exposes neither exact policy bytes nor PEM
/// material, and in particular never formats the server private key.
pub struct InstalledGatewayMachineArtifacts {
    authority: GatewayWorkloadIdentityAuthority,
    exact_authority_bytes: Vec<u8>,
    client_ca_bundle_pem: Vec<u8>,
    server_certificate_pem: Vec<u8>,
    server_private_key_pem: Vec<u8>,
}

/// Startup-pinned Node Route v2 verification and mTLS server material.
pub struct InstalledNodeRouteV2MachineArtifacts {
    ring: InstalledRouteGrantV2PublicKeyRing,
    gateway_client_ca_bundle_pem: Vec<u8>,
    server_certificate_pem: Vec<u8>,
    server_private_key_pem: Vec<u8>,
}

/// Startup-pinned Gateway identity and trust material for the Node hop.
pub struct InstalledGatewayNodeRouteV2MachineArtifacts {
    node_server_ca_bundle_pem: Vec<u8>,
    client_certificate_pem: Vec<u8>,
    client_private_key_pem: Vec<u8>,
}

impl std::fmt::Debug for InstalledNodeRouteV2MachineArtifacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledNodeRouteV2MachineArtifacts")
            .field("ring", &self.ring)
            .field("gateway_client_ca_bundle_pem", &"[redacted]")
            .field("server_certificate_pem", &"[redacted]")
            .field("server_private_key_pem", &"[redacted]")
            .finish()
    }
}

impl std::fmt::Debug for InstalledGatewayNodeRouteV2MachineArtifacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledGatewayNodeRouteV2MachineArtifacts")
            .field("node_server_ca_bundle_pem", &"[redacted]")
            .field("client_certificate_pem", &"[redacted]")
            .field("client_private_key_pem", &"[redacted]")
            .finish()
    }
}

impl InstalledNodeRouteV2MachineArtifacts {
    pub fn ring(&self) -> &InstalledRouteGrantV2PublicKeyRing {
        &self.ring
    }

    pub fn gateway_client_ca_bundle_pem(&self) -> &[u8] {
        &self.gateway_client_ca_bundle_pem
    }

    pub fn server_certificate_pem(&self) -> &[u8] {
        &self.server_certificate_pem
    }

    pub fn server_private_key_pem(&self) -> &[u8] {
        &self.server_private_key_pem
    }
}

impl InstalledGatewayNodeRouteV2MachineArtifacts {
    pub fn node_server_ca_bundle_pem(&self) -> &[u8] {
        &self.node_server_ca_bundle_pem
    }

    pub fn client_certificate_pem(&self) -> &[u8] {
        &self.client_certificate_pem
    }

    pub fn client_private_key_pem(&self) -> &[u8] {
        &self.client_private_key_pem
    }
}

impl std::fmt::Debug for InstalledGatewayMachineArtifacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledGatewayMachineArtifacts")
            .field("authority_id", &self.authority.authority_id)
            .field("fleet_id", &self.authority.fleet_id)
            .field("policy_revision", &self.authority.policy_revision)
            .field("exact_authority_bytes", &"[redacted]")
            .field("client_ca_bundle_pem", &"[redacted]")
            .field("server_certificate_pem", &"[redacted]")
            .field("server_private_key_pem", &"[redacted]")
            .finish()
    }
}

impl InstalledGatewayMachineArtifacts {
    pub fn authority(&self) -> &GatewayWorkloadIdentityAuthority {
        &self.authority
    }

    pub fn exact_authority_bytes(&self) -> &[u8] {
        &self.exact_authority_bytes
    }

    pub fn client_ca_bundle_pem(&self) -> &[u8] {
        &self.client_ca_bundle_pem
    }

    pub fn server_certificate_pem(&self) -> &[u8] {
        &self.server_certificate_pem
    }

    /// The returned bytes are secret material and must only be retained long
    /// enough to construct the TLS private-key provider object.
    pub fn server_private_key_pem(&self) -> &[u8] {
        &self.server_private_key_pem
    }
}

impl std::fmt::Debug for InstalledRouteGrantV2Signer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledRouteGrantV2Signer")
            .field("reference", &self.reference)
            .field("ring", &self.ring)
            .field(
                "private_key_pem",
                &self.private_key_pem.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl InstalledRouteGrantV2Signer {
    pub fn reference(&self) -> &RouteGrantV2SignerReference {
        &self.reference
    }

    pub fn exact_reference_bytes(&self) -> &[u8] {
        &self.exact_reference_bytes
    }

    pub fn ring(&self) -> &InstalledRouteGrantV2PublicKeyRing {
        &self.ring
    }

    /// `Some` only for an `active` descriptor. Callers must keep the slice in
    /// memory only long enough to construct the private-key provider object.
    pub fn private_key_pem(&self) -> Option<&[u8]> {
        self.private_key_pem.as_deref()
    }
}

impl InstalledRuntimeProvisionerTrustBundle {
    pub fn bundle(&self) -> &RuntimeProvisionerTrustBundle {
        &self.bundle
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
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
    #[error("Runtime provisioner trust path must be the canonical installed path")]
    WrongProvisionerTrustPath,
    #[error("Route Grant v2 public-key ring path must be the canonical installed path")]
    WrongRouteGrantV2PublicKeyRingPath,
    #[error("Route Grant v2 signer paths must be the canonical installed paths")]
    WrongRouteGrantV2SignerPath,
    #[error("Gateway machine artifact paths must be the canonical installed paths")]
    WrongGatewayMachineArtifactPath,
    #[error("Node Route v2 machine artifact paths must be the canonical installed paths")]
    WrongNodeRouteV2MachineArtifactPath,
    #[error("Gateway-to-Node Route v2 artifact paths must be the canonical installed paths")]
    WrongGatewayNodeRouteV2MachineArtifactPath,
    #[error("Guest runtime release is not supported on this platform")]
    UnsupportedPlatform,
    #[error("Guest runtime release filesystem contract failed at {path}")]
    Filesystem { path: PathBuf },
    #[error("Guest runtime release exceeds its wire or member limit")]
    LimitExceeded,
    #[error("Guest runtime release contract is invalid")]
    InvalidReceipt,
    #[error("Runtime provisioner trust bundle is invalid")]
    InvalidProvisionerTrust,
    #[error("Route Grant v2 public-key ring is invalid")]
    InvalidRouteGrantV2PublicKeyRing,
    #[error("Route Grant v2 signer artifact set is invalid")]
    InvalidRouteGrantV2Signer,
    #[error("Gateway machine artifact set is invalid")]
    InvalidGatewayMachineArtifacts,
    #[error("Node Route v2 machine artifact set is invalid")]
    InvalidNodeRouteV2MachineArtifacts,
    #[error("Gateway-to-Node Route v2 artifact set is invalid")]
    InvalidGatewayNodeRouteV2MachineArtifacts,
}

/// Load the one fixed Gateway policy and Control machine-listener TLS set.
/// Path arguments exist only so startup composition can prove that it accepted
/// no alternate installation roots or secret locations.
pub fn load_installed_gateway_machine_artifacts(
    authority_path: &Path,
    client_ca_bundle_path: &Path,
    server_certificate_path: &Path,
    server_private_key_path: &Path,
) -> Result<InstalledGatewayMachineArtifacts, RuntimeArtifactError> {
    if authority_path != Path::new(GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_PATH)
        || client_ca_bundle_path != Path::new(GATEWAY_CLIENT_CA_BUNDLE_PATH)
        || server_certificate_path != Path::new(CONTROL_MACHINE_SERVER_CERTIFICATE_PATH)
        || server_private_key_path != Path::new(CONTROL_MACHINE_SERVER_PRIVATE_KEY_PATH)
    {
        return Err(RuntimeArtifactError::WrongGatewayMachineArtifactPath);
    }
    load_installed_gateway_machine_artifacts_platform()
}

#[cfg(unix)]
fn load_installed_gateway_machine_artifacts_platform(
) -> Result<InstalledGatewayMachineArtifacts, RuntimeArtifactError> {
    let directory = open_installed_directory(
        &["etc", "cats", "route-v2"],
        InstalledDirectoryMode::Exact(0o700),
    )?;
    load_gateway_machine_artifacts_from(
        &directory,
        InstalledFileContract::root(0o644),
        InstalledFileContract::root(0o600),
    )
}

#[cfg(not(unix))]
fn load_installed_gateway_machine_artifacts_platform(
) -> Result<InstalledGatewayMachineArtifacts, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

#[cfg(unix)]
fn load_gateway_machine_artifacts_from(
    directory: &InstalledDirectoryPath,
    public_file_contract: InstalledFileContract,
    private_file_contract: InstalledFileContract,
) -> Result<InstalledGatewayMachineArtifacts, RuntimeArtifactError> {
    load_gateway_machine_artifacts_from_with_phase(
        directory,
        public_file_contract,
        private_file_contract,
        |_| {},
    )
}

#[cfg(unix)]
fn load_gateway_machine_artifacts_from_with_phase(
    directory: &InstalledDirectoryPath,
    public_file_contract: InstalledFileContract,
    private_file_contract: InstalledFileContract,
    mut after_read: impl FnMut(GatewayMachineArtifactReadPhase),
) -> Result<InstalledGatewayMachineArtifacts, RuntimeArtifactError> {
    let authority_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "gateway-workload-authority.v1.json",
        Path::new(GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_PATH),
        GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_MAX_WIRE_BYTES,
        public_file_contract,
    )?;
    after_read(GatewayMachineArtifactReadPhase::Authority);
    let client_ca_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "gateway-client-ca-bundle.pem",
        Path::new(GATEWAY_CLIENT_CA_BUNDLE_PATH),
        GATEWAY_CLIENT_CA_BUNDLE_MAX_WIRE_BYTES,
        public_file_contract,
    )?;
    after_read(GatewayMachineArtifactReadPhase::ClientCaBundle);
    let server_certificate_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "control-machine-server-certificate.pem",
        Path::new(CONTROL_MACHINE_SERVER_CERTIFICATE_PATH),
        CONTROL_MACHINE_SERVER_CERTIFICATE_MAX_WIRE_BYTES,
        public_file_contract,
    )?;
    after_read(GatewayMachineArtifactReadPhase::ServerCertificate);
    let server_private_key_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "control-machine-server-private-key.pem",
        Path::new(CONTROL_MACHINE_SERVER_PRIVATE_KEY_PATH),
        CONTROL_MACHINE_SERVER_PRIVATE_KEY_MAX_WIRE_BYTES,
        private_file_contract,
    )?;
    after_read(GatewayMachineArtifactReadPhase::ServerPrivateKey);

    if client_ca_file.exact_bytes().is_empty()
        || server_certificate_file.exact_bytes().is_empty()
        || server_private_key_file.exact_bytes().is_empty()
    {
        return Err(RuntimeArtifactError::InvalidGatewayMachineArtifacts);
    }

    // This is one startup/read transaction. Reopening the canonical directory
    // once and comparing every retained descriptor closes directory and
    // basename replacement during any of the four reads.
    let fresh_directory = directory.reopen_canonical_path()?;
    for (file, cap, contract) in [
        (
            &authority_file,
            GATEWAY_WORKLOAD_IDENTITY_AUTHORITY_MAX_WIRE_BYTES,
            public_file_contract,
        ),
        (
            &client_ca_file,
            GATEWAY_CLIENT_CA_BUNDLE_MAX_WIRE_BYTES,
            public_file_contract,
        ),
        (
            &server_certificate_file,
            CONTROL_MACHINE_SERVER_CERTIFICATE_MAX_WIRE_BYTES,
            public_file_contract,
        ),
        (
            &server_private_key_file,
            CONTROL_MACHINE_SERVER_PRIVATE_KEY_MAX_WIRE_BYTES,
            private_file_contract,
        ),
    ] {
        file.revalidate_from(&fresh_directory, cap, contract)?;
    }

    let authority = decode_gateway_workload_identity_authority(authority_file.exact_bytes())
        .map_err(|_| RuntimeArtifactError::InvalidGatewayMachineArtifacts)?;
    Ok(InstalledGatewayMachineArtifacts {
        authority,
        exact_authority_bytes: authority_file.into_exact_bytes(),
        client_ca_bundle_pem: client_ca_file.into_exact_bytes(),
        server_certificate_pem: server_certificate_file.into_exact_bytes(),
        server_private_key_pem: server_private_key_file.into_exact_bytes(),
    })
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayMachineArtifactReadPhase {
    Authority,
    ClientCaBundle,
    ServerCertificate,
    ServerPrivateKey,
}

/// Load the one fixed Node Route v2 ring and mTLS server set. Path arguments
/// prove that production startup accepted neither alternate trust roots nor
/// caller-selected private material.
pub fn load_installed_node_route_v2_machine_artifacts(
    public_key_ring_path: &Path,
    gateway_client_ca_bundle_path: &Path,
    server_certificate_path: &Path,
    server_private_key_path: &Path,
) -> Result<InstalledNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    if public_key_ring_path != Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH)
        || gateway_client_ca_bundle_path != Path::new(GATEWAY_CLIENT_CA_BUNDLE_PATH)
        || server_certificate_path != Path::new(NODE_ROUTE_V2_SERVER_CERTIFICATE_PATH)
        || server_private_key_path != Path::new(NODE_ROUTE_V2_SERVER_PRIVATE_KEY_PATH)
    {
        return Err(RuntimeArtifactError::WrongNodeRouteV2MachineArtifactPath);
    }
    load_installed_node_route_v2_machine_artifacts_platform()
}

/// Load the fixed Gateway client identity and Node-server trust root used by
/// the production Gateway-to-Node hop.
pub fn load_installed_gateway_node_route_v2_machine_artifacts(
    node_server_ca_bundle_path: &Path,
    client_certificate_path: &Path,
    client_private_key_path: &Path,
) -> Result<InstalledGatewayNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    if node_server_ca_bundle_path != Path::new(NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH)
        || client_certificate_path != Path::new(GATEWAY_ROUTE_V2_CLIENT_CERTIFICATE_PATH)
        || client_private_key_path != Path::new(GATEWAY_ROUTE_V2_CLIENT_PRIVATE_KEY_PATH)
    {
        return Err(RuntimeArtifactError::WrongGatewayNodeRouteV2MachineArtifactPath);
    }
    load_installed_gateway_node_route_v2_machine_artifacts_platform()
}

#[cfg(unix)]
fn load_installed_node_route_v2_machine_artifacts_platform(
) -> Result<InstalledNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    let directory = open_installed_directory(
        &["etc", "cats", "route-v2"],
        InstalledDirectoryMode::Exact(0o700),
    )?;
    load_node_route_v2_machine_artifacts_from(
        &directory,
        InstalledFileContract::root(0o644),
        InstalledFileContract::root(0o600),
    )
}

#[cfg(unix)]
fn load_node_route_v2_machine_artifacts_from(
    directory: &InstalledDirectoryPath,
    public: InstalledFileContract,
    private: InstalledFileContract,
) -> Result<InstalledNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    let ring_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "public-key-ring.v1.json",
        Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH),
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        public,
    )?;
    let client_ca_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "gateway-client-ca-bundle.pem",
        Path::new(GATEWAY_CLIENT_CA_BUNDLE_PATH),
        GATEWAY_CLIENT_CA_BUNDLE_MAX_WIRE_BYTES,
        public,
    )?;
    let server_certificate_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "node-machine-server-certificate.pem",
        Path::new(NODE_ROUTE_V2_SERVER_CERTIFICATE_PATH),
        ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES,
        public,
    )?;
    let server_private_key_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "node-machine-server-private-key.pem",
        Path::new(NODE_ROUTE_V2_SERVER_PRIVATE_KEY_PATH),
        ROUTE_V2_PRIVATE_KEY_MAX_WIRE_BYTES,
        private,
    )?;
    let fresh = directory.reopen_canonical_path()?;
    ring_file.revalidate_from(&fresh, ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES, public)?;
    client_ca_file.revalidate_from(&fresh, GATEWAY_CLIENT_CA_BUNDLE_MAX_WIRE_BYTES, public)?;
    server_certificate_file.revalidate_from(&fresh, ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES, public)?;
    server_private_key_file.revalidate_from(
        &fresh,
        ROUTE_V2_PRIVATE_KEY_MAX_WIRE_BYTES,
        private,
    )?;
    if client_ca_file.exact_bytes().is_empty()
        || server_certificate_file.exact_bytes().is_empty()
        || server_private_key_file.exact_bytes().is_empty()
    {
        return Err(RuntimeArtifactError::InvalidNodeRouteV2MachineArtifacts);
    }
    let ring = decode_route_grant_v2_public_key_ring(ring_file.exact_bytes())
        .map_err(|_| RuntimeArtifactError::InvalidNodeRouteV2MachineArtifacts)?;
    Ok(InstalledNodeRouteV2MachineArtifacts {
        ring: InstalledRouteGrantV2PublicKeyRing {
            ring,
            exact_bytes: ring_file.into_exact_bytes(),
        },
        gateway_client_ca_bundle_pem: client_ca_file.into_exact_bytes(),
        server_certificate_pem: server_certificate_file.into_exact_bytes(),
        server_private_key_pem: server_private_key_file.into_exact_bytes(),
    })
}

#[cfg(not(unix))]
fn load_installed_node_route_v2_machine_artifacts_platform(
) -> Result<InstalledNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

#[cfg(unix)]
fn load_installed_gateway_node_route_v2_machine_artifacts_platform(
) -> Result<InstalledGatewayNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    let directory = open_installed_directory(
        &["etc", "cats", "route-v2"],
        InstalledDirectoryMode::Exact(0o700),
    )?;
    load_gateway_node_route_v2_machine_artifacts_from(
        &directory,
        InstalledFileContract::root(0o644),
        InstalledFileContract::root(0o600),
    )
}

#[cfg(unix)]
fn load_gateway_node_route_v2_machine_artifacts_from(
    directory: &InstalledDirectoryPath,
    public: InstalledFileContract,
    private: InstalledFileContract,
) -> Result<InstalledGatewayNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    let ca_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "node-server-ca-bundle.pem",
        Path::new(NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH),
        ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES,
        public,
    )?;
    let certificate_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "gateway-machine-client-certificate.pem",
        Path::new(GATEWAY_ROUTE_V2_CLIENT_CERTIFICATE_PATH),
        ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES,
        public,
    )?;
    let private_key_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "gateway-machine-client-private-key.pem",
        Path::new(GATEWAY_ROUTE_V2_CLIENT_PRIVATE_KEY_PATH),
        ROUTE_V2_PRIVATE_KEY_MAX_WIRE_BYTES,
        private,
    )?;
    let fresh = directory.reopen_canonical_path()?;
    ca_file.revalidate_from(&fresh, ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES, public)?;
    certificate_file.revalidate_from(&fresh, ROUTE_V2_CERTIFICATE_MAX_WIRE_BYTES, public)?;
    private_key_file.revalidate_from(&fresh, ROUTE_V2_PRIVATE_KEY_MAX_WIRE_BYTES, private)?;
    if ca_file.exact_bytes().is_empty()
        || certificate_file.exact_bytes().is_empty()
        || private_key_file.exact_bytes().is_empty()
    {
        return Err(RuntimeArtifactError::InvalidGatewayNodeRouteV2MachineArtifacts);
    }
    Ok(InstalledGatewayNodeRouteV2MachineArtifacts {
        node_server_ca_bundle_pem: ca_file.into_exact_bytes(),
        client_certificate_pem: certificate_file.into_exact_bytes(),
        client_private_key_pem: private_key_file.into_exact_bytes(),
    })
}

#[cfg(not(unix))]
fn load_installed_gateway_node_route_v2_machine_artifacts_platform(
) -> Result<InstalledGatewayNodeRouteV2MachineArtifacts, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

/// Load the one public ring installed on a Node. The path argument exists only
/// so production CLI composition can prove it did not accept an alternate.
pub fn load_installed_route_grant_v2_public_key_ring(
    selected_path: &Path,
) -> Result<InstalledRouteGrantV2PublicKeyRing, RuntimeArtifactError> {
    if selected_path != Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH) {
        return Err(RuntimeArtifactError::WrongRouteGrantV2PublicKeyRingPath);
    }
    load_installed_route_grant_v2_public_key_ring_platform()
}

/// Inspect the exact production Node public-ring path without accepting a
/// caller-selected alternate or treating an invalid installed artifact as
/// unavailable.
pub fn inspect_installed_route_grant_v2_public_key_ring(
) -> Result<InstalledRouteGrantV2PublicKeyRingState, RuntimeArtifactError> {
    inspect_installed_route_grant_v2_public_key_ring_platform()
}

#[cfg(unix)]
fn load_installed_route_grant_v2_public_key_ring_platform(
) -> Result<InstalledRouteGrantV2PublicKeyRing, RuntimeArtifactError> {
    let directory = open_installed_directory(
        &["etc", "cats", "route-v2"],
        InstalledDirectoryMode::Exact(0o700),
    )?;
    load_route_grant_v2_public_key_ring_from(&directory, InstalledFileContract::root(0o644))
}

#[cfg(unix)]
fn inspect_installed_route_grant_v2_public_key_ring_platform(
) -> Result<InstalledRouteGrantV2PublicKeyRingState, RuntimeArtifactError> {
    let Some(directory) = open_installed_directory_if_present(
        &["etc", "cats", "route-v2"],
        InstalledDirectoryMode::Exact(0o700),
    )?
    else {
        return Ok(InstalledRouteGrantV2PublicKeyRingState::Unavailable);
    };
    inspect_route_grant_v2_public_key_ring_from(&directory, InstalledFileContract::root(0o644))
}

#[cfg(not(unix))]
fn load_installed_route_grant_v2_public_key_ring_platform(
) -> Result<InstalledRouteGrantV2PublicKeyRing, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn inspect_installed_route_grant_v2_public_key_ring_platform(
) -> Result<InstalledRouteGrantV2PublicKeyRingState, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

/// Load one Control-only descriptor/ring/private-material set from a retained
/// directory descriptor. Disabled descriptors deliberately do not open or read
/// the private-material entry.
pub fn load_installed_route_grant_v2_signer(
    signer_reference_path: &Path,
    public_key_ring_path: &Path,
    private_key_path: &Path,
) -> Result<InstalledRouteGrantV2Signer, RuntimeArtifactError> {
    if signer_reference_path != Path::new(ROUTE_GRANT_V2_SIGNER_REFERENCE_PATH)
        || public_key_ring_path != Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH)
        || private_key_path != Path::new(ROUTE_GRANT_V2_SIGNER_PRIVATE_KEY_PATH)
    {
        return Err(RuntimeArtifactError::WrongRouteGrantV2SignerPath);
    }
    load_installed_route_grant_v2_signer_platform()
}

#[cfg(unix)]
fn load_installed_route_grant_v2_signer_platform(
) -> Result<InstalledRouteGrantV2Signer, RuntimeArtifactError> {
    let directory = open_installed_directory(
        &["etc", "cats", "route-v2"],
        InstalledDirectoryMode::Exact(0o700),
    )?;
    load_route_grant_v2_signer_from(
        &directory,
        InstalledFileContract::root(0o644),
        InstalledFileContract::root(0o600),
    )
}

#[cfg(not(unix))]
fn load_installed_route_grant_v2_signer_platform(
) -> Result<InstalledRouteGrantV2Signer, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
}

#[cfg(unix)]
fn load_route_grant_v2_public_key_ring_from(
    directory: &InstalledDirectoryPath,
    file_contract: InstalledFileContract,
) -> Result<InstalledRouteGrantV2PublicKeyRing, RuntimeArtifactError> {
    load_route_grant_v2_public_key_ring_from_with_phase(directory, file_contract, |_| {})
}

#[cfg(unix)]
fn load_route_grant_v2_public_key_ring_from_with_phase(
    directory: &InstalledDirectoryPath,
    file_contract: InstalledFileContract,
    mut after_read: impl FnMut(RouteGrantV2ArtifactReadPhase),
) -> Result<InstalledRouteGrantV2PublicKeyRing, RuntimeArtifactError> {
    let pinned = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "public-key-ring.v1.json",
        Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH),
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        file_contract,
    )?;
    after_read(RouteGrantV2ArtifactReadPhase::PublicKeyRing);
    let fresh_directory = directory.reopen_canonical_path()?;
    pinned.revalidate_from(
        &fresh_directory,
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        file_contract,
    )?;
    let ring = decode_route_grant_v2_public_key_ring(pinned.exact_bytes())
        .map_err(|_| RuntimeArtifactError::InvalidRouteGrantV2PublicKeyRing)?;
    Ok(InstalledRouteGrantV2PublicKeyRing {
        ring,
        exact_bytes: pinned.into_exact_bytes(),
    })
}

#[cfg(unix)]
fn inspect_route_grant_v2_public_key_ring_from(
    directory: &InstalledDirectoryPath,
    file_contract: InstalledFileContract,
) -> Result<InstalledRouteGrantV2PublicKeyRingState, RuntimeArtifactError> {
    inspect_route_grant_v2_public_key_ring_from_with_phase(directory, file_contract, |_| {})
}

#[cfg(unix)]
fn inspect_route_grant_v2_public_key_ring_from_with_phase(
    directory: &InstalledDirectoryPath,
    file_contract: InstalledFileContract,
    mut after_read: impl FnMut(RouteGrantV2ArtifactReadPhase),
) -> Result<InstalledRouteGrantV2PublicKeyRingState, RuntimeArtifactError> {
    let pinned = read_pinned_installed_file_at_with_contract_if_present(
        directory.final_descriptor(),
        "public-key-ring.v1.json",
        Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH),
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        file_contract,
    )?;
    after_read(RouteGrantV2ArtifactReadPhase::PublicKeyRing);
    let Some(pinned) = pinned else {
        let fresh_directory = directory.reopen_canonical_path()?;
        ensure_entry_absent_at(
            &fresh_directory,
            "public-key-ring.v1.json",
            Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH),
        )?;
        return Ok(InstalledRouteGrantV2PublicKeyRingState::Unavailable);
    };
    let fresh_directory = directory.reopen_canonical_path()?;
    pinned.revalidate_from(
        &fresh_directory,
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        file_contract,
    )?;
    let ring = decode_route_grant_v2_public_key_ring(pinned.exact_bytes())
        .map_err(|_| RuntimeArtifactError::InvalidRouteGrantV2PublicKeyRing)?;
    Ok(InstalledRouteGrantV2PublicKeyRingState::Loaded(
        InstalledRouteGrantV2PublicKeyRing {
            ring,
            exact_bytes: pinned.into_exact_bytes(),
        },
    ))
}

#[cfg(unix)]
fn load_route_grant_v2_signer_from(
    directory: &InstalledDirectoryPath,
    public_file_contract: InstalledFileContract,
    private_file_contract: InstalledFileContract,
) -> Result<InstalledRouteGrantV2Signer, RuntimeArtifactError> {
    load_route_grant_v2_signer_from_with_phase(
        directory,
        public_file_contract,
        private_file_contract,
        |_| {},
    )
}

#[cfg(unix)]
fn load_route_grant_v2_signer_from_with_phase(
    directory: &InstalledDirectoryPath,
    public_file_contract: InstalledFileContract,
    private_file_contract: InstalledFileContract,
    mut after_read: impl FnMut(RouteGrantV2ArtifactReadPhase),
) -> Result<InstalledRouteGrantV2Signer, RuntimeArtifactError> {
    let reference_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "signer.v1.json",
        Path::new(ROUTE_GRANT_V2_SIGNER_REFERENCE_PATH),
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        public_file_contract,
    )?;
    after_read(RouteGrantV2ArtifactReadPhase::SignerReference);
    let reference = decode_route_grant_v2_signer_reference(reference_file.exact_bytes())
        .map_err(|_| RuntimeArtifactError::InvalidRouteGrantV2Signer)?;
    let ring_file = read_pinned_installed_file_at_with_contract(
        directory.final_descriptor(),
        "public-key-ring.v1.json",
        Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH),
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        public_file_contract,
    )?;
    after_read(RouteGrantV2ArtifactReadPhase::PublicKeyRing);
    let private_key_file = match &reference.signer {
        RouteGrantV2SignerSelection::Disabled => None,
        RouteGrantV2SignerSelection::Active { .. } => {
            let file = read_pinned_installed_file_at_with_contract(
                directory.final_descriptor(),
                "signer-private-key.pem",
                Path::new(ROUTE_GRANT_V2_SIGNER_PRIVATE_KEY_PATH),
                ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
                private_file_contract,
            )?;
            if file.exact_bytes().is_empty() {
                return Err(RuntimeArtifactError::InvalidRouteGrantV2Signer);
            }
            after_read(RouteGrantV2ArtifactReadPhase::PrivateKey);
            Some(file)
        }
    };

    // This closes one startup/read transaction. It deliberately does not
    // claim to watch the installed path after return; versioned reload and
    // Node ACK semantics belong to the future rotation slice.
    let fresh_directory = directory.reopen_canonical_path()?;
    reference_file.revalidate_from(
        &fresh_directory,
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        public_file_contract,
    )?;
    ring_file.revalidate_from(
        &fresh_directory,
        ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
        public_file_contract,
    )?;
    if let Some(private_key_file) = &private_key_file {
        private_key_file.revalidate_from(
            &fresh_directory,
            ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
            private_file_contract,
        )?;
    }

    let ring = decode_route_grant_v2_public_key_ring(ring_file.exact_bytes())
        .map_err(|_| RuntimeArtifactError::InvalidRouteGrantV2Signer)?;
    reference
        .validate_ring(&ring)
        .map_err(|_| RuntimeArtifactError::InvalidRouteGrantV2Signer)?;
    Ok(InstalledRouteGrantV2Signer {
        reference,
        exact_reference_bytes: reference_file.into_exact_bytes(),
        ring: InstalledRouteGrantV2PublicKeyRing {
            ring,
            exact_bytes: ring_file.into_exact_bytes(),
        },
        private_key_pem: private_key_file.map(PinnedInstalledFile::into_exact_bytes),
    })
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteGrantV2ArtifactReadPhase {
    SignerReference,
    PublicKeyRing,
    PrivateKey,
}

/// Read and pin the one deployment-provisioner trust bundle before the admin
/// listener opens. The descriptor-based reader rejects path replacement,
/// symlinks, hard links, ownership/mode drift, and bytes changed during read.
pub fn load_installed_runtime_provisioner_trust_bundle(
    selected_path: &Path,
) -> Result<InstalledRuntimeProvisionerTrustBundle, RuntimeArtifactError> {
    if selected_path != Path::new(RUNTIME_PROVISIONER_TRUST_PATH) {
        return Err(RuntimeArtifactError::WrongProvisionerTrustPath);
    }
    load_installed_runtime_provisioner_trust_bundle_platform(selected_path)
}

#[cfg(unix)]
fn load_installed_runtime_provisioner_trust_bundle_platform(
    path: &Path,
) -> Result<InstalledRuntimeProvisionerTrustBundle, RuntimeArtifactError> {
    let identity_directory = open_installed_directory(
        &["etc", "cats", "identity"],
        InstalledDirectoryMode::ProvisionerIdentity,
    )?;
    let exact_bytes = read_exact_installed_file_at(
        identity_directory.final_descriptor(),
        "runtime-provisioner-trust.v1.json",
        path,
        RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES,
    )?;
    let bundle = decode_runtime_provisioner_trust_bundle(&exact_bytes)
        .map_err(|_| RuntimeArtifactError::InvalidProvisionerTrust)?;
    Ok(InstalledRuntimeProvisionerTrustBundle {
        bundle,
        exact_bytes,
    })
}

#[cfg(not(unix))]
fn load_installed_runtime_provisioner_trust_bundle_platform(
    _path: &Path,
) -> Result<InstalledRuntimeProvisionerTrustBundle, RuntimeArtifactError> {
    Err(RuntimeArtifactError::UnsupportedPlatform)
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
    let release_directory = open_installed_directory(
        &["opt", "cats", "release"],
        InstalledDirectoryMode::Exact(0o755),
    )?;
    let manifest_path = Path::new(GUEST_RUNTIME_RELEASE_MANIFEST_PATH);
    let exact_manifest_bytes = read_exact_installed_file_at(
        release_directory.final_descriptor(),
        "guest-runtime-release-manifest.v1.json",
        manifest_path,
        GUEST_RUNTIME_RELEASE_MANIFEST_MAX_BYTES,
    )?;
    let manifest = decode_release_manifest(&exact_manifest_bytes)?;
    let exact_bytes = read_exact_installed_file_at(
        release_directory.final_descriptor(),
        "guest-runtime-profile.v1.json",
        receipt_path,
        GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES,
    )?;
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
    let guest_directory = open_installed_directory(
        &["opt", "cats", "guest"],
        InstalledDirectoryMode::Exact(0o755),
    )?;
    let kernel = read_exact_installed_file_at(
        guest_directory.final_descriptor(),
        "vmlinuz",
        Path::new(GUEST_KERNEL_PATH),
        GUEST_BOOT_MEMBER_MAX_BYTES,
    )?;
    validate_member_bytes(
        &installed.manifest.kernel,
        "guest/vmlinuz",
        &kernel,
        GUEST_BOOT_MEMBER_MAX_BYTES,
    )?;
    match &installed.manifest.initramfs {
        Some(member) => {
            let initramfs = read_exact_installed_file_at(
                guest_directory.final_descriptor(),
                "initramfs.img",
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
        None => ensure_entry_absent_at(
            guest_directory.final_descriptor(),
            "initramfs.img",
            Path::new(GUEST_INITRAMFS_PATH),
        )?,
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
    let guest_directory = open_installed_directory(
        &["opt", "cats", "guest"],
        InstalledDirectoryMode::Exact(0o755),
    )?;
    let kernel = open_verified_installed_member_at(
        guest_directory.final_descriptor(),
        "vmlinuz",
        kernel_path,
        &contract.kernel,
        "guest/vmlinuz",
        GUEST_BOOT_MEMBER_MAX_BYTES,
    )?;
    let initramfs = match (&contract.initramfs, initramfs_path) {
        (Some(member), Some(path)) => Some(open_verified_installed_member_at(
            guest_directory.final_descriptor(),
            "initramfs.img",
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
#[derive(Clone, Copy)]
enum InstalledDirectoryMode {
    Exact(u32),
    ProvisionerIdentity,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct InstalledFileContract {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
impl InstalledFileContract {
    const fn root(mode: u32) -> Self {
        Self {
            uid: 0,
            gid: 0,
            mode,
        }
    }
}

#[cfg(unix)]
impl InstalledDirectoryMode {
    fn accepts(self, mode: u32) -> bool {
        let mode = mode & 0o7777;
        match self {
            Self::Exact(expected) => mode == expected,
            // Metal keeps identity material private (0700), while the
            // container image exposes this non-secret public-key trust bundle
            // from a traversal-only installed directory (0755). No other mode
            // is part of the installed artifact contract.
            Self::ProvisionerIdentity => matches!(mode, 0o700 | 0o755),
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct RetainedInstalledDirectory {
    name: Option<String>,
    display: PathBuf,
    descriptor: File,
    metadata: StableFileMetadata,
}

#[cfg(unix)]
#[derive(Debug)]
struct InstalledDirectoryPath {
    canonical_root: PathBuf,
    directories: Vec<RetainedInstalledDirectory>,
}

#[cfg(unix)]
impl InstalledDirectoryPath {
    fn final_descriptor(&self) -> &File {
        &self
            .directories
            .last()
            .expect("an installed directory path always retains its root")
            .descriptor
    }

    /// Reopen the fixed lexical path from its root and prove that every
    /// retained directory still names the same stable inode. This is the
    /// final check of one read transaction, not a persistent filesystem watch.
    fn reopen_canonical_path(&self) -> Result<File, RuntimeArtifactError> {
        let mut fresh = Vec::with_capacity(self.directories.len());
        fresh.push(open_directory_path(
            &self.canonical_root,
            &self.directories[0].display,
        )?);
        for retained in self.directories.iter().skip(1) {
            let parent = fresh
                .last()
                .expect("the fresh path always retains its root");
            fresh.push(open_directory_at(
                parent,
                retained
                    .name
                    .as_deref()
                    .expect("only the retained root has no basename"),
                &retained.display,
            )?);
        }

        for (retained, fresh_descriptor) in self.directories.iter().zip(&fresh) {
            let retained_metadata = StableFileMetadata::new(
                &retained
                    .descriptor
                    .metadata()
                    .map_err(|_| filesystem_error(&retained.display))?,
            );
            let fresh_metadata = StableFileMetadata::new(
                &fresh_descriptor
                    .metadata()
                    .map_err(|_| filesystem_error(&retained.display))?,
            );
            if retained_metadata != retained.metadata
                || fresh_metadata != retained.metadata
                || !retained.metadata.is_directory
            {
                return Err(filesystem_error(&retained.display));
            }
        }

        Ok(fresh.pop().expect("the fresh path always retains its root"))
    }
}

#[cfg(unix)]
fn open_installed_directory(
    components: &[&str],
    final_mode: InstalledDirectoryMode,
) -> Result<InstalledDirectoryPath, RuntimeArtifactError> {
    open_installed_directory_from(
        Path::new("/"),
        components,
        final_mode,
        InstalledDirectoryOwner::Root,
    )
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum InstalledDirectoryOwner {
    Root,
    #[cfg(test)]
    Exact {
        uid: u32,
        gid: u32,
    },
}

#[cfg(unix)]
impl InstalledDirectoryOwner {
    fn accepts(self, uid: u32, gid: u32) -> bool {
        match self {
            Self::Root => uid == 0 && gid == 0,
            #[cfg(test)]
            Self::Exact {
                uid: expected_uid,
                gid: expected_gid,
            } => uid == expected_uid && gid == expected_gid,
        }
    }
}

#[cfg(unix)]
fn open_installed_directory_from(
    canonical_root: &Path,
    components: &[&str],
    final_mode: InstalledDirectoryMode,
    owner: InstalledDirectoryOwner,
) -> Result<InstalledDirectoryPath, RuntimeArtifactError> {
    use std::os::unix::fs::MetadataExt as _;

    let root_display = canonical_root.to_path_buf();
    let root = open_directory_path(canonical_root, &root_display)?;
    let root_metadata = root
        .metadata()
        .map_err(|_| filesystem_error(&root_display))?;
    if !root_metadata.file_type().is_dir()
        || !owner.accepts(root_metadata.uid(), root_metadata.gid())
        || root_metadata.mode() & 0o022 != 0
    {
        return Err(filesystem_error(&root_display));
    }
    let mut directories = vec![RetainedInstalledDirectory {
        name: None,
        display: root_display.clone(),
        descriptor: root,
        metadata: StableFileMetadata::new(&root_metadata),
    }];
    let mut display = root_display;
    for (index, component) in components.iter().enumerate() {
        display.push(component);
        let directory = open_directory_at(
            &directories
                .last()
                .expect("the installed path always retains its root")
                .descriptor,
            component,
            &display,
        )?;
        let metadata = directory
            .metadata()
            .map_err(|_| filesystem_error(&display))?;
        let mode_is_valid = if index + 1 == components.len() {
            final_mode.accepts(metadata.mode())
        } else {
            metadata.mode() & 0o022 == 0
        };
        if !metadata.file_type().is_dir()
            || !owner.accepts(metadata.uid(), metadata.gid())
            || !mode_is_valid
        {
            return Err(filesystem_error(&display));
        }
        directories.push(RetainedInstalledDirectory {
            name: Some((*component).to_owned()),
            display: display.clone(),
            descriptor: directory,
            metadata: StableFileMetadata::new(&metadata),
        });
    }
    Ok(InstalledDirectoryPath {
        canonical_root: canonical_root.to_path_buf(),
        directories,
    })
}

#[cfg(unix)]
fn open_directory_path(path: &Path, display: &Path) -> Result<File, RuntimeArtifactError> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| filesystem_error(display))?;
    // SAFETY: `path` is NUL-terminated, and a successful descriptor is
    // immediately owned by `File`.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(filesystem_error(display));
    }
    // SAFETY: `open` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_installed_directory_if_present(
    components: &[&str],
    final_mode: InstalledDirectoryMode,
) -> Result<Option<InstalledDirectoryPath>, RuntimeArtifactError> {
    open_installed_directory_if_present_from(
        Path::new("/"),
        components,
        final_mode,
        InstalledDirectoryOwner::Root,
    )
}

#[cfg(unix)]
fn open_installed_directory_if_present_from(
    canonical_root: &Path,
    components: &[&str],
    final_mode: InstalledDirectoryMode,
    owner: InstalledDirectoryOwner,
) -> Result<Option<InstalledDirectoryPath>, RuntimeArtifactError> {
    open_installed_directory_if_present_from_with_phase(
        canonical_root,
        components,
        final_mode,
        owner,
        |_| {},
    )
}

#[cfg(unix)]
fn open_installed_directory_if_present_from_with_phase(
    canonical_root: &Path,
    components: &[&str],
    final_mode: InstalledDirectoryMode,
    owner: InstalledDirectoryOwner,
    mut after_absent_lookup: impl FnMut(&Path),
) -> Result<Option<InstalledDirectoryPath>, RuntimeArtifactError> {
    use std::os::unix::fs::MetadataExt as _;

    let root_display = canonical_root.to_path_buf();
    let root = open_directory_path(canonical_root, &root_display)?;
    let root_metadata = root
        .metadata()
        .map_err(|_| filesystem_error(&root_display))?;
    if !root_metadata.file_type().is_dir()
        || !owner.accepts(root_metadata.uid(), root_metadata.gid())
        || root_metadata.mode() & 0o022 != 0
    {
        return Err(filesystem_error(&root_display));
    }
    let mut directories = vec![RetainedInstalledDirectory {
        name: None,
        display: root_display.clone(),
        descriptor: root,
        metadata: StableFileMetadata::new(&root_metadata),
    }];
    let mut display = root_display;
    for (index, component) in components.iter().enumerate() {
        display.push(component);
        let Some(directory) = try_open_directory_at(
            &directories
                .last()
                .expect("the installed path always retains its root")
                .descriptor,
            component,
            &display,
        )?
        else {
            let retained = InstalledDirectoryPath {
                canonical_root: canonical_root.to_path_buf(),
                directories,
            };
            after_absent_lookup(&display);
            let fresh_parent = retained.reopen_canonical_path()?;
            ensure_directory_entry_absent_at(&fresh_parent, component, &display)?;
            return Ok(None);
        };
        let metadata = directory
            .metadata()
            .map_err(|_| filesystem_error(&display))?;
        let mode_is_valid = if index + 1 == components.len() {
            final_mode.accepts(metadata.mode())
        } else {
            metadata.mode() & 0o022 == 0
        };
        if !metadata.file_type().is_dir()
            || !owner.accepts(metadata.uid(), metadata.gid())
            || !mode_is_valid
        {
            return Err(filesystem_error(&display));
        }
        directories.push(RetainedInstalledDirectory {
            name: Some((*component).to_owned()),
            display: display.clone(),
            descriptor: directory,
            metadata: StableFileMetadata::new(&metadata),
        });
    }
    Ok(Some(InstalledDirectoryPath {
        canonical_root: canonical_root.to_path_buf(),
        directories,
    }))
}

#[cfg(unix)]
fn open_directory_at(
    parent: &File,
    name: &str,
    display: &Path,
) -> Result<File, RuntimeArtifactError> {
    try_open_directory_at(parent, name, display)?.ok_or_else(|| filesystem_error(display))
}

#[cfg(unix)]
fn try_open_directory_at(
    parent: &File,
    name: &str,
    display: &Path,
) -> Result<Option<File>, RuntimeArtifactError> {
    let name = CString::new(name).map_err(|_| filesystem_error(display))?;
    // SAFETY: `parent` remains open for the call, `name` is NUL-terminated,
    // and a successful descriptor is immediately owned by `File`.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(filesystem_error(display))
        };
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(Some(unsafe { File::from_raw_fd(descriptor) }))
}

#[cfg(unix)]
fn ensure_directory_entry_absent_at(
    parent: &File,
    name: &str,
    display: &Path,
) -> Result<(), RuntimeArtifactError> {
    if try_open_directory_at(parent, name, display)?.is_some() {
        Err(filesystem_error(display))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn open_file_at(
    directory: &File,
    name: &str,
    display: &Path,
) -> Result<File, RuntimeArtifactError> {
    try_open_file_at(directory, name, display)?.ok_or_else(|| filesystem_error(display))
}

#[cfg(unix)]
fn try_open_file_at(
    directory: &File,
    name: &str,
    display: &Path,
) -> Result<Option<File>, RuntimeArtifactError> {
    let name = CString::new(name).map_err(|_| filesystem_error(display))?;
    // SAFETY: `directory` remains open for the call, `name` is
    // NUL-terminated, and a successful descriptor is immediately owned.
    // `O_NONBLOCK` prevents a FIFO from hanging before every caller's
    // immediate exact-regular-file metadata check; it is inert for regular
    // installed files.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(filesystem_error(display))
        };
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(Some(unsafe { File::from_raw_fd(descriptor) }))
}

#[cfg(unix)]
fn ensure_entry_absent_at(
    directory: &File,
    name: &str,
    display: &Path,
) -> Result<(), RuntimeArtifactError> {
    if try_open_file_at(directory, name, display)?.is_some() {
        Err(filesystem_error(display))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn read_exact_installed_file_at(
    directory: &File,
    name: &str,
    path: &Path,
    cap: usize,
) -> Result<Vec<u8>, RuntimeArtifactError> {
    read_exact_installed_file_at_with_contract(
        directory,
        name,
        path,
        cap,
        InstalledFileContract::root(0o644),
    )
}

#[cfg(unix)]
fn read_exact_installed_file_at_with_contract(
    directory: &File,
    name: &str,
    path: &Path,
    cap: usize,
    contract: InstalledFileContract,
) -> Result<Vec<u8>, RuntimeArtifactError> {
    let mut file = open_file_at(directory, name, path)?;
    let before = StableFileMetadata::new(&file.metadata().map_err(|_| filesystem_error(path))?);
    if !before.is_exact_installed_file(contract) {
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
struct PinnedInstalledFile {
    basename: &'static str,
    display: &'static Path,
    descriptor: File,
    metadata: StableFileMetadata,
    exact_bytes: Vec<u8>,
}

#[cfg(unix)]
impl std::fmt::Debug for PinnedInstalledFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedInstalledFile")
            .field("basename", &self.basename)
            .field("display", &self.display)
            .field("metadata", &self.metadata)
            .field("exact_bytes", &"[redacted]")
            .finish()
    }
}

#[cfg(unix)]
impl PinnedInstalledFile {
    fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    fn into_exact_bytes(self) -> Vec<u8> {
        self.exact_bytes
    }

    fn revalidate_from(
        &self,
        fresh_directory: &File,
        cap: usize,
        contract: InstalledFileContract,
    ) -> Result<(), RuntimeArtifactError> {
        let (retained_metadata, retained_bytes) =
            read_stable_descriptor_bytes(&self.descriptor, self.display, cap, contract)?;
        let fresh_descriptor = open_file_at(fresh_directory, self.basename, self.display)?;
        let (fresh_metadata, fresh_bytes) =
            read_stable_descriptor_bytes(&fresh_descriptor, self.display, cap, contract)?;
        if retained_metadata != self.metadata
            || fresh_metadata != self.metadata
            || retained_bytes != self.exact_bytes
            || fresh_bytes != self.exact_bytes
        {
            return Err(filesystem_error(self.display));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_pinned_installed_file_at_with_contract(
    directory: &File,
    basename: &'static str,
    display: &'static Path,
    cap: usize,
    contract: InstalledFileContract,
) -> Result<PinnedInstalledFile, RuntimeArtifactError> {
    read_pinned_installed_file_at_with_contract_if_present(
        directory, basename, display, cap, contract,
    )?
    .ok_or_else(|| filesystem_error(display))
}

#[cfg(unix)]
fn read_pinned_installed_file_at_with_contract_if_present(
    directory: &File,
    basename: &'static str,
    display: &'static Path,
    cap: usize,
    contract: InstalledFileContract,
) -> Result<Option<PinnedInstalledFile>, RuntimeArtifactError> {
    let Some(descriptor) = try_open_file_at(directory, basename, display)? else {
        return Ok(None);
    };
    let (metadata, exact_bytes) =
        read_stable_descriptor_bytes(&descriptor, display, cap, contract)?;
    Ok(Some(PinnedInstalledFile {
        basename,
        display,
        descriptor,
        metadata,
        exact_bytes,
    }))
}

#[cfg(unix)]
fn read_stable_descriptor_bytes(
    descriptor: &File,
    path: &Path,
    cap: usize,
    contract: InstalledFileContract,
) -> Result<(StableFileMetadata, Vec<u8>), RuntimeArtifactError> {
    use std::os::unix::fs::FileExt as _;

    let before =
        StableFileMetadata::new(&descriptor.metadata().map_err(|_| filesystem_error(path))?);
    if !before.is_exact_installed_file(contract) {
        return Err(filesystem_error(path));
    }
    if before.len > cap as u64 {
        return Err(RuntimeArtifactError::LimitExceeded);
    }
    let mut bytes = vec![0_u8; before.len as usize];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let count = descriptor
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|_| filesystem_error(path))?;
        if count == 0 {
            return Err(filesystem_error(path));
        }
        offset = offset
            .checked_add(count)
            .ok_or(RuntimeArtifactError::LimitExceeded)?;
    }
    let mut extra = [0_u8; 1];
    if descriptor
        .read_at(&mut extra, offset as u64)
        .map_err(|_| filesystem_error(path))?
        != 0
    {
        return Err(RuntimeArtifactError::LimitExceeded);
    }
    let after =
        StableFileMetadata::new(&descriptor.metadata().map_err(|_| filesystem_error(path))?);
    if before != after || bytes.len() as u64 != after.len {
        return Err(filesystem_error(path));
    }
    Ok((after, bytes))
}

#[cfg(unix)]
fn open_verified_installed_member_at(
    directory: &File,
    name: &str,
    path: &Path,
    member: &GuestRuntimeReleaseMember,
    expected_path: &str,
    cap: usize,
) -> Result<File, RuntimeArtifactError> {
    let mut file = open_file_at(directory, name, path)?;
    let before = StableFileMetadata::new(&file.metadata().map_err(|_| filesystem_error(path))?);
    if !before.is_exact_installed_file(InstalledFileContract::root(0o644))
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
    is_file: bool,
    is_directory: bool,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl StableFileMetadata {
    fn new(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            is_file: metadata.file_type().is_file(),
            is_directory: metadata.file_type().is_dir(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn is_exact_installed_file(self, contract: InstalledFileContract) -> bool {
        self.is_file
            && self.mode & 0o7777 == contract.mode
            && self.uid == contract.uid
            && self.gid == contract.gid
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
    const ROUTE_RING: &[u8] = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}"#;
    const ROUTE_SIGNER: &[u8] = br#"{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:7c7e324d7be6c6ee71735c900ce1041de63af7cc08fb39b6800853f966e81e34"}"#;
    const ROUTE_PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/route_grant_v2_private_ed25519.pem");
    const GATEWAY_AUTHORITY: &[u8] = br#"{"version":1,"authority_id":"gateway_authority_a","fleet_id":"fleet_a","policy_revision":1,"expected_previous":null,"credentials":[{"credential_id":"gateway_credential_a","public_key_spki":"MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8","scope":{"kind":"fleet"}}]}"#;
    const TEST_CLIENT_CA: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nclient-ca\n-----END CERTIFICATE-----\n";
    const TEST_SERVER_CERTIFICATE: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----\n";
    const TEST_SERVER_PRIVATE_KEY: &[u8] =
        b"-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n";

    #[cfg(unix)]
    fn open_test_route_directory(root: &Path) -> InstalledDirectoryPath {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(root).unwrap();
        open_installed_directory_from(
            root,
            &["route-v2"],
            InstalledDirectoryMode::Exact(0o700),
            InstalledDirectoryOwner::Exact {
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn disabled_route_signer_bytes() -> Vec<u8> {
        let mut disabled = decode_route_grant_v2_signer_reference(ROUTE_SIGNER).unwrap();
        disabled.signer = RouteGrantV2SignerSelection::Disabled;
        crate::route_grant_v2::encode_route_grant_v2_signer_reference(&disabled).unwrap()
    }

    #[cfg(unix)]
    fn write_test_route_artifacts(directory: &Path, disabled: bool) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reference = if disabled {
            disabled_route_signer_bytes()
        } else {
            ROUTE_SIGNER.to_vec()
        };
        let reference_path = directory.join("signer.v1.json");
        let ring_path = directory.join("public-key-ring.v1.json");
        std::fs::write(&reference_path, reference).unwrap();
        std::fs::write(&ring_path, ROUTE_RING).unwrap();
        std::fs::set_permissions(&reference_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&ring_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        if disabled {
            std::os::unix::fs::symlink(
                "/definitely/not/a/route/key",
                directory.join("signer-private-key.pem"),
            )
            .unwrap();
        } else {
            let private_path = directory.join("signer-private-key.pem");
            std::fs::write(&private_path, ROUTE_PRIVATE_KEY).unwrap();
            std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }

    #[cfg(unix)]
    fn write_test_gateway_machine_artifacts(directory: &Path) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (basename, bytes, mode) in [
            (
                "gateway-workload-authority.v1.json",
                GATEWAY_AUTHORITY,
                0o644,
            ),
            ("gateway-client-ca-bundle.pem", TEST_CLIENT_CA, 0o644),
            (
                "control-machine-server-certificate.pem",
                TEST_SERVER_CERTIFICATE,
                0o644,
            ),
            (
                "control-machine-server-private-key.pem",
                TEST_SERVER_PRIVATE_KEY,
                0o600,
            ),
        ] {
            let path = directory.join(basename);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    #[cfg(unix)]
    fn write_test_node_route_v2_machine_artifacts(directory: &Path) {
        use std::os::unix::fs::PermissionsExt as _;

        write_test_route_artifacts(directory, false);
        for (basename, bytes, mode) in [
            ("gateway-client-ca-bundle.pem", TEST_CLIENT_CA, 0o644),
            (
                "node-machine-server-certificate.pem",
                TEST_SERVER_CERTIFICATE,
                0o644,
            ),
            (
                "node-machine-server-private-key.pem",
                TEST_SERVER_PRIVATE_KEY,
                0o600,
            ),
        ] {
            let path = directory.join(basename);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    #[cfg(unix)]
    fn write_test_gateway_node_route_v2_machine_artifacts(directory: &Path) {
        use std::os::unix::fs::PermissionsExt as _;

        write_test_route_artifacts(directory, false);
        for (basename, bytes, mode) in [
            ("node-server-ca-bundle.pem", TEST_CLIENT_CA, 0o644),
            (
                "gateway-machine-client-certificate.pem",
                TEST_SERVER_CERTIFICATE,
                0o644,
            ),
            (
                "gateway-machine-client-private-key.pem",
                TEST_SERVER_PRIVATE_KEY,
                0o600,
            ),
        ] {
            let path = directory.join(basename);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    #[cfg(unix)]
    fn test_gateway_contracts(directory: &Path) -> (InstalledFileContract, InstalledFileContract) {
        use std::os::unix::fs::MetadataExt as _;

        let metadata =
            std::fs::metadata(directory.join("gateway-workload-authority.v1.json")).unwrap();
        (
            InstalledFileContract {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o644,
            },
            InstalledFileContract {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o600,
            },
        )
    }

    #[cfg(unix)]
    fn replace_gateway_basename(directory: &Path, phase: GatewayMachineArtifactReadPhase) {
        use std::os::unix::fs::PermissionsExt as _;

        let (basename, bytes, mode) = match phase {
            GatewayMachineArtifactReadPhase::Authority => (
                "gateway-workload-authority.v1.json",
                GATEWAY_AUTHORITY,
                0o644,
            ),
            GatewayMachineArtifactReadPhase::ClientCaBundle => {
                ("gateway-client-ca-bundle.pem", TEST_CLIENT_CA, 0o644)
            }
            GatewayMachineArtifactReadPhase::ServerCertificate => (
                "control-machine-server-certificate.pem",
                TEST_SERVER_CERTIFICATE,
                0o644,
            ),
            GatewayMachineArtifactReadPhase::ServerPrivateKey => (
                "control-machine-server-private-key.pem",
                TEST_SERVER_PRIVATE_KEY,
                0o600,
            ),
        };
        let path = directory.join(basename);
        std::fs::rename(&path, directory.join(format!("{basename}.displaced"))).unwrap();
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn test_route_contracts(directory: &Path) -> (InstalledFileContract, InstalledFileContract) {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = std::fs::metadata(directory.join("signer.v1.json")).unwrap();
        (
            InstalledFileContract {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o644,
            },
            InstalledFileContract {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o600,
            },
        )
    }

    #[cfg(unix)]
    fn recreate_route_directory(directory: &Path, disabled: bool) {
        let displaced = directory.with_file_name("route-v2-displaced");
        std::fs::rename(directory, displaced).unwrap();
        write_test_route_artifacts(directory, disabled);
    }

    #[cfg(unix)]
    fn recreate_route_basename(
        directory: &Path,
        phase: RouteGrantV2ArtifactReadPhase,
        disabled: bool,
    ) {
        use std::os::unix::fs::PermissionsExt as _;

        let (basename, bytes, mode) = match phase {
            RouteGrantV2ArtifactReadPhase::SignerReference => (
                "signer.v1.json",
                if disabled {
                    disabled_route_signer_bytes()
                } else {
                    ROUTE_SIGNER.to_vec()
                },
                0o644,
            ),
            RouteGrantV2ArtifactReadPhase::PublicKeyRing => {
                ("public-key-ring.v1.json", ROUTE_RING.to_vec(), 0o644)
            }
            RouteGrantV2ArtifactReadPhase::PrivateKey => {
                ("signer-private-key.pem", ROUTE_PRIVATE_KEY.to_vec(), 0o600)
            }
        };
        let path = directory.join(basename);
        std::fs::rename(&path, directory.join(format!("{basename}.displaced"))).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn replace_route_basename_with_fifo(directory: &Path, basename: &str, mode: u32) -> PathBuf {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        let path = directory.join(basename);
        std::fs::remove_file(&path).unwrap();
        let raw_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `raw_path` is a valid NUL-terminated filesystem path.
        let result = unsafe { libc::mkfifo(raw_path.as_ptr(), mode as libc::mode_t) };
        assert_eq!(result, 0);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    fn assert_fifo_read_fails_bounded(
        fifo_path: &Path,
        read: impl FnOnce() -> Result<(), RuntimeArtifactError> + Send + 'static,
    ) {
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::sync::mpsc;
        use std::time::Duration;

        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || sender.send(read()).unwrap());
        let outcome = match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Cleanup for the pre-fix failure mode: pair with a reader
                // blocked in `open(O_RDONLY)` so it can reach fstat, reject
                // the FIFO, and join instead of leaking a stuck test thread.
                let writer = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(fifo_path)
                    .expect("the timed-out FIFO reader must be waiting in open");
                let outcome = receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("the FIFO reader must settle after cleanup");
                drop(writer);
                reader.join().unwrap();
                panic!("installed artifact FIFO open exceeded its bound: {outcome:?}");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                reader.join().unwrap();
                panic!("installed artifact FIFO reader disconnected")
            }
        };
        reader.join().unwrap();
        assert!(matches!(
            outcome,
            Err(RuntimeArtifactError::Filesystem { .. })
        ));
    }

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
    fn provisioner_trust_path_rejects_every_alternate_before_filesystem_access() {
        assert!(matches!(
            load_installed_runtime_provisioner_trust_bundle(Path::new("relative.json")),
            Err(RuntimeArtifactError::WrongProvisionerTrustPath)
        ));
    }

    #[test]
    fn route_signing_paths_reject_every_alternate_before_filesystem_access() {
        assert!(matches!(
            load_installed_route_grant_v2_public_key_ring(Path::new("relative.json")),
            Err(RuntimeArtifactError::WrongRouteGrantV2PublicKeyRingPath)
        ));
        assert!(matches!(
            load_installed_route_grant_v2_signer(
                Path::new("relative.json"),
                Path::new(ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH),
                Path::new(ROUTE_GRANT_V2_SIGNER_PRIVATE_KEY_PATH),
            ),
            Err(RuntimeArtifactError::WrongRouteGrantV2SignerPath)
        ));
    }

    #[test]
    fn gateway_machine_paths_reject_every_alternate_before_filesystem_access() {
        assert!(matches!(
            load_installed_gateway_machine_artifacts(
                Path::new("relative.json"),
                Path::new(GATEWAY_CLIENT_CA_BUNDLE_PATH),
                Path::new(CONTROL_MACHINE_SERVER_CERTIFICATE_PATH),
                Path::new(CONTROL_MACHINE_SERVER_PRIVATE_KEY_PATH),
            ),
            Err(RuntimeArtifactError::WrongGatewayMachineArtifactPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn provisioner_identity_directory_accepts_metal_and_container_modes_only() {
        let contract = InstalledDirectoryMode::ProvisionerIdentity;
        assert!(contract.accepts(0o700), "Metal identity directory");
        assert!(contract.accepts(0o755), "container identity directory");
        for unsafe_mode in [
            0o000, 0o500, 0o711, 0o750, 0o770, 0o775, 0o777, 0o1700, 0o2700, 0o4700,
        ] {
            assert!(
                !contract.accepts(unsafe_mode),
                "mode {unsafe_mode:o} escaped the closed identity-directory contract"
            );
        }
        let route_contract = InstalledDirectoryMode::Exact(0o700);
        assert!(route_contract.accepts(0o700));
        assert!(!route_contract.accepts(0o1700));
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

    #[cfg(unix)]
    #[test]
    fn retained_directory_descriptor_cannot_be_redirected_by_path_replacement() {
        use std::io::Read as _;

        let temp = tempfile::tempdir().unwrap();
        let release_path = temp.path().join("release");
        std::fs::create_dir(&release_path).unwrap();
        std::fs::write(release_path.join("member"), b"old-directory").unwrap();
        let parent = File::open(temp.path()).unwrap();
        let retained = open_directory_at(&parent, "release", &release_path).unwrap();
        std::fs::rename(&release_path, temp.path().join("release-displaced")).unwrap();
        std::fs::create_dir(&release_path).unwrap();
        std::fs::write(release_path.join("member"), b"replacement-directory").unwrap();

        let mut member = open_file_at(&retained, "member", Path::new("member")).unwrap();
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"old-directory");
        assert_eq!(
            std::fs::read(release_path.join("member")).unwrap(),
            b"replacement-directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn active_route_signer_rejects_directory_rename_recreate_after_every_read_phase() {
        for target in [
            RouteGrantV2ArtifactReadPhase::SignerReference,
            RouteGrantV2ArtifactReadPhase::PublicKeyRing,
            RouteGrantV2ArtifactReadPhase::PrivateKey,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let directory_path = temp.path().join("route-v2");
            write_test_route_artifacts(&directory_path, false);
            let (public_contract, private_contract) = test_route_contracts(&directory_path);
            let retained = open_test_route_directory(temp.path());
            let mut replaced = false;
            let result = load_route_grant_v2_signer_from_with_phase(
                &retained,
                public_contract,
                private_contract,
                |phase| {
                    if phase == target {
                        recreate_route_directory(&directory_path, false);
                        replaced = true;
                    }
                },
            );
            assert!(replaced, "read barrier for {target:?} was not reached");
            assert!(
                matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
                "directory replacement after {target:?} escaped: {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn active_route_signer_rejects_exact_byte_basename_recreate_after_every_read_phase() {
        for target in [
            RouteGrantV2ArtifactReadPhase::SignerReference,
            RouteGrantV2ArtifactReadPhase::PublicKeyRing,
            RouteGrantV2ArtifactReadPhase::PrivateKey,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let directory_path = temp.path().join("route-v2");
            write_test_route_artifacts(&directory_path, false);
            let (public_contract, private_contract) = test_route_contracts(&directory_path);
            let retained = open_test_route_directory(temp.path());
            let mut replaced = false;
            let result = load_route_grant_v2_signer_from_with_phase(
                &retained,
                public_contract,
                private_contract,
                |phase| {
                    if phase == target {
                        recreate_route_basename(&directory_path, target, false);
                        replaced = true;
                    }
                },
            );
            assert!(replaced, "read barrier for {target:?} was not reached");
            assert!(
                matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
                "exact-byte basename replacement after {target:?} escaped: {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn disabled_route_signer_rejects_path_drift_without_opening_private_material() {
        for replace_directory in [false, true] {
            for target in [
                RouteGrantV2ArtifactReadPhase::SignerReference,
                RouteGrantV2ArtifactReadPhase::PublicKeyRing,
            ] {
                let temp = tempfile::tempdir().unwrap();
                let directory_path = temp.path().join("route-v2");
                write_test_route_artifacts(&directory_path, true);
                let (public_contract, private_contract) = test_route_contracts(&directory_path);
                let retained = open_test_route_directory(temp.path());
                let mut replaced = false;
                let result = load_route_grant_v2_signer_from_with_phase(
                    &retained,
                    public_contract,
                    private_contract,
                    |phase| {
                        assert_ne!(phase, RouteGrantV2ArtifactReadPhase::PrivateKey);
                        if phase == target {
                            if replace_directory {
                                recreate_route_directory(&directory_path, true);
                            } else {
                                recreate_route_basename(&directory_path, target, true);
                            }
                            replaced = true;
                        }
                    },
                );
                assert!(replaced, "read barrier for {target:?} was not reached");
                assert!(
                    matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
                    "disabled path replacement after {target:?} escaped: {result:?}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn public_route_ring_reader_rejects_directory_and_exact_byte_basename_recreate() {
        for replace_directory in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let directory_path = temp.path().join("route-v2");
            write_test_route_artifacts(&directory_path, false);
            let (public_contract, _) = test_route_contracts(&directory_path);
            let retained = open_test_route_directory(temp.path());
            let mut replaced = false;
            let result = load_route_grant_v2_public_key_ring_from_with_phase(
                &retained,
                public_contract,
                |phase| {
                    assert_eq!(phase, RouteGrantV2ArtifactReadPhase::PublicKeyRing);
                    if replace_directory {
                        recreate_route_directory(&directory_path, false);
                    } else {
                        recreate_route_basename(&directory_path, phase, false);
                    }
                    replaced = true;
                },
            );
            assert!(replaced, "public-ring read barrier was not reached");
            assert!(
                matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
                "public-ring path replacement escaped: {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_route_artifact_fifo_is_rejected_without_blocking() {
        for (basename, mode) in [
            ("signer.v1.json", 0o644),
            ("public-key-ring.v1.json", 0o644),
            ("signer-private-key.pem", 0o600),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let directory_path = temp.path().join("route-v2");
            write_test_route_artifacts(&directory_path, false);
            let (public_contract, private_contract) = test_route_contracts(&directory_path);
            let fifo_path = replace_route_basename_with_fifo(&directory_path, basename, mode);
            let retained = open_test_route_directory(temp.path());
            assert_fifo_read_fails_bounded(&fifo_path, move || {
                load_route_grant_v2_signer_from(&retained, public_contract, private_contract)
                    .map(|_| ())
            });
        }

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        write_test_route_artifacts(&directory_path, false);
        let (public_contract, _) = test_route_contracts(&directory_path);
        let fifo_path =
            replace_route_basename_with_fifo(&directory_path, "public-key-ring.v1.json", 0o644);
        let retained = open_test_route_directory(temp.path());
        assert_fifo_read_fails_bounded(&fifo_path, move || {
            load_route_grant_v2_public_key_ring_from(&retained, public_contract).map(|_| ())
        });
    }

    #[cfg(unix)]
    #[test]
    fn optional_route_ring_reader_rejects_absence_and_loaded_path_aba() {
        use std::os::unix::fs::PermissionsExt as _;

        for replace_directory in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let directory_path = temp.path().join("route-v2");
            write_test_route_artifacts(&directory_path, false);
            let (public_contract, _) = test_route_contracts(&directory_path);
            let retained = open_test_route_directory(temp.path());
            let result = inspect_route_grant_v2_public_key_ring_from_with_phase(
                &retained,
                public_contract,
                |phase| {
                    assert_eq!(phase, RouteGrantV2ArtifactReadPhase::PublicKeyRing);
                    if replace_directory {
                        recreate_route_directory(&directory_path, false);
                    } else {
                        recreate_route_basename(&directory_path, phase, false);
                    }
                },
            );
            assert!(
                matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
                "optional loaded-ring path replacement escaped: {result:?}"
            );
        }

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        std::fs::create_dir(&directory_path).unwrap();
        std::fs::set_permissions(&directory_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let retained = open_test_route_directory(temp.path());
        let (uid, gid) = {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = std::fs::metadata(&directory_path).unwrap();
            (metadata.uid(), metadata.gid())
        };
        let result = inspect_route_grant_v2_public_key_ring_from_with_phase(
            &retained,
            InstalledFileContract {
                uid,
                gid,
                mode: 0o644,
            },
            |_| {
                let path = directory_path.join("public-key-ring.v1.json");
                std::fs::write(&path, ROUTE_RING).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            },
        );
        assert!(
            matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
            "a ring created after the absent lookup escaped: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pinned_private_file_debug_never_contains_exact_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        write_test_route_artifacts(&directory_path, false);
        let (_, private_contract) = test_route_contracts(&directory_path);
        let retained = open_test_route_directory(temp.path());
        let pinned = read_pinned_installed_file_at_with_contract(
            retained.final_descriptor(),
            "signer-private-key.pem",
            Path::new(ROUTE_GRANT_V2_SIGNER_PRIVATE_KEY_PATH),
            ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES,
            private_contract,
        )
        .unwrap();

        let debug = format!("{pinned:?}");
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains("signer-private-key.pem"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));
        assert!(!debug.contains(&format!("{:?}", ROUTE_PRIVATE_KEY)));
    }

    #[cfg(unix)]
    #[test]
    fn optional_installed_directory_absence_is_revalidated_on_the_retained_chain() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(temp.path()).unwrap();
        let owner = InstalledDirectoryOwner::Exact {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        assert!(open_installed_directory_if_present_from(
            temp.path(),
            &["route-v2"],
            InstalledDirectoryMode::Exact(0o700),
            owner,
        )
        .unwrap()
        .is_none());

        let result = open_installed_directory_if_present_from_with_phase(
            temp.path(),
            &["route-v2"],
            InstalledDirectoryMode::Exact(0o700),
            owner,
            |missing| {
                std::fs::create_dir(missing).unwrap();
                std::fs::set_permissions(missing, std::fs::Permissions::from_mode(0o700)).unwrap();
            },
        );
        assert!(
            matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
            "a directory created after the absent lookup escaped: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn route_signer_reader_pins_one_closed_set_and_redacts_private_material() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        std::fs::create_dir(&directory_path).unwrap();
        std::fs::set_permissions(&directory_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ring_path = directory_path.join("public-key-ring.v1.json");
        let reference_path = directory_path.join("signer.v1.json");
        let private_path = directory_path.join("signer-private-key.pem");
        std::fs::write(&ring_path, ROUTE_RING).unwrap();
        std::fs::write(&reference_path, ROUTE_SIGNER).unwrap();
        std::fs::write(&private_path, ROUTE_PRIVATE_KEY).unwrap();
        std::fs::set_permissions(&ring_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&reference_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let metadata = std::fs::metadata(&reference_path).unwrap();
        let public_contract = InstalledFileContract {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: 0o644,
        };
        let private_contract = InstalledFileContract {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: 0o600,
        };
        let retained = open_test_route_directory(temp.path());
        let installed =
            load_route_grant_v2_signer_from(&retained, public_contract, private_contract).unwrap();
        assert_eq!(installed.exact_reference_bytes(), ROUTE_SIGNER);
        assert_eq!(installed.ring().exact_bytes(), ROUTE_RING);
        assert_eq!(installed.private_key_pem(), Some(ROUTE_PRIVATE_KEY));
        let debug = format!("{installed:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));

        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_route_grant_v2_signer_from(&retained, public_contract, private_contract).is_err()
        );
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o4600)).unwrap();
        assert!(
            load_route_grant_v2_signer_from(&retained, public_contract, private_contract).is_err()
        );
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&private_path, directory_path.join("private-hardlink")).unwrap();
        assert!(
            load_route_grant_v2_signer_from(&retained, public_contract, private_contract).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn route_ring_inspection_distinguishes_absence_from_invalid_installed_bytes() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        std::fs::create_dir(&directory_path).unwrap();
        std::fs::set_permissions(&directory_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(&directory_path).unwrap();
        let contract = InstalledFileContract {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: 0o644,
        };
        let retained = open_test_route_directory(temp.path());

        assert!(matches!(
            inspect_route_grant_v2_public_key_ring_from(&retained, contract).unwrap(),
            InstalledRouteGrantV2PublicKeyRingState::Unavailable
        ));

        let ring_path = directory_path.join("public-key-ring.v1.json");
        std::fs::write(&ring_path, ROUTE_RING).unwrap();
        std::fs::set_permissions(&ring_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let retained = open_test_route_directory(temp.path());
        let InstalledRouteGrantV2PublicKeyRingState::Loaded(installed) =
            inspect_route_grant_v2_public_key_ring_from(&retained, contract).unwrap()
        else {
            panic!("canonical installed ring was reported unavailable")
        };
        assert_eq!(installed.exact_bytes(), ROUTE_RING);
        assert_eq!(installed.ring().ring_version.get(), 1);

        std::fs::write(&ring_path, b"{}").unwrap();
        let retained = open_test_route_directory(temp.path());
        assert!(matches!(
            inspect_route_grant_v2_public_key_ring_from(&retained, contract),
            Err(RuntimeArtifactError::InvalidRouteGrantV2PublicKeyRing)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn gateway_machine_reader_pins_one_closed_set_and_redacts_private_material() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        write_test_gateway_machine_artifacts(&directory_path);
        let (public_contract, private_contract) = test_gateway_contracts(&directory_path);
        let retained = open_test_route_directory(temp.path());
        let installed =
            load_gateway_machine_artifacts_from(&retained, public_contract, private_contract)
                .unwrap();
        assert_eq!(installed.exact_authority_bytes(), GATEWAY_AUTHORITY);
        assert_eq!(installed.client_ca_bundle_pem(), TEST_CLIENT_CA);
        assert_eq!(installed.server_certificate_pem(), TEST_SERVER_CERTIFICATE);
        assert_eq!(installed.server_private_key_pem(), TEST_SERVER_PRIVATE_KEY);
        assert_eq!(
            installed.authority().authority_id.as_str(),
            "gateway_authority_a"
        );
        let debug = format!("{installed:?}");
        assert!(debug.contains("gateway_authority_a"));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));

        let private_path = directory_path.join("control-machine-server-private-key.pem");
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_gateway_machine_artifacts_from(&retained, public_contract, private_contract),
            Err(RuntimeArtifactError::Filesystem { .. })
        ));
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&private_path, directory_path.join("private-hardlink")).unwrap();
        assert!(matches!(
            load_gateway_machine_artifacts_from(&retained, public_contract, private_contract),
            Err(RuntimeArtifactError::Filesystem { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn gateway_machine_reader_rejects_basename_replacement_after_every_read_phase() {
        for target in [
            GatewayMachineArtifactReadPhase::Authority,
            GatewayMachineArtifactReadPhase::ClientCaBundle,
            GatewayMachineArtifactReadPhase::ServerCertificate,
            GatewayMachineArtifactReadPhase::ServerPrivateKey,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let directory_path = temp.path().join("route-v2");
            write_test_gateway_machine_artifacts(&directory_path);
            let (public_contract, private_contract) = test_gateway_contracts(&directory_path);
            let retained = open_test_route_directory(temp.path());
            let result = load_gateway_machine_artifacts_from_with_phase(
                &retained,
                public_contract,
                private_contract,
                |phase| {
                    if phase == target {
                        replace_gateway_basename(&directory_path, phase);
                    }
                },
            );
            assert!(
                matches!(result, Err(RuntimeArtifactError::Filesystem { .. })),
                "Gateway artifact replacement escaped at {target:?}: {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn gateway_machine_reader_enforces_pem_bounds_and_nonempty_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        write_test_gateway_machine_artifacts(&directory_path);
        let (public_contract, private_contract) = test_gateway_contracts(&directory_path);
        let ca_path = directory_path.join("gateway-client-ca-bundle.pem");
        std::fs::write(
            &ca_path,
            vec![b'x'; GATEWAY_CLIENT_CA_BUNDLE_MAX_WIRE_BYTES + 1],
        )
        .unwrap();
        std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let retained = open_test_route_directory(temp.path());
        assert!(matches!(
            load_gateway_machine_artifacts_from(&retained, public_contract, private_contract),
            Err(RuntimeArtifactError::LimitExceeded)
        ));

        std::fs::write(&ca_path, []).unwrap();
        let retained = open_test_route_directory(temp.path());
        assert!(matches!(
            load_gateway_machine_artifacts_from(&retained, public_contract, private_contract),
            Err(RuntimeArtifactError::InvalidGatewayMachineArtifacts)
        ));
    }

    #[test]
    fn route_v2_machine_readers_reject_every_alternate_path_before_io() {
        assert!(matches!(
            load_installed_node_route_v2_machine_artifacts(
                Path::new("/not/the/fixed/ring"),
                Path::new(GATEWAY_CLIENT_CA_BUNDLE_PATH),
                Path::new(NODE_ROUTE_V2_SERVER_CERTIFICATE_PATH),
                Path::new(NODE_ROUTE_V2_SERVER_PRIVATE_KEY_PATH),
            )
            .unwrap_err(),
            RuntimeArtifactError::WrongNodeRouteV2MachineArtifactPath
        ));
        assert!(matches!(
            load_installed_gateway_node_route_v2_machine_artifacts(
                Path::new(NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH),
                Path::new(GATEWAY_ROUTE_V2_CLIENT_CERTIFICATE_PATH),
                Path::new("/not/the/fixed/client-key"),
            )
            .unwrap_err(),
            RuntimeArtifactError::WrongGatewayNodeRouteV2MachineArtifactPath
        ));
    }

    #[cfg(unix)]
    #[test]
    fn node_route_v2_machine_reader_pins_closed_set_and_private_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        write_test_node_route_v2_machine_artifacts(&directory_path);
        let (public_contract, private_contract) = test_route_contracts(&directory_path);
        let retained = open_test_route_directory(temp.path());
        let installed =
            load_node_route_v2_machine_artifacts_from(&retained, public_contract, private_contract)
                .unwrap();
        assert_eq!(installed.ring().exact_bytes(), ROUTE_RING);
        assert_eq!(installed.gateway_client_ca_bundle_pem(), TEST_CLIENT_CA);
        assert_eq!(installed.server_certificate_pem(), TEST_SERVER_CERTIFICATE);
        assert_eq!(installed.server_private_key_pem(), TEST_SERVER_PRIVATE_KEY);
        let debug = format!("{installed:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));

        let key_path = directory_path.join("node-machine-server-private-key.pem");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_node_route_v2_machine_artifacts_from(&retained, public_contract, private_contract,),
            Err(RuntimeArtifactError::Filesystem { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn gateway_node_route_v2_machine_reader_pins_closed_set_and_private_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        write_test_gateway_node_route_v2_machine_artifacts(&directory_path);
        let (public_contract, private_contract) = test_route_contracts(&directory_path);
        let retained = open_test_route_directory(temp.path());
        let installed = load_gateway_node_route_v2_machine_artifacts_from(
            &retained,
            public_contract,
            private_contract,
        )
        .unwrap();
        assert_eq!(installed.node_server_ca_bundle_pem(), TEST_CLIENT_CA);
        assert_eq!(installed.client_certificate_pem(), TEST_SERVER_CERTIFICATE);
        assert_eq!(installed.client_private_key_pem(), TEST_SERVER_PRIVATE_KEY);
        let debug = format!("{installed:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));

        let key_path = directory_path.join("gateway-machine-client-private-key.pem");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_gateway_node_route_v2_machine_artifacts_from(
                &retained,
                public_contract,
                private_contract,
            ),
            Err(RuntimeArtifactError::Filesystem { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn disabled_route_signer_never_opens_private_material() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let directory_path = temp.path().join("route-v2");
        std::fs::create_dir(&directory_path).unwrap();
        let ring_path = directory_path.join("public-key-ring.v1.json");
        let reference_path = directory_path.join("signer.v1.json");
        std::fs::write(&ring_path, ROUTE_RING).unwrap();
        let mut disabled = decode_route_grant_v2_signer_reference(ROUTE_SIGNER).unwrap();
        disabled.signer = RouteGrantV2SignerSelection::Disabled;
        std::fs::write(
            &reference_path,
            crate::route_grant_v2::encode_route_grant_v2_signer_reference(&disabled).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&ring_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&reference_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(
            "/definitely/not/a/route/key",
            directory_path.join("signer-private-key.pem"),
        )
        .unwrap();

        let metadata = std::fs::metadata(&reference_path).unwrap();
        let public_contract = InstalledFileContract {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: 0o644,
        };
        std::fs::set_permissions(&directory_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let retained = open_test_route_directory(temp.path());
        let installed = load_route_grant_v2_signer_from(
            &retained,
            public_contract,
            InstalledFileContract {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o600,
            },
        )
        .unwrap();
        assert!(matches!(
            &installed.reference().signer,
            RouteGrantV2SignerSelection::Disabled
        ));
        assert_eq!(installed.private_key_pem(), None);
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Cursor};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::gateway_workload_identity::{
    canonical_gateway_leaf_spki_sha256, decode_gateway_workload_identity_authority,
    encode_gateway_workload_identity_authority, GatewayWorkloadCredentialPolicy,
    GatewayWorkloadCredentialScope, GatewayWorkloadIdentityAuthority,
};
use cats_api::route_grant_v2::{
    decode_route_grant_v2_public_key_ring, decode_route_grant_v2_signer_reference,
    encode_route_grant_v2_public_key_ring, encode_route_grant_v2_signer_reference,
    RouteGrantV2PublicKey, RouteGrantV2PublicKeyEntry, RouteGrantV2PublicKeyRingArtifact,
    RouteGrantV2SignerReference, RouteGrantV2SignerSelection,
};
use cats_api::route_signing_operator::{
    decode_route_v2_rotation_operator_trust, encode_route_v2_rotation_operator_trust,
    RouteV2RotationOperatorCredential, RouteV2RotationOperatorTrust,
};
use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, Base64UrlNoPad, ContractVersion, Epoch, Hostname, Id,
    Sha256Digest,
};
use ring::rand::{SecureRandom as _, SystemRandom};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    generate_pkcs8_v2_pem, list_directory_names, open_directory_nofollow, open_file_at,
    read_regular_at, read_stable_file, report, set_file_mode, sync_directory, validate_directory,
    validate_regular_metadata, write_new_file_at, Cli, RuntimeProvisionerRouteV2R1Command,
};
use crate::stable_unix_fs::{c_os_name, mkdir_at};

const CONTROL_MACHINE_DNS: &str = "cats-controld-route-v2.cats.svc.cluster.local";
const HTTP_11_ALPN: &[u8] = b"http/1.1";
const MAX_PEM_BYTES: usize = 65_536;
const MAX_PRIVATE_KEY_BYTES: usize = 16_384;
const MAX_JSON_BYTES: usize = 262_144;
const ROOT_DIRECTORIES: [&str; 5] = ["authority", "control", "gateway", "node", "provider"];
const AUTHORITY_FILES: [(&str, u32); 3] = [
    ("route-v2-ca-certificate.pem", 0o644),
    ("route-v2-ca-private-key.pem", 0o600),
    ("rotation-operator-private-key.pem", 0o600),
];
const CONTROL_FILES: [(&str, u32); 8] = [
    ("control-machine-server-certificate.pem", 0o644),
    ("control-machine-server-private-key.pem", 0o600),
    ("gateway-client-ca-bundle.pem", 0o644),
    ("gateway-workload-authority.v1.json", 0o644),
    ("public-key-ring.v1.json", 0o644),
    ("rotation-operator-trust.v1.json", 0o644),
    ("signer-private-key.pem", 0o600),
    ("signer.v1.json", 0o644),
];
const GATEWAY_FILES: [(&str, u32); 3] = [
    ("gateway-machine-client-certificate.pem", 0o644),
    ("gateway-machine-client-private-key.pem", 0o600),
    ("node-server-ca-bundle.pem", 0o644),
];
const NODE_FILES: [(&str, u32); 5] = [
    ("gateway-client-ca-bundle.pem", 0o644),
    ("node-machine-server-certificate.pem", 0o644),
    ("node-machine-server-private-key.pem", 0o600),
    ("public-key-ring.v1.json", 0o644),
    ("rotation-operator-trust.v1.json", 0o644),
];
const PROVIDER_FILES: [(&str, u32); 3] = [
    ("control-secret.v1.json", 0o600),
    ("gateway-secret.v1.json", 0o600),
    ("node-secret.v1.json", 0o600),
];

pub(super) fn run(cli: &Cli, command: &RuntimeProvisionerRouteV2R1Command) -> Result<()> {
    let inputs = match command {
        RuntimeProvisionerRouteV2R1Command::Generate {
            output,
            node_server_dns,
            control_secret_name,
            gateway_secret_name,
            node_secret_name,
            release_commit_sha,
            openssl,
        } => {
            let inputs = Inputs::new(
                output,
                node_server_dns,
                control_secret_name,
                gateway_secret_name,
                node_secret_name,
                release_commit_sha,
            )?;
            let (candidate, created) = Candidate::open_or_create(&inputs.root, 0)?;
            if created {
                let openssl = validate_openssl(openssl, 0)?;
                generate(&candidate, &inputs, &openssl)?;
            }
            inputs
        }
        RuntimeProvisionerRouteV2R1Command::Verify {
            input,
            node_server_dns,
            control_secret_name,
            gateway_secret_name,
            node_secret_name,
            release_commit_sha,
        } => Inputs::new(
            input,
            node_server_dns,
            control_secret_name,
            gateway_secret_name,
            node_secret_name,
            release_commit_sha,
        )?,
    };
    let candidate = Candidate::open_existing(&inputs.root, 0)?;
    let receipt = verify(&candidate, &inputs)?;
    report(cli, &receipt)
}

struct Inputs {
    root: PathBuf,
    node_server_dns: Vec<String>,
    control_secret_name: String,
    gateway_secret_name: String,
    node_secret_name: String,
    release_commit_sha: String,
}

impl Inputs {
    fn new(
        root: &Path,
        node_server_dns: &[String],
        control_secret_name: &str,
        gateway_secret_name: &str,
        node_secret_name: &str,
        release_commit_sha: &str,
    ) -> Result<Self> {
        anyhow::ensure!(
            root.is_absolute() && root != Path::new("/"),
            "Route v2 output must be an absolute non-root directory"
        );
        let mut dns = BTreeSet::new();
        for value in node_server_dns {
            let hostname = Hostname::new(value.clone()).context("invalid Node server DNS name")?;
            anyhow::ensure!(
                dns.insert(hostname.to_string()),
                "Node server DNS names must be unique"
            );
        }
        anyhow::ensure!(
            !dns.is_empty(),
            "at least one Node server DNS name is required"
        );
        validate_kubernetes_secret_name(control_secret_name)?;
        validate_kubernetes_secret_name(gateway_secret_name)?;
        anyhow::ensure!(
            release_commit_sha.len() == 40
                && release_commit_sha
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Route v2 release commit SHA must be exact lowercase 40-hex"
        );
        anyhow::ensure!(
            node_secret_name.len() <= 512
                && node_secret_name.ends_with("-route-v2-node-r1")
                && node_secret_name.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }),
            "Node Secrets Manager name must end in -route-v2-node-r1 and contain lowercase DNS-label characters"
        );
        Ok(Self {
            root: root.to_path_buf(),
            node_server_dns: dns.into_iter().collect(),
            control_secret_name: control_secret_name.to_owned(),
            gateway_secret_name: gateway_secret_name.to_owned(),
            node_secret_name: node_secret_name.to_owned(),
            release_commit_sha: release_commit_sha.to_owned(),
        })
    }
}

fn validate_kubernetes_secret_name(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() <= 253
            && value.ends_with("-r1")
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
            }),
        "Kubernetes Secret name must be a DNS subdomain ending in -r1"
    );
    Ok(())
}

struct Candidate {
    root_path: PathBuf,
    root: File,
    authority: File,
    control: File,
    gateway: File,
    node: File,
    provider: File,
    expected_uid: u32,
}

impl Candidate {
    fn open_or_create(path: &Path, expected_uid: u32) -> Result<(Self, bool)> {
        let parent_path = path.parent().context("Route v2 output has no parent")?;
        let basename = path
            .file_name()
            .context("Route v2 output has no basename")?;
        let parent = open_directory_nofollow(parent_path)?;
        validate_directory(&parent, expected_uid, None, "Route v2 output parent")?;
        let name = c_os_name(basename)?;
        let (root, created) =
            match open_file_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(root) => (root, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    mkdir_at(&parent, &name, 0o700).context("create Route v2 output directory")?;
                    sync_directory(&parent, "sync Route v2 output parent")?;
                    let root = open_file_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                    set_file_mode(&root, 0o700)?;
                    root.sync_all().context("sync Route v2 output directory")?;
                    (root, true)
                }
                Err(error) => return Err(error).context("open Route v2 output directory"),
            };
        validate_directory(
            &root,
            expected_uid,
            Some(0o700),
            "Route v2 output directory",
        )?;
        if created {
            for directory in ROOT_DIRECTORIES {
                let name = super::c_name(directory)?;
                mkdir_at(&root, &name, 0o700)
                    .with_context(|| format!("create Route v2 {directory} directory"))?;
                let child = open_file_at(&root, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                set_file_mode(&child, 0o700)?;
                child.sync_all().context("sync Route v2 child directory")?;
            }
            sync_directory(&root, "sync Route v2 output children")?;
        }
        Ok((Self::from_root(path, root, expected_uid)?, created))
    }

    fn open_existing(path: &Path, expected_uid: u32) -> Result<Self> {
        let root = open_directory_nofollow(path)?;
        validate_directory(
            &root,
            expected_uid,
            Some(0o700),
            "Route v2 output directory",
        )?;
        Self::from_root(path, root, expected_uid)
    }

    fn from_root(path: &Path, root: File, expected_uid: u32) -> Result<Self> {
        let open_child = |label: &str| -> Result<File> {
            let name = super::c_name(label)?;
            let child = open_file_at(&root, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .with_context(|| format!("open Route v2 {label} directory"))?;
            validate_directory(
                &child,
                expected_uid,
                Some(0o700),
                "Route v2 child directory",
            )?;
            Ok(child)
        };
        Ok(Self {
            root_path: path.to_path_buf(),
            authority: open_child("authority")?,
            control: open_child("control")?,
            gateway: open_child("gateway")?,
            node: open_child("node")?,
            provider: open_child("provider")?,
            root,
            expected_uid,
        })
    }
}

fn generate(candidate: &Candidate, inputs: &Inputs, openssl_executable: &Path) -> Result<()> {
    let work_name = super::c_name(".generation-incomplete.v1")?;
    mkdir_at(&candidate.root, &work_name, 0o700).context("create private generation directory")?;
    let work = open_file_at(
        &candidate.root,
        &work_name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    set_file_mode(&work, 0o700)?;
    work.sync_all()
        .context("sync private generation directory")?;
    sync_directory(&candidate.root, "sync private generation parent")?;
    let work_path = candidate.root_path.join(".generation-incomplete.v1");

    let ca_key = work_path.join("ca-key.pem");
    let ca_certificate = work_path.join("ca-certificate.pem");
    openssl(
        openssl_executable,
        &[
            "genpkey".as_ref(),
            "-algorithm".as_ref(),
            "ED25519".as_ref(),
            "-out".as_ref(),
            ca_key.as_os_str(),
        ],
    )?;
    openssl(
        openssl_executable,
        &[
            "req".as_ref(),
            "-new".as_ref(),
            "-x509".as_ref(),
            "-key".as_ref(),
            ca_key.as_os_str(),
            "-out".as_ref(),
            ca_certificate.as_os_str(),
            "-days".as_ref(),
            "3650".as_ref(),
            "-subj".as_ref(),
            "/CN=Cats Route v2 revision 1 root".as_ref(),
            "-addext".as_ref(),
            "basicConstraints=critical,CA:TRUE,pathlen:0".as_ref(),
            "-addext".as_ref(),
            "keyUsage=critical,keyCertSign,cRLSign".as_ref(),
            "-addext".as_ref(),
            "subjectKeyIdentifier=hash".as_ref(),
        ],
    )?;

    let control = issue_leaf(
        &work,
        &work_path,
        LeafSpec {
            label: "control",
            common_name: "Cats Route v2 Control machine",
            extended_key_usage: "serverAuth",
            dns_names: &[CONTROL_MACHINE_DNS.to_owned()],
        },
        &ca_key,
        &ca_certificate,
        openssl_executable,
    )?;
    let node = issue_leaf(
        &work,
        &work_path,
        LeafSpec {
            label: "node",
            common_name: "Cats Route v2 Node machine",
            extended_key_usage: "serverAuth",
            dns_names: &inputs.node_server_dns,
        },
        &ca_key,
        &ca_certificate,
        openssl_executable,
    )?;
    let gateway = issue_leaf(
        &work,
        &work_path,
        LeafSpec {
            label: "gateway",
            common_name: "Cats Route v2 Gateway machine",
            extended_key_usage: "clientAuth",
            dns_names: &[],
        },
        &ca_key,
        &ca_certificate,
        openssl_executable,
    )?;

    let ca_key_bytes = read_generated(
        &ca_key,
        MAX_PRIVATE_KEY_BYTES,
        0o600,
        candidate.expected_uid,
    )?;
    let ca_certificate_bytes = read_generated(
        &ca_certificate,
        MAX_PEM_BYTES,
        0o644,
        candidate.expected_uid,
    )?;
    let control_key = read_generated(
        &control.key,
        MAX_PRIVATE_KEY_BYTES,
        0o600,
        candidate.expected_uid,
    )?;
    let control_certificate = read_generated(
        &control.certificate,
        MAX_PEM_BYTES,
        0o644,
        candidate.expected_uid,
    )?;
    let node_key = read_generated(
        &node.key,
        MAX_PRIVATE_KEY_BYTES,
        0o600,
        candidate.expected_uid,
    )?;
    let node_certificate = read_generated(
        &node.certificate,
        MAX_PEM_BYTES,
        0o644,
        candidate.expected_uid,
    )?;
    let gateway_key = read_generated(
        &gateway.key,
        MAX_PRIVATE_KEY_BYTES,
        0o600,
        candidate.expected_uid,
    )?;
    let gateway_certificate = read_generated(
        &gateway.certificate,
        MAX_PEM_BYTES,
        0o644,
        candidate.expected_uid,
    )?;

    let mut signer_private_key = generate_pkcs8_v2_pem()?;
    let signer_validation_id = Id::new(random_id("route_signer_validation")?)
        .expect("generated signer validation ID is valid");
    let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(signer_validation_id, &signer_private_key)
        .map_err(|_| anyhow!("generated Route v2 signer is not strict PKCS#8 v2"))?;
    let signer_public = RouteGrantV2PublicKey::from_spki_der(signer.public_key_spki_der())
        .context("derive Route v2 signer public key")?;
    let signer_spki = Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.public_key_spki_der()))
        .expect("generated Ed25519 SPKI is canonical base64url");
    let ring = RouteGrantV2PublicKeyRingArtifact {
        version: ContractVersion::V1,
        ring_version: Epoch::new(1).expect("one is a valid ring version"),
        expected_previous: None,
        keys: vec![RouteGrantV2PublicKeyEntry {
            kid: signer_public.kid().clone(),
            public_key_spki: signer_spki,
        }],
    };
    let ring_bytes = encode_route_grant_v2_public_key_ring(&ring)
        .map_err(|error| anyhow!("encode generated Route v2 ring: {error:?}"))?;
    let signer_reference = RouteGrantV2SignerReference {
        version: ContractVersion::V1,
        deployment_id: Id::new(random_id("route_deployment")?)
            .expect("generated deployment ID is valid"),
        signer_revision: Epoch::new(1).expect("one is a valid signer revision"),
        expected_previous: None,
        signer: RouteGrantV2SignerSelection::Active {
            active_kid: signer_public.kid().clone(),
            secret_reference_id: Id::new(random_id("route_secret")?)
                .expect("generated secret reference ID is valid"),
        },
        public_key_ring_version: ring.ring_version,
        public_key_ring_digest: ring
            .digest()
            .map_err(|error| anyhow!("digest generated Route v2 ring: {error:?}"))?,
    };
    let signer_reference_bytes = encode_route_grant_v2_signer_reference(&signer_reference)
        .map_err(|error| anyhow!("encode generated Route v2 signer reference: {error:?}"))?;
    let mut rotation_operator_private_key = generate_pkcs8_v2_pem()?;
    let rotation_operator_credential_id = Id::new(random_id("route_rotation_operator")?)
        .expect("generated Route rotation operator credential ID is valid");
    let rotation_operator_signer = Ed25519RequestSigner::from_pkcs8_v2_pem(
        rotation_operator_credential_id.clone(),
        &rotation_operator_private_key,
    )
    .map_err(|_| anyhow!("generated Route rotation operator key is not strict PKCS#8 v2"))?;
    let rotation_operator_spki =
        Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(rotation_operator_signer.public_key_spki_der()))
            .expect("generated Route rotation operator SPKI is canonical base64url");
    let rotation_operator_trust = RouteV2RotationOperatorTrust {
        version: ContractVersion::V1,
        authority_id: Id::new(random_id("route_rotation_authority")?)
            .expect("generated Route rotation authority ID is valid"),
        route_deployment_id: signer_reference.deployment_id.clone(),
        release_commit_sha: inputs.release_commit_sha.clone(),
        threshold: 1,
        credentials: vec![RouteV2RotationOperatorCredential {
            credential_id: rotation_operator_credential_id,
            public_key_spki_sha256: canonical_ed25519_spki_sha256(&rotation_operator_spki)
                .expect("generated Route rotation operator SPKI is canonical Ed25519"),
            public_key_spki: rotation_operator_spki,
        }],
    };
    let rotation_operator_trust_bytes =
        encode_route_v2_rotation_operator_trust(&rotation_operator_trust)
            .map_err(|error| anyhow!("encode Route rotation operator trust: {error}"))?;

    let gateway_credential_id = Id::new(random_id("gateway_credential")?)
        .expect("generated Gateway credential ID is valid");
    let gateway_signer =
        Ed25519RequestSigner::from_pkcs8_pem(gateway_credential_id.clone(), &gateway_key)
            .map_err(|_| anyhow!("generated Gateway TLS key is not Ed25519 PKCS#8"))?;
    let gateway_authority = GatewayWorkloadIdentityAuthority {
        version: ContractVersion::V1,
        authority_id: Id::new(random_id("gateway_authority")?)
            .expect("generated Gateway authority ID is valid"),
        fleet_id: Id::new(random_id("fleet")?).expect("generated fleet ID is valid"),
        policy_revision: Epoch::new(1).expect("one is a valid policy revision"),
        expected_previous: None,
        credentials: vec![GatewayWorkloadCredentialPolicy {
            credential_id: gateway_credential_id,
            public_key_spki: Base64UrlNoPad::new(
                URL_SAFE_NO_PAD.encode(gateway_signer.public_key_spki_der()),
            )
            .expect("generated Gateway SPKI is canonical base64url"),
            scope: GatewayWorkloadCredentialScope::Fleet,
        }],
    };
    let gateway_authority_bytes = encode_gateway_workload_identity_authority(&gateway_authority)
        .map_err(|error| anyhow!("encode generated Gateway authority: {error:?}"))?;

    publish(
        &candidate.authority,
        "route-v2-ca-certificate.pem",
        &ca_certificate_bytes,
        0o644,
    )?;
    publish(
        &candidate.authority,
        "route-v2-ca-private-key.pem",
        &ca_key_bytes,
        0o600,
    )?;
    publish(
        &candidate.authority,
        "rotation-operator-private-key.pem",
        &rotation_operator_private_key,
        0o600,
    )?;
    rotation_operator_private_key.fill(0);
    publish(
        &candidate.control,
        "gateway-workload-authority.v1.json",
        &gateway_authority_bytes,
        0o644,
    )?;
    publish(
        &candidate.control,
        "gateway-client-ca-bundle.pem",
        &ca_certificate_bytes,
        0o644,
    )?;
    publish(
        &candidate.control,
        "control-machine-server-certificate.pem",
        &control_certificate,
        0o644,
    )?;
    publish(
        &candidate.control,
        "control-machine-server-private-key.pem",
        &control_key,
        0o600,
    )?;
    publish(
        &candidate.control,
        "signer.v1.json",
        &signer_reference_bytes,
        0o644,
    )?;
    publish(
        &candidate.control,
        "public-key-ring.v1.json",
        &ring_bytes,
        0o644,
    )?;
    publish(
        &candidate.control,
        "rotation-operator-trust.v1.json",
        &rotation_operator_trust_bytes,
        0o644,
    )?;
    publish(
        &candidate.control,
        "signer-private-key.pem",
        &signer_private_key,
        0o600,
    )?;
    signer_private_key.fill(0);
    publish(
        &candidate.gateway,
        "node-server-ca-bundle.pem",
        &ca_certificate_bytes,
        0o644,
    )?;
    publish(
        &candidate.gateway,
        "gateway-machine-client-certificate.pem",
        &gateway_certificate,
        0o644,
    )?;
    publish(
        &candidate.gateway,
        "gateway-machine-client-private-key.pem",
        &gateway_key,
        0o600,
    )?;
    publish(
        &candidate.node,
        "public-key-ring.v1.json",
        &ring_bytes,
        0o644,
    )?;
    publish(
        &candidate.node,
        "rotation-operator-trust.v1.json",
        &rotation_operator_trust_bytes,
        0o644,
    )?;
    publish(
        &candidate.node,
        "gateway-client-ca-bundle.pem",
        &ca_certificate_bytes,
        0o644,
    )?;
    publish(
        &candidate.node,
        "node-machine-server-certificate.pem",
        &node_certificate,
        0o644,
    )?;
    publish(
        &candidate.node,
        "node-machine-server-private-key.pem",
        &node_key,
        0o600,
    )?;

    let control_data = read_role_data(&candidate.control, &CONTROL_FILES, candidate.expected_uid)?;
    let gateway_data = read_role_data(&candidate.gateway, &GATEWAY_FILES, candidate.expected_uid)?;
    let node_data = read_role_data(&candidate.node, &NODE_FILES, candidate.expected_uid)?;
    let control_manifest = encode_kubernetes_secret(&inputs.control_secret_name, &control_data)?;
    let gateway_manifest = encode_kubernetes_secret(&inputs.gateway_secret_name, &gateway_data)?;
    let node_secret = encode_node_secret(&inputs.node_secret_name, &node_data)?;
    publish(
        &candidate.provider,
        "control-secret.v1.json",
        &control_manifest,
        0o600,
    )?;
    publish(
        &candidate.provider,
        "gateway-secret.v1.json",
        &gateway_manifest,
        0o600,
    )?;
    publish(
        &candidate.provider,
        "node-secret.v1.json",
        &node_secret,
        0o600,
    )?;

    std::fs::remove_dir_all(&work_path).context("remove completed private generation directory")?;
    sync_directory(&candidate.root, "sync completed Route v2 candidate")
}

struct LeafPaths {
    key: PathBuf,
    certificate: PathBuf,
}

struct LeafSpec<'a> {
    label: &'a str,
    common_name: &'a str,
    extended_key_usage: &'a str,
    dns_names: &'a [String],
}

fn issue_leaf(
    work: &File,
    work_path: &Path,
    spec: LeafSpec<'_>,
    ca_key: &Path,
    ca_certificate: &Path,
    openssl_executable: &Path,
) -> Result<LeafPaths> {
    let LeafSpec {
        label,
        common_name,
        extended_key_usage,
        dns_names,
    } = spec;
    let key = work_path.join(format!("{label}-key.pem"));
    let request = work_path.join(format!("{label}.csr"));
    let certificate = work_path.join(format!("{label}-certificate.pem"));
    let extension_name = format!("{label}-extensions.cnf");
    let extension_path = work_path.join(&extension_name);
    let mut extensions = String::from(
        "[extensions]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n",
    );
    extensions.push_str(&format!("extendedKeyUsage={extended_key_usage}\n"));
    extensions.push_str("subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n");
    if !dns_names.is_empty() {
        extensions.push_str("subjectAltName=");
        for (index, name) in dns_names.iter().enumerate() {
            if index != 0 {
                extensions.push(',');
            }
            extensions.push_str("DNS:");
            extensions.push_str(name);
        }
        extensions.push('\n');
    }
    write_new_file_at(work, &extension_name, extensions.as_bytes(), 0o600)?;
    openssl(
        openssl_executable,
        &[
            "genpkey".as_ref(),
            "-algorithm".as_ref(),
            "ED25519".as_ref(),
            "-out".as_ref(),
            key.as_os_str(),
        ],
    )?;
    let subject = format!("/CN={common_name}");
    openssl(
        openssl_executable,
        &[
            "req".as_ref(),
            "-new".as_ref(),
            "-key".as_ref(),
            key.as_os_str(),
            "-out".as_ref(),
            request.as_os_str(),
            "-subj".as_ref(),
            subject.as_ref(),
        ],
    )?;
    let serial = format!("0x{}", random_hex(16)?);
    openssl(
        openssl_executable,
        &[
            "x509".as_ref(),
            "-req".as_ref(),
            "-in".as_ref(),
            request.as_os_str(),
            "-CA".as_ref(),
            ca_certificate.as_os_str(),
            "-CAkey".as_ref(),
            ca_key.as_os_str(),
            "-set_serial".as_ref(),
            serial.as_ref(),
            "-days".as_ref(),
            "825".as_ref(),
            "-extfile".as_ref(),
            extension_path.as_os_str(),
            "-extensions".as_ref(),
            "extensions".as_ref(),
            "-out".as_ref(),
            certificate.as_os_str(),
        ],
    )?;
    Ok(LeafPaths { key, certificate })
}

fn validate_openssl(path: &Path, expected_uid: u32) -> Result<PathBuf> {
    anyhow::ensure!(path.is_absolute(), "offline OpenSSL path must be absolute");
    let canonical = path
        .canonicalize()
        .context("resolve offline OpenSSL executable")?;
    use std::os::unix::fs::OpenOptionsExt as _;
    let executable = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical)
        .context("open offline OpenSSL executable")?;
    let metadata = executable.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == expected_uid
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0,
        "offline OpenSSL executable is not a trusted owner-only-stable executable"
    );
    Ok(canonical)
}

fn openssl(executable: &Path, arguments: &[&OsStr]) -> Result<()> {
    let status = Command::new(executable)
        .args(arguments)
        .env_remove("OPENSSL_CONF")
        .env_remove("OPENSSL_MODULES")
        .env_remove("RANDFILE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("execute offline OpenSSL credential operation")?;
    anyhow::ensure!(
        status.success(),
        "offline OpenSSL credential operation failed"
    );
    Ok(())
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow!("read system CSPRNG"))?;
    Ok(hex::encode(value))
}

fn random_id(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}_{}", random_hex(16)?))
}

fn read_generated(path: &Path, maximum: usize, mode: u32, expected_uid: u32) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open generated credential {}", path.display()))?;
    set_file_mode(&file, mode)?;
    file.sync_all().context("sync generated credential")?;
    validate_regular_metadata(&file, expected_uid, mode, "generated credential")?;
    read_stable_file(&file, maximum)
}

fn publish(directory: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    anyhow::ensure!(!bytes.is_empty(), "Route v2 artifact is empty");
    write_new_file_at(directory, name, bytes, mode)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KubernetesSecretManifest {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: KubernetesSecretMetadata,
    immutable: bool,
    #[serde(rename = "type")]
    type_name: String,
    data: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KubernetesSecretMetadata {
    name: String,
    namespace: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsCreateSecretInput {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "SecretString")]
    secret_string: String,
}

fn encode_kubernetes_secret(name: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let manifest = KubernetesSecretManifest {
        api_version: "v1".to_owned(),
        kind: "Secret".to_owned(),
        metadata: KubernetesSecretMetadata {
            name: name.to_owned(),
            namespace: "cats".to_owned(),
        },
        immutable: true,
        type_name: "Opaque".to_owned(),
        data: files
            .iter()
            .map(|(key, value)| (key.clone(), STANDARD.encode(value)))
            .collect(),
    };
    serde_json::to_vec(&manifest).context("encode immutable Kubernetes Secret input")
}

fn encode_node_secret(name: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let fields = BTreeMap::from([
        (
            "gateway_client_ca_bundle_pem_b64".to_owned(),
            STANDARD.encode(required(files, "gateway-client-ca-bundle.pem")?),
        ),
        (
            "node_machine_server_certificate_pem_b64".to_owned(),
            STANDARD.encode(required(files, "node-machine-server-certificate.pem")?),
        ),
        (
            "node_machine_server_private_key_pem_b64".to_owned(),
            STANDARD.encode(required(files, "node-machine-server-private-key.pem")?),
        ),
        (
            "public_key_ring_v1_json_b64".to_owned(),
            STANDARD.encode(required(files, "public-key-ring.v1.json")?),
        ),
        (
            "rotation_operator_trust_v1_json_b64".to_owned(),
            STANDARD.encode(required(files, "rotation-operator-trust.v1.json")?),
        ),
    ]);
    let secret_string = serde_json::to_string(&fields).context("encode Node SecretString")?;
    serde_json::to_vec(&AwsCreateSecretInput {
        name: name.to_owned(),
        description: "Cats Route v2 immutable Node revision-1 artifacts".to_owned(),
        secret_string,
    })
    .context("encode Secrets Manager create-secret input")
}

fn required<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8]> {
    files
        .get(name)
        .map(Vec::as_slice)
        .with_context(|| format!("missing Route v2 artifact {name}"))
}

#[derive(Serialize)]
struct VerificationReceipt {
    version: u32,
    release_commit_sha: String,
    output_directory: String,
    control_secret_name: String,
    gateway_secret_name: String,
    node_secret_name: String,
    node_server_dns: Vec<String>,
    gateway_authority_sha256: String,
    signer_reference_sha256: String,
    public_key_ring_sha256: String,
    public_key_ring_digest: String,
    rotation_operator_authority_id: String,
    rotation_operator_route_deployment_id: String,
    rotation_operator_trust_sha256: String,
    ca_certificate_sha256: String,
}

fn verify(candidate: &Candidate, inputs: &Inputs) -> Result<VerificationReceipt> {
    ensure_names(&candidate.root, &ROOT_DIRECTORIES)?;
    ensure_file_contract(
        &candidate.authority,
        &AUTHORITY_FILES,
        candidate.expected_uid,
    )?;
    ensure_file_contract(&candidate.control, &CONTROL_FILES, candidate.expected_uid)?;
    ensure_file_contract(&candidate.gateway, &GATEWAY_FILES, candidate.expected_uid)?;
    ensure_file_contract(&candidate.node, &NODE_FILES, candidate.expected_uid)?;
    ensure_file_contract(&candidate.provider, &PROVIDER_FILES, candidate.expected_uid)?;

    let authority = read_role_data(
        &candidate.authority,
        &AUTHORITY_FILES,
        candidate.expected_uid,
    )?;
    let control = read_role_data(&candidate.control, &CONTROL_FILES, candidate.expected_uid)?;
    let gateway = read_role_data(&candidate.gateway, &GATEWAY_FILES, candidate.expected_uid)?;
    let node = read_role_data(&candidate.node, &NODE_FILES, candidate.expected_uid)?;

    // The production command is root-only, so exercise the same descriptor-relative,
    // root-owned closed-set reader that the one-time Node installer uses. Tests run as
    // their ordinary uid and cover the equivalent file contract above; the reader has
    // its own calibrated non-root fixtures in cats-api.
    if candidate.expected_uid == 0 {
        let installed =
            cats_api::runtime_artifacts::load_initial_node_route_v2_machine_artifact_candidate(
                &candidate.root_path.join("node"),
            )
            .map_err(|error| {
                anyhow!("production Node Route v2 reader rejected candidate: {error:?}")
            })?;
        anyhow::ensure!(
            installed.ring().exact_bytes() == required(&node, "public-key-ring.v1.json")?
                && installed.gateway_client_ca_bundle_pem()
                    == required(&node, "gateway-client-ca-bundle.pem")?
                && installed.server_certificate_pem()
                    == required(&node, "node-machine-server-certificate.pem")?
                && installed.server_private_key_pem()
                    == required(&node, "node-machine-server-private-key.pem")?
                && installed.rotation_operator_trust().exact_bytes()
                    == required(&node, "rotation-operator-trust.v1.json")?,
            "production Node Route v2 reader returned different candidate bytes"
        );
    }

    let ca_certificate = required(&authority, "route-v2-ca-certificate.pem")?;
    for observed in [
        required(&control, "gateway-client-ca-bundle.pem")?,
        required(&gateway, "node-server-ca-bundle.pem")?,
        required(&node, "gateway-client-ca-bundle.pem")?,
    ] {
        anyhow::ensure!(
            observed == ca_certificate,
            "Route v2 trust bundles do not share the reviewed CA root"
        );
    }
    let ca_private_spki = private_key_spki(required(&authority, "route-v2-ca-private-key.pem")?)?;
    let ca_certificate_der = strict_certificates(ca_certificate, "Route v2 CA")?;
    anyhow::ensure!(
        canonical_gateway_leaf_spki_sha256(ca_certificate_der[0].as_ref())
            == Some(Sha256Digest::from_bytes(
                Sha256::digest(&ca_private_spki).into()
            )),
        "Route v2 CA certificate does not match its private key"
    );

    let ring_bytes = required(&control, "public-key-ring.v1.json")?;
    anyhow::ensure!(
        ring_bytes == required(&node, "public-key-ring.v1.json")?,
        "Control and Node Route v2 public rings differ"
    );
    let ring = decode_route_grant_v2_public_key_ring(ring_bytes)
        .map_err(|error| anyhow!("decode canonical Route v2 ring: {error:?}"))?;
    anyhow::ensure!(
        ring.ring_version.get() == 1 && ring.expected_previous.is_none() && ring.keys.len() == 1,
        "Route v2 initial ring is not the closed revision-1 shape"
    );
    let signer_reference_bytes = required(&control, "signer.v1.json")?;
    let signer_reference = decode_route_grant_v2_signer_reference(signer_reference_bytes)
        .map_err(|error| anyhow!("decode canonical Route v2 signer reference: {error:?}"))?;
    signer_reference
        .validate_ring(&ring)
        .map_err(|error| anyhow!("validate Route v2 signer/ring binding: {error:?}"))?;
    anyhow::ensure!(
        signer_reference.signer_revision.get() == 1 && signer_reference.expected_previous.is_none(),
        "Route v2 signer is not revision 1"
    );
    let rotation_operator_trust_bytes = required(&control, "rotation-operator-trust.v1.json")?;
    anyhow::ensure!(
        rotation_operator_trust_bytes == required(&node, "rotation-operator-trust.v1.json")?,
        "Control and Node Route rotation operator trusts differ"
    );
    let rotation_operator_trust =
        decode_route_v2_rotation_operator_trust(rotation_operator_trust_bytes)
            .map_err(|error| anyhow!("decode Route rotation operator trust: {error}"))?;
    anyhow::ensure!(
        rotation_operator_trust.route_deployment_id == signer_reference.deployment_id
            && rotation_operator_trust.release_commit_sha == inputs.release_commit_sha
            && rotation_operator_trust.threshold == 1
            && rotation_operator_trust.credentials.len() == 1,
        "Route rotation operator trust does not bind revision one and the exact release"
    );
    let rotation_operator_private_key = required(&authority, "rotation-operator-private-key.pem")?;
    let rotation_operator_signer = Ed25519RequestSigner::from_pkcs8_v2_pem(
        rotation_operator_trust.credentials[0].credential_id.clone(),
        rotation_operator_private_key,
    )
    .map_err(|_| anyhow!("Route rotation operator private key is not canonical PKCS#8 v2 PEM"))?;
    anyhow::ensure!(
        Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(rotation_operator_signer.public_key_spki_der()))
            .as_ref()
            == Some(&rotation_operator_trust.credentials[0].public_key_spki),
        "Route rotation operator private key does not match its fixed trust"
    );
    let signer_private_key = required(&control, "signer-private-key.pem")?;
    let signer_validator = Ed25519RequestSigner::from_pkcs8_v2_pem(
        Id::new("route_signer_verifier").expect("fixed verifier ID is valid"),
        signer_private_key,
    )
    .map_err(|_| anyhow!("Route v2 signer private key is not canonical PKCS#8 v2 PEM"))?;
    let signer_spki = signer_validator.public_key_spki_der().to_vec();
    let signer_public = RouteGrantV2PublicKey::from_spki_der(&signer_spki)
        .context("derive installed Route v2 signer public key")?;
    let RouteGrantV2SignerSelection::Active { active_kid, .. } = &signer_reference.signer else {
        bail!("Route v2 revision-1 signer is not active");
    };
    anyhow::ensure!(
        active_kid == signer_public.kid()
            && ring.key(active_kid).is_some_and(|entry| {
                URL_SAFE_NO_PAD
                    .decode(entry.public_key_spki.as_str())
                    .ok()
                    .as_deref()
                    == Some(signer_spki.as_slice())
            }),
        "Route v2 signer private key does not match the active ring entry"
    );

    let gateway_authority_bytes = required(&control, "gateway-workload-authority.v1.json")?;
    let gateway_authority = decode_gateway_workload_identity_authority(gateway_authority_bytes)
        .map_err(|error| anyhow!("decode canonical Gateway authority: {error:?}"))?;
    anyhow::ensure!(
        gateway_authority.policy_revision.get() == 1
            && gateway_authority.expected_previous.is_none()
            && gateway_authority.credentials.len() == 1
            && matches!(
                gateway_authority.credentials[0].scope,
                GatewayWorkloadCredentialScope::Fleet
            ),
        "Gateway authority is not the closed fleet-scoped revision-1 shape"
    );
    let gateway_spki = private_key_spki(required(
        &gateway,
        "gateway-machine-client-private-key.pem",
    )?)?;
    anyhow::ensure!(
        URL_SAFE_NO_PAD
            .decode(gateway_authority.credentials[0].public_key_spki.as_str())
            .ok()
            .as_deref()
            == Some(gateway_spki.as_slice()),
        "Gateway workload authority does not match the Gateway TLS private key"
    );

    let gateway_client = build_client_config(
        ca_certificate,
        required(&gateway, "gateway-machine-client-certificate.pem")?,
        required(&gateway, "gateway-machine-client-private-key.pem")?,
    )?;
    let control_server = build_server_config(
        ca_certificate,
        required(&control, "control-machine-server-certificate.pem")?,
        required(&control, "control-machine-server-private-key.pem")?,
    )?;
    let control_peer = handshake(
        Arc::clone(&gateway_client),
        control_server,
        CONTROL_MACHINE_DNS,
    )?;
    let expected_gateway_digest = Sha256Digest::from_bytes(Sha256::digest(&gateway_spki).into());
    anyhow::ensure!(
        canonical_gateway_leaf_spki_sha256(&control_peer) == Some(expected_gateway_digest.clone()),
        "Control TLS handshake authenticated a different Gateway leaf"
    );
    let node_server = build_server_config(
        ca_certificate,
        required(&node, "node-machine-server-certificate.pem")?,
        required(&node, "node-machine-server-private-key.pem")?,
    )?;
    for dns in &inputs.node_server_dns {
        let peer = handshake(Arc::clone(&gateway_client), Arc::clone(&node_server), dns)?;
        anyhow::ensure!(
            canonical_gateway_leaf_spki_sha256(&peer) == Some(expected_gateway_digest.clone()),
            "Node TLS handshake authenticated a different Gateway leaf"
        );
    }

    let distinct_spkis = [
        ca_private_spki,
        signer_spki,
        gateway_spki,
        private_key_spki(required(
            &control,
            "control-machine-server-private-key.pem",
        )?)?,
        private_key_spki(required(&node, "node-machine-server-private-key.pem")?)?,
    ]
    .into_iter()
    .map(|spki| Sha256::digest(spki).to_vec())
    .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        distinct_spkis.len() == 5,
        "Route v2 generated authorities reuse a private key"
    );

    verify_kubernetes_secret(
        read_file(
            &candidate.provider,
            "control-secret.v1.json",
            0o600,
            candidate.expected_uid,
            MAX_JSON_BYTES,
        )?,
        &inputs.control_secret_name,
        &control,
    )?;
    verify_kubernetes_secret(
        read_file(
            &candidate.provider,
            "gateway-secret.v1.json",
            0o600,
            candidate.expected_uid,
            MAX_JSON_BYTES,
        )?,
        &inputs.gateway_secret_name,
        &gateway,
    )?;
    verify_node_secret(
        read_file(
            &candidate.provider,
            "node-secret.v1.json",
            0o600,
            candidate.expected_uid,
            MAX_JSON_BYTES,
        )?,
        &inputs.node_secret_name,
        &node,
    )?;

    Ok(VerificationReceipt {
        version: 1,
        release_commit_sha: inputs.release_commit_sha.clone(),
        output_directory: candidate.root_path.display().to_string(),
        control_secret_name: inputs.control_secret_name.clone(),
        gateway_secret_name: inputs.gateway_secret_name.clone(),
        node_secret_name: inputs.node_secret_name.clone(),
        node_server_dns: inputs.node_server_dns.clone(),
        gateway_authority_sha256: sha256(gateway_authority_bytes),
        signer_reference_sha256: sha256(signer_reference_bytes),
        public_key_ring_sha256: sha256(ring_bytes),
        public_key_ring_digest: ring
            .digest()
            .map_err(|error| anyhow!("digest verified Route v2 ring: {error:?}"))?
            .to_string(),
        rotation_operator_authority_id: rotation_operator_trust.authority_id.to_string(),
        rotation_operator_route_deployment_id: rotation_operator_trust
            .route_deployment_id
            .to_string(),
        rotation_operator_trust_sha256: sha256(rotation_operator_trust_bytes),
        ca_certificate_sha256: sha256(ca_certificate),
    })
}

fn ensure_file_contract(directory: &File, files: &[(&str, u32)], expected_uid: u32) -> Result<()> {
    let names = files.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    ensure_names(directory, &names)?;
    for (name, mode) in files {
        let name = super::c_name(name)?;
        let file = open_file_at(directory, &name, libc::O_RDONLY, 0)?;
        validate_regular_metadata(&file, expected_uid, *mode, "Route v2 artifact")?;
    }
    Ok(())
}

fn ensure_names(directory: &File, expected: &[impl AsRef<OsStr>]) -> Result<()> {
    let expected = expected
        .iter()
        .map(|name| name.as_ref().to_os_string())
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        list_directory_names(directory)? == expected,
        "Route v2 artifact directory is not an exact closed set"
    );
    Ok(())
}

fn read_role_data(
    directory: &File,
    files: &[(&str, u32)],
    expected_uid: u32,
) -> Result<BTreeMap<String, Vec<u8>>> {
    files
        .iter()
        .map(|(name, mode)| {
            let maximum = if name.ends_with(".json") {
                MAX_JSON_BYTES
            } else if *mode == 0o600 {
                MAX_PRIVATE_KEY_BYTES
            } else {
                MAX_PEM_BYTES
            };
            Ok((
                (*name).to_owned(),
                read_file(directory, name, *mode, expected_uid, maximum)?,
            ))
        })
        .collect()
}

fn read_file(
    directory: &File,
    name: &str,
    mode: u32,
    expected_uid: u32,
    maximum: usize,
) -> Result<Vec<u8>> {
    read_regular_at(directory, name, expected_uid, mode, maximum)
}

fn strict_certificates(bytes: &[u8], description: &str) -> Result<Vec<CertificateDer<'static>>> {
    validate_pem_sequence(bytes, "CERTIFICATE", false)?;
    CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("decode {description} certificate chain"))
}

fn private_key_spki(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_pem_sequence(bytes, "PRIVATE KEY", true)?;
    let key = PrivatePkcs8KeyDer::from_pem_slice(bytes).context("decode Ed25519 PKCS#8 key")?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key.secret_pkcs8_der())
        .map_err(|_| anyhow!("private key is not Ed25519 PKCS#8"))?;
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    use ring::signature::KeyPair as _;
    spki.extend_from_slice(pair.public_key().as_ref());
    anyhow::ensure!(spki.len() == 44, "Ed25519 SPKI has the wrong length");
    Ok(spki)
}

fn validate_pem_sequence(bytes: &[u8], label: &str, exactly_one: bool) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("Route v2 PEM is not UTF-8")?;
    anyhow::ensure!(text.is_ascii(), "Route v2 PEM is not ASCII");
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut inside = false;
    let mut body_lines = 0_usize;
    let mut count = 0_usize;
    for line in text.lines() {
        if !inside {
            if line.is_empty() {
                continue;
            }
            anyhow::ensure!(line == begin, "Route v2 PEM contains an unexpected section");
            inside = true;
            body_lines = 0;
        } else if line == end {
            anyhow::ensure!(body_lines > 0, "Route v2 PEM section is empty");
            inside = false;
            count += 1;
        } else {
            anyhow::ensure!(
                !line.is_empty()
                    && line
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte)),
                "Route v2 PEM body is invalid"
            );
            body_lines += 1;
        }
    }
    anyhow::ensure!(
        !inside && if exactly_one { count == 1 } else { count > 0 },
        "Route v2 PEM cardinality is invalid"
    );
    Ok(())
}

fn build_server_config(
    ca: &[u8],
    certificate: &[u8],
    private_key: &[u8],
) -> Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    for certificate in strict_certificates(ca, "Gateway client CA")? {
        roots.add(certificate).context("add Gateway client CA")?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .context("build Gateway client verifier")?;
    let certificates = strict_certificates(certificate, "machine server")?;
    anyhow::ensure!(
        canonical_gateway_leaf_spki_sha256(certificates[0].as_ref()).is_some(),
        "machine server leaf is not canonical Ed25519"
    );
    validate_pem_sequence(private_key, "PRIVATE KEY", true)?;
    let key =
        PrivatePkcs8KeyDer::from_pem_slice(private_key).context("decode machine server key")?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("build TLS 1.3 server")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, PrivateKeyDer::Pkcs8(key))
        .context("validate machine server certificate/private key")?;
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    Ok(Arc::new(config))
}

fn build_client_config(
    ca: &[u8],
    certificate: &[u8],
    private_key: &[u8],
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for certificate in strict_certificates(ca, "machine server CA")? {
        roots.add(certificate).context("add machine server CA")?;
    }
    let certificates = strict_certificates(certificate, "Gateway client")?;
    anyhow::ensure!(
        canonical_gateway_leaf_spki_sha256(certificates[0].as_ref()).is_some(),
        "Gateway client leaf is not canonical Ed25519"
    );
    validate_pem_sequence(private_key, "PRIVATE KEY", true)?;
    let key =
        PrivatePkcs8KeyDer::from_pem_slice(private_key).context("decode Gateway client key")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("build TLS 1.3 client")?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, PrivateKeyDer::Pkcs8(key))
        .context("validate Gateway client certificate/private key")?;
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    Ok(Arc::new(config))
}

fn handshake(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    server_dns: &str,
) -> Result<Vec<u8>> {
    let server_name =
        ServerName::try_from(server_dns.to_owned()).context("invalid TLS server name")?;
    let mut client =
        ClientConnection::new(client_config, server_name).context("create TLS client")?;
    let mut server = ServerConnection::new(server_config).context("create TLS server")?;
    for _ in 0..32 {
        let mut progressed = false;
        if client.wants_write() {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes)?;
            if !bytes.is_empty() {
                server.read_tls(&mut Cursor::new(bytes))?;
                server
                    .process_new_packets()
                    .context("validate TLS client flight")?;
                progressed = true;
            }
        }
        if server.wants_write() {
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes)?;
            if !bytes.is_empty() {
                client.read_tls(&mut Cursor::new(bytes))?;
                client
                    .process_new_packets()
                    .context("validate TLS server flight")?;
                progressed = true;
            }
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        anyhow::ensure!(progressed, "Route v2 TLS validation made no progress");
    }
    anyhow::ensure!(
        !client.is_handshaking()
            && !server.is_handshaking()
            && client.alpn_protocol() == Some(HTTP_11_ALPN)
            && server.alpn_protocol() == Some(HTTP_11_ALPN),
        "Route v2 TLS handshake did not close"
    );
    let peer = server
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("Route v2 TLS server did not authenticate a Gateway leaf")?;
    Ok(peer.as_ref().to_vec())
}

fn verify_kubernetes_secret(
    bytes: Vec<u8>,
    expected_name: &str,
    expected_files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let secret: KubernetesSecretManifest =
        serde_json::from_slice(&bytes).context("decode immutable Kubernetes Secret input")?;
    anyhow::ensure!(
        serde_json::to_vec(&secret)? == bytes
            && secret.api_version == "v1"
            && secret.kind == "Secret"
            && secret.metadata.name == expected_name
            && secret.metadata.namespace == "cats"
            && secret.immutable
            && secret.type_name == "Opaque",
        "Kubernetes Secret input is not the exact immutable target"
    );
    let decoded = secret
        .data
        .into_iter()
        .map(|(name, value)| {
            STANDARD
                .decode(value)
                .map(|bytes| (name, bytes))
                .context("decode Kubernetes Secret data")
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    anyhow::ensure!(
        decoded == *expected_files,
        "Kubernetes Secret input differs from the validated role files"
    );
    Ok(())
}

fn verify_node_secret(
    bytes: Vec<u8>,
    expected_name: &str,
    expected_files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let secret: AwsCreateSecretInput =
        serde_json::from_slice(&bytes).context("decode Secrets Manager input")?;
    anyhow::ensure!(
        serde_json::to_vec(&secret)? == bytes
            && secret.name == expected_name
            && secret.description == "Cats Route v2 immutable Node revision-1 artifacts",
        "Secrets Manager input is not the exact revision-1 target"
    );
    let fields: BTreeMap<String, String> =
        serde_json::from_str(&secret.secret_string).context("decode Node SecretString")?;
    anyhow::ensure!(
        serde_json::to_string(&fields)? == secret.secret_string
            && fields.keys().map(String::as_str).collect::<Vec<_>>()
                == vec![
                    "gateway_client_ca_bundle_pem_b64",
                    "node_machine_server_certificate_pem_b64",
                    "node_machine_server_private_key_pem_b64",
                    "public_key_ring_v1_json_b64",
                    "rotation_operator_trust_v1_json_b64",
                ],
        "Node SecretString is not the exact five-field shape"
    );
    let mapping = [
        (
            "gateway_client_ca_bundle_pem_b64",
            "gateway-client-ca-bundle.pem",
        ),
        (
            "node_machine_server_certificate_pem_b64",
            "node-machine-server-certificate.pem",
        ),
        (
            "node_machine_server_private_key_pem_b64",
            "node-machine-server-private-key.pem",
        ),
        ("public_key_ring_v1_json_b64", "public-key-ring.v1.json"),
        (
            "rotation_operator_trust_v1_json_b64",
            "rotation-operator-trust.v1.json",
        ),
    ];
    for (field, file) in mapping {
        let decoded = STANDARD
            .decode(
                fields
                    .get(field)
                    .context("missing Node SecretString field")?,
            )
            .context("decode Node SecretString field")?;
        anyhow::ensure!(
            decoded.as_slice() == required(expected_files, file)?,
            "Node SecretString field differs from validated Node file"
        );
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn provider_inputs_preserve_the_exact_closed_role_bytes() {
        let files = BTreeMap::from([
            ("one.pem".to_owned(), b"public".to_vec()),
            ("two.pem".to_owned(), b"private-marker".to_vec()),
        ]);
        let encoded = encode_kubernetes_secret("cats-route-v2-control-r1", &files).unwrap();
        verify_kubernetes_secret(encoded, "cats-route-v2-control-r1", &files).unwrap();

        let node = BTreeMap::from([
            ("gateway-client-ca-bundle.pem".to_owned(), b"ca".to_vec()),
            (
                "node-machine-server-certificate.pem".to_owned(),
                b"cert".to_vec(),
            ),
            (
                "node-machine-server-private-key.pem".to_owned(),
                b"key".to_vec(),
            ),
            ("public-key-ring.v1.json".to_owned(), b"ring".to_vec()),
            (
                "rotation-operator-trust.v1.json".to_owned(),
                b"trust".to_vec(),
            ),
        ]);
        let encoded = encode_node_secret("cats-production-route-v2-node-r1", &node).unwrap();
        verify_node_secret(encoded, "cats-production-route-v2-node-r1", &node).unwrap();
    }

    #[test]
    fn generator_immediately_revalidates_the_complete_revision_one_transaction() {
        let root = TempDir::new().unwrap();
        let output = root.path().join("route-v2-r1");
        let inputs = Inputs::new(
            &output,
            &["localhost".to_owned()],
            "cats-route-v2-control-r1",
            "cats-route-v2-gateway-r1",
            "cats-production-route-v2-node-r1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let uid = super::super::effective_uid();
        let (candidate, created) = Candidate::open_or_create(&output, uid).unwrap();
        assert!(created);
        let openssl = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("openssl"))
            .find(|path| path.is_file())
            .unwrap();
        let openssl_owner = std::fs::metadata(openssl.canonicalize().unwrap())
            .unwrap()
            .uid();
        let openssl = validate_openssl(&openssl, openssl_owner).unwrap();
        generate(&candidate, &inputs, &openssl).unwrap();
        let receipt = verify(&candidate, &inputs).unwrap();

        assert_eq!(receipt.version, 1);
        assert_eq!(receipt.node_server_dns, vec!["localhost"]);
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(!receipt_bytes
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY"));
    }
}

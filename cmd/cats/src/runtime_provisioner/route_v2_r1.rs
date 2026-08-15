use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Cursor};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    RouteGrantV2PublicKeyRingExpectedPrevious, RouteGrantV2SignerExpectedPrevious,
    RouteGrantV2SignerReference, RouteGrantV2SignerSelection,
};
use cats_api::route_signing_operator::{
    decode_route_v2_control_rollout_apply_receipt_payload, decode_route_v2_rotation_operator_trust,
    decode_route_v2_signing_authority_current, decode_route_v2_signing_command_payload,
    decode_signed_route_v2_control_rollout_apply_receipt, decode_signed_route_v2_signing_command,
    encode_route_v2_rotation_operator_trust, encode_route_v2_signing_command_payload,
    encode_signed_route_v2_control_rollout_apply_receipt, encode_signed_route_v2_signing_command,
    sign_route_v2_control_rollout_apply_receipt, sign_route_v2_signing_command,
    verify_signed_route_v2_control_rollout_apply_receipt, verify_signed_route_v2_signing_command,
    RouteGrantV2SigningAuthorityCommand, RouteGrantV2SigningAuthorityCommandKind,
    RouteV2ControlRolloutApplyOutcome, RouteV2LoadedSignerState, RouteV2RotationOperatorCredential,
    RouteV2RotationOperatorTrust, RouteV2SigningCommandPayload,
    SignedRouteV2ControlRolloutApplyReceipt, SignedRouteV2SigningCommand,
    ROUTE_V2_CONTROL_ROLLOUT_APPLY_RECEIPT_MAX_WIRE_BYTES, ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES,
    ROUTE_V2_SIGNING_CURRENT_RESPONSE_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, Base64UrlNoPad, ContractVersion, Epoch, Hostname, Id,
    RandomId128, Sha256Digest, UnixMillis,
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
    publish_user_file_idempotent, read_regular_at, read_stable_file, read_user_file, report,
    set_file_mode, sync_directory, validate_directory, validate_regular_metadata,
    write_new_file_at, Cli, RuntimeProvisionerRouteV2R1Command,
};
use crate::stable_unix_fs::{c_os_name, mkdir_at};

const CONTROL_MACHINE_DNS: &str = "cats-controld-route-v2.cats.svc.cluster.local";
const CONTROL_ROTATION_MACHINE_DNS: &str = "cats-controld-route-rotation.cats.svc.cluster.local";
const HTTP_11_ALPN: &[u8] = b"http/1.1";
const MAX_PEM_BYTES: usize = 65_536;
const MAX_PRIVATE_KEY_BYTES: usize = 16_384;
const MAX_JSON_BYTES: usize = 262_144;
const MAX_ROTATION_RECOVERY_BUNDLE_BYTES: usize = 1_048_576;
const ROTATION_RECOVERY_COMMAND_LIFETIME_MILLIS: u64 = 5 * 60 * 1_000;
const INSTALLED_ROTATION_OPERATOR_TRUST_PATH: &str =
    "/etc/cats/route-v2/rotation-operator-trust.v1.json";
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
const NODE_FILES: [(&str, u32); 6] = [
    ("gateway-client-ca-bundle.pem", 0o644),
    ("node-machine-server-certificate.pem", 0o644),
    ("node-machine-server-private-key.pem", 0o600),
    ("node-server-ca-bundle.pem", 0o644),
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
        RuntimeProvisionerRouteV2R1Command::SignCommand {
            input,
            payload,
            output,
        } => return sign_command(cli, input, payload, output),
        RuntimeProvisionerRouteV2R1Command::PrepareRotationRecovery {
            input,
            output,
            run_id,
        } => return prepare_rotation_recovery(cli, input, output, run_id),
        RuntimeProvisionerRouteV2R1Command::VerifyRotationRecovery {
            input,
            output,
            run_id,
        } => return verify_rotation_recovery_command(cli, input, output, run_id),
        RuntimeProvisionerRouteV2R1Command::SignRotationRecoveryPhase {
            input,
            recovery,
            phase,
            output,
        } => return sign_rotation_recovery_phase(cli, input, recovery, phase, output),
        RuntimeProvisionerRouteV2R1Command::VerifyRotationCurrent {
            input,
            recovery,
            signer_revision,
            discovery,
            output,
        } => {
            return verify_rotation_current(
                cli,
                input,
                recovery,
                *signer_revision,
                discovery,
                output,
            )
        }
        RuntimeProvisionerRouteV2R1Command::SignPreparedRotationPhase {
            trust,
            operator_private_key,
            command_bundle,
            phase,
            output,
        } => {
            return sign_prepared_rotation_phase(
                cli,
                trust,
                operator_private_key,
                command_bundle,
                phase,
                output,
            )
        }
        RuntimeProvisionerRouteV2R1Command::VerifyPreparedRotationCurrent {
            trust,
            command_bundle,
            signer_revision,
            discovery,
            output,
        } => {
            return verify_prepared_rotation_current(
                cli,
                trust,
                command_bundle,
                *signer_revision,
                discovery,
                output,
            )
        }
        RuntimeProvisionerRouteV2R1Command::SignControlRolloutApplyReceipt {
            trust,
            operator_private_keys,
            payload,
            output,
        } => {
            return sign_control_rollout_apply_receipt(
                cli,
                trust,
                operator_private_keys,
                payload,
                output,
            )
        }
        RuntimeProvisionerRouteV2R1Command::VerifyControlRolloutApplyReceipt {
            trust,
            command_bundle,
            phase,
            qualification_catalog_sha256,
            saved_plan_sha256,
            receipt,
            output,
        } => {
            return verify_control_rollout_apply_receipt(
                cli,
                trust,
                command_bundle,
                phase,
                qualification_catalog_sha256,
                saved_plan_sha256,
                receipt,
                output,
            )
        }
    };
    let candidate = Candidate::open_existing(&inputs.root, 0)?;
    let receipt = verify(&candidate, &inputs)?;
    report(cli, &receipt)
}

#[derive(Serialize)]
struct CommandSigningReceipt {
    version: u32,
    authority_id: String,
    route_deployment_id: String,
    release_commit_sha: String,
    command_id: String,
    exact_payload_sha256: String,
    exact_command_sha256: String,
    output: String,
}

fn sign_command(cli: &Cli, input: &Path, payload: &Path, output: &Path) -> Result<()> {
    let candidate = Candidate::open_existing(input, 0)?;
    let trust_bytes = read_file(
        &candidate.control,
        "rotation-operator-trust.v1.json",
        0o644,
        candidate.expected_uid,
        MAX_JSON_BYTES,
    )?;
    let node_trust_bytes = read_file(
        &candidate.node,
        "rotation-operator-trust.v1.json",
        0o644,
        candidate.expected_uid,
        MAX_JSON_BYTES,
    )?;
    anyhow::ensure!(
        trust_bytes == node_trust_bytes,
        "Control and Node Route rotation operator trusts differ"
    );
    let trust = decode_route_v2_rotation_operator_trust(&trust_bytes)
        .map_err(|error| anyhow!("decode Route rotation operator trust: {error}"))?;
    anyhow::ensure!(
        trust.threshold == 1 && trust.credentials.len() == 1,
        "revision-1 offline signer requires the generated one-of-one operator trust"
    );

    let payload_bytes = read_user_file(
        payload,
        ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES,
        0o644,
        false,
    )?;
    let payload_value = decode_route_v2_signing_command_payload(&payload_bytes)
        .map_err(|error| anyhow!("decode canonical Route v2 signing payload: {error}"))?;
    anyhow::ensure!(
        payload_value.authority_id == trust.authority_id
            && payload_value.release_commit_sha == trust.release_commit_sha
            && payload_value.command.successor.deployment_id == trust.route_deployment_id,
        "Route v2 signing payload does not bind the fixed operator trust"
    );

    let mut private_key = read_file(
        &candidate.authority,
        "rotation-operator-private-key.pem",
        0o600,
        candidate.expected_uid,
        MAX_PRIVATE_KEY_BYTES,
    )?;
    let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(
        trust.credentials[0].credential_id.clone(),
        &private_key,
    )
    .map_err(|_| anyhow!("Route rotation operator private key is not strict PKCS#8 v2"))?;
    private_key.fill(0);
    anyhow::ensure!(
        Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.public_key_spki_der())).as_ref()
            == Some(&trust.credentials[0].public_key_spki),
        "Route rotation operator private key does not match fixed trust"
    );
    let proof = sign_route_v2_signing_command(&payload_value, &signer)
        .map_err(|error| anyhow!("sign Route v2 command: {error}"))?;
    let signed = SignedRouteV2SigningCommand {
        payload: payload_value,
        proofs: vec![proof],
    };
    let command_bytes = encode_signed_route_v2_signing_command(&signed)
        .map_err(|error| anyhow!("encode signed Route v2 command: {error}"))?;
    publish_user_file_idempotent(output, &command_bytes, 0o644)?;
    report(
        cli,
        &CommandSigningReceipt {
            version: 1,
            authority_id: trust.authority_id.to_string(),
            route_deployment_id: trust.route_deployment_id.to_string(),
            release_commit_sha: trust.release_commit_sha,
            command_id: signed.payload.command_id.to_string(),
            exact_payload_sha256: sha256(&payload_bytes),
            exact_command_sha256: sha256(&command_bytes),
            output: output.display().to_string(),
        },
    )
}

const ROTATION_RECOVERY_REVISIONS: [u64; 7] = [2, 3, 4, 5, 6, 7, 8];
const ROTATION_RECOVERY_ROOT_DIRECTORIES: [&str; 5] = [
    "authority",
    "commands",
    "control",
    "provider",
    "secret-channel",
];
const ROTATION_RECOVERY_AUTHORITY_FILES: [(&str, u32); 2] = [
    ("normal-successor-private-key.pem", 0o600),
    ("recovery-successor-private-key.pem", 0o600),
];
const ROTATION_RECOVERY_COMMAND_FILES: [(&str, u32); 1] =
    [("route-v2-rotation-command-bundle.v1.json", 0o600)];
const ROTATION_RECOVERY_PROVIDER_FILES: [(&str, u32); 1] =
    [("control-rollout-reference.v1.json", 0o600)];
const ROTATION_RECOVERY_SECRET_FILES: [(&str, u32); 1] = [("control-secret.v1.json", 0o600)];
const ROTATION_RECOVERY_CASE_ID: &str = "route-v2-rotation-disable-live-delivery";
const ROTATION_RECOVERY_PHASES: [&str; 7] = [
    "publish_overlap",
    "switch_active",
    "publish_new_only",
    "retire",
    "disable",
    "publish_recovery",
    "activate",
];

struct RotationRecoveryOutput {
    root_path: PathBuf,
    root: File,
    authority: File,
    commands: File,
    control: BTreeMap<u64, File>,
    provider: BTreeMap<u64, File>,
    secret_channel: BTreeMap<u64, File>,
    expected_uid: u32,
}

impl RotationRecoveryOutput {
    fn open_or_create(path: &Path, expected_uid: u32) -> Result<(Self, bool)> {
        anyhow::ensure!(
            path.is_absolute() && path != Path::new("/"),
            "Route v2 recovery output must be an absolute non-root directory"
        );
        let parent_path = path.parent().context("recovery output has no parent")?;
        let basename = path
            .file_name()
            .context("recovery output has no basename")?;
        let parent = open_directory_nofollow(parent_path)?;
        validate_directory(&parent, expected_uid, None, "recovery output parent")?;
        let name = c_os_name(basename)?;
        let (root, created) =
            match open_file_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(root) => (root, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    mkdir_at(&parent, &name, 0o700).context("create recovery output")?;
                    sync_directory(&parent, "sync recovery output parent")?;
                    let root = open_file_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                    set_file_mode(&root, 0o700)?;
                    root.sync_all().context("sync recovery output")?;
                    (root, true)
                }
                Err(error) => return Err(error).context("open recovery output"),
            };
        validate_directory(&root, expected_uid, Some(0o700), "recovery output")?;
        if created {
            for directory in ROTATION_RECOVERY_ROOT_DIRECTORIES {
                create_private_directory(&root, directory)?;
            }
            for parent_name in ["control", "provider", "secret-channel"] {
                let parent_dir = open_child_directory(&root, parent_name, expected_uid)?;
                for revision in ROTATION_RECOVERY_REVISIONS {
                    create_private_directory(&parent_dir, &format!("r{revision}"))?;
                }
            }
            sync_directory(&root, "sync recovery output children")?;
        }
        Ok((Self::from_root(path, root, expected_uid)?, created))
    }

    fn open_existing(path: &Path, expected_uid: u32) -> Result<Self> {
        let root = open_directory_nofollow(path)?;
        validate_directory(&root, expected_uid, Some(0o700), "recovery output")?;
        Self::from_root(path, root, expected_uid)
    }

    fn from_root(path: &Path, root: File, expected_uid: u32) -> Result<Self> {
        let authority = open_child_directory(&root, "authority", expected_uid)?;
        let commands = open_child_directory(&root, "commands", expected_uid)?;
        let control_root = open_child_directory(&root, "control", expected_uid)?;
        let provider_root = open_child_directory(&root, "provider", expected_uid)?;
        let secret_root = open_child_directory(&root, "secret-channel", expected_uid)?;
        let open_revisions = |parent: &File| -> Result<BTreeMap<u64, File>> {
            ROTATION_RECOVERY_REVISIONS
                .into_iter()
                .map(|revision| {
                    Ok((
                        revision,
                        open_child_directory(parent, &format!("r{revision}"), expected_uid)?,
                    ))
                })
                .collect()
        };
        Ok(Self {
            root_path: path.to_path_buf(),
            root,
            authority,
            commands,
            control: open_revisions(&control_root)?,
            provider: open_revisions(&provider_root)?,
            secret_channel: open_revisions(&secret_root)?,
            expected_uid,
        })
    }
}

fn create_private_directory(parent: &File, name: &str) -> Result<()> {
    let name = super::c_name(name)?;
    mkdir_at(parent, &name, 0o700)
        .with_context(|| format!("create recovery directory {name:?}"))?;
    let child = open_file_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    set_file_mode(&child, 0o700)?;
    child.sync_all().context("sync recovery directory")?;
    sync_directory(parent, "sync recovery directory parent")
}

fn open_child_directory(parent: &File, name: &str, expected_uid: u32) -> Result<File> {
    let name = super::c_name(name)?;
    let child = open_file_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    validate_directory(
        &child,
        expected_uid,
        Some(0o700),
        "recovery child directory",
    )?;
    Ok(child)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationRecoveryCommandEntry {
    phase: String,
    signer_revision: u64,
    ring_version: u64,
    exact_authority_command_sha256: String,
    exact_authority_command_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationRecoveryRolloutEntry {
    signer_revision: u64,
    secret_name: String,
    signer_reference_sha256: String,
    public_key_ring_digest: String,
    secret_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationRecoveryCommandBundle {
    version: u32,
    case_id: String,
    source_commit_sha: String,
    qualification_run_id: String,
    route_deployment_id: String,
    rotation_operator_authority_id: String,
    rotation_operator_trust_sha256: String,
    commands: Vec<RotationRecoveryCommandEntry>,
    control_rollouts: Vec<RotationRecoveryRolloutEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationRecoveryRolloutReference {
    version: u32,
    signer_revision: u64,
    secret_name: String,
    secret_manifest_sha256: String,
    signer_reference_sha256: String,
    public_key_ring_digest: String,
}

#[derive(Serialize)]
struct RotationRecoveryVerificationReceipt {
    version: u32,
    output_directory: String,
    case_id: String,
    qualification_run_id: String,
    source_commit_sha: String,
    route_deployment_id: String,
    rotation_operator_authority_id: String,
    rotation_operator_trust_sha256: String,
    command_bundle_sha256: String,
    first_signer_revision: u64,
    terminal_signer_revision: u64,
    terminal_ring_version: u64,
    terminal_secret_name: String,
}

#[derive(Serialize)]
struct RotationRecoveryPhaseSigningReceipt {
    version: u32,
    case_id: String,
    qualification_run_id: String,
    phase: String,
    signer_revision: u64,
    ring_version: u64,
    authority_id: String,
    route_deployment_id: String,
    release_commit_sha: String,
    command_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    exact_authority_command_sha256: String,
    exact_payload_sha256: String,
    exact_signed_command_sha256: String,
    pending_command_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationCurrentVerificationReceipt {
    version: u32,
    case_id: String,
    qualification_run_id: String,
    source_commit_sha: String,
    authority_id: String,
    route_deployment_id: String,
    rotation_operator_trust_sha256: String,
    signer_revision: u64,
    signer_reference_sha256: String,
    signer_state: String,
    active_kid: Option<String>,
    public_key_ring_version: u64,
    public_key_ring_digest: String,
    database_current: bool,
    process_ready: bool,
    exact_discovery_sha256: String,
}

#[derive(Serialize)]
struct ControlRolloutApplySigningReceipt {
    version: u32,
    case_id: String,
    qualification_run_id: String,
    source_commit_sha: String,
    phase: String,
    signer_revision: u64,
    authority_id: String,
    route_deployment_id: String,
    rotation_operator_trust_sha256: String,
    proof_credential_ids: Vec<String>,
    exact_payload_sha256: String,
    exact_signed_receipt_sha256: String,
    terminal_marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRolloutApplyVerificationReceipt {
    version: u32,
    case_id: String,
    qualification_run_id: String,
    source_commit_sha: String,
    qualification_catalog_sha256: String,
    phase: String,
    signer_revision: u64,
    authority_id: String,
    route_deployment_id: String,
    rotation_operator_trust_sha256: String,
    saved_plan_sha256: String,
    terraform_show_json_sha256: String,
    plan_validation_receipt_sha256: String,
    terraform_executable_sha256: String,
    deployment_operator_executable_sha256: String,
    saved_plan_validator_executable_sha256: String,
    receipt_signer_executable_sha256: String,
    successor_secret_name: String,
    successor_secret_manifest_sha256: String,
    successor_signer_reference_sha256: String,
    successor_signer_state: String,
    successor_active_kid: Option<String>,
    successor_public_key_ring_version: u64,
    successor_public_key_ring_digest: String,
    apply_started_at_unix_ms: u64,
    apply_completed_at_unix_ms: u64,
    apply_outcome: String,
    terraform_apply_stdout_sha256: String,
    terraform_apply_stderr_sha256: String,
    postcondition_discovery_sha256: String,
    exact_signed_receipt_sha256: String,
    terminal_marker: String,
}

struct RotationRecoverySource {
    control_files: BTreeMap<String, Vec<u8>>,
    control_secret_r1: String,
    signer_reference: RouteGrantV2SignerReference,
    public_ring: RouteGrantV2PublicKeyRingArtifact,
    signer_private_key: Vec<u8>,
    operator_trust: RouteV2RotationOperatorTrust,
    operator_trust_bytes: Vec<u8>,
    operator_private_key: Vec<u8>,
}

struct RotationRecoveryRevision {
    reference: RouteGrantV2SignerReference,
    ring: RouteGrantV2PublicKeyRingArtifact,
    signer_private_key: Vec<u8>,
    command: RouteGrantV2SigningAuthorityCommand,
}

fn prepare_rotation_recovery(cli: &Cli, input: &Path, output: &Path, run_id: &str) -> Result<()> {
    validate_rotation_recovery_run_id(run_id)?;
    let candidate = Candidate::open_existing(input, 0)?;
    let source = load_rotation_recovery_source(&candidate)?;
    let (recovery, created) = RotationRecoveryOutput::open_or_create(output, 0)?;
    if created {
        generate_rotation_recovery(&recovery, &source, run_id)?;
    }
    let receipt = verify_rotation_recovery(&recovery, &source, run_id)?;
    report(cli, &receipt)
}

fn verify_rotation_recovery_command(
    cli: &Cli,
    input: &Path,
    output: &Path,
    run_id: &str,
) -> Result<()> {
    validate_rotation_recovery_run_id(run_id)?;
    let candidate = Candidate::open_existing(input, 0)?;
    let source = load_rotation_recovery_source(&candidate)?;
    let recovery = RotationRecoveryOutput::open_existing(output, 0)?;
    let receipt = verify_rotation_recovery(&recovery, &source, run_id)?;
    report(cli, &receipt)
}

fn validate_rotation_recovery_run_id(run_id: &str) -> Result<()> {
    anyhow::ensure!(
        Id::new(run_id.to_owned()).is_some(),
        "qualification run ID is not a canonical Cats ID"
    );
    Ok(())
}

fn load_rotation_recovery_source(candidate: &Candidate) -> Result<RotationRecoverySource> {
    ensure_file_contract(
        &candidate.authority,
        &AUTHORITY_FILES,
        candidate.expected_uid,
    )?;
    ensure_file_contract(&candidate.control, &CONTROL_FILES, candidate.expected_uid)?;
    ensure_file_contract(&candidate.provider, &PROVIDER_FILES, candidate.expected_uid)?;
    let authority = read_role_data(
        &candidate.authority,
        &AUTHORITY_FILES,
        candidate.expected_uid,
    )?;
    let control_files = read_role_data(&candidate.control, &CONTROL_FILES, candidate.expected_uid)?;
    let signer_bytes = required(&control_files, "signer.v1.json")?;
    let signer_reference = decode_route_grant_v2_signer_reference(signer_bytes)
        .map_err(|error| anyhow!("decode recovery source signer reference: {error:?}"))?;
    let ring_bytes = required(&control_files, "public-key-ring.v1.json")?;
    let public_ring = decode_route_grant_v2_public_key_ring(ring_bytes)
        .map_err(|error| anyhow!("decode recovery source public ring: {error:?}"))?;
    signer_reference
        .validate_ring(&public_ring)
        .map_err(|error| anyhow!("bind recovery source signer/ring: {error:?}"))?;
    anyhow::ensure!(
        signer_reference.signer_revision.get() == 1
            && public_ring.ring_version.get() == 1
            && signer_reference.expected_previous.is_none()
            && public_ring.expected_previous.is_none()
            && public_ring.keys.len() == 1,
        "recovery source is not the exact revision-1 lineage root"
    );
    let RouteGrantV2SignerSelection::Active { active_kid, .. } = &signer_reference.signer else {
        bail!("recovery source revision-1 signer is disabled")
    };
    anyhow::ensure!(
        public_ring.key(active_kid).is_some(),
        "recovery source active signer is absent from its ring"
    );

    let signer_private_key = required(&control_files, "signer-private-key.pem")?.to_vec();
    ensure_private_key_matches_kid(&signer_private_key, active_kid.as_str())?;
    let operator_trust_bytes =
        required(&control_files, "rotation-operator-trust.v1.json")?.to_vec();
    let operator_trust = decode_route_v2_rotation_operator_trust(&operator_trust_bytes)
        .map_err(|error| anyhow!("decode recovery source operator trust: {error}"))?;
    anyhow::ensure!(
        operator_trust.route_deployment_id == signer_reference.deployment_id
            && operator_trust.threshold == 1
            && operator_trust.credentials.len() == 1,
        "recovery source operator trust does not bind the revision-1 deployment"
    );
    let operator_private_key = required(&authority, "rotation-operator-private-key.pem")?.to_vec();
    let operator = Ed25519RequestSigner::from_pkcs8_v2_pem(
        operator_trust.credentials[0].credential_id.clone(),
        &operator_private_key,
    )
    .map_err(|_| anyhow!("recovery source operator key is not strict PKCS#8 v2"))?;
    anyhow::ensure!(
        Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(operator.public_key_spki_der())).as_ref()
            == Some(&operator_trust.credentials[0].public_key_spki),
        "recovery source operator key does not match its trust"
    );

    let provider_bytes = read_file(
        &candidate.provider,
        "control-secret.v1.json",
        0o600,
        candidate.expected_uid,
        MAX_JSON_BYTES,
    )?;
    let provider: KubernetesSecretManifest = serde_json::from_slice(&provider_bytes)
        .context("decode revision-1 immutable Control Secret")?;
    anyhow::ensure!(
        serde_json::to_vec(&provider)? == provider_bytes,
        "revision-1 Control Secret input is not canonical JSON"
    );
    verify_kubernetes_secret(provider_bytes, &provider.metadata.name, &control_files)?;
    validate_kubernetes_secret_name_at_revision(&provider.metadata.name, 1)?;

    Ok(RotationRecoverySource {
        control_files,
        control_secret_r1: provider.metadata.name,
        signer_reference,
        public_ring,
        signer_private_key,
        operator_trust,
        operator_trust_bytes,
        operator_private_key,
    })
}

fn generate_rotation_recovery(
    output: &RotationRecoveryOutput,
    source: &RotationRecoverySource,
    run_id: &str,
) -> Result<()> {
    let mut normal_private_key = generate_pkcs8_v2_pem()?;
    let mut recovery_private_key = generate_pkcs8_v2_pem()?;
    let normal_entry = public_entry_for_private_key("route_normal_successor", &normal_private_key)?;
    let recovery_entry =
        public_entry_for_private_key("route_recovery_successor", &recovery_private_key)?;
    anyhow::ensure!(
        normal_entry.kid != recovery_entry.kid
            && source.public_ring.key(&normal_entry.kid).is_none()
            && source.public_ring.key(&recovery_entry.kid).is_none(),
        "generated Route v2 successor keys are not fresh"
    );
    let normal_secret_reference_id =
        Id::new(random_id("route_secret")?).expect("generated normal secret reference ID is valid");
    let recovery_secret_reference_id = Id::new(random_id("route_secret")?)
        .expect("generated recovery secret reference ID is valid");
    anyhow::ensure!(
        normal_secret_reference_id != recovery_secret_reference_id
            && source_secret_reference_id(&source.signer_reference)
                != Some(&normal_secret_reference_id)
            && source_secret_reference_id(&source.signer_reference)
                != Some(&recovery_secret_reference_id),
        "generated Route v2 secret reference IDs are not fresh"
    );

    let revisions = build_rotation_recovery_revisions(
        source,
        &normal_entry,
        &normal_secret_reference_id,
        &normal_private_key,
        &recovery_entry,
        &recovery_secret_reference_id,
        &recovery_private_key,
    )?;

    publish(
        &output.authority,
        "normal-successor-private-key.pem",
        &normal_private_key,
        0o600,
    )?;
    publish(
        &output.authority,
        "recovery-successor-private-key.pem",
        &recovery_private_key,
        0o600,
    )?;

    let mut command_entries = Vec::with_capacity(ROTATION_RECOVERY_REVISIONS.len());
    let mut rollout_entries = Vec::with_capacity(ROTATION_RECOVERY_REVISIONS.len());
    for (phase, revision) in ROTATION_RECOVERY_PHASES
        .into_iter()
        .zip(ROTATION_RECOVERY_REVISIONS)
    {
        let material = revisions
            .get(&revision)
            .context("missing generated Route v2 recovery revision")?;
        let reference_bytes = encode_route_grant_v2_signer_reference(&material.reference)
            .map_err(|error| anyhow!("encode recovery signer reference r{revision}: {error:?}"))?;
        let ring_bytes = encode_route_grant_v2_public_key_ring(&material.ring)
            .map_err(|error| anyhow!("encode recovery public ring r{revision}: {error:?}"))?;
        let control_directory = output
            .control
            .get(&revision)
            .context("missing recovery Control revision directory")?;
        for (name, mode) in CONTROL_FILES {
            let bytes = match name {
                "signer.v1.json" => reference_bytes.as_slice(),
                "public-key-ring.v1.json" => ring_bytes.as_slice(),
                "signer-private-key.pem" => material.signer_private_key.as_slice(),
                fixed => required(&source.control_files, fixed)?,
            };
            publish(control_directory, name, bytes, mode)?;
        }
        sync_directory(control_directory, "sync recovery Control revision")?;
        let control_data = read_role_data(control_directory, &CONTROL_FILES, output.expected_uid)?;
        let secret_name = revisioned_control_secret_name(&source.control_secret_r1, revision)?;
        let secret_manifest = encode_kubernetes_secret(&secret_name, &control_data)?;
        let secret_directory = output
            .secret_channel
            .get(&revision)
            .context("missing recovery secret-channel revision directory")?;
        publish(
            secret_directory,
            "control-secret.v1.json",
            &secret_manifest,
            0o600,
        )?;
        sync_directory(secret_directory, "sync recovery secret-channel revision")?;

        let rollout = RotationRecoveryRolloutReference {
            version: 1,
            signer_revision: revision,
            secret_name: secret_name.clone(),
            secret_manifest_sha256: sha256(&secret_manifest),
            signer_reference_sha256: sha256(&reference_bytes),
            public_key_ring_digest: material
                .ring
                .digest()
                .map_err(|error| anyhow!("digest recovery ring r{revision}: {error:?}"))?
                .to_string(),
        };
        let rollout_bytes = serde_json::to_vec(&rollout).context("encode Control rollout ref")?;
        let provider_directory = output
            .provider
            .get(&revision)
            .context("missing recovery provider revision directory")?;
        publish(
            provider_directory,
            "control-rollout-reference.v1.json",
            &rollout_bytes,
            0o600,
        )?;
        sync_directory(provider_directory, "sync recovery provider revision")?;

        let command_bytes = encode_authority_command(&material.command)?;
        command_entries.push(RotationRecoveryCommandEntry {
            phase: phase.to_owned(),
            signer_revision: revision,
            ring_version: material.reference.public_key_ring_version.get(),
            exact_authority_command_sha256: sha256(&command_bytes),
            exact_authority_command_json: String::from_utf8(command_bytes)
                .expect("canonical Route v2 command JSON is UTF-8"),
        });
        rollout_entries.push(RotationRecoveryRolloutEntry {
            signer_revision: revision,
            secret_name,
            signer_reference_sha256: rollout.signer_reference_sha256,
            public_key_ring_digest: rollout.public_key_ring_digest,
            secret_manifest_sha256: rollout.secret_manifest_sha256,
        });
    }

    let bundle = RotationRecoveryCommandBundle {
        version: 1,
        case_id: ROTATION_RECOVERY_CASE_ID.to_owned(),
        source_commit_sha: source.operator_trust.release_commit_sha.clone(),
        qualification_run_id: run_id.to_owned(),
        route_deployment_id: source.signer_reference.deployment_id.to_string(),
        rotation_operator_authority_id: source.operator_trust.authority_id.to_string(),
        rotation_operator_trust_sha256: sha256(&source.operator_trust_bytes),
        commands: command_entries,
        control_rollouts: rollout_entries,
    };
    let bundle_bytes = serde_json::to_vec(&bundle).context("encode recovery command bundle")?;
    anyhow::ensure!(
        bundle_bytes.len() <= MAX_ROTATION_RECOVERY_BUNDLE_BYTES,
        "recovery command bundle exceeds its closed byte limit"
    );
    publish(
        &output.commands,
        "route-v2-rotation-command-bundle.v1.json",
        &bundle_bytes,
        0o600,
    )?;
    sync_directory(&output.commands, "sync recovery command bundle")?;
    sync_directory(&output.root, "sync completed Route v2 recovery output")?;
    normal_private_key.fill(0);
    recovery_private_key.fill(0);
    Ok(())
}

fn build_rotation_recovery_revisions(
    source: &RotationRecoverySource,
    normal_entry: &RouteGrantV2PublicKeyEntry,
    normal_secret_reference_id: &Id,
    normal_private_key: &[u8],
    recovery_entry: &RouteGrantV2PublicKeyEntry,
    recovery_secret_reference_id: &Id,
    recovery_private_key: &[u8],
) -> Result<BTreeMap<u64, RotationRecoveryRevision>> {
    let mut revisions = BTreeMap::new();

    let ring2 = successor_ring(
        &source.public_ring,
        vec![source.public_ring.keys[0].clone(), normal_entry.clone()],
    )?;
    let reference2 = successor_reference(
        &source.signer_reference,
        source.signer_reference.signer.clone(),
        &ring2,
    )?;
    insert_recovery_revision(
        &mut revisions,
        2,
        reference2,
        ring2.clone(),
        source.signer_private_key.clone(),
        RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
            successor_ring: ring2,
            new_secret_reference_id: normal_secret_reference_id.clone(),
        },
    )?;

    let reference3 = successor_reference(
        &revisions[&2].reference,
        RouteGrantV2SignerSelection::Active {
            active_kid: normal_entry.kid.clone(),
            secret_reference_id: normal_secret_reference_id.clone(),
        },
        &revisions[&2].ring,
    )?;
    let ring2_for_revision3 = revisions[&2].ring.clone();
    insert_recovery_revision(
        &mut revisions,
        3,
        reference3,
        ring2_for_revision3,
        normal_private_key.to_vec(),
        RouteGrantV2SigningAuthorityCommandKind::SwitchActive,
    )?;

    let ring3 = successor_ring(&revisions[&3].ring, vec![normal_entry.clone()])?;
    let reference4 = successor_reference(
        &revisions[&3].reference,
        revisions[&3].reference.signer.clone(),
        &ring3,
    )?;
    insert_recovery_revision(
        &mut revisions,
        4,
        reference4,
        ring3.clone(),
        normal_private_key.to_vec(),
        RouteGrantV2SigningAuthorityCommandKind::PublishNewOnly {
            successor_ring: ring3,
        },
    )?;

    let reference5 = successor_reference(
        &revisions[&4].reference,
        revisions[&4].reference.signer.clone(),
        &revisions[&4].ring,
    )?;
    let ring3_for_revision5 = revisions[&4].ring.clone();
    insert_recovery_revision(
        &mut revisions,
        5,
        reference5,
        ring3_for_revision5,
        normal_private_key.to_vec(),
        RouteGrantV2SigningAuthorityCommandKind::Retire,
    )?;

    let ring4 = successor_ring(&revisions[&5].ring, Vec::new())?;
    let reference6 = successor_reference(
        &revisions[&5].reference,
        RouteGrantV2SignerSelection::Disabled,
        &ring4,
    )?;
    insert_recovery_revision(
        &mut revisions,
        6,
        reference6,
        ring4.clone(),
        normal_private_key.to_vec(),
        RouteGrantV2SigningAuthorityCommandKind::Disable {
            successor_ring: ring4,
        },
    )?;

    let ring5 = successor_ring(&revisions[&6].ring, vec![recovery_entry.clone()])?;
    let reference7 = successor_reference(
        &revisions[&6].reference,
        RouteGrantV2SignerSelection::Disabled,
        &ring5,
    )?;
    insert_recovery_revision(
        &mut revisions,
        7,
        reference7,
        ring5.clone(),
        recovery_private_key.to_vec(),
        RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
            successor_ring: ring5,
            new_secret_reference_id: recovery_secret_reference_id.clone(),
        },
    )?;

    let reference8 = successor_reference(
        &revisions[&7].reference,
        RouteGrantV2SignerSelection::Active {
            active_kid: recovery_entry.kid.clone(),
            secret_reference_id: recovery_secret_reference_id.clone(),
        },
        &revisions[&7].ring,
    )?;
    let ring5_for_revision8 = revisions[&7].ring.clone();
    insert_recovery_revision(
        &mut revisions,
        8,
        reference8,
        ring5_for_revision8,
        recovery_private_key.to_vec(),
        RouteGrantV2SigningAuthorityCommandKind::Activate,
    )?;

    Ok(revisions)
}

fn insert_recovery_revision(
    revisions: &mut BTreeMap<u64, RotationRecoveryRevision>,
    revision: u64,
    reference: RouteGrantV2SignerReference,
    ring: RouteGrantV2PublicKeyRingArtifact,
    signer_private_key: Vec<u8>,
    kind: RouteGrantV2SigningAuthorityCommandKind,
) -> Result<()> {
    anyhow::ensure!(
        reference.signer_revision.get() == revision,
        "generated recovery signer revision is not adjacent"
    );
    reference
        .validate_ring(&ring)
        .map_err(|error| anyhow!("generated recovery signer/ring mismatch: {error:?}"))?;
    let command = RouteGrantV2SigningAuthorityCommand {
        successor: reference.clone(),
        kind,
    };
    command
        .validate()
        .map_err(|error| anyhow!("generated recovery command is invalid: {error}"))?;
    anyhow::ensure!(
        revisions
            .insert(
                revision,
                RotationRecoveryRevision {
                    reference,
                    ring,
                    signer_private_key,
                    command,
                },
            )
            .is_none(),
        "duplicate recovery revision"
    );
    Ok(())
}

fn successor_ring(
    current: &RouteGrantV2PublicKeyRingArtifact,
    mut keys: Vec<RouteGrantV2PublicKeyEntry>,
) -> Result<RouteGrantV2PublicKeyRingArtifact> {
    keys.sort_by(|left, right| left.kid.cmp(&right.kid));
    let ring = RouteGrantV2PublicKeyRingArtifact {
        version: ContractVersion::V1,
        ring_version: Epoch::new(
            current
                .ring_version
                .get()
                .checked_add(1)
                .context("recovery ring version overflow")?,
        )
        .context("invalid recovery ring version")?,
        expected_previous: Some(RouteGrantV2PublicKeyRingExpectedPrevious {
            ring_version: current.ring_version,
            key_ring_digest: current
                .digest()
                .map_err(|error| anyhow!("digest previous recovery ring: {error:?}"))?,
        }),
        keys,
    };
    ring.validate()
        .map_err(|error| anyhow!("generated recovery ring is invalid: {error:?}"))?;
    Ok(ring)
}

fn successor_reference(
    current: &RouteGrantV2SignerReference,
    signer: RouteGrantV2SignerSelection,
    ring: &RouteGrantV2PublicKeyRingArtifact,
) -> Result<RouteGrantV2SignerReference> {
    let reference = RouteGrantV2SignerReference {
        version: ContractVersion::V1,
        deployment_id: current.deployment_id.clone(),
        signer_revision: Epoch::new(
            current
                .signer_revision
                .get()
                .checked_add(1)
                .context("recovery signer revision overflow")?,
        )
        .context("invalid recovery signer revision")?,
        expected_previous: Some(RouteGrantV2SignerExpectedPrevious {
            signer_revision: current.signer_revision,
            signer_reference_sha256: current
                .digest()
                .map_err(|error| anyhow!("digest previous signer reference: {error:?}"))?,
        }),
        signer,
        public_key_ring_version: ring.ring_version,
        public_key_ring_digest: ring
            .digest()
            .map_err(|error| anyhow!("digest recovery public ring: {error:?}"))?,
    };
    reference
        .validate_ring(ring)
        .map_err(|error| anyhow!("generated recovery signer reference is invalid: {error:?}"))?;
    Ok(reference)
}

fn public_entry_for_private_key(
    validation_label: &str,
    private_key: &[u8],
) -> Result<RouteGrantV2PublicKeyEntry> {
    let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(
        Id::new(random_id(validation_label)?)
            .expect("generated key validation ID is a canonical Cats ID"),
        private_key,
    )
    .map_err(|_| anyhow!("generated recovery signer is not strict PKCS#8 v2"))?;
    let public = RouteGrantV2PublicKey::from_spki_der(signer.public_key_spki_der())
        .context("derive recovery signer public key")?;
    Ok(RouteGrantV2PublicKeyEntry {
        kid: public.kid().clone(),
        public_key_spki: Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.public_key_spki_der()))
            .expect("generated recovery signer SPKI is canonical base64url"),
    })
}

fn source_secret_reference_id(reference: &RouteGrantV2SignerReference) -> Option<&Id> {
    match &reference.signer {
        RouteGrantV2SignerSelection::Active {
            secret_reference_id,
            ..
        } => Some(secret_reference_id),
        RouteGrantV2SignerSelection::Disabled => None,
    }
}

fn encode_authority_command(command: &RouteGrantV2SigningAuthorityCommand) -> Result<Vec<u8>> {
    command
        .validate()
        .map_err(|error| anyhow!("validate Route v2 authority command: {error}"))?;
    serde_json::to_vec(command).context("encode canonical Route v2 authority command")
}

fn decode_authority_command(bytes: &[u8]) -> Result<RouteGrantV2SigningAuthorityCommand> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES,
        "Route v2 authority command exceeds its closed byte limit"
    );
    let command: RouteGrantV2SigningAuthorityCommand =
        serde_json::from_slice(bytes).context("decode Route v2 authority command")?;
    anyhow::ensure!(
        encode_authority_command(&command)? == bytes,
        "Route v2 authority command is not canonical JSON"
    );
    Ok(command)
}

fn revisioned_control_secret_name(revision_one: &str, revision: u64) -> Result<String> {
    validate_kubernetes_secret_name_at_revision(revision_one, 1)?;
    anyhow::ensure!(
        revision > 0,
        "Control Secret signer revision must be positive"
    );
    let prefix = revision_one
        .strip_suffix("-r1")
        .context("revision-1 Control Secret name has no canonical suffix")?;
    let name = format!("{prefix}-r{revision}");
    validate_kubernetes_secret_name_at_revision(&name, revision)?;
    Ok(name)
}

fn ensure_private_key_matches_kid(private_key: &[u8], expected_kid: &str) -> Result<()> {
    let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(
        Id::new("route_recovery_key_verifier").expect("fixed verifier ID is valid"),
        private_key,
    )
    .map_err(|_| anyhow!("Route v2 recovery signer key is not strict PKCS#8 v2"))?;
    let public = RouteGrantV2PublicKey::from_spki_der(signer.public_key_spki_der())
        .context("derive Route v2 recovery signer kid")?;
    anyhow::ensure!(
        public.kid().as_str() == expected_kid,
        "Route v2 recovery private key does not match the selected kid"
    );
    Ok(())
}

fn verify_rotation_recovery(
    output: &RotationRecoveryOutput,
    source: &RotationRecoverySource,
    run_id: &str,
) -> Result<RotationRecoveryVerificationReceipt> {
    ensure_names(&output.root, &ROTATION_RECOVERY_ROOT_DIRECTORIES)?;
    ensure_file_contract(
        &output.authority,
        &ROTATION_RECOVERY_AUTHORITY_FILES,
        output.expected_uid,
    )?;
    ensure_file_contract(
        &output.commands,
        &ROTATION_RECOVERY_COMMAND_FILES,
        output.expected_uid,
    )?;
    let expected_revisions = ROTATION_RECOVERY_REVISIONS
        .into_iter()
        .map(|revision| format!("r{revision}"))
        .collect::<Vec<_>>();
    for parent_name in ["control", "provider", "secret-channel"] {
        let parent = open_child_directory(&output.root, parent_name, output.expected_uid)?;
        ensure_names(&parent, &expected_revisions)?;
    }

    let bundle_bytes = read_file(
        &output.commands,
        "route-v2-rotation-command-bundle.v1.json",
        0o600,
        output.expected_uid,
        MAX_ROTATION_RECOVERY_BUNDLE_BYTES,
    )?;
    let bundle: RotationRecoveryCommandBundle =
        serde_json::from_slice(&bundle_bytes).context("decode Route v2 recovery command bundle")?;
    anyhow::ensure!(
        serde_json::to_vec(&bundle)? == bundle_bytes
            && bundle.version == 1
            && bundle.case_id == ROTATION_RECOVERY_CASE_ID
            && bundle.source_commit_sha == source.operator_trust.release_commit_sha
            && bundle.qualification_run_id == run_id
            && bundle.route_deployment_id == source.signer_reference.deployment_id.as_str()
            && bundle.rotation_operator_authority_id == source.operator_trust.authority_id.as_str()
            && bundle.rotation_operator_trust_sha256 == sha256(&source.operator_trust_bytes)
            && bundle.commands.len() == ROTATION_RECOVERY_REVISIONS.len()
            && bundle.control_rollouts.len() == ROTATION_RECOVERY_REVISIONS.len(),
        "Route v2 recovery command bundle is not the exact source-bound target"
    );

    let normal_private_key = read_file(
        &output.authority,
        "normal-successor-private-key.pem",
        0o600,
        output.expected_uid,
        MAX_PRIVATE_KEY_BYTES,
    )?;
    let recovery_private_key = read_file(
        &output.authority,
        "recovery-successor-private-key.pem",
        0o600,
        output.expected_uid,
        MAX_PRIVATE_KEY_BYTES,
    )?;
    let normal_entry =
        public_entry_for_private_key("normal_recovery_verifier", &normal_private_key)?;
    let recovery_entry =
        public_entry_for_private_key("disabled_recovery_verifier", &recovery_private_key)?;
    anyhow::ensure!(
        normal_entry.kid != recovery_entry.kid
            && source.public_ring.key(&normal_entry.kid).is_none()
            && source.public_ring.key(&recovery_entry.kid).is_none(),
        "Route v2 recovery output reuses a signer lineage"
    );

    let mut previous_reference = source.signer_reference.clone();
    let mut previous_ring = source.public_ring.clone();
    let mut normal_secret_reference_id: Option<Id> = None;
    let mut recovery_secret_reference_id: Option<Id> = None;
    let mut terminal_secret_name = None;
    for (index, ((phase, revision), command_entry)) in ROTATION_RECOVERY_PHASES
        .into_iter()
        .zip(ROTATION_RECOVERY_REVISIONS)
        .zip(&bundle.commands)
        .enumerate()
    {
        anyhow::ensure!(
            command_entry.phase == phase
                && command_entry.signer_revision == revision
                && command_entry.exact_authority_command_sha256
                    == sha256(command_entry.exact_authority_command_json.as_bytes()),
            "Route v2 recovery command entry {phase} is not canonical"
        );
        let command =
            decode_authority_command(command_entry.exact_authority_command_json.as_bytes())?;
        let control_directory = output
            .control
            .get(&revision)
            .context("missing verified recovery Control directory")?;
        ensure_file_contract(control_directory, &CONTROL_FILES, output.expected_uid)?;
        let control_data = read_role_data(control_directory, &CONTROL_FILES, output.expected_uid)?;
        for (name, _) in CONTROL_FILES {
            if !matches!(
                name,
                "signer.v1.json" | "public-key-ring.v1.json" | "signer-private-key.pem"
            ) {
                anyhow::ensure!(
                    required(&control_data, name)? == required(&source.control_files, name)?,
                    "fixed Control artifact {name} changes at recovery r{revision}"
                );
            }
        }
        let reference_bytes = required(&control_data, "signer.v1.json")?;
        let reference = decode_route_grant_v2_signer_reference(reference_bytes)
            .map_err(|error| anyhow!("decode recovery signer r{revision}: {error:?}"))?;
        let ring_bytes = required(&control_data, "public-key-ring.v1.json")?;
        let ring = decode_route_grant_v2_public_key_ring(ring_bytes)
            .map_err(|error| anyhow!("decode recovery ring r{revision}: {error:?}"))?;
        reference
            .validate_ring(&ring)
            .map_err(|error| anyhow!("bind recovery signer/ring r{revision}: {error:?}"))?;
        anyhow::ensure!(
            reference.signer_revision.get() == revision
                && reference.deployment_id == source.signer_reference.deployment_id
                && reference.expected_previous
                    == Some(RouteGrantV2SignerExpectedPrevious {
                        signer_revision: previous_reference.signer_revision,
                        signer_reference_sha256: previous_reference.digest().map_err(|error| {
                            anyhow!("digest previous recovery signer: {error:?}")
                        })?,
                    })
                && command.successor == reference
                && command_entry.ring_version == ring.ring_version.get(),
            "Route v2 recovery signer r{revision} is not the exact adjacent command target"
        );

        let expected_private_key: &[u8] = match revision {
            2 => &source.signer_private_key,
            3..=6 => &normal_private_key,
            7..=8 => &recovery_private_key,
            _ => unreachable!("closed recovery revision set"),
        };
        anyhow::ensure!(
            required(&control_data, "signer-private-key.pem")? == expected_private_key,
            "Route v2 recovery Control private key does not match r{revision}"
        );

        verify_rotation_recovery_phase(
            phase,
            &command,
            &previous_reference,
            &previous_ring,
            &ring,
            &normal_entry,
            &recovery_entry,
            &mut normal_secret_reference_id,
            &mut recovery_secret_reference_id,
        )?;

        let secret_name = revisioned_control_secret_name(&source.control_secret_r1, revision)?;
        let secret_directory = output
            .secret_channel
            .get(&revision)
            .context("missing verified recovery secret-channel directory")?;
        ensure_file_contract(
            secret_directory,
            &ROTATION_RECOVERY_SECRET_FILES,
            output.expected_uid,
        )?;
        let secret_manifest = read_file(
            secret_directory,
            "control-secret.v1.json",
            0o600,
            output.expected_uid,
            MAX_JSON_BYTES,
        )?;
        verify_kubernetes_secret(secret_manifest.clone(), &secret_name, &control_data)?;
        let provider_directory = output
            .provider
            .get(&revision)
            .context("missing verified recovery provider directory")?;
        ensure_file_contract(
            provider_directory,
            &ROTATION_RECOVERY_PROVIDER_FILES,
            output.expected_uid,
        )?;
        let rollout_bytes = read_file(
            provider_directory,
            "control-rollout-reference.v1.json",
            0o600,
            output.expected_uid,
            MAX_JSON_BYTES,
        )?;
        let rollout: RotationRecoveryRolloutReference = serde_json::from_slice(&rollout_bytes)
            .context("decode recovery Control rollout reference")?;
        let expected_rollout = RotationRecoveryRolloutReference {
            version: 1,
            signer_revision: revision,
            secret_name: secret_name.clone(),
            secret_manifest_sha256: sha256(&secret_manifest),
            signer_reference_sha256: sha256(reference_bytes),
            public_key_ring_digest: ring
                .digest()
                .map_err(|error| anyhow!("digest verified recovery ring: {error:?}"))?
                .to_string(),
        };
        anyhow::ensure!(
            rollout == expected_rollout
                && serde_json::to_vec(&rollout)? == rollout_bytes
                && bundle.control_rollouts[index]
                    == RotationRecoveryRolloutEntry {
                        signer_revision: revision,
                        secret_name: secret_name.clone(),
                        signer_reference_sha256: expected_rollout.signer_reference_sha256.clone(),
                        public_key_ring_digest: expected_rollout.public_key_ring_digest.clone(),
                        secret_manifest_sha256: expected_rollout.secret_manifest_sha256.clone(),
                    },
            "Route v2 recovery rollout reference differs at r{revision}"
        );
        terminal_secret_name = Some(secret_name);
        previous_reference = reference;
        previous_ring = ring;
    }

    let normal_secret_reference_id = normal_secret_reference_id
        .context("recovery bundle has no normal successor secret reference")?;
    let recovery_secret_reference_id = recovery_secret_reference_id
        .context("recovery bundle has no recovery successor secret reference")?;
    anyhow::ensure!(
        normal_secret_reference_id != recovery_secret_reference_id
            && source_secret_reference_id(&source.signer_reference)
                != Some(&normal_secret_reference_id)
            && source_secret_reference_id(&source.signer_reference)
                != Some(&recovery_secret_reference_id),
        "Route v2 recovery bundle reuses a secret reference lineage"
    );
    let RouteGrantV2SignerSelection::Active { active_kid, .. } = &previous_reference.signer else {
        bail!("terminal Route v2 recovery signer is not active")
    };
    anyhow::ensure!(
        active_kid == &recovery_entry.kid
            && previous_reference.signer_revision.get() == 8
            && previous_ring.ring_version.get() == 5
            && previous_ring.keys == vec![recovery_entry],
        "terminal Route v2 recovery target is not the fresh active lineage"
    );

    Ok(RotationRecoveryVerificationReceipt {
        version: 1,
        output_directory: output.root_path.display().to_string(),
        case_id: ROTATION_RECOVERY_CASE_ID.to_owned(),
        qualification_run_id: run_id.to_owned(),
        source_commit_sha: source.operator_trust.release_commit_sha.clone(),
        route_deployment_id: source.signer_reference.deployment_id.to_string(),
        rotation_operator_authority_id: source.operator_trust.authority_id.to_string(),
        rotation_operator_trust_sha256: sha256(&source.operator_trust_bytes),
        command_bundle_sha256: sha256(&bundle_bytes),
        first_signer_revision: 2,
        terminal_signer_revision: previous_reference.signer_revision.get(),
        terminal_ring_version: previous_ring.ring_version.get(),
        terminal_secret_name: terminal_secret_name.context("missing terminal Control Secret")?,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_rotation_recovery_phase(
    phase: &str,
    command: &RouteGrantV2SigningAuthorityCommand,
    previous_reference: &RouteGrantV2SignerReference,
    previous_ring: &RouteGrantV2PublicKeyRingArtifact,
    ring: &RouteGrantV2PublicKeyRingArtifact,
    normal_entry: &RouteGrantV2PublicKeyEntry,
    recovery_entry: &RouteGrantV2PublicKeyEntry,
    normal_secret_reference_id: &mut Option<Id>,
    recovery_secret_reference_id: &mut Option<Id>,
) -> Result<()> {
    match (phase, &command.kind) {
        (
            "publish_overlap",
            RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                successor_ring,
                new_secret_reference_id,
            },
        ) => {
            anyhow::ensure!(
                command.successor.signer == previous_reference.signer
                    && successor_ring == ring
                    && ring_is_successor_of(previous_ring, ring)?
                    && ring.keys.len() == 2
                    && previous_ring
                        .keys
                        .iter()
                        .all(|entry| ring.key(&entry.kid) == Some(entry))
                    && ring.key(&normal_entry.kid) == Some(normal_entry),
                "normal Route v2 overlap phase is not the exact two-key successor"
            );
            anyhow::ensure!(
                normal_secret_reference_id
                    .replace(new_secret_reference_id.clone())
                    .is_none(),
                "normal Route v2 successor secret reference appears twice"
            );
        }
        ("switch_active", RouteGrantV2SigningAuthorityCommandKind::SwitchActive) => {
            let RouteGrantV2SignerSelection::Active {
                active_kid,
                secret_reference_id,
            } = &command.successor.signer
            else {
                bail!("normal Route v2 switch target is not active")
            };
            anyhow::ensure!(
                ring == previous_ring
                    && active_kid == &normal_entry.kid
                    && Some(secret_reference_id) == normal_secret_reference_id.as_ref(),
                "normal Route v2 switch target does not select the fresh successor"
            );
        }
        (
            "publish_new_only",
            RouteGrantV2SigningAuthorityCommandKind::PublishNewOnly { successor_ring },
        ) => {
            anyhow::ensure!(
                command.successor.signer == previous_reference.signer
                    && successor_ring == ring
                    && ring_is_successor_of(previous_ring, ring)?
                    && ring.keys == vec![normal_entry.clone()],
                "normal Route v2 new-only phase is not the exact one-key successor"
            );
        }
        ("retire", RouteGrantV2SigningAuthorityCommandKind::Retire) => {
            anyhow::ensure!(
                command.successor.signer == previous_reference.signer && ring == previous_ring,
                "normal Route v2 retire phase changes the signer or public ring"
            );
        }
        ("disable", RouteGrantV2SigningAuthorityCommandKind::Disable { successor_ring }) => {
            anyhow::ensure!(
                command.successor.signer == RouteGrantV2SignerSelection::Disabled
                    && successor_ring == ring
                    && ring_is_successor_of(previous_ring, ring)?
                    && ring.keys.is_empty(),
                "Route v2 disable phase is not the exact empty-ring successor"
            );
        }
        (
            "publish_recovery",
            RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                successor_ring,
                new_secret_reference_id,
            },
        ) => {
            anyhow::ensure!(
                previous_reference.signer == RouteGrantV2SignerSelection::Disabled
                    && command.successor.signer == RouteGrantV2SignerSelection::Disabled
                    && successor_ring == ring
                    && ring_is_successor_of(previous_ring, ring)?
                    && ring.keys == vec![recovery_entry.clone()],
                "Route v2 recovery publication is not a fresh disabled one-key successor"
            );
            anyhow::ensure!(
                recovery_secret_reference_id
                    .replace(new_secret_reference_id.clone())
                    .is_none(),
                "Route v2 recovery secret reference appears twice"
            );
        }
        ("activate", RouteGrantV2SigningAuthorityCommandKind::Activate) => {
            let RouteGrantV2SignerSelection::Active {
                active_kid,
                secret_reference_id,
            } = &command.successor.signer
            else {
                bail!("Route v2 activation target is not active")
            };
            anyhow::ensure!(
                previous_reference.signer == RouteGrantV2SignerSelection::Disabled
                    && ring == previous_ring
                    && active_kid == &recovery_entry.kid
                    && Some(secret_reference_id) == recovery_secret_reference_id.as_ref(),
                "Route v2 activation does not select the fresh recovery signer"
            );
        }
        _ => bail!("Route v2 recovery phase {phase} has the wrong typed command"),
    }
    Ok(())
}

fn ring_is_successor_of(
    previous: &RouteGrantV2PublicKeyRingArtifact,
    successor: &RouteGrantV2PublicKeyRingArtifact,
) -> Result<bool> {
    Ok(
        previous.ring_version.get().checked_add(1) == Some(successor.ring_version.get())
            && successor.expected_previous
                == Some(RouteGrantV2PublicKeyRingExpectedPrevious {
                    ring_version: previous.ring_version,
                    key_ring_digest: previous
                        .digest()
                        .map_err(|error| anyhow!("digest previous recovery ring: {error:?}"))?,
                }),
    )
}

fn sign_rotation_recovery_phase(
    cli: &Cli,
    input: &Path,
    recovery_path: &Path,
    phase: &str,
    output: &Path,
) -> Result<()> {
    anyhow::ensure!(
        ROTATION_RECOVERY_PHASES.contains(&phase),
        "unknown Route v2 recovery phase"
    );
    let candidate = Candidate::open_existing(input, 0)?;
    let source = load_rotation_recovery_source(&candidate)?;
    let recovery = RotationRecoveryOutput::open_existing(recovery_path, 0)?;
    let bundle_bytes = read_file(
        &recovery.commands,
        "route-v2-rotation-command-bundle.v1.json",
        0o600,
        recovery.expected_uid,
        MAX_ROTATION_RECOVERY_BUNDLE_BYTES,
    )?;
    let bundle: RotationRecoveryCommandBundle = serde_json::from_slice(&bundle_bytes)
        .context("decode Route v2 recovery command bundle before signing")?;
    validate_rotation_recovery_run_id(&bundle.qualification_run_id)?;
    verify_rotation_recovery(&recovery, &source, &bundle.qualification_run_id)?;
    let entry = bundle
        .commands
        .iter()
        .find(|entry| entry.phase == phase)
        .context("prepared recovery bundle is missing the requested phase")?;
    let authority_command =
        decode_authority_command(entry.exact_authority_command_json.as_bytes())?;

    let signed_bytes = if output.exists() {
        read_user_file(output, ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES, 0o600, true)?
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time predates the Unix epoch")?
            .as_millis();
        let now = u64::try_from(now).context("system time exceeds Route v2 wire range")?;
        let issued_at = now.saturating_sub(5_000);
        let expires_at = issued_at
            .checked_add(ROTATION_RECOVERY_COMMAND_LIFETIME_MILLIS)
            .context("Route v2 recovery command expiry overflow")?;
        let payload = RouteV2SigningCommandPayload {
            version: ContractVersion::V1,
            authority_id: source.operator_trust.authority_id.clone(),
            release_commit_sha: source.operator_trust.release_commit_sha.clone(),
            command_id: RandomId128::new(random_hex(16)?)
                .expect("generated Route v2 command ID is canonical 128-bit hex"),
            issued_at_unix_ms: UnixMillis::new(issued_at)
                .context("invalid Route v2 recovery issue time")?,
            expires_at_unix_ms: UnixMillis::new(expires_at)
                .context("invalid Route v2 recovery expiry time")?,
            command: authority_command,
        };
        let operator = Ed25519RequestSigner::from_pkcs8_v2_pem(
            source.operator_trust.credentials[0].credential_id.clone(),
            &source.operator_private_key,
        )
        .map_err(|_| anyhow!("Route rotation operator key is not strict PKCS#8 v2"))?;
        let proof = sign_route_v2_signing_command(&payload, &operator)
            .map_err(|error| anyhow!("sign fresh Route v2 recovery command: {error}"))?;
        let signed = SignedRouteV2SigningCommand {
            payload,
            proofs: vec![proof],
        };
        let bytes = encode_signed_route_v2_signing_command(&signed)
            .map_err(|error| anyhow!("encode fresh Route v2 recovery command: {error}"))?;
        publish_user_file_idempotent(output, &bytes, 0o600)?;
        bytes
    };

    let signed = decode_signed_route_v2_signing_command(&signed_bytes)
        .map_err(|error| anyhow!("decode durable Route v2 recovery command: {error}"))?;
    verify_signed_route_v2_signing_command(
        &source.operator_trust,
        &source.operator_trust.release_commit_sha,
        &signed,
    )
    .map_err(|error| anyhow!("verify durable Route v2 recovery command: {error}"))?;
    anyhow::ensure!(
        signed.payload.command
            == decode_authority_command(entry.exact_authority_command_json.as_bytes())?
            && signed
                .payload
                .expires_at_unix_ms
                .get()
                .checked_sub(signed.payload.issued_at_unix_ms.get())
                == Some(ROTATION_RECOVERY_COMMAND_LIFETIME_MILLIS),
        "durable Route v2 recovery command does not match the prepared phase"
    );
    let payload_bytes = encode_route_v2_signing_command_payload(&signed.payload)
        .map_err(|error| anyhow!("encode durable Route v2 recovery payload: {error}"))?;
    report(
        cli,
        &RotationRecoveryPhaseSigningReceipt {
            version: 1,
            case_id: ROTATION_RECOVERY_CASE_ID.to_owned(),
            qualification_run_id: bundle.qualification_run_id,
            phase: phase.to_owned(),
            signer_revision: entry.signer_revision,
            ring_version: entry.ring_version,
            authority_id: source.operator_trust.authority_id.to_string(),
            route_deployment_id: source.operator_trust.route_deployment_id.to_string(),
            release_commit_sha: source.operator_trust.release_commit_sha,
            command_id: signed.payload.command_id.to_string(),
            issued_at_unix_ms: signed.payload.issued_at_unix_ms.get(),
            expires_at_unix_ms: signed.payload.expires_at_unix_ms.get(),
            exact_authority_command_sha256: entry.exact_authority_command_sha256.clone(),
            exact_payload_sha256: sha256(&payload_bytes),
            exact_signed_command_sha256: sha256(&signed_bytes),
            pending_command_path: output.display().to_string(),
        },
    )
}

fn verify_rotation_current(
    cli: &Cli,
    input: &Path,
    recovery_path: &Path,
    signer_revision: u64,
    discovery_path: &Path,
    output: &Path,
) -> Result<()> {
    anyhow::ensure!(
        ROTATION_RECOVERY_REVISIONS.contains(&signer_revision),
        "current-binding signer revision is outside the prepared recovery lineage"
    );
    let candidate = Candidate::open_existing(input, 0)?;
    let source = load_rotation_recovery_source(&candidate)?;
    let recovery = RotationRecoveryOutput::open_existing(recovery_path, 0)?;
    let bundle_bytes = read_file(
        &recovery.commands,
        "route-v2-rotation-command-bundle.v1.json",
        0o600,
        recovery.expected_uid,
        MAX_ROTATION_RECOVERY_BUNDLE_BYTES,
    )?;
    let bundle: RotationRecoveryCommandBundle = serde_json::from_slice(&bundle_bytes)
        .context("decode Route v2 recovery bundle for current verification")?;
    verify_rotation_recovery(&recovery, &source, &bundle.qualification_run_id)?;

    let control_directory = recovery
        .control
        .get(&signer_revision)
        .context("prepared recovery has no requested Control revision")?;
    let reference_bytes = read_file(
        control_directory,
        "signer.v1.json",
        0o644,
        recovery.expected_uid,
        MAX_JSON_BYTES,
    )?;
    let expected = decode_route_grant_v2_signer_reference(&reference_bytes)
        .map_err(|error| anyhow!("decode expected recovery signer: {error:?}"))?;
    let discovery_bytes = read_user_file(
        discovery_path,
        ROUTE_V2_SIGNING_CURRENT_RESPONSE_MAX_WIRE_BYTES,
        0o600,
        true,
    )?;
    let discovered = decode_route_v2_signing_authority_current(&discovery_bytes)
        .map_err(|error| anyhow!("decode canonical Route v2 current discovery: {error}"))?;
    let (expected_state, expected_active_kid) = match &expected.signer {
        RouteGrantV2SignerSelection::Active { active_kid, .. } => {
            (RouteV2LoadedSignerState::Active, Some(active_kid.clone()))
        }
        RouteGrantV2SignerSelection::Disabled => (RouteV2LoadedSignerState::Disabled, None),
    };
    anyhow::ensure!(
        discovered.authority_id == source.operator_trust.authority_id
            && discovered.route_deployment_id == source.operator_trust.route_deployment_id
            && discovered.release_commit_sha == source.operator_trust.release_commit_sha
            && discovered.rotation_operator_trust_sha256
                == source
                    .operator_trust
                    .exact_digest()
                    .map_err(|error| anyhow!("digest Route v2 operator trust: {error}"))?
            && discovered.loaded_signer_revision == expected.signer_revision
            && discovered.loaded_signer_reference_sha256
                == Sha256Digest::from_bytes(Sha256::digest(&reference_bytes).into())
            && discovered.loaded_signer_state == expected_state
            && discovered.loaded_active_kid == expected_active_kid
            && discovered.loaded_public_key_ring_version == expected.public_key_ring_version
            && discovered.loaded_public_key_ring_digest == expected.public_key_ring_digest
            && discovered.database_current
            && discovered.process_ready == (expected_state == RouteV2LoadedSignerState::Active),
        "Control process does not prove the exact PostgreSQL-current recovery binding"
    );

    let receipt = RotationCurrentVerificationReceipt {
        version: 1,
        case_id: ROTATION_RECOVERY_CASE_ID.to_owned(),
        qualification_run_id: bundle.qualification_run_id,
        source_commit_sha: discovered.release_commit_sha,
        authority_id: discovered.authority_id.to_string(),
        route_deployment_id: discovered.route_deployment_id.to_string(),
        rotation_operator_trust_sha256: discovered.rotation_operator_trust_sha256.to_string(),
        signer_revision: discovered.loaded_signer_revision.get(),
        signer_reference_sha256: discovered.loaded_signer_reference_sha256.to_string(),
        signer_state: match discovered.loaded_signer_state {
            RouteV2LoadedSignerState::Active => "active",
            RouteV2LoadedSignerState::Disabled => "disabled",
        }
        .to_owned(),
        active_kid: discovered.loaded_active_kid.map(|kid| kid.to_string()),
        public_key_ring_version: discovered.loaded_public_key_ring_version.get(),
        public_key_ring_digest: discovered.loaded_public_key_ring_digest.to_string(),
        database_current: discovered.database_current,
        process_ready: discovered.process_ready,
        exact_discovery_sha256: sha256(&discovery_bytes),
    };
    let receipt_bytes = serde_json::to_vec(&receipt)
        .context("encode Route v2 current-binding verification receipt")?;
    publish_user_file_idempotent(output, &receipt_bytes, 0o600)?;
    report(cli, &receipt)
}

fn load_staged_rotation_contract(
    trust_path: &Path,
    bundle_path: &Path,
) -> Result<(RouteV2RotationOperatorTrust, RotationRecoveryCommandBundle)> {
    let (trust, trust_bytes) = load_staged_rotation_trust(trust_path)?;
    let bundle_bytes =
        read_user_file(bundle_path, MAX_ROTATION_RECOVERY_BUNDLE_BYTES, 0o600, true)?;
    let bundle: RotationRecoveryCommandBundle = serde_json::from_slice(&bundle_bytes)
        .context("decode staged Route rotation command bundle")?;
    anyhow::ensure!(
        serde_json::to_vec(&bundle)? == bundle_bytes
            && bundle.version == 1
            && bundle.case_id == ROTATION_RECOVERY_CASE_ID
            && bundle.source_commit_sha == trust.release_commit_sha
            && bundle.route_deployment_id == trust.route_deployment_id.as_str()
            && bundle.rotation_operator_authority_id == trust.authority_id.as_str()
            && bundle.rotation_operator_trust_sha256 == sha256(&trust_bytes)
            && bundle.commands.len() == ROTATION_RECOVERY_PHASES.len()
            && bundle.control_rollouts.len() == ROTATION_RECOVERY_PHASES.len()
            && bundle
                .commands
                .iter()
                .zip(ROTATION_RECOVERY_PHASES)
                .all(|(entry, phase)| entry.phase == phase),
        "staged Route rotation bundle does not bind the fixed trust and closed phase set"
    );
    validate_rotation_recovery_run_id(&bundle.qualification_run_id)?;
    validate_staged_rotation_lineage(&bundle)?;
    Ok((trust, bundle))
}

fn load_staged_rotation_trust(
    trust_path: &Path,
) -> Result<(RouteV2RotationOperatorTrust, Vec<u8>)> {
    // Only the fixed release artifact is public 0644. Every runner copy is a
    // root-only 0600 staged input; arbitrary public copies are not authority.
    let trust_bytes = read_staged_rotation_trust_file(trust_path)?;
    let trust = decode_route_v2_rotation_operator_trust(&trust_bytes)
        .map_err(|error| anyhow!("decode staged Route rotation trust: {error}"))?;
    Ok((trust, trust_bytes))
}

fn read_staged_rotation_trust_file(path: &Path) -> Result<Vec<u8>> {
    read_rotation_trust_file_as(path, rotation_trust_representation(path), 0, 0)
}

fn rotation_trust_representation(path: &Path) -> RotationTrustRepresentation {
    if path == Path::new(INSTALLED_ROTATION_OPERATOR_TRUST_PATH) {
        RotationTrustRepresentation::InstalledRelease
    } else {
        RotationTrustRepresentation::RunnerStaged
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RotationTrustRepresentation {
    InstalledRelease,
    RunnerStaged,
}

impl RotationTrustRepresentation {
    fn exact_mode(self) -> u32 {
        match self {
            Self::InstalledRelease => 0o644,
            Self::RunnerStaged => 0o600,
        }
    }
}

fn read_rotation_trust_file_as(
    path: &Path,
    representation: RotationTrustRepresentation,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        path.is_absolute(),
        "staged Route rotation trust path must be absolute"
    );
    let parent = open_directory_nofollow(
        path.parent()
            .context("staged Route rotation trust path has no parent")?,
    )?;
    let parent_metadata = parent.metadata()?;
    anyhow::ensure!(
        parent_metadata.file_type().is_dir()
            && parent_metadata.uid() == expected_uid
            && parent_metadata.gid() == expected_gid
            && parent_metadata.mode() & 0o022 == 0,
        "staged Route rotation trust parent is not owner-controlled"
    );
    let name = c_os_name(
        path.file_name()
            .context("staged Route rotation trust path has no basename")?,
    )?;
    let file = open_file_at(&parent, &name, libc::O_RDONLY, 0)
        .with_context(|| format!("open staged Route rotation trust {}", path.display()))?;
    let metadata = file.metadata()?;
    validate_rotation_trust_metadata(&metadata, representation, expected_uid, expected_gid)?;
    read_stable_file(&file, MAX_JSON_BYTES)
}

fn validate_rotation_trust_metadata(
    metadata: &std::fs::Metadata,
    representation: RotationTrustRepresentation,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == expected_uid
            && metadata.gid() == expected_gid
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == representation.exact_mode(),
        "staged Route rotation trust has the wrong type, owner, link count, or mode"
    );
    Ok(())
}

fn validate_staged_rotation_lineage(bundle: &RotationRecoveryCommandBundle) -> Result<()> {
    let mut previous_reference: Option<RouteGrantV2SignerReference> = None;
    let mut previous_ring: Option<RouteGrantV2PublicKeyRingArtifact> = None;
    let mut normal_secret_reference_id: Option<Id> = None;
    let mut recovery_secret_reference_id: Option<Id> = None;
    let mut normal_kid = None;
    let mut secret_name_prefix = None;

    for (index, (((phase, revision), command_entry), rollout)) in ROTATION_RECOVERY_PHASES
        .into_iter()
        .zip(ROTATION_RECOVERY_REVISIONS)
        .zip(&bundle.commands)
        .zip(&bundle.control_rollouts)
        .enumerate()
    {
        anyhow::ensure!(
            command_entry.phase == phase
                && command_entry.signer_revision == revision
                && command_entry.exact_authority_command_sha256
                    == sha256(command_entry.exact_authority_command_json.as_bytes()),
            "staged Route rotation command entry {phase} is not exact"
        );
        let command =
            decode_authority_command(command_entry.exact_authority_command_json.as_bytes())?;
        anyhow::ensure!(
            command.successor.signer_revision.get() == revision
                && command.successor.deployment_id.as_str() == bundle.route_deployment_id,
            "staged Route rotation command {phase} has the wrong successor coordinate"
        );
        if let Some(previous) = &previous_reference {
            anyhow::ensure!(
                command.successor.expected_previous
                    == Some(RouteGrantV2SignerExpectedPrevious {
                        signer_revision: previous.signer_revision,
                        signer_reference_sha256: previous.digest().map_err(|error| anyhow!(
                            "digest staged Route rotation predecessor: {error:?}"
                        ))?,
                    }),
                "staged Route rotation command {phase} is not the adjacent signer successor"
            );
        } else {
            anyhow::ensure!(
                command.successor.expected_previous.is_some(),
                "staged Route rotation first command omits its installed predecessor"
            );
        }

        let ring = match &command.kind {
            RouteGrantV2SigningAuthorityCommandKind::PublishOverlap { successor_ring, .. }
            | RouteGrantV2SigningAuthorityCommandKind::PublishNewOnly { successor_ring }
            | RouteGrantV2SigningAuthorityCommandKind::Disable { successor_ring } => {
                successor_ring.clone()
            }
            RouteGrantV2SigningAuthorityCommandKind::SwitchActive
            | RouteGrantV2SigningAuthorityCommandKind::Retire
            | RouteGrantV2SigningAuthorityCommandKind::Activate => previous_ring
                .clone()
                .context("staged Route rotation command requires a predecessor ring")?,
        };
        command
            .successor
            .validate_ring(&ring)
            .map_err(|error| anyhow!("bind staged Route rotation command {phase}: {error:?}"))?;
        anyhow::ensure!(
            command_entry.ring_version == ring.ring_version.get(),
            "staged Route rotation command {phase} has the wrong ring version"
        );

        match (phase, &command.kind) {
            (
                "publish_overlap",
                RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                    successor_ring,
                    new_secret_reference_id,
                },
            ) => {
                let RouteGrantV2SignerSelection::Active { active_kid, .. } =
                    &command.successor.signer
                else {
                    bail!("staged normal overlap does not retain an active predecessor")
                };
                let added = successor_ring
                    .keys
                    .iter()
                    .filter(|entry| &entry.kid != active_kid)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    successor_ring.keys.len() == 2
                        && successor_ring.key(active_kid).is_some()
                        && added.len() == 1,
                    "staged normal overlap does not carry one retained and one fresh key"
                );
                normal_secret_reference_id = Some(new_secret_reference_id.clone());
                normal_kid = Some(added[0].kid.clone());
            }
            ("switch_active", RouteGrantV2SigningAuthorityCommandKind::SwitchActive) => {
                let RouteGrantV2SignerSelection::Active {
                    active_kid,
                    secret_reference_id,
                } = &command.successor.signer
                else {
                    bail!("staged normal switch does not select an active signer")
                };
                anyhow::ensure!(
                    Some(secret_reference_id) == normal_secret_reference_id.as_ref()
                        && normal_kid.as_ref() == Some(active_kid),
                    "staged normal switch does not select its prepared successor"
                );
            }
            (
                "publish_new_only",
                RouteGrantV2SigningAuthorityCommandKind::PublishNewOnly { successor_ring },
            ) => {
                anyhow::ensure!(
                    successor_ring.keys.len() == 1
                        && normal_kid
                            .as_ref()
                            .is_some_and(|kid| successor_ring.key(kid).is_some()),
                    "staged new-only phase does not retain only the normal successor"
                );
            }
            ("retire", RouteGrantV2SigningAuthorityCommandKind::Retire) => {}
            ("disable", RouteGrantV2SigningAuthorityCommandKind::Disable { successor_ring }) => {
                anyhow::ensure!(
                    successor_ring.keys.is_empty()
                        && command.successor.signer == RouteGrantV2SignerSelection::Disabled,
                    "staged disable phase is not an empty disabled successor"
                )
            }
            (
                "publish_recovery",
                RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                    successor_ring,
                    new_secret_reference_id,
                },
            ) => {
                anyhow::ensure!(
                    previous_reference.as_ref().is_some_and(|reference| {
                        reference.signer == RouteGrantV2SignerSelection::Disabled
                    }) && command.successor.signer == RouteGrantV2SignerSelection::Disabled
                        && successor_ring.keys.len() == 1
                        && normal_kid
                            .as_ref()
                            .is_some_and(|kid| successor_ring.key(kid).is_none())
                        && normal_secret_reference_id.as_ref() != Some(new_secret_reference_id),
                    "staged recovery publication reuses or bypasses the disabled lineage"
                );
                recovery_secret_reference_id = Some(new_secret_reference_id.clone());
            }
            ("activate", RouteGrantV2SigningAuthorityCommandKind::Activate) => {
                let RouteGrantV2SignerSelection::Active {
                    active_kid,
                    secret_reference_id,
                } = &command.successor.signer
                else {
                    bail!("staged recovery activation does not select an active signer")
                };
                anyhow::ensure!(
                    Some(secret_reference_id) == recovery_secret_reference_id.as_ref()
                        && ring.keys.len() == 1
                        && ring.key(active_kid).is_some(),
                    "staged activation does not select only the fresh recovery signer"
                );
            }
            _ => bail!("staged Route rotation phase {phase} has the wrong typed command"),
        }

        let secret_suffix = format!("-r{revision}");
        let prefix = rollout
            .secret_name
            .strip_suffix(&secret_suffix)
            .context("staged Control rollout Secret has the wrong revision suffix")?;
        if let Some(expected) = &secret_name_prefix {
            anyhow::ensure!(
                prefix == expected,
                "staged Control rollout changes its immutable Secret prefix"
            );
        } else {
            anyhow::ensure!(!prefix.is_empty(), "staged Control Secret prefix is empty");
            secret_name_prefix = Some(prefix.to_owned());
        }
        let reference_digest = command
            .successor
            .digest()
            .map_err(|error| anyhow!("digest staged Route rotation successor: {error:?}"))?;
        let ring_digest = ring
            .digest()
            .map_err(|error| anyhow!("digest staged Route rotation ring: {error:?}"))?;
        anyhow::ensure!(
            rollout.signer_revision == revision
                && rollout.signer_reference_sha256 == reference_digest.to_string()
                && rollout.public_key_ring_digest == ring_digest.to_string()
                && is_canonical_sha256(&rollout.secret_manifest_sha256),
            "staged Control rollout r{revision} differs from its authority command"
        );
        if index > 0 {
            let prior_ring = previous_ring
                .as_ref()
                .context("staged Route rotation predecessor ring disappeared")?;
            match phase {
                "publish_new_only" | "disable" | "publish_recovery" => anyhow::ensure!(
                    ring_is_successor_of(prior_ring, &ring)?,
                    "staged Route rotation ring for {phase} is not adjacent"
                ),
                _ => anyhow::ensure!(
                    &ring == prior_ring,
                    "staged Route rotation phase {phase} unexpectedly changes the ring"
                ),
            }
        }
        previous_reference = Some(command.successor);
        previous_ring = Some(ring);
    }
    Ok(())
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sign_prepared_rotation_phase(
    cli: &Cli,
    trust_path: &Path,
    operator_private_key_path: &Path,
    bundle_path: &Path,
    phase: &str,
    output: &Path,
) -> Result<()> {
    let (trust, bundle) = load_staged_rotation_contract(trust_path, bundle_path)?;
    let entry = bundle
        .commands
        .iter()
        .find(|entry| entry.phase == phase)
        .context("staged Route rotation bundle has no requested phase")?;
    anyhow::ensure!(
        entry.exact_authority_command_sha256
            == sha256(entry.exact_authority_command_json.as_bytes()),
        "staged Route rotation authority command digest differs"
    );
    let authority_command =
        decode_authority_command(entry.exact_authority_command_json.as_bytes())?;
    let signed_bytes = if output.exists() {
        read_user_file(output, ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES, 0o600, true)?
    } else {
        let mut operator_private_key = read_user_file(
            operator_private_key_path,
            MAX_PRIVATE_KEY_BYTES,
            0o600,
            true,
        )?;
        let signed_result = (|| {
            anyhow::ensure!(
                trust.threshold == 1 && trust.credentials.len() == 1,
                "staged recovery signer requires exact one-of-one operator trust"
            );
            let operator = Ed25519RequestSigner::from_pkcs8_v2_pem(
                trust.credentials[0].credential_id.clone(),
                &operator_private_key,
            )
            .map_err(|_| anyhow!("staged Route rotation operator key is not strict PKCS#8 v2"))?;
            anyhow::ensure!(
                Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(operator.public_key_spki_der()))
                    .as_ref()
                    == Some(&trust.credentials[0].public_key_spki),
                "staged Route rotation operator key does not match fixed trust"
            );
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system time predates the Unix epoch")?
                .as_millis();
            let now = u64::try_from(now).context("system time exceeds Route v2 wire range")?;
            let issued_at = now.saturating_sub(5_000);
            let expires_at = issued_at
                .checked_add(ROTATION_RECOVERY_COMMAND_LIFETIME_MILLIS)
                .context("Route v2 recovery command expiry overflow")?;
            let payload = RouteV2SigningCommandPayload {
                version: ContractVersion::V1,
                authority_id: trust.authority_id.clone(),
                release_commit_sha: trust.release_commit_sha.clone(),
                command_id: RandomId128::new(random_hex(16)?)
                    .expect("generated Route v2 command ID is canonical 128-bit hex"),
                issued_at_unix_ms: UnixMillis::new(issued_at)
                    .context("invalid Route v2 recovery issue time")?,
                expires_at_unix_ms: UnixMillis::new(expires_at)
                    .context("invalid Route v2 recovery expiry time")?,
                command: authority_command,
            };
            let proof = sign_route_v2_signing_command(&payload, &operator)
                .map_err(|error| anyhow!("sign staged Route v2 recovery command: {error}"))?;
            encode_signed_route_v2_signing_command(&SignedRouteV2SigningCommand {
                payload,
                proofs: vec![proof],
            })
            .map_err(|error| anyhow!("encode staged Route v2 recovery command: {error}"))
        })();
        operator_private_key.fill(0);
        let bytes = signed_result?;
        publish_user_file_idempotent(output, &bytes, 0o600)?;
        bytes
    };
    let signed = decode_signed_route_v2_signing_command(&signed_bytes)
        .map_err(|error| anyhow!("decode durable staged Route v2 command: {error}"))?;
    verify_signed_route_v2_signing_command(&trust, &trust.release_commit_sha, &signed)
        .map_err(|error| anyhow!("verify durable staged Route v2 command: {error}"))?;
    anyhow::ensure!(
        signed.payload.command
            == decode_authority_command(entry.exact_authority_command_json.as_bytes())?
            && signed
                .payload
                .expires_at_unix_ms
                .get()
                .checked_sub(signed.payload.issued_at_unix_ms.get())
                == Some(ROTATION_RECOVERY_COMMAND_LIFETIME_MILLIS),
        "durable staged Route v2 command differs from the prepared phase"
    );
    let payload_bytes = encode_route_v2_signing_command_payload(&signed.payload)
        .map_err(|error| anyhow!("encode staged Route v2 recovery payload: {error}"))?;
    report(
        cli,
        &RotationRecoveryPhaseSigningReceipt {
            version: 1,
            case_id: ROTATION_RECOVERY_CASE_ID.to_owned(),
            qualification_run_id: bundle.qualification_run_id,
            phase: phase.to_owned(),
            signer_revision: entry.signer_revision,
            ring_version: entry.ring_version,
            authority_id: trust.authority_id.to_string(),
            route_deployment_id: trust.route_deployment_id.to_string(),
            release_commit_sha: trust.release_commit_sha,
            command_id: signed.payload.command_id.to_string(),
            issued_at_unix_ms: signed.payload.issued_at_unix_ms.get(),
            expires_at_unix_ms: signed.payload.expires_at_unix_ms.get(),
            exact_authority_command_sha256: entry.exact_authority_command_sha256.clone(),
            exact_payload_sha256: sha256(&payload_bytes),
            exact_signed_command_sha256: sha256(&signed_bytes),
            pending_command_path: output.display().to_string(),
        },
    )
}

fn verify_prepared_rotation_current(
    cli: &Cli,
    trust_path: &Path,
    bundle_path: &Path,
    signer_revision: u64,
    discovery_path: &Path,
    output: &Path,
) -> Result<()> {
    let (trust, bundle) = load_staged_rotation_contract(trust_path, bundle_path)?;
    let entry = bundle
        .commands
        .iter()
        .find(|entry| entry.signer_revision == signer_revision)
        .context("staged Route rotation bundle has no requested signer revision")?;
    let command = decode_authority_command(entry.exact_authority_command_json.as_bytes())?;
    let expected = command.successor;
    let reference_bytes = encode_route_grant_v2_signer_reference(&expected)
        .map_err(|error| anyhow!("encode staged expected signer reference: {error:?}"))?;
    let discovery_bytes = read_user_file(
        discovery_path,
        ROUTE_V2_SIGNING_CURRENT_RESPONSE_MAX_WIRE_BYTES,
        0o600,
        true,
    )?;
    let discovered = decode_route_v2_signing_authority_current(&discovery_bytes)
        .map_err(|error| anyhow!("decode staged current-binding discovery: {error}"))?;
    let (expected_state, expected_active_kid) = match &expected.signer {
        RouteGrantV2SignerSelection::Active { active_kid, .. } => {
            (RouteV2LoadedSignerState::Active, Some(active_kid.clone()))
        }
        RouteGrantV2SignerSelection::Disabled => (RouteV2LoadedSignerState::Disabled, None),
    };
    anyhow::ensure!(
        discovered.authority_id == trust.authority_id
            && discovered.route_deployment_id == trust.route_deployment_id
            && discovered.release_commit_sha == trust.release_commit_sha
            && discovered.rotation_operator_trust_sha256
                == trust
                    .exact_digest()
                    .map_err(|error| anyhow!("digest staged Route rotation trust: {error}"))?
            && discovered.loaded_signer_revision == expected.signer_revision
            && discovered.loaded_signer_reference_sha256
                == Sha256Digest::from_bytes(Sha256::digest(&reference_bytes).into())
            && discovered.loaded_signer_state == expected_state
            && discovered.loaded_active_kid == expected_active_kid
            && discovered.loaded_public_key_ring_version == expected.public_key_ring_version
            && discovered.loaded_public_key_ring_digest == expected.public_key_ring_digest
            && discovered.database_current
            && discovered.process_ready == (expected_state == RouteV2LoadedSignerState::Active),
        "staged Control discovery does not prove exact PostgreSQL-current process binding"
    );
    let receipt = RotationCurrentVerificationReceipt {
        version: 1,
        case_id: ROTATION_RECOVERY_CASE_ID.to_owned(),
        qualification_run_id: bundle.qualification_run_id,
        source_commit_sha: discovered.release_commit_sha,
        authority_id: discovered.authority_id.to_string(),
        route_deployment_id: discovered.route_deployment_id.to_string(),
        rotation_operator_trust_sha256: discovered.rotation_operator_trust_sha256.to_string(),
        signer_revision: discovered.loaded_signer_revision.get(),
        signer_reference_sha256: discovered.loaded_signer_reference_sha256.to_string(),
        signer_state: match discovered.loaded_signer_state {
            RouteV2LoadedSignerState::Active => "active",
            RouteV2LoadedSignerState::Disabled => "disabled",
        }
        .to_owned(),
        active_kid: discovered.loaded_active_kid.map(|kid| kid.to_string()),
        public_key_ring_version: discovered.loaded_public_key_ring_version.get(),
        public_key_ring_digest: discovered.loaded_public_key_ring_digest.to_string(),
        database_current: discovered.database_current,
        process_ready: discovered.process_ready,
        exact_discovery_sha256: sha256(&discovery_bytes),
    };
    let receipt_bytes = serde_json::to_vec(&receipt)
        .context("encode staged Route v2 current verification receipt")?;
    publish_user_file_idempotent(output, &receipt_bytes, 0o600)?;
    report(cli, &receipt)
}

fn sign_control_rollout_apply_receipt(
    cli: &Cli,
    trust_path: &Path,
    operator_private_key_paths: &[PathBuf],
    payload_path: &Path,
    output: &Path,
) -> Result<()> {
    let (trust, _) = load_staged_rotation_trust(trust_path)?;
    anyhow::ensure!(
        !operator_private_key_paths.is_empty()
            && operator_private_key_paths.len() <= trust.credentials.len(),
        "apply receipt signer key count is outside the fixed operator trust"
    );
    let payload_bytes = read_user_file(
        payload_path,
        ROUTE_V2_CONTROL_ROLLOUT_APPLY_RECEIPT_MAX_WIRE_BYTES,
        0o600,
        true,
    )?;
    let payload = decode_route_v2_control_rollout_apply_receipt_payload(&payload_bytes)
        .map_err(|error| anyhow!("decode canonical Route v2 apply receipt payload: {error}"))?;

    let signed_bytes = if output.exists() {
        read_user_file(
            output,
            ROUTE_V2_CONTROL_ROLLOUT_APPLY_RECEIPT_MAX_WIRE_BYTES,
            0o600,
            true,
        )?
    } else {
        let mut proofs = Vec::with_capacity(operator_private_key_paths.len());
        let mut credential_ids = BTreeSet::new();
        for private_key_path in operator_private_key_paths {
            let mut private_key =
                read_user_file(private_key_path, MAX_PRIVATE_KEY_BYTES, 0o600, true)?;
            let proof_result = (|| {
                let matching = trust.credentials.iter().find_map(|credential| {
                    let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(
                        credential.credential_id.clone(),
                        &private_key,
                    )
                    .ok()?;
                    (Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.public_key_spki_der()))
                        .as_ref()
                        == Some(&credential.public_key_spki))
                    .then_some(signer)
                });
                let signer = matching.context(
                    "apply receipt operator private key is not strict PKCS#8 v2 bound by trust",
                )?;
                anyhow::ensure!(
                    credential_ids.insert(signer.credential_id().clone()),
                    "apply receipt repeats an operator credential"
                );
                sign_route_v2_control_rollout_apply_receipt(&payload, &signer)
                    .map_err(|error| anyhow!("sign Route v2 apply receipt: {error}"))
            })();
            private_key.fill(0);
            proofs.push(proof_result?);
        }
        proofs.sort_by(|left, right| left.credential_id.cmp(&right.credential_id));
        anyhow::ensure!(
            proofs.len() >= usize::from(trust.threshold),
            "apply receipt does not satisfy the operator trust threshold"
        );
        let signed = SignedRouteV2ControlRolloutApplyReceipt {
            payload: payload.clone(),
            proofs,
        };
        verify_signed_route_v2_control_rollout_apply_receipt(
            &trust,
            &trust.release_commit_sha,
            &signed,
        )
        .map_err(|error| anyhow!("verify freshly signed Route v2 apply receipt: {error}"))?;
        let bytes = encode_signed_route_v2_control_rollout_apply_receipt(&signed)
            .map_err(|error| anyhow!("encode signed Route v2 apply receipt: {error}"))?;
        publish_user_file_idempotent(output, &bytes, 0o600)?;
        bytes
    };
    let signed = decode_signed_route_v2_control_rollout_apply_receipt(&signed_bytes)
        .map_err(|error| anyhow!("decode durable Route v2 apply receipt: {error}"))?;
    verify_signed_route_v2_control_rollout_apply_receipt(
        &trust,
        &trust.release_commit_sha,
        &signed,
    )
    .map_err(|error| anyhow!("verify durable Route v2 apply receipt: {error}"))?;
    anyhow::ensure!(
        signed.payload == payload,
        "durable Route v2 apply receipt differs from the fresh discovered payload"
    );
    report(
        cli,
        &ControlRolloutApplySigningReceipt {
            version: 1,
            case_id: payload.case_id,
            qualification_run_id: payload.qualification_run_id,
            source_commit_sha: payload.source_commit_sha,
            phase: payload.phase,
            signer_revision: payload.signer_revision.get(),
            authority_id: payload.authority_id.to_string(),
            route_deployment_id: payload.route_deployment_id.to_string(),
            rotation_operator_trust_sha256: payload.rotation_operator_trust_sha256.to_string(),
            proof_credential_ids: signed
                .proofs
                .into_iter()
                .map(|proof| proof.credential_id.to_string())
                .collect(),
            exact_payload_sha256: sha256(&payload_bytes),
            exact_signed_receipt_sha256: sha256(&signed_bytes),
            terminal_marker: payload.terminal_marker,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_control_rollout_apply_receipt(
    cli: &Cli,
    trust_path: &Path,
    bundle_path: &Path,
    phase: &str,
    qualification_catalog_sha256: &str,
    saved_plan_sha256: &str,
    receipt_path: &Path,
    output: &Path,
) -> Result<()> {
    let (trust, bundle) = load_staged_rotation_contract(trust_path, bundle_path)?;
    let entry = bundle
        .commands
        .iter()
        .find(|entry| entry.phase == phase)
        .context("staged Route rotation bundle has no requested apply phase")?;
    let rollout = bundle
        .control_rollouts
        .iter()
        .find(|rollout| rollout.signer_revision == entry.signer_revision)
        .context("staged Route rotation bundle has no requested rollout")?;
    let command = decode_authority_command(entry.exact_authority_command_json.as_bytes())?;
    let expected_reference = command.successor;
    let (expected_state, expected_active_kid) = match &expected_reference.signer {
        RouteGrantV2SignerSelection::Active { active_kid, .. } => {
            (RouteV2LoadedSignerState::Active, Some(active_kid.clone()))
        }
        RouteGrantV2SignerSelection::Disabled => (RouteV2LoadedSignerState::Disabled, None),
    };
    let expected_catalog = Sha256Digest::new(qualification_catalog_sha256.to_owned())
        .context("invalid qualification catalog digest")?;
    let expected_plan = Sha256Digest::new(saved_plan_sha256.to_owned())
        .context("invalid reviewed saved-plan digest")?;
    let receipt_bytes = read_user_file(
        receipt_path,
        ROUTE_V2_CONTROL_ROLLOUT_APPLY_RECEIPT_MAX_WIRE_BYTES,
        0o600,
        true,
    )?;
    let signed = decode_signed_route_v2_control_rollout_apply_receipt(&receipt_bytes)
        .map_err(|error| anyhow!("decode canonical signed Route v2 apply receipt: {error}"))?;
    verify_signed_route_v2_control_rollout_apply_receipt(
        &trust,
        &trust.release_commit_sha,
        &signed,
    )
    .map_err(|error| anyhow!("verify signed Route v2 apply receipt: {error}"))?;
    let payload = &signed.payload;
    anyhow::ensure!(
        payload.qualification_run_id == bundle.qualification_run_id
            && payload.qualification_catalog_sha256 == expected_catalog
            && payload.phase == phase
            && payload.signer_revision.get() == entry.signer_revision
            && payload.saved_plan_sha256 == expected_plan
            && payload.successor_secret_name == rollout.secret_name
            && payload.successor_secret_manifest_sha256.to_string()
                == rollout.secret_manifest_sha256
            && payload.successor_signer_reference_sha256.to_string()
                == rollout.signer_reference_sha256
            && payload.successor_signer_state == expected_state
            && payload.successor_active_kid == expected_active_kid
            && payload.successor_public_key_ring_version
                == expected_reference.public_key_ring_version
            && payload.successor_public_key_ring_digest
                == expected_reference.public_key_ring_digest,
        "signed Route v2 apply receipt differs from the exact next frozen phase"
    );
    let verification = ControlRolloutApplyVerificationReceipt {
        version: 1,
        case_id: payload.case_id.clone(),
        qualification_run_id: payload.qualification_run_id.clone(),
        source_commit_sha: payload.source_commit_sha.clone(),
        qualification_catalog_sha256: payload.qualification_catalog_sha256.to_string(),
        phase: payload.phase.clone(),
        signer_revision: payload.signer_revision.get(),
        authority_id: payload.authority_id.to_string(),
        route_deployment_id: payload.route_deployment_id.to_string(),
        rotation_operator_trust_sha256: payload.rotation_operator_trust_sha256.to_string(),
        saved_plan_sha256: payload.saved_plan_sha256.to_string(),
        terraform_show_json_sha256: payload.terraform_show_json_sha256.to_string(),
        plan_validation_receipt_sha256: payload.plan_validation_receipt_sha256.to_string(),
        terraform_executable_sha256: payload.terraform_executable_sha256.to_string(),
        deployment_operator_executable_sha256: payload
            .deployment_operator_executable_sha256
            .to_string(),
        saved_plan_validator_executable_sha256: payload
            .saved_plan_validator_executable_sha256
            .to_string(),
        receipt_signer_executable_sha256: payload.receipt_signer_executable_sha256.to_string(),
        successor_secret_name: payload.successor_secret_name.clone(),
        successor_secret_manifest_sha256: payload.successor_secret_manifest_sha256.to_string(),
        successor_signer_reference_sha256: payload.successor_signer_reference_sha256.to_string(),
        successor_signer_state: match payload.successor_signer_state {
            RouteV2LoadedSignerState::Active => "active",
            RouteV2LoadedSignerState::Disabled => "disabled",
        }
        .to_owned(),
        successor_active_kid: payload
            .successor_active_kid
            .as_ref()
            .map(ToString::to_string),
        successor_public_key_ring_version: payload.successor_public_key_ring_version.get(),
        successor_public_key_ring_digest: payload.successor_public_key_ring_digest.to_string(),
        apply_started_at_unix_ms: payload.apply_started_at_unix_ms.get(),
        apply_completed_at_unix_ms: payload.apply_completed_at_unix_ms.get(),
        apply_outcome: match payload.apply_outcome {
            RouteV2ControlRolloutApplyOutcome::Succeeded => "succeeded",
            RouteV2ControlRolloutApplyOutcome::AmbiguousResolvedCurrent => {
                "ambiguous_resolved_current"
            }
        }
        .to_owned(),
        terraform_apply_stdout_sha256: payload.terraform_apply_stdout_sha256.to_string(),
        terraform_apply_stderr_sha256: payload.terraform_apply_stderr_sha256.to_string(),
        postcondition_discovery_sha256: payload.postcondition_discovery_sha256.to_string(),
        exact_signed_receipt_sha256: sha256(&receipt_bytes),
        terminal_marker: payload.terminal_marker.clone(),
    };
    let verification_bytes =
        serde_json::to_vec(&verification).context("encode Route v2 apply receipt verification")?;
    publish_user_file_idempotent(output, &verification_bytes, 0o600)?;
    report(cli, &verification)
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
    validate_kubernetes_secret_name_at_revision(value, 1)
}

fn validate_kubernetes_secret_name_at_revision(value: &str, revision: u64) -> Result<()> {
    anyhow::ensure!(revision > 0, "Kubernetes Secret revision must be positive");
    let suffix = format!("-r{revision}");
    anyhow::ensure!(
        value.len() <= 253
            && value.ends_with(&suffix)
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
        "Kubernetes Secret name must be a DNS subdomain ending in {suffix}"
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
            dns_names: &[
                CONTROL_MACHINE_DNS.to_owned(),
                CONTROL_ROTATION_MACHINE_DNS.to_owned(),
            ],
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
        "node-server-ca-bundle.pem",
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
            "node_server_ca_bundle_pem_b64".to_owned(),
            STANDARD.encode(required(files, "node-server-ca-bundle.pem")?),
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
                && installed.node_server_ca_bundle_pem()
                    == required(&node, "node-server-ca-bundle.pem")?
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
        required(&node, "node-server-ca-bundle.pem")?,
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
        Arc::clone(&control_server),
        CONTROL_MACHINE_DNS,
    )?;
    handshake(
        Arc::clone(&gateway_client),
        control_server,
        CONTROL_ROTATION_MACHINE_DNS,
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
                    "node_server_ca_bundle_pem_b64",
                    "public_key_ring_v1_json_b64",
                    "rotation_operator_trust_v1_json_b64",
                ],
        "Node SecretString is not the exact six-field shape"
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
        ("node_server_ca_bundle_pem_b64", "node-server-ca-bundle.pem"),
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
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use tempfile::TempDir;

    fn write_test_trust(path: &Path, mode: u32) {
        std::fs::write(path, b"canonical-trust").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn test_owner(path: &Path) -> (u32, u32) {
        let metadata = std::fs::metadata(path).unwrap();
        (metadata.uid(), metadata.gid())
    }

    #[test]
    fn staged_and_fixed_rotation_trust_admit_only_their_exact_modes() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("rotation-operator-trust.v1.json");
        let (uid, gid) = test_owner(root.path());

        assert_eq!(
            rotation_trust_representation(Path::new(INSTALLED_ROTATION_OPERATOR_TRUST_PATH)),
            RotationTrustRepresentation::InstalledRelease
        );
        assert_eq!(
            rotation_trust_representation(&path),
            RotationTrustRepresentation::RunnerStaged
        );

        write_test_trust(&path, 0o600);
        assert_eq!(
            read_rotation_trust_file_as(
                &path,
                RotationTrustRepresentation::RunnerStaged,
                uid,
                gid,
            )
            .unwrap(),
            b"canonical-trust"
        );
        assert!(read_rotation_trust_file_as(
            &path,
            RotationTrustRepresentation::InstalledRelease,
            uid,
            gid,
        )
        .is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_rotation_trust_file_as(
                &path,
                RotationTrustRepresentation::InstalledRelease,
                uid,
                gid,
            )
            .unwrap(),
            b"canonical-trust"
        );
        assert!(read_rotation_trust_file_as(
            &path,
            RotationTrustRepresentation::RunnerStaged,
            uid,
            gid,
        )
        .is_err());
    }

    #[test]
    fn staged_rotation_trust_rejects_loose_modes_links_and_wrong_owner() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("rotation-operator-trust.v1.json");
        let (uid, gid) = test_owner(root.path());

        for mode in [0o640, 0o660, 0o664, 0o604] {
            if path.exists() {
                std::fs::remove_file(&path).unwrap();
            }
            write_test_trust(&path, mode);
            assert!(read_rotation_trust_file_as(
                &path,
                RotationTrustRepresentation::RunnerStaged,
                uid,
                gid,
            )
            .is_err());
        }

        std::fs::remove_file(&path).unwrap();
        let target = root.path().join("trust-target.json");
        write_test_trust(&target, 0o600);
        symlink(&target, &path).unwrap();
        assert!(read_rotation_trust_file_as(
            &path,
            RotationTrustRepresentation::RunnerStaged,
            uid,
            gid,
        )
        .is_err());

        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(read_rotation_trust_file_as(
            &path,
            RotationTrustRepresentation::RunnerStaged,
            uid,
            gid,
        )
        .is_err());

        let wrong_owner_path = root.path().join("wrong-owner.json");
        write_test_trust(&wrong_owner_path, 0o600);
        let metadata = std::fs::metadata(&wrong_owner_path).unwrap();
        let wrong_uid = if uid == 0 { 1 } else { 0 };
        assert!(validate_rotation_trust_metadata(
            &metadata,
            RotationTrustRepresentation::RunnerStaged,
            wrong_uid,
            gid,
        )
        .is_err());
    }

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
            ("node-server-ca-bundle.pem".to_owned(), b"ca".to_vec()),
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
        // The production reader rejects world-writable ancestors, so the
        // accepted-candidate root cannot live under a sticky /tmp (the Linux
        // gate's default). The workspace target directory satisfies the
        // ancestor contract on every gate host.
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/route-v2-r1-test-tmp");
        std::fs::create_dir_all(&base).unwrap();
        let base = base.canonicalize().unwrap();
        let root = TempDir::new_in(&base).unwrap();
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

        let source = load_rotation_recovery_source(&candidate).unwrap();
        let recovery_path = root.path().join("rotation-recovery");
        let (recovery, created) =
            RotationRecoveryOutput::open_or_create(&recovery_path, uid).unwrap();
        assert!(created);
        generate_rotation_recovery(&recovery, &source, "qualification_run_a").unwrap();
        let recovery_receipt =
            verify_rotation_recovery(&recovery, &source, "qualification_run_a").unwrap();
        assert_eq!(recovery_receipt.first_signer_revision, 2);
        assert_eq!(recovery_receipt.terminal_signer_revision, 8);
        assert_eq!(recovery_receipt.terminal_ring_version, 5);
        assert_eq!(
            recovery_receipt.terminal_secret_name,
            "cats-route-v2-control-r8"
        );
        let command_bundle = read_file(
            &recovery.commands,
            "route-v2-rotation-command-bundle.v1.json",
            0o600,
            uid,
            MAX_ROTATION_RECOVERY_BUNDLE_BYTES,
        )
        .unwrap();
        assert!(!String::from_utf8(command_bundle)
            .unwrap()
            .contains("issued_at_unix_ms"));
    }
}

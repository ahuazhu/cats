//! Offline A23 provisioner artifacts and the fixed Host-local initial
//! NodeIdentity installation transaction.
//!
//! This module deliberately does not implement an HTTP client or signing
//! dialect. The official `cats admin runtime-node provision` state machine is
//! the only component allowed to perform the signed Control apply.

mod route_v2_r1;

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use cats_api::agent_registration::{
    validate_node_identity_material, validate_state_path_component, Ed25519RequestSigner,
};
use cats_api::runtime_reconciliation::{
    decode_runtime_node_authority_apply_result, decode_runtime_provisioner_trust_bundle,
    encode_node_identity, encode_runtime_node_authority_apply_result,
    encode_runtime_provisioner_active_set, encode_runtime_provisioner_trust_bundle,
    runtime_provisioner_active_set_digest, Base64UrlNoPad, ContractVersion, CredentialBinding,
    Epoch, Id, NodeIdentity, NodeIdentityState, RuntimeNodeAuthorityOutcome,
    RuntimeProvisionerActiveSet, RuntimeProvisionerCredential, RuntimeProvisionerTrustBundle,
    Sha256Digest, RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES,
    RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES,
};
use fs2::FileExt as _;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::stable_unix_fs::{
    c_os_name, effective_gid, effective_uid, mkdir_at, open_directory_nofollow, open_file_at,
    rename_noreplace_at, sync_directory, unlink_at,
};
use crate::{
    Cli, RuntimeProvisionerCommand, RuntimeProvisionerNodeIdentityCommand,
    RuntimeProvisionerRouteV2R1Command, RuntimeProvisionerTrustCommand,
};

const PRIVATE_KEY_MAX_BYTES: usize = 16_384;
const NODE_IDENTITY_MAX_BYTES: usize = 16_384;
const CREDENTIAL_ID_MAX_BYTES: usize = 129;
const PROVISION_LOCK: &str = ".provision.lock";
const INCOMPLETE_SET: &str = ".node-identity-recovery.incomplete.v1";
const INITIAL_SET: &str = ".node-identity-provision.v1";
const ROTATION_NEW_SET: &str = ".node-identity-rotation-new.v1";
const ROTATION_OLD_SET: &str = ".node-identity-rotation-old.v1";
const IDENTITY_FILE: &str = "node-identity.v1.json";
const PRIVATE_KEY_FILE: &str = "node-registration-key.pem";
const CREDENTIAL_ID_FILE: &str = "node-registration-credential-id";
const ACTIVE_TEMP_SUFFIX: &str = ".activation-incomplete.v1";

#[derive(Debug, Serialize)]
struct TrustVerificationReceipt<'a> {
    version: u32,
    deployment_id: &'a str,
    trust_revision: u64,
    credential_id: &'a str,
    public_key_spki_sha256: String,
    active_set_sha256: String,
    trust_bundle_sha256: String,
}

#[derive(Debug, Serialize)]
struct NodeIdentityReceipt<'a> {
    version: u32,
    node_id: &'a str,
    immutable_host_id: &'a str,
    credential_id: &'a str,
    state_path_id: &'a str,
    public_key_spki_sha256: &'a str,
    node_identity_sha256: String,
    phase: &'static str,
}

#[derive(Debug)]
struct IdentitySet {
    identity: NodeIdentity,
    identity_bytes: Vec<u8>,
    private_key_bytes: Vec<u8>,
    credential_id_bytes: Vec<u8>,
}

impl Drop for IdentitySet {
    fn drop(&mut self) {
        self.private_key_bytes.fill(0);
    }
}

struct HostIdentityRoot {
    identity_directory: File,
    expected_uid: u32,
    _lock: File,
}

pub(crate) fn run(cli: &Cli, command: &RuntimeProvisionerCommand) -> Result<()> {
    anyhow::ensure!(
        cli.token.is_none() && cli.workspace.is_none(),
        "Runtime provisioner artifact tooling is offline and cannot use token or Workspace identity"
    );
    match command {
        RuntimeProvisionerCommand::Trust { cmd } => run_trust(cli, cmd),
        RuntimeProvisionerCommand::NodeIdentity { cmd } => {
            anyhow::ensure!(
                effective_uid() == 0,
                "Host NodeIdentity provisioning must run as root"
            );
            run_node_identity(cli, cmd, Path::new("/"), 0)
        }
        RuntimeProvisionerCommand::RouteV2R1 { cmd } => {
            anyhow::ensure!(
                effective_uid() == 0,
                "Route v2 credential provisioning must run as root"
            );
            route_v2_r1::run(cli, cmd)
        }
    }
}

fn run_trust(cli: &Cli, command: &RuntimeProvisionerTrustCommand) -> Result<()> {
    match command {
        RuntimeProvisionerTrustCommand::Generate {
            deployment_id,
            credential_id,
            private_key_out,
            trust_bundle_out,
        } => {
            let deployment_id = Id::new(deployment_id.clone()).context("invalid deployment ID")?;
            let credential_id = Id::new(credential_id.clone()).context("invalid credential ID")?;
            let mut private_key = load_or_generate_private_key(private_key_out, &credential_id)?;
            let signer = signer_from_private_key_and_zero(&credential_id, &mut private_key)
                .context("strictly verify generated provisioner PKCS#8 v2 key")?;
            let bundle = initial_trust_bundle(&deployment_id, &credential_id, &signer)?;
            let bundle_bytes = encode_runtime_provisioner_trust_bundle(&bundle)
                .map_err(|error| anyhow!("encode provisioner trust bundle: {error:?}"))?;
            publish_user_file_idempotent(trust_bundle_out, &bundle_bytes, 0o644)?;
            report_trust_receipt(cli, &bundle, &credential_id, &signer, &bundle_bytes)
        }
        RuntimeProvisionerTrustCommand::Verify {
            credential_id,
            private_key,
            trust_bundle,
        } => {
            let credential_id = Id::new(credential_id.clone()).context("invalid credential ID")?;
            let mut private_key_bytes =
                read_user_file(private_key, PRIVATE_KEY_MAX_BYTES, 0o600, true)?;
            let signer = signer_from_private_key_and_zero(&credential_id, &mut private_key_bytes)
                .context("strictly verify provisioner PKCS#8 v2 key")?;
            let bundle_bytes = read_user_file(
                trust_bundle,
                RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES,
                0,
                false,
            )?;
            let bundle = decode_runtime_provisioner_trust_bundle(&bundle_bytes)
                .map_err(|error| anyhow!("decode provisioner trust bundle: {error:?}"))?;
            let canonical = encode_runtime_provisioner_trust_bundle(&bundle)
                .map_err(|error| anyhow!("re-encode provisioner trust bundle: {error:?}"))?;
            anyhow::ensure!(
                canonical == bundle_bytes,
                "provisioner trust bundle is not canonical"
            );
            report_trust_receipt(cli, &bundle, &credential_id, &signer, &bundle_bytes)
        }
    }
}

fn initial_trust_bundle(
    deployment_id: &Id,
    credential_id: &Id,
    signer: &Ed25519RequestSigner,
) -> Result<RuntimeProvisionerTrustBundle> {
    let public_key_spki = Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.public_key_spki_der()))
        .context("generated provisioner SPKI is not canonical base64url")?;
    let bundle = RuntimeProvisionerTrustBundle {
        version: ContractVersion::V1,
        deployment_id: deployment_id.clone(),
        trust_revision: Epoch::new(1).expect("one is a valid trust revision"),
        expected_previous: None,
        credentials: vec![RuntimeProvisionerCredential {
            credential_id: credential_id.clone(),
            public_key_spki,
        }],
    };
    encode_runtime_provisioner_trust_bundle(&bundle)
        .map_err(|error| anyhow!("generated provisioner trust bundle is invalid: {error:?}"))?;
    Ok(bundle)
}

fn signer_from_private_key_and_zero(
    credential_id: &Id,
    private_key: &mut [u8],
) -> std::result::Result<Ed25519RequestSigner, cats_api::agent_registration::RequestSignerError> {
    let result = Ed25519RequestSigner::from_pkcs8_v2_pem(credential_id.clone(), private_key);
    private_key.fill(0);
    result
}

fn report_trust_receipt(
    cli: &Cli,
    bundle: &RuntimeProvisionerTrustBundle,
    credential_id: &Id,
    signer: &Ed25519RequestSigner,
    bundle_bytes: &[u8],
) -> Result<()> {
    let expected_spki = URL_SAFE_NO_PAD.encode(signer.public_key_spki_der());
    let credential = bundle
        .credentials
        .iter()
        .find(|candidate| candidate.credential_id == *credential_id)
        .context("trust bundle does not contain the selected provisioner credential")?;
    anyhow::ensure!(
        credential.public_key_spki.as_str() == expected_spki,
        "provisioner private key does not match the trust-bundle credential SPKI"
    );
    let active_set = RuntimeProvisionerActiveSet {
        version: ContractVersion::V1,
        deployment_id: bundle.deployment_id.clone(),
        credentials: bundle.credentials.clone(),
    };
    let active_bytes = encode_runtime_provisioner_active_set(&active_set)
        .map_err(|error| anyhow!("encode provisioner active set: {error:?}"))?;
    let active_digest = runtime_provisioner_active_set_digest(&active_set)
        .map_err(|error| anyhow!("digest provisioner active set: {error:?}"))?;
    let independently_computed = Sha256Digest::from_bytes(Sha256::digest(&active_bytes).into());
    anyhow::ensure!(
        active_digest == independently_computed,
        "provisioner active-set digest helper disagrees with canonical bytes"
    );
    let receipt = TrustVerificationReceipt {
        version: 1,
        deployment_id: bundle.deployment_id.as_str(),
        trust_revision: bundle.trust_revision.get(),
        credential_id: credential_id.as_str(),
        public_key_spki_sha256: signer.public_key_spki_sha256().to_string(),
        active_set_sha256: active_digest.to_string(),
        trust_bundle_sha256: sha256_wire(bundle_bytes),
    };
    report(cli, &receipt)
}

fn run_node_identity(
    cli: &Cli,
    command: &RuntimeProvisionerNodeIdentityCommand,
    filesystem_root: &Path,
    expected_uid: u32,
) -> Result<()> {
    let root = HostIdentityRoot::open(filesystem_root, expected_uid)?;
    match command {
        RuntimeProvisionerNodeIdentityCommand::Prepare {
            node_id,
            immutable_host_id,
            state_path_id,
            credential_id,
        } => {
            let node_id = Id::new(node_id.clone()).context("invalid Node ID")?;
            let immutable_host_id =
                Id::new(immutable_host_id.clone()).context("invalid immutable Host ID")?;
            let state_path_id = Id::new(state_path_id.clone()).context("invalid state path ID")?;
            validate_state_path_component(&state_path_id)
                .context("state path ID is not a safe path component")?;
            let credential_id = Id::new(credential_id.clone()).context("invalid credential ID")?;
            let set = root.prepare(&node_id, &immutable_host_id, &state_path_id, &credential_id)?;
            report_node_identity(cli, &set, "prepared")
        }
        RuntimeProvisionerNodeIdentityCommand::Export => {
            let set = root.load_initial_set()?;
            io::stdout()
                .write_all(&set.identity_bytes)
                .context("write canonical public NodeIdentity to stdout")?;
            io::stdout().flush().context("flush NodeIdentity stdout")
        }
        RuntimeProvisionerNodeIdentityCommand::Activate { apply_result } => {
            let result_bytes = read_user_file(
                apply_result,
                RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES,
                0o600,
                true,
            )?;
            let result =
                decode_runtime_node_authority_apply_result(&result_bytes).map_err(|error| {
                    anyhow!("decode Runtime Node authority apply result: {error:?}")
                })?;
            anyhow::ensure!(
                encode_runtime_node_authority_apply_result(&result).map_err(|error| anyhow!(
                    "re-encode Runtime Node authority result: {error:?}"
                ))? == result_bytes,
                "Runtime Node authority apply result is not canonical"
            );
            anyhow::ensure!(
                result.outcome == RuntimeNodeAuthorityOutcome::Provisioned
                    && result.identity_state == NodeIdentityState::Provisioned
                    && result.policy_revision.get() == 1,
                "activation requires the canonical successful initial-provision result"
            );
            let set = root.activate(&result.node_id, filesystem_root)?;
            report_node_identity(cli, &set, "activated")
        }
    }
}

impl HostIdentityRoot {
    fn open(filesystem_root: &Path, expected_uid: u32) -> Result<Self> {
        let root = open_directory_nofollow(filesystem_root)?;
        validate_directory(&root, expected_uid, None, "filesystem root")?;
        let etc = open_or_create_protected_directory(&root, "etc", 0o755, None, expected_uid)?;
        let cats = open_or_create_protected_directory(&etc, "cats", 0o755, None, expected_uid)?;
        let identity_directory = open_or_create_protected_directory(
            &cats,
            "identity",
            0o700,
            Some(0o700),
            expected_uid,
        )?;
        let lock_name = c_name(PROVISION_LOCK)?;
        let lock = match open_file_at(
            &identity_directory,
            &lock_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(lock) => {
                set_file_mode(&lock, 0o600)?;
                lock.sync_all()
                    .context("sync new Node identity provision lock")?;
                sync_directory(
                    &identity_directory,
                    "sync Node identity provision-lock parent",
                )?;
                lock
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_file_at(&identity_directory, &lock_name, libc::O_RDWR, 0)
                    .context("open existing Node identity provision lock")?
            }
            Err(error) => return Err(error).context("create Node identity provision lock"),
        };
        validate_regular_metadata(&lock, expected_uid, 0o600, "Node identity provision lock")?;
        lock.lock_exclusive()
            .context("lock Node identity provision transaction")?;
        validate_regular_metadata(&lock, expected_uid, 0o600, "Node identity provision lock")?;
        Ok(Self {
            identity_directory,
            expected_uid,
            _lock: lock,
        })
    }

    fn prepare(
        &self,
        node_id: &Id,
        immutable_host_id: &Id,
        state_path_id: &Id,
        credential_id: &Id,
    ) -> Result<IdentitySet> {
        self.reject_rotation_sets()?;
        if let Some(existing) = self.load_set_if_exists(INITIAL_SET)? {
            ensure_identity_fields(
                &existing.identity,
                node_id,
                immutable_host_id,
                state_path_id,
                credential_id,
            )?;
            return Ok(existing);
        }
        self.reject_any_active_identity_file()?;
        self.remove_incomplete_set()?;

        let incomplete_name = c_name(INCOMPLETE_SET)?;
        mkdir_at(&self.identity_directory, &incomplete_name, 0o700)
            .context("create incomplete Node identity recovery set")?;
        let incomplete = open_file_at(
            &self.identity_directory,
            &incomplete_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .context("open incomplete Node identity recovery set")?;
        validate_directory(
            &incomplete,
            self.expected_uid,
            Some(0o700),
            "incomplete Node identity recovery set",
        )?;

        let mut private_key = generate_pkcs8_v2_pem()?;
        let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(credential_id.clone(), &private_key)
            .context("verify generated Node PKCS#8 v2 private key")?;
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: node_id.clone(),
            immutable_host_id: immutable_host_id.clone(),
            credential_id: credential_id.clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: state_path_id.clone(),
            state: NodeIdentityState::Provisioned,
        };
        let identity_bytes = encode_node_identity(&identity)
            .map_err(|error| anyhow!("encode generated NodeIdentity: {error:?}"))?;
        let credential_id_bytes = format!("{credential_id}\n").into_bytes();
        write_new_file_at(&incomplete, PRIVATE_KEY_FILE, &private_key, 0o600)?;
        private_key.fill(0);
        write_new_file_at(&incomplete, CREDENTIAL_ID_FILE, &credential_id_bytes, 0o600)?;
        write_new_file_at(&incomplete, IDENTITY_FILE, &identity_bytes, 0o600)?;
        sync_directory(&incomplete, "sync incomplete Node identity recovery set")?;
        let set = load_identity_set(&incomplete, self.expected_uid)?;
        ensure_identity_fields(
            &set.identity,
            node_id,
            immutable_host_id,
            state_path_id,
            credential_id,
        )?;
        let initial_name = c_name(INITIAL_SET)?;
        rename_noreplace_at(&self.identity_directory, &incomplete_name, &initial_name)
            .context("publish complete initial Node identity recovery set")?;
        sync_directory(
            &self.identity_directory,
            "sync Node identity directory after publishing recovery set",
        )?;
        self.load_initial_set()
    }

    fn load_initial_set(&self) -> Result<IdentitySet> {
        self.load_set_if_exists(INITIAL_SET)?
            .context("complete initial Node identity recovery set is missing")
    }

    fn activate(&self, result_node_id: &Id, filesystem_root: &Path) -> Result<IdentitySet> {
        // The identity artifact is installed last. Its presence therefore
        // means an interrupted run may only need state-path creation and/or
        // recovery-set cleanup, both of which forward-complete here.
        if entry_exists(&self.identity_directory, IDENTITY_FILE)? {
            let active = self.load_active_set()?;
            anyhow::ensure!(
                active.identity.node_id == *result_node_id,
                "apply result names a different Node than the active identity"
            );
            ensure_state_path(
                filesystem_root,
                self.expected_uid,
                &active.identity.state_path_id,
            )?;
            if entry_exists(&self.identity_directory, INITIAL_SET)? {
                self.remove_initial_set_matching(&active)?;
            }
            return Ok(active);
        }
        let source = match self.load_set_if_exists(INITIAL_SET)? {
            Some(set) => set,
            None => {
                bail!("complete initial Node identity recovery set is missing")
            }
        };
        anyhow::ensure!(
            source.identity.node_id == *result_node_id,
            "apply result names a different Node than the recovery identity"
        );

        install_active_file(
            &self.identity_directory,
            PRIVATE_KEY_FILE,
            &source.private_key_bytes,
            self.expected_uid,
        )?;
        install_active_file(
            &self.identity_directory,
            CREDENTIAL_ID_FILE,
            &source.credential_id_bytes,
            self.expected_uid,
        )?;
        // The public identity is the local complete marker and is installed last.
        install_active_file(
            &self.identity_directory,
            IDENTITY_FILE,
            &source.identity_bytes,
            self.expected_uid,
        )?;
        let active = self.load_active_set()?;
        anyhow::ensure!(
            active.identity == source.identity
                && active.identity_bytes == source.identity_bytes
                && active.private_key_bytes == source.private_key_bytes
                && active.credential_id_bytes == source.credential_id_bytes,
            "active Node identity set differs from its durable recovery source"
        );
        ensure_state_path(
            filesystem_root,
            self.expected_uid,
            &active.identity.state_path_id,
        )?;
        self.remove_initial_set_matching(&active)?;
        Ok(active)
    }

    fn load_active_set(&self) -> Result<IdentitySet> {
        let identity_bytes = read_regular_at(
            &self.identity_directory,
            IDENTITY_FILE,
            self.expected_uid,
            0o600,
            NODE_IDENTITY_MAX_BYTES,
        )?;
        let private_key_bytes = read_regular_at(
            &self.identity_directory,
            PRIVATE_KEY_FILE,
            self.expected_uid,
            0o600,
            PRIVATE_KEY_MAX_BYTES,
        )?;
        let credential_id_bytes = read_regular_at(
            &self.identity_directory,
            CREDENTIAL_ID_FILE,
            self.expected_uid,
            0o600,
            CREDENTIAL_ID_MAX_BYTES,
        )?;
        identity_set(identity_bytes, private_key_bytes, credential_id_bytes)
    }

    fn load_set_if_exists(&self, name: &str) -> Result<Option<IdentitySet>> {
        let name = c_name(name)?;
        let directory = match open_file_at(
            &self.identity_directory,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("open Node identity recovery set"),
        };
        validate_directory(
            &directory,
            self.expected_uid,
            Some(0o700),
            "Node identity recovery set",
        )?;
        Ok(Some(load_identity_set(&directory, self.expected_uid)?))
    }

    fn reject_rotation_sets(&self) -> Result<()> {
        for name in [ROTATION_NEW_SET, ROTATION_OLD_SET] {
            if entry_exists(&self.identity_directory, name)? {
                bail!("credential-rotation recovery set {name} exists; initial provision cannot continue");
            }
        }
        Ok(())
    }

    fn reject_any_active_identity_file(&self) -> Result<()> {
        for name in [IDENTITY_FILE, PRIVATE_KEY_FILE, CREDENTIAL_ID_FILE] {
            anyhow::ensure!(
                !entry_exists(&self.identity_directory, name)?,
                "active Node identity entry {name} exists without an initial recovery marker"
            );
        }
        Ok(())
    }

    fn remove_incomplete_set(&self) -> Result<()> {
        if !entry_exists(&self.identity_directory, INCOMPLETE_SET)? {
            return Ok(());
        }
        self.remove_set(INCOMPLETE_SET)
    }

    fn remove_initial_set_matching(&self, active: &IdentitySet) -> Result<()> {
        let set_name = c_name(INITIAL_SET)?;
        let directory = open_file_at(
            &self.identity_directory,
            &set_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .context("open initial recovery set for activation cleanup")?;
        validate_directory(
            &directory,
            self.expected_uid,
            Some(0o700),
            "initial Node identity recovery cleanup set",
        )?;
        let names = list_directory_names(&directory)?;
        let expected = [
            (PRIVATE_KEY_FILE, active.private_key_bytes.as_slice()),
            (CREDENTIAL_ID_FILE, active.credential_id_bytes.as_slice()),
            (IDENTITY_FILE, active.identity_bytes.as_slice()),
        ];
        let allowed: BTreeSet<OsString> = expected
            .iter()
            .map(|(name, _)| OsString::from(*name))
            .collect();
        anyhow::ensure!(
            names.iter().all(|entry| allowed.contains(entry)),
            "initial Node identity recovery set contains an unexpected entry"
        );
        for (file_name, expected_bytes) in expected {
            if names.contains(&OsString::from(file_name)) {
                let observed = read_regular_at(
                    &directory,
                    file_name,
                    self.expected_uid,
                    0o600,
                    expected_bytes.len(),
                )?;
                anyhow::ensure!(
                    observed == expected_bytes,
                    "initial recovery entry {file_name} differs from the active identity"
                );
                let c_file_name = c_name(file_name)?;
                unlink_at(&directory, &c_file_name, 0)
                    .context("remove activated initial recovery entry")?;
                sync_directory(
                    &directory,
                    "sync initial recovery set after activated entry cleanup",
                )?;
            }
        }
        unlink_at(&self.identity_directory, &set_name, libc::AT_REMOVEDIR)
            .context("remove activated initial recovery directory")?;
        sync_directory(
            &self.identity_directory,
            "sync Node identity directory after activated recovery cleanup",
        )
    }

    fn remove_set(&self, name: &str) -> Result<()> {
        let set_name = c_name(name)?;
        let directory = open_file_at(
            &self.identity_directory,
            &set_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .with_context(|| format!("open recovery set {name} for cleanup"))?;
        validate_directory(
            &directory,
            self.expected_uid,
            Some(0o700),
            "Node identity recovery cleanup set",
        )?;
        let names = list_directory_names(&directory)?;
        let allowed: BTreeSet<OsString> = [IDENTITY_FILE, PRIVATE_KEY_FILE, CREDENTIAL_ID_FILE]
            .into_iter()
            .map(OsString::from)
            .collect();
        anyhow::ensure!(
            names.iter().all(|entry| allowed.contains(entry)),
            "Node identity recovery set contains an unexpected entry"
        );
        for file_name in [PRIVATE_KEY_FILE, CREDENTIAL_ID_FILE, IDENTITY_FILE] {
            if names.contains(&OsString::from(file_name)) {
                let c_file_name = c_name(file_name)?;
                let file = open_file_at(&directory, &c_file_name, libc::O_RDONLY, 0)
                    .context("open recovery entry before cleanup")?;
                validate_regular_metadata(
                    &file,
                    self.expected_uid,
                    0o600,
                    "Node identity recovery entry",
                )?;
                unlink_at(&directory, &c_file_name, 0).context("remove recovery entry")?;
            }
        }
        sync_directory(&directory, "sync emptied Node identity recovery set")?;
        unlink_at(&self.identity_directory, &set_name, libc::AT_REMOVEDIR)
            .context("remove Node identity recovery directory")?;
        sync_directory(
            &self.identity_directory,
            "sync Node identity directory after recovery cleanup",
        )
    }
}

fn load_identity_set(directory: &File, expected_uid: u32) -> Result<IdentitySet> {
    let names = list_directory_names(directory)?;
    let expected: BTreeSet<OsString> = [IDENTITY_FILE, PRIVATE_KEY_FILE, CREDENTIAL_ID_FILE]
        .into_iter()
        .map(OsString::from)
        .collect();
    anyhow::ensure!(
        names == expected,
        "Node identity recovery set is not a closed file set"
    );
    let identity_bytes = read_regular_at(
        directory,
        IDENTITY_FILE,
        expected_uid,
        0o600,
        NODE_IDENTITY_MAX_BYTES,
    )?;
    let private_key_bytes = read_regular_at(
        directory,
        PRIVATE_KEY_FILE,
        expected_uid,
        0o600,
        PRIVATE_KEY_MAX_BYTES,
    )?;
    let credential_id_bytes = read_regular_at(
        directory,
        CREDENTIAL_ID_FILE,
        expected_uid,
        0o600,
        CREDENTIAL_ID_MAX_BYTES,
    )?;
    identity_set(identity_bytes, private_key_bytes, credential_id_bytes)
}

fn identity_set(
    identity_bytes: Vec<u8>,
    private_key_bytes: Vec<u8>,
    credential_id_bytes: Vec<u8>,
) -> Result<IdentitySet> {
    let (identity, signer) =
        validate_node_identity_material(&identity_bytes, &private_key_bytes, &credential_id_bytes)
            .context("cross-check Node identity material")?;
    let strict =
        Ed25519RequestSigner::from_pkcs8_v2_pem(identity.credential_id.clone(), &private_key_bytes)
            .context("Node identity recovery key is not strict PKCS#8 v2")?;
    anyhow::ensure!(
        strict.public_key_spki_der() == signer.public_key_spki_der(),
        "strict and runtime Node key parsers derived different SPKI bytes"
    );
    Ok(IdentitySet {
        identity,
        identity_bytes,
        private_key_bytes,
        credential_id_bytes,
    })
}

fn ensure_identity_fields(
    identity: &NodeIdentity,
    node_id: &Id,
    immutable_host_id: &Id,
    state_path_id: &Id,
    credential_id: &Id,
) -> Result<()> {
    anyhow::ensure!(
        identity.node_id == *node_id
            && identity.immutable_host_id == *immutable_host_id
            && identity.state_path_id == *state_path_id
            && identity.credential_id == *credential_id,
        "existing Node identity recovery set does not match the requested immutable fields"
    );
    Ok(())
}

fn report_node_identity(cli: &Cli, set: &IdentitySet, phase: &'static str) -> Result<()> {
    let CredentialBinding::PublicKey {
        public_key_spki_sha256,
    } = &set.identity.credential_binding
    else {
        bail!("Node identity has a non-public-key credential binding")
    };
    let receipt = NodeIdentityReceipt {
        version: 1,
        node_id: set.identity.node_id.as_str(),
        immutable_host_id: set.identity.immutable_host_id.as_str(),
        credential_id: set.identity.credential_id.as_str(),
        state_path_id: set.identity.state_path_id.as_str(),
        public_key_spki_sha256: public_key_spki_sha256.as_str(),
        node_identity_sha256: sha256_wire(&set.identity_bytes),
        phase,
    };
    report(cli, &receipt)
}

fn ensure_state_path(filesystem_root: &Path, expected_uid: u32, state_path_id: &Id) -> Result<()> {
    validate_state_path_component(state_path_id).context("unsafe Node state path component")?;
    let root = open_directory_nofollow(filesystem_root)?;
    validate_directory(&root, expected_uid, None, "filesystem root")?;
    let var = open_or_create_protected_directory(&root, "var", 0o755, None, expected_uid)?;
    let lib = open_or_create_protected_directory(&var, "lib", 0o755, None, expected_uid)?;
    let cats = open_or_create_protected_directory(&lib, "cats", 0o755, None, expected_uid)?;
    let node = open_or_create_protected_directory(&cats, "node", 0o700, None, expected_uid)?;
    let state = open_or_create_protected_directory(
        &node,
        state_path_id.as_str(),
        0o700,
        None,
        expected_uid,
    )?;
    validate_directory(
        &state,
        expected_uid,
        Some(0o700),
        "identity-selected Node state path",
    )
}

fn install_active_file(
    directory: &File,
    name: &str,
    expected_bytes: &[u8],
    expected_uid: u32,
) -> Result<()> {
    if entry_exists(directory, name)? {
        let existing = read_regular_at(directory, name, expected_uid, 0o600, expected_bytes.len())?;
        anyhow::ensure!(
            existing == expected_bytes,
            "active Node identity entry {name} differs"
        );
        sync_regular_at(directory, name, expected_uid, 0o600)?;
        sync_directory(directory, "sync replayed active Node identity directory")?;
        return Ok(());
    }
    let temporary_name = format!(".{name}{ACTIVE_TEMP_SUFFIX}");
    remove_inactive_temporary_file(directory, &temporary_name, expected_uid)?;
    write_new_file_at(directory, &temporary_name, expected_bytes, 0o600)?;
    let source = c_name(&temporary_name)?;
    let destination = c_name(name)?;
    match rename_noreplace_at(directory, &source, &destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            unlink_at(directory, &source, 0).context("remove losing activation temporary file")?;
        }
        Err(error) => return Err(error).context("activate Node identity file without replacement"),
    }
    sync_regular_at(directory, name, expected_uid, 0o600)?;
    sync_directory(directory, "sync active Node identity directory")?;
    let installed = read_regular_at(directory, name, expected_uid, 0o600, expected_bytes.len())?;
    anyhow::ensure!(
        installed == expected_bytes,
        "activated Node identity entry differs"
    );
    Ok(())
}

fn remove_inactive_temporary_file(directory: &File, name: &str, expected_uid: u32) -> Result<()> {
    if !entry_exists(directory, name)? {
        return Ok(());
    }
    let name = c_name(name)?;
    let file = open_file_at(directory, &name, libc::O_RDONLY, 0)
        .context("open incomplete activation file")?;
    validate_regular_metadata(&file, expected_uid, 0o600, "incomplete activation file")?;
    unlink_at(directory, &name, 0).context("remove incomplete activation file")?;
    sync_directory(directory, "sync incomplete activation cleanup")
}

fn load_or_generate_private_key(path: &Path, credential_id: &Id) -> Result<Vec<u8>> {
    if path.exists() {
        let bytes = read_user_file(path, PRIVATE_KEY_MAX_BYTES, 0o600, true)?;
        Ed25519RequestSigner::from_pkcs8_v2_pem(credential_id.clone(), &bytes)
            .context("existing provisioner key is not strict PKCS#8 v2")?;
        return Ok(bytes);
    }
    let mut bytes = generate_pkcs8_v2_pem()?;
    publish_user_file_idempotent(path, &bytes, 0o600)?;
    bytes.fill(0);
    read_user_file(path, PRIVATE_KEY_MAX_BYTES, 0o600, true)
}

fn generate_pkcs8_v2_pem() -> Result<Vec<u8>> {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow!("generate Ed25519 PKCS#8 v2 private key"))?;
    let encoded = STANDARD.encode(document.as_ref());
    let mut pem = Vec::with_capacity(encoded.len() + 80);
    pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
    Ok(pem)
}

fn publish_user_file_idempotent(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "provisioner output path must be absolute"
    );
    let parent_path = path.parent().context("provisioner output has no parent")?;
    let file_name = path
        .file_name()
        .context("provisioner output has no basename")?;
    let parent = open_directory_nofollow(parent_path)?;
    validate_directory(&parent, effective_uid(), None, "provisioner output parent")?;
    if path.exists() {
        let existing = read_user_file(path, bytes.len(), mode, mode == 0o600)?;
        anyhow::ensure!(
            existing == bytes,
            "existing provisioner output differs: {}",
            path.display()
        );
        return Ok(());
    }
    let final_label = file_name
        .to_str()
        .context("provisioner output basename is not UTF-8")?;
    let final_name = c_os_name(file_name)?;
    let temporary_name = c_name(&format!(".{}.incomplete.v1", final_label))?;
    if let Ok(file) = open_file_at(&parent, &temporary_name, libc::O_RDONLY, 0) {
        validate_regular_metadata(
            &file,
            effective_uid(),
            mode,
            "incomplete provisioner output",
        )?;
        unlink_at(&parent, &temporary_name, 0).context("remove incomplete provisioner output")?;
        sync_directory(&parent, "sync incomplete provisioner output cleanup")?;
    }
    let temporary_label = temporary_name
        .to_str()
        .context("provisioner temporary basename is not UTF-8")?;
    write_new_file_at(&parent, temporary_label, bytes, mode)?;
    match rename_noreplace_at(&parent, &temporary_name, &final_name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            unlink_at(&parent, &temporary_name, 0)
                .context("remove losing provisioner output temporary")?;
        }
        Err(error) => return Err(error).context("publish provisioner output without replacement"),
    }
    sync_directory(&parent, "sync provisioner output parent")?;
    let installed = read_user_file(path, bytes.len(), mode, mode == 0o600)?;
    anyhow::ensure!(installed == bytes, "published provisioner output differs");
    Ok(())
}

fn read_user_file(path: &Path, maximum: usize, exact_mode: u32, private: bool) -> Result<Vec<u8>> {
    anyhow::ensure!(
        path.is_absolute(),
        "provisioner input path must be absolute"
    );
    let parent = open_directory_nofollow(path.parent().context("input path has no parent")?)?;
    validate_directory(&parent, effective_uid(), None, "provisioner input parent")?;
    let name = c_os_name(path.file_name().context("input path has no basename")?)?;
    let file = open_file_at(&parent, &name, libc::O_RDONLY, 0)
        .with_context(|| format!("open provisioner input {}", path.display()))?;
    let metadata = file.metadata()?;
    validate_regular_metadata(
        &file,
        effective_uid(),
        if exact_mode == 0 {
            metadata.mode() & 0o7777
        } else {
            exact_mode
        },
        "provisioner input",
    )?;
    if private {
        anyhow::ensure!(
            metadata.mode() & 0o7777 == 0o600,
            "private input must have exact mode 0600"
        );
    } else {
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0,
            "public input is writable by another user"
        );
    }
    read_stable_file(&file, maximum)
}

fn write_new_file_at(directory: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let name = c_name(name)?;
    let mut file = open_file_at(
        directory,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        mode,
    )
    .context("create provisioner artifact")?;
    set_file_mode(&file, mode)?;
    file.write_all(bytes)
        .context("write provisioner artifact")?;
    file.sync_all().context("sync provisioner artifact")?;
    validate_regular_metadata(&file, effective_uid(), mode, "new provisioner artifact")?;
    file.seek(SeekFrom::Start(0))?;
    let mut observed = Vec::new();
    file.take(bytes.len().saturating_add(1) as u64)
        .read_to_end(&mut observed)?;
    anyhow::ensure!(
        observed == bytes,
        "new provisioner artifact changed while written"
    );
    Ok(())
}

fn read_regular_at(
    directory: &File,
    name: &str,
    expected_uid: u32,
    mode: u32,
    maximum: usize,
) -> Result<Vec<u8>> {
    let name = c_name(name)?;
    let file =
        open_file_at(directory, &name, libc::O_RDONLY, 0).context("open Node identity artifact")?;
    validate_regular_metadata(&file, expected_uid, mode, "Node identity artifact")?;
    read_stable_file(&file, maximum)
}

fn sync_regular_at(directory: &File, name: &str, expected_uid: u32, mode: u32) -> Result<()> {
    let name = c_name(name)?;
    let file = open_file_at(directory, &name, libc::O_RDONLY, 0)
        .context("open provisioner artifact for sync")?;
    validate_regular_metadata(&file, expected_uid, mode, "provisioner artifact for sync")?;
    file.sync_all().context("sync provisioner artifact")
}

fn read_stable_file(file: &File, maximum: usize) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "artifact exceeds its closed byte limit"
    );
    let after = file.metadata()?;
    anyhow::ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "artifact changed while being read"
    );
    Ok(bytes)
}

fn validate_regular_metadata(
    file: &File,
    expected_uid: u32,
    mode: u32,
    description: &str,
) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "{description} is not a regular file"
    );
    anyhow::ensure!(
        metadata.uid() == expected_uid,
        "{description} has the wrong owner"
    );
    anyhow::ensure!(
        metadata.gid() == effective_gid(),
        "{description} has the wrong group"
    );
    anyhow::ensure!(metadata.nlink() == 1, "{description} is not single-link");
    anyhow::ensure!(
        metadata.mode() & 0o7777 == mode,
        "{description} has the wrong mode"
    );
    Ok(())
}

fn validate_directory(
    directory: &File,
    expected_uid: u32,
    exact_mode: Option<u32>,
    description: &str,
) -> Result<()> {
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "{description} is not a directory"
    );
    anyhow::ensure!(
        metadata.uid() == expected_uid,
        "{description} has the wrong owner"
    );
    anyhow::ensure!(
        metadata.gid() == effective_gid(),
        "{description} has the wrong group"
    );
    if let Some(exact_mode) = exact_mode {
        anyhow::ensure!(
            metadata.mode() & 0o7777 == exact_mode,
            "{description} has the wrong mode"
        );
    } else {
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0,
            "{description} is writable by another user"
        );
    }
    Ok(())
}

fn open_or_create_protected_directory(
    parent: &File,
    name: &str,
    created_mode: u32,
    exact_mode: Option<u32>,
    expected_uid: u32,
) -> Result<File> {
    let name = c_name(name)?;
    let (directory, created) =
        match open_file_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(directory) => (directory, false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match mkdir_at(parent, &name, created_mode as libc::mode_t) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(error).context("create protected provisioner directory")
                    }
                }
                sync_directory(parent, "sync protected provisioner directory parent")?;
                (
                    open_file_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                        .context("open newly created protected provisioner directory")?,
                    true,
                )
            }
            Err(error) => return Err(error).context("open protected provisioner directory"),
        };
    if created {
        set_file_mode(&directory, created_mode)?;
        directory
            .sync_all()
            .context("sync newly created protected provisioner directory")?;
        sync_directory(parent, "sync protected provisioner directory parent")?;
    }
    validate_directory(
        &directory,
        expected_uid,
        exact_mode,
        "protected provisioner directory",
    )?;
    Ok(directory)
}

fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    // SAFETY: fchmod only changes metadata on the retained live descriptor.
    let result = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context("set provisioner artifact mode")
    }
}

fn entry_exists(directory: &File, name: &str) -> Result<bool> {
    let name = c_name(name)?;
    match open_file_at(directory, &name, libc::O_RDONLY, 0) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect provisioner entry"),
    }
}

fn list_directory_names(directory: &File) -> Result<BTreeSet<OsString>> {
    // SAFETY: dup returns a new owned descriptor or -1; ownership transfers to
    // fdopendir below on success.
    let duplicated = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error()).context("duplicate directory descriptor");
    }
    // SAFETY: duplicated is a fresh directory descriptor. fdopendir owns it on
    // success; on failure we close it below.
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe { libc::close(duplicated) };
        return Err(io::Error::last_os_error()).context("open directory stream");
    }
    // SAFETY: the stream is live. `dup` shares a directory offset with the
    // retained descriptor, so every bounded enumeration must rewind first.
    unsafe { libc::rewinddir(stream) };
    let mut names = BTreeSet::new();
    loop {
        // SAFETY: stream remains valid until closedir below. readdir returns a
        // pointer valid until the next call, which is copied immediately.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is a NUL-terminated array supplied by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.insert(OsString::from_vec(name.to_vec()));
    }
    // SAFETY: stream is live and closed exactly once here.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(io::Error::last_os_error()).context("close directory stream");
    }
    Ok(names)
}

fn c_name(value: &str) -> Result<CString> {
    CString::new(value.as_bytes()).context("provisioner entry contains NUL")
}

fn sha256_wire(bytes: &[u8]) -> String {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into()).to_string()
}

fn report<T: Serialize>(cli: &Cli, value: &T) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        let value = serde_json::to_value(value)?;
        let object = value
            .as_object()
            .context("provisioner receipt is not an object")?;
        for (key, value) in object {
            let rendered = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            println!("{key}={rendered}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdminCommand, Command};
    use clap::Parser as _;
    use tempfile::TempDir;

    fn node_command(root: &Path, command: RuntimeProvisionerNodeIdentityCommand) -> Result<()> {
        let cli = Cli::parse_from([
            "cats",
            "admin",
            "runtime-provisioner",
            "node-identity",
            "export",
        ]);
        run_node_identity(&cli, &command, root, effective_uid())
    }

    #[test]
    fn trust_generation_is_canonical_idempotent_and_private() {
        let temp = TempDir::new().unwrap();
        let key = temp.path().join("provisioner.pem");
        let bundle = temp.path().join("trust.json");
        let cli = Cli::parse_from([
            "cats",
            "--json",
            "admin",
            "runtime-provisioner",
            "trust",
            "generate",
            "--deployment-id",
            "deployment_a",
            "--credential-id",
            "provisioner_a",
            "--private-key-out",
            key.to_str().unwrap(),
            "--trust-bundle-out",
            bundle.to_str().unwrap(),
        ]);
        let Command::Admin {
            cmd: AdminCommand::RuntimeProvisioner { cmd },
        } = &cli.command
        else {
            panic!("wrong command")
        };
        run(&cli, cmd).unwrap();
        let first_key = std::fs::read(&key).unwrap();
        let first_bundle = std::fs::read(&bundle).unwrap();
        run(&cli, cmd).unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), first_key);
        assert_eq!(std::fs::read(&bundle).unwrap(), first_bundle);
        assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o7777, 0o600);
        let decoded = decode_runtime_provisioner_trust_bundle(&first_bundle).unwrap();
        assert_eq!(
            encode_runtime_provisioner_trust_bundle(&decoded).unwrap(),
            first_bundle
        );
        assert!(!first_bundle
            .windows(16)
            .any(|window| window == b"BEGIN PRIVATE KEY"));

        let verify = RuntimeProvisionerCommand::Trust {
            cmd: RuntimeProvisionerTrustCommand::Verify {
                credential_id: "provisioner_a".to_owned(),
                private_key: key.clone(),
                trust_bundle: bundle.clone(),
            },
        };
        run(&cli, &verify).unwrap();
        let mut noncanonical = first_bundle;
        noncanonical.push(b'\n');
        std::fs::write(&bundle, noncanonical).unwrap();
        assert!(run(&cli, &verify).is_err());
    }

    #[test]
    fn prepare_replays_complete_marker_and_rejects_field_drift() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let prepare = RuntimeProvisionerNodeIdentityCommand::Prepare {
            node_id: "node_a".to_owned(),
            immutable_host_id: "host_a".to_owned(),
            state_path_id: "state_path_a".to_owned(),
            credential_id: "credential_a".to_owned(),
        };
        node_command(root, prepare).unwrap();
        let marker = root.join(format!("etc/cats/identity/{INITIAL_SET}"));
        let first_key = std::fs::read(marker.join(PRIVATE_KEY_FILE)).unwrap();
        node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Prepare {
                node_id: "node_a".to_owned(),
                immutable_host_id: "host_a".to_owned(),
                state_path_id: "state_path_a".to_owned(),
                credential_id: "credential_a".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(marker.join(PRIVATE_KEY_FILE)).unwrap(),
            first_key
        );
        assert!(node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Prepare {
                node_id: "node_b".to_owned(),
                immutable_host_id: "host_a".to_owned(),
                state_path_id: "state_path_a".to_owned(),
                credential_id: "credential_a".to_owned(),
            },
        )
        .is_err());
        assert_eq!(
            std::fs::read(marker.join(PRIVATE_KEY_FILE)).unwrap(),
            first_key
        );
    }

    #[test]
    fn prepare_recovers_only_a_closed_partial_incomplete_set() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let identity_dir = root.join("etc/cats/identity");
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::set_permissions(
            &identity_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let incomplete = identity_dir.join(INCOMPLETE_SET);
        std::fs::create_dir(&incomplete).unwrap();
        std::fs::set_permissions(
            &incomplete,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(incomplete.join(CREDENTIAL_ID_FILE), b"partial").unwrap();
        std::fs::set_permissions(
            incomplete.join(CREDENTIAL_ID_FILE),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Prepare {
                node_id: "node_a".to_owned(),
                immutable_host_id: "host_a".to_owned(),
                state_path_id: "state_path_a".to_owned(),
                credential_id: "credential_a".to_owned(),
            },
        )
        .unwrap();
        assert!(identity_dir.join(INITIAL_SET).is_dir());

        let another = TempDir::new().unwrap();
        let another_identity = another.path().join("etc/cats/identity");
        std::fs::create_dir_all(another_identity.join(INCOMPLETE_SET)).unwrap();
        std::fs::set_permissions(
            &another_identity,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            another_identity.join(INCOMPLETE_SET),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(
            another_identity.join(INCOMPLETE_SET).join("unexpected"),
            b"do not delete",
        )
        .unwrap();
        assert!(node_command(
            another.path(),
            RuntimeProvisionerNodeIdentityCommand::Prepare {
                node_id: "node_a".to_owned(),
                immutable_host_id: "host_a".to_owned(),
                state_path_id: "state_path_a".to_owned(),
                credential_id: "credential_a".to_owned(),
            },
        )
        .is_err());
        assert_eq!(
            std::fs::read(another_identity.join(INCOMPLETE_SET).join("unexpected")).unwrap(),
            b"do not delete"
        );
    }

    #[test]
    fn prepare_export_activate_is_crash_replay_safe_and_artifact_last() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let prepare = RuntimeProvisionerNodeIdentityCommand::Prepare {
            node_id: "node_a".to_owned(),
            immutable_host_id: "host_a".to_owned(),
            state_path_id: "state_path_a".to_owned(),
            credential_id: "credential_a".to_owned(),
        };
        node_command(root, prepare).unwrap();
        let recovery = root.join(format!("etc/cats/identity/{INITIAL_SET}"));
        let identity = std::fs::read(recovery.join(IDENTITY_FILE)).unwrap();

        // Simulate a crash after the private key was activated but before the
        // credential ID and identity complete marker.
        let active_dir = root.join("etc/cats/identity");
        std::fs::copy(
            recovery.join(PRIVATE_KEY_FILE),
            active_dir.join(PRIVATE_KEY_FILE),
        )
        .unwrap();
        std::fs::set_permissions(
            active_dir.join(PRIVATE_KEY_FILE),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let result = cats_api::runtime_reconciliation::RuntimeNodeAuthorityApplyResult {
            version: ContractVersion::V1,
            apply_id: cats_api::runtime_reconciliation::RandomId128::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            node_id: Id::new("node_a").unwrap(),
            outcome: RuntimeNodeAuthorityOutcome::Provisioned,
            identity_state: NodeIdentityState::Provisioned,
            policy_revision: Epoch::new(1).unwrap(),
        };
        let result_path = temp.path().join("apply-result.json");
        std::fs::write(
            &result_path,
            encode_runtime_node_authority_apply_result(&result).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            &result_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Activate {
                apply_result: result_path,
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(active_dir.join(IDENTITY_FILE)).unwrap(),
            identity
        );
        assert!(!recovery.exists());
        assert!(root.join("var/lib/cats/node/state_path_a").is_dir());
    }

    #[test]
    fn activation_recovers_after_crash_during_recovery_set_deletion() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Prepare {
                node_id: "node_a".to_owned(),
                immutable_host_id: "host_a".to_owned(),
                state_path_id: "state_path_a".to_owned(),
                credential_id: "credential_a".to_owned(),
            },
        )
        .unwrap();
        let active_dir = root.join("etc/cats/identity");
        let recovery = active_dir.join(INITIAL_SET);
        for name in [PRIVATE_KEY_FILE, CREDENTIAL_ID_FILE, IDENTITY_FILE] {
            std::fs::copy(recovery.join(name), active_dir.join(name)).unwrap();
            std::fs::set_permissions(
                active_dir.join(name),
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )
            .unwrap();
        }
        // Simulate a crash after the complete active marker was durable and
        // the first recovery entry had already been removed.
        std::fs::remove_file(recovery.join(PRIVATE_KEY_FILE)).unwrap();

        let result = cats_api::runtime_reconciliation::RuntimeNodeAuthorityApplyResult {
            version: ContractVersion::V1,
            apply_id: cats_api::runtime_reconciliation::RandomId128::new(
                "cccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            node_id: Id::new("node_a").unwrap(),
            outcome: RuntimeNodeAuthorityOutcome::Provisioned,
            identity_state: NodeIdentityState::Provisioned,
            policy_revision: Epoch::new(1).unwrap(),
        };
        let result_path = temp.path().join("apply-result.json");
        std::fs::write(
            &result_path,
            encode_runtime_node_authority_apply_result(&result).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            &result_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Activate {
                apply_result: result_path,
            },
        )
        .unwrap();
        assert!(!recovery.exists());
        assert!(active_dir.join(IDENTITY_FILE).exists());
        assert!(root.join("var/lib/cats/node/state_path_a").is_dir());
    }

    #[test]
    fn activation_rejects_wrong_or_noncanonical_result_before_active_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Prepare {
                node_id: "node_a".to_owned(),
                immutable_host_id: "host_a".to_owned(),
                state_path_id: "state_path_a".to_owned(),
                credential_id: "credential_a".to_owned(),
            },
        )
        .unwrap();
        let result_path = temp.path().join("bad-result.json");
        let wrong_node = cats_api::runtime_reconciliation::RuntimeNodeAuthorityApplyResult {
            version: ContractVersion::V1,
            apply_id: cats_api::runtime_reconciliation::RandomId128::new(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            node_id: Id::new("node_b").unwrap(),
            outcome: RuntimeNodeAuthorityOutcome::Provisioned,
            identity_state: NodeIdentityState::Provisioned,
            policy_revision: Epoch::new(1).unwrap(),
        };
        std::fs::write(
            &result_path,
            encode_runtime_node_authority_apply_result(&wrong_node).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            &result_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Activate {
                apply_result: result_path.clone(),
            },
        )
        .is_err());
        assert!(!root
            .join(format!("etc/cats/identity/{IDENTITY_FILE}"))
            .exists());

        std::fs::write(
            &result_path,
            br#"{ "version": 1, "apply_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }"#,
        )
        .unwrap();
        std::fs::set_permissions(
            &result_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(node_command(
            root,
            RuntimeProvisionerNodeIdentityCommand::Activate {
                apply_result: result_path,
            },
        )
        .is_err());
        assert!(!root
            .join(format!("etc/cats/identity/{IDENTITY_FILE}"))
            .exists());
    }
}

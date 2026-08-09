//! Durable A23 Runtime Node-authority CLI state machine.
//!
//! The local pending record is authority for retries.  It is published before
//! the first HTTP send and contains no signing key or access token.  Only the
//! two terminal responses frozen by A23 can publish a resolution receipt and
//! durably remove that pending record.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
use cats_api::runtime_node_authority::{
    sign_runtime_node_authority_request, NODE_AUTHORITY_APPLY_ID_HEADER,
    PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_SIGNATURE_HEADER, RUNTIME_NODE_AUTHORITY_PATH,
};
use cats_api::runtime_reconciliation::{
    decode_node_identity, decode_node_placement_policy, decode_runtime_node_authority_apply,
    decode_runtime_node_authority_apply_result, encode_node_identity, encode_node_placement_policy,
    encode_runtime_node_authority_apply, encode_runtime_node_authority_apply_result,
    ContractVersion, Epoch, Id, NodeIdentity, NodeIdentityState, NodePlacementPolicy, RandomId128,
    RuntimeNodeAuthorityApply, RuntimeNodeAuthorityApplyResult, RuntimeNodeAuthorityMutation,
    RuntimeNodeAuthorityOutcome, NODE_IDENTITY_MAX_WIRE_BYTES,
    NODE_PLACEMENT_POLICY_MAX_WIRE_BYTES, RUNTIME_NODE_AUTHORITY_APPLY_MAX_WIRE_BYTES,
    RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    auth, config, Cli, RuntimeNodeAuthorityAuth, RuntimeNodeCommand, RuntimeNodeCredentialCommand,
    RuntimeNodePolicyCommand,
};

const STATE_VERSION: u32 = 1;
const METHOD: &str = "POST";
const PENDING_MAX_BYTES: usize = 100_000;
const RECEIPT_MAX_BYTES: usize = 64_000;
const SETTLED_INDEX_MAX_BYTES: usize = 8_192;
const PRIVATE_KEY_MAX_BYTES: usize = 16_384;
const ERROR_BODY_MAX_BYTES: usize = 20_480;
const RESPONSE_READ_LIMIT: usize = ERROR_BODY_MAX_BYTES + 1;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const AUTHORITY_PRECONDITION_FAILED: &[u8] = br#"{"code":"authority_precondition_failed","message":"runtime node authority precondition failed"}"#;
const APPLY_ID_CONFLICT: &[u8] = br#"{"code":"apply_id_conflict","message":"runtime node authority apply ID conflicts with another request"}"#;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    version: u32,
    origin: String,
    method: String,
    target: String,
    content_type: String,
    apply_id: String,
    node_id: String,
    request_sha256: String,
    body_base64: String,
}

impl PendingRecord {
    fn from_apply(origin: &str, apply: &RuntimeNodeAuthorityApply) -> Result<Self> {
        let body = encode_runtime_node_authority_apply(apply)
            .map_err(|error| anyhow!("encode Runtime Node authority request: {error:?}"))?;
        Ok(Self {
            version: STATE_VERSION,
            origin: validate_https_origin(origin)?,
            method: METHOD.to_owned(),
            target: RUNTIME_NODE_AUTHORITY_PATH.to_owned(),
            content_type: JSON_CONTENT_TYPE.to_owned(),
            apply_id: apply.apply_id.as_str().to_owned(),
            node_id: apply.node_id.as_str().to_owned(),
            request_sha256: sha256_digest(&body),
            body_base64: URL_SAFE_NO_PAD.encode(body),
        })
    }

    fn body(&self) -> Result<Vec<u8>> {
        decode_canonical_base64(&self.body_base64)
            .context("pending Runtime Node authority body is not canonical base64url")
    }

    fn apply(&self) -> Result<RuntimeNodeAuthorityApply> {
        let body = self.body()?;
        let apply = decode_runtime_node_authority_apply(&body).map_err(|error| {
            anyhow!("pending Runtime Node authority request is invalid: {error:?}")
        })?;
        let canonical = encode_runtime_node_authority_apply(&apply).map_err(|error| {
            anyhow!("re-encode pending Runtime Node authority request: {error:?}")
        })?;
        anyhow::ensure!(
            canonical == body,
            "pending Runtime Node authority body is not canonical"
        );
        anyhow::ensure!(
            self.version == STATE_VERSION
                && self.method == METHOD
                && self.target == RUNTIME_NODE_AUTHORITY_PATH
                && self.content_type == JSON_CONTENT_TYPE
                && self.apply_id == apply.apply_id.as_str()
                && self.node_id == apply.node_id.as_str()
                && self.request_sha256 == sha256_digest(&body),
            "pending Runtime Node authority record is internally inconsistent"
        );
        validate_https_origin(&self.origin)?;
        Ok(apply)
    }

    /// Recover the command-level binding without changing the V1 pending
    /// schema. Official provision/policy commands generate apply IDs, while
    /// rotate/retire files carry an exact caller-selected apply ID.
    fn settled_binding(&self) -> Result<SettledBinding> {
        let apply = self.apply()?;
        match &apply.mutation {
            RuntimeNodeAuthorityMutation::Provision { .. }
            | RuntimeNodeAuthorityMutation::UpdatePolicy { .. } => Ok(SettledBinding {
                kind: SettledBindingKind::GeneratedMutation,
                sha256: mutation_digest(&apply)?,
            }),
            RuntimeNodeAuthorityMutation::RotateCredential { .. }
            | RuntimeNodeAuthorityMutation::Retire { .. } => Ok(SettledBinding {
                kind: SettledBindingKind::ExactApply,
                sha256: self.request_sha256.clone(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HeaderOccurrence {
    name: String,
    value_base64: String,
}

impl HeaderOccurrence {
    fn new(name: &str, value: &[u8]) -> Self {
        Self {
            name: name.to_ascii_lowercase(),
            value_base64: URL_SAFE_NO_PAD.encode(value),
        }
    }

    fn value(&self) -> Result<Vec<u8>> {
        decode_canonical_base64(&self.value_base64)
            .context("resolution receipt contains an invalid header value")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredHttpResponse {
    status: u16,
    headers: Vec<HeaderOccurrence>,
    body_base64: String,
}

impl StoredHttpResponse {
    fn body(&self) -> Result<Vec<u8>> {
        decode_canonical_base64(&self.body_base64)
            .context("resolution receipt contains an invalid response body")
    }

    fn header_values(&self, name: &str) -> Result<Vec<Vec<u8>>> {
        self.headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name))
            .map(HeaderOccurrence::value)
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResolutionReceipt {
    version: u32,
    apply_id: String,
    node_id: String,
    request_sha256: String,
    response: StoredHttpResponse,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SettledIndex {
    version: u32,
    origin: String,
    node_id: String,
    binding_kind: SettledBindingKind,
    binding_sha256: String,
    apply_id: String,
    request_sha256: String,
}

impl SettledIndex {
    fn from_pending(pending: &PendingRecord) -> Result<Self> {
        let binding = pending.settled_binding()?;
        Ok(Self {
            version: STATE_VERSION,
            origin: validate_https_origin(&pending.origin)?,
            node_id: pending.node_id.clone(),
            binding_kind: binding.kind,
            binding_sha256: binding.sha256,
            apply_id: pending.apply_id.clone(),
            request_sha256: pending.request_sha256.clone(),
        })
    }

    fn binds(&self, origin: &str, desired: &DesiredApply) -> Result<bool> {
        let origin = validate_https_origin(origin)?;
        let binding = desired.binding()?;
        Ok(self.version == STATE_VERSION
            && self.origin == origin
            && self.node_id == desired.node_id().as_str()
            && self.binding_kind == binding.kind
            && self.binding_sha256 == binding.sha256)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SettledBindingKind {
    GeneratedMutation,
    ExactApply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SettledBinding {
    kind: SettledBindingKind,
    sha256: String,
}

enum DesiredApply {
    Generated {
        node_id: Id,
        mutation: RuntimeNodeAuthorityMutation,
    },
    Exact(RuntimeNodeAuthorityApply),
}

impl DesiredApply {
    fn node_id(&self) -> &Id {
        match self {
            Self::Generated { node_id, .. } => node_id,
            Self::Exact(apply) => &apply.node_id,
        }
    }

    fn materialize(&self, existing: Option<&PendingRecord>) -> Result<RuntimeNodeAuthorityApply> {
        if let Some(existing) = existing {
            let apply = existing.apply()?;
            match self {
                Self::Generated { node_id, mutation } => anyhow::ensure!(
                    &apply.node_id == node_id && &apply.mutation == mutation,
                    "a different unresolved Runtime Node authority request already exists for {}",
                    node_id
                ),
                Self::Exact(expected) => anyhow::ensure!(
                    &apply == expected,
                    "a different unresolved Runtime Node authority request already exists for {}",
                    expected.node_id
                ),
            }
            return Ok(apply);
        }
        match self {
            Self::Generated { node_id, mutation } => Ok(RuntimeNodeAuthorityApply {
                version: ContractVersion::V1,
                apply_id: fresh_apply_id()?,
                node_id: node_id.clone(),
                mutation: mutation.clone(),
            }),
            Self::Exact(apply) => Ok(apply.clone()),
        }
    }

    fn binding(&self) -> Result<SettledBinding> {
        match self {
            Self::Generated { node_id, mutation } => Ok(SettledBinding {
                kind: SettledBindingKind::GeneratedMutation,
                sha256: mutation_digest(&RuntimeNodeAuthorityApply {
                    version: ContractVersion::V1,
                    apply_id: zero_apply_id()?,
                    node_id: node_id.clone(),
                    mutation: mutation.clone(),
                })?,
            }),
            Self::Exact(apply) => {
                let bytes = encode_runtime_node_authority_apply(apply).map_err(|error| {
                    anyhow!("encode exact Runtime Node authority binding: {error:?}")
                })?;
                Ok(SettledBinding {
                    kind: SettledBindingKind::ExactApply,
                    sha256: sha256_digest(&bytes),
                })
            }
        }
    }

    fn with_apply_id(&self, apply_id: RandomId128) -> RuntimeNodeAuthorityApply {
        match self {
            Self::Generated { node_id, mutation } => RuntimeNodeAuthorityApply {
                version: ContractVersion::V1,
                apply_id,
                node_id: node_id.clone(),
                mutation: mutation.clone(),
            },
            Self::Exact(apply) => RuntimeNodeAuthorityApply {
                version: apply.version,
                apply_id,
                node_id: apply.node_id.clone(),
                mutation: apply.mutation.clone(),
            },
        }
    }
}

struct PendingState {
    display_root: PathBuf,
    state_root: StateRoot,
    _lock: File,
    lock_directory: File,
    lock_name: CString,
    lock_identity: FileIdentity,
    slot: String,
}

impl PendingState {
    fn acquire(root: &Path, node_id: &Id) -> Result<Self> {
        let state_root = StateRoot::open_or_create(root)?;
        let slot = hex_digest(node_id.as_str().as_bytes());
        let lock_directory = open_global_lock_directory()?;
        let namespace = state_path_namespace(root)?;
        let lock_name = c_name(&format!(
            ".cats-runtime-node-authority-{}-{namespace}-{slot}.lock",
            effective_uid()
        ))?;
        let (lock, lock_created) = open_state_lock(&lock_directory, &lock_name)?;
        FileExt::lock_exclusive(&lock)
            .with_context(|| format!("lock Runtime Node authority state for {node_id}"))?;
        validate_private_regular_file_descriptor(&lock, lock_name.to_string_lossy().as_ref())?;
        let lock_metadata = lock.metadata()?;
        anyhow::ensure!(
            lock_metadata.nlink() == 1 && lock_metadata.mode() & 0o7777 == 0o600,
            "Runtime Node authority lock is not a private single-link file"
        );
        if lock_created {
            lock_directory
                .sync_all()
                .context("sync global Runtime Node authority lock directory")?;
        }
        let state = Self {
            display_root: root.to_owned(),
            lock_identity: FileIdentity::of(&lock)?,
            lock_name,
            lock_directory,
            _lock: lock,
            state_root,
            slot,
        };
        state.assert_current_authority()?;
        Ok(state)
    }

    fn pending_name(&self) -> Result<CString> {
        c_name(&format!("node-{}.pending.json", self.slot))
    }

    fn pending_path(&self) -> PathBuf {
        self.display_root
            .join(format!("node-{}.pending.json", self.slot))
    }

    fn receipt_name(&self, apply_id: &str) -> Result<CString> {
        c_name(&format!("node-{}.{}.resolution.json", self.slot, apply_id))
    }

    fn settled_name(&self, origin: &str, binding: &SettledBinding) -> Result<CString> {
        let digest = settled_lookup_digest(origin, binding)?;
        let kind = match binding.kind {
            SettledBindingKind::GeneratedMutation => "generated",
            SettledBindingKind::ExactApply => "exact",
        };
        c_name(&format!("node-{}.{kind}-{digest}.settled.json", self.slot))
    }

    fn assert_current_authority(&self) -> Result<()> {
        self.state_root.assert_current()?;
        let current_lock = identity_at(
            &self.lock_directory,
            &self.lock_name,
            libc::AT_SYMLINK_NOFOLLOW,
        )?;
        anyhow::ensure!(
            current_lock == self.lock_identity,
            "Runtime Node authority lock identity changed"
        );
        Ok(())
    }

    fn load_pending(&self) -> Result<Option<PendingRecord>> {
        let name = self.pending_name()?;
        cleanup_publish_temp(&self.state_root.directory, &name)?;
        let Some(bytes) =
            read_optional_state_file(&self.state_root.directory, &name, PENDING_MAX_BYTES)?
        else {
            return Ok(None);
        };
        let pending: PendingRecord =
            serde_json::from_slice(&bytes).context("parse pending Runtime Node authority state")?;
        anyhow::ensure!(
            serde_json::to_vec(&pending)? == bytes,
            "pending Runtime Node authority state is not canonical"
        );
        pending.apply()?;
        Ok(Some(pending))
    }

    fn prepare(&self, origin: &str, desired: &DesiredApply) -> Result<PendingRecord> {
        let existing = self.load_pending()?;
        if let Some(existing) = existing {
            desired.materialize(Some(&existing))?;
            anyhow::ensure!(
                existing.settled_binding()? == desired.binding()?,
                "the unresolved Runtime Node authority request has an incompatible apply-ID policy"
            );
            anyhow::ensure!(
                validate_https_origin(&existing.origin)? == validate_https_origin(origin)?,
                "the unresolved Runtime Node authority request is bound to a different origin or body"
            );
            return Ok(existing);
        }
        let apply = desired.materialize(None)?;
        let candidate = PendingRecord::from_apply(origin, &apply)?;
        anyhow::ensure!(
            candidate.settled_binding()? == desired.binding()?,
            "Runtime Node authority command has an incompatible apply-ID policy"
        );
        let bytes = serde_json::to_vec(&candidate)?;
        anyhow::ensure!(
            bytes.len() <= PENDING_MAX_BYTES,
            "pending state exceeds its bound"
        );
        publish_new(&self.state_root.directory, &self.pending_name()?, &bytes)?;
        Ok(candidate)
    }

    fn recover_resolution(&self, pending: &PendingRecord) -> Result<Option<TerminalOutcome>> {
        let Some((receipt, terminal)) = self.load_receipt(pending)? else {
            return Ok(None);
        };
        self.publish_settled_index(pending, &receipt)?;
        self.delete_pending()?;
        Ok(Some(terminal))
    }

    fn recover_settled(
        &self,
        origin: &str,
        desired: &DesiredApply,
    ) -> Result<Option<TerminalOutcome>> {
        let binding = desired.binding()?;
        let name = self.settled_name(origin, &binding)?;
        cleanup_publish_temp(&self.state_root.directory, &name)?;
        let Some(bytes) =
            read_optional_state_file(&self.state_root.directory, &name, SETTLED_INDEX_MAX_BYTES)?
        else {
            return Ok(None);
        };
        let index: SettledIndex =
            serde_json::from_slice(&bytes).context("parse settled Runtime Node authority index")?;
        anyhow::ensure!(
            serde_json::to_vec(&index)? == bytes,
            "settled Runtime Node authority index is not canonical"
        );
        anyhow::ensure!(
            index.binds(origin, desired)?,
            "settled Runtime Node authority index does not bind its direct lookup key"
        );
        let settled_apply_id =
            RandomId128::new(index.apply_id.clone()).context("settled apply ID is invalid")?;
        let apply = desired.with_apply_id(settled_apply_id);
        let pending = PendingRecord {
            version: STATE_VERSION,
            origin: index.origin.clone(),
            method: METHOD.to_owned(),
            target: RUNTIME_NODE_AUTHORITY_PATH.to_owned(),
            content_type: JSON_CONTENT_TYPE.to_owned(),
            apply_id: index.apply_id.clone(),
            node_id: index.node_id.clone(),
            request_sha256: index.request_sha256.clone(),
            body_base64: URL_SAFE_NO_PAD.encode(
                encode_runtime_node_authority_apply(&apply)
                    .map_err(|error| anyhow!("encode settled Runtime Node request: {error:?}"))?,
            ),
        };
        pending.apply()?;
        let recovered_binding = pending.settled_binding()?;
        anyhow::ensure!(
            recovered_binding.kind == index.binding_kind
                && recovered_binding.sha256 == index.binding_sha256,
            "settled Runtime Node authority index has an inconsistent binding"
        );
        let Some((_receipt, terminal)) = self.load_receipt(&pending)? else {
            bail!("settled Runtime Node authority index points to a missing receipt")
        };
        Ok(Some(terminal))
    }

    fn load_receipt(
        &self,
        pending: &PendingRecord,
    ) -> Result<Option<(ResolutionReceipt, TerminalOutcome)>> {
        let name = self.receipt_name(&pending.apply_id)?;
        cleanup_publish_temp(&self.state_root.directory, &name)?;
        let Some(bytes) =
            read_optional_state_file(&self.state_root.directory, &name, RECEIPT_MAX_BYTES)?
        else {
            return Ok(None);
        };
        let receipt: ResolutionReceipt = serde_json::from_slice(&bytes)
            .context("parse Runtime Node authority resolution receipt")?;
        anyhow::ensure!(
            serde_json::to_vec(&receipt)? == bytes,
            "Runtime Node authority resolution receipt is not canonical"
        );
        anyhow::ensure!(
            receipt.version == STATE_VERSION
                && receipt.apply_id == pending.apply_id
                && receipt.node_id == pending.node_id
                && receipt.request_sha256 == pending.request_sha256,
            "resolution receipt does not bind the pending request"
        );
        validate_stored_response(&receipt.response)?;
        let terminal = match classify_response(pending, &receipt.response)? {
            ResponseClassification::Terminal(terminal) => terminal,
            _ => bail!("resolution receipt does not contain a terminal response"),
        };
        Ok(Some((receipt, terminal)))
    }

    fn settle(
        &self,
        pending: &PendingRecord,
        response: StoredHttpResponse,
    ) -> Result<TerminalOutcome> {
        let terminal = match classify_response(pending, &response)? {
            ResponseClassification::Terminal(terminal) => terminal,
            _ => bail!("refusing to settle a nonterminal Runtime Node authority response"),
        };
        let receipt = ResolutionReceipt {
            version: STATE_VERSION,
            apply_id: pending.apply_id.clone(),
            node_id: pending.node_id.clone(),
            request_sha256: pending.request_sha256.clone(),
            response,
        };
        let bytes = serde_json::to_vec(&receipt)?;
        anyhow::ensure!(
            bytes.len() <= RECEIPT_MAX_BYTES,
            "resolution receipt exceeds its bound"
        );
        let name = self.receipt_name(&pending.apply_id)?;
        match publish_new(&self.state_root.directory, &name, &bytes) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
            {
                let existing =
                    read_optional_state_file(&self.state_root.directory, &name, RECEIPT_MAX_BYTES)?
                        .context("resolution receipt disappeared")?;
                anyhow::ensure!(
                    existing == bytes,
                    "a different resolution receipt already exists for apply {}",
                    pending.apply_id
                );
            }
            Err(error) => return Err(error),
        }
        self.publish_settled_index(pending, &receipt)?;
        self.delete_pending()?;
        Ok(terminal)
    }

    fn publish_settled_index(
        &self,
        pending: &PendingRecord,
        receipt: &ResolutionReceipt,
    ) -> Result<()> {
        anyhow::ensure!(
            receipt.apply_id == pending.apply_id
                && receipt.node_id == pending.node_id
                && receipt.request_sha256 == pending.request_sha256,
            "cannot index a receipt for a different pending request"
        );
        let index = SettledIndex::from_pending(pending)?;
        let bytes = serde_json::to_vec(&index)?;
        anyhow::ensure!(
            bytes.len() <= SETTLED_INDEX_MAX_BYTES,
            "settled Runtime Node authority index exceeds its bound"
        );
        let binding = SettledBinding {
            kind: index.binding_kind,
            sha256: index.binding_sha256.clone(),
        };
        let name = self.settled_name(&index.origin, &binding)?;
        match publish_new(&self.state_root.directory, &name, &bytes) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
            {
                let existing = read_optional_state_file(
                    &self.state_root.directory,
                    &name,
                    SETTLED_INDEX_MAX_BYTES,
                )?
                .context("settled Runtime Node authority index disappeared")?;
                anyhow::ensure!(
                    existing == bytes,
                    "a different settled Runtime Node authority index already exists"
                );
            }
            Err(error) => return Err(error),
        }
        // This unconditional barrier also covers the EEXIST-same recovery
        // path. It orders both the immutable receipt and its direct index
        // before the subsequent pending unlink; `delete_pending` supplies the
        // second directory barrier after that unlink.
        self.state_root
            .directory
            .sync_all()
            .context("sync settled receipt and index before pending deletion")
    }

    fn delete_pending(&self) -> Result<()> {
        let name = self.pending_name()?;
        match unlink_at(&self.state_root.directory, &name) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove pending Runtime Node authority state"),
        }
        self.state_root
            .directory
            .sync_all()
            .context("sync Runtime Node authority state directory")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TerminalOutcome {
    Applied(RuntimeNodeAuthorityApplyResult),
    AuthorityPreconditionFailed,
}

enum ResponseClassification {
    Terminal(TerminalOutcome),
    ApplyIdConflict,
    Nonterminal,
}

enum RequestAuthority {
    FleetAdministrator {
        access_token: String,
    },
    DeploymentProvisioner {
        deployment_id: Id,
        signer: Ed25519RequestSigner,
    },
}

enum PreparedApply {
    Terminal(TerminalOutcome),
    Pending(PendingRecord),
}

struct OutboundRequest {
    method: &'static str,
    url: String,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

trait AuthorityTransport {
    fn send(&self, request: OutboundRequest) -> Result<StoredHttpResponse>;
}

struct ReqwestAuthorityTransport;

pub(crate) fn run(
    cli: &Cli,
    authority: &RuntimeNodeAuthorityAuth<'_>,
    command: &RuntimeNodeCommand,
) -> Result<()> {
    anyhow::ensure!(
        cli.workspace.is_none(),
        "Runtime Node authority is fleet-scoped, not Workspace-scoped; remove --workspace/CATS_WORKSPACE"
    );
    let origin = validate_https_origin(&auth::configured_api_url(cli.api_url.as_deref())?)?;
    let desired = desired_apply(command)?;
    let state_root = state_root()?;
    let state = PendingState::acquire(&state_root, desired.node_id())?;
    let pending = match prepare_apply(&state, &origin, &desired)? {
        PreparedApply::Terminal(terminal) => return report_terminal(cli, terminal),
        PreparedApply::Pending(pending) => pending,
    };

    let request_authority = request_authority(cli, authority, &origin)?;
    let response = send_pending(
        &state,
        &pending,
        &request_authority,
        &ReqwestAuthorityTransport,
    )
    .with_context(|| {
        format!(
            "Runtime Node authority response was not terminal; exact request {} remains pending in {}",
            pending.apply_id,
            state.pending_path().display()
        )
    })?;
    match classify_response(&pending, &response)? {
        ResponseClassification::Terminal(_) => {
            let terminal = state.settle(&pending, response)?;
            report_terminal(cli, terminal)
        }
        ResponseClassification::ApplyIdConflict => bail!(
            "ALERT: apply ID {} conflicts with another request; automatic retry is stopped and exact pending state remains at {}",
            pending.apply_id,
            state.pending_path().display()
        ),
        ResponseClassification::Nonterminal => bail!(
            "Runtime Node authority response was not terminal; retry the same command to replay apply {} (pending {})",
            pending.apply_id,
            state.pending_path().display()
        ),
    }
}

fn prepare_apply(
    state: &PendingState,
    origin: &str,
    desired: &DesiredApply,
) -> Result<PreparedApply> {
    if state.load_pending()?.is_none() {
        if let Some(terminal) = state.recover_settled(origin, desired)? {
            return Ok(PreparedApply::Terminal(terminal));
        }
    }
    let pending = state.prepare(origin, desired)?;
    if let Some(terminal) = state.recover_resolution(&pending)? {
        return Ok(PreparedApply::Terminal(terminal));
    }
    Ok(PreparedApply::Pending(pending))
}

fn desired_apply(command: &RuntimeNodeCommand) -> Result<DesiredApply> {
    match command {
        RuntimeNodeCommand::Provision { identity, policy } => {
            let identity = read_canonical_identity(identity)?;
            let policy = read_canonical_policy(policy)?;
            anyhow::ensure!(
                identity.node_id == policy.node_id,
                "identity and policy name different Nodes"
            );
            Ok(DesiredApply::Generated {
                node_id: identity.node_id.clone(),
                mutation: RuntimeNodeAuthorityMutation::Provision {
                    node_identity: Box::new(identity),
                    placement_policy: Box::new(policy),
                },
            })
        }
        RuntimeNodeCommand::Policy {
            cmd:
                RuntimeNodePolicyCommand::Apply {
                    node,
                    expected_revision,
                    file,
                },
        } => {
            let node_id = Id::new(node.clone()).context("invalid Node ID")?;
            let expected_policy_revision =
                Epoch::new(*expected_revision).context("invalid expected policy revision")?;
            let policy = read_canonical_policy(file)?;
            anyhow::ensure!(
                policy.node_id == node_id,
                "policy belongs to a different Node"
            );
            Ok(DesiredApply::Generated {
                node_id,
                mutation: RuntimeNodeAuthorityMutation::UpdatePolicy {
                    expected_policy_revision,
                    placement_policy: Box::new(policy),
                },
            })
        }
        RuntimeNodeCommand::Credential {
            cmd: RuntimeNodeCredentialCommand::Rotate { request },
        } => {
            let apply = read_canonical_apply(request)?;
            anyhow::ensure!(
                matches!(
                    apply.mutation,
                    RuntimeNodeAuthorityMutation::RotateCredential { .. }
                ),
                "credential rotate request file contains a different mutation"
            );
            Ok(DesiredApply::Exact(apply))
        }
        RuntimeNodeCommand::Retire { request } => {
            let apply = read_canonical_apply(request)?;
            anyhow::ensure!(
                matches!(apply.mutation, RuntimeNodeAuthorityMutation::Retire { .. }),
                "retire request file contains a different mutation"
            );
            Ok(DesiredApply::Exact(apply))
        }
    }
}

fn read_canonical_identity(path: &Path) -> Result<NodeIdentity> {
    let bytes = read_user_file_bounded(path, NODE_IDENTITY_MAX_WIRE_BYTES)?;
    let value = decode_node_identity(&bytes)
        .map_err(|error| anyhow!("invalid Node identity {}: {error:?}", path.display()))?;
    let canonical = encode_node_identity(&value)
        .map_err(|error| anyhow!("encode Node identity {}: {error:?}", path.display()))?;
    anyhow::ensure!(
        canonical == bytes,
        "Node identity {} is not canonical",
        path.display()
    );
    Ok(value)
}

fn read_canonical_policy(path: &Path) -> Result<NodePlacementPolicy> {
    let bytes = read_user_file_bounded(path, NODE_PLACEMENT_POLICY_MAX_WIRE_BYTES)?;
    let value = decode_node_placement_policy(&bytes)
        .map_err(|error| anyhow!("invalid placement policy {}: {error:?}", path.display()))?;
    let canonical = encode_node_placement_policy(&value)
        .map_err(|error| anyhow!("encode placement policy {}: {error:?}", path.display()))?;
    anyhow::ensure!(
        canonical == bytes,
        "placement policy {} is not canonical",
        path.display()
    );
    Ok(value)
}

fn read_canonical_apply(path: &Path) -> Result<RuntimeNodeAuthorityApply> {
    let bytes = read_user_file_bounded(path, RUNTIME_NODE_AUTHORITY_APPLY_MAX_WIRE_BYTES)?;
    let value = decode_runtime_node_authority_apply(&bytes)
        .map_err(|error| anyhow!("invalid Runtime Node request {}: {error:?}", path.display()))?;
    let canonical = encode_runtime_node_authority_apply(&value)
        .map_err(|error| anyhow!("encode Runtime Node request {}: {error:?}", path.display()))?;
    anyhow::ensure!(
        canonical == bytes,
        "Runtime Node request {} is not canonical",
        path.display()
    );
    Ok(value)
}

fn request_authority(
    cli: &Cli,
    source: &RuntimeNodeAuthorityAuth<'_>,
    origin: &str,
) -> Result<RequestAuthority> {
    let machine_fields = [
        source.deployment_id.is_some(),
        source.provisioner_credential_id.is_some(),
        source.provisioner_private_key_file.is_some(),
    ];
    if machine_fields.iter().any(|present| *present) {
        anyhow::ensure!(
            machine_fields.iter().all(|present| *present),
            "deployment provisioner authentication requires --deployment-id, --provisioner-credential-id, and --provisioner-private-key-file together"
        );
        anyhow::ensure!(
            cli.token.is_none(),
            "deployment provisioner authentication cannot be mixed with --token"
        );
        let deployment_id = Id::new(source.deployment_id.unwrap().to_owned())
            .context("invalid deployment provisioner deployment ID")?;
        let credential_id = Id::new(source.provisioner_credential_id.unwrap().to_owned())
            .context("invalid deployment provisioner credential ID")?;
        let mut private_key = read_private_key(source.provisioner_private_key_file.unwrap())?;
        let parsed_signer = Ed25519RequestSigner::from_pkcs8_pem(credential_id, &private_key);
        private_key.fill(0);
        let signer =
            parsed_signer.context("parse deployment provisioner PKCS#8 Ed25519 private key")?;
        return Ok(RequestAuthority::DeploymentProvisioner {
            deployment_id,
            signer,
        });
    }

    if let Some(token) = &cli.token {
        anyhow::ensure!(!token.is_empty(), "--token is empty");
        return Ok(RequestAuthority::FleetAdministrator {
            access_token: token.clone(),
        });
    }
    let session = auth::fleet_admin_session(cli.api_url.as_deref())?;
    anyhow::ensure!(
        validate_https_origin(&session.api_url)? == origin,
        "fleet-administrator login origin changed after the request became pending"
    );
    Ok(RequestAuthority::FleetAdministrator {
        access_token: session.access_token,
    })
}

fn send_pending(
    state: &PendingState,
    pending: &PendingRecord,
    authority: &RequestAuthority,
    transport: &dyn AuthorityTransport,
) -> Result<StoredHttpResponse> {
    pending.apply()?;
    // Older V1 records retained equivalent host-case/default-port spellings;
    // reqwest always sends their canonical URL. Preserve the immutable record
    // while comparing and sending its canonical exact origin.
    let request_url = format!(
        "{}{}",
        validate_https_origin(&pending.origin)?,
        pending.target
    );
    let body = pending.body()?;
    let mut headers = vec![
        (
            reqwest::header::CONTENT_TYPE.as_str(),
            pending.content_type.clone(),
        ),
        (
            reqwest::header::ACCEPT.as_str(),
            JSON_CONTENT_TYPE.to_owned(),
        ),
        (
            reqwest::header::ACCEPT_ENCODING.as_str(),
            "identity".to_owned(),
        ),
    ];
    match authority {
        RequestAuthority::FleetAdministrator { access_token } => headers.push((
            reqwest::header::AUTHORIZATION.as_str(),
            format!("Bearer {access_token}"),
        )),
        RequestAuthority::DeploymentProvisioner {
            deployment_id,
            signer,
        } => {
            let proof = sign_runtime_node_authority_request(deployment_id, signer, &body);
            headers.push((PROVISIONER_CREDENTIAL_ID_HEADER, proof.credential_id));
            headers.push((PROVISIONER_SIGNATURE_HEADER, proof.signature));
        }
    }
    // This is the last fallible step before the first network effect. If the
    // config ancestors, state root, or global path-scoped lock entry was renamed or
    // replaced while credentials were acquired, this invocation sends zero
    // bytes. A second instance cannot pass the same global lock until
    // this one releases it.
    state.assert_current_authority()?;
    transport.send(OutboundRequest {
        method: METHOD,
        url: request_url,
        headers,
        body,
    })
}

impl AuthorityTransport for ReqwestAuthorityTransport {
    fn send(&self, request: OutboundRequest) -> Result<StoredHttpResponse> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .context("build closed Runtime Node authority HTTP client")?;
        let mut builder = client.request(
            reqwest::Method::from_bytes(request.method.as_bytes())
                .context("invalid closed Runtime Node authority method")?,
            &request.url,
        );
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        let mut response = builder
            .body(request.body)
            .send()
            .context("send Runtime Node authority request")?;
        anyhow::ensure!(
            response.url().as_str() == request.url,
            "Runtime Node authority response came from a different URL"
        );
        let status = response.status().as_u16();
        let mut headers = Vec::new();
        let mut names = response.headers().keys().cloned().collect::<Vec<_>>();
        names.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        for name in names {
            for value in response.headers().get_all(&name) {
                headers.push(HeaderOccurrence::new(name.as_str(), value.as_bytes()));
            }
        }
        headers.sort_by(|left, right| {
            (&left.name, &left.value_base64).cmp(&(&right.name, &right.value_base64))
        });
        let mut body = Vec::new();
        (&mut response)
            .take(RESPONSE_READ_LIMIT as u64)
            .read_to_end(&mut body)
            .context("read Runtime Node authority response")?;
        anyhow::ensure!(
            body.len() <= ERROR_BODY_MAX_BYTES,
            "Runtime Node authority response exceeds the closed body limit"
        );
        Ok(StoredHttpResponse {
            status,
            headers,
            body_base64: URL_SAFE_NO_PAD.encode(body),
        })
    }
}

fn classify_response(
    pending: &PendingRecord,
    response: &StoredHttpResponse,
) -> Result<ResponseClassification> {
    let body = response.body()?;
    let content_types = response.header_values(reqwest::header::CONTENT_TYPE.as_str())?;
    let content_encoding = response.header_values(reqwest::header::CONTENT_ENCODING.as_str())?;
    let exact_json =
        content_types.as_slice() == [JSON_CONTENT_TYPE.as_bytes()] && content_encoding.is_empty();

    if response.status == 200
        && exact_json
        && body.len() <= RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES
    {
        if let Ok(result) = decode_runtime_node_authority_apply_result(&body) {
            let canonical = encode_runtime_node_authority_apply_result(&result)
                .map_err(|error| anyhow!("re-encode Runtime Node authority result: {error:?}"))?;
            if canonical == body && result_binds_request(&pending.apply()?, &result) {
                return Ok(ResponseClassification::Terminal(TerminalOutcome::Applied(
                    result,
                )));
            }
        }
    }

    if response.status == 409 && body == APPLY_ID_CONFLICT {
        return Ok(ResponseClassification::ApplyIdConflict);
    }

    if response.status == 409
        && exact_json
        && body == AUTHORITY_PRECONDITION_FAILED
        && body.len() <= ERROR_BODY_MAX_BYTES
    {
        let apply_ids = response.header_values(NODE_AUTHORITY_APPLY_ID_HEADER)?;
        if apply_ids.as_slice() == [pending.apply_id.as_bytes()] {
            return Ok(ResponseClassification::Terminal(
                TerminalOutcome::AuthorityPreconditionFailed,
            ));
        }
    }
    Ok(ResponseClassification::Nonterminal)
}

fn validate_stored_response(response: &StoredHttpResponse) -> Result<()> {
    let mut previous: Option<(&str, &str)> = None;
    for header in &response.headers {
        anyhow::ensure!(
            header.name == header.name.to_ascii_lowercase()
                && reqwest::header::HeaderName::from_bytes(header.name.as_bytes()).is_ok(),
            "resolution receipt contains a noncanonical header name"
        );
        header.value()?;
        let current = (header.name.as_str(), header.value_base64.as_str());
        anyhow::ensure!(
            previous.is_none_or(|previous| previous <= current),
            "resolution receipt headers are not canonical"
        );
        previous = Some(current);
    }
    response.body()?;
    Ok(())
}

fn result_binds_request(
    apply: &RuntimeNodeAuthorityApply,
    result: &RuntimeNodeAuthorityApplyResult,
) -> bool {
    if result.version != ContractVersion::V1
        || result.apply_id != apply.apply_id
        || result.node_id != apply.node_id
    {
        return false;
    }
    match &apply.mutation {
        RuntimeNodeAuthorityMutation::Provision { .. } => {
            result.outcome == RuntimeNodeAuthorityOutcome::Provisioned
                && result.identity_state == NodeIdentityState::Provisioned
                && result.policy_revision.get() == 1
        }
        RuntimeNodeAuthorityMutation::UpdatePolicy {
            placement_policy, ..
        } => {
            result.outcome == RuntimeNodeAuthorityOutcome::PolicyUpdated
                && result.identity_state == NodeIdentityState::Provisioned
                && result.policy_revision == placement_policy.policy_revision
        }
        RuntimeNodeAuthorityMutation::RotateCredential {
            expected_policy_revision,
            ..
        } => {
            result.outcome == RuntimeNodeAuthorityOutcome::CredentialRotated
                && result.identity_state == NodeIdentityState::Provisioned
                && result.policy_revision == *expected_policy_revision
        }
        RuntimeNodeAuthorityMutation::Retire {
            expected_policy_revision,
            ..
        } => {
            result.outcome == RuntimeNodeAuthorityOutcome::Retired
                && result.identity_state == NodeIdentityState::Retired
                && result.policy_revision == *expected_policy_revision
        }
    }
}

fn report_terminal(cli: &Cli, terminal: TerminalOutcome) -> Result<()> {
    match terminal {
        TerminalOutcome::Applied(result) => {
            if cli.json {
                println!(
                    "{}",
                    String::from_utf8(
                        encode_runtime_node_authority_apply_result(&result)
                            .map_err(|error| anyhow!("encode Runtime Node result: {error:?}"))?
                    )?
                );
            } else {
                println!(
                    "apply {} {:?}: node={} state={:?} policy-revision={}",
                    result.apply_id,
                    result.outcome,
                    result.node_id,
                    result.identity_state,
                    result.policy_revision.get()
                );
            }
            Ok(())
        }
        TerminalOutcome::AuthorityPreconditionFailed => {
            bail!("Runtime Node authority precondition failed (terminal; pending request settled)")
        }
    }
}

fn validate_https_origin(value: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(value).context("invalid Runtime Node authority origin")?;
    anyhow::ensure!(
        parsed.scheme() == "https"
            && parsed.has_host()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "Runtime Node authority requires an exact HTTPS origin without path, query, credentials, or fragment"
    );
    Ok(parsed.origin().ascii_serialization())
}

fn state_root() -> Result<PathBuf> {
    let config = config::config_path();
    let parent = config.parent().context("Cats config path has no parent")?;
    Ok(parent.join("runtime-node-authority-v1"))
}

fn fresh_apply_id() -> Result<RandomId128> {
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .context("UUID v4 did not form a Runtime random ID")
}

fn zero_apply_id() -> Result<RandomId128> {
    RandomId128::new("00000000000000000000000000000001".to_owned())
        .context("fixed Runtime random ID is invalid")
}

fn mutation_digest(apply: &RuntimeNodeAuthorityApply) -> Result<String> {
    let canonical = RuntimeNodeAuthorityApply {
        version: apply.version,
        apply_id: zero_apply_id()?,
        node_id: apply.node_id.clone(),
        mutation: apply.mutation.clone(),
    };
    let bytes = encode_runtime_node_authority_apply(&canonical)
        .map_err(|error| anyhow!("encode Runtime Node authority mutation binding: {error:?}"))?;
    Ok(sha256_digest(&bytes))
}

fn settled_lookup_digest(origin: &str, binding: &SettledBinding) -> Result<String> {
    let origin = validate_https_origin(origin)?;
    anyhow::ensure!(
        binding.sha256.starts_with("sha256:") && binding.sha256.len() == 71,
        "settled binding is not a SHA-256 digest"
    );
    let kind = match binding.kind {
        SettledBindingKind::GeneratedMutation => b"generated".as_slice(),
        SettledBindingKind::ExactApply => b"exact".as_slice(),
    };
    let mut framed = b"cats.runtime-node-authority.settled-index.v1\0".to_vec();
    for value in [origin.as_bytes(), kind, binding.sha256.as_bytes()] {
        framed.extend_from_slice(&(value.len() as u64).to_be_bytes());
        framed.extend_from_slice(value);
    }
    Ok(hex_digest(&framed))
}

fn state_path_namespace(path: &Path) -> Result<String> {
    anyhow::ensure!(path.is_absolute(), "state path is not absolute");
    let mut framed = b"cats.runtime-node-authority.state-path.v1\0".to_vec();
    for component in path.components() {
        use std::path::Component;
        let value = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(value) => value,
            Component::ParentDir => bail!("Runtime Node authority state path may not contain '..'"),
            Component::Prefix(_) => bail!("unsupported Runtime Node authority state path"),
        };
        framed.extend_from_slice(&(value.as_bytes().len() as u64).to_be_bytes());
        framed.extend_from_slice(value.as_bytes());
    }
    Ok(hex_digest(&framed))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn decode_canonical_base64(value: &str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("invalid base64url without padding")?;
    anyhow::ensure!(
        URL_SAFE_NO_PAD.encode(&decoded) == value,
        "noncanonical base64url encoding"
    );
    Ok(decoded)
}

fn read_user_file_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file =
        open_read_only_nofollow(path).with_context(|| format!("open input {}", path.display()))?;
    anyhow::ensure!(
        file.metadata()?.file_type().is_file(),
        "input {} is not a regular file",
        path.display()
    );
    read_bounded(file, maximum).with_context(|| format!("read input {}", path.display()))
}

fn read_private_key(path: &Path) -> Result<Vec<u8>> {
    let file = open_read_only_nofollow(path)
        .with_context(|| format!("open provisioner private-key file {}", path.display()))?;
    let before = file.metadata()?;
    validate_private_regular_file(&file, path)?;
    anyhow::ensure!(
        before.nlink() == 1,
        "provisioner private-key file must have one link"
    );
    anyhow::ensure!(
        before.mode() & 0o7777 == 0o600,
        "provisioner private-key file must have exact mode 0600"
    );
    let bytes = read_bounded(file.try_clone()?, PRIVATE_KEY_MAX_BYTES)
        .context("read bounded provisioner private-key file")?;
    let after = file.metadata()?;
    anyhow::ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "provisioner private-key file changed while being read"
    );
    Ok(bytes)
}

fn read_optional_state_file(
    directory: &File,
    name: &CStr,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let file = match open_file_at(directory, name, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open Runtime Node authority state entry"),
    };
    validate_private_regular_file_descriptor(&file, name.to_string_lossy().as_ref())?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.nlink() == 1 && metadata.mode() & 0o7777 == 0o600,
        "Runtime Node authority state entry is not a private single-link file"
    );
    read_bounded(file, maximum)
        .context("read Runtime Node authority state entry")
        .map(Some)
}

fn read_bounded(file: File, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= maximum, "file exceeds its closed byte limit");
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

struct DirectoryLink {
    parent: File,
    entry_name: CString,
    child_identity: FileIdentity,
}

struct StableDirectory {
    directory: File,
    links: Vec<DirectoryLink>,
    identity: FileIdentity,
}

impl StableDirectory {
    fn open_or_create(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            path.is_absolute(),
            "Runtime Node authority state requires an absolute CATS_CONFIG_DIR"
        );
        let mut directory = open_directory_nofollow(Path::new("/"))?;
        let mut links = Vec::new();
        for component in path.components() {
            use std::path::Component;
            let component = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(component) => component,
                Component::ParentDir => {
                    bail!("Runtime Node authority state path may not contain '..'")
                }
                Component::Prefix(_) => bail!("unsupported Runtime Node authority state path"),
            };
            let name = c_os_name(component)?;
            let (next, created) = open_or_create_directory_at(&directory, &name)?;
            // Sync even when another process won the mkdir race: observing an
            // entry does not prove that process completed its parent barrier.
            // Thus every selected ancestor is durable before traversal moves
            // below it, and no request can precede an ancestor barrier.
            sync_directory(&directory, "sync selected state ancestor parent")?;
            if created {
                sync_directory(&next, "sync newly-created state ancestor")?;
            }
            links.push(DirectoryLink {
                parent: directory.try_clone()?,
                entry_name: name,
                child_identity: FileIdentity::of(&next)?,
            });
            directory = next;
        }
        validate_owned_directory(&directory, false)?;
        let identity = FileIdentity::of(&directory)?;
        Ok(Self {
            directory,
            links,
            identity,
        })
    }

    fn assert_current(&self) -> Result<()> {
        anyhow::ensure!(
            FileIdentity::of(&self.directory)? == self.identity,
            "Runtime Node authority state parent descriptor changed identity"
        );
        for link in &self.links {
            let linked = identity_at(&link.parent, &link.entry_name, libc::AT_SYMLINK_NOFOLLOW)?;
            anyhow::ensure!(
                linked == link.child_identity,
                "Runtime Node authority state ancestor was renamed or replaced"
            );
        }
        Ok(())
    }
}

struct StateRoot {
    parent: StableDirectory,
    directory: File,
    entry_name: CString,
    identity: FileIdentity,
}

impl StateRoot {
    fn open_or_create(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            path.is_absolute(),
            "Runtime Node authority state requires an absolute CATS_CONFIG_DIR"
        );
        let parent_path = path
            .parent()
            .context("Runtime Node authority state root has no parent")?;
        let entry_name = c_os_name(
            path.file_name()
                .context("Runtime Node authority state root has no basename")?,
        )?;
        let parent = StableDirectory::open_or_create(parent_path)?;
        parent.assert_current()?;
        let (directory, created) = open_or_create_directory_at(&parent.directory, &entry_name)?;
        validate_owned_directory(&directory, true)?;
        sync_directory(
            &parent.directory,
            "sync selected Runtime Node authority state-root parent",
        )?;
        if created {
            sync_directory(&directory, "sync Runtime Node authority state root")?;
        }
        let identity = FileIdentity::of(&directory)?;
        let state = Self {
            parent,
            directory,
            entry_name,
            identity,
        };
        state.assert_current()?;
        Ok(state)
    }

    fn assert_current(&self) -> Result<()> {
        self.parent.assert_current()?;
        anyhow::ensure!(
            FileIdentity::of(&self.directory)? == self.identity,
            "Runtime Node authority state-root descriptor changed identity"
        );
        let linked = identity_at(
            &self.parent.directory,
            &self.entry_name,
            libc::AT_SYMLINK_NOFOLLOW,
        )?;
        anyhow::ensure!(
            linked == self.identity,
            "Runtime Node authority state root was renamed or replaced"
        );
        Ok(())
    }
}

fn open_or_create_directory_at(parent: &File, name: &CStr) -> Result<(File, bool)> {
    match open_file_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(file) => Ok((file, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match mkdir_at(parent, name, 0o700) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return Ok((
                        open_file_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
                        false,
                    ));
                }
                Err(error) => return Err(error).context("create state directory"),
            }
            let file = open_file_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            Ok((file, true))
        }
        Err(error) => Err(error).context("open Runtime Node authority state directory"),
    }
}

fn sync_directory(directory: &File, context: &'static str) -> Result<()> {
    #[cfg(test)]
    if directory_sync_probe_should_fail() {
        bail!("injected directory-sync failure: {context}");
    }
    directory.sync_all().context(context)
}

#[cfg(test)]
thread_local! {
    static DIRECTORY_SYNC_PROBE: std::cell::Cell<(Option<usize>, usize)> =
        const { std::cell::Cell::new((None, 0)) };
}

#[cfg(test)]
fn directory_sync_probe_should_fail() -> bool {
    DIRECTORY_SYNC_PROBE.with(|probe| {
        let (fail_at, count) = probe.get();
        probe.set((fail_at, count + 1));
        fail_at == Some(count)
    })
}

#[cfg(test)]
struct DirectorySyncProbeGuard;

#[cfg(test)]
impl DirectorySyncProbeGuard {
    fn start(fail_at: Option<usize>) -> Self {
        DIRECTORY_SYNC_PROBE.with(|probe| probe.set((fail_at, 0)));
        Self
    }

    fn count(&self) -> usize {
        DIRECTORY_SYNC_PROBE.with(|probe| probe.get().1)
    }
}

#[cfg(test)]
impl Drop for DirectorySyncProbeGuard {
    fn drop(&mut self) {
        DIRECTORY_SYNC_PROBE.with(|probe| probe.set((None, 0)));
    }
}

fn open_state_lock(parent: &File, name: &CStr) -> Result<(File, bool)> {
    match open_file_at(
        parent,
        name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Ok((open_file_at(parent, name, libc::O_RDWR, 0)?, false))
        }
        Err(error) => Err(error).context("open Runtime Node authority state lock"),
    }
}

fn open_global_lock_directory() -> Result<File> {
    #[cfg(target_os = "macos")]
    const COMPONENTS: &[&str] = &["private", "tmp"];
    #[cfg(not(target_os = "macos"))]
    const COMPONENTS: &[&str] = &["tmp"];

    let mut directory = open_directory_nofollow(Path::new("/"))?;
    for component in COMPONENTS {
        let name = c_name(component)?;
        directory = open_file_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .context("open global Runtime Node authority lock directory")?;
    }
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && metadata.uid() == 0 && metadata.mode() & 0o1777 == 0o1777,
        "global Runtime Node authority lock directory is not root-owned sticky 01777"
    );
    Ok(directory)
}

fn open_read_only_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

fn open_directory_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .with_context(|| format!("open directory {}", path.display()))
}

fn validate_private_regular_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "{} is not a regular file",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.uid() == effective_uid(),
            "{} has a different owner",
            path.display()
        );
        anyhow::ensure!(
            metadata.mode() & 0o077 == 0,
            "{} is accessible to another user",
            path.display()
        );
    }
    Ok(())
}

fn validate_private_regular_file_descriptor(file: &File, display: &str) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "{display} is not a regular file"
    );
    anyhow::ensure!(
        metadata.uid() == effective_uid(),
        "{display} has a different owner"
    );
    anyhow::ensure!(
        metadata.mode() & 0o077 == 0,
        "{display} is accessible to another user"
    );
    Ok(())
}

fn validate_owned_directory(directory: &File, private: bool) -> Result<()> {
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "state entry is not a directory"
    );
    anyhow::ensure!(
        metadata.uid() == effective_uid(),
        "state directory has a different owner"
    );
    if private {
        anyhow::ensure!(
            metadata.mode() & 0o7777 == 0o700,
            "state directory must have exact mode 0700"
        );
    } else {
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0,
            "state directory is writable by another user"
        );
    }
    Ok(())
}

fn publish_new(directory: &File, target: &CStr, bytes: &[u8]) -> Result<()> {
    cleanup_publish_temp(directory, target)?;
    let temporary = publish_temp_name(target)?;
    let mut file = open_file_at(
        directory,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .context("create temporary Runtime Node authority state")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Err(error) = rename_relative(directory, &temporary, target, true) {
        let _ = unlink_at(directory, &temporary);
        let _ = directory.sync_all();
        return Err(error).context("publish immutable Runtime Node authority state");
    }
    directory.sync_all()?;
    Ok(())
}

fn cleanup_publish_temp(directory: &File, target: &CStr) -> Result<()> {
    let temporary = publish_temp_name(target)?;
    match unlink_at(directory, &temporary) {
        Ok(()) => directory.sync_all().context("sync state temp cleanup"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove stale Runtime Node authority state temp"),
    }
}

fn publish_temp_name(target: &CStr) -> Result<CString> {
    c_name(&format!(".{}.tmp", target.to_string_lossy()))
}

#[cfg(target_os = "linux")]
fn rename_relative(
    directory: &File,
    source: &CStr,
    target: &CStr,
    no_replace: bool,
) -> io::Result<()> {
    let flags = if no_replace {
        libc::RENAME_NOREPLACE
    } else {
        0
    };
    // SAFETY: names are NUL-terminated single components and both are resolved
    // against the held, validated state-directory descriptor.
    let result = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_relative(
    directory: &File,
    source: &CStr,
    target: &CStr,
    no_replace: bool,
) -> io::Result<()> {
    let flags = if no_replace { libc::RENAME_EXCL } else { 0 };
    // SAFETY: names are NUL-terminated single components and both are resolved
    // against the held, validated state-directory descriptor.
    let result = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_relative(
    directory: &File,
    source: &CStr,
    target: &CStr,
    no_replace: bool,
) -> io::Result<()> {
    let result = if no_replace {
        // SAFETY: names are valid and resolved beneath the same held directory.
        unsafe {
            libc::linkat(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
                0,
            )
        }
    } else {
        // SAFETY: names are valid and resolved beneath the same held directory.
        unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if no_replace {
        unlink_at(directory, source)?;
    }
    Ok(())
}

fn c_name(value: &str) -> Result<CString> {
    anyhow::ensure!(
        !value.is_empty() && !value.as_bytes().contains(&b'/'),
        "state entry is not a single path component"
    );
    CString::new(value).context("state entry contains NUL")
}

fn c_os_name(value: &OsStr) -> Result<CString> {
    anyhow::ensure!(
        !value.is_empty() && !value.as_bytes().contains(&b'/'),
        "state entry is not a single path component"
    );
    CString::new(value.as_bytes()).context("state entry contains NUL")
}

fn open_file_at(directory: &File, name: &CStr, flags: i32, mode: libc::c_uint) -> io::Result<File> {
    // SAFETY: `name` is a live NUL-terminated component and the returned file
    // descriptor is uniquely transferred into `File` on success.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `descriptor` is a fresh owned descriptor from `openat`.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn mkdir_at(directory: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `name` is a live NUL-terminated component resolved against the
    // held directory descriptor.
    let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), mode) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_at(directory: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: `name` is a live NUL-terminated component resolved against the
    // held directory descriptor; flags zero refuses directory removal.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn identity_at(directory: &File, name: &CStr, flags: i32) -> io::Result<FileIdentity> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata points to writable storage for one `stat`, and `name`
    // is a live NUL-terminated component beneath the held directory.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            flags,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    let file_type = metadata.st_mode & libc::S_IFMT;
    if file_type != libc::S_IFREG && file_type != libc::S_IFDIR {
        return Err(io::Error::other(
            "state authority entry has an unsupported file type",
        ));
    }
    #[cfg(target_os = "macos")]
    let device = u64::try_from(metadata.st_dev).map_err(|_| io::Error::other("invalid device"))?;
    #[cfg(not(target_os = "macos"))]
    let device = metadata.st_dev;
    Ok(FileIdentity {
        device,
        inode: metadata.st_ino,
    })
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no pointers and only reads the calling process's
    // effective credential; it cannot violate Rust memory invariants.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::mpsc;

    use base64::engine::general_purpose::STANDARD;
    use cats_api::runtime_reconciliation::{PublicKeyCredentialBinding, Sha256Digest};
    use clap::Parser as _;

    use super::*;

    const UPDATE: &[u8] = br#"{"apply_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}"#;

    fn update() -> RuntimeNodeAuthorityApply {
        decode_runtime_node_authority_apply(UPDATE).unwrap()
    }

    fn retire(apply_id: &str) -> RuntimeNodeAuthorityApply {
        RuntimeNodeAuthorityApply {
            version: ContractVersion::V1,
            apply_id: RandomId128::new(apply_id.to_owned()).unwrap(),
            node_id: Id::new("node_a".to_owned()).unwrap(),
            mutation: RuntimeNodeAuthorityMutation::Retire {
                expected_policy_revision: Epoch::new(2).unwrap(),
                expected_credential_id: Id::new("credential_a".to_owned()).unwrap(),
                expected_credential_binding: PublicKeyCredentialBinding::PublicKey {
                    public_key_spki_sha256: Sha256Digest::from_bytes([0x42; 32]),
                },
            },
        }
    }

    fn test_base(directory: &tempfile::TempDir) -> PathBuf {
        fs::canonicalize(directory.path()).unwrap()
    }

    fn pending() -> PendingRecord {
        PendingRecord::from_apply("https://control.example:8443", &update()).unwrap()
    }

    fn response(status: u16, body: Vec<u8>) -> StoredHttpResponse {
        StoredHttpResponse {
            status,
            headers: vec![HeaderOccurrence::new("content-type", b"application/json")],
            body_base64: URL_SAFE_NO_PAD.encode(body),
        }
    }

    fn success() -> StoredHttpResponse {
        let apply = update();
        let result = RuntimeNodeAuthorityApplyResult {
            version: ContractVersion::V1,
            apply_id: apply.apply_id,
            node_id: apply.node_id,
            outcome: RuntimeNodeAuthorityOutcome::PolicyUpdated,
            identity_state: NodeIdentityState::Provisioned,
            policy_revision: Epoch::new(2).unwrap(),
        };
        response(
            200,
            encode_runtime_node_authority_apply_result(&result).unwrap(),
        )
    }

    fn success_for(pending: &PendingRecord) -> StoredHttpResponse {
        let apply = pending.apply().unwrap();
        let (outcome, identity_state, policy_revision) = match &apply.mutation {
            RuntimeNodeAuthorityMutation::Provision {
                placement_policy, ..
            } => (
                RuntimeNodeAuthorityOutcome::Provisioned,
                NodeIdentityState::Provisioned,
                placement_policy.policy_revision,
            ),
            RuntimeNodeAuthorityMutation::UpdatePolicy {
                placement_policy, ..
            } => (
                RuntimeNodeAuthorityOutcome::PolicyUpdated,
                NodeIdentityState::Provisioned,
                placement_policy.policy_revision,
            ),
            RuntimeNodeAuthorityMutation::RotateCredential {
                expected_policy_revision,
                ..
            } => (
                RuntimeNodeAuthorityOutcome::CredentialRotated,
                NodeIdentityState::Provisioned,
                *expected_policy_revision,
            ),
            RuntimeNodeAuthorityMutation::Retire {
                expected_policy_revision,
                ..
            } => (
                RuntimeNodeAuthorityOutcome::Retired,
                NodeIdentityState::Retired,
                *expected_policy_revision,
            ),
        };
        response(
            200,
            encode_runtime_node_authority_apply_result(&RuntimeNodeAuthorityApplyResult {
                version: ContractVersion::V1,
                apply_id: apply.apply_id,
                node_id: apply.node_id,
                outcome,
                identity_state,
                policy_revision,
            })
            .unwrap(),
        )
    }

    fn generated_update(apply: RuntimeNodeAuthorityApply) -> DesiredApply {
        DesiredApply::Generated {
            node_id: apply.node_id,
            mutation: apply.mutation,
        }
    }

    fn pkcs8_der(seed: [u8; 32]) -> Vec<u8> {
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&seed);
        der
    }

    fn signer_from_seed(credential_id: &str, seed: [u8; 32]) -> Ed25519RequestSigner {
        Ed25519RequestSigner::from_pkcs8_der(
            Id::new(credential_id.to_owned()).unwrap(),
            &pkcs8_der(seed),
        )
        .unwrap()
    }

    fn pkcs8_pem(seed: [u8; 32]) -> Vec<u8> {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(pkcs8_der(seed))
        )
        .into_bytes()
    }

    #[derive(Default)]
    struct RecordingTransport {
        requests: RefCell<Vec<OutboundRequest>>,
        responses: RefCell<VecDeque<StoredHttpResponse>>,
    }

    impl RecordingTransport {
        fn respond_with(&self, response: StoredHttpResponse) {
            self.responses.borrow_mut().push_back(response);
        }

        fn request_count(&self) -> usize {
            self.requests.borrow().len()
        }
    }

    impl AuthorityTransport for RecordingTransport {
        fn send(&self, request: OutboundRequest) -> Result<StoredHttpResponse> {
            self.requests.borrow_mut().push(request);
            self.responses
                .borrow_mut()
                .pop_front()
                .context("recording transport has no response")
        }
    }

    fn apply_with_transport(
        state: &PendingState,
        origin: &str,
        desired: &DesiredApply,
        transport: &RecordingTransport,
    ) -> TerminalOutcome {
        match prepare_apply(state, origin, desired).unwrap() {
            PreparedApply::Terminal(terminal) => terminal,
            PreparedApply::Pending(pending) => {
                transport.respond_with(success_for(&pending));
                let response = send_pending(
                    state,
                    &pending,
                    &RequestAuthority::FleetAdministrator {
                        access_token: "short-lived-workos-jwt".to_owned(),
                    },
                    transport,
                )
                .unwrap();
                state.settle(&pending, response).unwrap()
            }
        }
    }

    #[test]
    fn pending_is_published_once_and_replayed_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = DesiredApply::Exact(retire("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let first = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        assert!(state.pending_path().exists());
        drop(state);

        let state = PendingState::acquire(&root, &node).unwrap();
        let replay = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        assert_eq!(first, replay);
        assert!(state
            .prepare("https://different.example", &desired)
            .unwrap_err()
            .to_string()
            .contains("different origin"));
    }

    #[test]
    fn existing_v1_pending_replays_without_a_schema_upgrade() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = generated_update(update());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let mut old_pending =
            PendingRecord::from_apply("https://control.example", &update()).unwrap();
        // The original V1 normalizer retained host case and explicit default
        // ports. The replacement normalizer must compare the same origin
        // semantically without rewriting the immutable pending record.
        old_pending.origin = "https://CONTROL.EXAMPLE:443".to_owned();
        let old_bytes = serde_json::to_vec(&old_pending).unwrap();
        assert!(!old_bytes.windows(12).any(|part| part == b"binding_kind"));
        publish_new(
            &state.state_root.directory,
            &state.pending_name().unwrap(),
            &old_bytes,
        )
        .unwrap();
        drop(state);

        let state = PendingState::acquire(&root, &node).unwrap();
        let replay = state.prepare("https://control.example", &desired).unwrap();
        assert_eq!(replay, old_pending);
        assert_eq!(fs::read(state.pending_path()).unwrap(), old_bytes);
    }

    #[test]
    fn durable_receipt_wins_crash_before_pending_delete() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = DesiredApply::Exact(retire("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        let stored = success_for(&pending);
        let receipt = ResolutionReceipt {
            version: STATE_VERSION,
            apply_id: pending.apply_id.clone(),
            node_id: pending.node_id.clone(),
            request_sha256: pending.request_sha256.clone(),
            response: stored,
        };
        publish_new(
            &state.state_root.directory,
            &state.receipt_name(&pending.apply_id).unwrap(),
            &serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(
            state.pending_path().exists(),
            "simulated crash left pending"
        );
        drop(state);

        let state = PendingState::acquire(&root, &node).unwrap();
        let pending = state.load_pending().unwrap().unwrap();
        assert!(matches!(
            state.recover_resolution(&pending).unwrap(),
            Some(TerminalOutcome::Applied(_))
        ));
        assert!(!state.pending_path().exists());
        assert!(read_optional_state_file(
            &state.state_root.directory,
            &state.receipt_name(&pending.apply_id).unwrap(),
            RECEIPT_MAX_BYTES,
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn existing_receipt_and_index_still_order_before_pending_unlink() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = DesiredApply::Exact(retire("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        let receipt = ResolutionReceipt {
            version: STATE_VERSION,
            apply_id: pending.apply_id.clone(),
            node_id: pending.node_id.clone(),
            request_sha256: pending.request_sha256.clone(),
            response: success_for(&pending),
        };
        publish_new(
            &state.state_root.directory,
            &state.receipt_name(&pending.apply_id).unwrap(),
            &serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        state.publish_settled_index(&pending, &receipt).unwrap();

        assert!(matches!(
            state.recover_resolution(&pending).unwrap(),
            Some(TerminalOutcome::Applied(_))
        ));
        assert!(!state.pending_path().exists());
        assert!(state
            .recover_settled(&pending.origin, &desired)
            .unwrap()
            .is_some());
    }

    #[test]
    fn generated_settled_indexes_survive_later_mutations() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let origin = "https://control.example:8443";
        let first = generated_update(update());
        let node = first.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let transport = RecordingTransport::default();
        let first_result = apply_with_transport(&state, origin, &first, &transport);
        let first_apply_id = match first_result {
            TerminalOutcome::Applied(result) => result.apply_id,
            TerminalOutcome::AuthorityPreconditionFailed => unreachable!(),
        };

        let mut second_apply = update();
        match &mut second_apply.mutation {
            RuntimeNodeAuthorityMutation::UpdatePolicy {
                expected_policy_revision,
                placement_policy,
            } => {
                *expected_policy_revision = Epoch::new(2).unwrap();
                placement_policy.policy_revision = Epoch::new(3).unwrap();
            }
            _ => unreachable!(),
        }
        let second = generated_update(second_apply);
        apply_with_transport(&state, origin, &second, &transport);
        let recovered = apply_with_transport(&state, origin, &first, &transport);
        assert!(matches!(
            recovered,
            TerminalOutcome::Applied(result) if result.apply_id == first_apply_id
        ));
        assert_eq!(
            transport.request_count(),
            2,
            "A -> B -> A sent only A and B"
        );
    }

    #[test]
    fn settled_indexes_are_isolated_by_exact_origin() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = generated_update(update());
        let state = PendingState::acquire(&root, desired.node_id()).unwrap();
        let transport = RecordingTransport::default();

        let first = apply_with_transport(
            &state,
            "https://control-a.example:8443",
            &desired,
            &transport,
        );
        let second = apply_with_transport(
            &state,
            "https://control-b.example:8443",
            &desired,
            &transport,
        );
        assert!(!matches!(
            first,
            TerminalOutcome::AuthorityPreconditionFailed
        ));
        assert!(!matches!(
            second,
            TerminalOutcome::AuthorityPreconditionFailed
        ));
        apply_with_transport(
            &state,
            "https://control-a.example:8443",
            &desired,
            &transport,
        );
        apply_with_transport(
            &state,
            "https://control-b.example:8443",
            &desired,
            &transport,
        );
        assert_eq!(
            transport.request_count(),
            2,
            "each origin settles once and then resolves through its own direct index"
        );
    }

    #[test]
    fn equivalent_origin_spellings_share_one_settled_binding() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = generated_update(update());
        let state = PendingState::acquire(&root, desired.node_id()).unwrap();
        let transport = RecordingTransport::default();

        apply_with_transport(&state, "https://CONTROL.EXAMPLE:443", &desired, &transport);
        apply_with_transport(&state, "https://control.example", &desired, &transport);
        assert_eq!(transport.request_count(), 1);
    }

    #[test]
    fn exact_binding_includes_caller_apply_id() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let origin = "https://control.example:8443";
        let first = DesiredApply::Exact(retire("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
        let node = first.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let first_pending = state.prepare(origin, &first).unwrap();
        state
            .settle(&first_pending, success_for(&first_pending))
            .unwrap();

        let different_apply_id = retire("ffffffffffffffffffffffffffffffff");
        let second = DesiredApply::Exact(different_apply_id);
        assert!(state.recover_settled(origin, &second).unwrap().is_none());
        let second_pending = state.prepare(origin, &second).unwrap();
        assert_eq!(second_pending.apply_id, "ffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn machine_transport_uses_only_the_fixed_a23_headers_and_frame() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let apply = update();
        let state = PendingState::acquire(&root, &apply.node_id).unwrap();
        let pending = PendingRecord::from_apply("https://control.example:8443", &apply).unwrap();
        publish_new(
            &state.state_root.directory,
            &state.pending_name().unwrap(),
            &serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
        let signer = signer_from_seed(
            "provisioner_a",
            [
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
                0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
                0x1c, 0xae, 0x7f, 0x60,
            ],
        );
        let authority = RequestAuthority::DeploymentProvisioner {
            deployment_id: Id::new("deployment_a".to_owned()).unwrap(),
            signer,
        };
        let transport = RecordingTransport::default();
        transport.respond_with(success_for(&pending));
        let response = send_pending(&state, &pending, &authority, &transport).unwrap();
        state.settle(&pending, response).unwrap();

        let requests = transport.requests.borrow();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.url,
            "https://control.example:8443/v1/admin/runtime/node-authority-applies"
        );
        assert_eq!(request.body, UPDATE);
        assert!(!request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization")));
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| *name == PROVISIONER_CREDENTIAL_ID_HEADER)
                .map(|(_, value)| value.as_str()),
            Some("provisioner_a")
        );
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| *name == PROVISIONER_SIGNATURE_HEADER)
                .map(|(_, value)| value.as_str()),
            Some("ODZ9ao3-zOZNrZSGcUq3se8HkOhcA7Jcxsag74DJ9gyk5ISaM_CngBLR9gCKcUXD4aI3gIjx_x-UDsA6GKaQAQ")
        );

        drop(requests);
        for entry in fs::read_dir(&root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let state_bytes = fs::read(entry.path()).unwrap();
                assert!(!state_bytes.windows(11).any(|part| part == b"PRIVATE KEY"));
                assert!(!state_bytes.windows(8).any(|part| part == b"9d61b19d"));
            }
        }
    }

    #[test]
    fn unresolved_pending_is_resigned_with_the_current_provisioner_key() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = generated_update(update());
        let state = PendingState::acquire(&root, desired.node_id()).unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        let pending_before = fs::read(state.pending_path()).unwrap();
        let deployment_id = Id::new("deployment_a".to_owned()).unwrap();
        let old = RequestAuthority::DeploymentProvisioner {
            deployment_id: deployment_id.clone(),
            signer: signer_from_seed(
                "provisioner_old",
                [
                    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92,
                    0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b,
                    0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
                ],
            ),
        };
        let current = RequestAuthority::DeploymentProvisioner {
            deployment_id,
            signer: signer_from_seed(
                "provisioner_current",
                [
                    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec,
                    0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c,
                    0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
                ],
            ),
        };
        let transport = RecordingTransport::default();
        transport.respond_with(response(503, b"retry".to_vec()));
        send_pending(&state, &pending, &old, &transport).unwrap();
        transport.respond_with(success_for(&pending));
        send_pending(&state, &pending, &current, &transport).unwrap();

        let requests = transport.requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
        let credential = |request: &OutboundRequest| {
            request
                .headers
                .iter()
                .find(|(name, _)| *name == PROVISIONER_CREDENTIAL_ID_HEADER)
                .map(|(_, value)| value.clone())
                .unwrap()
        };
        let signature = |request: &OutboundRequest| {
            request
                .headers
                .iter()
                .find(|(name, _)| *name == PROVISIONER_SIGNATURE_HEADER)
                .map(|(_, value)| value.clone())
                .unwrap()
        };
        assert_eq!(credential(&requests[0]), "provisioner_old");
        assert_eq!(credential(&requests[1]), "provisioner_current");
        assert_ne!(signature(&requests[0]), signature(&requests[1]));
        drop(requests);
        assert_eq!(fs::read(state.pending_path()).unwrap(), pending_before);
        assert!(!String::from_utf8_lossy(&pending_before).contains("provisioner_"));
    }

    #[test]
    fn provisioner_private_key_source_is_private_single_link_and_nofollow() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("provisioner.pem");
        let key_bytes = b"strict-pkcs8-input-is-parsed-after-the-file-contract";
        fs::write(&key, key_bytes).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private_key(&key).unwrap(), key_bytes);

        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_private_key(&key).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

        let second_link = directory.path().join("second-link.pem");
        fs::hard_link(&key, &second_link).unwrap();
        assert!(read_private_key(&key)
            .unwrap_err()
            .to_string()
            .contains("must have one link"));
        fs::remove_file(&second_link).unwrap();

        let symbolic_link = directory.path().join("symbolic-link.pem");
        symlink(&key, &symbolic_link).unwrap();
        assert!(read_private_key(&symbolic_link).is_err());
    }

    #[test]
    fn private_key_octets_never_enter_cli_state_or_transport() {
        use std::ffi::OsString;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let base = test_base(&directory);
        let key_path = base.join("provisioner-private.pem");
        let private_key = pkcs8_pem([0x43; 32]);
        fs::write(&key_path, &private_key).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let arguments = vec![
            OsString::from("cats"),
            OsString::from("admin"),
            OsString::from("runtime-node"),
            OsString::from("provision"),
            OsString::from("--identity"),
            OsString::from("unused-identity.json"),
            OsString::from("--policy"),
            OsString::from("unused-policy.json"),
            OsString::from("--deployment-id"),
            OsString::from("deployment_a"),
            OsString::from("--provisioner-credential-id"),
            OsString::from("provisioner_file_source"),
            OsString::from("--provisioner-private-key-file"),
            key_path.as_os_str().to_owned(),
        ];
        assert!(arguments.iter().all(|argument| {
            !argument
                .to_string_lossy()
                .as_bytes()
                .windows(private_key.len())
                .any(|part| part == private_key)
        }));
        let cli = Cli::parse_from(arguments);
        let source = match &cli.command {
            crate::Command::Admin {
                cmd:
                    crate::AdminCommand::RuntimeNode {
                        deployment_id,
                        provisioner_credential_id,
                        provisioner_private_key_file,
                        ..
                    },
            } => RuntimeNodeAuthorityAuth {
                deployment_id: deployment_id.as_deref(),
                provisioner_credential_id: provisioner_credential_id.as_deref(),
                provisioner_private_key_file: provisioner_private_key_file.as_deref(),
            },
            _ => unreachable!(),
        };

        let desired = generated_update(update());
        let root = base.join("state");
        let state = PendingState::acquire(&root, desired.node_id()).unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        let pending_bytes = fs::read(state.pending_path()).unwrap();
        let authority = request_authority(&cli, &source, "https://control.example:8443").unwrap();
        let transport = RecordingTransport::default();
        transport.respond_with(success_for(&pending));
        let response = send_pending(&state, &pending, &authority, &transport).unwrap();
        state.settle(&pending, response).unwrap();

        let key_path_bytes = key_path.to_string_lossy();
        let mut artifacts = vec![pending_bytes];
        for entry in fs::read_dir(&root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                artifacts.push(fs::read(entry.path()).unwrap());
            }
        }
        for artifact in artifacts {
            assert!(!artifact
                .windows(private_key.len())
                .any(|part| part == private_key));
            assert!(!String::from_utf8_lossy(&artifact).contains(key_path_bytes.as_ref()));
            assert!(!artifact
                .windows(b"BEGIN PRIVATE KEY".len())
                .any(|part| part == b"BEGIN PRIVATE KEY"));
        }
        for request in transport.requests.borrow().iter() {
            assert!(request.headers.iter().all(|(_, value)| {
                !value.contains(key_path_bytes.as_ref())
                    && !value
                        .as_bytes()
                        .windows(private_key.len())
                        .any(|part| part == private_key)
            }));
        }
    }

    #[test]
    fn root_replacement_blocks_old_send_and_keeps_one_parent_lock() {
        let directory = tempfile::tempdir().unwrap();
        let base = test_base(&directory);
        let root = base.join("state");
        let moved = base.join("state-old");
        let desired = generated_update(update());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let (sender, receiver) = mpsc::channel();
        let second_root = root.clone();
        let second_node = node.clone();
        let join = std::thread::spawn(move || {
            sender.send(PendingState::acquire(&second_root, &second_node).is_ok())
        });
        assert!(
            receiver.recv_timeout(Duration::from_millis(100)).is_err(),
            "replacement root must not create an independent per-Node lock"
        );

        let transport = RecordingTransport::default();
        transport.respond_with(success_for(&pending));
        assert!(send_pending(
            &state,
            &pending,
            &RequestAuthority::FleetAdministrator {
                access_token: "short-lived-workos-jwt".to_owned(),
            },
            &transport,
        )
        .is_err());
        assert_eq!(transport.request_count(), 0);
        drop(state);
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        join.join().unwrap().unwrap();
    }

    #[test]
    fn higher_ancestor_replacement_is_detected_under_the_global_lock() {
        let directory = tempfile::tempdir().unwrap();
        let base = test_base(&directory);
        let upper = base.join("upper");
        let old_upper = base.join("upper-old");
        let root = upper.join("config/runtime-node-authority-v1");
        let desired = generated_update(update());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();

        fs::rename(&upper, &old_upper).unwrap();
        fs::create_dir(&upper).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&upper, fs::Permissions::from_mode(0o700)).unwrap();

        let (sender, receiver) = mpsc::channel();
        let second_root = root.clone();
        let second_node = node.clone();
        let join = std::thread::spawn(move || {
            sender.send(PendingState::acquire(&second_root, &second_node).is_ok())
        });
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
        let transport = RecordingTransport::default();
        transport.respond_with(success_for(&pending));
        assert!(send_pending(
            &state,
            &pending,
            &RequestAuthority::FleetAdministrator {
                access_token: "short-lived-workos-jwt".to_owned(),
            },
            &transport,
        )
        .is_err());
        assert_eq!(transport.request_count(), 0);
        drop(state);
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        join.join().unwrap().unwrap();
    }

    #[test]
    fn relative_state_roots_are_rejected() {
        assert!(PendingState::acquire(Path::new("relative/state"), &update().node_id).is_err());
    }

    #[test]
    fn every_first_use_ancestor_sync_failure_prevents_authority() {
        let directory = tempfile::tempdir().unwrap();
        let base = test_base(&directory);
        let baseline = base.join("baseline/one/two/state");
        let expected_barriers = baseline
            .parent()
            .unwrap()
            .components()
            .filter(|component| matches!(component, std::path::Component::Normal(_)))
            .count()
            // Newly created baseline/one/two child directories.
            + 3
            // State-root parent entry barrier and newly created root barrier.
            + 2;
        let baseline_probe = DirectorySyncProbeGuard::start(None);
        StateRoot::open_or_create(&baseline).unwrap();
        assert_eq!(baseline_probe.count(), expected_barriers);
        drop(baseline_probe);

        let transport = RecordingTransport::default();
        for fail_at in 0..expected_barriers {
            let root = base.join(format!("case-{fail_at}/one/two/state"));
            let probe = DirectorySyncProbeGuard::start(Some(fail_at));
            let result = StateRoot::open_or_create(&root);
            assert!(result.is_err(), "directory sync window {fail_at}");
            assert_eq!(probe.count(), fail_at + 1);
        }
        assert_eq!(
            transport.request_count(),
            0,
            "no transport exists before every ancestor barrier succeeds"
        );
    }

    #[test]
    fn only_exact_bound_responses_are_terminal() {
        let pending = pending();
        assert!(matches!(
            classify_response(&pending, &success()).unwrap(),
            ResponseClassification::Terminal(TerminalOutcome::Applied(_))
        ));

        let mut wrong = success();
        wrong
            .headers
            .push(HeaderOccurrence::new("content-type", b"application/json"));
        assert!(matches!(
            classify_response(&pending, &wrong).unwrap(),
            ResponseClassification::Nonterminal
        ));

        let apply = update();
        let wrong_revision = RuntimeNodeAuthorityApplyResult {
            version: ContractVersion::V1,
            apply_id: apply.apply_id,
            node_id: apply.node_id,
            outcome: RuntimeNodeAuthorityOutcome::PolicyUpdated,
            identity_state: NodeIdentityState::Provisioned,
            policy_revision: Epoch::new(1).unwrap(),
        };
        let wrong_revision = response(
            200,
            encode_runtime_node_authority_apply_result(&wrong_revision).unwrap(),
        );
        assert!(matches!(
            classify_response(&pending, &wrong_revision).unwrap(),
            ResponseClassification::Nonterminal
        ));

        let mut compressed = success();
        compressed
            .headers
            .push(HeaderOccurrence::new("content-encoding", b"gzip"));
        assert!(matches!(
            classify_response(&pending, &compressed).unwrap(),
            ResponseClassification::Nonterminal
        ));

        let conflict = response(409, APPLY_ID_CONFLICT.to_vec());
        assert!(matches!(
            classify_response(&pending, &conflict).unwrap(),
            ResponseClassification::ApplyIdConflict
        ));

        let mut precondition = response(409, AUTHORITY_PRECONDITION_FAILED.to_vec());
        precondition.headers.push(HeaderOccurrence::new(
            NODE_AUTHORITY_APPLY_ID_HEADER,
            pending.apply_id.as_bytes(),
        ));
        assert!(matches!(
            classify_response(&pending, &precondition).unwrap(),
            ResponseClassification::Terminal(TerminalOutcome::AuthorityPreconditionFailed)
        ));
        precondition.headers.push(HeaderOccurrence::new(
            NODE_AUTHORITY_APPLY_ID_HEADER,
            pending.apply_id.as_bytes(),
        ));
        assert!(matches!(
            classify_response(&pending, &precondition).unwrap(),
            ResponseClassification::Nonterminal
        ));

        for status in [301, 302, 303, 307, 308, 401, 403, 429, 500, 503] {
            assert!(matches!(
                classify_response(&pending, &response(status, Vec::new())).unwrap(),
                ResponseClassification::Nonterminal
            ));
        }
        assert_eq!(AUTHORITY_PRECONDITION_FAILED.len(), 95);
    }

    #[test]
    fn stale_publish_temps_are_bounded_and_cleaned() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let exact = retire("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let desired = DesiredApply::Exact(exact.clone());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let target_name = state.pending_name().unwrap();
        let temporary_name = publish_temp_name(&target_name).unwrap();
        let temporary = root.join(temporary_name.to_string_lossy().as_ref());
        fs::write(&temporary, b"interrupted").unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        assert_eq!(pending.apply().unwrap(), exact);
        assert!(!temporary.exists());
    }

    #[test]
    fn linked_publish_window_recovers_without_replacing_pending() {
        let directory = tempfile::tempdir().unwrap();
        let root = test_base(&directory).join("state");
        let desired = generated_update(update());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let candidate = PendingRecord::from_apply("https://control.example", &update()).unwrap();
        let bytes = serde_json::to_vec(&candidate).unwrap();
        let target = state.pending_path();
        let temporary_name = publish_temp_name(&state.pending_name().unwrap()).unwrap();
        let temporary = root.join(temporary_name.to_string_lossy().as_ref());
        fs::write(&temporary, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::hard_link(&temporary, &target).unwrap();
        state.state_root.directory.sync_all().unwrap();
        drop(state);

        let state = PendingState::acquire(&root, &node).unwrap();
        let recovered = state.load_pending().unwrap().unwrap();
        assert_eq!(recovered, candidate);
        assert!(!temporary.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(target).unwrap().nlink(), 1);
        }
    }

    #[test]
    fn origins_are_closed_https_authorities() {
        assert_eq!(
            validate_https_origin("https://control.example:8443/").unwrap(),
            "https://control.example:8443"
        );
        assert_eq!(
            validate_https_origin("https://CONTROL.EXAMPLE:443").unwrap(),
            "https://control.example"
        );
        for invalid in [
            "http://control.example",
            "https://control.example/path",
            "https://control.example//",
            "https://user@control.example",
            "https://control.example?query",
        ] {
            assert!(validate_https_origin(invalid).is_err(), "{invalid}");
        }
    }
}

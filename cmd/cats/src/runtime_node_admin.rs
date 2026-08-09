//! Durable A23 Runtime Node-authority CLI state machine.
//!
//! The local pending record is authority for retries.  It is published before
//! the first HTTP send and contains no signing key or access token.  Only the
//! two terminal responses frozen by A23 can publish a resolution receipt and
//! durably remove that pending record.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cats_api::agent_registration::JSON_CONTENT_TYPE;
use cats_api::runtime_node_authority::{
    NODE_AUTHORITY_APPLY_ID_HEADER, RUNTIME_NODE_AUTHORITY_PATH,
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
    auth, config, Cli, RuntimeNodeCommand, RuntimeNodeCredentialCommand, RuntimeNodePolicyCommand,
};

const STATE_VERSION: u32 = 1;
const METHOD: &str = "POST";
const PENDING_MAX_BYTES: usize = 100_000;
const RECEIPT_MAX_BYTES: usize = 64_000;
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
            origin: origin.to_owned(),
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
}

struct PendingState {
    root: PathBuf,
    directory: File,
    _lock: File,
    slot: String,
}

impl PendingState {
    fn acquire(root: &Path, node_id: &Id) -> Result<Self> {
        let directory = open_or_create_state_directory(root)?;
        let slot = hex_digest(node_id.as_str().as_bytes());
        let lock_path = root.join(format!("node-{slot}.lock"));
        let lock_created = !lock_path.exists();
        let lock = open_state_lock(&lock_path)?;
        FileExt::lock_exclusive(&lock)
            .with_context(|| format!("lock Runtime Node authority state for {node_id}"))?;
        validate_private_regular_file(&lock, &lock_path)?;
        if lock_created {
            directory
                .sync_all()
                .with_context(|| format!("sync state directory {}", root.display()))?;
        }
        Ok(Self {
            root: root.to_owned(),
            directory,
            _lock: lock,
            slot,
        })
    }

    fn pending_path(&self) -> PathBuf {
        self.root.join(format!("node-{}.pending.json", self.slot))
    }

    fn receipt_path(&self, apply_id: &str) -> PathBuf {
        self.root
            .join(format!("node-{}.{}.resolution.json", self.slot, apply_id))
    }

    fn load_pending(&self) -> Result<Option<PendingRecord>> {
        let path = self.pending_path();
        cleanup_publish_temp(&self.directory, &path)?;
        let Some(bytes) = read_optional_state_file(&path, PENDING_MAX_BYTES)? else {
            return Ok(None);
        };
        let pending: PendingRecord = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse pending state {}", path.display()))?;
        anyhow::ensure!(
            serde_json::to_vec(&pending)? == bytes,
            "pending state {} is not canonical",
            path.display()
        );
        pending.apply()?;
        Ok(Some(pending))
    }

    fn prepare(&self, origin: &str, desired: &DesiredApply) -> Result<PendingRecord> {
        let existing = self.load_pending()?;
        let apply = desired.materialize(existing.as_ref())?;
        let candidate = PendingRecord::from_apply(origin, &apply)?;
        if let Some(existing) = existing {
            anyhow::ensure!(
                existing == candidate,
                "the unresolved Runtime Node authority request is bound to a different origin or body"
            );
            return Ok(existing);
        }
        let bytes = serde_json::to_vec(&candidate)?;
        anyhow::ensure!(
            bytes.len() <= PENDING_MAX_BYTES,
            "pending state exceeds its bound"
        );
        publish_new(&self.directory, &self.pending_path(), &bytes)?;
        Ok(candidate)
    }

    fn recover_resolution(&self, pending: &PendingRecord) -> Result<Option<TerminalOutcome>> {
        let path = self.receipt_path(&pending.apply_id);
        cleanup_publish_temp(&self.directory, &path)?;
        let Some(bytes) = read_optional_state_file(&path, RECEIPT_MAX_BYTES)? else {
            return Ok(None);
        };
        let receipt: ResolutionReceipt = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse resolution receipt {}", path.display()))?;
        anyhow::ensure!(
            serde_json::to_vec(&receipt)? == bytes,
            "resolution receipt {} is not canonical",
            path.display()
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
        self.delete_pending()?;
        Ok(Some(terminal))
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
        let path = self.receipt_path(&pending.apply_id);
        match publish_new(&self.directory, &path, &bytes) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
            {
                let existing = read_optional_state_file(&path, RECEIPT_MAX_BYTES)?
                    .context("resolution receipt disappeared")?;
                anyhow::ensure!(
                    existing == bytes,
                    "a different resolution receipt already exists for apply {}",
                    pending.apply_id
                );
            }
            Err(error) => return Err(error),
        }
        self.delete_pending()?;
        Ok(terminal)
    }

    fn delete_pending(&self) -> Result<()> {
        let path = self.pending_path();
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("remove pending state {}", path.display()))
            }
        }
        self.directory
            .sync_all()
            .with_context(|| format!("sync state directory {}", self.root.display()))
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

pub(crate) fn run(cli: &Cli, command: &RuntimeNodeCommand) -> Result<()> {
    let origin = validate_https_origin(&auth::configured_api_url(cli.api_url.as_deref())?)?;
    let desired = desired_apply(command)?;
    let state_root = state_root()?;
    let state = PendingState::acquire(&state_root, desired.node_id())?;
    let pending = state.prepare(&origin, &desired)?;

    if let Some(terminal) = state.recover_resolution(&pending)? {
        return report_terminal(cli, terminal);
    }

    let token = authority_access_token(cli, &origin)?;
    let response = send_pending(&pending, &token).with_context(|| {
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

fn authority_access_token(cli: &Cli, origin: &str) -> Result<String> {
    if let Some(token) = &cli.token {
        anyhow::ensure!(!token.is_empty(), "--token is empty");
        return Ok(token.clone());
    }
    let session = auth::user_session(cli.api_url.as_deref(), cli.workspace.as_deref())?;
    anyhow::ensure!(
        validate_https_origin(&session.api_url)? == origin,
        "login session origin changed after the request became pending"
    );
    Ok(session.access_token)
}

fn send_pending(pending: &PendingRecord, token: &str) -> Result<StoredHttpResponse> {
    pending.apply()?;
    let request_url = format!("{}{}", pending.origin, pending.target);
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .context("build closed Runtime Node authority HTTP client")?;
    let mut response = client
        .post(&request_url)
        .header(reqwest::header::CONTENT_TYPE, pending.content_type.as_str())
        .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .bearer_auth(token)
        .body(pending.body()?)
        .send()
        .context("send Runtime Node authority request")?;
    anyhow::ensure!(
        response.url().as_str() == request_url,
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
    let origin = value.trim_end_matches('/');
    let parsed = reqwest::Url::parse(origin).context("invalid Runtime Node authority origin")?;
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
    Ok(origin.to_owned())
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

fn read_optional_state_file(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>> {
    let file = match open_read_only_nofollow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open state {}", path.display())),
    };
    validate_private_regular_file(&file, path)?;
    read_bounded(file, maximum)
        .with_context(|| format!("read state {}", path.display()))
        .map(Some)
}

fn read_bounded(file: File, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= maximum, "file exceeds its closed byte limit");
    Ok(bytes)
}

fn open_or_create_state_directory(path: &Path) -> Result<File> {
    let parent = path
        .parent()
        .context("Runtime Node state path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create state parent {}", parent.display()))?;
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error).with_context(|| format!("create state directory {}", path.display()))
        }
    };
    #[cfg(unix)]
    if created {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "state path is not a directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.uid() == effective_uid(),
            "state directory has a different owner"
        );
        anyhow::ensure!(
            metadata.mode() & 0o077 == 0,
            "state directory is accessible to another user"
        );
    }
    let directory = open_directory_nofollow(path)?;
    if created {
        open_directory_nofollow(parent)?.sync_all()?;
        directory.sync_all()?;
    }
    Ok(directory)
}

fn open_state_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    Ok(options.open(path)?)
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

fn publish_new(directory: &File, target: &Path, bytes: &[u8]) -> Result<()> {
    cleanup_publish_temp(directory, target)?;
    let temporary = publish_temp_path(target)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create temporary state {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Err(error) = rename_noreplace(&temporary, target) {
        let _ = fs::remove_file(&temporary);
        let _ = directory.sync_all();
        return Err(error).with_context(|| format!("publish state {}", target.display()));
    }
    directory.sync_all()?;
    Ok(())
}

fn cleanup_publish_temp(directory: &File, target: &Path) -> Result<()> {
    let temporary = publish_temp_path(target)?;
    match fs::remove_file(&temporary) {
        Ok(()) => directory.sync_all().context("sync state temp cleanup"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove stale state temp {}", temporary.display()))
        }
    }
}

fn publish_temp_path(target: &Path) -> Result<PathBuf> {
    let name = target.file_name().context("state target has no basename")?;
    Ok(target.with_file_name(format!(".{}.tmp", name.to_string_lossy())))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, target: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: both C strings are NUL-terminated and live for the duration of
    // the call. `AT_FDCWD` resolves the exact paths supplied above, and
    // `RENAME_NOREPLACE` makes the publication atomic without overwriting an
    // existing authority record.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(source: &Path, target: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: both C strings are NUL-terminated and live for the duration of
    // the call. `RENAME_EXCL` is Darwin's atomic no-replace rename flag.
    let result = unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(source: &Path, target: &Path) -> io::Result<()> {
    // The supported production platforms use an actual no-replace rename.
    // A hard link is the portable same-filesystem no-replace publication
    // fallback; unlinking the temporary name leaves the target inode intact.
    fs::hard_link(source, target)?;
    fs::remove_file(source)
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no pointers and only reads the calling process's
    // effective credential; it cannot violate Rust memory invariants.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPDATE: &[u8] = br#"{"apply_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}"#;

    fn update() -> RuntimeNodeAuthorityApply {
        decode_runtime_node_authority_apply(UPDATE).unwrap()
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

    #[test]
    fn pending_is_published_once_and_replayed_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("state");
        let desired = DesiredApply::Exact(update());
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
    fn durable_receipt_wins_crash_before_pending_delete() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("state");
        let desired = DesiredApply::Exact(update());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        let stored = success();
        let receipt = ResolutionReceipt {
            version: STATE_VERSION,
            apply_id: pending.apply_id.clone(),
            node_id: pending.node_id.clone(),
            request_sha256: pending.request_sha256.clone(),
            response: stored,
        };
        publish_new(
            &state.directory,
            &state.receipt_path(&pending.apply_id),
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
        assert!(state.receipt_path(&pending.apply_id).exists());
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
        let root = directory.path().join("state");
        let desired = DesiredApply::Exact(update());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let target = state.pending_path();
        let temporary = publish_temp_path(&target).unwrap();
        fs::write(&temporary, b"interrupted").unwrap();
        let pending = state
            .prepare("https://control.example:8443", &desired)
            .unwrap();
        assert_eq!(pending.body().unwrap(), UPDATE);
        assert!(!temporary.exists());
    }

    #[test]
    fn linked_publish_window_recovers_without_replacing_pending() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("state");
        let desired = DesiredApply::Exact(update());
        let node = desired.node_id().clone();
        let state = PendingState::acquire(&root, &node).unwrap();
        let candidate = PendingRecord::from_apply("https://control.example", &update()).unwrap();
        let bytes = serde_json::to_vec(&candidate).unwrap();
        let target = state.pending_path();
        let temporary = publish_temp_path(&target).unwrap();
        fs::write(&temporary, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::hard_link(&temporary, &target).unwrap();
        state.directory.sync_all().unwrap();
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
        for invalid in [
            "http://control.example",
            "https://control.example/path",
            "https://user@control.example",
            "https://control.example?query",
        ] {
            assert!(validate_https_origin(invalid).is_err(), "{invalid}");
        }
    }
}

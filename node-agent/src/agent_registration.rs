//! Crash-safe Node registration over the one runtime-internal transport.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _};
use cats_api::agent_registration::{
    decode_agent_registration_error, AgentRegistrationErrorDetail, Ed25519RequestSigner,
    HttpRequestRejection, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
    REGISTRATION_ERROR_MAX_WIRE_BYTES, REGISTRATION_METHOD, REGISTRATION_PATH,
    REGISTRATION_SUCCESS_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    decode_agent_registration_attempt, decode_agent_session, decode_node_identity,
    encode_agent_registration_attempt, encode_agent_session, encode_node_identity,
    guest_config_digest, AgentRegistrationAttempt, AgentSession, ContractVersion,
    CredentialBinding, Epoch, GuestRuntimeProfileReceipt, NodeBootId, NodeIdentity,
    NodeIdentityState, RandomId128,
};

pub const NODE_IDENTITY_PATH: &str = "/etc/cats/identity/node-identity.v1.json";
pub const NODE_REGISTRATION_KEY_PATH: &str = "/etc/cats/identity/node-registration-key.pem";
pub const NODE_REGISTRATION_CREDENTIAL_ID_PATH: &str =
    "/etc/cats/identity/node-registration-credential-id";
pub const NODE_STATE_ROOT: &str = "/var/lib/cats/node";
pub const HOST_LOCK_BASENAME: &str = "host.lock";
pub const PENDING_ATTEMPT_RELATIVE_PATH: &str = "agent-registration/pending-attempt.json";
pub const SESSION_RELATIVE_PATH: &str = "agent-registration/session.json";

const IDENTITY_MAX_BYTES: usize = 16_384;
const PRIVATE_KEY_MAX_BYTES: usize = 16_384;
const CREDENTIAL_ID_MAX_BYTES: usize = 129;
const INITIAL_RETRY: Duration = Duration::from_millis(200);
const MAX_RETRY: Duration = Duration::from_secs(30);

/// Fully cross-checked local authority needed to construct registration.
///
/// The retained Host-lock descriptor is deliberately part of the value, so
/// no caller can separate identity consumption from exclusive state access.
#[derive(Clone)]
pub struct AgentRegistrationConfig {
    identity: Arc<NodeIdentity>,
    signer: Ed25519RequestSigner,
    state_path: PathBuf,
    node_boot_id: NodeBootId,
    guest_config_digest: cats_api::runtime_reconciliation::Sha256Digest,
    _host_lock: Arc<File>,
    transport: RegistrationTransport,
}

#[derive(Clone, Copy)]
enum RegistrationTransport {
    ProductionHttps,
    LoopbackTest,
}

impl std::fmt::Debug for AgentRegistrationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentRegistrationConfig")
            .field("node_id", &self.identity.node_id)
            .field("immutable_host_id", &self.identity.immutable_host_id)
            .field("state_path", &self.state_path)
            .finish_non_exhaustive()
    }
}

impl AgentRegistrationConfig {
    /// Loads only the fixed production identity/key/state paths.
    pub fn load_installed(receipt: &GuestRuntimeProfileReceipt) -> anyhow::Result<Self> {
        validate_identity_ancestors()?;
        let identity_bytes =
            read_exact_root_file(Path::new(NODE_IDENTITY_PATH), 0o600, IDENTITY_MAX_BYTES)?;
        let key_bytes = read_exact_root_file(
            Path::new(NODE_REGISTRATION_KEY_PATH),
            0o600,
            PRIVATE_KEY_MAX_BYTES,
        )?;
        let credential_bytes = read_exact_root_file(
            Path::new(NODE_REGISTRATION_CREDENTIAL_ID_PATH),
            0o600,
            CREDENTIAL_ID_MAX_BYTES,
        )?;
        let (identity, signer) =
            validate_identity_material(&identity_bytes, &key_bytes, &credential_bytes)?;
        let state_path = Path::new(NODE_STATE_ROOT).join(identity.state_path_id.as_str());
        let host_lock = open_and_lock_state_path(&state_path)?;
        Ok(Self {
            identity: Arc::new(identity),
            signer,
            state_path,
            node_boot_id: installed_node_boot_id()?,
            guest_config_digest: guest_config_digest(receipt)
                .map_err(|_| anyhow::anyhow!("installed Guest runtime receipt is invalid"))?,
            _host_lock: Arc::new(host_lock),
            transport: RegistrationTransport::ProductionHttps,
        })
    }

    /// Explicit loopback-only constructor for process and crash tests.
    #[doc(hidden)]
    pub fn for_loopback_test(
        identity: NodeIdentity,
        signer: Ed25519RequestSigner,
        state_path: PathBuf,
        node_boot_id: NodeBootId,
        receipt: &GuestRuntimeProfileReceipt,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            identity.state == NodeIdentityState::Provisioned,
            "test identity must be provisioned"
        );
        anyhow::ensure!(
            identity.credential_id == *signer.credential_id(),
            "test credential ID does not match signer"
        );
        anyhow::ensure!(
            identity.credential_binding
                == (CredentialBinding::PublicKey {
                    public_key_spki_sha256: signer.public_key_spki_sha256(),
                }),
            "test credential binding does not match signer"
        );
        std::fs::create_dir_all(&state_path)?;
        let lock_path = state_path.join(HOST_LOCK_BASENAME);
        let host_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        lock_exclusive_nonblocking(&host_lock)?;
        Ok(Self {
            identity: Arc::new(identity),
            signer,
            state_path,
            node_boot_id,
            guest_config_digest: guest_config_digest(receipt)
                .map_err(|_| anyhow::anyhow!("test Guest runtime receipt is invalid"))?,
            _host_lock: Arc::new(host_lock),
            transport: RegistrationTransport::LoopbackTest,
        })
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Keeps one exact pending attempt durable across every ambiguous result.
    /// A returned session has already been validated, fsynced, and made the
    /// sole durable current session before the pending file was removed.
    pub async fn register_until_session(
        &self,
        control_plane_origin: &str,
    ) -> anyhow::Result<AgentSession> {
        let origin = validate_control_plane_origin(control_plane_origin, self.transport)?;
        let registration_dir = self.state_path.join("agent-registration");
        ensure_registration_directory(&registration_dir, self.transport)?;
        let pending_path = self.state_path.join(PENDING_ATTEMPT_RELATIVE_PATH);
        let session_path = self.state_path.join(SESSION_RELATIVE_PATH);
        let agent_instance_id = random_id();
        let existing_pending =
            read_optional_bounded(&pending_path, IDENTITY_MAX_BYTES, self.transport)?;
        let mut pending = match existing_pending {
            Some(bytes) => {
                let attempt = decode_agent_registration_attempt(&bytes).map_err(|_| {
                    anyhow::anyhow!("durable Agent registration attempt is invalid")
                })?;
                self.validate_pending(&attempt)?;
                DurableAttempt { attempt, bytes }
            }
            None => {
                let expected = self.load_previous_epoch(&session_path)?;
                self.create_pending(&pending_path, agent_instance_id.clone(), expected)?
            }
        };
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .context("build Agent registration HTTP client")?;
        let url = origin
            .join(REGISTRATION_PATH)
            .expect("validated origin accepts the fixed registration path");
        let mut backoff = INITIAL_RETRY;
        loop {
            let proof = self
                .signer
                .sign(REGISTRATION_METHOD, REGISTRATION_PATH, &pending.bytes);
            let response = client
                .post(url.clone())
                .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
                .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
                .header(NODE_SIGNATURE_HEADER, proof.signature)
                .body(pending.bytes.clone())
                .send()
                .await;
            match classify_response(response, &pending.attempt).await {
                RegistrationResult::Accepted(session) => {
                    atomic_replace(
                        &session_path,
                        &encode_agent_session(&session).map_err(|_| {
                            anyhow::anyhow!("accepted Agent session cannot be canonically encoded")
                        })?,
                    )?;
                    remove_durable(&pending_path)?;
                    // A pending file loaded at process startup belongs to the
                    // process that durably created it. Resolve its ambiguous
                    // result first, then replace that old process/boot binding
                    // before any runtime gate can consume a session.
                    if session.node_boot_id != self.node_boot_id
                        || session.agent_instance_id != agent_instance_id
                    {
                        pending = self.create_pending(
                            &pending_path,
                            agent_instance_id.clone(),
                            Some(session.agent_session_epoch),
                        )?;
                        backoff = INITIAL_RETRY;
                        continue;
                    }
                    return Ok(session);
                }
                RegistrationResult::ReplaceExpected(current_epoch) => {
                    pending = self.create_pending(
                        &pending_path,
                        agent_instance_id.clone(),
                        current_epoch,
                    )?;
                    backoff = INITIAL_RETRY;
                }
                RegistrationResult::Terminal(error) => return Err(error),
                RegistrationResult::Ambiguous(reason) => {
                    tracing::warn!(
                        node = %self.identity.node_id,
                        registration_attempt_id = %pending.attempt.registration_attempt_id,
                        %reason,
                        "Agent registration result is ambiguous; retrying the exact durable attempt"
                    );
                    tokio::time::sleep(jittered(backoff, &pending.attempt.registration_attempt_id))
                        .await;
                    backoff = backoff.saturating_mul(2).min(MAX_RETRY);
                }
            }
        }
    }

    fn load_previous_epoch(&self, session_path: &Path) -> anyhow::Result<Option<Epoch>> {
        let Some(bytes) = read_optional_bounded(
            session_path,
            REGISTRATION_SUCCESS_MAX_WIRE_BYTES,
            self.transport,
        )?
        else {
            return Ok(None);
        };
        let session = decode_agent_session(&bytes)
            .map_err(|_| anyhow::anyhow!("durable Agent session is invalid"))?;
        self.validate_session_identity(&session)?;
        Ok(Some(session.agent_session_epoch))
    }

    fn create_pending(
        &self,
        path: &Path,
        agent_instance_id: RandomId128,
        expected_agent_session_epoch: Option<Epoch>,
    ) -> anyhow::Result<DurableAttempt> {
        let attempt = AgentRegistrationAttempt {
            version: ContractVersion::V1,
            node_id: self.identity.node_id.clone(),
            immutable_host_id: self.identity.immutable_host_id.clone(),
            node_boot_id: self.node_boot_id.clone(),
            agent_instance_id,
            registration_attempt_id: random_id(),
            guest_config_digest: self.guest_config_digest.clone(),
            expected_agent_session_epoch,
        };
        let bytes = encode_agent_registration_attempt(&attempt)
            .map_err(|_| anyhow::anyhow!("new Agent registration attempt is invalid"))?;
        atomic_replace(path, &bytes)?;
        Ok(DurableAttempt { attempt, bytes })
    }

    fn validate_pending(&self, attempt: &AgentRegistrationAttempt) -> anyhow::Result<()> {
        anyhow::ensure!(
            attempt.node_id == self.identity.node_id
                && attempt.immutable_host_id == self.identity.immutable_host_id
                && attempt.guest_config_digest == self.guest_config_digest,
            "durable pending attempt does not match installed identity and release"
        );
        Ok(())
    }

    fn validate_session_identity(&self, session: &AgentSession) -> anyhow::Result<()> {
        anyhow::ensure!(
            session.node_id == self.identity.node_id
                && session.immutable_host_id == self.identity.immutable_host_id
                && session.guest_config_digest == self.guest_config_digest,
            "durable Agent session does not match installed identity and release"
        );
        Ok(())
    }
}

struct DurableAttempt {
    attempt: AgentRegistrationAttempt,
    bytes: Vec<u8>,
}

enum RegistrationResult {
    Accepted(AgentSession),
    ReplaceExpected(Option<Epoch>),
    Terminal(anyhow::Error),
    Ambiguous(String),
}

async fn classify_response(
    response: Result<reqwest::Response, reqwest::Error>,
    attempt: &AgentRegistrationAttempt,
) -> RegistrationResult {
    let mut response = match response {
        Ok(response) => response,
        Err(error) => return RegistrationResult::Ambiguous(format!("request failed: {error}")),
    };
    let status = response.status();
    let expected_cap = if status == reqwest::StatusCode::OK {
        REGISTRATION_SUCCESS_MAX_WIRE_BYTES
    } else {
        REGISTRATION_ERROR_MAX_WIRE_BYTES
    };
    if response
        .headers()
        .contains_key(reqwest::header::CONTENT_ENCODING)
        || (status != reqwest::StatusCode::NOT_FOUND
            && !has_one_exact_header(
                response.headers(),
                reqwest::header::CONTENT_TYPE,
                JSON_CONTENT_TYPE,
            ))
    {
        return RegistrationResult::Ambiguous(format!(
            "registration response {status} has invalid representation headers"
        ));
    }
    if declared_response_exceeds(response.headers(), expected_cap) {
        return RegistrationResult::Ambiguous(format!(
            "registration response {status} exceeds its wire limit"
        ));
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= expected_cap => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) => {
                return RegistrationResult::Ambiguous(format!(
                    "registration response {status} exceeds its wire limit"
                ));
            }
            Ok(None) => break,
            Err(error) => {
                return RegistrationResult::Ambiguous(format!(
                    "registration response body failed: {error}"
                ));
            }
        }
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        if response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
            || (has_one_exact_header(
                response.headers(),
                reqwest::header::CONTENT_TYPE,
                JSON_CONTENT_TYPE,
            ) && decode_agent_registration_error(&body).is_ok())
        {
            return RegistrationResult::Ambiguous(
                "registration returned a non-plain 404 response".into(),
            );
        }
        return RegistrationResult::Terminal(anyhow::anyhow!(
            "Agent registration route is not deployed"
        ));
    }
    if status == reqwest::StatusCode::OK {
        let session = match decode_agent_session(&body) {
            Ok(session) => session,
            Err(_) => {
                return RegistrationResult::Ambiguous(
                    "200 registration response is not a canonical AgentSession".into(),
                );
            }
        };
        if !session_matches_attempt(&session, attempt) {
            return RegistrationResult::Ambiguous(
                "200 registration response does not match the pending attempt".into(),
            );
        }
        return RegistrationResult::Accepted(session);
    }
    let envelope = match decode_agent_registration_error(&body) {
        Ok(envelope) => envelope,
        Err(_) => {
            return RegistrationResult::Ambiguous(format!(
                "registration response {status} has no canonical typed error"
            ));
        }
    };
    match (&envelope.error, status) {
        (
            AgentRegistrationErrorDetail::SessionEpochMismatch {
                current_agent_session_epoch,
                presented_expected_agent_session_epoch,
            },
            reqwest::StatusCode::CONFLICT,
        ) if *presented_expected_agent_session_epoch == attempt.expected_agent_session_epoch => {
            if current_agent_session_epoch == presented_expected_agent_session_epoch {
                RegistrationResult::Ambiguous(
                    "registration epoch-mismatch response carried equal epochs".into(),
                )
            } else {
                RegistrationResult::ReplaceExpected(*current_agent_session_epoch)
            }
        }
        (AgentRegistrationErrorDetail::AuthenticationFailed, reqwest::StatusCode::UNAUTHORIZED)
            if has_one_exact_header(
                response.headers(),
                reqwest::header::WWW_AUTHENTICATE,
                NODE_AUTHENTICATE_CHALLENGE,
            ) =>
        {
            terminal_error(status, envelope.message)
        }
        (AgentRegistrationErrorDetail::IdentityNotEligible, reqwest::StatusCode::FORBIDDEN)
        | (
            AgentRegistrationErrorDetail::HttpRequestRejected {
                problem:
                    HttpRequestRejection::QueryNotAllowed
                    | HttpRequestRejection::AuthorizationNotAllowed,
            },
            reqwest::StatusCode::BAD_REQUEST,
        )
        | (
            AgentRegistrationErrorDetail::HttpRequestRejected {
                problem:
                    HttpRequestRejection::ContentTypeNotAllowed
                    | HttpRequestRejection::ContentEncodingNotAllowed,
            },
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ) => terminal_error(status, envelope.message),
        (AgentRegistrationErrorDetail::ContractError { contract_error }, status)
            if contract_error_status_matches(contract_error, status) =>
        {
            terminal_error(status, envelope.message)
        }
        (
            AgentRegistrationErrorDetail::HttpRequestRejected {
                problem: HttpRequestRejection::MethodNotAllowed,
            },
            reqwest::StatusCode::METHOD_NOT_ALLOWED,
        ) if has_one_exact_header(
            response.headers(),
            reqwest::header::ALLOW,
            REGISTRATION_METHOD,
        ) =>
        {
            terminal_error(status, envelope.message)
        }
        (
            AgentRegistrationErrorDetail::TemporarilyUnavailable,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        )
        | (AgentRegistrationErrorDetail::Internal, reqwest::StatusCode::INTERNAL_SERVER_ERROR) => {
            RegistrationResult::Ambiguous(format!("registration returned typed {status}"))
        }
        _ => RegistrationResult::Ambiguous(format!(
            "registration returned mismatched typed status {status}"
        )),
    }
}

fn contract_error_status_matches(
    contract_error: &cats_api::runtime_reconciliation::ContractError,
    status: reqwest::StatusCode,
) -> bool {
    use cats_api::runtime_reconciliation::ContractErrorDetail;

    matches!(
        (contract_error.error.as_ref(), status),
        (
            ContractErrorDetail::MalformedPayload { .. }
                | ContractErrorDetail::UnsupportedVersion { .. },
            reqwest::StatusCode::BAD_REQUEST
        ) | (
            ContractErrorDetail::LimitExceeded { .. },
            reqwest::StatusCode::PAYLOAD_TOO_LARGE
        ) | (
            ContractErrorDetail::RegistrationAttemptConflict { .. },
            reqwest::StatusCode::CONFLICT
        ) | (
            ContractErrorDetail::GuestConfigMismatch { .. },
            reqwest::StatusCode::PRECONDITION_FAILED
        )
    )
}

fn terminal_error(status: reqwest::StatusCode, message: String) -> RegistrationResult {
    RegistrationResult::Terminal(anyhow::anyhow!(
        "Agent registration was rejected with {status}: {message}"
    ))
}

fn session_matches_attempt(session: &AgentSession, attempt: &AgentRegistrationAttempt) -> bool {
    session.version == attempt.version
        && session.node_id == attempt.node_id
        && session.immutable_host_id == attempt.immutable_host_id
        && session.node_boot_id == attempt.node_boot_id
        && session.agent_instance_id == attempt.agent_instance_id
        && session.registration_attempt_id == attempt.registration_attempt_id
        && session.guest_config_digest == attempt.guest_config_digest
}

fn has_one_exact_header(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(expected) && values.next().is_none()
}

fn declared_response_exceeds(headers: &reqwest::header::HeaderMap, cap: usize) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_some()
        || value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_none_or(|length| length > cap as u64)
}

fn validate_control_plane_origin(
    input: &str,
    transport: RegistrationTransport,
) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(input).context("parse --control-plane-url")?;
    anyhow::ensure!(
        url.username().is_empty(),
        "control-plane origin has userinfo"
    );
    anyhow::ensure!(
        url.password().is_none(),
        "control-plane origin has userinfo"
    );
    anyhow::ensure!(url.query().is_none(), "control-plane origin has a query");
    anyhow::ensure!(
        url.fragment().is_none(),
        "control-plane origin has a fragment"
    );
    anyhow::ensure!(url.path() == "/", "control-plane origin has a path");
    anyhow::ensure!(url.host_str().is_some(), "control-plane origin has no host");
    match transport {
        RegistrationTransport::ProductionHttps => {
            anyhow::ensure!(
                url.scheme() == "https",
                "production control-plane origin must use HTTPS"
            );
        }
        RegistrationTransport::LoopbackTest => {
            anyhow::ensure!(
                url.scheme() == "http"
                    && url
                        .host_str()
                        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                        .is_some_and(|host| host.is_loopback()),
                "test HTTP control-plane origin must be a loopback IP"
            );
        }
    }
    Ok(url)
}

fn validate_identity_material(
    identity_bytes: &[u8],
    key_bytes: &[u8],
    credential_bytes: &[u8],
) -> anyhow::Result<(NodeIdentity, Ed25519RequestSigner)> {
    let identity = decode_node_identity(identity_bytes)
        .map_err(|_| anyhow::anyhow!("NodeIdentity artifact is invalid"))?;
    anyhow::ensure!(
        encode_node_identity(&identity).is_ok_and(|canonical| canonical == identity_bytes),
        "NodeIdentity artifact is not canonical"
    );
    anyhow::ensure!(
        identity.state == NodeIdentityState::Provisioned,
        "NodeIdentity is not provisioned"
    );
    cats_api::agent_registration::validate_state_path_component(&identity.state_path_id)
        .context("NodeIdentity state_path_id is not a safe path component")?;
    let expected_credential = format!("{}\n", identity.credential_id);
    anyhow::ensure!(
        credential_bytes == expected_credential.as_bytes(),
        "credential ID file does not exactly match NodeIdentity"
    );
    let signer = Ed25519RequestSigner::from_pkcs8_pem(identity.credential_id.clone(), key_bytes)
        .context("parse Node registration private key")?;
    let CredentialBinding::PublicKey {
        public_key_spki_sha256,
    } = &identity.credential_binding
    else {
        bail!("NodeIdentity credential binding is not an Ed25519 public key")
    };
    anyhow::ensure!(
        public_key_spki_sha256 == &signer.public_key_spki_sha256(),
        "Node registration private key does not match NodeIdentity binding"
    );
    Ok((identity, signer))
}

fn validate_identity_ancestors() -> anyhow::Result<()> {
    for (path, exact_mode) in [
        ("/", None),
        ("/etc", None),
        ("/etc/cats", None),
        ("/etc/cats/identity", Some(0o700)),
    ] {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspect identity ancestor {path}"))?;
        anyhow::ensure!(
            metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && exact_mode
                    .map(|mode| metadata.mode() & 0o777 == mode)
                    .unwrap_or_else(|| metadata.mode() & 0o022 == 0),
            "identity ancestor {path} violates owner/mode/type contract"
        );
    }
    Ok(())
}

fn read_exact_root_file(path: &Path, mode: u32, cap: usize) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let before = StableMetadata::new(&file.metadata()?);
    anyhow::ensure!(
        before.is_exact_file(mode),
        "{} metadata is invalid",
        path.display()
    );
    anyhow::ensure!(
        before.len <= cap as u64,
        "{} exceeds its byte cap",
        path.display()
    );
    let mut bytes = Vec::with_capacity(before.len as usize);
    std::io::Read::by_ref(&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= cap,
        "{} exceeds its byte cap",
        path.display()
    );
    let after = StableMetadata::new(&file.metadata()?);
    anyhow::ensure!(
        before == after && bytes.len() as u64 == after.len,
        "{} changed while being read",
        path.display()
    );
    Ok(bytes)
}

fn open_and_lock_state_path(state_path: &Path) -> anyhow::Result<File> {
    for path in [
        Path::new("/"),
        Path::new("/var"),
        Path::new("/var/lib"),
        Path::new("/var/lib/cats"),
        Path::new(NODE_STATE_ROOT),
        state_path,
    ] {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspect state path {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0,
            "state path {} violates owner/mode/type contract",
            path.display()
        );
    }
    let lock_path = state_path.join(HOST_LOCK_BASENAME);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| format!("open Host lock {}", lock_path.display()))?;
    let metadata = StableMetadata::new(&lock.metadata()?);
    anyhow::ensure!(
        metadata.is_exact_file(0o600),
        "Host lock violates owner/mode/type contract"
    );
    lock_exclusive_nonblocking(&lock)?;
    Ok(lock)
}

fn lock_exclusive_nonblocking(file: &File) -> anyhow::Result<()> {
    // SAFETY: `file` owns a live descriptor for the entire call. `flock`
    // neither retains the pointer nor accesses Rust memory.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    anyhow::ensure!(result == 0, "another Node process holds the Host lock");
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct StableMetadata {
    dev: u64,
    ino: u64,
    is_file: bool,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl StableMetadata {
    fn new(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            is_file: metadata.file_type().is_file(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        }
    }

    fn is_exact_file(self, mode: u32) -> bool {
        self.is_file
            && self.mode & 0o777 == mode
            && self.uid == 0
            && self.gid == 0
            && self.nlink == 1
    }
}

fn installed_node_boot_id() -> anyhow::Result<NodeBootId> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read kernel boot ID")?;
    let compact = text.strip_suffix('\n').unwrap_or(&text).replace('-', "");
    NodeBootId::new(compact).ok_or_else(|| anyhow::anyhow!("kernel boot ID is invalid"))
}

fn random_id() -> RandomId128 {
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .expect("UUID simple form is a nonzero 128-bit random ID")
}

fn jittered(base: Duration, attempt_id: &RandomId128) -> Duration {
    let last = u16::from_str_radix(&attempt_id.as_str()[28..], 16).unwrap_or(0) as u64;
    let percent = 75 + last % 51;
    base.saturating_mul(percent as u32) / 100
}

fn ensure_registration_directory(
    path: &Path,
    transport: RegistrationTransport,
) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    let (uid, gid) = expected_state_owner(transport);
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == uid
            && metadata.gid() == gid
            && metadata.mode() & 0o777 == 0o700,
        "Agent registration state directory violates owner/mode/type contract"
    );
    Ok(())
}

fn expected_state_owner(transport: RegistrationTransport) -> (u32, u32) {
    match transport {
        RegistrationTransport::ProductionHttps => (0, 0),
        // SAFETY: these libc calls have no preconditions and only return the
        // effective identity of the current test process.
        RegistrationTransport::LoopbackTest => unsafe { (libc::geteuid(), libc::getegid()) },
    }
}

fn read_optional_bounded(
    path: &Path,
    cap: usize,
    transport: RegistrationTransport,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let metadata = file.metadata()?;
    let before = StableMetadata::new(&metadata);
    let (uid, gid) = expected_state_owner(transport);
    anyhow::ensure!(
        before.is_file
            && before.mode & 0o777 == 0o600
            && before.uid == uid
            && before.gid == gid
            && before.nlink == 1,
        "{} metadata is invalid",
        path.display()
    );
    anyhow::ensure!(
        before.len <= cap as u64,
        "{} exceeds its cap",
        path.display()
    );
    let mut bytes = Vec::with_capacity(before.len as usize);
    std::io::Read::by_ref(&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= cap, "{} exceeds its cap", path.display());
    let after = StableMetadata::new(&file.metadata()?);
    anyhow::ensure!(
        before == after && bytes.len() as u64 == after.len,
        "{} changed while being read",
        path.display()
    );
    Ok(Some(bytes))
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().context("durable state path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".registration-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn remove_durable(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    File::open(path.parent().context("durable state path has no parent")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use cats_api::runtime_reconciliation::{Id, Sha256Digest};

    fn vector_material() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
        .into_bytes();
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: Id::new("node_a").unwrap(),
            immutable_host_id: Id::new("host_a").unwrap(),
            credential_id: Id::new("credential_a").unwrap(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: Sha256Digest::new(
                    "sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9",
                )
                .unwrap(),
            },
            state_path_id: Id::new("state_path_a").unwrap(),
            state: NodeIdentityState::Provisioned,
        };
        (
            encode_node_identity(&identity).unwrap(),
            pem,
            b"credential_a\n".to_vec(),
        )
    }

    #[test]
    fn fixed_identity_material_cross_checks_every_authority() {
        let (identity, key, credential) = vector_material();
        assert_eq!(identity.len(), 287);
        let (decoded, signer) = validate_identity_material(&identity, &key, &credential).unwrap();
        assert_eq!(decoded.node_id.as_str(), "node_a");
        assert_eq!(signer.credential_id().as_str(), "credential_a");

        let mut wrong_credential = credential.clone();
        wrong_credential.pop();
        assert!(validate_identity_material(&identity, &key, &wrong_credential).is_err());
        let mut wrong_key = key.clone();
        let index = wrong_key.iter().position(|byte| *byte == b'A').unwrap();
        wrong_key[index] = b'B';
        assert!(validate_identity_material(&identity, &wrong_key, &credential).is_err());
    }

    #[test]
    fn state_path_dot_components_and_noncanonical_identity_are_rejected() {
        let (identity, key, credential) = vector_material();
        for component in [".", ".."] {
            let mut value: serde_json::Value = serde_json::from_slice(&identity).unwrap();
            value["state_path_id"] = serde_json::Value::String(component.into());
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(validate_identity_material(&bytes, &key, &credential).is_err());
        }
        let mut noncanonical = identity;
        noncanonical.insert(1, b' ');
        assert!(validate_identity_material(&noncanonical, &key, &credential).is_err());
    }

    #[test]
    fn production_origin_requires_an_exact_https_origin() {
        assert!(validate_control_plane_origin(
            "https://control.example.test",
            RegistrationTransport::ProductionHttps
        )
        .is_ok());
        for value in [
            "http://control.example.test",
            "https://control.example.test/path",
            "https://user@control.example.test",
            "https://control.example.test?",
            "https://control.example.test#fragment",
        ] {
            assert!(
                validate_control_plane_origin(value, RegistrationTransport::ProductionHttps)
                    .is_err()
            );
        }
        assert!(validate_control_plane_origin(
            "http://127.0.0.1:1234",
            RegistrationTransport::LoopbackTest
        )
        .is_ok());
        assert!(validate_control_plane_origin(
            "http://example.test:1234",
            RegistrationTransport::LoopbackTest
        )
        .is_err());
    }
}

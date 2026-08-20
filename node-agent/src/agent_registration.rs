//! Crash-safe Node registration over the one runtime-internal transport.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use cats_api::agent_registration::{
    decode_agent_registration_error, AgentRegistrationErrorDetail, Ed25519RequestSigner,
    HttpRequestRejection, JSON_CONTENT_TYPE, NODE_AUTHENTICATE_CHALLENGE,
    NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
    REGISTRATION_ERROR_MAX_WIRE_BYTES, REGISTRATION_METHOD, REGISTRATION_PATH,
    REGISTRATION_SUCCESS_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    decode_agent_registration_attempt, decode_agent_session, encode_agent_registration_attempt,
    encode_agent_session, guest_config_digest, AgentRegistrationAttempt, AgentSession,
    ContractVersion, CredentialBinding, Epoch, GuestRuntimeProfileReceipt, NodeBootId,
    NodeIdentity, NodeIdentityState, RandomId128,
};

use crate::state_directory::StateDirectory;

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
    _state_parent_directory: Arc<File>,
    state_directory: Arc<File>,
    state_directory_identity: StableDirectoryIdentity,
    runtime_state_directory: StateDirectory,
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
        let identity_directory = open_installed_identity_directory()?;
        let identity_bytes = read_exact_root_file_at(
            &identity_directory,
            OsStr::new("node-identity.v1.json"),
            Path::new(NODE_IDENTITY_PATH),
            0o600,
            IDENTITY_MAX_BYTES,
        )?;
        let key_bytes = read_exact_root_file_at(
            &identity_directory,
            OsStr::new("node-registration-key.pem"),
            Path::new(NODE_REGISTRATION_KEY_PATH),
            0o600,
            PRIVATE_KEY_MAX_BYTES,
        )?;
        let credential_bytes = read_exact_root_file_at(
            &identity_directory,
            OsStr::new("node-registration-credential-id"),
            Path::new(NODE_REGISTRATION_CREDENTIAL_ID_PATH),
            0o600,
            CREDENTIAL_ID_MAX_BYTES,
        )?;
        let (identity, signer) =
            validate_identity_material(&identity_bytes, &key_bytes, &credential_bytes)?;
        let state_path = Path::new(NODE_STATE_ROOT).join(identity.state_path_id.as_str());
        let state_parent_directory = open_installed_state_root()?;
        let host_lock = open_and_lock_host_file(
            &state_parent_directory,
            RegistrationTransport::ProductionHttps,
        )?;
        let state_directory_name = CString::new(identity.state_path_id.as_str())?;
        let state_directory = open_directory_at(
            &state_parent_directory,
            state_directory_name.as_c_str(),
            &state_path,
        )?;
        validate_state_directory(&state_directory, RegistrationTransport::ProductionHttps)?;
        let state_directory_identity = StableDirectoryIdentity::new(&state_directory.metadata()?);
        let runtime_state_directory =
            StateDirectory::from_installed_directory(&state_directory, &state_path)?;
        Ok(Self {
            identity: Arc::new(identity),
            signer,
            state_path,
            _state_parent_directory: Arc::new(state_parent_directory),
            state_directory: Arc::new(state_directory),
            state_directory_identity,
            runtime_state_directory,
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
        // blockd's serving-handoff reader requires the production state-dir
        // contract (owner-only 0700); create_dir_all's umask default is wider.
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o700))?;
        let state_parent_path = state_path
            .parent()
            .context("test state path has no parent")?;
        let state_directory_name = CString::new(
            state_path
                .file_name()
                .context("test state path has no final component")?
                .as_bytes(),
        )?;
        let state_parent_directory = File::open(state_parent_path)?;
        let host_lock = create_and_lock_test_host_file(&state_parent_directory)?;
        let state_directory = open_directory_at(
            &state_parent_directory,
            state_directory_name.as_c_str(),
            &state_path,
        )?;
        validate_state_directory(&state_directory, RegistrationTransport::LoopbackTest)?;
        let state_directory_identity = StableDirectoryIdentity::new(&state_directory.metadata()?);
        let runtime_state_directory =
            StateDirectory::from_test_directory(&state_directory, &state_path)?;
        Ok(Self {
            identity: Arc::new(identity),
            signer,
            state_path,
            _state_parent_directory: Arc::new(state_parent_directory),
            state_directory: Arc::new(state_directory),
            state_directory_identity,
            runtime_state_directory,
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

    pub fn runtime_state_directory(&self) -> StateDirectory {
        self.runtime_state_directory.clone()
    }

    /// Reuses the exact installed A19 credential for all runtime-internal
    /// Node requests. The private key remains encapsulated by the signer.
    pub(crate) fn runtime_request_signer(&self) -> Ed25519RequestSigner {
        self.signer.clone()
    }

    #[cfg(test)]
    pub(crate) fn uses_loopback_transport_for_test(&self) -> bool {
        matches!(self.transport, RegistrationTransport::LoopbackTest)
    }

    /// Keeps one exact pending attempt durable across every ambiguous result.
    /// A returned session has already been validated, fsynced, and made the
    /// sole durable current session before the pending file was removed.
    pub async fn register_until_session(
        &self,
        control_plane_origin: &str,
    ) -> anyhow::Result<AgentSession> {
        let origin = validate_control_plane_origin(control_plane_origin, self.transport)?;
        self.ensure_state_directory_identity()?;
        let registration_directory =
            ensure_registration_directory(&self.state_directory, self.transport, durability_noop)?;
        let agent_instance_id = random_id();
        let existing_pending = read_optional_bounded_at(
            &registration_directory,
            OsStr::new("pending-attempt.json"),
            &self.state_path.join(PENDING_ATTEMPT_RELATIVE_PATH),
            IDENTITY_MAX_BYTES,
            self.transport,
        )?;
        let mut pending = match existing_pending {
            Some(bytes) => {
                let attempt = decode_agent_registration_attempt(&bytes).map_err(|_| {
                    anyhow::anyhow!("durable Agent registration attempt is invalid")
                })?;
                self.validate_pending(&attempt)?;
                DurableAttempt { attempt, bytes }
            }
            None => {
                let expected = self.load_previous_epoch(&registration_directory)?;
                self.create_pending(&registration_directory, agent_instance_id.clone(), expected)?
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
            self.ensure_state_directory_identity()?;
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
                    self.ensure_state_directory_identity()?;
                    atomic_replace_at(
                        &registration_directory,
                        OsStr::new("session.json"),
                        &encode_agent_session(&session).map_err(|_| {
                            anyhow::anyhow!("accepted Agent session cannot be canonically encoded")
                        })?,
                    )?;
                    remove_durable_at(&registration_directory, OsStr::new("pending-attempt.json"))?;
                    // A pending file loaded at process startup belongs to the
                    // process that durably created it. Resolve its ambiguous
                    // result first, then replace that old process/boot binding
                    // before any runtime gate can consume a session.
                    if session.node_boot_id != self.node_boot_id
                        || session.agent_instance_id != agent_instance_id
                    {
                        pending = self.create_pending(
                            &registration_directory,
                            agent_instance_id.clone(),
                            Some(session.agent_session_epoch),
                        )?;
                        backoff = INITIAL_RETRY;
                        continue;
                    }
                    return Ok(session);
                }
                RegistrationResult::ReplaceExpected(current_epoch) => {
                    self.ensure_state_directory_identity()?;
                    pending = self.create_pending(
                        &registration_directory,
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

    fn load_previous_epoch(&self, registration_directory: &File) -> anyhow::Result<Option<Epoch>> {
        let Some(bytes) = read_optional_bounded_at(
            registration_directory,
            OsStr::new("session.json"),
            &self.state_path.join(SESSION_RELATIVE_PATH),
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
        registration_directory: &File,
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
        atomic_replace_at(
            registration_directory,
            OsStr::new("pending-attempt.json"),
            &bytes,
        )?;
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

    fn ensure_state_directory_identity(&self) -> anyhow::Result<()> {
        // The identity-selected directory is a process-lifetime resource. Do
        // not resolve its former pathname again: a privileged rename must not
        // redirect registration state away from the descriptor that was
        // selected while the Host-global parent lock was acquired.
        validate_state_directory(&self.state_directory, self.transport)?;
        anyhow::ensure!(
            StableDirectoryIdentity::new(&self.state_directory.metadata()?)
                == self.state_directory_identity,
            "retained Node state directory descriptor changed identity"
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
    cats_api::agent_registration::validate_node_identity_material(
        identity_bytes,
        key_bytes,
        credential_bytes,
    )
    .map_err(anyhow::Error::from)
}

fn open_installed_identity_directory() -> anyhow::Result<File> {
    open_rooted_directory(&["etc", "cats", "identity"], Some(0o700))
}

fn open_installed_state_root() -> anyhow::Result<File> {
    open_rooted_directory(&["var", "lib", "cats", "node"], None)
}

fn open_rooted_directory(components: &[&str], final_mode: Option<u32>) -> anyhow::Result<File> {
    let mut directory = File::open("/").context("open filesystem root")?;
    validate_root_owned_directory(&directory, Path::new("/"), None)?;
    let mut display = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
        display.push(component);
        let name = CString::new(*component)?;
        directory = open_directory_at(&directory, name.as_c_str(), &display)?;
        validate_root_owned_directory(
            &directory,
            &display,
            (index + 1 == components.len())
                .then_some(final_mode)
                .flatten(),
        )?;
    }
    Ok(directory)
}

fn validate_root_owned_directory(
    directory: &File,
    display: &Path,
    exact_mode: Option<u32>,
) -> anyhow::Result<()> {
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && exact_mode
                .map(|mode| metadata.mode() & 0o777 == mode)
                .unwrap_or_else(|| metadata.mode() & 0o022 == 0),
        "directory {} violates owner/mode/type contract",
        display.display()
    );
    Ok(())
}

fn open_directory_at(parent: &File, name: &std::ffi::CStr, display: &Path) -> anyhow::Result<File> {
    // SAFETY: `parent` is live for the call, `name` is NUL-terminated, and a
    // successful new descriptor is immediately transferred to `File`.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open directory {}", display.display()));
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_file_at(
    directory: &File,
    name: &OsStr,
    flags: i32,
    create_mode: libc::c_uint,
    display: &Path,
) -> anyhow::Result<File> {
    anyhow::ensure!(
        !name.is_empty()
            && name != OsStr::new(".")
            && name != OsStr::new("..")
            && !name.as_bytes().contains(&b'/'),
        "descriptor-relative file name is not one component"
    );
    let name = CString::new(name.as_bytes())?;
    // SAFETY: the parent descriptor and C string are live for this call; the
    // mode argument is supplied for the optional O_CREAT case; ownership of a
    // successful descriptor is immediately transferred to `File`.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            create_mode,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open {}", display.display()));
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn read_exact_root_file_at(
    directory: &File,
    name: &OsStr,
    path: &Path,
    mode: u32,
    cap: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut file = open_file_at(directory, name, libc::O_RDONLY, 0, path)?;
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

fn validate_state_directory(
    directory: &File,
    transport: RegistrationTransport,
) -> anyhow::Result<()> {
    let metadata = directory.metadata()?;
    let (uid, gid) = expected_state_owner(transport);
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == uid
            && metadata.gid() == gid
            && metadata.mode() & 0o022 == 0,
        "Node state directory violates owner/mode/type contract"
    );
    Ok(())
}

fn open_and_lock_host_file(
    state_directory: &File,
    transport: RegistrationTransport,
) -> anyhow::Result<File> {
    let lock = open_file_at(
        state_directory,
        OsStr::new(HOST_LOCK_BASENAME),
        libc::O_RDWR,
        0,
        Path::new(HOST_LOCK_BASENAME),
    )?;
    let metadata = StableMetadata::new(&lock.metadata()?);
    let (uid, gid) = expected_state_owner(transport);
    anyhow::ensure!(
        metadata.is_exact_file_for(0o600, uid, gid),
        "Host lock violates owner/mode/type contract"
    );
    lock_exclusive_nonblocking(&lock)?;
    Ok(lock)
}

fn create_and_lock_test_host_file(state_directory: &File) -> anyhow::Result<File> {
    let lock = open_file_at(
        state_directory,
        OsStr::new(HOST_LOCK_BASENAME),
        libc::O_RDWR | libc::O_CREAT,
        0o600,
        Path::new(HOST_LOCK_BASENAME),
    )?;
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let (uid, gid) = expected_state_owner(RegistrationTransport::LoopbackTest);
    anyhow::ensure!(
        StableMetadata::new(&lock.metadata()?).is_exact_file_for(0o600, uid, gid),
        "test Host lock violates owner/mode/type contract"
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
struct StableDirectoryIdentity {
    dev: u64,
    ino: u64,
}

impl StableDirectoryIdentity {
    fn new(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
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
        self.is_exact_file_for(mode, 0, 0)
    }

    fn is_exact_file_for(self, mode: u32, uid: u32, gid: u32) -> bool {
        self.is_file
            && self.mode & 0o777 == mode
            && self.uid == uid
            && self.gid == gid
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableStatePoint {
    RegistrationDirectoryCreated,
    RegistrationDirectoryParentSynced,
    TemporaryFileSynced,
    StateRenamed,
    StateParentSynced,
    StateRemoved,
    StateRemovalParentSynced,
}

fn durability_noop(_point: DurableStatePoint) -> anyhow::Result<()> {
    Ok(())
}

fn ensure_registration_directory(
    state_directory: &File,
    transport: RegistrationTransport,
    mut probe: impl FnMut(DurableStatePoint) -> anyhow::Result<()>,
) -> anyhow::Result<File> {
    let name = CString::new("agent-registration").expect("fixed directory has no NUL");
    // SAFETY: the state directory descriptor and fixed C string remain live
    // for the call. mkdirat has no retained Rust-memory references.
    let created = match unsafe { libc::mkdirat(state_directory.as_raw_fd(), name.as_ptr(), 0o700) }
    {
        0 => true,
        _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists => false,
        _ => return Err(std::io::Error::last_os_error()).context("create Agent registration dir"),
    };
    if created {
        probe(DurableStatePoint::RegistrationDirectoryCreated)?;
    }
    let directory = open_directory_at(
        state_directory,
        name.as_c_str(),
        Path::new("agent-registration"),
    )?;
    let metadata = directory.metadata()?;
    let (uid, gid) = expected_state_owner(transport);
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == uid
            && metadata.gid() == gid
            && metadata.mode() & 0o777 == 0o700,
        "Agent registration state directory violates owner/mode/type contract"
    );
    // Always sync the state directory, not only when mkdirat reported
    // creation. After a power loss the directory entry may be visible again
    // even though the previous parent fsync never became durable.
    state_directory.sync_all()?;
    probe(DurableStatePoint::RegistrationDirectoryParentSynced)?;
    Ok(directory)
}

fn expected_state_owner(transport: RegistrationTransport) -> (u32, u32) {
    match transport {
        RegistrationTransport::ProductionHttps => (0, 0),
        // SAFETY: these libc calls have no preconditions and only return the
        // effective identity of the current test process.
        RegistrationTransport::LoopbackTest => unsafe { (libc::geteuid(), libc::getegid()) },
    }
}

fn read_optional_bounded_at(
    directory: &File,
    name: &OsStr,
    path: &Path,
    cap: usize,
    transport: RegistrationTransport,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut file = match open_file_at(directory, name, libc::O_RDONLY, 0, path) {
        Ok(file) => file,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
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

fn atomic_replace_at(directory: &File, name: &OsStr, bytes: &[u8]) -> anyhow::Result<()> {
    atomic_replace_at_with_probe(directory, name, bytes, durability_noop)
}

fn atomic_replace_at_with_probe(
    directory: &File,
    name: &OsStr,
    bytes: &[u8],
    mut probe: impl FnMut(DurableStatePoint) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let temporary = format!(".registration-{}.tmp", uuid::Uuid::new_v4().simple());
    let temporary = OsStr::new(&temporary);
    let display = Path::new(temporary);
    let mut file = open_file_at(
        directory,
        temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
        display,
    )?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        probe(DurableStatePoint::TemporaryFileSynced)?;
        rename_at(directory, temporary, name)?;
        probe(DurableStatePoint::StateRenamed)?;
        directory.sync_all()?;
        probe(DurableStatePoint::StateParentSynced)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlink_at(directory, temporary);
    }
    result
}

fn remove_durable_at(directory: &File, name: &OsStr) -> anyhow::Result<()> {
    remove_durable_at_with_probe(directory, name, durability_noop)
}

fn remove_durable_at_with_probe(
    directory: &File,
    name: &OsStr,
    mut probe: impl FnMut(DurableStatePoint) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    match unlink_at(directory, name) {
        Ok(()) => probe(DurableStatePoint::StateRemoved)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    directory.sync_all()?;
    probe(DurableStatePoint::StateRemovalParentSynced)?;
    Ok(())
}

fn rename_at(directory: &File, from: &OsStr, to: &OsStr) -> anyhow::Result<()> {
    let from = CString::new(from.as_bytes())?;
    let to = CString::new(to.as_bytes())?;
    // SAFETY: both names are one-component C strings and the live directory
    // descriptor is used for both sides, so the rename cannot escape it.
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).context("rename durable Agent state")
    }
}

fn unlink_at(directory: &File, name: &OsStr) -> std::io::Result<()> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    // SAFETY: `directory` and `name` are live for the call. No Rust memory is
    // retained and flags=0 only removes a non-directory entry.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use cats_api::runtime_reconciliation::encode_node_identity;
    use cats_api::runtime_reconciliation::{AsciiText, Id, Sha256Digest};
    use std::sync::{Arc, Barrier};

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
            provider_scope: cats_api::runtime_reconciliation::ProviderScope {
                provider: Id::new("test_provider").unwrap(),
                partition: Id::new("test_partition").unwrap(),
                account_id: Id::new("test_account").unwrap(),
                region: Id::new("test_region").unwrap(),
            },
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

    fn loopback_registration(state_path: PathBuf) -> AgentRegistrationConfig {
        let (identity, key, credential) = vector_material();
        let (identity, signer) = validate_identity_material(&identity, &key, &credential).unwrap();
        let receipt = GuestRuntimeProfileReceipt {
            version: ContractVersion::V1,
            kernel_digest: Sha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            initramfs_digest: None,
            kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
            guest_agent_protocol_version: ContractVersion::V1,
        };
        AgentRegistrationConfig::for_loopback_test(
            identity,
            signer,
            state_path,
            NodeBootId::new("11111111111111111111111111111111").unwrap(),
            &receipt,
        )
        .unwrap()
    }

    #[test]
    fn fixed_identity_material_cross_checks_every_authority() {
        let (identity, key, credential) = vector_material();
        assert_eq!(identity.len(), 413);
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

    #[test]
    fn renamed_state_directory_never_redirects_the_locked_process_to_replacement_state() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("state");
        let registration = loopback_registration(state_path.clone());
        let old_registration_directory = ensure_registration_directory(
            &registration.state_directory,
            RegistrationTransport::LoopbackTest,
            durability_noop,
        )
        .unwrap();
        atomic_replace_at(
            &old_registration_directory,
            OsStr::new("pending-attempt.json"),
            b"old-directory",
        )
        .unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = barrier.clone();
        let worker_state = state_path.clone();
        let displaced = temp.path().join("state-displaced");
        let worker_displaced = displaced.clone();
        let replacer = std::thread::spawn(move || {
            worker_barrier.wait();
            std::fs::rename(&worker_state, &worker_displaced).unwrap();
            std::fs::create_dir(&worker_state).unwrap();
            let replacement_registration = worker_state.join("agent-registration");
            std::fs::create_dir(&replacement_registration).unwrap();
            std::fs::set_permissions(
                &replacement_registration,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::write(
                replacement_registration.join("pending-attempt.json"),
                b"replacement-directory",
            )
            .unwrap();
        });
        barrier.wait();
        replacer.join().unwrap();

        registration.ensure_state_directory_identity().unwrap();
        atomic_replace_at(
            &old_registration_directory,
            OsStr::new("pending-attempt.json"),
            b"retained-directory",
        )
        .unwrap();
        let retained = read_optional_bounded_at(
            &old_registration_directory,
            OsStr::new("pending-attempt.json"),
            Path::new("pending-attempt.json"),
            64,
            RegistrationTransport::LoopbackTest,
        )
        .unwrap()
        .unwrap();
        assert_eq!(retained, b"retained-directory");
        assert_eq!(
            std::fs::read(displaced.join(PENDING_ATTEMPT_RELATIVE_PATH)).unwrap(),
            b"retained-directory"
        );
        assert_eq!(
            std::fs::read(state_path.join(PENDING_ATTEMPT_RELATIVE_PATH)).unwrap(),
            b"replacement-directory"
        );
        #[cfg(target_os = "linux")]
        {
            let anchored = registration.runtime_state_directory();
            let error = anchored
                .ensure_child_inheritance()
                .expect_err("runtime must reject the replacement lexical state path");
            assert!(
                error.to_string().contains("canonical Node state directory"),
                "unexpected lexical-state error: {error:#}"
            );
            assert!(anchored.inherited_fd().is_some());
            assert!(anchored.try_clone_directory().is_err());
            assert!(!state_path.join("runtime-after-replacement").exists());
            assert!(!state_path.join("child-write").exists());
            assert!(!displaced.join("runtime-after-replacement").exists());
            assert!(!displaced.join("child-write").exists());
        }
        // The Host-global lock lives in the retained state root, so replacing
        // the identity-selected child cannot let a second Agent start.
        let (identity, key, credential) = vector_material();
        let (identity, signer) = validate_identity_material(&identity, &key, &credential).unwrap();
        let receipt = GuestRuntimeProfileReceipt {
            version: ContractVersion::V1,
            kernel_digest: Sha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            initramfs_digest: None,
            kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
            guest_agent_protocol_version: ContractVersion::V1,
        };
        assert!(AgentRegistrationConfig::for_loopback_test(
            identity,
            signer,
            state_path,
            NodeBootId::new("11111111111111111111111111111111").unwrap(),
            &receipt,
        )
        .is_err());
    }

    #[test]
    fn every_registration_state_durability_window_replays_to_exact_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("state");
        std::fs::create_dir(&state_path).unwrap();
        let state_directory = File::open(&state_path).unwrap();
        let mut failed_creation = false;
        assert!(ensure_registration_directory(
            &state_directory,
            RegistrationTransport::LoopbackTest,
            |point| {
                if point == DurableStatePoint::RegistrationDirectoryCreated {
                    failed_creation = true;
                    anyhow::bail!("injected power loss after mkdir")
                }
                Ok(())
            }
        )
        .is_err());
        assert!(failed_creation);
        let registration_directory = ensure_registration_directory(
            &state_directory,
            RegistrationTransport::LoopbackTest,
            durability_noop,
        )
        .unwrap();

        for name in ["pending-attempt.json", "session.json"] {
            for failure_point in [
                DurableStatePoint::TemporaryFileSynced,
                DurableStatePoint::StateRenamed,
                DurableStatePoint::StateParentSynced,
            ] {
                let mut injected = false;
                assert!(atomic_replace_at_with_probe(
                    &registration_directory,
                    OsStr::new(name),
                    name.as_bytes(),
                    |point| {
                        if !injected && point == failure_point {
                            injected = true;
                            anyhow::bail!("injected state-write power loss")
                        }
                        Ok(())
                    }
                )
                .is_err());
                assert!(injected);
                atomic_replace_at(&registration_directory, OsStr::new(name), name.as_bytes())
                    .unwrap();
                assert_eq!(
                    read_optional_bounded_at(
                        &registration_directory,
                        OsStr::new(name),
                        Path::new(name),
                        64,
                        RegistrationTransport::LoopbackTest,
                    )
                    .unwrap()
                    .unwrap(),
                    name.as_bytes()
                );
            }
        }

        for failure_point in [
            DurableStatePoint::StateRemoved,
            DurableStatePoint::StateRemovalParentSynced,
        ] {
            atomic_replace_at(
                &registration_directory,
                OsStr::new("pending-attempt.json"),
                b"pending",
            )
            .unwrap();
            let mut injected = false;
            assert!(remove_durable_at_with_probe(
                &registration_directory,
                OsStr::new("pending-attempt.json"),
                |point| {
                    if !injected && point == failure_point {
                        injected = true;
                        anyhow::bail!("injected state-remove power loss")
                    }
                    Ok(())
                }
            )
            .is_err());
            assert!(injected);
            remove_durable_at(&registration_directory, OsStr::new("pending-attempt.json")).unwrap();
            assert!(read_optional_bounded_at(
                &registration_directory,
                OsStr::new("pending-attempt.json"),
                Path::new("pending-attempt.json"),
                64,
                RegistrationTransport::LoopbackTest,
            )
            .unwrap()
            .is_none());
        }
    }
}

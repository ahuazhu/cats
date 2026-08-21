//! Session-fenced per-Endpoint Route command wire.
//!
//! Route commands are automatically derived by Control from current Endpoint
//! metadata and the current lifecycle projection. They are not lifecycle
//! commands and do not share the per-Cat lifecycle lane: every Endpoint has
//! its own serial lane. Both lanes meet only in the Node AdmissionCell.
//!
//! Observation is deliberately absent. `Serving` is an exact Node receipt for
//! one Endpoint binding, effective RuntimeReady source and AgentSession. A
//! public-ring ACK carried by the authenticated poll only records which ring
//! that session loaded; it does not establish RuntimeReady or Serving.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_lifecycle::{EffectiveRuntimeReady, PlacementIdentity};
use crate::runtime_reconciliation::{
    encode_agent_session, key_ring_digest, AgentSession, AsciiText, ContractVersion, Epoch,
    Hostname, HttpProtocol, Id, KeyId, RandomId128, Sequence, SessionBinding, Sha256Digest,
    UnixMillis, WireU64,
};

pub const ROUTE_INTERNAL_METHOD: &str = "POST";
pub const ROUTE_COMMAND_POLL_PATH: &str = "/v1/internal/runtime/route-command-polls";
pub const ROUTE_RESULT_COMMIT_PATH: &str = "/v1/internal/runtime/route-result-commits";

pub const ROUTE_COMMAND_ENVELOPE_MAX_WIRE_BYTES: usize = 65_536;
pub const ROUTE_COMMAND_RESPONSE_MAX_WIRE_BYTES: usize = 65_536;
pub const ROUTE_COMMAND_POLL_MAX_WIRE_BYTES: usize = 65_536;
pub const ROUTE_COMMAND_BATCH_MAX_WIRE_BYTES: usize = 4_194_304;
pub const ROUTE_RESULT_COMMIT_MAX_WIRE_BYTES: usize = 65_536;
pub const ROUTE_RESULT_STORED_ACK_MAX_WIRE_BYTES: usize = 16_384;
pub const ROUTE_OPERATION_MAX_WIRE_BYTES: usize = 262_144;
pub const ROUTE_ERROR_MAX_WIRE_BYTES: usize = 16_384;
pub const ROUTE_COMMAND_BATCH_MAX_COMMANDS: usize = 64;
pub const ROUTE_RING_ACK_MAX_LOADED_KIDS: usize = 64;

const COMMAND_FINGERPRINT_DOMAIN: &[u8] = b"cats.runtime-route.command.v1";
const TERMINAL_RESULT_DIGEST_DOMAIN: &[u8] = b"cats.runtime-route.result.v1";
const CONTROL_INVALIDATION_DIGEST_DOMAIN: &[u8] = b"cats.runtime-route.invalidation.v1";
const RING_ACK_DIGEST_DOMAIN: &[u8] = b"cats.runtime-route.ring-ack.v1";

/// Exact identity installed in one Endpoint gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteServingBinding {
    pub workspace_id: Id,
    pub endpoint_id: Id,
    pub hostname: Hostname,
    pub cat_id: Id,
    pub placement_identity: PlacementIdentity,
    pub effective_runtime_ready: EffectiveRuntimeReady,
    pub route_epoch: Epoch,
    pub admission_session: SessionBinding,
    pub protocol: HttpProtocol,
    pub target_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteCommandKind {
    Enable,
    Disable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTerminalResultKind {
    Serving,
    Closed,
    Rejected,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteCommandPredecessor {
    Genesis,
    Exact {
        operation_id: Id,
        terminal_result_kind: RouteTerminalResultKind,
        terminal_result_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteCommand {
    Enable,
    Disable,
}

impl RouteCommand {
    pub const fn kind(self) -> RouteCommandKind {
        match self {
            Self::Enable => RouteCommandKind::Enable,
            Self::Disable => RouteCommandKind::Disable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCommandEnvelope {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub binding: RouteServingBinding,
    pub predecessor: RouteCommandPredecessor,
    pub command: RouteCommand,
    pub request_fingerprint: Sha256Digest,
}

impl RouteCommandEnvelope {
    pub fn new(
        operation_id: Id,
        binding: RouteServingBinding,
        predecessor: RouteCommandPredecessor,
        command: RouteCommand,
    ) -> Result<Self, RuntimeRouteContractError> {
        let mut envelope = Self {
            version: ContractVersion::V1,
            operation_id,
            binding,
            predecessor,
            command,
            request_fingerprint: Sha256Digest::from_bytes([0; 32]),
        };
        envelope.request_fingerprint = route_command_request_fingerprint(&envelope)?;
        validate_route_command_envelope(&envelope)?;
        Ok(envelope)
    }

    pub const fn command_kind(&self) -> RouteCommandKind {
        self.command.kind()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteRejectionReason {
    StaleLifecycleSource,
    StaleEndpointBinding,
    StaleSession,
    AdmissionClosed,
    RuntimeUnavailable,
    StoredEvidenceConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteServingResult {
    pub binding: RouteServingBinding,
    pub admission_cell_receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteClosedResult {
    pub binding: RouteServingBinding,
    pub admission_cell_receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRejectedResult {
    pub binding: RouteServingBinding,
    pub reason: RouteRejectionReason,
    /// Exact local evidence that no new serving effect was published.
    pub no_effect_receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteNodeResult {
    Serving(RouteServingResult),
    Closed(RouteClosedResult),
    Rejected(RouteRejectedResult),
}

impl RouteNodeResult {
    pub const fn kind(&self) -> RouteTerminalResultKind {
        match self {
            Self::Serving(_) => RouteTerminalResultKind::Serving,
            Self::Closed(_) => RouteTerminalResultKind::Closed,
            Self::Rejected(_) => RouteTerminalResultKind::Rejected,
        }
    }

    pub fn binding(&self) -> &RouteServingBinding {
        match self {
            Self::Serving(result) => &result.binding,
            Self::Closed(result) => &result.binding,
            Self::Rejected(result) => &result.binding,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCommandResponse {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub endpoint_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub result: RouteNodeResult,
}

impl RouteCommandResponse {
    pub fn new(
        command: &RouteCommandEnvelope,
        result: RouteNodeResult,
    ) -> Result<Self, RuntimeRouteContractError> {
        let response = Self {
            version: ContractVersion::V1,
            operation_id: command.operation_id.clone(),
            endpoint_id: command.binding.endpoint_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            result,
        };
        validate_route_command_response_for_command(&response, command)?;
        Ok(response)
    }
}

/// Durable proof that one current AgentSession atomically loaded a public ring.
/// This is delivery eligibility only; it is never RuntimeReady or Serving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteNodeRingAck {
    pub version: ContractVersion,
    pub ack_id: RandomId128,
    pub ack_sequence: Sequence,
    pub session: SessionBinding,
    pub ring_version: Epoch,
    pub key_ring_digest: Sha256Digest,
    pub loaded_kids: Vec<KeyId>,
    pub ack_digest: Sha256Digest,
}

impl RouteNodeRingAck {
    pub fn new(
        session: SessionBinding,
        ack_id: RandomId128,
        ack_sequence: Sequence,
        ring_version: Epoch,
        loaded_kids: Vec<KeyId>,
    ) -> Result<Self, RuntimeRouteContractError> {
        let key_ring_digest = key_ring_digest(ring_version, &loaded_kids)
            .map_err(|_| RuntimeRouteContractError::InvalidContract)?;
        let mut ack = Self {
            version: ContractVersion::V1,
            ack_id,
            ack_sequence,
            session,
            ring_version,
            key_ring_digest,
            loaded_kids,
            ack_digest: Sha256Digest::from_bytes([0; 32]),
        };
        ack.ack_digest = route_node_ring_ack_digest(&ack)?;
        validate_route_node_ring_ack(&ack)?;
        Ok(ack)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCommandPollRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub request_sequence: Sequence,
    pub installed_ring_ack: Option<RouteNodeRingAck>,
}

impl RouteCommandPollRequest {
    pub fn new(
        session: &AgentSession,
        request_sequence: Sequence,
        installed_ring_ack: Option<RouteNodeRingAck>,
    ) -> Result<Self, RuntimeRouteContractError> {
        validate_agent_session(session)?;
        let poll = Self {
            version: ContractVersion::V1,
            session: session_binding(session),
            request_sequence,
            installed_ring_ack,
        };
        validate_route_command_poll_request(&poll)?;
        Ok(poll)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCommandBatch {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub request_sequence: Sequence,
    pub commands: Vec<RouteCommandEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteResultCommitRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub response: Box<RouteCommandResponse>,
    pub terminal_result_digest: Sha256Digest,
}

impl RouteResultCommitRequest {
    pub fn new(
        session: &AgentSession,
        response: RouteCommandResponse,
    ) -> Result<Self, RuntimeRouteContractError> {
        validate_agent_session(session)?;
        let mut commit = Self {
            version: ContractVersion::V1,
            session: session_binding(session),
            response: Box::new(response),
            terminal_result_digest: Sha256Digest::from_bytes([0; 32]),
        };
        commit.terminal_result_digest = route_terminal_result_digest(&commit.response)?;
        validate_route_result_commit_request(&commit)?;
        Ok(commit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteResultStoredAck {
    pub version: ContractVersion,
    pub node_id: Id,
    pub endpoint_id: Id,
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub terminal_result_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteControlInvalidationReason {
    EndpointBindingChanged,
    LifecycleClosed,
    LifecycleCloseAmbiguous,
    AgentSessionReplaced,
}

/// Exact Control terminal for an unresolved command that can no longer act.
/// It frees that Endpoint lane without accepting a late Node result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteControlInvalidation {
    pub version: ContractVersion,
    pub endpoint_id: Id,
    pub invalidated_operation_id: Id,
    pub reason: RouteControlInvalidationReason,
    pub invalidating_lifecycle_operation_id: Option<Id>,
    pub replacement_session: Option<SessionBinding>,
    pub resulting_route_epoch: Epoch,
    pub invalidated_at_unix_ms: UnixMillis,
    pub invalidation_digest: Sha256Digest,
}

impl RouteControlInvalidation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint_id: Id,
        invalidated_operation_id: Id,
        reason: RouteControlInvalidationReason,
        invalidating_lifecycle_operation_id: Option<Id>,
        replacement_session: Option<SessionBinding>,
        resulting_route_epoch: Epoch,
        invalidated_at_unix_ms: UnixMillis,
    ) -> Result<Self, RuntimeRouteContractError> {
        let mut invalidation = Self {
            version: ContractVersion::V1,
            endpoint_id,
            invalidated_operation_id,
            reason,
            invalidating_lifecycle_operation_id,
            replacement_session,
            resulting_route_epoch,
            invalidated_at_unix_ms,
            invalidation_digest: Sha256Digest::from_bytes([0; 32]),
        };
        invalidation.invalidation_digest = route_control_invalidation_digest(&invalidation)?;
        validate_route_control_invalidation(&invalidation)?;
        Ok(invalidation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteOperationTerminal {
    NodeResult {
        response: Box<RouteCommandResponse>,
        terminal_result_digest: Sha256Digest,
    },
    ControlInvalidation {
        invalidation: Box<RouteControlInvalidation>,
    },
}

impl RouteOperationTerminal {
    pub const fn kind(&self) -> RouteTerminalResultKind {
        match self {
            Self::NodeResult { response, .. } => response.result.kind(),
            Self::ControlInvalidation { .. } => RouteTerminalResultKind::Invalidated,
        }
    }

    pub fn digest(&self) -> &Sha256Digest {
        match self {
            Self::NodeResult {
                terminal_result_digest,
                ..
            } => terminal_result_digest,
            Self::ControlInvalidation { invalidation } => &invalidation.invalidation_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteOperationState {
    Unresolved,
    Terminal {
        terminal: Box<RouteOperationTerminal>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOperation {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub endpoint_id: Id,
    pub command_kind: RouteCommandKind,
    pub canonical_request: Box<RouteCommandEnvelope>,
    pub request_fingerprint: Sha256Digest,
    pub state: RouteOperationState,
    pub created_at_unix_ms: UnixMillis,
    pub terminal_at_unix_ms: Option<UnixMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeRouteError {
    MalformedPayload {
        json_pointer: AsciiText,
        message: AsciiText,
    },
    UnsupportedVersion {
        supported_version: ContractVersion,
    },
    LimitExceeded {
        limit: AsciiText,
        maximum: WireU64,
    },
    AuthenticationFailed,
    WrongNode {
        expected_node_id: Id,
    },
    RouteOperationInProgress {
        endpoint_id: Id,
        operation_id: Id,
    },
    OperationIdentityConflict {
        operation_id: Id,
    },
    StaleOperation {
        endpoint_id: Id,
        current_operation_id: Option<Id>,
    },
    SupersededOperation {
        endpoint_id: Id,
        current_operation_id: Option<Id>,
    },
    ConflictingTerminalResult {
        operation_id: Id,
    },
    TemporarilyUnavailable,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeRouteContractError {
    #[error("runtime Route wire body exceeds its byte limit")]
    WireTooLarge,
    #[error("runtime Route wire body is malformed")]
    Malformed,
    #[error("runtime Route wire body is not exact canonical JSON")]
    NonCanonical,
    #[error("runtime Route contract is invalid")]
    InvalidContract,
}

#[derive(Serialize)]
struct CommandFingerprintInput<'a> {
    version: ContractVersion,
    operation_id: &'a Id,
    binding: &'a RouteServingBinding,
    predecessor: &'a RouteCommandPredecessor,
    command: RouteCommand,
}

#[derive(Serialize)]
struct RingAckDigestInput<'a> {
    version: ContractVersion,
    ack_id: &'a RandomId128,
    ack_sequence: Sequence,
    session: &'a SessionBinding,
    ring_version: Epoch,
    key_ring_digest: &'a Sha256Digest,
    loaded_kids: &'a [KeyId],
}

#[derive(Serialize)]
struct InvalidationDigestInput<'a> {
    version: ContractVersion,
    endpoint_id: &'a Id,
    invalidated_operation_id: &'a Id,
    reason: RouteControlInvalidationReason,
    invalidating_lifecycle_operation_id: &'a Option<Id>,
    replacement_session: &'a Option<SessionBinding>,
    resulting_route_epoch: Epoch,
    invalidated_at_unix_ms: UnixMillis,
}

pub fn route_command_request_fingerprint(
    envelope: &RouteCommandEnvelope,
) -> Result<Sha256Digest, RuntimeRouteContractError> {
    validate_route_command_envelope_unsigned(envelope)?;
    digest_canonical(
        COMMAND_FINGERPRINT_DOMAIN,
        &CommandFingerprintInput {
            version: envelope.version,
            operation_id: &envelope.operation_id,
            binding: &envelope.binding,
            predecessor: &envelope.predecessor,
            command: envelope.command,
        },
        ROUTE_COMMAND_ENVELOPE_MAX_WIRE_BYTES,
    )
}

pub fn route_terminal_result_digest(
    response: &RouteCommandResponse,
) -> Result<Sha256Digest, RuntimeRouteContractError> {
    validate_route_command_response(response)?;
    digest_canonical(
        TERMINAL_RESULT_DIGEST_DOMAIN,
        response,
        ROUTE_COMMAND_RESPONSE_MAX_WIRE_BYTES,
    )
}

pub fn route_control_invalidation_digest(
    invalidation: &RouteControlInvalidation,
) -> Result<Sha256Digest, RuntimeRouteContractError> {
    validate_route_control_invalidation_unsigned(invalidation)?;
    digest_canonical(
        CONTROL_INVALIDATION_DIGEST_DOMAIN,
        &InvalidationDigestInput {
            version: invalidation.version,
            endpoint_id: &invalidation.endpoint_id,
            invalidated_operation_id: &invalidation.invalidated_operation_id,
            reason: invalidation.reason,
            invalidating_lifecycle_operation_id: &invalidation.invalidating_lifecycle_operation_id,
            replacement_session: &invalidation.replacement_session,
            resulting_route_epoch: invalidation.resulting_route_epoch,
            invalidated_at_unix_ms: invalidation.invalidated_at_unix_ms,
        },
        ROUTE_OPERATION_MAX_WIRE_BYTES,
    )
}

pub fn route_node_ring_ack_digest(
    ack: &RouteNodeRingAck,
) -> Result<Sha256Digest, RuntimeRouteContractError> {
    validate_route_node_ring_ack_unsigned(ack)?;
    digest_canonical(
        RING_ACK_DIGEST_DOMAIN,
        &RingAckDigestInput {
            version: ack.version,
            ack_id: &ack.ack_id,
            ack_sequence: ack.ack_sequence,
            session: &ack.session,
            ring_version: ack.ring_version,
            key_ring_digest: &ack.key_ring_digest,
            loaded_kids: &ack.loaded_kids,
        },
        ROUTE_COMMAND_POLL_MAX_WIRE_BYTES,
    )
}

macro_rules! canonical_codec {
    ($encode:ident, $decode:ident, $type:ty, $limit:expr, $validate:ident) => {
        pub fn $encode(value: &$type) -> Result<Vec<u8>, RuntimeRouteContractError> {
            $validate(value)?;
            encode_canonical(value, $limit)
        }

        pub fn $decode(bytes: &[u8]) -> Result<$type, RuntimeRouteContractError> {
            decode_canonical(bytes, $limit, $validate)
        }
    };
}

canonical_codec!(
    encode_route_command_envelope,
    decode_route_command_envelope,
    RouteCommandEnvelope,
    ROUTE_COMMAND_ENVELOPE_MAX_WIRE_BYTES,
    validate_route_command_envelope
);
canonical_codec!(
    encode_route_command_response,
    decode_route_command_response,
    RouteCommandResponse,
    ROUTE_COMMAND_RESPONSE_MAX_WIRE_BYTES,
    validate_route_command_response
);
canonical_codec!(
    encode_route_command_poll_request,
    decode_route_command_poll_request,
    RouteCommandPollRequest,
    ROUTE_COMMAND_POLL_MAX_WIRE_BYTES,
    validate_route_command_poll_request
);
canonical_codec!(
    encode_route_command_batch,
    decode_route_command_batch,
    RouteCommandBatch,
    ROUTE_COMMAND_BATCH_MAX_WIRE_BYTES,
    validate_route_command_batch
);
canonical_codec!(
    encode_route_result_commit_request,
    decode_route_result_commit_request,
    RouteResultCommitRequest,
    ROUTE_RESULT_COMMIT_MAX_WIRE_BYTES,
    validate_route_result_commit_request
);
canonical_codec!(
    encode_route_result_stored_ack,
    decode_route_result_stored_ack,
    RouteResultStoredAck,
    ROUTE_RESULT_STORED_ACK_MAX_WIRE_BYTES,
    validate_route_result_stored_ack
);
canonical_codec!(
    encode_route_node_ring_ack,
    decode_route_node_ring_ack,
    RouteNodeRingAck,
    ROUTE_COMMAND_POLL_MAX_WIRE_BYTES,
    validate_route_node_ring_ack
);
canonical_codec!(
    encode_route_control_invalidation,
    decode_route_control_invalidation,
    RouteControlInvalidation,
    ROUTE_OPERATION_MAX_WIRE_BYTES,
    validate_route_control_invalidation
);
canonical_codec!(
    encode_route_operation,
    decode_route_operation,
    RouteOperation,
    ROUTE_OPERATION_MAX_WIRE_BYTES,
    validate_route_operation
);
canonical_codec!(
    encode_runtime_route_error,
    decode_runtime_route_error,
    RuntimeRouteError,
    ROUTE_ERROR_MAX_WIRE_BYTES,
    validate_runtime_route_error
);

pub fn validate_route_serving_binding(
    binding: &RouteServingBinding,
) -> Result<(), RuntimeRouteContractError> {
    if binding.target_port == 0
        || binding.placement_identity.node_id != binding.admission_session.node_id
    {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

fn validate_route_command_envelope_unsigned(
    envelope: &RouteCommandEnvelope,
) -> Result<(), RuntimeRouteContractError> {
    if envelope.version != ContractVersion::V1 {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    validate_route_serving_binding(&envelope.binding)
}

pub fn validate_route_command_envelope(
    envelope: &RouteCommandEnvelope,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_command_envelope_unsigned(envelope)?;
    if route_command_request_fingerprint(envelope)? != envelope.request_fingerprint {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_command_response(
    response: &RouteCommandResponse,
) -> Result<(), RuntimeRouteContractError> {
    if response.version != ContractVersion::V1
        || response.endpoint_id != response.result.binding().endpoint_id
    {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    validate_route_serving_binding(response.result.binding())
}

pub fn validate_route_command_response_for_command(
    response: &RouteCommandResponse,
    command: &RouteCommandEnvelope,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_command_response(response)?;
    validate_route_command_envelope(command)?;
    let legal_result = matches!(
        (command.command, &response.result),
        (RouteCommand::Enable, RouteNodeResult::Serving(_))
            | (RouteCommand::Enable, RouteNodeResult::Rejected(_))
            | (RouteCommand::Disable, RouteNodeResult::Closed(_))
            | (RouteCommand::Disable, RouteNodeResult::Rejected(_))
    );
    if response.operation_id != command.operation_id
        || response.endpoint_id != command.binding.endpoint_id
        || response.request_fingerprint != command.request_fingerprint
        || response.result.binding() != &command.binding
        || !legal_result
    {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

fn validate_route_node_ring_ack_unsigned(
    ack: &RouteNodeRingAck,
) -> Result<(), RuntimeRouteContractError> {
    if ack.version != ContractVersion::V1
        || ack.loaded_kids.len() > ROUTE_RING_ACK_MAX_LOADED_KIDS
        || key_ring_digest(ack.ring_version, &ack.loaded_kids)
            .map_err(|_| RuntimeRouteContractError::InvalidContract)?
            != ack.key_ring_digest
    {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_node_ring_ack(
    ack: &RouteNodeRingAck,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_node_ring_ack_unsigned(ack)?;
    if route_node_ring_ack_digest(ack)? != ack.ack_digest {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_command_poll_request(
    poll: &RouteCommandPollRequest,
) -> Result<(), RuntimeRouteContractError> {
    if poll.version != ContractVersion::V1 {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    if let Some(ack) = &poll.installed_ring_ack {
        validate_route_node_ring_ack(ack)?;
        if ack.session != poll.session {
            return Err(RuntimeRouteContractError::InvalidContract);
        }
    }
    Ok(())
}

pub fn validate_route_command_poll_for_session(
    poll: &RouteCommandPollRequest,
    current_session: &AgentSession,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_command_poll_request(poll)?;
    validate_agent_session(current_session)?;
    if poll.session != session_binding(current_session) {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_command_batch(
    batch: &RouteCommandBatch,
) -> Result<(), RuntimeRouteContractError> {
    if batch.version != ContractVersion::V1
        || batch.commands.len() > ROUTE_COMMAND_BATCH_MAX_COMMANDS
        || !batch
            .commands
            .windows(2)
            .all(|pair| pair[0].binding.endpoint_id.as_str() < pair[1].binding.endpoint_id.as_str())
        || has_duplicate_by(&batch.commands, |command| command.operation_id.as_str())
    {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    for command in &batch.commands {
        validate_route_command_envelope(command)?;
        if command.binding.admission_session != batch.session {
            return Err(RuntimeRouteContractError::InvalidContract);
        }
    }
    Ok(())
}

pub fn validate_route_command_batch_for_poll(
    batch: &RouteCommandBatch,
    poll: &RouteCommandPollRequest,
    current_session: &AgentSession,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_command_batch(batch)?;
    validate_route_command_poll_for_session(poll, current_session)?;
    if batch.session != poll.session || batch.request_sequence != poll.request_sequence {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_result_commit_request(
    commit: &RouteResultCommitRequest,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_command_response(&commit.response)?;
    if commit.version != ContractVersion::V1
        || commit.session != commit.response.result.binding().admission_session
        || commit.terminal_result_digest != route_terminal_result_digest(&commit.response)?
    {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_result_commit_for_command(
    commit: &RouteResultCommitRequest,
    command: &RouteCommandEnvelope,
    current_session: &AgentSession,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_result_commit_request(commit)?;
    validate_route_command_response_for_command(&commit.response, command)?;
    validate_agent_session(current_session)?;
    if commit.session != session_binding(current_session) {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_result_stored_ack(
    ack: &RouteResultStoredAck,
) -> Result<(), RuntimeRouteContractError> {
    if ack.version == ContractVersion::V1 {
        Ok(())
    } else {
        Err(RuntimeRouteContractError::InvalidContract)
    }
}

fn validate_route_control_invalidation_unsigned(
    invalidation: &RouteControlInvalidation,
) -> Result<(), RuntimeRouteContractError> {
    let exact_cause = match invalidation.reason {
        RouteControlInvalidationReason::EndpointBindingChanged => {
            invalidation.invalidating_lifecycle_operation_id.is_none()
                && invalidation.replacement_session.is_none()
        }
        RouteControlInvalidationReason::LifecycleClosed
        | RouteControlInvalidationReason::LifecycleCloseAmbiguous => {
            invalidation.invalidating_lifecycle_operation_id.is_some()
                && invalidation.replacement_session.is_none()
        }
        RouteControlInvalidationReason::AgentSessionReplaced => {
            invalidation.invalidating_lifecycle_operation_id.is_none()
                && invalidation.replacement_session.is_some()
        }
    };
    if invalidation.version != ContractVersion::V1 || !exact_cause {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_control_invalidation(
    invalidation: &RouteControlInvalidation,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_control_invalidation_unsigned(invalidation)?;
    if route_control_invalidation_digest(invalidation)? != invalidation.invalidation_digest {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_route_operation(
    operation: &RouteOperation,
) -> Result<(), RuntimeRouteContractError> {
    validate_route_command_envelope(&operation.canonical_request)?;
    if operation.version != ContractVersion::V1
        || operation.operation_id != operation.canonical_request.operation_id
        || operation.endpoint_id != operation.canonical_request.binding.endpoint_id
        || operation.command_kind != operation.canonical_request.command_kind()
        || operation.request_fingerprint != operation.canonical_request.request_fingerprint
    {
        return Err(RuntimeRouteContractError::InvalidContract);
    }
    match (&operation.state, operation.terminal_at_unix_ms) {
        (RouteOperationState::Unresolved, None) => Ok(()),
        (RouteOperationState::Terminal { terminal }, Some(_)) => match terminal.as_ref() {
            RouteOperationTerminal::NodeResult {
                response,
                terminal_result_digest,
            } => {
                validate_route_command_response_for_command(
                    response,
                    &operation.canonical_request,
                )?;
                if route_terminal_result_digest(response)? != *terminal_result_digest {
                    return Err(RuntimeRouteContractError::InvalidContract);
                }
                Ok(())
            }
            RouteOperationTerminal::ControlInvalidation { invalidation } => {
                validate_route_control_invalidation(invalidation)?;
                if invalidation.endpoint_id != operation.endpoint_id
                    || invalidation.invalidated_operation_id != operation.operation_id
                {
                    return Err(RuntimeRouteContractError::InvalidContract);
                }
                Ok(())
            }
        },
        _ => Err(RuntimeRouteContractError::InvalidContract),
    }
}

pub fn validate_runtime_route_error(
    error: &RuntimeRouteError,
) -> Result<(), RuntimeRouteContractError> {
    encode_canonical(error, ROUTE_ERROR_MAX_WIRE_BYTES).map(|_| ())
}

fn validate_agent_session(session: &AgentSession) -> Result<(), RuntimeRouteContractError> {
    encode_agent_session(session)
        .map(|_| ())
        .map_err(|_| RuntimeRouteContractError::InvalidContract)
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn has_duplicate_by<T>(values: &[T], key: fn(&T) -> &str) -> bool {
    let mut keys = values.iter().map(key).collect::<Vec<_>>();
    keys.sort_unstable();
    keys.windows(2).any(|pair| pair[0] == pair[1])
}

fn digest_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
    maximum: usize,
) -> Result<Sha256Digest, RuntimeRouteContractError> {
    let bytes = encode_canonical(value, maximum)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(bytes);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, RuntimeRouteContractError> {
    let bytes = serde_json::to_vec(value).map_err(|_| RuntimeRouteContractError::Malformed)?;
    if bytes.len() > maximum {
        return Err(RuntimeRouteContractError::WireTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T>(
    bytes: &[u8],
    maximum: usize,
    validate: impl Fn(&T) -> Result<(), RuntimeRouteContractError>,
) -> Result<T, RuntimeRouteContractError>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    if bytes.len() > maximum {
        return Err(RuntimeRouteContractError::WireTooLarge);
    }
    let value =
        serde_json::from_slice::<T>(bytes).map_err(|_| RuntimeRouteContractError::Malformed)?;
    validate(&value)?;
    if serde_json::to_vec(&value).map_err(|_| RuntimeRouteContractError::Malformed)? != bytes {
        return Err(RuntimeRouteContractError::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_reconciliation::NodeBootId;

    fn id(value: &str) -> Id {
        Id::new(value.to_owned()).unwrap()
    }

    fn random(value: u8) -> RandomId128 {
        RandomId128::new(format!("{value:02x}").repeat(16)).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }

    fn sequence(value: u64) -> Sequence {
        Sequence::new(value).unwrap()
    }

    fn session(epoch_value: u64) -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("ab".repeat(16)).unwrap(),
            agent_instance_id: random(epoch_value as u8),
            agent_session_epoch: epoch(epoch_value),
        }
    }

    fn binding(route_epoch: u64, session_epoch: u64) -> RouteServingBinding {
        RouteServingBinding {
            workspace_id: id("workspace_a"),
            endpoint_id: id("endpoint_a"),
            hostname: Hostname::new("cat-a.example.test".to_owned()).unwrap(),
            cat_id: id("cat_a"),
            placement_identity: PlacementIdentity {
                node_id: id("node_a"),
                placement_epoch: epoch(7),
            },
            effective_runtime_ready: EffectiveRuntimeReady {
                source_lifecycle_operation_id: id("lifecycle_start_a"),
                runtime_incarnation: random(4),
                runtime_config_digest: digest(5),
                runtime_ready_receipt_digest: digest(6),
            },
            route_epoch: epoch(route_epoch),
            admission_session: session(session_epoch),
            protocol: HttpProtocol::Http,
            target_port: 8080,
        }
    }

    fn enable(route_epoch: u64, session_epoch: u64) -> RouteCommandEnvelope {
        RouteCommandEnvelope::new(
            id("route_operation_a"),
            binding(route_epoch, session_epoch),
            RouteCommandPredecessor::Genesis,
            RouteCommand::Enable,
        )
        .unwrap()
    }

    #[test]
    fn command_and_result_are_exact_canonical_replay_units() {
        let command = enable(3, 2);
        let result = RouteNodeResult::Serving(RouteServingResult {
            binding: command.binding.clone(),
            admission_cell_receipt_digest: digest(8),
        });
        let response = RouteCommandResponse::new(&command, result).unwrap();

        let encoded = encode_route_command_envelope(&command).unwrap();
        assert_eq!(decode_route_command_envelope(&encoded).unwrap(), command);
        let encoded = encode_route_command_response(&response).unwrap();
        assert_eq!(decode_route_command_response(&encoded).unwrap(), response);
    }

    #[test]
    fn result_for_another_binding_or_command_kind_is_rejected() {
        let command = enable(3, 2);
        let mut wrong = command.binding.clone();
        wrong.route_epoch = epoch(4);
        assert_eq!(
            RouteCommandResponse::new(
                &command,
                RouteNodeResult::Serving(RouteServingResult {
                    binding: wrong,
                    admission_cell_receipt_digest: digest(8),
                }),
            ),
            Err(RuntimeRouteContractError::InvalidContract)
        );
        assert_eq!(
            RouteCommandResponse::new(
                &command,
                RouteNodeResult::Closed(RouteClosedResult {
                    binding: command.binding.clone(),
                    admission_cell_receipt_digest: digest(8),
                }),
            ),
            Err(RuntimeRouteContractError::InvalidContract)
        );
    }

    #[test]
    fn ring_ack_is_session_bound_and_recomputes_the_loaded_set() {
        let ack = RouteNodeRingAck::new(session(2), random(9), sequence(1), epoch(4), Vec::new())
            .unwrap();
        validate_route_node_ring_ack(&ack).unwrap();

        let mut tampered = ack;
        tampered.ring_version = epoch(5);
        assert_eq!(
            validate_route_node_ring_ack(&tampered),
            Err(RuntimeRouteContractError::InvalidContract)
        );
    }

    #[test]
    fn batch_is_per_endpoint_and_exact_session() {
        let mut first = enable(3, 2);
        first.binding.endpoint_id = id("endpoint_a");
        first.request_fingerprint = route_command_request_fingerprint(&first).unwrap();
        let mut second = enable(3, 2);
        second.operation_id = id("route_operation_b");
        second.binding.endpoint_id = id("endpoint_b");
        second.request_fingerprint = route_command_request_fingerprint(&second).unwrap();
        let batch = RouteCommandBatch {
            version: ContractVersion::V1,
            session: session(2),
            request_sequence: sequence(1),
            commands: vec![first, second],
        };
        validate_route_command_batch(&batch).unwrap();

        let mut stale = batch;
        stale.commands[1].binding.admission_session = session(3);
        stale.commands[1].request_fingerprint =
            route_command_request_fingerprint(&stale.commands[1]).unwrap();
        assert_eq!(
            validate_route_command_batch(&stale),
            Err(RuntimeRouteContractError::InvalidContract)
        );
    }

    #[test]
    fn control_invalidation_has_one_exact_authority_source() {
        let invalidation = RouteControlInvalidation::new(
            id("endpoint_a"),
            id("route_operation_a"),
            RouteControlInvalidationReason::AgentSessionReplaced,
            None,
            Some(session(3)),
            epoch(4),
            UnixMillis::new(10).unwrap(),
        )
        .unwrap();
        validate_route_control_invalidation(&invalidation).unwrap();

        assert_eq!(
            RouteControlInvalidation::new(
                id("endpoint_a"),
                id("route_operation_a"),
                RouteControlInvalidationReason::AgentSessionReplaced,
                Some(id("lifecycle_a")),
                Some(session(3)),
                epoch(4),
                UnixMillis::new(10).unwrap(),
            ),
            Err(RuntimeRouteContractError::InvalidContract)
        );
    }

    #[test]
    fn noncanonical_wire_is_rejected() {
        let command = enable(3, 2);
        let mut bytes = encode_route_command_envelope(&command).unwrap();
        bytes.push(b'\n');
        assert_eq!(
            decode_route_command_envelope(&bytes),
            Err(RuntimeRouteContractError::NonCanonical)
        );
    }
}

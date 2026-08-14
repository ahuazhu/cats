//! Provider-neutral trusted Host-fence evidence and effect ports.
//!
//! A successful proof always includes the independently authoritative object
//! writer cutoff.  Compute and workload-network observations are required
//! serving barriers, but neither can authorize recovery on its own.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use cats_api::runtime_reconciliation::{
    AsciiText, Epoch, Id, NodeBootId, ProviderScope, Sha256Digest, UnixMillis, WireU64,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HOST_FENCE_PROVIDER_EVIDENCE_VERSION: u16 = 1;
pub const MAX_HOST_FENCE_NETWORK_INTERFACES: usize = 64;

/// Exact Cats and provider lineage targeted by one fence attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFenceBinding {
    pub provider_scope: ProviderScope,
    pub immutable_host_id: Id,
    pub node_id: Id,
    pub expected_node_boot_id: NodeBootId,
    pub expected_agent_session_epoch: Epoch,
    pub fence_attempt_id: Id,
}

/// Stable provider references for the old writer.  These are identifiers,
/// never credential bytes, bucket credentials, or an ambient SDK context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriterFenceTarget {
    pub writer_authority_id: Id,
    pub provider_scope: ProviderScope,
    pub workload_principal_id: AsciiText,
    pub object_store_scope_id: AsciiText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFenceAttemptRequest {
    pub binding: HostFenceBinding,
    pub network_quarantine_boundary_id: AsciiText,
    pub object_writer: ObjectWriterFenceTarget,
}

/// Provider-authoritative execution cutoff observed after the object-writer
/// terminal/visibility barrier.  Host destruction does not by itself prove
/// destruction of the Cats state path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostExecutionCutoffEvidence {
    HostStopped {
        immutable_host_id: Id,
        effect_token: AsciiText,
        provider_attempt_id: AsciiText,
        authoritative_observation_id: AsciiText,
        observed_at_unix_ms: UnixMillis,
    },
    HostDestroyed {
        immutable_host_id: Id,
        effect_token: AsciiText,
        provider_attempt_id: AsciiText,
        authoritative_observation_id: AsciiText,
        observed_at_unix_ms: UnixMillis,
    },
}

impl HostExecutionCutoffEvidence {
    pub fn immutable_host_id(&self) -> &Id {
        match self {
            Self::HostStopped {
                immutable_host_id, ..
            }
            | Self::HostDestroyed {
                immutable_host_id, ..
            } => immutable_host_id,
        }
    }

    pub fn effect_token(&self) -> &AsciiText {
        match self {
            Self::HostStopped { effect_token, .. } | Self::HostDestroyed { effect_token, .. } => {
                effect_token
            }
        }
    }

    pub fn provider_attempt_id(&self) -> &AsciiText {
        match self {
            Self::HostStopped {
                provider_attempt_id,
                ..
            }
            | Self::HostDestroyed {
                provider_attempt_id,
                ..
            } => provider_attempt_id,
        }
    }

    pub fn observed_at_unix_ms(&self) -> UnixMillis {
        match self {
            Self::HostStopped {
                observed_at_unix_ms,
                ..
            }
            | Self::HostDestroyed {
                observed_at_unix_ms,
                ..
            } => *observed_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantinedNetworkInterfaceEvidence {
    pub interface_id: Id,
    pub effect_token: AsciiText,
    pub provider_attempt_id: AsciiText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadNetworkCutoffEvidence {
    WorkloadInterfacesQuarantined {
        immutable_host_id: Id,
        quarantine_policy_id: Id,
        boundary_effect_token: AsciiText,
        boundary_provider_attempt_id: AsciiText,
        policy_observation_id: AsciiText,
        policy_observed_at_unix_ms: UnixMillis,
        interfaces: Vec<QuarantinedNetworkInterfaceEvidence>,
        authoritative_observation_id: AsciiText,
        observed_at_unix_ms: UnixMillis,
    },
}

impl WorkloadNetworkCutoffEvidence {
    pub fn immutable_host_id(&self) -> &Id {
        match self {
            Self::WorkloadInterfacesQuarantined {
                immutable_host_id, ..
            } => immutable_host_id,
        }
    }

    pub fn quarantine_policy_id(&self) -> &Id {
        match self {
            Self::WorkloadInterfacesQuarantined {
                quarantine_policy_id,
                ..
            } => quarantine_policy_id,
        }
    }

    pub fn boundary_effect_token(&self) -> &AsciiText {
        match self {
            Self::WorkloadInterfacesQuarantined {
                boundary_effect_token,
                ..
            } => boundary_effect_token,
        }
    }

    pub fn boundary_provider_attempt_id(&self) -> &AsciiText {
        match self {
            Self::WorkloadInterfacesQuarantined {
                boundary_provider_attempt_id,
                ..
            } => boundary_provider_attempt_id,
        }
    }

    pub fn interfaces(&self) -> &[QuarantinedNetworkInterfaceEvidence] {
        match self {
            Self::WorkloadInterfacesQuarantined { interfaces, .. } => interfaces,
        }
    }

    pub fn policy_observed_at_unix_ms(&self) -> UnixMillis {
        match self {
            Self::WorkloadInterfacesQuarantined {
                policy_observed_at_unix_ms,
                ..
            } => *policy_observed_at_unix_ms,
        }
    }

    pub fn interfaces_observed_at_unix_ms(&self) -> UnixMillis {
        match self {
            Self::WorkloadInterfacesQuarantined {
                observed_at_unix_ms,
                ..
            } => *observed_at_unix_ms,
        }
    }

    pub fn observed_at_unix_ms(&self) -> UnixMillis {
        std::cmp::max(
            self.policy_observed_at_unix_ms(),
            self.interfaces_observed_at_unix_ms(),
        )
    }
}

/// Object-store authority receipt.  The variant asserts all three facts as
/// one closed result: the old principal cannot start another PUT, every PUT
/// accepted before cutoff is permanently terminal, and every successful PUT
/// is visible to subsequently-started strong LIST operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectWriteCutoffEvidence {
    PrincipalCutoffWithAcceptedPutTerminalBarrier {
        binding: HostFenceBinding,
        object_writer: ObjectWriterFenceTarget,
        effect_token: AsciiText,
        provider_attempt_id: AsciiText,
        cutoff_receipt_id: AsciiText,
        cutoff_effective_at_unix_ms: UnixMillis,
        cutoff_sequence: WireU64,
        accepted_put_terminal_receipt_id: AsciiText,
        accepted_puts_terminal_at_unix_ms: UnixMillis,
        terminal_sequence: WireU64,
        terminal_prefix_sha256: Sha256Digest,
        successful_put_visibility_receipt_id: AsciiText,
        successful_puts_visible_at_unix_ms: UnixMillis,
    },
}

impl ObjectWriteCutoffEvidence {
    pub fn binding(&self) -> &HostFenceBinding {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier { binding, .. } => binding,
        }
    }

    pub fn object_writer(&self) -> &ObjectWriterFenceTarget {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier { object_writer, .. } => {
                object_writer
            }
        }
    }

    pub fn effect_token(&self) -> &AsciiText {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier { effect_token, .. } => {
                effect_token
            }
        }
    }

    pub fn provider_attempt_id(&self) -> &AsciiText {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                provider_attempt_id,
                ..
            } => provider_attempt_id,
        }
    }

    pub fn cutoff_effective_at_unix_ms(&self) -> UnixMillis {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                cutoff_effective_at_unix_ms,
                ..
            } => *cutoff_effective_at_unix_ms,
        }
    }

    pub fn accepted_puts_terminal_at_unix_ms(&self) -> UnixMillis {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                accepted_puts_terminal_at_unix_ms,
                ..
            } => *accepted_puts_terminal_at_unix_ms,
        }
    }

    pub fn cutoff_sequence(&self) -> WireU64 {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                cutoff_sequence, ..
            } => *cutoff_sequence,
        }
    }

    pub fn terminal_sequence(&self) -> WireU64 {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                terminal_sequence, ..
            } => *terminal_sequence,
        }
    }

    pub fn successful_puts_visible_at_unix_ms(&self) -> UnixMillis {
        match self {
            Self::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                successful_puts_visible_at_unix_ms,
                ..
            } => *successful_puts_visible_at_unix_ms,
        }
    }
}

/// Complete proof.  There is no compute-only, network-only, timeout, or
/// heartbeat-derived success representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFenceProviderEvidence {
    pub version: u16,
    pub binding: HostFenceBinding,
    pub object_write_cutoff: ObjectWriteCutoffEvidence,
    pub execution_cutoff: HostExecutionCutoffEvidence,
    pub network_cutoff: WorkloadNetworkCutoffEvidence,
    pub completed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostFenceEvidenceError {
    #[error("unsupported Host-fence evidence version")]
    UnsupportedVersion,
    #[error("Host-fence evidence is bound to another attempt")]
    BindingMismatch,
    #[error("Host-fence evidence is bound to another provider scope")]
    ProviderScopeMismatch,
    #[error("execution observation names another immutable Host")]
    ExecutionHostMismatch,
    #[error("network observation names another immutable Host")]
    NetworkHostMismatch,
    #[error("network observation names another quarantine boundary")]
    NetworkBoundaryMismatch,
    #[error("network observation is empty or exceeds its hard limit")]
    NetworkInterfaceCount,
    #[error("network interfaces are not in strict canonical order")]
    NetworkInterfaceOrder,
    #[error("effect token does not bind the exact attempt and target")]
    EffectTokenMismatch,
    #[error("provider attempt id does not bind the exact attempt and target")]
    ProviderAttemptMismatch,
    #[error("object-write cutoff names another writer")]
    ObjectWriterMismatch,
    #[error("object-write cutoff, terminal, and visibility times are not ordered")]
    ObjectWriteTimeOrder,
    #[error("execution or network observation predates the object-write barrier")]
    PostBarrierObservationMissing,
    #[error("completion time is not the exact final observation time")]
    CompletionTimeMismatch,
}

pub fn host_fence_request_from_provider_evidence(
    evidence: &HostFenceProviderEvidence,
) -> Result<HostFenceAttemptRequest, HostFenceEvidenceError> {
    let boundary = AsciiText::new(
        evidence
            .network_cutoff
            .quarantine_policy_id()
            .as_str()
            .to_owned(),
    )
    .ok_or(HostFenceEvidenceError::NetworkBoundaryMismatch)?;
    Ok(HostFenceAttemptRequest {
        binding: evidence.binding.clone(),
        network_quarantine_boundary_id: boundary,
        object_writer: evidence.object_write_cutoff.object_writer().clone(),
    })
}

pub fn validate_object_write_cutoff_evidence(
    request: &HostFenceAttemptRequest,
    evidence: &ObjectWriteCutoffEvidence,
) -> Result<(), HostFenceEvidenceError> {
    if evidence.binding() != &request.binding {
        return Err(HostFenceEvidenceError::BindingMismatch);
    }
    if evidence.object_writer().provider_scope != request.object_writer.provider_scope {
        return Err(HostFenceEvidenceError::ProviderScopeMismatch);
    }
    if evidence.object_writer() != &request.object_writer {
        return Err(HostFenceEvidenceError::ObjectWriterMismatch);
    }
    validate_effect_identity(
        &request.binding,
        b"object-write-cutoff",
        &object_writer_target_bytes(&request.object_writer)?,
        evidence.effect_token(),
        evidence.provider_attempt_id(),
    )?;
    let cutoff = evidence.cutoff_effective_at_unix_ms();
    let terminal = evidence.accepted_puts_terminal_at_unix_ms();
    let visible = evidence.successful_puts_visible_at_unix_ms();
    if cutoff > terminal
        || terminal > visible
        || evidence.cutoff_sequence() != evidence.terminal_sequence()
    {
        return Err(HostFenceEvidenceError::ObjectWriteTimeOrder);
    }
    Ok(())
}

pub fn validate_host_fence_provider_evidence(
    request: &HostFenceAttemptRequest,
    evidence: &HostFenceProviderEvidence,
) -> Result<(), HostFenceEvidenceError> {
    if evidence.version != HOST_FENCE_PROVIDER_EVIDENCE_VERSION {
        return Err(HostFenceEvidenceError::UnsupportedVersion);
    }
    if evidence.binding != request.binding {
        return Err(HostFenceEvidenceError::BindingMismatch);
    }
    if evidence.binding.provider_scope != request.binding.provider_scope {
        return Err(HostFenceEvidenceError::ProviderScopeMismatch);
    }
    if evidence.execution_cutoff.immutable_host_id() != &request.binding.immutable_host_id {
        return Err(HostFenceEvidenceError::ExecutionHostMismatch);
    }
    validate_effect_identity(
        &request.binding,
        b"host-execution-cutoff",
        request.binding.immutable_host_id.as_str().as_bytes(),
        evidence.execution_cutoff.effect_token(),
        evidence.execution_cutoff.provider_attempt_id(),
    )?;

    if evidence.network_cutoff.immutable_host_id() != &request.binding.immutable_host_id {
        return Err(HostFenceEvidenceError::NetworkHostMismatch);
    }
    if evidence.network_cutoff.quarantine_policy_id().as_str()
        != request.network_quarantine_boundary_id.as_str()
    {
        return Err(HostFenceEvidenceError::NetworkBoundaryMismatch);
    }
    validate_effect_identity(
        &request.binding,
        b"network-boundary-cutoff",
        request.network_quarantine_boundary_id.as_str().as_bytes(),
        evidence.network_cutoff.boundary_effect_token(),
        evidence.network_cutoff.boundary_provider_attempt_id(),
    )?;
    let interfaces = evidence.network_cutoff.interfaces();
    if interfaces.is_empty() || interfaces.len() > MAX_HOST_FENCE_NETWORK_INTERFACES {
        return Err(HostFenceEvidenceError::NetworkInterfaceCount);
    }
    if interfaces
        .windows(2)
        .any(|pair| pair[0].interface_id >= pair[1].interface_id)
    {
        return Err(HostFenceEvidenceError::NetworkInterfaceOrder);
    }
    let unique_tokens = interfaces
        .iter()
        .map(|interface| &interface.effect_token)
        .collect::<BTreeSet<_>>();
    let unique_attempts = interfaces
        .iter()
        .map(|interface| &interface.provider_attempt_id)
        .collect::<BTreeSet<_>>();
    if unique_tokens.len() != interfaces.len() || unique_attempts.len() != interfaces.len() {
        return Err(HostFenceEvidenceError::ProviderAttemptMismatch);
    }
    for interface in interfaces {
        validate_effect_identity(
            &request.binding,
            b"network-interface-cutoff",
            interface.interface_id.as_str().as_bytes(),
            &interface.effect_token,
            &interface.provider_attempt_id,
        )?;
    }

    validate_object_write_cutoff_evidence(request, &evidence.object_write_cutoff)?;
    let object_barrier_at = evidence
        .object_write_cutoff
        .successful_puts_visible_at_unix_ms();
    let execution_at = evidence.execution_cutoff.observed_at_unix_ms();
    let interfaces_at = evidence.network_cutoff.interfaces_observed_at_unix_ms();
    let policy_at = evidence.network_cutoff.policy_observed_at_unix_ms();
    if execution_at < object_barrier_at
        || interfaces_at < object_barrier_at
        || policy_at < object_barrier_at
    {
        return Err(HostFenceEvidenceError::PostBarrierObservationMissing);
    }
    let network_at = std::cmp::max(interfaces_at, policy_at);
    if evidence.completed_at_unix_ms != std::cmp::max(execution_at, network_at) {
        return Err(HostFenceEvidenceError::CompletionTimeMismatch);
    }
    Ok(())
}

pub fn host_fence_effect_token(
    binding: &HostFenceBinding,
    effect_kind: &[u8],
    effect_target: &[u8],
) -> Result<AsciiText, HostFenceEvidenceError> {
    derived_token(
        b"cats.host-fence-effect-token.v1",
        "hfe1_",
        binding,
        effect_kind,
        effect_target,
    )
}

pub fn host_fence_provider_attempt_id(
    binding: &HostFenceBinding,
    effect_kind: &[u8],
    effect_target: &[u8],
) -> Result<AsciiText, HostFenceEvidenceError> {
    derived_token(
        b"cats.host-fence-provider-attempt.v1",
        "hfpa1_",
        binding,
        effect_kind,
        effect_target,
    )
}

fn validate_effect_identity(
    binding: &HostFenceBinding,
    effect_kind: &[u8],
    effect_target: &[u8],
    effect_token: &AsciiText,
    provider_attempt_id: &AsciiText,
) -> Result<(), HostFenceEvidenceError> {
    if effect_token != &host_fence_effect_token(binding, effect_kind, effect_target)? {
        return Err(HostFenceEvidenceError::EffectTokenMismatch);
    }
    if provider_attempt_id != &host_fence_provider_attempt_id(binding, effect_kind, effect_target)?
    {
        return Err(HostFenceEvidenceError::ProviderAttemptMismatch);
    }
    Ok(())
}

fn object_writer_target_bytes(
    target: &ObjectWriterFenceTarget,
) -> Result<Vec<u8>, HostFenceEvidenceError> {
    let mut bytes = Vec::new();
    push_frame(&mut bytes, target.writer_authority_id.as_str().as_bytes())?;
    push_frame(
        &mut bytes,
        target.provider_scope.provider.as_str().as_bytes(),
    )?;
    push_frame(
        &mut bytes,
        target.provider_scope.partition.as_str().as_bytes(),
    )?;
    push_frame(
        &mut bytes,
        target.provider_scope.account_id.as_str().as_bytes(),
    )?;
    push_frame(&mut bytes, target.provider_scope.region.as_str().as_bytes())?;
    push_frame(&mut bytes, target.workload_principal_id.as_str().as_bytes())?;
    push_frame(&mut bytes, target.object_store_scope_id.as_str().as_bytes())?;
    Ok(bytes)
}

fn derived_token(
    domain: &[u8],
    prefix: &str,
    binding: &HostFenceBinding,
    effect_kind: &[u8],
    effect_target: &[u8],
) -> Result<AsciiText, HostFenceEvidenceError> {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, domain)?;
    hash_frame(
        &mut hasher,
        binding.provider_scope.provider.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        binding.provider_scope.partition.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        binding.provider_scope.account_id.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        binding.provider_scope.region.as_str().as_bytes(),
    )?;
    hash_frame(&mut hasher, binding.immutable_host_id.as_str().as_bytes())?;
    hash_frame(&mut hasher, binding.node_id.as_str().as_bytes())?;
    hash_frame(
        &mut hasher,
        binding.expected_node_boot_id.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        &binding.expected_agent_session_epoch.get().to_be_bytes(),
    )?;
    hash_frame(&mut hasher, binding.fence_attempt_id.as_str().as_bytes())?;
    hash_frame(&mut hasher, effect_kind)?;
    hash_frame(&mut hasher, effect_target)?;
    let digest = Sha256Digest::from_bytes(hasher.finalize().into());
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(HostFenceEvidenceError::EffectTokenMismatch)?;
    AsciiText::new(format!("{prefix}{hex}")).ok_or(HostFenceEvidenceError::EffectTokenMismatch)
}

fn push_frame(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), HostFenceEvidenceError> {
    let length =
        u64::try_from(value.len()).map_err(|_| HostFenceEvidenceError::EffectTokenMismatch)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) -> Result<(), HostFenceEvidenceError> {
    let length =
        u64::try_from(value.len()).map_err(|_| HostFenceEvidenceError::EffectTokenMismatch)?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

pub type HostFencePortFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, HostFenceProviderError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostFenceProviderError {
    #[error("Host-fence request is invalid")]
    InvalidRequest,
    #[error("Host-fence deadline elapsed")]
    DeadlineExceeded,
    #[error("execution or network postcondition remains ambiguous")]
    ServingCutoffObservationAmbiguous,
    #[error("provider is unavailable")]
    ProviderUnavailable,
    #[error("object-write cutoff/terminal/visibility barrier is unavailable")]
    ObjectWriteBarrierUnavailable,
    #[error("provider evidence does not match the exact request")]
    EvidenceMismatch,
}

impl From<HostFenceEvidenceError> for HostFenceProviderError {
    fn from(_: HostFenceEvidenceError) -> Self {
        Self::EvidenceMismatch
    }
}

pub trait HostFenceProviderPort: Send + Sync {
    fn establish_fence<'a>(
        &'a self,
        request: &'a HostFenceAttemptRequest,
        absolute_deadline: Instant,
    ) -> HostFencePortFuture<'a, HostFenceProviderEvidence>;
}

/// Independent authority for old-principal cutoff and accepted-PUT closure.
/// A compute/network API acknowledgement cannot implement this port.
pub trait ObjectWriteCutoffPort: Send + Sync {
    fn establish_cutoff<'a>(
        &'a self,
        request: &'a HostFenceAttemptRequest,
        absolute_deadline: Instant,
    ) -> HostFencePortFuture<'a, ObjectWriteCutoffEvidence>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableObjectWriteCutoff;

impl ObjectWriteCutoffPort for UnavailableObjectWriteCutoff {
    fn establish_cutoff<'a>(
        &'a self,
        _request: &'a HostFenceAttemptRequest,
        _absolute_deadline: Instant,
    ) -> HostFencePortFuture<'a, ObjectWriteCutoffEvidence> {
        Box::pin(async { Err(HostFenceProviderError::ObjectWriteBarrierUnavailable) })
    }
}

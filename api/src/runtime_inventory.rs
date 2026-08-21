//! Session-bound runtime inventory and telemetry v1.
//!
//! This contract deliberately carries observations, never lifecycle intent or
//! completion authority. It has no Desired revision/spec, reconcile step,
//! retired runtime checkpoint, route gate, or lifecycle settlement field. A full report
//! establishes one session-bound physical-inventory attestation; a partial
//! report can refresh facts for members of that inventory but cannot replace
//! or expand it.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_lifecycle::{DiskRole, LifecycleCommandKind, PlacementIdentity};
use crate::runtime_reconciliation::{
    AsciiText, ContractVersion, Epoch, FenceEpoch, Generation, Id, RandomId128, Sequence,
    SessionBinding, Sha256Digest, UnixMillis, WireU64,
};

pub const RUNTIME_INVENTORY_METHOD: &str = "POST";
pub const RUNTIME_INVENTORY_PATH: &str = "/v1/internal/runtime/observations";
pub const RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES: usize = 8_388_608;
pub const RUNTIME_INVENTORY_ACCEPTANCE_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_INVENTORY_ERROR_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_INVENTORY_MAX_CATS: usize = 1_024;
pub const RUNTIME_INVENTORY_MAX_VOLUMES_PER_CAT: usize = 64;
pub const RUNTIME_INVENTORY_MAX_ARTIFACTS_PER_CAT: usize = 1_024;
pub const RUNTIME_INVENTORY_MAX_UNATTRIBUTED_ARTIFACTS: usize = 4_096;
pub const RUNTIME_INVENTORY_MAX_CONDITIONS_PER_CAT: usize = 64;

const FULL_INVENTORY_DIGEST_DOMAIN: &[u8] = b"cats.runtime-inventory.full.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryReport {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub report_id: RandomId128,
    pub sequence: Sequence,
    pub collected_at_unix_ms: UnixMillis,
    pub inventory: RuntimeInventoryBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeInventoryBody {
    Full {
        inventory_epoch: Epoch,
        scan_id: RandomId128,
        inventory_digest: Sha256Digest,
        cats: Vec<ObservedCatRuntimeTelemetry>,
        unattributed_artifacts: Vec<ObservedArtifactClassification>,
    },
    Partial {
        inventory_epoch: Epoch,
        cats: Vec<ObservedCatRuntimeTelemetry>,
    },
}

impl RuntimeInventoryBody {
    pub fn inventory_epoch(&self) -> Epoch {
        match self {
            Self::Full {
                inventory_epoch, ..
            }
            | Self::Partial {
                inventory_epoch, ..
            } => *inventory_epoch,
        }
    }

    pub fn cats(&self) -> &[ObservedCatRuntimeTelemetry] {
        match self {
            Self::Full { cats, .. } | Self::Partial { cats, .. } => cats,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCatRuntimeTelemetry {
    pub cat_id: Id,
    pub observed_placement: PlacementIdentity,
    pub observed_command_journal: Option<ObservedCommandJournal>,
    pub observed_physical_state: ObservedRuntimePhysicalState,
    pub observed_runtime_incarnation: Option<RandomId128>,
    pub observed_artifact_manifest_digest: Sha256Digest,
    pub observed_artifact_classifications: Vec<ObservedArtifactClassification>,
    pub observed_volumes: Vec<ObservedVolumeWatermarkSummary>,
    pub observed_conditions: Vec<ObservedRuntimeCondition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedRuntimePhysicalState {
    Absent,
    Executing,
    Paused,
    WarmSnapshotRetained,
    StoppedRetained,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedCommandJournal {
    Accepted {
        operation_id: Id,
        command_kind: LifecycleCommandKind,
        request_fingerprint: Sha256Digest,
        journal_digest: Sha256Digest,
    },
    Executing {
        operation_id: Id,
        command_kind: LifecycleCommandKind,
        request_fingerprint: Sha256Digest,
        journal_digest: Sha256Digest,
    },
    Terminal {
        operation_id: Id,
        command_kind: LifecycleCommandKind,
        request_fingerprint: Sha256Digest,
        journal_digest: Sha256Digest,
        terminal_result_digest: Sha256Digest,
    },
    AwaitingResultStoredAck {
        operation_id: Id,
        command_kind: LifecycleCommandKind,
        request_fingerprint: Sha256Digest,
        journal_digest: Sha256Digest,
        terminal_result_digest: Sha256Digest,
    },
    CompletedDeleteReceipt {
        operation_id: Id,
        request_fingerprint: Sha256Digest,
        journal_digest: Sha256Digest,
        terminal_result_digest: Sha256Digest,
        completed_receipt_digest: Sha256Digest,
    },
}

impl ObservedCommandJournal {
    pub fn operation_id(&self) -> &Id {
        match self {
            Self::Accepted { operation_id, .. }
            | Self::Executing { operation_id, .. }
            | Self::Terminal { operation_id, .. }
            | Self::AwaitingResultStoredAck { operation_id, .. }
            | Self::CompletedDeleteReceipt { operation_id, .. } => operation_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedVolumeWatermarkSummary {
    pub volume_id: Id,
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub observed_attachment: ObservedVolumeAttachment,
    pub observed_watermark: ObservedVolumeWatermark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedVolumeAttachment {
    Unowned {
        attachment_epoch: FenceEpoch,
    },
    Owned {
        owner_node_id: Id,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
    },
    Deleting {
        previous_owner_node_id: Option<Id>,
        fenced_attachment_epoch: FenceEpoch,
    },
    Unknown {
        evidence_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedVolumeWatermark {
    Known {
        local_durable_generation: Generation,
        remote_durable_generation: Generation,
    },
    Unknown {
        evidence_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRuntimeCondition {
    pub kind: ObservedRuntimeConditionKind,
    pub evidence_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedRuntimeConditionKind {
    Healthy,
    Progressing,
    Blocked,
    Degraded,
    Drift,
    Quarantined,
    DataLossPossible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedArtifactClassification {
    AdoptableCatState {
        artifact_id: Id,
        ownership_digest: Sha256Digest,
    },
    CatOwnedGcCandidate {
        artifact_id: Id,
        ownership_digest: Sha256Digest,
        postcondition_digest: Sha256Digest,
    },
    RetainedAuthorityOrData {
        artifact_id: Id,
        evidence_digest: Sha256Digest,
    },
    QuarantinedForeignOrAmbiguous {
        artifact_id: Id,
        evidence_digest: Sha256Digest,
    },
}

impl ObservedArtifactClassification {
    pub fn artifact_id(&self) -> &Id {
        match self {
            Self::AdoptableCatState { artifact_id, .. }
            | Self::CatOwnedGcCandidate { artifact_id, .. }
            | Self::RetainedAuthorityOrData { artifact_id, .. }
            | Self::QuarantinedForeignOrAmbiguous { artifact_id, .. } => artifact_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryAcceptance {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub report_id: RandomId128,
    pub sequence: Sequence,
    pub accepted_at_unix_ms: UnixMillis,
    pub lease_deadline_unix_ms: UnixMillis,
    pub inventory: RuntimeInventoryAcceptanceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeInventoryAcceptanceKind {
    Full {
        attestation: Box<RuntimeInventoryAttestation>,
    },
    Partial {
        inventory_epoch: Epoch,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryAttestation {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub inventory_epoch: Epoch,
    pub scan_id: RandomId128,
    pub inventory_digest: Sha256Digest,
    pub source_report_id: RandomId128,
    pub source_sequence: Sequence,
    pub accepted_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryError {
    pub version: ContractVersion,
    pub error: Box<RuntimeInventoryErrorDetail>,
    pub message: AsciiText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeInventoryErrorDetail {
    MalformedPayload,
    UnsupportedVersion {
        supported_version: ContractVersion,
    },
    LimitExceeded {
        field: AsciiText,
        maximum: WireU64,
    },
    AuthenticationFailed,
    IdentityNotEligible,
    HttpRequestRejected {
        problem: RuntimeInventoryHttpProblem,
    },
    MissingAgentSession {
        node_id: Id,
    },
    StaleSession {
        node_id: Id,
        presented_agent_session_epoch: Epoch,
        current_agent_session_epoch: Epoch,
    },
    WrongSession {
        expected: SessionBinding,
        presented: SessionBinding,
    },
    SessionExpired {
        node_id: Id,
        agent_session_epoch: Epoch,
        lease_deadline_unix_ms: UnixMillis,
        server_time_unix_ms: UnixMillis,
    },
    StaleReportSequence {
        node_id: Id,
        agent_session_epoch: Epoch,
        presented_sequence: Sequence,
        last_accepted_sequence: Sequence,
    },
    ReportSequenceConflict {
        node_id: Id,
        agent_session_epoch: Epoch,
        sequence: Sequence,
        accepted_report_id: RandomId128,
        presented_report_id: RandomId128,
    },
    MissingFullInventory {
        node_id: Id,
        agent_session_epoch: Epoch,
    },
    StaleInventoryEpoch {
        node_id: Id,
        agent_session_epoch: Epoch,
        presented_inventory_epoch: Epoch,
        current_inventory_epoch: Epoch,
    },
    WrongInventoryEpoch {
        node_id: Id,
        agent_session_epoch: Epoch,
        expected_inventory_epoch: Epoch,
        presented_inventory_epoch: Epoch,
    },
    PartialCatNotInFullInventory {
        node_id: Id,
        agent_session_epoch: Epoch,
        inventory_epoch: Epoch,
        cat_id: Id,
    },
    NodeRequestInFlight,
    TemporarilyUnavailable,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeInventoryHttpProblem {
    MethodNotAllowed,
    QueryNotAllowed,
    ContentTypeNotAllowed,
    ContentEncodingNotAllowed,
    AuthorizationNotAllowed,
    AcceptNotAllowed,
    SemanticHeaderNotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryContractError {
    Malformed,
    UnsupportedVersion,
    WireTooLarge,
    LimitExceeded,
    InvalidContract,
    DigestMismatch,
    NotFullInventory,
}

impl std::fmt::Display for RuntimeInventoryContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "runtime inventory payload is malformed",
            Self::UnsupportedVersion => "runtime inventory version is unsupported",
            Self::WireTooLarge => "runtime inventory wire exceeds its bound",
            Self::LimitExceeded => "runtime inventory collection exceeds its bound",
            Self::InvalidContract => "runtime inventory contract is invalid",
            Self::DigestMismatch => "runtime inventory digest does not match",
            Self::NotFullInventory => "runtime inventory digest requires a full report",
        })
    }
}

impl std::error::Error for RuntimeInventoryContractError {}

pub fn encode_runtime_inventory_report(
    report: &RuntimeInventoryReport,
) -> Result<Vec<u8>, RuntimeInventoryContractError> {
    validate_report(report, true)?;
    encode_canonical(report, RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES)
}

pub fn decode_runtime_inventory_report(
    bytes: &[u8],
) -> Result<RuntimeInventoryReport, RuntimeInventoryContractError> {
    decode_canonical(
        bytes,
        RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES,
        |report: &RuntimeInventoryReport| validate_report(report, true),
    )
}

pub fn full_inventory_digest(
    report: &RuntimeInventoryReport,
) -> Result<Sha256Digest, RuntimeInventoryContractError> {
    validate_report(report, false)?;
    let RuntimeInventoryBody::Full { .. } = &report.inventory else {
        return Err(RuntimeInventoryContractError::NotFullInventory);
    };
    let mut value =
        serde_json::to_value(report).map_err(|_| RuntimeInventoryContractError::InvalidContract)?;
    value
        .get_mut("inventory")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|inventory| inventory.remove("inventory_digest"))
        .ok_or(RuntimeInventoryContractError::InvalidContract)?;
    let canonical = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    let mut hasher = Sha256::new();
    hasher.update(FULL_INVENTORY_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

pub fn encode_runtime_inventory_acceptance(
    acceptance: &RuntimeInventoryAcceptance,
) -> Result<Vec<u8>, RuntimeInventoryContractError> {
    validate_acceptance(acceptance)?;
    encode_canonical(acceptance, RUNTIME_INVENTORY_ACCEPTANCE_MAX_WIRE_BYTES)
}

pub fn decode_runtime_inventory_acceptance(
    bytes: &[u8],
) -> Result<RuntimeInventoryAcceptance, RuntimeInventoryContractError> {
    decode_canonical(
        bytes,
        RUNTIME_INVENTORY_ACCEPTANCE_MAX_WIRE_BYTES,
        validate_acceptance,
    )
}

pub fn encode_runtime_inventory_error(
    error: &RuntimeInventoryError,
) -> Result<Vec<u8>, RuntimeInventoryContractError> {
    validate_version(error.version)?;
    encode_canonical(error, RUNTIME_INVENTORY_ERROR_MAX_WIRE_BYTES)
}

pub fn decode_runtime_inventory_error(
    bytes: &[u8],
) -> Result<RuntimeInventoryError, RuntimeInventoryContractError> {
    decode_canonical(
        bytes,
        RUNTIME_INVENTORY_ERROR_MAX_WIRE_BYTES,
        |error: &RuntimeInventoryError| validate_version(error.version),
    )
}

fn validate_report(
    report: &RuntimeInventoryReport,
    check_digest: bool,
) -> Result<(), RuntimeInventoryContractError> {
    validate_version(report.version)?;
    if report.session.node_id.as_str().is_empty() {
        return Err(RuntimeInventoryContractError::InvalidContract);
    }
    match &report.inventory {
        RuntimeInventoryBody::Full {
            inventory_digest,
            cats,
            unattributed_artifacts,
            ..
        } => {
            validate_cats(cats, &report.session.node_id)?;
            validate_artifacts(
                unattributed_artifacts,
                RUNTIME_INVENTORY_MAX_UNATTRIBUTED_ARTIFACTS,
            )?;
            if check_digest && full_inventory_digest(report)? != *inventory_digest {
                return Err(RuntimeInventoryContractError::DigestMismatch);
            }
        }
        RuntimeInventoryBody::Partial { cats, .. } => validate_cats(cats, &report.session.node_id)?,
    }
    Ok(())
}

fn validate_cats(
    cats: &[ObservedCatRuntimeTelemetry],
    reporting_node_id: &Id,
) -> Result<(), RuntimeInventoryContractError> {
    if cats.len() > RUNTIME_INVENTORY_MAX_CATS {
        return Err(RuntimeInventoryContractError::LimitExceeded);
    }
    if !strictly_sorted_by(cats, |cat| cat.cat_id.as_str()) {
        return Err(RuntimeInventoryContractError::InvalidContract);
    }
    for cat in cats {
        validate_observed_cat_runtime_telemetry(cat, reporting_node_id)?;
    }
    Ok(())
}

/// Validates one persisted or in-flight per-Cat projection against the Node
/// that observed it. Collection-level Cat ordering is checked by the report
/// validator.
pub fn validate_observed_cat_runtime_telemetry(
    cat: &ObservedCatRuntimeTelemetry,
    reporting_node_id: &Id,
) -> Result<(), RuntimeInventoryContractError> {
    if cat.observed_placement.node_id != *reporting_node_id {
        return Err(RuntimeInventoryContractError::InvalidContract);
    }
    match cat.observed_physical_state {
        ObservedRuntimePhysicalState::Executing | ObservedRuntimePhysicalState::Paused
            if cat.observed_runtime_incarnation.is_none() =>
        {
            return Err(RuntimeInventoryContractError::InvalidContract);
        }
        ObservedRuntimePhysicalState::Absent if cat.observed_runtime_incarnation.is_some() => {
            return Err(RuntimeInventoryContractError::InvalidContract);
        }
        _ => {}
    }
    validate_artifacts(
        &cat.observed_artifact_classifications,
        RUNTIME_INVENTORY_MAX_ARTIFACTS_PER_CAT,
    )?;
    if cat.observed_volumes.len() > RUNTIME_INVENTORY_MAX_VOLUMES_PER_CAT
        || !strictly_sorted_by(&cat.observed_volumes, |volume| volume.volume_id.as_str())
        || has_duplicate_by(&cat.observed_volumes, |volume| volume.disk_id.as_str())
    {
        return Err(RuntimeInventoryContractError::InvalidContract);
    }
    for volume in &cat.observed_volumes {
        if let ObservedVolumeWatermark::Known {
            local_durable_generation,
            remote_durable_generation,
        } = volume.observed_watermark
        {
            if remote_durable_generation > local_durable_generation {
                return Err(RuntimeInventoryContractError::InvalidContract);
            }
        }
    }
    if cat.observed_conditions.len() > RUNTIME_INVENTORY_MAX_CONDITIONS_PER_CAT
        || !cat
            .observed_conditions
            .windows(2)
            .all(|pair| pair[0].kind < pair[1].kind)
    {
        return Err(RuntimeInventoryContractError::InvalidContract);
    }
    Ok(())
}

fn validate_artifacts(
    artifacts: &[ObservedArtifactClassification],
    maximum: usize,
) -> Result<(), RuntimeInventoryContractError> {
    if artifacts.len() > maximum
        || !strictly_sorted_by(artifacts, |artifact| artifact.artifact_id().as_str())
    {
        return Err(RuntimeInventoryContractError::InvalidContract);
    }
    Ok(())
}

fn validate_acceptance(
    acceptance: &RuntimeInventoryAcceptance,
) -> Result<(), RuntimeInventoryContractError> {
    validate_version(acceptance.version)?;
    if acceptance.lease_deadline_unix_ms < acceptance.accepted_at_unix_ms {
        return Err(RuntimeInventoryContractError::InvalidContract);
    }
    if let RuntimeInventoryAcceptanceKind::Full { attestation } = &acceptance.inventory {
        validate_version(attestation.version)?;
        if attestation.session != acceptance.session
            || attestation.source_report_id != acceptance.report_id
            || attestation.source_sequence != acceptance.sequence
            || attestation.accepted_at_unix_ms != acceptance.accepted_at_unix_ms
        {
            return Err(RuntimeInventoryContractError::InvalidContract);
        }
    }
    Ok(())
}

fn validate_version(version: ContractVersion) -> Result<(), RuntimeInventoryContractError> {
    if version == ContractVersion::V1 {
        Ok(())
    } else {
        Err(RuntimeInventoryContractError::UnsupportedVersion)
    }
}

fn strictly_sorted_by<T>(values: &[T], key: fn(&T) -> &str) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn has_duplicate_by<T>(values: &[T], key: fn(&T) -> &str) -> bool {
    values.iter().enumerate().any(|(index, value)| {
        values[index + 1..]
            .iter()
            .any(|other| key(value) == key(other))
    })
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, RuntimeInventoryContractError> {
    let value =
        serde_json::to_value(value).map_err(|_| RuntimeInventoryContractError::InvalidContract)?;
    let bytes = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    if bytes.len() > maximum {
        return Err(RuntimeInventoryContractError::WireTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T>(
    bytes: &[u8],
    maximum: usize,
    validate: fn(&T) -> Result<(), RuntimeInventoryContractError>,
) -> Result<T, RuntimeInventoryContractError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > maximum {
        return Err(RuntimeInventoryContractError::WireTooLarge);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value =
        T::deserialize(&mut decoder).map_err(|_| RuntimeInventoryContractError::Malformed)?;
    decoder
        .end()
        .map_err(|_| RuntimeInventoryContractError::Malformed)?;
    validate(&value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn session() -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: crate::runtime_reconciliation::NodeBootId::new(
                "11111111111111111111111111111111",
            )
            .unwrap(),
            agent_instance_id: random(2),
            agent_session_epoch: Epoch::new(3).unwrap(),
        }
    }

    fn full_report() -> RuntimeInventoryReport {
        let mut report = RuntimeInventoryReport {
            version: ContractVersion::V1,
            session: session(),
            report_id: random(4),
            sequence: Sequence::new(5).unwrap(),
            collected_at_unix_ms: UnixMillis::new(6).unwrap(),
            inventory: RuntimeInventoryBody::Full {
                inventory_epoch: Epoch::new(1).unwrap(),
                scan_id: random(7),
                inventory_digest: digest(0),
                cats: Vec::new(),
                unattributed_artifacts: Vec::new(),
            },
        };
        let computed = full_inventory_digest(&report).unwrap();
        let RuntimeInventoryBody::Full {
            inventory_digest, ..
        } = &mut report.inventory
        else {
            unreachable!()
        };
        *inventory_digest = computed;
        report
    }

    #[test]
    fn full_report_round_trips_canonical_bytes() {
        let report = full_report();
        let encoded = encode_runtime_inventory_report(&report).unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            concat!(
                "{\"collected_at_unix_ms\":6,\"inventory\":{\"cats\":[],\"inventory_digest\":",
                "\"sha256:04a80ea20c2306d1a7fd8c2b7d9fa718886fef8a99edcfa2a646492a01c9cae4\",",
                "\"inventory_epoch\":1,\"kind\":\"full\",\"scan_id\":",
                "\"00000000000000000000000000000007\",\"unattributed_artifacts\":[]},",
                "\"report_id\":\"00000000000000000000000000000004\",\"sequence\":5,",
                "\"session\":{\"agent_instance_id\":\"00000000000000000000000000000002\",",
                "\"agent_session_epoch\":3,\"node_boot_id\":\"11111111111111111111111111111111\",",
                "\"node_id\":\"node_a\"},\"version\":1}",
            )
        );
        assert_eq!(decode_runtime_inventory_report(&encoded).unwrap(), report);
        assert_eq!(encode_runtime_inventory_report(&report).unwrap(), encoded);
    }

    #[test]
    fn full_digest_fixed_vector_changes_with_scan_identity_or_facts() {
        let report = full_report();
        let original = full_inventory_digest(&report).unwrap();
        assert_eq!(
            original.as_str(),
            "sha256:04a80ea20c2306d1a7fd8c2b7d9fa718886fef8a99edcfa2a646492a01c9cae4"
        );
        let mut changed = report.clone();
        let RuntimeInventoryBody::Full { scan_id, .. } = &mut changed.inventory else {
            unreachable!()
        };
        *scan_id = random(8);
        assert_ne!(full_inventory_digest(&changed).unwrap(), original);
    }

    #[test]
    fn claimed_full_digest_is_verified() {
        let mut report = full_report();
        let RuntimeInventoryBody::Full {
            inventory_digest, ..
        } = &mut report.inventory
        else {
            unreachable!()
        };
        *inventory_digest = digest(9);
        assert_eq!(
            encode_runtime_inventory_report(&report),
            Err(RuntimeInventoryContractError::DigestMismatch)
        );
    }

    #[test]
    fn partial_has_no_full_inventory_digest() {
        let report = RuntimeInventoryReport {
            version: ContractVersion::V1,
            session: session(),
            report_id: random(9),
            sequence: Sequence::new(6).unwrap(),
            collected_at_unix_ms: UnixMillis::new(7).unwrap(),
            inventory: RuntimeInventoryBody::Partial {
                inventory_epoch: Epoch::new(1).unwrap(),
                cats: Vec::new(),
            },
        };
        assert_eq!(
            full_inventory_digest(&report),
            Err(RuntimeInventoryContractError::NotFullInventory)
        );
        let encoded = encode_runtime_inventory_report(&report).unwrap();
        assert_eq!(decode_runtime_inventory_report(&encoded).unwrap(), report);
    }

    #[test]
    fn vectors_are_strictly_sorted_and_watermarks_obey_r_le_l() {
        let cat = |name: &str| ObservedCatRuntimeTelemetry {
            cat_id: id(name),
            observed_placement: PlacementIdentity {
                node_id: id("node_a"),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            observed_command_journal: None,
            observed_physical_state: ObservedRuntimePhysicalState::Absent,
            observed_runtime_incarnation: None,
            observed_artifact_manifest_digest: digest(1),
            observed_artifact_classifications: Vec::new(),
            observed_volumes: Vec::new(),
            observed_conditions: Vec::new(),
        };
        let mut report = full_report();
        let RuntimeInventoryBody::Full { cats, .. } = &mut report.inventory else {
            unreachable!()
        };
        cats.extend([cat("cat_b"), cat("cat_a")]);
        assert_eq!(
            full_inventory_digest(&report),
            Err(RuntimeInventoryContractError::InvalidContract)
        );

        let volume = ObservedVolumeWatermarkSummary {
            volume_id: id("volume_a"),
            disk_id: id("disk_a"),
            disk_role: DiskRole::Root,
            observed_attachment: ObservedVolumeAttachment::Unowned {
                attachment_epoch: FenceEpoch::new(1).unwrap(),
            },
            observed_watermark: ObservedVolumeWatermark::Known {
                local_durable_generation: Generation::new(1).unwrap(),
                remote_durable_generation: Generation::new(2).unwrap(),
            },
        };
        let mut report = full_report();
        let RuntimeInventoryBody::Full { cats, .. } = &mut report.inventory else {
            unreachable!()
        };
        let mut one = cat("cat_a");
        one.observed_volumes.push(volume);
        cats.push(one);
        assert_eq!(
            full_inventory_digest(&report),
            Err(RuntimeInventoryContractError::InvalidContract)
        );

        let mut report = full_report();
        let RuntimeInventoryBody::Full { cats, .. } = &mut report.inventory else {
            unreachable!()
        };
        let mut wrong_node = cat("cat_a");
        wrong_node.observed_placement.node_id = id("node_b");
        cats.push(wrong_node);
        assert_eq!(
            full_inventory_digest(&report),
            Err(RuntimeInventoryContractError::InvalidContract)
        );
    }

    #[test]
    fn unknown_and_trailing_fields_are_rejected() {
        let bytes = br#"{"version":1,"session":{},"report_id":"00000000000000000000000000000000","sequence":1,"collected_at_unix_ms":1,"inventory":{"kind":"partial","inventory_epoch":1,"cats":[]},"legacy_desired_revision":1}"#;
        assert_eq!(
            decode_runtime_inventory_report(bytes),
            Err(RuntimeInventoryContractError::Malformed)
        );
        let mut encoded = encode_runtime_inventory_report(&full_report()).unwrap();
        encoded.extend_from_slice(b" {}");
        assert_eq!(
            decode_runtime_inventory_report(&encoded),
            Err(RuntimeInventoryContractError::Malformed)
        );
    }

    #[test]
    fn gc_candidate_wire_requires_distinct_ownership_and_postcondition_digests() {
        let artifact = ObservedArtifactClassification::CatOwnedGcCandidate {
            artifact_id: id("owned_leaf"),
            ownership_digest: digest(11),
            postcondition_digest: digest(12),
        };
        let mut report = RuntimeInventoryReport {
            version: ContractVersion::V1,
            session: session(),
            report_id: random(13),
            sequence: Sequence::new(14).unwrap(),
            collected_at_unix_ms: UnixMillis::new(15).unwrap(),
            inventory: RuntimeInventoryBody::Partial {
                inventory_epoch: Epoch::new(16).unwrap(),
                cats: vec![ObservedCatRuntimeTelemetry {
                    cat_id: id("cat_a"),
                    observed_placement: PlacementIdentity {
                        node_id: id("node_a"),
                        placement_epoch: Epoch::new(17).unwrap(),
                    },
                    observed_command_journal: None,
                    observed_physical_state: ObservedRuntimePhysicalState::Absent,
                    observed_runtime_incarnation: None,
                    observed_artifact_manifest_digest: digest(18),
                    observed_artifact_classifications: vec![artifact],
                    observed_volumes: Vec::new(),
                    observed_conditions: Vec::new(),
                }],
            },
        };
        let encoded = encode_runtime_inventory_report(&report).unwrap();
        let encoded_text = std::str::from_utf8(&encoded).unwrap();
        assert!(encoded_text.contains("\"ownership_digest\""));
        assert!(encoded_text.contains("\"postcondition_digest\""));
        assert!(!encoded_text.contains("\"evidence_digest\""));
        assert_eq!(decode_runtime_inventory_report(&encoded).unwrap(), report);

        let value = serde_json::to_value(&report).unwrap();
        let mut legacy = value;
        let artifact = legacy
            .pointer_mut("/inventory/cats/0/observed_artifact_classifications/0")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        artifact.remove("ownership_digest");
        artifact.remove("postcondition_digest");
        artifact.insert(
            "evidence_digest".into(),
            serde_json::Value::String(digest(11).as_str().to_owned()),
        );
        let legacy = serde_json::to_vec(&legacy).unwrap();
        assert_eq!(
            decode_runtime_inventory_report(&legacy),
            Err(RuntimeInventoryContractError::Malformed)
        );

        let RuntimeInventoryBody::Partial { cats, .. } = &mut report.inventory else {
            unreachable!()
        };
        let ObservedArtifactClassification::CatOwnedGcCandidate {
            postcondition_digest,
            ..
        } = &mut cats[0].observed_artifact_classifications[0]
        else {
            unreachable!()
        };
        *postcondition_digest = digest(19);
        assert_ne!(
            encode_runtime_inventory_report(&report).unwrap(),
            encoded,
            "the postcondition digest is part of the canonical observation"
        );
    }
}

//! Closed, observation-only fleet facts used by the production cutover verifier.
//!
//! The Control response intentionally contains no `ready` bit. The operator
//! client owns the expected Node set and public key-ring artifact and derives
//! success from the exact facts in one PostgreSQL read snapshot.

use serde::{Deserialize, Serialize};

use crate::runtime_reconciliation::{
    key_ring_digest, AdmissionInventoryAttestation, AgentSession, ContractVersion, Epoch, Id,
    KeyId, RandomId128, Sequence, SessionBinding, Sha256Digest, UnixMillis, WireU64,
};

pub const FLEET_VERIFICATION_PATH: &str = "/v1/admin/runtime/fleet-verification";
pub const FLEET_VERIFICATION_METHOD: &str = "GET";
pub const FLEET_VERIFICATION_MAX_NODES: usize = 1_024;
pub const FLEET_VERIFICATION_MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
pub const FLEET_INVENTORY_MAX_AGE_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetRouteSigningAuthority {
    pub deployment_id: Id,
    pub signer_revision: Epoch,
    pub signer_reference_sha256: Sha256Digest,
    pub active_kid: Option<KeyId>,
    pub public_key_ring_version: Epoch,
    pub public_key_ring_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetVerificationInventory {
    pub source_session: SessionBinding,
    pub attestation: AdmissionInventoryAttestation,
    pub source_observation_id: RandomId128,
    pub source_heartbeat_sequence: Sequence,
    pub source_observed_at_unix_ms: UnixMillis,
    pub complete_inventory: bool,
    pub assigned_desired_count: WireU64,
    pub runtime_count: WireU64,
    pub residue_count: WireU64,
    pub lifecycle_open_count: WireU64,
    pub route_active_count: WireU64,
    pub route_closed_count: WireU64,
    pub active_guard_count: WireU64,
    pub cancellation_pending_count: WireU64,
    pub quarantined_condition_count: WireU64,
    pub key_ring_version: Option<Epoch>,
    pub key_ring_digest: Option<Sha256Digest>,
    pub loaded_kids: Vec<KeyId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetVerificationNode {
    pub node_id: Id,
    pub session: Option<AgentSession>,
    pub inventory: Option<FleetVerificationInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetVerificationSnapshot {
    pub version: ContractVersion,
    /// Qualified source commit embedded by the exact release build. An
    /// unqualified local/ad-hoc build reports `null`, which the CLI rejects.
    pub control_release_commit_sha: Option<String>,
    pub evaluated_at_unix_ms: UnixMillis,
    pub approved_guest_config_digest: Sha256Digest,
    pub desired_runtime_count: WireU64,
    pub current_runtime_observation_count: WireU64,
    pub route_signing_authority: Option<FleetRouteSigningAuthority>,
    pub nodes: Vec<FleetVerificationNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetExpectedKeyRing {
    pub ring_version: Epoch,
    pub key_ring_digest: Sha256Digest,
    pub kids: Vec<KeyId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetVerificationEvidence {
    pub version: ContractVersion,
    pub release_commit_sha: String,
    pub started_at_unix_ms: UnixMillis,
    pub deadline_unix_ms: UnixMillis,
    pub completed_at_unix_ms: UnixMillis,
    pub expected_nodes: Vec<Id>,
    pub expected_key_ring: FleetExpectedKeyRing,
    pub snapshot: FleetVerificationSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FleetVerificationContractError {
    #[error("fleet-verification body exceeds its wire-byte limit")]
    WireTooLarge,
    #[error("fleet-verification body is malformed")]
    Malformed,
    #[error("fleet-verification body is not canonical")]
    NonCanonical,
    #[error("fleet-verification body violates the closed contract")]
    Invalid,
}

pub fn encode_fleet_verification_snapshot(
    snapshot: &FleetVerificationSnapshot,
) -> Result<Vec<u8>, FleetVerificationContractError> {
    validate_snapshot(snapshot)?;
    encode_canonical(snapshot)
}

pub fn decode_fleet_verification_snapshot(
    body: &[u8],
) -> Result<FleetVerificationSnapshot, FleetVerificationContractError> {
    if body.len() > FLEET_VERIFICATION_MAX_WIRE_BYTES {
        return Err(FleetVerificationContractError::WireTooLarge);
    }
    let snapshot: FleetVerificationSnapshot = decode_one(body)?;
    validate_snapshot(&snapshot)?;
    if encode_fleet_verification_snapshot(&snapshot)?.as_slice() != body {
        return Err(FleetVerificationContractError::NonCanonical);
    }
    Ok(snapshot)
}

pub fn encode_fleet_verification_evidence(
    evidence: &FleetVerificationEvidence,
) -> Result<Vec<u8>, FleetVerificationContractError> {
    validate_evidence(evidence)?;
    encode_canonical(evidence)
}

fn decode_one<T>(body: &[u8]) -> Result<T, FleetVerificationContractError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value =
        T::deserialize(&mut decoder).map_err(|_| FleetVerificationContractError::Malformed)?;
    decoder
        .end()
        .map_err(|_| FleetVerificationContractError::Malformed)?;
    Ok(value)
}

fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, FleetVerificationContractError> {
    let value = serde_json::to_value(value).map_err(|_| FleetVerificationContractError::Invalid)?;
    let bytes = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    if bytes.len() > FLEET_VERIFICATION_MAX_WIRE_BYTES {
        return Err(FleetVerificationContractError::WireTooLarge);
    }
    Ok(bytes)
}

fn validate_snapshot(
    snapshot: &FleetVerificationSnapshot,
) -> Result<(), FleetVerificationContractError> {
    if snapshot.version != ContractVersion::V1
        || snapshot
            .control_release_commit_sha
            .as_ref()
            .is_some_and(|sha| {
                sha.len() != 40
                    || !sha
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        || snapshot.nodes.len() > FLEET_VERIFICATION_MAX_NODES
        || !strict_ids(snapshot.nodes.iter().map(|node| &node.node_id))
    {
        return Err(FleetVerificationContractError::Invalid);
    }
    for node in &snapshot.nodes {
        if node.session.as_ref().is_some_and(|session| {
            session.version != ContractVersion::V1 || session.node_id != node.node_id
        }) {
            return Err(FleetVerificationContractError::Invalid);
        }
        let Some(inventory) = &node.inventory else {
            continue;
        };
        if inventory.source_session.node_id != node.node_id
            || inventory.attestation.version != ContractVersion::V1
            || inventory.attestation.node_id != node.node_id
            || inventory.attestation.agent_session_epoch
                != inventory.source_session.agent_session_epoch
            || inventory.key_ring_version.is_some() != inventory.key_ring_digest.is_some()
            || !strict_ids(inventory.loaded_kids.iter())
        {
            return Err(FleetVerificationContractError::Invalid);
        }
    }
    Ok(())
}

fn validate_evidence(
    evidence: &FleetVerificationEvidence,
) -> Result<(), FleetVerificationContractError> {
    validate_snapshot(&evidence.snapshot)?;
    let valid_sha = evidence.release_commit_sha.len() == 40
        && evidence
            .release_commit_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if evidence.version != ContractVersion::V1
        || !valid_sha
        || evidence.expected_nodes.is_empty()
        || evidence.expected_nodes.len() > FLEET_VERIFICATION_MAX_NODES
        || !strict_ids(evidence.expected_nodes.iter())
        || evidence.expected_key_ring.kids.is_empty()
        || !strict_ids(evidence.expected_key_ring.kids.iter())
        || evidence.started_at_unix_ms > evidence.completed_at_unix_ms
        || evidence.completed_at_unix_ms > evidence.deadline_unix_ms
        || key_ring_digest(
            evidence.expected_key_ring.ring_version,
            &evidence.expected_key_ring.kids,
        )
        .ok()
        .as_ref()
            != Some(&evidence.expected_key_ring.key_ring_digest)
        || evidence.snapshot.control_release_commit_sha.as_deref()
            != Some(evidence.release_commit_sha.as_str())
        || evidence.snapshot.desired_runtime_count.get() != 0
        || evidence.snapshot.current_runtime_observation_count.get() != 0
        || evidence
            .snapshot
            .nodes
            .iter()
            .map(|node| &node.node_id)
            .ne(evidence.expected_nodes.iter())
    {
        return Err(FleetVerificationContractError::Invalid);
    }
    let Some(signer) = &evidence.snapshot.route_signing_authority else {
        return Err(FleetVerificationContractError::Invalid);
    };
    let Some(active_kid) = &signer.active_kid else {
        return Err(FleetVerificationContractError::Invalid);
    };
    if signer.public_key_ring_version != evidence.expected_key_ring.ring_version
        || signer.public_key_ring_digest != evidence.expected_key_ring.key_ring_digest
        || evidence
            .expected_key_ring
            .kids
            .binary_search(active_kid)
            .is_err()
        || evidence
            .snapshot
            .nodes
            .iter()
            .any(|node| !successful_node(node, &evidence.snapshot, &evidence.expected_key_ring))
    {
        return Err(FleetVerificationContractError::Invalid);
    }
    Ok(())
}

fn successful_node(
    node: &FleetVerificationNode,
    snapshot: &FleetVerificationSnapshot,
    expected_ring: &FleetExpectedKeyRing,
) -> bool {
    let Some(session) = &node.session else {
        return false;
    };
    let Some(inventory) = &node.inventory else {
        return false;
    };
    let Some(fresh_until) = inventory
        .attestation
        .accepted_at_unix_ms
        .get()
        .checked_add(FLEET_INVENTORY_MAX_AGE_MS)
    else {
        return false;
    };
    session.guest_config_digest == snapshot.approved_guest_config_digest
        && snapshot.evaluated_at_unix_ms < session.lease_deadline_unix_ms
        && inventory.source_session.node_id == session.node_id
        && inventory.source_session.node_boot_id == session.node_boot_id
        && inventory.source_session.agent_instance_id == session.agent_instance_id
        && inventory.source_session.agent_session_epoch == session.agent_session_epoch
        && inventory.attestation.accepted_at_unix_ms <= snapshot.evaluated_at_unix_ms
        && snapshot.evaluated_at_unix_ms.get() < fresh_until
        && inventory.complete_inventory
        && inventory.assigned_desired_count.get() == 0
        && inventory.runtime_count.get() == 0
        && inventory.residue_count.get() == 0
        && inventory.lifecycle_open_count.get() == 0
        && inventory.route_active_count.get() == 0
        && inventory.route_closed_count.get() == 0
        && inventory.active_guard_count.get() == 0
        && inventory.cancellation_pending_count.get() == 0
        && inventory.quarantined_condition_count.get() == 0
        && inventory.key_ring_version == Some(expected_ring.ring_version)
        && inventory.key_ring_digest.as_ref() == Some(&expected_ring.key_ring_digest)
        && inventory.loaded_kids == expected_ring.kids
}

fn strict_ids<'a, T, I>(values: I) -> bool
where
    T: Ord + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut previous: Option<&T> = None;
    for value in values {
        if previous.is_some_and(|previous| previous >= value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_decoder_rejects_noncanonical_and_duplicate_members() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let canonical = format!(
            "{{\"approved_guest_config_digest\":\"{digest}\",\"control_release_commit_sha\":null,\"current_runtime_observation_count\":0,\"desired_runtime_count\":0,\"evaluated_at_unix_ms\":1,\"nodes\":[],\"route_signing_authority\":null,\"version\":1}}"
        );
        let snapshot = decode_fleet_verification_snapshot(canonical.as_bytes()).unwrap();
        assert_eq!(
            encode_fleet_verification_snapshot(&snapshot).unwrap(),
            canonical.as_bytes()
        );
        assert!(decode_fleet_verification_snapshot(
            format!("{{ \"approved_guest_config_digest\":\"{digest}\",\"control_release_commit_sha\":null,\"current_runtime_observation_count\":0,\"desired_runtime_count\":0,\"evaluated_at_unix_ms\":1,\"nodes\":[],\"route_signing_authority\":null,\"version\":1}}").as_bytes()
        )
        .is_err());
        assert!(decode_fleet_verification_snapshot(
            format!("{{\"approved_guest_config_digest\":\"{digest}\",\"control_release_commit_sha\":null,\"current_runtime_observation_count\":0,\"desired_runtime_count\":0,\"evaluated_at_unix_ms\":1,\"nodes\":[],\"nodes\":[],\"route_signing_authority\":null,\"version\":1}}").as_bytes()
        )
        .is_err());
    }
}

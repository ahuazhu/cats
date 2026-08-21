//! Durable, terminal Host-fence facts accepted by the Control authority.
//!
//! Provider execution and network observations are deliberately insufficient.
//! A trusted event exists only after the provider-neutral Host-fence validator
//! has also closed the old object writer and proved its accepted PUT prefix
//! terminal and visible.  The event has no rejoin transition: it is an
//! immutable D2 fact used to authorize one exact recovery transaction.

use cats_api::runtime_reconciliation::{Id, Sha256Digest, UnixMillis};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::host_fence::{
    host_fence_request_from_provider_evidence, validate_host_fence_provider_evidence,
    HostFenceBinding, HostFenceEvidenceError, HostFenceProviderEvidence,
};

const TRUSTED_HOST_FENCE_EVENT_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence-event.v1";
const TRUSTED_HOST_FENCE_EVENT_ID_DOMAIN: &[u8] = b"cats.trusted-host-fence-event-id.v1";
const TRUSTED_HOST_FENCE_EVENT_ID_PREFIX: &str = "trusted_hfe_v1_";

/// The only Host-fence event accepted by the clean-slate recovery writer.
///
/// `provider_evidence` contains the complete compute, workload-network and
/// object-write cutoff result.  Its digest and the derived event ID make an
/// ambiguous PostgreSQL response discoverable without accepting a caller-
/// selected replay namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceEventV1 {
    pub event_id: Id,
    pub binding: HostFenceBinding,
    pub provider_evidence: HostFenceProviderEvidence,
    pub provider_evidence_sha256: Sha256Digest,
    pub committed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustedHostFenceEventError {
    #[error("Host-fence provider evidence is invalid")]
    ProviderEvidence(HostFenceEvidenceError),
    #[error("trusted Host-fence binding does not match provider evidence")]
    BindingMismatch,
    #[error("trusted Host-fence provider-evidence digest does not match")]
    DigestMismatch,
    #[error("trusted Host-fence event ID does not match its immutable evidence")]
    EventIdMismatch,
    #[error("trusted Host-fence commit predates completion of provider evidence")]
    CommitPredatesEvidence,
    #[error("trusted Host-fence JSON is malformed or non-canonical")]
    NonCanonicalJson,
}

impl From<HostFenceEvidenceError> for TrustedHostFenceEventError {
    fn from(error: HostFenceEvidenceError) -> Self {
        Self::ProviderEvidence(error)
    }
}

/// Canonical bytes used by both the durable row and exact replay comparison.
///
/// Every nested wire type is a closed struct/enum and contains no unordered
/// map.  Serde's declared field order is therefore the protocol's sole JSON
/// spelling, matching the repository's other strict re-encode codecs.
pub fn encode_trusted_host_fence_event_v1(
    event: &TrustedHostFenceEventV1,
) -> Result<Vec<u8>, TrustedHostFenceEventError> {
    serde_json::to_vec(event).map_err(|_| TrustedHostFenceEventError::NonCanonicalJson)
}

pub fn decode_trusted_host_fence_event_v1(
    bytes: &[u8],
) -> Result<TrustedHostFenceEventV1, TrustedHostFenceEventError> {
    let event: TrustedHostFenceEventV1 =
        serde_json::from_slice(bytes).map_err(|_| TrustedHostFenceEventError::NonCanonicalJson)?;
    if encode_trusted_host_fence_event_v1(&event)? != bytes {
        return Err(TrustedHostFenceEventError::NonCanonicalJson);
    }
    validate_trusted_host_fence_event_v1(&event)?;
    Ok(event)
}

/// Digest the exact canonical provider evidence in the frozen V1 domain.
pub fn trusted_host_fence_provider_evidence_sha256(
    evidence: &HostFenceProviderEvidence,
) -> Result<Sha256Digest, TrustedHostFenceEventError> {
    let canonical =
        serde_json::to_vec(evidence).map_err(|_| TrustedHostFenceEventError::NonCanonicalJson)?;
    Ok(domain_digest(
        TRUSTED_HOST_FENCE_EVENT_DIGEST_DOMAIN,
        &canonical,
    ))
}

#[derive(Serialize)]
struct TrustedHostFenceEventIdentity<'a> {
    binding: &'a HostFenceBinding,
    provider_evidence_sha256: &'a Sha256Digest,
}

/// Derive the replay key from the complete Host binding and evidence digest.
pub fn trusted_host_fence_event_id(
    binding: &HostFenceBinding,
    provider_evidence_sha256: &Sha256Digest,
) -> Result<Id, TrustedHostFenceEventError> {
    let canonical = serde_json::to_vec(&TrustedHostFenceEventIdentity {
        binding,
        provider_evidence_sha256,
    })
    .map_err(|_| TrustedHostFenceEventError::NonCanonicalJson)?;
    let digest = domain_digest(TRUSTED_HOST_FENCE_EVENT_ID_DOMAIN, &canonical);
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(TrustedHostFenceEventError::EventIdMismatch)?;
    Id::new(format!("{TRUSTED_HOST_FENCE_EVENT_ID_PREFIX}{hex}"))
        .ok_or(TrustedHostFenceEventError::EventIdMismatch)
}

/// Construct a terminal event only from already-complete provider evidence.
pub fn trusted_host_fence_event_v1(
    provider_evidence: HostFenceProviderEvidence,
    committed_at_unix_ms: UnixMillis,
) -> Result<TrustedHostFenceEventV1, TrustedHostFenceEventError> {
    let request = host_fence_request_from_provider_evidence(&provider_evidence)?;
    validate_host_fence_provider_evidence(&request, &provider_evidence)?;
    let binding = provider_evidence.binding.clone();
    let provider_evidence_sha256 = trusted_host_fence_provider_evidence_sha256(&provider_evidence)?;
    let event_id = trusted_host_fence_event_id(&binding, &provider_evidence_sha256)?;
    let event = TrustedHostFenceEventV1 {
        event_id,
        binding,
        provider_evidence,
        provider_evidence_sha256,
        committed_at_unix_ms,
    };
    validate_trusted_host_fence_event_v1(&event)?;
    Ok(event)
}

pub fn validate_trusted_host_fence_event_v1(
    event: &TrustedHostFenceEventV1,
) -> Result<(), TrustedHostFenceEventError> {
    let request = host_fence_request_from_provider_evidence(&event.provider_evidence)?;
    validate_host_fence_provider_evidence(&request, &event.provider_evidence)?;
    if event.binding != event.provider_evidence.binding || event.binding != request.binding {
        return Err(TrustedHostFenceEventError::BindingMismatch);
    }
    let digest = trusted_host_fence_provider_evidence_sha256(&event.provider_evidence)?;
    if event.provider_evidence_sha256 != digest {
        return Err(TrustedHostFenceEventError::DigestMismatch);
    }
    if event.event_id != trusted_host_fence_event_id(&event.binding, &digest)? {
        return Err(TrustedHostFenceEventError::EventIdMismatch);
    }
    if event.committed_at_unix_ms < event.provider_evidence.completed_at_unix_ms {
        return Err(TrustedHostFenceEventError::CommitPredatesEvidence);
    }
    Ok(())
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        AsciiText, Epoch, FenceEpoch, Generation, Id, NodeBootId, ProviderScope, RandomId128,
        RemoteHead, Sha256Digest, UnixMillis, VolumeDurability, WireU64,
    };

    use crate::authority::{
        consume_trusted_takeover_v1, normal_acquire, AuthorityError, AuthorizationRecord,
        AuthorizationState, NormalAcquireRequest, VolumeAdminState, VolumeAuthorization,
        VolumeRecord, VolumeTakeoverAuthorization,
    };
    use crate::host_fence::{
        host_fence_effect_token, host_fence_provider_attempt_id, HostExecutionCutoffEvidence,
        HostFenceBinding, HostFenceProviderEvidence, ObjectWriteCutoffEvidence,
        ObjectWriterFenceTarget, QuarantinedNetworkInterfaceEvidence,
        WorkloadNetworkCutoffEvidence, HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
    };

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn text(value: &str) -> AsciiText {
        AsciiText::new(value).unwrap()
    }

    fn time(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn scope() -> ProviderScope {
        ProviderScope {
            provider: id("provider"),
            partition: id("partition"),
            account_id: id("account"),
            region: id("region"),
        }
    }

    fn binding() -> HostFenceBinding {
        HostFenceBinding {
            provider_scope: scope(),
            immutable_host_id: id("host-old"),
            node_id: id("node-old"),
            expected_node_boot_id: NodeBootId::new("00000000000000000000000000000001").unwrap(),
            expected_agent_session_epoch: Epoch::new(7).unwrap(),
            fence_attempt_id: id("attempt-1"),
        }
    }

    fn framed(values: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend_from_slice(&u64::try_from(value.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }

    fn evidence() -> HostFenceProviderEvidence {
        let binding = binding();
        let object_writer = ObjectWriterFenceTarget {
            writer_authority_id: id("writer-1"),
            provider_scope: scope(),
            workload_principal_id: text("principal-1"),
            object_store_scope_id: text("bucket-scope-1"),
        };
        let object_target = framed(&[
            object_writer.writer_authority_id.as_str().as_bytes(),
            object_writer.provider_scope.provider.as_str().as_bytes(),
            object_writer.provider_scope.partition.as_str().as_bytes(),
            object_writer.provider_scope.account_id.as_str().as_bytes(),
            object_writer.provider_scope.region.as_str().as_bytes(),
            object_writer.workload_principal_id.as_str().as_bytes(),
            object_writer.object_store_scope_id.as_str().as_bytes(),
        ]);
        let host_target = binding.immutable_host_id.as_str().as_bytes();
        let boundary = text("quarantine-boundary-1");
        let interface_id = id("interface-1");
        HostFenceProviderEvidence {
            version: HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
            binding: binding.clone(),
            object_write_cutoff:
                ObjectWriteCutoffEvidence::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                    binding: binding.clone(),
                    object_writer,
                    effect_token: host_fence_effect_token(
                        &binding,
                        b"object-write-cutoff",
                        &object_target,
                    )
                    .unwrap(),
                    provider_attempt_id: host_fence_provider_attempt_id(
                        &binding,
                        b"object-write-cutoff",
                        &object_target,
                    )
                    .unwrap(),
                    cutoff_receipt_id: text("cutoff-receipt-1"),
                    cutoff_effective_at_unix_ms: time(10),
                    cutoff_sequence: WireU64::new(4).unwrap(),
                    accepted_put_terminal_receipt_id: text("terminal-receipt-1"),
                    accepted_puts_terminal_at_unix_ms: time(20),
                    terminal_sequence: WireU64::new(4).unwrap(),
                    terminal_prefix_sha256: Sha256Digest::from_bytes([4; 32]),
                    successful_put_visibility_receipt_id: text("visibility-receipt-1"),
                    successful_puts_visible_at_unix_ms: time(30),
                },
            execution_cutoff: HostExecutionCutoffEvidence::HostDestroyed {
                immutable_host_id: binding.immutable_host_id.clone(),
                effect_token: host_fence_effect_token(
                    &binding,
                    b"host-execution-cutoff",
                    host_target,
                )
                .unwrap(),
                provider_attempt_id: host_fence_provider_attempt_id(
                    &binding,
                    b"host-execution-cutoff",
                    host_target,
                )
                .unwrap(),
                authoritative_observation_id: text("execution-observation-1"),
                observed_at_unix_ms: time(40),
            },
            network_cutoff: WorkloadNetworkCutoffEvidence::WorkloadInterfacesQuarantined {
                immutable_host_id: binding.immutable_host_id.clone(),
                quarantine_policy_id: id(boundary.as_str()),
                boundary_effect_token: host_fence_effect_token(
                    &binding,
                    b"network-boundary-cutoff",
                    boundary.as_str().as_bytes(),
                )
                .unwrap(),
                boundary_provider_attempt_id: host_fence_provider_attempt_id(
                    &binding,
                    b"network-boundary-cutoff",
                    boundary.as_str().as_bytes(),
                )
                .unwrap(),
                policy_observation_id: text("policy-observation-1"),
                policy_observed_at_unix_ms: time(50),
                interfaces: vec![QuarantinedNetworkInterfaceEvidence {
                    interface_id: interface_id.clone(),
                    effect_token: host_fence_effect_token(
                        &binding,
                        b"network-interface-cutoff",
                        interface_id.as_str().as_bytes(),
                    )
                    .unwrap(),
                    provider_attempt_id: host_fence_provider_attempt_id(
                        &binding,
                        b"network-interface-cutoff",
                        interface_id.as_str().as_bytes(),
                    )
                    .unwrap(),
                }],
                authoritative_observation_id: text("network-observation-1"),
                observed_at_unix_ms: time(50),
            },
            completed_at_unix_ms: time(50),
        }
    }

    #[test]
    fn complete_provider_evidence_derives_one_canonical_terminal_event() {
        let first = trusted_host_fence_event_v1(evidence(), time(60)).unwrap();
        let second = trusted_host_fence_event_v1(evidence(), time(60)).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.provider_evidence_sha256.as_str(),
            "sha256:0c4328fe9129254193b4cf795c04d37b2547f4fa4fe23fb0da5ee2e61b9ae9a5"
        );
        assert_eq!(
            first.event_id.as_str(),
            "trusted_hfe_v1_2ee43235b93d15849a0f93fc114a5514b4375e2f472393be30682ec37aa6d1b2"
        );
        let bytes = encode_trusted_host_fence_event_v1(&first).unwrap();
        assert_eq!(decode_trusted_host_fence_event_v1(&bytes).unwrap(), first);
        let wire = std::str::from_utf8(&bytes).unwrap();
        assert!(!wire.contains("rejoined"));
        assert!(!wire.contains("\"state\""));
    }

    #[test]
    fn compute_and_network_evidence_cannot_hide_a_provisional_object_barrier() {
        let mut provisional = evidence();
        let ObjectWriteCutoffEvidence::PrincipalCutoffWithAcceptedPutTerminalBarrier {
            terminal_sequence,
            ..
        } = &mut provisional.object_write_cutoff;
        *terminal_sequence = WireU64::new(3).unwrap();
        assert!(matches!(
            trusted_host_fence_event_v1(provisional, time(60)),
            Err(TrustedHostFenceEventError::ProviderEvidence(
                HostFenceEvidenceError::ObjectWriteTimeOrder
            ))
        ));
    }

    #[test]
    fn strict_decode_rejects_noncanonical_or_extended_terminal_json() {
        let event = trusted_host_fence_event_v1(evidence(), time(60)).unwrap();
        let mut bytes = encode_trusted_host_fence_event_v1(&event).unwrap();
        bytes.push(b'\n');
        assert_eq!(
            decode_trusted_host_fence_event_v1(&bytes),
            Err(TrustedHostFenceEventError::NonCanonicalJson)
        );

        let mut value = serde_json::to_value(event).unwrap();
        value.as_object_mut().unwrap().insert(
            "state".to_owned(),
            serde_json::Value::String("rejoined".to_owned()),
        );
        assert_eq!(
            decode_trusted_host_fence_event_v1(&serde_json::to_vec(&value).unwrap()),
            Err(TrustedHostFenceEventError::NonCanonicalJson)
        );
    }

    #[test]
    fn terminal_event_consumes_only_the_exact_owner_epoch_and_head() {
        let event = trusted_host_fence_event_v1(evidence(), time(60)).unwrap();
        let initial_head = RemoteHead {
            generation: Generation::new(4).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([4; 32])),
            root_object_id: Some(text("roots/4")),
        };
        let unowned = VolumeRecord {
            volume_id: id("volume-1"),
            size_bytes: 4 * 1024 * 1024,
            durability: VolumeDurability::Strict,
            admin_state: VolumeAdminState::Active,
            head: initial_head.clone(),
            lease_owner: None,
            lease_epoch: FenceEpoch::new(7).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        let acquire = NormalAcquireRequest {
            volume_id: unowned.volume_id.clone(),
            transition_id: RandomId128::new("00000000000000000000000000000001").unwrap(),
            attachment_id: id("attachment-old"),
            expected_unowned_epoch: unowned.lease_epoch,
            placement_epoch: Epoch::new(3).unwrap(),
            lease_duration_ms: 5_000,
        };
        let owned = normal_acquire(&unowned, &acquire, time(10)).unwrap().0;
        let authorization_id = id("takeover-auth-1");
        let authorization = AuthorizationRecord {
            authorization: VolumeAuthorization::Takeover(VolumeTakeoverAuthorization {
                authorization_id: authorization_id.clone(),
                operation_id: id("operation-takeover-1"),
                request_fingerprint: Sha256Digest::from_bytes([12; 32]),
                authorized_node_id: id("node-new"),
                host_fence_event_id: event.event_id.clone(),
                interrupted_operation_id: id("operation-interrupted-1"),
                host_lost_result_digest: Sha256Digest::from_bytes([13; 32]),
                disk_id: id("disk-1"),
                volume_id: owned.volume_id.clone(),
                cat_id: id("cat-1"),
                expected_attachment_id: owned.lease_owner.clone().unwrap(),
                expected_epoch: owned.lease_epoch,
                expected_head: owned.head.clone(),
                new_attachment_id: id("attachment-new"),
                new_placement_epoch: Epoch::new(4).unwrap(),
                lease_duration_ms: 6_000,
                not_after: time(100),
            }),
            state: AuthorizationState::Unconsumed,
        };

        let mut wrong_head = authorization.clone();
        let VolumeAuthorization::Takeover(payload) = &mut wrong_head.authorization else {
            unreachable!()
        };
        payload.expected_head.generation = Generation::new(5).unwrap();
        assert_eq!(
            consume_trusted_takeover_v1(&owned, &event, &wrong_head, &authorization_id, time(70),),
            Err(AuthorityError::InvalidAuthorization)
        );
        assert_eq!(owned.head, initial_head);
        assert!(matches!(
            authorization.state,
            AuthorizationState::Unconsumed
        ));

        let (taken_over, consumed, first) = consume_trusted_takeover_v1(
            &owned,
            &event,
            &authorization,
            &authorization_id,
            time(70),
        )
        .unwrap();
        assert_eq!(taken_over.lease_owner, Some(id("attachment-new")));
        assert_eq!(taken_over.head, initial_head);
        assert_eq!(first.resulting_head, initial_head);

        let (unchanged, same_row, replay) = consume_trusted_takeover_v1(
            &taken_over,
            &event,
            &consumed,
            &authorization_id,
            time(101),
        )
        .unwrap();
        assert_eq!(unchanged, taken_over);
        assert_eq!(same_row, consumed);
        assert_eq!(replay, first);
    }
}

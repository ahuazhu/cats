//! Cross-crate fixture that opens exactly the Control state one Node needs
//! before it can register an object-write credential.
//!
//! `node-agent` is the only crate that can see the Node credential module, the
//! write adapter and the gateway at once, so the end-to-end object-write
//! acceptance test lives there. Every Store entry point that establishes the
//! preconditions — provisioner trust, `Provision`,
//! `ProvisionObjectWriteAuthority`, `register_agent_session`, the Volume row
//! and `acquire_volume_authority` — is `pub(crate)` or narrower, and the
//! Volume insert is `pub(in crate::store::runtime_authority)`. This module
//! therefore composes them here, inside that visibility, and
//! [`crate::testsupport`] exposes the two async wrappers the external test
//! calls.
//!
//! Nothing here is a second management API: it drives the same production
//! transactions an operator drives, in the same order, and asserts each one
//! settled as applied. It is compiled only under the `test-support` feature,
//! which release binaries never enable.

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, guest_config_digest, object_write_writer_authority_id,
    AgentRegistrationAttempt, AllocatableMemoryBytes, AllocatableVcpus, AsciiText, ContractVersion,
    CredentialBinding, Epoch, FleetPolicyPrincipal, GuestIpv4Pool, GuestIpv4PoolKind, Id,
    Ipv4Address, NodeBootId, NodeIdentity, NodeIdentityState, NodePlacementPolicy,
    NodeTransportTarget, ProviderScope, RandomId128, RuntimeNodeAuthorityApply,
    RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome, RuntimeNodeAuthorityStoredOutcome,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeSchedulingState, SessionBinding,
    Sha256Digest,
};
use cats_storage::authority::{
    FenceEpoch, Generation, NormalAcquireRequest, RemoteHead, VolumeAdminState, VolumeDurability,
    VolumeRecord,
};

use super::placement_policy::RuntimeNodeAuthorityApplyStoreOutcome;
use super::rows::insert_volume;
use crate::store::agent_sessions::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy};
use crate::store::Store;

/// Everything the caller chooses about the Host, Volume and object-store
/// binding. The Node's A19 public key is an input because the Node mints that
/// keypair itself; the fixture only provisions the identity that trusts it.
#[derive(Debug, Clone)]
pub struct ObjectWriteNodeRequest {
    pub node_id: Id,
    pub immutable_host_id: Id,
    pub node_credential_id: Id,
    pub node_public_key_spki_sha256: Sha256Digest,
    pub host_provider_scope: ProviderScope,
    pub volume_id: Id,
    pub volume_size_bytes: u64,
    pub attachment_id: Id,
    pub object_provider_scope: ProviderScope,
    pub workload_principal_id: AsciiText,
    pub object_store_scope_id: AsciiText,
}

impl ObjectWriteNodeRequest {
    pub fn writer_authority_id(&self) -> Id {
        object_write_writer_authority_id(
            &self.node_id,
            &self.object_provider_scope,
            &self.workload_principal_id,
            &self.object_store_scope_id,
        )
    }

    fn node_credential(&self) -> AuthenticatedNodeCredential {
        AuthenticatedNodeCredential::new(
            self.node_credential_id.clone(),
            CredentialBinding::PublicKey {
                public_key_spki_sha256: self.node_public_key_spki_sha256.clone(),
            },
        )
    }

    fn identity(&self) -> NodeIdentity {
        NodeIdentity {
            version: ContractVersion::V1,
            node_id: self.node_id.clone(),
            provider_scope: self.host_provider_scope.clone(),
            immutable_host_id: self.immutable_host_id.clone(),
            credential_id: self.node_credential_id.clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: self.node_public_key_spki_sha256.clone(),
            },
            state_path_id: self.node_id.clone(),
            state: NodeIdentityState::Provisioned,
        }
    }

    fn policy(&self) -> NodePlacementPolicy {
        let release = crate::testsupport::test_guest_runtime_profile_receipt();
        NodePlacementPolicy {
            version: ContractVersion::V1,
            node_id: self.node_id.clone(),
            policy_revision: policy_revision(),
            scheduling_state: RuntimeSchedulingState::Cordoned,
            allocatable_vcpus: AllocatableVcpus::new(8).expect("positive fixture vCPUs"),
            allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30)
                .expect("positive fixture memory"),
            capabilities: RuntimePlacementCapabilities {
                vmm: RuntimePlacementVmm::CloudHypervisor,
                block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
                guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
                guest_transport: RuntimePlacementGuestTransport::Vsock,
                guest_agent_protocol_version: ContractVersion::V1,
                guest_config_digest: guest_config_digest(&release)
                    .expect("fixture Guest release digest"),
            },
            guest_ipv4_pool: GuestIpv4Pool {
                kind: GuestIpv4PoolKind::PrivateIpv4_16,
                network_address: Ipv4Address::new("10.240.0.0").expect("fixture Guest pool"),
                prefix_length: 16,
            },
            node_transport_target: NodeTransportTarget::new(format!(
                "https://{}.internal:7301",
                self.node_id.as_str().replace('_', "-")
            ))
            .expect("fixture Node transport target"),
        }
    }
}

/// The Control facts one Node needs to register an attachment key.
#[derive(Debug, Clone)]
pub struct ObjectWriteNodeFixture {
    pub session: SessionBinding,
    pub attachment_epoch: FenceEpoch,
    pub writer_authority_id: Id,
}

/// Revision one: the fixture provisions the Node once and never re-plans it.
fn policy_revision() -> Epoch {
    Epoch::new(1).expect("one is a valid Epoch")
}

fn provisioner_principal() -> FleetPolicyPrincipal {
    let bundle = crate::testsupport::test_runtime_provisioner_trust_bundle();
    let credential = bundle
        .credentials
        .first()
        .expect("the fixture trust bundle holds one credential")
        .clone();
    let public_key_spki_sha256 = canonical_ed25519_spki_sha256(&credential.public_key_spki)
        .expect("canonical fixture provisioner SPKI");
    FleetPolicyPrincipal::DeploymentProvisioner {
        deployment_id: bundle.deployment_id,
        credential_id: credential.credential_id,
        public_key_spki: credential.public_key_spki,
        public_key_spki_sha256,
    }
}

impl Store {
    /// Provision one Node identity, one current Agent session, one Active
    /// Volume and one Owned attachment epoch through the production
    /// transactions, and derive the writer authority ID that Node would use.
    ///
    /// The object-write authority itself is deliberately *not* opened here:
    /// [`Self::provision_object_write_authority`] is a separate call so a
    /// caller can measure the gateway's refusal while every other
    /// precondition already holds.
    pub(crate) fn provision_object_write_node(
        &self,
        request: &ObjectWriteNodeRequest,
    ) -> ObjectWriteNodeFixture {
        let release = crate::testsupport::test_guest_runtime_profile_receipt();
        self.install_runtime_provisioner_trust_bundle(
            &crate::testsupport::test_runtime_provisioner_trust_bundle(),
        )
        .expect("install fixture provisioner trust");

        let provision = RuntimeNodeAuthorityApply {
            version: ContractVersion::V1,
            apply_id: fixture_apply_id(request, 1),
            node_id: request.node_id.clone(),
            mutation: RuntimeNodeAuthorityMutation::Provision {
                node_identity: Box::new(request.identity()),
                placement_policy: Box::new(request.policy()),
            },
        };
        assert_eq!(
            applied(self.apply_runtime_node_authority(&provisioner_principal(), &provision)),
            (RuntimeNodeAuthorityOutcome::Provisioned, None),
            "fixture Node must provision"
        );

        let node_boot_id = NodeBootId::new(fixture_hex(request, 2)).expect("fixture boot ID");
        let agent_instance_id =
            RandomId128::new(fixture_hex(request, 3)).expect("fixture agent instance ID");
        let attempt = AgentRegistrationAttempt {
            version: ContractVersion::V1,
            node_id: request.node_id.clone(),
            immutable_host_id: request.immutable_host_id.clone(),
            node_boot_id,
            agent_instance_id,
            registration_attempt_id: RandomId128::new(fixture_hex(request, 4))
                .expect("fixture registration attempt ID"),
            guest_config_digest: guest_config_digest(&release)
                .expect("fixture Guest release digest"),
            expected_agent_session_epoch: None,
        };
        let policy = AgentSessionRegistrationPolicy::from_release_receipt(&release)
            .expect("fixture registration policy");
        let session = match self
            .register_agent_session(&request.node_credential(), &attempt, &policy)
            .expect("register fixture Agent session")
        {
            AgentRegistrationOutcome::Registered(session) => session,
            AgentRegistrationOutcome::Rejected(rejection) => {
                panic!("fixture AgentSession was rejected: {rejection:?}")
            }
        };

        let volume = VolumeRecord {
            volume_id: request.volume_id.clone(),
            size_bytes: request.volume_size_bytes,
            durability: VolumeDurability::Strict,
            admin_state: VolumeAdminState::Active,
            head: RemoteHead {
                generation: Generation::new(0).expect("zero generation"),
                root_hash: None,
                root_object_id: None,
            },
            lease_owner: None,
            lease_epoch: FenceEpoch::new(0).expect("unowned fence epoch"),
            lease_expires_at: None,
            last_transition: None,
        };
        self.authority_transaction(|transaction| insert_volume(transaction, &volume))
            .expect("insert fixture Volume");

        let acquired = self
            .acquire_volume_authority(
                &request.node_id,
                &NormalAcquireRequest {
                    volume_id: request.volume_id.clone(),
                    transition_id: RandomId128::new(fixture_hex(request, 5))
                        .expect("fixture transition ID"),
                    attachment_id: request.attachment_id.clone(),
                    expected_unowned_epoch: FenceEpoch::new(0).expect("unowned fence epoch"),
                    placement_epoch: policy_revision(),
                    // Registration requires an unexpired lease. Ten minutes
                    // outlives the whole acceptance run without becoming a
                    // timing assertion.
                    lease_duration_ms: 600_000,
                },
            )
            .expect("acquire fixture Volume authority");

        ObjectWriteNodeFixture {
            session: SessionBinding {
                node_id: session.node_id.clone(),
                node_boot_id: session.node_boot_id.clone(),
                agent_instance_id: session.agent_instance_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
            },
            attachment_epoch: acquired.resulting_epoch,
            writer_authority_id: request.writer_authority_id(),
        }
    }

    /// Open exactly one object-write writer authority for the fixture Host
    /// through `ProvisionObjectWriteAuthority`, and return its derived ID.
    pub(crate) fn provision_object_write_authority(&self, request: &ObjectWriteNodeRequest) -> Id {
        let apply = RuntimeNodeAuthorityApply {
            version: ContractVersion::V1,
            apply_id: fixture_apply_id(request, 6),
            node_id: request.node_id.clone(),
            mutation: RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
                expected_policy_revision: policy_revision(),
                object_provider_scope: request.object_provider_scope.clone(),
                workload_principal_id: request.workload_principal_id.clone(),
                object_store_scope_id: request.object_store_scope_id.clone(),
            },
        };
        let expected = request.writer_authority_id();
        assert_eq!(
            applied(self.apply_runtime_node_authority(&provisioner_principal(), &apply)),
            (
                RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned,
                Some(expected.clone())
            ),
            "fixture writer authority must be provisioned"
        );
        expected
    }
}

fn applied(
    outcome: crate::store::Result<RuntimeNodeAuthorityApplyStoreOutcome>,
) -> (RuntimeNodeAuthorityOutcome, Option<Id>) {
    match outcome.expect("fixture authority apply reached the Store") {
        RuntimeNodeAuthorityApplyStoreOutcome::Stored(
            RuntimeNodeAuthorityStoredOutcome::Applied { response },
        ) => (response.outcome, response.writer_authority_id),
        other => panic!("fixture authority apply did not settle as applied: {other:?}"),
    }
}

/// Deterministic per-fixture identifiers: the disposable schema is fresh for
/// every run, so a digest of the request plus a step index is stable across a
/// replay and distinct across steps.
fn fixture_hex(request: &ObjectWriteNodeRequest, step: u8) -> String {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(request.node_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(request.volume_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(request.attachment_id.as_str().as_bytes());
    hasher.update([0, step]);
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture_apply_id(request: &ObjectWriteNodeRequest, step: u8) -> RandomId128 {
    RandomId128::new(fixture_hex(request, step)).expect("fixture apply ID")
}

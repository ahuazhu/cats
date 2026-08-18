//! Real PostgreSQL acceptance tests for operator-provisioned object-write
//! writer authority.
//!
//! Before this path existed no production code created an
//! `object_write_authorities` row, so the ObjectWrite Gateway's registration
//! routine always refused and no attachment could publish. These tests own both
//! halves: the A23 apply that opens exactly one authority per Host, and the
//! gateway's own least-privilege routine accepting the row it writes.

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::object_write_gateway::{
    ObjectWriteCredentialReference, ObjectWriteCredentialRegistration,
    ObjectWriteCredentialRegistrationReceipt,
};
use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, guest_config_digest, object_write_writer_authority_id,
    AllocatableMemoryBytes, AllocatableVcpus, AsciiText, Base64UrlNoPad, ContractVersion,
    CredentialBinding, Epoch, FleetPolicyPrincipal, GuestIpv4Pool, GuestIpv4PoolKind,
    GuestRuntimeProfileReceipt, Id, Ipv4Address, NodeBootId, NodeIdentity, NodeIdentityState,
    NodePlacementPolicy, NodeTransportTarget, ProviderScope, RandomId128,
    RuntimeNodeAuthorityApply, RuntimeNodeAuthorityMutation, RuntimeNodeAuthorityOutcome,
    RuntimeNodeAuthorityStoredOutcome, RuntimePlacementBlockFrontend, RuntimePlacementCapabilities,
    RuntimePlacementGuestNetwork, RuntimePlacementGuestTransport, RuntimePlacementVmm,
    RuntimeProvisionerCredential, RuntimeProvisionerTrustBundle, RuntimeSchedulingState,
    SessionBinding, Sha256Digest, WireU64,
};
use cats_storage::authority::{
    FenceEpoch, Generation, NormalAcquireRequest, RemoteHead, Revision, VolumeAdminState,
    VolumeDurability, VolumeRecord,
};
use cats_storage::object_write_authority::{
    empty_terminal_prefix_sha256, ObjectWriteAuthority, ObjectWriteAuthorityState,
    ObjectWriterIdentity,
};
use postgres::NoTls;

use super::placement_policy::RuntimeNodeAuthorityApplyStoreOutcome;
use super::rows::insert_volume;
use crate::store::agent_sessions::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy};
use crate::store::{Store, OBJECT_WRITE_GATEWAY_POSTGRES_ROLE};

const ROLE_INSTALLER: &str =
    include_str!("../../../../deploy/postgres/object-write-gateway-role-v1.sql");
const NODE_ID: &str = "node_owa";
const HOST_ID: &str = "host_owa";
const VOLUME_ID: &str = "volume_owa";
const ATTACHMENT_ID: &str = "attachment_owa";
const SPKI: &str = "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const WORKLOAD_PRINCIPAL: &str = "arn:test:iam::test_account:role/cats-object-write-gateway";
const OBJECT_STORE_SCOPE: &str = "arn:test:s3:::cats-test/chunks";

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn text(value: &str) -> AsciiText {
    AsciiText::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn host_scope() -> ProviderScope {
    ProviderScope {
        provider: id("test_provider"),
        partition: id("test_partition"),
        account_id: id("test_account"),
        region: id("test_region"),
    }
}

fn object_scope() -> ProviderScope {
    ProviderScope {
        provider: id("test_object_provider"),
        partition: id("test_object_partition"),
        account_id: id("test_object_account"),
        region: id("test_object_region"),
    }
}

fn guest_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: digest(1),
        initramfs_digest: Some(digest(2)),
        kernel_cmdline: text("console=hvc0 root=/dev/vda"),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn identity() -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(NODE_ID),
        provider_scope: host_scope(),
        immutable_host_id: id(HOST_ID),
        credential_id: id("credential_owa"),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: digest(6),
        },
        state_path_id: id("state_path_owa"),
        state: NodeIdentityState::Provisioned,
    }
}

fn policy() -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: id(NODE_ID),
        policy_revision: Epoch::new(1).unwrap(),
        scheduling_state: RuntimeSchedulingState::Cordoned,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: guest_config_digest(&guest_release()).unwrap(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://node-owa.internal:7301").unwrap(),
    }
}

fn provisioner() -> RuntimeProvisionerCredential {
    RuntimeProvisionerCredential {
        credential_id: id("provisioner_owa"),
        public_key_spki: Base64UrlNoPad::new(SPKI).unwrap(),
    }
}

fn principal() -> FleetPolicyPrincipal {
    let credential = provisioner();
    FleetPolicyPrincipal::DeploymentProvisioner {
        deployment_id: id("deployment_owa"),
        credential_id: credential.credential_id.clone(),
        public_key_spki: credential.public_key_spki.clone(),
        public_key_spki_sha256: canonical_ed25519_spki_sha256(&credential.public_key_spki).unwrap(),
    }
}

fn trust_bundle() -> RuntimeProvisionerTrustBundle {
    RuntimeProvisionerTrustBundle {
        version: ContractVersion::V1,
        deployment_id: id("deployment_owa"),
        trust_revision: Epoch::new(1).unwrap(),
        expected_previous: None,
        credentials: vec![provisioner()],
    }
}

/// One Node provisioned by the same signed authority path an operator uses.
fn provisioned_store(url: &str) -> Store {
    let store = Store::connect(url, None).unwrap();
    store
        .install_runtime_provisioner_trust_bundle(&trust_bundle())
        .unwrap();
    let provision = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(1),
        node_id: id(NODE_ID),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(identity()),
            placement_policy: Box::new(policy()),
        },
    };
    assert_eq!(
        applied(store.apply_runtime_node_authority(&principal(), &provision)),
        RuntimeNodeAuthorityOutcome::Provisioned
    );
    store
}

fn writer_apply(
    apply_id: u128,
    scope: ProviderScope,
    object_store_scope_id: &str,
) -> RuntimeNodeAuthorityApply {
    RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(apply_id),
        node_id: id(NODE_ID),
        mutation: RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
            expected_policy_revision: Epoch::new(1).unwrap(),
            object_provider_scope: scope,
            workload_principal_id: text(WORKLOAD_PRINCIPAL),
            object_store_scope_id: text(object_store_scope_id),
        },
    }
}

fn assigned_id(apply: &RuntimeNodeAuthorityApply) -> Id {
    let RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
        object_provider_scope,
        workload_principal_id,
        object_store_scope_id,
        ..
    } = &apply.mutation
    else {
        panic!("fixture is a writer authority apply")
    };
    object_write_writer_authority_id(
        &apply.node_id,
        object_provider_scope,
        workload_principal_id,
        object_store_scope_id,
    )
}

fn stored(
    outcome: crate::store::Result<RuntimeNodeAuthorityApplyStoreOutcome>,
) -> RuntimeNodeAuthorityStoredOutcome {
    match outcome.unwrap() {
        RuntimeNodeAuthorityApplyStoreOutcome::Stored(stored) => stored,
        other => panic!("expected a stored outcome, got {other:?}"),
    }
}

fn applied(
    outcome: crate::store::Result<RuntimeNodeAuthorityApplyStoreOutcome>,
) -> RuntimeNodeAuthorityOutcome {
    match stored(outcome) {
        RuntimeNodeAuthorityStoredOutcome::Applied { response } => response.outcome,
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed => {
            panic!("expected an applied outcome")
        }
    }
}

fn applied_writer(
    outcome: crate::store::Result<RuntimeNodeAuthorityApplyStoreOutcome>,
) -> Option<Id> {
    match stored(outcome) {
        RuntimeNodeAuthorityStoredOutcome::Applied { response } => {
            assert_eq!(
                response.outcome,
                RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned
            );
            response.writer_authority_id
        }
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed => {
            panic!("expected an applied outcome")
        }
    }
}

/// Every persisted authority row for the fixture Host, as
/// `(writer_authority_id, state, object_store_scope_id, record digest)`.
fn authority_rows(store: &Store) -> Vec<(String, String, String, String)> {
    store
        .with(|client| {
            Ok(client
                .query(
                    "SELECT writer_authority_id, state, object_store_scope_id,
                            md5(record::TEXT) AS record_digest
                       FROM object_write_authorities
                      WHERE immutable_host_id=$1
                      ORDER BY writer_authority_id COLLATE \"C\"",
                    &[&HOST_ID],
                )?
                .iter()
                .map(|row| {
                    (
                        row.get("writer_authority_id"),
                        row.get("state"),
                        row.get("object_store_scope_id"),
                        row.get("record_digest"),
                    )
                })
                .collect())
        })
        .unwrap()
}

#[test]
fn one_apply_opens_exactly_one_empty_open_authority_bound_to_the_host() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = provisioned_store(&url);
    let apply = writer_apply(2, object_scope(), OBJECT_STORE_SCOPE);

    assert_eq!(
        applied_writer(store.apply_runtime_node_authority(&principal(), &apply)),
        Some(assigned_id(&apply))
    );

    let row = store
        .with(|client| {
            client.query_one(
                "SELECT writer_authority_id, host_provider, host_partition,
                        host_account_id, host_region, immutable_host_id, node_id,
                        object_provider, object_partition, object_account_id,
                        object_region, workload_principal_id,
                        object_store_scope_id, state, max_accepted_sequence,
                        terminal_prefix_sequence, terminal_prefix_sha256,
                        fence_attempt_id, cutoff_receipt::TEXT AS cutoff_receipt_json,
                        record #>> '{writer,authority_id}' AS record_authority_id,
                        record #>> '{writer,immutable_host_id}' AS record_host_id,
                        record #>> '{state,kind}' AS record_state
                   FROM object_write_authorities",
                &[],
            )
        })
        .unwrap();
    let expected = identity();
    assert_eq!(
        row.get::<_, String>("writer_authority_id"),
        assigned_id(&apply).as_str()
    );
    // Every Host fact is derived from the provisioned identity, not the apply.
    assert_eq!(
        row.get::<_, String>("host_provider"),
        expected.provider_scope.provider.as_str()
    );
    assert_eq!(
        row.get::<_, String>("host_partition"),
        expected.provider_scope.partition.as_str()
    );
    assert_eq!(
        row.get::<_, String>("host_account_id"),
        expected.provider_scope.account_id.as_str()
    );
    assert_eq!(
        row.get::<_, String>("host_region"),
        expected.provider_scope.region.as_str()
    );
    assert_eq!(row.get::<_, String>("immutable_host_id"), HOST_ID);
    assert_eq!(row.get::<_, String>("node_id"), NODE_ID);
    assert_eq!(
        row.get::<_, String>("object_provider"),
        "test_object_provider"
    );
    assert_eq!(row.get::<_, String>("object_region"), "test_object_region");
    assert_eq!(
        row.get::<_, String>("workload_principal_id"),
        WORKLOAD_PRINCIPAL
    );
    assert_eq!(
        row.get::<_, String>("object_store_scope_id"),
        OBJECT_STORE_SCOPE
    );
    assert_eq!(row.get::<_, String>("state"), "open");
    assert_eq!(row.get::<_, i64>("max_accepted_sequence"), 0);
    assert_eq!(row.get::<_, i64>("terminal_prefix_sequence"), 0);
    assert_eq!(
        row.get::<_, String>("terminal_prefix_sha256"),
        cats_storage::object_write_authority::empty_terminal_prefix_sha256().as_str()
    );
    assert_eq!(row.get::<_, Option<String>>("fence_attempt_id"), None);
    assert_eq!(row.get::<_, Option<String>>("cutoff_receipt_json"), None);
    assert_eq!(
        row.get::<_, String>("record_authority_id"),
        assigned_id(&apply).as_str()
    );
    assert_eq!(row.get::<_, String>("record_host_id"), HOST_ID);
    assert_eq!(row.get::<_, String>("record_state"), "open");
}

#[test]
fn exact_replay_returns_the_same_authority_without_writing_a_second_row() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = provisioned_store(&url);
    let apply = writer_apply(2, object_scope(), OBJECT_STORE_SCOPE);

    let first = stored(store.apply_runtime_node_authority(&principal(), &apply));
    let rows_after_first = authority_rows(&store);
    let replay = stored(store.apply_runtime_node_authority(&principal(), &apply));

    assert_eq!(first, replay);
    assert_eq!(authority_rows(&store), rows_after_first);
    assert_eq!(rows_after_first.len(), 1);

    // A fresh apply ID carrying the same binding is not a replay: the Host
    // already holds its one authority, so it settles as a refusal.
    let repeat = writer_apply(3, object_scope(), OBJECT_STORE_SCOPE);
    assert_eq!(
        stored(store.apply_runtime_node_authority(&principal(), &repeat)),
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
    );
    assert_eq!(authority_rows(&store), rows_after_first);
}

#[test]
fn a_changed_binding_is_refused_and_never_rewrites_the_current_authority() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = provisioned_store(&url);
    let first = writer_apply(2, object_scope(), OBJECT_STORE_SCOPE);
    assert_eq!(
        applied_writer(store.apply_runtime_node_authority(&principal(), &first)),
        Some(assigned_id(&first))
    );
    let installed = authority_rows(&store);

    let changed_scope = writer_apply(3, object_scope(), "arn:test:s3:::cats-other/chunks");
    let mut other_region = object_scope();
    other_region.region = id("test_other_region");
    let changed_region = writer_apply(4, other_region, OBJECT_STORE_SCOPE);
    let mut changed_principal = writer_apply(5, object_scope(), OBJECT_STORE_SCOPE);
    let RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
        workload_principal_id,
        ..
    } = &mut changed_principal.mutation
    else {
        panic!("fixture is a writer authority apply")
    };
    *workload_principal_id = text("arn:test:iam::test_account:role/other");

    for candidate in [&changed_scope, &changed_region, &changed_principal] {
        assert_ne!(assigned_id(candidate), assigned_id(&first));
        assert_eq!(
            stored(store.apply_runtime_node_authority(&principal(), candidate)),
            RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed,
            "a changed binding must be refused, not written"
        );
        assert_eq!(authority_rows(&store), installed);
    }
}

#[test]
fn a_cutoff_authority_is_never_reopened_by_a_later_apply() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = provisioned_store(&url);
    let opened = writer_apply(2, object_scope(), OBJECT_STORE_SCOPE);
    assert_eq!(
        applied_writer(store.apply_runtime_node_authority(&principal(), &opened)),
        Some(assigned_id(&opened))
    );

    for closed_state in ["cutoff_pending", "cutoff_complete"] {
        close_authority(&store, &assigned_id(&opened), closed_state);
        let closed_rows = authority_rows(&store);
        assert_eq!(closed_rows.len(), 1);
        assert_eq!(closed_rows[0].1, closed_state);

        // The exact same binding, and a different one, are both refused.
        for apply in [
            writer_apply(6, object_scope(), OBJECT_STORE_SCOPE),
            writer_apply(7, object_scope(), "arn:test:s3:::cats-other/chunks"),
        ] {
            assert_eq!(
                stored(store.apply_runtime_node_authority(&principal(), &apply)),
                RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
            );
            assert_eq!(authority_rows(&store), closed_rows);
        }
    }
}

#[test]
fn an_authority_id_already_held_elsewhere_fails_closed() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = provisioned_store(&url);
    let apply = writer_apply(2, object_scope(), OBJECT_STORE_SCOPE);
    // The catalog keeps one Host per Node ID, so a taken authority ID means the
    // stored lineage disagrees with the derivation. Refuse rather than trip the
    // primary key and report an internal failure.
    seed_foreign_authority(&store, &assigned_id(&apply));
    let seeded = authority_rows(&store);

    assert_eq!(
        stored(store.apply_runtime_node_authority(&principal(), &apply)),
        RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed
    );
    assert_eq!(authority_rows(&store), seeded);
}

/// Insert one open authority that already holds `writer_authority_id` while
/// naming a different Node and Host.
fn seed_foreign_authority(store: &Store, writer_authority_id: &Id) {
    let provision = RuntimeNodeAuthorityApply {
        version: ContractVersion::V1,
        apply_id: random(90),
        node_id: id("node_owa_other"),
        mutation: RuntimeNodeAuthorityMutation::Provision {
            node_identity: Box::new(NodeIdentity {
                node_id: id("node_owa_other"),
                immutable_host_id: id("host_owa_other"),
                credential_id: id("credential_owa_other"),
                credential_binding: CredentialBinding::PublicKey {
                    public_key_spki_sha256: digest(8),
                },
                state_path_id: id("state_path_owa_other"),
                ..identity()
            }),
            placement_policy: Box::new(NodePlacementPolicy {
                node_id: id("node_owa_other"),
                node_transport_target: NodeTransportTarget::new(
                    "https://node-owa-other.internal:7301",
                )
                .unwrap(),
                ..policy()
            }),
        },
    };
    assert_eq!(
        applied(store.apply_runtime_node_authority(&principal(), &provision)),
        RuntimeNodeAuthorityOutcome::Provisioned
    );
    let authority = ObjectWriteAuthority {
        writer: ObjectWriterIdentity {
            authority_id: writer_authority_id.clone(),
            host_provider_scope: host_scope(),
            immutable_host_id: id("host_owa_other"),
            node_id: id("node_owa_other"),
            object_provider_scope: object_scope(),
            workload_principal_id: text(WORKLOAD_PRINCIPAL),
            object_store_scope_id: text(OBJECT_STORE_SCOPE),
        },
        state: ObjectWriteAuthorityState::Open,
        max_accepted_sequence: WireU64::new(0).unwrap(),
        terminal_prefix_sequence: WireU64::new(0).unwrap(),
        terminal_prefix_sha256: empty_terminal_prefix_sha256(),
    };
    store
        .authority_transaction(|transaction| {
            super::object_write::insert_authority_for_test(transaction, &authority)
        })
        .unwrap();
}

/// Drive the fixture authority into a closed state directly. The cutoff
/// transition itself belongs to the Host-fence path; these tests only need a
/// persisted closed row that satisfies the table's state-shape constraint.
fn close_authority(store: &Store, writer_authority_id: &Id, state: &str) {
    let receipt = serde_json::json!({
        "writer_authority_id": writer_authority_id.as_str(),
        "fence_attempt_id": "fence_owa",
        "cutoff_receipt_id": "cutoff-receipt-owa",
        "cutoff_effective_at_unix_ms": 1_700_000_000_000_u64,
        "cutoff_sequence": 0,
        "accepted_put_terminal_receipt_id": "terminal-receipt-owa",
        "accepted_puts_terminal_at_unix_ms": 1_700_000_000_001_u64,
        "terminal_sequence": 0,
        "terminal_prefix_sha256":
            cats_storage::object_write_authority::empty_terminal_prefix_sha256().as_str(),
        "successful_put_visibility_receipt_id": "visible-receipt-owa",
        "successful_puts_visible_at_unix_ms": 1_700_000_000_002_u64,
    });
    let record_state = if state == "cutoff_pending" {
        serde_json::json!({
            "kind": "cutoff_pending",
            "fence_attempt_id": "fence_owa",
            "cutoff_sequence": 0,
            "cutoff_effective_at_unix_ms": 1_700_000_000_000_u64,
        })
    } else {
        serde_json::json!({"kind": "cutoff_complete", "receipt": receipt.clone()})
    };
    let record_state = serde_json::to_string(&record_state).unwrap();
    let receipt = serde_json::to_string(&receipt).unwrap();
    let cutoff_receipt = (state == "cutoff_complete").then_some(receipt);
    let changed = store
        .with(|client| {
            client.execute(
                "UPDATE object_write_authorities
                    SET state=$2,
                        record=jsonb_set(record, '{state}', $3::TEXT::jsonb, TRUE),
                        fence_attempt_id='fence_owa',
                        cutoff_effective_at_unix_ms=1700000000000,
                        cutoff_sequence=max_accepted_sequence,
                        cutoff_receipt=$4::TEXT::jsonb
                  WHERE writer_authority_id=$1",
                &[
                    &writer_authority_id.as_str(),
                    &state,
                    &record_state,
                    &cutoff_receipt,
                ],
            )
        })
        .unwrap();
    assert_eq!(changed, 1);
}

fn schema_of(dsn: &str) -> String {
    let marker = "search_path%3D";
    let start = dsn
        .find(marker)
        .expect("isolated DSN carries a search_path")
        + marker.len();
    let rest = &dsn[start..];
    let end = rest.find('%').unwrap_or(rest.len());
    rest[..end].to_owned()
}

fn base_of(dsn: &str) -> String {
    dsn.split_once('?')
        .map(|(base, _)| base.to_owned())
        .unwrap_or_else(|| dsn.to_owned())
}

/// Install the reviewed operator role script, minus its login password: these
/// tests reach the routine through `SET SESSION AUTHORIZATION` so concurrent
/// disposable schemas never fight over one cluster-wide password.
fn install_gateway_role(base: &str, schema: &str) {
    let mut admin = postgres::Client::connect(base, NoTls).expect("connect disposable PostgreSQL");
    let database: String = admin
        .query_one("SELECT current_database()::TEXT", &[])
        .expect("read current database")
        .get(0);
    let sql = ROLE_INSTALLER
        .replace("\\set ON_ERROR_STOP on", "")
        .replace(":\"control_database\"", &format!("\"{database}\""))
        .replace(":\"control_schema\"", &format!("\"{schema}\""));
    admin.batch_execute(&sql).expect("install gateway role");
}

/// Call the gateway's own registration routine as the gateway role.
fn gateway_register(
    base: &str,
    schema: &str,
    node: &AuthenticatedNodeCredential,
    registration: &ObjectWriteCredentialRegistration,
) -> Result<ObjectWriteCredentialRegistrationReceipt, postgres::Error> {
    let mut client = postgres::Client::connect(base, NoTls).expect("connect disposable PostgreSQL");
    client
        .batch_execute(&format!(
            "SET SESSION AUTHORIZATION {OBJECT_WRITE_GATEWAY_POSTGRES_ROLE}"
        ))
        .expect("assume the gateway login");
    let CredentialBinding::PublicKey {
        public_key_spki_sha256,
    } = node.binding()
    else {
        panic!("test Node credential is Ed25519")
    };
    let attachment = serde_json::to_string(&registration.credential).unwrap();
    let body = serde_json::to_string(registration).unwrap();
    let row = client.query_one(
        &format!(
            "SELECT \"{schema}\".control_object_write_gateway_register_v1(
                $1,$2,$3::TEXT::jsonb,$4::TEXT::jsonb)::TEXT"
        ),
        &[
            &node.credential_id().as_str(),
            &public_key_spki_sha256.as_str(),
            &attachment,
            &body,
        ],
    )?;
    Ok(serde_json::from_str(&row.get::<_, String>(0)).expect("canonical registration receipt"))
}

#[test]
fn gateway_registration_succeeds_only_once_the_writer_authority_exists() {
    let url = crate::testsupport::isolated_control_store_url();
    let schema = schema_of(&url);
    let base = base_of(&url);
    let store = provisioned_store(&url);

    // One current AgentSession and one currently owned Volume: every other
    // registration precondition is satisfied before the authority is opened.
    let identity = identity();
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let session = match store
        .register_agent_session(
            &authenticated,
            &cats_api::runtime_reconciliation::AgentRegistrationAttempt {
                version: ContractVersion::V1,
                node_id: identity.node_id.clone(),
                immutable_host_id: identity.immutable_host_id.clone(),
                node_boot_id: NodeBootId::new(format!("{:032x}", 11)).unwrap(),
                agent_instance_id: random(12),
                registration_attempt_id: random(13),
                guest_config_digest: guest_config_digest(&guest_release()).unwrap(),
                expected_agent_session_epoch: None,
            },
            &AgentSessionRegistrationPolicy::from_release_receipt(&guest_release()).unwrap(),
        )
        .unwrap()
    {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("test AgentSession was rejected: {rejection:?}")
        }
    };
    store
        .authority_transaction(|transaction| {
            insert_volume(
                transaction,
                &VolumeRecord {
                    volume_id: id(VOLUME_ID),
                    size_bytes: 4 * 1024 * 1024,
                    durability: VolumeDurability::Strict,
                    admin_state: VolumeAdminState::Active,
                    head: RemoteHead {
                        generation: Generation::new(0).unwrap(),
                        root_hash: None,
                        root_object_id: None,
                    },
                    lease_owner: None,
                    lease_epoch: FenceEpoch::new(0).unwrap(),
                    lease_expires_at: None,
                    last_transition: None,
                },
            )
        })
        .unwrap();
    let acquired = store
        .acquire_volume_authority(
            &identity.node_id,
            &NormalAcquireRequest {
                volume_id: id(VOLUME_ID),
                transition_id: random(14),
                attachment_id: id(ATTACHMENT_ID),
                expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                desired_revision: Revision::new(1).unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
                lease_duration_ms: 600_000,
            },
        )
        .unwrap();

    install_gateway_role(&base, &schema);
    let apply = writer_apply(2, object_scope(), OBJECT_STORE_SCOPE);
    let registration = ObjectWriteCredentialRegistration {
        version: ContractVersion::V1,
        session: SessionBinding {
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
        },
        writer_authority_id: assigned_id(&apply),
        volume_id: id(VOLUME_ID),
        attachment_id: id(ATTACHMENT_ID),
        attachment_epoch: acquired.resulting_epoch,
        credential: ObjectWriteCredentialReference {
            credential_id: id("attachment_credential_owa"),
            public_key_spki_sha256: digest(9),
        },
        public_key_spki: Base64UrlNoPad::new(SPKI).unwrap(),
        private_artifact_id: id("attachment_artifact_owa"),
        private_file_fsync_receipt_id: text("file-fsync-owa"),
        private_directory_fsync_receipt_id: text("directory-fsync-owa"),
    };

    let refused = gateway_register(&base, &schema, &authenticated, &registration)
        .expect_err("registration must fail closed while no authority exists");
    let refused = refused
        .as_db_error()
        .expect("the routine refuses with a PostgreSQL error");
    assert_eq!(
        refused.message(),
        "object-write authority is missing, closed, or changed"
    );
    assert_eq!(
        refused.code(),
        &postgres::error::SqlState::from_code("55000")
    );

    assert_eq!(
        applied_writer(store.apply_runtime_node_authority(&principal(), &apply)),
        Some(assigned_id(&apply))
    );

    // Calibration: the identical registration now succeeds, so the negative
    // above measured the missing authority and nothing else.
    let receipt = gateway_register(&base, &schema, &authenticated, &registration)
        .expect("registration must succeed once the authority is open");
    assert_eq!(receipt.writer_authority_id, assigned_id(&apply));
    assert_eq!(receipt.volume_id, registration.volume_id);
    assert_eq!(receipt.attachment_epoch, registration.attachment_epoch);
    let bound: String = store
        .with(|client| {
            Ok(client
                .query_one(
                    "SELECT writer_authority_id FROM object_write_credentials
                      WHERE credential_id=$1",
                    &[&registration.credential.credential_id.as_str()],
                )?
                .get(0))
        })
        .unwrap();
    assert_eq!(bound, assigned_id(&apply).as_str());
}

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    AgentRegistrationAttempt, AgentSession, AsciiText, ContractVersion, CredentialBinding, Epoch,
    GuestRuntimeProfileReceipt, Id, NodeBootId, NodeIdentity, NodeIdentityState, ProviderScope,
    RandomId128, Sha256Digest, UnixMillis, WireU64,
};
use cats_storage::host_fence::{
    host_fence_effect_token, host_fence_provider_attempt_id, HostExecutionCutoffEvidence,
    HostFenceAttemptRequest, HostFenceBinding, HostFenceProviderEvidence, ObjectWriterFenceTarget,
    QuarantinedNetworkInterfaceEvidence, WorkloadNetworkCutoffEvidence,
    HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
};
use cats_storage::object_write_authority::{
    empty_terminal_prefix_sha256, ObjectWriteAuthority, ObjectWriteAuthorityState,
    ObjectWriteCutoffReceipt, ObjectWriterIdentity,
};

use crate::store::agent_sessions::{AgentRegistrationOutcome, AgentSessionRegistrationPolicy};
use crate::store::Store;

use super::host_fence_provider_queue::{cutoff_evidence, evidence_sha256};

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn text(value: impl Into<String>) -> AsciiText {
    AsciiText::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn boot(value: u128) -> NodeBootId {
    NodeBootId::new(format!("{value:032x}")).unwrap()
}

fn scope() -> ProviderScope {
    ProviderScope {
        provider: id("aws"),
        partition: id("aws"),
        account_id: id("123456789012"),
        region: id("us-east-1"),
    }
}

fn runtime_release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::from_bytes([1; 32]),
        initramfs_digest: Some(Sha256Digest::from_bytes([2; 32])),
        kernel_cmdline: text("console=hvc0 root=/dev/vda"),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn register_session(store: &Store, identity: &NodeIdentity) -> AgentSession {
    let authenticated = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    );
    let policy = AgentSessionRegistrationPolicy::from_release_receipt(&runtime_release()).unwrap();
    let attempt = AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: boot(1),
        agent_instance_id: random(2),
        registration_attempt_id: random(3),
        guest_config_digest: policy.approved_guest_config_digest().clone(),
        expected_agent_session_epoch: None,
    };
    match store
        .register_agent_session(&authenticated, &attempt, &policy)
        .unwrap()
    {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("test AgentSession was rejected: {rejection:?}")
        }
    }
}

struct QueueFixture {
    store: Store,
    url: String,
    request: HostFenceAttemptRequest,
}

fn fixture() -> QueueFixture {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let identity = NodeIdentity {
        version: ContractVersion::V1,
        node_id: id("node-provider-queue"),
        provider_scope: scope(),
        immutable_host_id: id("i-0123456789abcdef0"),
        credential_id: id("credential-provider-queue"),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::from_bytes([7; 32]),
        },
        state_path_id: id("state-path-provider-queue"),
        state: NodeIdentityState::Provisioned,
    };
    store.provision_node_identity(&identity).unwrap();
    let session = register_session(&store, &identity);
    let writer = ObjectWriterIdentity {
        authority_id: id("owa1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        host_provider_scope: scope(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_id: identity.node_id.clone(),
        object_provider_scope: scope(),
        workload_principal_id: text(
            "arn:aws:iam::123456789012:role/cats-production-object-write-gateway",
        ),
        object_store_scope_id: text("arn:aws:s3:::cats-production/chunks"),
    };
    let authority = ObjectWriteAuthority {
        writer: writer.clone(),
        state: ObjectWriteAuthorityState::Open,
        max_accepted_sequence: WireU64::new(0).unwrap(),
        terminal_prefix_sequence: WireU64::new(0).unwrap(),
        terminal_prefix_sha256: empty_terminal_prefix_sha256(),
    };
    let record = serde_json::to_string(&authority).unwrap();
    store
        .with(|client| {
            client.execute(
                "INSERT INTO object_write_authorities (
                    writer_authority_id, record, host_provider, host_partition,
                    host_account_id, host_region, immutable_host_id, node_id,
                    object_provider, object_partition, object_account_id,
                    object_region, workload_principal_id, object_store_scope_id,
                    state, max_accepted_sequence, terminal_prefix_sequence,
                    terminal_prefix_sha256
                 ) VALUES (
                    $1,$2::TEXT::jsonb,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                    $13,$14,'open',0,0,$15
                 )",
                &[
                    &writer.authority_id.as_str(),
                    &record,
                    &writer.host_provider_scope.provider.as_str(),
                    &writer.host_provider_scope.partition.as_str(),
                    &writer.host_provider_scope.account_id.as_str(),
                    &writer.host_provider_scope.region.as_str(),
                    &writer.immutable_host_id.as_str(),
                    &writer.node_id.as_str(),
                    &writer.object_provider_scope.provider.as_str(),
                    &writer.object_provider_scope.partition.as_str(),
                    &writer.object_provider_scope.account_id.as_str(),
                    &writer.object_provider_scope.region.as_str(),
                    &writer.workload_principal_id.as_str(),
                    &writer.object_store_scope_id.as_str(),
                    &authority.terminal_prefix_sha256.as_str(),
                ],
            )
        })
        .unwrap();
    let request = HostFenceAttemptRequest {
        binding: HostFenceBinding {
            provider_scope: scope(),
            immutable_host_id: identity.immutable_host_id,
            node_id: identity.node_id,
            expected_node_boot_id: session.node_boot_id,
            expected_agent_session_epoch: session.agent_session_epoch,
            fence_attempt_id: id("fence-provider-attempt-1"),
        },
        network_quarantine_boundary_id: text("sg-0123456789abcdef0"),
        object_writer: ObjectWriterFenceTarget {
            writer_authority_id: writer.authority_id,
            provider_scope: writer.object_provider_scope,
            workload_principal_id: writer.workload_principal_id,
            object_store_scope_id: writer.object_store_scope_id,
        },
    };
    QueueFixture {
        store,
        url,
        request,
    }
}

fn queue_and_authority_state(store: &Store) -> (i64, String) {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT (SELECT count(*) FROM host_fence_provider_queue_v1),
                            (SELECT state FROM object_write_authorities)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap()
}

fn provider_role_setup(store: &Store) -> String {
    store
        .with(|client| {
            let schema: String = client
                .query_one("SELECT current_schema()::TEXT", &[])?
                .get(0);
            let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
            client.query_one("SELECT pg_advisory_lock(81249, 2)", &[])?;
            let result = client.batch_execute(&format!(
                "DO $role$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_roles
                         WHERE rolname='cats_host_fence_provider'
                    ) THEN
                        CREATE ROLE cats_host_fence_provider
                            LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
                            NOREPLICATION NOBYPASSRLS;
                    END IF;
                 END $role$;
                 GRANT USAGE ON SCHEMA {quoted} TO cats_host_fence_provider;
                 REVOKE ALL ON ALL TABLES IN SCHEMA {quoted}
                    FROM cats_host_fence_provider;
                 GRANT EXECUTE ON FUNCTION
                    {quoted}.control_host_fence_provider_startup_v1()
                    TO cats_host_fence_provider;
                 GRANT EXECUTE ON FUNCTION
                    {quoted}.control_host_fence_provider_claim_v1(
                        TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT)
                    TO cats_host_fence_provider;
                 GRANT EXECUTE ON FUNCTION
                    {quoted}.control_host_fence_provider_renew_v1(
                        TEXT,TEXT,TEXT,BIGINT)
                    TO cats_host_fence_provider;
                 GRANT EXECUTE ON FUNCTION
                    {quoted}.control_host_fence_provider_object_cutoff_v1(TEXT,TEXT)
                    TO cats_host_fence_provider;
                 GRANT EXECUTE ON FUNCTION
                    {quoted}.control_host_fence_provider_complete_v1(
                        TEXT,TEXT,BYTEA,TEXT)
                    TO cats_host_fence_provider;
                 GRANT EXECUTE ON FUNCTION
                    {quoted}.control_host_fence_provider_read_v1(TEXT,TEXT)
                    TO cats_host_fence_provider;"
            ));
            let _ = client.query_one("SELECT pg_advisory_unlock(81249, 2)", &[])?;
            result.map(|_| schema)
        })
        .unwrap()
}

fn with_provider_session<T: Send>(
    store: &Store,
    operation: impl FnOnce(&mut postgres::Client, &str) -> T + Send,
) -> T {
    let schema = provider_role_setup(store);
    store
        .with(|client| {
            client.batch_execute("SET SESSION AUTHORIZATION cats_host_fence_provider")?;
            let value = operation(client, &schema);
            client.batch_execute("RESET SESSION AUTHORIZATION")?;
            Ok(value)
        })
        .unwrap()
}

pub(super) fn terminal_evidence(
    request: &HostFenceAttemptRequest,
    receipt: ObjectWriteCutoffReceipt,
) -> HostFenceProviderEvidence {
    let object_write_cutoff = cutoff_evidence(request, receipt.clone()).unwrap();
    let observed = UnixMillis::new(
        receipt
            .successful_puts_visible_at_unix_ms
            .get()
            .checked_add(1)
            .unwrap(),
    )
    .unwrap();
    let interface_id = id("eni-0123456789abcdef0");
    HostFenceProviderEvidence {
        version: HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
        binding: request.binding.clone(),
        object_write_cutoff,
        execution_cutoff: HostExecutionCutoffEvidence::HostStopped {
            immutable_host_id: request.binding.immutable_host_id.clone(),
            effect_token: host_fence_effect_token(
                &request.binding,
                b"host-execution-cutoff",
                request.binding.immutable_host_id.as_str().as_bytes(),
            )
            .unwrap(),
            provider_attempt_id: host_fence_provider_attempt_id(
                &request.binding,
                b"host-execution-cutoff",
                request.binding.immutable_host_id.as_str().as_bytes(),
            )
            .unwrap(),
            authoritative_observation_id: text("execution-observation-1"),
            observed_at_unix_ms: observed,
        },
        network_cutoff: WorkloadNetworkCutoffEvidence::WorkloadInterfacesQuarantined {
            immutable_host_id: request.binding.immutable_host_id.clone(),
            quarantine_policy_id: id(request.network_quarantine_boundary_id.as_str()),
            boundary_effect_token: host_fence_effect_token(
                &request.binding,
                b"network-boundary-cutoff",
                request.network_quarantine_boundary_id.as_str().as_bytes(),
            )
            .unwrap(),
            boundary_provider_attempt_id: host_fence_provider_attempt_id(
                &request.binding,
                b"network-boundary-cutoff",
                request.network_quarantine_boundary_id.as_str().as_bytes(),
            )
            .unwrap(),
            policy_observation_id: text("policy-observation-1"),
            policy_observed_at_unix_ms: observed,
            interfaces: vec![QuarantinedNetworkInterfaceEvidence {
                effect_token: host_fence_effect_token(
                    &request.binding,
                    b"network-interface-cutoff",
                    interface_id.as_str().as_bytes(),
                )
                .unwrap(),
                provider_attempt_id: host_fence_provider_attempt_id(
                    &request.binding,
                    b"network-interface-cutoff",
                    interface_id.as_str().as_bytes(),
                )
                .unwrap(),
                interface_id,
            }],
            authoritative_observation_id: text("network-observation-1"),
            observed_at_unix_ms: observed,
        },
        completed_at_unix_ms: observed,
    }
}

#[test]
fn enqueue_closes_the_exact_writer_and_exact_replay_is_zero_write() {
    let fixture = fixture();
    assert_eq!(
        fixture
            .store
            .get_host_fence_provider_attempt_v1(&fixture.request.binding)
            .unwrap(),
        None
    );
    let first = fixture
        .store
        .enqueue_host_fence_provider_attempt_for_test(&fixture.request)
        .unwrap();
    let replay = fixture
        .store
        .enqueue_host_fence_provider_attempt_for_test(&fixture.request)
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(
        fixture
            .store
            .get_host_fence_provider_attempt_v1(&fixture.request.binding)
            .unwrap(),
        Some(first)
    );
    let mut wrong_scope = fixture.request.binding.clone();
    wrong_scope.expected_node_boot_id = boot(99);
    assert_eq!(
        fixture
            .store
            .get_host_fence_provider_attempt_v1(&wrong_scope)
            .unwrap(),
        None
    );
    assert_eq!(
        queue_and_authority_state(&fixture.store),
        (1, "cutoff_pending".into())
    );

    let mut drift = fixture.request.clone();
    drift.network_quarantine_boundary_id = text("sg-0ffffffffffffffff");
    let error = fixture
        .store
        .enqueue_host_fence_provider_attempt_for_test(&drift)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(
        queue_and_authority_state(&fixture.store),
        (1, "cutoff_pending".into())
    );
}

#[test]
fn stale_source_session_is_zero_side_effect() {
    let fixture = fixture();
    let mut stale = fixture.request.clone();
    stale.binding.expected_agent_session_epoch =
        Epoch::new(stale.binding.expected_agent_session_epoch.get() + 1).unwrap();
    let error = fixture
        .store
        .enqueue_host_fence_provider_attempt_for_test(&stale)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(
        queue_and_authority_state(&fixture.store),
        (0, "open".into())
    );
}

#[test]
fn concurrent_exact_enqueue_rechecks_after_the_source_lock() {
    let fixture = fixture();
    let application_name = format!("c2_enqueue_{}", uuid::Uuid::new_v4().simple());
    let concurrent_url = format!("{}&application_name={application_name}", fixture.url);
    let first_store = Store::connect(&concurrent_url, None).unwrap();
    let second_store = Store::connect(&concurrent_url, None).unwrap();
    let mut source_lock = postgres::Client::connect(&fixture.url, postgres::NoTls).unwrap();
    source_lock.batch_execute("BEGIN").unwrap();
    source_lock
        .query_one(
            "SELECT node_id FROM node_identities WHERE node_id=$1 FOR UPDATE",
            &[&fixture.request.binding.node_id.as_str()],
        )
        .unwrap();

    let first_request = fixture.request.clone();
    let second_request = fixture.request.clone();
    let first = std::thread::spawn(move || {
        first_store.enqueue_host_fence_provider_attempt_for_test(&first_request)
    });
    let second = std::thread::spawn(move || {
        second_store.enqueue_host_fence_provider_attempt_for_test(&second_request)
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let blocked: i64 = source_lock
            .query_one(
                "SELECT count(*)
                   FROM pg_stat_activity
                  WHERE datname=current_database()
                    AND application_name=$1
                    AND wait_event_type='Lock'
                    AND query LIKE '%node_identities%FOR UPDATE%'",
                &[&application_name],
            )
            .unwrap()
            .get(0);
        if blocked == 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "both exact enqueues did not reach the serialized source lock"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    source_lock.batch_execute("COMMIT").unwrap();

    let first = first.join().unwrap().unwrap();
    let second = second.join().unwrap().unwrap();
    assert_eq!(first, second);
    assert_eq!(
        queue_and_authority_state(&fixture.store),
        (1, "cutoff_pending".into())
    );
}

#[test]
fn least_privilege_functions_claim_recover_cutoff_and_complete_exactly() {
    let fixture = fixture();
    fixture
        .store
        .enqueue_host_fence_provider_attempt_for_test(&fixture.request)
        .unwrap();
    let claim_token_1 = "11111111111111111111111111111111";
    let claim_token_2 = "22222222222222222222222222222222";
    let (receipt, claim_generation) = with_provider_session(&fixture.store, |client, schema| {
        let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
        let identity = client
            .query_one(
                "SELECT current_user::TEXT, session_user::TEXT, current_schema()::TEXT",
                &[],
            )
            .unwrap();
        assert_eq!(identity.get::<_, String>(0), "cats_host_fence_provider");
        assert_eq!(identity.get::<_, String>(1), "cats_host_fence_provider");
        assert_eq!(identity.get::<_, String>(2), schema);
        let startup = client
            .query_one(
                &format!("SELECT * FROM {quoted}.control_host_fence_provider_startup_v1()"),
                &[],
            )
            .unwrap();
        assert_eq!(startup.get::<_, i64>("protocol_version"), 1);

        let claim_sql = format!(
            "SELECT * FROM {quoted}.control_host_fence_provider_claim_v1(
                    $1,$2,$3,$4,$5,$6,$7)"
        );
        let scope = scope();
        let first = client
            .query_one(
                &claim_sql,
                &[
                    &scope.provider.as_str(),
                    &scope.partition.as_str(),
                    &scope.account_id.as_str(),
                    &scope.region.as_str(),
                    &"worker-provider-test",
                    &claim_token_1,
                    &1_i64,
                ],
            )
            .unwrap();
        let replay = client
            .query_one(
                &claim_sql,
                &[
                    &scope.provider.as_str(),
                    &scope.partition.as_str(),
                    &scope.account_id.as_str(),
                    &scope.region.as_str(),
                    &"worker-provider-test",
                    &claim_token_1,
                    &1_i64,
                ],
            )
            .unwrap();
        assert_eq!(first.get::<_, i64>("claim_generation"), 1);
        assert_eq!(
            first.get::<_, i64>("claim_lease_expires_at_unix_ms"),
            replay.get::<_, i64>("claim_lease_expires_at_unix_ms")
        );
        std::thread::sleep(std::time::Duration::from_millis(3));
        let expired_replay = client.query_one(
            &claim_sql,
            &[
                &scope.provider.as_str(),
                &scope.partition.as_str(),
                &scope.account_id.as_str(),
                &scope.region.as_str(),
                &"worker-provider-test",
                &claim_token_1,
                &1_i64,
            ],
        );
        assert_eq!(expired_replay.unwrap_err().code().unwrap().code(), "55000");
        let recovered = client
            .query_one(
                &claim_sql,
                &[
                    &scope.provider.as_str(),
                    &scope.partition.as_str(),
                    &scope.account_id.as_str(),
                    &scope.region.as_str(),
                    &"worker-provider-test",
                    &claim_token_2,
                    &30_000_i64,
                ],
            )
            .unwrap();
        assert_eq!(recovered.get::<_, i64>("claim_generation"), 2);
        let renew_sql =
            format!("SELECT {quoted}.control_host_fence_provider_renew_v1($1,$2,$3,$4)");
        let renew_parameters: &[&(dyn postgres::types::ToSql + Sync)] = &[
            &fixture.request.binding.fence_attempt_id.as_str(),
            &claim_token_2,
            &"33333333333333333333333333333333",
            &30_000_i64,
        ];
        let renewed: i64 = client
            .query_one(&renew_sql, renew_parameters)
            .unwrap()
            .get(0);
        let renew_replay: i64 = client
            .query_one(&renew_sql, renew_parameters)
            .unwrap()
            .get(0);
        assert_eq!(renew_replay, renewed);
        let changed_token_replay = client.query_one(
            &renew_sql,
            &[
                &fixture.request.binding.fence_attempt_id.as_str(),
                &claim_token_2,
                &"33333333333333333333333333333333",
                &60_000_i64,
            ],
        );
        assert!(changed_token_replay.is_err());
        let denied = client.query_one(
            &format!("SELECT count(*) FROM {quoted}.host_fence_provider_queue_v1"),
            &[],
        );
        assert_eq!(
            denied.unwrap_err().code().unwrap().code(),
            "42501",
            "provider role unexpectedly has table SELECT"
        );
        let cutoff = client
            .query_one(
                &format!(
                    "SELECT result_kind,
                                cutoff_receipt::TEXT AS cutoff_receipt_json
                           FROM {quoted}.control_host_fence_provider_object_cutoff_v1($1,$2)"
                ),
                &[
                    &fixture.request.binding.fence_attempt_id.as_str(),
                    &claim_token_2,
                ],
            )
            .unwrap();
        assert_eq!(cutoff.get::<_, String>("result_kind"), "complete");
        let receipt: ObjectWriteCutoffReceipt =
            serde_json::from_str(&cutoff.get::<_, String>("cutoff_receipt_json")).unwrap();
        let incomplete_evidence = b"{}";
        let incomplete_digest = evidence_sha256(incomplete_evidence);
        let incomplete_completion = client.query_one(
            &format!("SELECT * FROM {quoted}.control_host_fence_provider_complete_v1($1,$2,$3,$4)"),
            &[
                &fixture.request.binding.fence_attempt_id.as_str(),
                &claim_token_2,
                &incomplete_evidence.as_slice(),
                &incomplete_digest.as_str(),
            ],
        );
        assert!(incomplete_completion.is_err());
        (receipt, recovered.get::<_, i64>("claim_generation"))
    });
    assert_eq!(claim_generation, 2);
    assert_eq!(
        fixture
            .store
            .complete_object_writer_cutoff(&fixture.request.object_writer.writer_authority_id)
            .unwrap()
            .state,
        ObjectWriteAuthorityState::CutoffComplete {
            receipt: receipt.clone()
        }
    );

    let evidence = terminal_evidence(&fixture.request, receipt);
    let bytes = serde_json::to_vec(&evidence).unwrap();
    let digest = evidence_sha256(&bytes);
    with_provider_session(&fixture.store, |client, schema| {
        let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
        let complete_sql =
            format!("SELECT * FROM {quoted}.control_host_fence_provider_complete_v1($1,$2,$3,$4)");
        let parameters: &[&(dyn postgres::types::ToSql + Sync)] = &[
            &fixture.request.binding.fence_attempt_id.as_str(),
            &claim_token_2,
            &bytes,
            &digest.as_str(),
        ];
        let first = client.query_one(&complete_sql, parameters).unwrap();
        let replay = client.query_one(&complete_sql, parameters).unwrap();
        assert_eq!(
            first.get::<_, Vec<u8>>("evidence_bytes"),
            replay.get::<_, Vec<u8>>("evidence_bytes")
        );
        let read = client
            .query_one(
                &format!(
                    "SELECT state, evidence_sha256
                       FROM {quoted}.control_host_fence_provider_read_v1($1,$2)"
                ),
                &[
                    &fixture.request.binding.fence_attempt_id.as_str(),
                    &claim_token_2,
                ],
            )
            .unwrap();
        assert_eq!(read.get::<_, String>("state"), "terminal");
        assert_eq!(read.get::<_, String>("evidence_sha256"), digest.as_str());
    });
}

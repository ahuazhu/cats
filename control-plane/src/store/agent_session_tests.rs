use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use cats_api::error::ErrorCode;
use cats_api::runtime_reconciliation::{
    decode_agent_session, encode_agent_registration_attempt, encode_agent_session,
    guest_config_digest, AgentRegistrationAttempt, AgentSession, AsciiText, ContractError,
    ContractErrorDetail, ContractVersion, CredentialBinding, Epoch, GuestRuntimeProfileReceipt, Id,
    NodeBootId, NodeIdentity, NodeIdentityState, RandomId128, Sha256Digest, UnixMillis,
};

use super::agent_sessions::{
    AgentRegistrationOutcome, AgentRegistrationRejection, AgentSessionRegistrationPolicy,
    AuthenticatedNodeCredential,
};
use super::Store;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random_id(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn boot_id(value: u128) -> NodeBootId {
    NodeBootId::new(format!("{value:032x}")).unwrap()
}

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn release_receipt() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: digest('1'),
        initramfs_digest: Some(digest('2')),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn policy(duration_ms: u64) -> AgentSessionRegistrationPolicy {
    AgentSessionRegistrationPolicy::from_release_receipt(
        &release_receipt(),
        Duration::from_millis(duration_ms),
    )
    .unwrap()
}

fn approved_digest() -> Sha256Digest {
    guest_config_digest(&release_receipt()).unwrap()
}

fn credential_binding(principal: &str) -> CredentialBinding {
    CredentialBinding::ProviderPrincipal {
        provider: id("test_provider"),
        principal: AsciiText::new(principal).unwrap(),
    }
}

fn identity(number: u64) -> NodeIdentity {
    NodeIdentity {
        version: ContractVersion::V1,
        node_id: id(&format!("node_{number}")),
        immutable_host_id: id(&format!("host_{number}")),
        credential_id: id(&format!("credential_{number}")),
        credential_binding: CredentialBinding::PublicKey {
            public_key_spki_sha256: Sha256Digest::new(format!("sha256:{number:064x}")).unwrap(),
        },
        state_path_id: id(&format!("state_path_{number}")),
        state: NodeIdentityState::Provisioned,
    }
}

fn public_key_identity(number: u64) -> NodeIdentity {
    identity(number)
}

fn authenticated(identity: &NodeIdentity) -> AuthenticatedNodeCredential {
    AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        identity.credential_binding.clone(),
    )
}

fn attempt(
    identity: &NodeIdentity,
    boot: u128,
    instance: u128,
    registration: u128,
    expected_epoch: Option<u64>,
) -> AgentRegistrationAttempt {
    AgentRegistrationAttempt {
        version: ContractVersion::V1,
        node_id: identity.node_id.clone(),
        immutable_host_id: identity.immutable_host_id.clone(),
        node_boot_id: boot_id(boot),
        agent_instance_id: random_id(instance),
        registration_attempt_id: random_id(registration),
        guest_config_digest: approved_digest(),
        expected_agent_session_epoch: expected_epoch.map(|value| Epoch::new(value).unwrap()),
    }
}

fn registered(outcome: AgentRegistrationOutcome) -> AgentSession {
    match outcome {
        AgentRegistrationOutcome::Registered(session) => session,
        AgentRegistrationOutcome::Rejected(rejection) => {
            panic!("expected registered AgentSession, got {rejection:?}")
        }
    }
}

fn counts(store: &Store, node_id: &Id) -> (i64, i64) {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM agent_registration_attempts WHERE node_id=$1),
                        (SELECT count(*) FROM current_agent_sessions WHERE node_id=$1)",
                    &[&node_id.as_str()],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
        .unwrap()
}

fn current_session(store: &Store, node_id: &Id) -> AgentSession {
    let json = store
        .with(|client| {
            client
                .query_one(
                    "SELECT record::text FROM current_agent_sessions WHERE node_id=$1",
                    &[&node_id.as_str()],
                )
                .map(|row| row.get::<_, String>(0))
        })
        .unwrap();
    decode_agent_session(json.as_bytes()).unwrap()
}

fn database_now_ms(store: &Store) -> u64 {
    store
        .with(|client| {
            client
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
                    &[],
                )
                .map(|row| row.get::<_, i64>(0))
        })
        .unwrap()
        .try_into()
        .unwrap()
}

fn assert_identity_rejected(outcome: AgentRegistrationOutcome) {
    assert_eq!(
        outcome,
        AgentRegistrationOutcome::Rejected(AgentRegistrationRejection::IdentityNotEligible)
    );
}

#[test]
fn registration_policy_requires_a_positive_bigint_millisecond_duration() {
    for duration in [Duration::ZERO, Duration::from_nanos(1)] {
        let error =
            AgentSessionRegistrationPolicy::from_release_receipt(&release_receipt(), duration)
                .unwrap_err();
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }

    let above_bigint = Duration::from_millis(i64::MAX.unsigned_abs() + 1);
    let error =
        AgentSessionRegistrationPolicy::from_release_receipt(&release_receipt(), above_bigint)
            .unwrap_err();
    assert_eq!(error.code, ErrorCode::FailedPrecondition);

    AgentSessionRegistrationPolicy::from_release_receipt(
        &release_receipt(),
        Duration::from_millis(1),
    )
    .unwrap();
}

#[test]
fn first_registration_replay_and_replacement_keep_one_current_session() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let identity = identity(1);
    store.provision_node_identity(&identity).unwrap();
    let authenticated = authenticated(&identity);
    let policy = policy(60_000);

    store
        .with(|client| {
            client.execute(
                "INSERT INTO nodes (
                    id, agent_url, gateway_url, state, cpus, memory_mib,
                    last_heartbeat_ms, telemetry_json, scheduling_disabled,
                    reported_cats_json, route_grant_public_key_sha256
                 ) VALUES ('legacy-sentinel', 'http://old-node', 'http://old-gateway',
                    'ready', 2, 4096, 77, 'sentinel', FALSE, '[]', NULL)",
                &[],
            )?;
            Ok(())
        })
        .unwrap();

    let before_registration = database_now_ms(&store);
    let first_attempt = attempt(&identity, 1, 11, 111, None);
    let first = registered(
        store
            .register_agent_session(&authenticated, &first_attempt, &policy)
            .unwrap(),
    );
    let after_registration = database_now_ms(&store);
    assert_eq!(first.agent_session_epoch.get(), 1);
    assert!(
        first.lease_deadline_unix_ms.get() >= before_registration + 60_000
            && first.lease_deadline_unix_ms.get() <= after_registration + 60_000,
        "lease deadline must be derived from PostgreSQL time and the configured duration"
    );
    let replay = registered(
        store
            .register_agent_session(&authenticated, &first_attempt, &policy)
            .unwrap(),
    );
    assert_eq!(replay, first, "replay must not refresh the DB deadline");

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE agent_registration_attempts
                        SET lease_deadline_unix_ms=lease_deadline_unix_ms + 1
                      WHERE node_id=$1 AND registration_attempt_id=$2",
                    &[
                        &identity.node_id.as_str(),
                        &first_attempt.registration_attempt_id.as_str(),
                    ],
                )
                .map(|_| ())
        })
        .unwrap_err();
    let mut next_release = release_receipt();
    next_release.kernel_digest = digest('3');
    let next_release_policy = AgentSessionRegistrationPolicy::from_release_receipt(
        &next_release,
        Duration::from_millis(60_000),
    )
    .unwrap();
    let replay_after_release_change = registered(
        store
            .register_agent_session(&authenticated, &first_attempt, &next_release_policy)
            .unwrap(),
    );
    assert_eq!(
        replay_after_release_change, first,
        "an exact committed attempt replays before active-release validation"
    );

    let replacement_attempt = attempt(&identity, 1, 12, 112, Some(1));
    let replacement = registered(
        store
            .register_agent_session(&authenticated, &replacement_attempt, &policy)
            .unwrap(),
    );
    assert_eq!(replacement.agent_session_epoch.get(), 2);
    assert_eq!(current_session(&store, &identity.node_id), replacement);
    assert_eq!(counts(&store, &identity.node_id), (2, 1));

    let lost_old_response = registered(
        store
            .register_agent_session(&authenticated, &first_attempt, &policy)
            .unwrap(),
    );
    assert_eq!(lost_old_response, first);
    assert_eq!(current_session(&store, &identity.node_id), replacement);

    let sentinel: (String, i64, String) = store
        .with(|client| {
            client
                .query_one(
                    "SELECT state, last_heartbeat_ms, telemetry_json
                       FROM nodes WHERE id='legacy-sentinel'",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
        })
        .unwrap();
    assert_eq!(sentinel, ("ready".to_owned(), 77, "sentinel".to_owned()));
}

#[test]
fn node_lineage_is_idempotent_then_permanently_retired_and_non_reusable() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let original = identity(1);
    store.provision_node_identity(&original).unwrap();
    store.provision_node_identity(&original).unwrap();

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE node_identities SET immutable_host_id='changed_host'
                      WHERE node_id=$1",
                    &[&original.node_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap_err();
    store
        .with(|client| {
            client
                .execute(
                    "DELETE FROM node_identities WHERE node_id=$1",
                    &[&original.node_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap_err();

    let mut reused_lineage = identity(2);
    reused_lineage.immutable_host_id = original.immutable_host_id.clone();
    reused_lineage.state_path_id = original.state_path_id.clone();
    let error = store.provision_node_identity(&reused_lineage).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);

    let mut reused_credential = identity(3);
    reused_credential.credential_id = original.credential_id.clone();
    let error = store
        .provision_node_identity(&reused_credential)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);

    let original_authenticated = authenticated(&original);
    let original_attempt = attempt(&original, 1, 11, 111, None);
    let original_session = registered(
        store
            .register_agent_session(&original_authenticated, &original_attempt, &policy(60_000))
            .unwrap(),
    );

    store.retire_node_identity(&original.node_id).unwrap();
    store.retire_node_identity(&original.node_id).unwrap();
    assert_eq!(
        registered(
            store
                .register_agent_session(
                    &original_authenticated,
                    &original_attempt,
                    &policy(60_000),
                )
                .unwrap(),
        ),
        original_session,
        "retirement must not hide the exact result of a committed attempt"
    );
    assert_identity_rejected(
        store
            .register_agent_session(
                &original_authenticated,
                &attempt(&original, 1, 12, 112, Some(1)),
                &policy(60_000),
            )
            .unwrap(),
    );
    assert_eq!(counts(&store, &original.node_id), (1, 1));

    let error = store.provision_node_identity(&original).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);

    let mut rebound_node = identity(4);
    rebound_node.node_id = original.node_id.clone();
    let error = store.provision_node_identity(&rebound_node).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);

    let replacement = identity(5);
    store.provision_node_identity(&replacement).unwrap();
    registered(
        store
            .register_agent_session(
                &authenticated(&replacement),
                &attempt(&replacement, 5, 51, 551, None),
                &policy(60_000),
            )
            .unwrap(),
    );

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE node_identities SET state='provisioned' WHERE node_id=$1",
                    &[&original.node_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap_err();
}

#[test]
fn public_key_credentials_round_trip_and_the_projection_is_strictly_one_of() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let identity = public_key_identity(1);
    store.provision_node_identity(&identity).unwrap();

    registered(
        store
            .register_agent_session(
                &authenticated(&identity),
                &attempt(&identity, 1, 11, 111, None),
                &policy(60_000),
            )
            .unwrap(),
    );

    store
        .with(|client| {
            client
                .execute(
                    "UPDATE node_identities
                        SET credential_provider='forbidden_second_variant',
                            credential_principal='forbidden-principal'
                      WHERE node_id=$1",
                    &[&identity.node_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap_err();
    assert_eq!(counts(&store, &identity.node_id), (1, 1));
}

#[test]
fn every_changed_attempt_binding_conflicts_before_active_release_validation() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let identity = identity(1);
    store.provision_node_identity(&identity).unwrap();
    let authenticated = authenticated(&identity);
    let policy = policy(60_000);
    let original = attempt(&identity, 1, 11, 111, None);
    registered(
        store
            .register_agent_session(&authenticated, &original, &policy)
            .unwrap(),
    );

    let mut changed_host = original.clone();
    changed_host.immutable_host_id = id("another_host");
    let mut changed_boot = original.clone();
    changed_boot.node_boot_id = boot_id(2);
    let mut changed_instance = original.clone();
    changed_instance.agent_instance_id = random_id(12);
    let mut changed_digest = original.clone();
    changed_digest.guest_config_digest = digest('a');
    let mut changed_expected = original.clone();
    changed_expected.expected_agent_session_epoch = Epoch::new(1);

    for changed in [
        changed_host,
        changed_boot,
        changed_instance,
        changed_digest,
        changed_expected,
    ] {
        let outcome = store
            .register_agent_session(&authenticated, &changed, &policy)
            .unwrap();
        let AgentRegistrationOutcome::Rejected(AgentRegistrationRejection::Contract(error)) =
            outcome
        else {
            panic!("changed attempt binding did not return its canonical conflict");
        };
        let ContractErrorDetail::RegistrationAttemptConflict {
            node_id,
            registration_attempt_id,
            expected,
            presented,
        } = error.error.as_ref()
        else {
            panic!("wrong ContractError for changed attempt: {:?}", error.error);
        };
        assert_eq!(node_id, &original.node_id);
        assert_eq!(registration_attempt_id, &original.registration_attempt_id);
        assert_eq!(expected.immutable_host_id, original.immutable_host_id);
        assert_eq!(presented.immutable_host_id, changed.immutable_host_id);
        assert_eq!(expected.node_boot_id, original.node_boot_id);
        assert_eq!(presented.node_boot_id, changed.node_boot_id);
        assert_eq!(expected.agent_instance_id, original.agent_instance_id);
        assert_eq!(presented.agent_instance_id, changed.agent_instance_id);
        assert_eq!(expected.guest_config_digest, original.guest_config_digest);
        assert_eq!(presented.guest_config_digest, changed.guest_config_digest);
        assert_eq!(
            expected.expected_agent_session_epoch,
            original.expected_agent_session_epoch
        );
        assert_eq!(
            presented.expected_agent_session_epoch,
            changed.expected_agent_session_epoch
        );
        assert_eq!(counts(&store, &identity.node_id), (1, 1));
    }
}

#[test]
fn identity_digest_retirement_and_epoch_rejections_have_zero_side_effects() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let identity = identity(1);
    store.provision_node_identity(&identity).unwrap();
    let authenticated = authenticated(&identity);
    let policy = policy(60_000);

    let wrong_credential = AuthenticatedNodeCredential::new(
        id("missing_credential"),
        identity.credential_binding.clone(),
    );
    assert_identity_rejected(
        store
            .register_agent_session(
                &wrong_credential,
                &attempt(&identity, 1, 11, 101, None),
                &policy,
            )
            .unwrap(),
    );
    let wrong_binding = AuthenticatedNodeCredential::new(
        identity.credential_id.clone(),
        credential_binding("another-principal"),
    );
    assert_identity_rejected(
        store
            .register_agent_session(
                &wrong_binding,
                &attempt(&identity, 1, 11, 102, None),
                &policy,
            )
            .unwrap(),
    );
    let mut wrong_host = attempt(&identity, 1, 11, 103, None);
    wrong_host.immutable_host_id = id("wrong_host");
    assert_identity_rejected(
        store
            .register_agent_session(&authenticated, &wrong_host, &policy)
            .unwrap(),
    );

    let mut wrong_digest = attempt(&identity, 1, 11, 104, None);
    wrong_digest.guest_config_digest = digest('a');
    let outcome = store
        .register_agent_session(&authenticated, &wrong_digest, &policy)
        .unwrap();
    assert!(matches!(
        outcome,
        AgentRegistrationOutcome::Rejected(AgentRegistrationRejection::Contract(ContractError {
            error,
            ..
        })) if matches!(error.as_ref(), ContractErrorDetail::GuestConfigMismatch { .. })
    ));
    assert_eq!(counts(&store, &identity.node_id), (0, 0));

    let wrong_first_epoch = attempt(&identity, 1, 11, 105, Some(1));
    assert!(matches!(
        store
            .register_agent_session(&authenticated, &wrong_first_epoch, &policy)
            .unwrap(),
        AgentRegistrationOutcome::Rejected(AgentRegistrationRejection::SessionEpochMismatch {
            current_agent_session_epoch: None,
            presented_expected_agent_session_epoch: Some(_),
        })
    ));
    assert_eq!(counts(&store, &identity.node_id), (0, 0));

    let first = registered(
        store
            .register_agent_session(
                &authenticated,
                &attempt(&identity, 1, 11, 106, None),
                &policy,
            )
            .unwrap(),
    );
    assert_eq!(first.agent_session_epoch.get(), 1);
    let unexpected_null = attempt(&identity, 1, 12, 107, None);
    assert!(matches!(
        store
            .register_agent_session(&authenticated, &unexpected_null, &policy)
            .unwrap(),
        AgentRegistrationOutcome::Rejected(AgentRegistrationRejection::SessionEpochMismatch { .. })
    ));
    assert_eq!(counts(&store, &identity.node_id), (1, 1));

    let second = registered(
        store
            .register_agent_session(
                &authenticated,
                &attempt(&identity, 1, 12, 108, Some(1)),
                &policy,
            )
            .unwrap(),
    );
    assert_eq!(second.agent_session_epoch.get(), 2);
    let stale = attempt(&identity, 1, 13, 109, Some(1));
    assert!(matches!(
        store
            .register_agent_session(&authenticated, &stale, &policy)
            .unwrap(),
        AgentRegistrationOutcome::Rejected(
            AgentRegistrationRejection::SessionEpochMismatch {
                current_agent_session_epoch: Some(current),
                presented_expected_agent_session_epoch: Some(presented),
            }
        ) if current.get() == 2 && presented.get() == 1
    ));
    assert_eq!(counts(&store, &identity.node_id), (2, 1));

    store.retire_node_identity(&identity.node_id).unwrap();
    assert_identity_rejected(
        store
            .register_agent_session(
                &authenticated,
                &attempt(&identity, 1, 14, 110, Some(2)),
                &policy,
            )
            .unwrap(),
    );
    assert_eq!(counts(&store, &identity.node_id), (2, 1));
}

#[test]
fn epoch_and_db_deadline_overflow_fail_closed() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Store::connect(&url, None).unwrap();
    let identity = identity(1);
    store.provision_node_identity(&identity).unwrap();
    let authenticated = authenticated(&identity);

    let deadline_overflow_policy = policy(i64::MAX.unsigned_abs());
    let error = store
        .register_agent_session(
            &authenticated,
            &attempt(&identity, 1, 11, 111, None),
            &deadline_overflow_policy,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(counts(&store, &identity.node_id), (0, 0));

    let normal_policy = policy(60_000);
    let first_attempt = attempt(&identity, 1, 11, 112, None);
    let maximum = AgentSession {
        version: ContractVersion::V1,
        node_id: first_attempt.node_id.clone(),
        immutable_host_id: first_attempt.immutable_host_id.clone(),
        node_boot_id: first_attempt.node_boot_id.clone(),
        agent_instance_id: first_attempt.agent_instance_id.clone(),
        agent_session_epoch: Epoch::new(i64::MAX.unsigned_abs()).unwrap(),
        registration_attempt_id: first_attempt.registration_attempt_id.clone(),
        guest_config_digest: first_attempt.guest_config_digest.clone(),
        lease_deadline_unix_ms: UnixMillis::new(1_000).unwrap(),
    };
    let first_attempt_record =
        String::from_utf8(encode_agent_registration_attempt(&first_attempt).unwrap()).unwrap();
    let maximum_record = String::from_utf8(encode_agent_session(&maximum).unwrap()).unwrap();
    let maximum_epoch = i64::MAX;
    store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "INSERT INTO agent_registration_attempts (
                    node_id, registration_attempt_id, attempt_record,
                    immutable_host_id, node_boot_id, agent_instance_id,
                    guest_config_digest, expected_agent_session_epoch,
                    session_record, agent_session_epoch, lease_deadline_unix_ms
                 ) VALUES ($1, $2, $3::TEXT::jsonb, $4, $5, $6, $7, NULL,
                    $8::TEXT::jsonb, $9, $10)",
                &[
                    &identity.node_id.as_str(),
                    &first_attempt.registration_attempt_id.as_str(),
                    &first_attempt_record,
                    &first_attempt.immutable_host_id.as_str(),
                    &first_attempt.node_boot_id.as_str(),
                    &first_attempt.agent_instance_id.as_str(),
                    &first_attempt.guest_config_digest.as_str(),
                    &maximum_record,
                    &maximum_epoch,
                    &(maximum.lease_deadline_unix_ms.get() as i64),
                ],
            )?;
            transaction.execute(
                "INSERT INTO current_agent_sessions (
                    node_id, record, immutable_host_id, node_boot_id,
                    agent_instance_id, agent_session_epoch, registration_attempt_id,
                    guest_config_digest, lease_deadline_unix_ms
                 ) VALUES ($1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &identity.node_id.as_str(),
                    &maximum_record,
                    &maximum.immutable_host_id.as_str(),
                    &maximum.node_boot_id.as_str(),
                    &maximum.agent_instance_id.as_str(),
                    &maximum_epoch,
                    &maximum.registration_attempt_id.as_str(),
                    &maximum.guest_config_digest.as_str(),
                    &(maximum.lease_deadline_unix_ms.get() as i64),
                ],
            )?;
            transaction.commit()
        })
        .unwrap();

    let error = store
        .register_agent_session(
            &authenticated,
            &attempt(&identity, 1, 12, 113, Some(i64::MAX.unsigned_abs())),
            &normal_policy,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(counts(&store, &identity.node_id), (1, 1));
    assert_eq!(
        current_session(&store, &identity.node_id).agent_session_epoch,
        maximum.agent_session_epoch
    );
}

#[test]
fn two_first_sessions_for_one_node_have_one_winner() {
    let url = crate::testsupport::isolated_control_store_url();
    let first_store = Store::connect(&url, None).unwrap();
    let second_store = Store::connect(&url, None).unwrap();
    let observer = Store::connect(&url, None).unwrap();
    let identity = identity(1);
    first_store.provision_node_identity(&identity).unwrap();
    let authenticated = authenticated(&identity);
    let policy = policy(60_000);
    let barrier = Arc::new(Barrier::new(2));

    let (first, second) = std::thread::scope(|scope| {
        let first_barrier = Arc::clone(&barrier);
        let first_auth = authenticated.clone();
        let first_policy = policy.clone();
        let first_attempt = attempt(&identity, 1, 11, 111, None);
        let first = scope.spawn(move || {
            first_barrier.wait();
            first_store.register_agent_session(&first_auth, &first_attempt, &first_policy)
        });
        let second_barrier = Arc::clone(&barrier);
        let second_auth = authenticated.clone();
        let second_policy = policy.clone();
        let second_attempt = attempt(&identity, 1, 12, 112, None);
        let second = scope.spawn(move || {
            second_barrier.wait();
            second_store.register_agent_session(&second_auth, &second_attempt, &second_policy)
        });
        (
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        )
    });

    let registered = [&first, &second]
        .into_iter()
        .filter(|outcome| matches!(outcome, AgentRegistrationOutcome::Registered(_)))
        .count();
    let rejected = [&first, &second]
        .into_iter()
        .filter(|outcome| {
            matches!(
                outcome,
                AgentRegistrationOutcome::Rejected(
                    AgentRegistrationRejection::SessionEpochMismatch { .. }
                )
            )
        })
        .count();
    assert_eq!((registered, rejected), (1, 1));
    assert_eq!(counts(&observer, &identity.node_id), (1, 1));
    assert_eq!(
        current_session(&observer, &identity.node_id)
            .agent_session_epoch
            .get(),
        1
    );
}

#[test]
fn a_locked_node_identity_does_not_serialize_another_node() {
    let url = crate::testsupport::isolated_control_store_url();
    let seed = Store::connect(&url, None).unwrap();
    let first_identity = identity(1);
    let second_identity = identity(2);
    seed.provision_node_identity(&first_identity).unwrap();
    seed.provision_node_identity(&second_identity).unwrap();

    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let lock_url = url.clone();
    let first_credential = first_identity.credential_id.to_string();
    let locker = std::thread::spawn(move || {
        let mut client = postgres::Client::connect(&lock_url, postgres::NoTls).unwrap();
        let mut transaction = client.transaction().unwrap();
        transaction
            .query_one(
                "SELECT node_id FROM node_identities WHERE credential_id=$1 FOR UPDATE",
                &[&first_credential],
            )
            .unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        transaction.commit().unwrap();
    });
    locked_rx.recv().unwrap();

    let worker_store = Store::connect(&url, None).unwrap();
    let second_auth = authenticated(&second_identity);
    let second_attempt = attempt(&second_identity, 2, 21, 221, None);
    let second_policy = policy(60_000);
    let (result_tx, result_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        result_tx
            .send(worker_store.register_agent_session(
                &second_auth,
                &second_attempt,
                &second_policy,
            ))
            .unwrap();
    });
    let outcome = result_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("another Node must not wait for the locked identity")
        .unwrap();
    assert!(matches!(outcome, AgentRegistrationOutcome::Registered(_)));
    release_tx.send(()).unwrap();
    locker.join().unwrap();
    worker.join().unwrap();
}

#[test]
fn stored_identity_attempt_and_current_projection_corruption_fail_backend_unknown() {
    let corrupt_identity_url = crate::testsupport::isolated_control_store_url();
    let corrupt_identity_store = Store::connect(&corrupt_identity_url, None).unwrap();
    let corrupt_identity = identity(1);
    corrupt_identity_store
        .provision_node_identity(&corrupt_identity)
        .unwrap();
    corrupt_identity_store
        .with(|client| {
            client
                .execute(
                    "UPDATE node_identities
                        SET record=jsonb_set(record, '{immutable_host_id}',
                            to_jsonb('different_host'::text))
                      WHERE node_id=$1",
                    &[&corrupt_identity.node_id.as_str()],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = corrupt_identity_store
        .register_agent_session(
            &authenticated(&corrupt_identity),
            &attempt(&corrupt_identity, 1, 11, 111, None),
            &policy(60_000),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);

    let corrupt_attempt_url = crate::testsupport::isolated_control_store_url();
    let corrupt_attempt_store = Store::connect(&corrupt_attempt_url, None).unwrap();
    let corrupt_attempt_identity = identity(2);
    corrupt_attempt_store
        .provision_node_identity(&corrupt_attempt_identity)
        .unwrap();
    let original_attempt = attempt(&corrupt_attempt_identity, 2, 21, 221, None);
    let stored_session = AgentSession {
        version: ContractVersion::V1,
        node_id: original_attempt.node_id.clone(),
        immutable_host_id: original_attempt.immutable_host_id.clone(),
        node_boot_id: original_attempt.node_boot_id.clone(),
        agent_instance_id: original_attempt.agent_instance_id.clone(),
        agent_session_epoch: Epoch::new(1).unwrap(),
        registration_attempt_id: original_attempt.registration_attempt_id.clone(),
        guest_config_digest: original_attempt.guest_config_digest.clone(),
        lease_deadline_unix_ms: UnixMillis::new(1_000).unwrap(),
    };
    let attempt_record =
        String::from_utf8(encode_agent_registration_attempt(&original_attempt).unwrap()).unwrap();
    let session_record = String::from_utf8(encode_agent_session(&stored_session).unwrap()).unwrap();
    corrupt_attempt_store
        .with(|client| {
            client
                .execute(
                    "INSERT INTO agent_registration_attempts (
                        node_id, registration_attempt_id, attempt_record,
                        immutable_host_id, node_boot_id, agent_instance_id,
                        guest_config_digest, expected_agent_session_epoch,
                        session_record, agent_session_epoch, lease_deadline_unix_ms
                     ) VALUES ($1, $2, $3::TEXT::jsonb, $4, $5,
                        '99999999999999999999999999999999', $6, NULL,
                        $7::TEXT::jsonb, 1, 1000)",
                    &[
                        &corrupt_attempt_identity.node_id.as_str(),
                        &original_attempt.registration_attempt_id.as_str(),
                        &attempt_record,
                        &original_attempt.immutable_host_id.as_str(),
                        &original_attempt.node_boot_id.as_str(),
                        &original_attempt.guest_config_digest.as_str(),
                        &session_record,
                    ],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = corrupt_attempt_store
        .register_agent_session(
            &authenticated(&corrupt_attempt_identity),
            &original_attempt,
            &policy(60_000),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);

    let corrupt_current_url = crate::testsupport::isolated_control_store_url();
    let corrupt_current_store = Store::connect(&corrupt_current_url, None).unwrap();
    let corrupt_current_identity = identity(3);
    corrupt_current_store
        .provision_node_identity(&corrupt_current_identity)
        .unwrap();
    registered(
        corrupt_current_store
            .register_agent_session(
                &authenticated(&corrupt_current_identity),
                &attempt(&corrupt_current_identity, 3, 31, 331, None),
                &policy(60_000),
            )
            .unwrap(),
    );
    let mut divergent_current =
        current_session(&corrupt_current_store, &corrupt_current_identity.node_id);
    divergent_current.immutable_host_id = id("coherently_wrong_host");
    divergent_current.node_boot_id = boot_id(999);
    divergent_current.agent_instance_id = random_id(999);
    divergent_current.guest_config_digest = digest('a');
    divergent_current.lease_deadline_unix_ms = UnixMillis::new(999).unwrap();
    let divergent_record =
        String::from_utf8(encode_agent_session(&divergent_current).unwrap()).unwrap();
    corrupt_current_store
        .with(|client| {
            client
                .execute(
                    "UPDATE current_agent_sessions
                        SET record=$2::TEXT::jsonb,
                            immutable_host_id=$3,
                            node_boot_id=$4,
                            agent_instance_id=$5,
                            guest_config_digest=$6,
                            lease_deadline_unix_ms=$7
                      WHERE node_id=$1",
                    &[
                        &corrupt_current_identity.node_id.as_str(),
                        &divergent_record,
                        &divergent_current.immutable_host_id.as_str(),
                        &divergent_current.node_boot_id.as_str(),
                        &divergent_current.agent_instance_id.as_str(),
                        &divergent_current.guest_config_digest.as_str(),
                        &(divergent_current.lease_deadline_unix_ms.get() as i64),
                    ],
                )
                .map(|_| ())
        })
        .unwrap();
    let error = corrupt_current_store
        .register_agent_session(
            &authenticated(&corrupt_current_identity),
            &attempt(&corrupt_current_identity, 3, 32, 332, Some(1)),
            &policy(60_000),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(
        counts(&corrupt_current_store, &corrupt_current_identity.node_id),
        (1, 1)
    );
    assert_eq!(
        current_session(&corrupt_current_store, &corrupt_current_identity.node_id),
        divergent_current,
        "failed replacement must not rewrite the divergent current row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_active_registration_commits_once_and_exact_retry_recovers_response() {
    let url = crate::testsupport::isolated_control_store_url();
    let store = Arc::new(Store::connect(&url, None).unwrap());
    let observer = Store::connect(&url, None).unwrap();
    let identity = identity(1);
    store.provision_node_identity(&identity).unwrap();

    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let lock_url = url.clone();
    let credential_id = identity.credential_id.to_string();
    let locker = std::thread::spawn(move || {
        let mut client = postgres::Client::connect(&lock_url, postgres::NoTls).unwrap();
        let mut transaction = client.transaction().unwrap();
        transaction
            .query_one(
                "SELECT node_id FROM node_identities WHERE credential_id=$1 FOR UPDATE",
                &[&credential_id],
            )
            .unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        transaction.commit().unwrap();
    });
    locked_rx.recv().unwrap();

    let task_store = Arc::clone(&store);
    let task_authenticated = authenticated(&identity);
    let task_attempt = attempt(&identity, 1, 11, 111, None);
    let task_policy = policy(60_000);
    let task = tokio::spawn(async move {
        task_store
            .execute(move |store| {
                store.register_agent_session(&task_authenticated, &task_attempt, &task_policy)
            })
            .await
    });

    let mut waiting_on_identity = false;
    for _ in 0..200 {
        waiting_on_identity = observer
            .with(|client| {
                client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1 FROM pg_stat_activity
                             WHERE datname=current_database()
                               AND wait_event_type='Lock'
                               AND query LIKE '%FROM node_identities%'
                         )",
                        &[],
                    )
                    .map(|row| row.get(0))
            })
            .unwrap();
        if waiting_on_identity {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        waiting_on_identity,
        "registration never reached its row lock"
    );
    task.abort();
    release_tx.send(()).unwrap();
    locker.join().unwrap();

    let mut committed = false;
    for _ in 0..200 {
        if counts(&observer, &identity.node_id) == (1, 1) {
            committed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        committed,
        "active cancelled registration did not finish its transaction"
    );
    let committed_session = current_session(&observer, &identity.node_id);

    let replay_authenticated = authenticated(&identity);
    let replay_attempt = attempt(&identity, 1, 11, 111, None);
    let replay_policy = policy(60_000);
    let replay = store
        .execute(move |store| {
            store.register_agent_session(&replay_authenticated, &replay_attempt, &replay_policy)
        })
        .await
        .unwrap();
    assert_eq!(registered(replay), committed_session);
    assert_eq!(counts(&observer, &identity.node_id), (1, 1));

    let backend_pid: i32 = store
        .execute(|store| {
            store.with(|client| {
                client
                    .query_one("SELECT pg_backend_pid()", &[])
                    .map(|row| row.get(0))
            })
        })
        .await
        .unwrap();
    let backend_state: Option<String> = observer
        .with(|client| {
            client
                .query_opt(
                    "SELECT state FROM pg_stat_activity WHERE pid=$1",
                    &[&backend_pid],
                )
                .map(|row| row.map(|row| row.get(0)))
        })
        .unwrap();
    assert_eq!(backend_state.as_deref(), Some("idle"));
}

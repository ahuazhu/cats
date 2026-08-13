//! Real PostgreSQL acceptance for the startup-pinned Route v2 signer binding.

use std::sync::{mpsc, Arc, Barrier};
use std::time::{Duration, Instant};

use cats_api::route_grant_v2::{
    decode_route_grant_v2_public_key_ring, decode_route_grant_v2_signer_reference,
    encode_route_grant_v2_signer_reference, RouteGrantV2PublicKey, RouteGrantV2PublicKeyEntry,
    RouteGrantV2PublicKeyRingArtifact, RouteGrantV2PublicKeyRingExpectedPrevious,
    RouteGrantV2SignerExpectedPrevious, RouteGrantV2SignerReference, RouteGrantV2SignerSelection,
};
use cats_api::runtime_reconciliation::{
    AllocatableMemoryBytes, AllocatableVcpus, AsciiText, Base64UrlNoPad, ContractVersion, Epoch,
    GuestIpv4Pool, GuestIpv4PoolKind, GuestRuntimeProfileReceipt, HostPath, Id, Ipv4Address, KeyId,
    NodePlacementPolicy, NodeResidue, NodeTransportTarget, OwnershipTokenEvidence, RandomId128,
    RuntimePlacementBlockFrontend, RuntimePlacementCapabilities, RuntimePlacementGuestNetwork,
    RuntimePlacementGuestTransport, RuntimePlacementVmm, RuntimeSchedulingState, Sha256Digest,
    UnixMillis,
};

use crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority;
use crate::store::runtime_authority::placement_policy::insert_policy_on_store_for_test;
use crate::store::runtime_authority::route_signing_authority::{
    strictly_after_retention, RouteGrantV2SigningAuthorityCommand,
    RouteGrantV2SigningAuthorityCommandKind, RouteGrantV2SigningAuthorityCommandResult,
    RouteGrantV2SigningAuthorityStoreOutcome, RETENTION_MILLIS,
};
use crate::store::runtime_authority::runtime_spine::PlacementAdmissionSnapshot;
use crate::store::runtime_authority::runtime_spine_tests::{
    accept_partial_heartbeat_for_test, accept_ring_admission_for_test,
    establish_empty_admission_for, refresh_assigned_admission_for_test,
    refresh_assigned_admission_with_residue_for_test, replace_agent_session_for_test,
};
use crate::store::AuthorityRequestContext;
use crate::store::Store;

const RING: &[u8] = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}"#;
const SIGNER: &[u8] = br#"{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:7c7e324d7be6c6ee71735c900ce1041de63af7cc08fb39b6800853f966e81e34"}"#;
const PRIVATE_KEY: &[u8] =
    include_bytes!("../../../../tests/fixtures/route_grant_v2_private_ed25519.pem");
const OTHER_KID: &str = "47ff3f28dd2cc185ac432f34ecc346a121c52934b16993ab9fb7fcb92a3406f8";
const OTHER_SPKI: &str = "MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk";
const THIRD_SPKI: &str = "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fn installation(bytes: &[u8]) -> InstalledRouteGrantV2SigningAuthority {
    let reference = decode_route_grant_v2_signer_reference(bytes).unwrap();
    let ring = decode_route_grant_v2_public_key_ring(RING).unwrap();
    let private_key = match &reference.signer {
        RouteGrantV2SignerSelection::Active { .. } => Some(PRIVATE_KEY),
        RouteGrantV2SignerSelection::Disabled => None,
    };
    InstalledRouteGrantV2SigningAuthority::from_authority_artifacts(
        &reference,
        bytes,
        &ring,
        private_key,
        120,
    )
    .unwrap()
}

fn row_versions(store: &Store) -> Vec<String> {
    store
        .with(|client| {
            client
                .query(
                    "SELECT row_name, xmin
                       FROM (
                         SELECT 'authority' AS row_name, xmin::TEXT AS xmin
                           FROM route_v2_signing_authority
                         UNION ALL
                         SELECT 'revision:' || signer_revision, xmin::TEXT
                           FROM route_v2_signer_revisions
                         UNION ALL
                         SELECT 'key:' || kid, xmin::TEXT
                           FROM route_v2_signer_key_lineage
                         UNION ALL
                         SELECT 'ring:' || ring_version, xmin::TEXT
                           FROM route_v2_public_key_ring_revisions
                         UNION ALL
                         SELECT 'retirement:' || kid, xmin::TEXT
                           FROM route_v2_signer_retirements
                         UNION ALL
                         SELECT 'authorization:' || authorization_id, xmin::TEXT
                           FROM route_v2_secret_deletion_authorizations
                         UNION ALL
                         SELECT 'command:' || command_id, xmin::TEXT
                           FROM route_v2_signing_authority_commands
                       ) rows
                      ORDER BY row_name",
                    &[],
                )?
                .into_iter()
                .map(|row| {
                    Ok(format!(
                        "{}:{}",
                        row.try_get::<_, String>(0)?,
                        row.try_get::<_, String>(1)?
                    ))
                })
                .collect()
        })
        .unwrap()
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn random(value: u128) -> RandomId128 {
    RandomId128::new(format!("{value:032x}")).unwrap()
}

fn initial_ring() -> RouteGrantV2PublicKeyRingArtifact {
    decode_route_grant_v2_public_key_ring(RING).unwrap()
}

pub(super) fn install_initial_signer_for_test(store: &Store) -> RouteGrantV2PublicKeyRingArtifact {
    store
        .install_route_grant_v2_signer_authority(&installation(SIGNER))
        .unwrap();
    initial_ring()
}

fn other_entry() -> RouteGrantV2PublicKeyEntry {
    RouteGrantV2PublicKeyEntry {
        kid: KeyId::new(OTHER_KID).unwrap(),
        public_key_spki: Base64UrlNoPad::new(OTHER_SPKI).unwrap(),
    }
}

fn third_entry() -> RouteGrantV2PublicKeyEntry {
    let public_key_spki = Base64UrlNoPad::new(THIRD_SPKI).unwrap();
    let public = RouteGrantV2PublicKey::from_base64url_spki(&public_key_spki).unwrap();
    RouteGrantV2PublicKeyEntry {
        kid: public.kid().clone(),
        public_key_spki,
    }
}

fn successor_ring(
    current: &RouteGrantV2PublicKeyRingArtifact,
    keys: Vec<RouteGrantV2PublicKeyEntry>,
) -> RouteGrantV2PublicKeyRingArtifact {
    let mut keys = keys;
    keys.sort_by(|left, right| left.kid.cmp(&right.kid));
    RouteGrantV2PublicKeyRingArtifact {
        version: ContractVersion::V1,
        ring_version: Epoch::new(current.ring_version.get() + 1).unwrap(),
        expected_previous: Some(RouteGrantV2PublicKeyRingExpectedPrevious {
            ring_version: current.ring_version,
            key_ring_digest: current.digest().unwrap(),
        }),
        keys,
    }
}

fn successor_reference(
    current: &RouteGrantV2SignerReference,
    signer: RouteGrantV2SignerSelection,
    ring: &RouteGrantV2PublicKeyRingArtifact,
) -> RouteGrantV2SignerReference {
    RouteGrantV2SignerReference {
        version: ContractVersion::V1,
        deployment_id: current.deployment_id.clone(),
        signer_revision: Epoch::new(current.signer_revision.get() + 1).unwrap(),
        expected_previous: Some(RouteGrantV2SignerExpectedPrevious {
            signer_revision: current.signer_revision,
            signer_reference_sha256: current.digest().unwrap(),
        }),
        signer,
        public_key_ring_version: ring.ring_version,
        public_key_ring_digest: ring.digest().unwrap(),
    }
}

fn apply(
    store: &Store,
    command: &RouteGrantV2SigningAuthorityCommand,
) -> RouteGrantV2SigningAuthorityStoreOutcome {
    store
        .apply_route_grant_v2_signing_authority_command(
            command,
            &AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5)),
        )
        .unwrap()
}

fn assert_applied(
    outcome: RouteGrantV2SigningAuthorityStoreOutcome,
) -> RouteGrantV2SigningAuthorityCommandResult {
    let RouteGrantV2SigningAuthorityStoreOutcome::Stored(result) = outcome else {
        panic!("expected stored Route v2 command outcome")
    };
    assert!(matches!(
        result,
        RouteGrantV2SigningAuthorityCommandResult::Applied { .. }
    ));
    result
}

fn assert_precondition_failed(outcome: RouteGrantV2SigningAuthorityStoreOutcome) {
    assert_eq!(
        outcome,
        RouteGrantV2SigningAuthorityStoreOutcome::Stored(
            RouteGrantV2SigningAuthorityCommandResult::PreconditionFailed
        )
    );
}

fn release() -> GuestRuntimeProfileReceipt {
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: Sha256Digest::from_bytes([1; 32]),
        initramfs_digest: Some(Sha256Digest::from_bytes([2; 32])),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda").unwrap(),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

fn schedulable_policy(admission: &PlacementAdmissionSnapshot) -> NodePlacementPolicy {
    NodePlacementPolicy {
        version: ContractVersion::V1,
        node_id: admission.node_identity.node_id.clone(),
        policy_revision: Epoch::new(1).unwrap(),
        scheduling_state: RuntimeSchedulingState::Schedulable,
        allocatable_vcpus: AllocatableVcpus::new(8).unwrap(),
        allocatable_memory_bytes: AllocatableMemoryBytes::new(16 << 30).unwrap(),
        capabilities: RuntimePlacementCapabilities {
            vmm: RuntimePlacementVmm::CloudHypervisor,
            block_frontend: RuntimePlacementBlockFrontend::KernelNbd,
            guest_network: RuntimePlacementGuestNetwork::IsolatedIpv4,
            guest_transport: RuntimePlacementGuestTransport::Vsock,
            guest_agent_protocol_version: ContractVersion::V1,
            guest_config_digest: admission.agent_session.guest_config_digest.clone(),
        },
        guest_ipv4_pool: GuestIpv4Pool {
            kind: GuestIpv4PoolKind::PrivateIpv4_16,
            network_address: Ipv4Address::new("10.240.0.0").unwrap(),
            prefix_length: 16,
        },
        node_transport_target: NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
    }
}

#[test]
fn initial_install_and_exact_replay_are_current_and_zero_write() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let installed = installation(SIGNER);
    store
        .install_route_grant_v2_signer_authority(&installed)
        .unwrap();
    assert!(store
        .route_grant_v2_signer_is_current_for_test(installed.binding())
        .unwrap());
    let before = row_versions(&store);
    store
        .install_route_grant_v2_signer_authority(&installed)
        .unwrap();
    assert_eq!(row_versions(&store), before, "exact replay wrote rows");

    store
        .with(|client| {
            let pointer = client.query_one(
                "SELECT deployment_id, current_signer_revision,
                        current_signer_reference_sha256, signer_state,
                        active_kid, public_key_ring_version,
                        public_key_ring_digest, secret_reference_id
                   FROM route_v2_signing_authority WHERE singleton",
                &[],
            )?;
            assert_eq!(pointer.get::<_, String>(0), "route_deployment_a");
            assert_eq!(pointer.get::<_, i64>(1), 1);
            assert_eq!(
                pointer.get::<_, String>(2),
                installed.binding().reference_sha256().as_str()
            );
            assert_eq!(pointer.get::<_, String>(3), "active");
            assert_eq!(
                pointer.get::<_, String>(4),
                installed.binding().reference().signer.active_kid_for_test()
            );
            assert_eq!(pointer.get::<_, i64>(5), 1);
            assert_eq!(
                pointer.get::<_, String>(6),
                installed
                    .binding()
                    .reference()
                    .public_key_ring_digest
                    .as_str()
            );
            assert_eq!(pointer.get::<_, String>(7), "route_secret_a");
            Ok(())
        })
        .unwrap();
}

#[test]
fn startup_refuses_conflict_or_valid_successor_without_mutation() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let initial = installation(SIGNER);
    store
        .install_route_grant_v2_signer_authority(&initial)
        .unwrap();
    let baseline = row_versions(&store);

    let mut disabled = initial.binding().reference().clone();
    disabled.signer = RouteGrantV2SignerSelection::Disabled;
    let disabled_bytes = encode_route_grant_v2_signer_reference(&disabled).unwrap();
    let conflict = installation(&disabled_bytes);
    assert!(store
        .install_route_grant_v2_signer_authority(&conflict)
        .is_err());
    assert!(!store
        .route_grant_v2_signer_is_current_for_test(conflict.binding())
        .unwrap());

    let mut successor = initial.binding().reference().clone();
    successor.signer_revision = Epoch::new(2).unwrap();
    successor.expected_previous = Some(RouteGrantV2SignerExpectedPrevious {
        signer_revision: Epoch::new(1).unwrap(),
        signer_reference_sha256: initial.binding().reference_sha256().clone(),
    });
    let successor_bytes = encode_route_grant_v2_signer_reference(&successor).unwrap();
    let successor = installation(&successor_bytes);
    assert!(store
        .install_route_grant_v2_signer_authority(&successor)
        .is_err());
    assert_eq!(row_versions(&store), baseline);
    assert!(store
        .route_grant_v2_signer_is_current_for_test(initial.binding())
        .unwrap());
}

#[test]
fn disabled_initial_authority_persists_without_a_key_lineage() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let mut reference = decode_route_grant_v2_signer_reference(SIGNER).unwrap();
    reference.signer = RouteGrantV2SignerSelection::Disabled;
    let bytes = encode_route_grant_v2_signer_reference(&reference).unwrap();
    let disabled = installation(&bytes);
    store
        .install_route_grant_v2_signer_authority(&disabled)
        .unwrap();
    assert!(store
        .route_grant_v2_signer_is_current_for_test(disabled.binding())
        .unwrap());
    store
        .with(|client| {
            assert_eq!(
                client
                    .query_one("SELECT count(*) FROM route_v2_signer_key_lineage", &[])?
                    .get::<_, i64>(0),
                0
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn immutable_rows_and_projection_drift_fail_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let installed = installation(SIGNER);
    store
        .install_route_grant_v2_signer_authority(&installed)
        .unwrap();
    store
        .with(|client| {
            assert!(client
                .execute(
                    "UPDATE route_v2_signer_revisions
                        SET signer_reference_bytes='{}'::BYTEA",
                    &[],
                )
                .is_err());
            assert!(client
                .execute(
                    "UPDATE route_v2_signer_key_lineage
                        SET secret_reference_id='route_secret_b'",
                    &[],
                )
                .is_err());
            client.batch_execute(
                "ALTER TABLE route_v2_signer_key_lineage
                     DISABLE TRIGGER route_v2_signer_key_lineage_update;
                 UPDATE route_v2_signer_key_lineage
                    SET public_key_spki='MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk'",
            )?;
            Ok(())
        })
        .unwrap();
    assert!(store
        .route_grant_v2_signer_is_current_for_test(installed.binding())
        .is_err());
}

#[test]
fn shared_route_authority_lock_orders_initial_signer_install() {
    let url = crate::testsupport::isolated_control_store_url();
    drop(Store::connect(&url, None).unwrap());
    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut snapshot = reader.transaction().unwrap();
    snapshot
        .query_one(
            "SELECT pg_advisory_xact_lock_shared(hashtextextended(
                current_schema() || ':route-v2-gateway-identity', 0::BIGINT))",
            &[],
        )
        .unwrap();

    let (send, receive) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let store = Store::connect(&url, None).unwrap();
        send.send(store.install_route_grant_v2_signer_authority(&installation(SIGNER)))
            .unwrap();
    });
    assert!(matches!(
        receive.recv_timeout(Duration::from_millis(150)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    snapshot.commit().unwrap();
    receive
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    writer.join().unwrap();
}

#[test]
fn normal_rotation_requires_both_exact_full_ring_acks_and_emits_only_a_receipt() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let initial = installation(SIGNER);
    store
        .install_route_grant_v2_signer_authority(&initial)
        .unwrap();
    let mut admission = establish_empty_admission_for(&store, &release(), "rotation", 31);
    insert_policy_on_store_for_test(&store, &schedulable_policy(&admission)).unwrap();

    let ring_one = initial_ring();
    let ring_two = successor_ring(&ring_one, vec![ring_one.keys[0].clone(), other_entry()]);
    let reference_one = initial.binding().reference().clone();
    let reference_two =
        successor_reference(&reference_one, reference_one.signer.clone(), &ring_two);
    let overlap = RouteGrantV2SigningAuthorityCommand {
        command_id: random(1),
        successor: reference_two.clone(),
        kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
            successor_ring: ring_two.clone(),
            new_secret_reference_id: id("route_secret_b"),
        },
    };
    assert_applied(apply(&store, &overlap));

    let reference_three = successor_reference(
        &reference_two,
        RouteGrantV2SignerSelection::Active {
            active_kid: other_entry().kid,
            secret_reference_id: id("route_secret_b"),
        },
        &ring_two,
    );
    let switch = RouteGrantV2SigningAuthorityCommand {
        command_id: random(2),
        successor: reference_three.clone(),
        kind: RouteGrantV2SigningAuthorityCommandKind::SwitchActive,
    };

    assert_precondition_failed(apply(&store, &switch));
    admission = accept_ring_admission_for_test(&store, &admission, &ring_one, 2, 2);
    assert_precondition_failed(apply(&store, &switch));
    accept_partial_heartbeat_for_test(&store, &admission);
    assert_precondition_failed(apply(&store, &switch));
    admission = accept_ring_admission_for_test(&store, &admission, &ring_two, 3, 4);
    replace_agent_session_for_test(&store, &admission, &release(), 32);
    assert_precondition_failed(apply(&store, &switch));
    admission =
        refresh_assigned_admission_for_test(&store, &admission.node_identity, &release(), 33);
    admission = accept_ring_admission_for_test(&store, &admission, &ring_two, 2, 2);
    let second_admission = establish_empty_admission_for(&store, &release(), "rotation_b", 34);
    insert_policy_on_store_for_test(&store, &schedulable_policy(&second_admission)).unwrap();
    assert_precondition_failed(apply(&store, &switch));
    let second_admission =
        accept_ring_admission_for_test(&store, &second_admission, &ring_two, 2, 2);
    assert_applied(apply(&store, &switch));

    let pipelined_ring = successor_ring(
        &ring_two,
        vec![
            ring_two.keys[0].clone(),
            ring_two.keys[1].clone(),
            third_entry(),
        ],
    );
    let pipelined_reference = successor_reference(
        &reference_three,
        reference_three.signer.clone(),
        &pipelined_ring,
    );
    assert_precondition_failed(apply(
        &store,
        &RouteGrantV2SigningAuthorityCommand {
            command_id: random(99),
            successor: pipelined_reference,
            kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                successor_ring: pipelined_ring,
                new_secret_reference_id: id("route_secret_c"),
            },
        },
    ));

    store
        .with(|client| {
            client.batch_execute(
                "ALTER TABLE route_v2_signer_retirements
                     DISABLE TRIGGER route_v2_signer_retirement_update;
                 DO $$
                 DECLARE changed BIGINT;
                 BEGIN
                   UPDATE route_v2_signer_retirements
                      SET last_old_issue_at_unix_ms =
                          floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT - 305001
                    WHERE deployment_id='route_deployment_a' AND source='normal';
                   GET DIAGNOSTICS changed = ROW_COUNT;
                   IF changed <> 1 THEN
                     RAISE EXCEPTION 'test retirement fixture changed % rows', changed;
                   END IF;
                 END
                 $$;
                 ALTER TABLE route_v2_signer_retirements
                     ENABLE TRIGGER route_v2_signer_retirement_update;",
            )
        })
        .unwrap();

    let ring_three = successor_ring(&ring_two, vec![other_entry()]);
    let reference_four = successor_reference(
        &reference_three,
        reference_three.signer.clone(),
        &ring_three,
    );
    let publish_new_only = RouteGrantV2SigningAuthorityCommand {
        command_id: random(3),
        successor: reference_four.clone(),
        kind: RouteGrantV2SigningAuthorityCommandKind::PublishNewOnly {
            successor_ring: ring_three.clone(),
        },
    };
    assert_applied(apply(&store, &publish_new_only));

    let reference_five =
        successor_reference(&reference_four, reference_four.signer.clone(), &ring_three);
    let retire = RouteGrantV2SigningAuthorityCommand {
        command_id: random(4),
        successor: reference_five.clone(),
        kind: RouteGrantV2SigningAuthorityCommandKind::Retire,
    };
    assert_precondition_failed(apply(&store, &retire));
    let _new_only_admission = accept_ring_admission_for_test(&store, &admission, &ring_three, 3, 3);
    let _second_new_only_admission =
        accept_ring_admission_for_test(&store, &second_admission, &ring_three, 3, 3);
    let result = assert_applied(apply(&store, &retire));
    let RouteGrantV2SigningAuthorityCommandResult::Applied {
        secret_deletion_authorizations,
        ..
    } = &result
    else {
        unreachable!()
    };
    assert_eq!(secret_deletion_authorizations.len(), 1);
    let receipt = secret_deletion_authorizations[0].clone();
    assert_eq!(receipt.kid, ring_one.keys[0].kid);
    assert_eq!(receipt.secret_reference_id, id("route_secret_a"));

    let before_replay = row_versions(&store);
    assert_eq!(
        apply(&store, &retire),
        RouteGrantV2SigningAuthorityStoreOutcome::Stored(result.clone())
    );
    assert_eq!(
        row_versions(&store),
        before_replay,
        "exact replay wrote rows"
    );

    let reused_key_ring =
        successor_ring(&ring_three, vec![ring_one.keys[0].clone(), other_entry()]);
    assert_precondition_failed(apply(
        &store,
        &RouteGrantV2SigningAuthorityCommand {
            command_id: random(5),
            successor: successor_reference(
                &reference_five,
                reference_five.signer.clone(),
                &reused_key_ring,
            ),
            kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                successor_ring: reused_key_ring,
                new_secret_reference_id: id("route_secret_c"),
            },
        },
    ));
    let reused_secret_ring = successor_ring(&ring_three, vec![other_entry(), third_entry()]);
    assert_precondition_failed(apply(
        &store,
        &RouteGrantV2SigningAuthorityCommand {
            command_id: random(6),
            successor: successor_reference(
                &reference_five,
                reference_five.signer.clone(),
                &reused_secret_ring,
            ),
            kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                successor_ring: reused_secret_ring,
                new_secret_reference_id: id("route_secret_a"),
            },
        },
    ));
    assert_eq!(row_versions(&store), before_replay, "ABA retry wrote rows");

    let mut conflicting = retire.clone();
    conflicting.kind = RouteGrantV2SigningAuthorityCommandKind::Activate;
    assert_eq!(
        apply(&store, &conflicting),
        RouteGrantV2SigningAuthorityStoreOutcome::CommandIdConflict
    );
    let mut different_successor = retire.clone();
    different_successor.successor.deployment_id = id("route_deployment_conflict");
    assert_eq!(
        apply(&store, &different_successor),
        RouteGrantV2SigningAuthorityStoreOutcome::CommandIdConflict
    );
    assert_eq!(row_versions(&store), before_replay);

    store
        .with(|client| {
            assert!(client
                .execute(
                    "UPDATE route_v2_signer_retirements
                        SET last_old_issue_at_unix_ms=last_old_issue_at_unix_ms + 1",
                    &[],
                )
                .is_err());
            assert!(client
                .execute(
                    "UPDATE route_v2_signing_authority_commands SET outcome='{}'::BYTEA",
                    &[],
                )
                .is_err());
            let row = client
                .query_one(
                    "SELECT lineage.state, retirement.state,
                        receipt.authorization_id,
                        receipt.secret_reference_id
                   FROM route_v2_signer_key_lineage lineage
                   JOIN route_v2_signer_retirements retirement
                     ON retirement.deployment_id=lineage.deployment_id
                    AND retirement.kid=lineage.kid
                   JOIN route_v2_secret_deletion_authorizations receipt
                     ON receipt.deployment_id=retirement.deployment_id
                    AND receipt.kid=retirement.kid
                    AND receipt.secret_reference_id=retirement.secret_reference_id
                  WHERE lineage.kid=$1",
                    &[&ring_one.keys[0].kid.as_str()],
                )
                .unwrap();
            assert_eq!(row.get::<_, String>(0), "retired");
            assert_eq!(row.get::<_, String>(1), "retired");
            assert_eq!(row.get::<_, String>(2), receipt.authorization_id.as_str());
            assert_eq!(row.get::<_, String>(3), "route_secret_a");
            Ok(())
        })
        .unwrap();
}

#[test]
fn emergency_disable_is_immediate_and_reactivation_retires_only_after_fresh_ring() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let initial = installation(SIGNER);
    store
        .install_route_grant_v2_signer_authority(&initial)
        .unwrap();
    let ring_one = initial_ring();
    let reference_one = initial.binding().reference().clone();

    let overlap_ring = successor_ring(&ring_one, vec![ring_one.keys[0].clone(), other_entry()]);
    let overlap_reference =
        successor_reference(&reference_one, reference_one.signer.clone(), &overlap_ring);
    assert_applied(apply(
        &store,
        &RouteGrantV2SigningAuthorityCommand {
            command_id: random(10),
            successor: overlap_reference.clone(),
            kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
                successor_ring: overlap_ring.clone(),
                new_secret_reference_id: id("route_secret_b"),
            },
        },
    ));

    let disabled_reference = successor_reference(
        &overlap_reference,
        RouteGrantV2SignerSelection::Disabled,
        &overlap_ring,
    );
    let disable = RouteGrantV2SigningAuthorityCommand {
        command_id: random(11),
        successor: disabled_reference.clone(),
        kind: RouteGrantV2SigningAuthorityCommandKind::Disable,
    };
    assert_applied(apply(&store, &disable));
    assert!(!store
        .route_grant_v2_signer_is_current_for_test(initial.binding())
        .unwrap());

    let fresh_ring = successor_ring(&overlap_ring, vec![third_entry()]);
    let fresh_disabled = successor_reference(
        &disabled_reference,
        RouteGrantV2SignerSelection::Disabled,
        &fresh_ring,
    );
    let publish_fresh = RouteGrantV2SigningAuthorityCommand {
        command_id: random(12),
        successor: fresh_disabled.clone(),
        kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
            successor_ring: fresh_ring.clone(),
            new_secret_reference_id: id("route_secret_c"),
        },
    };
    let admission = establish_empty_admission_for(&store, &release(), "emergency", 61);
    let mut cordoned = schedulable_policy(&admission);
    cordoned.scheduling_state = RuntimeSchedulingState::Cordoned;
    insert_policy_on_store_for_test(&store, &cordoned).unwrap();
    let admission = refresh_assigned_admission_with_residue_for_test(
        &store,
        &admission.node_identity,
        &release(),
        62,
        vec![NodeResidue::ControlSocket {
            socket_path: HostPath::new("/run/cats/orphan-route.sock").unwrap(),
            role_hint: None,
            ownership_token: OwnershipTokenEvidence::Missing,
        }],
    );
    assert_precondition_failed(apply(&store, &publish_fresh));
    let admission =
        refresh_assigned_admission_for_test(&store, &admission.node_identity, &release(), 63);
    assert_applied(apply(&store, &publish_fresh));

    let active_reference = successor_reference(
        &fresh_disabled,
        RouteGrantV2SignerSelection::Active {
            active_kid: third_entry().kid,
            secret_reference_id: id("route_secret_c"),
        },
        &fresh_ring,
    );
    let activate = RouteGrantV2SigningAuthorityCommand {
        command_id: random(13),
        successor: active_reference,
        kind: RouteGrantV2SigningAuthorityCommandKind::Activate,
    };
    assert_precondition_failed(apply(&store, &activate));
    let _fresh_ack = accept_ring_admission_for_test(&store, &admission, &fresh_ring, 2, 2);
    let result = assert_applied(apply(&store, &activate));
    let RouteGrantV2SigningAuthorityCommandResult::Applied {
        secret_deletion_authorizations,
        ..
    } = result
    else {
        unreachable!()
    };
    assert_eq!(secret_deletion_authorizations.len(), 2);
    let retired = secret_deletion_authorizations
        .iter()
        .map(|receipt| (receipt.kid.clone(), receipt.secret_reference_id.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        retired,
        std::collections::BTreeSet::from([
            (ring_one.keys[0].kid.clone(), id("route_secret_a")),
            (other_entry().kid, id("route_secret_b")),
        ])
    );
    store
        .with(|client| {
            let pointer = client.query_one(
                "SELECT signer_state, active_kid, public_key_ring_version
                   FROM route_v2_signing_authority WHERE singleton",
                &[],
            )?;
            assert_eq!(pointer.get::<_, String>(0), "active");
            assert_eq!(pointer.get::<_, String>(1), third_entry().kid.as_str());
            assert_eq!(pointer.get::<_, i64>(2), 3);
            Ok(())
        })
        .unwrap();
}

#[test]
fn cancelled_command_is_zero_write_and_response_loss_exactly_replays() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let initial = installation(SIGNER);
    store
        .install_route_grant_v2_signer_authority(&initial)
        .unwrap();
    let ring_one = initial_ring();
    let ring_two = successor_ring(&ring_one, vec![ring_one.keys[0].clone(), other_entry()]);
    let reference_two = successor_reference(
        initial.binding().reference(),
        initial.binding().reference().signer.clone(),
        &ring_two,
    );
    let overlap = RouteGrantV2SigningAuthorityCommand {
        command_id: random(20),
        successor: reference_two,
        kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
            successor_ring: ring_two,
            new_secret_reference_id: id("route_secret_b"),
        },
    };
    let before = row_versions(&store);
    let cancelled = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
    cancelled.cancel();
    assert!(store
        .apply_route_grant_v2_signing_authority_command(&overlap, &cancelled)
        .is_err());
    assert_eq!(row_versions(&store), before);

    store.inject_committed_response_loss_once();
    assert!(store
        .apply_route_grant_v2_signing_authority_command(
            &overlap,
            &AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5)),
        )
        .is_err());
    let committed = row_versions(&store);
    assert_ne!(committed, before);
    assert_applied(apply(&store, &overlap));
    assert_eq!(row_versions(&store), committed);
}

#[test]
fn concurrent_control_replicas_apply_one_exact_command_once() {
    let url = crate::testsupport::isolated_control_store_url();
    let setup = Store::connect(&url, None).unwrap();
    let initial = installation(SIGNER);
    setup
        .install_route_grant_v2_signer_authority(&initial)
        .unwrap();
    let ring_one = initial_ring();
    let ring_two = successor_ring(&ring_one, vec![ring_one.keys[0].clone(), other_entry()]);
    let command = Arc::new(RouteGrantV2SigningAuthorityCommand {
        command_id: random(30),
        successor: successor_reference(
            initial.binding().reference(),
            initial.binding().reference().signer.clone(),
            &ring_two,
        ),
        kind: RouteGrantV2SigningAuthorityCommandKind::PublishOverlap {
            successor_ring: ring_two,
            new_secret_reference_id: id("route_secret_b"),
        },
    });
    let barrier = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let url = url.clone();
            let command = Arc::clone(&command);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = Store::connect(&url, None).unwrap();
                barrier.wait();
                apply(&store, &command)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes[0], outcomes[1]);
    assert!(matches!(
        outcomes[0],
        RouteGrantV2SigningAuthorityStoreOutcome::Stored(
            RouteGrantV2SigningAuthorityCommandResult::Applied { .. }
        )
    ));
    setup
        .with(|client| {
            let row = client.query_one(
                "SELECT
                    (SELECT count(*) FROM route_v2_signer_revisions),
                    (SELECT count(*) FROM route_v2_public_key_ring_revisions),
                    (SELECT count(*) FROM route_v2_signer_key_lineage),
                    (SELECT count(*) FROM route_v2_signing_authority_commands)",
                &[],
            )?;
            assert_eq!(row.get::<_, i64>(0), 2);
            assert_eq!(row.get::<_, i64>(1), 2);
            assert_eq!(row.get::<_, i64>(2), 2);
            assert_eq!(row.get::<_, i64>(3), 1);
            Ok(())
        })
        .unwrap();
}

#[test]
fn retention_boundary_is_strict() {
    let issue = UnixMillis::new(10).unwrap();
    let equality = UnixMillis::new(10 + RETENTION_MILLIS).unwrap();
    let after = UnixMillis::new(11 + RETENTION_MILLIS).unwrap();
    assert!(matches!(
        strictly_after_retention(equality, issue),
        Ok(false)
    ));
    assert!(matches!(strictly_after_retention(after, issue), Ok(true)));
}

trait ActiveKidForTest {
    fn active_kid_for_test(&self) -> String;
}

impl ActiveKidForTest for RouteGrantV2SignerSelection {
    fn active_kid_for_test(&self) -> String {
        match self {
            RouteGrantV2SignerSelection::Active { active_kid, .. } => {
                active_kid.as_str().to_owned()
            }
            RouteGrantV2SignerSelection::Disabled => String::new(),
        }
    }
}

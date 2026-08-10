//! Real PostgreSQL acceptance for the independent Gateway workload authority.

use std::sync::{Arc, Barrier};

use cats_api::gateway_workload_identity::{
    GatewayWorkloadCredentialPolicy, GatewayWorkloadCredentialScope,
    GatewayWorkloadIdentityAuthority, GatewayWorkloadIdentityExpectedPrevious,
};
use cats_api::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, Base64UrlNoPad, ContractVersion, Epoch, Id, Sha256Digest,
};

use crate::store::Store;

const SPKI_A: &str = "MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8";
const SPKI_B: &str = "MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk";

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn credential(
    credential_id: &str,
    spki: &str,
    scope: GatewayWorkloadCredentialScope,
) -> GatewayWorkloadCredentialPolicy {
    GatewayWorkloadCredentialPolicy {
        credential_id: id(credential_id),
        public_key_spki: Base64UrlNoPad::new(spki).unwrap(),
        scope,
    }
}

fn fleet_credential(credential_id: &str, spki: &str) -> GatewayWorkloadCredentialPolicy {
    credential(credential_id, spki, GatewayWorkloadCredentialScope::Fleet)
}

fn authority(
    revision: u64,
    credentials: Vec<GatewayWorkloadCredentialPolicy>,
    previous: Option<&GatewayWorkloadIdentityAuthority>,
) -> GatewayWorkloadIdentityAuthority {
    GatewayWorkloadIdentityAuthority {
        version: ContractVersion::V1,
        authority_id: id("gateway_authority_a"),
        fleet_id: id("fleet_a"),
        policy_revision: Epoch::new(revision).unwrap(),
        expected_previous: previous.map(|previous| GatewayWorkloadIdentityExpectedPrevious {
            policy_revision: previous.policy_revision,
            policy_sha256: previous.digest().unwrap(),
        }),
        credentials,
    }
}

fn spki_digest(spki: &str) -> Sha256Digest {
    canonical_ed25519_spki_sha256(&Base64UrlNoPad::new(spki).unwrap()).unwrap()
}

fn row_versions(store: &Store) -> Vec<String> {
    store
        .with(|client| {
            client
                .query(
                    "SELECT table_name, xmin
                       FROM (
                         SELECT 'authority' AS table_name, xmin::TEXT AS xmin
                           FROM route_v2_gateway_identity_authority
                         UNION ALL
                         SELECT 'revision', xmin::TEXT
                           FROM route_v2_gateway_identity_revisions
                         UNION ALL
                         SELECT 'lineage:' || credential_id, xmin::TEXT
                           FROM route_v2_gateway_credential_lineage
                         UNION ALL
                         SELECT 'current:' || credential_id, xmin::TEXT
                           FROM route_v2_gateway_current_credentials
                       ) rows
                      ORDER BY table_name",
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

#[test]
fn initial_exact_replay_rotation_revocation_and_empty_disable_are_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = fleet_credential("gateway_a", SPKI_A);
    let b = credential(
        "gateway_b",
        SPKI_B,
        GatewayWorkloadCredentialScope::Workspaces {
            workspace_ids: vec![id("workspace_a")],
        },
    );
    let revision1 = authority(1, vec![a.clone()], None);
    store
        .install_gateway_workload_identity_authority(&revision1)
        .unwrap();
    let before_replay = row_versions(&store);
    store
        .install_gateway_workload_identity_authority(&revision1)
        .unwrap();
    assert_eq!(
        row_versions(&store),
        before_replay,
        "exact replay wrote rows"
    );

    let principal_a = store
        .authenticate_gateway_tls_peer_for_test(&spki_digest(SPKI_A))
        .unwrap()
        .unwrap();
    assert_eq!(principal_a.credential_id, a.credential_id);
    assert!(store
        .gateway_principal_authorizes_workspace_for_test(&principal_a, &id("workspace_z"))
        .unwrap());
    assert!(store
        .authenticate_gateway_tls_peer_for_test(&Sha256Digest::from_bytes([9; 32]))
        .unwrap()
        .is_none());

    let revision2 = authority(2, vec![a.clone(), b.clone()], Some(&revision1));
    store
        .install_gateway_workload_identity_authority(&revision2)
        .unwrap();
    let principal_b = store
        .authenticate_gateway_tls_peer_for_test(&spki_digest(SPKI_B))
        .unwrap()
        .unwrap();
    assert!(store
        .gateway_principal_authorizes_workspace_for_test(&principal_b, &id("workspace_a"))
        .unwrap());
    assert!(!store
        .gateway_principal_authorizes_workspace_for_test(&principal_b, &id("workspace_b"))
        .unwrap());

    let revision3 = authority(3, vec![b.clone()], Some(&revision2));
    store
        .install_gateway_workload_identity_authority(&revision3)
        .unwrap();
    assert!(store
        .authenticate_gateway_tls_peer_for_test(&spki_digest(SPKI_A))
        .unwrap()
        .is_none());
    assert!(!store
        .gateway_principal_authorizes_workspace_for_test(&principal_a, &id("workspace_a"))
        .unwrap());
    assert!(!store
        .gateway_principal_authorizes_workspace_for_test(&principal_b, &id("workspace_a"))
        .unwrap());
    let principal_b_revision3 = store
        .authenticate_gateway_tls_peer_for_test(&spki_digest(SPKI_B))
        .unwrap()
        .unwrap();
    assert_eq!(
        principal_b_revision3.policy_revision,
        Epoch::new(3).unwrap()
    );
    assert!(store
        .gateway_principal_authorizes_workspace_for_test(&principal_b_revision3, &id("workspace_a"))
        .unwrap());

    let reintroduced = authority(4, vec![a, b.clone()], Some(&revision3));
    assert!(store
        .install_gateway_workload_identity_authority(&reintroduced)
        .is_err());
    assert!(store
        .install_gateway_workload_identity_authority(&revision2)
        .is_err());

    let revision4 = authority(4, Vec::new(), Some(&revision3));
    store
        .install_gateway_workload_identity_authority(&revision4)
        .unwrap();
    assert!(store
        .authenticate_gateway_tls_peer_for_test(&spki_digest(SPKI_B))
        .unwrap()
        .is_none());
    store
        .with(|client| {
            assert_eq!(
                client
                    .query_one(
                        "SELECT current_policy_revision
                           FROM route_v2_gateway_identity_authority WHERE singleton",
                        &[],
                    )?
                    .get::<_, i64>(0),
                4
            );
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM route_v2_gateway_current_credentials",
                        &[],
                    )?
                    .get::<_, i64>(0),
                0
            );
            let states = client.query(
                "SELECT credential_id, state
                   FROM route_v2_gateway_credential_lineage
                  ORDER BY credential_id COLLATE \"C\"",
                &[],
            )?;
            assert_eq!(states.len(), 2);
            assert!(states
                .iter()
                .all(|row| row.get::<_, String>(1) == "revoked"));
            Ok(())
        })
        .unwrap();
}

#[test]
fn same_revision_conflict_gap_and_permanent_id_or_spki_reuse_do_not_mutate() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let a = fleet_credential("gateway_a", SPKI_A);
    let b = fleet_credential("gateway_b", SPKI_B);
    let revision1 = authority(1, vec![a.clone()], None);
    store
        .install_gateway_workload_identity_authority(&revision1)
        .unwrap();
    let baseline = row_versions(&store);

    let same_revision_conflict = authority(1, vec![a.clone(), b.clone()], None);
    assert!(store
        .install_gateway_workload_identity_authority(&same_revision_conflict)
        .is_err());
    let gap = authority(3, vec![a.clone()], Some(&revision1));
    assert!(store
        .install_gateway_workload_identity_authority(&gap)
        .is_err());
    assert_eq!(row_versions(&store), baseline);

    let revision2 = authority(2, Vec::new(), Some(&revision1));
    store
        .install_gateway_workload_identity_authority(&revision2)
        .unwrap();
    let reuse_id = authority(
        3,
        vec![fleet_credential("gateway_a", SPKI_B)],
        Some(&revision2),
    );
    assert!(store
        .install_gateway_workload_identity_authority(&reuse_id)
        .is_err());
    let reuse_spki = authority(
        3,
        vec![fleet_credential("gateway_c", SPKI_A)],
        Some(&revision2),
    );
    assert!(store
        .install_gateway_workload_identity_authority(&reuse_spki)
        .is_err());
    store
        .with(|client| {
            assert_eq!(
                client
                    .query_one(
                        "SELECT current_policy_revision
                           FROM route_v2_gateway_identity_authority WHERE singleton",
                        &[],
                    )?
                    .get::<_, i64>(0),
                2
            );
            assert_eq!(
                client
                    .query_one(
                        "SELECT count(*) FROM route_v2_gateway_identity_revisions",
                        &[],
                    )?
                    .get::<_, i64>(0),
                2
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn concurrent_successor_cas_has_one_exact_winner() {
    let url = crate::testsupport::isolated_control_store_url();
    let seed = Store::connect(&url, None).unwrap();
    let a = fleet_credential("gateway_a", SPKI_A);
    let initial = authority(1, vec![a.clone()], None);
    seed.install_gateway_workload_identity_authority(&initial)
        .unwrap();
    let candidates = [
        authority(
            2,
            vec![credential(
                "gateway_a",
                SPKI_A,
                GatewayWorkloadCredentialScope::Workspaces {
                    workspace_ids: vec![id("workspace_a")],
                },
            )],
            Some(&initial),
        ),
        authority(
            2,
            vec![credential(
                "gateway_a",
                SPKI_A,
                GatewayWorkloadCredentialScope::Workspaces {
                    workspace_ids: vec![id("workspace_b")],
                },
            )],
            Some(&initial),
        ),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let handles = candidates.map(|candidate| {
        let url = url.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let store = Store::connect(&url, None).unwrap();
            barrier.wait();
            store.install_gateway_workload_identity_authority(&candidate)
        })
    });
    let outcomes = handles.map(|handle| handle.join().unwrap());
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
    seed.with(|client| {
        assert_eq!(
            client
                .query_one(
                    "SELECT current_policy_revision
                       FROM route_v2_gateway_identity_authority WHERE singleton",
                    &[],
                )?
                .get::<_, i64>(0),
            2
        );
        assert_eq!(
            client
                .query_one(
                    "SELECT count(*) FROM route_v2_gateway_identity_revisions",
                    &[],
                )?
                .get::<_, i64>(0),
            2
        );
        assert_eq!(
            client
                .query_one(
                    "SELECT count(*) FROM route_v2_gateway_current_credentials",
                    &[],
                )?
                .get::<_, i64>(0),
            1
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn projection_drift_and_partial_revocation_fail_closed() {
    let store = Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
    let initial = authority(1, vec![fleet_credential("gateway_a", SPKI_A)], None);
    store
        .install_gateway_workload_identity_authority(&initial)
        .unwrap();
    store
        .with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "UPDATE route_v2_gateway_credential_lineage
                    SET state='revoked', revoked_at_unix_ms=first_committed_at_unix_ms
                  WHERE credential_id='gateway_a'",
                &[],
            )?;
            assert!(transaction.commit().is_err());
            Ok(())
        })
        .unwrap();
    assert!(store
        .authenticate_gateway_tls_peer_for_test(&spki_digest(SPKI_A))
        .unwrap()
        .is_some());

    store
        .with(|client| {
            client.execute(
                "UPDATE route_v2_gateway_current_credentials
                    SET scope='{\"kind\":\"workspaces\",\"workspace_ids\":[\"workspace_z\"]}'::JSONB
                  WHERE credential_id='gateway_a'",
                &[],
            )?;
            Ok(())
        })
        .unwrap();
    let error = store
        .authenticate_gateway_tls_peer_for_test(&spki_digest(SPKI_A))
        .unwrap_err();
    assert_eq!(error.code, cats_api::error::ErrorCode::Internal);
}

//! Real PostgreSQL acceptance for the startup-pinned Route v2 signer binding.

use std::sync::mpsc;
use std::time::Duration;

use cats_api::route_grant_v2::{
    decode_route_grant_v2_public_key_ring, decode_route_grant_v2_signer_reference,
    encode_route_grant_v2_signer_reference, RouteGrantV2SignerExpectedPrevious,
    RouteGrantV2SignerSelection,
};
use cats_api::runtime_reconciliation::Epoch;

use crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority;
use crate::store::Store;

const RING: &[u8] = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb","public_key_spki":"MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"}]}"#;
const SIGNER: &[u8] = br#"{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:4e6fec49756e03044438af279f7bfd9507f06cf065ff0673447bd6377cd07ac0"}"#;
const PRIVATE_KEY: &[u8] =
    include_bytes!("../../../../tests/fixtures/route_grant_private_ed25519.pem");

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

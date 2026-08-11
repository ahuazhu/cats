//! Helpers for pointing a control Store at a disposable PostgreSQL schema.
//!
//! Not part of the public API: this exists so the crate's own tests and the
//! workspace's integration/E2E suites can isolate per test without each
//! reinventing the DSN handling. The server named by `CATS_TEST_POSTGRES_URL`
//! is treated as disposable; schemas are created and never dropped.

use std::sync::Arc;

use postgres::NoTls;

struct UnavailableImageBlob;

impl cats_storage::BlobStore for UnavailableImageBlob {
    fn put_immutable(&self, key: &str, _data: &[u8]) -> cats_storage::blob::Result<()> {
        Err(unavailable_blob_error(key))
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        Err(unavailable_blob_error(key))
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        Err(unavailable_blob_error(key))
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        Err(unavailable_blob_error(key))
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        Err(unavailable_blob_error(prefix))
    }
}

fn unavailable_blob_error(key: &str) -> cats_storage::BlobError {
    cats_storage::BlobError::Backend {
        key: key.to_string(),
        message: "test image blob is intentionally unavailable".into(),
    }
}

pub fn unavailable_image_blob() -> Arc<dyn cats_storage::BlobStore> {
    Arc::new(UnavailableImageBlob)
}

/// Explicit typed receipt injection for tests that never exercise the
/// production fixed-path filesystem reader.
pub fn test_guest_runtime_profile_receipt(
) -> cats_api::runtime_reconciliation::GuestRuntimeProfileReceipt {
    use cats_api::runtime_reconciliation::{
        AsciiText, ContractVersion, GuestRuntimeProfileReceipt, Sha256Digest,
    };

    let digest = |byte: char| {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64)))
            .expect("test digest is valid")
    };
    GuestRuntimeProfileReceipt {
        version: ContractVersion::V1,
        kernel_digest: digest('1'),
        initramfs_digest: Some(digest('2')),
        kernel_cmdline: AsciiText::new("console=hvc0 root=/dev/vda")
            .expect("test command line is valid"),
        guest_agent_protocol_version: ContractVersion::V1,
    }
}

/// Revision-one deployment provisioner trust for HTTP/server tests. Tests
/// inject the typed value and therefore do not weaken the production fixed-
/// path filesystem reader.
pub fn test_runtime_provisioner_trust_bundle(
) -> cats_api::runtime_reconciliation::RuntimeProvisionerTrustBundle {
    use cats_api::runtime_reconciliation::{
        Base64UrlNoPad, ContractVersion, Epoch, Id, RuntimeProvisionerCredential,
        RuntimeProvisionerTrustBundle,
    };

    RuntimeProvisionerTrustBundle {
        version: ContractVersion::V1,
        deployment_id: Id::new("deployment_a".to_owned()).expect("valid test deployment ID"),
        trust_revision: Epoch::new(1).expect("positive test trust revision"),
        expected_previous: None,
        credentials: vec![RuntimeProvisionerCredential {
            credential_id: Id::new("provisioner_a".to_owned()).expect("valid test credential ID"),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
            )
            .expect("canonical test Ed25519 SPKI"),
        }],
    }
}

/// Seed a disposable schema with a typed provisioner-trust revision before a
/// server using the next revision is started.
pub fn seed_runtime_provisioner_trust_bundle(
    dsn: &str,
    bundle: &cats_api::runtime_reconciliation::RuntimeProvisionerTrustBundle,
) {
    let dsn = dsn.to_owned();
    let bundle = bundle.clone();
    crate::store::off_runtime(move || {
        let store = crate::store::Store::connect(&dsn, None).expect("connect test control Store");
        store
            .install_runtime_provisioner_trust_bundle(&bundle)
            .expect("install test runtime provisioner trust bundle");
    });
}

/// Advance provisioner trust through the production typed Store while an
/// isolated HTTP server remains live.
pub async fn install_runtime_provisioner_trust_bundle(
    store: &Arc<crate::store::Store>,
    bundle: cats_api::runtime_reconciliation::RuntimeProvisionerTrustBundle,
) {
    store
        .execute(move |store| store.install_runtime_provisioner_trust_bundle(&bundle))
        .await
        .expect("install test runtime provisioner trust bundle");
}

pub fn route_grant_signer() -> Arc<crate::route_grant::RouteGrantSigner> {
    Arc::new(
        crate::route_grant::RouteGrantSigner::from_ed25519_pem(
            include_bytes!("../../tests/fixtures/route_grant_private_ed25519.pem"),
            include_bytes!("../../tests/fixtures/route_grant_public_ed25519.pem"),
            120,
        )
        .expect("test Route Grant key is valid"),
    )
}

/// Base DSN of the disposable test server.
///
/// Panics with instructions when unset: silently skipping the store tests
/// would let the quality gate pass without exercising persistence at all.
pub fn base_url() -> String {
    std::env::var("CATS_TEST_POSTGRES_URL").expect(
        "control-plane tests need CATS_TEST_POSTGRES_URL pointing at a disposable PostgreSQL \
         server. quality.sh and CI provide one; locally:\n  docker run --rm -d --name cats-test-pg \
         -p 5433:5432 -e POSTGRES_PASSWORD=cats postgres:16\n  export \
         CATS_TEST_POSTGRES_URL=postgres://postgres:cats@127.0.0.1:5433/postgres",
    )
}

/// Create a fresh schema on the test server and return a DSN scoped to it via
/// `search_path`, suitable for `Store::connect` or a literal `Config` DSN.
pub fn isolated_control_store_url() -> String {
    let base = base_url();
    let schema = format!("t_{}", uuid::Uuid::new_v4().simple());
    // The sync postgres client cannot run on an async runtime thread, and
    // this helper is called from #[tokio::test] bodies.
    crate::store::off_runtime(|| {
        let mut admin =
            postgres::Client::connect(&base, NoTls).expect("connect disposable test PostgreSQL");
        admin
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create test schema");
    });
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

/// Provision one runtime identity through the production Store transaction.
///
/// This is intentionally test support rather than a second management API:
/// the provisioning HTTP surface belongs to a later cutover slice, while
/// transport tests need a real PostgreSQL identity authority now.
pub async fn provision_node_identity(
    store: &Arc<crate::store::Store>,
    identity: cats_api::runtime_reconciliation::NodeIdentity,
) {
    store
        .execute(move |store| store.provision_node_identity(&identity))
        .await
        .expect("provision test NodeIdentity");
}

/// Canonical database fingerprint for proving that a rejected signed runtime
/// request neither advances a sequence nor renews the current session.
pub async fn runtime_spine_state_fingerprint(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) -> String {
    store
        .execute(move |store| {
            store.with(|client| {
                client
                    .query_one(
                        "SELECT jsonb_build_object(
                            'session', (SELECT to_jsonb(s) FROM current_agent_sessions s
                                         WHERE s.node_id=$1),
                            'desired', (SELECT to_jsonb(d) FROM runtime_desired_read_states d
                                         WHERE d.node_id=$1),
                            'receive', (SELECT to_jsonb(r) FROM runtime_observation_receive_states r
                                         WHERE r.node_id=$1),
                            'inventory', (SELECT to_jsonb(i) FROM runtime_admission_inventory_states i
                                           WHERE i.node_id=$1),
                            'cat_observations', (SELECT count(*)
                                                   FROM runtime_current_cat_observations c
                                                  WHERE c.node_id=$1)
                         )::text",
                        &[&node_id.as_str()],
                    )
                    .map(|row| row.get(0))
            })
        })
        .await
        .expect("fingerprint runtime spine state")
}

/// Persisted facts used by the cross-router runtime cutover acceptance test.
///
/// The test drives only public/machine HTTP routes. This final projection is
/// deliberately read-only: it proves that replay barriers produced one
/// authority graph, that Cat-create did not fall back to the retired product
/// tables, and that observation renewed only the mutable current session.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeCutoverAcceptanceFacts {
    pub node_identity_count: i64,
    pub node_credential_lineage_count: i64,
    pub node_policy_count: i64,
    pub node_authority_apply_count: i64,
    pub registration_attempt_count: i64,
    pub current_session_count: i64,
    pub desired_read_state_count: i64,
    pub observation_receive_state_count: i64,
    pub admission_inventory_state_count: i64,
    pub current_cat_observation_count: i64,
    pub cat_record_count: i64,
    pub disk_record_count: i64,
    pub volume_record_count: i64,
    pub desired_spec_count: i64,
    pub endpoint_record_count: i64,
    pub hostname_lookup_count: i64,
    pub runtime_operation_count: i64,
    pub api_result_count: i64,
    pub retired_node_count: i64,
    pub retired_cat_count: i64,
    pub registration_attempt_lease_deadline_unix_ms: Option<i64>,
    pub current_session_lease_deadline_unix_ms: Option<i64>,
    pub desired_read_last_request_sequence: Option<i64>,
    pub stored_api_response_body: Option<Vec<u8>>,
    pub stored_persistent_disk_response_body: Option<Vec<u8>>,
}

pub async fn runtime_cutover_acceptance_facts(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) -> RuntimeCutoverAcceptanceFacts {
    store
        .execute(move |store| {
            store.with(|client| {
                client
                    .query_one(
                        "SELECT
                            (SELECT count(*) FROM node_identities),
                            (SELECT count(*) FROM runtime_node_credential_lineage),
                            (SELECT count(*) FROM runtime_node_placement_policies),
                            (SELECT count(*) FROM runtime_node_authority_apply_records),
                            (SELECT count(*) FROM agent_registration_attempts),
                            (SELECT count(*) FROM current_agent_sessions),
                            (SELECT count(*) FROM runtime_desired_read_states),
                            (SELECT count(*) FROM runtime_observation_receive_states),
                            (SELECT count(*) FROM runtime_admission_inventory_states),
                            (SELECT count(*) FROM runtime_current_cat_observations),
                            (SELECT count(*) FROM cat_records),
                            (SELECT count(*) FROM disk_records),
                            (SELECT count(*) FROM volume_records),
                            (SELECT count(*) FROM desired_runtime_specs),
                            (SELECT count(*) FROM endpoint_records),
                            (SELECT count(*) FROM hostname_desired_lookups),
                            (SELECT count(*) FROM runtime_operations),
                            (SELECT count(*) FROM api_idempotency_results),
                            (SELECT count(*) FROM nodes),
                            (SELECT count(*) FROM cats),
                            (SELECT lease_deadline_unix_ms
                               FROM agent_registration_attempts WHERE node_id=$1),
                            (SELECT lease_deadline_unix_ms
                               FROM current_agent_sessions WHERE node_id=$1),
                            (SELECT last_request_sequence
                               FROM runtime_desired_read_states WHERE node_id=$1),
                            (SELECT response_body FROM api_idempotency_results
                              WHERE canonical_route='POST /v1/workspaces/{workspace}/cats'
                              LIMIT 1),
                            (SELECT response_body FROM api_idempotency_results
                              WHERE canonical_route='POST /v1/workspaces/{workspace}/disks'
                                AND http_status=201
                              LIMIT 1)",
                        &[&node_id.as_str()],
                    )
                    .map(|row| RuntimeCutoverAcceptanceFacts {
                        node_identity_count: row.get(0),
                        node_credential_lineage_count: row.get(1),
                        node_policy_count: row.get(2),
                        node_authority_apply_count: row.get(3),
                        registration_attempt_count: row.get(4),
                        current_session_count: row.get(5),
                        desired_read_state_count: row.get(6),
                        observation_receive_state_count: row.get(7),
                        admission_inventory_state_count: row.get(8),
                        current_cat_observation_count: row.get(9),
                        cat_record_count: row.get(10),
                        disk_record_count: row.get(11),
                        volume_record_count: row.get(12),
                        desired_spec_count: row.get(13),
                        endpoint_record_count: row.get(14),
                        hostname_lookup_count: row.get(15),
                        runtime_operation_count: row.get(16),
                        api_result_count: row.get(17),
                        retired_node_count: row.get(18),
                        retired_cat_count: row.get(19),
                        registration_attempt_lease_deadline_unix_ms: row.get(20),
                        current_session_lease_deadline_unix_ms: row.get(21),
                        desired_read_last_request_sequence: row.get(22),
                        stored_api_response_body: row.get(23),
                        stored_persistent_disk_response_body: row.get(24),
                    })
            })
        })
        .await
        .expect("load runtime cutover acceptance facts")
}

/// Expire one isolated test session while preserving every JSON/projection
/// invariant. The immutable-attempt trigger is disabled only inside this
/// disposable-schema transaction and is restored before commit.
pub async fn expire_agent_session_for_test(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) {
    store
        .execute(move |store| {
            store.with(|client| {
                let mut transaction = client.transaction()?;
                transaction.batch_execute(
                    "ALTER TABLE agent_registration_attempts DISABLE TRIGGER USER",
                )?;
                let attempts = transaction.execute(
                    "UPDATE agent_registration_attempts
                        SET session_record=jsonb_set(
                                session_record, '{lease_deadline_unix_ms}', '1'::jsonb, FALSE),
                            lease_deadline_unix_ms=1
                      WHERE node_id=$1",
                    &[&node_id.as_str()],
                )?;
                let current = transaction.execute(
                    "UPDATE current_agent_sessions
                        SET record=jsonb_set(
                                record, '{lease_deadline_unix_ms}', '1'::jsonb, FALSE),
                            lease_deadline_unix_ms=1
                      WHERE node_id=$1",
                    &[&node_id.as_str()],
                )?;
                transaction
                    .batch_execute("ALTER TABLE agent_registration_attempts ENABLE TRIGGER USER")?;
                assert_eq!((attempts, current), (1, 1));
                transaction.commit()
            })
        })
        .await
        .expect("expire isolated test AgentSession");
}

/// Move the current Desired cursor just into the past without changing its
/// sequence/read position, retaining a valid issued-before-expires interval.
pub async fn expire_runtime_cursor_for_test(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) {
    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, encode_desired_read_snapshot, UnixMillis,
    };

    store
        .execute(move |store| {
            store.with(|client| {
                let row = client.query_one(
                    "SELECT response::text,
                            (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                       FROM runtime_desired_read_states WHERE node_id=$1",
                    &[&node_id.as_str()],
                )?;
                let response: String = row.get(0);
                let now: i64 = row.get(1);
                let mut snapshot = decode_desired_read_snapshot(response.as_bytes())
                    .expect("stored Desired snapshot is valid");
                let expires = u64::try_from(now).expect("database clock is nonnegative");
                snapshot.issued_at_unix_ms =
                    UnixMillis::new(expires.saturating_sub(1)).expect("issued time is valid");
                snapshot.expires_at_unix_ms =
                    UnixMillis::new(expires).expect("expiry time is valid");
                let encoded = String::from_utf8(
                    encode_desired_read_snapshot(&snapshot).expect("expired cursor still encodes"),
                )
                .expect("runtime wire JSON is UTF-8");
                client.execute(
                    "UPDATE runtime_desired_read_states
                        SET response=$2::TEXT::jsonb, issued_at_unix_ms=$3,
                            expires_at_unix_ms=$4
                      WHERE node_id=$1",
                    &[
                        &node_id.as_str(),
                        &encoded,
                        &i64::try_from(snapshot.issued_at_unix_ms.get())
                            .expect("issued time fits PostgreSQL"),
                        &i64::try_from(snapshot.expires_at_unix_ms.get())
                            .expect("expiry time fits PostgreSQL"),
                    ],
                )?;
                Ok(())
            })
        })
        .await
        .expect("expire isolated test Desired cursor");
}

/// Insert one valid assignment after a cursor was issued. This is a transport
/// regression fixture: the observation must reject the changed assigned set
/// before trying to infer a missing runtime.
pub async fn insert_assigned_desired_after_cursor_for_test(
    store: &Arc<crate::store::Store>,
    node_id: cats_api::runtime_reconciliation::Id,
) {
    use cats_api::runtime_reconciliation::{
        encode_desired_runtime_spec, spec_digest, AssignedKind, AssignedPlacement, ContractVersion,
        DesiredRuntimeSpec, Epoch, Id, Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig,
        Revision, RuntimeConfig, RuntimeTarget, RuntimeTransition, Sha256Digest,
    };

    let digest = |byte: char| {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64)))
            .expect("test digest is valid")
    };
    store
        .execute(move |store| {
            store.with(|client| {
                let mut transaction = client.transaction()?;
                let row = transaction.query_one(
                    "SELECT id, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                       FROM workspaces WHERE is_default ORDER BY id LIMIT 1",
                    &[],
                )?;
                let workspace_id =
                    Id::new(row.get::<_, String>(0)).expect("bootstrap workspace id is valid");
                let now: i64 = row.get(1);
                let cat_id = Id::new("cat_http_assigned").expect("test Cat id is valid");
                let mut desired = DesiredRuntimeSpec {
                    version: ContractVersion::V1,
                    workspace_id: workspace_id.clone(),
                    cat_id: cat_id.clone(),
                    desired_revision: Revision::new(1).expect("one is valid"),
                    target: RuntimeTarget::Running,
                    placement: AssignedPlacement {
                        kind: AssignedKind::Assigned,
                        node_id,
                        placement_epoch: Epoch::new(1).expect("one is valid"),
                    },
                    runtime: RuntimeConfig {
                        vcpus: 1,
                        memory_bytes: 512 * 1024 * 1024,
                        boot_image_digest: digest('3'),
                        guest_config_digest: digest('4'),
                        network_config: NetworkConfig {
                            kind: IsolatedIpv4Kind::IsolatedIpv4,
                            network_id: Id::new("net_http_assigned")
                                .expect("test Network id is valid"),
                            guest_mac: MacAddress::new("02:00:00:00:00:01")
                                .expect("test MAC is valid"),
                            guest_ipv4: Ipv4Address::new("10.0.0.1")
                                .expect("test guest IPv4 is valid"),
                            prefix_length: 30,
                            gateway_ipv4: Ipv4Address::new("10.0.0.2")
                                .expect("test gateway IPv4 is valid"),
                        },
                    },
                    volumes: Vec::new(),
                    endpoints: Vec::new(),
                    transition: RuntimeTransition::CancelAndDrain,
                    spec_digest: digest('0'),
                };
                desired.spec_digest = spec_digest(&desired).expect("test Desired is valid");
                let desired_json = String::from_utf8(
                    encode_desired_runtime_spec(&desired).expect("test Desired encodes"),
                )
                .expect("runtime wire JSON is UTF-8");
                let cat_json = serde_json::json!({
                    "cat_id": cat_id.as_str(),
                    "workspace_id": workspace_id.as_str(),
                    "name": "assigned_after_cursor",
                    "created_at": u64::try_from(now).expect("database clock is nonnegative"),
                })
                .to_string();
                transaction.execute(
                    "INSERT INTO cat_records
                        (cat_id, record, workspace_id, name, created_at)
                     VALUES ($1, $2::TEXT::jsonb, $3, 'assigned_after_cursor', $4)",
                    &[&cat_id.as_str(), &cat_json, &workspace_id.as_str(), &now],
                )?;
                transaction.execute(
                    "INSERT INTO desired_runtime_specs
                        (cat_id, record, workspace_id, desired_revision, spec_digest,
                         target, node_id, placement_epoch)
                     VALUES ($1, $2::TEXT::jsonb, $3, 1, $4, 'running', $5, 1)",
                    &[
                        &cat_id.as_str(),
                        &desired_json,
                        &workspace_id.as_str(),
                        &desired.spec_digest.as_str(),
                        &desired.placement.node_id.as_str(),
                    ],
                )?;
                transaction.commit()
            })
        })
        .await
        .expect("insert assigned Desired after cursor");
}

/// Transitional V1 lifecycle fixture. Runtime-session production code never
/// calls this; the broad pre-cutover E2E suite still schedules through the old
/// `nodes` table while F3c replaces that consumer.
#[allow(clippy::too_many_arguments)]
pub async fn register_legacy_test_node(
    store: &Arc<crate::store::Store>,
    node_id: String,
    agent_url: String,
    gateway_url: String,
    cpus: u32,
    memory_mib: u64,
    route_grant_public_key_sha256: String,
) {
    store
        .execute(move |store| {
            store.register_node_with_admission(
                &node_id,
                &agent_url,
                &gateway_url,
                cpus,
                memory_mib,
                crate::store::NodeAdmission::for_route_grant_for_test(
                    false,
                    &route_grant_public_key_sha256,
                ),
            )
        })
        .await
        .expect("register legacy lifecycle test Node");
}

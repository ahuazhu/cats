//! Helpers for pointing a control Store at a disposable PostgreSQL schema.
//!
//! Not part of the public API: this exists so the crate's own tests and the
//! workspace's integration/E2E suites can isolate per test without each
//! reinventing the DSN handling. The server named by `CATS_TEST_POSTGRES_URL`
//! is treated as disposable; schemas are created and never dropped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use postgres::NoTls;

/// Private mirror of the canonical `cats_test_support::wait::poll_bound`.
///
/// This module is compiled into the production `cats-control-plane` library
/// target so downstream crates' tests can reuse it, which means
/// dev-dependencies such as `cats-test-support` are not visible here. Keep
/// the contract in sync with `tests/support/src/wait.rs`: a pure polling
/// upper bound is not a performance assertion — success exits early, so a
/// healthy run pays nothing and the default must be absurdly wide instead of
/// being calibrated against an idle development machine.
fn poll_bound() -> Duration {
    const ENV: &str = "CATS_TEST_POLL_BOUND_SECS";
    match std::env::var(ENV) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => panic!("{ENV} must be a positive whole number of seconds, got {raw:?}"),
        },
        Err(std::env::VarError::NotPresent) => Duration::from_secs(180),
        Err(err) => panic!("{ENV} is not readable: {err}"),
    }
}

/// Hold an isolated test schema's runtime_operations table at an
/// ACCESS-EXCLUSIVE barrier and report when one production Store query is
/// waiting behind it. This is shared by unit and cross-router cancellation
/// tests so both prove that the blocking Store closure has been claimed.
pub struct RuntimeOperationsTableLockForTest {
    blocked: tokio::sync::oneshot::Receiver<Result<(), String>>,
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RuntimeOperationsTableLockForTest {
    pub async fn acquire(dsn: &str) -> Self {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let dsn = dsn.to_owned();
        let worker = std::thread::spawn(move || {
            let mut client = postgres::Client::connect(&dsn, postgres::NoTls).unwrap();
            client
                .batch_execute(
                    "BEGIN;
                     SET LOCAL lock_timeout='5s';
                     LOCK TABLE runtime_operations IN ACCESS EXCLUSIVE MODE",
                )
                .unwrap();
            let own_pid: i32 = client
                .query_one("SELECT pg_backend_pid()", &[])
                .unwrap()
                .get(0);
            ready_tx.send(()).unwrap();

            // Pure poll upper bound; a saturated gate host (late in the
            // full suite, with a bloated shared PostgreSQL catalog) can take
            // far longer than an idle one to schedule the handler onto the
            // lock. The poll exits as soon as the handler blocks.
            let deadline = Instant::now() + poll_bound();
            loop {
                if release_rx.try_recv().is_ok() {
                    client.batch_execute("ROLLBACK").unwrap();
                    return;
                }
                // Background sweepers also scan runtime_operations; only the
                // handler's by-id Operation read proves the claimed request
                // reached the lock barrier, so bind the waiter to its query.
                let blocked: bool = client
                    .query_one(
                        "SELECT EXISTS (
                            SELECT 1
                              FROM pg_locks waiting
                              JOIN pg_class relation ON relation.oid=waiting.relation
                              JOIN pg_namespace namespace
                                ON namespace.oid=relation.relnamespace
                              JOIN pg_stat_activity activity
                                ON activity.pid=waiting.pid
                             WHERE waiting.pid<>$1 AND NOT waiting.granted
                               AND waiting.locktype='relation'
                               AND namespace.nspname=current_schema()
                               AND relation.relname='runtime_operations'
                               AND (activity.query LIKE
                                   '%workspace_id COLLATE \"C\"=$1 AND operation_id COLLATE \"C\"=$2%'
                                 OR activity.query LIKE
                                   '%FROM runtime_operations WHERE operation_id=$1%')
                         )",
                        &[&own_pid],
                    )
                    .unwrap()
                    .get(0);
                if blocked {
                    let _ = blocked_tx.send(Ok(()));
                    break;
                }
                if Instant::now() >= deadline {
                    // Do not guess between "nothing ever queued" and "another
                    // session (for example a background sweeper on the shared
                    // Store lane) starved the by-id read": report the exact
                    // waiter set and session activity for this schema.
                    let diagnostic = client
                        .query(
                            "SELECT activity.pid::text, activity.state,
                                    coalesce(activity.wait_event_type, ''),
                                    activity.query
                               FROM pg_stat_activity activity
                              WHERE activity.datname=current_database()
                                AND activity.pid<>$1
                                AND activity.query LIKE '%runtime_operations%'",
                            &[&own_pid],
                        )
                        .map(|rows| {
                            rows.into_iter()
                                .map(|row| {
                                    format!(
                                        "pid={} state={} wait={} query={}",
                                        row.get::<_, String>(0),
                                        row.get::<_, String>(1),
                                        row.get::<_, String>(2),
                                        row.get::<_, String>(3)
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(" | ")
                        })
                        .unwrap_or_else(|error| format!("diagnostic query failed: {error}"));
                    let _ = blocked_tx.send(Err(diagnostic));
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = release_rx.recv_timeout(poll_bound());
            client.batch_execute("ROLLBACK").unwrap();
        });
        tokio::time::timeout(poll_bound(), ready_rx)
            .await
            .expect("runtime_operations table lock was not acquired")
            .expect("runtime_operations table-lock worker stopped");
        Self {
            blocked: blocked_rx,
            release: Some(release_tx),
            worker: Some(worker),
        }
    }

    pub async fn wait_until_query_blocked(&mut self) {
        // Strictly wider than the worker's own poll bound so the worker's
        // diagnostic report arrives instead of this timeout.
        if let Err(diagnostic) =
            tokio::time::timeout(poll_bound() + Duration::from_secs(10), &mut self.blocked)
                .await
                .expect("runtime Operation query did not reach the PostgreSQL lock barrier")
                .expect("runtime_operations table-lock worker stopped")
        {
            panic!("runtime Operation query never blocked on runtime_operations: {diagnostic}");
        }
    }

    pub fn release(mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

impl Drop for RuntimeOperationsTableLockForTest {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

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

/// Independent E13 offline-operator public trust for server tests.
pub fn test_production_cutover_operator_trust_bundle(
) -> cats_api::production_mutation_admission::ProductionCutoverOperatorTrustBundle {
    use cats_api::production_mutation_admission::{
        ProductionCutoverAwsPartition, ProductionCutoverAwsRoleScope,
        ProductionCutoverOperatorCredential, ProductionCutoverOperatorTrustBundle,
    };
    use cats_api::runtime_reconciliation::{Base64UrlNoPad, ContractVersion, Id, WireU64};

    ProductionCutoverOperatorTrustBundle {
        version: ContractVersion::V1,
        deployment_id: Id::new("deployment_a").expect("valid test deployment ID"),
        release_id: Id::new("release_a").expect("valid test release ID"),
        source_commit_sha: "a".repeat(40),
        signature_threshold: WireU64::new(1).expect("valid test threshold"),
        credentials: vec![ProductionCutoverOperatorCredential {
            credential_id: Id::new("cutover_a").expect("valid test credential ID"),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            )
            .expect("canonical test Ed25519 SPKI"),
            scope: ProductionCutoverAwsRoleScope {
                aws_partition: ProductionCutoverAwsPartition::Aws,
                account_id: "123456789012".to_owned(),
                role_arn: "arn:aws:iam::123456789012:role/cats-production-cutover".to_owned(),
            },
        }],
    }
}

/// Enter the exact workspace-scoped ADR-0052 Qualification mode through the
/// same dedicated signature verifier and Store CAS used by production.
///
/// This is deliberately an explicit fixture action after Account/Workspace
/// provisioning. It is neither an automatic schema default nor a Store
/// bypass, and it cannot construct a final `Open` binding.
#[cfg(any(test, debug_assertions, feature = "test-support"))]
pub fn begin_production_qualification_for_product_test(
    store: &crate::store::Store,
    workspace_id: &cats_api::runtime_reconciliation::Id,
) -> cats_api::production_mutation_admission::ProductionQualificationAdmissionBinding {
    use cats_api::production_mutation_admission::{
        ProductionCutoverAwsPartition, ProductionMutationAdmissionBinding,
        ProductionMutationAdmissionCommand, ProductionMutationAdmissionMode,
        ProductionMutationAdmissionMutation, ProductionMutationAdmissionStoredOutcome,
        ProductionQualificationAdmissionBinding, PRODUCTION_QUALIFICATION_MUTATION_CLASSES,
    };
    use cats_api::runtime_reconciliation::{
        ContractVersion, Epoch, Id, RandomId128, Sha256Digest, UnixMillis, WireU64,
    };
    use sha2::{Digest as _, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    let cats_account_id: String = store
        .with(|client| {
            client
                .query_one(
                    "SELECT account_id FROM workspaces WHERE id=$1",
                    &[&workspace_id.as_str()],
                )
                .map(|row| row.get(0))
        })
        .expect("load exact qualification Account/Workspace scope");
    let mut state = store
        .production_mutation_admission_state()
        .expect("discover default-Closed qualification admission state");
    if state.mode == ProductionMutationAdmissionMode::Qualification {
        let ProductionMutationAdmissionBinding::Qualification(installed) = state
            .binding
            .as_ref()
            .expect("Qualification mode has a binding")
        else {
            panic!("Qualification mode did not carry a Qualification binding")
        };
        if &installed.workspace_id == workspace_id {
            return installed.clone();
        }
        end_production_qualification_for_product_test(store);
        state = store
            .production_mutation_admission_state()
            .expect("discover Closed state after test Qualification End");
    }
    assert_eq!(state.mode, ProductionMutationAdmissionMode::Closed);
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock is after the epoch")
            .as_millis(),
    )
    .expect("test time fits u64");
    let digest = |byte: char| {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64)))
            .expect("test digest is valid")
    };
    let binding = ProductionQualificationAdmissionBinding {
        qualification_id: Id::new(format!("qualification_{workspace_id}"))
            .expect("valid test qualification ID"),
        deployment_id: Id::new("deployment_a").expect("valid test deployment ID"),
        release_id: Id::new("release_a").expect("valid test release ID"),
        source_commit_sha: "a".repeat(40),
        control_schema_version: WireU64::new(
            cats_api::production_mutation_admission::PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION,
        )
        .expect("valid schema version"),
        source_manifest_sha256: digest('0'),
        source_bundle_sha256: digest('1'),
        build_receipt_sha256: digest('2'),
        release_manifest_sha256: digest('3'),
        worker_bundle_sha256: digest('4'),
        qualification_catalog_sha256: digest('5'),
        qualification_cell_manifest_sha256: digest('6'),
        aws_partition: ProductionCutoverAwsPartition::Aws,
        aws_account_id: "123456789012".to_owned(),
        aws_region: "us-east-1".to_owned(),
        cell_id: Id::new("test-cell-a").expect("valid test cell ID"),
        cell_namespace: "cats-qualification".to_owned(),
        cats_account_id: Id::new(cats_account_id).expect("valid Cats account ID"),
        workspace_id: workspace_id.clone(),
        allowed_mutation_classes: PRODUCTION_QUALIFICATION_MUTATION_CLASSES.to_vec(),
        qualification_expires_at_unix_ms: UnixMillis::new(now + 60 * 60 * 1_000)
            .expect("valid qualification expiry"),
    };
    let command_id = RandomId128::new(hex::encode(
        &Sha256::digest(format!("{workspace_id}:{}", state.revision.get()).as_bytes())[..16],
    ))
    .expect("valid deterministic test command ID");
    let command = ProductionMutationAdmissionCommand {
        version: ContractVersion::V1,
        command_id,
        issued_at_unix_ms: UnixMillis::new(now).expect("valid issued time"),
        expires_at_unix_ms: UnixMillis::new(now + 60_000).expect("valid command expiry"),
        operator: test_production_cutover_sts_principal(),
        expected_revision: Epoch::new(state.revision.get()).expect("positive state revision"),
        mutation: ProductionMutationAdmissionMutation::BeginQualification {
            binding: binding.clone(),
        },
    };
    let receipt = apply_production_admission_for_product_test(store, &command, now);
    assert!(matches!(
        receipt.outcome,
        ProductionMutationAdmissionStoredOutcome::Applied { ref state }
            if state.mode == ProductionMutationAdmissionMode::Qualification
                && state.binding.as_ref()
                    == Some(&cats_api::production_mutation_admission::ProductionMutationAdmissionBinding::Qualification(binding.clone()))
    ));
    binding
}

/// Leave an installed test Qualification through the official signed End CAS.
/// Disposable product fixtures use this only when they intentionally move the
/// singleton to another exact Workspace scope.
#[cfg(any(test, debug_assertions, feature = "test-support"))]
pub fn end_production_qualification_for_product_test(store: &crate::store::Store) {
    use cats_api::production_mutation_admission::{
        ProductionMutationAdmissionBinding, ProductionMutationAdmissionCommand,
        ProductionMutationAdmissionMode, ProductionMutationAdmissionMutation,
        ProductionMutationAdmissionStoredOutcome,
    };
    use cats_api::runtime_reconciliation::{ContractVersion, Epoch, RandomId128, UnixMillis};
    use sha2::{Digest as _, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    let state = store
        .production_mutation_admission_state()
        .expect("discover installed test Qualification");
    let ProductionMutationAdmissionBinding::Qualification(binding) = state
        .binding
        .clone()
        .expect("test Qualification has a binding")
    else {
        panic!("test Qualification did not carry a Qualification binding")
    };
    assert_eq!(state.mode, ProductionMutationAdmissionMode::Qualification);
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock is after the epoch")
            .as_millis(),
    )
    .expect("test time fits u64");
    let command_id = RandomId128::new(hex::encode(
        &Sha256::digest(
            format!("end:{}:{}", binding.qualification_id, state.revision.get()).as_bytes(),
        )[..16],
    ))
    .expect("valid deterministic test End command ID");
    let command = ProductionMutationAdmissionCommand {
        version: ContractVersion::V1,
        command_id,
        issued_at_unix_ms: UnixMillis::new(now).expect("valid issued time"),
        expires_at_unix_ms: UnixMillis::new(now + 60_000).expect("valid command expiry"),
        operator: test_production_cutover_sts_principal(),
        expected_revision: Epoch::new(state.revision.get()).expect("positive state revision"),
        mutation: ProductionMutationAdmissionMutation::EndQualification { binding },
    };
    let receipt = apply_production_admission_for_product_test(store, &command, now);
    assert!(matches!(
        receipt.outcome,
        ProductionMutationAdmissionStoredOutcome::Applied { ref state }
            if state.mode == ProductionMutationAdmissionMode::Closed
    ));
}

#[cfg(any(test, debug_assertions, feature = "test-support"))]
fn test_production_cutover_sts_principal(
) -> cats_api::production_mutation_admission::ProductionCutoverStsPrincipal {
    use cats_api::production_mutation_admission::{
        ProductionCutoverAwsPartition, ProductionCutoverStsPrincipal,
    };

    ProductionCutoverStsPrincipal {
        aws_partition: ProductionCutoverAwsPartition::Aws,
        account_id: "123456789012".to_owned(),
        role_arn: "arn:aws:iam::123456789012:role/cats-production-cutover".to_owned(),
        principal_arn:
            "arn:aws:sts::123456789012:assumed-role/cats-production-cutover/test-session".to_owned(),
    }
}

#[cfg(any(test, debug_assertions, feature = "test-support"))]
fn apply_production_admission_for_product_test(
    store: &crate::store::Store,
    command: &cats_api::production_mutation_admission::ProductionMutationAdmissionCommand,
    now_unix_ms: u64,
) -> cats_api::production_mutation_admission::ProductionMutationAdmissionCommandReceipt {
    use cats_api::agent_registration::Ed25519RequestSigner;
    use cats_api::production_mutation_admission::{
        encode_production_mutation_admission_command, sign_production_mutation_admission_command,
        verify_production_mutation_admission_command,
    };
    use cats_api::runtime_reconciliation::Id;

    let body = encode_production_mutation_admission_command(command)
        .expect("canonical test production admission command");
    let mut pkcs8 =
        hex::decode("302e020100300506032b657004220420").expect("valid test PKCS#8 prefix");
    pkcs8.extend_from_slice(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .expect("valid test Ed25519 seed"),
    );
    let signer = Ed25519RequestSigner::from_pkcs8_der(
        Id::new("cutover_a").expect("valid test credential ID"),
        &pkcs8,
    )
    .expect("valid test cutover signer");
    let trust = test_production_cutover_operator_trust_bundle();
    let proof = sign_production_mutation_admission_command(&trust, &signer, &body)
        .expect("sign test production admission command");
    let principal = verify_production_mutation_admission_command(
        &trust,
        &proof.credential_id,
        &proof.signature,
        &body,
        now_unix_ms,
    )
    .expect("verify test production admission command through production verifier");
    let request = crate::store::AuthorityRequestContext::new(
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    );
    let outcome = store
        .apply_production_mutation_admission_command_request(&principal, command, &request)
        .expect("apply test production admission through production Store");
    let crate::store::runtime_authority::production_mutation_admission::ProductionMutationAdmissionCommandStoreOutcome::Stored(receipt) = outcome else {
        panic!("test production admission command was not stored: {outcome:?}");
    };
    receipt
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

#[cfg(any(debug_assertions, feature = "test-support"))]
const TEST_ROUTE_V2_SIGNER_REFERENCE: &[u8] = br#"{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:7c7e324d7be6c6ee71735c900ce1041de63af7cc08fb39b6800853f966e81e34"}"#;
#[cfg(any(debug_assertions, feature = "test-support"))]
const TEST_ROUTE_V2_PUBLIC_KEY_RING: &[u8] = br#"{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}"#;

#[cfg(any(debug_assertions, feature = "test-support"))]
fn route_v2_signing_authority_fixture() -> anyhow::Result<(
    Arc<crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority>,
    cats_api::route_grant_v2::RouteGrantV2PublicKeyRingArtifact,
)> {
    use cats_api::route_grant_v2::{
        decode_route_grant_v2_public_key_ring, decode_route_grant_v2_signer_reference,
    };

    let signer_reference = decode_route_grant_v2_signer_reference(TEST_ROUTE_V2_SIGNER_REFERENCE)?;
    let public_key_ring = decode_route_grant_v2_public_key_ring(TEST_ROUTE_V2_PUBLIC_KEY_RING)?;
    let signing_authority = Arc::new(
        crate::route_grant_v2::InstalledRouteGrantV2SigningAuthority::from_authority_artifacts(
            &signer_reference,
            TEST_ROUTE_V2_SIGNER_REFERENCE,
            &public_key_ring,
            Some(include_bytes!(
                "../../tests/fixtures/route_grant_v2_private_ed25519.pem"
            )),
            120,
        )?,
    );
    Ok((signing_authority, public_key_ring))
}

/// PostgreSQL backend PID for the ordinary single-connection control Store.
/// Integration concurrency tests use it only to distinguish one claimed
/// production request from unrelated sessions in the same disposable server.
pub async fn control_store_backend_pid(store: &Arc<crate::store::Store>) -> i32 {
    store
        .execute(|store| {
            store.with(|client| {
                client
                    .query_one("SELECT pg_backend_pid()", &[])
                    .map(|row| row.get(0))
            })
        })
        .await
        .expect("read test control Store backend PID")
}

#[cfg(any(debug_assertions, feature = "test-support"))]
fn route_v2_gateway_machine_fixture_inner(
    listen: impl Into<String>,
) -> anyhow::Result<(
    crate::server::GatewayMachineConfig,
    cats_api::route_grant_v2::RouteGrantV2PublicKeyRingArtifact,
)> {
    use cats_api::gateway_workload_identity::{
        GatewayWorkloadCredentialPolicy, GatewayWorkloadCredentialScope,
        GatewayWorkloadIdentityAuthority,
    };
    use cats_api::runtime_reconciliation::{Base64UrlNoPad, ContractVersion, Epoch, Id};
    let (signing_authority, public_key_ring) = route_v2_signing_authority_fixture()?;
    let gateway_authority = GatewayWorkloadIdentityAuthority {
        version: ContractVersion::V1,
        authority_id: Id::new("gateway_authority_route_e2e")
            .expect("test Gateway authority ID is valid"),
        fleet_id: Id::new("fleet_route_e2e").expect("test Gateway fleet ID is valid"),
        policy_revision: Epoch::new(1).expect("test Gateway policy revision is positive"),
        expected_previous: None,
        credentials: vec![GatewayWorkloadCredentialPolicy {
            credential_id: Id::new("gateway_credential_route_e2e")
                .expect("test Gateway credential ID is valid"),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEAFqokynUVEeIXMF7pBwDCDQn6N97Q4hJUz7DUbPlbJu8",
            )
            .expect("test Gateway credential SPKI is canonical"),
            scope: GatewayWorkloadCredentialScope::Fleet,
        }],
    };
    let tls_config = crate::gateway_machine::GatewayMachineTlsConfig::from_pem_for_test(
        include_bytes!("../tests/fixtures/gateway_machine_ca_certificate.pem"),
        include_bytes!("../tests/fixtures/gateway_machine_server_certificate.pem"),
        include_bytes!("../tests/fixtures/gateway_machine_server_private_key.pem"),
    )?;
    let config = crate::server::GatewayMachineConfig::from_test_composition(
        listen,
        gateway_authority,
        tls_config,
        signing_authority,
    )?;
    Ok((config, public_key_ring))
}

/// Compose the real isolated Control Route v2 listener with the shared r1
/// signer and mTLS fixtures, and return the exact ring a Node must ACK. This
/// debug-only surface cannot become a production signer-install authority.
#[cfg(debug_assertions)]
pub fn route_v2_gateway_machine_fixture(
    listen: impl Into<String>,
) -> anyhow::Result<(
    crate::server::GatewayMachineConfig,
    cats_api::route_grant_v2::RouteGrantV2PublicKeyRingArtifact,
)> {
    route_v2_gateway_machine_fixture_inner(listen)
}

/// Compose the real isolated Control Route v2 listener with the shared r1
/// signer and mTLS fixtures. This test-only feature avoids adding any
/// caller-selected artifact path or credential input to production startup.
#[cfg(feature = "test-support")]
pub fn route_v2_gateway_machine_config(
    listen: impl Into<String>,
) -> anyhow::Result<crate::server::GatewayMachineConfig> {
    route_v2_gateway_machine_fixture_inner(listen).map(|(config, _)| config)
}

/// Start a test Control process through the same mandatory Route v2 entrypoint
/// as production. The reduced fixed fixture omits only the operator rotation
/// transport, whose production artifact composition has separate tests.
#[cfg(any(debug_assertions, feature = "test-support"))]
pub async fn spawn_control_plane_for_test(
    config: crate::server::Config,
) -> anyhow::Result<crate::server::Handle> {
    let machine = route_v2_gateway_machine_fixture_inner("127.0.0.1:0")?.0;
    crate::server::spawn_with_gateway_machine(config, machine).await
}

#[cfg(feature = "test-support")]
pub use crate::store::runtime_authority::object_write_e2e_fixture::{
    ObjectWriteNodeFixture, ObjectWriteNodeRequest,
};

/// Provision one Node identity, current Agent session, Active Volume and Owned
/// attachment epoch through the production Store transactions.
///
/// The object-write writer authority is deliberately left closed; open it with
/// [`provision_object_write_authority`] so a caller can first measure the
/// gateway's refusal while every other precondition already holds.
#[cfg(feature = "test-support")]
pub async fn provision_object_write_node(
    store: &Arc<crate::store::Store>,
    request: ObjectWriteNodeRequest,
) -> ObjectWriteNodeFixture {
    store
        .execute(move |store| Ok(store.provision_object_write_node(&request)))
        .await
        .expect("provision object-write Node fixture")
}

/// Open exactly one object-write writer authority for the fixture Host through
/// the production `ProvisionObjectWriteAuthority` mutation.
#[cfg(feature = "test-support")]
pub async fn provision_object_write_authority(
    store: &Arc<crate::store::Store>,
    request: ObjectWriteNodeRequest,
) -> cats_api::runtime_reconciliation::Id {
    store
        .execute(move |store| Ok(store.provision_object_write_authority(&request)))
        .await
        .expect("provision object-write writer authority")
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
    isolated_schema_url(&base, &schema)
}

fn isolated_schema_url(base: &str, schema: &str) -> String {
    // Preserve the supplied DSN byte-for-byte. In particular, postgres treats
    // a raw `+` in a query value literally rather than as an HTML-form space.
    // A final `options` parameter matches the helper's historical last-value
    // behavior while adding the exact marker to the existing search path.
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}%20-ccats.test_schema_bootstrap%3Don")
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
                            'receive', (SELECT to_jsonb(r) FROM runtime_inventory_receive_states r
                                         WHERE r.node_id=$1),
                            'full_inventory', (SELECT to_jsonb(i) FROM runtime_full_inventory_attestations i
                                           WHERE i.node_id=$1),
                            'cat_telemetry', (SELECT count(*)
                                                FROM runtime_current_cat_telemetry c
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

/// Exact PostgreSQL tuple identity plus bytes for one Volume Authority row.
///
/// Value equality alone cannot prove that an idempotent Runtime restart made
/// no same-value `UPDATE`: PostgreSQL assigns that write a new `xmin`. This
/// narrow test projection therefore binds both the canonical row and its MVCC
/// creator before and after production reconciliation.
pub async fn runtime_volume_row_fingerprint(
    store: &Arc<crate::store::Store>,
    volume_id: cats_api::runtime_reconciliation::Id,
) -> String {
    store
        .execute(move |store| {
            store.with(|client| {
                client
                    .query_one(
                        "SELECT jsonb_build_object(
                            'xmin', xmin::text,
                            'ctid', ctid::text,
                            'row', to_jsonb(v)
                         )::text
                           FROM volume_records v
                          WHERE volume_id=$1",
                        &[&volume_id.as_str()],
                    )
                    .map(|row| row.get(0))
            })
        })
        .await
        .expect("fingerprint Runtime Volume row")
}

enum RuntimeSchemaWriteBarrierCommand {
    Finish {
        result: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    Shutdown,
}

/// Hold every ordinary table in one isolated test schema against DML while a
/// negative HTTP mutation probe runs.
///
/// A before/after row snapshot alone cannot see an INSERT followed by DELETE.
/// PostgreSQL INSERT, UPDATE and DELETE all acquire `ROW EXCLUSIVE`, which
/// conflicts with the `SHARE` locks retained here. Sequence state remains in
/// the coherent before/after fingerprint because `nextval` is intentionally
/// non-transactional. The owner uses a connection independent of `Store`, so
/// holding this barrier never occupies the production Store executor.
///
/// Callers must join the bounded request/handler set under test before
/// settlement. This is not a server drain and cannot rule out a detached
/// producer which decides to issue a new write only after settlement begins.
pub struct RuntimeSchemaWriteBarrierForTest {
    dsn: String,
    command: Option<std::sync::mpsc::Sender<RuntimeSchemaWriteBarrierCommand>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RuntimeSchemaWriteBarrierForTest {
    pub async fn acquire(dsn: &str) -> Self {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let worker_dsn = dsn.to_owned();
        let worker = std::thread::spawn(move || {
            let opened = RuntimeSchemaWriteBarrierWorker::open(&worker_dsn);
            match opened {
                Ok(mut barrier) => {
                    if ready_tx.send(Ok(())).is_err() {
                        barrier.rollback();
                        return;
                    }
                    barrier.run(command_rx);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            }
        });
        tokio::time::timeout(poll_bound(), ready_rx)
            .await
            .expect("Runtime schema write barrier did not acquire its bounded table locks")
            .expect("Runtime schema write-barrier worker stopped")
            .unwrap_or_else(|error| panic!("acquire Runtime schema write barrier: {error}"));
        Self {
            dsn: dsn.to_owned(),
            command: Some(command_tx),
            worker: Some(worker),
        }
    }

    /// Calibrate the barrier against one known-positive INSERT, UPDATE and
    /// DELETE. Each must reach PostgreSQL's table-lock wait and terminate with
    /// the configured lock timeout; another SQLSTATE is not accepted.
    pub async fn calibrate_dml_blocked(&self) {
        let dsn = self.dsn.clone();
        tokio::time::timeout(
            poll_bound(),
            tokio::task::spawn_blocking(move || calibrate_runtime_schema_dml_barrier(&dsn)),
        )
        .await
        .expect("Runtime schema DML calibration exceeded its deadline")
        .expect("Runtime schema DML calibration worker panicked")
        .unwrap_or_else(|error| panic!("calibrate Runtime schema DML barrier: {error}"));
    }

    /// Compare the coherent snapshot, sample that no writer is then queued
    /// behind the barrier, roll the transaction back and join its owning
    /// thread.
    pub async fn finish_unchanged(mut self) {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.command
            .as_ref()
            .expect("Runtime schema write-barrier command channel")
            .send(RuntimeSchemaWriteBarrierCommand::Finish { result: result_tx })
            .expect("Runtime schema write-barrier worker stopped");
        let result = tokio::time::timeout(poll_bound(), result_rx)
            .await
            .expect("Runtime schema write-barrier settlement exceeded its deadline")
            .expect("Runtime schema write-barrier worker stopped before settlement");
        self.command.take();
        if let Some(worker) = self.worker.take() {
            tokio::time::timeout(
                poll_bound(),
                tokio::task::spawn_blocking(move || worker.join()),
            )
            .await
            .expect("Runtime schema write-barrier worker did not join")
            .expect("Runtime schema write-barrier join task panicked")
            .expect("Runtime schema write-barrier worker panicked");
        }
        result.unwrap_or_else(|error| panic!("Runtime schema write barrier changed: {error}"));
    }
}

impl Drop for RuntimeSchemaWriteBarrierForTest {
    fn drop(&mut self) {
        if let Some(command) = self.command.take() {
            let _ = command.send(RuntimeSchemaWriteBarrierCommand::Shutdown);
        }
        // Drop can run during panic/cancellation and must not synchronously
        // join a PostgreSQL call. Session statement/lock timeouts bound any
        // in-flight command; disconnecting the command channel then makes the
        // worker roll back and close its connection.
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

struct RuntimeSchemaWriteBarrierWorker {
    client: postgres::Client,
    tables: Vec<(String, String)>,
    before: String,
    transaction_open: bool,
}

impl RuntimeSchemaWriteBarrierWorker {
    fn open(dsn: &str) -> Result<Self, String> {
        let mut client =
            postgres::Client::connect(dsn, NoTls).map_err(|error| error.to_string())?;
        client
            .batch_execute(
                "SET statement_timeout='5s';
                 SET lock_timeout='5s';
                 BEGIN ISOLATION LEVEL READ COMMITTED",
            )
            .map_err(|error| error.to_string())?;
        let tables =
            runtime_schema_ordinary_tables(&mut client).map_err(|error| error.to_string())?;
        if tables.is_empty() {
            let _ = client.batch_execute("ROLLBACK");
            return Err("isolated Runtime schema contains no ordinary tables".to_owned());
        }
        let qualified = tables
            .iter()
            .map(|(_, qualified)| qualified.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        client
            .batch_execute(&format!("LOCK TABLE {qualified} IN SHARE MODE"))
            .map_err(|error| error.to_string())?;
        let locked_tables =
            runtime_schema_ordinary_tables(&mut client).map_err(|error| error.to_string())?;
        if locked_tables != tables {
            let _ = client.batch_execute("ROLLBACK");
            return Err(
                "isolated Runtime schema table set changed while locks were acquired".to_owned(),
            );
        }
        let before =
            runtime_schema_fingerprint(&mut client, &tables).map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            tables,
            before,
            transaction_open: true,
        })
    }

    fn run(&mut self, commands: std::sync::mpsc::Receiver<RuntimeSchemaWriteBarrierCommand>) {
        match commands.recv() {
            Ok(RuntimeSchemaWriteBarrierCommand::Finish { result }) => {
                let settled = self.settle();
                let _ = result.send(settled);
            }
            Ok(RuntimeSchemaWriteBarrierCommand::Shutdown) | Err(_) => self.rollback(),
        }
    }

    fn settle(&mut self) -> Result<(), String> {
        let after = runtime_schema_fingerprint(&mut self.client, &self.tables)
            .map_err(|error| error.to_string());
        // This is deliberately a point-in-time diagnostic before ROLLBACK,
        // not an atomic promise about future writers. The caller must already
        // have joined every request producer whose behavior this barrier is
        // intended to cover.
        let waiters =
            runtime_schema_waiting_writers(&mut self.client).map_err(|error| error.to_string());
        let rollback = self.rollback_result();
        let after = after?;
        let waiters = waiters?;
        rollback?;
        if !waiters.is_empty() {
            return Err(format!(
                "DML remained queued behind the table barrier: {}",
                waiters.join(", ")
            ));
        }
        if after != self.before {
            return Err(
                "MVCC rows or sequence state differ from the locked before snapshot".to_owned(),
            );
        }
        Ok(())
    }

    fn rollback_result(&mut self) -> Result<(), String> {
        if !self.transaction_open {
            return Ok(());
        }
        self.transaction_open = false;
        self.client
            .batch_execute("ROLLBACK")
            .map_err(|error| error.to_string())
    }

    fn rollback(&mut self) {
        let _ = self.rollback_result();
    }
}

impl Drop for RuntimeSchemaWriteBarrierWorker {
    fn drop(&mut self) {
        self.rollback();
    }
}

fn runtime_schema_ordinary_tables(
    client: &mut postgres::Client,
) -> Result<Vec<(String, String)>, postgres::Error> {
    client
        .query(
            "SELECT c.relname, format('%I.%I', n.nspname, c.relname)
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=current_schema()
                AND c.relkind='r'
              ORDER BY c.relname",
            &[],
        )
        .map(|rows| {
            rows.into_iter()
                .map(|row| (row.get(0), row.get(1)))
                .collect()
        })
}

fn runtime_schema_fingerprint(
    client: &mut postgres::Client,
    tables: &[(String, String)],
) -> Result<String, postgres::Error> {
    let mut fingerprint = String::new();
    for (table, qualified) in tables {
        let rows: String = client
            .query_one(
                &format!(
                    "SELECT COALESCE(
                        jsonb_agg(
                            jsonb_build_object(
                                'xmin', t.xmin::text,
                                'ctid', t.ctid::text,
                                'row', to_jsonb(t)
                            ) ORDER BY t.ctid
                        ),
                        '[]'::jsonb
                     )::text
                       FROM {qualified} AS t"
                ),
                &[],
            )?
            .get(0);
        fingerprint.push_str(table);
        fingerprint.push('\0');
        fingerprint.push_str(&rows);
        fingerprint.push('\0');
    }
    let sequences: String = client
        .query_one(
            "SELECT COALESCE(
                jsonb_agg(to_jsonb(s) ORDER BY s.sequencename),
                '[]'::jsonb
             )::text
               FROM pg_catalog.pg_sequences s
              WHERE s.schemaname=current_schema()",
            &[],
        )?
        .get(0);
    fingerprint.push_str("sequences\0");
    fingerprint.push_str(&sequences);
    Ok(fingerprint)
}

fn runtime_schema_waiting_writers(
    client: &mut postgres::Client,
) -> Result<Vec<String>, postgres::Error> {
    client
        .query(
            "SELECT DISTINCT format('%s:%I', waiting.pid, relation.relname)
               FROM pg_catalog.pg_locks waiting
               JOIN pg_catalog.pg_class relation ON relation.oid=waiting.relation
               JOIN pg_catalog.pg_namespace namespace
                 ON namespace.oid=relation.relnamespace
              WHERE waiting.pid<>pg_backend_pid()
                AND NOT waiting.granted
                AND waiting.locktype='relation'
                AND namespace.nspname=current_schema()
              ORDER BY 1",
            &[],
        )
        .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
}

fn calibrate_runtime_schema_dml_barrier(dsn: &str) -> Result<(), String> {
    let mut client = postgres::Client::connect(dsn, NoTls).map_err(|error| error.to_string())?;
    let event_id = format!("cats-schema-barrier-{}", uuid::Uuid::new_v4());
    for (name, statement) in [
        (
            "INSERT",
            "INSERT INTO workos_event_receipts
                 (workos_event_id, event_name, processed_at)
             VALUES ($1, 'runtime-schema-barrier-calibration', 0)",
        ),
        (
            "UPDATE",
            "UPDATE workos_event_receipts
                SET event_name=event_name
              WHERE workos_event_id=$1",
        ),
        (
            "DELETE",
            "DELETE FROM workos_event_receipts WHERE workos_event_id=$1",
        ),
    ] {
        client
            .batch_execute(
                "BEGIN;
                 SET LOCAL statement_timeout='2s';
                 SET LOCAL lock_timeout='250ms'",
            )
            .map_err(|error| error.to_string())?;
        let result = client.execute(statement, &[&event_id]);
        let rollback = client.batch_execute("ROLLBACK");
        match result {
            Err(error) if error.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) => {}
            Err(error) => {
                let _ = rollback;
                return Err(format!(
                    "known-positive {name} failed before the table-lock barrier: {error}"
                ));
            }
            Ok(_) => {
                let _ = rollback;
                return Err(format!(
                    "known-positive {name} crossed the Runtime schema table-lock barrier"
                ));
            }
        }
        rollback.map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod isolated_schema_url_tests {
    use super::isolated_schema_url;

    #[test]
    fn preserves_raw_query_and_appends_postgres_encoded_options() {
        let dsn = isolated_schema_url(
            "postgres://user:password@db.invalid/control?application_name=cats+test&options=-cfoo.bar%3Da+b",
            "t_fixed",
        );
        assert!(dsn.starts_with(
            "postgres://user:password@db.invalid/control?application_name=cats+test&options=-cfoo.bar%3Da+b&"
        ));

        let config = dsn.parse::<postgres::Config>().unwrap();
        assert_eq!(config.get_application_name(), Some("cats+test"));
        assert_eq!(
            config.get_options(),
            Some("-csearch_path=t_fixed -ccats.test_schema_bootstrap=on")
        );
    }
}

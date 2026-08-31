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

pub fn test_boot_image() -> String {
    format!("sha256:{}", "0".repeat(64))
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

/// Independent qualification-operator public trust for server tests.
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
            .expect("Qualification mode has a binding");
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
        .expect("test Qualification has a binding");
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
    use cats_api::node_identity::Ed25519RequestSigner;
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

/// Start a test semantic Control process through the production composition.
#[cfg(any(debug_assertions, feature = "test-support"))]
pub async fn spawn_control_plane_for_test(
    config: crate::server::Config,
) -> anyhow::Result<crate::server::Handle> {
    crate::server::spawn(config).await
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

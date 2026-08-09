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

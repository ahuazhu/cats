//! End-to-end acceptance for one Cats Node publishing a ChunkStore object
//! through the ObjectWrite Gateway.
//!
//! Every piece of this chain was already implemented and unit tested, and
//! nothing drove the whole thing: the writer-authority provisioning path, the
//! gateway daemon, the Node credential lifecycle and the write adapter were
//! each proved against their own doubles. This module composes the real
//! components in one process instead:
//!
//! * a real control Store on a disposable PostgreSQL schema, bootstrapped by
//!   `Store::connect_from_async`;
//! * the gateway's own least-privilege PostgreSQL role, installed from the
//!   reviewed `deploy/postgres/object-write-gateway-role-v1.sql`;
//! * a Node identity, Agent session, Owned Volume attachment epoch and
//!   object-write writer authority opened through the production
//!   `RuntimeNodeAuthorityMutation` transactions;
//! * the real gateway service from `run_object_write_gateway`, serving TLS 1.3
//!   from the repository's gateway fixtures over its own
//!   `ObjectWriteGatewayClient` connected as the gateway role;
//! * the real Node credential lifecycle in
//!   [`crate::object_write_credential`], which mints and persists the
//!   attachment Ed25519 key and registers its public half over HTTP;
//! * the real `cats_object_store_gateway::ObjectWriteGatewayBlobStore`, signing
//!   with the key that module loaded.
//!
//! # The one permitted double, and the one transport bridge
//!
//! The object-store provider *downstream* is the only substituted component.
//! It is injected as `Arc<dyn ObjectWriteGatewayDownstream>`, so the identical
//! chain runs against [`RecordingObjectStore`] offline and against the
//! production `AwsObjectWriteGatewayDownstream` when a disposable bucket is
//! named — see [`live_object_store_publishes_the_same_chain`].
//!
//! The gateway listener is TLS-only, while both real clients (the credential
//! registrar and the write adapter) build their own `reqwest` clients whose
//! roots are webpki's and cannot be told about a test CA. Both already accept a
//! loopback `http://` origin by design, so [`spawn_loopback_tls_bridge`] pipes
//! one plaintext loopback socket into a real TLS 1.3 + `http/1.1` ALPN
//! connection to the gateway. That is a byte tunnel, not a component: the
//! gateway still terminates its own real TLS with its own fixture certificate.
//! What it does *not* exercise is the two clients' own TLS trust
//! configuration.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::object_write_gateway::{
    object_write_key, ObjectWriteImmutableKey, ObjectWriteProviderRequestObservationV1,
    VolumeDataObjectKind,
};
use cats_api::runtime_reconciliation::{
    AsciiText, Id, ProviderScope, RandomId128, Sha256Digest, UnixMillis, WireU64,
};
use cats_control_plane::object_write_gateway::{
    run_object_write_gateway, ObjectWriteGatewayConfig,
};
use cats_control_plane::store::{
    DsnSource, ObjectWriteGatewayClient, Store, OBJECT_WRITE_GATEWAY_POSTGRES_ROLE,
};
use cats_control_plane::testsupport::{
    isolated_control_store_url, provision_object_write_authority, provision_object_write_node,
    ObjectWriteNodeRequest,
};
use cats_object_store_gateway::{ObjectWriteError, ObjectWriteGatewayBlobStore};
use cats_storage::object_write_authority::{
    validate_downstream_put, validate_qualification_downstream_put, ObjectPutDescriptor,
    ObjectWriteDownstreamError, ObjectWriteDownstreamFuture, ObjectWriteDownstreamPut,
    ObjectWriteDownstreamPutOutcome, ObjectWriteGatewayDownstream, ObjectWriteQualificationPut,
    ObjectWriteQualificationPutOutcome, ObjectWriteVisibilityOutcome,
};
use cats_storage::BlobStore;
use cats_test_support::wait::{bounded, wait_until_async};
use postgres::NoTls;
use ring::signature::Ed25519KeyPair;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha2::Digest as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use crate::object_write_credential::{
    LoadedObjectWriteCredential, ObjectWriteCredentialError, ObjectWriteCredentialHttpRegistrar,
    ObjectWriteCredentialScope, ObjectWriteCredentialStore,
};

const ROLE_INSTALLER: &str = include_str!("../../deploy/postgres/object-write-gateway-role-v1.sql");
const CA_CERTIFICATE: &[u8] =
    include_bytes!("../../control-plane/tests/fixtures/gateway_machine_ca_certificate.pem");
const SERVER_CERTIFICATE: &[u8] =
    include_bytes!("../../control-plane/tests/fixtures/gateway_machine_server_certificate.pem");
const SERVER_PRIVATE_KEY: &[u8] =
    include_bytes!("../../control-plane/tests/fixtures/gateway_machine_server_private_key.pem");
const HTTP_11_ALPN: &[u8] = b"http/1.1";

const NODE_ID: &str = "node_owe2e";
const HOST_ID: &str = "host_owe2e";
const NODE_CREDENTIAL_ID: &str = "credential_owe2e";
const VOLUME_ID: &str = "volume_owe2e";
const ATTACHMENT_ID: &str = "attachment_owe2e";
const WORKLOAD_PRINCIPAL: &str = "arn:test:iam::test_account:role/cats-object-write-gateway";

fn id(value: &str) -> Id {
    Id::new(value).expect("valid test identifier")
}

fn ascii(value: &str) -> AsciiText {
    AsciiText::new(value).expect("valid test ASCII text")
}

fn host_scope() -> ProviderScope {
    ProviderScope {
        provider: id("test_provider"),
        partition: id("test_partition"),
        account_id: id("test_account"),
        region: id("test_region"),
    }
}

// ---------------------------------------------------------------------------
// The one permitted double: a recording, conditional object store.
// ---------------------------------------------------------------------------

/// One accepted conditional PUT, as the gateway dispatched it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedConditionalPut {
    canonical_logical_key: String,
    content_sha256: Sha256Digest,
    content_length: u64,
    body: Vec<u8>,
    provider_attempt_id: AsciiText,
}

/// An immutable object store that records exactly what the gateway asked it to
/// publish, reads the body back out of the durable spool the gateway fsynced,
/// and enforces the conditional contract: a second PUT of an already-present
/// key is a conflict, never a silent overwrite.
struct RecordingObjectStore {
    durable_spool_root: PathBuf,
    /// `database_now - local_now`, measured once against the same PostgreSQL
    /// whose clock stamped `provider_issued_at_unix_ms`. The production AWS
    /// adapter reads `SystemTime::now()` and relies on NTP; a disposable
    /// container gets the correction explicitly so a settled terminal receipt
    /// can never be rejected for being a few milliseconds early.
    clock_skew_ms: i64,
    accepted: Mutex<BTreeMap<String, RecordedConditionalPut>>,
    conditional_puts: Mutex<Vec<RecordedConditionalPut>>,
    qualification_puts: AtomicUsize,
    visibility_probes: AtomicUsize,
}

impl RecordingObjectStore {
    fn new(durable_spool_root: PathBuf, clock_skew_ms: i64) -> Self {
        Self {
            durable_spool_root,
            clock_skew_ms,
            accepted: Mutex::new(BTreeMap::new()),
            conditional_puts: Mutex::new(Vec::new()),
            qualification_puts: AtomicUsize::new(0),
            visibility_probes: AtomicUsize::new(0),
        }
    }

    fn conditional_puts(&self) -> Vec<RecordedConditionalPut> {
        self.conditional_puts.lock().expect("recorder lock").clone()
    }

    fn now(&self) -> UnixMillis {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_millis();
        let local = i64::try_from(local).expect("Unix milliseconds fit in i64");
        UnixMillis::new(u64::try_from(local + self.clock_skew_ms).unwrap_or_default())
            .expect("corrected wall clock is a valid UnixMillis")
    }

    fn spool_body(&self, spool_id: &AsciiText) -> Result<Vec<u8>, ObjectWriteDownstreamError> {
        let path = self
            .durable_spool_root
            .join(format!("{}.body", spool_id.as_str()));
        std::fs::read(path).map_err(|_| ObjectWriteDownstreamError::Unavailable)
    }

    fn record(
        &self,
        request: &ObjectWriteDownstreamPut,
    ) -> Result<RecordedConditionalPut, ObjectWriteDownstreamError> {
        let body = self.spool_body(&request.spool.spool_id)?;
        let digest = Sha256Digest::from_bytes(sha2::Sha256::digest(&body).into());
        if digest != request.descriptor.content_sha256
            || body.len() as u64 != request.descriptor.content_length.get()
        {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        let put = RecordedConditionalPut {
            canonical_logical_key: request.descriptor.target.canonical_logical_key.clone(),
            content_sha256: digest,
            content_length: request.descriptor.content_length.get(),
            body,
            provider_attempt_id: request.descriptor.provider_attempt_id.clone(),
        };
        let mut accepted = self.accepted.lock().expect("recorder lock");
        if accepted.contains_key(&put.canonical_logical_key) {
            // Exactly the immutable-key conditional semantics: the object
            // already exists, so this request creates nothing.
            return Err(ObjectWriteDownstreamError::ConflictingObject);
        }
        accepted.insert(put.canonical_logical_key.clone(), put.clone());
        self.conditional_puts
            .lock()
            .expect("recorder lock")
            .push(put.clone());
        Ok(put)
    }
}

impl ObjectWriteGatewayDownstream for RecordingObjectStore {
    fn put_exact<'a>(
        &'a self,
        request: ObjectWriteDownstreamPut,
        absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteDownstreamPutOutcome> {
        Box::pin(async move {
            validate_downstream_put(&request, absolute_deadline)
                .map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?;
            let put = self.record(&request)?;
            Ok(ObjectWriteDownstreamPutOutcome::Succeeded {
                provider_attempt_id: put.provider_attempt_id,
                put_receipt_id: ascii(&format!(
                    "recorded-put-{}",
                    &request.descriptor.request_id.as_str()[7..23]
                )),
                completed_at_unix_ms: self.now(),
            })
        })
    }

    fn put_qualification_exact<'a>(
        &'a self,
        request: &'a ObjectWriteQualificationPut,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteQualificationPutOutcome> {
        self.qualification_puts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            validate_qualification_downstream_put(request)
                .map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?;
            // The production write path never signs a qualification fault, so
            // reaching this arm is itself the failure the count asserts on.
            Err(ObjectWriteDownstreamError::InvalidRequest)
        })
    }

    fn discover_visibility<'a>(
        &'a self,
        descriptor: &'a ObjectPutDescriptor,
        _absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteVisibilityOutcome> {
        self.visibility_probes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let accepted = self
                .accepted
                .lock()
                .expect("recorder lock")
                .get(&descriptor.target.canonical_logical_key)
                .cloned();
            let Some(put) = accepted else {
                return Ok(ObjectWriteVisibilityOutcome::NotVisible);
            };
            if put.content_sha256 != descriptor.content_sha256 {
                return Ok(ObjectWriteVisibilityOutcome::ConflictingObject);
            }
            Ok(ObjectWriteVisibilityOutcome::VisibleExact {
                provider_attempt_id: put.provider_attempt_id.clone(),
                visibility_receipt_id: ascii(&format!(
                    "recorded-head-{}",
                    &descriptor.request_id.as_str()[7..23]
                )),
                provider_request: Box::new(ObjectWriteProviderRequestObservationV1 {
                    request_id: ascii(&format!(
                        "recorded-request-{}",
                        &descriptor.request_id.as_str()[7..23]
                    )),
                    extended_request_id: None,
                    content_sha256: put.content_sha256,
                    content_length: Some(
                        WireU64::new(put.content_length).expect("recorded length is a wire u64"),
                    ),
                    entity_tag: None,
                    version_id: None,
                }),
                preceding_conditional_request: None,
                observed_at_unix_ms: self.now(),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Disposable schema, gateway role, TLS files and the loopback TLS bridge.
// ---------------------------------------------------------------------------

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

/// Applies the reviewed operator script the way an operator does: psql
/// variables substituted, the transaction executed as one statement batch, and
/// a login password set afterwards. This mirrors
/// `control-plane/tests/object_write_gateway_startup.rs`.
fn install_gateway_role(base: &str, schema: &str, password: &str) {
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
    admin
        .batch_execute(&format!(
            "ALTER ROLE {OBJECT_WRITE_GATEWAY_POSTGRES_ROLE} LOGIN PASSWORD '{password}'"
        ))
        .expect("set gateway login password");
}

fn gateway_dsn(base: &str, schema: &str, password: &str) -> String {
    let rest = base
        .split_once("://")
        .map(|(_, rest)| rest)
        .expect("base DSN has a scheme");
    let host_and_path = rest.split_once('@').map_or(rest, |(_, tail)| tail);
    format!(
        "postgres://{OBJECT_WRITE_GATEWAY_POSTGRES_ROLE}:{password}@{host_and_path}\
         ?options=-csearch_path%3D{schema}"
    )
}

/// `database_now - local_now`, in milliseconds.
fn clock_skew_ms(base: &str) -> i64 {
    let mut client = postgres::Client::connect(base, NoTls).expect("connect disposable PostgreSQL");
    let database: i64 = client
        .query_one(
            "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
            &[],
        )
        .expect("read the database clock")
        .get(0);
    let local = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_millis(),
    )
    .expect("Unix milliseconds fit in i64");
    database - local
}

/// The gateway validates its own fixed TLS material: absolute paths, regular
/// non-symlink files, mode 0644 certificate and mode 0600 private key.
fn install_tls_material(directory: &Path) -> (PathBuf, PathBuf) {
    let certificate = directory.join("object-write-server-certificate.pem");
    let private_key = directory.join("object-write-server-private-key.pem");
    std::fs::write(&certificate, SERVER_CERTIFICATE).expect("write fixture certificate");
    std::fs::write(&private_key, SERVER_PRIVATE_KEY).expect("write fixture private key");
    std::fs::set_permissions(&certificate, std::fs::Permissions::from_mode(0o644))
        .expect("chmod fixture certificate");
    std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600))
        .expect("chmod fixture private key");
    (certificate, private_key)
}

/// A canonical, absolute, mode-0700 durable spool root, as both the gateway's
/// own spool and the AWS adapter require.
fn install_spool_root(directory: &Path) -> PathBuf {
    let root = directory.join("object-write-spool");
    std::fs::create_dir_all(&root).expect("create durable spool root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("chmod durable spool root");
    std::fs::canonicalize(&root).expect("canonicalize durable spool root")
}

/// `ObjectWriteGatewayConfig::listen` is a string the listener binds itself, so
/// the port has to be chosen before the gateway starts. Reserving and releasing
/// an ephemeral port keeps concurrent test binaries apart; it is the only
/// address handshake the production config shape allows.
fn reserved_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port");
    let port = listener.local_addr().expect("read reserved port").port();
    drop(listener);
    port
}

fn bridge_client_tls() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA_CERTIFICATE).expect("fixture CA is PEM"))
        .expect("trust the fixture gateway CA");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3-only bridge client")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    Arc::new(config)
}

/// Terminate one plaintext loopback socket into a real TLS 1.3 + `http/1.1`
/// connection to the gateway. See this module's header for why the bridge
/// exists and what it does not prove.
async fn spawn_loopback_tls_bridge(gateway: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the loopback TLS bridge");
    let address = listener.local_addr().expect("read bridge address");
    let tls = bridge_client_tls();
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                return;
            };
            let connector = TlsConnector::from(Arc::clone(&tls));
            tokio::spawn(async move {
                let Ok(tcp) = TcpStream::connect(gateway).await else {
                    return;
                };
                let server_name = ServerName::try_from("localhost").expect("fixture SAN");
                let Ok(mut upstream) = connector.connect(server_name, tcp).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
            });
        }
    });
    address
}

// ---------------------------------------------------------------------------
// The chain.
// ---------------------------------------------------------------------------

/// Everything the composed chain hands back for assertion.
struct Chain {
    store: Arc<Store>,
    base: String,
    schema: String,
    fixture_request: ObjectWriteNodeRequest,
    session: cats_api::runtime_reconciliation::SessionBinding,
    attachment_epoch: cats_storage::authority::FenceEpoch,
    writer_authority_id: Id,
    node_signer: Ed25519RequestSigner,
    node_state_directory: PathBuf,
    registrar_origin: String,
    gateway_origin: String,
    reads: Arc<dyn BlobStore>,
    shutdown: tokio::sync::watch::Sender<bool>,
    gateway: tokio::task::JoinHandle<anyhow::Result<()>>,
    _directory: tempfile::TempDir,
}

impl Chain {
    /// Compose the real control store, gateway role, Node fixture and running
    /// gateway around one caller-supplied provider downstream. The writer
    /// authority is deliberately still closed.
    async fn compose(
        object_provider_scope: ProviderScope,
        object_store_scope_id: AsciiText,
        downstream: impl FnOnce(PathBuf, i64) -> Arc<dyn ObjectWriteGatewayDownstream>,
    ) -> Self {
        let dsn = isolated_control_store_url();
        let schema = schema_of(&dsn);
        let base = base_of(&dsn);

        // 1. Real control store; connecting bootstraps the target schema,
        //    including the gateway's own SQL routines.
        let store = Arc::new(
            Store::connect_from_async(DsnSource::Literal(dsn.clone()), None)
                .await
                .expect("bootstrap the control schema"),
        );

        // 2. The gateway's own PostgreSQL role, from the reviewed script.
        let password = format!("p{}", uuid::Uuid::new_v4().simple());
        let skew = {
            let (base, schema, password) = (base.clone(), schema.clone(), password.clone());
            tokio::task::spawn_blocking(move || {
                install_gateway_role(&base, &schema, &password);
                clock_skew_ms(&base)
            })
            .await
            .expect("install the gateway role")
        };

        // 3. Provisioned Node identity, Agent session, Active Volume and one
        //    Owned attachment epoch, through the production transactions.
        let node_signer = mint_node_signer();
        let fixture_request = ObjectWriteNodeRequest {
            node_id: id(NODE_ID),
            immutable_host_id: id(HOST_ID),
            node_credential_id: id(NODE_CREDENTIAL_ID),
            node_public_key_spki_sha256: node_public_key_spki_sha256(&node_signer),
            host_provider_scope: host_scope(),
            volume_id: id(VOLUME_ID),
            volume_size_bytes: 4 * 1024 * 1024,
            attachment_id: id(ATTACHMENT_ID),
            object_provider_scope,
            workload_principal_id: ascii(WORKLOAD_PRINCIPAL),
            object_store_scope_id,
        };
        let fixture = provision_object_write_node(&store, fixture_request.clone()).await;

        // 4. The real gateway service, on its own least-privilege lane.
        let directory = tempfile::tempdir().expect("temporary Node/gateway root");
        let (certificate, private_key) = install_tls_material(directory.path());
        let durable_spool_root = install_spool_root(directory.path());
        let authority = ObjectWriteGatewayClient::connect_from_async(
            DsnSource::Literal(gateway_dsn(&base, &schema, &password)),
            None,
            schema.clone(),
        )
        .await
        .expect("start the gateway PostgreSQL lane as the gateway role");
        let listen: SocketAddr = format!("127.0.0.1:{}", reserved_loopback_port())
            .parse()
            .expect("loopback listen address");
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let gateway = tokio::spawn(run_object_write_gateway(
            ObjectWriteGatewayConfig {
                listen: listen.to_string(),
                server_certificate_file: certificate,
                server_private_key_file: private_key,
                durable_spool_root: durable_spool_root.clone(),
            },
            authority,
            downstream(durable_spool_root, skew),
            shutdown_rx,
        ));
        let bridge = spawn_loopback_tls_bridge(listen).await;
        let health = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build the health client");
        let healthz = format!("http://{bridge}/healthz");
        wait_until_async("the object-write gateway reports ready", || async {
            health
                .get(&healthz)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
        })
        .await;

        let node_state_directory = directory.path().join("node-state");
        std::fs::create_dir_all(&node_state_directory).expect("create Node state directory");
        let reads = Arc::new(
            cats_object_store_file::FileBlobStore::open(directory.path().join("reads"))
                .expect("open the read-side blob store"),
        ) as Arc<dyn BlobStore>;

        Self {
            store,
            base,
            schema,
            fixture_request,
            session: fixture.session,
            attachment_epoch: fixture.attachment_epoch,
            writer_authority_id: fixture.writer_authority_id,
            node_signer,
            node_state_directory,
            registrar_origin: format!("http://{bridge}/"),
            gateway_origin: format!("http://{bridge}"),
            reads,
            shutdown,
            gateway,
            _directory: directory,
        }
    }

    fn credential_scope(&self) -> ObjectWriteCredentialScope {
        ObjectWriteCredentialScope {
            session: self.session.clone(),
            writer_authority_id: self.writer_authority_id.clone(),
            volume_id: self.fixture_request.volume_id.clone(),
            attachment_id: self.fixture_request.attachment_id.clone(),
            attachment_epoch: self.attachment_epoch,
        }
    }

    /// Run the real Node credential lifecycle: mint and persist the attachment
    /// private key locally, then register its public half with the running
    /// gateway over HTTP under the Node's A19 proof.
    async fn establish_credential(
        &self,
    ) -> Result<LoadedObjectWriteCredential, ObjectWriteCredentialError> {
        let state_directory = self.node_state_directory.clone();
        let origin = self.registrar_origin.clone();
        let scope = self.credential_scope();
        let node_signer = self.node_signer.clone();
        tokio::task::spawn_blocking(move || {
            let registrar = ObjectWriteCredentialHttpRegistrar::for_loopback_test(&origin)
                .expect("loopback registration transport");
            let store = ObjectWriteCredentialStore::open(&state_directory)?;
            store.establish(
                &scope,
                &node_signer,
                &registrar,
                Instant::now() + Duration::from_secs(60),
            )
        })
        .await
        .expect("Node credential lifecycle did not panic")
    }

    /// Publish through the real write adapter, signing with the key the
    /// credential module loaded.
    async fn publish(
        &self,
        credential: &LoadedObjectWriteCredential,
        key: String,
        body: Vec<u8>,
    ) -> Result<(), ObjectWriteError> {
        let origin = self.gateway_origin.clone();
        let volume_id = self.fixture_request.volume_id.clone();
        let signer = credential.signer().clone();
        let reads = Arc::clone(&self.reads);
        tokio::task::spawn_blocking(move || {
            ObjectWriteGatewayBlobStore::new(
                &origin,
                volume_id,
                signer,
                reads,
                // The in-process gateway serves plaintext loopback, so this
                // chain deliberately does not cover the production TLS hop.
                cats_object_store_gateway::ObjectWriteGatewayServerTrust::PlaintextLoopback,
            )?
            .publish(&key, &body)
        })
        .await
        .expect("write adapter did not panic")
    }

    async fn query<T, F>(&self, projection: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&mut postgres::Client) -> T + Send + 'static,
    {
        let base = self.base.clone();
        let schema = self.schema.clone();
        tokio::task::spawn_blocking(move || {
            let mut client =
                postgres::Client::connect(&base, NoTls).expect("connect disposable PostgreSQL");
            client
                .batch_execute(&format!("SET search_path TO \"{schema}\""))
                .expect("scope the assertion session to the isolated schema");
            projection(&mut client)
        })
        .await
        .expect("assertion query did not panic")
    }

    async fn settle(self) {
        let _ = self.shutdown.send(true);
        bounded("the object-write gateway to shut down", self.gateway)
            .await
            .expect("gateway task did not panic")
            .expect("gateway shut down cleanly");
    }
}

fn mint_node_signer() -> Ed25519RequestSigner {
    let document = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .expect("generate the Node A19 keypair");
    Ed25519RequestSigner::from_pkcs8_der(id(NODE_CREDENTIAL_ID), document.as_ref())
        .expect("the generated Node key is a canonical Ed25519 key")
}

fn node_public_key_spki_sha256(signer: &Ed25519RequestSigner) -> Sha256Digest {
    signer.public_key_spki_sha256()
}

/// One writable ChunkStore data key for `volume_id`, plus its body.
///
/// The volume-data key class is `(transaction, chunk)` and does not embed the
/// content digest, so two different `body_seed`s under one `transaction_seed`
/// are two different bodies competing for the same immutable object key.
fn volume_data_object(
    volume_id: &Id,
    transaction_seed: u8,
    body_seed: u8,
    length: usize,
) -> (String, Vec<u8>) {
    let body: Vec<u8> = (0..length).map(|index| (index as u8) ^ body_seed).collect();
    let content_sha256 = Sha256Digest::from_bytes(sha2::Sha256::digest(&body).into());
    let transaction_id = RandomId128::new(format!(
        "{:032x}",
        0x0e2e_0000_0000_0000_u64 + u64::from(transaction_seed)
    ))
    .expect("valid transaction ID");
    let key = object_write_key(
        volume_id,
        &ObjectWriteImmutableKey::VolumeData {
            transaction_id,
            chunk_index: WireU64::new(0).expect("chunk index zero is a wire u64"),
            object_kind: VolumeDataObjectKind::Base,
        },
        &content_sha256,
    )
    .expect("canonical volume-data key");
    (key, body)
}

/// Every persisted fact the terminal assertion reads back, as
/// `(state, terminal_kind, object_key, content_sha256, content_length,
/// credential_id, writer_authority_id, accepted_sequence)`.
type TerminalRow = (String, String, String, String, i64, String, String, i64);

fn terminal_rows(client: &mut postgres::Client) -> Vec<TerminalRow> {
    client
        .query(
            "SELECT state, terminal_kind, object_key, content_sha256, content_length,
                    credential_id, writer_authority_id, accepted_sequence
               FROM object_write_attempts
              WHERE accepted_sequence IS NOT NULL
              ORDER BY accepted_sequence",
            &[],
        )
        .expect("read object-write attempts")
        .iter()
        .map(|row| {
            (
                row.get(0),
                row.get::<_, Option<String>>(1).unwrap_or_default(),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                row.get(6),
                row.get::<_, Option<i64>>(7).unwrap_or_default(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The acceptance test.
// ---------------------------------------------------------------------------

async fn drive_chain(
    object_provider_scope: ProviderScope,
    object_store_scope_id: AsciiText,
    downstream: impl FnOnce(PathBuf, i64) -> Arc<dyn ObjectWriteGatewayDownstream>,
    inspect: impl AsyncFnOnce(&Chain, &LoadedObjectWriteCredential, &str, &[u8]),
) {
    let chain = Chain::compose(object_provider_scope, object_store_scope_id, downstream).await;

    // Negative calibration 1: every other precondition holds, but the Host has
    // no object-write writer authority. Registration must fail closed.
    let refused = chain
        .establish_credential()
        .await
        .expect_err("registration must fail closed while no writer authority exists");
    assert!(
        matches!(refused, ObjectWriteCredentialError::Rejected(_)),
        "a missing writer authority must be a decision, not an ambiguity: {refused}"
    );
    let credentials: i64 = chain
        .query(|client| {
            client
                .query_one("SELECT count(*) FROM object_write_credentials", &[])
                .expect("count credentials")
                .get(0)
        })
        .await;
    assert_eq!(
        credentials, 0,
        "a refused registration must not persist a credential"
    );

    // Positive: the same run, with the writer authority opened through the
    // production `ProvisionObjectWriteAuthority` mutation.
    let provisioned =
        provision_object_write_authority(&chain.store, chain.fixture_request.clone()).await;
    assert_eq!(provisioned, chain.writer_authority_id);

    let credential = chain
        .establish_credential()
        .await
        .expect("registration must succeed once the writer authority is open");
    let registered: (String, String, String, i64) = chain
        .query(|client| {
            let row = client
                .query_one(
                    "SELECT credential_id, public_key_spki_sha256, writer_authority_id,
                            attachment_epoch
                       FROM object_write_credentials",
                    &[],
                )
                .expect("read the registered credential");
            (row.get(0), row.get(1), row.get(2), row.get(3))
        })
        .await;
    assert_eq!(
        registered.0,
        credential.credential().credential_id.as_str(),
        "the Node registered exactly the credential it loaded"
    );
    assert_eq!(
        registered.1,
        credential.credential().public_key_spki_sha256.as_str()
    );
    assert_eq!(registered.2, chain.writer_authority_id.as_str());
    assert_eq!(
        u64::try_from(registered.3).expect("attachment epoch is non-negative"),
        chain.attachment_epoch.get()
    );

    // The publish itself.
    let (key, body) = volume_data_object(&chain.fixture_request.volume_id, 1, 0x5a, 4096);
    chain
        .publish(&credential, key.clone(), body.clone())
        .await
        .expect("the Node must publish one object through the gateway");

    // The control store recorded exactly one terminal successful write, for
    // exactly this key, digest, length and credential.
    let rows = chain.query(terminal_rows).await;
    let content_sha256 = Sha256Digest::from_bytes(sha2::Sha256::digest(&body).into());
    assert_eq!(
        rows,
        vec![(
            // `spool_removed` is the terminal state after the gateway removed
            // the durable spool it no longer needs.
            "spool_removed".to_owned(),
            "succeeded_visible".to_owned(),
            key.clone(),
            content_sha256.as_str().to_owned(),
            i64::try_from(body.len()).expect("body length fits in i64"),
            credential.credential().credential_id.as_str().to_owned(),
            chain.writer_authority_id.as_str().to_owned(),
            1,
        )],
        "the control store must record exactly one settled successful write"
    );

    // Immutability: different bytes for the same accepted object key are
    // refused before acceptance, and never reach the object store. This is the
    // gateway's own `object_key_conflict` rejection path.
    let (_, other_body) = volume_data_object(&chain.fixture_request.volume_id, 1, 0x37, 4096);
    let conflict = chain
        .publish(&credential, key.clone(), other_body)
        .await
        .expect_err("an accepted immutable key must not accept different bytes");
    assert!(
        matches!(conflict, ObjectWriteError::Rejected { .. }),
        "an immutable-key conflict must fail closed with a decision: {conflict}"
    );
    let rejected = chain
        .query(|client| {
            client
                .query(
                    "SELECT rejection_kind FROM object_write_attempts
                      WHERE state='rejected_before_accept'",
                    &[],
                )
                .expect("read rejected attempts")
                .iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<Vec<_>>()
        })
        .await;
    assert_eq!(
        rejected,
        vec!["object_key_conflict".to_owned()],
        "the conflicting write must settle as one rejected-before-accept attempt"
    );

    // Negative calibration 2: retire the credential through the production
    // Host-fence cutoff, then re-publish. The gateway must refuse, and the
    // refusal must be a decision rather than an ambiguity.
    let writer_authority_id = chain.writer_authority_id.clone();
    chain
        .store
        .execute(move |store| {
            store.begin_object_writer_cutoff(
                &writer_authority_id,
                &Id::new("fence_owe2e").expect("valid fence attempt ID"),
                UnixMillis::new(
                    u64::try_from(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("clock is after the Unix epoch")
                            .as_millis(),
                    )
                    .expect("Unix milliseconds fit in u64"),
                )
                .expect("valid cutoff timestamp"),
            )
        })
        .await
        .expect("cut off the writer authority");
    let retired: String = chain
        .query(|client| {
            client
                .query_one("SELECT state FROM object_write_credentials", &[])
                .expect("read the retired credential")
                .get(0)
        })
        .await;
    assert_eq!(
        retired, "retired",
        "the cutoff must retire the attachment key"
    );

    let (closed_key, closed_body) =
        volume_data_object(&chain.fixture_request.volume_id, 2, 0xa5, 512);
    let closed = chain
        .publish(&credential, closed_key.clone(), closed_body)
        .await
        .expect_err("a retired credential must not publish");
    assert!(
        matches!(
            closed,
            ObjectWriteError::Rejected { .. } | ObjectWriteError::CredentialRejected { .. }
        ),
        "a retired credential must fail closed with a decision: {closed}"
    );
    let after = chain.query(terminal_rows).await;
    assert_eq!(
        after.len(),
        1,
        "the refused write must not create a second attempt"
    );
    assert!(
        !after.iter().any(|row| row.2 == closed_key),
        "the refused write must never reach the object store"
    );

    // Inspect the provider downstream last, so its "exactly one conditional
    // PUT" claim covers the two refused publishes as well as the accepted one.
    inspect(&chain, &credential, &key, &body).await;

    chain.settle().await;
}

/// The whole chain, offline, against the recording conditional object store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_publishes_one_object_through_the_real_object_write_gateway() {
    let recorder: Arc<Mutex<Option<Arc<RecordingObjectStore>>>> = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&recorder);
    drive_chain(
        ProviderScope {
            provider: id("test_object_provider"),
            partition: id("test_object_partition"),
            account_id: id("test_object_account"),
            region: id("test_object_region"),
        },
        ascii("arn:test:s3:::cats-test/chunks"),
        move |spool_root, skew| {
            let store = Arc::new(RecordingObjectStore::new(spool_root, skew));
            *captured.lock().expect("recorder slot") = Some(Arc::clone(&store));
            store as Arc<dyn ObjectWriteGatewayDownstream>
        },
        async |_chain, credential, key, body| {
            let store = recorder
                .lock()
                .expect("recorder slot")
                .clone()
                .expect("the recorder was installed");
            let puts = store.conditional_puts();
            assert_eq!(
                puts.len(),
                1,
                "the gateway must dispatch exactly one conditional PUT"
            );
            let put = &puts[0];
            assert_eq!(put.canonical_logical_key, key);
            assert_eq!(
                put.content_sha256,
                Sha256Digest::from_bytes(sha2::Sha256::digest(body).into())
            );
            assert_eq!(put.content_length, body.len() as u64);
            assert_eq!(put.body, body, "the published bytes must be the adapter's");
            assert_eq!(
                store.qualification_puts.load(Ordering::SeqCst),
                0,
                "an ordinary production write must never take the qualification path"
            );
            assert!(
                store.visibility_probes.load(Ordering::SeqCst) >= 1,
                "the gateway must independently prove visibility"
            );
            // The credential the adapter presented is the registered one.
            assert_eq!(
                credential.registered_artifact().receipt.credential,
                *credential.credential()
            );
        },
    )
    .await;
}

/// The identical chain against a real object store.
///
/// Ignored by default: it needs AWS credentials, real STS and a disposable S3
/// bucket, so it cannot run in the offline gate. It deliberately does not skip
/// silently when its variables are absent — running it without them fails
/// loudly instead of reporting a vacuous pass:
///
/// ```bash
/// CATS_TEST_POSTGRES_URL=postgres://postgres:cats@127.0.0.1:55433/cats \
/// CATS_OBJECT_WRITE_LIVE_BUCKET=<disposable-bucket> \
/// CATS_OBJECT_WRITE_LIVE_PREFIX=<disposable-prefix> \
/// CATS_OBJECT_WRITE_LIVE_REGION=<region> \
/// CATS_OBJECT_WRITE_LIVE_ACCOUNT_ID=<account-id> \
/// AWS_PROFILE=<profile> \
///   cargo test -p cats-node-agent --lib \
///   object_write_end_to_end::live_object_store_publishes_the_same_chain \
///   -- --ignored --exact --nocapture
/// ```
///
/// The prefix is written to and never cleaned up; point it at a bucket with a
/// lifecycle rule. The `PermanentlyFailed`/conflict arms are not reachable from
/// a fresh prefix, so a rerun against the same prefix is expected to fail on
/// the immutable conditional PUT.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs AWS credentials and a disposable S3 bucket; see the doc comment"]
async fn live_object_store_publishes_the_same_chain() {
    let variable = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| {
            panic!("{name} must name a disposable live object-store target; see the doc comment")
        })
    };
    let bucket = variable("CATS_OBJECT_WRITE_LIVE_BUCKET");
    let prefix = variable("CATS_OBJECT_WRITE_LIVE_PREFIX");
    let region = variable("CATS_OBJECT_WRITE_LIVE_REGION");
    let account_id = variable("CATS_OBJECT_WRITE_LIVE_ACCOUNT_ID");
    let scope = ProviderScope {
        provider: id("aws"),
        partition: id("aws"),
        account_id: id(&account_id),
        region: id(&region),
    };
    let object_store_scope_id = ascii(&format!("arn:aws:s3:::{bucket}/{prefix}"));
    let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region))
        .load()
        .await;
    let binding = cats_host_fence_aws::VerifiedAwsProviderBinding::establish(
        &sdk,
        &scope,
        Instant::now() + Duration::from_secs(30),
    )
    .await
    .expect("verify the live AWS provider binding");

    let live_scope = scope.clone();
    let live_scope_id = object_store_scope_id.clone();
    drive_chain(
        scope,
        object_store_scope_id,
        move |spool_root, _skew| {
            let config = cats_host_fence_aws::AwsObjectWriteConfig::new(
                live_scope,
                bucket,
                prefix,
                live_scope_id,
                spool_root,
            )
            .expect("validate the live AWS object-write target");
            Arc::new(
                cats_host_fence_aws::AwsObjectWriteGatewayDownstream::from_verified_binding(
                    config, &binding,
                )
                .expect("construct the live AWS object-write adapter"),
            ) as Arc<dyn ObjectWriteGatewayDownstream>
        },
        async |_chain, credential, _key, _body| {
            assert_eq!(
                credential.registered_artifact().receipt.credential,
                *credential.credential()
            );
        },
    )
    .await;
}

//! Independent TLS 1.3 / HTTP/1.1 listener for Gateway Route v2 resolve.
//!
//! This module terminates only the machine hop. It neither joins the public
//! management router nor exposes a Gateway-to-Node proxy/listener.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use axum::routing::post;
use axum::{Extension, Router};
use cats_api::gateway_workload_identity::canonical_gateway_leaf_spki_sha256;
use cats_api::route_grant_v2::ROUTE_RESOLVE_V2_PATH;
use cats_api::runtime_artifacts::InstalledGatewayMachineArtifacts;
use cats_api::runtime_reconciliation::Sha256Digest;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::api::route_resolve_v2::{
    self, RouteResolveV2MachineControl, RouteResolveV2Service, VerifiedGatewayTlsPeer,
};

const TLS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const REQUEST_HEADER_DEADLINE: Duration = Duration::from_secs(5);
const LISTENER_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(35);
const LISTENER_TASK_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(40);
const MACHINE_CONNECTION_LIMIT: usize = 64;
const HTTP_11_ALPN: &[u8] = b"http/1.1";

pub(crate) struct GatewayMachineListener {
    addr: SocketAddr,
    service: Arc<RouteResolveV2Service>,
    control: Arc<RouteResolveV2MachineControl>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

pub(crate) struct GatewayMachineTlsConfig(Arc<ServerConfig>);

impl GatewayMachineTlsConfig {
    pub(crate) fn from_installed_artifacts(
        artifacts: &InstalledGatewayMachineArtifacts,
    ) -> anyhow::Result<Self> {
        build_tls_config(artifacts).map(Self)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_pem_for_test(
        client_ca_bundle_pem: &[u8],
        server_certificate_pem: &[u8],
        server_private_key_pem: &[u8],
    ) -> anyhow::Result<Self> {
        build_tls_config_from_pem(
            client_ca_bundle_pem,
            server_certificate_pem,
            server_private_key_pem,
        )
        .map(Self)
    }
}

impl GatewayMachineListener {
    pub(crate) async fn spawn(
        listen: &str,
        tls_config: GatewayMachineTlsConfig,
        service: Arc<RouteResolveV2Service>,
        control: Arc<RouteResolveV2MachineControl>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind Gateway machine listener {listen}"))?;
        let addr = listener.local_addr()?;
        let run_service = Arc::clone(&service);
        let shutdown = control.subscribe();
        let failure_service = Arc::clone(&service);
        let failure_control = Arc::clone(&control);
        let task = tokio::spawn(async move {
            if let Err(error) = run_listener(listener, tls_config.0, run_service, shutdown).await {
                failure_service.begin_shutdown();
                failure_control.fail_closed();
                tracing::error!(%error, "Gateway machine listener exited unexpectedly");
            }
        });
        Ok(Self {
            addr,
            service,
            control,
            task: Mutex::new(Some(task)),
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn begin_shutdown(&self) {
        self.control.begin_shutdown();
        // The service closes authentication first and resolve second.
        self.service.begin_shutdown();
    }

    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        let task = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let service_shutdown = self.service.shutdown();
        let listener_shutdown = async move {
            if let Some(mut task) = task {
                match tokio::time::timeout(LISTENER_TASK_SHUTDOWN_DEADLINE, &mut task).await {
                    Ok(joined) => joined.context("Gateway machine listener task panicked")?,
                    Err(_) => {
                        task.abort();
                        let joined = task.await;
                        anyhow::ensure!(
                            joined.as_ref().is_err_and(tokio::task::JoinError::is_cancelled),
                            "Gateway machine listener did not cancel cleanly after its shutdown deadline"
                        );
                        anyhow::bail!("Gateway machine listener exceeded its shutdown deadline");
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        let (service, listener) = tokio::join!(service_shutdown, listener_shutdown);
        service?;
        listener
    }

    #[cfg(test)]
    pub(crate) async fn wait_until_stopped_for_test(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let stopped = self
                    .task
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .is_none_or(tokio::task::JoinHandle::is_finished);
                if stopped {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Gateway machine listener did not stop after fatal signer drift");
    }
}

impl Drop for GatewayMachineListener {
    fn drop(&mut self) {
        self.begin_shutdown();
        if let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

fn build_tls_config(
    artifacts: &InstalledGatewayMachineArtifacts,
) -> anyhow::Result<Arc<ServerConfig>> {
    build_tls_config_from_pem(
        artifacts.client_ca_bundle_pem(),
        artifacts.server_certificate_pem(),
        artifacts.server_private_key_pem(),
    )
}

fn build_tls_config_from_pem(
    client_ca_bundle_pem: &[u8],
    server_certificate_pem: &[u8],
    server_private_key_pem: &[u8],
) -> anyhow::Result<Arc<ServerConfig>> {
    let client_ca_count = validate_pem_sequence(
        client_ca_bundle_pem,
        "CERTIFICATE",
        PemCardinality::OneOrMore,
    )?;
    let client_ca_certificates = CertificateDer::pem_slice_iter(client_ca_bundle_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("decode fixed Gateway client CA bundle")?;
    anyhow::ensure!(
        client_ca_certificates.len() == client_ca_count,
        "fixed Gateway client CA bundle contains an unsupported PEM section"
    );
    let mut client_roots = RootCertStore::empty();
    for certificate in client_ca_certificates {
        client_roots
            .add(certificate)
            .context("add fixed Gateway client CA certificate")?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider))
            .build()
            .context("build mandatory Gateway client-certificate verifier")?;

    let server_certificate_count = validate_pem_sequence(
        server_certificate_pem,
        "CERTIFICATE",
        PemCardinality::OneOrMore,
    )?;
    let server_certificates = CertificateDer::pem_slice_iter(server_certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("decode fixed Control machine server chain")?;
    anyhow::ensure!(
        server_certificates.len() == server_certificate_count,
        "fixed Control machine server chain contains an unsupported PEM section"
    );
    let server_leaf = server_certificates
        .first()
        .context("fixed Control machine server chain has no leaf")?;
    leaf_ed25519_spki_sha256(server_leaf.as_ref())
        .context("fixed Control machine server leaf is not canonical Ed25519")?;
    validate_pem_sequence(
        server_private_key_pem,
        "PRIVATE KEY",
        PemCardinality::ExactlyOne,
    )?;
    let server_private_key = PrivatePkcs8KeyDer::from_pem_slice(server_private_key_pem)
        .context("decode fixed Control machine PKCS#8 server private key")?;

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("build TLS 1.3-only Gateway machine configuration")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            server_certificates,
            PrivateKeyDer::Pkcs8(server_private_key),
        )
        .context("validate fixed Control machine server certificate/private-key pair")?;
    config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    Ok(Arc::new(config))
}

#[derive(Clone, Copy)]
enum PemCardinality {
    OneOrMore,
    ExactlyOne,
}

/// Close rustls-pki-types' deliberately permissive filtering: fixed files may
/// contain only the requested PEM label, strict base64 body lines and blank
/// separators. Unknown labels or arbitrary prefix/suffix text fail startup.
fn validate_pem_sequence(
    bytes: &[u8],
    label: &str,
    cardinality: PemCardinality,
) -> anyhow::Result<usize> {
    let text = std::str::from_utf8(bytes).context("fixed TLS PEM is not UTF-8 ASCII")?;
    anyhow::ensure!(text.is_ascii(), "fixed TLS PEM is not ASCII");
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut inside = false;
    let mut body_lines = 0_usize;
    let mut count = 0_usize;
    for line in text.lines() {
        if !inside {
            if line.is_empty() {
                continue;
            }
            anyhow::ensure!(
                line == begin,
                "fixed TLS PEM contains an unexpected section"
            );
            inside = true;
            body_lines = 0;
        } else if line == end {
            anyhow::ensure!(body_lines > 0, "fixed TLS PEM section is empty");
            inside = false;
            count += 1;
        } else {
            anyhow::ensure!(
                !line.is_empty()
                    && line
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte)),
                "fixed TLS PEM body is malformed"
            );
            body_lines += 1;
        }
    }
    anyhow::ensure!(!inside, "fixed TLS PEM section is unterminated");
    match cardinality {
        PemCardinality::OneOrMore => {
            anyhow::ensure!(count > 0, "fixed TLS PEM contains no certificates")
        }
        PemCardinality::ExactlyOne => {
            anyhow::ensure!(
                count == 1,
                "fixed TLS PEM must contain exactly one private key"
            )
        }
    }
    Ok(count)
}

async fn run_listener(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    service: Arc<RouteResolveV2Service>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let connection_permits = Arc::new(tokio::sync::Semaphore::new(MACHINE_CONNECTION_LIMIT));
    let (connection_shutdown, _) = tokio::sync::watch::channel(false);
    let mut connections = JoinSet::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            },
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = joined {
                    tracing::warn!(%error, "Gateway machine connection task panicked");
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept Gateway machine connection")?;
                let Ok(permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                stream.set_nodelay(true).context("set Gateway machine TCP_NODELAY")?;
                let acceptor = tls_acceptor.clone();
                let service = Arc::clone(&service);
                let connection_shutdown = connection_shutdown.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(
                        stream,
                        acceptor,
                        service,
                        connection_shutdown,
                    )
                    .await
                    {
                        tracing::debug!(%error, "Gateway machine connection closed");
                    }
                });
            }
        }
    }

    let _ = connection_shutdown.send(true);
    let joined = tokio::time::timeout(LISTENER_SHUTDOWN_DEADLINE, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "Gateway machine connection task panicked");
            }
        }
    })
    .await;
    if joined.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        anyhow::bail!("Gateway machine connections exceeded the shutdown deadline");
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    service: Arc<RouteResolveV2Service>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = tokio::time::timeout(TLS_HANDSHAKE_DEADLINE, tls_acceptor.accept(stream))
        .await
        .context("Gateway TLS handshake exceeded its deadline")?
        .context("Gateway TLS handshake failed")?;
    let (_, connection) = tls.get_ref();
    anyhow::ensure!(
        connection.alpn_protocol() == Some(HTTP_11_ALPN),
        "Gateway TLS connection did not negotiate HTTP/1.1"
    );
    let peer_certificates = connection
        .peer_certificates()
        .context("Gateway TLS connection has no verified peer certificate")?;
    let leaf = peer_certificates
        .first()
        .context("Gateway TLS connection has an empty verified peer chain")?;
    let peer =
        VerifiedGatewayTlsPeer::from_verified_spki_sha256(leaf_ed25519_spki_sha256(leaf.as_ref())?);

    let app = Router::new()
        .route(
            ROUTE_RESOLVE_V2_PATH,
            post(route_resolve_v2::resolve).fallback(route_resolve_v2::resolve),
        )
        .fallback(route_resolve_v2::resolve)
        .layer(Extension(peer))
        .layer(Extension(service));
    let mut http = http1::Builder::new();
    http.keep_alive(true)
        .header_read_timeout(REQUEST_HEADER_DEADLINE)
        .timer(TokioTimer::new());
    let connection = http.serve_connection(TokioIo::new(tls), TowerToHyperService::new(app));
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result.context("serve Gateway HTTP/1.1 connection")?,
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                connection.as_mut().graceful_shutdown();
            }
            connection.await.context("gracefully close Gateway HTTP/1.1 connection")?;
        }
    }
    Ok(())
}

fn leaf_ed25519_spki_sha256(certificate_der: &[u8]) -> anyhow::Result<Sha256Digest> {
    canonical_gateway_leaf_spki_sha256(certificate_der)
        .context("Gateway leaf SubjectPublicKeyInfo is not canonical Ed25519 DER")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection};
    use tokio_rustls::TlsConnector;

    const CA_CERTIFICATE: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_ca_certificate.pem");
    const SERVER_CERTIFICATE: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_server_certificate.pem");
    const SERVER_PRIVATE_KEY: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_server_private_key.pem");
    const CLIENT_CERTIFICATE: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_client_certificate.pem");
    const CLIENT_PRIVATE_KEY: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_client_private_key.pem");
    const WRONG_EKU_CERTIFICATE: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_wrong_eku_client_certificate.pem");
    const WRONG_EKU_PRIVATE_KEY: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_wrong_eku_client_private_key.pem");
    const UNKNOWN_CA_CERTIFICATE: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_unknown_ca_certificate.pem");
    const UNKNOWN_CLIENT_CERTIFICATE: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_unknown_client_certificate.pem");
    const UNKNOWN_CLIENT_PRIVATE_KEY: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_unknown_client_private_key.pem");
    const RSA_CLIENT_CERTIFICATE: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_rsa_client_certificate.pem");
    const RSA_CLIENT_PRIVATE_KEY: &[u8] =
        include_bytes!("../tests/fixtures/gateway_machine_rsa_client_private_key.pem");

    struct HandshakeOutcome {
        server_succeeded: bool,
        client_succeeded: bool,
        peer_proof: Option<Result<Sha256Digest, String>>,
    }

    async fn handshake(
        client_chain: Option<&[&[u8]]>,
        client_private_key: Option<&[u8]>,
        client_alpn: &[&[u8]],
    ) -> HandshakeOutcome {
        let server =
            build_tls_config_from_pem(CA_CERTIFICATE, SERVER_CERTIFICATE, SERVER_PRIVATE_KEY)
                .unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(CA_CERTIFICATE).unwrap())
            .unwrap();
        let builder = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
        let mut client = match (client_chain, client_private_key) {
            (Some(chain), Some(key)) => {
                let certificates = chain
                    .iter()
                    .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                let key = PrivatePkcs8KeyDer::from_pem_slice(key).unwrap();
                builder
                    .with_client_auth_cert(certificates, PrivateKeyDer::Pkcs8(key))
                    .unwrap()
            }
            (None, None) => builder.with_no_client_auth(),
            _ => panic!("test client identity must supply both chain and key"),
        };
        client.alpn_protocols = client_alpn
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        // Constructing the connection separately also proves the TLS 1.3-only
        // client configuration is accepted before any I/O starts.
        ClientConnection::new(
            Arc::new(client.clone()),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server_handshake = TlsAcceptor::from(server).accept(server_io);
        let client_handshake = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("localhost").unwrap(), client_io);
        let (server_result, client_result) = tokio::join!(server_handshake, client_handshake);
        let peer_proof = server_result
            .as_ref()
            .ok()
            .filter(|stream| stream.get_ref().1.alpn_protocol() == Some(HTTP_11_ALPN))
            .and_then(|stream| {
                stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .map(|leaf| {
                        leaf_ed25519_spki_sha256(leaf.as_ref()).map_err(|error| error.to_string())
                    })
            });
        HandshakeOutcome {
            server_succeeded: server_result.is_ok(),
            client_succeeded: client_result.is_ok(),
            peer_proof,
        }
    }

    #[test]
    fn fixed_tls_pem_parser_rejects_extra_sections_and_wrong_server_pair() {
        let mut ca_with_key = CA_CERTIFICATE.to_vec();
        ca_with_key.extend_from_slice(SERVER_PRIVATE_KEY);
        assert!(
            build_tls_config_from_pem(&ca_with_key, SERVER_CERTIFICATE, SERVER_PRIVATE_KEY)
                .is_err()
        );

        let mut two_keys = SERVER_PRIVATE_KEY.to_vec();
        two_keys.extend_from_slice(SERVER_PRIVATE_KEY);
        assert!(build_tls_config_from_pem(CA_CERTIFICATE, SERVER_CERTIFICATE, &two_keys).is_err());
        assert!(
            build_tls_config_from_pem(CA_CERTIFICATE, SERVER_CERTIFICATE, CLIENT_PRIVATE_KEY)
                .is_err()
        );
        assert!(build_tls_config_from_pem(
            CA_CERTIFICATE,
            RSA_CLIENT_CERTIFICATE,
            RSA_CLIENT_PRIVATE_KEY,
        )
        .is_err());
    }

    #[tokio::test]
    async fn tls_matrix_requires_known_client_auth_and_canonical_ed25519_leaf() {
        let valid = handshake(
            Some(&[CLIENT_CERTIFICATE]),
            Some(CLIENT_PRIVATE_KEY),
            &[HTTP_11_ALPN],
        )
        .await;
        assert!(valid.server_succeeded && valid.client_succeeded);
        assert_eq!(
            valid.peer_proof.unwrap().unwrap().as_str(),
            "sha256:c82f69461d48dda0d056def48aff86908f4f32213163d47de658ea98c6527795"
        );

        let anonymous = handshake(None, None, &[HTTP_11_ALPN]).await;
        assert!(!anonymous.server_succeeded || !anonymous.client_succeeded);
        assert!(anonymous.peer_proof.is_none());

        let unknown = handshake(
            Some(&[UNKNOWN_CLIENT_CERTIFICATE, UNKNOWN_CA_CERTIFICATE]),
            Some(UNKNOWN_CLIENT_PRIVATE_KEY),
            &[HTTP_11_ALPN],
        )
        .await;
        assert!(!unknown.server_succeeded || !unknown.client_succeeded);
        assert!(unknown.peer_proof.is_none());

        let wrong_eku = handshake(
            Some(&[WRONG_EKU_CERTIFICATE]),
            Some(WRONG_EKU_PRIVATE_KEY),
            &[HTTP_11_ALPN],
        )
        .await;
        assert!(!wrong_eku.server_succeeded || !wrong_eku.client_succeeded);
        assert!(wrong_eku.peer_proof.is_none());

        // The CA may legitimately issue another algorithm, but Cats never
        // turns such a leaf into the typed Gateway proof.
        let rsa = handshake(
            Some(&[RSA_CLIENT_CERTIFICATE]),
            Some(RSA_CLIENT_PRIVATE_KEY),
            &[HTTP_11_ALPN],
        )
        .await;
        assert!(rsa.server_succeeded && rsa.client_succeeded);
        assert!(rsa.peer_proof.unwrap().is_err());

        let no_alpn = handshake(Some(&[CLIENT_CERTIFICATE]), Some(CLIENT_PRIVATE_KEY), &[]).await;
        assert!(no_alpn.server_succeeded && no_alpn.client_succeeded);
        assert!(no_alpn.peer_proof.is_none());

        let wrong_alpn = handshake(
            Some(&[CLIENT_CERTIFICATE]),
            Some(CLIENT_PRIVATE_KEY),
            &[b"h2"],
        )
        .await;
        assert!(!wrong_alpn.server_succeeded || !wrong_alpn.client_succeeded);
        assert!(wrong_alpn.peer_proof.is_none());
    }

    #[test]
    fn leaf_spki_parser_is_bounded_and_rejects_non_certificate_der() {
        let certificate = CertificateDer::from_pem_slice(CLIENT_CERTIFICATE).unwrap();
        assert_eq!(
            leaf_ed25519_spki_sha256(certificate.as_ref())
                .unwrap()
                .as_str(),
            "sha256:c82f69461d48dda0d056def48aff86908f4f32213163d47de658ea98c6527795"
        );
        assert!(leaf_ed25519_spki_sha256(&certificate[..certificate.len() - 1]).is_err());
        assert!(leaf_ed25519_spki_sha256(&[0_u8; 12]).is_err());
    }
}

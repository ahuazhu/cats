//! TLS 1.3 / HTTP/1.1 Gateway-to-Node Route v2 tunnel ingress.
//!
//! One authenticated request is upgraded into the actual public-request byte
//! tunnel. The handler verifies the signed Grant and acquires the same
//! process-owned per-Cat admission cell used by reconciliation before it opens
//! the Guest TCP socket. No legacy bearer, Node URL, or HTTP-supplied identity
//! participates in this boundary.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use bytes::Bytes;
use cats_api::gateway_workload_identity::canonical_gateway_leaf_spki_sha256;
use cats_api::route_grant_v2::{
    decode_route_tunnel_v2_request, encode_route_admission_v2_failure, RouteAdmissionV2Failure,
    RouteAdmissionV2Reason, ROUTE_TUNNEL_V2_CONNECT_DEADLINE_MILLIS, ROUTE_TUNNEL_V2_METHOD,
    ROUTE_TUNNEL_V2_PATH, ROUTE_TUNNEL_V2_REQUEST_MAX_WIRE_BYTES, ROUTE_TUNNEL_V2_UPGRADE,
    ROUTE_V2_JSON_CONTENT_TYPE,
};
use cats_api::runtime_artifacts::InstalledNodeRouteV2MachineArtifacts;
use cats_api::runtime_reconciliation::{HttpProtocol, Id, Sha256Digest};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::route_grant_v2::{
    AdmittedRouteV2, AuthenticatedGatewayPrincipal, RouteAdmissionV2RequestBinding,
    RouteGrantV2KeyRing, RouteGrantV2Verifier,
};
use crate::runtime::reconciliation::AdmissionCellRegistry;

const TLS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const REQUEST_HEADER_DEADLINE: Duration = Duration::from_secs(5);
const REQUEST_BODY_DEADLINE: Duration = Duration::from_secs(2);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(35);
const CONNECTION_LIMIT: usize = 64;
const TUNNEL_LIMIT: usize = 256;
const HTTP_11_ALPN: &[u8] = b"http/1.1";
#[cfg(test)]
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Fully pinned production configuration for the Node machine listener.
pub struct RouteV2MachineConfig {
    listen: String,
    local_node_id: Id,
    tls: Arc<ServerConfig>,
    verifier: Arc<RouteGrantV2Verifier>,
}

impl std::fmt::Debug for RouteV2MachineConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteV2MachineConfig")
            .field("listen", &self.listen)
            .field("local_node_id", &self.local_node_id)
            .field("tls", &"[redacted]")
            .field("verifier", &self.verifier)
            .finish()
    }
}

impl RouteV2MachineConfig {
    pub fn from_installed_artifacts(
        listen: String,
        local_node_id: Id,
        artifacts: &InstalledNodeRouteV2MachineArtifacts,
    ) -> anyhow::Result<Self> {
        let ring = RouteGrantV2KeyRing::from_artifact(artifacts.ring().ring())
            .context("compose installed Route Grant v2 verification ring")?;
        let tls = build_server_tls(
            artifacts.gateway_client_ca_bundle_pem(),
            artifacts.server_certificate_pem(),
            artifacts.server_private_key_pem(),
        )?;
        Ok(Self {
            listen,
            local_node_id,
            tls,
            verifier: Arc::new(RouteGrantV2Verifier::new(ring)),
        })
    }

    pub(crate) fn verifier(&self) -> Arc<RouteGrantV2Verifier> {
        Arc::clone(&self.verifier)
    }

    #[cfg(test)]
    fn for_test(
        listen: String,
        local_node_id: Id,
        client_ca_bundle_pem: &[u8],
        server_certificate_pem: &[u8],
        server_private_key_pem: &[u8],
        verifier: Arc<RouteGrantV2Verifier>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            listen,
            local_node_id,
            tls: build_server_tls(
                client_ca_bundle_pem,
                server_certificate_pem,
                server_private_key_pem,
            )?,
            verifier,
        })
    }
}

pub(crate) struct RouteV2MachineListener {
    addr: SocketAddr,
    service: Arc<RouteV2MachineService>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl RouteV2MachineListener {
    pub(crate) async fn spawn(
        config: RouteV2MachineConfig,
        registry: Arc<AdmissionCellRegistry>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(&config.listen)
            .await
            .with_context(|| format!("bind Node Route v2 machine listener {}", config.listen))?;
        let addr = listener.local_addr()?;
        let (stop, shutdown) = watch::channel(false);
        let service = Arc::new(RouteV2MachineService::new(
            config.local_node_id,
            config.verifier,
            registry,
        ));
        let run_service = Arc::clone(&service);
        let task = tokio::spawn(run_listener(listener, config.tls, run_service, shutdown));
        Ok(Self {
            addr,
            service,
            stop,
            task: Some(task),
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn begin_shutdown(&self) {
        self.service.begin_shutdown();
        self.stop.send_replace(true);
    }

    pub(crate) async fn wait(&mut self) -> anyhow::Result<()> {
        let task = self
            .task
            .as_mut()
            .context("Node Route v2 listener already joined")?;
        let joined = task.await;
        self.task.take();
        joined.context("Node Route v2 listener task panicked")?
    }

    pub(crate) async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.begin_shutdown();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match tokio::time::timeout(SHUTDOWN_DEADLINE, &mut task).await {
            Ok(joined) => joined.context("Node Route v2 listener task panicked")?,
            Err(_) => {
                task.abort();
                let _ = task.await;
                anyhow::bail!("Node Route v2 listener exceeded its shutdown deadline");
            }
        }
    }
}

impl Drop for RouteV2MachineListener {
    fn drop(&mut self) {
        self.begin_shutdown();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct RouteV2MachineService {
    local_node_id: Id,
    verifier: Arc<RouteGrantV2Verifier>,
    registry: Arc<AdmissionCellRegistry>,
    accepting: AtomicBool,
    permits: Arc<tokio::sync::Semaphore>,
    tunnel_sender: mpsc::Sender<TunnelJob>,
    tunnel_receiver: Mutex<Option<mpsc::Receiver<TunnelJob>>>,
}

impl RouteV2MachineService {
    fn new(
        local_node_id: Id,
        verifier: Arc<RouteGrantV2Verifier>,
        registry: Arc<AdmissionCellRegistry>,
    ) -> Self {
        let (tunnel_sender, tunnel_receiver) = mpsc::channel(TUNNEL_LIMIT);
        Self {
            local_node_id,
            verifier,
            registry,
            accepting: AtomicBool::new(true),
            permits: Arc::new(tokio::sync::Semaphore::new(TUNNEL_LIMIT)),
            tunnel_sender,
            tunnel_receiver: Mutex::new(Some(tunnel_receiver)),
        }
    }

    fn begin_shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        self.permits.close();
    }

    fn try_begin(&self) -> Option<OwnedSemaphorePermit> {
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    fn take_tunnel_receiver(&self) -> anyhow::Result<mpsc::Receiver<TunnelJob>> {
        self.tunnel_receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .context("Node Route v2 tunnel supervisor was already started")
    }
}

struct TunnelJob {
    on_upgrade: hyper::upgrade::OnUpgrade,
    upstream: TcpStream,
    admitted: AdmittedRouteV2,
    _permit: OwnedSemaphorePermit,
}

async fn run_listener(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    service: Arc<RouteV2MachineService>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let connection_permits = Arc::new(tokio::sync::Semaphore::new(CONNECTION_LIMIT));
    let (connection_shutdown, _) = watch::channel(false);
    let (tunnel_shutdown, _) = watch::channel(false);
    let tunnel_receiver = service.take_tunnel_receiver()?;
    let mut tunnel_supervisor = tokio::spawn(run_tunnel_supervisor(
        tunnel_receiver,
        tunnel_shutdown.subscribe(),
    ));
    let mut connections = JoinSet::new();

    let (run_result, tunnel_supervisor_result) = loop {
        if *shutdown.borrow() {
            break (Ok(()), None);
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break (Ok(()), None);
                }
            }
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = joined {
                    tracing::warn!(%error, "Node Route v2 connection task panicked");
                }
            }
            result = &mut tunnel_supervisor => {
                service.begin_shutdown();
                let result = match result {
                    Ok(result) => result,
                    Err(error) => Err(anyhow::Error::new(error)
                        .context("Node Route v2 tunnel supervisor panicked")),
                };
                break (Ok(()), Some(result));
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        break (
                            Err(anyhow::Error::new(error)
                                .context("accept Node Route v2 machine connection")),
                            None,
                        );
                    }
                };
                let Ok(permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                if let Err(error) = stream.set_nodelay(true) {
                    break (
                        Err(anyhow::Error::new(error)
                            .context("set Node Route v2 TCP_NODELAY")),
                        None,
                    );
                }
                let acceptor = tls_acceptor.clone();
                let service = Arc::clone(&service);
                let connection_shutdown = connection_shutdown.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(stream, acceptor, service, connection_shutdown).await {
                        tracing::debug!(%error, "Node Route v2 machine connection closed");
                    }
                });
            }
        }
    };

    service.begin_shutdown();
    let _ = connection_shutdown.send(true);
    let _ = tunnel_shutdown.send(true);
    let tunnel_supervisor_finished = tunnel_supervisor_result.is_some();
    let shutdown_result = tokio::time::timeout(SHUTDOWN_DEADLINE, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "Node Route v2 connection task panicked");
            }
        }
        match tunnel_supervisor_result {
            Some(result) => result,
            None => (&mut tunnel_supervisor)
                .await
                .context("Node Route v2 tunnel supervisor panicked")?,
        }
    })
    .await;
    let cleanup_result = match shutdown_result {
        Ok(result) => result,
        Err(_) => {
            connections.abort_all();
            if !tunnel_supervisor_finished {
                tunnel_supervisor.abort();
            }
            while connections.join_next().await.is_some() {}
            if !tunnel_supervisor_finished {
                let _ = tunnel_supervisor.await;
            }
            Err(anyhow::anyhow!(
                "Node Route v2 connections exceeded the shutdown deadline"
            ))
        }
    };
    run_result.and(cleanup_result)
}

async fn serve_connection(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    service: Arc<RouteV2MachineService>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = tokio::time::timeout(TLS_HANDSHAKE_DEADLINE, tls_acceptor.accept(stream))
        .await
        .context("Node Route v2 TLS handshake exceeded its deadline")?
        .context("Node Route v2 TLS handshake failed")?;
    let (_, connection) = tls.get_ref();
    anyhow::ensure!(
        connection.alpn_protocol() == Some(HTTP_11_ALPN),
        "Node Route v2 TLS connection did not negotiate HTTP/1.1"
    );
    let leaf = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("Node Route v2 TLS connection has no verified Gateway leaf")?;
    let principal = AuthenticatedGatewayPrincipal::from_verified_spki_sha256(
        leaf_ed25519_spki_sha256(leaf.as_ref())?,
    );
    let request_service = Arc::clone(&service);
    let http_service = service_fn(move |request| {
        handle_tunnel_request(request, Arc::clone(&request_service), principal.clone())
    });
    let mut http = http1::Builder::new();
    http.keep_alive(false)
        .header_read_timeout(REQUEST_HEADER_DEADLINE)
        .timer(TokioTimer::new());
    let connection = http
        .serve_connection(TokioIo::new(tls), http_service)
        .with_upgrades();
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result.context("serve Node Route v2 HTTP/1.1 connection")?,
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                connection.as_mut().graceful_shutdown();
            }
            connection.await.context("gracefully close Node Route v2 HTTP/1.1 connection")?;
        }
    }
    Ok(())
}

async fn handle_tunnel_request(
    mut request: Request<Incoming>,
    service: Arc<RouteV2MachineService>,
    principal: AuthenticatedGatewayPrincipal,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let Some(permit) = service.try_begin() else {
        return Ok(plain_response(StatusCode::SERVICE_UNAVAILABLE));
    };
    if !valid_tunnel_head(&request) {
        return Ok(plain_response(StatusCode::BAD_REQUEST));
    }
    let on_upgrade = hyper::upgrade::on(&mut request);
    let body =
        match tokio::time::timeout(REQUEST_BODY_DEADLINE, request.into_body().collect()).await {
            Ok(Ok(body)) => body.to_bytes(),
            _ => return Ok(plain_response(StatusCode::BAD_REQUEST)),
        };
    if body.len() > ROUTE_TUNNEL_V2_REQUEST_MAX_WIRE_BYTES {
        return Ok(plain_response(StatusCode::BAD_REQUEST));
    }
    let frame = match decode_route_tunnel_v2_request(&body) {
        Ok(frame) => frame,
        Err(_) => return Ok(plain_response(StatusCode::BAD_REQUEST)),
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_secs(),
        Err(_) => return Ok(plain_response(StatusCode::SERVICE_UNAVAILABLE)),
    };
    let binding = RouteAdmissionV2RequestBinding {
        local_node_id: service.local_node_id.clone(),
        cat_id: frame.cat_id,
        endpoint_id: frame.endpoint_id,
        canonical_hostname: frame.hostname,
        protocol: HttpProtocol::Http,
    };
    let verified =
        match service
            .verifier
            .verify_request(&principal, &frame.opaque_grant, &binding, now)
        {
            Ok(verified) => verified,
            Err(failure) => return Ok(failure_response(failure)),
        };
    let Some(cell) = service.registry.get(verified.cat_id()) else {
        return Ok(failure_response(
            RouteAdmissionV2Failure::pre_admission(RouteAdmissionV2Reason::RuntimeNotReady)
                .expect("RuntimeNotReady is pre-admission"),
        ));
    };
    let admitted = match verified.admit(&cell) {
        Ok(admitted) => admitted,
        Err(failure) => return Ok(failure_response(failure)),
    };
    let upstream_target = format!(
        "{}:{}",
        admitted.guest_ipv4(),
        admitted.claims().target_port
    );
    let upstream = match tokio::time::timeout(
        Duration::from_millis(ROUTE_TUNNEL_V2_CONNECT_DEADLINE_MILLIS),
        TcpStream::connect(upstream_target),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => {
            return Ok(failure_response(
                RouteAdmissionV2Failure::upstream_unavailable(),
            ))
        }
    };
    if upstream.set_nodelay(true).is_err()
        || service
            .tunnel_sender
            .try_send(TunnelJob {
                on_upgrade,
                upstream,
                admitted,
                _permit: permit,
            })
            .is_err()
    {
        return Ok(failure_response(
            RouteAdmissionV2Failure::upstream_unavailable(),
        ));
    }
    Ok(upgrade_response())
}

fn valid_tunnel_head(request: &Request<Incoming>) -> bool {
    request.method() == Method::POST
        && ROUTE_TUNNEL_V2_METHOD == "POST"
        && request.version() == Version::HTTP_11
        && exact_uri(request.uri(), ROUTE_TUNNEL_V2_PATH)
        && headers_are_exact(request.headers())
}

fn exact_uri(uri: &Uri, expected_path: &str) -> bool {
    uri.path() == expected_path && uri.query().is_none()
}

fn headers_are_exact(headers: &HeaderMap) -> bool {
    if headers.keys().any(|name| {
        name != header::HOST
            && name != header::CONTENT_TYPE
            && name != header::CONTENT_LENGTH
            && name != header::CONNECTION
            && name != header::UPGRADE
    }) {
        return false;
    }
    single_header(headers, header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes() == ROUTE_V2_JSON_CONTENT_TYPE.as_bytes())
        && single_header(headers, header::CONNECTION)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"upgrade"))
        && single_header(headers, header::UPGRADE).is_some_and(|value| {
            value
                .as_bytes()
                .eq_ignore_ascii_case(ROUTE_TUNNEL_V2_UPGRADE.as_bytes())
        })
        && single_header(headers, header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length <= ROUTE_TUNNEL_V2_REQUEST_MAX_WIRE_BYTES)
}

fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn upgrade_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, ROUTE_TUNNEL_V2_UPGRADE)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::new()))
        .expect("fixed Route v2 upgrade response is valid")
}

fn failure_response(failure: RouteAdmissionV2Failure) -> Response<Full<Bytes>> {
    let status = if failure.guard_acquired {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::CONFLICT
    };
    match encode_route_admission_v2_failure(&failure) {
        Ok(body) => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::from(body)))
            .expect("fixed Route v2 failure response is valid"),
        Err(_) => plain_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn plain_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::new()))
        .expect("fixed Route v2 empty response is valid")
}

async fn run_tunnel_supervisor(
    mut receiver: mpsc::Receiver<TunnelJob>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let (task_shutdown, _) = watch::channel(false);
    let mut tunnels = JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            job = receiver.recv() => match job {
                Some(job) => {
                    let task_shutdown = task_shutdown.subscribe();
                    tunnels.spawn(run_tunnel(job, task_shutdown));
                }
                None => break,
            },
            Some(joined) = tunnels.join_next(), if !tunnels.is_empty() => {
                if let Err(error) = joined {
                    tracing::warn!(%error, "Node Route v2 tunnel task panicked");
                }
            }
        }
    }
    receiver.close();
    while receiver.try_recv().is_ok() {}
    let _ = task_shutdown.send(true);
    while let Some(result) = tunnels.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "Node Route v2 tunnel task panicked during shutdown");
        }
    }
    Ok(())
}

async fn run_tunnel(job: TunnelJob, mut shutdown: watch::Receiver<bool>) {
    let TunnelJob {
        on_upgrade,
        upstream,
        mut admitted,
        _permit,
    } = job;
    let upgraded = tokio::select! {
        result = on_upgrade => match result {
            Ok(upgraded) => upgraded,
            Err(_) => return,
        },
        _ = shutdown.changed() => return,
        _ = admitted.cancelled() => return,
    };
    let mut downstream = TokioIo::new(upgraded);
    let mut upstream = upstream;
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {}
        _ = shutdown.changed() => {}
        _ = admitted.cancelled() => {}
    }
    drop(admitted);
    drop(_permit);
}

fn build_server_tls(
    client_ca_bundle_pem: &[u8],
    server_certificate_pem: &[u8],
    server_private_key_pem: &[u8],
) -> anyhow::Result<Arc<ServerConfig>> {
    let client_ca_certificates = strict_certificates(client_ca_bundle_pem, "Gateway client CA")?;
    let mut client_roots = RootCertStore::empty();
    for certificate in client_ca_certificates {
        client_roots
            .add(certificate)
            .context("add Gateway client CA certificate")?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider))
            .build()
            .context("build mandatory Gateway client-certificate verifier")?;
    let server_certificates = strict_certificates(server_certificate_pem, "Node server")?;
    let leaf = server_certificates
        .first()
        .context("Node Route v2 server chain has no leaf")?;
    leaf_ed25519_spki_sha256(leaf.as_ref())
        .context("Node Route v2 server leaf is not canonical Ed25519")?;
    validate_private_key_pem(server_private_key_pem)?;
    let private_key = PrivatePkcs8KeyDer::from_pem_slice(server_private_key_pem)
        .context("decode Node Route v2 PKCS#8 server private key")?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("build TLS 1.3-only Node Route v2 configuration")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certificates, PrivateKeyDer::Pkcs8(private_key))
        .context("validate Node Route v2 server certificate/private-key pair")?;
    // The handler derives authority from the leaf on this exact connection;
    // do not replace that proof with a TLS 1.3 resumption ticket.
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    Ok(Arc::new(config))
}

fn strict_certificates(
    bytes: &[u8],
    description: &'static str,
) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    validate_pem_sequence(bytes, "CERTIFICATE", false)?;
    CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("decode fixed {description} certificate chain"))
}

fn validate_private_key_pem(bytes: &[u8]) -> anyhow::Result<()> {
    validate_pem_sequence(bytes, "PRIVATE KEY", true).map(|_| ())
}

fn validate_pem_sequence(bytes: &[u8], label: &str, exactly_one: bool) -> anyhow::Result<usize> {
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
    if exactly_one {
        anyhow::ensure!(
            count == 1,
            "fixed TLS PEM must contain exactly one private key"
        );
    } else {
        anyhow::ensure!(count > 0, "fixed TLS PEM contains no certificates");
    }
    Ok(count)
}

fn leaf_ed25519_spki_sha256(certificate_der: &[u8]) -> anyhow::Result<Sha256Digest> {
    canonical_gateway_leaf_spki_sha256(certificate_der)
        .context("Gateway leaf SubjectPublicKeyInfo is not canonical Ed25519 DER")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::route_grant_v2::{
        decode_route_admission_v2_failure, encode_route_tunnel_v2_request, RouteGrantV2Claims,
        RouteGrantV2ProtectedHeader, RouteGrantV2PublicKey, RouteGrantV2SigningInput,
        RouteTunnelV2Request, ROUTE_GRANT_V2_AUDIENCE, ROUTE_GRANT_V2_ISSUER,
        ROUTE_GRANT_V2_VERSION,
    };
    use cats_api::runtime_reconciliation::{
        AssignedKind, AssignedPlacement, CheckpointRouteGate, Epoch, Hostname, Ipv4Address,
        LifecycleAdmission, RandomId128, Revision, RouteGateBinding, RouteGateState,
    };
    use hyper::client::conn::http1 as client_http1;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use rustls::pki_types::ServerName;
    use rustls::ClientConfig;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsConnector;

    use crate::runtime::reconciliation::{
        AdmissionCell, AdmissionGatePort as _, AdmissionSnapshot,
    };

    const CA_CERTIFICATE: &[u8] =
        include_bytes!("../../control-plane/tests/fixtures/gateway_machine_ca_certificate.pem");
    const SERVER_CERTIFICATE: &[u8] =
        include_bytes!("../../control-plane/tests/fixtures/gateway_machine_server_certificate.pem");
    const SERVER_PRIVATE_KEY: &[u8] =
        include_bytes!("../../control-plane/tests/fixtures/gateway_machine_server_private_key.pem");
    const CLIENT_CERTIFICATE: &[u8] =
        include_bytes!("../../control-plane/tests/fixtures/gateway_machine_client_certificate.pem");
    const CLIENT_PRIVATE_KEY: &[u8] =
        include_bytes!("../../control-plane/tests/fixtures/gateway_machine_client_private_key.pem");
    const UNKNOWN_CA_CERTIFICATE: &[u8] = include_bytes!(
        "../../control-plane/tests/fixtures/gateway_machine_unknown_ca_certificate.pem"
    );
    const UNKNOWN_CLIENT_CERTIFICATE: &[u8] = include_bytes!(
        "../../control-plane/tests/fixtures/gateway_machine_unknown_client_certificate.pem"
    );
    const UNKNOWN_CLIENT_PRIVATE_KEY: &[u8] = include_bytes!(
        "../../control-plane/tests/fixtures/gateway_machine_unknown_client_private_key.pem"
    );
    const WRONG_EKU_CLIENT_CERTIFICATE: &[u8] = include_bytes!(
        "../../control-plane/tests/fixtures/gateway_machine_wrong_eku_client_certificate.pem"
    );
    const WRONG_EKU_CLIENT_PRIVATE_KEY: &[u8] = include_bytes!(
        "../../control-plane/tests/fixtures/gateway_machine_wrong_eku_client_private_key.pem"
    );
    const RSA_CLIENT_CERTIFICATE: &[u8] = include_bytes!(
        "../../control-plane/tests/fixtures/gateway_machine_rsa_client_certificate.pem"
    );
    const RSA_CLIENT_PRIVATE_KEY: &[u8] = include_bytes!(
        "../../control-plane/tests/fixtures/gateway_machine_rsa_client_private_key.pem"
    );

    struct TestKeys {
        public: RouteGrantV2PublicKey,
        private: Ed25519KeyPair,
    }

    fn keys() -> TestKeys {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let private = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(private.public_key().as_ref());
        TestKeys {
            public: RouteGrantV2PublicKey::from_spki_der(&spki).unwrap(),
            private,
        }
    }

    fn gateway_digest() -> Sha256Digest {
        let certificate = CertificateDer::from_pem_slice(CLIENT_CERTIFICATE).unwrap();
        leaf_ed25519_spki_sha256(certificate.as_ref()).unwrap()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn claims(cat: &str, endpoint: &str, target_port: u16) -> RouteGrantV2Claims {
        let now = now();
        RouteGrantV2Claims {
            version: ROUTE_GRANT_V2_VERSION,
            iss: ROUTE_GRANT_V2_ISSUER.to_owned(),
            aud: ROUTE_GRANT_V2_AUDIENCE.to_owned(),
            workspace_id: Id::new("ws_01").unwrap(),
            endpoint_id: Id::new(endpoint).unwrap(),
            hostname: Hostname::new("app.cats.run").unwrap(),
            cat_id: Id::new(cat).unwrap(),
            node_id: Id::new("node-a").unwrap(),
            runtime_incarnation: RandomId128::new("11111111111111111111111111111111").unwrap(),
            route_epoch: Epoch::new(7).unwrap(),
            protocol: HttpProtocol::Http,
            target_port,
            gateway_public_key_spki_sha256: gateway_digest(),
            iat: now,
            nbf: now,
            exp: now + 120,
        }
    }

    fn sign(keys: &TestKeys, claims: &RouteGrantV2Claims) -> String {
        sign_with_private(&keys.public, &keys.private, claims)
    }

    fn sign_with_private(
        public: &RouteGrantV2PublicKey,
        private: &Ed25519KeyPair,
        claims: &RouteGrantV2Claims,
    ) -> String {
        let input = RouteGrantV2SigningInput::new(
            &RouteGrantV2ProtectedHeader::new(public.kid().clone()),
            claims,
        )
        .unwrap();
        let signature: [u8; 64] = private.sign(input.as_bytes()).as_ref().try_into().unwrap();
        input.finish(&signature).unwrap()
    }

    fn cell(claims: &RouteGrantV2Claims, gate: RouteGateState) -> Arc<AdmissionCell> {
        cell_with_guest_target(claims, gate, true)
    }

    fn cell_with_guest_target(
        claims: &RouteGrantV2Claims,
        gate: RouteGateState,
        has_guest_target: bool,
    ) -> Arc<AdmissionCell> {
        let snapshot = AdmissionSnapshot::new(
            Revision::new(11).unwrap(),
            Sha256Digest::from_bytes([0x11; 32]),
            AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: claims.node_id.clone(),
                placement_epoch: Epoch::new(3).unwrap(),
            },
            Some(claims.runtime_incarnation.clone()),
            LifecycleAdmission::Open,
            vec![CheckpointRouteGate {
                binding: RouteGateBinding {
                    workspace_id: claims.workspace_id.clone(),
                    endpoint_id: claims.endpoint_id.clone(),
                    hostname: claims.hostname.clone(),
                    cat_id: claims.cat_id.clone(),
                    node_id: claims.node_id.clone(),
                    runtime_incarnation: claims.runtime_incarnation.clone(),
                    route_epoch: claims.route_epoch,
                    protocol: claims.protocol,
                    target_port: claims.target_port,
                },
                gate,
            }],
        );
        let snapshot = if has_guest_target {
            snapshot.with_guest_ipv4(Ipv4Address::new("127.0.0.1").unwrap())
        } else {
            snapshot
        };
        AdmissionCell::new(snapshot).unwrap()
    }

    async fn listener(
        keys: &TestKeys,
        registry: Arc<AdmissionCellRegistry>,
    ) -> RouteV2MachineListener {
        let ring =
            RouteGrantV2KeyRing::new(Epoch::new(1).unwrap(), vec![keys.public.clone()]).unwrap();
        let config = RouteV2MachineConfig::for_test(
            "127.0.0.1:0".to_owned(),
            Id::new("node-a").unwrap(),
            CA_CERTIFICATE,
            SERVER_CERTIFICATE,
            SERVER_PRIVATE_KEY,
            Arc::new(RouteGrantV2Verifier::new(ring)),
        )
        .unwrap();
        RouteV2MachineListener::spawn(config, registry)
            .await
            .unwrap()
    }

    fn client_tls(client_certificate: &[u8], client_private_key: &[u8]) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(CA_CERTIFICATE).unwrap())
            .unwrap();
        let certificates = CertificateDer::pem_slice_iter(client_certificate)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let private_key = PrivatePkcs8KeyDer::from_pem_slice(client_private_key).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, PrivateKeyDer::Pkcs8(private_key))
            .unwrap();
        config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        Arc::new(config)
    }

    enum Exchange {
        Upgraded(TokioIo<hyper::upgrade::Upgraded>),
        Rejected(StatusCode, Vec<u8>),
    }

    async fn exchange(
        address: SocketAddr,
        frame: &RouteTunnelV2Request,
        certificate: &[u8],
        private_key: &[u8],
    ) -> Result<Exchange, ()> {
        let tcp = TcpStream::connect(address).await.map_err(|_| ())?;
        let tls = TlsConnector::from(client_tls(certificate, private_key))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .map_err(|_| ())?;
        let (mut sender, connection) = client_http1::Builder::new()
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| ())?;
        let connection = tokio::spawn(async move { connection.with_upgrades().await });
        let body = encode_route_tunnel_v2_request(frame).unwrap();
        let response = sender
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri(ROUTE_TUNNEL_V2_PATH)
                    .header(header::HOST, "localhost")
                    .header(header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
                    .header(header::CONTENT_LENGTH, body.len())
                    .header(header::CONNECTION, "upgrade")
                    .header(header::UPGRADE, ROUTE_TUNNEL_V2_UPGRADE)
                    .body(Full::new(Bytes::from(body)))
                    .unwrap(),
            )
            .await
            .map_err(|_| ())?;
        let status = response.status();
        if status == StatusCode::SWITCHING_PROTOCOLS {
            let upgraded = hyper::upgrade::on(response).await.map_err(|_| ())?;
            connection.await.map_err(|_| ())?.map_err(|_| ())?;
            Ok(Exchange::Upgraded(TokioIo::new(upgraded)))
        } else {
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|_| ())?
                .to_bytes()
                .to_vec();
            connection.abort();
            let _ = connection.await;
            Ok(Exchange::Rejected(status, body))
        }
    }

    fn frame(claims: &RouteGrantV2Claims, token: String) -> RouteTunnelV2Request {
        RouteTunnelV2Request::new(
            claims.cat_id.clone(),
            claims.endpoint_id.clone(),
            claims.hostname.clone(),
            token,
        )
        .unwrap()
    }

    fn rejection(exchange: Exchange) -> (StatusCode, RouteAdmissionV2Failure) {
        match exchange {
            Exchange::Rejected(status, body) => {
                (status, decode_route_admission_v2_failure(&body).unwrap())
            }
            Exchange::Upgraded(_) => panic!("expected admission rejection"),
        }
    }

    #[tokio::test]
    async fn authenticated_upgrade_copies_bytes_and_shutdown_releases_guard() {
        let guest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = guest.local_addr().unwrap().port();
        let guest_task = tokio::spawn(async move {
            let (mut stream, _) = guest.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            stream.write_all(b"pong").await.unwrap();
            let mut tail = [0_u8; 1];
            assert_eq!(stream.read(&mut tail).await.unwrap(), 0);
        });
        let keys = keys();
        let claims = claims("cat_success", "ep_success", target_port);
        let active = cell(&claims, RouteGateState::Active);
        let temp = TempDir::new().unwrap();
        let registry = AdmissionCellRegistry::new(temp.path().join("checkpoints"));
        registry
            .insert_cell_for_machine_test(claims.cat_id.clone(), Arc::clone(&active))
            .unwrap();
        let mut listener = listener(&keys, registry).await;
        let exchange = exchange(
            listener.addr(),
            &frame(&claims, sign(&keys, &claims)),
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .await
        .unwrap();
        let mut tunnel = match exchange {
            Exchange::Upgraded(tunnel) => tunnel,
            Exchange::Rejected(status, body) => {
                panic!("unexpected rejection {status}: {body:?}")
            }
        };
        assert_eq!(active.active_guards(&claims.endpoint_id), Some(1));
        tunnel.write_all(b"ping").await.unwrap();
        let mut pong = [0_u8; 4];
        tunnel.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        listener.shutdown().await.unwrap();
        let mut tail = [0_u8; 1];
        let closed = tunnel.read(&mut tail).await;
        assert!(match closed {
            Ok(0) => true,
            Err(error) => error.kind() == std::io::ErrorKind::UnexpectedEof,
            Ok(_) => false,
        });
        assert_eq!(active.active_guards(&claims.endpoint_id), Some(0));
        guest_task.await.unwrap();
    }

    #[tokio::test]
    async fn closing_one_gate_cancels_only_that_live_machine_tunnel() {
        let guest_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let guest_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let claims_a = claims("cat_pair", "ep_a", guest_a.local_addr().unwrap().port());
        let claims_b = claims("cat_pair", "ep_b", guest_b.local_addr().unwrap().port());
        let guest_a_task = tokio::spawn(async move {
            let (mut stream, _) = guest_a.accept().await.unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });
        let guest_b_task = tokio::spawn(async move {
            let (mut stream, _) = guest_b.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            stream.write_all(b"pong").await.unwrap();
            let mut tail = [0_u8; 1];
            assert_eq!(stream.read(&mut tail).await.unwrap(), 0);
        });
        let routes = [&claims_a, &claims_b]
            .into_iter()
            .map(|claims| CheckpointRouteGate {
                binding: RouteGateBinding {
                    workspace_id: claims.workspace_id.clone(),
                    endpoint_id: claims.endpoint_id.clone(),
                    hostname: claims.hostname.clone(),
                    cat_id: claims.cat_id.clone(),
                    node_id: claims.node_id.clone(),
                    runtime_incarnation: claims.runtime_incarnation.clone(),
                    route_epoch: claims.route_epoch,
                    protocol: claims.protocol,
                    target_port: claims.target_port,
                },
                gate: RouteGateState::Active,
            })
            .collect();
        let snapshot = AdmissionSnapshot::new(
            Revision::new(11).unwrap(),
            Sha256Digest::from_bytes([0x11; 32]),
            AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: claims_a.node_id.clone(),
                placement_epoch: Epoch::new(3).unwrap(),
            },
            Some(claims_a.runtime_incarnation.clone()),
            LifecycleAdmission::Open,
            routes,
        )
        .with_guest_ipv4(Ipv4Address::new("127.0.0.1").unwrap());
        let active = AdmissionCell::new(snapshot).unwrap();
        let keys = keys();
        let temp = TempDir::new().unwrap();
        let registry = AdmissionCellRegistry::new(temp.path().join("checkpoints"));
        registry
            .insert_cell_for_machine_test(claims_a.cat_id.clone(), Arc::clone(&active))
            .unwrap();
        let mut listener = listener(&keys, registry).await;
        let mut tunnel_a = match exchange(
            listener.addr(),
            &frame(&claims_a, sign(&keys, &claims_a)),
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .await
        .unwrap()
        {
            Exchange::Upgraded(tunnel) => tunnel,
            Exchange::Rejected(status, _) => panic!("A was rejected with {status}"),
        };
        let mut tunnel_b = match exchange(
            listener.addr(),
            &frame(&claims_b, sign(&keys, &claims_b)),
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .await
        .unwrap()
        {
            Exchange::Upgraded(tunnel) => tunnel,
            Exchange::Rejected(status, _) => panic!("B was rejected with {status}"),
        };
        assert_eq!(active.active_guards(&claims_a.endpoint_id), Some(1));
        assert_eq!(active.active_guards(&claims_b.endpoint_id), Some(1));

        let expected = active.snapshot();
        let mut closed_routes = expected.endpoints().to_vec();
        closed_routes[0].gate = RouteGateState::Closed;
        let closed_a = AdmissionSnapshot::new(
            expected.applied_desired_revision(),
            expected.spec_digest().clone(),
            expected.placement().clone(),
            expected.runtime_incarnation().cloned(),
            expected.lifecycle_admission(),
            closed_routes,
        )
        .with_guest_ipv4(expected.guest_ipv4().cloned().unwrap());
        active
            .port()
            .close_gate(&expected, &closed_a, &claims_a.endpoint_id)
            .unwrap();

        let mut tail = [0_u8; 1];
        let a_closed = tokio::time::timeout(Duration::from_secs(2), tunnel_a.read(&mut tail))
            .await
            .expect("A tunnel must be cancelled");
        assert!(matches!(a_closed, Ok(0) | Err(_)));
        assert_eq!(active.active_guards(&claims_a.endpoint_id), Some(0));
        assert_eq!(active.active_guards(&claims_b.endpoint_id), Some(1));
        tunnel_b.write_all(b"ping").await.unwrap();
        let mut pong = [0_u8; 4];
        tunnel_b.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");

        let (status, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&claims_a, sign(&keys, &claims_a)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(failure.reason, RouteAdmissionV2Reason::GateClosed);
        listener.shutdown().await.unwrap();
        guest_a_task.await.unwrap();
        guest_b_task.await.unwrap();
    }

    #[tokio::test]
    async fn identity_binding_time_node_gate_and_missing_runtime_reject_before_guest_io() {
        let keys = keys();
        let temp = TempDir::new().unwrap();
        let registry = AdmissionCellRegistry::new(temp.path().join("checkpoints"));
        let active_claims = claims("cat_active", "ep_active", 9);
        let active = cell(&active_claims, RouteGateState::Active);
        registry
            .insert_cell_for_machine_test(active_claims.cat_id.clone(), Arc::clone(&active))
            .unwrap();
        let closed_claims = claims("cat_closed", "ep_closed", 9);
        let closed = cell(&closed_claims, RouteGateState::Closed);
        registry
            .insert_cell_for_machine_test(closed_claims.cat_id.clone(), Arc::clone(&closed))
            .unwrap();
        let targetless_claims = claims("cat_targetless", "ep_targetless", 9);
        let targetless = cell_with_guest_target(&targetless_claims, RouteGateState::Active, false);
        registry
            .insert_cell_for_machine_test(targetless_claims.cat_id.clone(), Arc::clone(&targetless))
            .unwrap();
        let mut listener = listener(&keys, registry).await;

        let mut wrong_gateway = active_claims.clone();
        wrong_gateway.gateway_public_key_spki_sha256 = Sha256Digest::from_bytes([0x55; 32]);
        let (_, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&wrong_gateway, sign(&keys, &wrong_gateway)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(failure.reason, RouteAdmissionV2Reason::BindingMismatch);

        let mut wrong_node = active_claims.clone();
        wrong_node.node_id = Id::new("node-b").unwrap();
        let (_, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&wrong_node, sign(&keys, &wrong_node)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(failure.reason, RouteAdmissionV2Reason::BindingMismatch);

        let wrong_frame_cat = RouteTunnelV2Request::new(
            Id::new("cat_untrusted_frame").unwrap(),
            active_claims.endpoint_id.clone(),
            active_claims.hostname.clone(),
            sign(&keys, &active_claims),
        )
        .unwrap();
        let (_, failure) = rejection(
            exchange(
                listener.addr(),
                &wrong_frame_cat,
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(failure.reason, RouteAdmissionV2Reason::BindingMismatch);

        let mut expired = active_claims.clone();
        expired.iat = now() - 120;
        expired.nbf = expired.iat;
        expired.exp = now() - 10;
        let (_, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&expired, sign(&keys, &expired)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(failure.reason, RouteAdmissionV2Reason::Expired);

        let (_, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&closed_claims, sign(&keys, &closed_claims)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(failure.reason, RouteAdmissionV2Reason::GateClosed);

        let missing_claims = claims("cat_missing", "ep_missing", 9);
        let (_, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&missing_claims, sign(&keys, &missing_claims)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(failure.reason, RouteAdmissionV2Reason::RuntimeNotReady);

        let (_, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&targetless_claims, sign(&keys, &targetless_claims)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(failure.reason, RouteAdmissionV2Reason::RuntimeNotReady);
        assert_eq!(active.active_guards(&active_claims.endpoint_id), Some(0));
        assert_eq!(closed.active_guards(&closed_claims.endpoint_id), Some(0));
        assert_eq!(
            targetless.active_guards(&targetless_claims.endpoint_id),
            Some(0)
        );

        assert!(exchange(
            listener.addr(),
            &frame(&active_claims, sign(&keys, &active_claims)),
            UNKNOWN_CLIENT_CERTIFICATE,
            UNKNOWN_CLIENT_PRIVATE_KEY,
        )
        .await
        .is_err());
        // The untrusted chain is never made acceptable by attaching its CA.
        assert_ne!(UNKNOWN_CA_CERTIFICATE, CA_CERTIFICATE);
        assert!(exchange(
            listener.addr(),
            &frame(&active_claims, sign(&keys, &active_claims)),
            WRONG_EKU_CLIENT_CERTIFICATE,
            WRONG_EKU_CLIENT_PRIVATE_KEY,
        )
        .await
        .is_err());
        // A chain-valid RSA client is not a canonical Cats Gateway principal.
        assert!(exchange(
            listener.addr(),
            &frame(&active_claims, sign(&keys, &active_claims)),
            RSA_CLIENT_CERTIFICATE,
            RSA_CLIENT_PRIVATE_KEY,
        )
        .await
        .is_err());
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn unverified_grants_cannot_probe_registry_presence_or_touch_guest() {
        let guest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = guest.local_addr().unwrap().port();
        let trusted = keys();
        let untrusted = keys();
        let claims = claims("cat_probe", "ep_probe", target_port);
        let active = cell(&claims, RouteGateState::Active);
        let present_root = TempDir::new().unwrap();
        let present_registry = AdmissionCellRegistry::new(present_root.path().join("checkpoints"));
        present_registry
            .insert_cell_for_machine_test(claims.cat_id.clone(), Arc::clone(&active))
            .unwrap();
        let absent_root = TempDir::new().unwrap();
        let absent_registry = AdmissionCellRegistry::new(absent_root.path().join("checkpoints"));
        let mut present_listener = listener(&trusted, present_registry).await;
        let mut absent_listener = listener(&trusted, absent_registry).await;

        let invalid_signature = sign_with_private(&trusted.public, &untrusted.private, &claims);
        let unknown_kid = sign(&untrusted, &claims);
        for (token, expected_reason) in [
            (invalid_signature, RouteAdmissionV2Reason::InvalidSignature),
            (unknown_kid, RouteAdmissionV2Reason::UnknownKey),
        ] {
            let present = rejection(
                exchange(
                    present_listener.addr(),
                    &frame(&claims, token.clone()),
                    CLIENT_CERTIFICATE,
                    CLIENT_PRIVATE_KEY,
                )
                .await
                .unwrap(),
            );
            let absent = rejection(
                exchange(
                    absent_listener.addr(),
                    &frame(&claims, token),
                    CLIENT_CERTIFICATE,
                    CLIENT_PRIVATE_KEY,
                )
                .await
                .unwrap(),
            );
            assert_eq!(present, absent);
            assert_eq!(present.0, StatusCode::CONFLICT);
            assert_eq!(present.1.reason, expected_reason);
            assert!(!present.1.guard_acquired);
            assert_eq!(active.active_guards(&claims.endpoint_id), Some(0));
        }

        let (_, valid_absent) = rejection(
            exchange(
                absent_listener.addr(),
                &frame(&claims, sign(&trusted, &claims)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            valid_absent,
            RouteAdmissionV2Failure::pre_admission(RouteAdmissionV2Reason::RuntimeNotReady)
                .unwrap()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), guest.accept())
                .await
                .is_err()
        );
        assert_eq!(active.active_guards(&claims.endpoint_id), Some(0));

        present_listener.shutdown().await.unwrap();
        absent_listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn failed_guest_connect_returns_guard_acquired_once_and_releases_it() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = unused.local_addr().unwrap().port();
        drop(unused);
        let keys = keys();
        let claims = claims("cat_refused", "ep_refused", target_port);
        let active = cell(&claims, RouteGateState::Active);
        let temp = TempDir::new().unwrap();
        let registry = AdmissionCellRegistry::new(temp.path().join("checkpoints"));
        registry
            .insert_cell_for_machine_test(claims.cat_id.clone(), Arc::clone(&active))
            .unwrap();
        let mut listener = listener(&keys, registry).await;
        let (status, failure) = rejection(
            exchange(
                listener.addr(),
                &frame(&claims, sign(&keys, &claims)),
                CLIENT_CERTIFICATE,
                CLIENT_PRIVATE_KEY,
            )
            .await
            .unwrap(),
        );
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(failure.guard_acquired);
        assert_eq!(failure.reason, RouteAdmissionV2Reason::UpstreamUnavailable);
        assert_eq!(active.active_guards(&claims.endpoint_id), Some(0));
        listener.shutdown().await.unwrap();
    }
}

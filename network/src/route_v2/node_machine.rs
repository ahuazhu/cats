//! Gateway-side mTLS client for one Route v2 Node tunnel.
//!
//! Every call opens one TLS 1.3 / HTTP/1.1 connection and either returns the
//! upgraded byte stream or one authenticated typed Node rejection. The call
//! never retries or replays the current public request.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cats_api::gateway_workload_identity::canonical_gateway_leaf_spki_sha256;
use cats_api::route_grant_v2::{
    decode_route_admission_v2_failure, encode_route_tunnel_v2_request, RouteAdmissionV2Failure,
    RouteTunnelV2Request, ROUTE_TUNNEL_V2_FAILURE_MAX_WIRE_BYTES, ROUTE_TUNNEL_V2_METHOD,
    ROUTE_TUNNEL_V2_PATH, ROUTE_TUNNEL_V2_UPGRADE, ROUTE_V2_JSON_CONTENT_TYPE,
};
use cats_api::runtime_artifacts::InstalledGatewayNodeRouteV2MachineArtifacts;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, StatusCode, Version};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use super::ResolvedRoute;

const CONNECT_DEADLINE: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const HTTP_EXCHANGE_DEADLINE: Duration = Duration::from_secs(5);
const UPGRADE_DEADLINE: Duration = Duration::from_secs(5);
const HTTP_11_ALPN: &[u8] = b"http/1.1";

#[derive(Clone)]
pub struct GatewayNodeRouteV2Client {
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for GatewayNodeRouteV2Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayNodeRouteV2Client")
            .field("tls", &"[redacted]")
            .finish()
    }
}

impl GatewayNodeRouteV2Client {
    pub fn from_installed_artifacts(
        artifacts: &InstalledGatewayNodeRouteV2MachineArtifacts,
    ) -> Result<Self, GatewayNodeRouteV2Error> {
        let tls = build_client_tls(
            artifacts.node_server_ca_bundle_pem(),
            artifacts.client_certificate_pem(),
            artifacts.client_private_key_pem(),
        )?;
        Ok(Self { tls })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn from_pem_for_test(
        server_ca_bundle_pem: &[u8],
        client_certificate_pem: &[u8],
        client_private_key_pem: &[u8],
    ) -> Result<Self, GatewayNodeRouteV2Error> {
        Ok(Self {
            tls: build_client_tls(
                server_ca_bundle_pem,
                client_certificate_pem,
                client_private_key_pem,
            )?,
        })
    }

    pub async fn open_tunnel(
        &self,
        route: &ResolvedRoute,
    ) -> Result<GatewayNodeRouteTunnel, GatewayNodeRouteV2Error> {
        let (hostname, port) = parse_target(route.node_transport_target().as_str())?;
        let grant = std::str::from_utf8(route.opaque_grant())
            .map_err(|_| GatewayNodeRouteV2Error::InvalidRoute)?;
        if !grant.is_ascii() {
            return Err(GatewayNodeRouteV2Error::InvalidRoute);
        }
        let frame = RouteTunnelV2Request::new(
            route.cat_id().clone(),
            route.endpoint_id().clone(),
            route.hostname().clone(),
            grant.to_owned(),
        )
        .map_err(|_| GatewayNodeRouteV2Error::InvalidRoute)?;
        let body = encode_route_tunnel_v2_request(&frame)
            .map_err(|_| GatewayNodeRouteV2Error::InvalidRoute)?;

        let tcp = tokio::time::timeout(CONNECT_DEADLINE, TcpStream::connect((hostname, port)))
            .await
            .map_err(|_| GatewayNodeRouteV2Error::Connect)?
            .map_err(|_| GatewayNodeRouteV2Error::Connect)?;
        tcp.set_nodelay(true)
            .map_err(|_| GatewayNodeRouteV2Error::Connect)?;
        let server_name = ServerName::try_from(hostname.to_owned())
            .map_err(|_| GatewayNodeRouteV2Error::InvalidTarget)?;
        let tls = tokio::time::timeout(
            TLS_HANDSHAKE_DEADLINE,
            TlsConnector::from(Arc::clone(&self.tls)).connect(server_name, tcp),
        )
        .await
        .map_err(|_| GatewayNodeRouteV2Error::Tls)?
        .map_err(|_| GatewayNodeRouteV2Error::Tls)?;
        if tls.get_ref().1.alpn_protocol() != Some(HTTP_11_ALPN) {
            return Err(GatewayNodeRouteV2Error::Tls);
        }
        let (mut sender, connection) = http1::Builder::new()
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| GatewayNodeRouteV2Error::Http)?;
        let mut connection_task =
            AbortOnDropTask::new(tokio::spawn(
                async move { connection.with_upgrades().await },
            ));
        let request = Request::builder()
            .method(Method::POST)
            .uri(ROUTE_TUNNEL_V2_PATH)
            .version(Version::HTTP_11)
            .header(header::HOST, format!("{hostname}:{port}"))
            .header(header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, ROUTE_TUNNEL_V2_UPGRADE)
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| GatewayNodeRouteV2Error::Http)?;
        debug_assert_eq!(ROUTE_TUNNEL_V2_METHOD, "POST");
        let response = match tokio::time::timeout(
            HTTP_EXCHANGE_DEADLINE,
            sender.send_request(request),
        )
        .await
        {
            Ok(Ok(response)) => response,
            _ => {
                connection_task.abort_and_join().await;
                return Err(GatewayNodeRouteV2Error::Http);
            }
        };
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let failure = read_failure(response).await;
            connection_task.abort_and_join().await;
            return failure;
        }
        if !valid_upgrade_response(&response) {
            connection_task.abort_and_join().await;
            return Err(GatewayNodeRouteV2Error::Protocol);
        }
        let upgraded =
            match tokio::time::timeout(UPGRADE_DEADLINE, hyper::upgrade::on(response)).await {
                Ok(Ok(upgraded)) => upgraded,
                _ => {
                    connection_task.abort_and_join().await;
                    return Err(GatewayNodeRouteV2Error::Protocol);
                }
            };
        match tokio::time::timeout(UPGRADE_DEADLINE, connection_task.task_mut()).await {
            Ok(Ok(Ok(()))) => {}
            _ => {
                connection_task.abort_and_join().await;
                return Err(GatewayNodeRouteV2Error::Protocol);
            }
        }
        connection_task.disarm();
        Ok(GatewayNodeRouteTunnel {
            stream: TokioIo::new(upgraded),
        })
    }
}

/// Tokio detaches a task when its bare `JoinHandle` is dropped. The HTTP
/// driver owns the TLS socket, so cancellation of `open_tunnel` must abort the
/// driver instead of allowing the authenticated request to continue unseen.
pub(super) struct AbortOnDropTask<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    pub(super) fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    fn task_mut(&mut self) -> &mut JoinHandle<T> {
        self.task
            .as_mut()
            .expect("connection task remains armed until its one join")
    }

    fn disarm(&mut self) {
        self.task.take();
    }

    pub(super) async fn abort_and_join(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// One admitted raw byte tunnel. Public HTTP/1.1 or WebSocket framing stays
/// end-to-end between the Gateway proxy and the Guest application.
pub struct GatewayNodeRouteTunnel {
    stream: TokioIo<hyper::upgrade::Upgraded>,
}

impl std::fmt::Debug for GatewayNodeRouteTunnel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GatewayNodeRouteTunnel { stream: [opaque] }")
    }
}

impl tokio::io::AsyncRead for GatewayNodeRouteTunnel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for GatewayNodeRouteTunnel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayNodeRouteV2Error {
    #[error("Route v2 Node target is invalid")]
    InvalidTarget,
    #[error("resolved Route v2 envelope is invalid")]
    InvalidRoute,
    #[error("Route v2 Node TCP connection failed")]
    Connect,
    #[error("Route v2 Node TLS authentication failed")]
    Tls,
    #[error("Route v2 Node HTTP exchange failed")]
    Http,
    #[error("Route v2 Node returned an invalid authenticated response")]
    Protocol,
    #[error("Route v2 Node rejected admission")]
    Admission(RouteAdmissionV2Failure),
}

async fn read_failure(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<GatewayNodeRouteTunnel, GatewayNodeRouteV2Error> {
    let status = response.status();
    if response.version() != Version::HTTP_11
        || !matches!(status, StatusCode::CONFLICT | StatusCode::BAD_GATEWAY)
        || !single_header(response.headers(), header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes() == ROUTE_V2_JSON_CONTENT_TYPE.as_bytes())
    {
        return Err(GatewayNodeRouteV2Error::Protocol);
    }
    let content_length = single_header(response.headers(), header::CONTENT_LENGTH);
    if response.headers().contains_key(header::CONTENT_LENGTH) && content_length.is_none() {
        return Err(GatewayNodeRouteV2Error::Protocol);
    }
    if content_length.is_some_and(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .is_none_or(|length| length == 0 || length > ROUTE_TUNNEL_V2_FAILURE_MAX_WIRE_BYTES)
    }) {
        return Err(GatewayNodeRouteV2Error::Protocol);
    }
    let mut incoming = response.into_body();
    let body = tokio::time::timeout(HTTP_EXCHANGE_DEADLINE, async {
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| GatewayNodeRouteV2Error::Protocol)?;
            let data = frame.data_ref().ok_or(GatewayNodeRouteV2Error::Protocol)?;
            let next = body
                .len()
                .checked_add(data.len())
                .filter(|length| *length <= ROUTE_TUNNEL_V2_FAILURE_MAX_WIRE_BYTES)
                .ok_or(GatewayNodeRouteV2Error::Protocol)?;
            body.reserve(next - body.len());
            body.extend_from_slice(data);
        }
        Ok::<_, GatewayNodeRouteV2Error>(body)
    })
    .await
    .map_err(|_| GatewayNodeRouteV2Error::Protocol)??;
    let failure =
        decode_route_admission_v2_failure(&body).map_err(|_| GatewayNodeRouteV2Error::Protocol)?;
    if (failure.guard_acquired && status != StatusCode::BAD_GATEWAY)
        || (!failure.guard_acquired && status != StatusCode::CONFLICT)
    {
        return Err(GatewayNodeRouteV2Error::Protocol);
    }
    Err(GatewayNodeRouteV2Error::Admission(failure))
}

fn valid_upgrade_response(response: &hyper::Response<hyper::body::Incoming>) -> bool {
    response.version() == Version::HTTP_11
        && single_header(response.headers(), header::CONNECTION)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"upgrade"))
        && single_header(response.headers(), header::UPGRADE).is_some_and(|value| {
            value
                .as_bytes()
                .eq_ignore_ascii_case(ROUTE_TUNNEL_V2_UPGRADE.as_bytes())
        })
}

fn single_header(headers: &hyper::HeaderMap, name: header::HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn parse_target(target: &str) -> Result<(&str, u16), GatewayNodeRouteV2Error> {
    let authority = target
        .strip_prefix("https://")
        .ok_or(GatewayNodeRouteV2Error::InvalidTarget)?;
    let (hostname, port) = authority
        .rsplit_once(':')
        .ok_or(GatewayNodeRouteV2Error::InvalidTarget)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(GatewayNodeRouteV2Error::InvalidTarget)?;
    Ok((hostname, port))
}

pub(super) fn build_client_tls(
    server_ca_bundle_pem: &[u8],
    client_certificate_pem: &[u8],
    client_private_key_pem: &[u8],
) -> Result<Arc<ClientConfig>, GatewayNodeRouteV2Error> {
    let root_count = validate_pem_sequence(server_ca_bundle_pem, "CERTIFICATE", false)?;
    let roots = CertificateDer::pem_slice_iter(server_ca_bundle_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayNodeRouteV2Error::Tls)?;
    if roots.len() != root_count {
        return Err(GatewayNodeRouteV2Error::Tls);
    }
    let mut root_store = RootCertStore::empty();
    for certificate in roots {
        root_store
            .add(certificate)
            .map_err(|_| GatewayNodeRouteV2Error::Tls)?;
    }
    let certificate_count = validate_pem_sequence(client_certificate_pem, "CERTIFICATE", false)?;
    let certificates = CertificateDer::pem_slice_iter(client_certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayNodeRouteV2Error::Tls)?;
    if certificates.len() != certificate_count
        || certificates
            .first()
            .and_then(|leaf| canonical_gateway_leaf_spki_sha256(leaf.as_ref()))
            .is_none()
    {
        return Err(GatewayNodeRouteV2Error::Tls);
    }
    validate_pem_sequence(client_private_key_pem, "PRIVATE KEY", true)?;
    let private_key = PrivatePkcs8KeyDer::from_pem_slice(client_private_key_pem)
        .map_err(|_| GatewayNodeRouteV2Error::Tls)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| GatewayNodeRouteV2Error::Tls)?
        .with_root_certificates(root_store)
        .with_client_auth_cert(certificates, PrivateKeyDer::Pkcs8(private_key))
        .map_err(|_| GatewayNodeRouteV2Error::Tls)?;
    // Each public request proves the currently installed client certificate
    // on its own connection; no resumed session may stand in for that leaf.
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    Ok(Arc::new(config))
}

fn validate_pem_sequence(
    bytes: &[u8],
    label: &str,
    exactly_one: bool,
) -> Result<usize, GatewayNodeRouteV2Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| GatewayNodeRouteV2Error::Tls)?;
    if !text.is_ascii() {
        return Err(GatewayNodeRouteV2Error::Tls);
    }
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
            if line != begin {
                return Err(GatewayNodeRouteV2Error::Tls);
            }
            inside = true;
            body_lines = 0;
        } else if line == end {
            if body_lines == 0 {
                return Err(GatewayNodeRouteV2Error::Tls);
            }
            inside = false;
            count += 1;
        } else {
            if line.is_empty()
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
            {
                return Err(GatewayNodeRouteV2Error::Tls);
            }
            body_lines += 1;
        }
    }
    if inside || (exactly_one && count != 1) || (!exactly_one && count == 0) {
        return Err(GatewayNodeRouteV2Error::Tls);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use cats_api::runtime_reconciliation::{Hostname, Id, NodeTransportTarget};
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use rustls::server::WebPkiClientVerifier;
    use rustls::ServerConfig;
    use sha2::{Digest as _, Sha256};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::time::Instant;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::route_v2::{AuthenticatedResolveEnvelope, GrantDigest};

    const CA_CERTIFICATE: &[u8] =
        include_bytes!("../../../control-plane/tests/fixtures/gateway_machine_ca_certificate.pem");
    const CLIENT_CERTIFICATE: &[u8] = include_bytes!(
        "../../../control-plane/tests/fixtures/gateway_machine_client_certificate.pem"
    );
    const CLIENT_PRIVATE_KEY: &[u8] = include_bytes!(
        "../../../control-plane/tests/fixtures/gateway_machine_client_private_key.pem"
    );
    const SERVER_CERTIFICATE: &[u8] = include_bytes!(
        "../../../control-plane/tests/fixtures/gateway_machine_server_certificate.pem"
    );
    const SERVER_PRIVATE_KEY: &[u8] = include_bytes!(
        "../../../control-plane/tests/fixtures/gateway_machine_server_private_key.pem"
    );

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[test]
    fn fixed_client_material_builds_tls13_http11_identity() {
        let client = GatewayNodeRouteV2Client::from_pem_for_test(
            CA_CERTIFICATE,
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .unwrap();
        assert_eq!(client.tls.alpn_protocols, vec![HTTP_11_ALPN.to_vec()]);
        assert!(GatewayNodeRouteV2Client::from_pem_for_test(
            CA_CERTIFICATE,
            CLIENT_CERTIFICATE,
            b"not a key",
        )
        .is_err());
    }

    #[tokio::test]
    async fn transport_failure_is_attempted_once_and_never_replayed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_task = Arc::clone(&accepted);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accepted_task.fetch_add(1, Ordering::SeqCst);
            let mut first = [0_u8; 1];
            let _ = stream.read(&mut first).await;
            drop(stream);
        });
        let grant = b"opaque-ascii-grant".to_vec();
        let route = AuthenticatedResolveEnvelope::from_authenticated_transport(
            Id::new("cat_01").unwrap(),
            Id::new("ep_01").unwrap(),
            NodeTransportTarget::new(format!("https://localhost:{}", address.port())).unwrap(),
            1_786_156_920,
            grant.clone(),
            GrantDigest::from_bytes(Sha256::digest(&grant).into()),
            grant.len() + 256,
        )
        .validate_for_hostname(
            &Hostname::new("app.cats.run").unwrap(),
            1_786_156_800,
            Instant::now(),
        )
        .unwrap();
        let client = GatewayNodeRouteV2Client::from_pem_for_test(
            CA_CERTIFICATE,
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .unwrap();
        assert_eq!(
            client.open_tunnel(&route).await.unwrap_err(),
            GatewayNodeRouteV2Error::Tls
        );
        server.await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn caller_cancellation_aborts_the_authenticated_http_driver() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let (dropped_sender, dropped_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(server_tls()).accept(tcp).await.unwrap();
            let entered_sender = Arc::new(Mutex::new(Some(entered_sender)));
            let dropped_sender = Arc::new(Mutex::new(Some(dropped_sender)));
            let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
                let entered_sender = Arc::clone(&entered_sender);
                let dropped_sender = Arc::clone(&dropped_sender);
                async move {
                    entered_sender
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap()
                        .send(())
                        .unwrap();
                    let _drop_signal = DropSignal(dropped_sender.lock().unwrap().take());
                    std::future::pending::<
                        Result<hyper::Response<Full<Bytes>>, std::convert::Infallible>,
                    >()
                    .await
                }
            });
            let _ = server_http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });

        let grant = b"opaque-ascii-grant".to_vec();
        let route = AuthenticatedResolveEnvelope::from_authenticated_transport(
            Id::new("cat_01").unwrap(),
            Id::new("ep_01").unwrap(),
            NodeTransportTarget::new(format!("https://localhost:{}", address.port())).unwrap(),
            1_786_156_920,
            grant.clone(),
            GrantDigest::from_bytes(Sha256::digest(&grant).into()),
            grant.len() + 256,
        )
        .validate_for_hostname(
            &Hostname::new("app.cats.run").unwrap(),
            1_786_156_800,
            Instant::now(),
        )
        .unwrap();
        let client = GatewayNodeRouteV2Client::from_pem_for_test(
            CA_CERTIFICATE,
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .unwrap();
        let client_task = tokio::spawn(async move { client.open_tunnel(&route).await });
        tokio::time::timeout(Duration::from_secs(2), entered_receiver)
            .await
            .unwrap()
            .unwrap();
        client_task.abort();
        let _ = client_task.await;
        tokio::time::timeout(Duration::from_secs(2), dropped_receiver)
            .await
            .expect("server request must be cancelled when the caller drops open_tunnel")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn authenticated_upgrade_sends_exact_frame_and_returns_raw_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (frame_sender, frame_receiver) = tokio::sync::oneshot::channel();
        let (tunnel_sender, tunnel_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(server_tls()).accept(tcp).await.unwrap();
            let frame_sender = Arc::new(Mutex::new(Some(frame_sender)));
            let tunnel_sender = Arc::new(Mutex::new(Some(tunnel_sender)));
            let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
                let frame_sender = Arc::clone(&frame_sender);
                let tunnel_sender = Arc::clone(&tunnel_sender);
                async move {
                    assert_eq!(request.method(), Method::POST);
                    assert_eq!(request.uri().path(), ROUTE_TUNNEL_V2_PATH);
                    let on_upgrade = hyper::upgrade::on(&mut request);
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let frame =
                        cats_api::route_grant_v2::decode_route_tunnel_v2_request(&body).unwrap();
                    frame_sender
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap()
                        .send(frame)
                        .unwrap();
                    let completed = tunnel_sender.lock().unwrap().take().unwrap();
                    tokio::spawn(async move {
                        let upgraded = on_upgrade.await.unwrap();
                        let mut stream = TokioIo::new(upgraded);
                        let mut ping = [0_u8; 4];
                        stream.read_exact(&mut ping).await.unwrap();
                        assert_eq!(&ping, b"ping");
                        stream.write_all(b"pong").await.unwrap();
                        completed.send(()).unwrap();
                    });
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(header::CONNECTION, "upgrade")
                            .header(header::UPGRADE, ROUTE_TUNNEL_V2_UPGRADE)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }
            });
            server_http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .with_upgrades()
                .await
                .unwrap();
            tunnel_receiver.await.unwrap();
        });

        let grant = b"opaque-ascii-grant".to_vec();
        let route = AuthenticatedResolveEnvelope::from_authenticated_transport(
            Id::new("cat_01").unwrap(),
            Id::new("ep_01").unwrap(),
            NodeTransportTarget::new(format!("https://localhost:{}", address.port())).unwrap(),
            1_786_156_920,
            grant.clone(),
            GrantDigest::from_bytes(Sha256::digest(&grant).into()),
            grant.len() + 256,
        )
        .validate_for_hostname(
            &Hostname::new("app.cats.run").unwrap(),
            1_786_156_800,
            Instant::now(),
        )
        .unwrap();
        let client = GatewayNodeRouteV2Client::from_pem_for_test(
            CA_CERTIFICATE,
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .unwrap();
        let mut tunnel = client.open_tunnel(&route).await.unwrap();
        let frame = frame_receiver.await.unwrap();
        assert_eq!(frame.cat_id.as_str(), "cat_01");
        assert_eq!(frame.endpoint_id.as_str(), "ep_01");
        assert_eq!(frame.hostname.as_str(), "app.cats.run");
        assert_eq!(frame.opaque_grant.as_bytes(), grant);
        tunnel.write_all(b"ping").await.unwrap();
        let mut pong = [0_u8; 4];
        tunnel.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        server.await.unwrap();
    }

    fn server_tls() -> Arc<ServerConfig> {
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(CertificateDer::from_pem_slice(CA_CERTIFICATE).unwrap())
            .unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            Arc::clone(&provider),
        )
        .build()
        .unwrap();
        let certificates = CertificateDer::pem_slice_iter(SERVER_CERTIFICATE)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let private_key = PrivatePkcs8KeyDer::from_pem_slice(SERVER_PRIVATE_KEY).unwrap();
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, PrivateKeyDer::Pkcs8(private_key))
            .unwrap();
        config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
        Arc::new(config)
    }
}

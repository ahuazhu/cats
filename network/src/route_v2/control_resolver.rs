//! Machine-authenticated Control Plane adapter for the frozen Route v2
//! resolve frame.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use cats_api::route_grant_v2::{
    decode_route_resolve_v2_rejection, decode_route_resolve_v2_success,
    encode_route_resolve_v2_request, RouteResolveV2RejectionCode, RouteResolveV2Request,
    ROUTE_RESOLVE_V2_DEADLINE_MILLIS, ROUTE_RESOLVE_V2_METHOD, ROUTE_RESOLVE_V2_PATH,
    ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES, ROUTE_V2_JSON_CONTENT_TYPE,
};
use cats_api::runtime_artifacts::InstalledGatewayNodeRouteV2MachineArtifacts;
use cats_api::runtime_reconciliation::{Hostname, NodeTransportTarget};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, StatusCode, Version};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use super::node_machine::{build_client_tls, AbortOnDropTask};
use super::{
    AuthenticatedResolveEnvelope, GrantDigest, NegativeRoute, ResolveFailure, ResolveFuture,
    RouteResolution, RouteResolver,
};

const HTTP_11_ALPN: &[u8] = b"http/1.1";
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlMachineTarget {
    authority: String,
    hostname: String,
    port: u16,
}

impl ControlMachineTarget {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let authority = value.into();
        // Reuse the frozen strict HTTPS authority grammar without treating
        // the resulting value as Node placement authority.
        NodeTransportTarget::new(authority.clone())?;
        let host_and_port = authority.strip_prefix("https://")?;
        let (hostname, port) = host_and_port.rsplit_once(':')?;
        let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
        let hostname = hostname.to_owned();
        Some(Self {
            authority,
            hostname,
            port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.authority
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlRouteResolverError {
    #[error("Control Route v2 machine TLS material is invalid")]
    Tls,
}

#[derive(Clone)]
pub struct ControlRouteResolver {
    target: ControlMachineTarget,
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for ControlRouteResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlRouteResolver")
            .field("target", &self.target)
            .field("tls", &"[redacted]")
            .finish()
    }
}

impl ControlRouteResolver {
    pub fn from_installed_artifacts(
        target: ControlMachineTarget,
        artifacts: &InstalledGatewayNodeRouteV2MachineArtifacts,
    ) -> Result<Self, ControlRouteResolverError> {
        let tls = build_client_tls(
            artifacts.node_server_ca_bundle_pem(),
            artifacts.client_certificate_pem(),
            artifacts.client_private_key_pem(),
        )
        .map_err(|_| ControlRouteResolverError::Tls)?;
        Ok(Self { target, tls })
    }

    #[cfg(test)]
    fn from_pem_for_test(
        target: ControlMachineTarget,
        server_ca_bundle_pem: &[u8],
        client_certificate_pem: &[u8],
        client_private_key_pem: &[u8],
    ) -> Result<Self, ControlRouteResolverError> {
        let tls = build_client_tls(
            server_ca_bundle_pem,
            client_certificate_pem,
            client_private_key_pem,
        )
        .map_err(|_| ControlRouteResolverError::Tls)?;
        Ok(Self { target, tls })
    }

    pub fn into_route_resolver(self) -> RouteResolver {
        let resolver = Arc::new(self);
        Arc::new(move |hostname| {
            let resolver = Arc::clone(&resolver);
            Box::pin(async move { resolver.resolve(hostname).await }) as ResolveFuture
        })
    }

    async fn resolve(&self, hostname: Hostname) -> Result<RouteResolution, ResolveFailure> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(ROUTE_RESOLVE_V2_DEADLINE_MILLIS))
            .ok_or(ResolveFailure::Unavailable)?;
        let request_body =
            encode_route_resolve_v2_request(&RouteResolveV2Request::new(hostname.clone()))
                .map_err(|_| ResolveFailure::InvalidAuthority)?;

        let tcp = tokio::time::timeout_at(
            deadline,
            TcpStream::connect((self.target.hostname.as_str(), self.target.port)),
        )
        .await
        .map_err(|_| ResolveFailure::Unavailable)?
        .map_err(|_| ResolveFailure::Unavailable)?;
        tcp.set_nodelay(true)
            .map_err(|_| ResolveFailure::Unavailable)?;
        let server_name = ServerName::try_from(self.target.hostname.clone())
            .map_err(|_| ResolveFailure::InvalidAuthority)?;
        let tls = tokio::time::timeout_at(
            deadline,
            TlsConnector::from(Arc::clone(&self.tls)).connect(server_name, tcp),
        )
        .await
        .map_err(|_| ResolveFailure::Unavailable)?
        .map_err(|_| ResolveFailure::InvalidAuthority)?;
        if tls.get_ref().1.alpn_protocol() != Some(HTTP_11_ALPN) {
            return Err(ResolveFailure::InvalidAuthority);
        }
        let mut http = http1::Builder::new();
        http.max_headers(MAX_RESPONSE_HEADERS)
            .max_buf_size(MAX_RESPONSE_HEADER_BYTES);
        let (mut sender, connection) =
            tokio::time::timeout_at(deadline, http.handshake(TokioIo::new(tls)))
                .await
                .map_err(|_| ResolveFailure::Unavailable)?
                .map_err(|_| ResolveFailure::Unavailable)?;
        let mut connection_task = AbortOnDropTask::new(tokio::spawn(connection));
        let request = Request::builder()
            .method(Method::POST)
            .uri(ROUTE_RESOLVE_V2_PATH)
            .version(Version::HTTP_11)
            .header(
                header::HOST,
                format!("{}:{}", self.target.hostname, self.target.port),
            )
            .header(header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
            .header(header::ACCEPT, ROUTE_V2_JSON_CONTENT_TYPE)
            .header(header::CONTENT_LENGTH, request_body.len())
            .body(Full::new(Bytes::from(request_body)))
            .map_err(|_| ResolveFailure::InvalidAuthority)?;
        debug_assert_eq!(ROUTE_RESOLVE_V2_METHOD, "POST");
        let response = match tokio::time::timeout_at(deadline, sender.send_request(request)).await {
            Ok(Ok(response)) => response,
            _ => {
                connection_task.abort_and_join().await;
                return Err(ResolveFailure::Unavailable);
            }
        };
        let decoded = decode_response(response, hostname, deadline).await;
        connection_task.abort_and_join().await;
        decoded
    }
}

async fn decode_response(
    response: hyper::Response<hyper::body::Incoming>,
    hostname: Hostname,
    deadline: Instant,
) -> Result<RouteResolution, ResolveFailure> {
    if response.version() != Version::HTTP_11
        || response.headers().len() > MAX_RESPONSE_HEADERS
        || response.headers().contains_key(header::CONTENT_ENCODING)
        || single_header(response.headers(), header::CONTENT_TYPE)
            .is_none_or(|value| value.as_bytes() != ROUTE_V2_JSON_CONTENT_TYPE.as_bytes())
        || single_header(response.headers(), header::CACHE_CONTROL)
            .is_none_or(|value| value.as_bytes() != b"no-store")
    {
        return Err(ResolveFailure::InvalidAuthority);
    }
    let mut header_bytes = 0_usize;
    for (name, value) in response.headers() {
        header_bytes = header_bytes
            .checked_add(name.as_str().len())
            .and_then(|bytes| bytes.checked_add(value.as_bytes().len()))
            .ok_or(ResolveFailure::InvalidAuthority)?;
        if header_bytes > MAX_RESPONSE_HEADER_BYTES {
            return Err(ResolveFailure::InvalidAuthority);
        }
    }
    let content_length = optional_content_length(response.headers())?;
    if content_length.is_some_and(|length| length > ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES) {
        return Err(ResolveFailure::InvalidAuthority);
    }
    let status = response.status();
    let mut incoming = response.into_body();
    let body = tokio::time::timeout_at(deadline, async {
        let mut body = Vec::with_capacity(content_length.unwrap_or(0));
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| ResolveFailure::Unavailable)?;
            let data = frame.data_ref().ok_or(ResolveFailure::InvalidAuthority)?;
            let next = body
                .len()
                .checked_add(data.len())
                .filter(|length| *length <= ROUTE_RESOLVE_V2_RESPONSE_MAX_WIRE_BYTES)
                .ok_or(ResolveFailure::InvalidAuthority)?;
            body.reserve(next - body.len());
            body.extend_from_slice(data);
        }
        Ok::<_, ResolveFailure>(body)
    })
    .await
    .map_err(|_| ResolveFailure::Unavailable)??;
    if content_length.is_some_and(|length| length != body.len()) {
        return Err(ResolveFailure::InvalidAuthority);
    }

    if status == StatusCode::OK {
        let success =
            decode_route_resolve_v2_success(&body).map_err(|_| ResolveFailure::InvalidAuthority)?;
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolveFailure::InvalidAuthority)?
            .as_secs();
        let route = AuthenticatedResolveEnvelope::from_authenticated_transport(
            success.cat_id,
            success.endpoint_id,
            success.node_transport_target,
            success.expires_at_unix_seconds,
            success.opaque_grant.into_bytes(),
            GrantDigest::from_bytes(*success.grant_sha256.as_bytes()),
            body.len(),
        )
        .validate_for_hostname(&hostname, now_unix_seconds, Instant::now())
        .map_err(|_| ResolveFailure::InvalidAuthority)?;
        return Ok(RouteResolution::Positive(route));
    }

    let rejection =
        decode_route_resolve_v2_rejection(&body).map_err(|_| ResolveFailure::InvalidAuthority)?;
    match (status, rejection.code) {
        (StatusCode::NOT_FOUND, RouteResolveV2RejectionCode::NotFound) => {
            Ok(RouteResolution::Negative(NegativeRoute::NotFound))
        }
        (StatusCode::GONE, RouteResolveV2RejectionCode::Gone) => {
            Ok(RouteResolution::Negative(NegativeRoute::Gone))
        }
        (
            StatusCode::CONFLICT,
            RouteResolveV2RejectionCode::WakeRequired | RouteResolveV2RejectionCode::Pending,
        )
        | (StatusCode::SERVICE_UNAVAILABLE, RouteResolveV2RejectionCode::Unavailable)
        | (StatusCode::INTERNAL_SERVER_ERROR, RouteResolveV2RejectionCode::Internal) => {
            Err(ResolveFailure::Unavailable)
        }
        (StatusCode::UNAUTHORIZED, RouteResolveV2RejectionCode::AuthenticationFailed)
        | (
            StatusCode::BAD_REQUEST
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::NOT_ACCEPTABLE
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RouteResolveV2RejectionCode::InvalidRequest,
        ) => Err(ResolveFailure::InvalidAuthority),
        _ => Err(ResolveFailure::InvalidAuthority),
    }
}

fn single_header(headers: &hyper::HeaderMap, name: header::HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn optional_content_length(headers: &hyper::HeaderMap) -> Result<Option<usize>, ResolveFailure> {
    if !headers.contains_key(header::CONTENT_LENGTH) {
        return Ok(None);
    }
    let value =
        single_header(headers, header::CONTENT_LENGTH).ok_or(ResolveFailure::InvalidAuthority)?;
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(Some)
        .ok_or(ResolveFailure::InvalidAuthority)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cats_api::route_grant_v2::{encode_route_resolve_v2_success, RouteResolveV2Success};
    use cats_api::runtime_reconciliation::{Id, NodeTransportTarget};
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

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

    #[tokio::test]
    async fn production_adapter_uses_one_mtls_canonical_resolve_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let seen_server = Arc::clone(&seen);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(server_tls()).accept(tcp).await.unwrap();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let seen_server = Arc::clone(&seen_server);
                async move {
                    assert_eq!(request.method(), Method::POST);
                    assert_eq!(request.uri().path(), ROUTE_RESOLVE_V2_PATH);
                    assert_eq!(
                        request.headers().get(header::CONTENT_TYPE).unwrap(),
                        ROUTE_V2_JSON_CONTENT_TYPE
                    );
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let request =
                        cats_api::route_grant_v2::decode_route_resolve_v2_request(&body).unwrap();
                    *seen_server.lock().unwrap() = Some(request.hostname);
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let body = encode_route_resolve_v2_success(
                        &RouteResolveV2Success::new(
                            Id::new("cat_01").unwrap(),
                            Id::new("ep_01").unwrap(),
                            NodeTransportTarget::new("https://node-a.internal:7301").unwrap(),
                            now + 120,
                            "opaque-grant".to_owned(),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, ROUTE_V2_JSON_CONTENT_TYPE)
                            .header(header::CACHE_CONTROL, "no-store")
                            .header(header::CONTENT_LENGTH, body.len())
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                }
            });
            server_http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .unwrap();
        });

        let target =
            ControlMachineTarget::new(format!("https://localhost:{}", address.port())).unwrap();
        let resolver = ControlRouteResolver::from_pem_for_test(
            target,
            CA_CERTIFICATE,
            CLIENT_CERTIFICATE,
            CLIENT_PRIVATE_KEY,
        )
        .unwrap();
        let hostname = Hostname::new("app.cats.run").unwrap();
        let result = resolver.resolve(hostname.clone()).await.unwrap();
        let RouteResolution::Positive(route) = result else {
            panic!("authenticated success must produce a positive route");
        };
        assert_eq!(route.hostname(), &hostname);
        assert_eq!(route.opaque_grant(), b"opaque-grant");
        assert_eq!(seen.lock().unwrap().as_ref(), Some(&hostname));
        server.await.unwrap();
    }

    #[test]
    fn control_target_rejects_plaintext_paths_and_noncanonical_ports() {
        assert!(ControlMachineTarget::new("http://control.internal:7443").is_none());
        assert!(ControlMachineTarget::new("https://control.internal:07443").is_none());
        assert!(ControlMachineTarget::new("https://control.internal:7443/path").is_none());
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

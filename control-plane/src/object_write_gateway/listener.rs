use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use super::OBJECT_WRITE_GATEWAY_CONNECTION_LIMIT;

const TLS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const REQUEST_HEADER_DEADLINE: Duration = Duration::from_secs(5);
const CONNECTION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(65);
const HTTP_11_ALPN: &[u8] = b"http/1.1";

pub(super) async fn serve(
    listen: &str,
    certificate_file: &Path,
    private_key_file: &Path,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = load_tls(certificate_file, private_key_file)?;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind object-write gateway listener {listen}"))?;
    let acceptor = TlsAcceptor::from(tls);
    let permits = Arc::new(tokio::sync::Semaphore::new(
        OBJECT_WRITE_GATEWAY_CONNECTION_LIMIT,
    ));
    let (connection_shutdown, _) = watch::channel(false);
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
            }
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = joined {
                    tracing::warn!(%error, "object-write gateway connection task panicked");
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept object-write gateway connection")?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                stream.set_nodelay(true).context("set object-write gateway TCP_NODELAY")?;
                let acceptor = acceptor.clone();
                let app = app.clone();
                let shutdown = connection_shutdown.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(stream, acceptor, app, shutdown).await {
                        tracing::debug!(%error, "object-write gateway connection closed");
                    }
                });
            }
        }
    }

    let _ = connection_shutdown.send(true);
    if tokio::time::timeout(CONNECTION_SHUTDOWN_DEADLINE, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "object-write gateway connection task panicked");
            }
        }
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        anyhow::bail!("object-write gateway connections exceeded shutdown deadline");
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = tokio::time::timeout(TLS_HANDSHAKE_DEADLINE, acceptor.accept(stream))
        .await
        .context("object-write gateway TLS handshake exceeded deadline")?
        .context("object-write gateway TLS handshake failed")?;
    anyhow::ensure!(
        tls.get_ref().1.alpn_protocol() == Some(HTTP_11_ALPN),
        "object-write gateway did not negotiate HTTP/1.1"
    );
    let mut http = http1::Builder::new();
    http.keep_alive(true)
        .header_read_timeout(REQUEST_HEADER_DEADLINE)
        .timer(TokioTimer::new());
    let connection = http.serve_connection(TokioIo::new(tls), TowerToHyperService::new(app));
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => {
            result.context("serve object-write gateway HTTP/1.1 connection")?;
        }
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                connection.as_mut().graceful_shutdown();
            }
            connection.await.context("close object-write gateway HTTP/1.1 connection")?;
        }
    }
    Ok(())
}

fn load_tls(certificate_file: &Path, private_key_file: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    validate_fixed_file(certificate_file, 0o644, "server certificate")?;
    validate_fixed_file(private_key_file, 0o600, "server private key")?;
    let certificate_pem =
        std::fs::read(certificate_file).context("read fixed server certificate")?;
    let private_key_pem =
        std::fs::read(private_key_file).context("read fixed server private key")?;
    let certificate_count = validate_pem(&certificate_pem, "CERTIFICATE", false)?;
    let certificates = CertificateDer::pem_slice_iter(&certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("decode fixed server certificate chain")?;
    anyhow::ensure!(
        certificates.len() == certificate_count,
        "fixed server certificate file contains an unsupported PEM section"
    );
    validate_pem(&private_key_pem, "PRIVATE KEY", true)?;
    let private_key = PrivatePkcs8KeyDer::from_pem_slice(&private_key_pem)
        .context("decode fixed PKCS#8 server private key")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("build TLS 1.3-only object-write gateway configuration")?
        .with_no_client_auth()
        .with_single_cert(certificates, PrivateKeyDer::Pkcs8(private_key))
        .context("validate object-write gateway certificate/private-key pair")?;
    config.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    Ok(Arc::new(config))
}

fn validate_fixed_file(path: &Path, expected_mode: u32, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(path.is_absolute(), "fixed {label} path is not absolute");
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect fixed {label} file {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == expected_mode,
        "fixed {label} must be a regular non-symlink mode {expected_mode:o} file"
    );
    Ok(())
}

fn validate_pem(bytes: &[u8], label: &str, exactly_one: bool) -> anyhow::Result<usize> {
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
        anyhow::ensure!(count == 1, "fixed TLS PEM must contain exactly one key");
    } else {
        anyhow::ensure!(count > 0, "fixed TLS PEM contains no certificates");
    }
    Ok(count)
}

//! Server-authenticated TLS transport for Route v2 rotation and ring delivery.
//!
//! This listener remains reachable while the loaded Route signer is disabled.
//! It exposes only the independent signed-operator mutation and public,
//! canonical successor/current discovery. It has neither a bearer principal
//! nor a client-certificate principal and is never joined to public routing.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::server::AppState;

const TLS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const REQUEST_HEADER_DEADLINE: Duration = Duration::from_secs(5);
const LISTENER_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(35);
const LISTENER_TASK_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(40);
const CONNECTION_LIMIT: usize = 32;
const HTTP_11_ALPN: &[u8] = b"http/1.1";

pub(crate) struct RouteRotationMachineTlsConfig(Arc<ServerConfig>);

impl RouteRotationMachineTlsConfig {
    pub(crate) fn from_installed_artifacts(
        artifacts: &cats_api::runtime_artifacts::InstalledGatewayMachineArtifacts,
    ) -> anyhow::Result<Self> {
        crate::gateway_machine::build_server_auth_tls_config(artifacts).map(Self)
    }
}

pub(crate) struct RouteRotationMachineListener {
    addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<anyhow::Result<()>>>>,
}

impl RouteRotationMachineListener {
    pub(crate) async fn spawn(
        listen: &str,
        tls_config: RouteRotationMachineTlsConfig,
        state: AppState,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!listen.is_empty(), "Route rotation machine listen is empty");
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind Route rotation machine listener {listen}"))?;
        let addr = listener.local_addr()?;
        let readiness = Arc::clone(&state.readiness);
        let app = crate::api::route_v2_rotation_machine_router(state);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let result = run_listener(listener, tls_config.0, app, shutdown_rx).await;
            if let Err(error) = &result {
                readiness.poison();
                tracing::error!(%error, "Route rotation machine listener exited unexpectedly");
            }
            result
        });
        Ok(Self {
            addr,
            shutdown,
            task: Mutex::new(Some(task)),
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn begin_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        let task = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(mut task) = task else {
            return Ok(());
        };
        match tokio::time::timeout(LISTENER_TASK_SHUTDOWN_DEADLINE, &mut task).await {
            Ok(joined) => joined.context("Route rotation machine listener task panicked")?,
            Err(_) => {
                task.abort();
                let joined = task.await;
                anyhow::ensure!(
                    joined
                        .as_ref()
                        .is_err_and(tokio::task::JoinError::is_cancelled),
                    "Route rotation machine listener did not cancel cleanly"
                );
                anyhow::bail!("Route rotation machine listener exceeded its shutdown deadline");
            }
        }
    }
}

impl Drop for RouteRotationMachineListener {
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

async fn run_listener(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let connection_permits = Arc::new(tokio::sync::Semaphore::new(CONNECTION_LIMIT));
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
            }
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = joined {
                    tracing::warn!(%error, "Route rotation machine connection task panicked");
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept Route rotation machine connection")?;
                let Ok(permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                stream
                    .set_nodelay(true)
                    .context("set Route rotation machine TCP_NODELAY")?;
                let acceptor = tls_acceptor.clone();
                let app = app.clone();
                let connection_shutdown = connection_shutdown.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) =
                        serve_connection(stream, acceptor, app, connection_shutdown).await
                    {
                        tracing::debug!(%error, "Route rotation machine connection closed");
                    }
                });
            }
        }
    }

    let _ = connection_shutdown.send(true);
    let joined = tokio::time::timeout(LISTENER_SHUTDOWN_DEADLINE, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "Route rotation machine connection task panicked");
            }
        }
    })
    .await;
    if joined.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        anyhow::bail!("Route rotation machine connections exceeded the shutdown deadline");
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = tokio::time::timeout(TLS_HANDSHAKE_DEADLINE, tls_acceptor.accept(stream))
        .await
        .context("Route rotation TLS handshake exceeded its deadline")?
        .context("Route rotation TLS handshake failed")?;
    anyhow::ensure!(
        tls.get_ref().1.alpn_protocol() == Some(HTTP_11_ALPN),
        "Route rotation TLS connection did not negotiate HTTP/1.1"
    );
    anyhow::ensure!(
        tls.get_ref().1.peer_certificates().is_none(),
        "Route rotation TLS connection unexpectedly carried a client certificate"
    );
    let mut http = http1::Builder::new();
    http.keep_alive(true)
        .header_read_timeout(REQUEST_HEADER_DEADLINE)
        .timer(TokioTimer::new());
    let connection = http.serve_connection(TokioIo::new(tls), TowerToHyperService::new(app));
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => {
            result.context("serve Route rotation HTTP/1.1 connection")?;
        }
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                connection.as_mut().graceful_shutdown();
            }
            connection.await.context("gracefully close Route rotation HTTP/1.1 connection")?;
        }
    }
    Ok(())
}

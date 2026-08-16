//! Fleet-verification authentication and Store-owner composition.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cats_api::fleet_verification::FLEET_VERIFICATION_PATH;
use cats_control_plane::auth::{WorkOsConfig, WorkOsConfigParams};
use cats_control_plane::server::{spawn as spawn_production, Config, Handle};
use cats_control_plane::store::DsnSource;
use cats_metering::SqliteUsageStore;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::header;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use workos::helpers::{seal_session, SessionData};

const COOKIE_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_RSA_MODULUS: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";

async fn jwks() -> Json<Value> {
    Json(json!({
        "keys": [{
            "kid": "test-rsa-key",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_MODULUS,
            "e": "AQAB"
        }]
    }))
}

fn workos_jwt(issuer: &str, organization_id: &str, permissions: &[&str]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-rsa-key".into());
    encode(
        &header,
        &json!({
            "iss": issuer,
            "sub": "user_fleet_verifier",
            "sid": format!("session_{organization_id}"),
            "client_id": "client_test",
            "org_id": organization_id,
            "role": "member",
            "permissions": permissions,
            "exp": cats_control_plane::store::now_unix() + 3600
        }),
        &EncodingKey::from_rsa_pem(include_bytes!("fixtures/workos_test_private.pem")).unwrap(),
    )
    .unwrap()
}

fn sealed_admin_cookie() -> String {
    let claims = json!({
        "sid": "session_fleet_admin",
        "org_id": "org_admin",
        "role": "admin",
        "permissions": ["cats:fleet:admin"],
        "exp": cats_control_plane::store::now_unix() + 3600,
    });
    let access_token = format!(
        "e30.{}.test-signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let user: workos::User = serde_json::from_value(json!({
        "object": "user",
        "id": "user_fleet_admin",
        "name": "Fleet Administrator",
        "email": "fleet-admin@example.com",
        "email_verified": true,
        "created_at": "2026-08-13T00:00:00.000Z",
        "updated_at": "2026-08-13T00:00:00.000Z"
    }))
    .unwrap();
    let sealed = seal_session(
        &SessionData {
            access_token: access_token.into(),
            refresh_token: "refresh_fleet_admin".into(),
            user: Some(user),
            impersonator: None,
        },
        COOKIE_PASSWORD,
    )
    .unwrap();
    format!("cats_admin_session={sealed}")
}

#[derive(Clone, Copy)]
enum LockedTables {
    SnapshotOnly,
    AuthAndSnapshot,
}

/// A schema-local PostgreSQL barrier that reports only the two exact
/// production statements relevant to this composition. The static-admin
/// calibration below proves the positive `node_identities` probe before the
/// WorkOS assertion relies on absence of the `workspace_tokens` prefix.
struct FleetStoreBarrier {
    blocked: tokio::sync::oneshot::Receiver<Option<String>>,
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl FleetStoreBarrier {
    async fn acquire(dsn: &str, target_backend_pid: i32, tables: LockedTables) -> Self {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let dsn = dsn.to_owned();
        let worker = std::thread::spawn(move || {
            let mut client = postgres::Client::connect(&dsn, postgres::NoTls).unwrap();
            let lock = match tables {
                LockedTables::SnapshotOnly => "LOCK TABLE node_identities IN ACCESS EXCLUSIVE MODE",
                LockedTables::AuthAndSnapshot => {
                    "LOCK TABLE workspace_tokens, node_identities IN ACCESS EXCLUSIVE MODE"
                }
            };
            client
                .batch_execute(&format!("BEGIN; SET LOCAL lock_timeout='5s'; {lock}"))
                .unwrap();
            ready_tx.send(()).unwrap();

            let deadline = Instant::now() + Duration::from_secs(5);
            let blocked = loop {
                if release_rx.try_recv().is_ok() {
                    break None;
                }
                let blocked = client
                    .query_opt(
                        "SELECT relation.relname
                           FROM pg_locks waiting
                           JOIN pg_class relation ON relation.oid=waiting.relation
                           JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                           JOIN pg_stat_activity activity ON activity.pid=waiting.pid
                          WHERE waiting.pid=$1 AND NOT waiting.granted
                            AND waiting.locktype='relation'
                            AND namespace.nspname=current_schema()
                            AND relation.relname IN ('workspace_tokens', 'node_identities')
                            AND (
                                activity.query LIKE '%SELECT workspace_id FROM workspace_tokens%'
                                OR activity.query LIKE '%FROM current_agent_sessions AS child%'
                                OR (
                                    activity.query LIKE '%FROM node_identities%'
                                    AND activity.query LIKE '%AS has_current_session%'
                                )
                            )
                          ORDER BY relation.relname
                          LIMIT 1",
                        &[&target_backend_pid],
                    )
                    .unwrap()
                    .map(|row| row.get::<_, String>(0));
                if blocked.is_some() {
                    break blocked;
                }
                if Instant::now() >= deadline {
                    let activity = client
                        .query(
                            "SELECT state, coalesce(wait_event_type, ''),
                                    coalesce(wait_event, ''), query
                               FROM pg_stat_activity
                              WHERE pid=$1 AND datname=current_database()
                              ORDER BY pid",
                            &[&target_backend_pid],
                        )
                        .unwrap()
                        .into_iter()
                        .map(|row| {
                            format!(
                                "state={} wait={}/{} query={}",
                                row.get::<_, String>(0),
                                row.get::<_, String>(1),
                                row.get::<_, String>(2),
                                row.get::<_, String>(3)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    break Some(format!("diagnostic: {activity}"));
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let _ = blocked_tx.send(blocked);
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            client.batch_execute("ROLLBACK").unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("fleet verification table lock was not acquired")
            .expect("fleet verification table-lock worker stopped");
        Self {
            blocked: blocked_rx,
            release: Some(release_tx),
            worker: Some(worker),
        }
    }

    async fn wait_until_query_blocked(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(6), &mut self.blocked)
            .await
            .expect("fleet verification query did not reach the PostgreSQL lock barrier")
            .expect("fleet verification table-lock worker stopped")
            .expect("no exact fleet verification query reached a locked table")
    }

    async fn release(mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            tokio::task::spawn_blocking(move || worker.join().unwrap())
                .await
                .unwrap();
        }
    }
}

impl Drop for FleetStoreBarrier {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

async fn spawn_test_control(workos: Arc<WorkOsConfig>) -> (tempfile::TempDir, Handle, String) {
    let dir = tempfile::tempdir().unwrap();
    let usage: Arc<SqliteUsageStore> =
        Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap());
    let control_store_dsn = cats_control_plane::testsupport::isolated_control_store_url();
    let control = spawn_production(Config {
        listen: "127.0.0.1:0".into(),
        control_store_dsn: DsnSource::Literal(control_store_dsn.clone()),
        control_store_ca_file: None,
        usage_store: usage.clone(),
        credit_store: usage,
        retired_storage_meta_for_tests: None,
        image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
        auth_token: "service-token".into(),
        guest_runtime_profile_receipt:
            cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        runtime_provisioner_trust_bundle:
            cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
        production_cutover_operator_trust_bundle:
            cats_control_plane::testsupport::test_production_cutover_operator_trust_bundle(),
        route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
        admin_token: "admin-token".into(),
        workos: Some(workos),
        stripe: None,
        billing_enforcement_enabled: false,
        node_lease_timeout_ms: 30_000,
        reconcile_interval_ms: 30_000,
        oci_deploy_sync_wait_ms: 5_000,
        auto_tier_policy: Default::default(),
    })
    .await
    .unwrap();
    (dir, control, control_store_dsn)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fleet_auth_has_no_store_prefix_and_dropped_http_is_joined_on_shutdown() {
    let workos_app = Router::new().route("/sso/jwks/client_test", get(jwks));
    let workos_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let workos_base = format!("http://{}", workos_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(workos_listener, workos_app).await.unwrap();
    });
    let issuer = format!("{workos_base}/user_management/client_test");
    let workos = Arc::new(
        WorkOsConfig::new(WorkOsConfigParams {
            client_id: "client_test".into(),
            api_key: "sk_test_secret".into(),
            api_base_url: workos_base,
            issuer_url: issuer.clone(),
            redirect_uri: "http://127.0.0.1:7300/auth/callback".into(),
            cookie_password: COOKIE_PASSWORD.into(),
            account_organizations: BTreeMap::from([("default".into(), "org_default".into())]),
            admin_organization_id: "org_admin".into(),
            admin_permission: "cats:fleet:admin".into(),
            cookie_secure: false,
            cookie_domain: None,
            user_site_url: None,
            admin_site_url: None,
        })
        .unwrap(),
    );

    let (_calibration_dir, control, control_store_dsn) =
        spawn_test_control(Arc::clone(&workos)).await;
    let http = reqwest::Client::new();
    let url = format!("{}{}", control.base_url(), FLEET_VERIFICATION_PATH);

    assert_eq!(
        http.get(&url)
            .bearer_auth("admin-token")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        http.get(&url)
            .bearer_auth("service-token")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let workspace_token = format!("cats_wst_{}", "a".repeat(64));
    let workspace_token_hash = hex::encode(Sha256::digest(workspace_token.as_bytes()));
    let account = control
        .state
        .store
        .account_for_organization("org_default")
        .unwrap()
        .unwrap();
    let workspace = control
        .state
        .store
        .create_workspace(&account.id, "fleet-auth", "Fleet Auth")
        .unwrap();
    control
        .state
        .store
        .create_workspace_token(&workspace.id, "fleet-auth", &workspace_token_hash)
        .unwrap();
    assert_eq!(
        http.get(&url)
            .bearer_auth(&workspace_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        http.get(&url)
            .bearer_auth(format!("cats_wst_{}", "b".repeat(64)))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
        "workspace-token rejection must not disclose whether the digest exists"
    );

    let workos_admin = workos_jwt(&issuer, "org_admin", &["cats:fleet:admin"]);
    assert_eq!(
        http.get(&url)
            .bearer_auth(&workos_admin)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let ordinary_workos = workos_jwt(&issuer, "org_default", &["cats:workspace:write"]);
    assert_eq!(
        http.get(&url)
            .bearer_auth(ordinary_workos)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        http.get(&url)
            .header(header::COOKIE, sealed_admin_cookie())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // Positive calibration: static admin has no auth lookup and must reach the
    // exact snapshot query observed by the schema-local probe.
    let calibration_backend_pid =
        cats_control_plane::testsupport::control_store_backend_pid(&control.state.store).await;
    let mut calibration = FleetStoreBarrier::acquire(
        &control_store_dsn,
        calibration_backend_pid,
        LockedTables::SnapshotOnly,
    )
    .await;
    let calibration_http = http.clone();
    let calibration_url = url.clone();
    let calibration_request = tokio::spawn(async move {
        calibration_http
            .get(calibration_url)
            .bearer_auth("admin-token")
            .send()
            .await
    });
    assert_eq!(
        calibration.wait_until_query_blocked().await,
        "node_identities"
    );
    calibration.release().await;
    assert_eq!(
        calibration_request.await.unwrap().unwrap().status(),
        StatusCode::OK
    );
    control.shutdown().await.unwrap();

    // Use a fresh server/schema for the cancellation oracle so the positive
    // calibration cannot leave unrelated replica background work contending
    // for the process-wide blocking executor.
    let (_owner_dir, control, control_store_dsn) = spawn_test_control(Arc::clone(&workos)).await;
    let url = format!("{}{}", control.base_url(), FLEET_VERIFICATION_PATH);
    let workos_admin = workos_jwt(&issuer, "org_admin", &["cats:fleet:admin"]);
    assert_eq!(
        http.get(&url)
            .bearer_auth(&workos_admin)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let owner_backend_pid =
        cats_control_plane::testsupport::control_store_backend_pid(&control.state.store).await;

    // Lock both the obsolete generic auth lookup and the owned snapshot. A
    // WorkOS fleet administrator must now reach `node_identities` directly;
    // the pre-fix implementation blocks first on `workspace_tokens`.
    let mut barrier = FleetStoreBarrier::acquire(
        &control_store_dsn,
        owner_backend_pid,
        LockedTables::AuthAndSnapshot,
    )
    .await;
    let request_http = http.clone();
    let request_url = url;
    let request = tokio::spawn(async move {
        request_http
            .get(request_url)
            .bearer_auth(workos_admin)
            .send()
            .await
    });
    assert_eq!(
        barrier.wait_until_query_blocked().await,
        "node_identities",
        "WorkOS fleet auth performed Store work before entering the owned snapshot boundary"
    );

    // Drop the real HTTP client after PostgreSQL claims the snapshot. Shutdown
    // must remain pending until cancellation settles that worker and releases
    // the one-connection Store lane.
    request.abort();
    let _ = request.await;
    let store = control.state.store.clone();
    let shutdown = control.shutdown();
    tokio::pin!(shutdown);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), shutdown.as_mut())
            .await
            .is_err(),
        "shutdown reported settlement while fleet Store work remained claimed"
    );
    barrier.release().await;
    tokio::time::timeout(Duration::from_secs(5), shutdown.as_mut())
        .await
        .expect("fleet shutdown did not join the released Store query")
        .unwrap();
    assert!(store
        .execute(|store| store.account_for_organization("org_default"))
        .await
        .expect("fleet shutdown did not release the Store lane")
        .is_some());
}

//! WorkOS AuthKit browser-session contract tests with a local code-exchange
//! stub. No WorkOS credentials or network access are required.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cats_control_plane::auth::{WorkOsConfig, WorkOsConfigParams};
use cats_control_plane::server::{spawn, Config, Handle};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_storage::MetadataStore;
use reqwest::header::{LOCATION, SET_COOKIE};
use reqwest::{StatusCode, Url};
use serde_json::{json, Value};
use workos::helpers::{seal_session, SessionData};

const COOKIE_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct WorkOsStub {
    exchanges: Arc<AtomicUsize>,
    revoked_sessions: Arc<Mutex<Vec<String>>>,
}

async fn authenticate(State(stub): State<WorkOsStub>, Json(body): Json<Value>) -> Json<Value> {
    stub.exchanges.fetch_add(1, Ordering::SeqCst);
    assert_eq!(body["client_id"], "client_test");
    assert_eq!(body["client_secret"], "sk_test_secret");
    let code = if body["grant_type"] == "refresh_token" {
        assert!(body["refresh_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        "refreshed"
    } else {
        assert_eq!(body["grant_type"], "authorization_code");
        assert!(body["code_verifier"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        body["code"].as_str().unwrap()
    };
    let (organization_id, permissions, email) = match code {
        "user-code" => (
            Some("org_project"),
            vec!["cats:project:write"],
            "user@example.com",
        ),
        "new-user-code" => (None, vec![], "new-user@example.com"),
        "admin-code" => (
            Some("org_admin"),
            vec!["cats:fleet:admin"],
            "admin@example.com",
        ),
        "refreshed" => (
            Some("org_project"),
            vec!["cats:project:write"],
            "user@example.com",
        ),
        _ => panic!("unexpected authorization code or grant"),
    };
    let claims = json!({
        "sid": format!("session_{code}"),
        "org_id": organization_id.unwrap_or_default(),
        "role": if code == "admin-code" { "admin" } else { "member" },
        "permissions": permissions,
        "exp": cats_control_plane::store::now_unix() + 3600,
    });
    let access_token = format!(
        "e30.{}.test-signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    Json(json!({
        "user": {
            "object": "user",
            "id": format!("user_{code}"),
            "first_name": "Cats",
            "last_name": "Tester",
            "name": "Cats Tester",
            "email": email,
            "email_verified": true,
            "created_at": "2026-07-22T00:00:00.000Z",
            "updated_at": "2026-07-22T00:00:00.000Z"
        },
        "organization_id": organization_id,
        "access_token": access_token,
        "refresh_token": format!("refresh_{code}")
    }))
}

async fn revoke_session(State(stub): State<WorkOsStub>, Json(body): Json<Value>) -> StatusCode {
    stub.revoked_sessions
        .lock()
        .unwrap()
        .push(body["session_id"].as_str().unwrap().to_string());
    StatusCode::NO_CONTENT
}

struct Ctx {
    _dir: tempfile::TempDir,
    _cp: Handle,
    base: String,
    http: reqwest::Client,
    exchanges: Arc<AtomicUsize>,
    revoked_sessions: Arc<Mutex<Vec<String>>>,
}

impl Ctx {
    async fn new() -> Self {
        let exchanges = Arc::new(AtomicUsize::new(0));
        let revoked_sessions = Arc::new(Mutex::new(Vec::new()));
        let stub = WorkOsStub {
            exchanges: exchanges.clone(),
            revoked_sessions: revoked_sessions.clone(),
        };
        let app = Router::new()
            .route("/user_management/authenticate", post(authenticate))
            .route("/user_management/sessions/revoke", post(revoke_session))
            .with_state(stub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let workos_base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let workos = WorkOsConfig::new(WorkOsConfigParams {
            client_id: "client_test".into(),
            api_key: "sk_test_secret".into(),
            api_base_url: workos_base,
            redirect_uri: "http://127.0.0.1:7300/auth/callback".into(),
            cookie_password: COOKIE_PASSWORD.into(),
            project_organizations: BTreeMap::from([("default".into(), "org_project".into())]),
            admin_organization_id: "org_admin".into(),
            admin_permission: "cats:fleet:admin".into(),
            cookie_secure: false,
            cookie_domain: None,
            user_site_url: Some("https://cats.run/".into()),
            admin_site_url: Some("https://ops.cats.run/".into()),
        })
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("storage.db")).unwrap());
        let cp = spawn(Config {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("control.db"),
            storage_meta,
            auth_token: "service-token".into(),
            admin_token: "admin-token".into(),
            project_tokens: BTreeMap::from([("default".into(), "project-token".into())]),
            workos: Some(Arc::new(workos)),
            node_lease_timeout_ms: 3_000,
            reconcile_interval_ms: 200,
        })
        .await
        .unwrap();
        let base = cp.base_url();
        Self {
            _dir: dir,
            _cp: cp,
            base,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            exchanges,
            revoked_sessions,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn login(&self, site: &str, code: &str) -> String {
        let path = if site == "user" {
            "/auth/login?site=user&return_to=/user/"
        } else {
            "/auth/login?site=admin&return_to=/admin/"
        };
        let login = self.http.get(self.url(path)).send().await.unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let flow_cookie = cookie_pair(&login, &format!("cats_{site}_auth_flow"));
        let location =
            Url::parse(login.headers().get(LOCATION).unwrap().to_str().unwrap()).unwrap();
        assert_eq!(location.path(), "/user_management/authorize");
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "provider")
                .unwrap()
                .1,
            "authkit"
        );
        assert!(location
            .query_pairs()
            .any(|(key, _)| key == "code_challenge"));
        if site == "user" {
            assert!(!location
                .query_pairs()
                .any(|(key, _)| key == "organization_id"));
        }
        let state = location
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();

        let callback = self
            .http
            .get(self.url(&format!("/auth/callback?code={code}&state={state}")))
            .header("Cookie", flow_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            callback.headers().get(LOCATION).unwrap().to_str().unwrap(),
            format!("/{site}/")
        );
        cookie_pair(&callback, &format!("cats_{site}_session"))
    }
}

fn cookie_pair(response: &reqwest::Response, name: &str) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing {name} cookie"))
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn workos_user_and_admin_sessions_enforce_their_scopes() {
    let ctx = Ctx::new().await;

    let public_config: Value = ctx
        .http
        .get(ctx.url("/auth/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(public_config["workos_enabled"], true);
    assert!(public_config.get("token_login_enabled").is_none());
    assert!(public_config.get("projects").is_none());
    assert!(!public_config.to_string().contains("sk_test_secret"));

    let user_cookie = ctx.login("user", "user-code").await;
    let user_session: Value = ctx
        .http
        .get(ctx.url("/auth/session?site=user"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(user_session["authenticated"], true);
    assert_eq!(user_session["project"], "default");
    assert_eq!(user_session["user"]["email"], "user@example.com");

    let own_project = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(own_project.status(), StatusCode::OK);
    let other_project = ctx
        .http
        .get(ctx.url("/v1/projects/other/cats"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(other_project.status(), StatusCode::FORBIDDEN);
    let user_cannot_admin = ctx
        .http
        .get(ctx.url("/v1/admin/monitoring"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(user_cannot_admin.status(), StatusCode::FORBIDDEN);

    let admin_cookie = ctx.login("admin", "admin-code").await;
    let fleet = ctx
        .http
        .get(ctx.url("/v1/admin/monitoring"))
        .header("Cookie", &admin_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(fleet.status(), StatusCode::OK);
    let admin_can_read_project = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .header("Cookie", &admin_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(admin_can_read_project.status(), StatusCode::OK);
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn workos_callback_rejects_tampered_state_before_code_exchange() {
    let ctx = Ctx::new().await;
    let login = ctx
        .http
        .get(ctx.url("/auth/login?site=user&project=default"))
        .send()
        .await
        .unwrap();
    let flow_cookie = cookie_pair(&login, "cats_user_auth_flow");
    let rejected = ctx
        .http
        .get(ctx.url("/auth/callback?code=user-code&state=tampered"))
        .header("Cookie", flow_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn organizationless_workos_user_receives_an_isolated_personal_project() {
    let ctx = Ctx::new().await;
    let user_cookie = ctx.login("user", "new-user-code").await;

    let session: Value = ctx
        .http
        .get(ctx.url("/auth/session?site=user"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["authenticated"], true);
    assert_eq!(session["project"], "personal-user_new-user-code");

    let own_project = ctx
        .http
        .get(ctx.url("/v1/projects/personal-user_new-user-code/cats"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(own_project.status(), StatusCode::OK);
    let shared_project = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(shared_project.status(), StatusCode::FORBIDDEN);

    let personal_login = ctx
        .http
        .get(ctx.url("/auth/login?site=user&project=personal-user_new-user-code"))
        .send()
        .await
        .unwrap();
    assert_eq!(personal_login.status(), StatusCode::SEE_OTHER);
    let flow_cookie = cookie_pair(&personal_login, "cats_user_auth_flow");
    let location = Url::parse(
        personal_login
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert!(!location
        .query_pairs()
        .any(|(key, _)| key == "organization_id"));
    let state = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = ctx
        .http
        .get(ctx.url(&format!("/auth/callback?code=new-user-code&state={state}")))
        .header("Cookie", flow_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        callback.headers().get(LOCATION).unwrap(),
        "https://cats.run/"
    );
}

#[tokio::test]
async fn workos_logout_revokes_the_session_and_returns_to_the_requested_site() {
    let ctx = Ctx::new().await;

    let user_cookie = ctx.login("user", "user-code").await;
    let user_logout = ctx
        .http
        .get(ctx.url("/auth/logout?site=user"))
        .header("Cookie", user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(user_logout.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        user_logout.headers().get(LOCATION).unwrap(),
        "https://cats.run/"
    );
    assert!(user_logout
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with("cats_user_session=;") && value.contains("Max-Age=0")));

    let admin_cookie = ctx.login("admin", "admin-code").await;
    let admin_logout = ctx
        .http
        .get(ctx.url("/auth/logout?site=admin"))
        .header("Cookie", admin_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(admin_logout.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        admin_logout.headers().get(LOCATION).unwrap(),
        "https://ops.cats.run/"
    );
    assert_eq!(
        *ctx.revoked_sessions.lock().unwrap(),
        vec!["session_user-code", "session_admin-code"]
    );
}

#[tokio::test]
async fn expired_workos_session_is_refreshed_and_cookie_is_rotated() {
    let ctx = Ctx::new().await;
    let expired_claims = json!({
        "sid": "session_expired",
        "org_id": "org_project",
        "role": "member",
        "permissions": ["cats:project:write"],
        "exp": cats_control_plane::store::now_unix() - 1,
    });
    let expired_token = format!(
        "e30.{}.test-signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&expired_claims).unwrap())
    );
    let user: workos::User = serde_json::from_value(json!({
        "object": "user",
        "id": "user_refresh",
        "name": "Refresh Tester",
        "email": "user@example.com",
        "email_verified": true,
        "created_at": "2026-07-22T00:00:00.000Z",
        "updated_at": "2026-07-22T00:00:00.000Z"
    }))
    .unwrap();
    let sealed = seal_session(
        &SessionData {
            access_token: expired_token.into(),
            refresh_token: "refresh_expired".into(),
            user: Some(user),
            impersonator: None,
        },
        COOKIE_PASSWORD,
    )
    .unwrap();
    let response = ctx
        .http
        .get(ctx.url("/auth/session?site=user"))
        .header("Cookie", format!("cats_user_session={sealed}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with("cats_user_session=")));
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["project"], "default");
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 1);
}

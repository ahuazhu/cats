//! WorkOS AuthKit browser-session contract tests with a local code-exchange
//! stub. No WorkOS credentials or network access are required.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cats_control_plane::auth::{WorkOsConfig, WorkOsConfigParams};
use cats_control_plane::server::{spawn, Config, Handle};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::SqliteUsageStore;
use cats_storage::MetadataStore;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::header::{LOCATION, SET_COOKIE};
use reqwest::{StatusCode, Url};
use serde_json::{json, Value};
use workos::helpers::{seal_session, SessionData};

const COOKIE_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_RSA_MODULUS: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";

#[derive(Clone)]
struct WorkOsStub {
    exchanges: Arc<AtomicUsize>,
    revoked_sessions: Arc<Mutex<Vec<String>>>,
}

async fn authenticate(State(stub): State<WorkOsStub>, Json(body): Json<Value>) -> Json<Value> {
    stub.exchanges.fetch_add(1, Ordering::SeqCst);
    assert_eq!(body["client_id"], "client_test");
    assert_eq!(body["client_secret"], "sk_test_secret");
    let is_refresh = body["grant_type"] == "refresh_token";
    let code = if is_refresh {
        let refresh_token = body["refresh_token"]
            .as_str()
            .filter(|value| !value.is_empty())
            .expect("refresh token");
        match refresh_token {
            "refresh_admin-user-code" => "admin-user-refreshed",
            "refresh_expired" => "refreshed",
            _ => panic!("unexpected refresh token"),
        }
    } else {
        assert_eq!(body["grant_type"], "authorization_code");
        assert!(body["code_verifier"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        body["code"].as_str().unwrap()
    };
    let (organization_id, permissions, email, user_id) = match code {
        "user-code" => (
            Some("org_project"),
            vec!["cats:project:write"],
            "user@example.com",
            "user_user-code",
        ),
        "new-user-code" => (None, vec![], "new-user@example.com", "user_new-user-code"),
        "admin-code" => (
            Some("org_admin"),
            vec!["cats:fleet:admin"],
            "admin@example.com",
            "user_admin-code",
        ),
        "admin-user-code" => (
            Some("org_admin"),
            vec!["cats:fleet:admin"],
            "admin-user@example.com",
            "user_admin-user-code",
        ),
        "admin-user-refreshed" => (
            body["organization_id"].as_str(),
            vec!["cats:project:write"],
            "admin-user@example.com",
            "user_admin-user-code",
        ),
        "refreshed" => (
            body["organization_id"].as_str().or(Some("org_project")),
            vec!["cats:project:write"],
            "user@example.com",
            "user_refresh",
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
            "id": user_id,
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

fn test_user(id: &str) -> Value {
    json!({
        "object": "user",
        "id": id,
        "name": "Cats Tester",
        "email": "user@example.com",
        "email_verified": true,
        "created_at": "2026-07-22T00:00:00.000Z",
        "updated_at": "2026-07-22T00:00:00.000Z"
    })
}

async fn list_memberships(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let membership =
        |id: &str, user_id: &str, organization_id: &str, organization_name: &str, role: &str| {
            json!({
                "object": "organization_membership",
                "id": id,
                "user_id": user_id,
                "organization_id": organization_id,
                "status": "active",
                "directory_managed": false,
                "organization_name": organization_name,
                "created_at": "2026-07-22T00:00:00.000Z",
                "updated_at": "2026-07-22T00:00:00.000Z",
                "role": { "slug": role },
                "roles": [{ "slug": role }],
                "user": test_user(user_id)
            })
        };
    let user_id = query
        .get("user_id")
        .map(String::as_str)
        .unwrap_or("user_cli");
    let data = if user_id == "user_admin-user-code" {
        vec![membership(
            "om_admin_user",
            user_id,
            "org_project",
            "Default Workspace",
            "member",
        )]
    } else {
        vec![
            membership(
                "om_1",
                user_id,
                "org_project",
                "Default Workspace",
                "member",
            ),
            membership("om_2", user_id, "org_second", "Second Workspace", "admin"),
            membership("om_3", user_id, "org_unmapped", "Unmapped", "member"),
        ]
    };
    Json(json!({
        "object": "list",
        "data": data,
        "list_metadata": { "before": null, "after": null }
    }))
}

async fn get_user(Path(id): Path<String>) -> Json<Value> {
    Json(test_user(&id))
}

struct Ctx {
    _dir: tempfile::TempDir,
    _cp: Handle,
    base: String,
    http: reqwest::Client,
    exchanges: Arc<AtomicUsize>,
    revoked_sessions: Arc<Mutex<Vec<String>>>,
    issuer: String,
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
            .route("/sso/jwks/client_test", get(jwks))
            .route(
                "/user_management/organization_memberships",
                get(list_memberships),
            )
            .route("/user_management/users/{id}", get(get_user))
            .with_state(stub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let workos_base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let issuer = format!("{workos_base}/user_management/client_test");
        let workos = WorkOsConfig::new(WorkOsConfigParams {
            client_id: "client_test".into(),
            api_key: "sk_test_secret".into(),
            api_base_url: workos_base.clone(),
            issuer_url: issuer.clone(),
            redirect_uri: "http://127.0.0.1:7300/auth/callback".into(),
            cookie_password: COOKIE_PASSWORD.into(),
            project_organizations: BTreeMap::from([
                ("default".into(), "org_project".into()),
                ("second".into(), "org_second".into()),
            ]),
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
            usage_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            credit_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            storage_meta,
            auth_token: "service-token".into(),
            admin_token: "admin-token".into(),
            workos: Some(Arc::new(workos)),
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 3_000,
            reconcile_interval_ms: 200,
            auto_tier_policy: Default::default(),
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
            issuer,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn begin_login(&self, site: &str) -> (String, String) {
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
        (flow_cookie, state)
    }

    async fn login(&self, site: &str, code: &str) -> String {
        let (flow_cookie, state) = self.begin_login(site).await;
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

    fn cli_token(&self, organization_id: &str) -> String {
        self.cli_token_with_issuer(organization_id, &self.issuer)
    }

    fn cli_token_with_issuer(&self, organization_id: &str, issuer: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-rsa-key".into());
        encode(
            &header,
            &json!({
                "iss": issuer,
                "sub": "user_cli",
                "sid": format!("session_{organization_id}"),
                "client_id": "client_test",
                "org_id": organization_id,
                "role": "member",
                "permissions": [],
                "exp": cats_control_plane::store::now_unix() + 3600
            }),
            &EncodingKey::from_rsa_pem(include_bytes!("fixtures/workos_test_private.pem")).unwrap(),
        )
        .unwrap()
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
    assert_eq!(public_config["workos_client_id"], "client_test");
    assert!(public_config["workos_api_base_url"]
        .as_str()
        .unwrap()
        .starts_with("http://127.0.0.1:"));
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
async fn cli_jwt_lists_and_enforces_multiple_workspaces() {
    let ctx = Ctx::new().await;
    let default_token = ctx.cli_token("org_project");

    let me = ctx
        .http
        .get(ctx.url("/v1/me"))
        .bearer_auth(&default_token)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), StatusCode::OK);
    let me: Value = me.json().await.unwrap();
    assert_eq!(me["user"]["id"], "user_cli");
    assert_eq!(me["workspaces"].as_array().unwrap().len(), 2);
    assert_eq!(me["workspaces"][0]["slug"], "default");
    assert_eq!(me["workspaces"][1]["slug"], "second");
    assert!(!me.to_string().contains("org_unmapped"));

    let own = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .bearer_auth(&default_token)
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), StatusCode::OK);
    let other = ctx
        .http
        .get(ctx.url("/v1/projects/second/cats"))
        .bearer_auth(&default_token)
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::FORBIDDEN);

    let second_token = ctx.cli_token("org_second");
    let selected = ctx
        .http
        .get(ctx.url("/v1/projects/second/cats"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(selected.status(), StatusCode::OK);
    let wrong = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

    let tampered = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .bearer_auth(format!("{default_token}x"))
        .send()
        .await
        .unwrap();
    assert_eq!(tampered.status(), StatusCode::UNAUTHORIZED);

    let wrong_issuer = ctx.cli_token_with_issuer("org_project", "https://api.workos.com");
    let rejected = ctx
        .http
        .get(ctx.url("/v1/projects/default/cats"))
        .bearer_auth(wrong_issuer)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
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
async fn workos_callback_returns_auth_failures_to_the_originating_site() {
    let ctx = Ctx::new().await;

    let (user_flow_cookie, user_state) = ctx.begin_login("user").await;
    let cancelled = ctx
        .http
        .get(ctx.url(&format!(
            "/auth/callback?error=access_denied&state={user_state}"
        )))
        .header("Cookie", user_flow_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        cancelled.headers().get(LOCATION).unwrap(),
        "/user/?auth_error=authentication_failed"
    );
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 0);

    let (admin_flow_cookie, admin_state) = ctx.begin_login("admin").await;
    let unauthorized = ctx
        .http
        .get(ctx.url(&format!(
            "/auth/callback?code=new-user-code&state={admin_state}"
        )))
        .header("Cookie", admin_flow_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        unauthorized.headers().get(LOCATION).unwrap(),
        "/admin/?auth_error=admin_access_required"
    );
    assert!(unauthorized
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with("cats_admin_auth_flow=") && value.contains("Max-Age=0")));
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
async fn user_login_switches_from_admin_org_to_the_only_mapped_workspace() {
    let ctx = Ctx::new().await;
    let user_cookie = ctx.login("user", "admin-user-code").await;

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
    assert_eq!(session["project"], "default");
    assert_eq!(session["user"]["id"], "user_admin-user-code");
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 2);
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

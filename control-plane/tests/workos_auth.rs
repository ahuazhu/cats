//! WorkOS AuthKit browser-session contract tests with a local code-exchange
//! stub. No WorkOS credentials or network access are required.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MembershipFault {
    Healthy,
    Status500,
    Disconnect,
}

#[derive(Clone)]
struct WorkOsStub {
    exchanges: Arc<AtomicUsize>,
    membership_requests: Arc<AtomicUsize>,
    membership_fault: Arc<Mutex<MembershipFault>>,
    revoked_sessions: Arc<Mutex<Vec<String>>>,
    personal_organizations: Arc<Mutex<HashMap<String, String>>>,
    personal_memberships: Arc<Mutex<HashMap<String, String>>>,
    invitations: Arc<Mutex<Vec<Value>>>,
    invitation_requests: Arc<Mutex<HashMap<String, Value>>>,
}

async fn authenticate(State(stub): State<WorkOsStub>, Json(body): Json<Value>) -> Json<Value> {
    stub.exchanges.fetch_add(1, Ordering::SeqCst);
    assert_eq!(body["client_id"], "client_test");
    assert_eq!(body["client_secret"], "sk_test_secret");
    let is_refresh = body["grant_type"] == "refresh_token";
    let (code, session_code) = if is_refresh {
        let refresh_token = body["refresh_token"]
            .as_str()
            .filter(|value| !value.is_empty())
            .expect("refresh token");
        match refresh_token {
            "refresh_admin-user-code" => ("admin-user-refreshed", "admin-user-code"),
            "refresh_new-user-code" => ("new-user-refreshed", "new-user-code"),
            "refresh_expired" => ("refreshed", "expired"),
            "refresh_user-code" | "refresh_user-refreshed" => ("user-refreshed", "user-code"),
            _ => panic!("unexpected refresh token"),
        }
    } else {
        assert_eq!(body["grant_type"], "authorization_code");
        assert!(body["code_verifier"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        let code = body["code"].as_str().unwrap();
        (code, code)
    };
    let (organization_id, permissions, email, user_id) = match code {
        "user-code" => (
            Some("org_default"),
            vec!["cats:workspace:write"],
            "user@example.com",
            "user_user-code",
        ),
        "new-user-code" => (None, vec![], "new-user@example.com", "user_new-user-code"),
        "new-user-scoped-code" => (
            Some("org_personal_new-user-code"),
            vec![],
            "new-user@example.com",
            "user_new-user-code",
        ),
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
            vec!["cats:workspace:write"],
            "admin-user@example.com",
            "user_admin-user-code",
        ),
        "new-user-refreshed" => (
            body["organization_id"].as_str(),
            vec![],
            "new-user@example.com",
            "user_new-user-code",
        ),
        "user-refreshed" => (
            body["organization_id"].as_str(),
            vec!["cats:workspace:write"],
            "user@example.com",
            "user_user-code",
        ),
        "refreshed" => (
            body["organization_id"].as_str().or(Some("org_default")),
            vec!["cats:workspace:write"],
            "user@example.com",
            "user_refresh",
        ),
        _ => panic!("unexpected authorization code or grant"),
    };
    let claims = json!({
        "sid": format!("session_{session_code}"),
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

async fn list_memberships(
    State(stub): State<WorkOsStub>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    stub.membership_requests.fetch_add(1, Ordering::SeqCst);
    match *stub.membership_fault.lock().unwrap() {
        MembershipFault::Healthy => {}
        MembershipFault::Status500 => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "injected WorkOS membership failure",
            )
                .into_response();
        }
        MembershipFault::Disconnect => {
            let body = Body::from_stream(futures_util::stream::once(async {
                Err::<String, std::io::Error>(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "injected WorkOS membership connection reset",
                ))
            }));
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap();
        }
    }
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
    let mut data = if user_id == "user_admin-user-code" {
        vec![membership(
            "om_admin_user",
            user_id,
            "org_default",
            "Default Workspace",
            "member",
        )]
    } else {
        vec![
            membership(
                "om_1",
                user_id,
                "org_default",
                "Default Workspace",
                "member",
            ),
            membership("om_2", user_id, "org_second", "Second Workspace", "admin"),
            membership("om_3", user_id, "org_unmapped", "Unmapped", "member"),
        ]
    };
    if let Some(organization_id) = stub
        .personal_memberships
        .lock()
        .unwrap()
        .get(user_id)
        .cloned()
    {
        data.push(membership(
            "om_personal",
            user_id,
            &organization_id,
            "Personal Account",
            "admin",
        ));
    }
    if let Some(expected_organization_id) = query.get("organization_id") {
        data.retain(|item| item["organization_id"] == *expected_organization_id);
    }
    if !query.contains_key("user_id")
        && query.get("organization_id").map(String::as_str) == Some("org_default")
    {
        data.push(membership(
            "om_target",
            "user_target",
            "org_default",
            "Default Workspace",
            "member",
        ));
    }
    Json(json!({
        "object": "list",
        "data": data,
        "list_metadata": { "before": null, "after": null }
    }))
    .into_response()
}

fn test_invitation(id: &str, email: &str, organization_id: &str, state: &str) -> Value {
    json!({
        "object": "invitation",
        "id": id,
        "email": email,
        "state": state,
        "accepted_at": null,
        "revoked_at": if state == "revoked" { Some("2026-07-25T00:01:00.000Z") } else { None },
        "expires_at": "2026-08-01T00:00:00.000Z",
        "organization_id": organization_id,
        "inviter_user_id": "user_cli",
        "accepted_user_id": null,
        "role_slug": "member",
        "created_at": "2026-07-25T00:00:00.000Z",
        "updated_at": "2026-07-25T00:00:00.000Z",
        "token": "invite-token",
        "accept_invitation_url": "https://example.com/invite"
    })
}

async fn send_invitation(
    State(stub): State<WorkOsStub>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .expect("WorkOS invitation request must carry Idempotency-Key");
    if let Some(invitation) = stub
        .invitation_requests
        .lock()
        .unwrap()
        .get(idempotency_key)
        .cloned()
    {
        return Json(invitation);
    }
    let invitation = test_invitation(
        "invite_test",
        body["email"].as_str().unwrap(),
        body["organization_id"].as_str().unwrap(),
        "pending",
    );
    let mut invitation = invitation;
    invitation["inviter_user_id"] = body["inviter_user_id"].clone();
    invitation["role_slug"] = body["role_slug"].clone();
    stub.invitations.lock().unwrap().push(invitation.clone());
    stub.invitation_requests
        .lock()
        .unwrap()
        .insert(idempotency_key.to_string(), invitation.clone());
    Json(invitation)
}

async fn list_invitations(
    State(stub): State<WorkOsStub>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut data = stub.invitations.lock().unwrap().clone();
    if let Some(organization_id) = query.get("organization_id") {
        data.retain(|item| item["organization_id"] == *organization_id);
    }
    Json(json!({
        "object": "list",
        "data": data,
        "list_metadata": {"before": null, "after": null}
    }))
}

async fn revoke_invitation(State(stub): State<WorkOsStub>, Path(id): Path<String>) -> Json<Value> {
    let mut invitations = stub.invitations.lock().unwrap();
    let invitation = invitations
        .iter_mut()
        .find(|invitation| invitation["id"] == id)
        .unwrap();
    invitation["state"] = json!("revoked");
    invitation["revoked_at"] = json!("2026-07-25T00:01:00.000Z");
    Json(invitation.clone())
}

async fn get_membership(Path(id): Path<String>) -> Json<Value> {
    let user_id = if id == "om_target" {
        "user_target"
    } else {
        "user_cli"
    };
    Json(json!({
        "object": "organization_membership",
        "id": id,
        "user_id": user_id,
        "organization_id": "org_default",
        "status": "active",
        "directory_managed": false,
        "organization_name": "Default Workspace",
        "created_at": "2026-07-25T00:00:00.000Z",
        "updated_at": "2026-07-25T00:00:00.000Z",
        "role": {"slug": "member"},
        "roles": [{"slug": "member"}],
        "user": test_user(user_id)
    }))
}

async fn update_membership(Path(id): Path<String>, Json(body): Json<Value>) -> Json<Value> {
    let mut membership = get_membership(Path(id)).await.0;
    membership["role"] = json!({"slug": body["role_slug"]});
    membership["roles"] = json!([{"slug": body["role_slug"]}]);
    Json(membership)
}

async fn deactivate_membership(Path(id): Path<String>) -> Json<Value> {
    let mut membership = get_membership(Path(id)).await.0;
    membership["status"] = json!("inactive");
    Json(membership)
}

fn test_organization(id: &str, external_id: &str) -> Value {
    json!({
        "object": "organization",
        "id": id,
        "name": "Personal Account",
        "domains": [],
        "metadata": {"cats_account_kind": "personal"},
        "external_id": external_id,
        "created_at": "2026-07-25T00:00:00.000Z",
        "updated_at": "2026-07-25T00:00:00.000Z"
    })
}

async fn get_organization_by_external_id(
    State(stub): State<WorkOsStub>,
    Path(external_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let user_id = external_id
        .strip_prefix("cats-personal:")
        .ok_or(StatusCode::NOT_FOUND)?;
    let organizations = stub.personal_organizations.lock().unwrap();
    let organization_id = organizations.get(user_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(test_organization(organization_id, &external_id)))
}

async fn create_organization(
    State(stub): State<WorkOsStub>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let external_id = body["external_id"].as_str().unwrap();
    let user_id = external_id.strip_prefix("cats-personal:").unwrap();
    let organization_id = format!("org_personal_{}", user_id.trim_start_matches("user_"));
    stub.personal_organizations
        .lock()
        .unwrap()
        .insert(user_id.to_string(), organization_id.clone());
    Json(test_organization(&organization_id, external_id))
}

async fn create_membership(State(stub): State<WorkOsStub>, Json(body): Json<Value>) -> Json<Value> {
    let user_id = body["user_id"].as_str().unwrap();
    let organization_id = body["organization_id"].as_str().unwrap();
    stub.personal_memberships
        .lock()
        .unwrap()
        .insert(user_id.to_string(), organization_id.to_string());
    Json(json!({
        "object": "organization_membership",
        "id": "om_personal",
        "user_id": user_id,
        "organization_id": organization_id,
        "status": "active",
        "directory_managed": false,
        "created_at": "2026-07-25T00:00:00.000Z",
        "updated_at": "2026-07-25T00:00:00.000Z",
        "role": {"slug": "admin"},
        "roles": [{"slug": "admin"}],
        "user": test_user(user_id)
    }))
}

async fn get_user(Path(id): Path<String>) -> Json<Value> {
    Json(test_user(&id))
}

struct Ctx {
    _dir: tempfile::TempDir,
    cp: Handle,
    base: String,
    http: reqwest::Client,
    exchanges: Arc<AtomicUsize>,
    membership_requests: Arc<AtomicUsize>,
    membership_fault: Arc<Mutex<MembershipFault>>,
    revoked_sessions: Arc<Mutex<Vec<String>>>,
    issuer: String,
}

impl Ctx {
    async fn new() -> Self {
        let exchanges = Arc::new(AtomicUsize::new(0));
        let membership_requests = Arc::new(AtomicUsize::new(0));
        let membership_fault = Arc::new(Mutex::new(MembershipFault::Healthy));
        let revoked_sessions = Arc::new(Mutex::new(Vec::new()));
        let personal_organizations = Arc::new(Mutex::new(HashMap::new()));
        let personal_memberships = Arc::new(Mutex::new(HashMap::new()));
        let invitations = Arc::new(Mutex::new(Vec::new()));
        let invitation_requests = Arc::new(Mutex::new(HashMap::new()));
        let stub = WorkOsStub {
            exchanges: exchanges.clone(),
            membership_requests: membership_requests.clone(),
            membership_fault: membership_fault.clone(),
            revoked_sessions: revoked_sessions.clone(),
            personal_organizations,
            personal_memberships,
            invitations,
            invitation_requests,
        };
        let app = Router::new()
            .route("/user_management/authenticate", post(authenticate))
            .route("/user_management/sessions/revoke", post(revoke_session))
            .route("/sso/jwks/client_test", get(jwks))
            .route(
                "/user_management/organization_memberships",
                get(list_memberships).post(create_membership),
            )
            .route(
                "/user_management/organization_memberships/{id}",
                get(get_membership).put(update_membership),
            )
            .route(
                "/user_management/organization_memberships/{id}/deactivate",
                put(deactivate_membership),
            )
            .route(
                "/user_management/invitations",
                get(list_invitations).post(send_invitation),
            )
            .route(
                "/user_management/invitations/{id}/revoke",
                post(revoke_invitation),
            )
            .route("/organizations", post(create_organization))
            .route(
                "/organizations/external_id/{external_id}",
                get(get_organization_by_external_id),
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
            account_organizations: BTreeMap::from([
                ("default".into(), "org_default".into()),
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
            control_store_dsn: cats_control_plane::store::DsnSource::Literal(
                cats_control_plane::testsupport::isolated_control_store_url(),
            ),
            control_store_ca_file: None,
            usage_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            credit_store: Arc::new(SqliteUsageStore::open(&dir.path().join("control.db")).unwrap()),
            storage_meta,
            image_blob: cats_control_plane::testsupport::unavailable_image_blob(),
            auth_token: "service-token".into(),
            guest_runtime_profile_receipt:
                cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
            route_grant_signer: cats_control_plane::testsupport::route_grant_signer(),
            admin_token: "admin-token".into(),
            workos: Some(Arc::new(workos)),
            stripe: None,
            billing_enforcement_enabled: false,
            node_lease_timeout_ms: 3_000,
            reconcile_interval_ms: 200,
            oci_deploy_sync_wait_ms: 5_000,
            auto_tier_policy: Default::default(),
        })
        .await
        .unwrap();
        let base = cp.base_url();
        // One Account with two Workspaces plus a second Account keeps the
        // cross-Account and cross-Workspace authorization cases covered.
        let default_account = cp
            .state
            .store
            .account_for_organization("org_default")
            .unwrap()
            .unwrap();
        cp.state
            .store
            .create_workspace(&default_account.id, "sibling", "Sibling")
            .unwrap();
        Self {
            _dir: dir,
            cp,
            base,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            exchanges,
            membership_requests,
            membership_fault,
            revoked_sessions,
            issuer,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Resolve an `account/workspace` locator to the immutable ID the resource
    /// API routes on.
    fn workspace_id(&self, locator: &str) -> String {
        self.cp
            .state
            .store
            .list_all_workspace_views()
            .unwrap()
            .into_iter()
            .find(|workspace| workspace.locator == locator)
            .unwrap_or_else(|| panic!("no workspace {locator}"))
            .id
    }

    fn cats_url(&self, locator: &str) -> String {
        self.url(&format!(
            "/v1/workspaces/{}/cats",
            self.workspace_id(locator)
        ))
    }

    fn set_membership_fault(&self, fault: MembershipFault) {
        *self.membership_fault.lock().unwrap() = fault;
    }

    fn membership_request_count(&self) -> usize {
        self.membership_requests.load(Ordering::SeqCst)
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
        if callback.status() != StatusCode::SEE_OTHER {
            let status = callback.status();
            let body = callback.text().await.unwrap();
            panic!("callback returned {status}: {body}");
        }
        assert_eq!(
            callback.headers().get(LOCATION).unwrap().to_str().unwrap(),
            format!("/{site}/")
        );
        cookie_pair(&callback, &format!("cats_{site}_session"))
    }

    /// The `/auth/session` document a user-site session cookie resolves to.
    async fn user_session(&self, cookie: &str) -> Value {
        self.http
            .get(self.url("/auth/session?site=user"))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    fn cli_token(&self, organization_id: &str) -> String {
        self.cli_token_with_permissions(organization_id, &[])
    }

    fn cli_token_with_permissions(&self, organization_id: &str, permissions: &[&str]) -> String {
        self.cli_token_with_issuer_and_permissions(organization_id, &self.issuer, permissions)
    }

    fn cli_token_with_issuer(&self, organization_id: &str, issuer: &str) -> String {
        self.cli_token_with_issuer_and_permissions(organization_id, issuer, &[])
    }

    fn cli_token_with_issuer_and_permissions(
        &self,
        organization_id: &str,
        issuer: &str,
        permissions: &[&str],
    ) -> String {
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
                "permissions": permissions,
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

async fn assert_membership_unavailable(response: reqwest::Response) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "unavailable");
    assert_eq!(
        body["message"],
        "WorkOS membership is temporarily unavailable"
    );
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
    assert!(public_config.get("workspaces").is_none());
    assert!(!public_config.to_string().contains("sk_test_secret"));

    let user_cookie = ctx.login("user", "user-code").await;
    let user_session: Value = ctx.user_session(&user_cookie).await;
    assert_eq!(user_session["authenticated"], true);
    assert_eq!(
        user_session["active_workspace_id"],
        ctx.workspace_id("default/default")
    );
    assert_eq!(user_session["user"]["email"], "user@example.com");

    let own_workspace = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(own_workspace.status(), StatusCode::OK);
    let other_account = ctx
        .http
        .get(ctx.cats_url("second/default"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(other_account.status(), StatusCode::FORBIDDEN);
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
    let admin_can_read_any_workspace = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .header("Cookie", &admin_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(admin_can_read_any_workspace.status(), StatusCode::OK);
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cli_jwt_lists_and_enforces_multiple_workspaces() {
    let ctx = Ctx::new().await;
    let default_token = ctx.cli_token("org_default");

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
    assert_eq!(me["workspaces"].as_array().unwrap().len(), 3);
    assert_eq!(me["workspaces"][0]["locator"], "default/default");
    assert_eq!(me["workspaces"][1]["locator"], "default/sibling");
    assert_eq!(me["workspaces"][2]["locator"], "second/default");
    assert!(!me.to_string().contains("org_unmapped"));

    let own = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .bearer_auth(&default_token)
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), StatusCode::OK);
    let sibling_in_same_account = ctx
        .http
        .get(ctx.cats_url("default/sibling"))
        .bearer_auth(&default_token)
        .send()
        .await
        .unwrap();
    assert_eq!(sibling_in_same_account.status(), StatusCode::OK);
    let other = ctx
        .http
        .get(ctx.cats_url("second/default"))
        .bearer_auth(&default_token)
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::FORBIDDEN);

    let second_token = ctx.cli_token("org_second");
    let selected = ctx
        .http
        .get(ctx.cats_url("second/default"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(selected.status(), StatusCode::OK);
    let wrong = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

    let tampered = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .bearer_auth(format!("{default_token}x"))
        .send()
        .await
        .unwrap();
    assert_eq!(tampered.status(), StatusCode::UNAUTHORIZED);

    let wrong_issuer = ctx.cli_token_with_issuer("org_default", "https://api.workos.com");
    let rejected = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .bearer_auth(wrong_issuer)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cli_jwt_membership_5xx_fails_closed_and_recovers() {
    let ctx = Ctx::new().await;
    let token = ctx.cli_token("org_default");

    // Calibrate both the JWT and the membership path before injecting the
    // failure. This also loads JWKS so the failure below is specifically the
    // authorization membership dependency, not signing-key discovery.
    let healthy = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(healthy.status(), StatusCode::OK);
    let before_failure = ctx.membership_request_count();

    ctx.set_membership_fault(MembershipFault::Status500);
    let unavailable = tokio::time::timeout(
        Duration::from_secs(5),
        ctx.http
            .get(ctx.cats_url("default/default"))
            .bearer_auth(&token)
            .send(),
    )
    .await
    .expect("membership 5xx must produce a bounded API response")
    .unwrap();
    assert_membership_unavailable(unavailable).await;
    let after_failure = ctx.membership_request_count();
    assert!(after_failure > before_failure);

    let other_account = ctx
        .http
        .get(ctx.cats_url("second/default"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(other_account.status(), StatusCode::FORBIDDEN);
    assert_eq!(ctx.membership_request_count(), after_failure);

    ctx.set_membership_fault(MembershipFault::Healthy);
    let recovered = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    assert!(ctx.membership_request_count() > after_failure);
}

#[tokio::test]
async fn web_session_membership_disconnect_fails_closed_and_recovers() {
    let ctx = Ctx::new().await;
    let user_cookie = ctx.login("user", "user-code").await;

    let healthy = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(healthy.status(), StatusCode::OK);
    let before_failure = ctx.membership_request_count();

    ctx.set_membership_fault(MembershipFault::Disconnect);
    let unavailable = tokio::time::timeout(
        Duration::from_secs(5),
        ctx.http
            .get(ctx.cats_url("default/default"))
            .header("Cookie", &user_cookie)
            .send(),
    )
    .await
    .expect("membership disconnect must produce a bounded API response")
    .unwrap();
    assert_membership_unavailable(unavailable).await;
    let after_failure = ctx.membership_request_count();
    assert!(after_failure > before_failure);

    let other_account = ctx
        .http
        .get(ctx.cats_url("second/default"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(other_account.status(), StatusCode::FORBIDDEN);
    assert_eq!(ctx.membership_request_count(), after_failure);

    ctx.set_membership_fault(MembershipFault::Healthy);
    let recovered = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    assert!(ctx.membership_request_count() > after_failure);
}

#[tokio::test]
async fn workos_callback_rejects_tampered_state_before_code_exchange() {
    let ctx = Ctx::new().await;
    let login = ctx
        .http
        .get(ctx.url(&format!(
            "/auth/login?site=user&workspace={}",
            ctx.workspace_id("default/default")
        )))
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
async fn organizationless_workos_user_receives_an_isolated_personal_account() {
    let ctx = Ctx::new().await;
    let user_cookie = ctx.login("user", "new-user-code").await;

    let session: Value = ctx.user_session(&user_cookie).await;
    assert_eq!(session["authenticated"], true);
    let personal_workspace_id = session["active_workspace_id"].as_str().unwrap().to_string();
    let active = session["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|workspace| workspace["id"] == personal_workspace_id.as_str())
        .expect("the active workspace is listed");
    assert_eq!(active["kind"], "personal");
    assert_eq!(active["slug"], "default");
    assert!(active["is_default"].as_bool().unwrap());

    let own_workspace = ctx
        .http
        .get(ctx.url(&format!("/v1/workspaces/{personal_workspace_id}/cats")))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(own_workspace.status(), StatusCode::OK);
    let shared_workspace = ctx
        .http
        .get(ctx.cats_url("default/default"))
        .header("Cookie", &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(shared_workspace.status(), StatusCode::FORBIDDEN);

    let personal_login = ctx
        .http
        .get(ctx.url(&format!(
            "/auth/login?site=user&workspace={personal_workspace_id}"
        )))
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
    assert!(location
        .query_pairs()
        .any(|(key, value)| { key == "organization_id" && value == "org_personal_new-user-code" }));
    let state = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = ctx
        .http
        .get(ctx.url(&format!(
            "/auth/callback?code=new-user-scoped-code&state={state}"
        )))
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

    let session: Value = ctx.user_session(&user_cookie).await;
    assert_eq!(session["authenticated"], true);
    assert_eq!(
        session["active_workspace_id"],
        ctx.workspace_id("default/default")
    );
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
        "org_id": "org_default",
        "role": "member",
        "permissions": ["cats:workspace:write"],
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
    assert_eq!(
        body["active_workspace_id"],
        ctx.workspace_id("default/default")
    );
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn organization_manager_invites_and_manages_members_through_workos() {
    let ctx = Ctx::new().await;
    let denied = ctx
        .http
        .post(ctx.url("/v1/accounts/unknown/invitations"))
        .bearer_auth(ctx.cli_token("org_default"))
        .json(&json!({"email": "new@example.com", "role_slug": "member"}))
        .send()
        .await
        .unwrap();
    assert!(matches!(
        denied.status(),
        StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
    ));

    let manager_token = ctx.cli_token_with_permissions("org_default", &["cats:members:manage"]);
    let me: Value = ctx
        .http
        .get(ctx.url("/v1/me"))
        .bearer_auth(&manager_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let account_id = me["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["organization_id"] == "org_default")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let no_permission = ctx
        .http
        .post(ctx.url(&format!("/v1/accounts/{account_id}/invitations")))
        .bearer_auth(ctx.cli_token("org_default"))
        .header("Idempotency-Key", "invite-without-permission")
        .json(&json!({"email": "new@example.com", "role_slug": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(no_permission.status(), StatusCode::FORBIDDEN);

    let workspace: Value = ctx
        .http
        .post(ctx.url(&format!("/v1/accounts/{account_id}/workspaces")))
        .bearer_auth(&manager_token)
        .json(&json!({"slug": "dev", "display_name": "Development"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(workspace["locator"], "default/dev");
    let workspace_id = workspace["id"].as_str().unwrap();
    let renamed: Value = ctx
        .http
        .patch(ctx.url(&format!("/v1/workspaces/{workspace_id}")))
        .bearer_auth(&manager_token)
        .json(&json!({"slug": "engineering"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(renamed["locator"], "default/engineering");
    assert_eq!(renamed["id"], workspace_id);

    let created: Value = ctx
        .http
        .post(ctx.url(&format!("/v1/accounts/{account_id}/invitations")))
        .bearer_auth(&manager_token)
        .header("Idempotency-Key", "invite-new-example")
        .json(&json!({"email": "NEW@Example.com", "role_slug": "member"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["account_id"], account_id);
    assert_eq!(created["email"], "new@example.com");
    assert_eq!(created["state"], "pending");

    let replayed: Value = ctx
        .http
        .post(ctx.url(&format!("/v1/accounts/{account_id}/invitations")))
        .bearer_auth(&manager_token)
        .header("Idempotency-Key", "invite-new-example")
        .json(&json!({"email": "NEW@Example.com", "role_slug": "member"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replayed["id"], created["id"]);

    let invitations: Value = ctx
        .http
        .get(ctx.url(&format!("/v1/accounts/{account_id}/invitations")))
        .bearer_auth(&manager_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(invitations["items"].as_array().unwrap().len(), 1);

    let members: Value = ctx
        .http
        .get(ctx.url(&format!("/v1/accounts/{account_id}/members")))
        .bearer_auth(&manager_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(members["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|member| member["membership_id"] == "om_target"));

    let updated: Value = ctx
        .http
        .patch(ctx.url(&format!("/v1/accounts/{account_id}/members/om_target")))
        .bearer_auth(&manager_token)
        .json(&json!({"role_slug": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["role_slug"], "admin");

    let deactivated = ctx
        .http
        .delete(ctx.url(&format!("/v1/accounts/{account_id}/members/om_target")))
        .bearer_auth(&manager_token)
        .send()
        .await
        .unwrap();
    assert_eq!(deactivated.status(), StatusCode::NO_CONTENT);

    let revoked: Value = ctx
        .http
        .post(ctx.url(&format!(
            "/v1/accounts/{account_id}/invitations/invite_test/actions/revoke"
        )))
        .bearer_auth(&manager_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revoked["state"], "revoked");
}

#[tokio::test]
async fn web_switches_workspaces_locally_and_serializes_cross_account_refresh() {
    let ctx = Ctx::new().await;
    let user_cookie = ctx.login("user", "user-code").await;
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 1);
    let session: Value = ctx.user_session(&user_cookie).await;
    let workspace_id = |locator: &str| {
        session["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|workspace| workspace["locator"] == locator)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let sibling_id = workspace_id("default/sibling");
    let second_id = workspace_id("second/default");

    let same_account = ctx
        .http
        .post(ctx.url("/auth/workspace"))
        .header("Cookie", &user_cookie)
        .json(&json!({"workspace_id": sibling_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(same_account.status(), StatusCode::OK);
    assert_eq!(ctx.exchanges.load(Ordering::SeqCst), 1);
    assert!(!same_account
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with("cats_user_session=")));
    let body: Value = same_account.json().await.unwrap();
    assert_eq!(body["active_workspace_id"], sibling_id);

    let first = ctx
        .http
        .post(ctx.url("/auth/workspace"))
        .header("Cookie", &user_cookie)
        .json(&json!({"workspace_id": second_id}));
    let second = ctx
        .http
        .post(ctx.url("/auth/workspace"))
        .header("Cookie", &user_cookie)
        .json(&json!({"workspace_id": second_id.clone()}));
    let (first, second) = tokio::join!(first.send(), second.send());
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        ctx.exchanges.load(Ordering::SeqCst),
        2,
        "two stale tabs must consume only one rotating refresh token"
    );
}

//! Embedded, build-free web consoles. The user and administrator sites call
//! the same versioned API as the CLI and never receive service credentials.

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};

const PORTAL_HTML: &str = include_str!("../ui/index.html");
const USER_HTML: &str = include_str!("../ui/user.html");
const ADMIN_HTML: &str = include_str!("../ui/admin.html");
const STYLES_CSS: &str = include_str!("../ui/styles.css");
const COMMON_JS: &str = include_str!("../ui/common.js");
const USER_JS: &str = include_str!("../ui/user.js");
const ADMIN_JS: &str = include_str!("../ui/admin.js");

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

pub async fn portal() -> Response {
    asset("text/html; charset=utf-8", PORTAL_HTML)
}

pub async fn user_console() -> Response {
    asset("text/html; charset=utf-8", USER_HTML)
}

pub async fn admin_console() -> Response {
    asset("text/html; charset=utf-8", ADMIN_HTML)
}

pub async fn styles() -> Response {
    asset("text/css; charset=utf-8", STYLES_CSS)
}

pub async fn common_script() -> Response {
    asset("text/javascript; charset=utf-8", COMMON_JS)
}

pub async fn user_script() -> Response {
    asset("text/javascript; charset=utf-8", USER_JS)
}

pub async fn admin_script() -> Response {
    asset("text/javascript; charset=utf-8", ADMIN_JS)
}

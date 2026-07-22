//! Embedded, build-free web consoles. The user and administrator sites call
//! the same versioned API as the CLI and never receive service credentials.

use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};

const USER_HTML: &str = include_str!("../ui/user.html");
const ADMIN_HTML: &str = include_str!("../ui/admin.html");
const STYLES_CSS: &str = include_str!("../ui/styles.css");
const I18N_JS: &str = include_str!("../ui/i18n.js");
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

pub async fn portal(headers: HeaderMap) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())
        .unwrap_or_default();
    match host {
        "app.cats.run" => axum::response::Redirect::permanent("https://cats.run/").into_response(),
        "admin.cats.run" => {
            axum::response::Redirect::permanent("https://ops.cats.run/").into_response()
        }
        _ if host.starts_with("ops.") => asset("text/html; charset=utf-8", ADMIN_HTML),
        _ => asset("text/html; charset=utf-8", USER_HTML),
    }
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

pub async fn i18n_script() -> Response {
    asset("text/javascript; charset=utf-8", I18N_JS)
}

pub async fn user_script() -> Response {
    asset("text/javascript; charset=utf-8", USER_JS)
}

pub async fn admin_script() -> Response {
    asset("text/javascript; charset=utf-8", ADMIN_JS)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{ADMIN_HTML, ADMIN_JS, COMMON_JS, I18N_JS, USER_HTML, USER_JS};

    fn quoted_keys(source: &str, prefix: &str) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        let mut rest = source;
        while let Some(start) = rest.find(prefix) {
            rest = &rest[start + prefix.len()..];
            if let Some(end) = rest.find('"') {
                keys.insert(rest[..end].to_string());
                rest = &rest[end + 1..];
            } else {
                break;
            }
        }
        keys
    }

    #[test]
    fn every_static_and_direct_script_translation_key_has_both_locales() {
        let mut used = BTreeSet::new();
        for source in [USER_HTML, ADMIN_HTML] {
            used.extend(quoted_keys(source, "data-i18n=\""));
            used.extend(quoted_keys(source, "data-i18n-aria-label=\""));
            used.extend(quoted_keys(source, "data-i18n-placeholder=\""));
            used.extend(quoted_keys(source, "data-i18n-title=\""));
        }
        for source in [COMMON_JS, USER_JS, ADMIN_JS] {
            used.extend(quoted_keys(source, "t(\"").into_iter().filter(|key| {
                [
                    "language.",
                    "common.",
                    "brand.",
                    "user.",
                    "admin.",
                    "status.",
                    "kind.",
                    "operation.",
                    "error.",
                ]
                .iter()
                .any(|prefix| key.starts_with(prefix))
            }));
        }

        for key in used {
            let needle = format!("\"{key}\":");
            assert_eq!(
                I18N_JS.matches(&needle).count(),
                2,
                "translation key {key:?} must exist once in English and once in Chinese"
            );
        }
    }

    #[test]
    fn locale_selection_prefers_saved_choice_then_browser_environment() {
        for contract in [
            "window.localStorage.getItem(STORAGE_KEY)",
            "navigator.languages",
            "navigator.language",
            "locale.startsWith(\"zh-\")",
            "locale.startsWith(\"en-\")",
            "window.addEventListener(\"languagechange\"",
            "document.documentElement.lang = currentLocale",
        ] {
            assert!(
                I18N_JS.contains(contract),
                "missing locale contract: {contract}"
            );
        }
    }

    #[test]
    fn english_and_chinese_catalogs_have_the_same_keys() {
        let mut counts = std::collections::BTreeMap::<&str, usize>::new();
        for line in I18N_JS.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix('"') else {
                continue;
            };
            let Some((key, _)) = rest.split_once("\":") else {
                continue;
            };
            if key == "zh-CN" {
                continue;
            }
            *counts.entry(key).or_default() += 1;
        }
        assert!(!counts.is_empty());
        for (key, count) in counts {
            assert_eq!(count, 2, "translation key {key:?} is missing from a locale");
        }
    }

    #[test]
    fn dynamic_status_action_kind_and_operation_keys_have_both_locales() {
        for key in [
            "status.unknown",
            "status.creating",
            "status.starting",
            "status.running",
            "status.suspending",
            "status.suspended",
            "status.warming",
            "status.warm",
            "status.stopping",
            "status.cold",
            "status.failed",
            "status.deleted",
            "status.ready",
            "status.cordoned",
            "status.draining",
            "status.lost",
            "status.pending",
            "status.succeeded",
            "status.available",
            "status.bound",
            "status.deleting",
            "kind.root",
            "kind.persistent",
            "user.action.exec",
            "user.action.suspend",
            "user.action.warm",
            "user.action.stop",
            "user.action.resume",
            "user.action.start",
            "user.action.expose",
            "user.action.destroy",
            "user.action.snapshot",
            "user.action.unmount",
            "user.action.mount",
            "user.action.resize",
            "user.action.delete",
            "admin.action.cordon",
            "admin.action.drain",
            "admin.action.uncordon",
            "admin.action.cancelDrain",
            "admin.action.delete",
            "operation.cat_create",
            "operation.cat_start",
            "operation.cat_stop",
            "operation.cat_suspend",
            "operation.cat_resume",
            "operation.cat_warm",
            "operation.cat_wake",
            "operation.cat_work_wake",
            "operation.cat_auto_suspend",
            "operation.cat_delete",
        ] {
            assert_eq!(
                I18N_JS.matches(&format!("\"{key}\":")).count(),
                2,
                "dynamic translation key {key:?} must exist in both catalogs"
            );
        }
    }
}

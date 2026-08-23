use super::*;

pub(super) fn cookie_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter(|(candidate, _)| *candidate == name)
        .map(|(_, value)| value.to_string())
        .collect()
}

pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    cookie_values(headers, name).pop()
}

fn append_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age_seconds: u64,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    let secure_attribute = if secure { "; Secure" } else { "" };
    let domain_attribute = domain
        .map(|value| format!("; Domain={value}"))
        .unwrap_or_default();
    let cookie = format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{secure_attribute}{domain_attribute}"
    );
    let value = HeaderValue::from_str(&cookie)
        .map_err(|_| ApiError::internal("failed to encode session cookie"))?;
    response.headers_mut().append(header::SET_COOKIE, value);
    Ok(())
}

pub(super) fn append_set_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age_seconds: u64,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    // A host-only cookie and a Domain cookie with the same name/path are
    // distinct browser records and are both sent back. Expire the host-only
    // variant before publishing the configured Domain cookie so an older
    // session cannot shadow the replacement.
    if domain.is_some() {
        append_cookie(response, name, "", 0, secure, None)?;
    }
    append_cookie(response, name, value, max_age_seconds, secure, domain)
}

pub(super) fn append_delete_cookie(
    response: &mut Response,
    name: &str,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    append_cookie(response, name, "", 0, secure, None)?;
    if let Some(domain) = domain {
        append_cookie(response, name, "", 0, secure, Some(domain))?;
    }
    Ok(())
}

pub(super) fn set_no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn set_cookie_values(response: &Response) -> Vec<&str> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect()
    }

    #[test]
    fn domain_cookie_replaces_a_host_only_variant() {
        let mut response = StatusCode::OK.into_response();
        append_set_cookie(
            &mut response,
            "cats_user_session",
            "fresh",
            60,
            true,
            Some("cats.run"),
        )
        .unwrap();

        let cookies = set_cookie_values(&response);
        assert_eq!(cookies.len(), 2);
        assert!(cookies[0].starts_with("cats_user_session=;"));
        assert!(cookies[0].contains("Max-Age=0"));
        assert!(!cookies[0].contains("Domain="));
        assert!(cookies[1].starts_with("cats_user_session=fresh;"));
        assert!(cookies[1].contains("Domain=cats.run"));
    }

    #[test]
    fn delete_cookie_expires_host_only_and_domain_variants() {
        let mut response = StatusCode::OK.into_response();
        append_delete_cookie(&mut response, "cats_user_session", true, Some("cats.run")).unwrap();

        let cookies = set_cookie_values(&response);
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().all(|cookie| cookie.contains("Max-Age=0")));
        assert!(!cookies[0].contains("Domain="));
        assert!(cookies[1].contains("Domain=cats.run"));
    }
}

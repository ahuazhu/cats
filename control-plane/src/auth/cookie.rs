use super::*;

pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(candidate, value)| (candidate == name).then(|| value.to_string()))
}

pub(super) fn append_set_cookie(
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

pub(super) fn append_delete_cookie(
    response: &mut Response,
    name: &str,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    append_set_cookie(response, name, "", 0, secure, domain)
}

pub(super) fn set_no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

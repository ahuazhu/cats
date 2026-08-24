use std::fmt;
use std::thread;
use std::time::Duration;

use reqwest::blocking::Client as HttpClient;
use serde::de::DeserializeOwned;
use serde::Deserialize;

const DEVICE_AUTHORIZATION_PATH: &str = "/user_management/authorize/device";
const AUTHENTICATE_PATH: &str = "/user_management/authenticate";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
// Preserve the wire identity of the SDK release this narrow client replaces.
const USER_AGENT: &str = "workos-rust/2.5.0";

pub(crate) struct PublicClient {
    http: HttpClient,
    client_id: String,
    api_base_url: String,
}

impl PublicClient {
    pub(crate) fn new(client_id: &str, api_base_url: &str) -> Result<Self, Error> {
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .build()
            .map_err(Error::Network)?;
        Ok(Self {
            http,
            client_id: client_id.to_owned(),
            api_base_url: api_base_url.to_owned(),
        })
    }

    pub(crate) fn start_device_authorization(&self) -> Result<DeviceAuthorization, Error> {
        self.post_json(
            DEVICE_AUTHORIZATION_PATH,
            &serde_json::json!({ "client_id": self.client_id }),
        )
    }

    pub(crate) fn poll_device_code(
        &self,
        device_code: &str,
        interval: Duration,
    ) -> Result<Authentication, Error> {
        let mut interval = if interval.is_zero() {
            Duration::from_secs(5)
        } else {
            interval
        };
        loop {
            thread::sleep(interval);
            let result = self.post_json(
                AUTHENTICATE_PATH,
                &serde_json::json!({
                    "grant_type": DEVICE_CODE_GRANT,
                    "client_id": self.client_id,
                    "device_code": device_code,
                }),
            );
            match result {
                Ok(authentication) => return Ok(authentication),
                Err(error) if error.code() == Some("authorization_pending") => continue,
                Err(error) if error.code() == Some("slow_down") => {
                    interval += Duration::from_secs(5);
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn authenticate_with_refresh_token(
        &self,
        refresh_token: &str,
        organization_id: &str,
    ) -> Result<Authentication, Error> {
        self.post_json(
            AUTHENTICATE_PATH,
            &serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "organization_id": organization_id,
                "ip_address": null,
                "device_id": null,
                "user_agent": null,
                "client_id": self.client_id,
            }),
        )
    }

    fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, Error> {
        let response = self
            .http
            .post(format!("{}{}", self.api_base_url, path))
            .json(body)
            .send()
            .map_err(Error::Network)?;
        let status = response.status();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().map_err(Error::Network)?;
        if !status.is_success() {
            let (code, message) = parse_error_body(&body);
            return Err(Error::Api {
                status,
                code,
                message,
                request_id,
            });
        }
        serde_json::from_slice(&body).map_err(Error::Decode)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeviceAuthorization {
    pub(crate) device_code: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    #[serde(default)]
    pub(crate) verification_uri_complete: Option<String>,
    #[serde(rename = "expires_in")]
    _expires_in: f64,
    #[serde(default)]
    pub(crate) interval: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Authentication {
    pub(crate) user: User,
    #[serde(default)]
    pub(crate) organization_id: Option<String>,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct User {
    #[serde(rename = "object")]
    _object: String,
    pub(crate) id: String,
    pub(crate) email: String,
    #[serde(rename = "email_verified")]
    _email_verified: bool,
    #[serde(rename = "created_at")]
    _created_at: String,
    #[serde(rename = "updated_at")]
    _updated_at: String,
}

#[derive(Debug)]
pub(crate) enum Error {
    Api {
        status: reqwest::StatusCode,
        code: Option<String>,
        message: String,
        request_id: Option<String>,
    },
    Network(reqwest::Error),
    Decode(serde_json::Error),
}

impl Error {
    fn code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => code.as_deref(),
            Self::Network(_) | Self::Decode(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api {
                status,
                message,
                request_id,
                ..
            } => {
                write!(formatter, "API error {}: {message}", status.as_u16())?;
                if let Some(request_id) = request_id {
                    write!(formatter, " (request_id={request_id})")?;
                }
                Ok(())
            }
            Self::Network(error) => write!(formatter, "network error: {error}"),
            Self::Decode(error) => write!(formatter, "decode error: {error}"),
        }
    }
}

impl std::error::Error for Error {}

fn parse_error_body(body: &[u8]) -> (Option<String>, String) {
    let raw = String::from_utf8_lossy(body).into_owned();
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (None, raw);
    };
    let Some(object) = value.as_object() else {
        return (None, raw);
    };
    let code = object
        .get("code")
        .or_else(|| object.get("error"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let message = object
        .get("message")
        .or_else(|| object.get("error_description"))
        .or_else(|| object.get("error"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or(raw);
    (code, message)
}

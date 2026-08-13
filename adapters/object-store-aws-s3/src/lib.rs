//! AWS S3 adapter for the provider-neutral Cats blob-store port.
//!
//! The adapter uses AWS Signature V4 and path-style requests. A configurable
//! endpoint keeps MinIO usable as the contract-test target without exposing
//! S3 concepts to storage consumers.
//!
//! Immutability uses `If-None-Match: *`; a retry that finds an existing object
//! verifies its bytes before treating the operation as idempotently complete.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cats_storage::blob::{
    validate_key, validate_list_maximum, validate_list_result, BlobError, BlobListPage, BlobStore,
    Result,
};
use cats_storage::{AdapterConfig, AdapterError, BlobStoreFactory};

pub const ADAPTER_NAME: &str = "aws-s3";

/// Total attempts for one object-store request, including the first.
const RETRY_ATTEMPTS: u32 = 5;
const RETRY_INITIAL_DELAY_MS: u64 = 100;
const RETRY_MAX_DELAY_MS: u64 = 3_000;
const ERROR_RESPONSE_MAX_BYTES: usize = 8 * 1024;
const CREDENTIAL_RESPONSE_MAX_BYTES: usize = 16 * 1024;
const LIST_RESPONSE_BYTES_PER_KEY: usize = 8 * 1024;
const LIST_RESPONSE_FIXED_BYTES: usize = 64 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AwsS3Config {
    /// Endpoint origin, e.g. `https://s3.us-east-1.amazonaws.com` or
    /// `http://127.0.0.1:9000` (MinIO).
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// Session token for short-lived AWS credentials.
    pub session_token: Option<String>,
    /// Key prefix inside the bucket (tenant/env isolation).
    pub prefix: String,
}

pub struct AwsS3BlobStore {
    cfg: AwsS3Config,
    client: reqwest::blocking::Client,
    credentials: Mutex<CredentialState>,
}

#[derive(Clone)]
struct SigningCredentials {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

enum CredentialState {
    Static(SigningCredentials),
    Imds {
        role_name: String,
        credentials: SigningCredentials,
        refreshed_at: Instant,
    },
    Container {
        endpoint: String,
        token_file: PathBuf,
        credentials: SigningCredentials,
        refreshed_at: Instant,
    },
}

#[derive(Clone, Copy)]
struct ReadBounds {
    maximum: usize,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct RequestParts<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a [(String, String)],
    body: &'a [u8],
    extra_headers: &'a [(&'a str, &'a str)],
    key_for_errors: &'a str,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImdsCredentialDocument {
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

impl AwsS3BlobStore {
    pub fn new(mut cfg: AwsS3Config) -> Result<Self> {
        let endpoint = reqwest::Url::parse(&cfg.endpoint).map_err(|error| BlobError::Backend {
            key: "<config>".into(),
            message: format!("invalid AWS S3 endpoint: {error}"),
        })?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || !endpoint.has_host()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(BlobError::Backend {
                key: "<config>".into(),
                message: "AWS S3 endpoint must be an HTTP(S) origin without credentials, path, query, or fragment".into(),
            });
        }
        if cfg.bucket.is_empty() {
            return Err(BlobError::Backend {
                key: "<config>".into(),
                message: "AWS S3 bucket must not be empty".into(),
            });
        }
        cfg.endpoint = endpoint.origin().ascii_serialization();
        let client = reqwest::blocking::Client::builder()
            // Signed requests and link-local credential requests must never
            // be replayed to a Location that was not part of the signature or
            // exact credential-endpoint validation.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| BlobError::Backend {
                key: "<client>".into(),
                message: e.to_string(),
            })?;
        let credentials = SigningCredentials {
            access_key: cfg.access_key.clone(),
            secret_key: cfg.secret_key.clone(),
            session_token: cfg.session_token.clone(),
        };
        Ok(Self {
            cfg,
            client,
            credentials: Mutex::new(CredentialState::Static(credentials)),
        })
    }

    fn from_instance_role(mut cfg: AwsS3Config) -> Result<Self> {
        let (role_name, credentials) = load_imds_credentials(None, None)?;
        cfg.access_key = credentials.access_key.clone();
        cfg.secret_key = credentials.secret_key.clone();
        cfg.session_token = credentials.session_token.clone();
        let mut store = Self::new(cfg)?;
        store.credentials = Mutex::new(CredentialState::Imds {
            role_name,
            credentials,
            refreshed_at: Instant::now(),
        });
        Ok(store)
    }

    fn from_container_role(
        mut cfg: AwsS3Config,
        endpoint: String,
        token_file: PathBuf,
    ) -> Result<Self> {
        validate_container_credential_endpoint(&endpoint)?;
        let credentials = load_container_credentials(&endpoint, &token_file, None)?;
        cfg.access_key = credentials.access_key.clone();
        cfg.secret_key = credentials.secret_key.clone();
        cfg.session_token = credentials.session_token.clone();
        let mut store = Self::new(cfg)?;
        store.credentials = Mutex::new(CredentialState::Container {
            endpoint,
            token_file,
            credentials,
            refreshed_at: Instant::now(),
        });
        Ok(store)
    }

    fn signing_credentials(
        &self,
        key_for_errors: &str,
        deadline: Option<Instant>,
    ) -> Result<SigningCredentials> {
        let mut state = self.lock_credentials(key_for_errors, deadline)?;
        match &mut *state {
            CredentialState::Static(credentials) => Ok(credentials.clone()),
            CredentialState::Imds {
                role_name,
                credentials,
                refreshed_at,
            } => {
                // EC2 role credentials normally last hours. Refreshing every
                // five minutes avoids depending on timestamp parsing while
                // keeping a long-running blockd process current.
                if refreshed_at.elapsed() >= Duration::from_secs(5 * 60) {
                    let (_, replacement) = load_imds_credentials(Some(role_name), deadline)
                        .map_err(|error| BlobError::Backend {
                            key: key_for_errors.into(),
                            message: format!("refresh EC2 instance-role credentials: {error}"),
                        })?;
                    *credentials = replacement;
                    *refreshed_at = Instant::now();
                }
                Ok(credentials.clone())
            }
            CredentialState::Container {
                endpoint,
                token_file,
                credentials,
                refreshed_at,
            } => {
                if refreshed_at.elapsed() >= Duration::from_secs(5 * 60) {
                    *credentials = load_container_credentials(endpoint, token_file, deadline)
                        .map_err(|error| BlobError::Backend {
                            key: key_for_errors.into(),
                            message: format!("refresh EKS Pod Identity credentials: {error}"),
                        })?;
                    *refreshed_at = Instant::now();
                }
                Ok(credentials.clone())
            }
        }
    }

    fn lock_credentials(
        &self,
        key_for_errors: &str,
        deadline: Option<Instant>,
    ) -> Result<MutexGuard<'_, CredentialState>> {
        let Some(deadline) = deadline else {
            return self.credentials.lock().map_err(|_| BlobError::Backend {
                key: key_for_errors.into(),
                message: "AWS credential mutex was poisoned".into(),
            });
        };
        loop {
            match self.credentials.try_lock() {
                Ok(state) => return Ok(state),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(BlobError::Backend {
                        key: key_for_errors.into(),
                        message: "AWS credential mutex was poisoned".into(),
                    });
                }
                Err(TryLockError::WouldBlock) => {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|remaining| !remaining.is_zero())
                        .ok_or_else(|| deadline_error(key_for_errors))?;
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
            }
        }
    }

    fn full_key(&self, key: &str) -> String {
        if self.cfg.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.cfg.prefix.trim_end_matches('/'), key)
        }
    }

    fn host(&self) -> String {
        let e = self.cfg.endpoint.trim_end_matches('/');
        e.trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    }

    fn url(&self, path: &str, query: &[(String, String)]) -> String {
        let mut url = format!("{}{}", self.cfg.endpoint.trim_end_matches('/'), path);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&canonical_query(query));
        }
        url
    }

    /// Execute a signed request, retrying transient failures.
    ///
    /// A single failed object-store call is not a tolerable outcome here: the
    /// caller is a block device, so the error reaches the Guest as an I/O error
    /// on FLUSH, and its filesystem aborts its journal and remounts read-only.
    /// Object storage answers 5xx and drops connections as normal operation, so
    /// those must be retried rather than surfaced. Every operation this adapter
    /// issues is safe to repeat: reads and deletes are idempotent, and an
    /// immutable put that finds its object already present verifies the bytes
    /// (see the module docs).
    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: &[u8],
        extra_headers: &[(&str, &str)],
        key_for_errors: &str,
    ) -> Result<(u16, Vec<u8>)> {
        self.request_with_bounds(
            RequestParts {
                method,
                path,
                query,
                body,
                extra_headers,
                key_for_errors,
            },
            None,
        )
    }

    fn request_with_bounds(
        &self,
        request: RequestParts<'_>,
        bounds: Option<ReadBounds>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut delay = Duration::from_millis(RETRY_INITIAL_DELAY_MS);
        let mut attempt = 1;
        loop {
            if bounds.is_some_and(|bounds| Instant::now() >= bounds.deadline) {
                return Err(deadline_error(request.key_for_errors));
            }
            let outcome = self.request_once(request, bounds);
            let retryable = match &outcome {
                Err(BlobError::Backend { .. }) => true,
                Ok((status, _)) => *status == 429 || (500..600).contains(status),
                _ => false,
            };
            if !retryable || attempt >= RETRY_ATTEMPTS {
                if attempt > 1 {
                    tracing::warn!(
                        key = request.key_for_errors,
                        method = request.method,
                        attempts = attempt,
                        "object-store request settled after retries"
                    );
                }
                return outcome;
            }
            match &outcome {
                Err(error) => tracing::warn!(
                    key = request.key_for_errors, method = request.method, attempt, %error,
                    "object-store request failed; retrying"
                ),
                Ok((status, _)) => tracing::warn!(
                    key = request.key_for_errors,
                    method = request.method,
                    attempt,
                    status,
                    "object-store request returned a retryable status; retrying"
                ),
            }
            if let Some(bounds) = bounds {
                let Some(remaining) = bounds.deadline.checked_duration_since(Instant::now()) else {
                    return Err(deadline_error(request.key_for_errors));
                };
                if remaining <= delay {
                    return Err(deadline_error(request.key_for_errors));
                }
            }
            std::thread::sleep(delay);
            delay = (delay * 4).min(Duration::from_millis(RETRY_MAX_DELAY_MS));
            attempt += 1;
        }
    }

    fn request_once(
        &self,
        request: RequestParts<'_>,
        bounds: Option<ReadBounds>,
    ) -> Result<(u16, Vec<u8>)> {
        let RequestParts {
            method,
            path,
            query,
            body,
            extra_headers,
            key_for_errors,
        } = request;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| BlobError::Backend {
                key: key_for_errors.into(),
                message: format!("system clock is before the Unix epoch: {error}"),
            })?
            .as_secs();
        let now = i64::try_from(now).map_err(|error| BlobError::Backend {
            key: key_for_errors.into(),
            message: format!("system clock is outside the supported range: {error}"),
        })?;
        let (amz_date, date_stamp) = amz_timestamp(now);
        let payload_hash = hex::encode(Sha256::digest(body));
        let host = self.host();
        let credentials =
            self.signing_credentials(key_for_errors, bounds.map(|bounds| bounds.deadline))?;

        let mut headers = vec![
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if let Some(token) = &credentials.session_token {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }
        headers.extend(
            extra_headers
                .iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_string())),
        );
        let auth = sign_v4(
            method,
            path,
            query,
            &headers,
            &payload_hash,
            &amz_date,
            &date_stamp,
            &self.cfg.region,
            "s3",
            &credentials.access_key,
            &credentials.secret_key,
        );

        let url = self.url(path, query);
        let method =
            reqwest::Method::from_bytes(method.as_bytes()).map_err(|error| BlobError::Backend {
                key: key_for_errors.into(),
                message: format!("invalid HTTP method: {error}"),
            })?;
        let mut req = self.client.request(method, &url).body(body.to_vec());
        if let Some(bounds) = bounds {
            let remaining = bounds
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| deadline_error(key_for_errors))?;
            req = req.timeout(remaining);
        }
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        req = req.header("authorization", auth);
        let resp = req.send().map_err(|e| BlobError::Backend {
            key: key_for_errors.into(),
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        let bytes = read_response_body(resp, status, bounds, key_for_errors)?;
        Ok((status, bytes))
    }

    fn object_path(&self, key: &str) -> Result<String> {
        validate_key(key)?;
        Ok(format!(
            "/{}/{}",
            uri_encode(&self.cfg.bucket, false),
            uri_encode(&self.full_key(key), false)
        ))
    }
}

fn deadline_error(key: &str) -> BlobError {
    BlobError::Backend {
        key: key.to_string(),
        message: "bounded read deadline elapsed".into(),
    }
}

fn read_response_body(
    mut response: reqwest::blocking::Response,
    status: u16,
    bounds: Option<ReadBounds>,
    key: &str,
) -> Result<Vec<u8>> {
    let success_limit = (200..300).contains(&status).then_some(bounds).flatten();
    if let Some(bounds) = success_limit {
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(bounds.maximum).unwrap_or(u64::MAX))
        {
            return Err(BlobError::TooLarge {
                key: key.to_string(),
                maximum: bounds.maximum,
                observed_at_least: bounds.maximum.saturating_add(1),
            });
        }
    }

    let maximum = success_limit
        .map(|bounds| bounds.maximum)
        .unwrap_or(ERROR_RESPONSE_MAX_BYTES);
    if bounds.is_none() && (200..300).contains(&status) {
        return response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|error| BlobError::Backend {
                key: key.to_string(),
                message: error.to_string(),
            });
    }

    let read_limit = maximum.saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    response
        .by_ref()
        .take(u64::try_from(read_limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|error| BlobError::Backend {
            key: key.to_string(),
            message: error.to_string(),
        })?;
    if let Some(bounds) = success_limit {
        if bytes.len() > bounds.maximum {
            return Err(BlobError::TooLarge {
                key: key.to_string(),
                maximum: bounds.maximum,
                observed_at_least: bytes.len(),
            });
        }
        if Instant::now() > bounds.deadline {
            return Err(deadline_error(key));
        }
    } else if bytes.len() > maximum {
        bytes.truncate(maximum);
    }
    Ok(bytes)
}

fn load_imds_credentials(
    role_name: Option<&str>,
    deadline: Option<Instant>,
) -> Result<(String, SigningCredentials)> {
    if std::env::var("AWS_EC2_METADATA_DISABLED").is_ok_and(|value| value == "true") {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: "EC2 instance metadata is disabled".into(),
        });
    }
    const IMDS: &str = "http://169.254.169.254/latest";
    let initial_timeout = credential_timeout(deadline)?;
    let client = credential_client(initial_timeout)?;
    let token_response = client
        .put(format!("{IMDS}/api/token"))
        .timeout(credential_timeout(deadline)?)
        .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()
        .map_err(|error| BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("obtain EC2 metadata token: {error}"),
        })?;
    let token = read_credential_text(token_response, "obtain EC2 metadata token")?;
    let role_name = match role_name {
        Some(role_name) => role_name.to_string(),
        None => {
            let response = client
                .get(format!("{IMDS}/meta-data/iam/security-credentials/"))
                .timeout(credential_timeout(deadline)?)
                .header("x-aws-ec2-metadata-token", &token)
                .send()
                .map_err(|error| BlobError::Backend {
                    key: "<credentials>".into(),
                    message: format!("discover EC2 instance role: {error}"),
                })?;
            read_credential_text(response, "discover EC2 instance role")?
                .trim()
                .to_string()
        }
    };
    if role_name.is_empty() || role_name.contains(['/', '\n', '\r']) {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: "EC2 metadata returned an invalid role name".into(),
        });
    }
    let response = client
        .get(format!(
            "{IMDS}/meta-data/iam/security-credentials/{role_name}"
        ))
        .timeout(credential_timeout(deadline)?)
        .header("x-aws-ec2-metadata-token", token)
        .send()
        .map_err(|error| BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("read EC2 instance-role credentials: {error}"),
        })?;
    let document: ImdsCredentialDocument =
        read_credential_json(response, "read EC2 instance-role credentials")?;
    if document.access_key_id.is_empty()
        || document.secret_access_key.is_empty()
        || document.token.is_empty()
    {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: "EC2 metadata returned incomplete credentials".into(),
        });
    }
    Ok((
        role_name,
        SigningCredentials {
            access_key: document.access_key_id,
            secret_key: document.secret_access_key,
            session_token: Some(document.token),
        },
    ))
}

fn validate_container_credential_endpoint(endpoint: &str) -> Result<()> {
    let endpoint_url = reqwest::Url::parse(endpoint).map_err(|error| BlobError::Backend {
        key: "<credentials>".into(),
        message: format!("invalid EKS Pod Identity credential URI: {error}"),
    })?;
    if endpoint_url.scheme() != "http"
        || endpoint_url.host_str() != Some("169.254.170.23")
        || endpoint_url.port().is_some()
        || endpoint_url.path() != "/v1/credentials"
        || endpoint_url.query().is_some()
        || endpoint_url.fragment().is_some()
        || !endpoint_url.username().is_empty()
        || endpoint_url.password().is_some()
    {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message:
                "EKS Pod Identity credential URI must be exact http://169.254.170.23/v1/credentials"
                    .into(),
        });
    }
    Ok(())
}

fn load_container_credentials(
    endpoint: &str,
    token_file: &Path,
    deadline: Option<Instant>,
) -> Result<SigningCredentials> {
    validate_container_credential_endpoint(endpoint)?;
    let metadata = std::fs::metadata(token_file).map_err(|error| BlobError::Backend {
        key: "<credentials>".into(),
        message: format!("read EKS Pod Identity token metadata: {error}"),
    })?;
    if metadata.len() > 16 * 1024 {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: "EKS Pod Identity authorization token exceeds 16384 bytes".into(),
        });
    }
    let mut token_file = std::fs::File::open(token_file).map_err(|error| BlobError::Backend {
        key: "<credentials>".into(),
        message: format!("open EKS Pod Identity authorization token: {error}"),
    })?;
    let mut token = String::with_capacity(usize::try_from(metadata.len()).unwrap_or(16 * 1024));
    token_file
        .by_ref()
        .take(16 * 1024 + 1)
        .read_to_string(&mut token)
        .map_err(|error| BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("read EKS Pod Identity authorization token: {error}"),
        })?;
    if token.len() > 16 * 1024 {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: "EKS Pod Identity authorization token exceeds 16384 bytes".into(),
        });
    }
    let token = token.trim();
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: "EKS Pod Identity authorization token is empty or malformed".into(),
        });
    }
    let timeout = credential_timeout(deadline)?;
    let client = credential_client(timeout)?;
    let response = client
        .get(endpoint)
        .timeout(credential_timeout(deadline)?)
        .header("authorization", token)
        .send()
        .map_err(|error| BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("read EKS Pod Identity credentials: {error}"),
        })?;
    let document: ImdsCredentialDocument =
        read_credential_json(response, "read EKS Pod Identity credentials")?;
    if document.access_key_id.is_empty()
        || document.secret_access_key.is_empty()
        || document.token.is_empty()
    {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: "EKS Pod Identity returned incomplete credentials".into(),
        });
    }
    Ok(SigningCredentials {
        access_key: document.access_key_id,
        secret_key: document.secret_access_key,
        session_token: Some(document.token),
    })
}

fn read_credential_text(response: reqwest::blocking::Response, operation: &str) -> Result<String> {
    let bytes = read_credential_body(response, operation)?;
    String::from_utf8(bytes).map_err(|error| BlobError::Backend {
        key: "<credentials>".into(),
        message: format!("{operation}: response is not UTF-8: {error}"),
    })
}

fn credential_client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2).min(timeout))
        .timeout(timeout)
        .build()
        .map_err(|error| BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("build AWS credential client: {error}"),
        })
}

fn read_credential_json<T>(response: reqwest::blocking::Response, operation: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = read_credential_body(response, operation)?;
    serde_json::from_slice(&bytes).map_err(|error| BlobError::Backend {
        key: "<credentials>".into(),
        message: format!("{operation}: invalid JSON: {error}"),
    })
}

fn read_credential_body(
    mut response: reqwest::blocking::Response,
    operation: &str,
) -> Result<Vec<u8>> {
    response = response
        .error_for_status()
        .map_err(|error| BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("{operation}: {error}"),
        })?;
    if response.content_length().is_some_and(|length| {
        length > u64::try_from(CREDENTIAL_RESPONSE_MAX_BYTES).unwrap_or(u64::MAX)
    }) {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("{operation}: response exceeds {CREDENTIAL_RESPONSE_MAX_BYTES} bytes"),
        });
    }
    let mut bytes = Vec::with_capacity(CREDENTIAL_RESPONSE_MAX_BYTES.min(4 * 1024));
    response
        .by_ref()
        .take(u64::try_from(CREDENTIAL_RESPONSE_MAX_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|error| BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("{operation}: {error}"),
        })?;
    if bytes.len() > CREDENTIAL_RESPONSE_MAX_BYTES {
        return Err(BlobError::Backend {
            key: "<credentials>".into(),
            message: format!("{operation}: response exceeds {CREDENTIAL_RESPONSE_MAX_BYTES} bytes"),
        });
    }
    Ok(bytes)
}

fn credential_timeout(deadline: Option<Instant>) -> Result<Duration> {
    match deadline {
        Some(deadline) => deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| remaining.min(Duration::from_secs(3)))
            .ok_or_else(|| deadline_error("<credentials>")),
        None => Ok(Duration::from_secs(3)),
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AwsS3BlobStoreFactory;

impl BlobStoreFactory for AwsS3BlobStoreFactory {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn open(
        &self,
        config: &AdapterConfig,
    ) -> std::result::Result<Arc<dyn BlobStore>, AdapterError> {
        config.ensure_only(ADAPTER_NAME, &["endpoint", "bucket", "region", "prefix"])?;
        let bucket = config.required(ADAPTER_NAME, "bucket")?.to_string();
        let region = config.optional("region").unwrap_or("us-east-1").to_string();
        let endpoint = config
            .optional("endpoint")
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com"));
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").ok();
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok();
        if access_key.is_some() != secret_key.is_some() {
            return Err(AdapterError::InvalidConfig {
                adapter: ADAPTER_NAME,
                message: "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together".into(),
            });
        }
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        let config = AwsS3Config {
            endpoint,
            bucket,
            region,
            access_key: access_key.clone().unwrap_or_default(),
            secret_key: secret_key.unwrap_or_default(),
            session_token,
            prefix: config.optional("prefix").unwrap_or_default().to_string(),
        };
        let container_uri = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI").ok();
        let container_token_file =
            std::env::var_os("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE").map(PathBuf::from);
        if container_uri.is_some() != container_token_file.is_some() {
            return Err(AdapterError::InvalidConfig {
                adapter: ADAPTER_NAME,
                message: "AWS_CONTAINER_CREDENTIALS_FULL_URI and AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE must be set together".into(),
            });
        }
        if access_key.is_some() {
            AwsS3BlobStore::new(config)
        } else if let (Some(endpoint), Some(token_file)) = (container_uri, container_token_file) {
            AwsS3BlobStore::from_container_role(config, endpoint, token_file)
        } else {
            AwsS3BlobStore::from_instance_role(config)
        }
        .map(|store| Arc::new(store) as Arc<dyn BlobStore>)
        .map_err(|error| AdapterError::Open {
            adapter: ADAPTER_NAME,
            message: error.to_string(),
        })
    }
}

impl BlobStore for AwsS3BlobStore {
    fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.object_path(key)?;
        let (status, body) =
            self.request("PUT", &path, &[], data, &[("if-none-match", "*")], key)?;
        if matches!(status, 409 | 412) {
            return match self.get(key) {
                Ok(existing) if existing == data => Ok(()),
                Ok(_) => Err(BlobError::Backend {
                    key: key.to_string(),
                    message: "immutable object overwrite with different content".into(),
                }),
                Err(error) => Err(BlobError::Backend {
                    key: key.to_string(),
                    message: format!("conditional PUT conflicted and existing object could not be verified: {error}"),
                }),
            };
        }
        if !(200..300).contains(&status) {
            return Err(BlobError::Backend {
                key: key.to_string(),
                message: format!("PUT status {status}: {}", snippet(&body)),
            });
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.object_path(key)?;
        let (status, body) = self.request("GET", &path, &[], b"", &[], key)?;
        match status {
            200..=299 => Ok(body),
            404 => Err(BlobError::NotFound(key.to_string())),
            _ => Err(BlobError::Backend {
                key: key.to_string(),
                message: format!("GET status {status}: {}", snippet(&body)),
            }),
        }
    }

    fn get_bounded(&self, key: &str, maximum: usize) -> Result<Vec<u8>> {
        self.get_bounded_until(key, maximum, Instant::now() + Duration::from_secs(60))
    }

    fn get_bounded_until(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Vec<u8>> {
        let path = self.object_path(key)?;
        let (status, body) = self.request_with_bounds(
            RequestParts {
                method: "GET",
                path: &path,
                query: &[],
                body: b"",
                extra_headers: &[],
                key_for_errors: key,
            },
            Some(ReadBounds { maximum, deadline }),
        )?;
        match status {
            200..=299 => Ok(body),
            404 => Err(BlobError::NotFound(key.to_string())),
            _ => Err(BlobError::Backend {
                key: key.to_string(),
                message: format!("GET status {status}: {}", snippet(&body)),
            }),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let path = self.object_path(key)?;
        let (status, body) = self.request("HEAD", &path, &[], b"", &[], key)?;
        match status {
            200..=299 => Ok(true),
            404 => Ok(false),
            _ => Err(BlobError::Backend {
                key: key.to_string(),
                message: format!("HEAD status {status}: {}", snippet(&body)),
            }),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.object_path(key)?;
        let (status, body) = self.request("DELETE", &path, &[], b"", &[], key)?;
        if !(200..300).contains(&status) && status != 404 {
            return Err(BlobError::Backend {
                key: key.to_string(),
                message: format!("DELETE status {status}: {}", snippet(&body)),
            });
        }
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let full_prefix = self.full_key(prefix);
        let strip = if self.cfg.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.cfg.prefix.trim_end_matches('/'))
        };
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), full_prefix.clone()),
            ];
            if let Some(t) = &token {
                query.push(("continuation-token".to_string(), t.clone()));
            }
            let path = format!("/{}", uri_encode(&self.cfg.bucket, false));
            let (status, body) = self.request("GET", &path, &query, b"", &[], prefix)?;
            if !(200..300).contains(&status) {
                return Err(BlobError::Backend {
                    key: prefix.to_string(),
                    message: format!("LIST status {status}: {}", snippet(&body)),
                });
            }
            let xml = String::from_utf8_lossy(&body);
            for key in extract_tags(&xml, "Key") {
                let k = xml_unescape(&key);
                out.push(k.strip_prefix(&strip).unwrap_or(&k).to_string());
            }
            let truncated = extract_tags(&xml, "IsTruncated")
                .first()
                .is_some_and(|v| v == "true");
            if truncated {
                token = extract_tags(&xml, "NextContinuationToken")
                    .into_iter()
                    .next();
                if token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        out.sort();
        Ok(out)
    }

    fn list_bounded(&self, prefix: &str, maximum: usize) -> Result<BlobListPage> {
        validate_list_maximum(prefix, maximum)?;
        let full_prefix = self.full_key(prefix);
        let strip = if self.cfg.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.cfg.prefix.trim_end_matches('/'))
        };
        let query = vec![
            ("list-type".to_string(), "2".to_string()),
            ("prefix".to_string(), full_prefix),
            ("max-keys".to_string(), maximum.to_string()),
        ];
        let path = format!("/{}", uri_encode(&self.cfg.bucket, false));
        let maximum_bytes = maximum
            .checked_mul(LIST_RESPONSE_BYTES_PER_KEY)
            .and_then(|bytes| bytes.checked_add(LIST_RESPONSE_FIXED_BYTES))
            .ok_or_else(|| BlobError::Backend {
                key: prefix.to_string(),
                message: "bounded LIST response budget overflow".into(),
            })?;
        let (status, body) = self.request_with_bounds(
            RequestParts {
                method: "GET",
                path: &path,
                query: &query,
                body: b"",
                extra_headers: &[],
                key_for_errors: prefix,
            },
            Some(ReadBounds {
                maximum: maximum_bytes,
                deadline: Instant::now() + Duration::from_secs(60),
            }),
        )?;
        if !(200..300).contains(&status) {
            return Err(BlobError::Backend {
                key: prefix.to_string(),
                message: format!("LIST status {status}: {}", snippet(&body)),
            });
        }
        let xml = std::str::from_utf8(&body).map_err(|error| BlobError::Backend {
            key: prefix.to_string(),
            message: format!("LIST response is not UTF-8: {error}"),
        })?;
        let truncated_values = extract_tags(xml, "IsTruncated");
        let is_truncated = match truncated_values.as_slice() {
            [value] if value == "true" => true,
            [value] if value == "false" => false,
            _ => {
                return Err(BlobError::Backend {
                    key: prefix.to_string(),
                    message: "LIST response has no unique closed IsTruncated value".into(),
                });
            }
        };
        let mut keys = extract_tags(xml, "Key")
            .into_iter()
            .map(|key| {
                let key = xml_unescape(&key);
                key.strip_prefix(&strip).unwrap_or(&key).to_string()
            })
            .collect::<Vec<_>>();
        if keys.len() > maximum {
            return Err(BlobError::Backend {
                key: prefix.to_string(),
                message: "LIST response exceeded max-keys".into(),
            });
        }
        keys.sort();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BlobError::Backend {
                key: prefix.to_string(),
                message: "LIST response repeated an object key".into(),
            });
        }
        validate_list_result(prefix, &keys)?;
        Ok(BlobListPage { keys, is_truncated })
    }
}

fn snippet(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    s.chars().take(300).collect()
}

// ---------------------------------------------------------------------------
// SigV4 core (kept dependency-free and unit-tested against the AWS vector)
// ---------------------------------------------------------------------------

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// RFC3986 unreserved characters; `keep_slash` for canonical URIs.
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

#[allow(clippy::too_many_arguments)]
pub fn sign_v4(
    method: &str,
    canonical_path: &str,
    query: &[(String, String)],
    headers: &[(String, String)], // lowercase names, trimmed values
    payload_hash: &str,
    amz_date: &str,   // 20150830T123600Z
    date_stamp: &str, // 20150830
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
) -> String {
    let mut sorted = headers.to_vec();
    sorted.sort();
    let canonical_headers: String = sorted.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = sorted
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{canonical_path}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_query(query)
    );
    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

/// Format a unix timestamp as (`YYYYMMDD'T'HHMMSS'Z'`, `YYYYMMDD`).
pub fn amz_timestamp(unix_secs: i64) -> (String, String) {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    (
        format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Minimal XML tag extraction for ListObjectsV2 responses. Our keys never
/// contain nested XML; values are unescaped afterwards.
fn extract_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        if let Some(end) = after.find(&close) {
            out.push(after[..end].to_string());
            rest = &after[end + close.len()..];
        } else {
            break;
        }
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;

    use super::*;

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        request
    }

    fn local_store(
        respond: impl FnOnce(TcpStream) + Send + 'static,
    ) -> (AwsS3BlobStore, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            respond(stream);
        });
        let store = AwsS3BlobStore::new(AwsS3Config {
            endpoint,
            bucket: "test".into(),
            region: "us-east-1".into(),
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            session_token: None,
            prefix: String::new(),
        })
        .unwrap();
        (store, server)
    }

    fn assert_no_connection(listener: TcpListener, waited: Duration) {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + waited;
        loop {
            match listener.accept() {
                Ok(_) => panic!("redirect target received a credential-bearing request"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("redirect target accept failed: {error}"),
            }
        }
    }

    #[test]
    fn shared_blob_store_contract_when_s3_is_configured() {
        let Ok(endpoint) = std::env::var("CATS_AWS_S3_TEST_ENDPOINT") else {
            eprintln!("skipped: CATS_AWS_S3_TEST_ENDPOINT not set");
            return;
        };
        let bucket =
            std::env::var("CATS_AWS_S3_TEST_BUCKET").unwrap_or_else(|_| "cats-test".into());
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID");
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY");
        let prefix = format!("contract-{}", std::process::id());
        cats_test_support::blob_store_contract(|| {
            Arc::new(
                AwsS3BlobStore::new(AwsS3Config {
                    endpoint,
                    bucket,
                    region: "us-east-1".into(),
                    access_key,
                    secret_key,
                    session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
                    prefix,
                })
                .unwrap(),
            )
        });
    }

    /// A dead endpoint is the cheapest stand-in for a transient failure: every
    /// attempt fails to connect. The call must exhaust the retry budget rather
    /// than give up on the first error, because a single object-store failure
    /// reaches the Guest as an I/O error and takes its filesystem read-only.
    #[test]
    fn a_failing_endpoint_is_retried_before_the_error_is_returned() {
        let store = AwsS3BlobStore::new(AwsS3Config {
            // Port 1 refuses immediately, so the elapsed time is the backoff.
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "test".into(),
            region: "us-east-1".into(),
            access_key: "unused".into(),
            secret_key: "unused".into(),
            session_token: None,
            prefix: String::new(),
        })
        .unwrap();

        let started = Instant::now();
        assert!(matches!(
            store.get("some-key"),
            Err(BlobError::Backend { .. })
        ));
        let elapsed = started.elapsed();

        // 100 ms + 400 ms + 1600 ms + 3000 ms of sleeps between five attempts.
        let minimum = Duration::from_millis(RETRY_INITIAL_DELAY_MS * 5);
        assert!(
            elapsed >= minimum,
            "expected the retry budget to be spent, got {elapsed:?} (< {minimum:?})"
        );
    }

    #[test]
    fn malformed_object_key_fails_before_network_io() {
        let store = AwsS3BlobStore::new(AwsS3Config {
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "test".into(),
            region: "us-east-1".into(),
            access_key: "unused".into(),
            secret_key: "unused".into(),
            session_token: None,
            prefix: String::new(),
        })
        .unwrap();
        assert!(matches!(
            store.exists("../escape"),
            Err(BlobError::InvalidKey { .. })
        ));
    }

    #[test]
    fn pod_identity_credentials_accept_only_the_eks_link_local_endpoint() {
        validate_container_credential_endpoint("http://169.254.170.23/v1/credentials").unwrap();
        for endpoint in [
            "https://169.254.170.23/v1/credentials",
            "http://127.0.0.1/v1/credentials",
            "http://169.254.170.23.evil.example/v1/credentials",
            "http://169.254.170.23/v1/credentials?redirect=evil",
            "http://169.254.170.23/latest/meta-data",
        ] {
            assert!(validate_container_credential_endpoint(endpoint).is_err());
        }
    }

    #[test]
    fn signed_s3_request_never_follows_a_cross_origin_redirect() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let location = format!("http://{}/stolen", target.local_addr().unwrap());
        let (store, redirect) = local_store(move |mut stream| {
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        *store.credentials.lock().unwrap() = CredentialState::Static(SigningCredentials {
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            session_token: Some("session-secret".into()),
        });

        assert!(matches!(
            store.get("images/test/manifest.json"),
            Err(BlobError::Backend { .. })
        ));
        redirect.join().unwrap();
        assert_no_connection(target, Duration::from_millis(100));
    }

    #[test]
    fn signed_s3_request_treats_same_origin_redirect_as_a_terminal_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let location = format!("{endpoint}/redirected");
        let (request_tx, request_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            request_tx.send(read_request(&mut stream)).unwrap();
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            assert_no_connection(listener, Duration::from_millis(100));
        });
        let store = AwsS3BlobStore::new(AwsS3Config {
            endpoint,
            bucket: "test".into(),
            region: "us-east-1".into(),
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            session_token: Some("session-secret".into()),
            prefix: String::new(),
        })
        .unwrap();

        assert!(matches!(
            store.get("images/test/manifest.json"),
            Err(BlobError::Backend { .. })
        ));
        let request = String::from_utf8(request_rx.recv().unwrap()).unwrap();
        assert!(request.to_ascii_lowercase().contains("authorization:"));
        assert!(request.contains("x-amz-security-token: session-secret"));
        server.join().unwrap();
    }

    #[test]
    fn credential_client_rejects_redirects_and_caps_response_bodies() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_url = format!("http://{}/stolen", target.local_addr().unwrap());
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_url = format!("http://{}", redirect.local_addr().unwrap());
        let redirect_server = std::thread::spawn(move || {
            let (mut stream, _) = redirect.accept().unwrap();
            let _ = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let client = credential_client(Duration::from_secs(1)).unwrap();
        let response = client
            .get(redirect_url)
            .header("authorization", "credential-secret")
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 302);
        redirect_server.join().unwrap();
        assert_no_connection(target, Duration::from_millis(100));

        let oversized = TcpListener::bind("127.0.0.1:0").unwrap();
        let oversized_url = format!("http://{}", oversized.local_addr().unwrap());
        let oversized_server = std::thread::spawn(move || {
            let (mut stream, _) = oversized.accept().unwrap();
            let _ = read_request(&mut stream);
            let body = vec![b'x'; CREDENTIAL_RESPONSE_MAX_BYTES + 1];
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        let response = client.get(oversized_url).send().unwrap();
        assert!(matches!(
            read_credential_text(response, "test credential response"),
            Err(BlobError::Backend { .. })
        ));
        oversized_server.join().unwrap();
    }

    #[test]
    fn bounded_get_deadline_includes_waiting_for_a_credential_refresh() {
        let store = AwsS3BlobStore::new(AwsS3Config {
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "test".into(),
            region: "us-east-1".into(),
            access_key: "unused".into(),
            secret_key: "unused".into(),
            session_token: None,
            prefix: String::new(),
        })
        .unwrap();
        let _credential_refresh = store.credentials.lock().unwrap();
        let started = Instant::now();
        assert!(matches!(
            store.get_bounded_until(
                "images/test/manifest.json",
                4,
                Instant::now() + Duration::from_millis(30),
            ),
            Err(BlobError::Backend { .. })
        ));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn bounded_get_rejects_declared_and_streamed_oversize_bodies() {
        let (declared, server) = local_store(|mut stream| {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
                )
                .unwrap();
        });
        assert!(matches!(
            declared.get_bounded("images/test/manifest.json", 4),
            Err(BlobError::TooLarge {
                maximum: 4,
                observed_at_least: 5,
                ..
            })
        ));
        server.join().unwrap();

        let (streamed, server) = local_store(|mut stream| {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n12345\r\n0\r\n\r\n",
                )
                .unwrap();
        });
        assert!(matches!(
            streamed.get_bounded("images/test/manifest.json", 4),
            Err(BlobError::TooLarge {
                maximum: 4,
                observed_at_least: 5,
                ..
            })
        ));
        server.join().unwrap();
    }

    #[test]
    fn bounded_get_keeps_oversized_error_bodies_out_of_too_large() {
        let (store, server) = local_store(|mut stream| {
            let body = vec![b'x'; ERROR_RESPONSE_MAX_BYTES + 1];
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        assert!(matches!(
            store.get_bounded("images/test/manifest.json", 4),
            Err(BlobError::NotFound(_))
        ));
        server.join().unwrap();
    }

    #[test]
    fn bounded_list_uses_one_max_keys_page_and_validates_exact_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (request_tx, request_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            request_tx.send(read_request(&mut stream)).unwrap();
            let body = b"<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>env/volumes/vol_a/data/a</Key></Contents><Contents><Key>env/volumes/vol_a/maps/b</Key></Contents><NextContinuationToken>opaque</NextContinuationToken></ListBucketResult>";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let store = AwsS3BlobStore::new(AwsS3Config {
            endpoint,
            bucket: "test".into(),
            region: "us-east-1".into(),
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            session_token: None,
            prefix: "env".into(),
        })
        .unwrap();

        assert_eq!(
            store.list_bounded("volumes/vol_a/", 2).unwrap(),
            BlobListPage {
                keys: vec!["volumes/vol_a/data/a".into(), "volumes/vol_a/maps/b".into(),],
                is_truncated: true,
            }
        );
        let request = String::from_utf8(request_rx.recv().unwrap()).unwrap();
        assert!(request.starts_with(
            "GET /test?list-type=2&max-keys=2&prefix=env%2Fvolumes%2Fvol_a%2F HTTP/1.1"
        ));
        server.join().unwrap();
    }

    #[test]
    fn bounded_list_fails_closed_on_a_key_outside_the_requested_prefix() {
        let (store, server) = local_store(|mut stream| {
            let body = b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>volumes/vol_ab/data/not-a</Key></Contents></ListBucketResult>";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        assert!(matches!(
            store.list_bounded("volumes/vol_a/", 10),
            Err(BlobError::Backend { .. })
        ));
        server.join().unwrap();
    }

    #[test]
    fn bounded_get_transport_obeys_the_absolute_deadline() {
        let (store, server) = local_store(|mut stream| {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n",
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(250));
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        let started = Instant::now();
        assert!(matches!(
            store.get_bounded_until(
                "images/test/manifest.json",
                4,
                Instant::now() + Duration::from_millis(50)
            ),
            Err(BlobError::Backend { .. })
        ));
        assert!(started.elapsed() < Duration::from_millis(200));
        server.join().unwrap();
    }

    /// AWS SigV4 test-suite vector `get-vanilla`.
    #[test]
    fn sigv4_matches_aws_test_vector() {
        let auth = sign_v4(
            "GET",
            "/",
            &[],
            &[
                ("host".to_string(), "example.amazonaws.com".to_string()),
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
            ],
            // get-vanilla uses the empty-body hash.
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "20150830T123600Z",
            "20150830",
            "us-east-1",
            "service",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn timestamp_formatting() {
        // 2026-07-21T00:00:00Z
        let (ts, date) = amz_timestamp(1_784_592_000);
        assert_eq!(date, "20260721");
        assert!(ts.starts_with("20260721T"));
        let (ts2, _) = amz_timestamp(0);
        assert_eq!(ts2, "19700101T000000Z");
    }

    #[test]
    fn uri_encoding_rules() {
        assert_eq!(
            uri_encode("volumes/v1/data/a b", false),
            "volumes/v1/data/a%20b"
        );
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("A-Z_a.z~0", true), "A-Z_a.z~0");
    }

    #[test]
    fn xml_tag_extraction() {
        let xml = "<r><Key>a/b</Key><Key>c&amp;d</Key><IsTruncated>false</IsTruncated></r>";
        assert_eq!(extract_tags(xml, "Key"), vec!["a/b", "c&amp;d"]);
        assert_eq!(xml_unescape("c&amp;d"), "c&d");
    }
}

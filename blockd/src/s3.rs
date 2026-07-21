//! S3-compatible BlobStore over HTTP with AWS Signature V4 (path-style).
//!
//! Works against AWS S3, MinIO and other S3-compatible endpoints. This is
//! the production durable store (ADR-0003); `FileBlobStore` mirrors its
//! semantics for dev/tests. Live integration tests run only when
//! `CATS_S3_TEST_ENDPOINT` is set (see `blockd/tests/`).
//!
//! Immutability note: our object keys are content-stable (txn-derived), so a
//! repeated PUT always carries identical bytes; we deliberately do not spend
//! an extra HEAD per PUT to re-check.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::blobstore::{BlobError, BlobStore, Result};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct S3Config {
    /// Endpoint origin, e.g. `https://s3.us-east-1.amazonaws.com` or
    /// `http://127.0.0.1:9000` (MinIO).
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// Key prefix inside the bucket (tenant/env isolation).
    pub prefix: String,
}

pub struct S3BlobStore {
    cfg: S3Config,
    client: reqwest::blocking::Client,
}

impl S3BlobStore {
    pub fn new(cfg: S3Config) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| BlobError::Backend {
                key: "<client>".into(),
                message: e.to_string(),
            })?;
        Ok(Self { cfg, client })
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

    /// Execute a signed request. `path` must start with `/`.
    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: &[u8],
        key_for_errors: &str,
    ) -> Result<(u16, Vec<u8>)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let (amz_date, date_stamp) = amz_timestamp(now as i64);
        let payload_hash = hex::encode(Sha256::digest(body));
        let host = self.host();

        let headers = vec![
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
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
            &self.cfg.access_key,
            &self.cfg.secret_key,
        );

        let url = self.url(path, query);
        let m = reqwest::Method::from_bytes(method.as_bytes()).expect("valid method");
        let mut req = self.client.request(m, &url).body(body.to_vec());
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
        let bytes = resp
            .bytes()
            .map_err(|e| BlobError::Backend {
                key: key_for_errors.into(),
                message: e.to_string(),
            })?
            .to_vec();
        Ok((status, bytes))
    }

    fn object_path(&self, key: &str) -> String {
        format!(
            "/{}/{}",
            uri_encode(&self.cfg.bucket, false),
            uri_encode(&self.full_key(key), false)
        )
    }
}

impl BlobStore for S3BlobStore {
    fn put_immutable(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.object_path(key);
        let (status, body) = self.request("PUT", &path, &[], data, key)?;
        if !(200..300).contains(&status) {
            return Err(BlobError::Backend {
                key: key.to_string(),
                message: format!("PUT status {status}: {}", snippet(&body)),
            });
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.object_path(key);
        let (status, body) = self.request("GET", &path, &[], b"", key)?;
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
        let path = self.object_path(key);
        let (status, body) = self.request("HEAD", &path, &[], b"", key)?;
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
        let path = self.object_path(key);
        let (status, body) = self.request("DELETE", &path, &[], b"", key)?;
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
            let (status, body) = self.request("GET", &path, &query, b"", prefix)?;
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
    use super::*;

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

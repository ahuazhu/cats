use std::time::Duration;

use reqwest::header::{CONTENT_ENCODING, CONTENT_LENGTH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseBodyBounds {
    pub max_headers: usize,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub body_deadline: Duration,
}

impl Default for ResponseBodyBounds {
    fn default() -> Self {
        Self {
            max_headers: 64,
            max_header_bytes: 16 * 1024,
            max_body_bytes: 8 * 1024,
            body_deadline: Duration::from_secs(2),
        }
    }
}

impl ResponseBodyBounds {
    fn validate(self) -> Result<Self, ResponseReadError> {
        if self.max_headers == 0
            || self.max_header_bytes == 0
            || self.max_body_bytes == 0
            || self.body_deadline.is_zero()
        {
            return Err(ResponseReadError::InvalidBounds);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseReadError {
    InvalidBounds,
    ClientConfiguration,
    TooManyHeaders,
    HeadersTooLarge,
    CompressedBody,
    MultipleContentLengths,
    InvalidContentLength,
    BodyTooLarge,
    BodyDeadline,
    Transport,
}

impl std::fmt::Display for ResponseReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBounds => formatter.write_str("invalid Route response bounds"),
            Self::ClientConfiguration => {
                formatter.write_str("could not configure strict Route HTTPS client")
            }
            Self::TooManyHeaders => formatter.write_str("Route response has too many headers"),
            Self::HeadersTooLarge => formatter.write_str("Route response headers are too large"),
            Self::CompressedBody => {
                formatter.write_str("Route response uses forbidden Content-Encoding")
            }
            Self::MultipleContentLengths => {
                formatter.write_str("Route response has multiple Content-Length values")
            }
            Self::InvalidContentLength => {
                formatter.write_str("Route response has an invalid Content-Length")
            }
            Self::BodyTooLarge => formatter.write_str("Route response body is too large"),
            Self::BodyDeadline => formatter.write_str("Route response body deadline elapsed"),
            Self::Transport => formatter.write_str("Route response body transport failed"),
        }
    }
}

impl std::error::Error for ResponseReadError {}

/// Build a strict HTTPS client for non-mTLS bounded-response consumers.
///
/// The production Route resolver uses [`super::ControlRouteResolver`] so its
/// installed client certificate is inseparable from TLS construction. This
/// lower-level helper still refuses plaintext URLs, environment proxies and
/// redirects and applies both connect and whole-request deadlines.
pub fn strict_https_client(
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::Client, ResponseReadError> {
    build_client(connect_timeout, request_timeout, true)
}

fn build_client(
    connect_timeout: Duration,
    request_timeout: Duration,
    https_only: bool,
) -> Result<reqwest::Client, ResponseReadError> {
    if connect_timeout.is_zero() || request_timeout.is_zero() {
        return Err(ResponseReadError::InvalidBounds);
    }
    reqwest::Client::builder()
        .https_only(https_only)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
        .map_err(|_| ResponseReadError::ClientConfiguration)
}

/// Read a response body incrementally under exact header, byte and time caps.
///
/// The function never calls `Response::bytes` or trusts `Content-Length` as a
/// substitute for counting received chunks. Compression is rejected so the
/// cap is over the exact authenticated response octets.
pub async fn read_bounded_response_body(
    mut response: reqwest::Response,
    bounds: ResponseBodyBounds,
) -> Result<Vec<u8>, ResponseReadError> {
    let bounds = bounds.validate()?;
    if response.headers().len() > bounds.max_headers {
        return Err(ResponseReadError::TooManyHeaders);
    }
    let mut header_bytes = 0_usize;
    for (name, value) in response.headers() {
        header_bytes = header_bytes
            .checked_add(name.as_str().len())
            .and_then(|bytes| bytes.checked_add(value.as_bytes().len()))
            .ok_or(ResponseReadError::HeadersTooLarge)?;
        if header_bytes > bounds.max_header_bytes {
            return Err(ResponseReadError::HeadersTooLarge);
        }
    }
    if response.headers().contains_key(CONTENT_ENCODING) {
        return Err(ResponseReadError::CompressedBody);
    }

    let mut lengths = response.headers().get_all(CONTENT_LENGTH).iter();
    let declared_length = lengths
        .next()
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(ResponseReadError::InvalidContentLength)
        })
        .transpose()?;
    if lengths.next().is_some() {
        return Err(ResponseReadError::MultipleContentLengths);
    }
    if declared_length.is_some_and(|bytes| bytes > bounds.max_body_bytes) {
        return Err(ResponseReadError::BodyTooLarge);
    }

    let read = async {
        let mut body = Vec::with_capacity(declared_length.unwrap_or(0));
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ResponseReadError::Transport)?
        {
            let next_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or(ResponseReadError::BodyTooLarge)?;
            if next_len > bounds.max_body_bytes {
                return Err(ResponseReadError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };
    tokio::time::timeout(bounds.body_deadline, read)
        .await
        .map_err(|_| ResponseReadError::BodyDeadline)?
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn spawn_raw_server(
        response: &'static [u8],
        accepted: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(response).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn client_never_follows_a_loopback_redirect() {
        let destination_calls = Arc::new(AtomicUsize::new(0));
        let (destination, destination_task) = spawn_raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            destination_calls.clone(),
        )
        .await;
        let redirect = Box::leak(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {destination}/authority\r\nContent-Length: 0\r\n\r\n"
            )
            .into_bytes()
            .into_boxed_slice(),
        );
        let redirect_calls = Arc::new(AtomicUsize::new(0));
        let (origin, origin_task) = spawn_raw_server(redirect, redirect_calls.clone()).await;
        let client = build_client(Duration::from_secs(1), Duration::from_secs(1), false).unwrap();
        let response = client
            .get(format!("{origin}/resolve"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(redirect_calls.load(Ordering::SeqCst), 1);
        assert_eq!(destination_calls.load(Ordering::SeqCst), 0);
        origin_task.abort();
        destination_task.abort();
    }

    #[tokio::test]
    async fn production_client_rejects_plaintext_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = strict_https_client(Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let error = client
            .get(format!("http://{address}/resolve"))
            .send()
            .await
            .unwrap_err();
        assert!(error.is_builder());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}

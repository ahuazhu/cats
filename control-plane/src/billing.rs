//! Stripe-hosted prepaid top-ups.
//!
//! Checkout redirects are convenience only. Credits are issued exclusively
//! after a signed webhook has been validated and atomically applied by the
//! credit store.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use cats_api::error::ApiError;
use cats_metering::CheckoutIntent;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct StripeConfig {
    pub secret_key: String,
    pub webhook_secret: String,
    pub topup_prices: BTreeMap<i64, String>,
    pub checkout_success_url: String,
    pub checkout_cancel_url: String,
    pub livemode: bool,
    pub api_base_url: String,
}

#[derive(Clone)]
pub struct StripeClient {
    config: StripeConfig,
    http: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub livemode: bool,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

pub struct VerifiedStripeEvent {
    pub event: StripeEvent,
    pub payload_sha256: String,
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutResponse {
    id: String,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StripeErrorEnvelope {
    error: StripeErrorDetail,
}

#[derive(Debug, Deserialize)]
struct StripeErrorDetail {
    message: String,
}

impl StripeClient {
    pub fn new(config: StripeConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !config.secret_key.trim().is_empty(),
            "Stripe secret key must not be empty"
        );
        anyhow::ensure!(
            config.webhook_secret.starts_with("whsec_"),
            "Stripe webhook secret must start with whsec_"
        );
        anyhow::ensure!(
            !config.topup_prices.is_empty()
                && config
                    .topup_prices
                    .iter()
                    .all(|(amount, price)| *amount > 0 && price.starts_with("price_")),
            "Stripe top-up prices must map positive cents to price IDs"
        );
        anyhow::ensure!(
            config.checkout_success_url.starts_with("https://")
                && config.checkout_cancel_url.starts_with("https://"),
            "Stripe Checkout return URLs must use HTTPS"
        );
        anyhow::ensure!(
            config.api_base_url.starts_with("https://")
                || config.api_base_url.starts_with("http://127.0.0.1:")
                || config.api_base_url.starts_with("http://localhost:"),
            "Stripe API base URL must use HTTPS"
        );
        Ok(Self {
            config,
            http: reqwest::Client::new(),
        })
    }

    pub fn topup_options_cents(&self) -> Vec<i64> {
        self.config.topup_prices.keys().copied().collect()
    }

    pub fn livemode(&self) -> bool {
        self.config.livemode
    }

    pub async fn create_checkout_session(
        &self,
        intent: &CheckoutIntent,
        stripe_customer_id: Option<&str>,
    ) -> Result<CheckoutSession, ApiError> {
        let price_id = self
            .config
            .topup_prices
            .get(&intent.amount_cents)
            .ok_or_else(|| ApiError::invalid("unsupported top-up amount"))?;
        let mut form = vec![
            ("mode".to_string(), "payment".to_string()),
            ("line_items[0][price]".to_string(), price_id.clone()),
            ("line_items[0][quantity]".to_string(), "1".to_string()),
            (
                "success_url".to_string(),
                self.config.checkout_success_url.clone(),
            ),
            (
                "cancel_url".to_string(),
                self.config.checkout_cancel_url.clone(),
            ),
            ("client_reference_id".to_string(), intent.intent_id.clone()),
            (
                "metadata[checkout_intent_id]".to_string(),
                intent.intent_id.clone(),
            ),
            (
                "metadata[billing_account_id]".to_string(),
                intent.billing_account_id.clone(),
            ),
            (
                "metadata[project_id]".to_string(),
                intent.project_id.clone(),
            ),
            (
                "metadata[topup_cents]".to_string(),
                intent.amount_cents.to_string(),
            ),
            (
                "payment_intent_data[metadata][checkout_intent_id]".to_string(),
                intent.intent_id.clone(),
            ),
            (
                "payment_intent_data[metadata][billing_account_id]".to_string(),
                intent.billing_account_id.clone(),
            ),
        ];
        if let Some(customer_id) = stripe_customer_id {
            form.push(("customer".to_string(), customer_id.to_string()));
        } else {
            form.push(("customer_creation".to_string(), "always".to_string()));
        }
        let response = self
            .http
            .post(format!(
                "{}/v1/checkout/sessions",
                self.config.api_base_url.trim_end_matches('/')
            ))
            .basic_auth(&self.config.secret_key, Some(""))
            .header("Idempotency-Key", &intent.intent_id)
            .form(&form)
            .send()
            .await
            .map_err(|error| {
                ApiError::unavailable(format!("Stripe Checkout is unreachable: {error}"))
            })?;
        let status = response.status();
        let body = response.bytes().await.map_err(|error| {
            ApiError::unavailable(format!("could not read Stripe response: {error}"))
        })?;
        if !status.is_success() {
            let detail = serde_json::from_slice::<StripeErrorEnvelope>(&body)
                .map(|value| value.error.message)
                .unwrap_or_else(|_| format!("HTTP {status}"));
            return Err(ApiError::unavailable(format!(
                "Stripe could not create Checkout: {detail}"
            )));
        }
        let session: StripeCheckoutResponse = serde_json::from_slice(&body)
            .map_err(|error| ApiError::internal(format!("invalid Stripe response: {error}")))?;
        let url = session
            .url
            .filter(|value| value.starts_with("https://checkout.stripe.com/"))
            .ok_or_else(|| ApiError::internal("Stripe returned an invalid Checkout URL"))?;
        Ok(CheckoutSession {
            id: session.id,
            url,
        })
    }

    pub fn verify_webhook(
        &self,
        signature_header: &str,
        body: &[u8],
    ) -> Result<VerifiedStripeEvent, ApiError> {
        let (timestamp, signatures) = parse_signature_header(signature_header)?;
        let now = unix_seconds()?;
        if timestamp < now.saturating_sub(300) || timestamp > now.saturating_add(300) {
            return Err(ApiError::invalid(
                "Stripe webhook timestamp is outside the five-minute tolerance",
            ));
        }
        let mut signed = timestamp.to_string().into_bytes();
        signed.push(b'.');
        signed.extend_from_slice(body);
        let valid = signatures.iter().any(|signature| {
            let Ok(signature) = hex::decode(signature) else {
                return false;
            };
            let Ok(mut mac) = HmacSha256::new_from_slice(self.config.webhook_secret.as_bytes())
            else {
                return false;
            };
            mac.update(&signed);
            mac.verify_slice(&signature).is_ok()
        });
        if !valid {
            return Err(ApiError::invalid("invalid Stripe webhook signature"));
        }
        let event: StripeEvent = serde_json::from_slice(body)
            .map_err(|error| ApiError::invalid(format!("invalid Stripe event JSON: {error}")))?;
        if event.id.is_empty() || event.event_type.is_empty() {
            return Err(ApiError::invalid("Stripe event is missing its id or type"));
        }
        if event.livemode != self.config.livemode {
            return Err(ApiError::invalid(
                "Stripe event mode does not match this deployment",
            ));
        }
        Ok(VerifiedStripeEvent {
            event,
            payload_sha256: hex::encode(Sha256::digest(body)),
        })
    }
}

fn parse_signature_header(value: &str) -> Result<(i64, Vec<&str>), ApiError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in value.split(',') {
        if let Some(value) = part.strip_prefix("t=") {
            timestamp = Some(
                value
                    .parse::<i64>()
                    .map_err(|_| ApiError::invalid("invalid Stripe signature timestamp"))?,
            );
        } else if let Some(value) = part.strip_prefix("v1=") {
            signatures.push(value);
        }
    }
    let timestamp =
        timestamp.ok_or_else(|| ApiError::invalid("Stripe signature timestamp is missing"))?;
    if signatures.is_empty() {
        return Err(ApiError::invalid("Stripe v1 signature is missing"));
    }
    Ok((timestamp, signatures))
}

fn unix_seconds() -> Result<i64, ApiError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal("system time is before Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ApiError::internal("system time is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> StripeClient {
        StripeClient::new(StripeConfig {
            secret_key: "sk_test_example".into(),
            webhook_secret: "whsec_test_secret".into(),
            topup_prices: BTreeMap::from([(1_000, "price_test".into())]),
            checkout_success_url: "https://cats.run/user/?topup=success".into(),
            checkout_cancel_url: "https://cats.run/user/?topup=cancelled".into(),
            livemode: false,
            api_base_url: "https://api.stripe.com".into(),
        })
        .unwrap()
    }

    #[test]
    fn signature_header_requires_timestamp_and_v1() {
        assert!(parse_signature_header("t=10,v1=abcd").is_ok());
        assert!(parse_signature_header("t=10,v0=abcd").is_err());
        assert!(parse_signature_header("v1=abcd").is_err());
    }

    #[test]
    fn webhook_verification_uses_raw_body_mode_and_timestamp() {
        let client = test_client();
        let timestamp = unix_seconds().unwrap();
        let body = br#"{"id":"evt_test","type":"checkout.session.completed","livemode":false,"data":{"object":{}}}"#;
        let signed = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let mut mac = HmacSha256::new_from_slice(b"whsec_test_secret").unwrap();
        mac.update(signed.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let verified = client
            .verify_webhook(&format!("t={timestamp},v1={signature}"), body)
            .unwrap();
        assert_eq!(verified.event.id, "evt_test");
        assert_eq!(verified.event.event_type, "checkout.session.completed");
        assert!(!verified.event.livemode);
        assert_eq!(verified.payload_sha256, hex::encode(Sha256::digest(body)));
    }
}

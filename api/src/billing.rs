//! Prepaid billing wire types.
//!
//! Money is represented as signed decimal nanodollar strings so clients never
//! lose precision and a temporarily negative available balance remains
//! explicit.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingBalance {
    pub billing_account_id: String,
    pub project_id: String,
    pub currency: String,
    pub status: String,
    pub credit_nanos: String,
    pub provisional_usage_nanos: String,
    pub available_credit_nanos: String,
    pub signup_credit_nanos: String,
    pub stripe_enabled: bool,
    pub topup_options_cents: Vec<i64>,
    pub usage_visible_through_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCheckoutRequest {
    pub amount_cents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCheckoutResponse {
    pub checkout_intent_id: String,
    pub stripe_session_id: String,
    pub url: String,
}

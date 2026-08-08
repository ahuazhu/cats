use super::*;

struct BillingProjection {
    signup_credit_nanos: i128,
    credit_nanos: i128,
    usage_nanos: u128,
    available_nanos: i128,
    latest_interval_end_unix_ms: Option<i64>,
    stripe_customer_id: Option<String>,
}

fn unix_millis() -> Result<i64, Failure> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::internal("system time is before Unix epoch"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| ApiError::internal("system time is out of range").into())
}

async fn billing_projection(state: &AppState, workspace: &str) -> ApiResult<BillingProjection> {
    let now_ms = unix_millis()?;
    let workspace_id = workspace.to_string();
    let ledger = state
        .store
        .execute(move |store| store.billing_ledger_for_workspace(&workspace_id))
        .await?;
    let rate_card = RateCard::sprites_compute_v1();
    let credit = state
        .credits
        .ensure_account(
            &ledger.billing_account_id,
            &ledger.account_id,
            "USD",
            ledger.signup_credit_nanos,
            now_ms,
        )
        .await
        .map_err(metering_failure)?;
    // Every Workspace in an Account bills to that Account, so the balance is
    // read per Billing Account and never filtered by Workspace here.
    // Totals only. The window is unbounded below, so asking for per-interval
    // detail here made the cost of every paid request grow with the Account's
    // whole billing history; nothing below reads anything but the totals.
    let usage = state
        .usage
        .query_totals(&MeterUsageQuery {
            billing_account_id: ledger.billing_account_id,
            workspace_id: None,
            attributed_cat_id: None,
            interval_start_unix_ms: 0,
            interval_end_unix_ms: now_ms.max(1),
        })
        .await
        .map_err(metering_failure)?;
    let mut usage_nanos = 0_u128;
    for aggregate in usage.totals {
        if let Some(amount) = rate_card
            .rate_quantity(aggregate.metric, aggregate.quantity)
            .map_err(metering_failure)?
        {
            usage_nanos = usage_nanos
                .checked_add(amount)
                .ok_or_else(|| ApiError::internal("rated balance overflow"))?;
        }
    }
    let usage_signed = i128::try_from(usage_nanos)
        .map_err(|_| ApiError::internal("rated balance exceeds signed money range"))?;
    let available_nanos = credit
        .credit_nanos
        .checked_sub(usage_signed)
        .ok_or_else(|| ApiError::internal("available balance overflow"))?;
    Ok(BillingProjection {
        signup_credit_nanos: ledger.signup_credit_nanos,
        credit_nanos: credit.credit_nanos,
        usage_nanos,
        available_nanos,
        latest_interval_end_unix_ms: usage.latest_interval_end_unix_ms,
        stripe_customer_id: credit.stripe_customer_id,
    })
}

pub(super) async fn require_funded(state: &AppState, workspace: &str) -> ApiResult<()> {
    if !state.cfg.billing_enforcement_enabled {
        return Ok(());
    }
    let projection = billing_projection(state, workspace).await?;
    if projection.available_nanos <= 0 {
        return Err(ApiError::payment_required(
            "prepaid balance is exhausted; add funds in Billing before starting paid work",
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn enforce_exhausted_billing_accounts(state: &AppState) -> ApiResult<()> {
    let active_cats = state
        .store
        .execute(|store| {
            store
                .list_all_cats()?
                .into_iter()
                .filter(|cat| cat.desired_state == DesiredState::Running)
                .map(|cat| {
                    let account_id = store.workspace_by_id(&cat.workspace_id)?.account_id;
                    Ok((cat, account_id))
                })
                .collect::<Result<Vec<_>, ApiError>>()
        })
        .await?;
    let accounts = active_cats
        .iter()
        .map(|(cat, account_id)| (account_id.clone(), cat.workspace_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut changed = false;
    for (account_id, workspace) in accounts {
        let projection = billing_projection(state, &workspace).await?;
        if projection.available_nanos > 0 {
            continue;
        }
        for (cat, _) in active_cats
            .iter()
            .filter(|(_, cat_account_id)| cat_account_id == &account_id)
        {
            let billing_account = billing_account_id_for_workspace(state, &workspace).await?;
            let cat_id = cat.id.clone();
            match state
                .store
                .execute(move |store| {
                    store.set_desired(&cat_id, DesiredState::Cold, None, "cat.credit_exhausted")
                })
                .await
            {
                Ok(_) => {
                    changed = true;
                    tracing::warn!(
                        billing_account = %billing_account,
                        cat_id = %cat.id,
                        "prepaid balance exhausted; converging Cat to Cold"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        cat_id = %cat.id,
                        error = %error,
                        "could not apply exhausted-credit Cold state"
                    );
                }
            }
        }
    }
    if changed {
        state.notify.notify_one();
    }
    Ok(())
}

pub(super) async fn workspace_billing_balance(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let projection = billing_projection(&state, &workspace).await?;
    let stripe_enabled = state.cfg.stripe.is_some();
    let topup_options_cents = state
        .cfg
        .stripe
        .as_ref()
        .map(|stripe| stripe.topup_options_cents())
        .unwrap_or_default();
    let balance = BillingBalance {
        billing_account_id: billing_account_id_for_workspace(&state, &workspace).await?,
        workspace_id: workspace.clone(),
        currency: "USD".to_string(),
        status: if projection.available_nanos > 0 {
            "active"
        } else {
            "payment_required"
        }
        .to_string(),
        credit_nanos: projection.credit_nanos.to_string(),
        provisional_usage_nanos: projection.usage_nanos.to_string(),
        available_credit_nanos: projection.available_nanos.to_string(),
        signup_credit_nanos: projection.signup_credit_nanos.to_string(),
        stripe_enabled,
        topup_options_cents,
        usage_visible_through_unix_ms: projection.latest_interval_end_unix_ms,
    };
    let mut response = Json(balance).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(super) async fn create_billing_checkout(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateCheckoutRequest>,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let stripe = state
        .cfg
        .stripe
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("Stripe top-ups are not configured"))?;
    if !stripe.topup_options_cents().contains(&request.amount_cents) {
        return Err(ApiError::invalid("unsupported top-up amount").into());
    }
    let idempotency_key = idem_key(&headers)
        .filter(|value| !value.trim().is_empty() && value.len() <= 200)
        .ok_or_else(|| ApiError::invalid("Idempotency-Key is required for Checkout"))?;
    let query_workspace = workspace.clone();
    let scope = state
        .store
        .execute(move |store| store.workspace_scope(&query_workspace))
        .await?;
    let billing_account_id = scope.account.billing_account_id.clone();
    let projection = billing_projection(&state, &workspace).await?;
    let mut hasher = Sha256::new();
    for value in [&billing_account_id, &idempotency_key] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let intent_id = format!("checkout_{}", hex::encode(hasher.finalize()));
    let intent = state
        .credits
        .create_checkout_intent(&CheckoutIntent {
            intent_id,
            billing_account_id,
            account_id: scope.account.id,
            amount_cents: request.amount_cents,
            currency: "USD".to_string(),
            created_at_unix_ms: unix_millis()?,
            stripe_session_id: None,
            checkout_url: None,
        })
        .await
        .map_err(metering_failure)?;
    let intent = if intent.stripe_session_id.is_some() && intent.checkout_url.is_some() {
        intent
    } else {
        let session = stripe
            .create_checkout_session(&intent, projection.stripe_customer_id.as_deref())
            .await?;
        state
            .credits
            .attach_checkout_session(&intent.intent_id, &session.id, &session.url)
            .await
            .map_err(metering_failure)?
    };
    let response = CreateCheckoutResponse {
        checkout_intent_id: intent.intent_id,
        stripe_session_id: intent
            .stripe_session_id
            .ok_or_else(|| ApiError::internal("checkout session was not persisted"))?,
        url: intent
            .checkout_url
            .ok_or_else(|| ApiError::internal("checkout URL was not persisted"))?,
    };
    let mut response = Json(response).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StripeObjectId {
    Id(String),
    Object { id: String },
}

impl StripeObjectId {
    fn into_id(self) -> String {
        match self {
            Self::Id(id) | Self::Object { id } => id,
        }
    }
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutSessionEvent {
    id: String,
    amount_total: Option<i64>,
    currency: Option<String>,
    payment_status: String,
    payment_intent: Option<StripeObjectId>,
    customer: Option<StripeObjectId>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct StripeRefundEvent {
    id: String,
    amount: i64,
    currency: String,
    status: Option<String>,
    payment_intent: Option<StripeObjectId>,
}

pub(super) async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let stripe = state
        .cfg
        .stripe
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("Stripe top-ups are not configured"))?;
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::invalid("Stripe-Signature header is required"))?;
    let verified = stripe.verify_webhook(signature, &body)?;
    if matches!(
        verified.event.event_type.as_str(),
        "refund.created" | "refund.updated"
    ) {
        let refund: StripeRefundEvent = serde_json::from_value(verified.event.data.object)
            .map_err(|error| ApiError::invalid(format!("invalid refund event: {error}")))?;
        if refund.status.as_deref() != Some("succeeded") {
            return Ok(StatusCode::NO_CONTENT);
        }
        let payment_intent_id = refund
            .payment_intent
            .map(StripeObjectId::into_id)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApiError::invalid("refund payment_intent is missing"))?;
        let outcome = state
            .credits
            .apply_checkout_refund(&CheckoutRefund {
                event_id: verified.event.id,
                payload_sha256: verified.payload_sha256,
                stripe_refund_id: refund.id,
                stripe_payment_intent_id: payment_intent_id,
                amount_cents: refund.amount,
                currency: refund.currency.to_ascii_uppercase(),
                livemode: stripe.livemode(),
                processed_at_unix_ms: unix_millis()?,
            })
            .await
            .map_err(metering_failure)?;
        return match outcome {
            CreditApplyOutcome::Accepted | CreditApplyOutcome::Duplicate => {
                Ok(StatusCode::NO_CONTENT)
            }
        };
    }
    if !matches!(
        verified.event.event_type.as_str(),
        "checkout.session.completed" | "checkout.session.async_payment_succeeded"
    ) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let session: StripeCheckoutSessionEvent = serde_json::from_value(verified.event.data.object)
        .map_err(|error| ApiError::invalid(format!("invalid Checkout session event: {error}")))?;
    // A completed session can still be awaiting an asynchronous payment.
    // Only the paid state is allowed to mint credit.
    if session.payment_status != "paid" {
        return Ok(StatusCode::NO_CONTENT);
    }
    let intent_id = session
        .metadata
        .get("checkout_intent_id")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ApiError::invalid("Checkout metadata is missing checkout_intent_id"))?;
    let billing_account_id = session
        .metadata
        .get("billing_account_id")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ApiError::invalid("Checkout metadata is missing billing_account_id"))?;
    let amount_cents = session
        .amount_total
        .filter(|amount| *amount > 0)
        .ok_or_else(|| ApiError::invalid("Checkout amount_total must be positive"))?;
    let currency = session
        .currency
        .map(|value| value.to_ascii_uppercase())
        .ok_or_else(|| ApiError::invalid("Checkout currency is missing"))?;
    let payment_intent_id = session
        .payment_intent
        .map(StripeObjectId::into_id)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::invalid("Checkout payment_intent is missing"))?;
    let outcome = state
        .credits
        .apply_checkout_payment(&CheckoutPayment {
            event_id: verified.event.id,
            payload_sha256: verified.payload_sha256,
            intent_id,
            billing_account_id,
            stripe_session_id: session.id,
            stripe_payment_intent_id: payment_intent_id,
            stripe_customer_id: session.customer.map(StripeObjectId::into_id),
            amount_cents,
            currency,
            livemode: stripe.livemode(),
            processed_at_unix_ms: unix_millis()?,
        })
        .await
        .map_err(metering_failure)?;
    match outcome {
        CreditApplyOutcome::Accepted | CreditApplyOutcome::Duplicate => Ok(StatusCode::NO_CONTENT),
    }
}

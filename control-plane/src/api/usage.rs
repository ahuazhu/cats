use super::*;

use cats_api::metering::MAX_USAGE_CHECKPOINTS_PER_REQUEST;

pub(super) async fn ingest_usage_checkpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IngestUsageCheckpointsRequest>,
) -> ApiResult<Json<IngestUsageCheckpointsResponse>> {
    check_service_auth(&state, &headers).await?;
    if req.checkpoints.len() > MAX_USAGE_CHECKPOINTS_PER_REQUEST {
        return Err(ApiError::invalid(format!(
            "at most {MAX_USAGE_CHECKPOINTS_PER_REQUEST} checkpoints per request"
        ))
        .into());
    }
    // A missing/lost node cannot invent a producer identity. Registration is
    // also what lets operations fence a replaced node before accepting data.
    state.store.get_node(&req.node_id)?;

    let mut accepted = 0_u64;
    let mut duplicates = 0_u64;
    let mut rejected = Vec::new();
    for checkpoint in req.checkpoints {
        let expected_source = format!("node/{}/cat/{}", req.node_id, checkpoint.cat_id);
        if checkpoint.source_id != expected_source {
            return Err(ApiError::invalid(format!(
                "checkpoint source_id must be {expected_source}"
            ))
            .into());
        }
        let frozen_attribution = state
            .usage
            .source_epoch_attribution(&checkpoint.source_id, &checkpoint.source_epoch)
            .await
            .map_err(metering_failure)?;
        let attribution = match state.store.must_get_cat_by_id(&checkpoint.cat_id) {
            Ok(cat) => {
                if cat.node_id.as_deref() != Some(req.node_id.as_str()) {
                    return Err(ApiError::conflict(format!(
                        "node {} does not own Cat {}",
                        req.node_id, checkpoint.cat_id
                    ))
                    .into());
                }
                // A lifecycle job finalizes the runtime epoch that existed
                // before the desired-state mutation bumped the control-plane
                // generation. Accept an older acknowledged generation while
                // this node still owns the Cat; never accept a future one.
                if checkpoint.cat_generation > cat.generation {
                    return Err(ApiError::conflict(format!(
                        "Cat {} checkpoint generation {} is newer than current {}",
                        checkpoint.cat_id, checkpoint.cat_generation, cat.generation
                    ))
                    .into());
                }
                if let Some(attribution) = frozen_attribution {
                    validate_cat_attribution(&attribution, &cat)?;
                    attribution
                } else {
                    UsageAttribution {
                        billing_account_id: billing_account_id_for_workspace(
                            &state,
                            &cat.workspace_id,
                        )?,
                        workspace_id: cat.workspace_id,
                        resource_type: "cat".to_string(),
                        resource_id: checkpoint.cat_id.clone(),
                        attributed_cat_id: Some(checkpoint.cat_id.clone()),
                    }
                }
            }
            Err(error) if error.code == ErrorCode::NotFound => {
                // Durable outboxes can replay after resource deletion. Reuse
                // attribution already frozen in this exact source epoch; the
                // node never supplies or changes billing ownership.
                let Some(attribution) = frozen_attribution else {
                    // Nothing can ever make this acceptable: the Cat is gone, so
                    // no future request will freeze attribution for its epoch.
                    // Failing the request instead blocked the producer's whole
                    // ordered queue permanently -- observed in production as a
                    // 111,864-row outbox stalled behind one such checkpoint,
                    // which in turn stalled every lifecycle stop waiting on a
                    // final delivery. Reject this one and keep going.
                    let reason = format!(
                        "no frozen attribution exists for deleted Cat {} source epoch",
                        checkpoint.cat_id
                    );
                    tracing::warn!(
                        event = %checkpoint.event_id,
                        cat = %checkpoint.cat_id,
                        source_epoch = %checkpoint.source_epoch,
                        "rejecting an unattributable usage checkpoint; its usage is not billed"
                    );
                    rejected.push(RejectedCheckpoint {
                        event_id: checkpoint.event_id,
                        reason,
                    });
                    continue;
                };
                if !cat_attribution_matches(&attribution, &checkpoint.cat_id, None) {
                    return Err(ApiError::conflict(
                        "stored source-epoch attribution does not match checkpoint Cat",
                    )
                    .into());
                }
                attribution
            }
            Err(error) => return Err(error.into()),
        };
        let value = AttributedCheckpoint {
            attribution,
            checkpoint,
        };
        match state.usage.ingest(&value).await.map_err(metering_failure)? {
            IngestOutcome::Accepted => accepted += 1,
            IngestOutcome::Duplicate => duplicates += 1,
        }
    }
    Ok(Json(IngestUsageCheckpointsResponse {
        accepted,
        duplicates,
        rejected,
    }))
}

fn cat_attribution_matches(
    attribution: &UsageAttribution,
    cat_id: &str,
    workspace: Option<&str>,
) -> bool {
    attribution.resource_type == "cat"
        && attribution.resource_id == cat_id
        && attribution.attributed_cat_id.as_deref() == Some(cat_id)
        && workspace.is_none_or(|workspace| attribution.workspace_id == workspace)
}

fn validate_cat_attribution(attribution: &UsageAttribution, cat: &Cat) -> Result<(), Failure> {
    if cat_attribution_matches(attribution, &cat.id, Some(&cat.workspace_id)) {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "stored source-epoch attribution does not match current Cat ownership",
        )
        .into())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ProjectUsageQuery {
    from_ms: i64,
    to_ms: i64,
    #[serde(default)]
    cat: Option<String>,
    /// Immutable Cat resource ID for historical queries after deletion.
    #[serde(default)]
    cat_id: Option<String>,
    #[serde(default)]
    detail: bool,
    /// Optional bounded projection for charts and period-level detail tables.
    #[serde(default)]
    bucket_ms: Option<i64>,
}

const MIN_USAGE_BUCKET_MS: i64 = 60_000;
const MAX_USAGE_BUCKETS: i64 = 512;

fn validate_usage_bucket(
    from_ms: i64,
    to_ms: i64,
    bucket_ms: Option<i64>,
) -> Result<Option<i64>, Failure> {
    let Some(bucket_ms) = bucket_ms else {
        return Ok(None);
    };
    if bucket_ms < MIN_USAGE_BUCKET_MS {
        return Err(
            ApiError::invalid(format!("bucket_ms must be at least {MIN_USAGE_BUCKET_MS}")).into(),
        );
    }
    let duration = to_ms
        .checked_sub(from_ms)
        .ok_or_else(|| ApiError::invalid("usage query interval overflow"))?;
    if duration <= 0 {
        return Err(ApiError::invalid("usage query interval must be non-empty").into());
    }
    let bucket_count = duration
        .checked_add(bucket_ms - 1)
        .ok_or_else(|| ApiError::invalid("usage bucket count overflow"))?
        / bucket_ms;
    if bucket_count > MAX_USAGE_BUCKETS {
        return Err(ApiError::invalid(format!(
            "bucket_ms produces more than {MAX_USAGE_BUCKETS} buckets"
        ))
        .into());
    }
    Ok(Some(bucket_ms))
}

fn usage_time_buckets(
    intervals: &[UsageInterval],
    from_ms: i64,
    to_ms: i64,
    bucket_ms: i64,
    rate_card: &RateCard,
) -> cats_metering::Result<Vec<UsageTimeBucket>> {
    if to_ms <= from_ms {
        return Ok(Vec::new());
    }
    let duration = to_ms
        .checked_sub(from_ms)
        .ok_or(cats_metering::MeteringError::Overflow)?;
    let bucket_count = usize::try_from(
        duration
            .checked_add(bucket_ms - 1)
            .ok_or(cats_metering::MeteringError::Overflow)?
            / bucket_ms,
    )
    .map_err(|_| cats_metering::MeteringError::Overflow)?;
    let mut quantities = vec![BTreeMap::<&'static str, (UsageMetric, u128)>::new(); bucket_count];

    for interval in intervals {
        let interval_start = interval.interval_start_unix_ms.max(from_ms);
        let interval_end = interval.interval_end_unix_ms.min(to_ms);
        if interval_end <= interval_start || interval.quantity == 0 {
            continue;
        }
        let duration = u128::try_from(interval_end - interval_start)
            .map_err(|_| cats_metering::MeteringError::Overflow)?;
        let mut cursor = interval_start;
        while cursor < interval_end {
            let index = usize::try_from((cursor - from_ms) / bucket_ms)
                .map_err(|_| cats_metering::MeteringError::Overflow)?;
            let boundary = from_ms
                .checked_add(
                    i64::try_from(index + 1)
                        .map_err(|_| cats_metering::MeteringError::Overflow)?
                        .checked_mul(bucket_ms)
                        .ok_or(cats_metering::MeteringError::Overflow)?,
                )
                .ok_or(cats_metering::MeteringError::Overflow)?;
            let part_end = interval_end.min(boundary);
            let start_offset = u128::try_from(cursor - interval_start)
                .map_err(|_| cats_metering::MeteringError::Overflow)?;
            let end_offset = u128::try_from(part_end - interval_start)
                .map_err(|_| cats_metering::MeteringError::Overflow)?;
            let quantity_at_start = interval
                .quantity
                .checked_mul(start_offset)
                .ok_or(cats_metering::MeteringError::Overflow)?
                / duration;
            let quantity_at_end = interval
                .quantity
                .checked_mul(end_offset)
                .ok_or(cats_metering::MeteringError::Overflow)?
                / duration;
            let part_quantity = quantity_at_end
                .checked_sub(quantity_at_start)
                .ok_or(cats_metering::MeteringError::Overflow)?;
            let entry = quantities[index]
                .entry(interval.metric.slug())
                .or_insert((interval.metric, 0));
            entry.1 = entry
                .1
                .checked_add(part_quantity)
                .ok_or(cats_metering::MeteringError::Overflow)?;
            cursor = part_end;
        }
    }

    quantities
        .into_iter()
        .enumerate()
        .map(|(index, values)| {
            let interval_start_unix_ms = from_ms
                .checked_add(
                    i64::try_from(index)
                        .map_err(|_| cats_metering::MeteringError::Overflow)?
                        .checked_mul(bucket_ms)
                        .ok_or(cats_metering::MeteringError::Overflow)?,
                )
                .ok_or(cats_metering::MeteringError::Overflow)?;
            let interval_end_unix_ms = interval_start_unix_ms
                .checked_add(bucket_ms)
                .ok_or(cats_metering::MeteringError::Overflow)?
                .min(to_ms);
            let mut amount_nanos = 0_u128;
            let mut items = Vec::with_capacity(values.len());
            for (_, (metric, quantity)) in values {
                let amount = rate_card.rate_quantity(metric, quantity)?;
                if let Some(amount) = amount {
                    amount_nanos = amount_nanos
                        .checked_add(amount)
                        .ok_or(cats_metering::MeteringError::Overflow)?;
                }
                items.push(UsageSummaryLine {
                    metric,
                    quantity: quantity.to_string(),
                    unit: metric.canonical_unit().to_string(),
                    amount_nanos: amount.map(|value| value.to_string()),
                });
            }
            Ok(UsageTimeBucket {
                interval_start_unix_ms,
                interval_end_unix_ms,
                items,
                amount_nanos: amount_nanos.to_string(),
            })
        })
        .collect()
}

pub(super) async fn workspace_usage_view(
    state: &AppState,
    workspace: &str,
    attributed_cat_id: Option<String>,
    interval_start_unix_ms: i64,
    interval_end_unix_ms: i64,
) -> ApiResult<(String, UsageView)> {
    let ledger = state.store.billing_ledger_for_workspace(workspace)?;
    let view = state
        .usage
        .query(&MeterUsageQuery {
            billing_account_id: ledger.billing_account_id.clone(),
            workspace_id: Some(workspace.to_string()),
            attributed_cat_id,
            interval_start_unix_ms,
            interval_end_unix_ms,
        })
        .await
        .map_err(metering_failure)?;
    let latest_interval_end_unix_ms = view.latest_interval_end_unix_ms;
    let mut totals = view.totals;
    let mut cats = view.cats;
    let mut details = view.details;
    totals.sort_by_key(|aggregate| aggregate.metric.slug());
    for cat in &mut cats {
        cat.items.sort_by_key(|aggregate| aggregate.metric.slug());
    }
    cats.sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    details.sort_by(|left, right| {
        (
            left.interval_start_unix_ms,
            left.interval_end_unix_ms,
            left.source_id.as_str(),
            left.end_sequence,
        )
            .cmp(&(
                right.interval_start_unix_ms,
                right.interval_end_unix_ms,
                right.source_id.as_str(),
                right.end_sequence,
            ))
    });
    Ok((
        ledger.billing_account_id,
        UsageView {
            totals,
            cats,
            details,
            latest_interval_end_unix_ms,
        },
    ))
}

pub(super) async fn workspace_usage(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    Query(query): Query<ProjectUsageQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    if query.cat.is_some() && query.cat_id.is_some() {
        return Err(ApiError::invalid("cat and cat_id are mutually exclusive").into());
    }
    let bucket_ms = validate_usage_bucket(query.from_ms, query.to_ms, query.bucket_ms)?;
    let cat_id = if let Some(cat_id) = query.cat_id {
        if cat_id.trim().is_empty() {
            return Err(ApiError::invalid("cat_id must not be empty").into());
        }
        Some(cat_id)
    } else {
        query
            .cat
            .as_deref()
            .map(|cat| state.store.get_cat(&workspace, cat).map(|cat| cat.id))
            .transpose()?
    };
    let (billing_account_id, view) =
        workspace_usage_view(&state, &workspace, cat_id, query.from_ms, query.to_ms).await?;
    let rate_card = RateCard::sprites_compute_v1();

    let mut amount_nanos = 0_u128;
    let mut items = Vec::with_capacity(view.totals.len());
    for aggregate in &view.totals {
        let amount = rate_card
            .rate_quantity(aggregate.metric, aggregate.quantity)
            .map_err(metering_failure)?;
        if let Some(amount) = amount {
            amount_nanos = amount_nanos
                .checked_add(amount)
                .ok_or_else(|| ApiError::internal("rated amount overflow"))?;
        }
        items.push(UsageSummaryLine {
            metric: aggregate.metric,
            quantity: aggregate.quantity.to_string(),
            unit: aggregate.metric.canonical_unit().to_string(),
            amount_nanos: amount.map(|value| value.to_string()),
        });
    }

    let mut cats = Vec::with_capacity(view.cats.len());
    for cat in &view.cats {
        let mut cat_amount = 0_u128;
        let mut cat_items = Vec::with_capacity(cat.items.len());
        for aggregate in &cat.items {
            let amount = rate_card
                .rate_quantity(aggregate.metric, aggregate.quantity)
                .map_err(metering_failure)?;
            if let Some(amount) = amount {
                cat_amount = cat_amount
                    .checked_add(amount)
                    .ok_or_else(|| ApiError::internal("rated Cat amount overflow"))?;
            }
            cat_items.push(UsageSummaryLine {
                metric: aggregate.metric,
                quantity: aggregate.quantity.to_string(),
                unit: aggregate.metric.canonical_unit().to_string(),
                amount_nanos: amount.map(|value| value.to_string()),
            });
        }
        cats.push(CatUsageSummary {
            cat_id: cat.cat_id.clone(),
            items: cat_items,
            amount_nanos: cat_amount.to_string(),
        });
    }

    let time_buckets = if let (Some(bucket_ms), Some(latest_interval_end_unix_ms)) =
        (bucket_ms, view.latest_interval_end_unix_ms)
    {
        usage_time_buckets(
            &view.details,
            query.from_ms,
            query.to_ms.min(latest_interval_end_unix_ms),
            bucket_ms,
            &rate_card,
        )
        .map_err(metering_failure)?
    } else {
        Vec::new()
    };
    let details = if query.detail {
        view.details
            .iter()
            .map(|interval| UsageDetailLine {
                interval_start_unix_ms: interval.interval_start_unix_ms,
                interval_end_unix_ms: interval.interval_end_unix_ms,
                resource_type: interval.attribution.resource_type.clone(),
                resource_id: interval.attribution.resource_id.clone(),
                attributed_cat_id: interval.attribution.attributed_cat_id.clone(),
                metric: interval.metric,
                quantity: interval.quantity.to_string(),
                unit: interval.metric.canonical_unit().to_string(),
                source_id: interval.source_id.clone(),
                source_epoch: interval.source_epoch.clone(),
                end_sequence: interval.end_sequence,
            })
            .collect()
    } else {
        Vec::new()
    };
    let report = UsageReport {
        billing_account_id,
        workspace_id: workspace,
        interval_start_unix_ms: query.from_ms,
        interval_end_unix_ms: query.to_ms,
        status: "provisional".to_string(),
        currency: rate_card.currency,
        rate_card_id: rate_card.id,
        latest_interval_end_unix_ms: view.latest_interval_end_unix_ms,
        items,
        cats,
        time_buckets,
        details,
        amount_nanos: amount_nanos.to_string(),
    };
    let mut response = Json(report).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

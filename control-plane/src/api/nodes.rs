use super::*;
use std::sync::Arc;

#[cfg(debug_assertions)]
pub(super) async fn acquire_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AcquireWorkRequest>,
) -> ApiResult<Json<AcquireWorkResponse>> {
    check_service_auth(&state, &headers).await?;
    if request.kind == WorkKind::Guest {
        return Err(ApiError::invalid("guest work must come through the owning node").into());
    }
    let lease = state
        .store
        .execute(move |store| {
            store.acquire_work(
                &request.cat_id,
                request.kind,
                &request.owner_id,
                &request.label,
                request.ttl_ms,
            )
        })
        .await?;
    Ok(Json(AcquireWorkResponse { lease }))
}

#[cfg(debug_assertions)]
pub(super) async fn release_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReleaseWorkRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    let cat_id = state
        .store
        .execute(move |store| store.release_work(&request.lease_id))
        .await?;
    if let Some(cat_id) = cat_id {
        state.controller.maybe_auto_suspend(&cat_id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(debug_assertions)]
pub(super) async fn cordon_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    cordon_registered_node(&state, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(debug_assertions)]
pub(super) async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Node>>> {
    check_admin_auth(&state, &headers).await?;
    let items = state.store.execute(|store| store.list_nodes()).await?;
    Ok(Json(ListResponse { items }))
}

#[cfg(debug_assertions)]
pub(super) async fn admin_list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<NodeSummary>>> {
    check_admin_auth(&state, &headers).await?;
    let items = state
        .store
        .execute(|store| store.list_node_summaries())
        .await?;
    Ok(Json(ListResponse { items }))
}

/// Resource routes key on the immutable workspace ID, so a machine token — which
/// has no WorkOS identity to enumerate its own workspaces from — needs a way to
/// turn an `account/workspace` locator into that ID.
pub(super) async fn admin_list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<cats_api::auth::Workspace>>> {
    check_admin_auth(&state, &headers).await?;
    let items = state
        .store
        .execute(|store| store.list_all_workspace_views())
        .await?;
    Ok(Json(ListResponse { items }))
}

#[cfg(debug_assertions)]
pub(super) async fn admin_get_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<NodeSummary>> {
    check_admin_auth(&state, &headers).await?;
    let summary = state
        .store
        .execute(move |store| store.node_summary(&id))
        .await?;
    Ok(Json(summary))
}

#[cfg(debug_assertions)]
pub(super) async fn admin_node_cats(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<NodeCatSummary>>> {
    check_admin_auth(&state, &headers).await?;
    let items = state
        .store
        .execute(move |store| store.node_cat_summaries(&id))
        .await?;
    Ok(Json(ListResponse { items }))
}

#[cfg(debug_assertions)]
pub(super) async fn admin_node_action(
    State(state): State<AppState>,
    Path((id, verb)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    check_admin_auth(&state, &headers).await?;
    let query_id = id.clone();
    let node = state
        .store
        .execute(move |store| store.get_node(&query_id))
        .await?;
    let status = match verb.as_str() {
        "cordon" => {
            cordon_registered_node(&state, &id).await?;
            StatusCode::OK
        }
        "uncordon" => {
            let expected = state.cfg.route_grant_signer.public_key_sha256();
            let id = id.clone();
            let expected = expected.to_string();
            state
                .store
                .execute(move |store| store.uncordon_node_with_route_grant(&id, &expected))
                .await?;
            state.notify.notify_one();
            StatusCode::OK
        }
        "drain" => {
            if matches!(node.state, NodeState::Lost | NodeState::Fenced) {
                return Err(ApiError::failed_precondition(
                    "lost or fenced nodes cannot be drained",
                )
                .into());
            }
            let id = id.clone();
            state
                .store
                .execute(move |store| store.set_node_state(&id, NodeState::Draining))
                .await?;
            state.notify.notify_one();
            StatusCode::ACCEPTED
        }
        "fence" => {
            if !matches!(node.state, NodeState::Lost | NodeState::Fenced) {
                return Err(ApiError::failed_precondition(
                    "only a Lost node or an idempotent Fenced retry can be fenced",
                )
                .into());
            }
            let request: FenceNodeRequest = serde_json::from_slice(&body)
                .map_err(|_| ApiError::invalid("fence requires a JSON confirmation body"))?;
            if !request.confirm_host_stopped_or_isolated {
                return Err(
                    ApiError::invalid("confirm_host_stopped_or_isolated must be true").into(),
                );
            }
            state
                .controller
                .confirm_node_fenced(&id)
                .await
                .map_err(|error| ApiError::internal(error.to_string()))?;
            StatusCode::OK
        }
        _ => return Err(ApiError::invalid(format!("unknown node action {verb}")).into()),
    };
    let summary = state
        .store
        .execute(move |store| store.node_summary(&id))
        .await?;
    Ok((status, Json(summary)).into_response())
}

#[cfg(debug_assertions)]
pub(super) async fn admin_delete_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    state
        .store
        .execute(move |store| store.delete_node(&id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn monitoring_snapshot(store: &crate::store::Store) -> crate::store::Result<MonitoringOverview> {
    let mut cat_counts = CatStateCounts::default();
    for cat in store.list_all_cats()? {
        cat_counts.total += 1;
        match cat.observed_state {
            ObservedState::Running => cat_counts.running += 1,
            ObservedState::Suspended => cat_counts.suspended += 1,
            ObservedState::Warm => cat_counts.warm += 1,
            ObservedState::Cold => cat_counts.cold += 1,
            ObservedState::Failed | ObservedState::Unknown => cat_counts.failed_or_unknown += 1,
            _ => cat_counts.transitional += 1,
        }
    }

    let summaries = store.list_node_summaries()?;
    let mut node_counts = NodeStateCounts::default();
    let mut orphan_cats = 0_u64;
    let mut capacity = FleetCapacity::default();
    let mut usage = FleetUsage::default();
    let mut cpu_weighted_sum = 0.0;
    let mut cpu_weight = 0_u64;
    let mut logical_cpus = 0_u64;
    let mut memory_total = 0_u64;
    let mut memory_available = 0_u64;
    let mut memory_samples = 0_u64;
    let mut disk_total = 0_u64;
    let mut disk_available = 0_u64;
    let mut disk_samples = 0_u64;
    for summary in &summaries {
        node_counts.total += 1;
        match summary.node.state {
            NodeState::Ready => node_counts.ready += 1,
            NodeState::Cordoned => node_counts.cordoned += 1,
            NodeState::Draining => node_counts.draining += 1,
            NodeState::Lost => node_counts.lost += 1,
            NodeState::Fenced => node_counts.fenced += 1,
        }
        capacity.total_cpus += u64::from(summary.node.capacity.cpus);
        capacity.total_memory_mib += summary.node.capacity.memory_mib;
        capacity.assigned_cpus += u64::from(summary.assigned_cpus);
        capacity.assigned_memory_mib += summary.assigned_memory_mib;
        // Deliberately counted before the Lost/Fenced skip below: a Lost
        // node's last report is stale, but the runtimes it named were real
        // and unaccounted for -- exactly what this number must not hide.
        orphan_cats += summary.orphan_cats;

        if matches!(summary.node.state, NodeState::Lost | NodeState::Fenced) {
            continue;
        }
        let Some(telemetry) = &summary.node.telemetry else {
            continue;
        };
        if let Some(count) = telemetry.host_logical_cpus {
            logical_cpus += u64::from(count);
        }
        if let Some(percent) = telemetry.host_cpu_usage_percent {
            let weight = u64::from(
                telemetry
                    .host_logical_cpus
                    .unwrap_or(summary.node.capacity.cpus),
            );
            if weight > 0 {
                cpu_weighted_sum += percent.clamp(0.0, 100.0) * weight as f64;
                cpu_weight += weight;
            }
        }
        if let (Some(total), Some(available)) = (
            telemetry.host_memory_total_mib,
            telemetry.host_memory_available_mib,
        ) {
            memory_total = memory_total.saturating_add(total);
            memory_available = memory_available.saturating_add(available.min(total));
            memory_samples += 1;
        }
        if let (Some(total), Some(available)) = (
            telemetry.host_disk_total_bytes,
            telemetry.host_disk_available_bytes,
        ) {
            disk_total = disk_total.saturating_add(total);
            disk_available = disk_available.saturating_add(available.min(total));
            disk_samples += 1;
        }
    }
    if cpu_weight > 0 {
        usage.cpu_usage_percent = Some(cpu_weighted_sum / cpu_weight as f64);
    }
    if logical_cpus > 0 {
        usage.logical_cpus = Some(logical_cpus);
    }
    if memory_samples > 0 {
        usage.memory_total_mib = Some(memory_total);
        usage.memory_used_mib = Some(memory_total.saturating_sub(memory_available));
    }
    if disk_samples > 0 {
        usage.disk_total_bytes = Some(disk_total);
        usage.disk_used_bytes = Some(disk_total.saturating_sub(disk_available));
    }

    Ok(MonitoringOverview {
        generated_at_unix: crate::store::now_unix(),
        cats: cat_counts,
        nodes: node_counts,
        operations: store.operation_counts()?,
        capacity,
        usage,
        orphan_cats,
    })
}

#[cfg(debug_assertions)]
pub(super) async fn admin_monitoring(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MonitoringOverview>> {
    check_admin_auth(&state, &headers).await?;
    let snapshot = state
        .store
        .execute(|store| monitoring_snapshot(store))
        .await?;
    Ok(Json(snapshot))
}

pub(super) async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_metrics_auth(&state, &headers).await?;
    let store_metrics = crate::store::metrics_snapshot(&state.store);
    let mut body = String::new();
    store_metrics.append_prometheus(&mut body);
    state
        .observation_store
        .snapshot()
        .append_prometheus(&mut body);
    macro_rules! metric {
        ($name:expr, $value:expr) => {
            body.push_str(&format!("{} {}\n", $name, $value));
        };
    }
    if !state.retired_product_authority_for_tests() {
        // Production has no authoritative projection for the retired fleet
        // rows. Preserve the DB-independent executor and signed observation
        // diagnostics above, but never query or expose the legacy Cat/Node
        // snapshot from the cutover composition.
        metric!("cats_control_plane_metrics_database_snapshot_available", 0);
        return Ok((
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response());
    }
    // The executor gauges above are captured before touching PostgreSQL and
    // are the primary diagnostic when it is unhealthy. The explicit legacy
    // test composition retains the old fleet metrics, but makes them optional
    // behind a short scrape-only deadline. Cancelling a queued Store future
    // removes its closure; a call already started keeps its lane until the
    // configured physical/statement deadline closes it.
    let database_snapshot = tokio::time::timeout(Duration::from_millis(250), {
        let store = Arc::clone(&state.store);
        async move {
            store
                .execute(|store| Ok((monitoring_snapshot(store)?, store.list_node_summaries()?)))
                .await
        }
    })
    .await
    .ok()
    .and_then(|result| result.ok());
    let Some((overview, summaries)) = database_snapshot else {
        metric!("cats_control_plane_metrics_database_snapshot_available", 0);
        return Ok((
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response());
    };
    metric!("cats_control_plane_metrics_database_snapshot_available", 1);
    metric!("cats_control_plane_cats_total", overview.cats.total);
    metric!("cats_control_plane_cats_running", overview.cats.running);
    metric!("cats_control_plane_cats_suspended", overview.cats.suspended);
    metric!("cats_control_plane_cats_warm", overview.cats.warm);
    metric!("cats_control_plane_cats_cold", overview.cats.cold);
    metric!(
        "cats_control_plane_cats_transitional",
        overview.cats.transitional
    );
    metric!(
        "cats_control_plane_cats_failed_or_unknown",
        overview.cats.failed_or_unknown
    );
    metric!("cats_control_plane_nodes_ready", overview.nodes.ready);
    metric!("cats_control_plane_nodes_cordoned", overview.nodes.cordoned);
    metric!("cats_control_plane_nodes_draining", overview.nodes.draining);
    metric!("cats_control_plane_nodes_lost", overview.nodes.lost);
    metric!("cats_control_plane_nodes_fenced", overview.nodes.fenced);
    metric!(
        "cats_control_plane_operations_pending",
        overview.operations.pending
    );
    metric!(
        "cats_control_plane_operations_running",
        overview.operations.running
    );
    metric!(
        "cats_control_plane_operations_succeeded",
        overview.operations.succeeded
    );
    metric!(
        "cats_control_plane_operations_failed",
        overview.operations.failed
    );
    metric!(
        "cats_control_plane_capacity_cpus",
        overview.capacity.total_cpus
    );
    metric!(
        "cats_control_plane_capacity_assigned_cpus",
        overview.capacity.assigned_cpus
    );
    metric!(
        "cats_control_plane_capacity_memory_mib",
        overview.capacity.total_memory_mib
    );
    metric!(
        "cats_control_plane_capacity_assigned_memory_mib",
        overview.capacity.assigned_memory_mib
    );
    if let Some(percent) = overview.usage.cpu_usage_percent {
        metric!("cats_control_plane_host_cpu_usage_percent", percent);
    }
    if let Some(logical_cpus) = overview.usage.logical_cpus {
        metric!("cats_control_plane_host_logical_cpus", logical_cpus);
    }
    if let Some(total) = overview.usage.memory_total_mib {
        metric!("cats_control_plane_host_memory_total_mib", total);
    }
    if let Some(used) = overview.usage.memory_used_mib {
        metric!("cats_control_plane_host_memory_used_mib", used);
    }
    if let Some(total) = overview.usage.disk_total_bytes {
        metric!("cats_control_plane_host_disk_total_bytes", total);
    }
    if let Some(used) = overview.usage.disk_used_bytes {
        metric!("cats_control_plane_host_disk_used_bytes", used);
    }
    for summary in summaries {
        let node_id = summary
            .node
            .id
            .replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('"', "\\\"");
        metric!(
            format!("cats_node_heartbeat_age_seconds{{node_id=\"{node_id}\"}}"),
            summary.heartbeat_age_seconds
        );
        metric!(
            format!("cats_node_orphan_cats{{node_id=\"{node_id}\"}}"),
            summary.orphan_cats
        );
        if let Some(telemetry) = summary.node.telemetry {
            metric!(
                format!("cats_node_observed_cats{{node_id=\"{node_id}\"}}"),
                telemetry.observed_cats
            );
            metric!(
                format!("cats_node_allocated_cpus{{node_id=\"{node_id}\"}}"),
                telemetry.allocated_cpus
            );
            metric!(
                format!("cats_node_allocated_memory_mib{{node_id=\"{node_id}\"}}"),
                telemetry.allocated_memory_mib
            );
            // Concurrent-wake gate saturation (ADR-0002 §8). Exported
            // unconditionally so a node sitting at its budget is visible as a
            // gauge rather than only as wake latency.
            metric!(
                format!("cats_node_wake_in_flight{{node_id=\"{node_id}\"}}"),
                telemetry.wake_in_flight
            );
            metric!(
                format!("cats_node_wake_commitment_bytes{{node_id=\"{node_id}\"}}"),
                telemetry.wake_commitment_bytes
            );
            metric!(
                format!("cats_node_wake_peak_in_flight{{node_id=\"{node_id}\"}}"),
                telemetry.wake_peak_in_flight
            );
            metric!(
                format!("cats_node_wake_commitment_budget_bytes{{node_id=\"{node_id}\"}}"),
                telemetry.wake_commitment_budget_bytes
            );
            // Leaked kernel NBD devices (issue #79). Exported with the pool
            // size so an alarm can fire on a fraction of the pool: the count
            // alone has no threshold, and by the time it is obviously large
            // the host is already deadlocking on it.
            if let Some(leaked) = telemetry.leaked_nbd_devices {
                metric!(
                    format!("cats_node_leaked_nbd_devices{{node_id=\"{node_id}\"}}"),
                    leaked
                );
            }
            if let Some(total) = telemetry.nbd_devices_total {
                metric!(
                    format!("cats_node_nbd_devices_total{{node_id=\"{node_id}\"}}"),
                    total
                );
            }
            // Per-Cat runtime directories no live Cat owns (issue #99). The
            // byte gauge is the one to alarm on: the count says how many Cats
            // left something behind, the bytes say whether that is a rounding
            // error or most of the local medium.
            if let Some(dirs) = telemetry.unsupervised_runtime_dirs {
                metric!(
                    format!("cats_node_unsupervised_runtime_dirs{{node_id=\"{node_id}\"}}"),
                    dirs
                );
            }
            if let Some(bytes) = telemetry.unsupervised_runtime_bytes {
                metric!(
                    format!("cats_node_unsupervised_runtime_bytes{{node_id=\"{node_id}\"}}"),
                    bytes
                );
            }
            if let Some(logical_cpus) = telemetry.host_logical_cpus {
                metric!(
                    format!("cats_node_logical_cpus{{node_id=\"{node_id}\"}}"),
                    logical_cpus
                );
            }
            if let Some(percent) = telemetry.host_cpu_usage_percent {
                metric!(
                    format!("cats_node_cpu_usage_percent{{node_id=\"{node_id}\"}}"),
                    percent
                );
            }
            if let Some(load) = telemetry.load_average_1m {
                metric!(
                    format!("cats_node_load_average_1m{{node_id=\"{node_id}\"}}"),
                    load
                );
            }
            if let Some(available) = telemetry.host_memory_available_mib {
                metric!(
                    format!("cats_node_memory_available_mib{{node_id=\"{node_id}\"}}"),
                    available
                );
            }
            if let Some(total) = telemetry.host_memory_total_mib {
                metric!(
                    format!("cats_node_memory_total_mib{{node_id=\"{node_id}\"}}"),
                    total
                );
                if let Some(available) = telemetry.host_memory_available_mib {
                    metric!(
                        format!("cats_node_memory_used_mib{{node_id=\"{node_id}\"}}"),
                        total.saturating_sub(available.min(total))
                    );
                }
            }
            if let Some(available) = telemetry.host_disk_available_bytes {
                metric!(
                    format!("cats_node_disk_available_bytes{{node_id=\"{node_id}\"}}"),
                    available
                );
            }
            if let Some(total) = telemetry.host_disk_total_bytes {
                metric!(
                    format!("cats_node_disk_total_bytes{{node_id=\"{node_id}\"}}"),
                    total
                );
                if let Some(available) = telemetry.host_disk_available_bytes {
                    metric!(
                        format!("cats_node_disk_used_bytes{{node_id=\"{node_id}\"}}"),
                        total.saturating_sub(available.min(total))
                    );
                }
            }
            for cat in telemetry.cat_resources {
                let cat_id = cat
                    .cat_id
                    .replace('\\', "\\\\")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('"', "\\\"");
                let labels = format!("node_id=\"{node_id}\",cat_id=\"{cat_id}\"");
                if let Some(cores) = cat.cpu_usage_cores {
                    metric!(format!("cats_cat_cpu_usage_cores{{{labels}}}"), cores);
                }
                if let Some(bytes) = cat.memory_rss_bytes {
                    metric!(format!("cats_cat_memory_rss_bytes{{{labels}}}"), bytes);
                }
                if let Some(bytes) = cat.host_disk_used_bytes {
                    metric!(format!("cats_cat_host_disk_used_bytes{{{labels}}}"), bytes);
                }
                for disk in cat.disk_durability {
                    let disk_id = disk
                        .disk_id
                        .replace('\\', "\\\\")
                        .replace('\n', "\\n")
                        .replace('\r', "\\r")
                        .replace('"', "\\\"");
                    let mode = disk
                        .mode
                        .replace('\\', "\\\\")
                        .replace('\n', "\\n")
                        .replace('\r', "\\r")
                        .replace('"', "\\\"");
                    let disk_labels = format!("{labels},disk_id=\"{disk_id}\",mode=\"{mode}\"");
                    metric!(
                        format!("cats_disk_local_durable_generation{{{disk_labels}}}"),
                        disk.local_durable_generation
                    );
                    metric!(
                        format!("cats_disk_remote_durable_generation{{{disk_labels}}}"),
                        disk.remote_durable_generation
                    );
                    metric!(
                        format!("cats_disk_unpublished_generations{{{disk_labels}}}"),
                        disk.unpublished_generations
                    );
                    metric!(
                        format!("cats_disk_unpublished_bytes{{{disk_labels}}}"),
                        disk.unpublished_bytes
                    );
                    metric!(
                        format!("cats_disk_oldest_unpublished_age_ms{{{disk_labels}}}"),
                        disk.oldest_unpublished_age_ms
                    );
                    metric!(
                        format!("cats_disk_max_unpublished_generations{{{disk_labels}}}"),
                        disk.max_unpublished_generations
                    );
                    metric!(
                        format!("cats_disk_max_unpublished_bytes{{{disk_labels}}}"),
                        disk.max_unpublished_bytes
                    );
                    metric!(
                        format!("cats_disk_local_allocated_bytes{{{disk_labels}}}"),
                        disk.local_allocated_bytes
                    );
                    metric!(
                        format!("cats_disk_local_accounted_bytes{{{disk_labels}}}"),
                        disk.local_accounted_bytes
                    );
                    metric!(
                        format!("cats_disk_max_local_bytes{{{disk_labels}}}"),
                        disk.max_local_bytes
                    );
                    metric!(
                        format!("cats_disk_evicted_cache_chunks{{{disk_labels}}}"),
                        disk.evicted_cache_chunks
                    );
                    metric!(
                        format!("cats_disk_backpressured{{{disk_labels}}}"),
                        u8::from(disk.backpressured)
                    );
                    metric!(
                        format!("cats_disk_fenced{{{disk_labels}}}"),
                        u8::from(disk.fenced)
                    );
                    metric!(
                        format!("cats_disk_publish_error{{{disk_labels}}}"),
                        u8::from(disk.last_publish_error.is_some())
                    );
                }
            }
        }
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response())
}

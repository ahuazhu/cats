use super::*;

pub(super) async fn register_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterNodeRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    state.store.register_node(
        &req.node_id,
        &req.agent_url,
        &req.gateway_url,
        req.cpus,
        req.memory_mib,
    )?;
    state.notify.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    state
        .store
        .heartbeat_node(&req.node_id, req.telemetry.as_ref())?;
    // Drift detection: trust node reports for steady states at the same
    // generation; the reconciler drives any resulting divergence.
    for hb in &req.cats {
        if let Ok(cat) = state.store.must_get_cat_by_id(&hb.cat_id) {
            if cat.generation == hb.generation
                && cat.node_id.as_deref() == Some(req.node_id.as_str())
                && cat.observed_state != hb.state
                && matches!(
                    cat.observed_state,
                    ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
                )
            {
                state.store.set_observed(&cat.id, hb.state)?;
                state.notify.notify_one();
            }
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn node_work_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NodeWorkStatusRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    let should_wake = state.store.ingest_guest_work(&request)?;
    if should_wake {
        state.notify.notify_one();
    } else {
        state.controller.maybe_auto_suspend(&request.cat_id)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn acquire_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AcquireWorkRequest>,
) -> ApiResult<Json<AcquireWorkResponse>> {
    check_service_auth(&state, &headers).await?;
    if request.kind == WorkKind::Guest {
        return Err(ApiError::invalid("guest work must come through the owning node").into());
    }
    let lease = state.store.acquire_work(
        &request.cat_id,
        request.kind,
        &request.owner_id,
        &request.label,
        request.ttl_ms,
    )?;
    Ok(Json(AcquireWorkResponse { lease }))
}

pub(super) async fn release_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReleaseWorkRequest>,
) -> ApiResult<StatusCode> {
    check_service_auth(&state, &headers).await?;
    if let Some(cat_id) = state.store.release_work(&request.lease_id)? {
        state.controller.maybe_auto_suspend(&cat_id)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn cordon_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    cordon_registered_node(&state, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Node>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_nodes()?,
    }))
}

pub(super) async fn admin_list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<NodeSummary>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_node_summaries()?,
    }))
}

/// Resource routes key on the immutable workspace ID, so a machine token — which
/// has no WorkOS identity to enumerate its own workspaces from — needs a way to
/// turn an `account/workspace` locator into that ID.
pub(super) async fn admin_list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<cats_api::auth::Workspace>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.list_all_workspace_views()?,
    }))
}

pub(super) async fn admin_get_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<NodeSummary>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(state.store.node_summary(&id)?))
}

pub(super) async fn admin_node_cats(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<NodeCatSummary>>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(ListResponse {
        items: state.store.node_cat_summaries(&id)?,
    }))
}

pub(super) async fn admin_node_action(
    State(state): State<AppState>,
    Path((id, verb)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_admin_auth(&state, &headers).await?;
    let node = state.store.get_node(&id)?;
    let status = match verb.as_str() {
        "cordon" => {
            cordon_registered_node(&state, &id)?;
            StatusCode::OK
        }
        "uncordon" => {
            if node.state == NodeState::Lost {
                return Err(ApiError::failed_precondition(
                    "lost node must heartbeat or register before uncordon",
                )
                .into());
            }
            state.store.set_node_state(&id, NodeState::Ready)?;
            state.notify.notify_one();
            StatusCode::OK
        }
        "drain" => {
            if node.state == NodeState::Lost {
                return Err(ApiError::failed_precondition(
                    "lost nodes are fenced automatically and cannot be drained",
                )
                .into());
            }
            state.store.set_node_state(&id, NodeState::Draining)?;
            state.notify.notify_one();
            StatusCode::ACCEPTED
        }
        _ => return Err(ApiError::invalid(format!("unknown node action {verb}")).into()),
    };
    Ok((status, Json(state.store.node_summary(&id)?)).into_response())
}

pub(super) async fn admin_delete_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_admin_auth(&state, &headers).await?;
    state.store.delete_node(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

fn monitoring_snapshot(state: &AppState) -> crate::store::Result<MonitoringOverview> {
    let mut cat_counts = CatStateCounts::default();
    for cat in state.store.list_all_cats()? {
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

    let summaries = state.store.list_node_summaries()?;
    let mut node_counts = NodeStateCounts::default();
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
        }
        capacity.total_cpus += u64::from(summary.node.capacity.cpus);
        capacity.total_memory_mib += summary.node.capacity.memory_mib;
        capacity.assigned_cpus += u64::from(summary.assigned_cpus);
        capacity.assigned_memory_mib += summary.assigned_memory_mib;

        if summary.node.state == NodeState::Lost {
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
        operations: state.store.operation_counts()?,
        capacity,
        usage,
    })
}

pub(super) async fn admin_monitoring(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MonitoringOverview>> {
    check_admin_auth(&state, &headers).await?;
    Ok(Json(monitoring_snapshot(&state)?))
}

pub(super) async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_admin_auth(&state, &headers).await?;
    let overview = monitoring_snapshot(&state)?;
    let mut body = String::new();
    macro_rules! metric {
        ($name:expr, $value:expr) => {
            body.push_str(&format!("{} {}\n", $name, $value));
        };
    }
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
    for summary in state.store.list_node_summaries()? {
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

use super::*;

pub(super) async fn create_disk(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateDiskRequest>,
) -> ApiResult<Json<Disk>> {
    let scope = check_workspace_auth(&state, &headers, &workspace).await?;
    if req.size_bytes == 0 || req.size_bytes > cats_api::chunk::MAX_VOLUME_BYTES {
        return Err(ApiError::invalid("disk size out of range").into());
    }
    let disk =
        state
            .store
            .create_disk(&scope.workspace, &req.name, req.size_bytes, req.durability)?;
    // Create the storage volume eagerly so snapshots/resize work pre-attach.
    let size = cats_api::chunk::round_up_to_chunk(req.size_bytes);
    match state.storage_meta.create_volume(&disk.volume_id, size) {
        Ok(()) | Err(cats_storage::MetaError::AlreadyExists(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    Ok(Json(disk))
}

pub(super) async fn list_disks(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Disk>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(ListResponse {
        items: state.store.list_disks(&workspace)?,
    }))
}

pub(super) async fn get_disk(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Disk>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    Ok(Json(state.store.get_disk(&workspace, &disk)?))
}

pub(super) async fn delete_disk(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    if disk.kind == DiskKind::Root {
        return Err(ApiError::failed_precondition("root disks are deleted with their cat").into());
    }
    if disk.bound_cat_id.is_some() {
        return Err(ApiError::failed_precondition("disk must be Available (unmount first)").into());
    }
    match state.storage_meta.delete_volume(&disk.volume_id) {
        Ok(()) | Err(cats_storage::MetaError::NotFound(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    state.store.delete_disk_row(&disk.id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
pub(super) struct DiskActionBody {
    #[serde(default)]
    cat_id: Option<String>,
    #[serde(default)]
    mount_at: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

pub(super) async fn disk_action(
    State(state): State<AppState>,
    Path((workspace, disk, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<DiskActionBody>,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    match verb.as_str() {
        "mount" => {
            let cat_ref = body
                .cat_id
                .ok_or_else(|| ApiError::invalid("cat_id required"))?;
            let mount_at = body
                .mount_at
                .ok_or_else(|| ApiError::invalid("mount_at required"))?;
            let cat = state.store.get_cat(&workspace, &cat_ref)?;
            if disk.kind == DiskKind::Root {
                return Err(ApiError::failed_precondition("cannot mount a root disk").into());
            }
            let (binding, mode) = state
                .store
                .bind_disk_for_hot_change(&disk.id, &cat.id, &mount_at)?;
            if mode == crate::store::DiskChangeMode::HotRunning {
                if let Err(e) = hot_attach(&state, &cat, &disk, &binding.mount_path).await {
                    state.store.unbind_disk(&disk.id)?;
                    return Err(e);
                }
            }
            Ok(Json(binding).into_response())
        }
        "unmount" => {
            let Some(bound_cat) = disk.bound_cat_id.clone() else {
                return Err(ApiError::failed_precondition("disk is not mounted").into());
            };
            let cat = state.store.must_get_cat_by_id(&bound_cat)?;
            let (binding, mode) = state.store.unbind_disk_for_hot_change(&disk.id, &cat.id)?;
            if mode == crate::store::DiskChangeMode::HotRunning {
                if let Err(error) = hot_detach(&state, &cat, &disk).await {
                    state.store.restore_binding(&binding)?;
                    return Err(error);
                }
            }
            let revoke = match state.storage_meta.load_head(&disk.volume_id) {
                Ok(head) => match head.lease_owner {
                    Some(owner) => state
                        .storage_meta
                        .revoke_lease_if_matches(&disk.volume_id, &owner, head.lease_epoch)
                        .and_then(|revoked| {
                            if revoked {
                                Ok(())
                            } else {
                                Err(cats_storage::MetaError::Fenced)
                            }
                        }),
                    None => Ok(()),
                },
                Err(cats_storage::MetaError::NotFound(_)) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = revoke {
                state.store.restore_binding(&binding)?;
                return Err(ApiError::internal(error.to_string()).into());
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        "resize" => {
            let new_size = body
                .size_bytes
                .ok_or_else(|| ApiError::invalid("size_bytes required"))?;
            if disk.bound_cat_id.is_some() {
                return Err(ApiError::failed_precondition(
                    "v1 resize requires the disk to be Available",
                )
                .into());
            }
            if new_size < disk.size_bytes {
                return Err(ApiError::invalid("shrink is not supported").into());
            }
            let rounded = cats_api::chunk::round_up_to_chunk(new_size);
            state
                .storage_meta
                .resize_volume(&disk.volume_id, rounded)
                .map_err(|e| ApiError::failed_precondition(e.to_string()))?;
            state.store.set_disk_size(&disk.id, new_size)?;
            Ok(Json(state.store.get_disk(&workspace, &disk.id)?).into_response())
        }
        _ => Err(ApiError::invalid(format!("unknown disk action {verb}")).into()),
    }
}

pub(super) async fn hot_attach(
    state: &AppState,
    cat: &Cat,
    disk: &Disk,
    mount_path: &str,
) -> ApiResult<()> {
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "disk_attach", 120_000)?;
    let cat_id = cat.id.clone();
    let result = async {
        let cat = ensure_running(state, cat.clone()).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| Some(&n.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
        let size = cats_api::chunk::round_up_to_chunk(disk.size_bytes);
        match state.storage_meta.create_volume(&disk.volume_id, size) {
            Ok(()) | Err(cats_storage::MetaError::AlreadyExists(_)) => {}
            Err(e) => return Err(ApiError::internal(e.to_string()).into()),
        }
        let job = cats_api::nodejob::NodeJob {
            job_id: cats_api::nodejob::job_id(
                &cat.id,
                cat.generation,
                &format!("attach_{}", disk.id),
            ),
            cat_generation: cat.generation,
            action: cats_api::nodejob::NodeJobAction::AttachDisk {
                cat_id: cat.id.clone(),
                volume: cats_api::nodejob::VolumeGrant {
                    disk_id: disk.id.clone(),
                    volume_id: disk.volume_id.clone(),
                    attachment_id: format!("att_{}_{}_{}", cat.id, disk.id, cat.generation),
                    epoch: 0,
                    size_bytes: size,
                    mount_path: mount_path.to_string(),
                    durability: disk.durability,
                },
            },
        };
        dispatch_or_unavailable(state, &node.agent_url, &job).await
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result
}

pub(super) async fn hot_detach(state: &AppState, cat: &Cat, disk: &Disk) -> ApiResult<()> {
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "disk_detach", 120_000)?;
    let cat_id = cat.id.clone();
    let result = async {
        let cat = ensure_running(state, cat.clone()).await?;
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| Some(&n.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
        let job = cats_api::nodejob::NodeJob {
            job_id: cats_api::nodejob::job_id(
                &cat.id,
                cat.generation,
                &format!("detach_{}", disk.id),
            ),
            cat_generation: cat.generation,
            action: cats_api::nodejob::NodeJobAction::DetachDisk {
                cat_id: cat.id.clone(),
                disk_id: disk.id.clone(),
            },
        };
        dispatch_or_unavailable(state, &node.agent_url, &job).await
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result
}

/// Force every attached disk of a running cat to a remote durable point (ADR-0022):
/// guest page cache down through the engines, staged packs published. On a
/// Suspended cats can also be synced: they were syncfs'd before pause and their
/// frozen engines can be remotely drained without resuming. Warm/Cold cats have
/// already crossed a mandatory drain boundary.
pub(super) async fn sync_cat(state: &AppState, cat: &Cat) -> ApiResult<Response> {
    let cat = state.store.must_get_cat_by_id(&cat.id)?;
    if !matches!(
        cat.observed_state,
        ObservedState::Running | ObservedState::Suspended
    ) {
        return Ok((StatusCode::OK, Json(cat.clone())).into_response());
    }
    if state.store.lifecycle_dispatch(&cat.id)?.is_some()
        || state.store.observed_generation(&cat.id)? != cat.generation
    {
        state.notify.notify_one();
        return Err(ApiError::unavailable(
            "cat lifecycle generation is still converging; retry sync",
        )
        .into());
    }
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "cat_sync", 120_000)?;
    let result = async {
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|n| Some(&n.id) == cat.node_id.as_ref())
            .ok_or_else(|| ApiError::unavailable("cat node missing"))?;
        // The uuid keeps repeated syncs at one generation from replaying the
        // first run's journaled result: each call must actually drain.
        let job = cats_api::nodejob::NodeJob {
            job_id: cats_api::nodejob::job_id(
                &cat.id,
                cat.generation,
                &format!("sync_{}", uuid::Uuid::new_v4().simple()),
            ),
            cat_generation: cat.generation,
            action: cats_api::nodejob::NodeJobAction::SyncCat {
                cat_id: cat.id.clone(),
            },
        };
        dispatch_or_unavailable(state, &node.agent_url, &job).await
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    result?;
    Ok((
        StatusCode::OK,
        Json(state.store.must_get_cat_by_id(&cat.id)?),
    )
        .into_response())
}

pub(super) async fn dispatch_or_unavailable(
    state: &AppState,
    agent_url: &str,
    job: &cats_api::nodejob::NodeJob,
) -> ApiResult<()> {
    let resp = state
        .controller
        .http
        .post(format!("{}/v1/jobs", agent_url.trim_end_matches('/')))
        .bearer_auth(&state.cfg.auth_token)
        .json(job)
        .send()
        .await
        .map_err(|e| ApiError::unavailable(format!("node agent unreachable: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::unavailable(format!("node agent returned {}", resp.status())).into());
    }
    let result: cats_api::nodejob::NodeJobResult = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if result.phase != cats_api::nodejob::JobPhase::Succeeded {
        return Err(
            ApiError::unavailable(result.error.unwrap_or_else(|| "job failed".into())).into(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

pub(super) async fn create_snapshot(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Snapshot>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    if let Some(cat_id) = &disk.bound_cat_id {
        let cat = state.store.must_get_cat_by_id(cat_id)?;
        match cat.observed_state {
            ObservedState::Running | ObservedState::Suspended => {
                // Snapshot metadata must name the remote watermark, never an
                // older generation while acknowledged relaxed writes exist
                // only in a Host-local journal.
                sync_cat(&state, &cat).await?;
            }
            ObservedState::Warm | ObservedState::Cold => {}
            state => {
                return Err(ApiError::failed_precondition(format!(
                    "cannot snapshot disk while its cat is {state:?}"
                ))
                .into())
            }
        }
    }
    let snap_id = crate::store::new_id(cats_api::ids::SNAPSHOT_PREFIX);
    let row = state
        .storage_meta
        .create_snapshot(&snap_id, &disk.volume_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(Snapshot {
        id: row.snapshot_id,
        disk_id: disk.id,
        generation: row.generation,
        root_hash_hex: row.root_hash.map(hex_lower).unwrap_or_default(),
        created_at_unix: crate::store::now_unix(),
    }))
}

fn hex_lower(h: [u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) async fn list_snapshots(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<Snapshot>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state.store.get_disk(&workspace, &disk)?;
    let rows = state
        .storage_meta
        .list_snapshots(&disk.volume_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(ListResponse {
        items: rows
            .into_iter()
            .map(|r| Snapshot {
                id: r.snapshot_id,
                disk_id: disk.id.clone(),
                generation: r.generation,
                root_hash_hex: r.root_hash.map(hex_lower).unwrap_or_default(),
                created_at_unix: 0,
            })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Endpoints / routes
// ---------------------------------------------------------------------------

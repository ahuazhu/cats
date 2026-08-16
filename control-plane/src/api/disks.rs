use super::*;

fn retired_storage_meta(state: &AppState) -> ApiResult<&dyn cats_storage::MetadataStore> {
    #[cfg(debug_assertions)]
    {
        state
            .retired_storage_meta_for_tests
            .as_deref()
            .ok_or_else(|| ApiError::unavailable("legacy storage authority is not composed").into())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = state;
        Err(ApiError::unavailable("legacy storage authority is absent from release builds").into())
    }
}

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
    let size = cats_api::chunk::round_up_to_chunk(req.size_bytes);
    let workspace = scope.workspace;
    let disk = state
        .store
        .execute(move |store| {
            store.create_disk(&workspace, &req.name, req.size_bytes, req.durability)
        })
        .await?;
    // Create the storage volume eagerly so snapshots work before attachment.
    match retired_storage_meta(&state)?.create_volume(&disk.volume_id, size) {
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
    let items = state
        .store
        .execute(move |store| store.list_disks(&workspace))
        .await?;
    Ok(Json(ListResponse { items }))
}

pub(super) async fn get_disk(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Disk>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state
        .store
        .execute(move |store| store.get_disk(&workspace, &disk))
        .await?;
    Ok(Json(disk))
}

pub(super) async fn delete_disk(
    State(state): State<AppState>,
    Path((workspace, disk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let disk = state
        .store
        .execute(move |store| store.get_disk(&workspace, &disk))
        .await?;
    if disk.kind == DiskKind::Root {
        return Err(ApiError::failed_precondition("root disks are deleted with their cat").into());
    }
    if disk.bound_cat_id.is_some() {
        return Err(ApiError::failed_precondition("disk must be Available").into());
    }
    match retired_storage_meta(&state)?.delete_volume(&disk.volume_id) {
        Ok(()) | Err(cats_storage::MetaError::NotFound(_)) => {}
        Err(e) => return Err(ApiError::internal(e.to_string()).into()),
    }
    let disk_id = disk.id;
    state
        .store
        .execute(move |store| store.delete_disk_row(&disk_id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Force every attached disk of a running cat to a remote durable point (ADR-0022):
/// guest page cache down through the engines, staged packs published. On a
/// Suspended cats can also be synced: they were syncfs'd before pause and their
/// frozen engines can be remotely drained without resuming. Warm/Cold cats have
/// already crossed a mandatory drain boundary.
pub(super) async fn sync_cat(state: &AppState, cat: &Cat) -> ApiResult<Response> {
    if !matches!(
        cat.observed_state,
        ObservedState::Running | ObservedState::Suspended
    ) {
        return Ok((StatusCode::OK, Json(cat.clone())).into_response());
    }
    let owner = format!("control_{}", uuid::Uuid::new_v4().simple());
    let lease_cat_id = cat.id.clone();
    let lease = state
        .store
        .execute(move |store| {
            store.acquire_work(
                &lease_cat_id,
                WorkKind::Control,
                &owner,
                "cat_sync",
                120_000,
            )
        })
        .await?;
    let result = async {
        let node_id = cat.node_id.clone();
        let node = state
            .store
            .execute(move |store| {
                Ok(store
                    .list_nodes()?
                    .into_iter()
                    .find(|node| Some(&node.id) == node_id.as_ref()))
            })
            .await?
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
    let lease_id = lease.id;
    let _ = state
        .store
        .execute(move |store| store.release_work(&lease_id))
        .await;
    result?;
    let cat_id = cat.id.clone();
    let cat = state
        .store
        .execute(move |store| store.must_get_cat_by_id(&cat_id))
        .await?;
    Ok((StatusCode::OK, Json(cat)).into_response())
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
    require_retired_product_authority_for_tests(&state)?;
    check_workspace_auth(&state, &headers, &workspace).await?;
    let (disk, bound_cat) = state
        .store
        .execute(move |store| {
            let disk = store.get_disk(&workspace, &disk)?;
            let cat = disk
                .bound_cat_id
                .as_deref()
                .map(|cat_id| store.must_get_cat_by_id(cat_id))
                .transpose()?;
            Ok((disk, cat))
        })
        .await?;
    if let Some(cat) = bound_cat {
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
    let row = retired_storage_meta(&state)?
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
    let disk = state
        .store
        .execute(move |store| store.get_disk(&workspace, &disk))
        .await?;
    let rows = retired_storage_meta(&state)?
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

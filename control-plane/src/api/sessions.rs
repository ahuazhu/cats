use super::*;

pub(super) async fn exec_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<ExecResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state
        .store
        .execute(move |store| store.get_cat(&workspace, &cat))
        .await?;
    if req.command.is_empty() {
        return Err(ApiError::invalid("command must be a non-empty argv array").into());
    }
    let owner = format!("exec_{}", uuid::Uuid::new_v4().simple());
    let cat_id = cat.id.clone();
    // Bounds both the work lease and the transport timeout below, so a caller
    // asking for a long-running command gets one instead of a 60 s transport
    // failure. Note the Guest agent does not enforce it: a runaway command keeps
    // running there until the Cat is stopped.
    let ttl_ms = req.timeout_ms.unwrap_or(120_000).clamp(1_000, 3_600_000);
    // Guarded because an exec can outlive its caller too: an intermediary idle
    // timeout drops this future, and a release call placed after the awaited
    // work would never run, leaking the lease for its whole TTL.
    let lease_cat_id = cat.id.clone();
    let lease_owner = owner.clone();
    let _lease = state
        .store
        .execute(move |store| {
            store.acquire_work_guarded(&lease_cat_id, WorkKind::Exec, &lease_owner, "exec", ttl_ms)
        })
        .await?;
    let result: ApiResult<ExecResponse> = async {
        let mut cat = cat;
        let mut retried_suspend_conflict = false;
        loop {
            // Shell/exec always wakes (arch doc §8.2). An exec that reaches
            // the node while its suspend gate is closing gets a transient
            // 409 and cancels that suspend. Wait for the control plane to
            // observe Running again, then retry the exec once.
            cat = ensure_running(&state, cat).await?;
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
                .ok_or_else(|| ApiError::unavailable("cat has no live node"))?;
            let url = format!(
                "{}/v1/cats/{}/exec",
                node.agent_url.trim_end_matches('/'),
                cat.id
            );
            let resp = state
                .controller
                .http
                .post(url)
                // The shared client carries a 60 s timeout meant for node job
                // dispatch, which is shorter than the exec timeout this handler
                // already accepted (`timeout_ms`, 120 s by default). Without this
                // override a command that runs longer than 60 s fails in transport
                // while its work lease is still valid -- measured: fio write
                // workloads returned nothing at all, and `sleep 70` failed.
                .timeout(Duration::from_millis(ttl_ms) + Duration::from_secs(15))
                .bearer_auth(&state.cfg.auth_token)
                .json(&req)
                .send()
                .await
                .map_err(|e| ApiError::unavailable(format!("node agent unreachable: {e}")))?;
            let status = resp.status();
            if status.is_success() {
                break resp
                    .json::<ExecResponse>()
                    .await
                    .map_err(|e| ApiError::internal(format!("bad exec response: {e}")).into());
            }
            if status == StatusCode::CONFLICT && !retried_suspend_conflict {
                retried_suspend_conflict = true;
                continue;
            }
            let detail = resp.text().await.unwrap_or_default();
            let detail = detail.trim();
            let message = if detail.is_empty() {
                format!("exec failed: {status}")
            } else {
                format!("exec failed: {detail}")
            };
            break Err(ApiError::unavailable(message).into());
        }
    }
    .await;
    drop(_lease);
    let _ = state.controller.maybe_auto_suspend(&cat_id).await;
    result.map(Json)
}

/// How often the handler re-reads the operation it is waiting on. A deploy runs
/// for tens of seconds at least, so this only bounds the reply's latency.
const OCI_DEPLOY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The applications currently deployed in a Cat.
///
/// This is how a caller that received `202` collects the result: poll the
/// operation until it is terminal, then read the deployment here. Re-sending
/// the original request works too -- it replays -- but a read should not have
/// to be a write.
pub(super) async fn list_oci_deployments(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<ListResponse<OciDeployment>>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let items = state
        .store
        .execute(move |store| {
            let cat = store.get_cat(&workspace, &cat)?;
            store.list_oci_deployments(&cat.id)
        })
        .await?;
    Ok(Json(ListResponse { items }))
}

#[derive(Debug, Deserialize)]
pub(super) struct DeployOciQuery {
    /// How long to hold the response open before answering with an operation.
    /// `0` answers `202` immediately; omitted uses the configured default.
    /// Clamped to the configured maximum, which is what keeps a caller from
    /// asking for a wait longer than the edge in front of Cats will allow.
    wait_ms: Option<u64>,
}

/// Deploy one OCI application into a Cat.
///
/// The deploy outlives its request. It is driven by a detached task keyed on
/// `(cat, app, digest)`, so a caller that goes away -- an idle timeout at an
/// intermediary needs only 60 s -- neither cancels the work nor loses it: the
/// deployment record holds the outcome and the retry finds it.
///
/// Answers `200` with the deployment when it finishes inside the wait, and
/// `202` with an `Operation` when it does not. Both are successes; a caller
/// that predates operations sees only the `200` it already handled, as long as
/// its deploys finish inside the wait.
pub(super) async fn deploy_oci(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    Query(query): Query<DeployOciQuery>,
    headers: HeaderMap,
    Json(request): Json<DeployOciRequest>,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state
        .store
        .execute(move |store| store.get_cat(&workspace, &cat))
        .await?;
    // Reject a reference Cats cannot make an identity out of before claiming
    // anything: without a pinned digest there is nothing to be idempotent on.
    // The Guest reports the specific defect for anything subtler than this.
    let image_digest = cats_api::oci::pinned_digest(&request.image)
        .ok_or_else(|| {
            ApiError::invalid(
                "image must be pinned by digest, as <reference>@sha256:<64 hex lowercase>",
            )
        })?
        .to_string();
    let max_wait_ms = state.cfg.oci_deploy_sync_wait_ms;
    let wait = Duration::from_millis(query.wait_ms.unwrap_or(max_wait_ms).min(max_wait_ms));

    let claim_cat = cat.clone();
    let claim_app = request.app.clone();
    let claim_digest = image_digest.clone();
    let claim = state
        .store
        .execute(move |store| store.claim_oci_deployment(&claim_cat, &claim_app, &claim_digest))
        .await?;
    let operation = match claim {
        // Same cat, same app, same digest, already deployed. Answering from
        // the record is the point: re-running activation would restart a
        // service that is already running the requested image.
        OciDeploymentClaim::Replay {
            operation,
            deployment,
        } => {
            tracing::info!(
                cat = %cat.id, app = %request.app, operation = %operation.id,
                "replaying an OCI deployment that already succeeded"
            );
            return Ok((StatusCode::OK, Json(deployment)).into_response());
        }
        // A concurrent request already owns this identity. Wait on it rather
        // than starting a second pull, flatten and restart.
        OciDeploymentClaim::AlreadyRunning {
            operation,
            record_id,
        } => {
            tracing::info!(
                cat = %cat.id, app = %request.app, operation = %operation.id,
                record = %record_id,
                "joining an OCI deployment that is already in flight"
            );
            operation
        }
        OciDeploymentClaim::Claimed {
            operation,
            record_id,
            lease,
        } => {
            spawn_oci_deploy(
                &state,
                &cat,
                request,
                record_id,
                operation.id.clone(),
                lease,
            )
            .await?;
            operation
        }
    };

    await_oci_deployment(&state, &operation.id, wait).await
}

/// Drive a claimed deploy to a terminal phase in a detached task.
///
/// Detached on purpose: the work must not be cancellable by the caller
/// disappearing, and it must be able to outlive the response. The task owns the
/// work lease, so the lease covers the deploy rather than the request, and is
/// released by `Drop` when the task ends however it ends.
///
/// The request -- which carries one-pull registry credentials -- is moved into
/// the task and never persisted, which is also why an interrupted deploy is
/// failed at startup rather than resumed.
async fn spawn_oci_deploy(
    state: &AppState,
    cat: &Cat,
    request: DeployOciRequest,
    record_id: String,
    operation_id: String,
    owner_fence: Box<crate::store::OciDeploymentLease>,
) -> ApiResult<()> {
    let owner = format!("deploy_{}", uuid::Uuid::new_v4().simple());
    // Registry transfer + layer extraction can legitimately take minutes.
    // Holding explicit work prevents auto-suspend from racing the deployment.
    let ttl_ms = 3_600_000;
    let lease_cat_id = cat.id.clone();
    let operation_to_start = operation_id.clone();
    let lease = state
        .store
        .execute(move |store| {
            let lease = store.acquire_work_guarded(
                &lease_cat_id,
                WorkKind::Control,
                &owner,
                "oci-deploy",
                ttl_ms,
            )?;
            store.start_operation(&operation_to_start)?;
            Ok(lease)
        })
        .await?;
    let state = state.clone();
    let cat = cat.clone();
    tokio::spawn(async move {
        // Bind the lease to this task, not to the request that started it.
        let _lease = lease;
        // This PostgreSQL session lock is the cross-replica ownership fence.
        // Losing it lets another replica fail/retry the attempt; the
        // operation-id predicate below prevents this task from publishing a
        // late result after that takeover.
        let _owner_fence = owner_fence;
        let app = request.app.clone();
        let outcome = drive_oci_deploy(&state, cat.clone(), request, ttl_ms).await;
        let result_record_id = record_id.clone();
        let result_operation_id = operation_id.clone();
        let recorded = match &outcome {
            Ok(deployment) => {
                let deployment = deployment.clone();
                state
                    .store
                    .execute(move |store| {
                        store.succeed_oci_deployment(
                            &result_record_id,
                            &result_operation_id,
                            &deployment,
                        )
                    })
                    .await
            }
            Err(error) => {
                let error = ErrorBody::new(error.code, &error.message);
                state
                    .store
                    .execute(move |store| {
                        store.fail_oci_deployment(&result_record_id, &result_operation_id, &error)
                    })
                    .await
            }
        };
        match (&outcome, recorded) {
            (Ok(_), Ok(true)) => {
                tracing::info!(cat = %cat.id, app = %app, "OCI deployment succeeded")
            }
            (Err(error), Ok(true)) => {
                tracing::warn!(cat = %cat.id, app = %app, "OCI deployment failed: {}", error.message)
            }
            (_, Ok(false)) => tracing::warn!(
                cat = %cat.id, app = %app, record = %record_id,
                operation = %operation_id,
                "discarded an OCI deployment result after ownership was lost"
            ),
            // The deploy resolved but its outcome did not reach the store, so
            // the record stays `running` and no poller can ever see the answer.
            // Startup convergence is the backstop; say so loudly meanwhile.
            (_, Err(write_error)) => tracing::error!(
                cat = %cat.id, app = %app, record = %record_id,
                "recording the OCI deployment outcome failed: {write_error}"
            ),
        }
        let _ = state.controller.maybe_auto_suspend(&cat.id).await;
    });
    Ok(())
}

/// One deploy attempt against the Cat's node, waking it if necessary.
async fn drive_oci_deploy(
    state: &AppState,
    cat: Cat,
    request: DeployOciRequest,
    ttl_ms: u64,
) -> std::result::Result<OciDeployment, ApiError> {
    let mut cat = cat;
    let mut retried_suspend_conflict = false;
    loop {
        cat = ensure_running(state, cat)
            .await
            .map_err(|failure| failure.0)?;
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
            .ok_or_else(|| ApiError::unavailable("cat has no live node"))?;
        let url = format!(
            "{}/v1/cats/{}/oci-deployments",
            node.agent_url.trim_end_matches('/'),
            cat.id
        );
        let response = state
            .controller
            .http
            .post(url)
            .timeout(Duration::from_millis(ttl_ms) + Duration::from_secs(15))
            .bearer_auth(&state.cfg.auth_token)
            .json(&request)
            .send()
            .await
            .map_err(|error| ApiError::unavailable(format!("node agent unreachable: {error}")))?;
        let status = response.status();
        if status.is_success() {
            return response.json::<OciDeployment>().await.map_err(|error| {
                ApiError::internal(format!("bad OCI deployment response: {error}"))
            });
        }
        if status == StatusCode::CONFLICT && !retried_suspend_conflict {
            retried_suspend_conflict = true;
            continue;
        }
        let detail = response.text().await.unwrap_or_default();
        let message = if detail.trim().is_empty() {
            format!("OCI deployment failed: {status}")
        } else {
            format!("OCI deployment failed: {}", detail.trim())
        };
        return Err(ApiError::unavailable(message));
    }
}

/// Wait for a deploy operation to reach a terminal phase, up to `wait`.
///
/// Polls the record rather than joining the task, so a request that merely
/// joined an in-flight deploy waits the same way the request that started it
/// does -- including across a caller that reconnects.
async fn await_oci_deployment(
    state: &AppState,
    operation_id: &str,
    wait: Duration,
) -> ApiResult<Response> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let query_operation_id = operation_id.to_string();
        let operation = state
            .store
            .execute(move |store| store.get_operation(&query_operation_id))
            .await?;
        match operation.phase {
            OperationPhase::Succeeded => {
                let query_operation_id = operation_id.to_string();
                let deployment = state
                    .store
                    .execute(move |store| store.oci_deployment_for_operation(&query_operation_id))
                    .await?
                    .ok_or_else(|| {
                        ApiError::internal("succeeded OCI deployment is missing its result")
                    })?;
                return Ok((StatusCode::OK, Json(deployment)).into_response());
            }
            OperationPhase::Failed => {
                let error = operation.error.unwrap_or_else(|| {
                    ErrorBody::new(ErrorCode::Unavailable, "OCI deployment failed")
                });
                return Err(ApiError::new(error.code, error.message).into());
            }
            OperationPhase::Pending | OperationPhase::Running => {}
        }
        if tokio::time::Instant::now() >= deadline {
            // Not an error: the deploy is still running and its outcome is
            // durable. The caller polls the operation instead of retrying,
            // which is what stops a retry from restarting the service.
            let query_operation_id = operation_id.to_string();
            let deployment = state
                .store
                .execute(move |store| store.oci_deployment_for_operation(&query_operation_id))
                .await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(OciDeploymentOperationResponse {
                    operation,
                    deployment,
                }),
            )
                .into_response());
        }
        tokio::time::sleep(OCI_DEPLOY_POLL_INTERVAL).await;
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ShellQuery {
    #[serde(default = "default_terminal_rows")]
    rows: u16,
    #[serde(default = "default_terminal_cols")]
    cols: u16,
}

fn default_terminal_rows() -> u16 {
    24
}

fn default_terminal_cols() -> u16 {
    80
}

pub(super) async fn shell_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    Query(query): Query<ShellQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    if !(1..=1_000).contains(&query.rows) || !(1..=1_000).contains(&query.cols) {
        return Err(ApiError::invalid("terminal dimensions must be in 1..=1000").into());
    }
    let cat = state
        .store
        .execute(move |store| store.get_cat(&workspace, &cat))
        .await?;
    let owner = format!("shell_{}", uuid::Uuid::new_v4().simple());
    let lease_cat_id = cat.id.clone();
    let lease_owner = owner.clone();
    let lease = state
        .store
        .execute(move |store| {
            store.acquire_work(
                &lease_cat_id,
                WorkKind::Exec,
                &lease_owner,
                "shell",
                120_000,
            )
        })
        .await?;
    state.notify.notify_one();
    let cat_id = cat.id.clone();

    let prepared = prepare_node_shell(&state, cat, query.rows, query.cols).await;
    let node_socket = match prepared {
        Ok(socket) => socket,
        Err(error) => {
            let lease_id = lease.id;
            let _ = state
                .store
                .execute(move |store| store.release_work(&lease_id))
                .await;
            let _ = state.controller.maybe_auto_suspend(&cat_id).await;
            return Err(error);
        }
    };
    let cleanup_state = state.clone();
    Ok(ws
        .max_message_size(MAX_SHELL_MESSAGE_BYTES)
        .max_frame_size(MAX_SHELL_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            proxy_shell(
                socket,
                node_socket,
                cleanup_state.clone(),
                cat_id.clone(),
                owner,
            )
            .await;
            let lease_id = lease.id;
            let _ = cleanup_state
                .store
                .execute(move |store| store.release_work(&lease_id))
                .await;
            let _ = cleanup_state.controller.maybe_auto_suspend(&cat_id).await;
        }))
}

pub(super) async fn prepare_node_shell(
    state: &AppState,
    mut cat: Cat,
    rows: u16,
    cols: u16,
) -> ApiResult<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut retried_suspend_conflict = false;
    loop {
        cat = ensure_running(state, cat).await?;
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
            .ok_or_else(|| ApiError::unavailable("cat has no live node"))?;
        let mut url = reqwest::Url::parse(node.agent_url.trim_end_matches('/'))
            .map_err(|error| ApiError::internal(format!("invalid node agent URL: {error}")))?;
        url.set_scheme(match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => return Err(ApiError::internal("node agent URL must use http or https").into()),
        })
        .map_err(|_| ApiError::internal("invalid node WebSocket URL"))?;
        url.set_path(&format!("/v1/cats/{}/shell", cat.id));
        url.set_query(Some(&format!("rows={rows}&cols={cols}")));
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|error| ApiError::internal(format!("build node shell request: {error}")))?;
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", state.cfg.auth_token))
                .map_err(|_| ApiError::internal("invalid service authorization header"))?,
        );
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => return Ok(socket),
            Err(tokio_tungstenite::tungstenite::Error::Http(response))
                if response.status() == StatusCode::CONFLICT && !retried_suspend_conflict =>
            {
                retried_suspend_conflict = true;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // The node explains itself in the response body -- which Cat, which
            // state, which node. Tungstenite's Display prints only the status
            // line, so pass the body through or the caller sees one opaque 503
            // wrapped in another.
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                let status = response.status();
                let body = response
                    .into_body()
                    .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
                    .unwrap_or_default();
                let detail = if body.is_empty() {
                    format!("node shell connection failed: HTTP {status}")
                } else {
                    format!("node shell connection failed: HTTP {status}: {body}")
                };
                return Err(ApiError::unavailable(detail).into());
            }
            Err(error) => {
                return Err(
                    ApiError::unavailable(format!("node shell connection failed: {error}")).into(),
                )
            }
        }
    }
}

pub(super) async fn proxy_shell(
    client: WebSocket,
    node: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    state: AppState,
    cat_id: String,
    owner: String,
) {
    let (mut client_sender, mut client_receiver) = client.split();
    let (mut node_sender, mut node_receiver) = node.split();
    let mut renewal = tokio::time::interval(Duration::from_secs(30));
    renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renewal.tick().await;

    loop {
        tokio::select! {
            incoming = client_receiver.next() => {
                let Some(Ok(message)) = incoming else { break };
                let message = match message {
                    Message::Text(text) => {
                        tokio_tungstenite::tungstenite::Message::Text(text.to_string().into())
                    }
                    Message::Binary(data) => tokio_tungstenite::tungstenite::Message::Binary(data),
                    Message::Ping(data) => tokio_tungstenite::tungstenite::Message::Ping(data),
                    Message::Pong(data) => tokio_tungstenite::tungstenite::Message::Pong(data),
                    Message::Close(_) => tokio_tungstenite::tungstenite::Message::Close(None),
                };
                if node_sender.send(message).await.is_err() {
                    break;
                }
            }
            outgoing = node_receiver.next() => {
                let Some(Ok(message)) = outgoing else { break };
                let message = match message {
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        Message::Text(text.to_string().into())
                    }
                    tokio_tungstenite::tungstenite::Message::Binary(data) => Message::Binary(data),
                    tokio_tungstenite::tungstenite::Message::Ping(data) => Message::Ping(data),
                    tokio_tungstenite::tungstenite::Message::Pong(data) => Message::Pong(data),
                    tokio_tungstenite::tungstenite::Message::Close(_) => Message::Close(None),
                    tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
                };
                if client_sender.send(message).await.is_err() {
                    break;
                }
            }
            _ = renewal.tick() => {
                let renewal_cat_id = cat_id.clone();
                let renewal_owner = owner.clone();
                if let Err(error) = state.store.execute(move |store| {
                    store.acquire_work(
                        &renewal_cat_id,
                        WorkKind::Exec,
                        &renewal_owner,
                        "shell",
                        120_000,
                    )
                }).await {
                    tracing::warn!(cat_id, error = %error, "shell work lease renewal failed");
                    break;
                }
            }
        }
    }
    let _ = node_sender
        .send(tokio_tungstenite::tungstenite::Message::Close(None))
        .await;
}

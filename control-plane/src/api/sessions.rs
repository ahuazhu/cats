use super::*;

pub(super) async fn exec_cat(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<ExecResponse>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
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
    let lease = state
        .store
        .acquire_work(&cat.id, WorkKind::Exec, &owner, "exec", ttl_ms)?;
    let result: ApiResult<ExecResponse> = async {
        let mut cat = cat;
        let mut retried_suspend_conflict = false;
        loop {
            // Shell/exec always wakes (arch doc §8.2). An exec that reaches
            // the node while its suspend gate is closing gets a transient
            // 409 and cancels that suspend. Wait for the control plane to
            // observe Running again, then retry the exec once.
            cat = ensure_running(&state, cat).await?;
            let node = state
                .store
                .list_nodes()?
                .into_iter()
                .find(|n| Some(&n.id) == cat.node_id.as_ref())
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
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result.map(Json)
}

pub(super) async fn deploy_oci(
    State(state): State<AppState>,
    Path((workspace, cat)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<DeployOciRequest>,
) -> ApiResult<Json<OciDeployment>> {
    check_workspace_auth(&state, &headers, &workspace).await?;
    let cat = state.store.get_cat(&workspace, &cat)?;
    let owner = format!("deploy_{}", uuid::Uuid::new_v4().simple());
    let cat_id = cat.id.clone();
    // Registry transfer + layer extraction can legitimately take minutes.
    // Holding explicit work prevents auto-suspend from racing the deployment.
    let ttl_ms = 3_600_000;
    let lease =
        state
            .store
            .acquire_work(&cat.id, WorkKind::Control, &owner, "oci-deploy", ttl_ms)?;
    let result: ApiResult<OciDeployment> = async {
        let mut cat = cat;
        let mut retried_suspend_conflict = false;
        loop {
            cat = ensure_running(&state, cat).await?;
            let node = state
                .store
                .list_nodes()?
                .into_iter()
                .find(|node| Some(&node.id) == cat.node_id.as_ref())
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
                .map_err(|error| {
                    ApiError::unavailable(format!("node agent unreachable: {error}"))
                })?;
            let status = response.status();
            if status.is_success() {
                break response.json::<OciDeployment>().await.map_err(|error| {
                    ApiError::internal(format!("bad OCI deployment response: {error}")).into()
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
            break Err(ApiError::unavailable(message).into());
        }
    }
    .await;
    let _ = state.store.release_work(&lease.id);
    let _ = state.controller.maybe_auto_suspend(&cat_id);
    result.map(Json)
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
    let cat = state.store.get_cat(&workspace, &cat)?;
    let owner = format!("shell_{}", uuid::Uuid::new_v4().simple());
    let lease = state
        .store
        .acquire_work(&cat.id, WorkKind::Exec, &owner, "shell", 120_000)?;
    state.notify.notify_one();
    let cat_id = cat.id.clone();

    let prepared = prepare_node_shell(&state, cat, query.rows, query.cols).await;
    let node_socket = match prepared {
        Ok(socket) => socket,
        Err(error) => {
            let _ = state.store.release_work(&lease.id);
            let _ = state.controller.maybe_auto_suspend(&cat_id);
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
            let _ = cleanup_state.store.release_work(&lease.id);
            let _ = cleanup_state.controller.maybe_auto_suspend(&cat_id);
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
        let node = state
            .store
            .list_nodes()?
            .into_iter()
            .find(|node| Some(&node.id) == cat.node_id.as_ref())
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
                if let Err(error) = state.store.acquire_work(
                    &cat_id,
                    WorkKind::Exec,
                    &owner,
                    "shell",
                    120_000,
                ) {
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

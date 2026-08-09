//! End-to-end tests: real control plane + two node agents (FakeVmm, real
//! cats-blockd children) + gateway, driven through the real `cats` CLI
//! binary. Covers the minimal production acceptance scenarios from the
//! architecture doc §20.1 that are meaningful without KVM.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::guest::{GuestRequestBody, GuestResponseBody};
use cats_api::requests::{HeartbeatCat, HeartbeatRequest};
use cats_api::resources::NodeState;
use cats_api::runtime_reconciliation::{
    ContractVersion, CredentialBinding, Id, NodeBootId, NodeIdentity, NodeIdentityState,
};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::SqliteUsageStore;
use cats_node_agent::agent_registration::AgentRegistrationConfig;
use cats_node_agent::guest_client::GuestClient;
use cats_node_agent::server::{spawn as spawn_node, Handle as NodeHandle, ServerConfig};
use cats_object_store_file::FileBlobStore;
use cats_storage::{AdapterConfig, AdapterSelection, MetadataStore};
use cats_test_support::{fake_node_config, workspace_bin, NodeConfigBuilder};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const SERVICE_TOKEN: &str = "dev-service-token";
const ADMIN_TOKEN: &str = "dev-admin-token";
const ROUTE_GRANT_PRIVATE_KEY: &[u8] =
    include_bytes!("../fixtures/route_grant_private_ed25519.pem");
const ROUTE_GRANT_PUBLIC_KEY: &[u8] = include_bytes!("../fixtures/route_grant_public_ed25519.pem");

struct Cluster {
    dir: tempfile::TempDir,
    cp: cats_control_plane::server::Handle,
    gateway: cats_network::Handle,
    nodes: Vec<NodeHandle>,
    http: reqwest::Client,
    cli_bin: PathBuf,
    /// The bootstrap Account's default Workspace; resource routes key on its ID.
    workspace_id: String,
}

impl Cluster {
    async fn start(node_ids: &[&str]) -> Cluster {
        let dir = tempfile::tempdir().unwrap();
        let storage_meta_path = dir.path().join("storage-meta.db");
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&storage_meta_path).unwrap());
        let cp = cats_control_plane::server::spawn_with_legacy_heartbeat_for_tests(
            cats_control_plane::server::Config {
                listen: "127.0.0.1:0".into(),
                control_store_dsn: cats_control_plane::store::DsnSource::Literal(
                    cats_control_plane::testsupport::isolated_control_store_url(),
                ),
                control_store_ca_file: None,
                usage_store: Arc::new(
                    SqliteUsageStore::open(&dir.path().join("control.db")).unwrap(),
                ),
                credit_store: Arc::new(
                    SqliteUsageStore::open(&dir.path().join("control.db")).unwrap(),
                ),
                storage_meta,
                image_blob: Arc::new(FileBlobStore::open(dir.path().join("image-blob")).unwrap()),
                auth_token: SERVICE_TOKEN.into(),
                guest_runtime_profile_receipt:
                    cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
                route_grant_signer: Arc::new(
                    cats_control_plane::route_grant::RouteGrantSigner::from_ed25519_pem(
                        ROUTE_GRANT_PRIVATE_KEY,
                        ROUTE_GRANT_PUBLIC_KEY,
                        2,
                    )
                    .unwrap(),
                ),
                admin_token: ADMIN_TOKEN.into(),
                workos: None,
                stripe: None,
                billing_enforcement_enabled: false,
                node_lease_timeout_ms: 3_000,
                reconcile_interval_ms: 150,
                oci_deploy_sync_wait_ms: 5_000,
                auto_tier_policy: Default::default(),
            },
        )
        .await
        .unwrap();

        let gateway = cats_network::spawn(cats_network::GatewayConfig {
            listen: "127.0.0.1:0".into(),
            control_plane_url: cp.base_url(),
            auth_token: SERVICE_TOKEN.into(),
            cache_ttl_ms: 500,
            shared_route_cache_table: None,
        })
        .await
        .unwrap();

        let mut nodes = Vec::new();
        for id in node_ids {
            nodes.push(Self::start_node(&dir, &cp, &gateway, id).await);
        }
        let workspace_id = cp
            .state
            .store
            .list_all_workspace_views()
            .unwrap()
            .into_iter()
            .find(|workspace| workspace.is_default)
            .expect("the bootstrap account has a default workspace")
            .id;
        Cluster {
            dir,
            cp,
            gateway,
            nodes,
            http: reqwest::Client::new(),
            cli_bin: workspace_bin("cats"),
            workspace_id,
        }
    }

    async fn start_node(
        dir: &tempfile::TempDir,
        cp: &cats_control_plane::server::Handle,
        gateway: &cats_network::Handle,
        id: &str,
    ) -> NodeHandle {
        let meta_path = dir.path().join("storage-meta.db");
        let metadata_store = AdapterSelection {
            name: "sqlite".into(),
            config: AdapterConfig::from_pairs([("path", meta_path.display().to_string())]).unwrap(),
        };
        let object_store = AdapterSelection {
            name: "file".into(),
            config: AdapterConfig::from_pairs([(
                "root",
                dir.path().join("blob").display().to_string(),
            )])
            .unwrap(),
        };
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&meta_path).unwrap());
        let signer = Ed25519RequestSigner::from_pkcs8_pem(
            Id::new(format!("credential_{id}")).unwrap(),
            ROUTE_GRANT_PRIVATE_KEY,
        )
        .unwrap();
        let identity = NodeIdentity {
            version: ContractVersion::V1,
            node_id: Id::new(id.to_string()).unwrap(),
            immutable_host_id: Id::new(format!("host_{id}")).unwrap(),
            credential_id: signer.credential_id().clone(),
            credential_binding: CredentialBinding::PublicKey {
                public_key_spki_sha256: signer.public_key_spki_sha256(),
            },
            state_path_id: Id::new(format!("state_{id}")).unwrap(),
            state: NodeIdentityState::Provisioned,
        };
        cats_control_plane::testsupport::provision_node_identity(&cp.state.store, identity.clone())
            .await;
        // Each fixture Node represents a distinct physical Host. Give each
        // one its own fixed state parent so the production Host-global parent
        // lock does not incorrectly model both simulated Hosts as one.
        let state_dir = dir.path().join(format!("h{id}")).join("s");
        let registration = AgentRegistrationConfig::for_loopback_test(
            identity,
            signer,
            state_dir.clone(),
            NodeBootId::new(format!(
                "{:032x}",
                id.bytes().map(u128::from).sum::<u128>() + 1
            ))
            .unwrap(),
            &cats_control_plane::testsupport::test_guest_runtime_profile_receipt(),
        )
        .unwrap();
        let route_grant_verifier = Arc::new(
            cats_node_agent::route_grant::RouteGrantVerifier::from_ed25519_pem(
                ROUTE_GRANT_PUBLIC_KEY,
            )
            .unwrap(),
        );
        let mut node_config = fake_node_config!(NodeConfigBuilder::new(dir.path(), id.to_string())
            .with_state_dir(state_dir)
            .with_metadata_store(metadata_store)
            .with_object_store(object_store));
        node_config.state_dir = registration.runtime_state_directory();
        let node = spawn_node(ServerConfig {
            listen: "127.0.0.1:0".into(),
            control_plane_url: cp.base_url(),
            auth_token: SERVICE_TOKEN.into(),
            agent_registration: registration,
            route_grant_verifier: route_grant_verifier.clone(),
            heartbeat_ms: 300,
            storage_meta,
            node: node_config,
        })
        .await
        .unwrap();
        cats_control_plane::testsupport::register_legacy_test_node(
            &cp.state.store,
            id.to_string(),
            node.base_url(),
            gateway.base_url(),
            16,
            32_768,
            route_grant_verifier.public_key_sha256().to_string(),
        )
        .await;
        let runtime = node.state.runtime.clone();
        let node_health = format!("{}/healthz", node.base_url());
        let cp_heartbeat = format!("{}/v1/nodes/heartbeat", cp.base_url());
        let node_id = id.to_string();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                tokio::time::sleep(Duration::from_millis(300)).await;
                if client.get(&node_health).send().await.is_err() {
                    break;
                }
                let cats = runtime
                    .snapshot()
                    .into_iter()
                    .map(|(cat_id, generation, state)| HeartbeatCat {
                        cat_id,
                        generation,
                        state,
                    })
                    .collect();
                let _ = client
                    .post(&cp_heartbeat)
                    .bearer_auth(SERVICE_TOKEN)
                    .json(&HeartbeatRequest {
                        node_id: node_id.clone(),
                        cats,
                        telemetry: None,
                    })
                    .send()
                    .await;
            }
        });
        node
    }

    /// Run the real `cats` binary; returns (exit_ok, stdout, stderr).
    async fn cli(&self, args: &[&str]) -> (bool, String, String) {
        self.cli_with_token(args, ADMIN_TOKEN).await
    }

    async fn cli_with_token(&self, args: &[&str], token: &str) -> (bool, String, String) {
        let bin = self.cli_bin.clone();
        let api = self.cp.base_url();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let token = token.to_string();
        tokio::task::spawn_blocking(move || {
            let out = Command::new(bin)
                .args(&args)
                .env("CATS_API_URL", api)
                .env("CATS_TOKEN", token)
                .env("CATS_WORKSPACE", "default")
                .output()
                .expect("run cats CLI");
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        })
        .await
        .unwrap()
    }

    async fn cli_ok(&self, args: &[&str]) -> String {
        let (ok, stdout, stderr) = self.cli(args).await;
        assert!(
            ok,
            "cats {args:?} failed:\nstdout: {stdout}\nstderr: {stderr}"
        );
        stdout
    }

    async fn cli_with_input(&self, args: &[&str], input: &[u8]) -> (bool, String, String) {
        let bin = self.cli_bin.clone();
        let api = self.cp.base_url();
        let args: Vec<String> = args.iter().map(|value| value.to_string()).collect();
        let input = input.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(bin)
                .args(&args)
                .env("CATS_API_URL", api)
                .env("CATS_TOKEN", ADMIN_TOKEN)
                .env("CATS_WORKSPACE", "default")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run cats CLI");
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(&input)
                .expect("write cats CLI stdin");
            let output = child.wait_with_output().expect("wait for cats CLI");
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
        })
        .await
        .unwrap()
    }

    async fn admin_cli_ok(&self, args: &[&str]) -> String {
        let (ok, stdout, stderr) = self.cli_with_token(args, ADMIN_TOKEN).await;
        assert!(
            ok,
            "cats {args:?} failed:\nstdout: {stdout}\nstderr: {stderr}"
        );
        stdout
    }

    async fn api_get(&self, path: &str) -> serde_json::Value {
        self.http
            .get(format!("{}{}", self.cp.base_url(), path))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn cordon(&self, node: &str) {
        let resp = self
            .http
            .post(format!(
                "{}/v1/nodes/{node}/actions/cordon",
                self.cp.base_url()
            ))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    async fn cat_json(&self, name: &str) -> serde_json::Value {
        self.api_get(&format!("/v1/workspaces/{}/cats/{name}", self.workspace_id))
            .await
    }

    async fn wait_cat_state(&self, name: &str, state: &str) -> serde_json::Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let cat = self.cat_json(name).await;
            if cat["observed_state"] == state {
                return cat;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {name} to become {state}: {cat}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Guest control socket path on a given node (the harness owns the
    /// node state dirs, so reaching into them is fair game for oracles).
    fn guest_ctl(&self, node: &str, cat_id: &str) -> PathBuf {
        self.dir
            .path()
            .join(format!("h{node}"))
            .join("s")
            .join("cats")
            .join(cat_id)
            .join("ctl.sock")
    }

    fn guest_write(&self, node: &str, cat_id: &str, disk_id: &str, offset: u64, data: &[u8]) {
        let mut g = GuestClient::connect(&self.guest_ctl(node, cat_id)).unwrap();
        g.request(GuestRequestBody::WriteBlock {
            disk_id: disk_id.to_string(),
            offset,
            data_hex: hex::encode(data),
        })
        .unwrap();
        g.flush_disk(disk_id).unwrap();
    }

    fn guest_read(
        &self,
        node: &str,
        cat_id: &str,
        disk_id: &str,
        offset: u64,
        len: u32,
    ) -> Vec<u8> {
        let mut g = GuestClient::connect(&self.guest_ctl(node, cat_id)).unwrap();
        match g
            .request(GuestRequestBody::ReadBlock {
                disk_id: disk_id.to_string(),
                offset,
                len,
            })
            .unwrap()
        {
            GuestResponseBody::Data { data_hex } => hex::decode(data_hex).unwrap(),
            other => panic!("unexpected {other:?}"),
        }
    }

    async fn gateway_get(&self, hostname: &str, path: &str) -> (u16, String) {
        let hostname = hostname.strip_prefix("https://").unwrap_or(hostname);
        let resp = self
            .http
            .get(format!("{}{}", self.gateway.base_url(), path))
            .header("host", hostname)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap();
        (status, body)
    }

    async fn endpoint_hostname(&self, cat: &str, name: &str) -> String {
        let output = self.cli_ok(&["--json", "endpoint", "ls", cat]).await;
        let endpoints: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        endpoints
            .into_iter()
            .find(|endpoint| endpoint["name"] == name)
            .and_then(|endpoint| endpoint["hostname"].as_str().map(str::to_string))
            .unwrap_or_else(|| panic!("missing endpoint {name} for {cat}"))
    }

    /// Kill every child process a node runtime spawned (used at test end;
    /// production nodes do this via StopCat, but partitioned-node tests
    /// leave orphans on purpose).
    fn cleanup_node_children(&self, idx: usize) {
        let runtime = self.nodes[idx].state.runtime.clone();
        for (cat_id, generation, _) in runtime.snapshot() {
            let job = cats_api::nodejob::NodeJob {
                job_id: format!("job_cleanup_{cat_id}_{generation}_{idx}"),
                cat_generation: generation,
                action: cats_api::nodejob::NodeJobAction::CleanupCat { cat_id },
            };
            let _ = runtime.execute(job);
        }
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for i in 0..self.nodes.len() {
            self.cleanup_node_children(i);
        }
    }
}

fn extract(body: &str, key: &str) -> String {
    body.split_whitespace()
        .find_map(|tok| tok.strip_prefix(&format!("{key}=")))
        .unwrap_or_default()
        .to_string()
}

/// Work count 0 drives Suspend; an Endpoint wake leaves a bounded activation
/// lease, then the Cat goes back down after its TTL and the Node guard clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn work_driven_fast_suspend_and_gateway_wake_loop() {
    let cluster = Cluster::start(&["node-a"]).await;
    cluster
        .cli_ok(&[
            "create",
            "nap",
            "--root-size",
            "8MiB",
            "--memory",
            "256MiB",
            "--cpus",
            "1",
        ])
        .await;
    cluster.wait_cat_state("nap", "suspended").await;

    let status = cluster.cli_ok(&["sleep", "status", "nap"]).await;
    assert!(status.contains("auto-suspend=on"), "status: {status}");
    let hostname = cluster.endpoint_hostname("nap", "web").await;

    let (status, first) = cluster.gateway_get(&hostname, "/first").await;
    assert_eq!(status, 200, "first wake failed: {first}");
    let boot_id = extract(&first, "boot_id");
    cluster.wait_cat_state("nap", "suspended").await;

    let (status, second) = cluster.gateway_get(&hostname, "/second").await;
    assert_eq!(status, 200, "second wake failed: {second}");
    assert_eq!(extract(&second, "boot_id"), boot_id);
    cluster.wait_cat_state("nap", "suspended").await;

    cluster.cli_ok(&["sleep", "off", "nap"]).await;
    cluster.cli_ok(&["destroy", "nap"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn absolute_expiry_reaps_the_cat_without_any_caller() {
    let cluster = Cluster::start(&["node-a"]).await;
    cluster
        .cli_ok(&[
            "create",
            "ephemeral",
            "--root-size",
            "8MiB",
            "--memory",
            "256MiB",
            "--cpus",
            "1",
            "--expires-in",
            "3600",
        ])
        .await;
    let shown = cluster.cli_ok(&["expiry", "ephemeral"]).await;
    assert!(shown.contains("expires at unix"), "expiry get: {shown}");

    // Renew, then move the expiry into the past; the controller must reap it
    // with no further API traffic.
    cluster
        .cli_ok(&["expiry", "ephemeral", "--in", "7200"])
        .await;
    let renewed = cluster.cli_ok(&["expiry", "ephemeral"]).await;
    assert!(renewed.contains("expires at unix"), "renewed: {renewed}");
    cluster.cli_ok(&["expiry", "ephemeral", "--at", "1"]).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let (ok, stdout, stderr) = cluster.cli(&["get", "ephemeral"]).await;
        if !ok && (stdout + &stderr).contains("NotFound") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expired cat was never reaped"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // A cat whose expiry was cleared survives the same window.
    cluster
        .cli_ok(&[
            "create",
            "keeper",
            "--root-size",
            "8MiB",
            "--memory",
            "256MiB",
            "--cpus",
            "1",
            "--expires-in",
            "3600",
        ])
        .await;
    cluster.cli_ok(&["expiry", "keeper", "--never"]).await;
    let shown = cluster.cli_ok(&["expiry", "keeper"]).await;
    assert!(shown.contains("never expires"), "cleared: {shown}");
    cluster.cli_ok(&["destroy", "keeper"]).await;
}

/// Admission is authorized once. The Node holds its local activity guard for
/// the full stream, so neither control-plane loss nor V1 Grant expiry tears
/// down an established WebSocket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn established_endpoint_websocket_survives_control_plane_outage() {
    let cluster = Cluster::start(&["node-a"]).await;
    cluster
        .cli_ok(&[
            "create",
            "realtime",
            "--root-size",
            "8MiB",
            "--memory",
            "256MiB",
            "--cpus",
            "1",
            "--no-auto-suspend",
        ])
        .await;
    let hostname = cluster.endpoint_hostname("realtime", "web").await;
    let url = format!("{}/agent-ws", cluster.gateway.base_url()).replacen("http://", "ws://", 1);
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("host", hostname.parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    socket.send("hello from pr staging".into()).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "hello from pr staging"
    );
    socket
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            vec![0, 1, 2, 255].into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_data(),
        vec![0, 1, 2, 255]
    );

    cluster.cp.shutdown().await;
    // The removed control-plane work lease renewed every 30 seconds. Cross
    // that exact old failure boundary as well as the two-second test Grant.
    tokio::time::sleep(Duration::from_secs(31)).await;
    socket.send("after control outage".into()).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "after control outage"
    );
    socket.close(None).await.unwrap();
}

/// A Running Endpoint is data-plane traffic. Once the Gateway has a bounded V1
/// route authorization, losing every control-plane replica must not stop the
/// healthy Node and Guest before that authorization expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_endpoint_survives_control_plane_outage_with_cached_route_grant() {
    let cluster = Cluster::start(&["node-a"]).await;
    cluster
        .cli_ok(&[
            "create",
            "independent",
            "--root-size",
            "8MiB",
            "--memory",
            "256MiB",
            "--cpus",
            "1",
            "--no-auto-suspend",
        ])
        .await;
    let hostname = cluster.endpoint_hostname("independent", "web").await;

    let (status, first) = cluster.gateway_get(&hostname, "/before-outage").await;
    assert_eq!(status, 200, "failed to prime route cache: {first}");

    cluster.cp.shutdown().await;
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut successful_requests = 0;
    loop {
        assert!(
            Instant::now() < deadline,
            "the two-second test Route Grant never reached fail-closed expiry"
        );
        let started = Instant::now();
        let (status, body) = cluster.gateway_get(&hostname, "/during-outage").await;
        let latency = started.elapsed();
        if status == 200 {
            successful_requests += 1;
            assert!(
                latency < Duration::from_millis(500),
                "authorized outage traffic stalled on the control-plane timeout: {latency:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
            continue;
        }
        assert_eq!(
            status, 502,
            "the Gateway returned an unexpected status after grant expiry: {body}"
        );
        break;
    }
    assert!(
        successful_requests >= 10,
        "the sustained outage probe did not exercise enough authorized requests"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automation_token_is_confined_to_one_workspace_and_revocable() {
    let cluster = Cluster::start(&["node-a"]).await;
    let created = cluster
        .http
        .post(format!(
            "{}/v1/workspaces/{}/tokens",
            cluster.cp.base_url(),
            cluster.workspace_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .json(&serde_json::json!({ "label": "CI preview" }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: cats_api::requests::CreatedWorkspaceToken = created.json().await.unwrap();

    let own = cluster
        .http
        .get(format!(
            "{}/v1/workspaces/{}/cats",
            cluster.cp.base_url(),
            cluster.workspace_id
        ))
        .bearer_auth(&created.token)
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), 200);
    let other = cluster
        .http
        .get(format!(
            "{}/v1/workspaces/ws_not_owned/cats",
            cluster.cp.base_url()
        ))
        .bearer_auth(&created.token)
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 403);
    let mint_another = cluster
        .http
        .post(format!(
            "{}/v1/workspaces/{}/tokens",
            cluster.cp.base_url(),
            cluster.workspace_id
        ))
        .bearer_auth(&created.token)
        .json(&serde_json::json!({ "label": "not allowed" }))
        .send()
        .await
        .unwrap();
    assert_eq!(mint_another.status(), 403);

    let revoked = cluster
        .http
        .delete(format!(
            "{}/v1/workspaces/{}/tokens/{}",
            cluster.cp.base_url(),
            cluster.workspace_id,
            created.access_token.id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 204);
    let after_revoke = cluster
        .http
        .get(format!(
            "{}/v1/workspaces/{}/cats",
            cluster.cp.base_url(),
            cluster.workspace_id
        ))
        .bearer_auth(&created.token)
        .send()
        .await
        .unwrap();
    assert_eq!(after_revoke.status(), 401);
}

/// §20.1 正常路径 (KVM-free rendition): create -> exec -> endpoint ->
/// suspend/wake -> cross-node cold restart with data intact -> warm ->
/// persistent disk moves between cats -> destroy semantics.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn product_loop_end_to_end() {
    let cluster = Cluster::start(&["node-a", "node-b"]).await;

    // Create through the CLI and wait for convergence.
    let out = cluster
        .cli_ok(&[
            "create",
            "dev",
            "--root-size",
            "8MiB",
            "--memory",
            "256MiB",
            "--cpus",
            "1",
            "--no-auto-suspend",
        ])
        .await;
    assert!(out.contains("observed=running"), "create output: {out}");

    // exec inside the cat.
    let out = cluster
        .cli_ok(&["exec", "dev", "--", "echo", "hello-from-guest"])
        .await;
    assert_eq!(out.trim(), "hello-from-guest");

    // Interactive shell crosses CLI -> control plane -> node -> guest PTY,
    // and remains scriptable when stdin/stdout are pipes.
    let (ok, stdout, stderr) = cluster
        .cli_with_input(&["shell", "dev"], b"printf 'hello-from-shell\\n'; exit\n")
        .await;
    assert!(ok, "cats shell failed:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("hello-from-shell"),
        "shell output: {stdout}"
    );

    let cat = cluster.cat_json("dev").await;
    let cat_id = cat["id"].as_str().unwrap().to_string();
    let root_disk_id = cat["root_disk_id"].as_str().unwrap().to_string();
    let node_a = cat["node_id"].as_str().unwrap().to_string();

    // Write durable data through the real storage path.
    let payload = b"root-disk-payload".to_vec();
    cluster.guest_write(&node_a, &cat_id, &root_disk_id, 8192, &payload);

    // Every Cat has a default endpoint; no explicit expose step is required.
    let hostname = cluster.endpoint_hostname("dev", "web").await;
    assert!(
        hostname.starts_with("dev-") && hostname.ends_with(".cats.run"),
        "default hostname: {hostname}"
    );
    let (status, body) = cluster.gateway_get(&hostname, "/hello").await;
    assert_eq!(status, 200, "gateway body: {body}");
    let boot_running = extract(&body, "boot_id");
    assert!(!boot_running.is_empty());

    // Suspend, then let endpoint traffic wake it: same process must resume.
    cluster.cli_ok(&["suspend", "dev"]).await;
    let (status, body) = cluster.gateway_get(&hostname, "/after-suspend").await;
    assert_eq!(status, 200, "wake-through-gateway failed: {body}");
    assert_eq!(
        extract(&body, "boot_id"),
        boot_running,
        "suspend/resume must keep the process"
    );

    // Warm, then wake again: identity still preserved (ADR-0002 Warm).
    cluster.cli_ok(&["warm", "dev"]).await;
    let warm_cat = cluster.cat_json("dev").await;
    assert_eq!(warm_cat["observed_state"], "warm");
    let (status, body) = cluster.gateway_get(&hostname, "/after-warm").await;
    assert_eq!(status, 200, "wake-from-warm failed: {body}");
    assert_eq!(
        extract(&body, "boot_id"),
        boot_running,
        "warm restore must keep identity"
    );

    // Stop, cordon the current node, start again: the cat must move to the
    // other node and lazily restore its disk from the blobstore.
    cluster.cli_ok(&["stop", "dev"]).await;
    cluster.cordon(&node_a).await;
    let out = cluster.cli_ok(&["start", "dev"]).await;
    assert!(out.contains("observed=running"), "restart output: {out}");
    let cat = cluster.cat_json("dev").await;
    let node_b = cat["node_id"].as_str().unwrap().to_string();
    assert_ne!(node_b, node_a, "cordon must force the other node");

    // Data written on node A is readable on node B (empty-cache restore).
    let back = cluster.guest_read(&node_b, &cat_id, &root_disk_id, 8192, payload.len() as u32);
    assert_eq!(back, payload, "cross-node cold restore lost data");

    // Cold start must be a new boot; the endpoint rebinds to the new node.
    let (status, body) = cluster.gateway_get(&hostname, "/after-move").await;
    assert_eq!(status, 200, "gateway after move: {body}");
    let boot_after_move = extract(&body, "boot_id");
    assert_ne!(
        boot_after_move, boot_running,
        "cold start must be a fresh boot"
    );

    // A stale route straight at the old node fails closed (409).
    let old_agent = cluster
        .nodes
        .iter()
        .find(|n| n.state.cfg.node.node_id == node_a)
        .unwrap()
        .base_url();
    let stale = cluster
        .http
        .post(format!("{old_agent}/v1/cats/{cat_id}/proxy"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&cats_api::requests::ProxyHttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            target_port: 8080,
            route_epoch: 1,
            hostname: hostname.clone(),
            route_grant: String::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        stale.status().as_u16(),
        409,
        "old node must reject the moved cat"
    );

    // Persistent disk: create, mount into dev, write, move to another cat.
    cluster
        .cli_ok(&["disk", "create", "shared", "--size", "8MiB"])
        .await;
    cluster
        .cli_ok(&["mount", "shared", "--cat", "dev", "--at", "/data"])
        .await;
    let disks = cluster
        .api_get(&format!("/v1/workspaces/{}/disks", cluster.workspace_id))
        .await;
    let shared_id = disks["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "shared")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let disk_payload = b"portable-disk-data".to_vec();
    cluster.guest_write(&node_b, &cat_id, &shared_id, 0, &disk_payload);

    // RWO: mounting the bound disk somewhere else is rejected.
    cluster
        .cli_ok(&[
            "create",
            "second",
            "--root-size",
            "8MiB",
            "--cpus",
            "1",
            "--no-auto-suspend",
        ])
        .await;
    let (ok, _, stderr) = cluster
        .cli(&["mount", "shared", "--cat", "second", "--at", "/data"])
        .await;
    assert!(!ok, "RWO second mount must fail");
    assert!(
        stderr.contains("RWO") || stderr.contains("bound"),
        "stderr: {stderr}"
    );

    // Move the disk: unmount from dev, mount into second, data follows.
    cluster.cli_ok(&["unmount", "shared"]).await;
    cluster
        .cli_ok(&["mount", "shared", "--cat", "second", "--at", "/data"])
        .await;
    let second = cluster.cat_json("second").await;
    let second_id = second["id"].as_str().unwrap().to_string();
    let second_node = second["node_id"].as_str().unwrap().to_string();
    let back = cluster.guest_read(
        &second_node,
        &second_id,
        &shared_id,
        0,
        disk_payload.len() as u32,
    );
    assert_eq!(
        back, disk_payload,
        "persistent disk data must move with the disk"
    );

    // Destroy dev: its root disk goes away, the persistent disk stays.
    cluster.cli_ok(&["destroy", "dev"]).await;
    let disks = cluster
        .api_get(&format!("/v1/workspaces/{}/disks", cluster.workspace_id))
        .await;
    let names: Vec<&str> = disks["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["name"].as_str())
        .collect();
    assert!(
        names.contains(&"shared"),
        "persistent disk must survive destroy"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("dev-root")),
        "root disk must be deleted"
    );

    // Cleanup.
    cluster.cli_ok(&["unmount", "shared"]).await;
    cluster.cli_ok(&["disk", "delete", "shared"]).await;
    cluster.cli_ok(&["destroy", "second"]).await;
}

/// §20.1 破坏路径: kill an entire "host" while its cat runs. Heartbeat loss
/// only makes the claim Unknown; after an independent actor confirms Host
/// isolation, explicit fencing cold-starts the Cat on the surviving node with
/// every flushed byte intact and rejects the zombie writer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_loss_preserves_claim_until_explicit_fence_then_recovers_elsewhere() {
    let cluster = Cluster::start(&["node-a", "node-b"]).await;

    // Force placement onto node-a.
    cluster.cordon("node-b").await;
    cluster
        .cli_ok(&[
            "create",
            "victim",
            "--root-size",
            "8MiB",
            "--cpus",
            "1",
            "--no-auto-suspend",
        ])
        .await;
    let cat = cluster.cat_json("victim").await;
    let cat_id = cat["id"].as_str().unwrap().to_string();
    let root_disk = cat["root_disk_id"].as_str().unwrap().to_string();
    assert_eq!(cat["node_id"], "node-a");

    // Durable write, then one *unflushed* write (allowed to be lost).
    let durable = b"flushed-before-host-loss".to_vec();
    cluster.guest_write("node-a", &cat_id, &root_disk, 0, &durable);
    {
        let mut g = GuestClient::connect(&cluster.guest_ctl("node-a", &cat_id)).unwrap();
        g.request(GuestRequestBody::WriteBlock {
            disk_id: root_disk.clone(),
            offset: 1 << 20,
            data_hex: hex::encode(b"never-flushed"),
        })
        .unwrap();
        // no flush on purpose
    }

    // "Host loss": the node agent process dies (heartbeats stop) while its
    // children (guest + blockd) keep running — a real partition.
    cluster.nodes[0].shutdown();
    // Re-open the surviving node for placement through the administrator
    // action; registration/heartbeats intentionally preserve cordons.
    let resp = cluster
        .http
        .post(format!(
            "{}/v1/admin/nodes/node-b/actions/uncordon",
            cluster.cp.base_url()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Heartbeat expiry is only suspicion. The old Guest and disk epoch remain
    // intact, and no replacement starts while the Host could still execute.
    let lost_deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let cat = cluster.cat_json("victim").await;
        let node = cluster.cp.state.store.get_node("node-a").unwrap();
        if node.state == NodeState::Lost && cat["observed_state"] == "unknown" {
            assert_eq!(cat["node_id"], "node-a");
            break;
        }
        assert!(
            std::time::Instant::now() < lost_deadline,
            "node-a never became Lost with its claim preserved: {cat}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut partitioned = GuestClient::connect(&cluster.guest_ctl("node-a", &cat_id)).unwrap();
    partitioned
        .request(GuestRequestBody::WriteBlock {
            disk_id: root_disk.clone(),
            offset: 2 << 20,
            data_hex: hex::encode(b"accepted-before-explicit-fence"),
        })
        .expect("heartbeat loss alone must not fence the live blockd");

    // The test harness now plays the independent cloud/BMC fencing actor: the
    // node-agent is stopped, so it explicitly confirms Host isolation.
    let fenced = cluster
        .http
        .post(format!(
            "{}/v1/admin/nodes/node-a/actions/fence",
            cluster.cp.base_url()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .json(&serde_json::json!({
            "confirm_host_stopped_or_isolated": true
        }))
        .send()
        .await
        .unwrap();
    assert!(fenced.status().is_success());

    // Only the explicit fence may revoke epochs and reschedule onto node-b.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let cat = cluster.cat_json("victim").await;
        if cat["observed_state"] == "running" && cat["node_id"] == "node-b" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never recovered on node-b: {cat}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Flushed data survived; the unflushed write is (correctly) gone.
    let back = cluster.guest_read("node-b", &cat_id, &root_disk, 0, durable.len() as u32);
    assert_eq!(back, durable, "flushed data lost after host failure");
    let lost = cluster.guest_read("node-b", &cat_id, &root_disk, 1 << 20, 13);
    assert_eq!(lost, vec![0u8; 13], "unflushed write must not reappear");

    // The zombie guest on the dead host is fenced: its writes fail closed.
    let mut zombie = GuestClient::connect(&cluster.guest_ctl("node-a", &cat_id)).unwrap();
    let write = zombie.request(GuestRequestBody::WriteBlock {
        disk_id: root_disk.clone(),
        offset: 0,
        data_hex: hex::encode(b"split-brain!"),
    });
    let flush = zombie.request(GuestRequestBody::FlushDisk {
        disk_id: root_disk.clone(),
    });
    assert!(
        write.is_err() || flush.is_err(),
        "old host must not be able to publish writes after fencing"
    );
    // And the new node still reads the original data.
    let back = cluster.guest_read("node-b", &cat_id, &root_disk, 0, durable.len() as u32);
    assert_eq!(back, durable, "split-brain write leaked through");

    cluster.cli_ok(&["destroy", "victim"]).await;
}

/// Idempotency + no-wake endpoints + operation surfacing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_semantics_through_cli() {
    let cluster = Cluster::start(&["node-a"]).await;

    cluster
        .cli_ok(&[
            "create",
            "api",
            "--root-size",
            "8MiB",
            "--cpus",
            "1",
            "--no-auto-suspend",
        ])
        .await;

    // A no-wake endpoint answers 503 while the cat sleeps.
    let host = cluster
        .cli_ok(&["expose", "api", "9090", "--name", "pinned", "--no-wake"])
        .await
        .trim()
        .to_string();
    cluster.cli_ok(&["stop", "api"]).await;
    let (status, _) = cluster.gateway_get(&host, "/").await;
    assert_eq!(status, 503, "no_wake endpoint must not wake the cat");
    let cat = cluster.cat_json("api").await;
    assert_eq!(
        cat["observed_state"], "cold",
        "no_wake must leave the cat cold"
    );

    // exec wakes it regardless of endpoint policy.
    let out = cluster
        .cli_ok(&["exec", "api", "--", "echo", "woken"])
        .await;
    assert_eq!(out.trim(), "woken");
    let cat = cluster.cat_json("api").await;
    assert_eq!(cat["observed_state"], "running");

    // ls shows it; get is consistent.
    let out = cluster.cli_ok(&["ls"]).await;
    assert!(out.contains("api"));

    // The administrator view is available through the same CLI with an
    // administrator credential, without exposing it to workspace users.
    let monitoring = cluster.admin_cli_ok(&["admin", "monitoring"]).await;
    assert!(monitoring.contains("cats total="));
    let nodes = cluster.admin_cli_ok(&["admin", "nodes"]).await;
    assert!(nodes.contains("node-a"));

    cluster.cli_ok(&["destroy", "api"]).await;
}

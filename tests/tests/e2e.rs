//! End-to-end tests: real control plane + two node agents (FakeVmm, real
//! cats-blockd children) + gateway, driven through the real `cats` CLI
//! binary. Covers the minimal production acceptance scenarios from the
//! architecture doc §20.1 that are meaningful without KVM.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use cats_api::guest::{GuestRequestBody, GuestResponseBody};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_node_agent::guest_client::GuestClient;
use cats_node_agent::runtime::NodeConfig;
use cats_node_agent::server::{spawn as spawn_node, Handle as NodeHandle, ServerConfig};
use cats_node_agent::testutil::workspace_bin;
use cats_storage::{AdapterConfig, AdapterSelection, MetadataStore};

const USER_TOKEN: &str = "dev-token";
const SERVICE_TOKEN: &str = "dev-service-token";
const ADMIN_TOKEN: &str = "dev-admin-token";

struct Cluster {
    dir: tempfile::TempDir,
    cp: cats_control_plane::server::Handle,
    gateway: cats_network::Handle,
    nodes: Vec<NodeHandle>,
    http: reqwest::Client,
    cli_bin: PathBuf,
}

impl Cluster {
    async fn start(node_ids: &[&str]) -> Cluster {
        let dir = tempfile::tempdir().unwrap();
        let storage_meta_path = dir.path().join("storage-meta.db");
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&storage_meta_path).unwrap());
        let project_tokens = BTreeMap::from([("default".to_string(), USER_TOKEN.to_string())]);
        let cp = cats_control_plane::server::spawn(cats_control_plane::server::Config {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("control.db"),
            storage_meta,
            auth_token: SERVICE_TOKEN.into(),
            admin_token: ADMIN_TOKEN.into(),
            project_tokens,
            workos: None,
            node_lease_timeout_ms: 3_000,
            reconcile_interval_ms: 150,
        })
        .await
        .unwrap();

        let gateway = cats_network::spawn(cats_network::GatewayConfig {
            listen: "127.0.0.1:0".into(),
            control_plane_url: cp.base_url(),
            auth_token: SERVICE_TOKEN.into(),
            cache_ttl_ms: 500,
        })
        .await
        .unwrap();

        let mut nodes = Vec::new();
        for id in node_ids {
            nodes.push(Self::start_node(&dir, &cp, &gateway, id).await);
        }
        Cluster {
            dir,
            cp,
            gateway,
            nodes,
            http: reqwest::Client::new(),
            cli_bin: workspace_bin("cats"),
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
        spawn_node(ServerConfig {
            advertise_url: None,
            listen: "127.0.0.1:0".into(),
            control_plane_url: cp.base_url(),
            auth_token: SERVICE_TOKEN.into(),
            gateway_url: gateway.base_url(),
            cpus: 16,
            memory_mib: 32_768,
            heartbeat_ms: 300,
            storage_meta,
            node: NodeConfig {
                node_id: id.to_string(),
                state_dir: dir.path().join(format!("node-{id}")),
                blockd_bin: workspace_bin("cats-blockd"),
                guest_agent_bin: workspace_bin("cats-guest-agent"),
                metadata_store,
                object_store,
                blockd_lease_ttl_ms: 1_200,
                vmm: cats_node_agent::runtime::VmmMode::Fake,
            },
        })
        .await
        .unwrap()
    }

    /// Run the real `cats` binary; returns (exit_ok, stdout, stderr).
    async fn cli(&self, args: &[&str]) -> (bool, String, String) {
        self.cli_with_token(args, USER_TOKEN).await
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
                .env("CATS_PROJECT", "default")
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
            .bearer_auth(USER_TOKEN)
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
        self.api_get(&format!("/v1/projects/default/cats/{name}"))
            .await
    }

    /// Guest control socket path on a given node (the harness owns the
    /// node state dirs, so reaching into them is fair game for oracles).
    fn guest_ctl(&self, node: &str, cat_id: &str) -> PathBuf {
        self.dir
            .path()
            .join(format!("node-{node}"))
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
        ])
        .await;
    assert!(out.contains("observed=running"), "create output: {out}");

    // exec inside the cat.
    let out = cluster
        .cli_ok(&["exec", "dev", "--", "echo", "hello-from-guest"])
        .await;
    assert_eq!(out.trim(), "hello-from-guest");

    let cat = cluster.cat_json("dev").await;
    let cat_id = cat["id"].as_str().unwrap().to_string();
    let root_disk_id = cat["root_disk_id"].as_str().unwrap().to_string();
    let node_a = cat["node_id"].as_str().unwrap().to_string();

    // Write durable data through the real storage path.
    let payload = b"root-disk-payload".to_vec();
    cluster.guest_write(&node_a, &cat_id, &root_disk_id, 8192, &payload);

    // Expose an endpoint and reach the guest through the gateway.
    let hostname = cluster
        .cli_ok(&["expose", "dev", "8080", "--name", "web"])
        .await
        .trim()
        .to_string();
    assert_eq!(hostname, "web.dev.default.cats.local");
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
        .get(format!("{old_agent}/v1/cats/{cat_id}/proxy"))
        .bearer_auth(SERVICE_TOKEN)
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
    let disks = cluster.api_get("/v1/projects/default/disks").await;
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
        .cli_ok(&["create", "second", "--root-size", "8MiB", "--cpus", "1"])
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
    let disks = cluster.api_get("/v1/projects/default/disks").await;
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

/// §20.1 破坏路径: kill an entire "host" while its cat runs. The control
/// plane must fence the volumes, cold-start the cat on the surviving node
/// with every flushed byte intact, and the zombie writer on the dead node
/// must be unable to write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_loss_fences_and_recovers_elsewhere() {
    let cluster = Cluster::start(&["node-a", "node-b"]).await;

    // Force placement onto node-a.
    cluster.cordon("node-b").await;
    cluster
        .cli_ok(&["create", "victim", "--root-size", "8MiB", "--cpus", "1"])
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

    // Wait for fencing + rescheduling onto node-b.
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
        .cli_ok(&["create", "api", "--root-size", "8MiB", "--cpus", "1"])
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
    // administrator credential, without exposing it to project users.
    let monitoring = cluster.admin_cli_ok(&["admin", "monitoring"]).await;
    assert!(monitoring.contains("cats total="));
    let nodes = cluster.admin_cli_ok(&["admin", "nodes"]).await;
    assert!(nodes.contains("node-a"));

    cluster.cli_ok(&["destroy", "api"]).await;
}

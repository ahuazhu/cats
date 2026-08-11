//! Focused integration fixtures whose assertions remain valid.
//!
//! The former seven-test product loop was coupled to the retired Cat,
//! lifecycle, disk, Endpoint, Operation, and fleet-admin CLI/API authority.
//! The shipped CLI now sends the strict Cat-create v2 body and deliberately
//! rejects those other commands before HTTP, so keeping that loop here would
//! either test a false production surface or require reviving compatibility.
//! This file now retains only the workspace-token authorization check on a
//! current route and the explicit guard that stops the private retired
//! inventory writer before control-plane shutdown.
//!
//! Current coverage lives in:
//! - `cmd/cats/src/lib.rs` for the Cat-create v2 CLI wire/recovery contract and
//!   fail-closed retirement of the legacy commands;
//! - `control-plane/tests/runtime_control_spine_e2e.rs` for production
//!   Cat-create, registration, Desired, observation, and replica authority;
//! - `node-agent/src/runtime/reconciliation/` tests for checkpointed physical
//!   convergence and route admission;
//! - `network/tests/route_v2.rs` for the production Gateway cache/resolve path.
//!
//! Those suites are component and control-spine oracles, not a replacement
//! claim for the still-missing full production Cat-create-to-Guest E2E.

use std::sync::Arc;
use std::time::Duration;

use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::requests::{HeartbeatCat, HeartbeatRequest};
use cats_api::runtime_reconciliation::{
    ContractVersion, CredentialBinding, Id, NodeBootId, NodeIdentity, NodeIdentityState,
};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_metering::SqliteUsageStore;
use cats_node_agent::agent_registration::AgentRegistrationConfig;
use cats_node_agent::server::{spawn as spawn_node, Handle as NodeHandle, ServerConfig};
use cats_object_store_file::FileBlobStore;
use cats_storage::{AdapterConfig, AdapterSelection, MetadataStore};
use cats_test_support::{fake_node_config, NodeConfigBuilder};

const SERVICE_TOKEN: &str = "dev-service-token";
const ADMIN_TOKEN: &str = "dev-admin-token";
const ROUTE_GRANT_PRIVATE_KEY: &[u8] =
    include_bytes!("../fixtures/route_grant_private_ed25519.pem");
const ROUTE_GRANT_PUBLIC_KEY: &[u8] = include_bytes!("../fixtures/route_grant_public_ed25519.pem");
const RETIRED_INVENTORY_INTERVAL: Duration = Duration::from_millis(300);

fn node_request_signer(id: &str) -> Ed25519RequestSigner {
    // Each simulated Host needs a distinct credential lineage. Derive a
    // deterministic, test-only Ed25519 seed from the short fixture Node ID;
    // production keys are installed by the release workflow instead.
    let id_bytes = id.as_bytes();
    assert!(id_bytes.len() <= 31, "E2E fixture Node ID is too long");
    let mut seed = [0_u8; 32];
    seed[0] = u8::try_from(id_bytes.len()).unwrap();
    seed[1..1 + id_bytes.len()].copy_from_slice(id_bytes);
    let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
    der.extend_from_slice(&seed);
    Ed25519RequestSigner::from_pkcs8_der(Id::new(format!("credential_{id}")).unwrap(), &der)
        .unwrap()
}

struct Cluster {
    _dir: tempfile::TempDir,
    cp: cats_control_plane::server::Handle,
    _gateway: cats_network::Handle,
    _nodes: Vec<NodeHandle>,
    retired_inventory_tasks: Vec<RetiredInventoryTask>,
    http: reqwest::Client,
    /// The bootstrap Account's default Workspace; resource routes key on its ID.
    workspace_id: String,
}

struct RetiredInventoryTask {
    node_id: String,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RetiredInventoryTask {
    fn cancel(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }

    async fn stop(&mut self) {
        self.cancel();
        if let Some(task) = self.task.take() {
            task.await.expect("retired inventory fixture task panicked");
        }
    }

    fn abort(&mut self) {
        self.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Cluster {
    async fn start(node_ids: &[&str]) -> Cluster {
        let dir = tempfile::tempdir().unwrap();
        let storage_meta_path = dir.path().join("storage-meta.db");
        let storage_meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&storage_meta_path).unwrap());
        let cp = cats_control_plane::server::spawn_for_retired_product_tests(
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
                runtime_provisioner_trust_bundle:
                    cats_control_plane::testsupport::test_runtime_provisioner_trust_bundle(),
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
        })
        .await
        .unwrap();

        let mut nodes = Vec::new();
        let mut retired_inventory_tasks = Vec::new();
        for id in node_ids {
            let (node, retired_inventory_task) = Self::start_node(&dir, &cp, &gateway, id).await;
            nodes.push(node);
            retired_inventory_tasks.push(retired_inventory_task);
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
            _dir: dir,
            cp,
            _gateway: gateway,
            _nodes: nodes,
            retired_inventory_tasks,
            http: reqwest::Client::new(),
            workspace_id,
        }
    }

    async fn start_node(
        dir: &tempfile::TempDir,
        cp: &cats_control_plane::server::Handle,
        gateway: &cats_network::Handle,
        id: &str,
    ) -> (NodeHandle, RetiredInventoryTask) {
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
        let signer = node_request_signer(id);
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
        // The retired product loop still reads its private Node row, but no
        // HTTP caller may update it. Signed A19/A20 coverage lives in the
        // production Runtime suites; this direct fixture update disappears
        // with the old product E2E.
        let retired_store = Arc::clone(&cp.state.store);
        let node_id = id.to_string();
        let task_node_id = node_id.clone();
        let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                tokio::select! {
                    result = &mut cancelled => {
                        let _ = result;
                        break;
                    }
                    _ = tokio::time::sleep(RETIRED_INVENTORY_INTERVAL) => {}
                }
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
                let request = HeartbeatRequest {
                    node_id: node_id.clone(),
                    cats,
                    telemetry: None,
                };
                let _ = retired_store
                    .execute(move |store| {
                        store
                            .heartbeat_node(
                                &request.node_id,
                                request.telemetry.as_ref(),
                                &request.cats,
                            )
                            .map(|_| ())
                    })
                    .await;
            }
        });
        (
            node,
            RetiredInventoryTask {
                node_id: task_node_id,
                cancel: Some(cancel),
                task: Some(task),
            },
        )
    }

    fn retired_inventory_projection(&self) -> Vec<(String, i64)> {
        let mut projection = self
            .retired_inventory_tasks
            .iter()
            .map(|task| {
                let heartbeat = self
                    .cp
                    .state
                    .store
                    .get_node(&task.node_id)
                    .unwrap()
                    .last_heartbeat_unix;
                (task.node_id.clone(), heartbeat)
            })
            .collect::<Vec<_>>();
        projection.sort();
        projection
    }

    async fn shutdown_control_plane(&mut self) -> Vec<(String, i64)> {
        for task in &mut self.retired_inventory_tasks {
            task.stop().await;
        }
        let stopped_projection = self.retired_inventory_projection();
        self.cp.shutdown().await.unwrap();
        stopped_projection
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for task in &mut self.retired_inventory_tasks {
            task.abort();
        }
    }
}

/// The old product fixture writes its private heartbeat projection directly.
/// It must stop and join before a total control-plane outage so the test cannot
/// keep hidden control authority alive through an Arc to the Store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_inventory_fixture_stops_before_control_plane_outage() {
    let mut cluster = Cluster::start(&["node-a"]).await;
    let initial = cluster.retired_inventory_projection();
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    assert_ne!(
        cluster.retired_inventory_projection(),
        initial,
        "the positive fixture did not update the retired heartbeat projection",
    );

    let stopped = cluster.shutdown_control_plane().await;
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    assert_eq!(
        cluster.retired_inventory_projection(),
        stopped,
        "retired inventory fixture mutated Store state after control-plane shutdown",
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
            "{}/v1/workspaces/{}/billing/balance",
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
            "{}/v1/workspaces/ws_not_owned/billing/balance",
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
            "{}/v1/workspaces/{}/billing/balance",
            cluster.cp.base_url(),
            cluster.workspace_id
        ))
        .bearer_auth(&created.token)
        .send()
        .await
        .unwrap();
    assert_eq!(after_revoke.status(), 401);
}

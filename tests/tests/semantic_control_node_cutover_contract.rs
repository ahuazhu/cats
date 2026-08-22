use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read_workspace_file(path: &str) -> String {
    let path = workspace_root().join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn compact(source: &str) -> String {
    source
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn assert_contains_all(source: &str, contracts: &[&str], boundary: &str) {
    for contract in contracts {
        assert!(
            source.contains(contract),
            "{boundary} is missing contract {contract:?}"
        );
    }
}

fn assert_contains_none(source: &str, retired: &[&str], boundary: &str) {
    for contract in retired {
        assert!(
            !source.contains(contract),
            "{boundary} still contains retired protocol {contract:?}"
        );
    }
}

#[test]
fn accepted_decision_is_one_empty_schema_and_one_semantic_protocol() {
    let decision =
        read_workspace_file("docs/decisions/0059-semantic-control-node-synchronous-protocol.md");
    let design = read_workspace_file("docs/control-node-semantic-protocol.md");

    assert_contains_all(
        &decision,
        &[
            "- 状态：Accepted",
            "不提供新老 schema、wire、route 或状态的双写、双读、转换器和兼容窗口",
            "新的空数据库 schema",
            "旧 lifecycle Operation 表、command poll/result",
            "旧协议专属测试直接删除",
        ],
        "ADR-0059",
    );
    assert_contains_all(
        &design,
        &[
            "不使用调用方提供的 `request_id`",
            "slug 可以完全复用",
            "last_heartbeat_at",
            "reset_required",
            "一个允许的心跳窗口加上停止清理时间",
        ],
        "semantic protocol design",
    );
}

#[test]
fn clean_schema_encodes_slug_reuse_action_serialization_and_disk_rwo() {
    let schema = compact(&read_workspace_file("control-plane/src/store/schema.rs"));

    assert_contains_all(
        &schema,
        &[
            "cats (",
            "cat_slug",
            "current_action",
            "current_action_node_id",
            "destroyed_at",
            "cats_current_slug_unique",
            "where destroyed_at is null",
            "nodes (",
            "node_name",
            "node_heartbeats (",
            "last_heartbeat_at",
            "node_reported_at",
            "persistent_disks (",
            "disk_slug",
            "deleted_at",
            "disks_current_slug_unique",
            "where deleted_at is null",
            "disk_bindings (",
            "disk_bindings_disk_unique",
            "disk_bindings_cat_mount_unique",
        ],
        "semantic control schema",
    );
}

#[test]
fn control_claims_one_cat_action_and_recovers_unknown_response_by_query() {
    let service = read_workspace_file("control-plane/src/semantic_lifecycle.rs");
    let store = read_workspace_file("control-plane/src/store/semantic.rs");
    let combined = format!("{service}\n{store}");

    assert_contains_all(
        &combined,
        &[
            "SemanticLifecycleService",
            "SemanticLifecycleStore",
            "NodedClient",
            "IngressPort",
            "admit_create",
            "admit_action",
            "SameAction",
            "current_action",
            "current_action_node_id",
            "inspect",
            "withdraw",
            "publish",
            "withdraw:node-1",
            "node:Run",
            "publish:node-2",
        ],
        "semantic Control lifecycle",
    );
    assert_contains_none(
        &combined,
        &["request_id", "idempotency_key", "LifecycleOperation"],
        "semantic Control lifecycle",
    );
}

#[test]
fn noded_exposes_synchronous_semantic_routes_and_one_lane_per_cat() {
    let node = read_workspace_file("node-agent/src/semantic_lifecycle.rs");

    assert_contains_all(
        &node,
        &[
            "SemanticNodeService",
            "SemanticCatEffects",
            "semantic_node_router",
            "/v1/health",
            "/v1/cats",
            "/v1/cats/{cat_id}",
            "/v1/cats/{cat_id}/actions/run",
            "/v1/cats/{cat_id}/actions/suspend",
            "/v1/cats/{cat_id}/actions/warm",
            "/v1/cats/{cat_id}/actions/cold",
            "struct CatLane",
            "fn lane(&self, cat_id",
        ],
        "semantic noded lifecycle",
    );
    assert_contains_none(
        &node,
        &[
            "request_id",
            "LifecycleOperation",
            "command_poll",
            "result_commit",
        ],
        "semantic noded lifecycle",
    );
}

#[test]
fn offline_node_return_requires_reset_before_new_placement() {
    let api = read_workspace_file("api/src/semantic_node.rs");
    let control = read_workspace_file("control-plane/src/semantic_node.rs");
    let routes = read_workspace_file("control-plane/src/api/semantic_nodes.rs");
    let client = read_workspace_file("node-agent/src/semantic_node_client.rs");
    let combined = format!("{api}\n{control}\n{routes}\n{client}");

    assert_contains_all(
        &combined,
        &[
            "node_name",
            "last_heartbeat_at",
            "node_reported_at",
            "reset_required",
            "reset_complete",
            "offline",
            "placement",
        ],
        "semantic Node management",
    );
}

#[test]
fn production_composition_has_only_the_semantic_lifecycle_protocol() {
    let control_router = read_workspace_file("control-plane/src/api/mod.rs");
    let control_main = read_workspace_file("cmd/controld/src/main.rs");
    let node_main = read_workspace_file("cmd/noded/src/main.rs");
    let production = format!("{control_router}\n{control_main}\n{node_main}");

    assert_contains_all(
        &production,
        &["semantic_lifecycle", "semantic_node"],
        "production composition",
    );
    assert_contains_none(
        &production,
        &[
            "/v1/workspaces/{workspace}/operations/{operation}",
            "/v1/internal/runtime/agent-sessions",
            "/v1/internal/runtime/lifecycle-command-polls",
            "/v1/internal/runtime/lifecycle-result-commits",
            "/v1/internal/runtime/observations",
            "spawn_signed_runtime_cutover",
            "installed_atomic_lifecycle_executor",
            "LifecycleCommandRunner",
        ],
        "production composition",
    );
}

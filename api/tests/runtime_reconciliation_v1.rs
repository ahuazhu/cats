use std::fmt::Write as _;

use cats_api::runtime_reconciliation::*;

const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const SPEC_DIGEST: &str = "sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409";
const CHECKPOINT_DIGEST: &str =
    "sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb";

const DESIRED_DIGEST_INPUT: &str = r#"{"cat_id":"cat_01","desired_revision":7,"endpoints":[{"endpoint_id":"ep_01","hostname":"app.example.test","protocol":"http","route_epoch":9,"target_port":8080}],"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"runtime":{"boot_image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","guest_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","memory_bytes":2147483648,"network_config":{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","prefix_length":30},"vcpus":2},"target":"cold","transition":{"kind":"cancel_and_drain"},"version":1,"volumes":[{"access":"read_write_once","acquire":{"expected_unowned_epoch":0,"kind":"normal","transition_id":"22222222222222222222222222222222"},"attachment_id":"att_01","disk_id":"disk_root","disk_kind":"root","disposition":{"kind":"retain"},"durability":"strict","guest_device":{"serial":"cats-root","slot":0},"mount":null,"size_bytes":4294967296,"volume_id":"vol_root","volume_intent_id":"vint_root"}],"workspace_id":"ws_01"}"#;

const CHECKPOINT_WIRE: &str = r#"{"cat_id":"cat_01","desired_revision":7,"guest_transport":{"kind":"unavailable"},"lifecycle_admission":"closed","mounts":[],"networks":[],"node_id":"node_a","placement_epoch":3,"processes":[],"require_idle":{"kind":"not_applicable"},"route_gates":[],"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"updated_at_unix_ms":1720000000000,"version":1,"volumes":[],"warm_snapshot":{"kind":"absent"}}"#;

const EMPTY_INVENTORY_INPUT: &str = r#"{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":4,"inventory_read_position":12,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","residue":[],"runtimes":[],"version":1}"#;

const UNEXPECTED_INVENTORY_INPUT: &str = r#"{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":5,"inventory_read_position":13,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","residue":[{"kind":"control_socket","ownership_token":{"kind":"valid","ownership_token":"abababababababababababababababab"},"role_hint":null,"socket_path":"/run/cats/orphan/valid.sock"},{"checkpoint_path":"/var/lib/cats/checkpoints/cat_01.json","evidence":{"cat_id":"cat_01","content_digest":"sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb","desired_revision":7,"kind":"valid","node_id":"node_a","placement_epoch":3,"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","version":1},"kind":"checkpoint_file"}],"runtimes":[],"version":1}"#;

const NONEMPTY_INVENTORY_INPUT: &str = r#"{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":4,"inventory_read_position":12,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","residue":[{"cgroup_path":"/sys/fs/cgroup/system.slice/cats-orphan.scope","kind":"systemd_scope","ownership_token":{"kind":"valid","ownership_token":"dddddddddddddddddddddddddddddddd"},"scope_id":"cats-orphan.scope"},{"kind":"control_socket","ownership_token":{"kind":"missing"},"role_hint":null,"socket_path":"/run/cats/orphan/control.sock"},{"checkpoint_path":"/var/lib/cats/checkpoints/orphan.json","evidence":{"kind":"corrupt","raw_content_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"kind":"checkpoint_file"},{"data_directory":"/var/lib/cats/orphan-vol","kind":"data_directory","lineage":{"attachment_epoch_hint":4,"attachment_id_hint":"att_orphan","fenced":false,"kind":"readable","local_durable_generation":6,"pending_pack_count":2,"remote_durable_generation":5},"ownership_token":{"kind":"corrupt","raw_content_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"volume_id_hint":null}],"runtimes":[{"applied_desired":{"desired_revision":7,"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","target":"running"},"cat_id":"cat_01","checkpoint":{"cat_id":"cat_01","checkpoint_path":"/var/lib/cats/checkpoints/cat_01.json","content_digest":"sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb","desired_revision":7,"kind":"valid","node_id":"node_a","placement_epoch":3,"require_idle":{"kind":"not_applicable"},"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"updated_at_unix_ms":1720000000000,"version":1},"guest_transport":{"guest_agent_protocol_version":1,"guest_boot_id":"cccccccccccccccccccccccccccccccc","guest_cid":3,"guest_port":5000,"kind":"vsock_ready","runtime_incarnation":"55555555555555555555555555555555"},"lifecycle_admission":"closed","mounts":[{"access":"read_write","filesystem_uuid":"99999999999999999999999999999999","guest_device":{"serial":"cats-root","slot":0},"instance_count":1,"mount_path":"/","source_path":"/dev/nbd0","volume_id":"vol_root"}],"networks":[{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","ownership_token":{"kind":"valid","ownership_token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"prefix_length":30,"tap_name":"tap0"},{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","ownership_token":{"kind":"corrupt","raw_content_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"prefix_length":30,"tap_name":"tap1"}],"platform_guards":0,"processes":[{"control_handshake":{"kind":"verified"},"control_socket_path":"/run/cats/cat_01/vmm.sock","executable_path":"/usr/bin/cloud-hypervisor","observed_vm_shape":{"boot_image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","guest_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","memory_bytes":2147483648,"vcpus":2},"ownership_token":{"kind":"valid","ownership_token":"66666666666666666666666666666666"},"process_id":1001,"process_start_time_ticks":9001,"role":{"kind":"vmm","runtime_incarnation":"55555555555555555555555555555555"},"scope_id":"cats-cat_01","state":"running"},{"control_handshake":{"kind":"verified"},"control_socket_path":"/run/cats/cat_01/blockd-root.sock","executable_path":"/usr/bin/cats-blockd","observed_vm_shape":null,"ownership_token":{"kind":"valid","ownership_token":"77777777777777777777777777777777"},"process_id":1002,"process_start_time_ticks":9002,"role":{"attachment_epoch":8,"attachment_id":"att_01","kind":"blockd","volume_id":"vol_root"},"scope_id":"cats-cat_01","state":"running"}],"routes":[{"active_guards":0,"binding":{"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.example.test","node_id":"node_a","protocol":"http","route_epoch":9,"runtime_incarnation":"55555555555555555555555555555555","target_port":8080,"workspace_id":"ws_01"},"cancellation_pending":false,"gate":"closed","instance_count":2},{"active_guards":0,"binding":{"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.example.test","node_id":"node_a","protocol":"http","route_epoch":10,"runtime_incarnation":"55555555555555555555555555555555","target_port":8080,"workspace_id":"ws_01"},"cancellation_pending":false,"gate":"closed","instance_count":1}],"runtime_incarnation":"55555555555555555555555555555555","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"volumes":[{"authority":{"attachment_epoch":8,"attachment_id":"att_01","head":{"generation":4,"root_hash":"sha256:2222222222222222222222222222222222222222222222222222222222222222","root_object_id":"volumes/vol_root/roots/4"},"kind":"owned"},"devices":[{"device_path":"/dev/nbd0","guest_device":{"serial":"cats-root","slot":0},"kind":"kernel_nbd","ownership_token":{"kind":"valid","ownership_token":"88888888888888888888888888888888"}},{"guest_device":{"serial":"cats-root","slot":0},"kind":"vhost_user_blk","ownership_token":{"kind":"missing"},"socket_path":"/run/cats/cat_01/root.sock"}],"disk_id":"disk_root","disk_kind":"root","durability":"strict","local_lineages":[{"acquire_origin":{"kind":"normal","transition_id":"13579bdf2468ace013579bdf2468ace0"},"attachment_epoch":8,"attachment_id":"att_01","data_directory":"/var/lib/cats/vol_root","fenced":false,"local_durable_generation":5,"node_id":"node_a","pending_pack_count":1,"placement_epoch":3,"remote_durable_generation":4,"state":"active"}],"size_bytes":4294967296,"volume_id":"vol_root","volume_intent_id":"vint_root"}],"warm_snapshot":{"kind":"absent"}}],"version":1}"#;

const NODE_CLEANUP_WIRE: &str = r#"{"cleanup":{"desired_read_position":15,"inventory_epoch":4,"inventory_read_position":12,"inventory_session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"target":{"cat_id":"cat_01","checkpoint_path":"/var/lib/cats/checkpoints/cat_01.json","content_digest":"sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb","desired_revision":7,"kind":"checkpoint_file","node_id":"node_a","placement_epoch":3},"volume_release":null},"node_id":"node_a","version":1}"#;

const VOLUME_CLEANUP_WIRE: &str = r#"{"desired_read_position":15,"inventory_epoch":5,"inventory_read_position":13,"inventory_session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"target":{"attachment_epoch":8,"attachment_id":"att_01","kind":"volume","volume_id":"vol_root"},"volume_release":{"disposition":{"kind":"detach_retained"},"generation":5,"release_transition_id":"acacacacacacacacacacacacacacacac"}}"#;

const CONTRACT_ERROR_WIRE: &str = r#"{"error":{"accepted_observation_id":"10101010101010101010101010101010","agent_session_epoch":2,"code":"observation_sequence_conflict","heartbeat_sequence":19,"node_id":"node_a","presented_observation_id":"20202020202020202020202020202020"},"message":"same sequence carried a different observation","version":1}"#;

fn desired_wire(claim: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_str(DESIRED_DIGEST_INPUT).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("spec_digest".to_owned(), claim.into());
    serde_json::to_vec(&value).unwrap()
}

fn desired_value() -> serde_json::Value {
    serde_json::from_slice(&desired_wire(SPEC_DIGEST)).unwrap()
}

fn zero_remote_head() -> serde_json::Value {
    serde_json::json!({
        "generation": 0,
        "root_hash": null,
        "root_object_id": null,
    })
}

fn nonzero_remote_head() -> serde_json::Value {
    serde_json::json!({
        "generation": 1,
        "root_hash": ZERO_DIGEST,
        "root_object_id": "volumes/vol_root/roots/1",
    })
}

fn normal_acquire_step(lease_duration_ms: u64) -> serde_json::Value {
    serde_json::json!({
        "kind": "acquire_volume",
        "request": {
            "kind": "normal",
            "volume_id": "vol_root",
            "transition_id": "22222222222222222222222222222222",
            "attachment_id": "att_01",
            "expected_unowned_epoch": 0,
            "desired_revision": 7,
            "placement_epoch": 3,
            "lease_duration_ms": lease_duration_ms,
        },
    })
}

fn provision_root_image_step(size_bytes: u64) -> serde_json::Value {
    serde_json::json!({
        "kind": "provision_root_image",
        "provision_transition_id": "1234567890abcdef1234567890abcdef",
        "volume_id": "vol_root",
        "attachment_id": "att_01",
        "attachment_epoch": 8,
        "scope_id": "cats-cat_01-root-provision",
        "control_socket_path": "/run/cats/cat_01/blockd-root.sock",
        "data_directory": "/var/lib/cats/vol_root",
        "process_identity_token": "fedcba0987654321fedcba0987654321",
        "size_bytes": size_bytes,
        "boot_image_digest": ZERO_DIGEST,
        "expected_blank_head": zero_remote_head(),
        "expected_provisioned_head": nonzero_remote_head(),
    })
}

fn provision_root_image_request_value() -> serde_json::Value {
    serde_json::json!({
        "provision_transition_id": "1234567890abcdef1234567890abcdef",
        "volume_id": "vol_root",
        "attachment_id": "att_01",
        "attachment_epoch": 8,
        "size_bytes": 4_294_967_296_u64,
        "boot_image_digest": ZERO_DIGEST,
        "expected_blank_head": zero_remote_head(),
        "expected_provisioned_head": nonzero_remote_head(),
    })
}

fn provision_root_image_result_value() -> serde_json::Value {
    serde_json::json!({
        "provision_transition_id": "1234567890abcdef1234567890abcdef",
        "volume_id": "vol_root",
        "attachment_id": "att_01",
        "attachment_epoch": 8,
        "resulting_head": nonzero_remote_head(),
    })
}

fn provision_root_image_error_value(kind: &str, problem: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "provision_transition_id": "1234567890abcdef1234567890abcdef",
        "volume_id": "vol_root",
        "attachment_id": "att_01",
        "attachment_epoch": 8,
        "problem": problem,
    })
}

fn checkpoint_route_gate(endpoint_id: &str, route_epoch: u64, gate: &str) -> serde_json::Value {
    serde_json::json!({
        "binding": {
            "workspace_id": "ws_01",
            "endpoint_id": endpoint_id,
            "hostname": "app.example.test",
            "cat_id": "cat_01",
            "node_id": "node_a",
            "runtime_incarnation": "55555555555555555555555555555555",
            "protocol": "http",
            "target_port": 8080,
            "route_epoch": route_epoch,
        },
        "gate": gate,
    })
}

fn refresh_spec_digest(value: &mut serde_json::Value) {
    let spec: DesiredRuntimeSpec = serde_json::from_value(value.clone()).unwrap();
    value["spec_digest"] = spec_digest(&spec).unwrap().as_str().into();
}

fn node_identity_value() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "node_id": "node_a",
        "immutable_host_id": "host_a",
        "credential_id": "cred_a",
        "credential_binding": {
            "kind": "public_key",
            "public_key_spki_sha256": ZERO_DIGEST,
        },
        "state_path_id": "state_a",
        "state": "provisioned",
    })
}

fn desired_with_volume_count(count: usize) -> serde_json::Value {
    let mut value = desired_value();
    let template = value["volumes"][0].clone();
    let mut volumes = Vec::new();
    for index in 0..count {
        let mut volume = template.clone();
        volume["volume_intent_id"] = format!("intent_{index:03}").into();
        volume["disk_id"] = format!("disk_{index:03}").into();
        volume["volume_id"] = format!("volume_{index:03}").into();
        volume["attachment_id"] = format!("attachment_{index:03}").into();
        volume["guest_device"]["serial"] = format!("serial_{index:03}").into();
        volume["guest_device"]["slot"] = index.into();
        volumes.push(volume);
    }
    value["volumes"] = volumes.into();
    value
}

fn replace_once(input: &str, from: &str, to: &str) -> Vec<u8> {
    assert_eq!(input.matches(from).count(), 1, "replacement must be unique");
    input.replacen(from, to, 1).into_bytes()
}

fn operation_value() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "operation_id": "op_01",
        "workspace_id": "ws_01",
        "cat_id": "cat_01",
        "desired_revision": 7,
        "desired_spec_digest": SPEC_DIGEST,
        "placement": {"kind": "assigned", "node_id": "node_a", "placement_epoch": 3},
        "target": "cold",
        "phase": "pending",
        "terminal": null,
        "created_at_unix_ms": 1,
        "updated_at_unix_ms": 1,
    })
}

fn reject_node_identity(bytes: &[u8]) -> ContractError {
    decode_node_identity(bytes).unwrap_err()
}

fn reject_registration(bytes: &[u8]) -> ContractError {
    decode_agent_registration_attempt(bytes).unwrap_err()
}

fn reject_session(bytes: &[u8]) -> ContractError {
    decode_agent_session(bytes).unwrap_err()
}

fn reject_attestation(bytes: &[u8]) -> ContractError {
    decode_admission_inventory_attestation(bytes).unwrap_err()
}

fn reject_desired(bytes: &[u8]) -> ContractError {
    decode_desired_runtime_spec(bytes).unwrap_err()
}

fn reject_checkpoint(bytes: &[u8]) -> ContractError {
    decode_runtime_checkpoint(bytes).unwrap_err()
}

fn reject_node_cleanup(bytes: &[u8]) -> ContractError {
    decode_node_cleanup_checkpoint(bytes).unwrap_err()
}

fn reject_observation(bytes: &[u8]) -> ContractError {
    decode_node_observation(bytes).unwrap_err()
}

fn reject_operation(bytes: &[u8]) -> ContractError {
    decode_operation(bytes).unwrap_err()
}

fn reject_contract_error(bytes: &[u8]) -> ContractError {
    decode_contract_error(bytes).unwrap_err()
}

fn reject_provision_request(bytes: &[u8]) -> ProvisionRootImageWireDecodeError {
    decode_provision_root_image_request(bytes).unwrap_err()
}

fn reject_provision_result(bytes: &[u8]) -> ProvisionRootImageWireDecodeError {
    decode_provision_root_image_result(bytes).unwrap_err()
}

fn reject_provision_error(bytes: &[u8]) -> ProvisionRootImageWireDecodeError {
    decode_provision_root_image_error(bytes).unwrap_err()
}

fn accept_provision_request(bytes: &[u8]) -> Result<(), ProvisionRootImageWireDecodeError> {
    decode_provision_root_image_request(bytes).map(|_| ())
}

fn accept_provision_result(bytes: &[u8]) -> Result<(), ProvisionRootImageWireDecodeError> {
    decode_provision_root_image_result(bytes).map(|_| ())
}

fn accept_provision_error(bytes: &[u8]) -> Result<(), ProvisionRootImageWireDecodeError> {
    decode_provision_root_image_error(bytes).map(|_| ())
}

fn complete_observation_wire(projection: &str, claim: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_str(projection).unwrap();
    let object = value.as_object_mut().unwrap();
    object.insert(
        "observation_id".to_owned(),
        "10101010101010101010101010101010".into(),
    );
    object.insert("heartbeat_sequence".to_owned(), 1.into());
    object.insert("observed_at_unix_ms".to_owned(), 1.into());
    object.insert("complete_inventory".to_owned(), true.into());
    object.insert("inventory_digest".to_owned(), claim.into());
    object.insert("key_ring_version".to_owned(), serde_json::Value::Null);
    object.insert("key_ring_digest".to_owned(), serde_json::Value::Null);
    object.insert("loaded_kids".to_owned(), serde_json::json!([]));
    for runtime in object.get_mut("runtimes").unwrap().as_array_mut().unwrap() {
        runtime
            .as_object_mut()
            .unwrap()
            .insert("conditions".to_owned(), serde_json::json!([]));
    }
    serde_json::to_vec(&value).unwrap()
}

fn nonempty_observation_value() -> serde_json::Value {
    serde_json::from_slice(&complete_observation_wire(
        NONEMPTY_INVENTORY_INPUT,
        "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe",
    ))
    .unwrap()
}

fn refresh_inventory_digest(value: &mut serde_json::Value) {
    let observation: NodeObservation = serde_json::from_value(value.clone()).unwrap();
    let digest = inventory_digest(&observation).unwrap();
    value["inventory_digest"] = digest.as_str().into();
}

fn minimal_runtime(cat_id: &str, checkpoint_path: &str) -> serde_json::Value {
    let mut runtime: serde_json::Value =
        serde_json::from_str::<serde_json::Value>(NONEMPTY_INVENTORY_INPUT).unwrap()["runtimes"][0]
            .clone();
    runtime["cat_id"] = cat_id.into();
    runtime["applied_desired"]["target"] = "cold".into();
    runtime["runtime_incarnation"] = serde_json::Value::Null;
    runtime["stable_state"] = serde_json::Value::Null;
    runtime["checkpoint"]["cat_id"] = cat_id.into();
    runtime["checkpoint"]["checkpoint_path"] = checkpoint_path.into();
    runtime["checkpoint"]["runtime_incarnation"] = serde_json::Value::Null;
    runtime["checkpoint"]["stable_state"] = serde_json::Value::Null;
    runtime["processes"] = serde_json::json!([]);
    runtime["volumes"] = serde_json::json!([]);
    runtime["mounts"] = serde_json::json!([]);
    runtime["networks"] = serde_json::json!([]);
    runtime["guest_transport"] = serde_json::json!({"kind": "unavailable"});
    runtime["warm_snapshot"] = serde_json::json!({"kind": "absent"});
    runtime["routes"] = serde_json::json!([]);
    runtime["conditions"] = serde_json::json!([]);
    runtime
}

fn malformed(error: &ContractError) -> (&JsonPointer, MalformedProblem) {
    match error.error.as_ref() {
        ContractErrorDetail::MalformedPayload {
            json_pointer,
            problem,
            ..
        } => (json_pointer, *problem),
        detail => panic!("expected malformed_payload, got {detail:?}"),
    }
}

fn provision_wire_malformed(
    error: &ProvisionRootImageWireDecodeError,
) -> (&JsonPointer, MalformedProblem) {
    match error {
        ProvisionRootImageWireDecodeError::Malformed {
            json_pointer,
            problem,
        } => (json_pointer, *problem),
        ProvisionRootImageWireDecodeError::WireBytesLimitExceeded { .. } => {
            panic!("expected malformed provision payload, got {error:?}")
        }
    }
}

fn assert_inventory_collision(value: &serde_json::Value, pointer: &str) {
    let error = decode_node_observation(&serde_json::to_vec(value).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), pointer);
    assert_eq!(malformed(&error).1, MalformedProblem::DuplicateIdentity);
}

fn assert_valid_inventory(mut value: serde_json::Value) {
    refresh_inventory_digest(&mut value);
    decode_node_observation(&serde_json::to_vec(&value).unwrap()).unwrap();
}

fn canonical_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    fn write(value: &serde_json::Value, output: &mut Vec<u8>) {
        match value {
            serde_json::Value::Null => output.extend_from_slice(b"null"),
            serde_json::Value::Bool(true) => output.extend_from_slice(b"true"),
            serde_json::Value::Bool(false) => output.extend_from_slice(b"false"),
            serde_json::Value::Number(value) => {
                output.extend_from_slice(value.to_string().as_bytes())
            }
            serde_json::Value::String(value) => {
                output.extend_from_slice(serde_json::to_string(value).unwrap().as_bytes())
            }
            serde_json::Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(value, output);
                }
                output.push(b']');
            }
            serde_json::Value::Object(object) => {
                let mut members: Vec<_> = object.iter().collect();
                members.sort_unstable_by(|(left, _), (right, _)| {
                    left.as_bytes().cmp(right.as_bytes())
                });
                output.push(b'{');
                for (index, (key, value)) in members.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(serde_json::to_string(key).unwrap().as_bytes());
                    output.push(b':');
                    write(value, output);
                }
                output.push(b'}');
            }
        }
    }

    let mut output = Vec::new();
    write(&serde_json::to_value(value).unwrap(), &mut output);
    output
}

fn reverse_member_json(value: &serde_json::Value) -> Vec<u8> {
    fn write(value: &serde_json::Value, output: &mut Vec<u8>) {
        match value {
            serde_json::Value::Null => output.extend_from_slice(b"null"),
            serde_json::Value::Bool(true) => output.extend_from_slice(b"true"),
            serde_json::Value::Bool(false) => output.extend_from_slice(b"false"),
            serde_json::Value::Number(value) => {
                output.extend_from_slice(value.to_string().as_bytes())
            }
            serde_json::Value::String(value) => {
                output.extend_from_slice(serde_json::to_string(value).unwrap().as_bytes())
            }
            serde_json::Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(value, output);
                }
                output.push(b']');
            }
            serde_json::Value::Object(object) => {
                output.push(b'{');
                for (index, (key, value)) in object.iter().rev().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(serde_json::to_string(key).unwrap().as_bytes());
                    output.push(b':');
                    write(value, output);
                }
                output.push(b'}');
            }
        }
    }

    let mut output = Vec::new();
    write(value, &mut output);
    output
}

fn desired_projection(spec: &DesiredRuntimeSpec) -> serde_json::Value {
    let mut value = serde_json::to_value(spec).unwrap();
    value.as_object_mut().unwrap().remove("spec_digest");
    value
}

fn inventory_projection(observation: &NodeObservation) -> serde_json::Value {
    let source = serde_json::to_value(observation).unwrap();
    let source = source.as_object().unwrap();
    let mut runtimes = source["runtimes"].as_array().unwrap().clone();
    for runtime in &mut runtimes {
        runtime.as_object_mut().unwrap().remove("conditions");
    }
    serde_json::json!({
        "version": source["version"],
        "node_id": source["node_id"],
        "node_boot_id": source["node_boot_id"],
        "agent_instance_id": source["agent_instance_id"],
        "agent_session_epoch": source["agent_session_epoch"],
        "inventory_epoch": source["inventory_epoch"],
        "inventory_read_position": source["inventory_read_position"],
        "runtimes": runtimes,
        "residue": source["residue"],
    })
}

#[test]
fn fixed_desired_and_checkpoint_digests_match() {
    let desired = decode_desired_runtime_spec(&desired_wire(SPEC_DIGEST)).unwrap();
    assert_eq!(
        canonical_json(&desired_projection(&desired)),
        DESIRED_DIGEST_INPUT.as_bytes()
    );
    assert_eq!(spec_digest(&desired).unwrap().as_str(), SPEC_DIGEST);

    let checkpoint = decode_runtime_checkpoint(CHECKPOINT_WIRE.as_bytes()).unwrap();
    assert_eq!(canonical_json(&checkpoint), CHECKPOINT_WIRE.as_bytes());
    assert_eq!(
        checkpoint_content_digest(&checkpoint).unwrap().as_str(),
        CHECKPOINT_DIGEST
    );
}

#[test]
fn fixed_key_ring_digests_match() {
    let empty = key_ring_digest(Epoch::new(1).unwrap(), &[]).unwrap();
    assert_eq!(
        canonical_json(&serde_json::json!({
            "version": 1,
            "key_ring_version": 1,
            "loaded_kids": [],
        })),
        br#"{"key_ring_version":1,"loaded_kids":[],"version":1}"#
    );
    assert_eq!(
        empty.as_str(),
        "sha256:966a44bd1b4337c7e7dae913607740e7c7359bab2b7d4127419d63f3f9903cbb"
    );
    let kids = [
        KeyId::new("a".repeat(64)).unwrap(),
        KeyId::new("b".repeat(64)).unwrap(),
    ];
    let two = key_ring_digest(Epoch::new(5).unwrap(), &kids).unwrap();
    assert_eq!(
        canonical_json(&serde_json::json!({
            "version": 1,
            "key_ring_version": 5,
            "loaded_kids": ["a".repeat(64), "b".repeat(64)],
        })),
        br#"{"key_ring_version":5,"loaded_kids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"version":1}"#
    );
    assert_eq!(
        two.as_str(),
        "sha256:7881e60fd2e5dfa2fda716f560d6f124a7defd6c06b9d23c1038c42471cc8000"
    );
}

#[test]
fn sha256_digest_round_trips_the_public_byte_boundary() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let bytes = std::array::from_fn(|index| index as u8);
    let from_bytes = Sha256Digest::from_bytes(bytes);
    assert_eq!(from_bytes.as_bytes(), &bytes);

    let wire = serde_json::to_vec(&from_bytes).unwrap();
    let parsed: Sha256Digest = serde_json::from_slice(&wire).unwrap();
    assert_eq!(parsed.as_bytes(), &bytes);
    assert_eq!(parsed, from_bytes);

    let hash = |value: &Sha256Digest| {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    };
    assert_eq!(hash(&parsed), hash(&from_bytes));
}

#[test]
fn fixed_empty_inventory_digest_matches() {
    let expected = "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05";
    let observation =
        decode_node_observation(&complete_observation_wire(EMPTY_INVENTORY_INPUT, expected))
            .unwrap();
    assert_eq!(
        canonical_json(&inventory_projection(&observation)),
        EMPTY_INVENTORY_INPUT.as_bytes()
    );
    assert_eq!(inventory_digest(&observation).unwrap().as_str(), expected);
}

#[test]
fn fixed_unexpected_inventory_digest_matches() {
    let expected = "sha256:cfa4e65423289e7f61f400f00f1c9a11d1fb27c20d76a2c5653da1b125055f8f";
    let observation = decode_node_observation(&complete_observation_wire(
        UNEXPECTED_INVENTORY_INPUT,
        expected,
    ))
    .unwrap();
    assert_eq!(
        canonical_json(&inventory_projection(&observation)),
        UNEXPECTED_INVENTORY_INPUT.as_bytes()
    );
    assert_eq!(inventory_digest(&observation).unwrap().as_str(), expected);
}

#[test]
fn fixed_nonempty_inventory_digest_matches() {
    let expected = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    let observation = decode_node_observation(&complete_observation_wire(
        NONEMPTY_INVENTORY_INPUT,
        expected,
    ))
    .unwrap();
    assert_eq!(
        canonical_json(&inventory_projection(&observation)),
        NONEMPTY_INVENTORY_INPUT.as_bytes()
    );
    assert_eq!(inventory_digest(&observation).unwrap().as_str(), expected);
}

#[test]
fn fixed_non_digest_vectors_decode_exactly() {
    let volume_cleanup: CleanupRelease = serde_json::from_str(VOLUME_CLEANUP_WIRE).unwrap();
    assert_eq!(
        canonical_json(&volume_cleanup),
        VOLUME_CLEANUP_WIRE.as_bytes()
    );

    let cleanup = decode_node_cleanup_checkpoint(NODE_CLEANUP_WIRE.as_bytes()).unwrap();
    assert_eq!(cleanup.node_id.as_str(), "node_a");
    assert_eq!(canonical_json(&cleanup), NODE_CLEANUP_WIRE.as_bytes());

    let error = decode_contract_error(CONTRACT_ERROR_WIRE.as_bytes()).unwrap();
    assert_eq!(
        error.message,
        "same sequence carried a different observation"
    );
    assert_eq!(canonical_json(&error), CONTRACT_ERROR_WIRE.as_bytes());
}

#[test]
fn contract_error_variants_reject_self_contradictory_payloads() {
    let invalid_stale = serde_json::json!({
        "version": 1,
        "error": {
            "code": "stale_observation_sequence",
            "node_id": "node_a",
            "agent_session_epoch": 2,
            "presented_heartbeat_sequence": 20,
            "last_accepted_heartbeat_sequence": 19,
        },
        "message": "not stale",
    });
    let error = decode_contract_error(&serde_json::to_vec(&invalid_stale).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/error");

    let equal_digest = serde_json::json!({
        "version": 1,
        "error": {
            "code": "revision_digest_conflict",
            "cat_id": "cat_01",
            "desired_revision": 1,
            "expected_digest": ZERO_DIGEST,
            "presented_digest": ZERO_DIGEST,
        },
        "message": "not a conflict",
    });
    let error = decode_contract_error(&serde_json::to_vec(&equal_digest).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/error");

    let valid_stale = serde_json::json!({
        "version": 1,
        "error": {
            "code": "stale_revision",
            "cat_id": "cat_01",
            "presented_revision": 1,
            "current_revision": 2,
        },
        "message": "stale",
    });
    decode_contract_error(&serde_json::to_vec(&valid_stale).unwrap()).unwrap();
}

#[test]
fn all_explicit_encoders_validate_and_emit_canonical_wire() {
    let node_identity =
        decode_node_identity(&serde_json::to_vec(&node_identity_value()).unwrap()).unwrap();
    assert_eq!(
        encode_node_identity(&node_identity).unwrap(),
        canonical_json(&node_identity)
    );

    let registration = decode_agent_registration_attempt(
        br#"{"version":1,"node_id":"node_a","immutable_host_id":"host_a","node_boot_id":"11111111111111111111111111111111","agent_instance_id":"22222222222222222222222222222222","registration_attempt_id":"33333333333333333333333333333333","expected_agent_session_epoch":null}"#,
    )
    .unwrap();
    assert_eq!(
        encode_agent_registration_attempt(&registration).unwrap(),
        canonical_json(&registration)
    );

    let session = decode_agent_session(
        br#"{"version":1,"node_id":"node_a","immutable_host_id":"host_a","node_boot_id":"11111111111111111111111111111111","agent_instance_id":"22222222222222222222222222222222","agent_session_epoch":1,"registration_attempt_id":"33333333333333333333333333333333","lease_deadline_unix_ms":1}"#,
    )
    .unwrap();
    assert_eq!(
        encode_agent_session(&session).unwrap(),
        canonical_json(&session)
    );

    let attestation = decode_admission_inventory_attestation(
        format!(
            r#"{{"version":1,"node_id":"node_a","agent_session_epoch":1,"inventory_epoch":1,"inventory_digest":"{ZERO_DIGEST}","inventory_read_position":1,"accepted_at_unix_ms":1}}"#
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        encode_admission_inventory_attestation(&attestation).unwrap(),
        canonical_json(&attestation)
    );

    let desired = decode_desired_runtime_spec(&desired_wire(SPEC_DIGEST)).unwrap();
    assert_eq!(
        encode_desired_runtime_spec(&desired).unwrap(),
        canonical_json(&desired)
    );

    let checkpoint = decode_runtime_checkpoint(CHECKPOINT_WIRE.as_bytes()).unwrap();
    assert_eq!(
        encode_runtime_checkpoint(&checkpoint).unwrap(),
        CHECKPOINT_WIRE.as_bytes()
    );

    let cleanup = decode_node_cleanup_checkpoint(NODE_CLEANUP_WIRE.as_bytes()).unwrap();
    assert_eq!(
        encode_node_cleanup_checkpoint(&cleanup).unwrap(),
        NODE_CLEANUP_WIRE.as_bytes()
    );

    let observation = decode_node_observation(&complete_observation_wire(
        EMPTY_INVENTORY_INPUT,
        "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05",
    ))
    .unwrap();
    assert_eq!(
        encode_node_observation(&observation).unwrap(),
        canonical_json(&observation)
    );

    let operation = decode_operation(&serde_json::to_vec(&operation_value()).unwrap()).unwrap();
    assert_eq!(
        encode_operation(&operation).unwrap(),
        canonical_json(&operation)
    );

    let error = decode_contract_error(CONTRACT_ERROR_WIRE.as_bytes()).unwrap();
    assert_eq!(
        encode_contract_error(&error).unwrap(),
        CONTRACT_ERROR_WIRE.as_bytes()
    );

    let mut invalid_operation = operation;
    invalid_operation.updated_at_unix_ms = UnixMillis::new(0).unwrap();
    let error = encode_operation(&invalid_operation).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
}

#[test]
fn canonical_digests_ignore_member_order_and_bind_exact_projections() {
    let desired_input = desired_value();
    let desired = decode_desired_runtime_spec(&reverse_member_json(&desired_input)).unwrap();
    assert_eq!(spec_digest(&desired).unwrap().as_str(), SPEC_DIGEST);
    assert_eq!(
        encode_desired_runtime_spec(&desired).unwrap(),
        canonical_json(&desired)
    );

    let mut changed_claim = desired.clone();
    changed_claim.spec_digest = Sha256Digest::new(ZERO_DIGEST).unwrap();
    assert_eq!(spec_digest(&changed_claim).unwrap().as_str(), SPEC_DIGEST);

    let mut changed_spec = desired;
    changed_spec.runtime.vcpus = 3;
    let changed_digest = spec_digest(&changed_spec).unwrap();
    assert_ne!(changed_digest.as_str(), SPEC_DIGEST);
    assert_eq!(
        malformed(&encode_desired_runtime_spec(&changed_spec).unwrap_err())
            .0
            .as_str(),
        "/spec_digest"
    );
    changed_spec.spec_digest = changed_digest;
    encode_desired_runtime_spec(&changed_spec).unwrap();

    let checkpoint = decode_runtime_checkpoint(CHECKPOINT_WIRE.as_bytes()).unwrap();
    let mut changed_checkpoint = checkpoint.clone();
    changed_checkpoint.updated_at_unix_ms = UnixMillis::new(1_720_000_000_001).unwrap();
    assert_ne!(
        checkpoint_content_digest(&checkpoint).unwrap(),
        checkpoint_content_digest(&changed_checkpoint).unwrap()
    );

    let claim = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    let observation =
        decode_node_observation(&complete_observation_wire(NONEMPTY_INVENTORY_INPUT, claim))
            .unwrap();
    let mut condition_only = observation.clone();
    condition_only.runtimes[0]
        .conditions
        .push(Condition::Degraded {
            reason: DegradedReason::AttestationRefreshFailed {
                inventory_epoch: Epoch::new(4).unwrap(),
                since_unix_ms: UnixMillis::new(1).unwrap(),
            },
        });
    assert_eq!(
        inventory_digest(&condition_only).unwrap(),
        inventory_digest(&observation).unwrap()
    );

    let mut changed_inventory = observation.clone();
    changed_inventory.runtimes[0].routes[0].instance_count = 3;
    assert_ne!(
        inventory_digest(&changed_inventory).unwrap(),
        inventory_digest(&observation).unwrap()
    );
}

#[test]
fn transport_schema_and_number_errors_are_typed() {
    let invalid_utf8 = decode_node_identity(&[0xff]).unwrap_err();
    assert_eq!(malformed(&invalid_utf8).1, MalformedProblem::InvalidUtf8);
    assert_eq!(malformed(&invalid_utf8).0.as_str(), "");

    let invalid_json = decode_node_identity(br#"{"version":1"#).unwrap_err();
    assert_eq!(malformed(&invalid_json).1, MalformedProblem::InvalidJson);

    let duplicate = decode_node_identity(
        format!(
            r#"{{"version":1,"node_id":"node_a","node_id":"node_b","immutable_host_id":"host","credential_id":"cred","credential_binding":{{"kind":"public_key","public_key_spki_sha256":"{ZERO_DIGEST}"}},"state_path_id":"state","state":"provisioned"}}"#
        )
        .as_bytes(),
    )
    .unwrap_err();
    assert_eq!(malformed(&duplicate).1, MalformedProblem::DuplicateField);
    assert_eq!(malformed(&duplicate).0.as_str(), "/node_id");

    let non_integer = decode_agent_session(
        br#"{"version":1,"node_id":"node","immutable_host_id":"host","node_boot_id":"11111111111111111111111111111111","agent_instance_id":"22222222222222222222222222222222","agent_session_epoch":1e0,"registration_attempt_id":"33333333333333333333333333333333","lease_deadline_unix_ms":0}"#,
    )
    .unwrap_err();
    assert_eq!(malformed(&non_integer).1, MalformedProblem::InvalidValue);
    assert_eq!(malformed(&non_integer).0.as_str(), "/agent_session_epoch");
}

#[test]
fn malformed_json_table_fails_at_the_transport_boundary() {
    let cases: &[&[u8]] = &[
        b"",
        b"   ",
        b"{",
        br#"{"value":01}"#,
        br#"{"value":"\uD800"}"#,
        br#"{"value":tru}"#,
        br#"{1:2}"#,
        br#"{"value":[1,]}"#,
        br#"{"value":1} trailing"#,
    ];
    for input in cases {
        let error = decode_node_identity(input).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), "", "{input:?}");
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::InvalidJson,
            "{input:?}"
        );
    }
}

#[test]
fn unsigned_numbers_preserve_lexemes_and_enforce_domain_boundaries() {
    let base = r#"{"version":1,"node_id":"node","immutable_host_id":"host","node_boot_id":"11111111111111111111111111111111","agent_instance_id":"22222222222222222222222222222222","agent_session_epoch":1,"registration_attempt_id":"33333333333333333333333333333333","lease_deadline_unix_ms":0}"#;
    let epoch = r#""agent_session_epoch":1"#;

    let wrong_type = replace_once(base, epoch, r#""agent_session_epoch":"1""#);
    let error = decode_agent_session(&wrong_type).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/agent_session_epoch");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidType);

    for token in ["0", "1.0", "1e0", "-0", "-1", "9223372036854775808"] {
        let bytes = replace_once(base, epoch, &format!(r#""agent_session_epoch":{token}"#));
        let error = decode_agent_session(&bytes).unwrap_err();
        assert_eq!(
            malformed(&error).0.as_str(),
            "/agent_session_epoch",
            "{token}"
        );
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::InvalidValue,
            "{token}"
        );
    }

    let maximum = replace_once(base, epoch, r#""agent_session_epoch":9223372036854775807"#);
    decode_agent_session(&maximum).unwrap();
    let maximum_millis = replace_once(
        base,
        r#""lease_deadline_unix_ms":0"#,
        r#""lease_deadline_unix_ms":9223372036854775807"#,
    );
    decode_agent_session(&maximum_millis).unwrap();

    let mut operation = operation_value();
    operation["desired_revision"] = serde_json::json!(9_223_372_036_854_775_807_u64);
    operation["placement"]["placement_epoch"] = serde_json::json!(9_223_372_036_854_775_807_u64);
    decode_operation(&serde_json::to_vec(&operation).unwrap()).unwrap();

    let mut observation: serde_json::Value = serde_json::from_slice(&complete_observation_wire(
        EMPTY_INVENTORY_INPUT,
        "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05",
    ))
    .unwrap();
    observation["heartbeat_sequence"] = serde_json::json!(9_223_372_036_854_775_807_u64);
    decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap();

    let mut desired = decode_desired_runtime_spec(&desired_wire(SPEC_DIGEST)).unwrap();
    desired.runtime.vcpus = u32::MAX;
    desired.runtime.memory_bytes = 9_223_372_036_854_775_807;
    desired.endpoints[0].target_port = u16::MAX;
    if let VolumeAcquire::Normal {
        expected_unowned_epoch,
        ..
    } = &mut desired.volumes[0].acquire
    {
        *expected_unowned_epoch = FenceEpoch::new(9_223_372_036_854_775_807).unwrap();
    }
    desired.spec_digest = spec_digest(&desired).unwrap();
    encode_desired_runtime_spec(&desired).unwrap();

    desired.runtime.memory_bytes = 9_223_372_036_854_775_808;
    let error = spec_digest(&desired).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/runtime/memory_bytes");
}

#[test]
fn transport_and_schema_scan_the_tail_after_an_array_limit() {
    let value = desired_with_volume_count(65);
    let encoded = serde_json::to_string(&value).unwrap();

    let mut invalid_json = encoded.clone();
    assert_eq!(invalid_json.pop(), Some('}'));
    invalid_json.push_str(r#", "tail":"#);
    let error = decode_desired_runtime_spec(invalid_json.as_bytes()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidJson);

    let duplicate = replace_once(
        &encoded,
        r#""disk_id":"disk_064""#,
        r#""disk_id":"disk_064","disk_id":"other""#,
    );
    let error = decode_desired_runtime_spec(&duplicate).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/volumes/64/disk_id");
    assert_eq!(malformed(&error).1, MalformedProblem::DuplicateField);

    let mut unknown = value.clone();
    unknown["volumes"][64]["tail_unknown"] = true.into();
    let error = decode_desired_runtime_spec(&serde_json::to_vec(&unknown).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/volumes/64/tail_unknown");
    assert_eq!(malformed(&error).1, MalformedProblem::UnknownField);

    let mut missing = value.clone();
    missing["volumes"][64]
        .as_object_mut()
        .unwrap()
        .remove("disk_id");
    let error = decode_desired_runtime_spec(&serde_json::to_vec(&missing).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/volumes/64/disk_id");
    assert_eq!(malformed(&error).1, MalformedProblem::MissingField);

    let mut unknown_tag = value;
    unknown_tag["volumes"][64]["acquire"]["kind"] = "future".into();
    let error =
        decode_desired_runtime_spec(&serde_json::to_vec(&unknown_tag).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/volumes/64/acquire/kind");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
}

#[test]
fn candidate_selection_is_independent_of_object_member_order() {
    let first = format!(
        r#"{{"version":1,"node_id":"node_a","node_id":"node_b","immutable_host_id":"host","credential_id":"cred","credential_binding":{{"kind":"public_key","public_key_spki_sha256":"{ZERO_DIGEST}"}},"state_path_id":"state","state":"provisioned","state":"retired"}}"#
    );
    let second = format!(
        r#"{{"state":"provisioned","state":"retired","state_path_id":"state","credential_binding":{{"public_key_spki_sha256":"{ZERO_DIGEST}","kind":"public_key"}},"credential_id":"cred","immutable_host_id":"host","node_id":"node_a","node_id":"node_b","version":1}}"#
    );
    for input in [first, second] {
        let error = decode_node_identity(input.as_bytes()).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), "/node_id");
        assert_eq!(malformed(&error).1, MalformedProblem::DuplicateField);
    }

    let nested_before_parent =
        decode_node_identity(br#"{"z":1,"z":2,"a":{"q":1,"q":2}}"#).unwrap_err();
    assert_eq!(malformed(&nested_before_parent).0.as_str(), "/a/q");
    let parent_prefix =
        decode_node_identity(br#"{"a":{"q":1,"q":2},"a":{"p":1,"p":2}}"#).unwrap_err();
    assert_eq!(malformed(&parent_prefix).0.as_str(), "/a");

    let schema_candidates = serde_json::json!({
        "version": 1,
        "node_id": "node_a",
        "immutable_host_id": "host",
        "credential_binding": {
            "kind": "public_key",
            "public_key_spki_sha256": ZERO_DIGEST,
        },
        "state_path_id": "state",
        "state": true,
        "zzz": 1,
    });
    for input in [
        serde_json::to_vec(&schema_candidates).unwrap(),
        reverse_member_json(&schema_candidates),
    ] {
        let error = decode_node_identity(&input).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), "/credential_id");
        assert_eq!(malformed(&error).1, MalformedProblem::MissingField);
    }
}

#[test]
fn digest_claim_and_union_stages_are_deterministic() {
    let mismatch = decode_desired_runtime_spec(&desired_wire(ZERO_DIGEST)).unwrap_err();
    assert_eq!(malformed(&mismatch).0.as_str(), "/spec_digest");
    assert_eq!(malformed(&mismatch).1, MalformedProblem::InvalidValue);

    let unknown_tag_and_missing = decode_node_identity(
        br#"{"version":1,"node_id":"node","immutable_host_id":"host","credential_id":"cred","credential_binding":{"kind":"future"},"state_path_id":"state"}"#,
    )
    .unwrap_err();
    assert_eq!(malformed(&unknown_tag_and_missing).0.as_str(), "/state");
    assert_eq!(
        malformed(&unknown_tag_and_missing).1,
        MalformedProblem::MissingField
    );

    let unknown_tag_does_not_guess_a_variant = decode_node_identity(
        br#"{"version":1,"node_id":"node","immutable_host_id":"host","credential_id":"cred","credential_binding":{"kind":"future","public_key_spki_sha256":1},"state_path_id":"state","state":"provisioned"}"#,
    )
    .unwrap_err();
    assert_eq!(
        malformed(&unknown_tag_does_not_guess_a_variant).0.as_str(),
        "/credential_binding/kind"
    );
    assert_eq!(
        malformed(&unknown_tag_does_not_guess_a_variant).1,
        MalformedProblem::InvalidValue
    );

    let mut nested_tag_before_outer_variant = operation_value();
    nested_tag_before_outer_variant["phase"] = "failed".into();
    nested_tag_before_outer_variant["terminal"] = serde_json::json!({
        "kind": "failed",
        "error": {
            "kind": "precondition_failed",
            "reason": {"kind": "future"}
        }
    });
    let error = decode_operation(&serde_json::to_vec(&nested_tag_before_outer_variant).unwrap())
        .unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/terminal/error/reason/kind");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
}

#[test]
fn observation_inventory_and_key_ring_nullability_is_closed() {
    let inventory_claim = "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05";
    let empty_ring_claim =
        "sha256:966a44bd1b4337c7e7dae913607740e7c7359bab2b7d4127419d63f3f9903cbb";
    let base: serde_json::Value = serde_json::from_slice(&complete_observation_wire(
        EMPTY_INVENTORY_INPUT,
        inventory_claim,
    ))
    .unwrap();

    decode_node_observation(&serde_json::to_vec(&base).unwrap()).unwrap();

    let mut empty_ring = base.clone();
    empty_ring["key_ring_version"] = 1.into();
    empty_ring["key_ring_digest"] = empty_ring_claim.into();
    decode_node_observation(&serde_json::to_vec(&empty_ring).unwrap()).unwrap();

    let mut cases = Vec::new();
    let mut only_version = base.clone();
    only_version["key_ring_version"] = 1.into();
    cases.push(only_version);
    let mut only_digest = base.clone();
    only_digest["key_ring_digest"] = empty_ring_claim.into();
    cases.push(only_digest);
    let mut unavailable_with_key = base.clone();
    unavailable_with_key["loaded_kids"] = serde_json::json!(["a".repeat(64)]);
    cases.push(unavailable_with_key);
    let mut partial_with_claim = base.clone();
    partial_with_claim["complete_inventory"] = false.into();
    cases.push(partial_with_claim);

    for value in cases {
        let error = decode_node_observation(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), "");
        assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
    }

    let mut wrong_ring_claim = empty_ring;
    wrong_ring_claim["key_ring_digest"] = ZERO_DIGEST.into();
    let error =
        decode_node_observation(&serde_json::to_vec(&wrong_ring_claim).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/key_ring_digest");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);

    let mut valid_partial = base;
    valid_partial["complete_inventory"] = false.into();
    valid_partial["inventory_digest"] = serde_json::Value::Null;
    valid_partial["inventory_read_position"] = serde_json::Value::Null;
    decode_node_observation(&serde_json::to_vec(&valid_partial).unwrap()).unwrap();
}

#[test]
fn all_wire_byte_boundaries_and_shared_schema_initialization_are_safe() {
    type Decode = fn(&[u8]) -> Result<(), ContractError>;

    let node = serde_json::to_vec(&node_identity_value()).unwrap();
    let registration = br#"{"version":1,"node_id":"node_a","immutable_host_id":"host_a","node_boot_id":"11111111111111111111111111111111","agent_instance_id":"22222222222222222222222222222222","registration_attempt_id":"33333333333333333333333333333333","expected_agent_session_epoch":null}"#.to_vec();
    let session = br#"{"version":1,"node_id":"node_a","immutable_host_id":"host_a","node_boot_id":"11111111111111111111111111111111","agent_instance_id":"22222222222222222222222222222222","agent_session_epoch":1,"registration_attempt_id":"33333333333333333333333333333333","lease_deadline_unix_ms":1}"#.to_vec();
    let attestation = format!(
        r#"{{"version":1,"node_id":"node_a","agent_session_epoch":1,"inventory_epoch":1,"inventory_digest":"{ZERO_DIGEST}","inventory_read_position":1,"accepted_at_unix_ms":1}}"#
    )
    .into_bytes();
    let observation = complete_observation_wire(
        EMPTY_INVENTORY_INPUT,
        "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05",
    );
    let cases: Vec<(ContractName, usize, Vec<u8>, Decode)> = vec![
        (
            ContractName::NodeIdentity,
            NODE_IDENTITY_MAX_WIRE_BYTES,
            node.clone(),
            |bytes| decode_node_identity(bytes).map(|_| ()),
        ),
        (
            ContractName::AgentRegistrationAttempt,
            AGENT_REGISTRATION_ATTEMPT_MAX_WIRE_BYTES,
            registration,
            |bytes| decode_agent_registration_attempt(bytes).map(|_| ()),
        ),
        (
            ContractName::AgentSession,
            AGENT_SESSION_MAX_WIRE_BYTES,
            session,
            |bytes| decode_agent_session(bytes).map(|_| ()),
        ),
        (
            ContractName::AdmissionInventoryAttestation,
            ADMISSION_INVENTORY_ATTESTATION_MAX_WIRE_BYTES,
            attestation,
            |bytes| decode_admission_inventory_attestation(bytes).map(|_| ()),
        ),
        (
            ContractName::DesiredRuntimeSpec,
            DESIRED_RUNTIME_SPEC_MAX_WIRE_BYTES,
            desired_wire(SPEC_DIGEST),
            |bytes| decode_desired_runtime_spec(bytes).map(|_| ()),
        ),
        (
            ContractName::RuntimeCheckpoint,
            RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
            CHECKPOINT_WIRE.as_bytes().to_vec(),
            |bytes| decode_runtime_checkpoint(bytes).map(|_| ()),
        ),
        (
            ContractName::NodeCleanupCheckpoint,
            NODE_CLEANUP_CHECKPOINT_MAX_WIRE_BYTES,
            NODE_CLEANUP_WIRE.as_bytes().to_vec(),
            |bytes| decode_node_cleanup_checkpoint(bytes).map(|_| ()),
        ),
        (
            ContractName::NodeObservation,
            NODE_OBSERVATION_MAX_WIRE_BYTES,
            observation,
            |bytes| decode_node_observation(bytes).map(|_| ()),
        ),
        (
            ContractName::Operation,
            OPERATION_MAX_WIRE_BYTES,
            serde_json::to_vec(&operation_value()).unwrap(),
            |bytes| decode_operation(bytes).map(|_| ()),
        ),
        (
            ContractName::ContractError,
            CONTRACT_ERROR_MAX_WIRE_BYTES,
            CONTRACT_ERROR_WIRE.as_bytes().to_vec(),
            |bytes| decode_contract_error(bytes).map(|_| ()),
        ),
    ];

    for (expected_contract, maximum_bytes, mut wire, decode) in cases {
        assert!(wire.len() <= maximum_bytes, "{expected_contract:?}");
        wire.resize(maximum_bytes, b' ');
        decode(&wire).unwrap_or_else(|error| panic!("{expected_contract:?}: {error:?}"));

        wire.push(b' ');
        let error = decode(&wire).unwrap_err();
        match error.error.as_ref() {
            ContractErrorDetail::LimitExceeded {
                contract,
                json_pointer,
                limit,
                maximum,
                observed_at_least,
            } => {
                assert_eq!(*contract, expected_contract);
                assert_eq!(json_pointer.as_str(), "");
                assert_eq!(*limit, LimitKind::WireBytes);
                assert_eq!(maximum.get(), maximum_bytes as u64);
                assert_eq!(observed_at_least.get(), maximum_bytes as u64 + 1);
            }
            detail => panic!("expected wire byte limit for {expected_contract:?}, got {detail:?}"),
        }
    }

    let node = std::sync::Arc::new(node);
    let mut workers = Vec::new();
    for _ in 0..16 {
        let node = std::sync::Arc::clone(&node);
        workers.push(std::thread::spawn(move || {
            let value = decode_node_identity(&node).unwrap();
            assert_eq!(
                encode_node_identity(&value).unwrap(),
                canonical_json(&value)
            );
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn id_and_host_path_boundaries_are_exact() {
    let mut identity = node_identity_value();
    identity["node_id"] = "a".repeat(128).into();
    decode_node_identity(&serde_json::to_vec(&identity).unwrap()).unwrap();
    identity["node_id"] = "a".repeat(129).into();
    let error = decode_node_identity(&serde_json::to_vec(&identity).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/node_id");

    let mut cleanup: serde_json::Value = serde_json::from_str(NODE_CLEANUP_WIRE).unwrap();
    cleanup["cleanup"]["target"]["checkpoint_path"] = format!("/{}", "a".repeat(4095)).into();
    decode_node_cleanup_checkpoint(&serde_json::to_vec(&cleanup).unwrap()).unwrap();

    cleanup["cleanup"]["target"]["checkpoint_path"] = format!("/{}", "a".repeat(4096)).into();
    let error = decode_node_cleanup_checkpoint(&serde_json::to_vec(&cleanup).unwrap()).unwrap_err();
    assert_eq!(
        malformed(&error).0.as_str(),
        "/cleanup/target/checkpoint_path"
    );

    cleanup["cleanup"]["target"]["checkpoint_path"] = "/tmp/\u{1}".into();
    let error = decode_node_cleanup_checkpoint(&serde_json::to_vec(&cleanup).unwrap()).unwrap_err();
    assert_eq!(
        malformed(&error).0.as_str(),
        "/cleanup/target/checkpoint_path"
    );

    cleanup["cleanup"]["target"]["checkpoint_path"] = "/数据/checkpoint".into();
    decode_node_cleanup_checkpoint(&serde_json::to_vec(&cleanup).unwrap()).unwrap();
}

#[test]
fn physical_observation_can_report_network_conflicts_but_desired_cannot_request_them() {
    let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint["networks"] = serde_json::json!([{
        "kind": "isolated_ipv4",
        "network_id": "net_bad",
        "guest_mac": "00:00:00:00:00:01",
        "guest_ipv4": "10.0.0.1",
        "prefix_length": 30,
        "gateway_ipv4": "10.0.0.5",
        "tap_name": "tap_bad",
        "ownership_token": {"kind": "missing"},
    }]);
    decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();

    let mut desired = desired_value();
    desired["runtime"]["network_config"]["guest_mac"] = "00:00:00:00:00:01".into();
    desired["runtime"]["network_config"]["gateway_ipv4"] = "10.0.0.9".into();
    let error = decode_desired_runtime_spec(&serde_json::to_vec(&desired).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/runtime/network_config");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
}

#[test]
fn checkpoint_route_gate_has_one_binding_source_of_truth() {
    let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    let inventory: serde_json::Value = serde_json::from_str(NONEMPTY_INVENTORY_INPUT).unwrap();
    checkpoint["route_gates"] = serde_json::json!([{
        "binding": inventory["runtimes"][0]["routes"][0]["binding"].clone(),
        "gate": "closed",
        "endpoint_id": "ep_01",
    }]);
    let error = decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/route_gates/0/endpoint_id");
    assert_eq!(malformed(&error).1, MalformedProblem::UnknownField);
}

#[test]
fn desired_disposition_rules_use_the_minimum_common_object() {
    let mut non_deleted = desired_value();
    non_deleted["volumes"][0]["disposition"] = serde_json::json!({"kind": "detach_retained"});
    let error =
        decode_desired_runtime_spec(&serde_json::to_vec(&non_deleted).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "");

    let mut persistent_delete = desired_value();
    persistent_delete["target"] = "deleted".into();
    persistent_delete["volumes"][0]["disk_kind"] = "persistent".into();
    persistent_delete["volumes"][0]["disposition"] =
        serde_json::json!({"kind": "delete_disposable_root", "delete_id": "delete_01"});
    persistent_delete["volumes"][0]["mount"] = serde_json::json!({
        "filesystem_uuid": "99999999999999999999999999999999",
        "mount_path": "/data",
        "initialization": {"kind": "existing"},
    });
    let error =
        decode_desired_runtime_spec(&serde_json::to_vec(&persistent_delete).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/volumes/0");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
}

#[test]
fn cleanup_release_intrinsic_constraints_are_bidirectional() {
    let cleanup: serde_json::Value = serde_json::from_str(VOLUME_CLEANUP_WIRE).unwrap();
    let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint["step"] = serde_json::json!({
        "kind": "cleanup_release",
        "cleanup": cleanup,
    });
    decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();

    let mut missing_release = checkpoint.clone();
    missing_release["step"]["cleanup"]["volume_release"] = serde_json::Value::Null;
    let error =
        decode_runtime_checkpoint(&serde_json::to_vec(&missing_release).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/step/cleanup");

    let mut extra_release = checkpoint.clone();
    extra_release["step"]["cleanup"]["target"] = serde_json::json!({
        "kind": "device",
        "volume_id": "vol_root",
        "ownership_token": "abababababababababababababababab",
    });
    let error =
        decode_runtime_checkpoint(&serde_json::to_vec(&extra_release).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/step/cleanup");

    let mut stale_read = checkpoint.clone();
    stale_read["step"]["cleanup"]["desired_read_position"] = 12.into();
    stale_read["step"]["cleanup"]["inventory_read_position"] = 13.into();
    let error = decode_runtime_checkpoint(&serde_json::to_vec(&stale_read).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/step/cleanup");

    let mut destructive_release = checkpoint;
    destructive_release["step"]["cleanup"]["volume_release"]["disposition"] =
        serde_json::json!({"kind": "delete_disposable_root", "delete_id": "delete_01"});
    let error =
        decode_runtime_checkpoint(&serde_json::to_vec(&destructive_release).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/step/cleanup");
}

#[test]
fn partial_observation_requires_applied_desired_for_every_reported_runtime() {
    let claim = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    let mut observation: serde_json::Value =
        serde_json::from_slice(&complete_observation_wire(NONEMPTY_INVENTORY_INPUT, claim))
            .unwrap();
    observation["complete_inventory"] = false.into();
    observation["inventory_digest"] = serde_json::Value::Null;
    observation["inventory_read_position"] = serde_json::Value::Null;
    observation["residue"] = serde_json::json!([]);

    decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap();

    observation["runtimes"][0]["applied_desired"] = serde_json::Value::Null;
    let error = decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
}

#[test]
fn every_reconcile_step_host_reuses_the_same_cross_field_validator() {
    type Reject = fn(&[u8]) -> ContractError;

    let mut cleanup: serde_json::Value = serde_json::from_str(VOLUME_CLEANUP_WIRE).unwrap();
    cleanup["volume_release"] = serde_json::Value::Null;
    let invalid_step = serde_json::json!({
        "kind": "cleanup_release",
        "cleanup": cleanup,
    });

    let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint["step"] = invalid_step.clone();

    let claim = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    let observation: serde_json::Value =
        serde_json::from_slice(&complete_observation_wire(NONEMPTY_INVENTORY_INPUT, claim))
            .unwrap();

    // A valid checkpoint step and its enclosing runtime step must agree, so these
    // two occurrences are exercised together with the same invalid value.
    let mut observed_runtime_and_checkpoint = observation.clone();
    observed_runtime_and_checkpoint["runtimes"][0]["step"] = invalid_step.clone();
    observed_runtime_and_checkpoint["runtimes"][0]["checkpoint"]["step"] = invalid_step.clone();

    let mut progressing_condition = observation;
    progressing_condition["runtimes"][0]["conditions"] = serde_json::json!([{
        "kind": "progressing",
        "reason": {"kind": "reconcile_step", "step": invalid_step},
    }]);

    let cases: Vec<(&str, serde_json::Value, Reject, &str)> = vec![
        (
            "runtime_checkpoint",
            checkpoint,
            reject_checkpoint,
            "/step/cleanup",
        ),
        (
            "observed_runtime_and_checkpoint_evidence",
            observed_runtime_and_checkpoint,
            reject_observation,
            "/runtimes/0/checkpoint/step/cleanup",
        ),
        (
            "progressing_condition",
            progressing_condition,
            reject_observation,
            "/runtimes/0/conditions/0/reason/step/cleanup",
        ),
    ];

    for (host, value, reject, pointer) in cases {
        let error = reject(&serde_json::to_vec(&value).unwrap());
        assert_eq!(malformed(&error).0.as_str(), pointer, "{host}");
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::InvalidValue,
            "{host}"
        );
    }
}

#[test]
fn volume_and_gate_reconcile_steps_round_trip_without_copied_authority_payloads() {
    let steps = [
        (
            "close_gate",
            serde_json::json!({
                "kind": "close_gate",
                "endpoint_id": "ep_01",
                "route_epoch": 9,
            }),
        ),
        ("normal_acquire", normal_acquire_step(1)),
        (
            "provision_root_image",
            provision_root_image_step(4_294_967_296),
        ),
        (
            "takeover_acquire",
            serde_json::json!({
                "kind": "acquire_volume",
                "request": {"kind": "takeover", "authorization_id": "auth_01"},
            }),
        ),
        (
            "format_filesystem",
            serde_json::json!({
                "kind": "format_filesystem",
                "volume_id": "vol_root",
                "attachment_id": "att_01",
                "filesystem_uuid": "99999999999999999999999999999999",
                "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "expected_blank_head": zero_remote_head(),
            }),
        ),
        (
            "commit_initialized",
            serde_json::json!({
                "kind": "commit_initialized",
                "volume_id": "vol_root",
                "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "expected_blank_head": zero_remote_head(),
                "new_remote_head": nonzero_remote_head(),
            }),
        ),
        (
            "snapshot_warm_runtime",
            serde_json::json!({
                "kind": "snapshot_warm_runtime",
                "runtime_incarnation": "55555555555555555555555555555555",
                "snapshot_id": "snap_01",
                "temporary_path": "/var/lib/cats/snapshots/snap_01.tmp",
                "source_heads": [{
                    "volume_id": "vol_root",
                    "attachment_epoch": 8,
                    "head": nonzero_remote_head(),
                }],
            }),
        ),
        (
            "delete_disposable_root",
            serde_json::json!({
                "kind": "delete_disposable_root",
                "authorization_id": "auth_01",
            }),
        ),
    ];

    for (name, step) in steps {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = step;
        if name == "close_gate" {
            checkpoint["route_gates"] =
                serde_json::json!([checkpoint_route_gate("ep_01", 9, "active")]);
        }
        let decoded = decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap())
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let encoded = encode_runtime_checkpoint(&decoded).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
            checkpoint,
            "{name}",
        );
        assert_eq!(
            decode_runtime_checkpoint(&encoded).unwrap(),
            decoded,
            "{name}",
        );
    }
}

#[test]
fn provision_root_image_step_is_shared_by_every_wire_host() {
    let step = provision_root_image_step(4_294_967_296);

    let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint["step"] = step.clone();
    let decoded = decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(matches!(
        decoded.step,
        ReconcileStep::ProvisionRootImage {
            size_bytes: 4_294_967_296,
            ..
        }
    ));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_runtime_checkpoint(&decoded).unwrap())
            .unwrap(),
        checkpoint,
    );

    let mut observation = nonempty_observation_value();
    observation["runtimes"][0]["step"] = step.clone();
    observation["runtimes"][0]["checkpoint"]["step"] = step.clone();
    refresh_inventory_digest(&mut observation);
    let decoded = decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_node_observation(&decoded).unwrap())
            .unwrap(),
        observation,
    );

    let mut condition_host = nonempty_observation_value();
    condition_host["runtimes"][0]["conditions"] = serde_json::json!([{
        "kind": "progressing",
        "reason": {"kind": "reconcile_step", "step": step},
    }]);
    decode_node_observation(&serde_json::to_vec(&condition_host).unwrap()).unwrap();

    // Standalone F0 checks each RemoteHead's intrinsic nullability, but the
    // Desired/grant/manifest bindings and exact blank/generation-one roles are
    // deliberately context-bound.
    let mut context_bound = checkpoint;
    context_bound["step"]["expected_blank_head"] = serde_json::json!({
        "generation": 2,
        "root_hash": ZERO_DIGEST,
        "root_object_id": "volumes/vol_root/roots/2",
    });
    context_bound["step"]["expected_provisioned_head"] = zero_remote_head();
    decode_runtime_checkpoint(&serde_json::to_vec(&context_bound).unwrap()).unwrap();
}

#[test]
fn provision_root_image_reuses_remote_head_validation_in_every_wire_host() {
    type Reject = fn(&[u8]) -> ContractError;

    let mut invalid_step = provision_root_image_step(4_294_967_296);
    invalid_step["expected_provisioned_head"] = serde_json::json!({
        "generation": 1,
        "root_hash": null,
        "root_object_id": null,
    });

    let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint["step"] = invalid_step.clone();

    let mut observation = nonempty_observation_value();
    observation["runtimes"][0]["step"] = invalid_step.clone();
    observation["runtimes"][0]["checkpoint"]["step"] = invalid_step.clone();

    let mut condition_host = nonempty_observation_value();
    condition_host["runtimes"][0]["conditions"] = serde_json::json!([{
        "kind": "progressing",
        "reason": {"kind": "reconcile_step", "step": invalid_step},
    }]);

    let cases: Vec<(&str, serde_json::Value, Reject, &str)> = vec![
        (
            "runtime_checkpoint",
            checkpoint,
            reject_checkpoint,
            "/step/expected_provisioned_head",
        ),
        (
            "observation_runtime_and_checkpoint",
            observation,
            reject_observation,
            "/runtimes/0/checkpoint/step/expected_provisioned_head",
        ),
        (
            "progressing_condition",
            condition_host,
            reject_observation,
            "/runtimes/0/conditions/0/reason/step/expected_provisioned_head",
        ),
    ];

    for (host, value, reject, pointer) in cases {
        let error = reject(&serde_json::to_vec(&value).unwrap());
        assert_eq!(malformed(&error).0.as_str(), pointer, "{host}");
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::InvalidValue,
            "{host}"
        );
    }
}

#[test]
fn provision_root_image_size_and_shape_are_strict() {
    for size_bytes in [1, i64::MAX as u64] {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = provision_root_image_step(size_bytes);
        decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    }

    for size_bytes in [0, i64::MAX as u64 + 1] {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = provision_root_image_step(size_bytes);
        let error = reject_checkpoint(&serde_json::to_vec(&checkpoint).unwrap());
        assert_eq!(malformed(&error).0.as_str(), "/step/size_bytes");
        assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
    }

    let mut missing = provision_root_image_step(1);
    missing
        .as_object_mut()
        .unwrap()
        .remove("provision_transition_id");
    let mut expanded = provision_root_image_step(1);
    expanded
        .as_object_mut()
        .unwrap()
        .insert("manifest".to_owned(), serde_json::json!({"copied": true}));
    let mut old_heads = provision_root_image_step(1);
    old_heads
        .as_object_mut()
        .unwrap()
        .remove("expected_blank_head");
    old_heads
        .as_object_mut()
        .unwrap()
        .insert("expected_blank_generation".to_owned(), 0.into());
    let alias = serde_json::json!({
        "kind": "seed_root_image",
        "provision_transition_id": "1234567890abcdef1234567890abcdef",
    });
    let cases = [
        (
            "missing_transition",
            missing,
            "/step/provision_transition_id",
            MalformedProblem::MissingField,
        ),
        (
            "expanded_manifest",
            expanded,
            "/step/manifest",
            MalformedProblem::UnknownField,
        ),
        (
            "old_split_head",
            old_heads,
            "/step/expected_blank_generation",
            MalformedProblem::UnknownField,
        ),
        (
            "implicit_seed_alias",
            alias,
            "/step/kind",
            MalformedProblem::InvalidValue,
        ),
    ];
    for (name, step, pointer, problem) in cases {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = step;
        let error = reject_checkpoint(&serde_json::to_vec(&checkpoint).unwrap());
        assert_eq!(malformed(&error).0.as_str(), pointer, "{name}");
        assert_eq!(malformed(&error).1, problem, "{name}");
    }
}

#[test]
fn root_provision_conditions_and_operation_failure_are_closed_and_typed() {
    let blocked = serde_json::json!({
        "kind": "blocked",
        "reason": {
            "kind": "root_image_unavailable",
            "boot_image_digest": ZERO_DIGEST,
        },
    });
    let quarantined_reason = serde_json::json!({
        "kind": "root_provision_conflict",
        "volume_id": "vol_root",
        "provision_transition_id": "1234567890abcdef1234567890abcdef",
        "problem": "immutable_object",
    });
    let quarantined = serde_json::json!({
        "kind": "quarantined",
        "reason": quarantined_reason.clone(),
    });

    for condition in [blocked.clone(), quarantined] {
        let mut observation = nonempty_observation_value();
        observation["runtimes"][0]["conditions"] = serde_json::json!([condition]);
        let decoded = decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &encode_node_observation(&decoded).unwrap()
            )
            .unwrap(),
            observation,
        );
    }

    let mut operation = operation_value();
    operation["phase"] = "failed".into();
    operation["terminal"] = serde_json::json!({
        "kind": "failed",
        "error": {"kind": "quarantined", "reason": quarantined_reason},
        "completed_at_unix_ms": 1,
    });
    let decoded = decode_operation(&serde_json::to_vec(&operation).unwrap()).unwrap();
    assert!(matches!(
        &decoded.terminal,
        Some(OperationTerminal::Failed { error, .. })
            if matches!(
                error.as_ref(),
                OperationFailure::Quarantined { reason }
                    if matches!(
                        reason.as_ref(),
                        QuarantineReason::RootProvisionConflict {
                            problem: RootProvisionConflictProblem::ImmutableObject,
                            ..
                        }
                    )
            )
    ));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_operation(&decoded).unwrap()).unwrap(),
        operation,
    );
    operation["terminal"]["error"]["reason"]["problem"] = "opaque_message".into();
    let error = reject_operation(&serde_json::to_vec(&operation).unwrap());
    assert_eq!(
        malformed(&error).0.as_str(),
        "/terminal/error/reason/problem"
    );
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);

    let mut cases = Vec::new();
    let mut missing = blocked.clone();
    missing["reason"]
        .as_object_mut()
        .unwrap()
        .remove("boot_image_digest");
    cases.push((
        "blocked_missing_digest",
        missing,
        "/runtimes/0/conditions/0/reason/boot_image_digest",
        MalformedProblem::MissingField,
    ));
    let mut expanded = blocked;
    expanded["reason"]
        .as_object_mut()
        .unwrap()
        .insert("message".to_owned(), "try another image".into());
    cases.push((
        "blocked_expanded_message",
        expanded,
        "/runtimes/0/conditions/0/reason/message",
        MalformedProblem::UnknownField,
    ));
    let mut wrong_blocked_scalar = serde_json::json!({
        "kind": "blocked",
        "reason": {
            "kind": "root_image_unavailable",
            "boot_image_digest": ZERO_DIGEST,
        },
    });
    wrong_blocked_scalar["reason"]["boot_image_digest"] = 1.into();
    cases.push((
        "blocked_wrong_scalar_type",
        wrong_blocked_scalar,
        "/runtimes/0/conditions/0/reason/boot_image_digest",
        MalformedProblem::InvalidType,
    ));
    let mut missing_conflict_field = serde_json::json!({
        "kind": "quarantined",
        "reason": {
            "kind": "root_provision_conflict",
            "volume_id": "vol_root",
            "provision_transition_id": "1234567890abcdef1234567890abcdef",
            "problem": "local_state",
        },
    });
    missing_conflict_field["reason"]
        .as_object_mut()
        .unwrap()
        .remove("provision_transition_id");
    cases.push((
        "conflict_missing_transition",
        missing_conflict_field,
        "/runtimes/0/conditions/0/reason/provision_transition_id",
        MalformedProblem::MissingField,
    ));
    let mut wrong_conflict_scalar = serde_json::json!({
        "kind": "quarantined",
        "reason": {
            "kind": "root_provision_conflict",
            "volume_id": "vol_root",
            "provision_transition_id": "1234567890abcdef1234567890abcdef",
            "problem": "local_state",
        },
    });
    wrong_conflict_scalar["reason"]["volume_id"] = 1.into();
    cases.push((
        "conflict_wrong_scalar_type",
        wrong_conflict_scalar,
        "/runtimes/0/conditions/0/reason/volume_id",
        MalformedProblem::InvalidType,
    ));
    let mut unknown_problem = serde_json::json!({
        "kind": "quarantined",
        "reason": {
            "kind": "root_provision_conflict",
            "volume_id": "vol_root",
            "provision_transition_id": "1234567890abcdef1234567890abcdef",
            "problem": "opaque_message",
        },
    });
    cases.push((
        "unknown_conflict_problem",
        unknown_problem.clone(),
        "/runtimes/0/conditions/0/reason/problem",
        MalformedProblem::InvalidValue,
    ));
    unknown_problem["reason"]
        .as_object_mut()
        .unwrap()
        .insert("evidence".to_owned(), serde_json::json!({}));
    cases.push((
        "expanded_conflict_evidence",
        unknown_problem,
        "/runtimes/0/conditions/0/reason/evidence",
        MalformedProblem::UnknownField,
    ));

    for (name, condition, pointer, problem) in cases {
        let mut observation = nonempty_observation_value();
        observation["runtimes"][0]["conditions"] = serde_json::json!([condition]);
        let error = reject_observation(&serde_json::to_vec(&observation).unwrap());
        assert_eq!(malformed(&error).0.as_str(), pointer, "{name}");
        assert_eq!(malformed(&error).1, problem, "{name}");
    }
}

#[test]
fn new_condition_reasons_extend_the_existing_total_order() {
    let key_ring = serde_json::json!({
        "kind": "blocked",
        "reason": {
            "kind": "key_ring_unavailable",
            "expected_version": 1,
            "expected_digest": ZERO_DIGEST,
            "loaded_version": null,
            "loaded_digest": null,
        },
    });
    let image = serde_json::json!({
        "kind": "blocked",
        "reason": {"kind": "root_image_unavailable", "boot_image_digest": ZERO_DIGEST},
    });
    let route_binding = checkpoint_route_gate("ep_01", 9, "closed")["binding"].clone();
    let mut observed_binding = route_binding.clone();
    observed_binding["route_epoch"] = 10.into();
    let route = serde_json::json!({
        "kind": "quarantined",
        "reason": {
            "kind": "route_gate_conflict",
            "endpoint_id": "ep_01",
            "expected_binding": route_binding,
            "observed_binding": observed_binding,
        },
    });
    let provision = serde_json::json!({
        "kind": "quarantined",
        "reason": {
            "kind": "root_provision_conflict",
            "volume_id": "vol_root",
            "provision_transition_id": "1234567890abcdef1234567890abcdef",
            "problem": "head_conflict",
        },
    });

    for (name, ordered, reversed) in [
        (
            "blocked_reason_rank",
            vec![key_ring.clone(), image.clone()],
            vec![image, key_ring],
        ),
        (
            "quarantine_reason_rank",
            vec![route.clone(), provision.clone()],
            vec![provision, route],
        ),
    ] {
        let mut valid = nonempty_observation_value();
        valid["runtimes"][0]["conditions"] = ordered.into();
        decode_node_observation(&serde_json::to_vec(&valid).unwrap())
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));

        let mut invalid = nonempty_observation_value();
        invalid["runtimes"][0]["conditions"] = reversed.into();
        let error = reject_observation(&serde_json::to_vec(&invalid).unwrap());
        assert_eq!(malformed(&error).0.as_str(), "/runtimes/0/conditions");
        assert_eq!(malformed(&error).1, MalformedProblem::NonCanonicalOrder);
    }
}

#[test]
fn close_gate_is_one_exact_narrow_step_in_every_wire_host() {
    type Reject = fn(&[u8]) -> ContractError;

    let invalid_step = serde_json::json!({
        "kind": "close_gate",
        "endpoint_id": "ep_01",
        "route_epoch": 0,
    });
    let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint["step"] = invalid_step.clone();

    let observation: serde_json::Value = serde_json::from_slice(&complete_observation_wire(
        NONEMPTY_INVENTORY_INPUT,
        "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe",
    ))
    .unwrap();
    let mut observed_runtime_and_checkpoint = observation.clone();
    observed_runtime_and_checkpoint["runtimes"][0]["step"] = invalid_step.clone();
    observed_runtime_and_checkpoint["runtimes"][0]["checkpoint"]["step"] = invalid_step.clone();

    let mut progressing_condition = observation;
    progressing_condition["runtimes"][0]["conditions"] = serde_json::json!([{
        "kind": "progressing",
        "reason": {"kind": "reconcile_step", "step": invalid_step},
    }]);

    let cases: Vec<(&str, serde_json::Value, Reject, &str)> = vec![
        (
            "runtime_checkpoint",
            checkpoint,
            reject_checkpoint,
            "/step/route_epoch",
        ),
        (
            "observed_runtime_and_checkpoint",
            observed_runtime_and_checkpoint,
            reject_observation,
            "/runtimes/0/checkpoint/step/route_epoch",
        ),
        (
            "progressing_condition",
            progressing_condition,
            reject_observation,
            "/runtimes/0/conditions/0/reason/step/route_epoch",
        ),
    ];

    for (host, value, reject, pointer) in cases {
        let error = reject(&serde_json::to_vec(&value).unwrap());
        assert_eq!(malformed(&error).0.as_str(), pointer, "{host}");
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::InvalidValue,
            "{host}"
        );
    }
}

#[test]
fn runtime_checkpoint_close_gate_selects_one_exact_old_route_entry() {
    let close_gate = serde_json::json!({
        "kind": "close_gate",
        "endpoint_id": "ep_01",
        "route_epoch": 9,
    });
    for gate in ["active", "closed"] {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = close_gate.clone();
        checkpoint["route_gates"] = serde_json::json!([checkpoint_route_gate("ep_01", 9, gate)]);
        decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    }

    let cases = [
        ("missing_entry", serde_json::json!([])),
        (
            "wrong_endpoint",
            serde_json::json!([checkpoint_route_gate("ep_02", 9, "active")]),
        ),
        (
            "wrong_epoch",
            serde_json::json!([checkpoint_route_gate("ep_01", 10, "active")]),
        ),
    ];
    for (name, route_gates) in cases {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = close_gate.clone();
        checkpoint["route_gates"] = route_gates;
        let error =
            decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), "", "{name}");
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::InvalidValue,
            "{name}"
        );
    }
}

#[test]
fn nested_close_gate_shape_does_not_invent_missing_route_context() {
    let close_gate = serde_json::json!({
        "kind": "close_gate",
        "endpoint_id": "ep_01",
        "route_epoch": 9,
    });
    let mut observation = nonempty_observation_value();
    observation["runtimes"][0]["step"] = close_gate.clone();
    observation["runtimes"][0]["checkpoint"]["step"] = close_gate.clone();
    observation["runtimes"][0]["conditions"] = serde_json::json!([{
        "kind": "progressing",
        "reason": {"kind": "reconcile_step", "step": close_gate},
    }]);
    refresh_inventory_digest(&mut observation);
    decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap();
}

#[test]
fn close_gate_rejects_old_generic_and_expanded_payload_shapes() {
    let cases = [
        (
            "missing_route_epoch",
            serde_json::json!({"kind": "close_gate", "endpoint_id": "ep_01"}),
            "/step/route_epoch",
            MalformedProblem::MissingField,
        ),
        (
            "copied_binding",
            serde_json::json!({
                "kind": "close_gate",
                "endpoint_id": "ep_01",
                "route_epoch": 9,
                "binding": {
                    "endpoint_id": "ep_01",
                    "route_epoch": 9,
                },
            }),
            "/step/binding",
            MalformedProblem::UnknownField,
        ),
        (
            "generic_close_admission",
            serde_json::json!({
                "kind": "close_admission",
                "require_idle_attempt_id": null,
                "endpoint_id": "ep_01",
                "route_epoch": 9,
            }),
            "/step/endpoint_id",
            MalformedProblem::UnknownField,
        ),
        (
            "unknown_alias",
            serde_json::json!({
                "kind": "close_endpoint_gate",
                "endpoint_id": "ep_01",
                "route_epoch": 9,
            }),
            "/step/kind",
            MalformedProblem::InvalidValue,
        ),
    ];

    for (name, step, pointer, problem) in cases {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = step;
        let error =
            decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), pointer, "{name}");
        assert_eq!(malformed(&error).1, problem, "{name}");
    }
}

#[test]
fn desired_filesystem_initialization_round_trips_one_remote_head() {
    let mut desired = desired_value();
    desired["volumes"][0]["disk_kind"] = "persistent".into();
    desired["volumes"][0]["mount"] = serde_json::json!({
        "filesystem_uuid": "99999999999999999999999999999999",
        "mount_path": "/data",
        "initialization": {
            "kind": "initialize",
            "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_blank_head": zero_remote_head(),
        },
    });
    refresh_spec_digest(&mut desired);

    let decoded = decode_desired_runtime_spec(&serde_json::to_vec(&desired).unwrap()).unwrap();
    let encoded = encode_desired_runtime_spec(&decoded).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
        desired,
    );
}

#[test]
fn remote_head_accepts_exactly_the_two_complete_states() {
    let combinations = [
        (0, None, None, true),
        (0, Some(ZERO_DIGEST), None, false),
        (0, None, Some("volumes/vol_root/roots/0"), false),
        (
            0,
            Some(ZERO_DIGEST),
            Some("volumes/vol_root/roots/0"),
            false,
        ),
        (1, None, None, false),
        (1, Some(ZERO_DIGEST), None, false),
        (1, None, Some("volumes/vol_root/roots/1"), false),
        (1, Some(ZERO_DIGEST), Some("volumes/vol_root/roots/1"), true),
    ];

    for (generation, root_hash, root_object_id, valid) in combinations {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = serde_json::json!({
            "kind": "format_filesystem",
            "volume_id": "vol_root",
            "attachment_id": "att_01",
            "filesystem_uuid": "99999999999999999999999999999999",
            "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_blank_head": {
                "generation": generation,
                "root_hash": root_hash,
                "root_object_id": root_object_id,
            },
        });
        let result = decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap());
        if valid {
            result.unwrap();
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                malformed(&error).0.as_str(),
                "/step/expected_blank_head",
                "generation={generation}, hash={}, object={}",
                root_hash.is_some(),
                root_object_id.is_some(),
            );
            assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
        }
    }
}

#[test]
fn every_remote_head_host_reuses_the_same_validator() {
    type Reject = fn(&[u8]) -> ContractError;

    let invalid_head = serde_json::json!({
        "generation": 1,
        "root_hash": null,
        "root_object_id": null,
    });
    let invalid_step = serde_json::json!({
        "kind": "format_filesystem",
        "volume_id": "vol_root",
        "attachment_id": "att_01",
        "filesystem_uuid": "99999999999999999999999999999999",
        "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "expected_blank_head": invalid_head,
    });

    let mut desired = desired_value();
    desired["volumes"][0]["disk_kind"] = "persistent".into();
    desired["volumes"][0]["mount"] = serde_json::json!({
        "filesystem_uuid": "99999999999999999999999999999999",
        "mount_path": "/data",
        "initialization": {
            "kind": "initialize",
            "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_blank_head": invalid_head,
        },
    });

    let mut checkpoint_step: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint_step["step"] = invalid_step.clone();

    let projection: serde_json::Value = serde_json::from_str(NONEMPTY_INVENTORY_INPUT).unwrap();
    let volume = projection["runtimes"][0]["volumes"][0].clone();

    let mut checkpoint_authority: serde_json::Value =
        serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint_authority["volumes"] = serde_json::json!([volume]);
    checkpoint_authority["volumes"][0]["authority"]["head"] = invalid_head.clone();

    let invalid_snapshot = serde_json::json!({
        "kind": "present",
        "snapshot_id": "snap_01",
        "runtime_incarnation": "55555555555555555555555555555555",
        "path": "/var/lib/cats/snapshots/snap_01",
        "file_size_bytes": 4096,
        "file_digest": ZERO_DIGEST,
        "source_heads": [{
            "volume_id": "vol_root",
            "attachment_epoch": 8,
            "head": invalid_head,
        }],
        "durable_rename_complete": true,
    });
    let mut checkpoint_snapshot: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    checkpoint_snapshot["warm_snapshot"] = invalid_snapshot.clone();

    let observation: serde_json::Value = serde_json::from_slice(&complete_observation_wire(
        NONEMPTY_INVENTORY_INPUT,
        "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe",
    ))
    .unwrap();

    let mut observed_runtime_and_checkpoint = observation.clone();
    observed_runtime_and_checkpoint["runtimes"][0]["step"] = invalid_step.clone();
    observed_runtime_and_checkpoint["runtimes"][0]["checkpoint"]["step"] = invalid_step.clone();

    let mut progressing_condition = observation.clone();
    progressing_condition["runtimes"][0]["conditions"] = serde_json::json!([{
        "kind": "progressing",
        "reason": {"kind": "reconcile_step", "step": invalid_step},
    }]);

    let mut observed_authority = observation.clone();
    observed_authority["runtimes"][0]["volumes"][0]["authority"]["head"] = invalid_head.clone();

    let mut observed_snapshot = observation;
    observed_snapshot["runtimes"][0]["warm_snapshot"] = invalid_snapshot;

    let cases: Vec<(&str, serde_json::Value, Reject, &str)> = vec![
        (
            "desired_initialization",
            desired,
            reject_desired,
            "/volumes/0/mount/initialization/expected_blank_head",
        ),
        (
            "runtime_checkpoint_step",
            checkpoint_step,
            reject_checkpoint,
            "/step/expected_blank_head",
        ),
        (
            "observed_runtime_and_checkpoint_step",
            observed_runtime_and_checkpoint,
            reject_observation,
            "/runtimes/0/checkpoint/step/expected_blank_head",
        ),
        (
            "progressing_condition_step",
            progressing_condition,
            reject_observation,
            "/runtimes/0/conditions/0/reason/step/expected_blank_head",
        ),
        (
            "runtime_checkpoint_authority",
            checkpoint_authority,
            reject_checkpoint,
            "/volumes/0/authority/head",
        ),
        (
            "runtime_checkpoint_warm_snapshot",
            checkpoint_snapshot,
            reject_checkpoint,
            "/warm_snapshot/source_heads/0/head",
        ),
        (
            "observed_authority",
            observed_authority,
            reject_observation,
            "/runtimes/0/volumes/0/authority/head",
        ),
        (
            "observed_warm_snapshot",
            observed_snapshot,
            reject_observation,
            "/runtimes/0/warm_snapshot/source_heads/0/head",
        ),
    ];

    for (host, value, reject, pointer) in cases {
        let error = reject(&serde_json::to_vec(&value).unwrap());
        assert_eq!(malformed(&error).0.as_str(), pointer, "{host}");
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::InvalidValue,
            "{host}"
        );
    }
}

#[test]
fn normal_volume_acquire_requires_a_positive_signed_wire_duration() {
    for duration in [1, i64::MAX as u64] {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = normal_acquire_step(duration);
        decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    }

    for duration in [0, i64::MAX as u64 + 1] {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = normal_acquire_step(duration);
        let error =
            decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap_err();
        assert_eq!(
            malformed(&error).0.as_str(),
            "/step/request/lease_duration_ms",
            "duration={duration}",
        );
        assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
    }
}

#[test]
fn a10_old_volume_shapes_are_rejected_without_compatibility_aliases() {
    let projection: serde_json::Value = serde_json::from_str(NONEMPTY_INVENTORY_INPUT).unwrap();
    let volume = projection["runtimes"][0]["volumes"][0].clone();
    let old_steps = [
        (
            "acquire_volume",
            serde_json::json!({
                "kind": "acquire_volume",
                "volume_id": "vol_root",
                "attachment_id": "att_01",
                "acquire": {
                    "kind": "normal",
                    "transition_id": "22222222222222222222222222222222",
                    "expected_unowned_epoch": 0,
                },
            }),
            "/step/acquire",
        ),
        (
            "format_filesystem",
            serde_json::json!({
                "kind": "format_filesystem",
                "volume_id": "vol_root",
                "attachment_id": "att_01",
                "filesystem_uuid": "99999999999999999999999999999999",
                "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "expected_blank_root": null,
                "expected_blank_generation": 0,
            }),
            "/step/expected_blank_generation",
        ),
        (
            "commit_initialized",
            serde_json::json!({
                "kind": "commit_initialized",
                "volume_id": "vol_root",
                "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "expected_blank_root": null,
                "expected_blank_generation": 0,
                "new_remote_root": ZERO_DIGEST,
                "new_remote_generation": 1,
            }),
            "/step/expected_blank_generation",
        ),
        (
            "snapshot_head",
            serde_json::json!({
                "kind": "snapshot_warm_runtime",
                "runtime_incarnation": "55555555555555555555555555555555",
                "snapshot_id": "snap_01",
                "temporary_path": "/var/lib/cats/snapshots/snap_01.tmp",
                "source_heads": [{
                    "volume_id": "vol_root",
                    "attachment_epoch": 8,
                    "generation": 1,
                    "root": ZERO_DIGEST,
                }],
            }),
            "/step/source_heads/0/generation",
        ),
        (
            "takeover_payload_copy",
            serde_json::json!({
                "kind": "acquire_volume",
                "request": {
                    "kind": "takeover",
                    "authorization_id": "auth_01",
                    "volume_id": "vol_root",
                },
            }),
            "/step/request/volume_id",
        ),
        (
            "takeover_issuer_proof",
            serde_json::json!({
                "kind": "acquire_volume",
                "request": {
                    "kind": "takeover",
                    "authorization_id": "auth_01",
                    "issuer_proof": "copied-client-proof",
                },
            }),
            "/step/request/issuer_proof",
        ),
        (
            "disposable_root_payload_copy",
            serde_json::json!({
                "kind": "delete_disposable_root",
                "authorization_id": "auth_01",
                "volume_id": "vol_root",
            }),
            "/step/volume_id",
        ),
    ];

    for (name, step, pointer) in old_steps {
        let mut checkpoint: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
        checkpoint["step"] = step;
        let error =
            decode_runtime_checkpoint(&serde_json::to_vec(&checkpoint).unwrap()).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), pointer, "{name}");
        assert_eq!(
            malformed(&error).1,
            MalformedProblem::UnknownField,
            "{name}"
        );
    }

    let mut old_authority: serde_json::Value = serde_json::from_str(CHECKPOINT_WIRE).unwrap();
    old_authority["volumes"] = serde_json::json!([volume]);
    old_authority["volumes"][0]["authority"] = serde_json::json!({
        "kind": "owned",
        "attachment_id": "att_01",
        "attachment_epoch": 8,
        "generation": 4,
        "remote_root": ZERO_DIGEST,
    });
    let error =
        decode_runtime_checkpoint(&serde_json::to_vec(&old_authority).unwrap()).unwrap_err();
    assert_eq!(
        malformed(&error).0.as_str(),
        "/volumes/0/authority/generation"
    );
    assert_eq!(malformed(&error).1, MalformedProblem::UnknownField);

    let mut old_initialization = desired_value();
    old_initialization["volumes"][0]["disk_kind"] = "persistent".into();
    old_initialization["volumes"][0]["mount"] = serde_json::json!({
        "filesystem_uuid": "99999999999999999999999999999999",
        "mount_path": "/data",
        "initialization": {
            "kind": "initialize",
            "initialization_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_blank_root": null,
            "expected_blank_generation": 0,
        },
    });
    let error =
        decode_desired_runtime_spec(&serde_json::to_vec(&old_initialization).unwrap()).unwrap_err();
    assert_eq!(
        malformed(&error).0.as_str(),
        "/volumes/0/mount/initialization/expected_blank_generation",
    );
    assert_eq!(malformed(&error).1, MalformedProblem::UnknownField);
}

#[test]
fn acquire_origin_preserves_the_normal_and_takeover_namespaces() {
    let shared_id = "13579bdf2468ace013579bdf2468ace0";
    let normal_value = nonempty_observation_value();
    let normal = decode_node_observation(&serde_json::to_vec(&normal_value).unwrap()).unwrap();
    let normal_origin = &normal.runtimes[0].volumes[0].local_lineages[0].acquire_origin;
    assert!(
        matches!(normal_origin, AcquireOrigin::Normal { transition_id } if transition_id.as_str() == shared_id)
    );

    let mut takeover_value = normal_value;
    takeover_value["runtimes"][0]["volumes"][0]["local_lineages"][0]["acquire_origin"] =
        serde_json::json!({"kind": "takeover", "authorization_id": shared_id});
    refresh_inventory_digest(&mut takeover_value);
    let takeover = decode_node_observation(&serde_json::to_vec(&takeover_value).unwrap()).unwrap();
    let takeover_origin = &takeover.runtimes[0].volumes[0].local_lineages[0].acquire_origin;
    assert!(
        matches!(takeover_origin, AcquireOrigin::Takeover { authorization_id } if authorization_id.as_str() == shared_id)
    );
    assert_ne!(normal_origin, takeover_origin);

    let encoded = encode_node_observation(&takeover).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
        takeover_value,
    );
}

#[test]
fn acquire_origin_rejects_missing_unknown_and_old_bare_fields() {
    let base = nonempty_observation_value();
    let lineage_path = "/runtimes/0/volumes/0/local_lineages/0";
    let mut cases = Vec::new();

    let mut old_only = base.clone();
    old_only["runtimes"][0]["volumes"][0]["local_lineages"][0]
        .as_object_mut()
        .unwrap()
        .remove("acquire_origin");
    old_only["runtimes"][0]["volumes"][0]["local_lineages"][0]
        .as_object_mut()
        .unwrap()
        .insert("acquire_transition_id".to_owned(), "tx_01".into());
    cases.push((
        "old_bare_field_only",
        old_only,
        format!("{lineage_path}/acquire_origin"),
        MalformedProblem::MissingField,
    ));

    let mut old_alias = base.clone();
    old_alias["runtimes"][0]["volumes"][0]["local_lineages"][0]
        .as_object_mut()
        .unwrap()
        .insert("acquire_transition_id".to_owned(), "tx_01".into());
    cases.push((
        "old_bare_field_alias",
        old_alias,
        format!("{lineage_path}/acquire_transition_id"),
        MalformedProblem::UnknownField,
    ));

    let mut unknown_kind = base.clone();
    unknown_kind["runtimes"][0]["volumes"][0]["local_lineages"][0]["acquire_origin"] =
        serde_json::json!({"kind": "legacy", "transition_id": "13579bdf2468ace013579bdf2468ace0"});
    cases.push((
        "unknown_kind",
        unknown_kind,
        format!("{lineage_path}/acquire_origin/kind"),
        MalformedProblem::InvalidValue,
    ));

    let mut invalid_normal_id = base.clone();
    invalid_normal_id["runtimes"][0]["volumes"][0]["local_lineages"][0]["acquire_origin"] =
        serde_json::json!({"kind": "normal", "transition_id": "tx_01"});
    cases.push((
        "normal_requires_random_id",
        invalid_normal_id,
        format!("{lineage_path}/acquire_origin/transition_id"),
        MalformedProblem::InvalidValue,
    ));

    let mut mixed_variant = base;
    mixed_variant["runtimes"][0]["volumes"][0]["local_lineages"][0]["acquire_origin"] = serde_json::json!({
        "kind": "takeover",
        "authorization_id": "auth_01",
        "transition_id": "13579bdf2468ace013579bdf2468ace0",
    });
    cases.push((
        "mixed_variant_fields",
        mixed_variant,
        format!("{lineage_path}/acquire_origin/transition_id"),
        MalformedProblem::UnknownField,
    ));

    for (name, value, pointer, problem) in cases {
        let error = decode_node_observation(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), pointer, "{name}");
        assert_eq!(malformed(&error).1, problem, "{name}");
    }
}

#[test]
fn every_readable_residue_lineage_host_reuses_the_same_validator() {
    type Reject = fn(&[u8]) -> ContractError;

    let projection: serde_json::Value = serde_json::from_str(NONEMPTY_INVENTORY_INPUT).unwrap();
    let template = projection["residue"][3].clone();
    let mut invalid_lineages = Vec::new();

    let mut unpaired_hint = template.clone();
    unpaired_hint["lineage"]["attachment_epoch_hint"] = serde_json::Value::Null;
    invalid_lineages.push(("unpaired_hint", unpaired_hint));

    let mut reversed_generations = template;
    reversed_generations["lineage"]["local_durable_generation"] = 4.into();
    reversed_generations["lineage"]["remote_durable_generation"] = 5.into();
    invalid_lineages.push(("reversed_generations", reversed_generations));

    let claim = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    for (invariant, residue) in invalid_lineages {
        let observation: serde_json::Value =
            serde_json::from_slice(&complete_observation_wire(NONEMPTY_INVENTORY_INPUT, claim))
                .unwrap();

        let mut top_level = observation.clone();
        top_level["residue"] = serde_json::json!([residue.clone()]);

        let mut condition = observation;
        condition["runtimes"][0]["conditions"] = serde_json::json!([{
            "kind": "quarantined",
            "reason": {"kind": "unattributed_node_residue", "residue": residue.clone()},
        }]);

        let mut operation = operation_value();
        operation["phase"] = "failed".into();
        operation["terminal"] = serde_json::json!({
            "kind": "failed",
            "error": {
                "kind": "quarantined",
                "reason": {"kind": "unattributed_node_residue", "residue": residue},
            },
            "completed_at_unix_ms": 1,
        });

        let cases: Vec<(&str, serde_json::Value, Reject, &str)> = vec![
            (
                "node_observation",
                top_level,
                reject_observation,
                "/residue/0/lineage",
            ),
            (
                "condition",
                condition,
                reject_observation,
                "/runtimes/0/conditions/0/reason/residue/lineage",
            ),
            (
                "operation",
                operation,
                reject_operation,
                "/terminal/error/reason/residue/lineage",
            ),
        ];

        for (host, value, reject, pointer) in cases {
            let error = reject(&serde_json::to_vec(&value).unwrap());
            assert_eq!(
                malformed(&error).0.as_str(),
                pointer,
                "{invariant} in {host}"
            );
            assert_eq!(
                malformed(&error).1,
                MalformedProblem::InvalidValue,
                "{invariant} in {host}"
            );
        }
    }
}

#[test]
fn runtime_condition_fact_conflicts_point_to_the_runtime_common_object() {
    let reasons = [
        serde_json::json!({
            "kind": "ready",
            "reason": {"kind": "postcondition_satisfied", "target": "cold"},
        }),
        serde_json::json!({
            "kind": "quarantined",
            "reason": {
                "kind": "duplicate_device",
                "volume_id": "vol_root",
                "observed_device_count": 3,
            },
        }),
        serde_json::json!({
            "kind": "quarantined",
            "reason": {
                "kind": "duplicate_mount",
                "volume_id": "vol_root",
                "mount_path": "/",
                "observed_instance_count": 2,
            },
        }),
        serde_json::json!({
            "kind": "quarantined",
            "reason": {
                "kind": "duplicate_network",
                "network_id": "net_01",
                "observed_tap_count": 3,
            },
        }),
        serde_json::json!({
            "kind": "quarantined",
            "reason": {
                "kind": "duplicate_route",
                "endpoint_id": "ep_01",
                "observed_instance_count": 4,
            },
        }),
    ];

    let claim = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    for condition in reasons {
        let mut observation: serde_json::Value =
            serde_json::from_slice(&complete_observation_wire(NONEMPTY_INVENTORY_INPUT, claim))
                .unwrap();
        observation["runtimes"][0]["conditions"] = serde_json::json!([condition]);

        let error =
            decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap_err();
        assert_eq!(malformed(&error).0.as_str(), "/runtimes/0");
        assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
    }
}

#[test]
fn every_top_level_contract_uses_the_same_version_rules() {
    type Reject = fn(&[u8]) -> ContractError;
    let empty_observation: serde_json::Value = serde_json::from_slice(&complete_observation_wire(
        EMPTY_INVENTORY_INPUT,
        "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05",
    ))
    .unwrap();
    let cases: Vec<(ContractName, serde_json::Value, Reject)> = vec![
        (
            ContractName::NodeIdentity,
            serde_json::json!({
                "version": 1,
                "node_id": "node_a",
                "immutable_host_id": "host_a",
                "credential_id": "cred_a",
                "credential_binding": {"kind": "public_key", "public_key_spki_sha256": ZERO_DIGEST},
                "state_path_id": "state_a",
                "state": "provisioned",
            }),
            reject_node_identity,
        ),
        (
            ContractName::AgentRegistrationAttempt,
            serde_json::json!({
                "version": 1,
                "node_id": "node_a",
                "immutable_host_id": "host_a",
                "node_boot_id": "11111111111111111111111111111111",
                "agent_instance_id": "22222222222222222222222222222222",
                "registration_attempt_id": "33333333333333333333333333333333",
                "expected_agent_session_epoch": null,
            }),
            reject_registration,
        ),
        (
            ContractName::AgentSession,
            serde_json::json!({
                "version": 1,
                "node_id": "node_a",
                "immutable_host_id": "host_a",
                "node_boot_id": "11111111111111111111111111111111",
                "agent_instance_id": "22222222222222222222222222222222",
                "agent_session_epoch": 1,
                "registration_attempt_id": "33333333333333333333333333333333",
                "lease_deadline_unix_ms": 1,
            }),
            reject_session,
        ),
        (
            ContractName::AdmissionInventoryAttestation,
            serde_json::json!({
                "version": 1,
                "node_id": "node_a",
                "agent_session_epoch": 1,
                "inventory_epoch": 1,
                "inventory_digest": ZERO_DIGEST,
                "inventory_read_position": 1,
                "accepted_at_unix_ms": 1,
            }),
            reject_attestation,
        ),
        (
            ContractName::DesiredRuntimeSpec,
            desired_value(),
            reject_desired,
        ),
        (
            ContractName::RuntimeCheckpoint,
            serde_json::from_str(CHECKPOINT_WIRE).unwrap(),
            reject_checkpoint,
        ),
        (
            ContractName::NodeCleanupCheckpoint,
            serde_json::from_str(NODE_CLEANUP_WIRE).unwrap(),
            reject_node_cleanup,
        ),
        (
            ContractName::NodeObservation,
            empty_observation,
            reject_observation,
        ),
        (ContractName::Operation, operation_value(), reject_operation),
        (
            ContractName::ContractError,
            serde_json::from_str(CONTRACT_ERROR_WIRE).unwrap(),
            reject_contract_error,
        ),
    ];

    for (contract, valid, reject) in cases {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("version");
        let error = reject(&serde_json::to_vec(&missing).unwrap());
        assert_eq!(malformed(&error).0.as_str(), "/version", "{contract:?}");
        assert_eq!(malformed(&error).1, MalformedProblem::MissingField);

        let mut wrong_type = valid.clone();
        wrong_type["version"] = "1".into();
        let error = reject(&serde_json::to_vec(&wrong_type).unwrap());
        assert_eq!(malformed(&error).0.as_str(), "/version", "{contract:?}");
        assert_eq!(malformed(&error).1, MalformedProblem::InvalidType);

        let mut overflow = valid.clone();
        overflow["version"] = serde_json::json!(9_223_372_036_854_775_808_u64);
        let error = reject(&serde_json::to_vec(&overflow).unwrap());
        assert_eq!(malformed(&error).0.as_str(), "/version", "{contract:?}");
        assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);

        let mut unsupported = valid.clone();
        unsupported["version"] = 2.into();
        let error = reject(&serde_json::to_vec(&unsupported).unwrap());
        match error.error.as_ref() {
            ContractErrorDetail::UnsupportedVersion {
                contract: actual,
                presented_version,
                ..
            } => {
                assert_eq!(*actual, contract);
                assert_eq!(presented_version.get(), 2);
            }
            detail => panic!("expected unsupported_version for {contract:?}, got {detail:?}"),
        }

        let mut alias = valid;
        alias["format_version"] = 1.into();
        let error = reject(&serde_json::to_vec(&alias).unwrap());
        assert_eq!(
            malformed(&error).0.as_str(),
            "/format_version",
            "{contract:?}"
        );
        assert_eq!(malformed(&error).1, MalformedProblem::UnknownField);
    }
}

#[test]
fn array_limit_precedes_intrinsic_but_not_schema() {
    let mut value = desired_with_volume_count(65);
    value["volumes"][64]["disk_id"] = "bad id".into();
    let error = decode_desired_runtime_spec(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    match error.error.as_ref() {
        ContractErrorDetail::LimitExceeded {
            json_pointer,
            limit,
            maximum,
            observed_at_least,
            ..
        } => {
            assert_eq!(json_pointer.as_str(), "/volumes");
            assert_eq!(*limit, LimitKind::ArrayItems);
            assert_eq!(maximum.get(), 64);
            assert_eq!(observed_at_least.get(), 65);
        }
        detail => panic!("expected array limit, got {detail:?}"),
    }

    value["volumes"][64]["disk_id"] = true.into();
    let error = decode_desired_runtime_spec(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/volumes/64/disk_id");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidType);
}

#[test]
fn array_identity_order_and_numeric_indices_are_deterministic() {
    let mut value = desired_value();
    let first = value["volumes"][0].clone();
    let mut second = first.clone();
    second["volume_intent_id"] = "vint_two".into();
    second["disk_id"] = "disk_two".into();
    second["volume_id"] = "vol_two".into();
    second["attachment_id"] = "att_two".into();
    second["guest_device"]["serial"] = "cats-two".into();
    second["guest_device"]["slot"] = 1.into();

    value["volumes"] = vec![first.clone(), first.clone()].into();
    let duplicate = decode_desired_runtime_spec(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(malformed(&duplicate).0.as_str(), "/volumes");
    assert_eq!(malformed(&duplicate).1, MalformedProblem::DuplicateIdentity);

    value["volumes"] = vec![second, first].into();
    let reversed = decode_desired_runtime_spec(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(malformed(&reversed).0.as_str(), "/volumes");
    assert_eq!(malformed(&reversed).1, MalformedProblem::NonCanonicalOrder);

    let mut endpoints = Vec::new();
    let endpoint = desired_value()["endpoints"][0].clone();
    for index in 0..11 {
        let mut item = endpoint.clone();
        item["endpoint_id"] = format!("ep_{index:03}").into();
        item["hostname"] = format!("host-{index:03}.example.test").into();
        endpoints.push(item);
    }
    endpoints[2]["hostname"] = "BAD".into();
    endpoints[10]["hostname"] = "ALSO-BAD".into();
    let mut value = desired_value();
    value["endpoints"] = endpoints.into();
    let error = decode_desired_runtime_spec(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/endpoints/2/hostname");
}

#[test]
fn multiplicity_facts_cannot_be_split_across_duplicate_items() {
    let claim = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    let base: serde_json::Value =
        serde_json::from_slice(&complete_observation_wire(NONEMPTY_INVENTORY_INPUT, claim))
            .unwrap();

    let mut split_mount = base.clone();
    let mut second_mount = split_mount["runtimes"][0]["mounts"][0].clone();
    second_mount["instance_count"] = 2.into();
    split_mount["runtimes"][0]["mounts"]
        .as_array_mut()
        .unwrap()
        .push(second_mount);
    let error = decode_node_observation(&serde_json::to_vec(&split_mount).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/runtimes/0/mounts");
    assert_eq!(malformed(&error).1, MalformedProblem::DuplicateIdentity);

    let mut split_route = base;
    let mut second_route = split_route["runtimes"][0]["routes"][0].clone();
    second_route["instance_count"] = 3.into();
    split_route["runtimes"][0]["routes"]
        .as_array_mut()
        .unwrap()
        .insert(1, second_route);
    let error = decode_node_observation(&serde_json::to_vec(&split_route).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/runtimes/0/routes");
    assert_eq!(malformed(&error).1, MalformedProblem::DuplicateIdentity);
}

#[test]
fn complete_inventory_indexes_mount_snapshot_and_valid_route_identities() {
    let mut mount_collision = nonempty_observation_value();
    mount_collision["residue"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "kind": "mount",
            "volume_id_hint": "vol_root",
            "source_path": "/dev/nbd0",
            "mount_path": "/",
            "instance_count": 1,
        }));
    assert_inventory_collision(&mount_collision, "");

    let mut different_mount = mount_collision.clone();
    different_mount["residue"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["source_path"] = "/dev/nbd9".into();
    assert_valid_inventory(different_mount);

    // The fixed vector has two frontends for the same guest device; the
    // collision above still comes directly from the scanned source_path.

    let snapshot = serde_json::json!({
        "kind": "present",
        "snapshot_id": "snap_01",
        "runtime_incarnation": "55555555555555555555555555555555",
        "path": "/var/lib/cats/snapshots/snap_01",
        "file_size_bytes": 4096,
        "file_digest": ZERO_DIGEST,
        "source_heads": [],
        "durable_rename_complete": true,
    });
    let mut snapshot_collision = nonempty_observation_value();
    snapshot_collision["runtimes"][0]["warm_snapshot"] = snapshot;
    snapshot_collision["residue"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "kind": "warm_snapshot",
            "snapshot_id_hint": "snap_01",
            "path": "/var/lib/cats/snapshots/snap_01",
            "file_size_bytes": 4096,
            "file_digest": ZERO_DIGEST,
        }));
    assert_inventory_collision(&snapshot_collision, "");

    let mut different_snapshot = snapshot_collision;
    different_snapshot["residue"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["path"] = "/var/lib/cats/snapshots/other".into();
    assert_valid_inventory(different_snapshot);

    let mut route_collision = nonempty_observation_value();
    let binding = route_collision["runtimes"][0]["routes"][0]["binding"].clone();
    route_collision["residue"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "kind": "route_gate",
            "binding": {"kind": "valid", "binding": binding},
            "gate": "closed",
            "active_guards": 0,
            "cancellation_pending": false,
            "instance_count": 1,
        }));
    assert_inventory_collision(&route_collision, "");

    let mut different_route = route_collision.clone();
    different_route["residue"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["binding"]["binding"]["route_epoch"] = 11.into();
    assert_valid_inventory(different_route);

    let mut unproven_route = route_collision;
    unproven_route["residue"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["binding"] = serde_json::json!({"kind": "missing"});
    assert_valid_inventory(unproven_route);
}

#[test]
fn mount_collision_pointers_cover_each_inventory_scope() {
    let mount = |volume_id: &str, source_path: &str, filesystem_uuid: &str| {
        serde_json::json!({
            "volume_id": volume_id,
            "guest_device": {"serial": "cats-root", "slot": 0},
            "source_path": source_path,
            "filesystem_uuid": filesystem_uuid,
            "mount_path": "/",
            "access": "read_write",
            "instance_count": 1,
        })
    };

    let mut first_runtime = minimal_runtime("cat_01", "/checkpoints/cat_01.json");
    first_runtime["mounts"] = serde_json::json!([mount(
        "vol_a",
        "/dev/shared",
        "11111111111111111111111111111111"
    )]);
    let mut second_runtime = minimal_runtime("cat_02", "/checkpoints/cat_02.json");
    second_runtime["mounts"] = serde_json::json!([mount(
        "vol_b",
        "/dev/shared",
        "22222222222222222222222222222222"
    )]);
    let mut across_runtimes = nonempty_observation_value();
    across_runtimes["runtimes"] = serde_json::json!([first_runtime, second_runtime]);
    across_runtimes["residue"] = serde_json::json!([]);
    assert_inventory_collision(&across_runtimes, "/runtimes");

    let mut distinct_runtimes = across_runtimes;
    distinct_runtimes["runtimes"][1]["mounts"][0]["source_path"] = "/dev/different".into();
    assert_valid_inventory(distinct_runtimes);

    let mut one_runtime = minimal_runtime("cat_01", "/checkpoints/cat_01.json");
    one_runtime["mounts"] = serde_json::json!([
        mount("vol_a", "/dev/shared", "11111111111111111111111111111111"),
        mount("vol_a", "/dev/shared", "99999999999999999999999999999999"),
    ]);
    let mut within_runtime = nonempty_observation_value();
    within_runtime["runtimes"] = serde_json::json!([one_runtime]);
    within_runtime["residue"] = serde_json::json!([]);
    assert_inventory_collision(&within_runtime, "/runtimes/0/mounts");

    let empty_claim = "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05";
    let mut within_residue: serde_json::Value = serde_json::from_slice(&complete_observation_wire(
        EMPTY_INVENTORY_INPUT,
        empty_claim,
    ))
    .unwrap();
    within_residue["residue"] = serde_json::json!([
        {
            "kind": "mount",
            "volume_id_hint": "vol_a",
            "source_path": "/dev/shared",
            "mount_path": "/",
            "instance_count": 1,
        },
        {
            "kind": "mount",
            "volume_id_hint": "vol_b",
            "source_path": "/dev/shared",
            "mount_path": "/",
            "instance_count": 1,
        },
    ]);
    assert_inventory_collision(&within_residue, "/residue");
}

#[test]
fn inventory_collisions_share_the_array_identity_substage() {
    let mut runtime_and_residue = nonempty_observation_value();
    let mut second_mount = runtime_and_residue["runtimes"][0]["mounts"][0].clone();
    second_mount["filesystem_uuid"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    runtime_and_residue["runtimes"][0]["mounts"]
        .as_array_mut()
        .unwrap()
        .push(second_mount);
    runtime_and_residue["residue"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "kind": "mount",
            "volume_id_hint": null,
            "source_path": "/dev/nbd0",
            "mount_path": "/",
            "instance_count": 1,
        }));
    assert_inventory_collision(&runtime_and_residue, "");

    let mount = serde_json::json!({
        "volume_id": "vol_a",
        "guest_device": {"serial": "cats-root", "slot": 0},
        "source_path": "/dev/shared",
        "filesystem_uuid": "11111111111111111111111111111111",
        "mount_path": "/",
        "access": "read_write",
        "instance_count": 1,
    });
    let mut later_runtime = minimal_runtime("cat_02", "/checkpoints/cat_02.json");
    later_runtime["mounts"] = serde_json::json!([mount.clone()]);
    let mut earlier_runtime = minimal_runtime("cat_01", "/checkpoints/cat_01.json");
    earlier_runtime["mounts"] = serde_json::json!([mount]);
    let mut reversed_runtimes = nonempty_observation_value();
    reversed_runtimes["runtimes"] = serde_json::json!([later_runtime, earlier_runtime]);
    reversed_runtimes["residue"] = serde_json::json!([]);
    assert_inventory_collision(&reversed_runtimes, "/runtimes");
}

#[test]
fn complete_inventory_collision_pointers_use_the_lowest_common_object() {
    let snapshot = serde_json::json!({
        "kind": "present",
        "snapshot_id": "snap_shared",
        "runtime_incarnation": "55555555555555555555555555555555",
        "path": "/var/lib/cats/snapshots/shared",
        "file_size_bytes": 4096,
        "file_digest": ZERO_DIGEST,
        "source_heads": [],
        "durable_rename_complete": true,
    });
    let mut first_runtime = minimal_runtime("cat_01", "/checkpoints/cat_01.json");
    first_runtime["warm_snapshot"] = snapshot.clone();
    let mut second_runtime = minimal_runtime("cat_02", "/checkpoints/cat_02.json");
    second_runtime["warm_snapshot"] = snapshot;
    let mut across_runtimes = nonempty_observation_value();
    across_runtimes["runtimes"] = serde_json::json!([first_runtime, second_runtime]);
    across_runtimes["residue"] = serde_json::json!([]);
    assert_inventory_collision(&across_runtimes, "/runtimes");

    let mut distinct_runtimes = across_runtimes;
    distinct_runtimes["runtimes"][1]["warm_snapshot"]["path"] =
        "/var/lib/cats/snapshots/other".into();
    assert_valid_inventory(distinct_runtimes);

    let source: serde_json::Value = serde_json::from_str(NONEMPTY_INVENTORY_INPUT).unwrap();
    let mut first_volume = source["runtimes"][0]["volumes"][0].clone();
    first_volume["volume_id"] = "vol_a".into();
    first_volume["volume_intent_id"] = "vint_a".into();
    first_volume["disk_id"] = "disk_a".into();
    first_volume["local_lineages"] = serde_json::json!([]);
    let mut kernel = first_volume["devices"][0].clone();
    kernel["device_path"] = "/shared/block-path".into();
    first_volume["devices"] = serde_json::json!([kernel]);

    let mut second_volume = source["runtimes"][0]["volumes"][0].clone();
    second_volume["volume_id"] = "vol_b".into();
    second_volume["volume_intent_id"] = "vint_b".into();
    second_volume["disk_id"] = "disk_b".into();
    second_volume["local_lineages"] = serde_json::json!([]);
    let mut vhost = second_volume["devices"][1].clone();
    vhost["socket_path"] = "/shared/block-path".into();
    second_volume["devices"] = serde_json::json!([vhost]);

    let mut runtime = minimal_runtime("cat_01", "/checkpoints/cat_01.json");
    runtime["volumes"] = serde_json::json!([first_volume, second_volume]);
    let mut across_nested_arrays = nonempty_observation_value();
    across_nested_arrays["runtimes"] = serde_json::json!([runtime]);
    across_nested_arrays["residue"] = serde_json::json!([]);
    assert_inventory_collision(&across_nested_arrays, "/runtimes/0/volumes");

    let mut distinct_nested_arrays = across_nested_arrays;
    distinct_nested_arrays["runtimes"][0]["volumes"][1]["devices"][0]["socket_path"] =
        "/different/block-path".into();
    assert_valid_inventory(distinct_nested_arrays);

    let empty_claim = "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05";
    let mut across_residue_variants: serde_json::Value = serde_json::from_slice(
        &complete_observation_wire(EMPTY_INVENTORY_INPUT, empty_claim),
    )
    .unwrap();
    across_residue_variants["residue"] = serde_json::json!([
        {
            "kind": "kernel_nbd",
            "volume_id_hint": null,
            "guest_device": null,
            "device_path": "/shared/residue-path",
            "ownership_token": {"kind": "missing"},
        },
        {
            "kind": "vhost_user_blk",
            "volume_id_hint": null,
            "guest_device": null,
            "socket_path": "/shared/residue-path",
            "ownership_token": {"kind": "missing"},
        },
    ]);
    assert_inventory_collision(&across_residue_variants, "/residue");

    let mut distinct_residue_variants = across_residue_variants;
    distinct_residue_variants["residue"][1]["socket_path"] = "/different/residue-path".into();
    assert_valid_inventory(distinct_residue_variants);
}

#[test]
fn pointers_escape_then_fallback_without_affecting_selection() {
    let base = format!(
        r#""version":1,"node_id":"node_a","immutable_host_id":"host","credential_id":"cred","credential_binding":{{"kind":"public_key","public_key_spki_sha256":"{ZERO_DIGEST}"}},"state_path_id":"state","state":"provisioned""#
    );
    let escaped = format!(r#"{{{base},"a~/b":1}}"#);
    let error = decode_node_identity(escaped.as_bytes()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/a~0~1b");

    let exact_key = format!("{}a", "~".repeat(255));
    let exact = format!(r#"{{{base},"{exact_key}":1}}"#);
    let error = decode_node_identity(exact.as_bytes()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str().len(), 512);
    assert!(malformed(&error).0.as_str().contains("~0"));

    let long_key = "~".repeat(256);
    let over = format!(r#"{{{base},"{long_key}":1}}"#);
    let error = decode_node_identity(over.as_bytes()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "");
}

#[test]
fn operation_terminal_bindings_and_removed_tag_fail_closed() {
    let mut succeeded = operation_value();
    succeeded["target"] = "running".into();
    succeeded["phase"] = "succeeded".into();
    succeeded["terminal"] = serde_json::json!({
        "kind": "succeeded",
        "result": {
            "observation_id": "11111111111111111111111111111111",
            "node_id": "node_b",
            "agent_session_epoch": 1,
            "heartbeat_sequence": 1,
            "observed_target": "running",
            "runtime_incarnation": "22222222222222222222222222222222"
        },
        "completed_at_unix_ms": 1
    });
    let error = decode_operation(&serde_json::to_vec(&succeeded).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/terminal/result/node_id");

    let mut failed = operation_value();
    failed["phase"] = "failed".into();
    failed["terminal"] = serde_json::json!({
        "kind": "failed",
        "error": {
            "kind": "precondition_failed",
            "reason": {
                "kind": "placement_rejected",
                "node_id": "node_b",
                "placement_epoch": 4,
                "reason": "insufficient_vcpus"
            }
        },
        "completed_at_unix_ms": 1
    });
    let error = decode_operation(&serde_json::to_vec(&failed).unwrap()).unwrap_err();
    assert_eq!(
        malformed(&error).0.as_str(),
        "/terminal/error/reason/node_id"
    );

    failed["terminal"]["error"] = serde_json::json!({"kind": "contract_error"});
    let error = decode_operation(&serde_json::to_vec(&failed).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/terminal/error/kind");
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);

    failed["terminal"]["error"] = serde_json::json!({
        "kind": "contract_error",
        "error": {"code": "malformed_payload"}
    });
    let error = decode_operation(&serde_json::to_vec(&failed).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/terminal/error/error");
    assert_eq!(malformed(&error).1, MalformedProblem::UnknownField);

    failed["terminal"]["error"] = serde_json::json!({
        "kind": "host_lost",
        "node_id": "node_b",
        "agent_session_epoch": 1,
        "host_fence_event_id": "fence_01"
    });
    let error = decode_operation(&serde_json::to_vec(&failed).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/terminal/error/node_id");

    failed["terminal"]["error"] = serde_json::json!({
        "kind": "precondition_failed",
        "reason": {
            "kind": "placement_rejected",
            "node_id": "node_a",
            "placement_epoch": 4,
            "reason": "insufficient_vcpus"
        }
    });
    let error = decode_operation(&serde_json::to_vec(&failed).unwrap()).unwrap_err();
    assert_eq!(
        malformed(&error).0.as_str(),
        "/terminal/error/reason/placement_epoch"
    );
}

#[test]
fn removed_contract_error_condition_tag_is_not_a_compatibility_surface() {
    let claim = "sha256:41afca078d66aa835e402fe2a408a528e989c18ba25e5d7f4cc3ce4124df7dfe";
    let mut observation: serde_json::Value =
        serde_json::from_slice(&complete_observation_wire(NONEMPTY_INVENTORY_INPUT, claim))
            .unwrap();
    observation["runtimes"][0]["conditions"] = serde_json::json!([{"kind": "contract_error"}]);
    let error = decode_node_observation(&serde_json::to_vec(&observation).unwrap()).unwrap_err();
    assert_eq!(
        malformed(&error).0.as_str(),
        "/runtimes/0/conditions/0/kind"
    );
    assert_eq!(malformed(&error).1, MalformedProblem::InvalidValue);
}

#[test]
fn quarantine_identity_reasons_preserve_conflict_evidence() {
    let expected = "11111111111111111111111111111111";
    let different = "22222222222222222222222222222222";
    let mut operation = operation_value();
    operation["phase"] = "failed".into();
    operation["terminal"] = serde_json::json!({
        "kind": "failed",
        "error": {
            "kind": "quarantined",
            "reason": {
                "kind": "runtime_identity_conflict",
                "expected_incarnation": expected,
                "observed_incarnations": [different]
            }
        },
        "completed_at_unix_ms": 1
    });
    decode_operation(&serde_json::to_vec(&operation).unwrap()).unwrap();

    operation["terminal"]["error"]["reason"]["observed_incarnations"] =
        serde_json::json!([expected]);
    let error = decode_operation(&serde_json::to_vec(&operation).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/terminal/error/reason");

    operation["terminal"]["error"]["reason"] = serde_json::json!({
        "kind": "duplicate_runtime",
        "observed_incarnations": [expected]
    });
    let error = decode_operation(&serde_json::to_vec(&operation).unwrap()).unwrap_err();
    assert_eq!(malformed(&error).0.as_str(), "/terminal/error/reason");

    operation["terminal"]["error"]["reason"]["observed_incarnations"] =
        serde_json::json!([expected, different]);
    decode_operation(&serde_json::to_vec(&operation).unwrap()).unwrap();
}

#[test]
fn provision_root_image_payloads_round_trip_canonical_wire() {
    let request_value = provision_root_image_request_value();
    let request =
        decode_provision_root_image_request(&serde_json::to_vec(&request_value).unwrap()).unwrap();
    let request_bytes = encode_provision_root_image_request(&request).unwrap();
    assert_eq!(
        request_bytes,
        format!(
            "{{\"attachment_epoch\":8,\"attachment_id\":\"att_01\",\"boot_image_digest\":\"{ZERO_DIGEST}\",\"expected_blank_head\":{{\"generation\":0,\"root_hash\":null,\"root_object_id\":null}},\"expected_provisioned_head\":{{\"generation\":1,\"root_hash\":\"{ZERO_DIGEST}\",\"root_object_id\":\"volumes/vol_root/roots/1\"}},\"provision_transition_id\":\"1234567890abcdef1234567890abcdef\",\"size_bytes\":4294967296,\"volume_id\":\"vol_root\"}}"
        )
        .into_bytes(),
    );
    assert_eq!(
        decode_provision_root_image_request(&request_bytes).unwrap(),
        request
    );

    let result_value = provision_root_image_result_value();
    let result =
        decode_provision_root_image_result(&serde_json::to_vec(&result_value).unwrap()).unwrap();
    let result_bytes = encode_provision_root_image_result(&result).unwrap();
    assert_eq!(
        result_bytes,
        format!(
            "{{\"attachment_epoch\":8,\"attachment_id\":\"att_01\",\"provision_transition_id\":\"1234567890abcdef1234567890abcdef\",\"resulting_head\":{{\"generation\":1,\"root_hash\":\"{ZERO_DIGEST}\",\"root_object_id\":\"volumes/vol_root/roots/1\"}},\"volume_id\":\"vol_root\"}}"
        )
        .into_bytes(),
    );
    assert_eq!(
        decode_provision_root_image_result(&result_bytes).unwrap(),
        result
    );

    let variants: [(&str, &[&str]); 2] = [
        (
            "retryable",
            &[
                "image_unavailable",
                "object_store_unavailable",
                "authority_unavailable",
                "local_io_unavailable",
            ],
        ),
        (
            "definite_conflict",
            &[
                "request_binding",
                "image_manifest",
                "target_mismatch",
                "local_state",
                "immutable_object",
            ],
        ),
    ];
    for (kind, problems) in variants {
        for problem in problems {
            let value = provision_root_image_error_value(kind, problem);
            let decoded =
                decode_provision_root_image_error(&serde_json::to_vec(&value).unwrap()).unwrap();
            let encoded = encode_provision_root_image_error(&decoded).unwrap();
            if kind == "retryable" && *problem == "image_unavailable" {
                assert_eq!(
                    encoded,
                    b"{\"attachment_epoch\":8,\"attachment_id\":\"att_01\",\"kind\":\"retryable\",\"problem\":\"image_unavailable\",\"provision_transition_id\":\"1234567890abcdef1234567890abcdef\",\"volume_id\":\"vol_root\"}"
                );
            }
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
                value,
                "{kind}.{problem}",
            );
            assert_eq!(
                decode_provision_root_image_error(&encoded).unwrap(),
                decoded,
                "{kind}.{problem}",
            );
        }
    }

    let retryable = decode_provision_root_image_error(
        &serde_json::to_vec(&provision_root_image_error_value(
            "retryable",
            "authority_unavailable",
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        retryable,
        ProvisionRootImageError::Retryable {
            problem: ProvisionRootImageRetryableProblem::AuthorityUnavailable,
            ..
        }
    ));
}

#[test]
fn provision_root_image_payload_schema_is_strict_and_deterministic() {
    let request_value = provision_root_image_request_value();
    let valid_request = serde_json::to_string(&request_value).unwrap();

    let duplicate = replace_once(
        &valid_request,
        r#""volume_id":"vol_root""#,
        r#""volume_id":"vol_root","volume_id":"vol_other""#,
    );
    let error = reject_provision_request(&duplicate);
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "/volume_id");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::DuplicateField
    );

    let mut request_cases = Vec::new();
    let mut missing = request_value.clone();
    missing.as_object_mut().unwrap().remove("volume_id");
    request_cases.push((
        "missing",
        missing,
        "/volume_id",
        MalformedProblem::MissingField,
    ));
    let mut unknown = request_value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("image_id".to_owned(), "old-seed-alias".into());
    request_cases.push((
        "unknown",
        unknown,
        "/image_id",
        MalformedProblem::UnknownField,
    ));
    let mut versioned = request_value.clone();
    versioned
        .as_object_mut()
        .unwrap()
        .insert("version".to_owned(), 1.into());
    request_cases.push((
        "no_runtime_version_space",
        versioned,
        "/version",
        MalformedProblem::UnknownField,
    ));
    let mut wrong_type = request_value.clone();
    wrong_type["attachment_epoch"] = "8".into();
    request_cases.push((
        "wrong_type",
        wrong_type,
        "/attachment_epoch",
        MalformedProblem::InvalidType,
    ));
    let mut invalid_value = request_value;
    invalid_value["size_bytes"] = 0.into();
    request_cases.push((
        "invalid_value",
        invalid_value,
        "/size_bytes",
        MalformedProblem::InvalidValue,
    ));
    for (name, value, pointer, problem) in request_cases {
        let error = reject_provision_request(&serde_json::to_vec(&value).unwrap());
        assert_eq!(
            provision_wire_malformed(&error).0.as_str(),
            pointer,
            "{name}"
        );
        assert_eq!(provision_wire_malformed(&error).1, problem, "{name}");
    }

    let mut result = provision_root_image_result_value();
    result.as_object_mut().unwrap().remove("resulting_head");
    let error = reject_provision_result(&serde_json::to_vec(&result).unwrap());
    assert_eq!(
        provision_wire_malformed(&error).0.as_str(),
        "/resulting_head"
    );
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::MissingField
    );

    let mut result = provision_root_image_result_value();
    result
        .as_object_mut()
        .unwrap()
        .insert("root_hash".to_owned(), ZERO_DIGEST.into());
    let error = reject_provision_result(&serde_json::to_vec(&result).unwrap());
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "/root_hash");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::UnknownField
    );

    let mut local_error = provision_root_image_error_value("retryable", "image_unavailable");
    local_error.as_object_mut().unwrap().remove("kind");
    let error = reject_provision_error(&serde_json::to_vec(&local_error).unwrap());
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "/kind");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::MissingField
    );

    let mut local_error = provision_root_image_error_value("retryable", "image_unavailable");
    local_error
        .as_object_mut()
        .unwrap()
        .insert("message".to_owned(), "opaque".into());
    let error = reject_provision_error(&serde_json::to_vec(&local_error).unwrap());
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "/message");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::UnknownField
    );

    for (name, value, pointer, problem) in [
        (
            "unknown_kind",
            provision_root_image_error_value("conflict", "request_binding"),
            "/kind",
            MalformedProblem::InvalidValue,
        ),
        (
            "retryable_problem_cannot_expand",
            provision_root_image_error_value("retryable", "head_conflict"),
            "/problem",
            MalformedProblem::InvalidValue,
        ),
        (
            "definite_problem_cannot_expand",
            provision_root_image_error_value("definite_conflict", "authority_unavailable"),
            "/problem",
            MalformedProblem::InvalidValue,
        ),
    ] {
        let error = reject_provision_error(&serde_json::to_vec(&value).unwrap());
        assert_eq!(
            provision_wire_malformed(&error).0.as_str(),
            pointer,
            "{name}"
        );
        assert_eq!(provision_wire_malformed(&error).1, problem, "{name}");
    }

    let prefix = valid_request.strip_suffix('}').unwrap();
    for members in [r#""zzz":0,"aaa":0"#, r#""aaa":0,"zzz":0"#] {
        let input = format!("{prefix},{members}}}");
        let error = reject_provision_request(input.as_bytes());
        assert_eq!(provision_wire_malformed(&error).0.as_str(), "/aaa");
        assert_eq!(
            provision_wire_malformed(&error).1,
            MalformedProblem::UnknownField
        );
    }
}

#[test]
fn provision_root_image_payload_transport_numeric_and_depth_boundaries_are_closed() {
    let valid_request = serde_json::to_string(&provision_root_image_request_value()).unwrap();
    for (name, input, problem) in [
        ("invalid_utf8", vec![0xff], MalformedProblem::InvalidUtf8),
        ("invalid_json", b"{".to_vec(), MalformedProblem::InvalidJson),
        (
            "trailing_value",
            format!("{valid_request}[]").into_bytes(),
            MalformedProblem::InvalidJson,
        ),
    ] {
        let error = reject_provision_request(&input);
        assert_eq!(provision_wire_malformed(&error).0.as_str(), "", "{name}");
        assert_eq!(provision_wire_malformed(&error).1, problem, "{name}");
    }

    let duplicate_then_bad_tail = replace_once(
        &format!("{valid_request}[]"),
        r#""volume_id":"vol_root""#,
        r#""volume_id":"vol_root","volume_id":"vol_other""#,
    );
    let error = reject_provision_request(&duplicate_then_bad_tail);
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::InvalidJson
    );

    for (field, original, replacement) in [
        ("attachment_epoch", "8", "-0"),
        ("attachment_epoch", "8", "8e0"),
        ("size_bytes", "4294967296", "1.0"),
        ("size_bytes", "4294967296", "9223372036854775808"),
    ] {
        let needle = format!(r#""{field}":{original}"#);
        let replacement = format!(r#""{field}":{replacement}"#);
        let input = replace_once(&valid_request, &needle, &replacement);
        let error = reject_provision_request(&input);
        assert_eq!(
            provision_wire_malformed(&error).0.as_str(),
            format!("/{field}")
        );
        assert_eq!(
            provision_wire_malformed(&error).1,
            MalformedProblem::InvalidValue
        );
    }

    let base = valid_request.strip_suffix('}').unwrap();
    let depth = 1_500;
    let unknown = format!(
        "{base},\"unknown\":{}0{}}}",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    assert!(unknown.len() < PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES);
    let error = reject_provision_request(unknown.as_bytes());
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "/unknown");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::UnknownField
    );

    let depth = 600;
    let duplicate = format!(
        "{base},\"unknown\":{}{{\"same\":1,\"same\":2}}{}}}",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    assert!(duplicate.len() < PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES);
    let error = reject_provision_request(duplicate.as_bytes());
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::DuplicateField
    );
}

#[test]
fn each_provision_payload_decoder_reuses_transport_and_scalar_stages() {
    type Reject = fn(&[u8]) -> ProvisionRootImageWireDecodeError;
    let cases: Vec<(&str, String, Reject)> = vec![
        (
            "request",
            serde_json::to_string(&provision_root_image_request_value()).unwrap(),
            reject_provision_request,
        ),
        (
            "result",
            serde_json::to_string(&provision_root_image_result_value()).unwrap(),
            reject_provision_result,
        ),
        (
            "error",
            serde_json::to_string(&provision_root_image_error_value(
                "retryable",
                "image_unavailable",
            ))
            .unwrap(),
            reject_provision_error,
        ),
    ];

    for (name, valid, reject) in cases {
        for (transport, input, problem) in [
            ("utf8", vec![0xff], MalformedProblem::InvalidUtf8),
            ("json", b"{".to_vec(), MalformedProblem::InvalidJson),
            (
                "bom",
                [b"\xef\xbb\xbf".as_slice(), valid.as_bytes()].concat(),
                MalformedProblem::InvalidJson,
            ),
            (
                "tail",
                format!("{valid}[]").into_bytes(),
                MalformedProblem::InvalidJson,
            ),
        ] {
            let error = reject(&input);
            assert_eq!(
                provision_wire_malformed(&error).0.as_str(),
                "",
                "{name}.{transport}"
            );
            assert_eq!(
                provision_wire_malformed(&error).1,
                problem,
                "{name}.{transport}"
            );
        }

        let duplicate = replace_once(
            &valid,
            r#""volume_id":"vol_root""#,
            r#""volume_id":"vol_root","volume_id":"vol_other""#,
        );
        let error = reject(&duplicate);
        assert_eq!(
            provision_wire_malformed(&error).0.as_str(),
            "/volume_id",
            "{name}.duplicate"
        );
        assert_eq!(
            provision_wire_malformed(&error).1,
            MalformedProblem::DuplicateField,
            "{name}.duplicate"
        );

        let wrong_type = replace_once(
            &valid,
            r#""attachment_epoch":8"#,
            r#""attachment_epoch":"8""#,
        );
        let error = reject(&wrong_type);
        assert_eq!(
            provision_wire_malformed(&error).0.as_str(),
            "/attachment_epoch",
            "{name}.type"
        );
        assert_eq!(
            provision_wire_malformed(&error).1,
            MalformedProblem::InvalidType,
            "{name}.type"
        );

        let invalid_value = replace_once(
            &valid,
            r#""attachment_epoch":8"#,
            r#""attachment_epoch":-0"#,
        );
        let error = reject(&invalid_value);
        assert_eq!(
            provision_wire_malformed(&error).0.as_str(),
            "/attachment_epoch",
            "{name}.value"
        );
        assert_eq!(
            provision_wire_malformed(&error).1,
            MalformedProblem::InvalidValue,
            "{name}.value"
        );
    }
}

#[test]
fn all_provision_payload_caps_are_public_exact_and_shared_by_decoders() {
    type Accept = fn(&[u8]) -> Result<(), ProvisionRootImageWireDecodeError>;
    let cases: Vec<(&str, Vec<u8>, usize, Accept)> = vec![
        (
            "request",
            serde_json::to_vec(&provision_root_image_request_value()).unwrap(),
            PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
            accept_provision_request,
        ),
        (
            "result",
            serde_json::to_vec(&provision_root_image_result_value()).unwrap(),
            PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES,
            accept_provision_result,
        ),
        (
            "error",
            serde_json::to_vec(&provision_root_image_error_value(
                "retryable",
                "image_unavailable",
            ))
            .unwrap(),
            PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES,
            accept_provision_error,
        ),
    ];
    for (name, mut payload, maximum, accept) in cases {
        assert_eq!(maximum, 4_096, "{name}");
        payload.resize(maximum, b' ');
        accept(&payload).unwrap_or_else(|error| panic!("{name} exact cap: {error:?}"));

        payload.push(b' ');
        let error = accept(&payload).unwrap_err();
        assert_eq!(
            error,
            ProvisionRootImageWireDecodeError::WireBytesLimitExceeded {
                maximum: WireU64::new(maximum as u64).unwrap(),
                observed_at_least: WireU64::new(maximum as u64 + 1).unwrap(),
            },
            "{name}",
        );
    }
}

#[test]
fn provision_payload_remote_heads_are_intrinsic_but_roles_stay_context_bound() {
    let combinations = [
        (0, None, None, true),
        (0, Some(ZERO_DIGEST), None, false),
        (0, None, Some("volumes/vol_root/roots/0"), false),
        (
            0,
            Some(ZERO_DIGEST),
            Some("volumes/vol_root/roots/0"),
            false,
        ),
        (1, None, None, false),
        (1, Some(ZERO_DIGEST), None, false),
        (1, None, Some("volumes/vol_root/roots/1"), false),
        (1, Some(ZERO_DIGEST), Some("volumes/vol_root/roots/1"), true),
    ];
    for field in ["expected_blank_head", "expected_provisioned_head"] {
        for (generation, root_hash, root_object_id, valid) in combinations {
            let mut request = provision_root_image_request_value();
            request[field] = serde_json::json!({
                "generation": generation,
                "root_hash": root_hash,
                "root_object_id": root_object_id,
            });
            let decoded =
                decode_provision_root_image_request(&serde_json::to_vec(&request).unwrap());
            if valid {
                decoded.unwrap();
            } else {
                let error = decoded.unwrap_err();
                assert_eq!(
                    provision_wire_malformed(&error).0.as_str(),
                    format!("/{field}")
                );
                assert_eq!(
                    provision_wire_malformed(&error).1,
                    MalformedProblem::InvalidValue
                );
            }
        }
    }

    for (generation, root_hash, root_object_id, valid) in combinations {
        let mut result = provision_root_image_result_value();
        result["resulting_head"] = serde_json::json!({
            "generation": generation,
            "root_hash": root_hash,
            "root_object_id": root_object_id,
        });
        let decoded = decode_provision_root_image_result(&serde_json::to_vec(&result).unwrap());
        if valid {
            decoded.unwrap();
        } else {
            let error = decoded.unwrap_err();
            assert_eq!(
                provision_wire_malformed(&error).0.as_str(),
                "/resulting_head"
            );
            assert_eq!(
                provision_wire_malformed(&error).1,
                MalformedProblem::InvalidValue
            );
        }
    }

    let mut context_bound = provision_root_image_request_value();
    context_bound["expected_blank_head"] = nonzero_remote_head();
    context_bound["expected_provisioned_head"] = zero_remote_head();
    decode_provision_root_image_request(&serde_json::to_vec(&context_bound).unwrap()).unwrap();

    let mut scalar_precedes_cross = provision_root_image_request_value();
    scalar_precedes_cross["volume_id"] = "bad id".into();
    scalar_precedes_cross["expected_blank_head"] = serde_json::json!({
        "generation": 1,
        "root_hash": null,
        "root_object_id": null,
    });
    let error = reject_provision_request(&serde_json::to_vec(&scalar_precedes_cross).unwrap());
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "/volume_id");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::InvalidValue
    );
}

#[test]
fn provision_control_frame_contract_is_bounded_and_one_command_per_connection() {
    fn first_frame_payload<'a>(
        frame: &'a [u8],
        prefix: &[u8],
        maximum: usize,
    ) -> Result<&'a [u8], &'static str> {
        let remaining = frame.strip_prefix(prefix).ok_or("wrong prefix")?;
        let bounded = &remaining[..remaining.len().min(maximum + 1)];
        let line_end = bounded.iter().position(|byte| *byte == b'\n');
        let Some(line_end) = line_end else {
            return if remaining.len() > maximum {
                Err("wire bytes")
            } else {
                Err("missing LF")
            };
        };
        let payload = &remaining[..line_end];
        if payload.ends_with(b"\r") {
            return Err("CRLF");
        }
        Ok(payload)
    }

    type Accept = fn(&[u8]) -> Result<(), ProvisionRootImageWireDecodeError>;
    let cases: Vec<(&[u8], Vec<u8>, usize, Accept)> = vec![
        (
            b"provision_root_image ",
            serde_json::to_vec(&provision_root_image_request_value()).unwrap(),
            PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
            accept_provision_request,
        ),
        (
            b"OK ",
            serde_json::to_vec(&provision_root_image_result_value()).unwrap(),
            PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES,
            accept_provision_result,
        ),
        (
            b"ERR ",
            serde_json::to_vec(&provision_root_image_error_value(
                "retryable",
                "image_unavailable",
            ))
            .unwrap(),
            PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES,
            accept_provision_error,
        ),
    ];
    for (prefix, mut payload, maximum, accept) in cases {
        let canonical_payload = payload.clone();
        payload.resize(maximum, b' ');
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&payload);
        frame.push(b'\n');
        let decoded_payload = first_frame_payload(&frame, prefix, maximum).unwrap();
        assert_eq!(decoded_payload.len(), maximum);
        accept(decoded_payload).unwrap();

        let mut over = prefix.to_vec();
        over.extend_from_slice(&vec![b' '; maximum + 1]);
        over.push(b'\n');
        assert_eq!(
            first_frame_payload(&over, prefix, maximum),
            Err("wire bytes")
        );

        let mut crlf = prefix.to_vec();
        crlf.extend_from_slice(&canonical_payload);
        crlf.extend_from_slice(b"\r\n");
        assert_eq!(first_frame_payload(&crlf, prefix, maximum), Err("CRLF"));
    }

    let request = serde_json::to_vec(&provision_root_image_request_value()).unwrap();
    let mut wrong_prefix = b"seed_image ".to_vec();
    wrong_prefix.extend_from_slice(&request);
    wrong_prefix.push(b'\n');
    assert_eq!(
        first_frame_payload(
            &wrong_prefix,
            b"provision_root_image ",
            PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
        ),
        Err("wrong prefix")
    );

    let split = request.len() / 2;
    let mut embedded_lf = b"provision_root_image ".to_vec();
    embedded_lf.extend_from_slice(&request[..split]);
    embedded_lf.push(b'\n');
    embedded_lf.extend_from_slice(&request[split..]);
    embedded_lf.push(b'\n');
    let truncated = first_frame_payload(
        &embedded_lf,
        b"provision_root_image ",
        PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
    )
    .unwrap();
    let error = reject_provision_request(truncated);
    assert_eq!(provision_wire_malformed(&error).0.as_str(), "");
    assert_eq!(
        provision_wire_malformed(&error).1,
        MalformedProblem::InvalidJson
    );

    let mut followed_by_second = b"provision_root_image ".to_vec();
    followed_by_second.extend_from_slice(&request);
    followed_by_second.extend_from_slice(b"\nprovision_root_image ");
    followed_by_second.extend_from_slice(&request);
    followed_by_second.push(b'\n');
    let first = first_frame_payload(
        &followed_by_second,
        b"provision_root_image ",
        PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
    )
    .unwrap();
    assert_eq!(first, request);
    accept_provision_request(first).unwrap();
}

#[test]
fn deeply_nested_unknown_subtrees_are_scanned_without_process_stack_use() {
    let build = |depth: usize, duplicate_pairs: usize, descending: bool| {
        let mut input = String::from_utf8(complete_observation_wire(
            EMPTY_INVENTORY_INPUT,
            "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05",
        ))
        .unwrap();
        assert_eq!(input.pop(), Some('}'));
        input.push_str(r#", "unknown":"#);
        input.push_str(&"[".repeat(depth));
        input.push('{');
        for ordinal in 0..duplicate_pairs {
            if ordinal != 0 {
                input.push(',');
            }
            let key = if descending {
                duplicate_pairs - ordinal - 1
            } else {
                ordinal
            };
            write!(input, r#""{key:05}":0,"{key:05}":1"#).unwrap();
        }
        input.push('}');
        input.push_str(&"]".repeat(depth));
        input.push('}');
        input
    };

    let input = build(3_500_000, 50_000, true);
    assert!(input.len() < 8_388_608);

    let error = decode_node_observation(input.as_bytes()).unwrap_err();
    assert_eq!(malformed(&error).1, MalformedProblem::DuplicateField);
    assert_eq!(malformed(&error).0.as_str(), "");

    for descending in [false, true] {
        let input = build(3, 100, descending);
        let error = decode_node_observation(input.as_bytes()).unwrap_err();
        assert_eq!(malformed(&error).1, MalformedProblem::DuplicateField);
        assert_eq!(malformed(&error).0.as_str(), "/unknown/0/0/0/00000");
    }
}

#[test]
fn super_wide_invalid_array_keeps_one_schema_candidate_and_scans_its_tail() {
    const WIDTH: usize = 1_000_000;
    const MARKER: &str = r#""runtimes":[]"#;

    let base = String::from_utf8(complete_observation_wire(
        EMPTY_INVENTORY_INPUT,
        "sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05",
    ))
    .unwrap();
    let marker = base.find(MARKER).unwrap();
    let mut input = String::with_capacity(base.len() + WIDTH * 3);
    input.push_str(&base[..marker]);
    input.push_str(r#""runtimes":["#);
    for index in 0..WIDTH {
        if index != 0 {
            input.push(',');
        }
        input.push_str("{}");
    }
    input.push(']');
    input.push_str(&base[marker + MARKER.len()..]);
    assert!(input.len() < 8_388_608);

    let error = decode_node_observation(input.as_bytes()).unwrap_err();
    assert_eq!(
        malformed(&error),
        (
            &JsonPointer::new("/runtimes/0/applied_desired").unwrap(),
            MalformedProblem::MissingField,
        )
    );

    let tail = input.rfind("{}").unwrap();
    input.replace_range(tail..tail + 2, r#"{"same":1,"same":2}"#);
    let error = decode_node_observation(input.as_bytes()).unwrap_err();
    assert_eq!(malformed(&error).1, MalformedProblem::DuplicateField);
    assert_eq!(malformed(&error).0.as_str(), "/runtimes/999999/same");
}

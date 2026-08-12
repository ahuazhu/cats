use cats_api::runtime_reconciliation::{
    decode_node_placement_policy, decode_runtime_node_authority_apply,
    decode_runtime_node_authority_apply_result, decode_runtime_provisioner_active_set,
    decode_runtime_provisioner_trust_bundle, encode_node_placement_policy,
    encode_runtime_node_authority_apply, encode_runtime_node_authority_apply_result,
    encode_runtime_provisioner_active_set, encode_runtime_provisioner_trust_bundle,
    runtime_provisioner_active_set_digest,
};
use sha2::{Digest, Sha256};

const POLICY: &[u8] = br#"{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":1,"scheduling_state":"cordoned","version":1}"#;
const ACTIVE_SET: &[u8] = br#"{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],"deployment_id":"deployment_a","version":1}"#;
const TRUST_BUNDLE: &[u8] = br#"{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],"deployment_id":"deployment_a","expected_previous":null,"trust_revision":1,"version":1}"#;
const APPLY: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}"#;
const RESULT: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity_state":"provisioned","node_id":"node_a","outcome":"policy_updated","policy_revision":2,"version":1}"#;

fn assert_vector(bytes: &[u8], expected_len: usize, expected_sha256: &str) {
    assert_eq!(bytes.len(), expected_len);
    assert_eq!(hex::encode(Sha256::digest(bytes)), expected_sha256);
}

#[test]
fn canonical_fixed_vectors_round_trip_exactly() {
    let policy = decode_node_placement_policy(POLICY).unwrap();
    assert_eq!(encode_node_placement_policy(&policy).unwrap(), POLICY);
    assert_vector(
        POLICY,
        552,
        "fdfcf8bb96ab5ba124aeeaff498eb4bbd88eeda2e0afd2cf0ab188778e67464e",
    );

    let active_set = decode_runtime_provisioner_active_set(ACTIVE_SET).unwrap();
    assert_eq!(
        encode_runtime_provisioner_active_set(&active_set).unwrap(),
        ACTIVE_SET
    );
    assert_vector(
        ACTIVE_SET,
        174,
        "e348b9d89a43efd190cfc8443abdd2dcb4e14bf21537f5bfef0ec82a1d70a144",
    );
    assert_eq!(
        runtime_provisioner_active_set_digest(&active_set)
            .unwrap()
            .as_str(),
        "sha256:e348b9d89a43efd190cfc8443abdd2dcb4e14bf21537f5bfef0ec82a1d70a144"
    );

    let trust = decode_runtime_provisioner_trust_bundle(TRUST_BUNDLE).unwrap();
    assert_eq!(
        encode_runtime_provisioner_trust_bundle(&trust).unwrap(),
        TRUST_BUNDLE
    );
    assert_vector(
        TRUST_BUNDLE,
        218,
        "f054993251d9e78ea0cc9169ec5156e36465b874257f946d970a624d0b92b49a",
    );

    let apply = decode_runtime_node_authority_apply(APPLY).unwrap();
    assert_eq!(encode_runtime_node_authority_apply(&apply).unwrap(), APPLY);
    assert_vector(
        APPLY,
        718,
        "b03395b52d23522f5c549493b82c5d00f1b4ee102dbbe27770c475509cf36d21",
    );

    let result = decode_runtime_node_authority_apply_result(RESULT).unwrap();
    assert_eq!(
        encode_runtime_node_authority_apply_result(&result).unwrap(),
        RESULT
    );
    assert_vector(
        RESULT,
        156,
        "94ff5e6829405355d85dfff7c1a7f1e7f02cf420c64cab408c68366438e16468",
    );
}

#[test]
fn policy_rejects_unaligned_or_non_private_pool() {
    for address in ["10.240.1.0", "172.32.0.0", "192.0.0.0"] {
        let candidate = String::from_utf8(POLICY.to_vec())
            .unwrap()
            .replace("10.240.0.0", address);
        assert!(decode_node_placement_policy(candidate.as_bytes()).is_err());
    }
}

#[test]
fn policy_requires_one_canonical_https_node_transport_authority() {
    let policy = decode_node_placement_policy(POLICY).unwrap();
    assert_eq!(
        policy.node_transport_target.as_str(),
        "https://node-a.internal:7301"
    );
    for target in [
        "http://node-a.internal:7301",
        "HTTPS://node-a.internal:7301",
        "https://user@node-a.internal:7301",
        "https://node-a.internal:7301/",
        "https://node-a.internal:7301?query",
        "https://node-a.internal:7301#fragment",
        "https://NODE-a.internal:7301",
        "https://node-a.internal",
        "https://node-a.internal:0",
        "https://node-a.internal:07301",
        "https://node-a.internal:65536",
        "https://10.0.0.1:7301",
        "https://2130706433:7301",
        "https://127.1:7301",
        "https://010.0.0.1:7301",
        "https://0x7f.0.0.1:7301",
        "https://0x.0.0.1:7301",
    ] {
        let candidate = String::from_utf8(POLICY.to_vec())
            .unwrap()
            .replace("https://node-a.internal:7301", target);
        assert!(
            decode_node_placement_policy(candidate.as_bytes()).is_err(),
            "accepted non-canonical target {target:?}"
        );
    }
    for target in ["https://node-a.internal:1", "https://node-a.internal:65535"] {
        let candidate = String::from_utf8(POLICY.to_vec())
            .unwrap()
            .replace("https://node-a.internal:7301", target);
        assert!(
            decode_node_placement_policy(candidate.as_bytes()).is_ok(),
            "rejected canonical boundary target {target:?}"
        );
    }
}

#[test]
fn trust_bundle_rejects_invalid_revision_order_and_spki() {
    let empty = String::from_utf8(TRUST_BUNDLE.to_vec())
        .unwrap()
        .replace(
            r#"[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]"#,
            "[]",
        );
    assert!(decode_runtime_provisioner_trust_bundle(empty.as_bytes()).is_err());

    let wrong_revision = String::from_utf8(TRUST_BUNDLE.to_vec()).unwrap().replace(
        r#""expected_previous":null,"trust_revision":1"#,
        r#""expected_previous":null,"trust_revision":2"#,
    );
    assert!(decode_runtime_provisioner_trust_bundle(wrong_revision.as_bytes()).is_err());

    let wrong_spki = String::from_utf8(TRUST_BUNDLE.to_vec()).unwrap().replace(
        "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "AQ",
    );
    assert!(decode_runtime_provisioner_trust_bundle(wrong_spki.as_bytes()).is_err());
}

#[test]
fn apply_and_result_reject_self_consistent_wrong_bindings() {
    let wrong_node = String::from_utf8(APPLY.to_vec()).unwrap().replacen(
        r#""node_id":"node_a""#,
        r#""node_id":"node_b""#,
        1,
    );
    assert!(decode_runtime_node_authority_apply(wrong_node.as_bytes()).is_err());

    let wrong_revision = String::from_utf8(APPLY.to_vec()).unwrap().replace(
        r#""expected_policy_revision":1"#,
        r#""expected_policy_revision":2"#,
    );
    assert!(decode_runtime_node_authority_apply(wrong_revision.as_bytes()).is_err());

    let wrong_result = String::from_utf8(RESULT.to_vec()).unwrap().replace(
        r#""identity_state":"provisioned""#,
        r#""identity_state":"retired""#,
    );
    assert!(decode_runtime_node_authority_apply_result(wrong_result.as_bytes()).is_err());
}

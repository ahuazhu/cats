use cats_api::runtime_reconciliation::{
    decode_node_placement_policy, decode_runtime_node_authority_apply,
    decode_runtime_node_authority_apply_result, decode_runtime_provisioner_active_set,
    decode_runtime_provisioner_trust_bundle, encode_node_placement_policy,
    encode_runtime_node_authority_apply, encode_runtime_node_authority_apply_result,
    encode_runtime_provisioner_active_set, encode_runtime_provisioner_trust_bundle,
    object_write_writer_authority_id, runtime_provisioner_active_set_digest,
    RuntimeNodeAuthorityMutation,
};
use sha2::{Digest, Sha256};

const POLICY: &[u8] = br#"{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":1,"scheduling_state":"cordoned","version":1}"#;
const ACTIVE_SET: &[u8] = br#"{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],"deployment_id":"deployment_a","version":1}"#;
const TRUST_BUNDLE: &[u8] = br#"{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],"deployment_id":"deployment_a","expected_previous":null,"trust_revision":1,"version":1}"#;
const APPLY: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}"#;
const RESULT: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity_state":"provisioned","node_id":"node_a","outcome":"policy_updated","policy_revision":2,"version":1,"writer_authority_id":null}"#;

const OBJECT_WRITE_APPLY: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mutation":{"expected_policy_revision":2,"kind":"provision_object_write_authority","object_provider_scope":{"account_id":"123456789012","partition":"aws","provider":"aws","region":"us-east-1"},"object_store_scope_id":"arn:aws:s3:::cats-production/chunks","workload_principal_id":"arn:aws:iam::123456789012:role/cats-production-object-write-gateway"},"node_id":"node_a","version":1}"#;
const OBJECT_WRITE_RESULT: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity_state":"provisioned","node_id":"node_a","outcome":"object_write_authority_provisioned","policy_revision":2,"version":1,"writer_authority_id":"owa1_281bca4b03db70a1efdc5a7a2fb3c5c8c4e15672546f2ccf8459b458cd9abdfa"}"#;

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
        183,
        "3f97eb7605f89e57e2196b19c1e76bbddf839032603c050b7cb3d7cd3980bdfc",
    );
}

#[test]
fn object_write_authority_apply_freezes_its_wire_and_assigned_id() {
    let apply = decode_runtime_node_authority_apply(OBJECT_WRITE_APPLY).unwrap();
    assert_eq!(
        encode_runtime_node_authority_apply(&apply).unwrap(),
        OBJECT_WRITE_APPLY
    );
    assert_vector(
        OBJECT_WRITE_APPLY,
        428,
        "9512b8ea46a51c0ab48cd5a4e4b22ed1ef6ddb536bc206afe58b9c5dda8f2f5e",
    );

    let RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority {
        object_provider_scope,
        workload_principal_id,
        object_store_scope_id,
        ..
    } = &apply.mutation
    else {
        panic!("frozen vector is a writer-authority apply");
    };
    // The assigned ID is a closed function of the exact binding, so the frozen
    // result vector below is the only ID this apply can ever produce.
    assert_eq!(
        object_write_writer_authority_id(
            &apply.node_id,
            object_provider_scope,
            workload_principal_id,
            object_store_scope_id,
        )
        .as_str(),
        "owa1_281bca4b03db70a1efdc5a7a2fb3c5c8c4e15672546f2ccf8459b458cd9abdfa"
    );

    let result = decode_runtime_node_authority_apply_result(OBJECT_WRITE_RESULT).unwrap();
    assert_eq!(
        encode_runtime_node_authority_apply_result(&result).unwrap(),
        OBJECT_WRITE_RESULT
    );
    assert_vector(
        OBJECT_WRITE_RESULT,
        270,
        "8ea3bd1f3af6b63ced5325a8a76bb5548f925dfdde8f957c7c0e61bd13827cad",
    );
}

#[test]
fn assigned_writer_authority_id_belongs_to_exactly_one_outcome_and_shape() {
    let text = String::from_utf8(OBJECT_WRITE_RESULT.to_vec()).unwrap();
    for wrong in [
        r#""outcome":"policy_updated""#,
        r#""outcome":"provisioned""#,
        r#""outcome":"credential_rotated""#,
    ] {
        let candidate = text.replace(r#""outcome":"object_write_authority_provisioned""#, wrong);
        assert!(
            decode_runtime_node_authority_apply_result(candidate.as_bytes()).is_err(),
            "accepted an assigned writer authority ID on {wrong}"
        );
    }
    let missing = text.replace(
        r#""writer_authority_id":"owa1_281bca4b03db70a1efdc5a7a2fb3c5c8c4e15672546f2ccf8459b458cd9abdfa""#,
        r#""writer_authority_id":null"#,
    );
    assert!(decode_runtime_node_authority_apply_result(missing.as_bytes()).is_err());
    for wrong_shape in [
        "owa1_281BCA4B03DB70A1EFDC5A7A2FB3C5C8C4E15672546F2CCF8459B458CD9ABDFA",
        "owa1_281bca4b03db70a1efdc5a7a2fb3c5c8c4e15672546f2ccf8459b458cd9abdf",
        "owa2_281bca4b03db70a1efdc5a7a2fb3c5c8c4e15672546f2ccf8459b458cd9abdfa",
        "281bca4b03db70a1efdc5a7a2fb3c5c8c4e15672546f2ccf8459b458cd9abdfa",
    ] {
        let candidate = text.replace(
            "owa1_281bca4b03db70a1efdc5a7a2fb3c5c8c4e15672546f2ccf8459b458cd9abdfa",
            wrong_shape,
        );
        assert!(
            decode_runtime_node_authority_apply_result(candidate.as_bytes()).is_err(),
            "accepted a non-canonical writer authority ID {wrong_shape}"
        );
    }
    // Calibration: the exact frozen result still decodes.
    assert!(decode_runtime_node_authority_apply_result(OBJECT_WRITE_RESULT).is_ok());
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

//! Shared A23 runtime Node-authority HTTP proof primitives.
//!
//! The control-plane adapter owns header occurrence and credential-envelope
//! admission. This module owns the one deployment-provisioner Ed25519 dialect
//! so clients and the verifier cannot drift on framed bytes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest as _, Sha256};

use crate::agent_registration::Ed25519RequestSigner;
use crate::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, FleetPolicyPrincipal, RuntimeProvisionerCredential,
};

pub const RUNTIME_NODE_AUTHORITY_PATH: &str = "/v1/admin/runtime/node-authority-applies";
pub const RUNTIME_NODE_AUTHORITY_METHOD: &str = "POST";
pub const PROVISIONER_CREDENTIAL_ID_HEADER: &str = "cats-provisioner-credential-id";
pub const PROVISIONER_SIGNATURE_HEADER: &str = "cats-provisioner-signature";
pub const NODE_AUTHORITY_APPLY_ID_HEADER: &str = "cats-node-authority-apply-id";
pub const RUNTIME_NODE_AUTHORITY_REQUEST_MAX_WIRE_BYTES: usize = 65_536;
pub const RUNTIME_NODE_AUTHORITY_SUCCESS_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_NODE_AUTHORITY_ERROR_MAX_WIRE_BYTES: usize = 20_480;

const SIGNATURE_DOMAIN: &[u8] = b"cats.runtime-node-authority.request.v1";
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("runtime Node authority request authentication failed")]
pub struct RuntimeNodeAuthorityProofError;

/// The two exact headers emitted by a deployment provisioner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeNodeAuthorityProvisionerProof {
    pub credential_id: String,
    pub signature: String,
}

/// Sign the one frozen A23 deployment-provisioner request frame.
///
/// PKCS#8 parsing and Ed25519 key handling remain owned by
/// [`Ed25519RequestSigner`]; this wrapper prevents clients from copying or
/// subtly drifting the A23 frame.
pub fn sign_runtime_node_authority_request(
    deployment_id: &crate::runtime_reconciliation::Id,
    signer: &Ed25519RequestSigner,
    exact_body: &[u8],
) -> RuntimeNodeAuthorityProvisionerProof {
    let signed = runtime_node_authority_signed_request(
        deployment_id.as_str(),
        signer.credential_id().as_str(),
        exact_body,
    );
    RuntimeNodeAuthorityProvisionerProof {
        credential_id: signer.credential_id().to_string(),
        signature: URL_SAFE_NO_PAD.encode(signer.sign_framed(&signed)),
    }
}

/// Verify a machine apply against one credential from the fixed startup
/// bundle and return the only typed principal accepted by the Store.
pub fn verify_runtime_node_authority_request(
    deployment_id: &crate::runtime_reconciliation::Id,
    credential: &RuntimeProvisionerCredential,
    exact_body: &[u8],
    signature: &str,
) -> Result<FleetPolicyPrincipal, RuntimeNodeAuthorityProofError> {
    let spki = decode_base64url_exact::<ED25519_SPKI_LEN>(credential.public_key_spki.as_str())?;
    if spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(RuntimeNodeAuthorityProofError);
    }
    let signature = decode_base64url_exact::<64>(signature)?;
    let signed = runtime_node_authority_signed_request(
        deployment_id.as_str(),
        credential.credential_id.as_str(),
        exact_body,
    );
    UnparsedPublicKey::new(&ED25519, &spki[ED25519_SPKI_PREFIX.len()..])
        .verify(&signed, &signature)
        .map_err(|_| RuntimeNodeAuthorityProofError)?;
    let public_key_spki_sha256 = canonical_ed25519_spki_sha256(&credential.public_key_spki)
        .ok_or(RuntimeNodeAuthorityProofError)?;
    Ok(FleetPolicyPrincipal::DeploymentProvisioner {
        deployment_id: deployment_id.clone(),
        credential_id: credential.credential_id.clone(),
        public_key_spki: credential.public_key_spki.clone(),
        public_key_spki_sha256,
    })
}

/// Exact framed bytes signed by the deployment provisioner.
pub fn runtime_node_authority_signed_request(
    deployment_id: &str,
    credential_id: &str,
    exact_body: &[u8],
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(
        SIGNATURE_DOMAIN.len()
            + 1
            + 8 * 5
            + RUNTIME_NODE_AUTHORITY_METHOD.len()
            + RUNTIME_NODE_AUTHORITY_PATH.len()
            + crate::agent_registration::JSON_CONTENT_TYPE.len()
            + deployment_id.len()
            + credential_id.len()
            + 32,
    );
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.push(0);
    append_frame(&mut signed, RUNTIME_NODE_AUTHORITY_METHOD.as_bytes());
    append_frame(&mut signed, RUNTIME_NODE_AUTHORITY_PATH.as_bytes());
    append_frame(
        &mut signed,
        crate::agent_registration::JSON_CONTENT_TYPE.as_bytes(),
    );
    append_frame(&mut signed, deployment_id.as_bytes());
    append_frame(&mut signed, credential_id.as_bytes());
    signed.extend_from_slice(&(exact_body.len() as u64).to_be_bytes());
    signed.extend_from_slice(&Sha256::digest(exact_body));
    signed
}

fn append_frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_base64url_exact<const N: usize>(
    value: &str,
) -> Result<[u8; N], RuntimeNodeAuthorityProofError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    {
        return Err(RuntimeNodeAuthorityProofError);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RuntimeNodeAuthorityProofError)?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(RuntimeNodeAuthorityProofError);
    }
    decoded
        .try_into()
        .map_err(|_| RuntimeNodeAuthorityProofError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_reconciliation::{Base64UrlNoPad, Id};

    const APPLY: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}"#;

    #[test]
    fn frozen_signature_vector_verifies() {
        let deployment_id = Id::new("deployment_a".to_owned()).unwrap();
        let credential = RuntimeProvisionerCredential {
            credential_id: Id::new("provisioner_a".to_owned()).unwrap(),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
            )
            .unwrap(),
        };
        let principal = verify_runtime_node_authority_request(
            &deployment_id,
            &credential,
            APPLY,
            "2e7RW-nONH8NAPi7tPQeVdiOCRG0fUKI9OMO6MxjwvmPLPdefC2DWPwvDC-lE6BQ2XzFdZEoKcgb4LCo_MBXAA",
        )
        .unwrap();
        assert!(matches!(
            principal,
            FleetPolicyPrincipal::DeploymentProvisioner { .. }
        ));
        assert_eq!(
            hex::encode(Sha256::digest(runtime_node_authority_signed_request(
                "deployment_a",
                "provisioner_a",
                APPLY,
            ))),
            "4c67c5a92e987723f0e64e1468ca77a7ddcac6ea4f06d12c85444e9050fb939e"
        );
    }

    #[test]
    fn provisioner_signer_emits_the_frozen_signature_vector() {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        let signer = Ed25519RequestSigner::from_pkcs8_der(
            Id::new("provisioner_a".to_owned()).unwrap(),
            &der,
        )
        .unwrap();
        let deployment_id = Id::new("deployment_a".to_owned()).unwrap();
        let proof = sign_runtime_node_authority_request(&deployment_id, &signer, APPLY);
        assert_eq!(proof.credential_id, "provisioner_a");
        assert_eq!(
            proof.signature,
            "2e7RW-nONH8NAPi7tPQeVdiOCRG0fUKI9OMO6MxjwvmPLPdefC2DWPwvDC-lE6BQ2XzFdZEoKcgb4LCo_MBXAA"
        );
    }

    #[test]
    fn proof_binds_body_and_is_canonical_base64url() {
        let deployment_id = Id::new("deployment_a".to_owned()).unwrap();
        let credential = RuntimeProvisionerCredential {
            credential_id: Id::new("provisioner_a".to_owned()).unwrap(),
            public_key_spki: Base64UrlNoPad::new(
                "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
            )
            .unwrap(),
        };
        assert!(verify_runtime_node_authority_request(
            &deployment_id,
            &credential,
            b"{}",
            "2e7RW-nONH8NAPi7tPQeVdiOCRG0fUKI9OMO6MxjwvmPLPdefC2DWPwvDC-lE6BQ2XzFdZEoKcgb4LCo_MBXAA",
        )
        .is_err());
        assert!(verify_runtime_node_authority_request(
            &deployment_id,
            &credential,
            APPLY,
            "2e7RW-nONH8NAPi7tPQeVdiOCRG0fUKI9OMO6MxjwvmPLPdefC2DWPwvDC-lE6BQ2XzFdZEoKcgb4LCo_MBXAA=",
        )
        .is_err());
    }
}

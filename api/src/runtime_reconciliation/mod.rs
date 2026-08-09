//! Runtime Reconciliation v1 shared contracts.
//!
//! The explicit decoders implement the context-free validation pipeline from
//! the canonical specification; their paired encoders validate through those
//! decoders and emit the one canonical wire representation. Store-, filesystem-,
//! provider-, and current-session validation deliberately stays at the
//! consuming component boundary.
//!
//! Decoder working memory is linear in each contract's documented wire-byte
//! limit. Ingresses must enforce that limit while reading the body, before
//! calling a decoder, and must bound concurrent large-body decodes.
//!
//! Root-image provision request/result/error payloads reuse the same private
//! parser and scalar rules. Their named decoders accept JSON payload bytes
//! only; the blockd transport boundary owns the ASCII prefix, first-LF framing,
//! and one-command-per-connection rule.

mod canonical;
mod types;
mod wire;

/// Exact A20 internal HTTP method used by both runtime-spine routes.
pub const RUNTIME_SPINE_METHOD: &str = "POST";
/// Exact A20 Desired read route signed by the per-Node A19 credential.
pub const DESIRED_READ_PATH: &str = "/v1/internal/runtime/desired-reads";
/// Exact A20 observation route signed by the per-Node A19 credential.
pub const OBSERVATION_PATH: &str = "/v1/internal/runtime/observations";

pub const RUNTIME_VOLUME_TRANSITION_PATH: &str = "/v1/internal/runtime/volume-transitions";
pub const RUNTIME_VOLUME_TRANSITION_EVIDENCE_PATH: &str =
    "/v1/internal/runtime/volume-transition-evidence";

pub(crate) use canonical::value_bytes as canonical_json_value_bytes;

pub use canonical::{
    canonical_ed25519_spki_sha256, checkpoint_content_digest, guest_config_digest,
    inventory_digest, key_ring_digest, runtime_provisioner_active_set_digest, spec_digest,
};
pub use types::*;
pub use wire::{
    decode_admission_inventory_attestation, decode_agent_registration_attempt,
    decode_agent_session, decode_contract_error, decode_desired_read_request,
    decode_desired_read_snapshot, decode_desired_runtime_spec,
    decode_guest_runtime_profile_receipt, decode_node_cleanup_checkpoint, decode_node_identity,
    decode_node_observation, decode_node_placement_policy, decode_observation_acceptance,
    decode_operation, decode_provision_root_image_error, decode_provision_root_image_request,
    decode_provision_root_image_result, decode_runtime_checkpoint,
    decode_runtime_node_authority_apply, decode_runtime_node_authority_apply_result,
    decode_runtime_provisioner_active_set, decode_runtime_provisioner_trust_bundle,
    decode_runtime_spine_error, decode_runtime_volume_transition_error,
    decode_runtime_volume_transition_evidence_request,
    decode_runtime_volume_transition_evidence_success, encode_admission_inventory_attestation,
    encode_agent_registration_attempt, encode_agent_session, encode_contract_error,
    encode_desired_read_request, encode_desired_read_snapshot, encode_desired_runtime_spec,
    encode_guest_runtime_profile_receipt, encode_node_cleanup_checkpoint, encode_node_identity,
    encode_node_observation, encode_node_placement_policy, encode_observation_acceptance,
    encode_operation, encode_provision_root_image_error, encode_provision_root_image_request,
    encode_provision_root_image_result, encode_runtime_checkpoint,
    encode_runtime_node_authority_apply, encode_runtime_node_authority_apply_result,
    encode_runtime_provisioner_active_set, encode_runtime_provisioner_trust_bundle,
    encode_runtime_spine_error, encode_runtime_volume_transition_error,
    encode_runtime_volume_transition_evidence_request,
    encode_runtime_volume_transition_evidence_success,
    ADMISSION_INVENTORY_ATTESTATION_MAX_WIRE_BYTES,
    AGENT_REGISTRATION_ATTEMPT_MAX_WIRE_BYTES, AGENT_SESSION_MAX_WIRE_BYTES,
    CONTRACT_ERROR_MAX_WIRE_BYTES, DESIRED_READ_REQUEST_MAX_WIRE_BYTES,
    DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES, DESIRED_RUNTIME_SPEC_MAX_WIRE_BYTES,
    GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES, NODE_CLEANUP_CHECKPOINT_MAX_WIRE_BYTES,
    NODE_IDENTITY_MAX_WIRE_BYTES, NODE_OBSERVATION_MAX_WIRE_BYTES,
    NODE_PLACEMENT_POLICY_MAX_WIRE_BYTES, OBSERVATION_ACCEPTANCE_MAX_WIRE_BYTES,
    OPERATION_MAX_WIRE_BYTES, PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES,
    PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES, PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES,
    RUNTIME_CHECKPOINT_MAX_WIRE_BYTES, RUNTIME_NODE_AUTHORITY_APPLY_MAX_WIRE_BYTES,
    RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES,
    RUNTIME_PROVISIONER_ACTIVE_SET_MAX_WIRE_BYTES, RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES,
    RUNTIME_SPINE_ERROR_MAX_WIRE_BYTES,
    RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES,
    RUNTIME_VOLUME_TRANSITION_EVIDENCE_REQUEST_MAX_WIRE_BYTES,
    RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES,
};

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

pub use canonical::{
    checkpoint_content_digest, guest_config_digest, inventory_digest, key_ring_digest, spec_digest,
};
pub use types::*;
pub use wire::{
    decode_admission_inventory_attestation, decode_agent_registration_attempt,
    decode_agent_session, decode_contract_error, decode_desired_runtime_spec,
    decode_guest_runtime_profile_receipt, decode_node_cleanup_checkpoint, decode_node_identity,
    decode_node_observation, decode_operation, decode_provision_root_image_error,
    decode_provision_root_image_request, decode_provision_root_image_result,
    decode_runtime_checkpoint, encode_admission_inventory_attestation,
    encode_agent_registration_attempt, encode_agent_session, encode_contract_error,
    encode_desired_runtime_spec, encode_guest_runtime_profile_receipt,
    encode_node_cleanup_checkpoint, encode_node_identity, encode_node_observation,
    encode_operation, encode_provision_root_image_error, encode_provision_root_image_request,
    encode_provision_root_image_result, encode_runtime_checkpoint,
    ADMISSION_INVENTORY_ATTESTATION_MAX_WIRE_BYTES, AGENT_REGISTRATION_ATTEMPT_MAX_WIRE_BYTES,
    AGENT_SESSION_MAX_WIRE_BYTES, CONTRACT_ERROR_MAX_WIRE_BYTES,
    DESIRED_RUNTIME_SPEC_MAX_WIRE_BYTES, GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES,
    NODE_CLEANUP_CHECKPOINT_MAX_WIRE_BYTES, NODE_IDENTITY_MAX_WIRE_BYTES,
    NODE_OBSERVATION_MAX_WIRE_BYTES, OPERATION_MAX_WIRE_BYTES,
    PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES, PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
    PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES, RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
};

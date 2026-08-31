//! Shared scalar, Node identity, placement and Volume Authority contracts.
//!
//! ADR-0059 removed revision-driven lifecycle intent, AgentSession and
//! observation settlement. The remaining contracts are provider-neutral
//! storage and provisioning inputs still consumed by current modules.
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

/// Exact product-router fallback body for an unmatched `/v1/...` route.
/// Runtime clients use the whole shape (status, headers and these bytes) to
/// distinguish a deployment mismatch from an HTML/plain proxy response.
pub const RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY: &[u8] =
    br#"{"code":"not_found","message":"route not found"}"#;
pub const RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS: &str = "noindex, nofollow, noarchive";

pub use canonical::value_bytes as canonical_json_value_bytes;
pub(crate) use canonical::{append_frame, decode_base64url_exact};

pub use canonical::{
    canonical_ed25519_spki_sha256, guest_config_digest, key_ring_digest,
    runtime_provisioner_active_set_digest,
};
pub use types::*;
pub use wire::{
    decode_contract_error, decode_guest_runtime_profile_receipt, decode_node_identity,
    decode_node_placement_policy, decode_provision_root_image_error,
    decode_provision_root_image_request, decode_provision_root_image_result,
    decode_runtime_node_authority_apply, decode_runtime_node_authority_apply_result,
    decode_runtime_provisioner_active_set, decode_runtime_provisioner_trust_bundle,
    encode_contract_error, encode_guest_runtime_profile_receipt, encode_node_identity,
    encode_node_placement_policy, encode_provision_root_image_error,
    encode_provision_root_image_result, encode_runtime_node_authority_apply,
    encode_runtime_node_authority_apply_result, encode_runtime_provisioner_active_set,
    encode_runtime_provisioner_trust_bundle, CONTRACT_ERROR_MAX_WIRE_BYTES,
    GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES, NODE_IDENTITY_MAX_WIRE_BYTES,
    NODE_PLACEMENT_POLICY_MAX_WIRE_BYTES, PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES,
    PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES, PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES,
    RUNTIME_NODE_AUTHORITY_APPLY_MAX_WIRE_BYTES,
    RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES,
    RUNTIME_PROVISIONER_ACTIVE_SET_MAX_WIRE_BYTES, RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES,
};

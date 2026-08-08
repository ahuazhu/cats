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

mod canonical;
mod types;
mod wire;

pub use canonical::{checkpoint_content_digest, inventory_digest, key_ring_digest, spec_digest};
pub use types::*;
pub use wire::{
    decode_admission_inventory_attestation, decode_agent_registration_attempt,
    decode_agent_session, decode_contract_error, decode_desired_runtime_spec,
    decode_node_cleanup_checkpoint, decode_node_identity, decode_node_observation,
    decode_operation, decode_runtime_checkpoint, encode_admission_inventory_attestation,
    encode_agent_registration_attempt, encode_agent_session, encode_contract_error,
    encode_desired_runtime_spec, encode_node_cleanup_checkpoint, encode_node_identity,
    encode_node_observation, encode_operation, encode_runtime_checkpoint,
};

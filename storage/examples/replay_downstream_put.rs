//! Replay one production object-write descriptor through the downstream
//! validation to learn which authority rule refused it.
//!
//! The gateway flattens every verdict into one downstream error, so a live
//! refusal cannot say which rule fired. The validation is pure, so a recorded
//! descriptor and its durable spool receipt reproduce the verdict offline.
use std::time::{Duration, Instant};

use cats_storage::object_write_authority::{
    object_put_provider_attempt_id, object_put_request_id, object_write_spool_id,
    validate_downstream_put, DurableObjectWriteSpoolReceipt, ObjectPutDescriptor,
    ObjectWriteDownstreamPut,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let descriptor_path = arguments.next().expect("descriptor json path");
    let spool_path = arguments.next().expect("spool receipt json path");
    let descriptor: ObjectPutDescriptor = serde_json::from_slice(&std::fs::read(descriptor_path)?)?;
    let spool: DurableObjectWriteSpoolReceipt =
        serde_json::from_slice(&std::fs::read(spool_path)?)?;

    println!(
        "key            = {}",
        descriptor.target.canonical_logical_key
    );
    println!("request_id     = {}", descriptor.request_id.as_str());
    println!(
        "provider_id    = {}",
        descriptor.provider_attempt_id.as_str()
    );
    println!(
        "fault          = {:?}",
        descriptor.qualification_fault.is_some()
    );
    println!("accepted_at    = {}", descriptor.accepted_at_unix_ms.get());
    println!("spool durable  = {}", spool.durable_at_unix_ms.get());

    let recomputed = object_put_request_id(
        &descriptor.writer_authority_id,
        &descriptor.target,
        &descriptor.volume_id,
        &descriptor.key,
        &descriptor.content_sha256,
        descriptor.content_length,
        descriptor
            .qualification_fault
            .as_ref()
            .map(|fault| (&descriptor.credential, fault)),
    )?;
    println!("recomputed id  = {}", recomputed.as_str());
    println!("id matches     = {}", recomputed == descriptor.request_id);
    println!(
        "provider match = {}",
        descriptor.provider_attempt_id == object_put_provider_attempt_id(&recomputed)?
    );
    println!(
        "spool id match = {}",
        spool.spool_id == object_write_spool_id(&descriptor.request_id)?
    );

    let request = ObjectWriteDownstreamPut {
        descriptor: descriptor.clone(),
        spool: spool.clone(),
    };
    match validate_downstream_put(&request, Instant::now() + Duration::from_secs(60)) {
        Ok(()) => println!("\nVERDICT: validation passes with a fresh deadline"),
        Err(error) => println!("\nVERDICT: {error}"),
    }
    Ok(())
}

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::types::{
    AuthorizedServingAcquire, Base64UrlNoPad, ContractError, ContractErrorDetail, ContractName,
    ContractVersion, DesiredRuntimeSpec, Epoch, GuestRuntimeProfileReceipt, JsonPointer, KeyId,
    MalformedProblem, NodeObservation, RuntimeCheckpoint, RuntimeProvisionerActiveSet,
    Sha256Digest,
};

const SPEC_DOMAIN: &[u8] = b"cats.runtime.desired-spec.v1";
const CHECKPOINT_DOMAIN: &[u8] = b"cats.runtime.checkpoint-content.v1";
const INVENTORY_DOMAIN: &[u8] = b"cats.runtime.inventory.v1";
const KEY_RING_DOMAIN: &[u8] = b"cats.runtime.key-ring.v1";
const GUEST_RUNTIME_PROFILE_DOMAIN: &[u8] = b"cats.runtime.guest-runtime-profile.v1";
const RESIDUE_ACQUISITION_DOMAIN: &[u8] = b"cats.runtime.residue-acquisition.v1";

/// Computes the digest of the complete immutable acquire receipt carried by a
/// residue authority request. The digest is diagnostic binding, never an
/// authority substitute for the receipt itself.
pub fn residue_acquisition_digest(
    acquisition: &AuthorizedServingAcquire,
) -> Result<Sha256Digest, ContractError> {
    let value = as_value(acquisition, ContractName::RuntimeResidueAuthorityRequest)?;
    Ok(digest_value(RESIDUE_ACQUISITION_DOMAIN, &value))
}

/// Computes the digest of one validated canonical GuestRuntimeProfileReceipt artifact.
pub fn guest_config_digest(
    receipt: &GuestRuntimeProfileReceipt,
) -> Result<Sha256Digest, ContractError> {
    let canonical = super::wire::encode_guest_runtime_profile_receipt(receipt)?;
    Ok(digest_bytes(GUEST_RUNTIME_PROFILE_DOMAIN, &canonical))
}

/// Computes the DesiredRuntimeSpec digest after context-free intrinsic validation.
pub fn spec_digest(spec: &DesiredRuntimeSpec) -> Result<Sha256Digest, ContractError> {
    let mut value = as_value(spec, ContractName::DesiredRuntimeSpec)?;
    value
        .as_object_mut()
        .expect("DesiredRuntimeSpec serializes as an object")
        .remove("spec_digest");
    let digest = digest_value(SPEC_DOMAIN, &value);
    let mut validation_value = as_value(spec, ContractName::DesiredRuntimeSpec)?;
    validation_value
        .as_object_mut()
        .expect("DesiredRuntimeSpec serializes as an object")
        .insert(
            "spec_digest".to_owned(),
            Value::String(digest.as_str().to_owned()),
        );
    let encoded = serde_json::to_vec(&validation_value)
        .map_err(|_| invalid(ContractName::DesiredRuntimeSpec, ""))?;
    super::wire::decode_desired_runtime_spec(&encoded)?;
    Ok(digest)
}

/// Computes the digest binding every field in a RuntimeCheckpoint.
pub fn checkpoint_content_digest(
    checkpoint: &RuntimeCheckpoint,
) -> Result<Sha256Digest, ContractError> {
    let value = as_value(checkpoint, ContractName::RuntimeCheckpoint)?;
    let encoded =
        serde_json::to_vec(&value).map_err(|_| invalid(ContractName::RuntimeCheckpoint, ""))?;
    super::wire::decode_runtime_checkpoint(&encoded)?;
    Ok(digest_value(CHECKPOINT_DOMAIN, &value))
}

/// Computes the physical inventory projection digest for a complete observation.
pub fn inventory_digest(observation: &NodeObservation) -> Result<Sha256Digest, ContractError> {
    if !observation.complete_inventory || observation.inventory_read_position.is_none() {
        return Err(invalid(ContractName::NodeObservation, ""));
    }
    let digest = unchecked_inventory_digest(observation);
    let mut validation_value = as_value(observation, ContractName::NodeObservation)?;
    validation_value
        .as_object_mut()
        .expect("NodeObservation serializes as an object")
        .insert(
            "inventory_digest".to_owned(),
            Value::String(digest.as_str().to_owned()),
        );
    let encoded = serde_json::to_vec(&validation_value)
        .map_err(|_| invalid(ContractName::NodeObservation, ""))?;
    super::wire::decode_node_observation(&encoded)?;

    let mut source = as_value(observation, ContractName::NodeObservation)?;
    let source = source
        .as_object_mut()
        .expect("NodeObservation serializes as an object");
    let read_position = source
        .remove("inventory_read_position")
        .and_then(|value| (!value.is_null()).then_some(value))
        .ok_or_else(|| invalid(ContractName::NodeObservation, "/inventory_read_position"))?;
    let runtimes = source
        .remove("runtimes")
        .expect("NodeObservation always serializes runtimes");
    let mut projected_runtimes = runtimes
        .as_array()
        .expect("NodeObservation.runtimes serializes as an array")
        .clone();
    for runtime in &mut projected_runtimes {
        runtime
            .as_object_mut()
            .expect("ObservedRuntimeStatus serializes as an object")
            .remove("conditions");
    }
    let residue = source
        .remove("residue")
        .expect("NodeObservation always serializes residue");

    let mut projection = Map::new();
    for key in [
        "version",
        "node_id",
        "node_boot_id",
        "agent_instance_id",
        "agent_session_epoch",
        "inventory_epoch",
    ] {
        projection.insert(
            key.to_owned(),
            source
                .remove(key)
                .expect("NodeObservation projection field always serializes"),
        );
    }
    projection.insert("inventory_read_position".to_owned(), read_position);
    projection.insert("runtimes".to_owned(), Value::Array(projected_runtimes));
    projection.insert("residue".to_owned(), residue);
    let projected_digest = digest_value(INVENTORY_DOMAIN, &Value::Object(projection));
    debug_assert_eq!(projected_digest, digest);
    Ok(projected_digest)
}

/// Computes the digest for one atomically loaded key-ring version.
pub fn key_ring_digest(
    key_ring_version: Epoch,
    loaded_kids: &[KeyId],
) -> Result<Sha256Digest, ContractError> {
    super::wire::validate_key_ring(loaded_kids)?;
    let projection = serde_json::json!({
        "version": ContractVersion::V1,
        "key_ring_version": key_ring_version,
        "loaded_kids": loaded_kids,
    });
    Ok(digest_value(KEY_RING_DOMAIN, &projection))
}

/// Computes the ordinary SHA-256 of one validated canonical provisioner
/// active-set artifact. Unlike runtime content digests this authority pointer
/// deliberately has no domain prefix; the closed active-set schema is its
/// complete preimage contract.
pub fn runtime_provisioner_active_set_digest(
    active_set: &RuntimeProvisionerActiveSet,
) -> Result<Sha256Digest, ContractError> {
    let canonical = super::wire::encode_runtime_provisioner_active_set(active_set)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(canonical).into()))
}

/// Computes the ordinary SHA-256 of one exact canonical Ed25519 SPKI DER
/// value. The narrow `Option` keeps provider code from accepting a merely
/// base64url-shaped string as an Ed25519 key.
pub fn canonical_ed25519_spki_sha256(public_key_spki: &Base64UrlNoPad) -> Option<Sha256Digest> {
    let der = super::wire::canonical_ed25519_spki_bytes(public_key_spki)?;
    Some(Sha256Digest::from_bytes(Sha256::digest(der).into()))
}

pub(crate) fn unchecked_spec_digest(spec: &DesiredRuntimeSpec) -> Sha256Digest {
    let mut value = serde_json::to_value(spec).expect("typed contracts are serializable");
    value
        .as_object_mut()
        .expect("DesiredRuntimeSpec serializes as an object")
        .remove("spec_digest");
    digest_value(SPEC_DOMAIN, &value)
}

pub(crate) fn unchecked_inventory_digest(observation: &NodeObservation) -> Sha256Digest {
    let mut source = serde_json::to_value(observation).expect("typed contracts are serializable");
    let source = source
        .as_object_mut()
        .expect("NodeObservation serializes as an object");
    let mut projection = Map::new();
    for key in [
        "version",
        "node_id",
        "node_boot_id",
        "agent_instance_id",
        "agent_session_epoch",
        "inventory_epoch",
        "inventory_read_position",
        "runtimes",
        "residue",
    ] {
        let mut value = source
            .remove(key)
            .expect("NodeObservation projection field always serializes");
        if key == "runtimes" {
            for runtime in value
                .as_array_mut()
                .expect("NodeObservation.runtimes serializes as an array")
            {
                runtime
                    .as_object_mut()
                    .expect("ObservedRuntimeStatus serializes as an object")
                    .remove("conditions");
            }
        }
        projection.insert(key.to_owned(), value);
    }
    digest_value(INVENTORY_DOMAIN, &Value::Object(projection))
}

pub(crate) fn unchecked_key_ring_digest(version: Epoch, kids: &[KeyId]) -> Sha256Digest {
    digest_value(
        KEY_RING_DOMAIN,
        &serde_json::json!({
            "version": ContractVersion::V1,
            "key_ring_version": version,
            "loaded_kids": kids,
        }),
    )
}

fn as_value<T: Serialize>(value: &T, contract: ContractName) -> Result<Value, ContractError> {
    serde_json::to_value(value).map_err(|_| invalid(contract, ""))
}

fn invalid(contract: ContractName, pointer: &str) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::MalformedPayload {
            contract,
            json_pointer: JsonPointer::new(pointer).expect("static pointer is valid"),
            problem: MalformedProblem::InvalidValue,
        }),
        message: "contract cannot be canonically encoded".to_owned(),
    }
}

fn digest_value(domain: &[u8], value: &Value) -> Sha256Digest {
    let canonical = value_bytes(value);
    digest_bytes(domain, &canonical)
}

fn digest_bytes(domain: &[u8], canonical: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

pub(crate) fn value_bytes(value: &Value) -> Vec<u8> {
    let mut canonical = Vec::new();
    write_value(value, &mut canonical);
    canonical
}

fn write_value(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => write_string(string, output),
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_value(item, output);
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut members: Vec<_> = object.iter().collect();
            members.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            output.push(b'{');
            for (index, (key, member)) in members.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_string(key, output);
                output.push(b':');
                write_value(member, output);
            }
            output.push(b'}');
        }
    }
}

fn write_string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br#"\\"#),
            '\u{08}' => output.extend_from_slice(br#"\b"#),
            '\u{0c}' => output.extend_from_slice(br#"\f"#),
            '\n' => output.extend_from_slice(br#"\n"#),
            '\r' => output.extend_from_slice(br#"\r"#),
            '\t' => output.extend_from_slice(br#"\t"#),
            '\u{00}'..='\u{1f}' => {
                output.extend_from_slice(br#"\u00"#);
                let byte = character as u8;
                output.push(hex_digit(byte >> 4));
                output.push(hex_digit(byte & 0x0f));
            }
            _ => {
                let mut buffer = [0; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    output.push(b'"');
}

const fn hex_digit(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    }
}

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::types::{
    Base64UrlNoPad, ContractError, ContractVersion, Epoch, GuestRuntimeProfileReceipt, KeyId,
    RuntimeProvisionerActiveSet, Sha256Digest,
};

const KEY_RING_DOMAIN: &[u8] = b"cats.runtime.key-ring.v1";
const GUEST_RUNTIME_PROFILE_DOMAIN: &[u8] = b"cats.runtime.guest-runtime-profile.v1";
/// Computes the digest of one validated canonical GuestRuntimeProfileReceipt artifact.
pub fn guest_config_digest(
    receipt: &GuestRuntimeProfileReceipt,
) -> Result<Sha256Digest, ContractError> {
    let canonical = super::wire::encode_guest_runtime_profile_receipt(receipt)?;
    Ok(digest_bytes(GUEST_RUNTIME_PROFILE_DOMAIN, &canonical))
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

/// Encode one JSON value in the repository's canonical form: object keys are
/// ordered by their UTF-8 bytes, insignificant whitespace is absent, and
/// strings use the minimal fixed escaping rules below.
///
/// Persistence journals use this same primitive as public wire codecs so a
/// restart can reject semantically equivalent but byte-different documents.
pub fn value_bytes(value: &Value) -> Vec<u8> {
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

/// Appends one length-prefixed frame to a signing envelope.
///
/// Every signed dialect in this crate frames its parts the same way so a
/// shorter part can never be confused with a longer neighbour.
pub(crate) fn append_frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

/// Decodes exactly `N` bytes from canonical unpadded base64url.
///
/// Canonical means the input re-encodes to itself: an alternative encoding of
/// the same bytes is rejected rather than silently accepted, so a signature
/// cannot be replayed under a different spelling. The caller maps the unit
/// error onto its own protocol's rejection type.
pub(crate) fn decode_base64url_exact<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    {
        return Err(());
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(());
    }
    decoded.try_into().map_err(|_| ())
}

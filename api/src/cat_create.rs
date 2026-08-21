//! Frozen public DTOs for the signed-runtime Cat-create ingress.
//!
//! This module is deliberately separate from the legacy product request
//! legacy product-authority shapes. Production clients and the production
//! ingress share these types so neither side can silently retain retired
//! fields while the runtime authority is being cut over.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::runtime_reconciliation::{Durability, Id, Sha256Digest};

/// Maximum RootDisk size accepted by the v2 Cat-create ingress.
pub const CAT_CREATE_V2_MAX_ROOT_SIZE_BYTES: u64 = 1_099_511_627_776;

/// The exact production Cat-create request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatCreateV2Request {
    pub name: Id,
    pub boot_image_digest: Sha256Digest,
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub root_size_bytes: u64,
    pub durability: Durability,
}

impl CatCreateV2Request {
    /// Construct and validate the same semantic shape the production ingress
    /// accepts. Parsing from JSON remains strict but calls [`Self::validate`]
    /// separately so service-side error mapping stays explicit.
    pub fn new(
        name: impl Into<String>,
        boot_image_digest: impl Into<String>,
        vcpus: u32,
        memory_bytes: u64,
        root_size_bytes: u64,
        durability: Durability,
    ) -> Result<Self, CatCreateV2ValidationError> {
        let request = Self {
            name: Id::new(name).ok_or(CatCreateV2ValidationError::Name)?,
            boot_image_digest: Sha256Digest::new(boot_image_digest)
                .ok_or(CatCreateV2ValidationError::BootImageDigest)?,
            vcpus,
            memory_bytes,
            root_size_bytes,
            durability,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), CatCreateV2ValidationError> {
        let name = self.name.as_str().as_bytes();
        if !(1..=30).contains(&name.len())
            || !name
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            || !name
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !name
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(CatCreateV2ValidationError::Name);
        }
        if self.vcpus == 0 {
            return Err(CatCreateV2ValidationError::Vcpus);
        }
        if self.memory_bytes == 0 || self.memory_bytes > i64::MAX as u64 {
            return Err(CatCreateV2ValidationError::MemoryBytes);
        }
        if self.root_size_bytes == 0 || self.root_size_bytes > CAT_CREATE_V2_MAX_ROOT_SIZE_BYTES {
            return Err(CatCreateV2ValidationError::RootSizeBytes);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CatCreateV2ValidationError {
    #[error("Cat name must be 1..=30 lowercase ASCII letters, digits or interior hyphens")]
    Name,
    #[error("boot_image_digest must be one lowercase sha256 digest")]
    BootImageDigest,
    #[error("vcpus must be positive")]
    Vcpus,
    #[error("memory_bytes must be in 1..=9223372036854775807")]
    MemoryBytes,
    #[error("root_size_bytes must be in 1..=1099511627776")]
    RootSizeBytes,
}

/// The exact flat body returned with `202 Accepted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatCreateV2AcceptedResponse {
    pub cat_id: Id,
    pub operation_id: Id,
}

pub fn encode_cat_create_v2_accepted_response(
    cat_id: &Id,
    operation_id: &Id,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&CatCreateV2AcceptedResponse {
        cat_id: cat_id.clone(),
        operation_id: operation_id.clone(),
    })
}

pub fn decode_cat_create_v2_accepted_response(
    body: &[u8],
) -> Result<CatCreateV2AcceptedResponse, serde_json::Error> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let response = CatCreateV2AcceptedResponse::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn request_wire_is_the_frozen_six_field_shape() {
        let request = CatCreateV2Request::new(
            "app",
            DIGEST,
            2,
            2_147_483_648,
            4_294_967_296,
            Durability::Strict,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&request).unwrap(),
            br#"{"name":"app","boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vcpus":2,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"strict"}"#
        );
        assert!(serde_json::from_slice::<CatCreateV2Request>(
            br#"{"name":"app","boot_image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vcpus":2,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"strict","image":"legacy"}"#,
        )
        .is_err());
    }

    #[test]
    fn accepted_response_is_flat_and_strict() {
        let cat_id = Id::new("cat_01").unwrap();
        let operation_id = Id::new("op_01").unwrap();
        let wire = encode_cat_create_v2_accepted_response(&cat_id, &operation_id).unwrap();
        assert_eq!(wire, br#"{"cat_id":"cat_01","operation_id":"op_01"}"#);
        assert_eq!(
            decode_cat_create_v2_accepted_response(&wire).unwrap(),
            CatCreateV2AcceptedResponse {
                cat_id,
                operation_id,
            }
        );
        assert!(decode_cat_create_v2_accepted_response(
            br#"{"cat_id":"cat_01","operation_id":"op_01","operation":{}}"#,
        )
        .is_err());
        assert!(decode_cat_create_v2_accepted_response(
            br#"{"cat_id":"cat_01","cat_id":"cat_02","operation_id":"op_01"}"#,
        )
        .is_err());
    }
}

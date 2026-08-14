//! Closed public Cat and Disk read projections for the runtime-authority cutover.
//!
//! These DTOs deliberately contain product status only. They do not expose
//! volume ownership, attachment transitions, initialization tokens, physical
//! inventory, checkpoints, or any other field that could be mistaken for
//! lifecycle authority.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::runtime_reconciliation::{
    ContractVersion, Durability, Epoch, Hostname, HttpProtocol, Id, Revision, RuntimeTarget,
    Sha256Digest, StableState, UnixMillis,
};

pub const PRODUCT_READ_DEFAULT_LIMIT: usize = 50;
pub const PRODUCT_READ_MAX_LIMIT: usize = 100;
pub const ENDPOINT_READ_MAX_ITEMS: usize = 256;
const PRODUCT_READ_CURSOR_MAX_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductReadPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatReadV2 {
    pub version: ContractVersion,
    pub id: Id,
    pub workspace_id: Id,
    pub name: Id,
    pub created_at_unix_ms: UnixMillis,
    pub desired: CatDesiredReadV2,
    pub observed: Option<CatObservedReadV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatDesiredReadV2 {
    pub revision: Revision,
    pub target: RuntimeTarget,
    pub node_id: Id,
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub boot_image_digest: Sha256Digest,
    pub root_disk_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatObservedReadV2 {
    pub applied_desired_revision: Option<Revision>,
    pub stable_state: Option<StableState>,
    pub conditions: Vec<RuntimeConditionKind>,
    pub accepted_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConditionKind {
    Ready,
    Progressing,
    Blocked,
    PreconditionFailed,
    Degraded,
    Quarantined,
    DataLossPossible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskReadV2 {
    pub version: ContractVersion,
    pub id: Id,
    pub workspace_id: Id,
    pub name: Id,
    pub size_bytes: u64,
    pub durability: Durability,
    pub created_at_unix_ms: UnixMillis,
    pub kind: DiskReadKind,
    pub admin_state: DiskReadAdminState,
    pub binding: Option<DiskReadBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiskReadKind {
    Root { cat_id: Id },
    Persistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskReadAdminState {
    Active,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskReadBinding {
    pub cat_id: Id,
    pub desired_revision: Revision,
}

/// One complete current Endpoint membership projection for a Cat.
///
/// This is observation-only product state. In particular, `complete` is not
/// route admission authority and `items` never includes retained records that
/// are absent from the current DesiredRuntimeSpec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCollectionReadV2 {
    pub version: ContractVersion,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub complete: bool,
    pub items: Vec<EndpointReadV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointReadV2 {
    pub version: ContractVersion,
    pub endpoint_id: Id,
    pub name: Id,
    pub hostname: Hostname,
    pub target_port: u16,
    pub protocol: HttpProtocol,
    pub wake_policy: EndpointReadWakePolicy,
    pub route_epoch: Epoch,
}

/// Route Grant v2 has no public wake authority in this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointReadWakePolicy {
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductReadCursorV1 {
    version: u8,
    resource: ProductReadResource,
    last_id: Id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductReadResource {
    Cats,
    Disks,
}

impl ProductReadResource {
    fn id_prefix(self) -> &'static str {
        match self {
            Self::Cats => "cat_",
            Self::Disks => "disk_",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProductReadCursorError {
    #[error("cursor is not canonical base64url-no-pad")]
    Encoding,
    #[error("cursor payload is not the closed v1 contract")]
    Payload,
}

pub fn encode_product_read_cursor(resource: ProductReadResource, last_id: &Id) -> String {
    let payload = serde_json::to_vec(&ProductReadCursorV1 {
        version: 1,
        resource,
        last_id: last_id.clone(),
    })
    .expect("the closed cursor DTO is infallibly serializable");
    URL_SAFE_NO_PAD.encode(payload)
}

pub fn decode_product_read_cursor(
    expected_resource: ProductReadResource,
    value: &str,
) -> Result<Id, ProductReadCursorError> {
    if value.is_empty() || value.len() > PRODUCT_READ_CURSOR_MAX_BYTES {
        return Err(ProductReadCursorError::Encoding);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| ProductReadCursorError::Encoding)?;
    if URL_SAFE_NO_PAD.encode(&payload) != value {
        return Err(ProductReadCursorError::Encoding);
    }
    let mut decoder = serde_json::Deserializer::from_slice(&payload);
    let cursor = ProductReadCursorV1::deserialize(&mut decoder)
        .map_err(|_| ProductReadCursorError::Payload)?;
    decoder.end().map_err(|_| ProductReadCursorError::Payload)?;
    if cursor.version != 1
        || cursor.resource != expected_resource
        || !cursor
            .last_id
            .as_str()
            .starts_with(cursor.resource.id_prefix())
        || serde_json::to_vec(&cursor).map_err(|_| ProductReadCursorError::Payload)? != payload
    {
        return Err(ProductReadCursorError::Payload);
    }
    Ok(cursor.last_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    #[test]
    fn cursor_is_canonical_closed_and_versioned() {
        let encoded = encode_product_read_cursor(ProductReadResource::Cats, &id("cat_01"));
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&encoded).unwrap(),
            br#"{"version":1,"resource":"cats","last_id":"cat_01"}"#
        );
        assert_eq!(
            decode_product_read_cursor(ProductReadResource::Cats, &encoded).unwrap(),
            id("cat_01")
        );
        assert!(decode_product_read_cursor(ProductReadResource::Disks, &encoded).is_err());

        for payload in [
            br#"{"resource":"cats","version":1,"last_id":"cat_01"}"#.as_slice(),
            br#"{"version":2,"resource":"cats","last_id":"cat_01"}"#,
            br#"{"version":1,"resource":"cats","last_id":"cat_01","extra":true}"#,
            br#"{ "version":1,"resource":"cats","last_id":"cat_01"}"#,
            br#"{"version":1,"resource":"cats","last_id":""}"#,
            br#"{"version":1,"resource":"cats","last_id":"disk_01"}"#,
            br#"{"version":1,"resource":"operations","last_id":"op_01"}"#,
        ] {
            assert!(decode_product_read_cursor(
                ProductReadResource::Cats,
                &URL_SAFE_NO_PAD.encode(payload)
            )
            .is_err());
        }
        assert!(
            decode_product_read_cursor(ProductReadResource::Cats, &format!("{encoded}=")).is_err()
        );
        assert!(decode_product_read_cursor(ProductReadResource::Cats, "").is_err());
        assert!(decode_product_read_cursor(ProductReadResource::Cats, &"A".repeat(513)).is_err());
    }

    #[test]
    fn endpoint_collection_is_the_closed_v2_product_projection() {
        let response = EndpointCollectionReadV2 {
            version: ContractVersion::V1,
            cat_id: id("cat_01"),
            desired_revision: Revision::new(7).unwrap(),
            complete: true,
            items: vec![EndpointReadV2 {
                version: ContractVersion::V1,
                endpoint_id: id("ep_01"),
                name: id("web"),
                hostname: Hostname::new("web.example.test").unwrap(),
                target_port: 8080,
                protocol: HttpProtocol::Http,
                wake_policy: EndpointReadWakePolicy::Disabled,
                route_epoch: Epoch::new(3).unwrap(),
            }],
        };
        let encoded = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            encoded,
            br#"{"version":1,"cat_id":"cat_01","desired_revision":7,"complete":true,"items":[{"version":1,"endpoint_id":"ep_01","name":"web","hostname":"web.example.test","target_port":8080,"protocol":"http","wake_policy":"disabled","route_epoch":3}]}"#
        );
        assert_eq!(
            serde_json::from_slice::<EndpointCollectionReadV2>(&encoded).unwrap(),
            response
        );
        let with_extra = br#"{"version":1,"cat_id":"cat_01","desired_revision":7,"complete":true,"items":[],"extra":true}"#;
        assert!(serde_json::from_slice::<EndpointCollectionReadV2>(with_extra).is_err());
    }
}

//! Closed public Cat and Disk read projections for the runtime-authority cutover.
//!
//! These DTOs deliberately contain product status only. They do not expose
//! volume ownership, attachment transitions, initialization tokens, physical
//! inventory, checkpoints, or any other field that could be mistaken for
//! lifecycle authority.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::runtime_inventory::{ObservedRuntimeConditionKind, ObservedRuntimePhysicalState};
use crate::runtime_reconciliation::{
    ContractVersion, Durability, Epoch, Hostname, HttpProtocol, Id, RandomId128, Sequence,
    Sha256Digest, UnixMillis,
};

pub const PRODUCT_READ_DEFAULT_LIMIT: usize = 50;
pub const PRODUCT_READ_MAX_LIMIT: usize = 100;
pub const ENDPOINT_READ_MAX_ITEMS: usize = 256;
pub const CAT_OPERATION_READ_MAX_WIRE_BYTES: usize = 4096;
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
    pub current_runtime_config_id: Id,
    pub current_runtime_config_digest: Sha256Digest,
    pub lifecycle: CatLifecycleReadV2,
    pub observed: Option<CatObservedReadV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatLifecycleReadV2 {
    pub head_operation_id: Option<Id>,
    pub stable_state: Option<CatStableStateReadV2>,
    pub effective_runtime_ready_operation_id: Option<Id>,
    pub runtime_incarnation: Option<RandomId128>,
    pub deleted_at_unix_ms: Option<UnixMillis>,
}

/// Product projection of one Cat lifecycle Operation.
///
/// Node command names, placement, volume authority and physical recovery
/// evidence are deliberately absent. They belong to the private Node protocol
/// and must not become a second product lifecycle vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatOperationReadV1 {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub workspace_id: Id,
    pub cat_id: Id,
    pub action: CatOperationAction,
    pub state: CatOperationState,
    pub created_at_unix_ms: UnixMillis,
    pub terminal_at_unix_ms: Option<UnixMillis>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatOperationAction {
    Create,
    Run,
    Suspend,
    Warm,
    Cold,
    Destroy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatOperationState {
    InProgress,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CatOperationReadError {
    #[error("Cat Operation product projection is too large")]
    TooLarge,
    #[error("Cat Operation product projection is invalid")]
    Invalid,
}

impl CatOperationReadV1 {
    fn validate(&self) -> Result<(), CatOperationReadError> {
        let terminal_shape_is_valid = match self.state {
            CatOperationState::InProgress => self.terminal_at_unix_ms.is_none(),
            CatOperationState::Succeeded | CatOperationState::Failed => self
                .terminal_at_unix_ms
                .is_some_and(|terminal| terminal.get() >= self.created_at_unix_ms.get()),
        };
        if self.version != ContractVersion::V1
            || !self.operation_id.as_str().starts_with("op_")
            || !self.workspace_id.as_str().starts_with("ws_")
            || !self.cat_id.as_str().starts_with("cat_")
            || !terminal_shape_is_valid
        {
            return Err(CatOperationReadError::Invalid);
        }
        Ok(())
    }
}

pub fn encode_cat_operation_read_v1(
    operation: &CatOperationReadV1,
) -> Result<Vec<u8>, CatOperationReadError> {
    operation.validate()?;
    let encoded = serde_json::to_vec(operation).map_err(|_| CatOperationReadError::Invalid)?;
    if encoded.len() > CAT_OPERATION_READ_MAX_WIRE_BYTES {
        return Err(CatOperationReadError::TooLarge);
    }
    Ok(encoded)
}

pub fn decode_cat_operation_read_v1(
    bytes: &[u8],
) -> Result<CatOperationReadV1, CatOperationReadError> {
    if bytes.is_empty() || bytes.len() > CAT_OPERATION_READ_MAX_WIRE_BYTES {
        return Err(if bytes.len() > CAT_OPERATION_READ_MAX_WIRE_BYTES {
            CatOperationReadError::TooLarge
        } else {
            CatOperationReadError::Invalid
        });
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let operation = CatOperationReadV1::deserialize(&mut decoder)
        .map_err(|_| CatOperationReadError::Invalid)?;
    decoder.end().map_err(|_| CatOperationReadError::Invalid)?;
    operation.validate()?;
    if serde_json::to_vec(&operation).map_err(|_| CatOperationReadError::Invalid)? != bytes {
        return Err(CatOperationReadError::Invalid);
    }
    Ok(operation)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatStableStateReadV2 {
    Running,
    Suspended,
    Warm,
    Cold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatObservedReadV2 {
    pub node_id: Id,
    pub physical_state: ObservedRuntimePhysicalState,
    pub conditions: Vec<ObservedRuntimeConditionKind>,
    pub source_report_id: RandomId128,
    pub sequence: Sequence,
    pub accepted_at_unix_ms: UnixMillis,
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
    pub runtime_config_id: Id,
}

/// One complete current Endpoint membership projection for a Cat.
///
/// This is product metadata, not route admission authority. Retained unbound
/// Endpoint identities remain visible with an explicit closed binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCollectionReadV2 {
    pub version: ContractVersion,
    pub cat_id: Id,
    pub complete: bool,
    pub items: Vec<EndpointReadV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointReadV2 {
    pub version: ContractVersion,
    pub endpoint_id: Id,
    pub name: Id,
    pub route_epoch: Epoch,
    pub binding: EndpointReadBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EndpointReadBinding {
    Bound {
        hostname: Hostname,
        target_port: u16,
        protocol: HttpProtocol,
    },
    Unbound,
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
            complete: true,
            items: vec![EndpointReadV2 {
                version: ContractVersion::V1,
                endpoint_id: id("ep_01"),
                name: id("web"),
                route_epoch: Epoch::new(3).unwrap(),
                binding: EndpointReadBinding::Bound {
                    hostname: Hostname::new("web.example.test").unwrap(),
                    target_port: 8080,
                    protocol: HttpProtocol::Http,
                },
            }],
        };
        let encoded = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            encoded,
            br#"{"version":1,"cat_id":"cat_01","complete":true,"items":[{"version":1,"endpoint_id":"ep_01","name":"web","route_epoch":3,"binding":{"kind":"bound","hostname":"web.example.test","target_port":8080,"protocol":"http"}}]}"#
        );
        assert_eq!(
            serde_json::from_slice::<EndpointCollectionReadV2>(&encoded).unwrap(),
            response
        );
        let with_extra =
            br#"{"version":1,"cat_id":"cat_01","complete":true,"items":[],"extra":true}"#;
        assert!(serde_json::from_slice::<EndpointCollectionReadV2>(with_extra).is_err());
    }

    #[test]
    fn cat_operation_projection_is_canonical_closed_and_hides_node_protocol() {
        let operation = CatOperationReadV1 {
            version: ContractVersion::V1,
            operation_id: id("op_01"),
            workspace_id: id("ws_01"),
            cat_id: id("cat_01"),
            action: CatOperationAction::Run,
            state: CatOperationState::Succeeded,
            created_at_unix_ms: UnixMillis::new(10).unwrap(),
            terminal_at_unix_ms: Some(UnixMillis::new(20).unwrap()),
        };
        let encoded = encode_cat_operation_read_v1(&operation).unwrap();
        assert_eq!(
            encoded,
            br#"{"version":1,"operation_id":"op_01","workspace_id":"ws_01","cat_id":"cat_01","action":"run","state":"succeeded","created_at_unix_ms":10,"terminal_at_unix_ms":20}"#
        );
        assert_eq!(decode_cat_operation_read_v1(&encoded).unwrap(), operation);

        for invalid in [
            br#"{"version":1,"operation_id":"op_01","workspace_id":"ws_01","cat_id":"cat_01","action":"run","state":"in_progress","created_at_unix_ms":10,"terminal_at_unix_ms":20}"#.as_slice(),
            br#"{"version":1,"operation_id":"op_01","workspace_id":"ws_01","cat_id":"cat_01","action":"run","state":"succeeded","created_at_unix_ms":20,"terminal_at_unix_ms":10}"#,
            br#"{"version":1,"operation_id":"op_01","workspace_id":"ws_01","cat_id":"cat_01","action":"start","state":"succeeded","created_at_unix_ms":10,"terminal_at_unix_ms":20}"#,
            br#"{"version":1,"operation_id":"op_01","workspace_id":"ws_01","cat_id":"cat_01","action":"run","state":"succeeded","created_at_unix_ms":10,"terminal_at_unix_ms":20,"command_kind":"start"}"#,
        ] {
            assert!(decode_cat_operation_read_v1(invalid).is_err());
        }
    }
}
